//! OperationGrant: a bounded, time-limited capability an agent frontend holds
//! to relay operations through the broker.
//!
//! Design (§17 of the split design document):
//! - the user issues a grant for exactly one profile and an explicit set of
//!   operation kinds with a budget of at most `GRANT_BUDGET_CAP` operations;
//! - the grant binds the agent's Ed25519 public key and expires after
//!   `GRANT_TTL` (30 minutes); every request must additionally declare an
//!   absolute deadline at or before the grant's expiry;
//! - every grant request carries a proof-of-possession signature over the
//!   complete request prelude, so a stolen grant record without the agent key
//!   is useless;
//! - the broker decrements the budget per relayed root request and appends an
//!   audit entry for every relay and every rejection.

use crate::v6::V6RequestPrelude;
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroizing;

/// Grant lifetime: the capability horizon for agent-relayed operations.
pub const GRANT_TTL: Duration = Duration::from_secs(30 * 60);
/// Hard cap on the operation budget of one grant.
pub const GRANT_BUDGET_CAP: u32 = 1000;
/// Hard cap on the number of operation kinds one grant may authorize.
pub const GRANT_MAX_OPERATIONS: usize = 32;
/// Base64 length of one Ed25519 signature.
pub const POP_SIGNATURE_B64_LEN: usize = 88;

const POP_DOMAIN: &[u8] = b"serctl/ipc/v6/grant-pop/v1\0";

/// Wire/registry record of one issued grant. Never contains the agent's
/// private key; `holder_key` is the agent's Ed25519 public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationGrant {
    pub grant_id: [u8; 16],
    /// The profile this grant authorizes operations against.
    pub profile_name: String,
    /// Resolved at issuance; a replaced profile (new id) invalidates the grant.
    pub profile_id: [u8; 16],
    /// Authorized `frame_kind` values, e.g. `exec`, `sftp.list-dir`.
    pub operations: Vec<String>,
    pub budget: u32,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub holder_key: [u8; 32],
}

impl OperationGrant {
    pub fn new(
        profile_name: String,
        profile_id: [u8; 16],
        operations: Vec<String>,
        budget: u32,
        holder_key: &VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<Self> {
        ensure!(
            !profile_name.is_empty()
                && profile_name.len() <= 128
                && !profile_name
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':')),
            "grant profile name must satisfy the vault profile-name rules"
        );
        ensure!(
            (1..=GRANT_BUDGET_CAP).contains(&budget),
            "grant budget must be between 1 and {GRANT_BUDGET_CAP}"
        );
        ensure!(
            !operations.is_empty() && operations.len() <= GRANT_MAX_OPERATIONS,
            "grant must authorize 1..={GRANT_MAX_OPERATIONS} operation kinds"
        );
        let mut grant_id = [0_u8; 16];
        OsRng.fill_bytes(&mut grant_id);
        let expires_unix_ms = now_unix_ms
            .checked_add(
                u64::try_from(GRANT_TTL.as_millis()).context("grant TTL exceeds u64 millis")?,
            )
            .context("grant expiry overflow")?;
        Ok(Self {
            grant_id,
            profile_name,
            profile_id,
            operations,
            budget,
            issued_unix_ms: now_unix_ms,
            expires_unix_ms,
            holder_key: holder_key.to_bytes(),
        })
    }

    pub fn grant_id_hex(&self) -> String {
        hex::encode(self.grant_id)
    }

    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.expires_unix_ms
    }

    pub fn covers(&self, prelude: &V6RequestPrelude) -> bool {
        self.operations
            .iter()
            .any(|kind| kind == &prelude.operation_kind)
    }

    pub fn covers_profile(&self, prelude: &V6RequestPrelude) -> bool {
        prelude
            .profile_name
            .as_ref()
            .is_some_and(|name| name == &self.profile_name)
    }
}

/// The exact bytes an agent signs for proof of possession: the grant domain
/// separator followed by the canonical JSON of every authenticated prelude
/// field. Nothing about the declared root request can be swapped afterwards.
pub fn prelude_pop_message(prelude: &V6RequestPrelude) -> Result<Zeroizing<Vec<u8>>> {
    #[derive(Serialize)]
    struct PopPayload<'a> {
        protocol_version: u16,
        client_session_id: &'a [u8; 16],
        request_id: &'a [u8; 16],
        operation_kind: &'a str,
        profile_id: Option<[u8; 16]>,
        profile_name: Option<&'a str>,
        grant_id: Option<[u8; 16]>,
        profile_proof: Option<&'a str>,
        requested_deadline_unix_ms: u64,
        root_request_hash: &'a [u8; 32],
    }
    let payload = PopPayload {
        protocol_version: prelude.protocol_version,
        client_session_id: &prelude.client_session_id,
        request_id: &prelude.request_id,
        operation_kind: &prelude.operation_kind,
        profile_id: prelude.profile_id,
        profile_name: prelude.profile_name.as_deref(),
        grant_id: prelude.grant_id,
        profile_proof: prelude.profile_proof.as_deref(),
        requested_deadline_unix_ms: prelude.requested_deadline_unix_ms,
        root_request_hash: &prelude.root_request_hash,
    };
    let encoded = Zeroizing::new(
        serde_json::to_vec(&payload).context("serialize grant proof-of-possession payload")?,
    );
    let mut message = Zeroizing::new(Vec::with_capacity(POP_DOMAIN.len() + encoded.len()));
    message.extend_from_slice(POP_DOMAIN);
    message.extend_from_slice(&encoded);
    Ok(message)
}

/// Sign `prelude` with the agent's key, returning the Base64 signature for the
/// prelude's `pop_signature` field.
pub fn sign_prelude_pop(key: &SigningKey, prelude: &V6RequestPrelude) -> Result<String> {
    let message = prelude_pop_message(prelude)?;
    let signature = key.sign(&message);
    Ok(B64.encode(signature.to_bytes()))
}

/// Verify a grant prelude's proof-of-possession signature against the grant's
/// holder key. Fail closed on any malformed input.
pub fn verify_prelude_pop(
    holder_key: &[u8; 32],
    signature_b64: &str,
    prelude: &V6RequestPrelude,
) -> Result<()> {
    if signature_b64.len() > POP_SIGNATURE_B64_LEN + 16 {
        bail!("grant proof-of-possession signature is oversized");
    }
    let decoded = B64
        .decode(signature_b64)
        .context("decode grant proof-of-possession signature")?;
    let signature_bytes: [u8; 64] = decoded.try_into().map_err(|_| {
        anyhow::anyhow!("grant proof-of-possession signature must decode to 64 bytes")
    })?;
    let verifying = VerifyingKey::from_bytes(holder_key).context("grant holder key is invalid")?;
    let message = prelude_pop_message(prelude)?;
    verifying
        .verify(&message, &Signature::from_bytes(&signature_bytes))
        .context("grant proof-of-possession verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v6::{root_request_hash, IPC_PROTOCOL_VERSION_V6};
    use ed25519_dalek::SigningKey;

    fn prelude(grant_id: Option<[u8; 16]>) -> V6RequestPrelude {
        V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [1_u8; 16],
            request_id: [2_u8; 16],
            operation_kind: "exec".into(),
            profile_id: None,
            profile_name: Some("prod".into()),
            grant_id,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 123_456,
            root_request_hash: root_request_hash(&crate::Frame::Status).unwrap(),
        }
    }

    #[test]
    fn signed_prelude_verifies_and_tampering_fails_closed() {
        let key = SigningKey::generate(&mut OsRng);
        let grant = OperationGrant::new(
            "prod".into(),
            [9_u8; 16],
            vec!["exec".into()],
            10,
            &key.verifying_key(),
            1_000,
        )
        .unwrap();
        let mut request = prelude(Some(grant.grant_id));
        let signature = sign_prelude_pop(&key, &request).unwrap();
        request.pop_signature = Some(signature.clone());
        assert!(request.validate().is_ok());
        verify_prelude_pop(&grant.holder_key, &signature, &request).unwrap();

        // Any prelude mutation invalidates the proof.
        let mut tampered = request.clone();
        tampered.operation_kind = "sftp.list-dir".into();
        assert!(verify_prelude_pop(&grant.holder_key, &signature, &tampered).is_err());

        // A different key cannot verify.
        let other = SigningKey::generate(&mut OsRng);
        let other_signature = sign_prelude_pop(&other, &request).unwrap();
        assert!(verify_prelude_pop(&grant.holder_key, &other_signature, &request).is_err());
    }

    #[test]
    fn grant_scope_and_expiry_are_checked() {
        let key = SigningKey::generate(&mut OsRng);
        let grant = OperationGrant::new(
            "prod".into(),
            [9_u8; 16],
            vec!["exec".into()],
            5,
            &key.verifying_key(),
            1_000,
        )
        .unwrap();
        let request = prelude(Some(grant.grant_id));
        assert!(grant.covers(&request));
        assert!(grant.covers_profile(&request));
        assert!(!grant.is_expired(1_000));
        assert!(!grant.is_expired(grant.expires_unix_ms - 1));
        assert!(grant.is_expired(grant.expires_unix_ms));

        let mut other_op = request.clone();
        other_op.operation_kind = "shell.open".into();
        assert!(!grant.covers(&other_op));

        let mut other_profile = request;
        other_profile.profile_name = Some("dev".into());
        assert!(!grant.covers_profile(&other_profile));
    }

    #[test]
    fn grant_issuance_rejects_invalid_scope() {
        let key = SigningKey::generate(&mut OsRng);
        assert!(OperationGrant::new(
            "prod".into(),
            [9_u8; 16],
            Vec::new(),
            5,
            &key.verifying_key(),
            1_000,
        )
        .is_err());
        assert!(OperationGrant::new(
            "prod".into(),
            [9_u8; 16],
            vec!["exec".into()],
            GRANT_BUDGET_CAP + 1,
            &key.verifying_key(),
            1_000,
        )
        .is_err());
    }

    #[test]
    fn pop_signature_and_grant_id_are_bound_in_the_prelude() {
        let mut without_grant = prelude(None);
        assert!(without_grant.validate().is_ok());
        without_grant.pop_signature = Some("AA".into());
        assert!(without_grant.validate().is_err());

        let mut with_grant = prelude(Some([7_u8; 16]));
        assert!(
            with_grant.validate().is_err(),
            "grant without PoP must fail"
        );
        with_grant.pop_signature = Some(B64.encode([0_u8; 64]));
        assert!(with_grant.validate().is_ok());
    }
}
