//! IPC v6: one fresh, mutually authenticated, AEAD-protected connection per
//! root operation against the per-user/per-vault global daemon.
//!
//! Design (§10 of the split design document):
//! - every business operation uses a NEW connection carrying exactly ONE root
//!   request; the root request is committed in the plaintext handshake prelude
//!   (SHA-256 of the exact serialized request bytes) and verified after the
//!   AEAD channel is established;
//! - both peers hold the daemon's per-boot activation secret; the handshake
//!   proves possession in both directions with transcript-bound HMACs, then
//!   HKDF-SHA256 derives independent client→daemon and daemon→client keys;
//! - every subsequent frame is ChaCha20-Poly1305 encrypted with a nonce built
//!   from the direction byte and a strictly increasing 64-bit counter; any
//!   duplicate, skipped, or tampered frame closes the connection;
//! - version or endpoint-identity mismatches fail closed.
//!
//! The activation secret identifies a FRONTEND within the current OS user's
//! permission domain; it is not a proof that the caller is an official binary
//! (documented limitation, §7.3 of the design).

use crate::Frame;
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::pin::Pin;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

/// Previous wire version. Retained only so tests can prove that a v8
/// descriptor or handshake fails closed after the grant-generation wire
/// break; it is never advertised as supported by current binaries.
pub const IPC_PROTOCOL_VERSION_V8: u16 = 8;
/// Current wire protocol version carried by the authenticated handshake.
/// Binding OperationGrant to the exact profile generation is intentionally a
/// wire break: mixed v8/v9 binaries fail closed instead of silently dropping
/// the generation and reviving stale authorization after profile rotation.
pub const IPC_PROTOCOL_VERSION_V9: u16 = 9;
/// Compatibility name for callers while the module is split into a dedicated
/// v9 source file. Its value is v9; no older transport is accepted.
pub const IPC_PROTOCOL_VERSION_V6: u16 = IPC_PROTOCOL_VERSION_V9;

/// Cap for the plaintext handshake frames.
pub const V6_MAX_AUTH_FRAME: usize = 4 * 1024;
/// Transport cap for one encrypted data frame. Tighter per-operation limits
/// stay the caller's responsibility, mirroring the v5 layering.
pub const V6_MAX_DATA_FRAME: usize = 64 * 1024 * 1024;
const V6_AEAD_TAG_BYTES: usize = 16;
const V6_MAX_PLAINTEXT_FRAME: usize = V6_MAX_DATA_FRAME - V6_AEAD_TAG_BYTES;
/// Cap for the operation-kind string in a request prelude.
pub const V6_MAX_OPERATION_KIND_BYTES: usize = 32;
/// Hard lifetime of one daemon-held decrypted profile credential lease.
pub const CREDENTIAL_LEASE_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

const SERVER_MAC_DOMAIN: &[u8] = b"serctl/ipc/v6/auth/server/v1\0";
const CLIENT_MAC_DOMAIN: &[u8] = b"serctl/ipc/v6/auth/client/v1\0";
const KEY_INFO_DOMAIN: &[u8] = b"serctl/ipc/v6/keys/v1\0";
const FRAME_AAD_DOMAIN: &[u8] = b"serctl/ipc/v6/frame/v1\0";

fn validate_plaintext_frame_len(len: usize) -> Result<()> {
    ensure!(
        len <= V6_MAX_PLAINTEXT_FRAME,
        "IPC v6 plaintext frame exceeds its size cap"
    );
    Ok(())
}

fn validate_ciphertext_frame_len(len: usize) -> Result<()> {
    ensure!(
        (V6_AEAD_TAG_BYTES..=V6_MAX_DATA_FRAME).contains(&len),
        "IPC v6 encrypted data frame length is invalid"
    );
    Ok(())
}
const PROFILE_PROOF_DOMAIN: &[u8] = b"serctl/ipc/v6/profile-proof/v1\0";

const DIRECTION_C2D: u8 = 0;
const DIRECTION_D2C: u8 = 1;

fn sha256_bytes(data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut digest = Zeroizing::new([0_u8; 32]);
    digest.copy_from_slice(&Sha256::digest(data));
    digest
}

/// SHA-256 of the exact serialized bytes of a root request frame, for binding
/// into a request prelude. The hash covers the same `serde_json::to_vec`
/// serialization the v6 session and the stream adapter actually transfer.
pub fn root_request_hash(frame: &Frame) -> Result<[u8; 32]> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(frame).context("serialize root request for prelude binding")?,
    );
    Ok(*sha256_bytes(&bytes))
}

/// Random per-boot identity of one daemon instance. Grants, endpoints, and
/// runtime descriptors all bind to it so a restarted daemon rejects every
/// capability issued by its predecessor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceId(pub [u8; 16]);

impl InstanceId {
    pub fn random() -> Self {
        let mut bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(encoded: &str) -> Result<Self> {
        let bytes = hex::decode(encoded).context("instance id must be hex")?;
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("instance id must decode to 16 bytes"))?;
        Ok(Self(bytes))
    }
}

/// The per-boot activation secret shared by the daemon and every frontend in
/// the current user's permission domain. Held only in zeroizing storage.
#[derive(Clone)]
pub struct ActivationSecret(Zeroizing<[u8; 32]>);

impl ActivationSecret {
    pub fn random() -> Self {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(&mut *bytes);
        Self(bytes)
    }

    /// Decode the canonical padded Base64 form persisted in the protected
    /// runtime secret file.
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = Zeroizing::new(
            B64.decode(encoded)
                .context("decode daemon activation secret")?,
        );
        if decoded.len() != 32 {
            bail!("daemon activation secret must decode to 32 bytes");
        }
        let mut bytes = Zeroizing::new([0_u8; 32]);
        bytes.copy_from_slice(&decoded);
        Ok(Self(bytes))
    }

    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(B64.encode(self.0.as_ref()))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Operation kind declared in the handshake prelude. The daemon cross-checks
/// this against the actual root frame so a prelude can never authorize a
/// different operation than the one that follows it.
pub fn frame_kind(frame: &Frame) -> &'static str {
    match frame {
        Frame::AuthHello { .. }
        | Frame::AuthResponse { .. }
        | Frame::AuthChallenge { .. }
        | Frame::AuthAccepted => "auth",
        Frame::Exec { .. } => "ssh.exec",
        Frame::ConnectionIdentity { .. } => "ssh.connection-identity",
        Frame::Shell { .. } | Frame::ShellInput { .. } => "ssh.pty",
        Frame::Status => "daemon.status",
        Frame::Shutdown { .. } => "daemon.shutdown",
        Frame::Unlock { .. } => "daemon.unlock",
        Frame::ListProfiles => "daemon.list-profiles",
        Frame::IssueGrant { .. } => "daemon.issue-grant",
        Frame::ListDir { .. } => "sftp.list",
        Frame::CreateDir { .. } => "sftp.write",
        Frame::Download { .. } => "transfer.read",
        Frame::UploadBegin { .. } | Frame::UploadChunk { .. } | Frame::UploadEnd => {
            "transfer.write"
        }
        Frame::TransferStatus { .. } => "transfer.status",
        Frame::TransferCancel { .. } => "transfer.cancel",
        Frame::TunnelOpen { .. } | Frame::TunnelStop => "forward",
        Frame::ManagedTunnelOpen { spec, .. } => match spec.mode() {
            crate::TunnelMode::Local => "forward.local/open",
            crate::TunnelMode::Remote => "forward.remote/open",
            crate::TunnelMode::Dynamic => "forward.dynamic/open",
        },
        Frame::ManagedTunnelStatus { .. } => "forward.status",
        Frame::ManagedTunnelCancel { .. } => "forward.cancel",
        Frame::ExecOut { .. }
        | Frame::ExecErr { .. }
        | Frame::ExecExit { .. }
        | Frame::ShellOut { .. }
        | Frame::ShellClosed
        | Frame::ProfileList { .. }
        | Frame::GrantIssued { .. }
        | Frame::ProfileAuthorized { .. }
        | Frame::StatusInfo { .. }
        | Frame::Ack
        | Frame::CreateDirAccepted { .. }
        | Frame::TransferAck { .. }
        | Frame::DirList { .. }
        | Frame::FileChunk { .. }
        | Frame::TransferDone { .. }
        | Frame::TransferDigest { .. }
        | Frame::TransferProgress { .. }
        | Frame::TransferStatusInfo { .. }
        | Frame::TransferCancelAccepted { .. }
        | Frame::TunnelReady { .. }
        | Frame::TunnelClosed
        | Frame::ManagedTunnelOpened { .. }
        | Frame::ManagedTunnelStatusInfo { .. }
        | Frame::ManagedTunnelTerminal { .. }
        | Frame::ConnectionIdentityInfo { .. }
        | Frame::Error { .. } => "stream",
    }
}

/// A plaintext, bounded declaration of exactly one root request, committed
/// during the handshake. `root_request_hash` is SHA-256 of the exact
/// serialized bytes of the root `Frame` the client will send first.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V6RequestPrelude {
    pub protocol_version: u16,
    pub client_session_id: [u8; 16],
    pub request_id: [u8; 16],
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<[u8; 16]>,
    /// Base64 Ed25519 proof of possession by the grant holder over this exact
    /// prelude; required exactly when `grant_id` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pop_signature: Option<String>,
    /// HMAC-SHA256 proof under the profile's domain-separated call key.
    /// Required exactly for ordinary profile-id requests and forbidden for
    /// grant-bound requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_proof: Option<String>,
    /// The client's requested absolute deadline, advisory for the daemon:
    /// enforcement always uses the daemon's own monotonic clock.
    pub requested_deadline_unix_ms: u64,
    pub root_request_hash: [u8; 32],
}

impl V6RequestPrelude {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == IPC_PROTOCOL_VERSION_V6,
            "unsupported IPC v9 prelude version {}",
            self.protocol_version
        );
        ensure!(
            !self.operation_kind.is_empty()
                && self.operation_kind.len() <= V6_MAX_OPERATION_KIND_BYTES
                && self.operation_kind.bytes().all(|b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || matches!(b, b'.' | b'-' | b'_' | b'/')
                }),
            "operation kind must be 1..={V6_MAX_OPERATION_KIND_BYTES} bytes of [a-z0-9._/-]"
        );
        if self.profile_id.is_some() && self.grant_id.is_some() {
            bail!("prelude must name at most one of profile_id and grant_id");
        }
        ensure!(
            self.grant_id.is_some() == self.pop_signature.is_some(),
            "a grant prelude must carry a proof-of-possession signature, and only a grant prelude may"
        );
        ensure!(
            self.profile_id.is_some() == self.profile_proof.is_some(),
            "a profile-id prelude must carry a profile call proof, and only a profile-id prelude may"
        );
        if let Some(name) = &self.profile_name {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && !name
                        .chars()
                        .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':')),
                "prelude profile name must satisfy the vault profile-name rules"
            );
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            serde_json::to_vec(self).context("serialize v6 request prelude")?,
        ))
    }

    fn digest(&self) -> Result<Zeroizing<[u8; 32]>> {
        let bytes = self.canonical_bytes()?;
        Ok(sha256_bytes(&bytes))
    }
}

#[derive(Serialize)]
struct ProfileProofPayload<'a> {
    protocol_version: u16,
    client_session_id: &'a [u8; 16],
    request_id: &'a [u8; 16],
    operation_kind: &'a str,
    profile_id: Option<[u8; 16]>,
    profile_name: Option<&'a str>,
    grant_id: Option<[u8; 16]>,
    requested_deadline_unix_ms: u64,
    root_request_hash: &'a [u8; 32],
}

fn profile_proof_message(prelude: &V6RequestPrelude) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        prelude.profile_id.is_some(),
        "profile proof requires a profile id"
    );
    ensure!(
        prelude.grant_id.is_none(),
        "grant requests cannot carry a profile proof"
    );
    let payload = ProfileProofPayload {
        protocol_version: prelude.protocol_version,
        client_session_id: &prelude.client_session_id,
        request_id: &prelude.request_id,
        operation_kind: &prelude.operation_kind,
        profile_id: prelude.profile_id,
        profile_name: prelude.profile_name.as_deref(),
        grant_id: prelude.grant_id,
        requested_deadline_unix_ms: prelude.requested_deadline_unix_ms,
        root_request_hash: &prelude.root_request_hash,
    };
    let encoded = Zeroizing::new(
        serde_json::to_vec(&payload).context("serialize profile call-proof payload")?,
    );
    let mut message = Zeroizing::new(Vec::with_capacity(
        PROFILE_PROOF_DOMAIN.len() + encoded.len(),
    ));
    message.extend_from_slice(PROFILE_PROOF_DOMAIN);
    message.extend_from_slice(&encoded);
    Ok(message)
}

/// Produce a request-specific proof under a profile call key. The key is
/// derived from that profile's authenticated key package and cannot decrypt
/// either the vault or SSH credentials.
pub fn profile_prelude_proof(call_key: &[u8; 32], prelude: &V6RequestPrelude) -> Result<String> {
    let message = profile_proof_message(prelude)?;
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(call_key)
        .map_err(|_| anyhow::anyhow!("invalid profile call key"))?;
    mac.update(&message);
    Ok(B64.encode(mac.finalize().into_bytes()))
}

/// Verify an ordinary v6 request's profile-bound authorization proof.
pub fn verify_profile_prelude_proof(
    call_key: &[u8; 32],
    encoded: &str,
    prelude: &V6RequestPrelude,
) -> Result<()> {
    if encoded.len() > 64 {
        bail!("profile call proof is oversized");
    }
    let provided = Zeroizing::new(B64.decode(encoded).context("decode profile call proof")?);
    if provided.len() != 32 {
        bail!("profile call proof must decode to 32 bytes");
    }
    let expected = Zeroizing::new(B64.decode(profile_prelude_proof(call_key, prelude)?)?);
    if !bool::from(expected.as_slice().ct_eq(provided.as_slice())) {
        bail!("profile call proof verification failed");
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "t", content = "d", deny_unknown_fields)]
enum V6AuthFrame {
    Hello {
        version: u16,
        instance_id: [u8; 16],
        client_nonce: [u8; 32],
        prelude: V6RequestPrelude,
    },
    Challenge {
        version: u16,
        server_nonce: [u8; 32],
        server_mac: String,
    },
    Response {
        client_mac: String,
    },
}

fn transcript_input(
    version: u16,
    instance_id: &[u8; 16],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    prelude_digest: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(2 + 16 + 64 + 32));
    input.extend_from_slice(&version.to_be_bytes());
    input.extend_from_slice(instance_id);
    input.extend_from_slice(client_nonce);
    input.extend_from_slice(server_nonce);
    input.extend_from_slice(prelude_digest);
    input
}

/// Direction key pair derived by HKDF from the activation secret and the
/// handshake transcript.
type V6KeyPair = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

fn role_mac(
    secret: &ActivationSecret,
    domain: &[u8],
    version: u16,
    instance_id: &[u8; 16],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    prelude_digest: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid IPC v6 activation secret"))?;
    mac.update(domain);
    mac.update(&transcript_input(
        version,
        instance_id,
        client_nonce,
        server_nonce,
        prelude_digest,
    ));
    let mut result = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0_u8; 32]);
    out.copy_from_slice(&result);
    zeroize::Zeroize::zeroize(result.as_mut_slice());
    Ok(out)
}

#[expect(
    clippy::too_many_arguments,
    reason = "keeping every authenticated transcript field explicit prevents accidental omission"
)]
fn verify_role_mac(
    secret: &ActivationSecret,
    domain: &[u8],
    version: u16,
    instance_id: &[u8; 16],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    prelude_digest: &[u8; 32],
    encoded: &str,
) -> Result<()> {
    let provided = Zeroizing::new(B64.decode(encoded).context("decode IPC v6 handshake MAC")?);
    if provided.len() != 32 {
        bail!("IPC v6 handshake MAC must decode to 32 bytes");
    }
    let expected = role_mac(
        secret,
        domain,
        version,
        instance_id,
        client_nonce,
        server_nonce,
        prelude_digest,
    )?;
    if !bool::from(expected.as_ref().ct_eq(provided.as_slice())) {
        bail!("IPC v6 handshake MAC mismatch");
    }
    Ok(())
}

/// Direction-tagged 96-bit nonce built from a strict 64-bit counter.
fn frame_nonce(direction: u8, counter: u64) -> Nonce {
    let mut raw = [0_u8; 12];
    raw[0] = direction;
    raw[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(raw)
}

/// AAD binding every ciphertext to its version, instance, direction, and wire
/// length, so a frame cannot be transplanted across sessions or directions.
fn frame_aad(version: u16, instance_id: &[u8; 16], direction: u8, ciphertext_len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FRAME_AAD_DOMAIN.len() + 2 + 16 + 1 + 4);
    aad.extend_from_slice(FRAME_AAD_DOMAIN);
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(instance_id);
    aad.push(direction);
    aad.extend_from_slice(&ciphertext_len.to_be_bytes());
    aad
}

struct DirectionCipher {
    cipher: ChaCha20Poly1305,
    send_counter: u64,
}

struct SharedV6State {
    version: u16,
    instance_id: [u8; 16],
    c2d: DirectionCipher,
    d2c: DirectionCipher,
    c2d_recv_counter: u64,
    d2c_recv_counter: u64,
}

impl SharedV6State {
    fn encrypt_frame(&mut self, direction: u8, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        validate_plaintext_frame_len(plaintext.len())?;
        let cipher_state = match direction {
            DIRECTION_C2D => &mut self.c2d,
            DIRECTION_D2C => &mut self.d2c,
            other => bail!("unknown IPC v6 frame direction {other}"),
        };
        let counter = cipher_state.send_counter;
        let next_counter = cipher_state
            .send_counter
            .checked_add(1)
            .context("IPC v6 frame counter overflow")?;
        let nonce = frame_nonce(direction, counter);
        let ciphertext_len = u32::try_from(plaintext.len() + Tag::default().len())
            .context("IPC v6 frame exceeds the wire length limit")?;
        let aad = frame_aad(self.version, &self.instance_id, direction, ciphertext_len);
        let ciphertext = Zeroizing::new(
            cipher_state
                .cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("IPC v6 frame encryption failed"))?,
        );
        validate_ciphertext_frame_len(ciphertext.len())?;
        // A nonce/counter becomes consumed exactly when its complete
        // ciphertext has been produced. Any pre-encryption failure leaves the
        // state unchanged; the stream adapter then poisons the connection.
        cipher_state.send_counter = next_counter;
        Ok(ciphertext)
    }

    fn decrypt_frame(
        &mut self,
        direction: u8,
        ciphertext: &[u8],
        expected_counter: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        validate_ciphertext_frame_len(ciphertext.len())?;
        let cipher_state = match direction {
            DIRECTION_C2D => &self.c2d,
            DIRECTION_D2C => &self.d2c,
            other => bail!("unknown IPC v6 frame direction {other}"),
        };
        let ciphertext_len = u32::try_from(ciphertext.len())
            .context("IPC v6 frame exceeds the wire length limit")?;
        let nonce = frame_nonce(direction, expected_counter);
        let aad = frame_aad(self.version, &self.instance_id, direction, ciphertext_len);
        let plaintext = Zeroizing::new(
            cipher_state
                .cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("IPC v6 frame authentication failed"))?,
        );
        Ok(plaintext)
    }

    /// Verify the next receive counter for a direction is exactly the previous
    /// counter plus one; any duplicate or skipped frame closes the connection.
    fn expect_next_counter(&mut self, direction: u8) -> Result<u64> {
        let recv_counter = match direction {
            DIRECTION_C2D => &mut self.c2d_recv_counter,
            DIRECTION_D2C => &mut self.d2c_recv_counter,
            other => bail!("unknown IPC v6 frame direction {other}"),
        };
        let expected = *recv_counter;
        *recv_counter = recv_counter
            .checked_add(1)
            .context("IPC v6 receive counter overflow")?;
        Ok(expected)
    }
}

fn derive_keys(
    secret: &ActivationSecret,
    version: u16,
    instance_id: &[u8; 16],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    prelude_digest: &[u8; 32],
) -> Result<V6KeyPair> {
    let salt = sha256_bytes(&transcript_input(
        version,
        instance_id,
        client_nonce,
        server_nonce,
        prelude_digest,
    ));
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_ref()), secret.as_bytes());
    let mut okm = Zeroizing::new([0_u8; 64]);
    let mut info = Zeroizing::new(Vec::new());
    info.extend_from_slice(KEY_INFO_DOMAIN);
    info.extend_from_slice(&version.to_be_bytes());
    info.extend_from_slice(instance_id);
    info.extend_from_slice(&[DIRECTION_C2D]);
    hkdf.expand(info.as_ref(), &mut *okm)
        .map_err(|_| anyhow::anyhow!("IPC v6 key derivation failed"))?;
    let mut c2d = Zeroizing::new([0_u8; 32]);
    c2d.copy_from_slice(&okm[..32]);
    let direction_offset = KEY_INFO_DOMAIN.len() + 2 + 16;
    info[direction_offset] = DIRECTION_D2C;
    hkdf.expand(info.as_ref(), &mut *okm)
        .map_err(|_| anyhow::anyhow!("IPC v6 key derivation failed"))?;
    let mut d2c = Zeroizing::new([0_u8; 32]);
    d2c.copy_from_slice(&okm[..32]);
    Ok((c2d, d2c))
}

async fn write_handshake_frame<S>(
    stream: &mut S,
    frame: &V6AuthFrame,
    deadline: Instant,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let json =
        Zeroizing::new(serde_json::to_vec(frame).context("serialize IPC v6 handshake frame")?);
    ensure!(
        json.len() <= V6_MAX_AUTH_FRAME,
        "IPC v6 handshake frame exceeds its size cap"
    );
    let len = u32::try_from(json.len()).context("IPC v6 handshake frame length overflow")?;
    tokio::time::timeout_at(deadline, async {
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&json).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC v6 handshake timed out"))??;
    Ok(())
}

async fn read_handshake_frame<S>(stream: &mut S, deadline: Instant) -> Result<V6AuthFrame>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout_at(deadline, async {
        let mut lenbuf = [0_u8; 4];
        stream.read_exact(&mut lenbuf).await?;
        let len = u32::from_be_bytes(lenbuf) as usize;
        ensure!(
            len <= V6_MAX_AUTH_FRAME,
            "IPC v6 handshake frame exceeds its size cap"
        );
        let mut json = Zeroizing::new(vec![0_u8; len]);
        stream.read_exact(&mut json).await?;
        let frame: V6AuthFrame =
            serde_json::from_slice(&json).context("parse IPC v6 handshake frame")?;
        Ok::<_, anyhow::Error>(frame)
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC v6 handshake timed out"))?
}

/// Client half of an authenticated v6 channel. The first `send_frame` is the
/// root request bound to the handshake prelude; later sends carry stream data.
pub struct V6ClientSession<S> {
    stream: S,
    state: SharedV6State,
    root_request_hash: [u8; 32],
    root_sent: bool,
}

/// Server half of an authenticated v6 channel.
pub struct V6ServerSession<S> {
    stream: S,
    state: SharedV6State,
    prelude: V6RequestPrelude,
    root_received: bool,
}

// ── AsyncRead/AsyncWrite adapter over the AEAD channel ─────────────────────
//
// The v5-style frame handlers (daemon and client alike) operate over plain
// `AsyncRead + AsyncWrite` byte streams. This adapter makes a v6 session
// present exactly that surface: bytes written between flush() boundaries are
// encrypted as ONE AEAD frame, and reads decrypt one frame at a time into an
// internal plaintext buffer. The frame record boundaries stay invisible to
// the handler, so the entire per-operation code runs unchanged over v6, and
// the server additionally enforces the root-request commitment (hash + kind)
// on the first frame it decrypts.

/// Maximum plaintext of one adapted frame. The encrypted body (plaintext plus
/// the Poly1305 tag) must remain within `V6_MAX_DATA_FRAME` on both peers.
const V6_ADAPTER_MAX_FRAME: usize = V6_MAX_PLAINTEXT_FRAME;
/// Bound synchronous progress in one task poll. A transport that repeatedly
/// returns `Ready(partial)` is self-woken after this many advancing operations
/// so large frames cannot starve unrelated tasks.
const V6_ADAPTER_IO_BUDGET: usize = 64;

pub struct V6ClientIo<S> {
    session: V6ClientSession<S>,
    write_buf: Vec<u8>,
    send_header: Option<([u8; 4], usize)>,
    send_body: Option<(Vec<u8>, usize)>,
    recv_header: Option<([u8; 4], usize)>,
    recv_body: Option<(Vec<u8>, usize)>,
    read_buf: Vec<u8>,
    read_offset: usize,
    poisoned: bool,
}

pub struct V6ServerIo<S> {
    session: V6ServerSession<S>,
    write_buf: Vec<u8>,
    send_header: Option<([u8; 4], usize)>,
    send_body: Option<(Vec<u8>, usize)>,
    recv_header: Option<([u8; 4], usize)>,
    recv_body: Option<(Vec<u8>, usize)>,
    read_buf: Vec<u8>,
    read_offset: usize,
    poisoned: bool,
}

impl<S> V6ClientIo<S> {
    pub fn new(session: V6ClientSession<S>) -> Self {
        Self {
            session,
            write_buf: Vec::new(),
            send_header: None,
            send_body: None,
            recv_header: None,
            recv_body: None,
            read_buf: Vec::new(),
            read_offset: 0,
            poisoned: false,
        }
    }

    pub fn into_inner(self) -> V6ClientSession<S> {
        self.session
    }
}

impl<S> V6ServerIo<S> {
    pub fn new(session: V6ServerSession<S>) -> Self {
        Self {
            session,
            write_buf: Vec::new(),
            send_header: None,
            send_body: None,
            recv_header: None,
            recv_body: None,
            read_buf: Vec::new(),
            read_offset: 0,
            poisoned: false,
        }
    }
}

/// Drive an in-progress header/body write to completion without allocating.
fn poll_send_parts<S, P, W>(
    mut stream: Pin<&mut S>,
    cx: &mut std::task::Context<'_>,
    header: &mut Option<([u8; 4], usize)>,
    body: &mut Option<(Vec<u8>, usize)>,
    mut poll: P,
    mut write: W,
) -> std::task::Poll<std::io::Result<()>>
where
    S: AsyncWrite,
    P: FnMut(
        Pin<&mut S>,
        &mut std::task::Context<'_>,
        &[u8],
    ) -> std::task::Poll<std::io::Result<usize>>,
    W: FnMut(),
{
    let mut operations = 0_usize;
    loop {
        if operations >= V6_ADAPTER_IO_BUDGET && (header.is_some() || body.is_some()) {
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        if let Some((bytes, offset)) = header.as_mut() {
            match poll(stream.as_mut(), cx, &bytes[*offset..]) {
                std::task::Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "IPC v6 transport wrote zero bytes",
                        )));
                    }
                    operations += 1;
                    *offset += n;
                    if *offset < 4 {
                        continue;
                    }
                    *header = None;
                    write();
                    continue;
                }
                std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        if let Some((bytes, offset)) = body.as_mut() {
            match poll(stream.as_mut(), cx, &bytes[*offset..]) {
                std::task::Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "IPC v6 transport wrote zero bytes",
                        )));
                    }
                    operations += 1;
                    *offset += n;
                    if *offset < bytes.len() {
                        continue;
                    }
                    *body = None;
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        return std::task::Poll::Ready(Ok(()));
    }
}

macro_rules! impl_v6_io {
    ($io:ident, $session_ty:ident, $dir_send:expr, $dir_recv:expr) => {
        impl<S> $io<S>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            fn poisoned_error() -> std::io::Error {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "IPC v6 adapter is poisoned",
                )
            }

            fn zeroize_buffers(&mut self) {
                self.write_buf.zeroize();
                if let Some((body, _)) = self.send_body.as_mut() {
                    body.zeroize();
                }
                if let Some((body, _)) = self.recv_body.as_mut() {
                    body.zeroize();
                }
                self.read_buf.zeroize();
                self.send_header = None;
                self.send_body = None;
                self.recv_header = None;
                self.recv_body = None;
                self.read_offset = 0;
            }

            fn poison(&mut self, error: std::io::Error) -> std::io::Error {
                self.poisoned = true;
                self.zeroize_buffers();
                error
            }

            fn arm_send(&mut self) -> std::io::Result<()> {
                if self.send_header.is_some() || self.send_body.is_some() {
                    return Ok(());
                }
                if self.write_buf.is_empty() {
                    return Ok(());
                }
                let plaintext = Zeroizing::new(std::mem::take(&mut self.write_buf));
                if plaintext.len() > V6_ADAPTER_MAX_FRAME {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "IPC v6 adapted frame exceeds its size cap",
                    ));
                }
                // The v5-style frame writers prefix every frame with its
                // 4-byte length; the root commitment hashes the serialized
                // frame body only. Verify the prefix consistency and commit
                // against the body.
                let root_payload = if plaintext.len() >= 4 {
                    let declared = u32::from_be_bytes(plaintext[..4].try_into().unwrap()) as usize;
                    if declared + 4 != plaintext.len() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "IPC v6 adapted frame length prefix is inconsistent",
                        ));
                    }
                    &plaintext[4..]
                } else {
                    &plaintext[..]
                };
                if !self.session.root_ok_for_send(root_payload) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "IPC v6 root request does not match the handshake prelude",
                    ));
                }
                let ciphertext = self
                    .session
                    .state
                    .encrypt_frame($dir_send, &plaintext)
                    .map_err(std::io::Error::other)?;
                let len = u32::try_from(ciphertext.len())
                    .map_err(|_| std::io::Error::other("IPC v6 frame length overflow"))?;
                self.session.note_root_sent();
                self.send_header = Some((len.to_be_bytes(), 0));
                self.send_body = Some((ciphertext.to_vec(), 0));
                Ok(())
            }

            fn poll_write_io(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                if self.poisoned {
                    return std::task::Poll::Ready(Err(Self::poisoned_error()));
                }
                if self.send_header.is_some() || self.send_body.is_some() {
                    match self.as_mut().poll_flush_io(cx) {
                        std::task::Poll::Ready(Ok(())) => {}
                        std::task::Poll::Ready(Err(error)) => {
                            return std::task::Poll::Ready(Err(error))
                        }
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                    }
                }
                let Some(buffered) = self.write_buf.len().checked_add(buf.len()) else {
                    let error = std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "IPC v6 adapted frame exceeds its size cap",
                    );
                    return std::task::Poll::Ready(Err(self.poison(error)));
                };
                if buffered > V6_ADAPTER_MAX_FRAME {
                    let error = std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "IPC v6 adapted frame exceeds its size cap",
                    );
                    return std::task::Poll::Ready(Err(self.poison(error)));
                }
                self.write_buf.extend_from_slice(buf);
                std::task::Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush_io(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if self.poisoned {
                    return std::task::Poll::Ready(Err(Self::poisoned_error()));
                }
                if let Err(error) = self.arm_send() {
                    let error = self.poison(error);
                    return std::task::Poll::Ready(Err(error));
                }
                let this = self.get_mut();
                let stream = Pin::new(&mut this.session.stream);
                let result = poll_send_parts(
                    stream,
                    cx,
                    &mut this.send_header,
                    &mut this.send_body,
                    |stream, cx, bytes| stream.poll_write(cx, bytes),
                    || {},
                );
                match result {
                    std::task::Poll::Ready(Err(error)) => {
                        std::task::Poll::Ready(Err(this.poison(error)))
                    }
                    other => other,
                }
            }

            fn poll_shutdown_io(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                match self.as_mut().poll_flush_io(cx) {
                    std::task::Poll::Ready(Err(error)) => {
                        return std::task::Poll::Ready(Err(error))
                    }
                    std::task::Poll::Ready(Ok(())) => {}
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
                let this = self.get_mut();
                match Pin::new(&mut this.session.stream).poll_shutdown(cx) {
                    std::task::Poll::Ready(Err(error)) => {
                        std::task::Poll::Ready(Err(this.poison(error)))
                    }
                    other => other,
                }
            }

            fn poll_read_io(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let this = self.get_mut();
                if this.poisoned {
                    return std::task::Poll::Ready(Err(Self::poisoned_error()));
                }
                let mut operations = 0_usize;
                loop {
                    // Serve the remaining plaintext of the current frame first.
                    if this.read_offset < this.read_buf.len() {
                        let take = std::cmp::min(
                            buf.remaining(),
                            this.read_buf.len() - this.read_offset,
                        );
                        let end = this.read_offset + take;
                        buf.put_slice(&this.read_buf[this.read_offset..end]);
                        this.read_offset = end;
                        if this.read_offset >= this.read_buf.len() {
                            this.read_buf.zeroize();
                            this.read_offset = 0;
                        }
                        return std::task::Poll::Ready(Ok(()));
                    }
                    let mut stream = Pin::new(&mut this.session.stream);
                    loop {
                        if operations >= V6_ADAPTER_IO_BUDGET {
                            cx.waker().wake_by_ref();
                            return std::task::Poll::Pending;
                        }
                        if let Some((bytes, offset)) = this.recv_header.as_mut() {
                            let mut temp = tokio::io::ReadBuf::new(&mut bytes[*offset..]);
                            match stream.as_mut().poll_read(cx, &mut temp) {
                                std::task::Poll::Ready(Ok(())) => {
                                    let n = temp.filled().len();
                                    if n == 0 {
                                        if *offset == 0 {
                                            return std::task::Poll::Ready(Ok(())); // EOF between frames
                                        }
                                        let error = std::io::Error::new(
                                            std::io::ErrorKind::UnexpectedEof,
                                            "IPC v6 transport ended during a frame header",
                                        );
                                        return std::task::Poll::Ready(Err(this.poison(error)));
                                    }
                                    operations += 1;
                                    *offset += n;
                                    if *offset < 4 {
                                        continue;
                                    }
                                    let len = u32::from_be_bytes(*bytes) as usize;
                                    if let Err(error) = validate_ciphertext_frame_len(len) {
                                        let error = std::io::Error::new(
                                            std::io::ErrorKind::InvalidData,
                                            error,
                                        );
                                        return std::task::Poll::Ready(Err(this.poison(error)));
                                    }
                                    this.recv_header = None;
                                    this.recv_body = Some((vec![0_u8; len], 0));
                                    continue;
                                }
                                std::task::Poll::Ready(Err(error)) => {
                                    return std::task::Poll::Ready(Err(this.poison(error)))
                                }
                                std::task::Poll::Pending => return std::task::Poll::Pending,
                            }
                        }
                        if let Some((bytes, offset)) = this.recv_body.as_mut() {
                            let mut temp = tokio::io::ReadBuf::new(&mut bytes[*offset..]);
                            match stream.as_mut().poll_read(cx, &mut temp) {
                                std::task::Poll::Ready(Ok(())) => {
                                    let n = temp.filled().len();
                                    if n == 0 {
                                        let error = std::io::Error::new(
                                            std::io::ErrorKind::UnexpectedEof,
                                            "IPC v6 transport ended during a frame body",
                                        );
                                        return std::task::Poll::Ready(Err(this.poison(error)));
                                    }
                                    operations += 1;
                                    *offset += n;
                                    if *offset < bytes.len() {
                                        continue;
                                    }
                                    let (body, _) = this.recv_body.take().unwrap();
                                    let ciphertext = Zeroizing::new(body);
                                    let counter =
                                        match this.session.state.expect_next_counter($dir_recv) {
                                            Ok(counter) => counter,
                                            Err(error) => {
                                                let error = std::io::Error::other(error);
                                                return std::task::Poll::Ready(Err(
                                                    this.poison(error),
                                                ));
                                            }
                                        };
                                    let plaintext = match this.session.state.decrypt_frame(
                                        $dir_recv,
                                        &ciphertext,
                                        counter,
                                    ) {
                                        Ok(plaintext) => plaintext,
                                        Err(error) => {
                                            let error = std::io::Error::other(error);
                                            return std::task::Poll::Ready(Err(this.poison(error)));
                                        }
                                    };
                                    if !this.session.root_ok_for_recv(&plaintext[4.min(plaintext.len())..])
                                    {
                                        let error = std::io::Error::new(
                                            std::io::ErrorKind::InvalidData,
                                            "IPC v6 root request does not match the handshake prelude",
                                        );
                                        return std::task::Poll::Ready(Err(this.poison(error)));
                                    }
                                    this.read_buf = plaintext.to_vec();
                                    this.read_offset = 0;
                                    break;
                                }
                                std::task::Poll::Ready(Err(error)) => {
                                    return std::task::Poll::Ready(Err(this.poison(error)))
                                }
                                std::task::Poll::Pending => return std::task::Poll::Pending,
                            }
                        }
                        // Start reading the next frame header.
                        this.recv_header = Some(([0_u8; 4], 0));
                    }
                }
            }
        }

        impl<S> tokio::io::AsyncWrite for $io<S>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                self.poll_write_io(cx, buf)
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                self.poll_flush_io(cx)
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                self.poll_shutdown_io(cx)
            }
        }

        impl<S> tokio::io::AsyncRead for $io<S>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                self.poll_read_io(cx, buf)
            }
        }
    };
}

// Root-request bookkeeping hooks used by the adapter.
impl<S> V6ClientSession<S> {
    fn root_ok_for_send(&self, plaintext: &[u8]) -> bool {
        if self.root_sent {
            return true;
        }
        let digest = sha256_bytes(plaintext);
        bool::from(digest.as_ref().ct_eq(self.root_request_hash.as_ref()))
    }

    fn note_root_sent(&mut self) {
        self.root_sent = true;
    }

    fn root_ok_for_recv(&mut self, _plaintext: &[u8]) -> bool {
        true
    }
}

impl<S> V6ServerSession<S> {
    fn root_ok_for_send(&self, _plaintext: &[u8]) -> bool {
        true
    }

    fn note_root_sent(&mut self) {}

    fn root_ok_for_recv(&mut self, plaintext: &[u8]) -> bool {
        if self.root_received {
            return true;
        }
        let digest = sha256_bytes(plaintext);
        let hash_ok = bool::from(
            digest
                .as_ref()
                .ct_eq(self.prelude.root_request_hash.as_ref()),
        );
        let kind_ok = match serde_json::from_slice::<Frame>(plaintext) {
            Ok(frame) => frame_kind(&frame) == self.prelude.operation_kind,
            Err(_) => false,
        };
        let ok = hash_ok && kind_ok;
        if ok {
            self.root_received = true;
        }
        ok
    }
}

impl_v6_io!(V6ClientIo, V6ClientSession, DIRECTION_C2D, DIRECTION_D2C);
impl_v6_io!(V6ServerIo, V6ServerSession, DIRECTION_D2C, DIRECTION_C2D);

async fn write_data_frame<S>(
    stream: &mut S,
    state: &mut SharedV6State,
    direction: u8,
    bytes: &[u8],
    deadline: Instant,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let ciphertext = state.encrypt_frame(direction, bytes)?;
    let len = u32::try_from(ciphertext.len()).context("IPC v6 frame length overflow")?;
    tokio::time::timeout_at(deadline, async {
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&ciphertext).await?;
        stream.flush().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC v6 frame write timed out"))??;
    Ok(())
}

async fn read_data_frame<S>(
    stream: &mut S,
    state: &mut SharedV6State,
    direction: u8,
    deadline: Instant,
) -> Result<Option<Zeroizing<Vec<u8>>>>
where
    S: AsyncRead + Unpin,
{
    let len = tokio::time::timeout_at(deadline, async {
        let mut lenbuf = [0_u8; 4];
        if stream.read(&mut lenbuf[..1]).await? == 0 {
            return Ok::<_, anyhow::Error>(None);
        }
        stream.read_exact(&mut lenbuf[1..]).await?;
        Ok::<_, anyhow::Error>(Some(u32::from_be_bytes(lenbuf) as usize))
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC v6 frame read timed out"))??;
    let Some(len) = len else { return Ok(None) };
    validate_ciphertext_frame_len(len)?;
    let mut ciphertext = Zeroizing::new(vec![0_u8; len]);
    tokio::time::timeout_at(deadline, stream.read_exact(&mut ciphertext))
        .await
        .map_err(|_| anyhow::anyhow!("IPC v6 frame read timed out"))??;
    let counter = state.expect_next_counter(direction)?;
    state
        .decrypt_frame(direction, &ciphertext, counter)
        .map(Some)
}

impl<S> V6ClientSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Encrypt and send one frame. The first call MUST be the root request the
    /// prelude committed to; the prelude hash is asserted client-side so a
    /// programming error fails before bytes leave the machine.
    pub async fn send_frame(&mut self, frame: &Frame, deadline: Instant) -> Result<()> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(frame).context("serialize IPC v6 data frame")?);
        if !self.root_sent {
            let digest = sha256_bytes(&bytes);
            if !bool::from(digest.as_ref().ct_eq(self.root_request_hash.as_ref())) {
                bail!("IPC v6 root request does not match the handshake prelude");
            }
        }
        write_data_frame(
            &mut self.stream,
            &mut self.state,
            DIRECTION_C2D,
            &bytes,
            deadline,
        )
        .await?;
        self.root_sent = true;
        Ok(())
    }

    pub async fn recv_frame(&mut self, deadline: Instant) -> Result<Option<Frame>> {
        let bytes =
            match read_data_frame(&mut self.stream, &mut self.state, DIRECTION_D2C, deadline)
                .await?
            {
                None => return Ok(None),
                Some(bytes) => bytes,
            };
        Ok(Some(
            serde_json::from_slice(&bytes).context("parse IPC v6 data frame")?,
        ))
    }
}

impl<S> V6ServerSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Decrypt and return the root request frame, verifying it matches the
    /// prelude committed during the handshake. Fails closed on mismatch.
    pub async fn recv_root_request(&mut self, deadline: Instant) -> Result<Frame> {
        ensure!(!self.root_received, "IPC v6 root request already consumed");
        let bytes = read_data_frame(&mut self.stream, &mut self.state, DIRECTION_C2D, deadline)
            .await?
            .context("IPC v6 peer closed before sending the root request")?;
        let digest = sha256_bytes(&bytes);
        if !bool::from(
            digest
                .as_ref()
                .ct_eq(self.prelude.root_request_hash.as_ref()),
        ) {
            bail!("IPC v6 root request does not match the handshake prelude");
        }
        let frame: Frame = serde_json::from_slice(&bytes).context("parse IPC v6 root request")?;
        ensure!(
            frame_kind(&frame) == self.prelude.operation_kind,
            "IPC v6 root request kind does not match the prelude"
        );
        self.root_received = true;
        Ok(frame)
    }

    /// Decrypt and return one stream frame. The root request must already have
    /// been consumed.
    pub async fn recv_frame(&mut self, deadline: Instant) -> Result<Option<Frame>> {
        ensure!(
            self.root_received,
            "IPC v6 server must consume the root request before stream frames"
        );
        let bytes =
            match read_data_frame(&mut self.stream, &mut self.state, DIRECTION_C2D, deadline)
                .await?
            {
                None => return Ok(None),
                Some(bytes) => bytes,
            };
        Ok(Some(
            serde_json::from_slice(&bytes).context("parse IPC v6 data frame")?,
        ))
    }

    pub async fn send_frame(&mut self, frame: &Frame, deadline: Instant) -> Result<()> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(frame).context("serialize IPC v6 data frame")?);
        write_data_frame(
            &mut self.stream,
            &mut self.state,
            DIRECTION_D2C,
            &bytes,
            deadline,
        )
        .await
    }
}

/// Run the client side of the v6 handshake: verify the daemon's role MAC,
/// prove possession of the activation secret, and derive the direction keys.
/// Returns a session whose first `send_frame` is the prelude-bound root
/// request.
pub async fn v6_client_handshake<S>(
    mut stream: S,
    secret: &ActivationSecret,
    instance_id: InstanceId,
    prelude: V6RequestPrelude,
    deadline: Instant,
) -> Result<V6ClientSession<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    prelude.validate()?;
    let prelude_digest = prelude.digest()?;
    let mut client_nonce = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut *client_nonce);

    let hello = V6AuthFrame::Hello {
        version: IPC_PROTOCOL_VERSION_V6,
        instance_id: instance_id.0,
        client_nonce: *client_nonce,
        prelude: prelude.clone(),
    };
    write_handshake_frame(&mut stream, &hello, deadline).await?;

    let mut challenge = read_handshake_frame(&mut stream, deadline).await?;
    let (server_nonce, server_mac) = match &mut challenge {
        V6AuthFrame::Challenge {
            version: IPC_PROTOCOL_VERSION_V6,
            server_nonce,
            server_mac,
        } => (
            Zeroizing::new(*server_nonce),
            Zeroizing::new(std::mem::take(server_mac)),
        ),
        V6AuthFrame::Challenge { version, .. } => {
            bail!("unsupported IPC v6 challenge version {version}")
        }
        _ => bail!("unexpected IPC v6 server handshake frame"),
    };
    if bool::from(client_nonce.as_ref().ct_eq(server_nonce.as_ref())) {
        bail!("IPC v6 server reused the client nonce");
    }
    verify_role_mac(
        secret,
        SERVER_MAC_DOMAIN,
        IPC_PROTOCOL_VERSION_V6,
        &instance_id.0,
        &client_nonce,
        &server_nonce,
        &prelude_digest,
        &server_mac,
    )?;
    let client_mac = role_mac(
        secret,
        CLIENT_MAC_DOMAIN,
        IPC_PROTOCOL_VERSION_V6,
        &instance_id.0,
        &client_nonce,
        &server_nonce,
        &prelude_digest,
    )?;
    let response = V6AuthFrame::Response {
        client_mac: B64.encode(client_mac.as_ref()),
    };
    write_handshake_frame(&mut stream, &response, deadline).await?;

    let (c2d, d2c) = derive_keys(
        secret,
        IPC_PROTOCOL_VERSION_V6,
        &instance_id.0,
        &client_nonce,
        &server_nonce,
        &prelude_digest,
    )?;
    Ok(V6ClientSession {
        stream,
        state: SharedV6State {
            version: IPC_PROTOCOL_VERSION_V6,
            instance_id: instance_id.0,
            c2d: DirectionCipher {
                cipher: ChaCha20Poly1305::new(Key::from_slice(&*c2d)),
                send_counter: 0,
            },
            d2c: DirectionCipher {
                cipher: ChaCha20Poly1305::new(Key::from_slice(&*d2c)),
                send_counter: 0,
            },
            c2d_recv_counter: 0,
            d2c_recv_counter: 0,
        },
        root_request_hash: prelude.root_request_hash,
        root_sent: false,
    })
}

/// Run the server side of the v6 handshake over an accepted connection.
/// Returns the committed prelude and a session whose first receive must be
/// `recv_root_request`.
pub async fn v6_server_handshake<S>(
    mut stream: S,
    secret: &ActivationSecret,
    instance_id: InstanceId,
    deadline: Instant,
) -> Result<(V6ServerSession<S>, V6RequestPrelude)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hello = read_handshake_frame(&mut stream, deadline).await?;
    let (client_nonce, prelude) = match &mut hello {
        V6AuthFrame::Hello {
            version: IPC_PROTOCOL_VERSION_V6,
            instance_id: received,
            client_nonce,
            prelude,
        } => {
            if received != &instance_id.0 {
                bail!("IPC v6 hello names a different daemon instance");
            }
            (Zeroizing::new(*client_nonce), prelude.clone())
        }
        V6AuthFrame::Hello { version, .. } => {
            bail!("unsupported IPC v6 hello version {version}")
        }
        _ => bail!("unexpected IPC v6 client handshake frame"),
    };
    prelude.validate()?;
    let prelude_digest = prelude.digest()?;
    let mut server_nonce = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut *server_nonce);
    while bool::from(client_nonce.as_ref().ct_eq(server_nonce.as_ref())) {
        OsRng.fill_bytes(&mut *server_nonce);
    }
    let server_mac = role_mac(
        secret,
        SERVER_MAC_DOMAIN,
        IPC_PROTOCOL_VERSION_V6,
        &instance_id.0,
        &client_nonce,
        &server_nonce,
        &prelude_digest,
    )?;
    let challenge = V6AuthFrame::Challenge {
        version: IPC_PROTOCOL_VERSION_V6,
        server_nonce: *server_nonce,
        server_mac: B64.encode(server_mac.as_ref()),
    };
    write_handshake_frame(&mut stream, &challenge, deadline).await?;

    let mut response = read_handshake_frame(&mut stream, deadline).await?;
    let client_mac = match &mut response {
        V6AuthFrame::Response { client_mac } => Zeroizing::new(std::mem::take(client_mac)),
        _ => bail!("unexpected IPC v6 client response frame"),
    };
    verify_role_mac(
        secret,
        CLIENT_MAC_DOMAIN,
        IPC_PROTOCOL_VERSION_V6,
        &instance_id.0,
        &client_nonce,
        &server_nonce,
        &prelude_digest,
        &client_mac,
    )?;

    let (c2d, d2c) = derive_keys(
        secret,
        IPC_PROTOCOL_VERSION_V6,
        &instance_id.0,
        &client_nonce,
        &server_nonce,
        &prelude_digest,
    )?;
    Ok((
        V6ServerSession {
            stream,
            state: SharedV6State {
                version: IPC_PROTOCOL_VERSION_V6,
                instance_id: instance_id.0,
                c2d: DirectionCipher {
                    cipher: ChaCha20Poly1305::new(Key::from_slice(&*c2d)),
                    send_counter: 0,
                },
                d2c: DirectionCipher {
                    cipher: ChaCha20Poly1305::new(Key::from_slice(&*d2c)),
                    send_counter: 0,
                },
                c2d_recv_counter: 0,
                d2c_recv_counter: 0,
            },
            prelude: prelude.clone(),
            root_received: false,
        },
        prelude,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    struct OneByteIo<S> {
        inner: S,
    }

    impl<S> OneByteIo<S> {
        fn new(inner: S) -> Self {
            Self { inner }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for OneByteIo<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if output.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut byte = [0_u8; 1];
            let mut limited = ReadBuf::new(&mut byte);
            match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
                Poll::Ready(Ok(())) => {
                    output.put_slice(limited.filled());
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for OneByteIo<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            let take = input.len().min(1);
            Pin::new(&mut self.inner).poll_write(cx, &input[..take])
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn prelude() -> V6RequestPrelude {
        let mut prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [1_u8; 16],
            request_id: [2_u8; 16],
            operation_kind: "ssh.exec".into(),
            profile_id: Some([3_u8; 16]),
            profile_name: None,
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: [0_u8; 32],
        };
        prelude.profile_proof = Some(profile_prelude_proof(&[7_u8; 32], &prelude).unwrap());
        prelude
    }

    fn exec_frame() -> Frame {
        Frame::Exec {
            cmd: "printf v6".into(),
            timeout_ms: 7_000,
        }
    }

    fn prelude_for(frame: &Frame) -> V6RequestPrelude {
        let bytes = serde_json::to_vec(frame).unwrap();
        let mut prelude = prelude();
        prelude.root_request_hash = *sha256_bytes(&bytes);
        prelude.profile_proof = None;
        prelude.profile_proof = Some(profile_prelude_proof(&[7_u8; 32], &prelude).unwrap());
        prelude
    }

    #[test]
    fn profile_call_proof_binds_the_complete_ordinary_prelude() {
        let key = [7_u8; 32];
        let request = exec_frame();
        let mut authorized = prelude_for(&request);
        let proof = authorized.profile_proof.clone().unwrap();
        verify_profile_prelude_proof(&key, &proof, &authorized).unwrap();
        authorized.request_id[0] ^= 1;
        assert!(verify_profile_prelude_proof(&key, &proof, &authorized).is_err());

        let mut missing = prelude_for(&request);
        missing.profile_proof = None;
        assert!(missing.validate().is_err());
    }

    #[tokio::test]
    async fn v6_handshake_and_root_request_round_trip() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let secret = ActivationSecret::random();
        let instance = InstanceId::random();
        let request = exec_frame();
        let prelude = prelude_for(&request);
        let d = deadline();
        let (client_result, server_result) = tokio::join!(
            v6_client_handshake(client, &secret, instance, prelude.clone(), d),
            v6_server_handshake(server, &secret, instance, d),
        );
        let mut client_session = client_result.unwrap();
        let (mut server_session, received_prelude) = server_result.unwrap();
        assert_eq!(
            received_prelude.root_request_hash,
            prelude.root_request_hash
        );

        let (send_result, recv_result) = tokio::join!(
            client_session.send_frame(&request, d),
            server_session.recv_root_request(d),
        );
        send_result.unwrap();
        assert!(matches!(recv_result.unwrap(), Frame::Exec { .. }));

        // Server → client stream frame round trip.
        let stream_frame = Frame::ExecOut {
            data: vec![0x5a; 4096],
        };
        let (send_result, recv_result) = tokio::join!(
            server_session.send_frame(&stream_frame, d),
            client_session.recv_frame(d),
        );
        send_result.unwrap();
        assert!(matches!(recv_result.unwrap(), Some(Frame::ExecOut { .. })));
    }

    #[tokio::test]
    async fn wrong_activation_secret_fails_both_directions() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let instance = InstanceId::random();
        let request = exec_frame();
        let prelude = prelude_for(&request);
        let d = deadline();
        let client_secret = ActivationSecret::random();
        let server_secret = ActivationSecret::random();
        let (client_result, server_result) = tokio::join!(
            v6_client_handshake(client, &client_secret, instance, prelude, d),
            v6_server_handshake(server, &server_secret, instance, d),
        );
        assert!(client_result.is_err());
        assert!(server_result.is_err());
    }

    #[tokio::test]
    async fn role_reflection_fails_against_a_fake_server() {
        // A fake server that echoes the client's hello back must fail the
        // client's server-MAC verification (or the unexpected-frame check).
        let (mut client, mut fake) = tokio::io::duplex(64 * 1024);
        let secret = ActivationSecret::random();
        let instance = InstanceId::random();
        let request = exec_frame();
        let prelude = prelude_for(&request);
        let d = deadline();

        let client_task =
            async { v6_client_handshake(&mut client, &secret, instance, prelude, d).await };
        let fake_task = async {
            let echoed = read_handshake_frame(&mut fake, d).await?;
            write_handshake_frame(&mut fake, &echoed, d).await?;
            Ok::<_, anyhow::Error>(())
        };
        let (client_result, fake_result) = tokio::join!(client_task, fake_task);
        fake_result.unwrap();
        assert!(client_result.is_err());
    }

    #[tokio::test]
    async fn instance_id_mismatch_fails_closed() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let secret = ActivationSecret::random();
        let request = exec_frame();
        let prelude = prelude_for(&request);
        let d = deadline();
        let (client_result, server_result) = tokio::join!(
            v6_client_handshake(client, &secret, InstanceId::random(), prelude, d),
            v6_server_handshake(server, &secret, InstanceId::random(), d),
        );
        assert!(server_result.is_err());
        assert!(client_result.is_err());
    }

    #[tokio::test]
    async fn root_request_mismatch_is_rejected_by_the_client() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let secret = ActivationSecret::random();
        let instance = InstanceId::random();
        let committed = exec_frame();
        let prelude = prelude_for(&committed);
        let different = Frame::Status;
        let d = deadline();
        let (client_result, server_result) = tokio::join!(
            v6_client_handshake(client, &secret, instance, prelude, d),
            v6_server_handshake(server, &secret, instance, d),
        );
        let mut client_session = client_result.unwrap();
        let (mut server_session, _) = server_result.unwrap();
        let (send_result, recv_result) = tokio::join!(
            client_session.send_frame(&different, d),
            server_session.recv_root_request(d),
        );
        // The client-side assertion fires first: the root no longer matches.
        assert!(send_result.is_err());
        assert!(recv_result.is_err());
    }

    #[tokio::test]
    async fn wrong_root_kind_against_matching_hash_is_rejected_by_the_server() {
        // The client asserts only the hash; the server additionally enforces
        // that the declared operation kind matches the actual frame kind.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let secret = ActivationSecret::random();
        let instance = InstanceId::random();
        let request = exec_frame();
        let mut prelude = prelude_for(&request);
        prelude.operation_kind = "daemon.status".into();
        let d = deadline();
        let (client_result, server_result) = tokio::join!(
            v6_client_handshake(client, &secret, instance, prelude, d),
            v6_server_handshake(server, &secret, instance, d),
        );
        let mut client_session = client_result.unwrap();
        let (mut server_session, _) = server_result.unwrap();
        let (send_result, recv_result) = tokio::join!(
            client_session.send_frame(&request, d),
            server_session.recv_root_request(d),
        );
        assert!(send_result.is_ok()); // hash matches, so the client sends it
        assert!(recv_result.is_err()); // kind mismatch fails closed
    }

    #[tokio::test]
    async fn tampered_frame_and_replayed_counter_fail_authentication() {
        // Direct state-level checks: tampering any ciphertext byte and reusing
        // a consumed counter both fail the AEAD.
        let secret = ActivationSecret::random();
        let instance = InstanceId::random();
        let nonce_a = Zeroizing::new([0_u8; 32]);
        let nonce_b = Zeroizing::new([1_u8; 32]);
        let mut prelude = prelude();
        prelude.root_request_hash = [0_u8; 32];
        let digest = prelude.digest().unwrap();
        let (c2d, d2c) = derive_keys(
            &secret,
            IPC_PROTOCOL_VERSION_V6,
            &instance.0,
            &nonce_a,
            &nonce_b,
            &digest,
        )
        .unwrap();
        let mut state = SharedV6State {
            version: IPC_PROTOCOL_VERSION_V6,
            instance_id: instance.0,
            c2d: DirectionCipher {
                cipher: ChaCha20Poly1305::new(Key::from_slice(&*c2d)),
                send_counter: 0,
            },
            d2c: DirectionCipher {
                cipher: ChaCha20Poly1305::new(Key::from_slice(&*d2c)),
                send_counter: 0,
            },
            c2d_recv_counter: 0,
            d2c_recv_counter: 0,
        };
        let ciphertext = state.encrypt_frame(DIRECTION_C2D, b"root request").unwrap();

        // Consume counter 0 normally.
        let counter = state.expect_next_counter(DIRECTION_C2D).unwrap();
        assert_eq!(counter, 0);
        assert!(state
            .decrypt_frame(DIRECTION_C2D, &ciphertext, counter)
            .is_ok());

        // A tampered copy at the NEXT counter fails.
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x80;
        let counter = state.expect_next_counter(DIRECTION_C2D).unwrap();
        assert!(state
            .decrypt_frame(DIRECTION_C2D, &tampered, counter)
            .is_err());

        // Replaying the ORIGINAL frame at a later counter fails too: the
        // nonce bound to counter 1 cannot decrypt a counter-0 ciphertext.
        let counter = state.expect_next_counter(DIRECTION_C2D).unwrap();
        assert!(state
            .decrypt_frame(DIRECTION_C2D, &ciphertext, counter)
            .is_err());
    }

    #[tokio::test]
    async fn every_pre_v9_and_future_version_fails_before_root_dispatch() {
        for version in (0..=IPC_PROTOCOL_VERSION_V8).chain([IPC_PROTOCOL_VERSION_V9 + 1, u16::MAX])
        {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let secret = ActivationSecret::random();
            let instance = InstanceId::random();
            let request = exec_frame();
            let mut prelude = prelude_for(&request);
            prelude.protocol_version = version;
            let dispatched = Arc::new(AtomicBool::new(false));
            let server_dispatched = Arc::clone(&dispatched);
            let d = deadline();
            let server = async {
                let result = v6_server_handshake(server, &secret, instance, d).await;
                if result.is_ok() {
                    server_dispatched.store(true, Ordering::Release);
                }
                result
            };
            let (client_result, server_result) = tokio::join!(
                v6_client_handshake(client, &secret, instance, prelude, d),
                server,
            );
            assert!(
                client_result.is_err(),
                "IPC v{version} client unexpectedly authenticated"
            );
            assert!(
                server_result.is_err(),
                "IPC v{version} server unexpectedly authenticated"
            );
            assert!(
                !dispatched.load(Ordering::Acquire),
                "IPC v{version} reached root dispatch"
            );
        }
    }

    #[tokio::test]
    async fn every_non_v9_handshake_envelope_fails_before_key_derivation_or_dispatch() {
        for version in (0..=IPC_PROTOCOL_VERSION_V8).chain([IPC_PROTOCOL_VERSION_V9 + 1, u16::MAX])
        {
            let (mut client, server) = tokio::io::duplex(64 * 1024);
            let secret = ActivationSecret::random();
            let instance = InstanceId::random();
            let hello = V6AuthFrame::Hello {
                version,
                instance_id: instance.0,
                client_nonce: [0x42; 32],
                prelude: prelude_for(&exec_frame()),
            };
            let encoded = serde_json::to_vec(&hello).unwrap();
            let dispatched = Arc::new(AtomicBool::new(false));
            let server_dispatched = Arc::clone(&dispatched);
            let d = deadline();
            let server = async {
                let result = v6_server_handshake(server, &secret, instance, d).await;
                if result.is_ok() {
                    server_dispatched.store(true, Ordering::Release);
                }
                result
            };
            let client = async {
                client
                    .write_all(&u32::try_from(encoded.len()).unwrap().to_be_bytes())
                    .await
                    .unwrap();
                client.write_all(&encoded).await.unwrap();
                client.flush().await.unwrap();
            };
            let ((), server_result) = tokio::join!(client, server);
            assert!(
                server_result.is_err(),
                "IPC v{version} handshake envelope unexpectedly authenticated"
            );
            assert!(
                !dispatched.load(Ordering::Acquire),
                "IPC v{version} handshake envelope reached root dispatch"
            );
        }
    }

    #[tokio::test]
    async fn malformed_handshake_versions_fail_before_root_dispatch() {
        for malformed in [
            serde_json::json!("9"),
            serde_json::json!(-1),
            serde_json::json!(65536),
            serde_json::Value::Null,
        ] {
            let (mut client, server) = tokio::io::duplex(64 * 1024);
            let secret = ActivationSecret::random();
            let instance = InstanceId::random();
            let request = exec_frame();
            let prelude = prelude_for(&request);
            let mut hello = serde_json::to_value(V6AuthFrame::Hello {
                version: IPC_PROTOCOL_VERSION_V9,
                instance_id: instance.0,
                client_nonce: [0x41; 32],
                prelude,
            })
            .unwrap();
            hello["d"]["version"] = malformed;
            let encoded = serde_json::to_vec(&hello).unwrap();
            let dispatched = Arc::new(AtomicBool::new(false));
            let server_dispatched = Arc::clone(&dispatched);
            let d = deadline();
            let server = async {
                let result = v6_server_handshake(server, &secret, instance, d).await;
                if result.is_ok() {
                    server_dispatched.store(true, Ordering::Release);
                }
                result
            };
            let client = async {
                client
                    .write_all(&u32::try_from(encoded.len()).unwrap().to_be_bytes())
                    .await
                    .unwrap();
                client.write_all(&encoded).await.unwrap();
                client.flush().await.unwrap();
            };
            let ((), server_result) = tokio::join!(client, server);
            assert!(server_result.is_err());
            assert!(!dispatched.load(Ordering::Acquire));
        }
    }

    #[tokio::test]
    async fn oversized_prelude_is_rejected() {
        let (client, _server) = tokio::io::duplex(64 * 1024);
        let secret = ActivationSecret::random();
        let instance = InstanceId::random();
        let mut prelude = prelude_for(&exec_frame());
        prelude.operation_kind = "x".repeat(V6_MAX_OPERATION_KIND_BYTES + 1);
        let d = deadline();
        let client_result = v6_client_handshake(client, &secret, instance, prelude, d).await;
        assert!(client_result.is_err());
    }

    #[test]
    fn activation_secret_round_trips_base64() {
        let secret = ActivationSecret::random();
        let encoded = secret.to_base64();
        let decoded = ActivationSecret::from_base64(&encoded).unwrap();
        assert_eq!(secret.as_bytes(), decoded.as_bytes());
        assert!(ActivationSecret::from_base64("not-base64!").is_err());
        assert!(ActivationSecret::from_base64(&B64.encode([0_u8; 16])).is_err());
    }

    #[test]
    fn instance_id_round_trips_hex() {
        let instance = InstanceId::random();
        assert_eq!(InstanceId::from_hex(&instance.as_hex()).unwrap(), instance);
        assert!(InstanceId::from_hex("xyz").is_err());
        assert!(InstanceId::from_hex("00").is_err());
    }

    #[test]
    fn encrypted_data_frame_cap_accounts_for_exact_aead_tag_overhead() {
        assert_eq!(
            V6_MAX_PLAINTEXT_FRAME + V6_AEAD_TAG_BYTES,
            V6_MAX_DATA_FRAME
        );
        assert!(validate_plaintext_frame_len(V6_MAX_PLAINTEXT_FRAME - 1).is_ok());
        assert!(validate_plaintext_frame_len(V6_MAX_PLAINTEXT_FRAME).is_ok());
        assert!(validate_plaintext_frame_len(V6_MAX_PLAINTEXT_FRAME + 1).is_err());
        assert!(validate_ciphertext_frame_len(V6_AEAD_TAG_BYTES - 1).is_err());
        assert!(validate_ciphertext_frame_len(V6_AEAD_TAG_BYTES).is_ok());
        assert!(validate_ciphertext_frame_len(V6_MAX_DATA_FRAME - 1).is_ok());
        assert!(validate_ciphertext_frame_len(V6_MAX_DATA_FRAME).is_ok());
        assert!(validate_ciphertext_frame_len(V6_MAX_DATA_FRAME + 1).is_err());
    }

    #[tokio::test]
    async fn adapter_presents_v5_style_frame_stream_over_the_aead_channel() {
        use crate::{
            read_frame_limited, write_frame_limited, MAX_CONTROL_FRAME, MAX_REQUEST_FRAME,
        };
        let (client, server) = tokio::io::duplex(64 * 1024);
        let secret = ActivationSecret::random();
        let instance = InstanceId::random();
        let request = exec_frame();
        let prelude = prelude_for(&request);
        let d = deadline();
        let (client_result, server_result) = tokio::join!(
            v6_client_handshake(client, &secret, instance, prelude, d),
            v6_server_handshake(server, &secret, instance, d),
        );
        let client_session = client_result.unwrap();
        let (server_session, _prelude) = server_result.unwrap();
        let client_io = V6ClientIo::new(client_session);
        let server_io = V6ServerIo::new(server_session);
        let (mut client_rd, mut client_wr) = tokio::io::split(client_io);
        let (mut server_rd, mut server_wr) = tokio::io::split(server_io);

        // Root request through the plain v5-style helpers.
        let send_result = write_frame_limited(&mut client_wr, &request, MAX_REQUEST_FRAME).await;
        send_result.unwrap();
        let recv_result = read_frame_limited(&mut server_rd, MAX_REQUEST_FRAME).await;
        assert!(matches!(recv_result.unwrap(), Some(Frame::Exec { .. })));

        // Server → client stream frame.
        let stream_frame = Frame::ExecOut {
            data: vec![0x5a; 4096],
        };
        let (send_result, recv_result) = tokio::join!(
            write_frame_limited(&mut server_wr, &stream_frame, MAX_CONTROL_FRAME),
            read_frame_limited(&mut client_rd, MAX_CONTROL_FRAME),
        );
        send_result.unwrap();
        assert!(matches!(recv_result.unwrap(), Some(Frame::ExecOut { .. })));

        // A mismatched root frame on a fresh connection must fail the
        // client-side commitment before leaving the adapter.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let prelude = prelude_for(&request);
        let (client_result, server_result) = tokio::join!(
            v6_client_handshake(client, &secret, instance, prelude, d),
            v6_server_handshake(server, &secret, instance, d),
        );
        let client_io = V6ClientIo::new(client_result.unwrap());
        let server_io = V6ServerIo::new(server_result.unwrap().0);
        let (_client_rd, mut client_wr) = tokio::io::split(client_io);
        let (mut server_rd, _server_wr) = tokio::io::split(server_io);
        let wrong = Frame::Status;
        // The client-side commitment rejects the mismatch before any bytes
        // leave the machine; the server then observes nothing (bounded read).
        let send_result = write_frame_limited(&mut client_wr, &wrong, MAX_REQUEST_FRAME).await;
        assert!(send_result.is_err());
        let recv_result = tokio::time::timeout(
            Duration::from_millis(200),
            read_frame_limited(&mut server_rd, MAX_REQUEST_FRAME),
        )
        .await;
        assert!(recv_result.is_err());
    }

    #[tokio::test]
    async fn adapter_short_io_preserves_flush_boundaries_and_frame_counters() {
        let (client, server) = tokio::io::duplex(8);
        let client = OneByteIo::new(client);
        let server = OneByteIo::new(server);
        let secret = ActivationSecret::random();
        let instance = InstanceId::random();
        let request = exec_frame();
        let prelude = prelude_for(&request);
        let d = Instant::now() + Duration::from_secs(30);
        let (client_result, server_result) = tokio::join!(
            v6_client_handshake(client, &secret, instance, prelude, d),
            v6_server_handshake(server, &secret, instance, d),
        );
        let client_io = V6ClientIo::new(client_result.unwrap());
        let server_io = V6ServerIo::new(server_result.unwrap().0);
        let (mut client_rd, mut client_wr) = tokio::io::split(client_io);
        let (mut server_rd, mut server_wr) = tokio::io::split(server_io);

        let (sent, received) = tokio::join!(
            crate::write_frame_limited(&mut client_wr, &request, crate::MAX_REQUEST_FRAME),
            crate::read_frame_limited(&mut server_rd, crate::MAX_REQUEST_FRAME),
        );
        sent.unwrap();
        assert!(matches!(received.unwrap(), Some(Frame::Exec { .. })));

        const OLD_THRESHOLD: usize = 64 * 1024;
        let plaintext_sizes = [
            5,
            32 * 1024,
            OLD_THRESHOLD - 1,
            OLD_THRESHOLD,
            OLD_THRESHOLD + 1,
        ];
        for (sequence, plaintext_len) in plaintext_sizes.into_iter().enumerate() {
            let body_len = plaintext_len - 4;
            let mut expected = vec![0_u8; plaintext_len];
            expected[..4].copy_from_slice(&(body_len as u32).to_be_bytes());
            for (index, byte) in expected[4..].iter_mut().enumerate() {
                *byte = ((index + sequence * 17) % 251) as u8;
            }
            let mut observed = vec![0_u8; plaintext_len];
            let (sent, received) = tokio::join!(
                async {
                    client_wr.write_all(&expected).await?;
                    client_wr.flush().await
                },
                server_rd.read_exact(&mut observed),
            );
            sent.unwrap();
            received.unwrap();
            assert_eq!(observed, expected, "plaintext size {plaintext_len}");
        }

        // Exercise the opposite direction after several client frames. If one
        // flush consumed more than one nonce/counter, this authentication fails.
        let reverse_len = OLD_THRESHOLD + 1;
        let reverse_body_len = reverse_len - 4;
        let mut reverse = vec![0x5a; reverse_len];
        reverse[..4].copy_from_slice(&(reverse_body_len as u32).to_be_bytes());
        let mut reverse_observed = vec![0_u8; reverse_len];
        let (sent, received) = tokio::join!(
            async {
                server_wr.write_all(&reverse).await?;
                server_wr.flush().await
            },
            client_rd.read_exact(&mut reverse_observed),
        );
        sent.unwrap();
        received.unwrap();
        assert_eq!(reverse_observed, reverse);

        client_wr.shutdown().await.unwrap();
        let mut eof = [0_u8; 1];
        assert_eq!(server_rd.read(&mut eof).await.unwrap(), 0);

        let client_io = client_rd.unsplit(client_wr);
        let server_io = server_rd.unsplit(server_wr);
        assert_eq!(client_io.session.state.c2d.send_counter, 6);
        assert_eq!(server_io.session.state.c2d_recv_counter, 6);
        assert_eq!(server_io.session.state.d2c.send_counter, 1);
        assert_eq!(client_io.session.state.d2c_recv_counter, 1);
    }

    #[tokio::test]
    async fn adapter_error_poisoning_is_permanent_and_clears_buffers() {
        let (client, server) = tokio::io::duplex(1024);
        let secret = ActivationSecret::random();
        let instance = InstanceId::random();
        let request = exec_frame();
        let prelude = prelude_for(&request);
        let d = deadline();
        let (client_result, server_result) = tokio::join!(
            v6_client_handshake(client, &secret, instance, prelude, d),
            v6_server_handshake(server, &secret, instance, d),
        );
        let mut client_io = V6ClientIo::new(client_result.unwrap());
        drop(server_result.unwrap());

        // Prefix declares two body bytes, but only one byte is buffered.
        client_io.write_all(&[0, 0, 0, 2, 0xa5]).await.unwrap();
        let first = client_io.flush().await.unwrap_err();
        assert_eq!(first.kind(), io::ErrorKind::InvalidData);
        assert!(client_io.poisoned);
        assert!(client_io.write_buf.is_empty());
        assert!(client_io.send_header.is_none());
        assert!(client_io.send_body.is_none());
        assert!(client_io.recv_header.is_none());
        assert!(client_io.recv_body.is_none());
        assert!(client_io.read_buf.is_empty());

        let retry = client_io.write_all(&[0, 0, 0, 0]).await.unwrap_err();
        assert_eq!(retry.kind(), io::ErrorKind::ConnectionAborted);
        assert!(client_io.flush().await.is_err());
        let mut byte = [0_u8; 1];
        assert!(client_io.read(&mut byte).await.is_err());
    }
}
