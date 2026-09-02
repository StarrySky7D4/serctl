//! Authenticated, profile-scoped local audit ledger.
//!
//! The ledger deliberately stores only bounded metadata and digests.  An
//! operation owner writes an `Intent` record before dispatch and an `Outcome`
//! record after obtaining a trustworthy terminal state.  Every record is
//! chained and the current head is authenticated with HMAC-SHA256.  A copied
//! checkpoint can be anchored outside this directory; presenting that anchor
//! during verification detects local rollback.
//!
//! A hash chain by itself is not tamper evidence because an attacker can
//! recompute it.  Callers must protect the checkpoint key separately and must
//! quarantine mutation operations whenever opening, appending, reconciling or
//! verifying this ledger fails.

use crate::security;
use crate::vault::{ProfileCallKey, ProfileIdentity};
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const AUDIT_SCHEMA_VERSION: u16 = 1;
pub const MAX_AUDIT_LOG_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_AUDIT_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_OPERATION_KIND_BYTES: usize = 64;
pub const MAX_REASON_CODE_BYTES: usize = 96;

const RECORD_DOMAIN: &[u8] = b"serctl/audit/record/v1\0";
const RECORD_MAC_DOMAIN: &[u8] = b"serctl/audit/record-mac/v1\0";
const CHECKPOINT_DOMAIN: &[u8] = b"serctl/audit/checkpoint/v1\0";
const AUDIT_KEY_DOMAIN: &[u8] = b"serctl/audit/profile-key/v1\0";
const RESOLVE_UNKNOWN_RESULT_DOMAIN: &[u8] = b"serctl/audit/resolve-unknown-result/v1\0";
const GENERATION_TRANSITION_DOMAIN: &[u8] = b"serctl/audit/generation-transition/v1\0";
const RESOLVE_UNKNOWN_REASON: &str = "administrative.resolve_unknown";
const ZERO_HASH: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    Intent,
    Outcome,
    Administrative,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Pending,
    Allowed,
    Denied,
    Succeeded,
    Failed,
    Unknown,
}

/// Bounded metadata for one audit event.  Paths, command text, output and
/// credentials never belong here; their canonical digests may be recorded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub profile_id: String,
    pub profile_generation: u64,
    pub request_id: [u8; 16],
    pub at_unix_ms: u64,
    pub operation_kind: String,
    pub phase: AuditPhase,
    pub decision: AuditDecision,
    pub policy_digest: String,
    pub intent_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    pub reason_code: String,
}

impl AuditEvent {
    pub fn validate(&self) -> Result<()> {
        validate_profile_id(&self.profile_id)?;
        ensure!(
            self.profile_generation > 0,
            "audit profile generation must be non-zero"
        );
        ensure!(self.at_unix_ms > 0, "audit timestamp must be non-zero");
        validate_token(
            &self.operation_kind,
            MAX_OPERATION_KIND_BYTES,
            "operation kind",
        )?;
        validate_token(&self.reason_code, MAX_REASON_CODE_BYTES, "reason code")?;
        validate_digest(&self.policy_digest, "policy digest")?;
        validate_digest(&self.intent_digest, "intent digest")?;
        if let Some(digest) = &self.result_digest {
            validate_digest(digest, "result digest")?;
        }
        match self.phase {
            AuditPhase::Intent => ensure!(
                self.decision == AuditDecision::Pending && self.result_digest.is_none(),
                "intent records must be pending and cannot carry a result digest"
            ),
            AuditPhase::Outcome => ensure!(
                !matches!(self.decision, AuditDecision::Pending) && self.result_digest.is_some(),
                "outcome records must be terminal and carry a result digest"
            ),
            AuditPhase::Administrative => ensure!(
                !matches!(self.decision, AuditDecision::Pending) && self.result_digest.is_some(),
                "administrative records must be terminal and carry a result digest"
            ),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditRecord {
    schema_version: u16,
    sequence: u64,
    previous_hash: String,
    event: AuditEvent,
    record_hash: String,
    record_mac: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpoint {
    pub schema_version: u16,
    pub profile_id: String,
    pub profile_generation: u64,
    pub sequence: u64,
    pub record_hash: String,
    pub mac: String,
}

/// Result of one explicitly authorized pending-Intent recovery. Existing
/// records are never edited: `resolved` terminal Unknown outcomes were
/// appended and `checkpoint` authenticates the new ledger head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingResolution {
    pub resolved: usize,
    pub checkpoint: AuditCheckpoint,
}

/// Authenticated, read-only ledger state. Pending Intents are reported only
/// after the complete chain, checkpoint and optional external anchor have
/// been verified; callers must not infer a terminal remote outcome from this
/// count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditInspection {
    pub pending_intents: usize,
    pub checkpoint: AuditCheckpoint,
}

impl AuditCheckpoint {
    fn unsigned(&self) -> UnsignedCheckpoint<'_> {
        UnsignedCheckpoint {
            schema_version: self.schema_version,
            profile_id: &self.profile_id,
            profile_generation: self.profile_generation,
            sequence: self.sequence,
            record_hash: &self.record_hash,
        }
    }
}

#[derive(Serialize)]
struct UnsignedCheckpoint<'a> {
    schema_version: u16,
    profile_id: &'a str,
    profile_generation: u64,
    sequence: u64,
    record_hash: &'a str,
}

#[derive(Debug)]
struct VerifiedLog {
    sequence: u64,
    record_hash: [u8; 32],
    hashes: Vec<[u8; 32]>,
    seen_intents: HashSet<[u8; 16]>,
    pending_intents: HashMap<[u8; 16], PendingIntentBinding>,
    first_event: Option<AuditEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingIntentBinding {
    operation_kind: String,
    policy_digest: String,
    intent_digest: String,
}

impl PendingIntentBinding {
    fn from_intent(event: &AuditEvent) -> Self {
        Self {
            operation_kind: event.operation_kind.clone(),
            policy_digest: event.policy_digest.clone(),
            intent_digest: event.intent_digest.clone(),
        }
    }

    fn ensure_matches_outcome(&self, event: &AuditEvent) -> Result<()> {
        ensure!(
            event.operation_kind == self.operation_kind,
            "audit Outcome operation kind does not match its Intent"
        );
        ensure!(
            event.policy_digest == self.policy_digest,
            "audit Outcome policy digest does not match its Intent"
        );
        ensure!(
            event.intent_digest == self.intent_digest,
            "audit Outcome intent digest does not match its Intent"
        );
        Ok(())
    }
}

/// One authenticated ledger.  The key is zeroized on drop.  `profile_id` and
/// `profile_generation` prevent a same-name replacement or credential rotation
/// from silently inheriting an older audit chain.
pub struct AuditLedger {
    log_path: PathBuf,
    checkpoint_path: PathBuf,
    profile_id: [u8; 16],
    profile_generation: u64,
    key: Zeroizing<[u8; 32]>,
}

impl AuditLedger {
    /// Derive a ledger-only key from the non-exportable profile call key. The
    /// explicit domain and profile identity prevent key reuse across protocol
    /// roles, profiles, or credential generations.
    pub fn from_profile_call_key(
        directory: &Path,
        identity: ProfileIdentity,
        call_key: &ProfileCallKey,
    ) -> Result<Self> {
        let mut derivation = <Hmac<Sha256> as Mac>::new_from_slice(call_key.audit_bytes())
            .map_err(|_| anyhow::anyhow!("invalid profile audit key input"))?;
        derivation.update(AUDIT_KEY_DOMAIN);
        derivation.update(&identity.profile_id);
        derivation.update(&identity.generation.to_be_bytes());
        let mut derived = derivation.finalize().into_bytes();
        let mut key = Zeroizing::new([0_u8; 32]);
        key.copy_from_slice(&derived);
        derived.as_mut_slice().zeroize();
        Self::with_protected_key(directory, identity.profile_id, identity.generation, key)
    }

    pub fn new(
        directory: &Path,
        profile_id: [u8; 16],
        profile_generation: u64,
        mut key: [u8; 32],
    ) -> Result<Self> {
        let protected = Zeroizing::new(key);
        key.zeroize();
        Self::with_protected_key(directory, profile_id, profile_generation, protected)
    }

    fn with_protected_key(
        directory: &Path,
        profile_id: [u8; 16],
        profile_generation: u64,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        ensure!(
            profile_generation > 0,
            "audit profile generation must be non-zero"
        );
        security::harden_directory(directory).context("harden audit ledger directory")?;
        let stem = format!("{}-g{profile_generation}", hex::encode(profile_id));
        Ok(Self {
            log_path: directory.join(format!("audit-{stem}.jsonl")),
            checkpoint_path: directory.join(format!("audit-{stem}.checkpoint.json")),
            profile_id,
            profile_generation,
            key,
        })
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn checkpoint_path(&self) -> &Path {
        &self.checkpoint_path
    }

    /// Inspect only whether either member of this generation's durable pair is
    /// present. Unsafe file types and inspection failures remain errors.
    pub fn has_any_material(&self) -> Result<bool> {
        let log = security::open_existing_protected_file(&self.log_path)
            .context("inspect existing authenticated audit log")?
            .is_some();
        let checkpoint = security::open_existing_protected_file(&self.checkpoint_path)
            .context("inspect existing authenticated audit checkpoint")?
            .is_some();
        Ok(log || checkpoint)
    }

    /// Verify and append one record, then durably replace the authenticated
    /// checkpoint.  A crash after the log sync but before checkpoint commit is
    /// recoverable by `reconcile`; a checkpoint ahead of or divergent from the
    /// log always fails closed.
    pub fn append(&self, event: &AuditEvent) -> Result<AuditCheckpoint> {
        event.validate()?;
        ensure!(
            event.profile_id == hex::encode(self.profile_id)
                && event.profile_generation == self.profile_generation,
            "audit event profile identity mismatch"
        );
        let mut file = security::open_existing_protected_file_for_update(&self.log_path)
            .context("open existing protected audit log")?
            .context("authenticated audit log is missing")?;
        file.lock_exclusive().context("lock protected audit log")?;
        let result = self.append_locked(&mut file, event);
        let unlock = FileExt::unlock(&file).context("unlock protected audit log");
        match (result, unlock) {
            (Ok(checkpoint), Ok(())) => Ok(checkpoint),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn append_locked(&self, file: &mut File, event: &AuditEvent) -> Result<AuditCheckpoint> {
        self.append_locked_with_checkpoint_mode(file, event, false)
    }

    fn append_locked_with_checkpoint_mode(
        &self,
        file: &mut File,
        event: &AuditEvent,
        create_new_checkpoint: bool,
    ) -> Result<AuditCheckpoint> {
        let verified = self.verify_log(file)?;
        if create_new_checkpoint {
            ensure!(
                verified.sequence == 0
                    && verified.first_event.is_none()
                    && verified.pending_intents.is_empty(),
                "new audit generation is not empty"
            );
            ensure!(
                self.read_checkpoint()?.is_none(),
                "new audit generation checkpoint already exists"
            );
        } else {
            self.verify_checkpoint_against_log(&verified, true)?;
        }
        match event.phase {
            AuditPhase::Intent => ensure!(
                !verified.seen_intents.contains(&event.request_id),
                "audit Intent request id was already used"
            ),
            AuditPhase::Outcome => verified
                .pending_intents
                .get(&event.request_id)
                .context("audit Outcome does not match a pending Intent")?
                .ensure_matches_outcome(event)?,
            AuditPhase::Administrative => {}
        }
        let sequence = verified
            .sequence
            .checked_add(1)
            .context("audit sequence overflow")?;
        let previous_hash = verified.record_hash;
        let record_hash = calculate_record_hash(sequence, &previous_hash, event)?;
        let record = AuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            sequence,
            previous_hash: hex::encode(previous_hash),
            event: event.clone(),
            record_hash: hex::encode(record_hash),
            record_mac: String::new(),
        };
        let mut record = record;
        record.record_mac = self.record_mac(&record)?;
        let mut encoded = serde_json::to_vec(&record).context("serialize audit record")?;
        ensure!(
            encoded.len() <= MAX_AUDIT_RECORD_BYTES,
            "audit record exceeds its size limit"
        );
        encoded.push(b'\n');
        let current_len = file.metadata().context("inspect audit log")?.len();
        ensure!(
            current_len.saturating_add(encoded.len() as u64) <= MAX_AUDIT_LOG_BYTES,
            "audit log reached its configured size limit"
        );
        file.seek(SeekFrom::End(0)).context("seek audit log end")?;
        file.write_all(&encoded).context("append audit record")?;
        file.sync_data().context("sync audit record")?;
        if create_new_checkpoint {
            security::sync_parent_directory(&self.log_path)
                .context("sync new authenticated audit log directory entry")?;
        }
        let checkpoint = self.make_checkpoint(sequence, record_hash)?;
        if create_new_checkpoint {
            self.persist_checkpoint_create_new(&checkpoint)?;
        } else {
            self.persist_checkpoint(&checkpoint)?;
        }
        Ok(checkpoint)
    }

    /// Verify the full chain and checkpoint.  When `anchor` is supplied, its
    /// authenticated head must occur in this log at the same sequence, which
    /// detects rollback to an older otherwise-valid local checkpoint.
    pub fn verify(&self, anchor: Option<&AuditCheckpoint>) -> Result<AuditCheckpoint> {
        self.verify_internal(anchor, false)
            .map(|inspection| inspection.checkpoint)
    }

    /// Verify the authenticated chain and additionally require every Intent
    /// to have a matching terminal Outcome. Daemon unlock uses this stricter
    /// form so a crash or failed Outcome write leaves a persistent quarantine
    /// signal across process restarts.
    pub fn verify_complete(&self, anchor: Option<&AuditCheckpoint>) -> Result<AuditCheckpoint> {
        self.verify_internal(anchor, true)
            .map(|inspection| inspection.checkpoint)
    }

    /// Inspect an authenticated ledger without requiring all Intents to be
    /// terminal. This is intended for explicit offline diagnosis before an
    /// administrator chooses whether to append Unknown outcomes.
    pub fn inspect(&self, anchor: Option<&AuditCheckpoint>) -> Result<AuditInspection> {
        self.verify_internal(anchor, false)
    }

    /// Initialize one generation with an authenticated administrative genesis
    /// or predecessor transition. This is the only API allowed to create an
    /// audit log. If a crash left the exact single MAC-authenticated record
    /// without its checkpoint, retry completes that pair; every other partial
    /// or pre-existing state fails closed.
    pub fn initialize_generation(
        &self,
        predecessor: Option<&AuditCheckpoint>,
        old_name: &str,
        new_name: &str,
        at_unix_ms: u64,
    ) -> Result<AuditCheckpoint> {
        ensure!(
            at_unix_ms > 0,
            "audit initialization timestamp must be non-zero"
        );
        validate_transition_name(old_name, "old profile name")?;
        validate_transition_name(new_name, "new profile name")?;
        let event =
            self.generation_transition_event(predecessor, old_name, new_name, at_unix_ms)?;

        let log_exists = security::open_existing_protected_file(&self.log_path)
            .context("inspect audit log before generation initialization")?
            .is_some();
        let checkpoint_exists = security::open_existing_protected_file(&self.checkpoint_path)
            .context("inspect audit checkpoint before generation initialization")?
            .is_some();
        match (log_exists, checkpoint_exists) {
            (false, false) => self.initialize_create_new(&event),
            (true, true) => self.verify_single_generation_event(&event),
            (true, false) => self.resume_generation_initialization(&event),
            (false, true) => {
                anyhow::bail!("audit generation checkpoint exists without its authenticated log")
            }
        }
    }

    /// Create a fresh ledger and its first authenticated record. General
    /// append/status paths never call this implicitly.
    pub fn initialize_create_new(&self, event: &AuditEvent) -> Result<AuditCheckpoint> {
        event.validate()?;
        ensure!(
            event.profile_id == hex::encode(self.profile_id)
                && event.profile_generation == self.profile_generation,
            "audit initialization event profile identity mismatch"
        );
        ensure!(
            security::open_existing_protected_file(&self.checkpoint_path)
                .context("inspect audit checkpoint before create-new initialization")?
                .is_none(),
            "audit checkpoint already exists"
        );
        let mut file = security::create_new_protected_file(&self.log_path)
            .context("create new protected audit log")?;
        file.lock_exclusive()
            .context("lock new protected audit log")?;
        let result = self.append_locked_with_checkpoint_mode(&mut file, event, true);
        let unlock = FileExt::unlock(&file).context("unlock new protected audit log");
        match (result, unlock) {
            (Ok(checkpoint), Ok(())) => Ok(checkpoint),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn resume_generation_initialization(&self, expected: &AuditEvent) -> Result<AuditCheckpoint> {
        let mut file = security::open_existing_protected_file_for_update(&self.log_path)
            .context("open incomplete generation audit log")?
            .context("incomplete generation audit log disappeared")?;
        file.lock_exclusive()
            .context("lock incomplete generation audit log")?;
        let result = (|| {
            let verified = self.verify_log(&mut file)?;
            if verified.sequence == 0 {
                ensure!(
                    verified.first_event.is_none() && verified.pending_intents.is_empty(),
                    "empty generation audit log has unexpected verification state"
                );
                return self.append_locked_with_checkpoint_mode(&mut file, expected, true);
            }
            ensure!(
                verified.sequence == 1 && verified.pending_intents.is_empty(),
                "incomplete generation audit log is not an exact single transition"
            );
            let actual = verified
                .first_event
                .as_ref()
                .context("incomplete generation audit log has no transition")?;
            ensure_generation_event_matches(actual, expected)?;
            let checkpoint = self.make_checkpoint(verified.sequence, verified.record_hash)?;
            self.persist_checkpoint_create_new(&checkpoint)?;
            Ok(checkpoint)
        })();
        let unlock = FileExt::unlock(&file).context("unlock incomplete generation audit log");
        match (result, unlock) {
            (Ok(checkpoint), Ok(())) => Ok(checkpoint),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn verify_single_generation_event(&self, expected: &AuditEvent) -> Result<AuditCheckpoint> {
        let mut file = security::open_existing_protected_file(&self.log_path)
            .context("open initialized generation audit log")?
            .context("initialized generation audit log is missing")?;
        file.lock_shared()
            .context("lock initialized generation audit log")?;
        let result = (|| {
            let verified = self.verify_log(&mut file)?;
            ensure!(
                verified.sequence == 1 && verified.pending_intents.is_empty(),
                "pre-existing generation audit ledger is not an exact transition"
            );
            let checkpoint = self.verify_checkpoint_against_log(&verified, false)?;
            let actual = verified
                .first_event
                .as_ref()
                .context("generation audit ledger has no transition")?;
            ensure_generation_event_matches(actual, expected)?;
            Ok(checkpoint)
        })();
        let unlock = FileExt::unlock(&file).context("unlock initialized generation audit log");
        match (result, unlock) {
            (Ok(checkpoint), Ok(())) => Ok(checkpoint),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn generation_transition_event(
        &self,
        predecessor: Option<&AuditCheckpoint>,
        old_name: &str,
        new_name: &str,
        at_unix_ms: u64,
    ) -> Result<AuditEvent> {
        let predecessor_bytes = match predecessor {
            Some(checkpoint) => {
                serde_json::to_vec(checkpoint).context("serialize predecessor audit checkpoint")?
            }
            None => Vec::new(),
        };
        let mut binding = Sha256::new();
        binding.update(GENERATION_TRANSITION_DOMAIN);
        binding.update((old_name.len() as u64).to_be_bytes());
        binding.update(old_name.as_bytes());
        binding.update((new_name.len() as u64).to_be_bytes());
        binding.update(new_name.as_bytes());
        binding.update((predecessor_bytes.len() as u64).to_be_bytes());
        binding.update(&predecessor_bytes);
        binding.update(self.profile_id);
        binding.update(self.profile_generation.to_be_bytes());
        let binding: [u8; 32] = binding.finalize().into();

        let mut policy = Sha256::new();
        policy.update(GENERATION_TRANSITION_DOMAIN);
        policy.update(b"policy");
        policy.update(self.profile_id);
        let policy_digest: [u8; 32] = policy.finalize().into();

        let mut result = Sha256::new();
        result.update(GENERATION_TRANSITION_DOMAIN);
        result.update(b"successor");
        result.update(self.profile_id);
        result.update(self.profile_generation.to_be_bytes());
        result.update(binding);
        let result_digest: [u8; 32] = result.finalize().into();

        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&binding[..16]);
        Ok(AuditEvent {
            profile_id: hex::encode(self.profile_id),
            profile_generation: self.profile_generation,
            request_id,
            at_unix_ms,
            operation_kind: "audit.generation".to_owned(),
            phase: AuditPhase::Administrative,
            decision: AuditDecision::Allowed,
            policy_digest: hex::encode(policy_digest),
            intent_digest: hex::encode(binding),
            result_digest: Some(hex::encode(result_digest)),
            reason_code: if predecessor.is_some() {
                "generation.transition".to_owned()
            } else {
                "generation.genesis".to_owned()
            },
        })
    }

    fn verify_internal(
        &self,
        anchor: Option<&AuditCheckpoint>,
        require_complete: bool,
    ) -> Result<AuditInspection> {
        let mut file = security::open_existing_protected_file(&self.log_path)
            .context("open existing protected audit log")?
            .context("authenticated audit log is missing")?;
        file.lock_shared().context("lock protected audit log")?;
        let result = (|| {
            let verified = self.verify_log(&mut file)?;
            if require_complete {
                ensure!(
                    verified.pending_intents.is_empty(),
                    "audit ledger contains an Intent without a terminal Outcome"
                );
            }
            let checkpoint = self.verify_checkpoint_against_log(&verified, false)?;
            self.verify_external_anchor(&verified, &checkpoint, anchor)?;
            Ok(AuditInspection {
                pending_intents: verified.pending_intents.len(),
                checkpoint,
            })
        })();
        let unlock = FileExt::unlock(&file).context("unlock protected audit log");
        match (result, unlock) {
            (Ok(inspection), Ok(())) => Ok(inspection),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Explicitly close every currently pending Intent as Unknown. This is a
    /// recovery primitive, not an automatic reconciliation path: callers must
    /// perform their own administrator/passphrase authorization before
    /// invoking it. Existing records are immutable and every generated
    /// Outcome retains the exact Intent operation/policy/intent binding.
    pub fn resolve_pending_as_unknown(
        &self,
        at_unix_ms: u64,
        anchor: Option<&AuditCheckpoint>,
    ) -> Result<PendingResolution> {
        ensure!(
            at_unix_ms > 0,
            "pending-resolution timestamp must be non-zero"
        );
        let mut file = security::open_existing_protected_file_for_update(&self.log_path)
            .context("open existing protected audit log")?
            .context("authenticated audit log is missing")?;
        file.lock_exclusive().context("lock protected audit log")?;
        let result = (|| {
            let verified = self.verify_log(&mut file)?;
            let current = self.verify_checkpoint_against_log(&verified, false)?;
            self.verify_external_anchor(&verified, &current, anchor)?;

            let mut pending: Vec<_> = verified.pending_intents.into_iter().collect();
            pending.sort_by_key(|(request_id, _)| *request_id);
            let resolved = pending.len();
            let mut checkpoint = current;
            for (request_id, binding) in pending {
                let result_digest = resolved_unknown_result_digest(
                    &self.profile_id,
                    self.profile_generation,
                    &request_id,
                    &binding,
                );
                let event = AuditEvent {
                    profile_id: hex::encode(self.profile_id),
                    profile_generation: self.profile_generation,
                    request_id,
                    at_unix_ms,
                    operation_kind: binding.operation_kind,
                    phase: AuditPhase::Outcome,
                    decision: AuditDecision::Unknown,
                    policy_digest: binding.policy_digest,
                    intent_digest: binding.intent_digest,
                    result_digest: Some(result_digest),
                    reason_code: RESOLVE_UNKNOWN_REASON.to_owned(),
                };
                checkpoint = self.append_locked(&mut file, &event)?;
            }
            Ok(PendingResolution {
                resolved,
                checkpoint,
            })
        })();
        let unlock = FileExt::unlock(&file).context("unlock protected audit log");
        match (result, unlock) {
            (Ok(resolution), Ok(())) => Ok(resolution),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn verify_external_anchor(
        &self,
        verified: &VerifiedLog,
        checkpoint: &AuditCheckpoint,
        anchor: Option<&AuditCheckpoint>,
    ) -> Result<()> {
        let Some(anchor) = anchor else {
            return Ok(());
        };
        self.verify_checkpoint_mac(anchor)?;
        ensure!(
            anchor.profile_id == checkpoint.profile_id
                && anchor.profile_generation == checkpoint.profile_generation,
            "audit anchor belongs to another profile identity"
        );
        ensure!(
            anchor.sequence <= verified.sequence,
            "audit ledger is older than the external anchor"
        );
        let anchored_hash = if anchor.sequence == 0 {
            ZERO_HASH
        } else {
            verified.hashes[(anchor.sequence - 1) as usize]
        };
        ensure!(
            hex::encode(anchored_hash) == anchor.record_hash,
            "audit ledger does not contain the external anchor"
        );
        Ok(())
    }

    /// Recover only the narrow crash window where valid chained records are
    /// ahead of the last authenticated checkpoint.  Divergence, truncation or
    /// a checkpoint ahead of the log is rejected.
    pub fn reconcile(&self) -> Result<AuditCheckpoint> {
        let mut file = security::open_existing_protected_file_for_update(&self.log_path)
            .context("open existing protected audit log")?
            .context("authenticated audit log is missing")?;
        file.lock_exclusive().context("lock protected audit log")?;
        let result = (|| {
            let verified = self.verify_log(&mut file)?;
            let prior = self.read_checkpoint()?;
            if let Some(checkpoint) = prior.as_ref() {
                self.verify_checkpoint_mac(checkpoint)?;
                ensure!(
                    checkpoint.sequence <= verified.sequence,
                    "audit checkpoint is ahead of the log"
                );
                let matching_hash = if checkpoint.sequence == 0 {
                    ZERO_HASH
                } else {
                    verified.hashes[(checkpoint.sequence - 1) as usize]
                };
                ensure!(
                    hex::encode(matching_hash) == checkpoint.record_hash,
                    "audit checkpoint diverges from the log"
                );
            } else {
                ensure!(verified.sequence == 0, "audit checkpoint is missing");
            }
            let checkpoint = self.make_checkpoint(verified.sequence, verified.record_hash)?;
            self.persist_checkpoint(&checkpoint)?;
            Ok(checkpoint)
        })();
        let unlock = FileExt::unlock(&file).context("unlock protected audit log");
        match (result, unlock) {
            (Ok(checkpoint), Ok(())) => Ok(checkpoint),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn verify_checkpoint_against_log(
        &self,
        verified: &VerifiedLog,
        allow_lagging: bool,
    ) -> Result<AuditCheckpoint> {
        let checkpoint = self
            .read_checkpoint()?
            .context("audit checkpoint is missing")?;
        self.verify_checkpoint_mac(&checkpoint)?;
        ensure!(
            checkpoint.sequence <= verified.sequence,
            "audit checkpoint is ahead of the log"
        );
        let matching_hash = if checkpoint.sequence == 0 {
            ZERO_HASH
        } else {
            verified.hashes[(checkpoint.sequence - 1) as usize]
        };
        ensure!(
            hex::encode(matching_hash) == checkpoint.record_hash,
            "audit checkpoint diverges from the log"
        );
        if !allow_lagging {
            ensure!(
                checkpoint.sequence == verified.sequence
                    && checkpoint.record_hash == hex::encode(verified.record_hash),
                "audit checkpoint lags behind the log; reconcile before use"
            );
        }
        Ok(checkpoint)
    }

    fn make_checkpoint(&self, sequence: u64, record_hash: [u8; 32]) -> Result<AuditCheckpoint> {
        let mut checkpoint = AuditCheckpoint {
            schema_version: AUDIT_SCHEMA_VERSION,
            profile_id: hex::encode(self.profile_id),
            profile_generation: self.profile_generation,
            sequence,
            record_hash: hex::encode(record_hash),
            mac: String::new(),
        };
        checkpoint.mac = self.checkpoint_mac(&checkpoint)?;
        Ok(checkpoint)
    }

    fn checkpoint_mac(&self, checkpoint: &AuditCheckpoint) -> Result<String> {
        let encoded = serde_json::to_vec(&checkpoint.unsigned())
            .context("serialize audit checkpoint payload")?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid audit checkpoint key"))?;
        mac.update(CHECKPOINT_DOMAIN);
        mac.update(&encoded);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn verify_checkpoint_mac(&self, checkpoint: &AuditCheckpoint) -> Result<()> {
        ensure!(
            checkpoint.schema_version == AUDIT_SCHEMA_VERSION,
            "unsupported audit checkpoint schema"
        );
        ensure!(
            checkpoint.profile_id == hex::encode(self.profile_id)
                && checkpoint.profile_generation == self.profile_generation,
            "audit checkpoint profile identity mismatch"
        );
        validate_digest(&checkpoint.record_hash, "checkpoint record hash")?;
        let provided = hex::decode(&checkpoint.mac).context("decode audit checkpoint MAC")?;
        ensure!(
            provided.len() == 32,
            "audit checkpoint MAC length is invalid"
        );
        let expected = hex::decode(self.checkpoint_mac(checkpoint)?)?;
        use subtle::ConstantTimeEq as _;
        ensure!(
            bool::from(expected.as_slice().ct_eq(provided.as_slice())),
            "audit checkpoint authentication failed"
        );
        Ok(())
    }

    fn read_checkpoint(&self) -> Result<Option<AuditCheckpoint>> {
        let Some(mut file) = security::open_existing_protected_file(&self.checkpoint_path)? else {
            return Ok(None);
        };
        let encoded =
            read_bounded_file(&mut file, MAX_AUDIT_RECORD_BYTES as u64, "audit checkpoint")?;
        let checkpoint = serde_json::from_slice(&encoded).context("parse audit checkpoint")?;
        Ok(Some(checkpoint))
    }

    fn persist_checkpoint(&self, checkpoint: &AuditCheckpoint) -> Result<()> {
        let encoded = serde_json::to_vec(checkpoint).context("serialize audit checkpoint")?;
        security::write_protected_atomic(&self.checkpoint_path, &encoded)
            .context("persist authenticated audit checkpoint")
    }

    fn persist_checkpoint_create_new(&self, checkpoint: &AuditCheckpoint) -> Result<()> {
        let encoded = serde_json::to_vec(checkpoint).context("serialize audit checkpoint")?;
        let mut file = security::create_new_protected_file(&self.checkpoint_path)
            .context("create new authenticated audit checkpoint")?;
        file.write_all(&encoded)
            .context("write new authenticated audit checkpoint")?;
        file.sync_all()
            .context("sync new authenticated audit checkpoint")?;
        security::sync_parent_directory(&self.checkpoint_path)
            .context("sync new authenticated audit checkpoint directory entry")
    }

    fn record_mac(&self, record: &AuditRecord) -> Result<String> {
        let encoded = serde_json::to_vec(&(
            record.schema_version,
            record.sequence,
            &record.previous_hash,
            &record.event,
            &record.record_hash,
        ))
        .context("serialize authenticated audit record")?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid audit record key"))?;
        mac.update(RECORD_MAC_DOMAIN);
        mac.update(&encoded);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn verify_record_mac(&self, record: &AuditRecord) -> Result<()> {
        let provided = hex::decode(&record.record_mac).context("decode audit record MAC")?;
        ensure!(provided.len() == 32, "audit record MAC length is invalid");
        let expected = hex::decode(self.record_mac(record)?)?;
        use subtle::ConstantTimeEq as _;
        ensure!(
            bool::from(expected.as_slice().ct_eq(provided.as_slice())),
            "audit record authentication failed"
        );
        Ok(())
    }

    fn verify_log(&self, file: &mut File) -> Result<VerifiedLog> {
        verify_log(file, &self.profile_id, self.profile_generation, |record| {
            self.verify_record_mac(record)
        })
    }
}

fn validate_token(value: &str, max: usize, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= max
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            }),
        "{label} must contain 1..={max} bytes of [a-z0-9._-]"
    );
    Ok(())
}

fn validate_profile_id(value: &str) -> Result<()> {
    ensure!(
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "audit profile id must be 32 lowercase hexadecimal characters"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "{label} must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn validate_transition_name(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control),
        "{label} is empty, oversized, or contains control characters"
    );
    Ok(())
}

fn ensure_generation_event_matches(actual: &AuditEvent, expected: &AuditEvent) -> Result<()> {
    let mut normalized = expected.clone();
    normalized.at_unix_ms = actual.at_unix_ms;
    ensure!(
        actual == &normalized,
        "pre-existing generation audit transition does not match the requested continuity"
    );
    Ok(())
}

fn calculate_record_hash(
    sequence: u64,
    previous_hash: &[u8; 32],
    event: &AuditEvent,
) -> Result<[u8; 32]> {
    let event_bytes = serde_json::to_vec(event).context("serialize canonical audit event")?;
    let mut digest = Sha256::new();
    digest.update(RECORD_DOMAIN);
    digest.update(AUDIT_SCHEMA_VERSION.to_be_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(previous_hash);
    digest.update((event_bytes.len() as u64).to_be_bytes());
    digest.update(&event_bytes);
    Ok(digest.finalize().into())
}

fn resolved_unknown_result_digest(
    profile_id: &[u8; 16],
    profile_generation: u64,
    request_id: &[u8; 16],
    binding: &PendingIntentBinding,
) -> String {
    let mut digest = Sha256::new();
    digest.update(RESOLVE_UNKNOWN_RESULT_DOMAIN);
    digest.update(profile_id);
    digest.update(profile_generation.to_be_bytes());
    digest.update(request_id);
    digest.update((binding.operation_kind.len() as u64).to_be_bytes());
    digest.update(binding.operation_kind.as_bytes());
    digest.update(binding.policy_digest.as_bytes());
    digest.update(binding.intent_digest.as_bytes());
    digest.update(RESOLVE_UNKNOWN_REASON.as_bytes());
    hex::encode(digest.finalize())
}

fn verify_log(
    file: &mut File,
    profile_id: &[u8; 16],
    profile_generation: u64,
    verify_record_mac: impl Fn(&AuditRecord) -> Result<()>,
) -> Result<VerifiedLog> {
    let encoded = read_bounded_file(file, MAX_AUDIT_LOG_BYTES, "audit log")?;
    let mut sequence = 0_u64;
    let mut previous_hash = ZERO_HASH;
    let mut hashes = Vec::new();
    let mut seen_intents = HashSet::new();
    let mut pending_intents = HashMap::new();
    let mut first_event = None;
    for raw_line in encoded.split_inclusive(|byte| *byte == b'\n') {
        ensure!(
            raw_line.ends_with(b"\n"),
            "audit log ends with a partial record"
        );
        let line = &raw_line[..raw_line.len() - 1];
        ensure!(!line.is_empty(), "audit log contains an empty record");
        ensure!(
            line.len() <= MAX_AUDIT_RECORD_BYTES,
            "audit record exceeds its size limit"
        );
        let record: AuditRecord = serde_json::from_slice(line).context("parse audit record")?;
        ensure!(
            record.schema_version == AUDIT_SCHEMA_VERSION,
            "unsupported audit record schema"
        );
        verify_record_mac(&record)?;
        if first_event.is_none() {
            first_event = Some(record.event.clone());
        }
        record.event.validate()?;
        ensure!(
            record.event.profile_id == hex::encode(profile_id)
                && record.event.profile_generation == profile_generation,
            "audit record profile identity mismatch"
        );
        match record.event.phase {
            AuditPhase::Intent => {
                ensure!(
                    seen_intents.insert(record.event.request_id),
                    "audit ledger contains a duplicate Intent request id"
                );
                pending_intents.insert(
                    record.event.request_id,
                    PendingIntentBinding::from_intent(&record.event),
                );
            }
            AuditPhase::Outcome => {
                pending_intents
                    .get(&record.event.request_id)
                    .context("audit Outcome does not match a pending Intent")?
                    .ensure_matches_outcome(&record.event)?;
                pending_intents.remove(&record.event.request_id);
            }
            AuditPhase::Administrative => {}
        }
        let expected_sequence = sequence.checked_add(1).context("audit sequence overflow")?;
        ensure!(
            record.sequence == expected_sequence,
            "audit record sequence gap, replay or reordering"
        );
        ensure!(
            record.previous_hash == hex::encode(previous_hash),
            "audit record previous hash mismatch"
        );
        let expected_hash = calculate_record_hash(record.sequence, &previous_hash, &record.event)?;
        ensure!(
            record.record_hash == hex::encode(expected_hash),
            "audit record hash mismatch"
        );
        previous_hash = expected_hash;
        sequence = record.sequence;
        hashes.push(expected_hash);
    }
    Ok(VerifiedLog {
        sequence,
        record_hash: previous_hash,
        hashes,
        seen_intents,
        pending_intents,
        first_event,
    })
}

fn read_bounded_file(file: &mut File, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let initial_len = file
        .metadata()
        .with_context(|| format!("inspect {label}"))?
        .len();
    ensure!(initial_len <= maximum, "{label} is oversized");
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {label}"))?;
    let capacity = usize::try_from(initial_len.min(maximum)).unwrap_or(0);
    let mut encoded = Vec::with_capacity(capacity);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut encoded)
        .with_context(|| format!("read {label}"))?;
    ensure!(encoded.len() as u64 <= maximum, "{label} is oversized");
    let final_len = file
        .metadata()
        .with_context(|| format!("reinspect {label}"))?
        .len();
    ensure!(final_len <= maximum, "{label} is oversized");
    ensure!(
        final_len == initial_len && final_len == encoded.len() as u64,
        "{label} changed while it was being read"
    );
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::ops::Deref;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "serctl-audit-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn event(id: u8, phase: AuditPhase, decision: AuditDecision) -> AuditEvent {
        AuditEvent {
            profile_id: hex::encode([7_u8; 16]),
            profile_generation: 9,
            request_id: [id; 16],
            at_unix_ms: 1_900_000_000_000 + u64::from(id),
            operation_kind: "typed.exec".into(),
            phase,
            decision,
            policy_digest: hex::encode([3_u8; 32]),
            intent_digest: hex::encode([id; 32]),
            result_digest: (phase == AuditPhase::Outcome).then(|| hex::encode([id + 1; 32])),
            reason_code: if phase == AuditPhase::Intent {
                "intent.recorded".into()
            } else {
                "result.verified".into()
            },
        }
    }

    struct TestLedger(AuditLedger);

    impl Deref for TestLedger {
        type Target = AuditLedger;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl TestLedger {
        fn append(&self, event: &AuditEvent) -> Result<AuditCheckpoint> {
            if self.log_path().exists() {
                self.0.append(event)
            } else {
                self.0.initialize_create_new(event)
            }
        }
    }

    fn ledger(path: &Path) -> TestLedger {
        TestLedger(AuditLedger::new(path, [7_u8; 16], 9, [11_u8; 32]).unwrap())
    }

    fn records(ledger: &AuditLedger) -> Vec<AuditRecord> {
        fs::read_to_string(ledger.log_path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn call_key_derivation_is_bound_to_profile_identity_and_generation() {
        let path = directory("derived-key");
        let call_key = ProfileCallKey::from_bytes_for_test([41_u8; 32]);
        let identity = ProfileIdentity {
            profile_id: [7_u8; 16],
            generation: 9,
        };
        let ledger = AuditLedger::from_profile_call_key(&path, identity, &call_key).unwrap();
        ledger
            .initialize_create_new(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();

        let wrong_key = ProfileCallKey::from_bytes_for_test([42_u8; 32]);
        let impostor = AuditLedger::from_profile_call_key(&path, identity, &wrong_key).unwrap();
        assert!(impostor.verify(None).is_err());

        let next_identity = ProfileIdentity {
            profile_id: identity.profile_id,
            generation: identity.generation + 1,
        };
        let next = AuditLedger::from_profile_call_key(&path, next_identity, &call_key).unwrap();
        assert!(next.verify(None).is_err());
        assert_ne!(ledger.log_path(), next.log_path());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn append_verify_and_external_anchor_are_stable() {
        let path = directory("append");
        let ledger = ledger(&path);
        let first = ledger
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        let second = ledger
            .append(&event(1, AuditPhase::Outcome, AuditDecision::Succeeded))
            .unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        assert_eq!(ledger.verify(Some(&first)).unwrap(), second);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn incomplete_intent_requires_explicit_unknown_resolution_across_reopen() {
        let path = directory("pending-intent");
        let initial = ledger(&path);
        initial
            .append(&event(2, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        initial
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        let inspection = initial.inspect(None).unwrap();
        assert_eq!(inspection.pending_intents, 2);
        assert_eq!(inspection.checkpoint.sequence, 2);
        assert!(initial.verify_complete(None).is_err());

        let reopened = ledger(&path);
        assert!(reopened.verify_complete(None).is_err());
        let resolution = reopened
            .resolve_pending_as_unknown(1_900_000_100_000, None)
            .unwrap();
        assert_eq!(resolution.resolved, 2);
        assert_eq!(resolution.checkpoint.sequence, 4);
        let inspection = reopened.inspect(None).unwrap();
        assert_eq!(inspection.pending_intents, 0);
        assert_eq!(inspection.checkpoint, resolution.checkpoint);
        assert!(reopened.verify_complete(None).is_ok());
        let written = records(&reopened);
        assert_eq!(written[2].event.request_id, [1_u8; 16]);
        assert_eq!(written[3].event.request_id, [2_u8; 16]);
        for outcome_record in &written[2..] {
            let outcome = &outcome_record.event;
            let intent = written
                .iter()
                .take(2)
                .find(|record| record.event.request_id == outcome.request_id)
                .unwrap();
            assert_eq!(outcome.phase, AuditPhase::Outcome);
            assert_eq!(outcome.decision, AuditDecision::Unknown);
            assert_eq!(outcome.operation_kind, intent.event.operation_kind);
            assert_eq!(outcome.policy_digest, intent.event.policy_digest);
            assert_eq!(outcome.intent_digest, intent.event.intent_digest);
            assert_eq!(outcome.reason_code, RESOLVE_UNKNOWN_REASON);
        }

        let no_op = reopened
            .resolve_pending_as_unknown(1_900_000_100_001, None)
            .unwrap();
        assert_eq!(no_op.resolved, 0);
        assert_eq!(no_op.checkpoint, resolution.checkpoint);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn outcome_binding_mismatch_fails_closed_without_consuming_pending_intent() {
        for mismatch in ["operation", "policy", "intent"] {
            let path = directory(mismatch);
            let ledger = ledger(&path);
            let intent = event(1, AuditPhase::Intent, AuditDecision::Pending);
            ledger.append(&intent).unwrap();
            let mut outcome = event(1, AuditPhase::Outcome, AuditDecision::Failed);
            match mismatch {
                "operation" => outcome.operation_kind = "sftp.list".into(),
                "policy" => outcome.policy_digest = hex::encode([4_u8; 32]),
                "intent" => outcome.intent_digest = hex::encode([5_u8; 32]),
                _ => unreachable!(),
            }
            let error = ledger.append(&outcome).unwrap_err();
            assert!(
                error.to_string().contains(mismatch),
                "unexpected {mismatch} error: {error:#}"
            );
            assert_eq!(ledger.verify(None).unwrap().sequence, 1);
            assert!(ledger.verify_complete(None).is_err());
            ledger
                .append(&event(1, AuditPhase::Outcome, AuditDecision::Failed))
                .unwrap();
            assert!(ledger.verify_complete(None).is_ok());
            fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn authenticated_stored_outcome_binding_mismatch_fails_verification() {
        for mismatch in ["operation", "policy", "intent"] {
            let path = directory(&format!("stored-{mismatch}"));
            let ledger = ledger(&path);
            ledger
                .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
                .unwrap();
            ledger
                .append(&event(1, AuditPhase::Outcome, AuditDecision::Succeeded))
                .unwrap();
            let mut stored = records(&ledger);
            match mismatch {
                "operation" => stored[1].event.operation_kind = "sftp.list".into(),
                "policy" => stored[1].event.policy_digest = hex::encode([4_u8; 32]),
                "intent" => stored[1].event.intent_digest = hex::encode([5_u8; 32]),
                _ => unreachable!(),
            }
            let prior_hash: [u8; 32] = hex::decode(&stored[0].record_hash)
                .unwrap()
                .try_into()
                .unwrap();
            let replacement_hash =
                calculate_record_hash(stored[1].sequence, &prior_hash, &stored[1].event).unwrap();
            stored[1].record_hash = hex::encode(replacement_hash);
            stored[1].record_mac = ledger.record_mac(&stored[1]).unwrap();
            let mut encoded = Vec::new();
            for record in stored {
                encoded.extend_from_slice(&serde_json::to_vec(&record).unwrap());
                encoded.push(b'\n');
            }
            fs::write(ledger.log_path(), encoded).unwrap();
            let checkpoint = ledger.make_checkpoint(2, replacement_hash).unwrap();
            ledger.persist_checkpoint(&checkpoint).unwrap();

            let error = ledger.verify(None).unwrap_err();
            assert!(
                error.to_string().contains(mismatch),
                "unexpected stored {mismatch} error: {error:#}"
            );
            fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn tampered_or_wrong_key_ledger_cannot_resolve_pending_intents() {
        let wrong_key_path = directory("resolve-wrong-key");
        let original = ledger(&wrong_key_path);
        original
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        let original_log = fs::read(original.log_path()).unwrap();
        let original_checkpoint = fs::read(original.checkpoint_path()).unwrap();
        let impostor = AuditLedger::new(&wrong_key_path, [7_u8; 16], 9, [12_u8; 32]).unwrap();
        assert!(impostor
            .resolve_pending_as_unknown(1_900_000_200_000, None)
            .is_err());
        assert_eq!(fs::read(original.log_path()).unwrap(), original_log);
        assert_eq!(
            fs::read(original.checkpoint_path()).unwrap(),
            original_checkpoint
        );
        fs::remove_dir_all(wrong_key_path).unwrap();

        let tampered_path = directory("resolve-tampered");
        let tampered = ledger(&tampered_path);
        tampered
            .append(&event(2, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        let mut damaged = fs::read(tampered.log_path()).unwrap();
        damaged[0] ^= 1;
        fs::write(tampered.log_path(), &damaged).unwrap();
        let checkpoint = fs::read(tampered.checkpoint_path()).unwrap();
        assert!(tampered
            .resolve_pending_as_unknown(1_900_000_200_001, None)
            .is_err());
        assert_eq!(fs::read(tampered.log_path()).unwrap(), damaged);
        assert_eq!(fs::read(tampered.checkpoint_path()).unwrap(), checkpoint);
        fs::remove_dir_all(tampered_path).unwrap();
    }

    #[test]
    fn bit_flip_truncation_and_reordering_fail_closed() {
        for mode in ["flip", "truncate", "reorder"] {
            let path = directory(mode);
            let ledger = ledger(&path);
            ledger
                .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
                .unwrap();
            ledger
                .append(&event(1, AuditPhase::Outcome, AuditDecision::Succeeded))
                .unwrap();
            let mut bytes = fs::read(ledger.log_path()).unwrap();
            match mode {
                "flip" => {
                    let index = bytes.iter().position(|byte| *byte == b't').unwrap();
                    bytes[index] = b'u';
                }
                "truncate" => {
                    bytes.pop();
                }
                "reorder" => {
                    let lines: Vec<&[u8]> = bytes.split_inclusive(|byte| *byte == b'\n').collect();
                    bytes = [lines[1], lines[0]].concat();
                }
                _ => unreachable!(),
            }
            fs::write(ledger.log_path(), bytes).unwrap();
            assert!(ledger.verify(None).is_err(), "{mode} was not detected");
            fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn authenticated_anchor_detects_local_rollback() {
        let path = directory("rollback");
        let ledger = ledger(&path);
        let old = ledger
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        let old_log = fs::read(ledger.log_path()).unwrap();
        let old_checkpoint = fs::read(ledger.checkpoint_path()).unwrap();
        let anchor = ledger
            .append(&event(1, AuditPhase::Outcome, AuditDecision::Succeeded))
            .unwrap();
        fs::write(ledger.log_path(), old_log).unwrap();
        fs::write(ledger.checkpoint_path(), old_checkpoint).unwrap();
        assert!(ledger.verify(Some(&anchor)).is_err());
        assert_eq!(ledger.verify(Some(&old)).unwrap().sequence, 1);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn reconcile_repairs_only_a_checkpoint_that_lags_on_the_same_chain() {
        let path = directory("reconcile");
        let ledger = ledger(&path);
        ledger
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        let first_checkpoint = fs::read(ledger.checkpoint_path()).unwrap();
        let second = ledger
            .append(&event(1, AuditPhase::Outcome, AuditDecision::Succeeded))
            .unwrap();
        fs::write(ledger.checkpoint_path(), first_checkpoint).unwrap();
        assert!(ledger.verify(None).is_err());
        assert_eq!(ledger.reconcile().unwrap(), second);
        assert_eq!(ledger.verify(None).unwrap(), second);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn missing_checkpoint_for_nonempty_log_fails_closed() {
        let path = directory("missing-checkpoint");
        let ledger = ledger(&path);
        ledger
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        fs::remove_file(ledger.checkpoint_path()).unwrap();
        assert!(ledger.verify(None).is_err());
        assert!(ledger.reconcile().is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn checkpoint_mac_rejects_unkeyed_replacement() {
        let path = directory("mac");
        let ledger = ledger(&path);
        ledger
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        let mut checkpoint: serde_json::Value =
            serde_json::from_slice(&fs::read(ledger.checkpoint_path()).unwrap()).unwrap();
        checkpoint["record_hash"] = serde_json::Value::String(hex::encode([99_u8; 32]));
        fs::write(
            ledger.checkpoint_path(),
            serde_json::to_vec(&checkpoint).unwrap(),
        )
        .unwrap();
        assert!(ledger.verify(None).is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn unkeyed_forged_tail_cannot_be_blessed_by_append_or_reconcile() {
        for tail_kind in ["matching-outcome", "administrative"] {
            for action in ["append", "reconcile"] {
                let path = directory(&format!("forged-{tail_kind}-tail-{action}"));
                let ledger = ledger(&path);
                ledger
                    .append(&event(7, AuditPhase::Intent, AuditDecision::Pending))
                    .unwrap();
                let checkpoint_before = fs::read(ledger.checkpoint_path()).unwrap();
                let first = records(&ledger)[0].clone();
                let previous_hash: [u8; 32] =
                    hex::decode(&first.record_hash).unwrap().try_into().unwrap();
                let forged_event = if tail_kind == "matching-outcome" {
                    event(7, AuditPhase::Outcome, AuditDecision::Succeeded)
                } else {
                    event(8, AuditPhase::Administrative, AuditDecision::Allowed)
                };
                let forged_hash = calculate_record_hash(2, &previous_hash, &forged_event).unwrap();
                let forged = AuditRecord {
                    schema_version: AUDIT_SCHEMA_VERSION,
                    sequence: 2,
                    previous_hash: first.record_hash,
                    event: forged_event,
                    record_hash: hex::encode(forged_hash),
                    record_mac: hex::encode([0_u8; 32]),
                };
                let mut bytes = fs::read(ledger.log_path()).unwrap();
                bytes.extend_from_slice(&serde_json::to_vec(&forged).unwrap());
                bytes.push(b'\n');
                fs::write(ledger.log_path(), &bytes).unwrap();

                let error = if action == "append" {
                    ledger
                        .append(&event(8, AuditPhase::Intent, AuditDecision::Pending))
                        .unwrap_err()
                } else {
                    ledger.reconcile().unwrap_err()
                };
                assert!(
                    error.to_string().contains("authentication"),
                    "unexpected forged-tail error: {error:#}"
                );
                assert_eq!(fs::read(ledger.log_path()).unwrap(), bytes);
                assert_eq!(
                    fs::read(ledger.checkpoint_path()).unwrap(),
                    checkpoint_before
                );
                fs::remove_dir_all(path).unwrap();
            }
        }
    }

    #[test]
    fn pair_deletion_never_synthesizes_an_empty_authenticated_chain() {
        let path = directory("pair-deletion");
        let ledger = ledger(&path);
        ledger
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        ledger
            .append(&event(1, AuditPhase::Outcome, AuditDecision::Succeeded))
            .unwrap();
        fs::remove_file(ledger.log_path()).unwrap();
        fs::remove_file(ledger.checkpoint_path()).unwrap();

        assert!(ledger.verify(None).is_err());
        assert!(ledger.inspect(None).is_err());
        assert!(ledger.reconcile().is_err());
        assert!(ledger
            .resolve_pending_as_unknown(1_900_000_300_000, None)
            .is_err());
        assert!(ledger
            .0
            .append(&event(2, AuditPhase::Intent, AuditDecision::Pending))
            .is_err());
        assert!(!ledger.log_path().exists());
        assert!(!ledger.checkpoint_path().exists());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn generation_initialization_is_bound_and_recovers_only_its_exact_crash_tail() {
        let path = directory("generation-transition");
        let old = AuditLedger::new(&path, [7_u8; 16], 9, [11_u8; 32]).unwrap();
        let old_head = old
            .initialize_generation(None, "old-name", "old-name", 1_900_000_400_000)
            .unwrap();
        let next = AuditLedger::new(&path, [7_u8; 16], 10, [12_u8; 32]).unwrap();
        let next_head = next
            .initialize_generation(Some(&old_head), "old-name", "new-name", 1_900_000_400_001)
            .unwrap();
        assert_eq!(next_head.sequence, 1);

        fs::remove_file(next.checkpoint_path()).unwrap();
        let resumed = next
            .initialize_generation(Some(&old_head), "old-name", "new-name", 1_900_000_400_999)
            .unwrap();
        assert_eq!(resumed, next_head);
        assert!(next
            .initialize_generation(
                Some(&old_head),
                "wrong-old-name",
                "new-name",
                1_900_000_401_000,
            )
            .is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn explicit_generation_initialization_recovers_a_durable_empty_create_new_log() {
        let path = directory("empty-generation-initialization");
        let ledger = AuditLedger::new(&path, [0x61_u8; 16], 3, [0x72_u8; 32]).unwrap();
        let file = security::create_new_protected_file(ledger.log_path()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        security::sync_parent_directory(ledger.log_path()).unwrap();

        // Existing-only status/verify never treats the empty object as a
        // valid chain. Only the explicit, still-uncommitted generation
        // initialization API may fill it with the exact expected genesis.
        assert!(ledger.verify_complete(None).is_err());
        let checkpoint = ledger
            .initialize_generation(None, "profile", "profile", 1_900_000_450_000)
            .unwrap();
        assert_eq!(checkpoint.sequence, 1);
        assert_eq!(ledger.verify_complete(None).unwrap(), checkpoint);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn event_bounds_and_phase_invariants_are_enforced() {
        let mut invalid = event(1, AuditPhase::Intent, AuditDecision::Pending);
        invalid.operation_kind = "x".repeat(MAX_OPERATION_KIND_BYTES + 1);
        assert!(invalid.validate().is_err());
        invalid = event(1, AuditPhase::Intent, AuditDecision::Succeeded);
        assert!(invalid.validate().is_err());
        invalid = event(1, AuditPhase::Outcome, AuditDecision::Pending);
        assert!(invalid.validate().is_err());

        invalid = event(1, AuditPhase::Outcome, AuditDecision::Succeeded);
        invalid.result_digest = None;
        assert!(invalid.validate().is_err());

        invalid = event(1, AuditPhase::Administrative, AuditDecision::Pending);
        invalid.result_digest = Some(hex::encode([8_u8; 32]));
        assert!(invalid.validate().is_err());

        invalid = event(1, AuditPhase::Administrative, AuditDecision::Allowed);
        assert!(invalid.validate().is_err());
        invalid.result_digest = Some(hex::encode([8_u8; 32]));
        assert!(invalid.validate().is_ok());
    }

    #[test]
    fn unbound_terminal_record_is_rejected_without_mutating_the_durable_pair() {
        let path = directory("unbound-terminal");
        let ledger = ledger(&path);
        ledger
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        let log_before = fs::read(ledger.log_path()).unwrap();
        let checkpoint_before = fs::read(ledger.checkpoint_path()).unwrap();

        let mut unbound = event(1, AuditPhase::Outcome, AuditDecision::Succeeded);
        unbound.result_digest = None;
        let error = ledger.append(&unbound).unwrap_err();
        assert!(
            error.to_string().contains("carry a result digest"),
            "unexpected unbound-terminal error: {error:#}"
        );
        assert_eq!(fs::read(ledger.log_path()).unwrap(), log_before);
        assert_eq!(
            fs::read(ledger.checkpoint_path()).unwrap(),
            checkpoint_before
        );
        assert!(ledger.verify_complete(None).is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn outcome_requires_one_unique_pending_intent() {
        let path = directory("intent-pairing");
        let ledger = ledger(&path);
        ledger
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .unwrap();
        assert!(ledger
            .append(&event(2, AuditPhase::Outcome, AuditDecision::Failed))
            .is_err());
        assert!(ledger
            .append(&event(1, AuditPhase::Intent, AuditDecision::Pending))
            .is_err());
        ledger
            .append(&event(1, AuditPhase::Outcome, AuditDecision::Succeeded))
            .unwrap();
        assert!(ledger
            .append(&event(1, AuditPhase::Outcome, AuditDecision::Succeeded))
            .is_err());
        assert!(ledger.verify_complete(None).is_ok());
        fs::remove_dir_all(path).unwrap();
    }
}
