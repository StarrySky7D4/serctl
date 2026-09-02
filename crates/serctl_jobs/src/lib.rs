//! Crash-safe job state and authenticated receipt primitives.
//!
//! A transport timeout or helper restart never becomes a successful result by
//! inference. Reconciliation remains `Unknown` unless a receipt proves the
//! exact job, profile generation, policy, input, and random per-job token.

#![forbid(unsafe_code)]

use anyhow::{bail, ensure, Context as _, Result};
use hmac::{Hmac, Mac as _};
use serctl_remote_protocol::{Digest32, HeartbeatFrame, JobId, ProfileId, Secret32};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize;

pub use serctl_remote_protocol::JobId as RemoteJobId;

pub const JOB_SCHEMA_VERSION: u16 = 1;
pub const RECEIPT_VERSION: u16 = 1;
pub const MAX_JOURNAL_BYTES: usize = 16 * 1024;
pub const RECEIPT_BYTES: usize =
    4 + 2 + 16 + 16 + 8 + 32 + 32 + 4 + (8 * 4) + 32 + 32 + 1 + 4 + 8 + 32 + 32;
pub const MAX_RELAY_WINDOW_MS: u64 = 40 * 60 * 1000;
pub const MAX_RESULT_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
const RECEIPT_MAGIC: [u8; 4] = *b"SRRC";
const TOKEN_HASH_DOMAIN: &[u8] = b"serctl-job-token-v1\0";
const RECEIPT_MAC_DOMAIN: &[u8] = b"serctl-job-receipt-v1\0";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStage {
    Submitted,
    Running,
    Cancelling,
    Unknown,
    Completed,
    Failed,
    Cancelled,
}

impl JobStage {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobDeadlines {
    pub remote_unix_ms: u64,
    pub relay_unix_ms: u64,
    pub result_retention_unix_ms: u64,
}

impl JobDeadlines {
    pub fn validate_at(self, now_unix_ms: u64) -> Result<()> {
        ensure!(
            now_unix_ms < self.remote_unix_ms,
            "remote deadline must be in the future"
        );
        ensure!(
            self.remote_unix_ms <= self.relay_unix_ms,
            "relay deadline precedes remote deadline"
        );
        ensure!(
            self.relay_unix_ms <= self.result_retention_unix_ms,
            "result retention precedes relay deadline"
        );
        ensure!(
            self.relay_unix_ms.saturating_sub(now_unix_ms) <= MAX_RELAY_WINDOW_MS,
            "relay deadline exceeds the 40-minute grant window"
        );
        ensure!(
            self.result_retention_unix_ms.saturating_sub(now_unix_ms) <= MAX_RESULT_RETENTION_MS,
            "result retention exceeds the policy ceiling"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobIdentity {
    pub job_id: JobId,
    pub profile_id: ProfileId,
    pub profile_generation: u64,
    pub policy_digest: Digest32,
    pub input_digest: Digest32,
}

impl JobIdentity {
    pub fn validate(self) -> Result<()> {
        ensure!(
            self.job_id.as_bytes().iter().any(|byte| *byte != 0),
            "job identifier must be non-zero"
        );
        ensure!(
            self.profile_id.as_bytes().iter().any(|byte| *byte != 0),
            "profile identifier must be non-zero"
        );
        ensure!(
            self.profile_generation > 0,
            "profile generation must be non-zero"
        );
        ensure!(
            self.policy_digest.as_bytes().iter().any(|byte| *byte != 0),
            "policy digest must be non-zero"
        );
        ensure!(
            self.input_digest.as_bytes().iter().any(|byte| *byte != 0),
            "input digest must be non-zero"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobRecord {
    pub identity: JobIdentity,
    pub deadlines: JobDeadlines,
    pub run_as_uid: u32,
    pub stage: JobStage,
    pub heartbeat_ordinal: u64,
    pub elapsed_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub max_output_bytes: u64,
    pub updated_unix_ms: u64,
}

impl JobRecord {
    pub fn submitted(
        identity: JobIdentity,
        deadlines: JobDeadlines,
        run_as_uid: u32,
        max_output_bytes: u64,
        now_unix_ms: u64,
    ) -> Result<Self> {
        identity.validate()?;
        deadlines.validate_at(now_unix_ms)?;
        ensure!(run_as_uid != 0, "execution UID must be non-zero");
        ensure!(max_output_bytes > 0, "output budget must be non-zero");
        Ok(Self {
            identity,
            deadlines,
            run_as_uid,
            stage: JobStage::Submitted,
            heartbeat_ordinal: 0,
            elapsed_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            max_output_bytes,
            updated_unix_ms: now_unix_ms,
        })
    }

    pub fn mark_running(&mut self, now_unix_ms: u64) -> Result<()> {
        ensure!(
            self.stage == JobStage::Submitted,
            "job can enter running only from submitted"
        );
        ensure!(
            now_unix_ms >= self.updated_unix_ms,
            "job clock moved backwards"
        );
        ensure!(
            now_unix_ms < self.deadlines.remote_unix_ms,
            "remote deadline already elapsed"
        );
        self.stage = JobStage::Running;
        self.updated_unix_ms = now_unix_ms;
        Ok(())
    }

    pub fn observe_heartbeat(
        &mut self,
        heartbeat: &HeartbeatFrame,
        now_unix_ms: u64,
    ) -> Result<()> {
        ensure!(
            matches!(self.stage, JobStage::Running | JobStage::Cancelling),
            "heartbeat is invalid in the current stage"
        );
        ensure!(
            heartbeat.job_id == self.identity.job_id,
            "heartbeat job mismatch"
        );
        ensure!(
            heartbeat.ordinal > self.heartbeat_ordinal,
            "heartbeat replay or reordering"
        );
        ensure!(
            heartbeat.elapsed_ms >= self.elapsed_ms,
            "elapsed time regressed"
        );
        ensure!(
            heartbeat.stdout_bytes >= self.stdout_bytes
                && heartbeat.stderr_bytes >= self.stderr_bytes,
            "output counters regressed"
        );
        ensure!(
            heartbeat
                .stdout_bytes
                .saturating_add(heartbeat.stderr_bytes)
                <= self.max_output_bytes,
            "output budget exceeded"
        );
        ensure!(
            now_unix_ms >= self.updated_unix_ms,
            "job clock moved backwards"
        );
        self.heartbeat_ordinal = heartbeat.ordinal;
        self.elapsed_ms = heartbeat.elapsed_ms;
        self.stdout_bytes = heartbeat.stdout_bytes;
        self.stderr_bytes = heartbeat.stderr_bytes;
        self.updated_unix_ms = now_unix_ms;
        Ok(())
    }

    pub fn request_cancel(&mut self, now_unix_ms: u64) -> Result<()> {
        ensure!(self.stage == JobStage::Running, "job is not cancellable");
        ensure!(
            now_unix_ms >= self.updated_unix_ms,
            "job clock moved backwards"
        );
        self.stage = JobStage::Cancelling;
        self.updated_unix_ms = now_unix_ms;
        Ok(())
    }

    /// Disconnects, process restarts, and relay deadlines are inconclusive.
    pub fn mark_unknown(&mut self, now_unix_ms: u64) -> Result<()> {
        ensure!(
            !self.stage.is_terminal(),
            "terminal jobs cannot become unknown"
        );
        ensure!(
            now_unix_ms >= self.updated_unix_ms,
            "job clock moved backwards"
        );
        self.stage = JobStage::Unknown;
        self.updated_unix_ms = now_unix_ms;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptOutcome {
    Exited(i32),
    Cancelled,
    DeadlineExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptBody {
    pub identity: JobIdentity,
    pub run_as_uid: u32,
    pub deadlines: JobDeadlines,
    pub max_output_bytes: u64,
    pub stdout_digest: Digest32,
    pub stderr_digest: Digest32,
    pub outcome: ReceiptOutcome,
    pub completed_unix_ms: u64,
}

pub struct AuthenticatedReceipt {
    body: ReceiptBody,
    token_hash: [u8; 32],
    mac: [u8; 32],
}

impl fmt::Debug for AuthenticatedReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedReceipt")
            .field("body", &self.body)
            .field("token_hash", &"[REDACTED]")
            .field("mac", &"[REDACTED]")
            .finish()
    }
}

impl Drop for AuthenticatedReceipt {
    fn drop(&mut self) {
        self.token_hash.zeroize();
        self.mac.zeroize();
    }
}

impl AuthenticatedReceipt {
    pub fn issue(body: ReceiptBody, token: &Secret32) -> Result<Self> {
        body.identity.validate()?;
        ensure!(body.run_as_uid != 0, "execution UID must be non-zero");
        ensure!(
            body.deadlines.remote_unix_ms <= body.deadlines.relay_unix_ms
                && body.deadlines.relay_unix_ms <= body.deadlines.result_retention_unix_ms,
            "receipt deadline ordering is invalid"
        );
        ensure!(
            body.max_output_bytes > 0,
            "receipt output budget must be non-zero"
        );
        ensure!(
            body.completed_unix_ms > 0,
            "completion time must be non-zero"
        );
        let token_hash = hash_token(token);
        let canonical = canonical_receipt_body(&body);
        let mac = receipt_mac(token, &canonical, &token_hash)?;
        Ok(Self {
            body,
            token_hash,
            mac,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = canonical_receipt_body(&self.body);
        bytes.extend_from_slice(&self.token_hash);
        bytes.extend_from_slice(&self.mac);
        debug_assert_eq!(bytes.len(), RECEIPT_BYTES);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == RECEIPT_BYTES, "receipt length is invalid");
        ensure!(bytes[..4] == RECEIPT_MAGIC, "receipt magic is invalid");
        let version = u16::from_be_bytes(bytes[4..6].try_into().expect("fixed receipt field"));
        ensure!(version == RECEIPT_VERSION, "receipt version is unsupported");
        let mut cursor = 6;
        let job_id = JobId::from_bytes(take_array(bytes, &mut cursor)?);
        let profile_id = ProfileId::from_bytes(take_array(bytes, &mut cursor)?);
        let profile_generation = take_u64(bytes, &mut cursor)?;
        let policy_digest = Digest32::from_bytes(take_array(bytes, &mut cursor)?);
        let input_digest = Digest32::from_bytes(take_array(bytes, &mut cursor)?);
        let run_as_uid = take_u32(bytes, &mut cursor)?;
        let deadlines = JobDeadlines {
            remote_unix_ms: take_u64(bytes, &mut cursor)?,
            relay_unix_ms: take_u64(bytes, &mut cursor)?,
            result_retention_unix_ms: take_u64(bytes, &mut cursor)?,
        };
        let max_output_bytes = take_u64(bytes, &mut cursor)?;
        let stdout_digest = Digest32::from_bytes(take_array(bytes, &mut cursor)?);
        let stderr_digest = Digest32::from_bytes(take_array(bytes, &mut cursor)?);
        let outcome_kind = take_u8(bytes, &mut cursor)?;
        let exit_code = take_i32(bytes, &mut cursor)?;
        let outcome = match (outcome_kind, exit_code) {
            (0, code) => ReceiptOutcome::Exited(code),
            (1, 0) => ReceiptOutcome::Cancelled,
            (2, 0) => ReceiptOutcome::DeadlineExceeded,
            _ => bail!("receipt outcome is invalid"),
        };
        let completed_unix_ms = take_u64(bytes, &mut cursor)?;
        let token_hash = take_array(bytes, &mut cursor)?;
        let mac = take_array(bytes, &mut cursor)?;
        ensure!(cursor == bytes.len(), "receipt has trailing bytes");
        let receipt = Self {
            body: ReceiptBody {
                identity: JobIdentity {
                    job_id,
                    profile_id,
                    profile_generation,
                    policy_digest,
                    input_digest,
                },
                run_as_uid,
                deadlines,
                max_output_bytes,
                stdout_digest,
                stderr_digest,
                outcome,
                completed_unix_ms,
            },
            token_hash,
            mac,
        };
        receipt.body.identity.validate()?;
        ensure!(
            receipt.body.run_as_uid != 0,
            "receipt execution UID is invalid"
        );
        ensure!(
            receipt.body.deadlines.remote_unix_ms <= receipt.body.deadlines.relay_unix_ms
                && receipt.body.deadlines.relay_unix_ms
                    <= receipt.body.deadlines.result_retention_unix_ms,
            "receipt deadline ordering is invalid"
        );
        ensure!(
            receipt.body.max_output_bytes > 0,
            "receipt output budget is invalid"
        );
        Ok(receipt)
    }

    pub fn verify(
        &self,
        expected: &JobIdentity,
        deadlines: JobDeadlines,
        run_as_uid: u32,
        max_output_bytes: u64,
        token: &Secret32,
        now_unix_ms: u64,
    ) -> Result<ReceiptBody> {
        ensure!(&self.body.identity == expected, "receipt identity mismatch");
        ensure!(
            self.body.run_as_uid == run_as_uid && run_as_uid != 0,
            "receipt execution UID mismatch"
        );
        ensure!(
            self.body.deadlines == deadlines,
            "receipt deadlines mismatch"
        );
        ensure!(
            self.body.max_output_bytes == max_output_bytes && max_output_bytes != 0,
            "receipt output budget mismatch"
        );
        ensure!(
            self.body.completed_unix_ms <= deadlines.relay_unix_ms,
            "receipt completion exceeds relay deadline"
        );
        ensure!(
            self.body.completed_unix_ms <= now_unix_ms,
            "receipt completion is in the future"
        );
        ensure!(
            now_unix_ms <= deadlines.result_retention_unix_ms,
            "receipt retention expired"
        );
        let expected_hash = hash_token(token);
        ensure!(
            bool::from(expected_hash.ct_eq(&self.token_hash)),
            "receipt token mismatch"
        );
        let canonical = canonical_receipt_body(&self.body);
        let expected_mac = receipt_mac(token, &canonical, &self.token_hash)?;
        ensure!(
            bool::from(expected_mac.ct_eq(&self.mac)),
            "receipt authentication failed"
        );
        Ok(self.body)
    }
}

fn canonical_receipt_body(body: &ReceiptBody) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RECEIPT_BYTES - 64);
    bytes.extend_from_slice(&RECEIPT_MAGIC);
    bytes.extend_from_slice(&RECEIPT_VERSION.to_be_bytes());
    bytes.extend_from_slice(body.identity.job_id.as_bytes());
    bytes.extend_from_slice(body.identity.profile_id.as_bytes());
    bytes.extend_from_slice(&body.identity.profile_generation.to_be_bytes());
    bytes.extend_from_slice(body.identity.policy_digest.as_bytes());
    bytes.extend_from_slice(body.identity.input_digest.as_bytes());
    bytes.extend_from_slice(&body.run_as_uid.to_be_bytes());
    bytes.extend_from_slice(&body.deadlines.remote_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&body.deadlines.relay_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&body.deadlines.result_retention_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&body.max_output_bytes.to_be_bytes());
    bytes.extend_from_slice(body.stdout_digest.as_bytes());
    bytes.extend_from_slice(body.stderr_digest.as_bytes());
    match body.outcome {
        ReceiptOutcome::Exited(code) => {
            bytes.push(0);
            bytes.extend_from_slice(&code.to_be_bytes());
        }
        ReceiptOutcome::Cancelled => {
            bytes.push(1);
            bytes.extend_from_slice(&0_i32.to_be_bytes());
        }
        ReceiptOutcome::DeadlineExceeded => {
            bytes.push(2);
            bytes.extend_from_slice(&0_i32.to_be_bytes());
        }
    }
    bytes.extend_from_slice(&body.completed_unix_ms.to_be_bytes());
    bytes
}

fn hash_token(token: &Secret32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_HASH_DOMAIN);
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

fn receipt_mac(token: &Secret32, body: &[u8], token_hash: &[u8; 32]) -> Result<[u8; 32]> {
    let mut mac =
        HmacSha256::new_from_slice(token.as_bytes()).context("initialize receipt HMAC")?;
    mac.update(RECEIPT_MAC_DOMAIN);
    mac.update(body);
    mac.update(token_hash);
    Ok(mac.finalize().into_bytes().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    Unknown(JobRecord),
    Recovered {
        record: JobRecord,
        receipt: Box<ReceiptBody>,
    },
}

pub fn reconcile(
    mut record: JobRecord,
    receipt_bytes: Option<&[u8]>,
    token: &Secret32,
    now_unix_ms: u64,
) -> Result<ReconcileOutcome> {
    let Some(bytes) = receipt_bytes else {
        ensure!(
            now_unix_ms >= record.updated_unix_ms,
            "job clock moved backwards"
        );
        record.stage = JobStage::Unknown;
        record.updated_unix_ms = now_unix_ms;
        return Ok(ReconcileOutcome::Unknown(record));
    };
    let receipt = AuthenticatedReceipt::decode(bytes)?;
    let body = receipt.verify(
        &record.identity,
        record.deadlines,
        record.run_as_uid,
        record.max_output_bytes,
        token,
        now_unix_ms,
    )?;
    record.stage = match body.outcome {
        ReceiptOutcome::Exited(0) => JobStage::Completed,
        ReceiptOutcome::Exited(_) | ReceiptOutcome::DeadlineExceeded => JobStage::Failed,
        ReceiptOutcome::Cancelled => JobStage::Cancelled,
    };
    record.updated_unix_ms = body.completed_unix_ms;
    Ok(ReconcileOutcome::Recovered {
        record,
        receipt: Box::new(body),
    })
}

#[derive(Clone, Debug)]
pub struct JobStore {
    root: PathBuf,
}

impl JobStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        ensure!(root.is_absolute(), "job store path must be absolute");
        ensure!(
            !root.components().any(|component| matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )),
            "job store path contains traversal components"
        );
        ensure!(
            root.as_os_str().to_string_lossy().len() <= 4096,
            "job store path is too long"
        );
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn create_journal(&self, record: &JobRecord) -> Result<PathBuf> {
        self.prepare_root()?;
        let path = self.journal_path(record.identity.job_id);
        create_new_private(&path, &encode_journal(record)?)?;
        Ok(path)
    }

    pub fn update_journal(&self, record: &JobRecord) -> Result<()> {
        self.validate_root()?;
        let path = self.journal_path(record.identity.job_id);
        ensure_existing_private_regular(&path)?;
        write_atomic_private(&path, &encode_journal(record)?)
    }

    pub fn load_journal(&self, job_id: JobId) -> Result<JobRecord> {
        self.validate_root()?;
        let bytes = read_private_bounded(&self.journal_path(job_id), MAX_JOURNAL_BYTES)?;
        let record = decode_journal(&bytes)?;
        ensure!(record.identity.job_id == job_id, "journal job mismatch");
        Ok(record)
    }

    /// Receipts are immutable. Existing receipt paths are never overwritten.
    pub fn persist_receipt(&self, receipt: &AuthenticatedReceipt) -> Result<PathBuf> {
        self.prepare_root()?;
        let path = self.receipt_path(receipt.body.identity.job_id);
        let mut bytes = receipt.encode();
        let result = create_new_private(&path, &bytes).map(|()| path);
        bytes.zeroize();
        result
    }

    pub fn load_receipt(&self, job_id: JobId) -> Result<Vec<u8>> {
        self.validate_root()?;
        read_private_bounded(&self.receipt_path(job_id), RECEIPT_BYTES)
    }

    pub fn journal_path(&self, job_id: JobId) -> PathBuf {
        self.root.join(format!("{job_id}.journal"))
    }

    pub fn receipt_path(&self, job_id: JobId) -> PathBuf {
        self.root.join(format!("{job_id}.receipt"))
    }

    #[cfg(target_os = "linux")]
    fn prepare_root(&self) -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        if !self.root.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(&self.root)
                .with_context(|| format!("create job store {}", self.root.display()))?;
        }
        self.validate_root()?;
        std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect job store {}", self.root.display()))?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn prepare_root(&self) -> Result<()> {
        bail!("crash-safe job persistence is supported only by the Linux remote helper")
    }

    #[cfg(target_os = "linux")]
    fn validate_root(&self) -> Result<()> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = std::fs::symlink_metadata(&self.root)
            .with_context(|| format!("inspect job store {}", self.root.display()))?;
        ensure!(
            metadata.file_type().is_dir(),
            "job store is not a directory"
        );
        ensure!(!metadata.file_type().is_symlink(), "job store is a symlink");
        ensure!(
            owner_matches_current(metadata.uid(), effective_uid()?),
            "job store owner mismatch"
        );
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "job store grants group or other access"
        );
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn validate_root(&self) -> Result<()> {
        bail!("crash-safe job persistence is supported only by the Linux remote helper")
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskJobRecord {
    schema_version: u16,
    job_id: String,
    profile_id: String,
    profile_generation: u64,
    policy_digest: String,
    input_digest: String,
    remote_deadline_unix_ms: u64,
    relay_deadline_unix_ms: u64,
    result_retention_unix_ms: u64,
    run_as_uid: u32,
    stage: JobStage,
    heartbeat_ordinal: u64,
    elapsed_ms: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
    max_output_bytes: u64,
    updated_unix_ms: u64,
}

fn encode_journal(record: &JobRecord) -> Result<Vec<u8>> {
    let disk = DiskJobRecord {
        schema_version: JOB_SCHEMA_VERSION,
        job_id: hex::encode(record.identity.job_id.as_bytes()),
        profile_id: hex::encode(record.identity.profile_id.as_bytes()),
        profile_generation: record.identity.profile_generation,
        policy_digest: hex::encode(record.identity.policy_digest.as_bytes()),
        input_digest: hex::encode(record.identity.input_digest.as_bytes()),
        remote_deadline_unix_ms: record.deadlines.remote_unix_ms,
        relay_deadline_unix_ms: record.deadlines.relay_unix_ms,
        result_retention_unix_ms: record.deadlines.result_retention_unix_ms,
        run_as_uid: record.run_as_uid,
        stage: record.stage,
        heartbeat_ordinal: record.heartbeat_ordinal,
        elapsed_ms: record.elapsed_ms,
        stdout_bytes: record.stdout_bytes,
        stderr_bytes: record.stderr_bytes,
        max_output_bytes: record.max_output_bytes,
        updated_unix_ms: record.updated_unix_ms,
    };
    let bytes = serde_json::to_vec(&disk).context("serialize job journal")?;
    ensure!(
        bytes.len() <= MAX_JOURNAL_BYTES,
        "job journal exceeds size limit"
    );
    Ok(bytes)
}

fn decode_journal(bytes: &[u8]) -> Result<JobRecord> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_JOURNAL_BYTES,
        "job journal size is invalid"
    );
    let disk: DiskJobRecord = serde_json::from_slice(bytes).context("parse job journal")?;
    ensure!(
        disk.schema_version == JOB_SCHEMA_VERSION,
        "job journal schema is unsupported"
    );
    let identity = JobIdentity {
        job_id: JobId::from_bytes(decode_hex_array(&disk.job_id, "job_id")?),
        profile_id: ProfileId::from_bytes(decode_hex_array(&disk.profile_id, "profile_id")?),
        profile_generation: disk.profile_generation,
        policy_digest: Digest32::from_bytes(decode_hex_array(
            &disk.policy_digest,
            "policy_digest",
        )?),
        input_digest: Digest32::from_bytes(decode_hex_array(&disk.input_digest, "input_digest")?),
    };
    identity.validate()?;
    let record = JobRecord {
        identity,
        deadlines: JobDeadlines {
            remote_unix_ms: disk.remote_deadline_unix_ms,
            relay_unix_ms: disk.relay_deadline_unix_ms,
            result_retention_unix_ms: disk.result_retention_unix_ms,
        },
        run_as_uid: disk.run_as_uid,
        stage: disk.stage,
        heartbeat_ordinal: disk.heartbeat_ordinal,
        elapsed_ms: disk.elapsed_ms,
        stdout_bytes: disk.stdout_bytes,
        stderr_bytes: disk.stderr_bytes,
        max_output_bytes: disk.max_output_bytes,
        updated_unix_ms: disk.updated_unix_ms,
    };
    ensure!(record.run_as_uid != 0, "journal execution UID is invalid");
    ensure!(
        record.max_output_bytes > 0,
        "journal output budget is invalid"
    );
    ensure!(
        record.stdout_bytes.saturating_add(record.stderr_bytes) <= record.max_output_bytes,
        "journal output counters exceed budget"
    );
    ensure!(
        record.deadlines.remote_unix_ms <= record.deadlines.relay_unix_ms
            && record.deadlines.relay_unix_ms <= record.deadlines.result_retention_unix_ms,
        "journal deadline ordering is invalid"
    );
    Ok(record)
}

fn decode_hex_array<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    ensure!(value.len() == N * 2, "{field} has invalid length");
    let bytes = hex::decode(value).with_context(|| format!("decode {field}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} has invalid length"))
}

#[cfg(target_os = "linux")]
fn create_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let parent = path.parent().context("protected file has no parent")?;
    let (temporary, mut file) = (0..4)
        .find_map(|_| {
            let candidate = parent.join(format!(".serctl-create-{}", JobId::random()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&candidate)
            {
                Ok(file) => Some(Ok((candidate, file))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .transpose()
        .with_context(|| format!("create protected temporary for {}", path.display()))?
        .context("exhausted protected temporary names")?;

    let staged = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(error) = staged {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("stage protected file {}", path.display()));
    }

    if let Err(error) = std::fs::hard_link(&temporary, path) {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("publish protected file {}", path.display()));
    }
    let staged_metadata = file.metadata()?;
    let published_metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        staged_metadata.dev() == published_metadata.dev()
            && staged_metadata.ino() == published_metadata.ino(),
        "published protected file identity mismatch"
    );
    ensure_existing_private_regular(path)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync protected parent for {}", path.display()))?;
    std::fs::remove_file(&temporary)
        .with_context(|| format!("remove protected temporary for {}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync protected cleanup for {}", path.display()))
}

#[cfg(not(target_os = "linux"))]
fn create_new_private(_path: &Path, _bytes: &[u8]) -> Result<()> {
    bail!("crash-safe job persistence is supported only by the Linux remote helper")
}

#[cfg(target_os = "linux")]
fn ensure_existing_private_regular(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect protected file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "protected path is not a regular file"
    );
    ensure!(
        !metadata.file_type().is_symlink(),
        "protected path is a symlink"
    );
    ensure!(
        owner_matches_current(metadata.uid(), effective_uid()?),
        "protected file owner mismatch"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "protected file grants group or other access"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_existing_private_regular(_path: &Path) -> Result<()> {
    bail!("crash-safe job persistence is supported only by the Linux remote helper")
}

#[cfg(target_os = "linux")]
fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use atomic_write_file::AtomicWriteFile;
    use std::os::unix::fs::PermissionsExt as _;
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic journal for {}", path.display()))?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.commit()
        .with_context(|| format!("commit atomic journal {}", path.display()))?;
    ensure_existing_private_regular(path)?;
    File::open(path.parent().context("journal has no parent")?)
        .and_then(|parent| parent.sync_all())
        .with_context(|| format!("sync journal parent for {}", path.display()))
}

#[cfg(not(target_os = "linux"))]
fn write_atomic_private(_path: &Path, _bytes: &[u8]) -> Result<()> {
    bail!("crash-safe job persistence is supported only by the Linux remote helper")
}

#[cfg(target_os = "linux")]
fn read_private_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open protected file {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "protected path is not a regular file");
    ensure!(
        owner_matches_current(metadata.uid(), effective_uid()?),
        "protected file owner mismatch"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "protected file grants group or other access"
    );
    ensure!(
        metadata.len() as usize <= maximum,
        "protected file is too large"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "protected file is too large");
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn read_private_bounded(_path: &Path, _maximum: usize) -> Result<Vec<u8>> {
    bail!("crash-safe job persistence is supported only by the Linux remote helper")
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status").context("read process identity")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .context("process UID is unavailable")?;
    line[4..]
        .split_ascii_whitespace()
        .nth(1)
        .context("effective UID is unavailable")?
        .parse()
        .context("parse effective UID")
}

#[cfg(target_os = "linux")]
const fn owner_matches_current(owner_uid: u32, effective_uid: u32) -> bool {
    owner_uid == effective_uid
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor.checked_add(N).context("receipt length overflow")?;
    let value = bytes.get(*cursor..end).context("receipt is truncated")?;
    *cursor = end;
    value.try_into().context("receipt field length")
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    Ok(take_array::<1>(bytes, cursor)?[0])
}
fn take_i32(bytes: &[u8], cursor: &mut usize) -> Result<i32> {
    Ok(i32::from_be_bytes(take_array(bytes, cursor)?))
}
fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    Ok(u32::from_be_bytes(take_array(bytes, cursor)?))
}
fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    Ok(u64::from_be_bytes(take_array(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> JobIdentity {
        JobIdentity {
            job_id: JobId::from_bytes([1; 16]),
            profile_id: ProfileId::from_bytes([2; 16]),
            profile_generation: 3,
            policy_digest: Digest32::from_bytes([4; 32]),
            input_digest: Digest32::from_bytes([5; 32]),
        }
    }

    fn deadlines() -> JobDeadlines {
        JobDeadlines {
            remote_unix_ms: 2_000,
            relay_unix_ms: 3_000,
            result_retention_unix_ms: 4_000,
        }
    }

    fn receipt(token: &Secret32) -> AuthenticatedReceipt {
        AuthenticatedReceipt::issue(
            ReceiptBody {
                identity: identity(),
                run_as_uid: 1000,
                deadlines: deadlines(),
                max_output_bytes: 100,
                stdout_digest: Digest32::from_bytes([6; 32]),
                stderr_digest: Digest32::from_bytes([7; 32]),
                outcome: ReceiptOutcome::Exited(0),
                completed_unix_ms: 1_900,
            },
            token,
        )
        .unwrap()
    }

    #[test]
    fn deadlines_are_ordered_and_retention_is_bounded() {
        deadlines().validate_at(1_000).unwrap();
        assert!(JobDeadlines {
            remote_unix_ms: 3_000,
            relay_unix_ms: 2_000,
            result_retention_unix_ms: 4_000,
        }
        .validate_at(1_000)
        .is_err());
        assert!(JobDeadlines {
            remote_unix_ms: 2_000,
            relay_unix_ms: MAX_RELAY_WINDOW_MS + 1_001,
            result_retention_unix_ms: MAX_RELAY_WINDOW_MS + 2_001,
        }
        .validate_at(1_000)
        .is_err());
        assert!(JobDeadlines {
            remote_unix_ms: 2_000,
            relay_unix_ms: 3_000,
            result_retention_unix_ms: MAX_RESULT_RETENTION_MS + 1_001,
        }
        .validate_at(1_000)
        .is_err());
    }

    #[test]
    fn heartbeat_progress_is_monotonic_and_bounded() {
        let mut record = JobRecord::submitted(identity(), deadlines(), 1000, 100, 1_000).unwrap();
        record.mark_running(1_001).unwrap();
        record
            .observe_heartbeat(
                &HeartbeatFrame {
                    job_id: identity().job_id,
                    ordinal: 1,
                    elapsed_ms: 10,
                    stdout_bytes: 25,
                    stderr_bytes: 0,
                },
                1_010,
            )
            .unwrap();
        assert!(record
            .observe_heartbeat(
                &HeartbeatFrame {
                    job_id: identity().job_id,
                    ordinal: 1,
                    elapsed_ms: 11,
                    stdout_bytes: 26,
                    stderr_bytes: 0,
                },
                1_011,
            )
            .is_err());
        assert!(record
            .observe_heartbeat(
                &HeartbeatFrame {
                    job_id: identity().job_id,
                    ordinal: 2,
                    elapsed_ms: 12,
                    stdout_bytes: 101,
                    stderr_bytes: 0,
                },
                1_012,
            )
            .is_err());
    }

    #[test]
    fn receipt_detects_tampering_and_token_mismatch() {
        let token = Secret32::new([8; 32]);
        let encoded = receipt(&token).encode();
        let decoded = AuthenticatedReceipt::decode(&encoded).unwrap();
        decoded
            .verify(&identity(), deadlines(), 1000, 100, &token, 2_000)
            .unwrap();

        let other = Secret32::new([9; 32]);
        assert!(decoded
            .verify(&identity(), deadlines(), 1000, 100, &other, 2_000)
            .is_err());

        let mut tampered = encoded;
        tampered[70] ^= 1;
        let tampered = AuthenticatedReceipt::decode(&tampered).unwrap();
        assert!(tampered
            .verify(&identity(), deadlines(), 1000, 100, &token, 2_000)
            .is_err());
    }

    #[test]
    fn quarter_progress_interruption_stays_unknown_until_proven() {
        let token = Secret32::new([8; 32]);
        let mut record = JobRecord::submitted(identity(), deadlines(), 1000, 100, 1_000).unwrap();
        record.mark_running(1_001).unwrap();
        record
            .observe_heartbeat(
                &HeartbeatFrame {
                    job_id: identity().job_id,
                    ordinal: 1,
                    elapsed_ms: 100,
                    stdout_bytes: 25,
                    stderr_bytes: 0,
                },
                1_100,
            )
            .unwrap();
        assert!(matches!(
            reconcile(record.clone(), None, &token, 1_200).unwrap(),
            ReconcileOutcome::Unknown(JobRecord {
                stage: JobStage::Unknown,
                stdout_bytes: 25,
                ..
            })
        ));

        let receipt_bytes = receipt(&token).encode();
        assert!(matches!(
            reconcile(record, Some(&receipt_bytes), &token, 2_000).unwrap(),
            ReconcileOutcome::Recovered {
                record: JobRecord {
                    stage: JobStage::Completed,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn terminal_journal_without_receipt_is_still_unknown() {
        let token = Secret32::new([8; 32]);
        let mut record = JobRecord::submitted(identity(), deadlines(), 1000, 100, 1_000).unwrap();
        record.stage = JobStage::Completed;
        assert!(matches!(
            reconcile(record, None, &token, 1_100).unwrap(),
            ReconcileOutcome::Unknown(JobRecord {
                stage: JobStage::Unknown,
                ..
            })
        ));
    }

    #[test]
    fn receipt_rejects_identity_and_retention_mismatch() {
        let token = Secret32::new([8; 32]);
        let receipt = receipt(&token);
        let mut wrong = identity();
        wrong.profile_generation += 1;
        assert!(receipt
            .verify(&wrong, deadlines(), 1000, 100, &token, 2_000)
            .is_err());
        assert!(receipt
            .verify(&identity(), deadlines(), 1000, 100, &token, 4_001)
            .is_err());
    }

    #[test]
    fn receipt_authenticates_execution_uid_deadlines_and_output_budget() {
        let token = Secret32::new([8; 32]);
        let original_receipt = receipt(&token);
        assert!(original_receipt
            .verify(&identity(), deadlines(), 1001, 100, &token, 2_000)
            .is_err());
        let mut changed_deadlines = deadlines();
        changed_deadlines.relay_unix_ms += 1;
        assert!(original_receipt
            .verify(&identity(), changed_deadlines, 1000, 100, &token, 2_000,)
            .is_err());
        assert!(original_receipt
            .verify(&identity(), deadlines(), 1000, 101, &token, 2_000)
            .is_err());

        // Even if an attacker changes both an untrusted journal expectation
        // and the decoded receipt field to the same value, the original MAC
        // cannot authenticate the altered execution constraints.
        let mut altered_uid = receipt(&token);
        altered_uid.body.run_as_uid = 1001;
        assert!(altered_uid
            .verify(&identity(), deadlines(), 1001, 100, &token, 2_000)
            .is_err());

        let mut altered_deadlines = receipt(&token);
        altered_deadlines.body.deadlines.relay_unix_ms += 1;
        let altered_expected_deadlines = altered_deadlines.body.deadlines;
        assert!(altered_deadlines
            .verify(
                &identity(),
                altered_expected_deadlines,
                1000,
                100,
                &token,
                2_000,
            )
            .is_err());

        let mut altered_budget = receipt(&token);
        altered_budget.body.max_output_bytes = 101;
        assert!(altered_budget
            .verify(&identity(), deadlines(), 1000, 101, &token, 2_000)
            .is_err());
    }

    #[test]
    fn journal_schema_rejects_unknown_fields_and_bad_lengths() {
        let record = JobRecord::submitted(identity(), deadlines(), 1000, 100, 1_000).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&encode_journal(&record).unwrap()).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(decode_journal(&serde_json::to_vec(&value).unwrap()).is_err());
        value.as_object_mut().unwrap().remove("extra");
        value["job_id"] = serde_json::json!("00");
        assert!(decode_journal(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_persistence_fails_closed() {
        let store = JobStore::new(std::env::temp_dir().join("serctl-jobs-test")).unwrap();
        let record = JobRecord::submitted(identity(), deadlines(), 1000, 100, 1_000).unwrap();
        let error = store.create_journal(&record).unwrap_err().to_string();
        assert!(error.contains("supported only by the Linux remote helper"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receipt_is_create_new_and_journal_update_is_atomic() {
        assert!(owner_matches_current(1000, 1000));
        assert!(!owner_matches_current(1001, 1000));
        let root = std::env::temp_dir().join(format!("serctl-jobs-{}", JobId::random()));
        let store = JobStore::new(&root).unwrap();
        let mut record = JobRecord::submitted(identity(), deadlines(), 1000, 100, 1_000).unwrap();
        store.create_journal(&record).unwrap();
        record.mark_running(1_001).unwrap();
        store.update_journal(&record).unwrap();
        assert_eq!(store.load_journal(identity().job_id).unwrap(), record);
        let token = Secret32::new([8; 32]);
        let receipt = receipt(&token);
        store.persist_receipt(&receipt).unwrap();
        assert!(store.persist_receipt(&receipt).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
