//! IPC client for exec / shell / status / down against the global daemon,
//! plus the OperationGrant issuance and agent stdio gateway.
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crossterm::{
    event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant as StdInstant};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use serctl_core::security;
use serctl_core::ssh::{
    validate_remote_command, validate_remote_path, validate_shell_dimensions,
    validate_upload_remote_path, CreateDirOutcomeUnknown, CreateDirSubmissionState,
    ExecOutcomeUnknown, ExecSubmissionState, RemoteEntry, MAX_TRANSFER_BYTES,
};
use serctl_core::vault::{self, now_unix};
use serctl_protocol as ipc;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};

pub use serctl_core::ssh::{TunnelMode, TunnelReady, TunnelSpec};

const IPC_SHELL_SETUP_TIMEOUT: Duration = Duration::from_secs(32);
const SHELL_INPUT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const SHELL_OUTPUT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const SHELL_EVENT_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const STDIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
const STDIN_SEND_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const CONTROL_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);
// Daemon shutdown may spend four seconds draining handlers followed by up to
// two seconds each on transport and runtime-lock cleanup. Keep two seconds of
// scheduling margin so an acknowledged, healthy shutdown is not misreported.
const DAEMON_LOCK_RELEASE_TIMEOUT: Duration = Duration::from_secs(10);
const IPC_TUNNEL_SETUP_TIMEOUT: Duration = Duration::from_secs(32);
const TUNNEL_CONTROL_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
// Daemon-routed cancellation can spend up to 2 seconds writing TunnelStop
// and then 4 seconds waiting for the daemon's bounded SSH cleanup response.
// Leave scheduling margin before aborting the client worker.
const GUI_TUNNEL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(7);
const GUI_TUNNEL_ABORT_JOIN_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_UPLOAD_CHUNK_BYTES: usize = 64 * 1024;
const MAX_SHELL_INPUT_BYTES: usize = 64 * 1024;
const LOCAL_PARTIAL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const LOCAL_PARTIAL_CLEANUP_JOIN_MARGIN: Duration = Duration::from_millis(100);
const LOCAL_COMMIT_TIMEOUT: Duration = Duration::from_secs(1);
const LOCAL_COMMIT_RECONCILE_TIMEOUT: Duration = Duration::from_secs(2);
const REMOTE_COMMIT_RECONCILE_TIMEOUT: Duration = Duration::from_millis(2250);
const MAX_AGENT_GRANT_BYTES: usize = 64 * 1024;
const MAX_AGENT_REQUEST_LINE_BYTES: usize = 1024 * 1024;
const AGENT_TRANSFER_WRITE_OPERATION: &str = "transfer.write";
const DOWNLOAD_DURABLE_WINDOW_BYTES: u64 = 8 * 1024 * 1024;
const TRANSFER_JOURNAL_SCHEMA: u8 = 1;
const MAX_TRANSFER_JOURNAL_BYTES: u64 = 64 * 1024;

pub type TransferProgressSink = Arc<dyn Fn(ipc::TransferProgress) + Send + Sync + 'static>;

#[derive(Clone)]
pub struct TransferOptions {
    pub backend: ipc::TransferBackend,
    pub resume: ipc::TransferResumeMode,
    pub idle_timeout: Duration,
    pub deadline: Option<Duration>,
    pub progress: Option<TransferProgressSink>,
}

impl TransferOptions {
    fn legacy(timeout: Duration) -> Self {
        Self {
            backend: ipc::TransferBackend::Sftp,
            resume: ipc::TransferResumeMode::Never,
            idle_timeout: timeout,
            deadline: Some(timeout),
            progress: None,
        }
    }

    fn request_bound(&self) -> Duration {
        self.deadline
            .unwrap_or(serctl_protocol::v6::CREDENTIAL_LEASE_TTL)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UploadTransferJournal {
    schema: u8,
    transfer_id: String,
    profile_name: String,
    profile_id: String,
    profile_generation: u64,
    direction: ipc::TransferDirection,
    remote_target: String,
    size: u64,
    sha256: String,
    backend: ipc::TransferBackend,
    resume_token: String,
    durable_offset: u64,
}

impl Drop for UploadTransferJournal {
    fn drop(&mut self) {
        self.profile_name.zeroize();
        self.profile_id.zeroize();
        self.remote_target.zeroize();
        self.sha256.zeroize();
        self.resume_token.zeroize();
    }
}

struct UploadResumeJournal {
    path: PathBuf,
    state: StdMutex<UploadTransferJournal>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DownloadTransferJournal {
    schema: u8,
    transfer_id: String,
    profile_name: String,
    profile_id: String,
    profile_generation: u64,
    direction: ipc::TransferDirection,
    remote_source: String,
    local_target: String,
    partial_path: String,
    expected_size: Option<u64>,
    expected_sha256: Option<String>,
    backend: ipc::TransferBackend,
    durable_offset: u64,
}

impl Drop for DownloadTransferJournal {
    fn drop(&mut self) {
        self.profile_name.zeroize();
        self.profile_id.zeroize();
        self.remote_source.zeroize();
        self.local_target.zeroize();
        self.partial_path.zeroize();
        self.expected_sha256.zeroize();
    }
}

struct DownloadResumeJournal {
    path: PathBuf,
    state: StdMutex<DownloadTransferJournal>,
}

struct DownloadResumeSnapshot {
    transfer_id: ipc::TransferId,
    partial_path: PathBuf,
    durable_offset: u64,
    expected_size: Option<u64>,
    expected_sha256: Option<String>,
}

impl DownloadResumeJournal {
    fn snapshot(&self) -> Result<DownloadResumeSnapshot> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("download journal lock is poisoned"))?;
        Ok(DownloadResumeSnapshot {
            transfer_id: ipc::TransferId::parse(&state.transfer_id)?,
            partial_path: PathBuf::from(&state.partial_path),
            durable_offset: state.durable_offset,
            expected_size: state.expected_size,
            expected_sha256: state.expected_sha256.clone(),
        })
    }

    fn record_remote_identity(&self, size: u64, sha256: &str) -> Result<()> {
        ensure!(
            sha256.len() == 64
                && sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "download journal received an invalid SHA-256"
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("download journal lock is poisoned"))?;
        match (&state.expected_size, &state.expected_sha256) {
            (None, None) => {
                state.expected_size = Some(size);
                state.expected_sha256 = Some(sha256.to_owned());
                persist_download_journal(&self.path, &state)?;
            }
            (Some(expected_size), Some(expected_sha256)) => {
                ensure!(
                    *expected_size == size && expected_sha256 == sha256,
                    "remote source identity changed since the download journal was written"
                );
            }
            _ => bail!("download journal carries incomplete remote identity"),
        }
        Ok(())
    }

    fn record_durable(&self, offset: u64) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("download journal lock is poisoned"))?;
        let size = state
            .expected_size
            .context("download journal has no remote size")?;
        ensure!(
            offset <= size,
            "download durable offset exceeds remote size"
        );
        ensure!(
            offset >= state.durable_offset,
            "download durable offset moved backwards"
        );
        if offset > state.durable_offset {
            state.durable_offset = offset;
            persist_download_journal(&self.path, &state)?;
        }
        Ok(())
    }

    fn remove(self: &Arc<Self>) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("remove completed download journal"),
        }
    }
}

fn persist_download_journal(path: &Path, journal: &DownloadTransferJournal) -> Result<()> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(journal).context("serialize protected download journal")?,
    );
    ensure!(
        bytes.len() as u64 <= MAX_TRANSFER_JOURNAL_BYTES,
        "download journal exceeds its size cap"
    );
    security::write_protected_atomic(path, &bytes)
        .with_context(|| format!("persist download journal {}", path.display()))
}

fn prepare_download_resume_journal(
    profile: &ipc::WireProfile,
    remote: &str,
    local: &Path,
    backend: ipc::TransferBackend,
    new_transfer_id: &ipc::TransferId,
) -> Result<Arc<DownloadResumeJournal>> {
    let directory = vault::dir()?.join("transfers");
    prepare_download_resume_journal_in(&directory, profile, remote, local, backend, new_transfer_id)
}

fn prepare_download_resume_journal_in(
    directory: &Path,
    profile: &ipc::WireProfile,
    remote: &str,
    local: &Path,
    backend: ipc::TransferBackend,
    new_transfer_id: &ipc::TransferId,
) -> Result<Arc<DownloadResumeJournal>> {
    ensure!(
        matches!(
            backend,
            ipc::TransferBackend::Auto | ipc::TransferBackend::Native
        ),
        "resume=auto requires backend auto or native"
    );
    let local_text = local
        .to_str()
        .context("resume=auto requires a Unicode local destination path")?;
    std::fs::create_dir_all(directory).context("create protected transfer journal directory")?;
    security::harden_directory(directory)?;
    let mut key = Sha256::new();
    key.update(b"serctl/download-journal/v1\0");
    key.update(profile.profile_id.as_bytes());
    key.update(profile.generation.to_be_bytes());
    key.update(remote.as_bytes());
    key.update(local_text.as_bytes());
    let path = directory.join(format!("{}.json", hex::encode(key.finalize())));
    let journal = if let Some(file) = security::open_existing_protected_file(&path)? {
        let length = file.metadata()?.len();
        ensure!(
            (1..=MAX_TRANSFER_JOURNAL_BYTES).contains(&length),
            "download journal is empty or too large"
        );
        let mut bytes = Zeroizing::new(Vec::with_capacity(length as usize));
        file.take(MAX_TRANSFER_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == length,
            "download journal changed while reading"
        );
        let journal: DownloadTransferJournal =
            serde_json::from_slice(&bytes).context("parse protected download journal")?;
        ensure!(
            journal.schema == TRANSFER_JOURNAL_SCHEMA,
            "unsupported download journal schema"
        );
        ipc::TransferId::parse(&journal.transfer_id)?;
        ensure!(
            journal.profile_name == profile.name,
            "download journal profile name mismatch"
        );
        ensure!(
            journal.profile_id == profile.profile_id,
            "download journal profile id mismatch"
        );
        ensure!(
            journal.profile_generation == profile.generation,
            "download journal profile generation mismatch"
        );
        ensure!(
            journal.direction == ipc::TransferDirection::Pull,
            "download journal direction mismatch"
        );
        ensure!(
            journal.remote_source == remote,
            "download journal source mismatch"
        );
        ensure!(
            journal.local_target == local_text,
            "download journal target mismatch"
        );
        ensure!(
            journal.backend == backend,
            "download journal backend mismatch"
        );
        ensure!(
            journal.expected_size.is_some() == journal.expected_sha256.is_some(),
            "download journal remote identity is incomplete"
        );
        if let Some(size) = journal.expected_size {
            ensure!(
                journal.durable_offset <= size,
                "download journal durable offset exceeds remote size"
            );
        } else {
            ensure!(
                journal.durable_offset == 0,
                "download journal without identity has a durable prefix"
            );
        }
        journal
    } else {
        let mut partial = local.as_os_str().to_os_string();
        partial.push(format!(".serctl-resume-{}", new_transfer_id.as_str()));
        let partial_path = PathBuf::from(partial);
        let partial_text = partial_path
            .to_str()
            .context("resume=auto requires a Unicode partial path")?;
        let journal = DownloadTransferJournal {
            schema: TRANSFER_JOURNAL_SCHEMA,
            transfer_id: new_transfer_id.as_str().to_owned(),
            profile_name: profile.name.clone(),
            profile_id: profile.profile_id.clone(),
            profile_generation: profile.generation,
            direction: ipc::TransferDirection::Pull,
            remote_source: remote.to_owned(),
            local_target: local_text.to_owned(),
            partial_path: partial_text.to_owned(),
            expected_size: None,
            expected_sha256: None,
            backend,
            durable_offset: 0,
        };
        persist_download_journal(&path, &journal)?;
        journal
    };
    Ok(Arc::new(DownloadResumeJournal {
        path,
        state: StdMutex::new(journal),
    }))
}

impl UploadResumeJournal {
    fn transfer_id(&self) -> Result<ipc::TransferId> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("transfer journal lock is poisoned"))?;
        ipc::TransferId::parse(&state.transfer_id)
    }

    fn resume_token(&self) -> Result<Zeroizing<String>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("transfer journal lock is poisoned"))?;
        Ok(Zeroizing::new(state.resume_token.clone()))
    }

    fn durable_offset(&self) -> Result<u64> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("transfer journal lock is poisoned"))?;
        Ok(state.durable_offset)
    }

    fn observe(&self, progress: &ipc::TransferProgress) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("transfer journal lock is poisoned"))?;
        ensure!(
            progress.transfer_id.as_str() == state.transfer_id,
            "daemon progress names a different transfer than its journal"
        );
        ensure!(
            progress.durable_bytes <= state.size,
            "daemon durable offset exceeds the journaled source size"
        );
        if progress.durable_bytes > state.durable_offset {
            state.durable_offset = progress.durable_bytes;
            persist_upload_journal(&self.path, &state)?;
        }
        Ok(())
    }

    fn remove(self: &Arc<Self>) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("remove completed transfer journal"),
        }
    }
}

fn persist_upload_journal(path: &Path, journal: &UploadTransferJournal) -> Result<()> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(journal).context("serialize protected transfer journal")?,
    );
    ensure!(
        bytes.len() as u64 <= MAX_TRANSFER_JOURNAL_BYTES,
        "transfer journal exceeds its size cap"
    );
    security::write_protected_atomic(path, &bytes)
        .with_context(|| format!("persist transfer journal {}", path.display()))
}

fn prepare_upload_resume_journal(
    profile: &ipc::WireProfile,
    remote: &str,
    size: u64,
    sha256: &str,
    backend: ipc::TransferBackend,
    new_transfer_id: &ipc::TransferId,
) -> Result<Arc<UploadResumeJournal>> {
    let directory = vault::dir()?.join("transfers");
    prepare_upload_resume_journal_in(
        &directory,
        profile,
        remote,
        size,
        sha256,
        backend,
        new_transfer_id,
    )
}

fn prepare_upload_resume_journal_in(
    directory: &Path,
    profile: &ipc::WireProfile,
    remote: &str,
    size: u64,
    sha256: &str,
    backend: ipc::TransferBackend,
    new_transfer_id: &ipc::TransferId,
) -> Result<Arc<UploadResumeJournal>> {
    ensure!(
        matches!(
            backend,
            ipc::TransferBackend::Auto | ipc::TransferBackend::Native
        ),
        "resume=auto requires backend auto or native"
    );
    std::fs::create_dir_all(directory).context("create protected transfer journal directory")?;
    security::harden_directory(directory)?;
    let mut key = Sha256::new();
    key.update(b"serctl/upload-journal/v1\0");
    key.update(profile.profile_id.as_bytes());
    key.update(profile.generation.to_be_bytes());
    key.update(remote.as_bytes());
    key.update(size.to_be_bytes());
    key.update(sha256.as_bytes());
    let path = directory.join(format!("{}.json", hex::encode(key.finalize())));

    let expected = |journal: &UploadTransferJournal| -> Result<()> {
        ensure!(
            journal.schema == TRANSFER_JOURNAL_SCHEMA,
            "unsupported transfer journal schema"
        );
        ipc::TransferId::parse(&journal.transfer_id)?;
        ensure!(
            journal.profile_name == profile.name,
            "transfer journal profile name mismatch"
        );
        ensure!(
            journal.profile_id == profile.profile_id,
            "transfer journal profile id mismatch"
        );
        ensure!(
            journal.profile_generation == profile.generation,
            "transfer journal profile generation mismatch"
        );
        ensure!(
            journal.direction == ipc::TransferDirection::Push,
            "transfer journal direction mismatch"
        );
        ensure!(
            journal.remote_target == remote,
            "transfer journal target mismatch"
        );
        ensure!(journal.size == size, "transfer journal size mismatch");
        ensure!(
            journal.sha256 == sha256,
            "transfer journal SHA-256 mismatch"
        );
        ensure!(
            journal.backend == backend,
            "transfer journal backend mismatch"
        );
        ensure!(
            journal.resume_token.len() == 64
                && journal
                    .resume_token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "transfer journal resume token is invalid"
        );
        ensure!(
            journal.durable_offset <= size,
            "transfer journal durable offset exceeds source size"
        );
        Ok(())
    };

    let journal = if let Some(file) = security::open_existing_protected_file(&path)? {
        let length = file.metadata()?.len();
        ensure!(
            (1..=MAX_TRANSFER_JOURNAL_BYTES).contains(&length),
            "transfer journal is empty or too large"
        );
        let mut bytes = Zeroizing::new(Vec::with_capacity(length as usize));
        file.take(MAX_TRANSFER_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == length,
            "transfer journal changed while reading"
        );
        let journal: UploadTransferJournal =
            serde_json::from_slice(&bytes).context("parse protected transfer journal")?;
        expected(&journal)?;
        journal
    } else {
        let mut token = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(&mut *token);
        let journal = UploadTransferJournal {
            schema: TRANSFER_JOURNAL_SCHEMA,
            transfer_id: new_transfer_id.as_str().to_owned(),
            profile_name: profile.name.clone(),
            profile_id: profile.profile_id.clone(),
            profile_generation: profile.generation,
            direction: ipc::TransferDirection::Push,
            remote_target: remote.to_owned(),
            size,
            sha256: sha256.to_owned(),
            backend,
            resume_token: hex::encode(*token),
            durable_offset: 0,
        };
        persist_upload_journal(&path, &journal)?;
        journal
    };
    Ok(Arc::new(UploadResumeJournal {
        path,
        state: StdMutex::new(journal),
    }))
}

struct TransferRateTracker {
    started: StdInstant,
    last_advanced: StdInstant,
    baseline_confirmed: u64,
    last_confirmed: u64,
    observations: VecDeque<(StdInstant, u64)>,
}

impl TransferRateTracker {
    fn new(now: StdInstant) -> Self {
        let mut observations = VecDeque::new();
        observations.push_back((now, 0));
        Self {
            started: now,
            last_advanced: now,
            baseline_confirmed: 0,
            last_confirmed: 0,
            observations,
        }
    }

    fn enrich(
        &mut self,
        mut progress: ipc::TransferProgress,
        now: StdInstant,
    ) -> Result<ipc::TransferProgress> {
        progress.validate()?;
        if progress.event == "resumed" {
            self.started = now;
            self.last_advanced = now;
            self.baseline_confirmed = progress.confirmed_bytes;
            self.last_confirmed = progress.confirmed_bytes;
            self.observations.clear();
            self.observations.push_back((now, progress.confirmed_bytes));
        }
        ensure!(
            progress.confirmed_bytes >= self.last_confirmed,
            "transfer confirmation moved backwards"
        );
        if progress.confirmed_bytes > self.last_confirmed {
            self.last_advanced = now;
            self.last_confirmed = progress.confirmed_bytes;
            self.observations.push_back((now, progress.confirmed_bytes));
        }
        while self.observations.len() > 1
            && now.duration_since(self.observations[1].0) >= Duration::from_secs(3)
        {
            self.observations.pop_front();
        }
        let (window_started, window_bytes) = self
            .observations
            .front()
            .copied()
            .unwrap_or((now, progress.confirmed_bytes));
        let window_elapsed = now.duration_since(window_started).as_secs_f64();
        progress.window_bps = if window_elapsed > 0.0 {
            progress.confirmed_bytes.saturating_sub(window_bytes) as f64 / window_elapsed
        } else {
            0.0
        };
        if now.duration_since(self.last_advanced) >= Duration::from_secs(3) {
            progress.window_bps = 0.0;
        }
        let elapsed = now.duration_since(self.started).as_secs_f64();
        progress.average_bps = if elapsed > 0.0 {
            progress
                .confirmed_bytes
                .saturating_sub(self.baseline_confirmed) as f64
                / elapsed
        } else {
            0.0
        };
        progress.eta_ms = if progress.window_bps > 0.0 {
            Some(
                ((progress
                    .total_bytes
                    .saturating_sub(progress.confirmed_bytes) as f64
                    / progress.window_bps)
                    * 1000.0)
                    .min(u64::MAX as f64) as u64,
            )
        } else {
            None
        };
        progress.validate()?;
        Ok(progress)
    }
}

fn emit_transfer_progress(
    tracker: &mut TransferRateTracker,
    sink: Option<&TransferProgressSink>,
    progress: ipc::TransferProgress,
) -> Result<()> {
    let progress = tracker.enrich(progress, StdInstant::now())?;
    if let Some(sink) = sink {
        sink(progress);
    }
    Ok(())
}

#[derive(Debug)]
struct ShutdownRejected(String);

impl std::fmt::Display for ShutdownRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ShutdownRejected {}

fn terminal_safe_field(value: &str) -> String {
    value.escape_debug().to_string()
}

fn terminal_safe_display(value: &(impl std::fmt::Display + ?Sized)) -> String {
    terminal_safe_field(&value.to_string())
}

fn terminal_safe_error(error: &anyhow::Error) -> String {
    terminal_safe_field(&format!("{error:#}"))
}

struct RawModeGuard<F: FnOnce()> {
    restore: Option<F>,
}

impl<F: FnOnce()> RawModeGuard<F> {
    fn new(restore: F) -> Self {
        Self {
            restore: Some(restore),
        }
    }
}

impl<F: FnOnce()> Drop for RawModeGuard<F> {
    fn drop(&mut self) {
        if let Some(restore) = self.restore.take() {
            restore();
        }
    }
}

fn enter_raw_mode_with<E, F>(enable: E, restore: F) -> Result<RawModeGuard<F>>
where
    E: FnOnce() -> io::Result<()>,
    F: FnOnce(),
{
    enable()?;
    Ok(RawModeGuard::new(restore))
}

fn restore_raw_mode() {
    let _ = disable_raw_mode();
}

fn enter_raw_mode() -> Result<RawModeGuard<fn()>> {
    enter_raw_mode_with(enable_raw_mode, restore_raw_mode as fn())
}

#[derive(Clone, Debug)]
pub struct DaemonStatus {
    pub profile: String,
    pub host: String,
    pub user: String,
    pub started_unix: i64,
    pub endpoint: String,
}

fn daemon_status_line(info: &DaemonStatus, now: i64) -> String {
    let up = elapsed_nonnegative_seconds(now, info.started_unix);
    format!(
        "daemon: ACTIVE  profile={}  {} as {}  uptime={up}s  ipc={}:{}",
        terminal_safe_field(&info.profile),
        terminal_safe_field(&info.host),
        terminal_safe_field(&info.user),
        terminal_safe_field(ipc::endpoint_kind()),
        terminal_safe_field(&info.endpoint),
    )
}

fn daemon_absent_line(profile: &str) -> String {
    format!(
        "daemon: not running for profile '{}'",
        terminal_safe_field(profile)
    )
}

fn daemon_down_line(profile: &str, stopped: bool) -> String {
    if stopped {
        "daemon stopped".to_owned()
    } else {
        format!(
            "no running daemon for '{}' (stale lock cleared)",
            terminal_safe_field(profile)
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<i32>,
}

#[derive(Debug)]
struct DaemonExecRejected(String);

impl std::fmt::Display for DaemonExecRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DaemonExecRejected {}

impl Drop for CommandOutput {
    fn drop(&mut self) {
        // Command output can contain credentials or server evidence. Keep the
        // cleanup invariant at the producer type so UI event-send failures,
        // stale reducer messages, early returns, and future consumers do not
        // have to remember a separate manual zeroization path.
        self.stdout.zeroize();
        self.stderr.zeroize();
    }
}

#[derive(Debug)]
pub enum ShellEvent {
    Output(Zeroizing<Vec<u8>>),
    Closed,
    Error(String),
}

impl ShellEvent {
    fn zeroize_sensitive(&mut self) {
        match self {
            Self::Output(data) => data.zeroize(),
            Self::Error(error) => error.zeroize(),
            Self::Closed => {}
        }
    }
}

fn try_send_shell_event(sender: &mpsc::Sender<ShellEvent>, event: ShellEvent) {
    if let Err(error) = sender.try_send(event) {
        let mut rejected = error.into_inner();
        rejected.zeroize_sensitive();
    }
}

pub struct GuiShell {
    pub input: mpsc::Sender<Zeroizing<Vec<u8>>>,
    pub events: mpsc::Receiver<ShellEvent>,
    pub cancellation: CancellationToken,
}

impl GuiShell {
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
}

impl Drop for GuiShell {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.events.close();
        while let Ok(mut event) = self.events.try_recv() {
            event.zeroize_sensitive();
        }
    }
}

#[derive(Debug)]
pub enum TunnelEvent {
    Ready { bind_host: String, bind_port: u16 },
    Error(String),
    Closed,
}

impl TunnelEvent {
    fn zeroize_sensitive(&mut self) {
        match self {
            Self::Ready { bind_host, .. } => bind_host.zeroize(),
            Self::Error(error) => error.zeroize(),
            Self::Closed => {}
        }
    }
}

fn try_send_tunnel_event(sender: &mpsc::Sender<TunnelEvent>, event: TunnelEvent) {
    if let Err(error) = sender.try_send(event) {
        let mut rejected = error.into_inner();
        rejected.zeroize_sensitive();
    }
}

/// A GUI-friendly tunnel lease. The initial bind address is available
/// synchronously after setup; later connection-count, error, and closure
/// notifications arrive through `events`. Dropping or cancelling the lease
/// closes its daemon control stream or direct SSH forwarding task.
pub struct GuiTunnel {
    ready: TunnelReady,
    pub events: mpsc::Receiver<TunnelEvent>,
    cancellation: CancellationToken,
    worker: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl GuiTunnel {
    pub fn ready(&self) -> &TunnelReady {
        &self.ready
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub async fn wait(mut self) -> Result<()> {
        let mut worker = self.worker.take().context("tunnel worker is missing")?;
        if !self.cancellation.is_cancelled() {
            tokio::select! {
                result = &mut worker => return result.context("join tunnel worker")?,
                _ = self.cancellation.cancelled() => {}
            }
        }
        match tokio::time::timeout(GUI_TUNNEL_CLEANUP_TIMEOUT, &mut worker).await {
            Ok(result) => result.context("join tunnel worker")?,
            Err(_) => {
                worker.abort();
                let _ = tokio::time::timeout(GUI_TUNNEL_ABORT_JOIN_TIMEOUT, &mut worker).await;
                bail!("tunnel worker cleanup exceeded its deadline")
            }
        }
    }
}

impl Drop for GuiTunnel {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.events.close();
        while let Ok(mut event) = self.events.try_recv() {
            event.zeroize_sensitive();
        }
    }
}

struct DaemonConnection {
    stream: serctl_protocol::v6::V6ClientIo<ipc::ClientStream>,
    endpoint: String,
}

/// One mirrored credential lease, keyed by daemon instance and profile id.
type UnlockedProfileKey = (String, [u8; 16]);

struct CachedProfileAuthorization {
    call_key: Arc<Zeroizing<[u8; 32]>>,
    expires_at: tokio::time::Instant,
}

/// Process-local mirror of the daemon's credential lease: profiles already
/// unlocked against one daemon instance skip the unlock round trip. A daemon
/// restart changes the instance id, so a stale mirror can never suppress a
/// required unlock.
static UNLOCKED_PROFILES: std::sync::LazyLock<
    StdMutex<HashMap<UnlockedProfileKey, CachedProfileAuthorization>>,
> = std::sync::LazyLock::new(|| StdMutex::new(HashMap::new()));

/// One reachable global daemon instance, identified by its runtime descriptor.
#[derive(Clone)]
struct DaemonAccess {
    instance_id: serctl_protocol::v6::InstanceId,
    secret: serctl_protocol::v6::ActivationSecret,
    endpoint: String,
    pid: u32,
}

/// Whether a live daemon is currently published in the runtime descriptor.
pub fn daemon_is_published() -> Result<bool> {
    let Some(descriptor) = serctl_core::daemon_runtime::read_descriptor()? else {
        return Ok(false);
    };
    Ok(serctl_core::daemon_runtime::pid_is_alive(descriptor.pid))
}

/// Resolve the current daemon from the protected runtime descriptor/secret,
/// cleaning up stale state (dead PID) under the startup singleton. Returns
/// `None` when no live daemon is published.
async fn resolve_daemon_until(deadline: tokio::time::Instant) -> Result<Option<DaemonAccess>> {
    let read = || -> Result<Option<DaemonAccess>> {
        let Some(descriptor) = serctl_core::daemon_runtime::read_descriptor()? else {
            return Ok(None);
        };
        if !serctl_core::daemon_runtime::pid_is_alive(descriptor.pid) {
            if let serctl_core::daemon_runtime::StartupLockAcquire::Acquired(lock) =
                serctl_core::daemon_runtime::acquire_startup_lock()?
            {
                let _ = serctl_core::daemon_runtime::cleanup_stale_runtime_if_dead(&lock);
            }
            return Ok(None);
        }
        let Some(secret) = serctl_core::daemon_runtime::read_secret()? else {
            return Ok(None);
        };
        Ok(Some(DaemonAccess {
            instance_id: serctl_protocol::v6::InstanceId::from_hex(&descriptor.instance_id)?,
            secret,
            endpoint: descriptor.endpoint,
            pid: descriptor.pid,
        }))
    };
    join_blocking_until(
        tokio::task::spawn_blocking(read),
        deadline,
        "daemon runtime descriptor read",
    )
    .await
}

/// Resolve a live daemon, launching the global broker through the singleton
/// startup protocol when none is published.
async fn ensure_daemon_until(deadline: tokio::time::Instant) -> Result<DaemonAccess> {
    loop {
        if let Some(access) = resolve_daemon_until(deadline).await? {
            return Ok(access);
        }
        match serctl_core::daemon_runtime::acquire_startup_lock()? {
            serctl_core::daemon_runtime::StartupLockAcquire::Acquired(startup_lock) => {
                // The CLI lock is only an advisory launch-throttling hint.
                // The daemon owns authoritative arbitration and takes this
                // lock itself through listener publication. Never wait for a
                // child while holding it: that would deadlock the child.
                if let Some(access) = resolve_daemon_until(deadline).await? {
                    return Ok(access);
                }
                let (_instance, _secret) = crate::launcher::spawn_global_daemon()?;
                drop(startup_lock);
                return wait_for_published_daemon_until(deadline, || {
                    resolve_daemon_until(deadline)
                })
                .await;
            }
            serctl_core::daemon_runtime::StartupLockAcquire::Contended => {
                if tokio::time::Instant::now() >= deadline {
                    bail!("another daemon startup is in progress and exceeded its deadline");
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }
    }
}

/// Wait for any fully published daemon. A spawned candidate may lose daemon
/// arbitration to a sibling; the client must accept that verified winner
/// rather than wait only for its own instance id.
async fn wait_for_published_daemon_until<R, F>(
    deadline: tokio::time::Instant,
    mut resolve: R,
) -> Result<DaemonAccess>
where
    R: FnMut() -> F,
    F: Future<Output = Result<Option<DaemonAccess>>>,
{
    loop {
        if let Some(access) = resolve().await? {
            return Ok(access);
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("daemon did not publish its runtime descriptor in time");
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// Fetch the sanitized profile catalog and resolve one profile id.
async fn catalog_profile_until(
    access: &DaemonAccess,
    profile: &str,
    deadline: tokio::time::Instant,
) -> Result<ipc::WireProfile> {
    let prelude = v6_prelude(&ipc::Frame::ListProfiles, None, None, deadline)?;
    let connection = connect_v6_until(access, prelude, deadline).await?;
    let mut stream = connection.stream;
    ipc::write_frame_limited(
        &mut stream,
        &ipc::Frame::ListProfiles,
        ipc::MAX_REQUEST_FRAME,
    )
    .await?;
    let reply = ipc::read_frame_limited(&mut stream, ipc::MAX_RESPONSE_FRAME)
        .await?
        .context("daemon closed before returning the profile catalog")?;
    let ipc::Frame::ProfileList { profiles } = reply else {
        bail!("daemon returned an unexpected catalog response")
    };
    profiles
        .into_iter()
        .find(|entry| entry.name == profile)
        .with_context(|| format!("profile '{profile}' does not exist"))
}

async fn catalog_profile_id_until(
    access: &DaemonAccess,
    profile: &str,
    deadline: tokio::time::Instant,
) -> Result<[u8; 16]> {
    let found = catalog_profile_until(access, profile, deadline).await?;
    let bytes = hex::decode(&found.profile_id).context("catalog carries an invalid profile id")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("catalog profile id must decode to 16 bytes"))
}

/// Unlock one profile against the daemon, unless this process already holds a
/// mirror of the credential lease for this exact daemon instance.
async fn ensure_profile_unlocked(
    access: &DaemonAccess,
    profile: &str,
    master: &str,
    profile_id: [u8; 16],
    deadline: tokio::time::Instant,
) -> Result<Arc<Zeroizing<[u8; 32]>>> {
    let key = (access.instance_id.as_hex(), profile_id);
    if let Ok(mut unlocked) = UNLOCKED_PROFILES.lock() {
        let now = tokio::time::Instant::now();
        unlocked.retain(|_, cached| cached.expires_at > now);
        if unlocked.get(&key).is_some() {
            return Ok(Arc::clone(&unlocked[&key].call_key));
        }
    }
    // Start the frontend's mirror TTL before the daemon verifies the unlock,
    // making it conservatively no later than the daemon-held lease.
    let unlocked_at = tokio::time::Instant::now();
    let request = ipc::Frame::Unlock {
        passphrase: master.to_owned(),
    };
    let prelude = v6_prelude(&request, None, Some(profile.to_owned()), deadline)?;
    let connection = connect_v6_until(access, prelude, deadline).await?;
    let mut stream = connection.stream;
    ipc::write_frame_limited(&mut stream, &request, ipc::MAX_REQUEST_FRAME).await?;
    let reply = ipc::read_frame_limited(&mut stream, ipc::MAX_RESPONSE_FRAME)
        .await?
        .context("daemon closed before answering the unlock request")?;
    let mut encoded_call_key = match reply {
        ipc::Frame::ProfileAuthorized { call_key } => call_key,
        ipc::Frame::Error { msg } => bail!("{msg}"),
        mut other => {
            other.zeroize_sensitive();
            bail!("daemon returned an unexpected unlock response")
        }
    };
    let decoded = Zeroizing::new(
        B64.decode(&encoded_call_key)
            .context("decode daemon profile authorization key")?,
    );
    encoded_call_key.zeroize();
    let call_key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("daemon profile authorization key must decode to 32 bytes"))?;
    let call_key = Arc::new(Zeroizing::new(call_key));
    if let Ok(mut unlocked) = UNLOCKED_PROFILES.lock() {
        unlocked.insert(
            key,
            CachedProfileAuthorization {
                call_key: Arc::clone(&call_key),
                expires_at: unlocked_at + serctl_protocol::v6::CREDENTIAL_LEASE_TTL,
            },
        );
    }
    Ok(call_key)
}

/// Build a v6 request prelude for one root request.
fn v6_prelude(
    request: &ipc::Frame,
    profile_id: Option<[u8; 16]>,
    profile_name: Option<String>,
    deadline: tokio::time::Instant,
) -> Result<serctl_protocol::v6::V6RequestPrelude> {
    let _ = deadline; // deadline guards the caller's connect path, not the prelude
    let operation_kind = serctl_protocol::v6::frame_kind(request).to_owned();
    let root_request_hash = serctl_protocol::v6::root_request_hash(request)?;
    let mut client_session_id = [0_u8; 16];
    let mut request_id = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut client_session_id);
    rand::rngs::OsRng.fill_bytes(&mut request_id);
    Ok(serctl_protocol::v6::V6RequestPrelude {
        protocol_version: serctl_protocol::v6::IPC_PROTOCOL_VERSION_V6,
        client_session_id,
        request_id,
        operation_kind,
        profile_id,
        profile_name,
        grant_id: None,
        pop_signature: None,
        profile_proof: None,
        requested_deadline_unix_ms: 0,
        root_request_hash,
    })
}

/// Connect to the published endpoint, cross-check the peer PID against the
/// descriptor, and complete the v6 handshake for one root request.
async fn connect_v6_until(
    access: &DaemonAccess,
    prelude: serctl_protocol::v6::V6RequestPrelude,
    deadline: tokio::time::Instant,
) -> Result<DaemonConnection> {
    let stream = ipc::connect(&access.endpoint).await?;
    ipc::validate_server_identity(&stream, access.pid)?;
    let session = serctl_protocol::v6::v6_client_handshake(
        stream,
        &access.secret,
        access.instance_id,
        prelude,
        deadline,
    )
    .await?;
    Ok(DaemonConnection {
        stream: serctl_protocol::v6::V6ClientIo::new(session),
        endpoint: access.endpoint.clone(),
    })
}

/// Connect to the global daemon (launching it on demand) and authorize exactly
/// `request` through a v6 handshake with a prelude-bound root request. The
/// profile passphrase reaches the daemon only inside the AEAD channel during
/// the unlock step; a wrong passphrase therefore never reaches SSH.
async fn connect_daemon_for_request_until(
    profile: &str,
    master: &str,
    expected_generation: Option<vault::ProfileIdentity>,
    request: &ipc::Frame,
    request_deadline: tokio::time::Instant,
) -> Result<DaemonConnection> {
    let access = ensure_daemon_until(request_deadline).await?;
    let catalog = catalog_profile_until(&access, profile, request_deadline).await?;
    validate_expected_catalog_identity(&catalog, expected_generation)?;
    connect_authorized_catalog_request_until(
        &access,
        profile,
        master,
        &catalog,
        request,
        request_deadline,
    )
    .await
}

/// Authorize exactly `request` against one already-resolved daemon instance:
/// catalog lookup, cached unlock, prelude, and handshake.
async fn connect_authorized_request_until(
    access: &DaemonAccess,
    profile: &str,
    master: &str,
    request: &ipc::Frame,
    request_deadline: tokio::time::Instant,
) -> Result<DaemonConnection> {
    let catalog = catalog_profile_until(access, profile, request_deadline).await?;
    connect_authorized_catalog_request_until(
        access,
        profile,
        master,
        &catalog,
        request,
        request_deadline,
    )
    .await
}

fn wire_profile_id(profile: &ipc::WireProfile) -> Result<[u8; 16]> {
    let bytes =
        hex::decode(&profile.profile_id).context("catalog carries an invalid profile id")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("catalog profile id must decode to 16 bytes"))
}

fn validate_expected_catalog_identity(
    catalog: &ipc::WireProfile,
    expected: Option<vault::ProfileIdentity>,
) -> Result<()> {
    if let Some(expected) = expected {
        ensure!(
            wire_profile_id(catalog)? == expected.profile_id
                && catalog.generation == expected.generation,
            "profile changed after the operation was authorized"
        );
    }
    Ok(())
}

async fn connect_authorized_catalog_request_until(
    access: &DaemonAccess,
    profile: &str,
    master: &str,
    catalog: &ipc::WireProfile,
    request: &ipc::Frame,
    request_deadline: tokio::time::Instant,
) -> Result<DaemonConnection> {
    ensure!(catalog.name == profile, "catalog profile name mismatch");
    let profile_id = wire_profile_id(catalog)?;
    let call_key =
        ensure_profile_unlocked(access, profile, master, profile_id, request_deadline).await?;
    let mut prelude = v6_prelude(
        request,
        Some(profile_id),
        Some(profile.to_owned()),
        request_deadline,
    )?;
    prelude.profile_proof = Some(serctl_protocol::v6::profile_prelude_proof(
        call_key.as_ref(),
        &prelude,
    )?);
    connect_v6_until(access, prelude, request_deadline).await
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Agent-side grant file: the issued grant plus the agent's Ed25519 signing
/// seed. The seed never reaches the daemon; only the public key is bound into
/// the grant.
#[derive(Serialize, Deserialize)]
pub struct AgentGrantFile {
    pub grant: serctl_protocol::grant::OperationGrant,
    /// Base64 32-byte Ed25519 signing-key seed.
    pub agent_key: String,
}

/// Load and decode an agent grant file into the grant plus its signing key.
pub fn load_agent_grant(
    path: &Path,
) -> Result<(serctl_protocol::grant::OperationGrant, SigningKey)> {
    use std::io::Read as _;
    let mut handle =
        security::open_existing_protected_file(path)?.context("agent grant file does not exist")?;
    let mut bytes = Zeroizing::new(Vec::new());
    handle
        .by_ref()
        .take((MAX_AGENT_GRANT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read agent grant file")?;
    ensure!(
        bytes.len() <= MAX_AGENT_GRANT_BYTES,
        "agent grant file exceeds its 64 KiB safety limit"
    );
    let mut file: AgentGrantFile =
        serde_json::from_slice(&bytes).context("parse agent grant file")?;
    let agent_key = Zeroizing::new(std::mem::take(&mut file.agent_key));
    let decoded = Zeroizing::new(
        B64.decode(agent_key.as_bytes())
            .context("decode agent key seed")?,
    );
    let seed: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("agent key seed must decode to 32 bytes"))?;
    let seed = Zeroizing::new(seed);
    let key = SigningKey::from_bytes(&seed);
    file.grant
        .policy_ttl()
        .context("agent grant TTL violates the current policy")?;
    ensure!(
        key.verifying_key().to_bytes() == file.grant.holder_key,
        "agent grant key does not match its holder binding"
    );
    ensure!(
        !file.grant.is_expired(now_unix_ms()),
        "agent grant has expired"
    );
    Ok((file.grant, key))
}

/// Issue a default-lifetime grant for an agent frontend. The profile must be
/// unlocked first (the same unlock authorizes the issuance), and the grant
/// plus the agent's private key are written atomically to `output`.
#[cfg(test)]
pub async fn issue_grant_until(
    profile: &str,
    master: &str,
    operations: Vec<String>,
    budget: u32,
    output: &Path,
) -> Result<serctl_protocol::grant::OperationGrant> {
    issue_grant_with_ttl_until(
        profile,
        master,
        operations,
        budget,
        serctl_protocol::grant::GRANT_DEFAULT_TTL,
        output,
    )
    .await
}

/// Issue a grant with an explicit protocol-policy-bounded lifetime.
pub async fn issue_grant_with_ttl_until(
    profile: &str,
    master: &str,
    operations: Vec<String>,
    budget: u32,
    ttl: Duration,
    output: &Path,
) -> Result<serctl_protocol::grant::OperationGrant> {
    ensure!(
        (serctl_protocol::grant::GRANT_MIN_TTL..=serctl_protocol::grant::GRANT_MAX_TTL)
            .contains(&ttl)
            && ttl.subsec_nanos() == 0
            && ttl.as_secs().is_multiple_of(60),
        "grant TTL must be between {} and {} whole minutes",
        serctl_protocol::grant::GRANT_MIN_TTL.as_secs() / 60,
        serctl_protocol::grant::GRANT_MAX_TTL.as_secs() / 60
    );
    let ttl_secs = u32::try_from(ttl.as_secs()).context("grant TTL exceeds the wire range")?;
    let signing = SigningKey::generate(&mut OsRng);
    let holder_key = B64.encode(signing.verifying_key().to_bytes());
    let request = ipc::Frame::IssueGrant {
        profile: profile.to_owned(),
        operations: operations.clone(),
        budget,
        ttl_secs,
        holder_key,
    };
    let deadline = tokio::time::Instant::now() + CONTROL_EXCHANGE_TIMEOUT;
    let access = ensure_daemon_until(deadline).await?;
    let profile_id = catalog_profile_id_until(&access, profile, deadline).await?;
    let call_key = ensure_profile_unlocked(&access, profile, master, profile_id, deadline).await?;
    let mut prelude = v6_prelude(
        &request,
        Some(profile_id),
        Some(profile.to_owned()),
        deadline,
    )?;
    prelude.profile_proof = Some(serctl_protocol::v6::profile_prelude_proof(
        call_key.as_ref(),
        &prelude,
    )?);
    let connection = connect_v6_until(&access, prelude, deadline).await?;
    let mut stream = connection.stream;
    let reply = tokio::time::timeout_at(deadline, async {
        ipc::write_frame_limited(&mut stream, &request, ipc::MAX_REQUEST_FRAME).await?;
        ipc::read_frame_limited(&mut stream, ipc::MAX_RESPONSE_FRAME)
            .await?
            .context("daemon closed before answering the grant request")
    })
    .await
    .map_err(|_| anyhow!("grant issuance exceeded its deadline"))??;
    let (grant_id, issued_unix_ms, expires_unix_ms) = match reply {
        ipc::Frame::GrantIssued {
            grant_id,
            issued_unix_ms,
            expires_unix_ms,
        } => (grant_id, issued_unix_ms, expires_unix_ms),
        ipc::Frame::Error { msg } => bail!("{msg}"),
        mut other => {
            other.zeroize_sensitive();
            bail!("daemon returned an unexpected grant response")
        }
    };
    let grant_id_bytes: [u8; 16] = hex::decode(&grant_id)
        .context("daemon returned an invalid grant id")?
        .try_into()
        .map_err(|_| anyhow!("daemon grant id must decode to 16 bytes"))?;
    let grant = serctl_protocol::grant::OperationGrant {
        grant_id: grant_id_bytes,
        profile_name: profile.to_owned(),
        profile_id,
        operations,
        budget,
        issued_unix_ms,
        expires_unix_ms,
        holder_key: signing.verifying_key().to_bytes(),
    };
    ensure!(
        grant.policy_ttl()? == ttl,
        "daemon returned a grant with a different TTL"
    );
    let mut file = AgentGrantFile {
        grant: grant.clone(),
        agent_key: B64.encode(signing.to_bytes()),
    };
    let encoded = Zeroizing::new(serde_json::to_vec(&file).context("serialize agent grant file")?);
    file.agent_key.zeroize();
    write_agent_grant_file(output, &encoded)
        .with_context(|| format!("write agent grant file {}", output.display()))?;
    Ok(grant)
}

/// Write the agent grant file through a create-new handle protected at
/// creation time (0600 on Unix, explicit protected DACL on Windows). It never
/// overwrites an existing grant.
fn write_agent_grant_file(path: &Path, encoded: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut file = security::create_new_protected_file(path)
        .with_context(|| format!("create agent grant file {}", path.display()))?;
    file.write_all(encoded).context("write agent grant file")?;
    file.sync_all().context("sync agent grant file")?;
    Ok(())
}

/// Connect one grant-authorized root request: the prelude carries the grant
/// id, an absolute operation deadline bounded by the grant expiry, and the
/// agent's proof-of-possession signature.
async fn connect_grant_request_until(
    grant: &serctl_protocol::grant::OperationGrant,
    signing: &SigningKey,
    request: &ipc::Frame,
    op_timeout: Duration,
) -> Result<DaemonConnection> {
    let deadline_ms = now_unix_ms()
        .checked_add(
            u64::try_from(op_timeout.as_millis())
                .context("operation timeout exceeds u64 millis")?,
        )
        .context("operation deadline overflow")?;
    ensure!(
        deadline_ms < grant.expires_unix_ms,
        "operation would exceed the grant expiry"
    );
    let handshake_deadline = tokio::time::Instant::now() + CONTROL_EXCHANGE_TIMEOUT;
    let access = ensure_daemon_until(handshake_deadline).await?;
    let mut prelude = v6_prelude(
        request,
        None,
        Some(grant.profile_name.clone()),
        handshake_deadline,
    )?;
    prelude.grant_id = Some(grant.grant_id);
    prelude.requested_deadline_unix_ms = deadline_ms;
    prelude.pop_signature = Some(serctl_protocol::grant::sign_prelude_pop(signing, &prelude)?);
    connect_v6_until(&access, prelude, handshake_deadline).await
}

/// One request line of the agent stdio protocol.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum AgentRequest {
    Exec {
        request_id: u64,
        cmd: String,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    ListDir {
        request_id: u64,
        path: String,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    CreateDir {
        request_id: u64,
        path: String,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    TransferPush {
        request_id: u64,
        local: PathBuf,
        remote: String,
        #[serde(default)]
        backend: Option<ipc::TransferBackend>,
        #[serde(default)]
        resume: Option<ipc::TransferResumeMode>,
        #[serde(default)]
        idle_timeout_ms: Option<u64>,
        #[serde(default)]
        deadline_ms: Option<u64>,
    },
    Status {
        request_id: u64,
    },
}

#[derive(Debug)]
struct AgentTransferWriteScopeRequired;

impl std::fmt::Display for AgentTransferWriteScopeRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("grant does not authorize transfer.write")
    }
}

impl std::error::Error for AgentTransferWriteScopeRequired {}

fn require_agent_transfer_write_scope(
    grant: &serctl_protocol::grant::OperationGrant,
) -> Result<()> {
    if grant
        .operations
        .iter()
        .any(|operation| operation == AGENT_TRANSFER_WRITE_OPERATION)
    {
        Ok(())
    } else {
        Err(AgentTransferWriteScopeRequired.into())
    }
}

/// Agent JSON must not echo local paths, protected state locations, or lower
/// error-chain values that could eventually carry credentials. Scope rejection
/// is a stable, non-secret diagnostic; all other detail remains local only.
fn agent_visible_transfer_error(error: anyhow::Error) -> anyhow::Error {
    if error.is::<AgentTransferWriteScopeRequired>() {
        error
    } else {
        anyhow!("transfer-push failed (local diagnostic detail withheld)")
    }
}

/// One result line of the agent stdio protocol: the visible relay record.
#[derive(Serialize)]
struct AgentResultLine {
    request_id: u64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

/// The agent stdio gateway: JSONL requests on stdin, JSONL relay results on
/// stdout. Every relayed operation is authorized by the grant's budget and
/// scope and proven by its proof-of-possession signature.
pub async fn agent_stdio_loop(grant_path: &Path) -> Result<()> {
    agent_stdio_loop_with(tokio::io::stdin(), tokio::io::stdout(), grant_path).await
}

async fn agent_stdio_loop_with<R, W>(reader: R, writer: W, grant_path: &Path) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (grant, signing) = load_agent_grant(grant_path)?;
    let mut lines = tokio::io::BufReader::new(reader);
    let mut stdout = writer;
    while let Some(line) = read_bounded_agent_line(&mut lines).await? {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let result = match serde_json::from_slice::<AgentRequest>(&line) {
            Err(error) => AgentResultLine {
                request_id: 0,
                ok: false,
                error: Some(format!("invalid request: {error}")),
                data: None,
            },
            Ok(request) => dispatch_agent_request(&grant, &signing, request).await,
        };
        let mut encoded = serde_json::to_vec(&result).context("serialize agent result line")?;
        encoded.push(b'\n');
        stdout
            .write_all(&encoded)
            .await
            .context("write agent result line")?;
        stdout.flush().await.context("flush agent result line")?;
    }
    Ok(())
}

async fn read_bounded_agent_line<R>(reader: &mut R) -> Result<Option<Zeroizing<Vec<u8>>>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = Zeroizing::new(Vec::new());
    loop {
        let available = reader.fill_buf().await.context("read agent request line")?;
        if available.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        ensure!(
            line.len().saturating_add(consumed) <= MAX_AGENT_REQUEST_LINE_BYTES + 1,
            "agent request line exceeds its 1 MiB safety limit"
        );
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

async fn dispatch_agent_request(
    grant: &serctl_protocol::grant::OperationGrant,
    signing: &SigningKey,
    request: AgentRequest,
) -> AgentResultLine {
    let (request_id, outcome) = match request {
        AgentRequest::Exec {
            request_id,
            cmd,
            timeout_ms,
        } => (
            request_id,
            agent_exec_until(
                grant,
                signing,
                &cmd,
                timeout_ms.unwrap_or(ipc::DEFAULT_EXEC_TIMEOUT_MS),
            )
            .await,
        ),
        AgentRequest::ListDir {
            request_id,
            path,
            timeout_ms,
        } => (
            request_id,
            agent_list_until(
                grant,
                signing,
                &path,
                timeout_ms.unwrap_or(ipc::DEFAULT_SFTP_TIMEOUT_MS),
            )
            .await,
        ),
        AgentRequest::CreateDir {
            request_id,
            path,
            timeout_ms,
        } => (
            request_id,
            agent_create_dir_until(
                grant,
                signing,
                &path,
                timeout_ms.unwrap_or(ipc::DEFAULT_SFTP_TIMEOUT_MS),
            )
            .await,
        ),
        AgentRequest::TransferPush {
            request_id,
            local,
            remote,
            backend,
            resume,
            idle_timeout_ms,
            deadline_ms,
        } => {
            let outcome = agent_transfer_push_until(
                grant,
                signing,
                &local,
                &remote,
                TransferOptions {
                    backend: backend.unwrap_or(ipc::TransferBackend::Auto),
                    resume: resume.unwrap_or(ipc::TransferResumeMode::Never),
                    idle_timeout: Duration::from_millis(
                        idle_timeout_ms.unwrap_or(ipc::DEFAULT_TRANSFER_IDLE_TIMEOUT_MS),
                    ),
                    deadline: deadline_ms.map(Duration::from_millis),
                    progress: None,
                },
            )
            .await
            .map_err(agent_visible_transfer_error);
            (request_id, outcome)
        }
        AgentRequest::Status { request_id } => {
            (request_id, agent_status_until(grant, signing).await)
        }
    };
    match outcome {
        Ok(data) => AgentResultLine {
            request_id,
            ok: true,
            error: None,
            data: Some(data),
        },
        Err(error) => AgentResultLine {
            request_id,
            ok: false,
            error: Some(format!("{error:#}")),
            data: None,
        },
    }
}

pub(crate) async fn agent_exec_until(
    grant: &serctl_protocol::grant::OperationGrant,
    signing: &SigningKey,
    cmd: &str,
    timeout_ms: u64,
) -> Result<serde_json::Value> {
    validate_remote_command(cmd)?;
    ensure!(
        (1..=ipc::MAX_EXEC_TIMEOUT_MS).contains(&timeout_ms),
        "exec timeout is outside the supported range"
    );
    let request = ipc::Frame::Exec {
        cmd: cmd.to_owned(),
        timeout_ms,
    };
    let timeout = Duration::from_millis(timeout_ms);
    let deadline = tokio::time::Instant::now() + timeout;
    let daemon = connect_grant_request_until(grant, signing, &request, timeout).await?;
    let mut stream = daemon.stream;
    let mut submission = ExecSubmissionState::BeforeRequest;
    write_daemon_exec_frame_until(&mut stream, &request, timeout_ms, deadline, &mut submission)
        .await?;
    let output = match tokio::time::timeout_at(deadline, read_exec_response(&mut stream)).await {
        Ok(result) => result,
        Err(_) => bail!("remote command exceeded its deadline of {timeout_ms} ms"),
    }
    .map_err(|error| classify_daemon_exec_read_error(submission, error))?;
    Ok(serde_json::json!({
        "stdout": B64.encode(&output.stdout),
        "stderr": B64.encode(&output.stderr),
        "code": output.code,
    }))
}

pub(crate) async fn agent_list_until(
    grant: &serctl_protocol::grant::OperationGrant,
    signing: &SigningKey,
    path: &str,
    timeout_ms: u64,
) -> Result<serde_json::Value> {
    validate_remote_path(path, false)?;
    ensure!(
        (1..=ipc::MAX_SFTP_TIMEOUT_MS).contains(&timeout_ms),
        "SFTP timeout is outside the supported range"
    );
    let request = ipc::Frame::ListDir {
        path: path.to_owned(),
        timeout_ms,
    };
    let timeout = Duration::from_millis(timeout_ms);
    let deadline = tokio::time::Instant::now() + timeout;
    let daemon = connect_grant_request_until(grant, signing, &request, timeout).await?;
    let mut stream = daemon.stream;
    let reply = tokio::time::timeout_at(deadline, async {
        ipc::write_frame_limited(&mut stream, &request, ipc::MAX_REQUEST_FRAME).await?;
        ipc::read_frame_limited(&mut stream, ipc::MAX_RESPONSE_FRAME)
            .await?
            .context("daemon disconnected during directory listing")
    })
    .await
    .map_err(|_| anyhow!("SFTP directory listing exceeded its deadline of {timeout_ms} ms"))??;
    match reply {
        ipc::Frame::DirList { path, entries } => {
            Ok(serde_json::json!({ "path": path, "entries": entries }))
        }
        ipc::Frame::Error { msg } => bail!("{msg}"),
        mut other => {
            other.zeroize_sensitive();
            bail!("daemon returned an unexpected directory response")
        }
    }
}

async fn agent_create_dir_until(
    grant: &serctl_protocol::grant::OperationGrant,
    signing: &SigningKey,
    path: &str,
    timeout_ms: u64,
) -> Result<serde_json::Value> {
    validate_remote_path(path, false)?;
    ensure!(
        (1..=ipc::MAX_SFTP_TIMEOUT_MS).contains(&timeout_ms),
        "SFTP timeout is outside the supported range"
    );
    let request = ipc::Frame::CreateDir {
        path: path.to_owned(),
        timeout_ms,
    };
    let timeout = Duration::from_millis(timeout_ms);
    let deadline = tokio::time::Instant::now() + timeout;
    let daemon = connect_grant_request_until(grant, signing, &request, timeout).await?;
    let mut stream = daemon.stream;
    let reply = tokio::time::timeout_at(deadline, async {
        ipc::write_frame_limited(&mut stream, &request, ipc::MAX_REQUEST_FRAME).await?;
        ipc::read_frame_limited(&mut stream, ipc::MAX_RESPONSE_FRAME)
            .await?
            .context("daemon disconnected during create-directory")
    })
    .await
    .map_err(|_| anyhow!("SFTP create-directory exceeded its deadline of {timeout_ms} ms"))??;
    match reply {
        ipc::Frame::Ack => Ok(serde_json::json!({ "created": path })),
        ipc::Frame::Error { msg } => bail!("{msg}"),
        mut other => {
            other.zeroize_sensitive();
            bail!("daemon returned an unexpected create-directory response")
        }
    }
}

pub(crate) async fn agent_transfer_push_until(
    grant: &serctl_protocol::grant::OperationGrant,
    signing: &SigningKey,
    local: &Path,
    remote: &str,
    options: TransferOptions,
) -> Result<serde_json::Value> {
    // Reject aliases before opening or hashing a caller-selected local file.
    // The daemon repeats the authoritative check against the signed root
    // prelude; this local check is a fail-fast confidentiality boundary.
    require_agent_transfer_write_scope(grant)?;
    validate_upload_remote_path(remote)?;
    let idle_timeout_ms = validated_sftp_timeout_ms(options.idle_timeout)?;
    let deadline_ms = options
        .deadline
        .map(validated_sftp_timeout_ms)
        .transpose()?;
    let operation_timeout = options.request_bound();
    let backend = options.backend;
    let deadline = tokio::time::Instant::now() + operation_timeout;
    let cancellation = CancellationToken::new();
    let (mut source, size) =
        open_local_upload_source(local, deadline, &cancellation, idle_timeout_ms).await?;
    let sha256 = hash_stable_upload_source(&mut source, size, deadline, &cancellation).await?;
    let candidate_transfer_id = ipc::TransferId::random();
    let resume_journal = if options.resume == ipc::TransferResumeMode::Auto {
        let access = ensure_daemon_until(deadline).await?;
        let catalog = catalog_profile_until(&access, &grant.profile_name, deadline).await?;
        ensure!(
            wire_profile_id(&catalog)? == grant.profile_id,
            "grant profile was replaced before transfer resume preparation"
        );
        Some(prepare_upload_resume_journal(
            &catalog,
            remote,
            size,
            &sha256,
            backend,
            &candidate_transfer_id,
        )?)
    } else {
        None
    };
    let transfer_id = match resume_journal.as_ref() {
        Some(journal) => journal.transfer_id()?,
        None => candidate_transfer_id,
    };
    let resume_token = resume_journal
        .as_ref()
        .map(|journal| journal.resume_token())
        .transpose()?;
    let request = ZeroizingRequestFrame(ipc::Frame::UploadBegin {
        transfer_id: transfer_id.clone(),
        path: remote.to_owned(),
        size,
        sha256,
        backend,
        resume: options.resume,
        resume_token: resume_token.as_ref().map(|token| token.to_string()),
        idle_timeout_ms,
        deadline_ms,
    });
    ensure!(
        serctl_protocol::v6::frame_kind(&request.0) == AGENT_TRANSFER_WRITE_OPERATION,
        "internal transfer-push root operation mismatch"
    );
    let daemon = connect_grant_request_until(grant, signing, &request.0, operation_timeout).await?;
    let diagnostics = Arc::new(StdMutex::new(None));
    let diagnostics_sink = diagnostics.clone();
    let progress_sink: TransferProgressSink = Arc::new(move |progress| {
        if let Ok(mut current) = diagnostics_sink.lock() {
            *current = Some((
                progress.backend,
                progress.chunk_bytes,
                progress.window_bytes,
            ));
        }
    });
    let bytes = upload_file_via_daemon(UploadDaemonRequest {
        daemon,
        source,
        size,
        timeout_ms: idle_timeout_ms,
        request,
        deadline,
        cancellation,
        progress_sink: Some(progress_sink),
        resume_journal: resume_journal.clone(),
    })
    .await?;
    if let Some(journal) = resume_journal {
        journal.remove()?;
    }
    let (actual_backend, chunk_bytes, window_bytes) = diagnostics
        .lock()
        .map_err(|_| anyhow!("transfer diagnostic lock is poisoned"))?
        .unwrap_or((backend, 0, 0));
    Ok(serde_json::json!({
        "transfer_id": transfer_id.as_str(),
        "bytes": bytes,
        "backend_requested": backend,
        "backend": actual_backend,
        "chunk_bytes": chunk_bytes,
        "window_bytes": window_bytes,
    }))
}

pub(crate) async fn agent_status_until(
    grant: &serctl_protocol::grant::OperationGrant,
    signing: &SigningKey,
) -> Result<serde_json::Value> {
    let request = ipc::Frame::Status;
    let timeout = CONTROL_EXCHANGE_TIMEOUT;
    let deadline = tokio::time::Instant::now() + timeout;
    let daemon = connect_grant_request_until(grant, signing, &request, timeout).await?;
    let mut stream = daemon.stream;
    let reply = tokio::time::timeout_at(deadline, async {
        ipc::write_frame_limited(&mut stream, &request, ipc::MAX_CONTROL_FRAME).await?;
        ipc::read_frame_limited(&mut stream, ipc::MAX_CONTROL_FRAME)
            .await?
            .context("daemon disconnected during status exchange")
    })
    .await
    .map_err(|_| anyhow!("daemon status exchange exceeded its deadline"))??;
    match reply {
        ipc::Frame::StatusInfo {
            profile,
            host,
            user,
            started_unix,
        } => Ok(serde_json::json!({
            "profile": profile,
            "host": host,
            "user": user,
            "started_unix": started_unix,
        })),
        ipc::Frame::Error { msg } => bail!("{msg}"),
        mut other => {
            other.zeroize_sensitive();
            bail!("daemon returned an unexpected status response")
        }
    }
}

#[derive(Debug)]
struct UploadCommitOutcomeUnknown(String);

impl std::fmt::Display for UploadCommitOutcomeUnknown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UploadCommitOutcomeUnknown {}

async fn join_blocking_until<T>(
    mut task: tokio::task::JoinHandle<Result<T>>,
    deadline: tokio::time::Instant,
    operation: &'static str,
) -> Result<T>
where
    T: Send + 'static,
{
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(joined) => joined.with_context(|| format!("join {operation}"))?,
        Err(_) => {
            // This prevents a queued blocking job from starting. A filesystem
            // or Argon2 call already running cannot be preempted; all jobs that
            // can mutate state retain their profile lease in the closure until
            // they finish, so a timed-out caller never opens an unsafe race.
            task.abort();
            bail!("{operation} exceeded its deadline")
        }
    }
}

fn ask_master() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(
        "master passphrase: ",
    )?))
}

#[derive(Clone, Copy)]
struct PendingProfileAuthorization<'a> {
    passphrase: Option<&'a str>,
    prompt_if_missing: bool,
    expected_generation: Option<vault::ProfileIdentity>,
}

struct OwnedPendingProfileAuthorization {
    passphrase: Option<Zeroizing<String>>,
    prompt_if_missing: bool,
    expected_generation: Option<vault::ProfileIdentity>,
}

pub async fn exec_with_timeout_and_master(
    profile: &str,
    cmd: &str,
    timeout: Duration,
    master: Option<Zeroizing<String>>,
) -> Result<i32> {
    let mut result = exec_capture_with_timeout_inner(
        profile,
        cmd,
        master.as_ref().map(|value| value.as_str()),
        master.is_none(),
        None,
        timeout,
    )
    .await?;
    let write_result = write_command_output(&result).await;
    let code = result
        .code
        .ok_or_else(|| anyhow!("remote command completed without an exit status"));
    result.stdout.zeroize();
    result.stderr.zeroize();
    write_result?;
    code
}

async fn write_command_output(result: &CommandOutput) -> Result<()> {
    // The CLI exits with the remote status immediately after this function.
    // Explicit flushes are therefore required for Tokio's blocking stdio
    // adapters; relying on destructor-based flushing loses short outputs.
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    write_command_output_to(result, &mut stdout, &mut stderr).await
}

async fn write_command_output_to<W, E>(
    result: &CommandOutput,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    stdout.write_all(&result.stdout).await?;
    stdout.flush().await?;
    stderr.write_all(&result.stderr).await?;
    stderr.flush().await?;
    Ok(())
}

/// Execute a command without touching process stdio. Every remote operation,
/// including one routed through a resident daemon, requires the master
/// passphrase supplied by the caller.
#[allow(dead_code)] // compatibility entry; the UI uses the generation-bound variant
pub async fn exec_capture(profile: &str, cmd: &str, master: Option<&str>) -> Result<CommandOutput> {
    exec_capture_with_timeout(
        profile,
        cmd,
        master,
        Duration::from_millis(ipc::DEFAULT_EXEC_TIMEOUT_MS),
    )
    .await
}

#[allow(dead_code)] // exercised by the integrated daemon/direct route tests
pub async fn exec_capture_with_timeout(
    profile: &str,
    cmd: &str,
    master: Option<&str>,
    timeout: Duration,
) -> Result<CommandOutput> {
    exec_capture_with_timeout_inner(profile, cmd, master, false, None, timeout).await
}

/// Execute on behalf of a generation-bound UI grant. The daemon derives
/// credentials from exactly that profile generation, so a stale cached
/// passphrase cannot authorize a newly replaced same-name profile.
pub(crate) async fn exec_capture_at_generation(
    profile: &str,
    cmd: &str,
    master: &str,
    expected_generation: vault::ProfileIdentity,
) -> Result<CommandOutput> {
    exec_capture_with_timeout_inner(
        profile,
        cmd,
        Some(master),
        false,
        Some(expected_generation),
        Duration::from_millis(ipc::DEFAULT_EXEC_TIMEOUT_MS),
    )
    .await
}

async fn exec_capture_with_timeout_inner(
    profile: &str,
    cmd: &str,
    master: Option<&str>,
    prompt_if_missing: bool,
    expected_generation: Option<vault::ProfileIdentity>,
    timeout: Duration,
) -> Result<CommandOutput> {
    validate_remote_command(cmd)?;
    let timeout_ms = u64::try_from(timeout.as_millis())
        .ok()
        .filter(|value| (1..=ipc::MAX_EXEC_TIMEOUT_MS).contains(value))
        .ok_or_else(|| anyhow!("exec timeout is outside the supported range"))?;
    let prompted_master = if master.is_none() && prompt_if_missing {
        Some(ask_master()?)
    } else {
        None
    };
    let master = master
        .or_else(|| prompted_master.as_ref().map(|value| value.as_str()))
        .ok_or_else(|| anyhow::anyhow!("master passphrase is required"))?;
    // Human input is outside the remote-operation deadline.
    let deadline = tokio::time::Instant::now() + timeout;
    let request = ZeroizingRequestFrame(ipc::Frame::Exec {
        cmd: cmd.to_owned(),
        timeout_ms,
    });
    let daemon = match tokio::time::timeout_at(
        deadline,
        connect_daemon_for_request_until(
            profile,
            master,
            expected_generation,
            &request.0,
            deadline,
        ),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => bail!("remote command exceeded its deadline of {timeout_ms} ms"),
    };
    let mut s = daemon.stream;
    let mut submission = ExecSubmissionState::BeforeRequest;
    write_daemon_exec_frame_until(&mut s, &request.0, timeout_ms, deadline, &mut submission)
        .await?;
    let result = match tokio::time::timeout_at(deadline, read_exec_response(&mut s)).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "remote command exceeded its deadline of {timeout_ms} ms"
        )),
    };
    result.map_err(|error| classify_daemon_exec_read_error(submission, error))
}

async fn poll_request_write_before_deadline<F>(
    deadline: tokio::time::Instant,
    deadline_message: &str,
    write: F,
) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    tokio::pin!(write);
    let mut first_poll = true;
    std::future::poll_fn(|context| {
        if first_poll {
            first_poll = false;
            // Tokio may poll an immediately-ready inner future once even when
            // its timeout has elapsed. Refuse that poll before serialization
            // or any frame bytes can reach the writer.
            if tokio::time::Instant::now() >= deadline {
                return std::task::Poll::Ready(Err(anyhow!(deadline_message.to_owned())));
            }
        }
        write.as_mut().poll(context)
    })
    .await
}

struct DeadlineAwareWriter<'a, W> {
    writer: &'a mut W,
    deadline: tokio::time::Instant,
    deadline_message: &'a str,
}

impl<W> DeadlineAwareWriter<'_, W> {
    fn deadline_error(&self) -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, self.deadline_message.to_owned())
    }
}

impl<W> AsyncWrite for DeadlineAwareWriter<'_, W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        if tokio::time::Instant::now() >= this.deadline {
            return std::task::Poll::Ready(Err(this.deadline_error()));
        }
        std::pin::Pin::new(&mut *this.writer).poll_write(context, buffer)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        if tokio::time::Instant::now() >= this.deadline {
            return std::task::Poll::Ready(Err(this.deadline_error()));
        }
        std::pin::Pin::new(&mut *this.writer).poll_flush(context)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        if tokio::time::Instant::now() >= this.deadline {
            return std::task::Poll::Ready(Err(this.deadline_error()));
        }
        std::pin::Pin::new(&mut *this.writer).poll_shutdown(context)
    }
}

#[cfg(test)]
async fn write_daemon_exec_request_until<W>(
    writer: &mut W,
    cmd: &str,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
    submission: &mut ExecSubmissionState,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let request = ZeroizingRequestFrame(ipc::Frame::Exec {
        cmd: cmd.to_string(),
        timeout_ms,
    });
    write_daemon_exec_frame_until(writer, &request.0, timeout_ms, deadline, submission).await
}

async fn write_daemon_exec_frame_until<W>(
    writer: &mut W,
    request: &ipc::Frame,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
    submission: &mut ExecSubmissionState,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    ensure!(
        matches!(request, ipc::Frame::Exec { .. }),
        "daemon exec writer received a non-exec root request"
    );
    let deadline_message = format!("remote command exceeded its deadline of {timeout_ms} ms");
    let result = {
        let mut deadline_writer = DeadlineAwareWriter {
            writer,
            deadline,
            deadline_message: &deadline_message,
        };
        let write = ipc::write_frame_limited_with_written_callback(
            &mut deadline_writer,
            request,
            ipc::MAX_REQUEST_FRAME,
            || submission.request_started(),
        );
        match tokio::time::timeout_at(
            deadline,
            poll_request_write_before_deadline(deadline, &deadline_message, write),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow!(deadline_message.clone())),
        }
    };
    result.map_err(|error| submission.classify(error))
}

fn classify_daemon_exec_read_error(
    submission: ExecSubmissionState,
    error: anyhow::Error,
) -> anyhow::Error {
    match error.downcast::<DaemonExecRejected>() {
        Ok(rejected) => anyhow!(rejected.0),
        Err(error) => submission.classify(error),
    }
}

async fn read_exec_response<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<CommandOutput> {
    let mut stdout = Zeroizing::new(Vec::new());
    let mut stderr = Zeroizing::new(Vec::new());
    loop {
        match ipc::read_frame_limited(reader, ipc::MAX_RESPONSE_FRAME).await? {
            Some(ipc::Frame::ExecOut { mut data }) => {
                let extend = extend_command_output(&mut stdout, &data, stderr.len());
                data.zeroize();
                extend?;
            }
            Some(ipc::Frame::ExecErr { mut data }) => {
                let extend = extend_command_output(&mut stderr, &data, stdout.len());
                data.zeroize();
                extend?;
            }
            Some(ipc::Frame::ExecExit { code }) => {
                let code =
                    code.ok_or_else(|| anyhow!("remote command completed without an exit status"))?;
                return Ok(CommandOutput {
                    stdout: std::mem::take(&mut *stdout),
                    stderr: std::mem::take(&mut *stderr),
                    code: Some(code),
                });
            }
            Some(ipc::Frame::Error { msg }) => {
                if let Some(error) = ExecOutcomeUnknown::from_wire_message(&msg) {
                    return Err(error.into());
                }
                return Err(DaemonExecRejected(msg).into());
            }
            None => bail!("daemon disconnected before returning an exit status"),
            Some(mut frame) => {
                frame.zeroize_sensitive();
                bail!("daemon returned an unexpected exec response")
            }
        }
    }
}

pub async fn status(profile: &str, master: &str) -> Result<()> {
    if let Some(info) = daemon_status(profile, master).await? {
        println!("{}", daemon_status_line(&info, now_unix()));
    } else {
        println!("{}", daemon_absent_line(profile));
    }
    Ok(())
}

fn elapsed_nonnegative_seconds(now: i64, started: i64) -> i64 {
    now.saturating_sub(started).max(0)
}

pub async fn daemon_status(profile: &str, master: &str) -> Result<Option<DaemonStatus>> {
    daemon_status_at_optional_generation(profile, master, None, true).await
}

pub async fn transfer_status(
    profile: &str,
    master: &str,
    transfer_id: Option<ipc::TransferId>,
) -> Result<Vec<ipc::TransferProgress>> {
    let deadline = tokio::time::Instant::now() + CONTROL_EXCHANGE_TIMEOUT;
    let access = ensure_daemon_until(deadline).await?;
    let request = ipc::Frame::TransferStatus { transfer_id };
    let daemon =
        connect_authorized_request_until(&access, profile, master, &request, deadline).await?;
    let mut stream = daemon.stream;
    ipc::write_frame_limited(&mut stream, &request, ipc::MAX_CONTROL_FRAME).await?;
    match tokio::time::timeout_at(
        deadline,
        ipc::read_frame_limited(&mut stream, ipc::MAX_CONTROL_FRAME),
    )
    .await
    {
        Ok(Ok(Some(ipc::Frame::TransferStatusInfo { transfers }))) => Ok(transfers),
        Ok(Ok(Some(ipc::Frame::Error { msg }))) => bail!(msg),
        Ok(Ok(Some(mut unexpected))) => {
            unexpected.zeroize_sensitive();
            bail!("daemon returned an unexpected transfer status response")
        }
        Ok(Ok(None)) => bail!("daemon disconnected during transfer status exchange"),
        Ok(Err(error)) => Err(error),
        Err(_) => bail!("transfer status exchange exceeded its deadline"),
    }
}

pub async fn transfer_cancel(
    profile: &str,
    master: &str,
    transfer_id: ipc::TransferId,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + CONTROL_EXCHANGE_TIMEOUT;
    let access = ensure_daemon_until(deadline).await?;
    let request = ipc::Frame::TransferCancel { transfer_id };
    let daemon =
        connect_authorized_request_until(&access, profile, master, &request, deadline).await?;
    let mut stream = daemon.stream;
    ipc::write_frame_limited(&mut stream, &request, ipc::MAX_CONTROL_FRAME).await?;
    match tokio::time::timeout_at(
        deadline,
        ipc::read_frame_limited(&mut stream, ipc::MAX_CONTROL_FRAME),
    )
    .await
    {
        Ok(Ok(Some(ipc::Frame::Ack))) => Ok(()),
        Ok(Ok(Some(ipc::Frame::Error { msg }))) => bail!(msg),
        Ok(Ok(Some(mut unexpected))) => {
            unexpected.zeroize_sensitive();
            bail!("daemon returned an unexpected transfer cancellation response")
        }
        Ok(Ok(None)) => bail!("daemon disconnected during transfer cancellation"),
        Ok(Err(error)) => Err(error),
        Err(_) => bail!("transfer cancellation exchange exceeded its deadline"),
    }
}

/// Status for one profile, launching the broker on demand (CLI `status`).
pub(crate) async fn daemon_status_at_generation(
    profile: &str,
    master: &str,
    expected_generation: vault::ProfileIdentity,
) -> Result<Option<DaemonStatus>> {
    daemon_status_at_optional_generation(profile, master, Some(expected_generation), true).await
}

/// Status probe for one profile that never launches the broker: UI refresh
/// must not start a background daemon merely by opening the window.
pub(crate) async fn daemon_status_probe_at_generation(
    profile: &str,
    master: &str,
    expected_generation: vault::ProfileIdentity,
) -> Result<Option<DaemonStatus>> {
    daemon_status_at_optional_generation(profile, master, Some(expected_generation), false).await
}

async fn daemon_status_at_optional_generation(
    profile: &str,
    master: &str,
    _expected_generation: Option<vault::ProfileIdentity>,
    launch_on_demand: bool,
) -> Result<Option<DaemonStatus>> {
    let deadline = tokio::time::Instant::now() + CONTROL_EXCHANGE_TIMEOUT;
    let access = if launch_on_demand {
        Some(ensure_daemon_until(deadline).await?)
    } else {
        resolve_daemon_until(deadline).await?
    };
    let Some(access) = access else {
        return Ok(None);
    };
    let request = ipc::Frame::Status;
    let operation = async {
        let daemon =
            connect_authorized_request_until(&access, profile, master, &request, deadline).await?;
        let endpoint = daemon.endpoint;
        let mut s = daemon.stream;
        ipc::write_frame_limited(&mut s, &request, ipc::MAX_CONTROL_FRAME).await?;
        match ipc::read_frame_limited(&mut s, ipc::MAX_CONTROL_FRAME).await? {
            Some(ipc::Frame::StatusInfo {
                profile,
                host,
                user,
                started_unix,
            }) => Ok(Some(DaemonStatus {
                profile,
                host,
                user,
                started_unix,
                endpoint,
            })),
            Some(mut frame) => {
                frame.zeroize_sensitive();
                bail!("daemon responded with an unexpected frame")
            }
            None => bail!("daemon disconnected during status exchange"),
        }
    };
    match tokio::time::timeout_at(deadline, operation).await {
        Ok(result) => result,
        Err(_) => bail!("daemon status exchange exceeded its deadline"),
    }
}

pub async fn down(profile: &str, master: &str) -> Result<()> {
    let stopped = down_quiet(profile, master).await?;
    println!("{}", daemon_down_line(profile, stopped));
    Ok(())
}

/// Stop the global daemon without writing to stdout after verifying the named
/// profile passphrase. Returns whether a live daemon was contacted, which
/// makes it suitable for both CLI and GUI frontends.
pub async fn down_quiet(profile: &str, master: &str) -> Result<bool> {
    down_quiet_at_optional_generation(profile, master, None).await
}

pub(crate) async fn down_quiet_at_generation(
    profile: &str,
    master: &str,
    expected_generation: vault::ProfileIdentity,
) -> Result<bool> {
    down_quiet_at_optional_generation(profile, master, Some(expected_generation)).await
}

async fn down_quiet_at_optional_generation(
    profile: &str,
    master: &str,
    expected_generation: Option<vault::ProfileIdentity>,
) -> Result<bool> {
    let mut shutdown_sent = false;
    let deadline = tokio::time::Instant::now() + CONTROL_EXCHANGE_TIMEOUT;
    let mut request = ipc::Frame::Shutdown {
        passphrase: master.to_owned(),
    };
    let exchange = async {
        // Shutdown never launches the broker: it only contacts a daemon that
        // is already published. The passphrase is then verified inside the
        // authenticated v6 AEAD channel without opening an SSH connection.
        let Some(access) = resolve_daemon_until(deadline).await? else {
            return Ok(false);
        };
        if let Some(expected) = expected_generation {
            let observed = vault::list_profile_metadata()?
                .into_iter()
                .find(|entry| entry.name == profile)
                .with_context(|| format!("profile '{profile}' does not exist"))?
                .identity();
            ensure!(
                observed == expected,
                "profile authorization no longer matches the current record"
            );
        }
        let prelude = v6_prelude(&request, None, Some(profile.to_owned()), deadline)?;
        let connection = connect_v6_until(&access, prelude, deadline).await?;
        let mut s = connection.stream;
        shutdown_daemon_exchange(&mut s, &request, &mut shutdown_sent, deadline).await?;
        Ok(true)
    };
    let exchange_result = match tokio::time::timeout_at(deadline, exchange).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("daemon shutdown exchange exceeded its deadline")),
    };
    request.zeroize_sensitive();
    if exchange_result
        .as_ref()
        .err()
        .is_some_and(|error| error.is::<ShutdownRejected>())
    {
        return exchange_result;
    }
    reconcile_shutdown_exchange(
        exchange_result,
        shutdown_sent,
        wait_for_daemon_exit(DAEMON_LOCK_RELEASE_TIMEOUT),
    )
    .await
}

async fn write_shutdown_request_until<W>(
    writer: &mut W,
    request: &ipc::Frame,
    shutdown_sent: &mut bool,
    deadline: tokio::time::Instant,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    const DEADLINE_ERROR: &str = "daemon shutdown exchange exceeded its deadline";
    let mut deadline_writer = DeadlineAwareWriter {
        writer,
        deadline,
        deadline_message: DEADLINE_ERROR,
    };
    let write = ipc::write_frame_limited_with_written_callback(
        &mut deadline_writer,
        request,
        ipc::MAX_CONTROL_FRAME,
        || *shutdown_sent = true,
    );
    match tokio::time::timeout_at(
        deadline,
        poll_request_write_before_deadline(deadline, DEADLINE_ERROR, write),
    )
    .await
    {
        Ok(result) => result.context("send daemon shutdown request"),
        Err(_) => bail!(DEADLINE_ERROR),
    }
}

async fn shutdown_daemon_exchange<S>(
    stream: &mut S,
    request: &ipc::Frame,
    shutdown_sent: &mut bool,
    deadline: tokio::time::Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // A complete framed write is the linearization point. If the Ack is lost,
    // the daemon may still have consumed the request and stopped, so callers
    // must reconcile against the runtime lock before reporting failure.
    write_shutdown_request_until(stream, request, shutdown_sent, deadline).await?;
    let response = match tokio::time::timeout_at(
        deadline,
        ipc::read_frame_limited(stream, ipc::MAX_CONTROL_FRAME),
    )
    .await
    {
        Ok(result) => result.context("read daemon shutdown acknowledgement")?,
        Err(_) => bail!("daemon shutdown exchange exceeded its deadline"),
    };
    match response {
        Some(ipc::Frame::Ack) => Ok(()),
        Some(ipc::Frame::Error { msg }) => Err(ShutdownRejected(msg).into()),
        Some(mut frame) => {
            frame.zeroize_sensitive();
            bail!("daemon returned an unexpected response")
        }
        None => bail!("daemon disconnected during shutdown exchange"),
    }
}

async fn reconcile_shutdown_exchange<F>(
    exchange_result: Result<bool>,
    shutdown_sent: bool,
    wait_for_release: F,
) -> Result<bool>
where
    F: Future<Output = Result<()>>,
{
    match exchange_result {
        Ok(false) => Ok(false),
        Ok(true) => {
            wait_for_release.await?;
            Ok(true)
        }
        Err(exchange_error) if shutdown_sent => match wait_for_release.await {
            Ok(()) => Ok(true),
            Err(reconcile_error) => Err(anyhow!(
                "{exchange_error:#}; shutdown request was sent, but daemon stop reconciliation failed: {reconcile_error:#}"
            )),
        },
        Err(exchange_error) => Err(exchange_error),
    }
}

/// Poll the daemon exit signal until it disappears: the daemon clears its
/// runtime descriptor and activation secret as the final step of shutdown, so
/// descriptor absence (or an unreadable/dead descriptor) is the authoritative
/// release signal for the singleton.
async fn wait_for_daemon_exit(timeout: Duration) -> Result<()> {
    wait_for_daemon_absent_until(timeout, |deadline| {
        join_blocking_until(
            tokio::task::spawn_blocking(|| daemon_is_published().map(|published| !published)),
            deadline,
            "daemon runtime descriptor probe",
        )
    })
    .await
}

async fn wait_for_daemon_absent_until<O, OFut>(timeout: Duration, mut observe: O) -> Result<()>
where
    O: FnMut(tokio::time::Instant) -> OFut,
    OFut: Future<Output = Result<bool>>,
{
    // Shutdown now drains live IPC handlers and closes their remote channels.
    // Do not report success merely because the request exchange completed: the
    // daemon must also clear its runtime state before another CLI may take the
    // singleton.
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "daemon did not release its runtime state within {} ms",
                timeout.as_millis()
            );
        }
        match observe(deadline).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) if tokio::time::Instant::now() >= deadline => {
                return Err(error).context(format!(
                    "daemon did not release its runtime state within {} ms",
                    timeout.as_millis()
                ));
            }
            Err(error) => return Err(error).context("probe daemon exit"),
        }
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + Duration::from_millis(20)).min(deadline),
        )
        .await;
    }
}

fn extend_command_output(target: &mut Vec<u8>, data: &[u8], other_len: usize) -> Result<()> {
    let total = target
        .len()
        .checked_add(other_len)
        .and_then(|size| size.checked_add(data.len()))
        .ok_or_else(|| anyhow!("remote command output size overflow"))?;
    if total > ipc::MAX_COMMAND_OUTPUT {
        bail!("remote command output exceeds the 8 MiB safety limit");
    }
    target.extend_from_slice(data);
    Ok(())
}

fn validated_sftp_timeout_ms(timeout: Duration) -> Result<u64> {
    u64::try_from(timeout.as_millis())
        .ok()
        .filter(|value| (1..=ipc::MAX_SFTP_TIMEOUT_MS).contains(value))
        .ok_or_else(|| anyhow!("SFTP timeout is outside the supported range"))
}

#[allow(dead_code)] // compatibility entry; the UI uses the generation-bound variant
pub async fn list_dir(
    profile: &str,
    path: &str,
    master: Option<&str>,
) -> Result<(String, Vec<RemoteEntry>)> {
    list_dir_with_timeout(
        profile,
        path,
        master,
        Duration::from_millis(ipc::DEFAULT_SFTP_TIMEOUT_MS),
    )
    .await
}

#[allow(dead_code)] // exercised by the integrated daemon/direct route tests
pub async fn list_dir_with_timeout(
    profile: &str,
    path: &str,
    master: Option<&str>,
    timeout: Duration,
) -> Result<(String, Vec<RemoteEntry>)> {
    let timeout_ms = validated_sftp_timeout_ms(timeout)?;
    let deadline = tokio::time::Instant::now() + timeout;
    list_dir_inner(profile, path, master, None, timeout_ms, deadline).await
}

pub(crate) async fn list_dir_at_generation(
    profile: &str,
    path: &str,
    master: &str,
    expected_generation: vault::ProfileIdentity,
    timeout: Duration,
) -> Result<(String, Vec<RemoteEntry>)> {
    let timeout_ms = validated_sftp_timeout_ms(timeout)?;
    let deadline = tokio::time::Instant::now() + timeout;
    list_dir_inner(
        profile,
        path,
        Some(master),
        Some(expected_generation),
        timeout_ms,
        deadline,
    )
    .await
}

async fn list_dir_inner(
    profile: &str,
    path: &str,
    master: Option<&str>,
    expected_generation: Option<vault::ProfileIdentity>,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
) -> Result<(String, Vec<RemoteEntry>)> {
    validate_remote_path(path, true)?;
    let master = master.ok_or_else(|| anyhow!("master passphrase is required"))?;
    let request = ZeroizingRequestFrame(ipc::Frame::ListDir {
        path: path.to_owned(),
        timeout_ms,
    });
    let daemon = match tokio::time::timeout_at(
        deadline,
        connect_daemon_for_request_until(
            profile,
            master,
            expected_generation,
            &request.0,
            deadline,
        ),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => bail!("SFTP directory listing exceeded its deadline of {timeout_ms} ms"),
    };
    let mut stream = daemon.stream;
    let operation = async {
        ipc::write_frame_limited(&mut stream, &request.0, ipc::MAX_REQUEST_FRAME).await?;
        match ipc::read_frame_limited(&mut stream, ipc::MAX_RESPONSE_FRAME).await? {
            Some(ipc::Frame::DirList { path, entries }) => Ok((path, entries)),
            Some(ipc::Frame::Error { msg }) => bail!(msg),
            Some(mut frame) => {
                frame.zeroize_sensitive();
                bail!("daemon returned an unexpected directory response")
            }
            None => bail!("daemon disconnected during directory listing"),
        }
    };
    match tokio::time::timeout_at(deadline, operation).await {
        Ok(result) => result,
        Err(_) => bail!("SFTP directory listing exceeded its deadline of {timeout_ms} ms"),
    }
}

#[allow(dead_code)] // compatibility entry; the UI uses the generation-bound variant
pub async fn create_dir(profile: &str, path: &str, master: Option<&str>) -> Result<()> {
    create_dir_with_timeout(
        profile,
        path,
        master,
        Duration::from_millis(ipc::DEFAULT_SFTP_TIMEOUT_MS),
    )
    .await
}

#[allow(dead_code)] // compatibility entry; the UI uses the generation-bound variant
pub async fn create_dir_with_timeout(
    profile: &str,
    path: &str,
    master: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    let timeout_ms = validated_sftp_timeout_ms(timeout)?;
    let deadline = tokio::time::Instant::now() + timeout;
    create_dir_inner(profile, path, master, None, timeout_ms, deadline).await
}

pub(crate) async fn create_dir_at_generation(
    profile: &str,
    path: &str,
    master: &str,
    expected_generation: vault::ProfileIdentity,
) -> Result<()> {
    let timeout = Duration::from_millis(ipc::DEFAULT_SFTP_TIMEOUT_MS);
    let timeout_ms = validated_sftp_timeout_ms(timeout)?;
    let deadline = tokio::time::Instant::now() + timeout;
    create_dir_inner(
        profile,
        path,
        Some(master),
        Some(expected_generation),
        timeout_ms,
        deadline,
    )
    .await
}

#[cfg(test)]
async fn write_daemon_create_dir_request_until<W>(
    writer: &mut W,
    path: &str,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
    submission: &mut CreateDirSubmissionState,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let request = ZeroizingRequestFrame(ipc::Frame::CreateDir {
        path: path.to_owned(),
        timeout_ms,
    });
    write_daemon_create_dir_frame_until(writer, &request.0, timeout_ms, deadline, submission).await
}

async fn write_daemon_create_dir_frame_until<W>(
    writer: &mut W,
    request: &ipc::Frame,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
    submission: &mut CreateDirSubmissionState,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    ensure!(
        matches!(request, ipc::Frame::CreateDir { .. }),
        "daemon create-directory writer received a non-create root request"
    );
    let deadline_message =
        format!("SFTP create-directory exceeded its deadline of {timeout_ms} ms");
    let result = {
        let mut deadline_writer = DeadlineAwareWriter {
            writer,
            deadline,
            deadline_message: &deadline_message,
        };
        let write = ipc::write_frame_limited_with_written_callback(
            &mut deadline_writer,
            request,
            ipc::MAX_REQUEST_FRAME,
            || submission.request_started(),
        );
        match tokio::time::timeout_at(
            deadline,
            poll_request_write_before_deadline(deadline, &deadline_message, write),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow!(deadline_message.clone())),
        }
    };
    result.map_err(|error| submission.classify(error))
}

async fn read_daemon_create_dir_response_until<R>(
    reader: &mut R,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
    submission: CreateDirSubmissionState,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let response = match tokio::time::timeout_at(
        deadline,
        ipc::read_frame_limited(reader, ipc::MAX_CONTROL_FRAME),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => return Err(submission.classify(error)),
        Err(_) => {
            return Err(submission.classify(anyhow!(
                "SFTP create-directory exceeded its deadline of {timeout_ms} ms"
            )))
        }
    };
    match response {
        Some(ipc::Frame::Ack) => Ok(()),
        Some(ipc::Frame::Error { msg }) => {
            if let Some(error) = CreateDirOutcomeUnknown::from_wire_message(&msg) {
                Err(error.into())
            } else {
                // The daemon emits plain errors only for validation/session
                // setup failures or an explicit SFTP STATUS rejection.
                Err(anyhow!(msg))
            }
        }
        Some(mut frame) => {
            frame.zeroize_sensitive();
            Err(submission.classify(anyhow!(
                "daemon returned an unexpected create-directory response"
            )))
        }
        None => Err(submission.classify(anyhow!(
            "daemon disconnected during create-directory request"
        ))),
    }
}

async fn create_dir_inner(
    profile: &str,
    path: &str,
    master: Option<&str>,
    expected_generation: Option<vault::ProfileIdentity>,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
) -> Result<()> {
    validate_remote_path(path, false)?;
    let master = master.ok_or_else(|| anyhow!("master passphrase is required"))?;
    let request = ZeroizingRequestFrame(ipc::Frame::CreateDir {
        path: path.to_owned(),
        timeout_ms,
    });
    let daemon = match tokio::time::timeout_at(
        deadline,
        connect_daemon_for_request_until(
            profile,
            master,
            expected_generation,
            &request.0,
            deadline,
        ),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => bail!("SFTP create-directory exceeded its deadline of {timeout_ms} ms"),
    };
    let mut stream = daemon.stream;
    let mut submission = CreateDirSubmissionState::BeforeRequest;
    write_daemon_create_dir_frame_until(
        &mut stream,
        &request.0,
        timeout_ms,
        deadline,
        &mut submission,
    )
    .await?;
    read_daemon_create_dir_response_until(&mut stream, timeout_ms, deadline, submission).await
}

/// High-level upload entry for callers that consume secrets before starting an
/// async runtime. `master` is moved and zeroized when this future completes.
pub async fn upload_with_timeout_and_master(
    profile: &str,
    local: &Path,
    remote: &str,
    timeout: Duration,
    master: Option<Zeroizing<String>>,
) -> Result<u64> {
    upload_with_timeout_and_master_cancellable(
        profile,
        local,
        remote,
        timeout,
        master,
        CancellationToken::new(),
    )
    .await
}

/// Cancellation-aware upload. Once cancellation is observed, the owned worker
/// remains alive long enough to close the transfer channel and run the bounded
/// remote-partial cleanup before this function returns.
pub async fn upload_with_timeout_and_master_cancellable(
    profile: &str,
    local: &Path,
    remote: &str,
    timeout: Duration,
    master: Option<Zeroizing<String>>,
    cancellation: CancellationToken,
) -> Result<u64> {
    let prompt_if_direct = master.is_none();
    upload_file_with_timeout_inner(
        profile,
        local,
        remote,
        PendingProfileAuthorization {
            passphrase: master.as_ref().map(|value| value.as_str()),
            prompt_if_missing: prompt_if_direct,
            expected_generation: None,
        },
        TransferOptions::legacy(timeout),
        cancellation,
    )
    .await
}

pub async fn transfer_push_with_master_cancellable(
    profile: &str,
    local: &Path,
    remote: &str,
    options: TransferOptions,
    master: Option<Zeroizing<String>>,
    cancellation: CancellationToken,
) -> Result<u64> {
    let prompt_if_direct = master.is_none();
    upload_file_with_timeout_inner(
        profile,
        local,
        remote,
        PendingProfileAuthorization {
            passphrase: master.as_ref().map(|value| value.as_str()),
            prompt_if_missing: prompt_if_direct,
            expected_generation: None,
        },
        options,
        cancellation,
    )
    .await
}

pub(crate) async fn transfer_push_at_generation_cancellable(
    profile: &str,
    local: &Path,
    remote: &str,
    options: TransferOptions,
    master: Zeroizing<String>,
    expected_generation: vault::ProfileIdentity,
    cancellation: CancellationToken,
) -> Result<u64> {
    upload_file_with_timeout_inner(
        profile,
        local,
        remote,
        PendingProfileAuthorization {
            passphrase: Some(master.as_str()),
            prompt_if_missing: false,
            expected_generation: Some(expected_generation),
        },
        options,
        cancellation,
    )
    .await
}

async fn upload_file_with_timeout_inner(
    profile: &str,
    local: &Path,
    remote: &str,
    authorization: PendingProfileAuthorization<'_>,
    options: TransferOptions,
    cancellation: CancellationToken,
) -> Result<u64> {
    validate_upload_remote_path(remote)?;
    let idle_timeout_ms = validated_sftp_timeout_ms(options.idle_timeout)?;
    let deadline_ms = options
        .deadline
        .map(validated_sftp_timeout_ms)
        .transpose()?;
    let prompted_master = if authorization.passphrase.is_none() && authorization.prompt_if_missing {
        Some(ask_master()?)
    } else {
        None
    };
    let master = authorization
        .passphrase
        .or_else(|| prompted_master.as_ref().map(|value| value.as_str()))
        .ok_or_else(|| anyhow!("master passphrase is required"))?;
    let deadline = tokio::time::Instant::now() + options.request_bound();
    let (mut source, size) =
        open_local_upload_source(local, deadline, &cancellation, idle_timeout_ms).await?;
    let candidate_transfer_id = ipc::TransferId::random();
    let local_progress = |stage, event: &str| ipc::TransferProgress {
        schema_version: ipc::TRANSFER_PROGRESS_SCHEMA_VERSION,
        event: event.to_owned(),
        transfer_id: candidate_transfer_id.clone(),
        direction: ipc::TransferDirection::Push,
        stage,
        total_bytes: size,
        confirmed_bytes: 0,
        durable_bytes: 0,
        window_bps: 0.0,
        average_bps: 0.0,
        eta_ms: None,
        backend: options.backend,
        chunk_bytes: 0,
        window_bytes: 0,
        updated_unix_ms: now_unix_ms(),
    };
    if let Some(sink) = options.progress.as_ref() {
        sink(local_progress(ipc::TransferStage::Preflight, "preflight"));
        sink(local_progress(ipc::TransferStage::Hash, "hash"));
    }
    let sha256 = hash_stable_upload_source(&mut source, size, deadline, &cancellation).await?;
    let (_transfer_id, resume_token, resume_journal, daemon) =
        if options.resume == ipc::TransferResumeMode::Auto {
            let access = ensure_daemon_until(deadline).await?;
            let catalog = catalog_profile_until(&access, profile, deadline).await?;
            validate_expected_catalog_identity(&catalog, authorization.expected_generation)?;
            let journal = prepare_upload_resume_journal(
                &catalog,
                remote,
                size,
                &sha256,
                options.backend,
                &candidate_transfer_id,
            )?;
            let transfer_id = journal.transfer_id()?;
            let resume_token = journal.resume_token()?;
            let request = ZeroizingRequestFrame(ipc::Frame::UploadBegin {
                transfer_id: transfer_id.clone(),
                path: remote.to_owned(),
                size,
                sha256: sha256.clone(),
                backend: options.backend,
                resume: options.resume,
                resume_token: Some(resume_token.to_string()),
                idle_timeout_ms,
                deadline_ms,
            });
            let daemon = connect_authorized_catalog_request_until(
                &access, profile, master, &catalog, &request.0, deadline,
            )
            .await?;
            (
                transfer_id,
                Some(resume_token),
                Some(journal),
                (request, daemon),
            )
        } else {
            let request = ZeroizingRequestFrame(ipc::Frame::UploadBegin {
                transfer_id: candidate_transfer_id.clone(),
                path: remote.to_owned(),
                size,
                sha256: sha256.clone(),
                backend: options.backend,
                resume: options.resume,
                resume_token: None,
                idle_timeout_ms,
                deadline_ms,
            });
            let daemon = match tokio::time::timeout_at(
                deadline,
                connect_daemon_for_request_until(
                    profile,
                    master,
                    authorization.expected_generation,
                    &request.0,
                    deadline,
                ),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => bail!("transfer upload exceeded its request bound"),
            };
            (candidate_transfer_id, None, None, (request, daemon))
        };
    let (request, daemon) = daemon;
    drop(resume_token);

    let worker_cancel = cancellation.clone();
    let worker_journal = resume_journal.clone();
    let worker = tokio::spawn(async move {
        upload_file_via_daemon(UploadDaemonRequest {
            daemon,
            source,
            size,
            timeout_ms: idle_timeout_ms,
            request,
            deadline,
            cancellation: worker_cancel,
            progress_sink: options.progress,
            resume_journal: worker_journal,
        })
        .await
    });
    let result = await_owned_upload_worker(worker, cancellation).await;
    if result.is_ok() {
        if let Some(journal) = resume_journal {
            if let Err(error) = journal.remove() {
                log::warn!(
                    "upload committed but completed transfer journal could not be removed: {}",
                    terminal_safe_error(&error)
                );
            }
        }
    }
    result
}

async fn open_local_upload_source(
    local: &Path,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    timeout_ms: u64,
) -> Result<(tokio::fs::File, u64)> {
    let local = local.to_owned();
    open_local_upload_source_with(local, deadline, cancellation, timeout_ms, |local| {
        // This handle is opened exactly once, before daemon/direct routing and
        // before any SSH authentication. All later reads therefore refer to
        // the same regular file even if the pathname is replaced concurrently.
        let source = security::open_regular_file_for_read(&local)
            .with_context(|| format!("open local upload source {}", local.display()))?;
        let size = source
            .metadata()
            .with_context(|| format!("inspect local upload source {}", local.display()))?
            .len();
        ensure!(
            size <= MAX_TRANSFER_BYTES,
            "upload exceeds the {} byte safety limit",
            MAX_TRANSFER_BYTES
        );
        Ok((source, size))
    })
    .await
}

async fn hash_stable_upload_source(
    source: &mut tokio::fs::File,
    size: u64,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<String> {
    let before = source
        .metadata()
        .await
        .context("inspect upload source before hashing")?;
    ensure!(
        before.len() == size,
        "upload source size changed before hashing"
    );
    source.seek(std::io::SeekFrom::Start(0)).await?;
    let mut hasher = Sha256::new();
    let mut hashed = 0_u64;
    let mut buffer = Zeroizing::new(vec![0_u8; 256 * 1024]);
    loop {
        let read = tokio::select! {
            biased;
            _ = cancellation.cancelled() => bail!("transfer cancelled while hashing the source"),
            result = tokio::time::timeout_at(deadline, source.read(&mut buffer)) => match result {
                Ok(result) => result?,
                Err(_) => bail!("transfer deadline elapsed while hashing the source"),
            },
        };
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        hashed = hashed
            .checked_add(read as u64)
            .context("upload hash byte count overflow")?;
        ensure!(hashed <= size, "upload source grew while hashing");
    }
    ensure!(hashed == size, "upload source shrank while hashing");
    let after = source
        .metadata()
        .await
        .context("inspect upload source after hashing")?;
    ensure!(
        after.len() == before.len(),
        "upload source size changed while hashing"
    );
    if let (Ok(before_modified), Ok(after_modified)) = (before.modified(), after.modified()) {
        ensure!(
            before_modified == after_modified,
            "upload source modification time changed while hashing"
        );
    }
    source.seek(std::io::SeekFrom::Start(0)).await?;
    Ok(hex::encode(hasher.finalize()))
}

async fn open_local_upload_source_with<F>(
    local: PathBuf,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    timeout_ms: u64,
    open: F,
) -> Result<(tokio::fs::File, u64)>
where
    F: FnOnce(PathBuf) -> Result<(std::fs::File, u64)> + Send + 'static,
{
    ensure!(!cancellation.is_cancelled(), "SFTP upload cancelled");
    ensure!(
        tokio::time::Instant::now() < deadline,
        "SFTP upload exceeded its deadline of {timeout_ms} ms"
    );
    let mut task = tokio::task::spawn_blocking(move || open(local));
    let joined = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            // Abort prevents a queued job from starting. If the OS open is
            // already running it cannot be preempted; its eventual unclaimed
            // std::fs::File result is dropped by Tokio and only closes that
            // stable handle.
            task.abort();
            bail!("SFTP upload cancelled");
        }
        result = tokio::time::timeout_at(deadline, &mut task) => match result {
            Ok(joined) => joined.with_context(|| "join local upload source open")?,
            Err(_) => {
                task.abort();
                bail!("SFTP upload exceeded its deadline of {timeout_ms} ms");
            }
        },
    };
    let (source, size) = joined?;
    Ok((tokio::fs::File::from_std(source), size))
}

const REMOTE_PARTIAL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

struct UploadCancellationGuard {
    cancellation: CancellationToken,
    armed: bool,
}

impl UploadCancellationGuard {
    fn new(cancellation: CancellationToken) -> Self {
        Self {
            cancellation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for UploadCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
        }
    }
}

async fn await_owned_upload_worker(
    worker: tokio::task::JoinHandle<Result<u64>>,
    cancellation: CancellationToken,
) -> Result<u64> {
    let mut guard = UploadCancellationGuard::new(cancellation);
    let result = worker.await.context("join owned upload worker")?;
    guard.disarm();
    result
}

struct ZeroizingUploadChunk(ipc::Frame);

impl Drop for ZeroizingUploadChunk {
    fn drop(&mut self) {
        if let ipc::Frame::UploadChunk { data } = &mut self.0 {
            data.zeroize();
        }
    }
}

struct ZeroizingRequestFrame(ipc::Frame);

impl Drop for ZeroizingRequestFrame {
    fn drop(&mut self) {
        self.0.zeroize_sensitive();
    }
}

async fn read_daemon_upload_commit_response<R>(
    reader: &mut R,
    expected: u64,
    rate_tracker: &mut TransferRateTracker,
    progress_sink: Option<&TransferProgressSink>,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = ipc::read_frame_limited(reader, ipc::MAX_CONTROL_FRAME)
            .await
            .map_err(|error| {
                UploadCommitOutcomeUnknown(format!(
                    "SFTP upload commit outcome unknown after an invalid daemon response: {error:#}; \
                     inspect the target before retry"
                ))
            })?;
        match frame {
        Some(ipc::Frame::TransferProgress { progress }) => {
            emit_transfer_progress(rate_tracker, progress_sink, progress)?;
            continue;
        }
        Some(ipc::Frame::TransferDone { bytes }) if bytes == expected => return Ok(bytes),
        Some(ipc::Frame::TransferDone { bytes }) => bail!(
            "upload commit completed with a size mismatch: expected {expected}, daemon stored \
             {bytes}; inspect the target before retry"
        ),
        Some(ipc::Frame::Error { msg }) => bail!(msg),
        Some(mut frame) => {
            frame.zeroize_sensitive();
            return Err(UploadCommitOutcomeUnknown(
                "SFTP upload commit outcome unknown: daemon returned an unexpected response; \
                 inspect the target before retry"
                    .into(),
            )
            .into())
        }
        None => return Err(UploadCommitOutcomeUnknown(
            "SFTP upload commit outcome unknown after daemon disconnect; inspect the target before retry"
                .into(),
        )
        .into()),
        }
    }
}

async fn await_daemon_upload_commit_response<R>(
    reader: &mut R,
    expected: u64,
    request_deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    reconciliation_only: bool,
    rate_tracker: &mut TransferRateTracker,
    progress_sink: Option<&TransferProgressSink>,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
{
    await_daemon_upload_commit_response_with_grace(
        reader,
        CommitWait {
            expected,
            request_deadline,
            cancellation,
            reconciliation_only,
            reconciliation_grace: REMOTE_COMMIT_RECONCILE_TIMEOUT,
            rate_tracker,
            progress_sink,
        },
    )
    .await
}

struct CommitWait<'a> {
    expected: u64,
    request_deadline: tokio::time::Instant,
    cancellation: &'a CancellationToken,
    reconciliation_only: bool,
    reconciliation_grace: Duration,
    rate_tracker: &'a mut TransferRateTracker,
    progress_sink: Option<&'a TransferProgressSink>,
}

async fn await_daemon_upload_commit_response_with_grace<R>(
    reader: &mut R,
    wait: CommitWait<'_>,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
{
    let CommitWait {
        expected,
        request_deadline,
        cancellation,
        reconciliation_only,
        reconciliation_grace,
        rate_tracker,
        progress_sink,
    } = wait;
    let response =
        read_daemon_upload_commit_response(reader, expected, rate_tracker, progress_sink);
    tokio::pin!(response);

    if !reconciliation_only && request_deadline > tokio::time::Instant::now() {
        enum FirstWait {
            Response(Result<u64>),
            Reconcile,
        }
        let first_wait = tokio::select! {
            biased;
            result = &mut response => FirstWait::Response(result),
            _ = cancellation.cancelled() => FirstWait::Reconcile,
            _ = tokio::time::sleep_until(request_deadline) => FirstWait::Reconcile,
        };
        if let FirstWait::Response(result) = first_wait {
            return result;
        }
    }

    match tokio::time::timeout(reconciliation_grace, &mut response).await {
            Ok(result) => result,
            Err(_) => Err(UploadCommitOutcomeUnknown(format!(
                "SFTP upload commit outcome unknown after {} ms reconciliation grace; inspect the target before retry",
                reconciliation_grace.as_millis()
            ))
            .into()),
    }
}

struct UploadDaemonRequest {
    daemon: DaemonConnection,
    source: tokio::fs::File,
    size: u64,
    timeout_ms: u64,
    request: ZeroizingRequestFrame,
    deadline: tokio::time::Instant,
    cancellation: CancellationToken,
    progress_sink: Option<TransferProgressSink>,
    resume_journal: Option<Arc<UploadResumeJournal>>,
}

async fn upload_file_via_daemon(request: UploadDaemonRequest) -> Result<u64> {
    let UploadDaemonRequest {
        daemon,
        mut source,
        size,
        timeout_ms,
        request,
        deadline,
        cancellation,
        progress_sink,
        resume_journal,
    } = request;
    let upload_end_started = std::sync::atomic::AtomicBool::new(false);
    let upload_end_sent = std::sync::atomic::AtomicBool::new(false);

    let mut stream = daemon.stream;
    let mut rate_tracker = TransferRateTracker::new(StdInstant::now());
    let operation = async {
        let mut negotiated_chunk = ipc::SFTP_SAFE_CHUNK_BYTES;
        let mut resume_offset = 0_u64;
        ensure!(
            matches!(&request.0, ipc::Frame::UploadBegin { .. }),
            "daemon upload worker received a non-upload root request"
        );
        ipc::write_frame_limited(&mut stream, &request.0, ipc::MAX_REQUEST_FRAME).await?;
        loop {
            match ipc::read_frame_limited(&mut stream, ipc::MAX_CONTROL_FRAME).await? {
                Some(ipc::Frame::TransferProgress { progress }) => {
                    if progress.chunk_bytes > 0 {
                        let announced = progress.chunk_bytes as usize;
                        ensure!(
                            announced <= MAX_UPLOAD_CHUNK_BYTES,
                            "daemon negotiated an upload chunk above the IPC safety limit"
                        );
                        negotiated_chunk = announced;
                    }
                    ensure!(
                        progress.durable_bytes <= size,
                        "daemon announced a resume offset beyond the source size"
                    );
                    resume_offset = resume_offset.max(progress.durable_bytes);
                    if let Some(journal) = resume_journal.as_ref() {
                        journal.observe(&progress)?;
                    }
                    emit_transfer_progress(&mut rate_tracker, progress_sink.as_ref(), progress)?;
                    continue;
                }
                Some(ipc::Frame::Ack) => break,
                Some(ipc::Frame::Error { msg }) => bail!(msg),
                Some(mut frame) => {
                    frame.zeroize_sensitive();
                    bail!("daemon rejected the upload")
                }
                None => bail!("daemon disconnected before accepting the upload"),
            }
        }
        if let Some(journal) = resume_journal.as_ref() {
            ensure!(
                resume_offset == journal.durable_offset()?,
                "daemon resume offset does not match the protected journal"
            );
        } else {
            ensure!(resume_offset == 0, "daemon resumed an unjournaled upload");
        }
        source
            .seek(std::io::SeekFrom::Start(resume_offset))
            .await
            .context("seek stable upload source to durable resume offset")?;
        let mut buffer = Zeroizing::new(vec![0_u8; negotiated_chunk]);
        loop {
            let read = source.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            ensure!(
                read <= MAX_UPLOAD_CHUNK_BYTES,
                "local upload chunk exceeds its safety limit"
            );
            let chunk = ZeroizingUploadChunk(ipc::Frame::UploadChunk {
                data: buffer[..read].to_vec(),
            });
            ipc::write_frame_limited(&mut stream, &chunk.0, ipc::MAX_UPLOAD_FRAME).await?;
            // Exactly one chunk may be outstanding. This makes every daemon
            // SFTP wait a safe point for detecting client disconnect without
            // consuming the next frame prefix.
            loop {
                match ipc::read_frame_limited(&mut stream, ipc::MAX_CONTROL_FRAME).await? {
                    Some(ipc::Frame::TransferProgress { progress }) => {
                        if let Some(journal) = resume_journal.as_ref() {
                            journal.observe(&progress)?;
                        }
                        emit_transfer_progress(
                            &mut rate_tracker,
                            progress_sink.as_ref(),
                            progress,
                        )?;
                        continue;
                    }
                    Some(ipc::Frame::Ack) => break,
                    Some(ipc::Frame::Error { msg }) => bail!(msg),
                    Some(mut frame) => {
                        frame.zeroize_sensitive();
                        bail!("daemon did not acknowledge an upload chunk")
                    }
                    None => bail!("daemon disconnected before acknowledging an upload chunk"),
                }
            }
        }
        upload_end_started.store(true, std::sync::atomic::Ordering::Release);
        ipc::write_frame_limited(&mut stream, &ipc::Frame::UploadEnd, ipc::MAX_REQUEST_FRAME)
            .await?;
        upload_end_sent.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    };
    enum End {
        Finished(Result<()>),
        Cancelled,
        TimedOut,
    }
    let end = tokio::select! {
        result = tokio::time::timeout_at(deadline, operation) => match result {
            Ok(result) => End::Finished(result),
            Err(_) => End::TimedOut,
        },
        _ = cancellation.cancelled() => End::Cancelled,
    };
    let commit_phase = upload_end_started.load(std::sync::atomic::Ordering::Acquire);
    let precommit_failure = !commit_phase && !matches!(&end, End::Finished(Ok(())));
    let result = match end {
        End::Finished(Ok(())) => {
            await_daemon_upload_commit_response(
                &mut stream,
                size,
                deadline,
                &cancellation,
                false,
                &mut rate_tracker,
                progress_sink.as_ref(),
            )
            .await
        }
        End::Finished(Err(error)) if commit_phase => {
            log::warn!(
                "upload commit frame write was interrupted: {}",
                terminal_safe_error(&error)
            );
            await_daemon_upload_commit_response(
                &mut stream,
                size,
                deadline,
                &cancellation,
                true,
                &mut rate_tracker,
                progress_sink.as_ref(),
            )
            .await
        }
        End::Finished(Err(error)) => Err(error),
        End::Cancelled if commit_phase => {
            await_daemon_upload_commit_response(
                &mut stream,
                size,
                deadline,
                &cancellation,
                true,
                &mut rate_tracker,
                progress_sink.as_ref(),
            )
            .await
        }
        End::TimedOut if commit_phase => {
            await_daemon_upload_commit_response(
                &mut stream,
                size,
                deadline,
                &cancellation,
                true,
                &mut rate_tracker,
                progress_sink.as_ref(),
            )
            .await
        }
        End::Cancelled => {
            // Closing IPC makes the daemon's flow-controlled remote step select
            // its disconnect branch. Give its bounded cleanup time to finish.
            Err(anyhow!("SFTP upload cancelled"))
        }
        End::TimedOut => Err(anyhow!(
            "SFTP upload exceeded its deadline of {timeout_ms} ms"
        )),
    };
    let outcome_unknown = result
        .as_ref()
        .err()
        .is_some_and(|error| error.is::<UploadCommitOutcomeUnknown>());
    drop(stream);
    if precommit_failure || outcome_unknown {
        tokio::time::sleep(REMOTE_PARTIAL_CLEANUP_TIMEOUT + Duration::from_millis(250)).await;
    }
    // `upload_end_sent` distinguishes a fully flushed commit request in logs;
    // an interrupted write is conservatively reconciled as unknown as well.
    if commit_phase && !upload_end_sent.load(std::sync::atomic::Ordering::Acquire) {
        log::warn!("upload commit frame did not finish flushing before reconciliation");
    }
    result
}

pub async fn download_with_timeout_and_master(
    profile: &str,
    remote: &str,
    local: &Path,
    timeout: Duration,
    master: Option<Zeroizing<String>>,
) -> Result<u64> {
    download_with_timeout_and_master_cancellable(
        profile,
        remote,
        local,
        timeout,
        master,
        CancellationToken::new(),
    )
    .await
}

/// Cancellation-aware download. The owned worker keeps the local partial-file
/// cleanup alive if its caller is dropped; cooperative callers should cancel
/// and wait for this future before shutting down the runtime.
pub async fn download_with_timeout_and_master_cancellable(
    profile: &str,
    remote: &str,
    local: &Path,
    timeout: Duration,
    master: Option<Zeroizing<String>>,
    cancellation: CancellationToken,
) -> Result<u64> {
    let prompt_if_direct = master.is_none();
    download_file_with_timeout_owned(
        profile,
        remote,
        local,
        OwnedPendingProfileAuthorization {
            passphrase: master,
            prompt_if_missing: prompt_if_direct,
            expected_generation: None,
        },
        TransferOptions::legacy(timeout),
        cancellation,
    )
    .await
}

pub async fn transfer_pull_with_master_cancellable(
    profile: &str,
    remote: &str,
    local: &Path,
    options: TransferOptions,
    master: Option<Zeroizing<String>>,
    cancellation: CancellationToken,
) -> Result<u64> {
    let prompt_if_direct = master.is_none();
    download_file_with_timeout_owned(
        profile,
        remote,
        local,
        OwnedPendingProfileAuthorization {
            passphrase: master,
            prompt_if_missing: prompt_if_direct,
            expected_generation: None,
        },
        options,
        cancellation,
    )
    .await
}

pub(crate) async fn transfer_pull_at_generation_cancellable(
    profile: &str,
    remote: &str,
    local: &Path,
    options: TransferOptions,
    master: Zeroizing<String>,
    expected_generation: vault::ProfileIdentity,
    cancellation: CancellationToken,
) -> Result<u64> {
    download_file_with_timeout_owned(
        profile,
        remote,
        local,
        OwnedPendingProfileAuthorization {
            passphrase: Some(master),
            prompt_if_missing: false,
            expected_generation: Some(expected_generation),
        },
        options,
        cancellation,
    )
    .await
}

async fn download_file_with_timeout_owned(
    profile: &str,
    remote: &str,
    local: &Path,
    authorization: OwnedPendingProfileAuthorization,
    options: TransferOptions,
    cancellation: CancellationToken,
) -> Result<u64> {
    validate_remote_path(remote, false)?;
    let profile = profile.to_owned();
    let remote = remote.to_owned();
    let local = local.to_owned();
    let worker_cancellation = cancellation.clone();
    let worker = tokio::spawn(async move {
        download_file_worker(
            &profile,
            &remote,
            &local,
            authorization,
            options,
            worker_cancellation,
        )
        .await
    });
    await_owned_upload_worker(worker, cancellation).await
}

async fn download_file_worker(
    profile: &str,
    remote: &str,
    local: &Path,
    authorization: OwnedPendingProfileAuthorization,
    options: TransferOptions,
    cancellation: CancellationToken,
) -> Result<u64> {
    let idle_timeout_ms = validated_sftp_timeout_ms(options.idle_timeout)?;
    let deadline_ms = options
        .deadline
        .map(validated_sftp_timeout_ms)
        .transpose()?;
    let request_bound = options.request_bound();
    let mut deadline = tokio::time::Instant::now() + request_bound;
    // Reject the obvious local conflict before connecting or prompting. The
    // inner check plus atomic commit still enforce this against later races.
    let exists = tokio::select! {
        biased;
        _ = cancellation.cancelled() => bail!("SFTP download cancelled"),
        result = tokio::time::timeout_at(deadline, tokio::fs::try_exists(local)) => match result {
            Ok(result) => result?,
            Err(_) => bail!("transfer download exceeded its request bound"),
        },
    };
    if exists {
        bail!("local destination already exists: {}", local.display());
    }
    let prompted_master = if authorization.passphrase.is_none() && authorization.prompt_if_missing {
        Some(ask_master()?)
    } else {
        None
    };
    if prompted_master.is_some() {
        deadline = tokio::time::Instant::now() + request_bound;
    }
    let master = authorization
        .passphrase
        .as_ref()
        .map(|value| value.as_str())
        .or_else(|| prompted_master.as_ref().map(|value| value.as_str()))
        .ok_or_else(|| anyhow!("master passphrase is required"))?;
    let candidate_transfer_id = ipc::TransferId::random();
    let (root_request, daemon, resume_journal) = if options.resume == ipc::TransferResumeMode::Auto
    {
        let access = ensure_daemon_until(deadline).await?;
        let catalog = catalog_profile_until(&access, profile, deadline).await?;
        validate_expected_catalog_identity(&catalog, authorization.expected_generation)?;
        let journal = prepare_download_resume_journal(
            &catalog,
            remote,
            local,
            options.backend,
            &candidate_transfer_id,
        )?;
        let snapshot = journal.snapshot()?;
        let root = ZeroizingRequestFrame(ipc::Frame::Download {
            transfer_id: snapshot.transfer_id,
            path: remote.to_owned(),
            backend: options.backend,
            resume: options.resume,
            resume_offset: snapshot.durable_offset,
            expected_size: snapshot.expected_size,
            expected_sha256: snapshot.expected_sha256,
            idle_timeout_ms,
            deadline_ms,
        });
        let daemon = connect_authorized_catalog_request_until(
            &access, profile, master, &catalog, &root.0, deadline,
        )
        .await?;
        (root, daemon, Some(journal))
    } else {
        let root = ZeroizingRequestFrame(ipc::Frame::Download {
            transfer_id: candidate_transfer_id,
            path: remote.to_owned(),
            backend: options.backend,
            resume: options.resume,
            resume_offset: 0,
            expected_size: None,
            expected_sha256: None,
            idle_timeout_ms,
            deadline_ms,
        });
        let daemon = tokio::select! {
            biased;
            _ = cancellation.cancelled() => bail!("SFTP download cancelled"),
            result = tokio::time::timeout_at(
                deadline,
                connect_daemon_for_request_until(
                    profile,
                    master,
                    authorization.expected_generation,
                    &root.0,
                    deadline,
                ),
            ) => match result {
                Ok(result) => result?,
                Err(_) => bail!("transfer download exceeded its request bound"),
            },
        };
        (root, daemon, None)
    };
    if cancellation.is_cancelled() {
        bail!("SFTP download cancelled");
    }
    download_file_inner(DownloadRequest {
        local,
        daemon,
        root_request,
        timeout_ms: idle_timeout_ms,
        deadline,
        cancellation,
        progress_sink: options.progress,
        resume_journal,
    })
    .await
}

struct DownloadDaemonRequest<'a> {
    daemon: &'a mut DaemonConnection,
    root_request: ZeroizingRequestFrame,
    destination: &'a mut tokio::fs::File,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
    cancellation: &'a CancellationToken,
    progress_sink: Option<&'a TransferProgressSink>,
    rate_tracker: &'a mut TransferRateTracker,
    resume_journal: Option<&'a Arc<DownloadResumeJournal>>,
}

async fn download_via_daemon_until(request: DownloadDaemonRequest<'_>) -> Result<u64> {
    let DownloadDaemonRequest {
        daemon,
        root_request,
        destination,
        timeout_ms,
        deadline,
        cancellation,
        progress_sink,
        rate_tracker,
        resume_journal,
    } = request;
    let mut stream = &mut daemon.stream;
    let operation = async {
        ensure!(
            matches!(&root_request.0, ipc::Frame::Download { .. }),
            "daemon download worker received a non-download root request"
        );
        let expected_transfer_id = match &root_request.0 {
            ipc::Frame::Download { transfer_id, .. } => transfer_id.clone(),
            _ => unreachable!("download root request was checked above"),
        };
        let resume_offset = resume_journal
            .map(|journal| journal.snapshot().map(|snapshot| snapshot.durable_offset))
            .transpose()?
            .unwrap_or(0);
        let mut received = resume_offset;
        let mut received_hasher = Sha256::new();
        let mut expected_digest: Option<String> = None;
        let mut announced_total: Option<u64> = None;
        if resume_offset > 0 {
            destination.seek(std::io::SeekFrom::Start(0)).await?;
            let mut remaining = resume_offset;
            let mut prefix = Zeroizing::new(vec![0_u8; MAX_UPLOAD_CHUNK_BYTES]);
            while remaining > 0 {
                let limit = usize::try_from(remaining.min(prefix.len() as u64))?;
                let read = destination.read(&mut prefix[..limit]).await?;
                ensure!(
                    read > 0,
                    "local resume partial ended before its durable offset"
                );
                received_hasher.update(&prefix[..read]);
                remaining -= read as u64;
            }
            destination
                .seek(std::io::SeekFrom::Start(resume_offset))
                .await?;
        }
        let mut durable = resume_offset;
        ipc::write_frame_limited(&mut stream, &root_request.0, ipc::MAX_REQUEST_FRAME).await?;
        loop {
            match ipc::read_frame_limited(&mut stream, ipc::MAX_RESPONSE_FRAME).await? {
                Some(ipc::Frame::FileChunk { data }) => {
                    let mut data = Zeroizing::new(data);
                    if data.is_empty() || data.len() > MAX_UPLOAD_CHUNK_BYTES {
                        data.zeroize();
                        bail!("daemon download chunk is empty or exceeds its safety limit");
                    }
                    let write = destination.write_all(&data).await;
                    received_hasher.update(data.as_slice());
                    let next_received = received.checked_add(data.len() as u64);
                    data.zeroize();
                    write?;
                    received = next_received.ok_or_else(|| anyhow!("download size overflow"))?;
                    ensure!(
                        received <= MAX_TRANSFER_BYTES,
                        "download exceeds the {} byte safety limit",
                        MAX_TRANSFER_BYTES
                    );
                    if let Some(journal) = resume_journal {
                        if received.saturating_sub(durable) >= DOWNLOAD_DURABLE_WINDOW_BYTES {
                            destination.sync_data().await?;
                            durable = received;
                            journal.record_durable(durable)?;
                        }
                    }
                    ipc::write_frame_limited(
                        stream,
                        &ipc::Frame::TransferAck {
                            confirmed_bytes: received,
                            durable_bytes: durable,
                        },
                        ipc::MAX_CONTROL_FRAME,
                    )
                    .await?;
                }
                Some(ipc::Frame::TransferProgress { progress }) => {
                    announced_total = Some(progress.total_bytes);
                    emit_transfer_progress(rate_tracker, progress_sink, progress)?;
                }
                Some(ipc::Frame::TransferDigest {
                    transfer_id,
                    sha256,
                }) => {
                    ensure!(
                        transfer_id == expected_transfer_id,
                        "daemon returned a digest for the wrong transfer"
                    );
                    ensure!(
                        sha256.len() == 64
                            && sha256.bytes().all(|byte| {
                                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
                            }),
                        "daemon returned an invalid transfer SHA-256"
                    );
                    if let Some(journal) = resume_journal {
                        let total = announced_total.context(
                            "daemon sent a download digest before announcing the remote size",
                        )?;
                        journal.record_remote_identity(total, &sha256)?;
                    }
                    expected_digest = Some(sha256);
                }
                Some(ipc::Frame::TransferDone { bytes }) if bytes == received => {
                    let expected_digest = expected_digest
                        .take()
                        .context("daemon did not provide a download SHA-256")?;
                    ensure!(
                        hex::encode(received_hasher.finalize()) == expected_digest,
                        "download SHA-256 mismatch"
                    );
                    if let Some(journal) = resume_journal {
                        destination.sync_data().await?;
                        journal.record_durable(received)?;
                    }
                    break Ok(bytes);
                }
                Some(ipc::Frame::TransferDone { bytes }) => {
                    break Err(anyhow!(
                        "download size mismatch: daemon reported {bytes}, received {received}"
                    ));
                }
                Some(ipc::Frame::Error { msg }) => break Err(anyhow!(msg)),
                None => break Err(anyhow!("daemon disconnected during download")),
                Some(mut frame) => {
                    frame.zeroize_sensitive();
                    break Err(anyhow!("daemon returned an unexpected download response"));
                }
            }
        }
    };
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => None,
        result = tokio::time::timeout_at(deadline, operation) => Some(result),
    };
    match result {
        Some(Ok(result)) => result,
        Some(Err(_)) => bail!("SFTP download exceeded its deadline of {timeout_ms} ms"),
        None => bail!("SFTP download cancelled"),
    }
}

struct DownloadRequest<'a> {
    local: &'a Path,
    daemon: DaemonConnection,
    root_request: ZeroizingRequestFrame,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
    cancellation: CancellationToken,
    progress_sink: Option<TransferProgressSink>,
    resume_journal: Option<Arc<DownloadResumeJournal>>,
}

async fn download_file_inner(request: DownloadRequest<'_>) -> Result<u64> {
    let DownloadRequest {
        local,
        daemon,
        root_request,
        timeout_ms,
        deadline,
        cancellation,
        progress_sink,
        resume_journal,
    } = request;
    let exists = tokio::select! {
        biased;
        _ = cancellation.cancelled() => bail!("SFTP download cancelled"),
        result = tokio::time::timeout_at(deadline, tokio::fs::try_exists(local)) => match result {
            Ok(result) => result?,
            Err(_) => bail!("SFTP download exceeded its deadline of {timeout_ms} ms"),
        },
    };
    if exists {
        bail!("local destination already exists: {}", local.display());
    }
    let partial = match resume_journal.as_ref() {
        Some(journal) => journal.snapshot()?.partial_path,
        None => partial_download_path(local),
    };
    ensure!(!cancellation.is_cancelled(), "SFTP download cancelled");
    ensure!(
        tokio::time::Instant::now() < deadline,
        "SFTP download exceeded its deadline of {timeout_ms} ms"
    );
    // The platform CREATE_NEW runs in an owned blocking worker. Its return
    // value has definite ownership semantics: only a successful create arms
    // cleanup. An AlreadyExists or other open failure can never delete a path
    // that belonged to another request.
    let (mut destination, mut partial_cleanup) = if let Some(journal) = resume_journal.as_ref() {
        let snapshot = journal.snapshot()?;
        ensure!(
            snapshot.partial_path == partial,
            "download journal partial path mismatch"
        );
        let file = match security::open_existing_protected_file(&partial)? {
            Some(file) => file,
            None if snapshot.durable_offset == 0 => security::create_new_protected_file(&partial)?,
            None => bail!("owned download partial is missing for a nonzero durable offset"),
        };
        let length = file.metadata()?.len();
        ensure!(
            length >= snapshot.durable_offset,
            "owned download partial is shorter than its durable offset"
        );
        if length != snapshot.durable_offset {
            file.set_len(snapshot.durable_offset)
                .context("truncate owned download partial to its durable prefix")?;
            file.sync_all().context("sync truncated download partial")?;
        }
        (tokio::fs::File::from_std(file), None::<LocalPartialCleanup>)
    } else {
        let (file, cleanup) =
            create_local_download_partial(&partial, deadline, &cancellation, timeout_ms).await?;
        (file, Some(cleanup))
    };
    if cancellation.is_cancelled() {
        drop(destination);
        if let Some(cleanup) = partial_cleanup.as_mut() {
            cleanup.cleanup().await;
        }
        bail!("SFTP download cancelled");
    }
    if tokio::time::Instant::now() >= deadline {
        drop(destination);
        if let Some(cleanup) = partial_cleanup.as_mut() {
            cleanup.cleanup().await;
        }
        bail!("SFTP download exceeded its deadline of {timeout_ms} ms");
    }

    let mut daemon = daemon;
    let mut rate_tracker = TransferRateTracker::new(StdInstant::now());
    let transfer: Result<u64> = download_via_daemon_until(DownloadDaemonRequest {
        daemon: &mut daemon,
        root_request,
        destination: &mut destination,
        timeout_ms,
        deadline,
        cancellation: &cancellation,
        progress_sink: progress_sink.as_ref(),
        rate_tracker: &mut rate_tracker,
        resume_journal: resume_journal.as_ref(),
    })
    .await;

    match transfer {
        Ok(bytes) => {
            if cancellation.is_cancelled() {
                drop(destination);
                if let Some(cleanup) = partial_cleanup.as_mut() {
                    cleanup.cleanup().await;
                }
                bail!("SFTP download cancelled");
            }
            // Hard-link creation is the linearization point. Once local commit
            // starts, cooperative cancellation is deliberately masked so a
            // caller cannot receive "cancelled" after the destination name was
            // already installed. The commit retains its own short hard bound.
            let commit_deadline = deadline.min(tokio::time::Instant::now() + LOCAL_COMMIT_TIMEOUT);
            let finalized = finalize_local_download(
                &mut destination,
                &partial,
                local,
                commit_deadline,
                &cancellation,
                std::future::ready(()),
            )
            .await;
            let partial_removed = match finalized {
                Ok(partial_removed) => partial_removed,
                Err(error) => {
                    drop(destination);
                    if let Some(cleanup) = partial_cleanup.as_mut() {
                        cleanup.cleanup().await;
                    }
                    return Err(error);
                }
            };
            drop(destination);
            if partial_removed {
                if let Some(cleanup) = partial_cleanup.as_mut() {
                    cleanup.disarm();
                }
            } else if partial_cleanup.is_none() {
                let _cleanup = partial_cleanup.insert(LocalPartialCleanup::new(partial.clone()));
            }
            ipc::write_frame_limited(&mut daemon.stream, &ipc::Frame::Ack, ipc::MAX_CONTROL_FRAME)
                .await?;
            match ipc::read_frame_limited(&mut daemon.stream, ipc::MAX_CONTROL_FRAME).await? {
                Some(ipc::Frame::TransferProgress { progress })
                    if progress.stage == ipc::TransferStage::Completed =>
                {
                    emit_transfer_progress(&mut rate_tracker, progress_sink.as_ref(), progress)?;
                }
                Some(ipc::Frame::Error { msg }) => bail!(msg),
                Some(mut unexpected) => {
                    unexpected.zeroize_sensitive();
                    bail!("daemon did not confirm the completed local download commit")
                }
                None => bail!("daemon disconnected before confirming the local download commit"),
            }
            if let Some(journal) = resume_journal {
                if let Err(error) = journal.remove() {
                    log::warn!(
                        "download committed but completed transfer journal could not be removed: {}",
                        terminal_safe_error(&error)
                    );
                }
            }
            Ok(bytes)
        }
        Err(error) => {
            drop(destination);
            if let Some(cleanup) = partial_cleanup.as_mut() {
                cleanup.cleanup().await;
            } else if let Some(journal) = resume_journal.as_ref() {
                let snapshot = journal.snapshot()?;
                if let Some(file) = security::open_existing_protected_file(&snapshot.partial_path)?
                {
                    file.set_len(snapshot.durable_offset)
                        .context("truncate failed download to its durable prefix")?;
                    file.sync_all()
                        .context("sync failed download durable prefix")?;
                }
            }
            Err(error)
        }
    }
}

fn partial_download_path(local: &Path) -> PathBuf {
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    let mut name = local.as_os_str().to_owned();
    name.push(format!(".serctl-part-{}", hex::encode(random)));
    PathBuf::from(name)
}

async fn create_local_download_partial(
    partial: &Path,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    timeout_ms: u64,
) -> Result<(tokio::fs::File, LocalPartialCleanup)> {
    create_local_download_partial_with(
        partial.to_owned(),
        deadline,
        cancellation,
        timeout_ms,
        UnclaimedLocalPartial::create,
    )
    .await
}

async fn create_local_download_partial_with<F>(
    partial: PathBuf,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    timeout_ms: u64,
    create: F,
) -> Result<(tokio::fs::File, LocalPartialCleanup)>
where
    F: FnOnce(PathBuf) -> Result<UnclaimedLocalPartial> + Send + 'static,
{
    ensure!(!cancellation.is_cancelled(), "SFTP download cancelled");
    ensure!(
        tokio::time::Instant::now() < deadline,
        "SFTP download exceeded its deadline of {timeout_ms} ms"
    );
    let mut task = tokio::task::spawn_blocking(move || create(partial));
    let joined = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            // A queued task is stopped. A running CREATE_NEW may finish late;
            // its output remains an armed UnclaimedLocalPartial and therefore
            // cleans only the random pathname it successfully created.
            task.abort();
            bail!("SFTP download cancelled");
        }
        result = tokio::time::timeout_at(deadline, &mut task) => match result {
            Ok(joined) => joined.with_context(|| "join local download partial create")?,
            Err(_) => {
                task.abort();
                bail!("SFTP download exceeded its deadline of {timeout_ms} ms");
            }
        },
    };
    // There is deliberately no await between receiving the armed owner and
    // moving its handle/path into the caller-owned cleanup guard. Cooperative
    // cancellation therefore cannot split this handoff.
    Ok(joined?.claim())
}

struct UnclaimedLocalPartial {
    file: Option<std::fs::File>,
    path: Option<PathBuf>,
}

impl UnclaimedLocalPartial {
    fn create(path: PathBuf) -> Result<Self> {
        let file = security::create_new_protected_file(&path)
            .with_context(|| format!("create protected temporary file {}", path.display()))?;
        Ok(Self {
            file: Some(file),
            path: Some(path),
        })
    }

    fn claim(mut self) -> (tokio::fs::File, LocalPartialCleanup) {
        let file = self
            .file
            .take()
            .expect("unclaimed local partial must retain its file handle");
        let path = self
            .path
            .take()
            .expect("unclaimed local partial must retain its cleanup path");
        (
            tokio::fs::File::from_std(file),
            LocalPartialCleanup::new(path),
        )
    }
}

impl Drop for UnclaimedLocalPartial {
    fn drop(&mut self) {
        // Windows removal needs the share-delete handle closed first. Cleanup
        // runs off the async executor because this Drop may run while Tokio is
        // discarding a late spawn_blocking result after the outer future was
        // cancelled, timed out, dropped, or unwound.
        drop(self.file.take());
        if let Some(path) = self.path.take() {
            schedule_local_partial_cleanup(path);
        }
    }
}

#[derive(Debug)]
struct LocalPartialCleanup {
    path: Option<PathBuf>,
}

impl LocalPartialCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }

    async fn cleanup(&mut self) {
        if let Some(path) = self.path.take() {
            // Dropping this JoinHandle cannot cancel a running blocking job;
            // the owned path therefore remains scheduled even if the outer
            // transfer future is cancelled during explicit cleanup.
            run_local_partial_cleanup_with(
                path,
                LOCAL_PARTIAL_CLEANUP_TIMEOUT + LOCAL_PARTIAL_CLEANUP_JOIN_MARGIN,
                |path| remove_local_partial_with_retry_blocking(&path),
            )
            .await;
        }
    }
}

impl Drop for LocalPartialCleanup {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        schedule_local_partial_cleanup(path);
    }
}

fn schedule_local_partial_cleanup(path: PathBuf) {
    let retained_on_spawn_failure = path.clone();
    if std::thread::Builder::new()
        .name("serctl-partial-cleanup".into())
        .spawn(move || remove_local_partial_with_retry_blocking(&path))
        .is_err()
    {
        // Thread exhaustion is exceptional, but Drop may be executing on the
        // single async runtime thread. Retain the still-owned random pathname
        // instead of performing synchronous filesystem I/O here and violating
        // every surrounding deadline. Process termination remains the final
        // cleanup boundary for this fail-closed resource-exhaustion case.
        let _ = Box::leak(Box::new(retained_on_spawn_failure));
    }
}

async fn run_local_partial_cleanup_with<F>(path: PathBuf, join_timeout: Duration, cleanup: F)
where
    F: FnOnce(PathBuf) + Send + 'static,
{
    let mut task = tokio::task::spawn_blocking(move || cleanup(path));
    // Do not abort on timeout even if this worker is still queued: the closure
    // owns the only cleanup pathname. Letting the JoinHandle drop detaches it
    // so it will eventually execute after blocking-pool pressure clears,
    // while the async caller still returns at this hard join boundary.
    let _ = tokio::time::timeout(join_timeout, &mut task).await;
}

fn remove_local_partial_with_retry_blocking(path: &Path) {
    let deadline = std::time::Instant::now() + LOCAL_PARTIAL_CLEANUP_TIMEOUT;
    loop {
        match std::fs::remove_file(path) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(_) => {}
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

async fn finalize_local_download<F>(
    destination: &mut tokio::fs::File,
    partial: &Path,
    local: &Path,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    after_link: F,
) -> Result<bool>
where
    F: Future<Output = ()>,
{
    ensure!(!cancellation.is_cancelled(), "SFTP download cancelled");
    tokio::time::timeout_at(deadline, destination.flush())
        .await
        .map_err(|_| anyhow!("flush local download exceeded its commit deadline"))?
        .context("flush local download before commit")?;
    tokio::time::timeout_at(deadline, destination.sync_all())
        .await
        .map_err(|_| anyhow!("sync local download exceeded its commit deadline"))?
        .context("sync local download before commit")?;
    commit_local_no_replace_with_hook(partial, local, destination, deadline, after_link).await
}

async fn commit_local_no_replace_with_hook<F>(
    partial: &Path,
    local: &Path,
    expected: &tokio::fs::File,
    deadline: tokio::time::Instant,
    after_link: F,
) -> Result<bool>
where
    F: Future<Output = ()>,
{
    commit_local_no_replace_with_hook_and_link(
        partial,
        local,
        expected,
        deadline,
        after_link,
        std::fs::hard_link,
    )
    .await
}

async fn commit_local_no_replace_with_hook_and_link<F, L>(
    partial: &Path,
    local: &Path,
    expected: &tokio::fs::File,
    deadline: tokio::time::Instant,
    after_link: F,
    link: L,
) -> Result<bool>
where
    F: Future<Output = ()>,
    L: FnOnce(PathBuf, PathBuf) -> std::io::Result<()> + Send + 'static,
{
    // timeout_at polls its inner future first, even when the deadline has
    // already elapsed. Reject before cloning paths or spawning the irreversible
    // hard-link worker so an expired request can never install `local`.
    ensure!(
        tokio::time::Instant::now() < deadline,
        "local hard-link commit deadline expired before it started"
    );
    // Both names are in the same directory. Creating a hard link is an atomic
    // no-replace operation on every platform supported by std: it either
    // installs `local` for this exact inode or fails if another process won the
    // destination-name race. A subsequent unlink commits the name transition.
    // Keep the blocking task handle after the public deadline: filesystem calls
    // cannot be cancelled once the kernel has accepted them, and detaching the
    // task would let `local` appear after this function reported a plain timeout.
    let partial_for_link = partial.to_owned();
    let local_for_link = local.to_owned();
    let mut link_task = tokio::task::spawn_blocking(move || link(partial_for_link, local_for_link));
    let linked = match tokio::time::timeout_at(deadline, &mut link_task).await {
        Ok(joined) => joined.context("join local hard-link commit")?,
        Err(_) => {
            let reconcile_deadline = tokio::time::Instant::now() + LOCAL_COMMIT_RECONCILE_TIMEOUT;
            match tokio::time::timeout_at(reconcile_deadline, &mut link_task).await {
                Ok(joined) => {
                    joined.context("join local hard-link commit during reconciliation")?
                }
                Err(_) => {
                    // The syscall may have committed the link even though its
                    // blocking task has not delivered a result. The still-open
                    // partial handle is the stable identity used to reconcile
                    // that ambiguous outcome.
                    let probe_deadline =
                        tokio::time::Instant::now() + LOCAL_COMMIT_RECONCILE_TIMEOUT;
                    let destination_exists = tokio::time::timeout_at(
                        probe_deadline,
                        tokio::fs::try_exists(local),
                    )
                    .await
                    .map_err(|_| {
                        anyhow!("reconcile timed-out local download commit exceeded its deadline")
                    })??;
                    if destination_exists {
                        if let Err(error) =
                            verify_committed_file_identity(local, expected, probe_deadline).await
                        {
                            link_task.abort();
                            return Err(error).context(
                                "local destination conflicts with a timed-out download commit",
                            );
                        }
                        Ok(())
                    } else {
                        // `abort` prevents a queued spawn_blocking job from
                        // starting, but cannot interrupt a filesystem syscall
                        // already in progress. There is therefore an
                        // irreducible platform boundary after this bounded
                        // reconciliation window: a pathological kernel call
                        // could still mutate the name after we return.
                        link_task.abort();
                        bail!(
                            "local download commit exceeded its deadline and reconciliation grace; \
                             the non-cancelable filesystem operation may still complete"
                        );
                    }
                }
            }
        }
    };
    if let Err(error) = linked {
        let error_deadline = tokio::time::Instant::now() + LOCAL_COMMIT_RECONCILE_TIMEOUT;
        let destination_exists =
            tokio::time::timeout_at(error_deadline, tokio::fs::try_exists(local))
                .await
                .map_err(|_| {
                    anyhow!("checking failed local download commit exceeded its deadline")
                })??;
        if destination_exists {
            bail!(
                "local destination was created during download: {}",
                local.display()
            );
        }
        return Err(error).with_context(|| {
            format!(
                "atomically commit temporary download {} to {}",
                partial.display(),
                local.display()
            )
        });
    }

    after_link.await;

    // Once the hard link exists, the operation is committed regardless of the
    // caller's original deadline. Use a fresh, bounded reconciliation window
    // to verify that exact inode, durably sync the directory, and remove the
    // temporary sibling name before reporting success.
    let post_commit_deadline = tokio::time::Instant::now() + LOCAL_COMMIT_RECONCILE_TIMEOUT;
    verify_committed_file_identity(local, expected, post_commit_deadline).await?;
    if let Err(error) = sync_parent_directory(local, post_commit_deadline).await {
        log::warn!(
            "download committed to {}, but parent-directory sync failed: {}",
            terminal_safe_display(&local.display()),
            terminal_safe_error(&error),
        );
    }

    match tokio::time::timeout_at(post_commit_deadline, tokio::fs::remove_file(partial)).await {
        Ok(Ok(())) => Ok(true),
        Ok(Err(error)) => {
            log::warn!(
                "download committed to {}, but temporary name {} could not be removed: {}",
                terminal_safe_display(&local.display()),
                terminal_safe_display(&partial.display()),
                terminal_safe_display(&error),
            );
            Ok(false)
        }
        Err(_) => {
            log::warn!(
                "download committed to {}, but temporary-name cleanup exceeded its deadline",
                terminal_safe_display(&local.display()),
            );
            Ok(false)
        }
    }
}

#[cfg(unix)]
async fn verify_committed_file_identity(
    local: &Path,
    expected: &tokio::fs::File,
    deadline: tokio::time::Instant,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let expected = tokio::time::timeout_at(deadline, expected.metadata())
        .await
        .map_err(|_| anyhow!("read local temporary-file identity exceeded its deadline"))??;
    let actual = tokio::time::timeout_at(deadline, tokio::fs::metadata(local))
        .await
        .map_err(|_| anyhow!("verify local download identity exceeded its deadline"))??;
    ensure!(
        actual.dev() == expected.dev() && actual.ino() == expected.ino(),
        "local temporary file changed identity during commit"
    );
    Ok(())
}

#[cfg(windows)]
async fn verify_committed_file_identity(
    local: &Path,
    expected: &tokio::fs::File,
    deadline: tokio::time::Instant,
) -> Result<()> {
    let expected = tokio::time::timeout_at(deadline, expected.try_clone())
        .await
        .map_err(|_| anyhow!("clone local temporary-file handle exceeded its deadline"))??;
    let actual = tokio::time::timeout_at(deadline, tokio::fs::File::open(local))
        .await
        .map_err(|_| anyhow!("open committed local file exceeded its deadline"))??;
    // Both async operations above have completed, so these fresh handles have
    // no in-flight Tokio operation. Conversion transfers stable owned handles
    // to the blocking identity worker without touching the original download
    // destination handle.
    let expected = expected
        .try_into_std()
        .map_err(|_| anyhow!("cloned local temporary-file handle remained busy"))?;
    let actual = actual
        .try_into_std()
        .map_err(|_| anyhow!("committed local file handle remained busy"))?;

    verify_owned_file_identities_until_with(expected, actual, deadline, |file| {
        use std::mem::MaybeUninit;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };

        let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        // SAFETY: `info` points to writable storage and the borrowed file keeps
        // its valid OS handle alive for the duration of the call.
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
        if succeeded == 0 {
            return Err(io::Error::last_os_error()).context("read Windows file identity");
        }
        // SAFETY: a successful call initializes every field of the structure.
        let info = unsafe { info.assume_init() };
        let index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
        Ok((info.dwVolumeSerialNumber, index))
    })
    .await
}

#[cfg(any(windows, test))]
async fn verify_owned_file_identities_until_with<I, F>(
    expected: std::fs::File,
    actual: std::fs::File,
    deadline: tokio::time::Instant,
    read_identity: F,
) -> Result<()>
where
    I: Eq + Send + 'static,
    F: Fn(&std::fs::File) -> Result<I> + Send + Sync + 'static,
{
    join_blocking_until(
        tokio::task::spawn_blocking(move || {
            let expected_id = read_identity(&expected)?;
            let actual_id = read_identity(&actual)?;
            ensure!(
                actual_id == expected_id,
                "local temporary file changed identity during commit"
            );
            Ok(())
        }),
        deadline,
        "local committed-file identity read",
    )
    .await
}

#[cfg(not(any(unix, windows)))]
async fn verify_committed_file_identity(
    _local: &Path,
    _expected: &tokio::fs::File,
    _deadline: tokio::time::Instant,
) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn sync_parent_directory(local: &Path, deadline: tokio::time::Instant) -> Result<()> {
    let parent = local
        .parent()
        .context("local download destination has no parent directory")?
        .to_owned();
    let sync = tokio::task::spawn_blocking(move || -> io::Result<()> {
        std::fs::File::open(parent)?.sync_all()
    });
    match tokio::time::timeout_at(deadline, sync).await {
        Ok(result) => result.context("join parent-directory sync")??,
        Err(_) => bail!("parent-directory sync exceeded its deadline"),
    }
    Ok(())
}

#[cfg(not(unix))]
async fn sync_parent_directory(_local: &Path, _deadline: tokio::time::Instant) -> Result<()> {
    Ok(())
}

async fn complete_shell_input_write_until<F, E>(
    write: F,
    deadline: tokio::time::Instant,
) -> Result<()>
where
    F: Future<Output = std::result::Result<(), E>>,
    E: Into<anyhow::Error>,
{
    match tokio::time::timeout_at(deadline, write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.into()).context("write shell input"),
        Err(_) => bail!("shell input write timed out"),
    }
}

struct ZeroizingShellInputFrame(ipc::Frame);

impl Drop for ZeroizingShellInputFrame {
    fn drop(&mut self) {
        if let ipc::Frame::ShellInput { data } = &mut self.0 {
            data.zeroize();
        }
    }
}

async fn write_ipc_shell_input<W>(writer: &mut W, mut data: Zeroizing<Vec<u8>>) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    validate_shell_input(&mut data)?;
    let frame = ZeroizingShellInputFrame(ipc::Frame::ShellInput {
        data: std::mem::take(&mut *data),
    });
    let result = complete_shell_input_write_until(
        ipc::write_frame_limited(writer, &frame.0, ipc::MAX_SHELL_FRAME),
        tokio::time::Instant::now() + SHELL_INPUT_WRITE_TIMEOUT,
    )
    .await;
    result
}

fn validate_shell_input(data: &mut Zeroizing<Vec<u8>>) -> Result<()> {
    if data.len() > MAX_SHELL_INPUT_BYTES {
        data.zeroize();
        bail!("shell input exceeds {MAX_SHELL_INPUT_BYTES} bytes");
    }
    Ok(())
}

async fn send_gui_shell_output(
    sender: &mpsc::Sender<ShellEvent>,
    data: Zeroizing<Vec<u8>>,
) -> Result<()> {
    match tokio::time::timeout(SHELL_EVENT_SEND_TIMEOUT, sender.reserve()).await {
        Ok(Ok(permit)) => {
            permit.send(ShellEvent::Output(data));
            Ok(())
        }
        Ok(Err(_)) => bail!("shell output receiver closed"),
        Err(_) => bail!("shell output receiver stopped draining events"),
    }
}

async fn send_gui_shell_output_or_cancel(
    sender: &mpsc::Sender<ShellEvent>,
    data: Zeroizing<Vec<u8>>,
    cancellation: &CancellationToken,
) -> Result<bool> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Ok(false),
        result = send_gui_shell_output(sender, data) => result.map(|()| true),
    }
}

async fn write_shell_output<W>(writer: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let operation = async {
        writer.write_all(data).await?;
        writer.flush().await?;
        Ok::<(), io::Error>(())
    };
    match tokio::time::timeout(SHELL_OUTPUT_WRITE_TIMEOUT, operation).await {
        Ok(result) => result.context("write shell output"),
        Err(_) => bail!("shell output write timed out"),
    }
}

fn zeroize_pending_shell_input(receiver: &mut mpsc::Receiver<Zeroizing<Vec<u8>>>) {
    receiver.close();
    while let Ok(mut data) = receiver.try_recv() {
        data.zeroize();
    }
}

/// Own the only in-progress IPC frame read for a shell connection. A raw
/// `read_frame_limited` future is not cancellation-safe after it consumes part
/// of the length prefix or payload; recreating it in every `select!` iteration
/// would interpret the middle of that frame as the next header whenever local
/// input won the race. This pump remains pinned across all competing events.
struct ZeroizingShellFrameRead {
    result: Result<Option<ipc::Frame>>,
    drop_observer: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl ZeroizingShellFrameRead {
    fn new(
        result: Result<Option<ipc::Frame>>,
        drop_observer: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        Self {
            result,
            drop_observer,
        }
    }

    fn into_inner(mut self) -> Result<Option<ipc::Frame>> {
        std::mem::replace(&mut self.result, Ok(None))
    }
}

impl Drop for ZeroizingShellFrameRead {
    fn drop(&mut self) {
        if let Ok(Some(frame)) = &mut self.result {
            frame.zeroize_sensitive();
        }
        if let Some(observer) = &self.drop_observer {
            observer.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

async fn read_shell_frame_pump_inner<R>(
    reader: &mut R,
    sender: mpsc::Sender<ZeroizingShellFrameRead>,
    drop_observer: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    construction_observer: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let result = ipc::read_frame_limited(reader, ipc::MAX_SHELL_FRAME).await;
        let terminal = !matches!(&result, Ok(Some(_)));
        if let Some(observer) = &construction_observer {
            observer.fetch_add(1, std::sync::atomic::Ordering::Release);
        }
        let envelope = ZeroizingShellFrameRead::new(result, drop_observer.clone());
        if sender.send(envelope).await.is_err() || terminal {
            break;
        }
    }
}

async fn read_shell_frame_pump<R>(reader: &mut R, sender: mpsc::Sender<ZeroizingShellFrameRead>)
where
    R: AsyncRead + Unpin,
{
    read_shell_frame_pump_inner(reader, sender, None, None).await;
}

fn zeroize_pending_shell_frames(receiver: &mut mpsc::Receiver<ZeroizingShellFrameRead>) {
    receiver.close();
    while receiver.try_recv().is_ok() {}
}

async fn run_gui_ipc_shell<R, W>(
    mut rd: R,
    mut wr: W,
    mut input_rx: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    event_tx: mpsc::Sender<ShellEvent>,
    cancellation: CancellationToken,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut terminal_error = None;
    let (frame_tx, mut frame_rx) = mpsc::channel(1);
    let frame_pump = read_shell_frame_pump(&mut rd, frame_tx);
    tokio::pin!(frame_pump);
    let mut frame_pump_running = true;
    'shell: loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            frame = frame_rx.recv() => match frame.map(ZeroizingShellFrameRead::into_inner) {
                Some(Ok(Some(ipc::Frame::ShellOut { data }))) => {
                    // Construct the RAII guard before building the select
                    // future. With a biased, already-ready cancellation
                    // branch, an unpolled async function still owns its raw
                    // arguments and would otherwise drop this Vec normally.
                    let data = Zeroizing::new(data);
                    match send_gui_shell_output_or_cancel(&event_tx, data, &cancellation).await {
                        Ok(true) => {}
                        Ok(false) => break 'shell,
                        Err(error) => {
                            terminal_error = Some(error.to_string());
                            break;
                        }
                    }
                }
                Some(Ok(Some(ipc::Frame::Error { msg }))) => {
                    terminal_error = Some(msg);
                    break;
                }
                Some(Ok(Some(ipc::Frame::ShellClosed))) | Some(Ok(None)) | None => break,
                Some(Ok(Some(mut frame))) => {
                    frame.zeroize_sensitive();
                    terminal_error = Some("daemon returned an unexpected shell frame".to_owned());
                    break;
                }
                Some(Err(error)) => {
                    terminal_error = Some(error.to_string());
                    break;
                }
            },
            () = &mut frame_pump, if frame_pump_running => {
                // EOF/errors are enqueued before the pump completes. Disable
                // this branch and let the next iteration consume that event.
                frame_pump_running = false;
            },
            input = input_rx.recv() => match input {
                Some(data) => {
                    let write = tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => break 'shell,
                        result = write_ipc_shell_input(&mut wr, data) => result,
                    };
                    if let Err(error) = write {
                        terminal_error = Some(error.to_string());
                        break;
                    }
                }
                None => break,
            },
        }
    }
    zeroize_pending_shell_input(&mut input_rx);
    zeroize_pending_shell_frames(&mut frame_rx);
    if let Some(error) = terminal_error {
        try_send_shell_event(&event_tx, ShellEvent::Error(error));
    }
    try_send_shell_event(&event_tx, ShellEvent::Closed);
}

#[cfg(test)]
async fn start_ipc_shell_until<R, W>(
    rd: &mut R,
    wr: &mut W,
    cols: u32,
    rows: u32,
    deadline: tokio::time::Instant,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    validate_shell_dimensions(cols, rows)?;
    let request = ipc::Frame::Shell { cols, rows };
    start_ipc_shell_frame_until(rd, wr, &request, deadline).await
}

async fn start_ipc_shell_frame_until<R, W>(
    rd: &mut R,
    wr: &mut W,
    request: &ipc::Frame,
    deadline: tokio::time::Instant,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    ensure!(
        matches!(request, ipc::Frame::Shell { .. }),
        "daemon shell setup received a non-shell root request"
    );
    let setup = async {
        ipc::write_frame_limited(wr, request, ipc::MAX_SHELL_FRAME).await?;
        match ipc::read_frame_limited(rd, ipc::MAX_SHELL_FRAME).await? {
            Some(ipc::Frame::Ack) => Ok(()),
            Some(ipc::Frame::Error { msg }) => bail!(msg),
            Some(mut frame) => {
                frame.zeroize_sensitive();
                bail!("daemon returned an unexpected shell response")
            }
            None => bail!("daemon disconnected during shell setup"),
        }
    };
    match tokio::time::timeout_at(deadline, setup).await {
        Ok(result) => result,
        Err(_) => bail!("daemon IPC shell setup timed out"),
    }
}

#[allow(dead_code)] // compatibility entry; retained for external callers
pub async fn open_gui_shell(profile: &str, master: Zeroizing<String>) -> Result<GuiShell> {
    open_gui_shell_at_optional_generation(profile, Some(master.as_str()), None).await
}

pub(crate) async fn open_gui_shell_at_generation(
    profile: &str,
    master: &str,
    expected_generation: vault::ProfileIdentity,
) -> Result<GuiShell> {
    open_gui_shell_at_optional_generation(profile, Some(master), Some(expected_generation)).await
}

async fn open_gui_shell_at_optional_generation(
    profile: &str,
    master: Option<&str>,
    expected_generation: Option<vault::ProfileIdentity>,
) -> Result<GuiShell> {
    validate_shell_dimensions(120, 36)?;
    let master = master.ok_or_else(|| anyhow!("master passphrase is required"))?;
    let (input_tx, input_rx) = mpsc::channel::<Zeroizing<Vec<u8>>>(64);
    let (event_tx, event_rx) = mpsc::channel::<ShellEvent>(128);
    let cancellation = CancellationToken::new();

    let ipc_setup_deadline = tokio::time::Instant::now() + IPC_SHELL_SETUP_TIMEOUT;
    let request = ZeroizingRequestFrame(ipc::Frame::Shell {
        cols: 120,
        rows: 36,
    });
    let daemon = connect_daemon_for_request_until(
        profile,
        master,
        expected_generation,
        &request.0,
        ipc_setup_deadline,
    )
    .await?;
    let stream = daemon.stream;
    let (mut rd, mut wr) = tokio::io::split(stream);
    start_ipc_shell_frame_until(&mut rd, &mut wr, &request.0, ipc_setup_deadline).await?;
    let worker_cancellation = cancellation.clone();
    tokio::spawn(run_gui_ipc_shell(
        rd,
        wr,
        input_rx,
        event_tx,
        worker_cancellation,
    ));

    Ok(GuiShell {
        input: input_tx,
        events: event_rx,
        cancellation,
    })
}

/// Start an SSH tunnel for the GUI and return only after its listener or
/// remote forward is ready. The master passphrase authorizes this one tunnel
/// start even when the SSH transport is owned by the daemon.
pub async fn open_gui_tunnel(
    profile: &str,
    spec: TunnelSpec,
    master: Zeroizing<String>,
) -> Result<GuiTunnel> {
    open_gui_tunnel_at_optional_generation(profile, spec, master, None).await
}

pub(crate) async fn open_gui_tunnel_at_generation(
    profile: &str,
    spec: TunnelSpec,
    master: Zeroizing<String>,
    expected_generation: vault::ProfileIdentity,
) -> Result<GuiTunnel> {
    open_gui_tunnel_at_optional_generation(profile, spec, master, Some(expected_generation)).await
}

async fn open_gui_tunnel_at_optional_generation(
    profile: &str,
    spec: TunnelSpec,
    master: Zeroizing<String>,
    expected_generation: Option<vault::ProfileIdentity>,
) -> Result<GuiTunnel> {
    spec.validate()?;
    let requested_mode = spec.mode();
    let request = ZeroizingRequestFrame(ipc::Frame::TunnelOpen { spec: spec.clone() });
    let ipc_deadline = tokio::time::Instant::now() + IPC_TUNNEL_SETUP_TIMEOUT;
    let mut daemon = connect_daemon_for_request_until(
        profile,
        &master,
        expected_generation,
        &request.0,
        ipc_deadline,
    )
    .await?;
    let ready = read_daemon_tunnel_ready_until(
        &mut daemon.stream,
        &request.0,
        requested_mode,
        ipc_deadline,
    )
    .await?;
    let cancellation = CancellationToken::new();
    let (event_tx, event_rx) = mpsc::channel(128);
    try_send_tunnel_event(
        &event_tx,
        TunnelEvent::Ready {
            bind_host: ready.bind_host.clone(),
            bind_port: ready.bind_port,
        },
    );
    let worker_cancellation = cancellation.clone();
    let worker = tokio::spawn(run_gui_ipc_tunnel(
        daemon.stream,
        event_tx,
        worker_cancellation,
    ));
    Ok(GuiTunnel {
        ready,
        events: event_rx,
        cancellation,
        worker: Some(worker),
    })
}

async fn read_daemon_tunnel_ready_until<S>(
    stream: &mut S,
    request: &ipc::Frame,
    expected_mode: TunnelMode,
    deadline: tokio::time::Instant,
) -> Result<TunnelReady>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let setup = async {
        ipc::write_frame_limited(stream, request, ipc::MAX_REQUEST_FRAME).await?;
        match ipc::read_frame_limited(stream, ipc::MAX_CONTROL_FRAME).await? {
            Some(ipc::Frame::TunnelReady { ready }) => {
                ensure!(
                    ready.mode == expected_mode,
                    "daemon returned a tunnel mode different from the authorized request"
                );
                Ok(ready)
            }
            Some(ipc::Frame::Error { msg }) => bail!(msg),
            Some(mut frame) => {
                frame.zeroize_sensitive();
                bail!("daemon returned an unexpected tunnel setup response")
            }
            None => bail!("daemon disconnected during tunnel setup"),
        }
    };
    match tokio::time::timeout_at(deadline, setup).await {
        Ok(result) => result,
        Err(_) => bail!("daemon IPC tunnel setup timed out"),
    }
}

async fn read_ipc_tunnel_until_closed<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    match ipc::read_frame_limited(stream, ipc::MAX_CONTROL_FRAME).await? {
        Some(ipc::Frame::TunnelClosed) | None => Ok(()),
        Some(ipc::Frame::Error { msg }) => Err(anyhow!(msg)),
        Some(mut frame) => {
            frame.zeroize_sensitive();
            bail!("daemon returned an unexpected tunnel control response")
        }
    }
}

async fn run_gui_ipc_tunnel<S>(
    stream: S,
    events: mpsc::Sender<TunnelEvent>,
    cancellation: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Keep one decoder alive for the whole control session. A fragmented
    // TunnelClosed/Error may already have consumed bytes when cancellation
    // arrives; rebuilding the decoder would interpret the remaining payload
    // as a new length header and lose protocol synchronization.
    let mut terminal = Box::pin(read_ipc_tunnel_until_closed(&mut reader));
    let result = tokio::select! {
        biased;
        result = &mut terminal => result,
        _ = cancellation.cancelled() => {
            let write_deadline = tokio::time::Instant::now() + TUNNEL_CONTROL_WRITE_TIMEOUT;
            match tokio::time::timeout_at(
                write_deadline,
                ipc::write_frame_limited(
                    &mut writer,
                    &ipc::Frame::TunnelStop,
                    ipc::MAX_CONTROL_FRAME,
                ),
            ).await {
                Ok(Ok(())) => {
                    let close_deadline = tokio::time::Instant::now() + Duration::from_secs(4);
                    match tokio::time::timeout_at(
                        close_deadline,
                        &mut terminal,
                    ).await {
                        Ok(result) => result,
                        Err(_) => Err(anyhow!("daemon tunnel cleanup exceeded its deadline")),
                    }
                }
                Ok(Err(error)) => Err(error).context("send daemon tunnel stop request"),
                Err(_) => Err(anyhow!("daemon tunnel stop request timed out")),
            }
        }
    };
    if let Err(error) = &result {
        try_send_tunnel_event(&events, TunnelEvent::Error(error.to_string()));
    }
    try_send_tunnel_event(&events, TunnelEvent::Closed);
    result
}

pub async fn tunnel_with_master(
    profile: &str,
    spec: TunnelSpec,
    master: Zeroizing<String>,
) -> Result<()> {
    let mut tunnel = open_gui_tunnel(profile, spec, master).await?;
    let ready = tunnel.ready().clone();
    println!(
        "tunnel ready: {:?} {}:{}",
        ready.mode,
        terminal_safe_field(&ready.bind_host),
        ready.bind_port
    );
    let mut interrupted = false;
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c(), if !interrupted => {
                signal.context("wait for Ctrl+C")?;
                interrupted = true;
                tunnel.cancel();
            }
            event = tunnel.events.recv() => match event {
                Some(TunnelEvent::Error(mut error)) => {
                    eprintln!("[serctl] tunnel error: {}", terminal_safe_field(&error));
                    error.zeroize();
                }
                Some(TunnelEvent::Closed) | None => break,
                Some(TunnelEvent::Ready { mut bind_host, .. }) => bind_host.zeroize(),
            }
        }
    }
    tunnel.wait().await
}

struct StdinPump {
    receiver: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    cancellation: CancellationToken,
}

impl StdinPump {
    async fn recv(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.receiver.recv().await
    }
}

impl Drop for StdinPump {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.receiver.close();
    }
}

fn send_stdin_input_until_cancelled(
    sender: &mpsc::Sender<Zeroizing<Vec<u8>>>,
    mut data: Zeroizing<Vec<u8>>,
    cancellation: &CancellationToken,
) -> bool {
    loop {
        if cancellation.is_cancelled() {
            return false;
        }
        match sender.try_send(data) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Full(returned)) => {
                data = returned;
                std::thread::sleep(STDIN_SEND_RETRY_INTERVAL);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
        }
    }
}

fn spawn_stdin_pump_with<P, R>(mut poll_event: P, mut read_event: R) -> StdinPump
where
    P: FnMut(Duration) -> io::Result<bool> + Send + 'static,
    R: FnMut() -> io::Result<Event> + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Zeroizing<Vec<u8>>>(64);
    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();
    std::thread::spawn(move || {
        while !worker_cancellation.is_cancelled() {
            match poll_event(STDIN_POLL_INTERVAL) {
                Ok(false) => continue,
                Ok(true) => match read_event() {
                    Ok(event) => {
                        if let Some(data) = key_to_bytes(&event) {
                            if !data.is_empty()
                                && !send_stdin_input_until_cancelled(
                                    &tx,
                                    Zeroizing::new(data),
                                    &worker_cancellation,
                                )
                            {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                },
                Err(_) => break,
            }
        }
    });
    StdinPump {
        receiver: rx,
        cancellation,
    }
}

fn spawn_stdin_pump() -> StdinPump {
    spawn_stdin_pump_with(crossterm::event::poll, crossterm::event::read)
}

pub async fn shell_with_master(profile: &str, master: Option<Zeroizing<String>>) -> Result<()> {
    let (cols, rows) = term_size();
    validate_shell_dimensions(cols, rows)?;
    let prompted_master = if master.is_none() {
        Some(ask_master()?)
    } else {
        None
    };
    let master = master
        .as_ref()
        .map(|value| value.as_str())
        .or_else(|| prompted_master.as_ref().map(|value| value.as_str()))
        .ok_or_else(|| anyhow!("master passphrase is required"))?;
    let ipc_setup_deadline = tokio::time::Instant::now() + IPC_SHELL_SETUP_TIMEOUT;
    let request = ZeroizingRequestFrame(ipc::Frame::Shell { cols, rows });
    let daemon =
        connect_daemon_for_request_until(profile, master, None, &request.0, ipc_setup_deadline)
            .await?;
    shell_via_ipc(daemon.stream, &request.0, ipc_setup_deadline).await
}

async fn shell_via_ipc<S>(
    stream: S,
    request: &ipc::Frame,
    setup_deadline: tokio::time::Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    start_ipc_shell_frame_until(&mut rd, &mut wr, request, setup_deadline).await?;

    let _raw_mode = enter_raw_mode()?;
    shell_loop_ipc(&mut rd, &mut wr).await
}

async fn shell_loop_ipc<R, W>(rd: &mut R, wr: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut kbrx = spawn_stdin_pump();
    let mut out = tokio::io::stdout();
    let (frame_tx, mut frame_rx) = mpsc::channel(1);
    let frame_pump = read_shell_frame_pump(rd, frame_tx);
    tokio::pin!(frame_pump);
    let mut frame_pump_running = true;
    let result: Result<()> = async {
        loop {
            tokio::select! {
                biased;
                frame = frame_rx.recv() => match frame.map(ZeroizingShellFrameRead::into_inner) {
                    Some(Ok(Some(ipc::Frame::ShellOut { data }))) => {
                        let mut data = Zeroizing::new(data);
                        let result = write_shell_output(&mut out, &data).await;
                        data.zeroize();
                        result?;
                    }
                    Some(Ok(Some(ipc::Frame::ShellClosed))) | Some(Ok(None)) | None => break,
                    Some(Ok(Some(ipc::Frame::Error { msg }))) => bail!(msg),
                    Some(Ok(Some(mut frame))) => {
                        frame.zeroize_sensitive();
                        bail!("daemon returned an unexpected shell frame")
                    }
                    Some(Err(error)) => return Err(error),
                },
                () = &mut frame_pump, if frame_pump_running => {
                    frame_pump_running = false;
                },
                key = kbrx.recv() => match key {
                    Some(b) => write_ipc_shell_input(wr, b).await?,
                    None => break,
                },
            }
        }
        Ok(())
    }
    .await;
    zeroize_pending_shell_frames(&mut frame_rx);
    result
}

fn term_size() -> (u32, u32) {
    crossterm::terminal::size()
        .map(|(c, r)| (c as u32, r as u32))
        .unwrap_or((80, 24))
}

fn key_to_bytes(ev: &Event) -> Option<Vec<u8>> {
    let e: &KeyEvent = match ev {
        Event::Key(e) => e,
        _ => return None,
    };
    if e.kind == KeyEventKind::Release {
        return None;
    }
    if e.modifiers.contains(KeyModifiers::CONTROL) {
        if let KeyCode::Char(c) = e.code {
            let lc = c.to_ascii_lowercase();
            if lc.is_ascii_lowercase() {
                return Some(vec![(lc as u8) - b'a' + 1]);
            }
            if c == ' ' {
                return Some(vec![0]);
            }
        }
    }
    let v: Vec<u8> = match e.code {
        KeyCode::Char(c) => {
            let mut b = [0u8; 4];
            c.encode_utf8(&mut b).as_bytes().to_vec()
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Left => vec![0x1b, b'[', b'D'],
        KeyCode::Right => vec![0x1b, b'[', b'C'],
        KeyCode::Up => vec![0x1b, b'[', b'A'],
        KeyCode::Down => vec![0x1b, b'[', b'B'],
        KeyCode::Home => vec![0x1b, b'[', b'H'],
        KeyCode::End => vec![0x1b, b'[', b'F'],
        KeyCode::Delete => vec![0x1b, b'[', b'3', b'~'],
        KeyCode::PageUp => vec![0x1b, b'[', b'5', b'~'],
        KeyCode::PageDown => vec![0x1b, b'[', b'6', b'~'],
        _ => vec![],
    };
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::{
        agent_stdio_loop_with, agent_transfer_push_until,
        await_daemon_upload_commit_response_with_grace, await_owned_upload_worker,
        classify_daemon_exec_read_error, commit_local_no_replace_with_hook,
        commit_local_no_replace_with_hook_and_link, complete_shell_input_write_until,
        create_dir_inner, create_local_download_partial, create_local_download_partial_with,
        daemon_absent_line, daemon_down_line, daemon_status_line, dispatch_agent_request,
        download_file_with_timeout_owned, elapsed_nonnegative_seconds, enter_raw_mode_with,
        exec_capture_with_timeout_inner, finalize_local_download, join_blocking_until,
        key_to_bytes, list_dir_inner, load_agent_grant, open_local_upload_source,
        open_local_upload_source_with, prepare_download_resume_journal_in,
        prepare_upload_resume_journal_in, read_daemon_create_dir_response_until,
        read_daemon_tunnel_ready_until, read_exec_response, read_shell_frame_pump,
        read_shell_frame_pump_inner, reconcile_shutdown_exchange, run_gui_ipc_shell,
        run_gui_ipc_tunnel, run_local_partial_cleanup_with, send_gui_shell_output_or_cancel,
        shutdown_daemon_exchange, spawn_stdin_pump_with, start_ipc_shell_until,
        terminal_safe_error, terminal_safe_field, upload_file_with_timeout_inner,
        validate_shell_input, validated_sftp_timeout_ms, verify_owned_file_identities_until_with,
        wait_for_daemon_absent_until, wait_for_published_daemon_until, write_command_output_to,
        write_daemon_create_dir_request_until, write_daemon_exec_request_until,
        write_shutdown_request_until, AgentGrantFile, AgentRequest,
        AgentTransferWriteScopeRequired, CommandOutput, DaemonAccess, DaemonStatus,
        OwnedPendingProfileAuthorization, PendingProfileAuthorization, ShellEvent, TransferOptions,
        TransferRateTracker, TunnelEvent, UnclaimedLocalPartial, UploadCommitOutcomeUnknown,
        AGENT_TRANSFER_WRITE_OPERATION, DAEMON_LOCK_RELEASE_TIMEOUT, MAX_SHELL_INPUT_BYTES,
    };
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serctl_core::ssh::{
        CreateDirOutcomeUnknown, CreateDirSubmissionState, ExecOutcomeUnknown, ExecSubmissionState,
        TunnelMode, TunnelReady, TunnelSpec,
    };
    use serctl_protocol::{self as ipc, Frame};
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::{Condvar, Mutex as StdMutex};
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::sync::{mpsc, oneshot, Notify};
    use tokio_util::sync::CancellationToken;
    use zeroize::{Zeroize, Zeroizing};

    #[derive(Default)]
    struct FlushTrackingWriter {
        bytes: Vec<u8>,
        flushed: bool,
    }

    fn test_transfer_progress(confirmed_bytes: u64) -> ipc::TransferProgress {
        ipc::TransferProgress {
            schema_version: ipc::TRANSFER_PROGRESS_SCHEMA_VERSION,
            event: "progress".into(),
            transfer_id: ipc::TransferId::parse("00000000000000000000000000000001").unwrap(),
            direction: ipc::TransferDirection::Push,
            stage: ipc::TransferStage::Transferring,
            total_bytes: 10 * 1024 * 1024,
            confirmed_bytes,
            durable_bytes: 0,
            window_bps: 0.0,
            average_bps: 0.0,
            eta_ms: None,
            backend: ipc::TransferBackend::Sftp,
            chunk_bytes: ipc::SFTP_SAFE_CHUNK_BYTES as u32,
            window_bytes: ipc::SFTP_SAFE_CHUNK_BYTES as u32,
            updated_unix_ms: 1,
        }
    }

    #[test]
    fn transfer_rate_tracker_is_monotonic_finite_and_stalls_to_zero() {
        let start = Instant::now();
        let mut tracker = TransferRateTracker::new(start);
        let initial = tracker.enrich(test_transfer_progress(0), start).unwrap();
        assert_eq!(initial.window_bps, 0.0);
        assert_eq!(initial.average_bps, 0.0);
        assert_eq!(initial.eta_ms, None);
        assert!(initial.window_bps.is_finite());

        let one_mib = 1024 * 1024;
        let moving = tracker
            .enrich(
                test_transfer_progress(one_mib),
                start + Duration::from_secs(1),
            )
            .unwrap();
        let expected = one_mib as f64;
        assert!((moving.window_bps - expected).abs() / expected <= 0.10);
        assert!((moving.average_bps - expected).abs() / expected <= 0.10);
        assert!(moving.eta_ms.is_some());

        let stalled = tracker
            .enrich(
                test_transfer_progress(one_mib),
                start + Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(stalled.window_bps, 0.0);
        assert_eq!(stalled.eta_ms, None);
        assert!(tracker
            .enrich(
                test_transfer_progress(one_mib - 1),
                start + Duration::from_secs(6),
            )
            .is_err());
    }

    #[test]
    fn transfer_rate_tracker_does_not_count_resumed_prefix_as_new_throughput() {
        let start = Instant::now();
        let mut tracker = TransferRateTracker::new(start);
        let mut resumed = test_transfer_progress(8 * 1024 * 1024);
        resumed.event = "resumed".into();
        resumed.durable_bytes = resumed.confirmed_bytes;
        let resumed = tracker
            .enrich(resumed, start + Duration::from_secs(1))
            .unwrap();
        assert_eq!(resumed.window_bps, 0.0);
        assert_eq!(resumed.average_bps, 0.0);
        assert_eq!(resumed.eta_ms, None);

        let transferred = tracker
            .enrich(
                test_transfer_progress(9 * 1024 * 1024),
                start + Duration::from_secs(2),
            )
            .unwrap();
        let expected = (1024 * 1024) as f64;
        assert!((transferred.window_bps - expected).abs() / expected <= 0.10);
        assert!((transferred.average_bps - expected).abs() / expected <= 0.10);
    }

    #[test]
    fn upload_resume_journal_reuses_only_exact_profile_generation_and_intent() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "serctl-upload-journal-test-{}-{nonce}",
            std::process::id()
        ));
        let profile = ipc::WireProfile {
            name: "journal-profile".into(),
            host: "127.0.0.1".into(),
            port: 22,
            generation: 7,
            profile_id: "11".repeat(16),
        };
        let first_id = ipc::TransferId::parse("01".repeat(16).as_str()).unwrap();
        let first = prepare_upload_resume_journal_in(
            &directory,
            &profile,
            "/tmp/target",
            100,
            &"22".repeat(32),
            ipc::TransferBackend::Native,
            &first_id,
        )
        .unwrap();
        let token = first.resume_token().unwrap();
        let mut progress = test_transfer_progress(75);
        progress.transfer_id = first_id.clone();
        progress.total_bytes = 100;
        progress.durable_bytes = 75;
        progress.backend = ipc::TransferBackend::Native;
        first.observe(&progress).unwrap();
        drop(first);

        let replacement_id = ipc::TransferId::parse("02".repeat(16).as_str()).unwrap();
        let resumed = prepare_upload_resume_journal_in(
            &directory,
            &profile,
            "/tmp/target",
            100,
            &"22".repeat(32),
            ipc::TransferBackend::Native,
            &replacement_id,
        )
        .unwrap();
        assert_eq!(resumed.transfer_id().unwrap(), first_id);
        assert_eq!(resumed.resume_token().unwrap().as_str(), token.as_str());
        assert_eq!(resumed.durable_offset().unwrap(), 75);

        let mut rotated = profile.clone();
        rotated.generation += 1;
        let rotated_journal = prepare_upload_resume_journal_in(
            &directory,
            &rotated,
            "/tmp/target",
            100,
            &"22".repeat(32),
            ipc::TransferBackend::Native,
            &replacement_id,
        )
        .unwrap();
        assert_eq!(rotated_journal.transfer_id().unwrap(), replacement_id);
        assert_eq!(rotated_journal.durable_offset().unwrap(), 0);

        serctl_core::security::write_protected_atomic(&resumed.path, b"{\"schema\":99}").unwrap();
        assert!(prepare_upload_resume_journal_in(
            &directory,
            &profile,
            "/tmp/target",
            100,
            &"22".repeat(32),
            ipc::TransferBackend::Native,
            &replacement_id,
        )
        .is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn download_resume_journal_binds_remote_identity_and_profile_generation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "serctl-download-journal-test-{}-{nonce}",
            std::process::id()
        ));
        let local = directory.join("result.bin");
        let profile = ipc::WireProfile {
            name: "download-journal-profile".into(),
            host: "127.0.0.1".into(),
            port: 22,
            generation: 9,
            profile_id: "33".repeat(16),
        };
        let first_id = ipc::TransferId::parse("03".repeat(16).as_str()).unwrap();
        let first = prepare_download_resume_journal_in(
            &directory,
            &profile,
            "/tmp/source",
            &local,
            ipc::TransferBackend::Native,
            &first_id,
        )
        .unwrap();
        let first_snapshot = first.snapshot().unwrap();
        assert_eq!(first_snapshot.durable_offset, 0);
        assert_eq!(first_snapshot.expected_size, None);
        assert_eq!(first_snapshot.expected_sha256, None);
        assert_ne!(first_snapshot.partial_path, local);
        let partial = first_snapshot.partial_path;

        let sha256 = "44".repeat(32);
        first.record_remote_identity(100, &sha256).unwrap();
        first.record_durable(75).unwrap();
        assert!(first.record_remote_identity(101, &sha256).is_err());
        drop(first);

        let replacement_id = ipc::TransferId::parse("04".repeat(16).as_str()).unwrap();
        let resumed = prepare_download_resume_journal_in(
            &directory,
            &profile,
            "/tmp/source",
            &local,
            ipc::TransferBackend::Native,
            &replacement_id,
        )
        .unwrap();
        let resumed_snapshot = resumed.snapshot().unwrap();
        assert_eq!(resumed_snapshot.transfer_id, first_id);
        assert_eq!(resumed_snapshot.partial_path, partial);
        assert_eq!(resumed_snapshot.durable_offset, 75);
        assert_eq!(resumed_snapshot.expected_size, Some(100));
        assert_eq!(
            resumed_snapshot.expected_sha256.as_deref(),
            Some(sha256.as_str())
        );

        let mut rotated = profile.clone();
        rotated.generation += 1;
        let rotated_journal = prepare_download_resume_journal_in(
            &directory,
            &rotated,
            "/tmp/source",
            &local,
            ipc::TransferBackend::Native,
            &replacement_id,
        )
        .unwrap();
        let rotated_snapshot = rotated_journal.snapshot().unwrap();
        assert_eq!(rotated_snapshot.transfer_id, replacement_id);
        assert_eq!(rotated_snapshot.durable_offset, 0);
        assert_eq!(rotated_snapshot.expected_size, None);

        serctl_core::security::write_protected_atomic(&resumed.path, b"{\"schema\":99}").unwrap();
        assert!(prepare_download_resume_journal_in(
            &directory,
            &profile,
            "/tmp/source",
            &local,
            ipc::TransferBackend::Native,
            &replacement_id,
        )
        .is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    impl AsyncWrite for FlushTrackingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushed = true;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct FailAfterBytesWriter {
        fail_after: usize,
        fail_flush: bool,
        accepted: usize,
        poll_writes: usize,
        flushes: usize,
    }

    impl AsyncWrite for FailAfterBytesWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.poll_writes += 1;
            if self.accepted >= self.fail_after {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "injected broken pipe",
                )));
            }
            let written = (self.fail_after - self.accepted).min(buf.len());
            self.accepted += written;
            Poll::Ready(Ok(written))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            if self.fail_flush {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "injected flush failure",
                )))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PendingUntilWriter {
        ready: Pin<Box<tokio::time::Sleep>>,
        accepted: usize,
        poll_writes: usize,
    }

    impl AsyncWrite for PendingUntilWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.poll_writes += 1;
            if self.ready.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.accepted += buf.len();
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn dropping_stdin_pump_stops_its_blocking_poll_thread() {
        struct ExitMarker(Arc<AtomicBool>);

        impl Drop for ExitMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let started = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicBool::new(false));
        let poll_started = Arc::clone(&started);
        let marker = ExitMarker(Arc::clone(&exited));
        let pump = spawn_stdin_pump_with(
            move |_| {
                let _keep_marker_alive = &marker;
                poll_started.store(true, Ordering::Release);
                std::thread::sleep(std::time::Duration::from_millis(5));
                Ok(false)
            },
            || -> std::io::Result<Event> { unreachable!("read must not follow a false poll") },
        );

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stdin poll worker did not start");
        drop(pump);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !exited.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled stdin poll worker did not exit");
    }

    #[tokio::test]
    async fn aborting_a_raw_mode_scope_runs_its_injected_restore() {
        let restored = Arc::new(AtomicBool::new(false));
        let worker_restored = Arc::clone(&restored);
        let (entered_tx, entered_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _raw_mode = enter_raw_mode_with(
                || Ok(()),
                move || worker_restored.store(true, Ordering::Release),
            )
            .unwrap();
            entered_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        entered_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(restored.load(Ordering::Acquire));
    }

    #[test]
    fn shell_keyboard_release_does_not_repeat_character_or_control_input() {
        let ctrl_c_release = Event::Key(KeyEvent::new_with_kind(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            KeyEventKind::Release,
        ));
        assert_eq!(key_to_bytes(&ctrl_c_release), None);

        let char_release = Event::Key(KeyEvent::new_with_kind(
            KeyCode::Char('x'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        ));
        assert_eq!(key_to_bytes(&char_release), None);

        for kind in [KeyEventKind::Press, KeyEventKind::Repeat] {
            let ctrl_c = Event::Key(KeyEvent::new_with_kind(
                KeyCode::Char('c'),
                KeyModifiers::CONTROL,
                kind,
            ));
            assert_eq!(key_to_bytes(&ctrl_c), Some(vec![3]));
        }
    }

    #[tokio::test]
    async fn shell_frame_reader_survives_competing_events_mid_frame() {
        let (mut reader, mut writer) = tokio::io::duplex(1);
        let (frame_tx, mut frame_rx) = mpsc::channel(1);
        let frame_pump = read_shell_frame_pump(&mut reader, frame_tx);
        tokio::pin!(frame_pump);
        let mut frame_pump_running = true;
        let expected = vec![0x5a; 32 * 1024];
        let sent = expected.clone();
        let writer_task = tokio::spawn(async move {
            ipc::write_frame_limited(
                &mut writer,
                &Frame::ShellOut { data: sent },
                ipc::MAX_SHELL_FRAME,
            )
            .await
            .unwrap();
        });

        let mut competing_events = 0_usize;
        let mut received = loop {
            tokio::select! {
                biased;
                frame = frame_rx.recv() => break frame
                    .expect("frame pump closed early")
                    .into_inner()
                    .unwrap()
                    .unwrap(),
                () = &mut frame_pump, if frame_pump_running => {
                    frame_pump_running = false;
                },
                _ = tokio::task::yield_now() => {
                    competing_events += 1;
                },
            }
        };
        writer_task.await.unwrap();
        match &mut received {
            Frame::ShellOut { data } => {
                assert_eq!(data, &expected);
                data.zeroize();
            }
            other => panic!("unexpected frame from persistent reader: {other:?}"),
        }
        assert!(
            competing_events > 0,
            "test did not exercise a competing select branch"
        );
    }

    #[tokio::test]
    async fn cancelling_full_shell_frame_pump_zeroizes_its_in_flight_frame() {
        let (reader, mut writer) = tokio::io::duplex(1);
        let (frame_tx, mut frame_rx) = mpsc::channel(1);
        let dropped = Arc::new(AtomicBool::new(false));
        let constructed = Arc::new(AtomicUsize::new(0));
        let pump_dropped = Arc::clone(&dropped);
        let pump_constructed = Arc::clone(&constructed);
        let pump = tokio::spawn(async move {
            let mut reader = reader;
            read_shell_frame_pump_inner(
                &mut reader,
                frame_tx,
                Some(pump_dropped),
                Some(pump_constructed),
            )
            .await;
        });

        for byte in [0x31, 0x32] {
            ipc::write_frame_limited(
                &mut writer,
                &Frame::ShellOut {
                    data: vec![byte; 1024],
                },
                ipc::MAX_SHELL_FRAME,
            )
            .await
            .unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while constructed.load(Ordering::Acquire) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pump did not construct its channel-blocked second envelope");

        pump.abort();
        assert!(pump.await.unwrap_err().is_cancelled());
        assert!(
            dropped.load(Ordering::Acquire),
            "cancelling a full pump bypassed its in-flight frame RAII cleanup"
        );
        let mut queued = frame_rx.try_recv().unwrap().into_inner().unwrap().unwrap();
        queued.zeroize_sensitive();
    }

    #[test]
    fn daemon_uptime_arithmetic_is_saturating_and_nonnegative() {
        assert_eq!(elapsed_nonnegative_seconds(10, 3), 7);
        assert_eq!(elapsed_nonnegative_seconds(3, 10), 0);
        assert_eq!(elapsed_nonnegative_seconds(i64::MAX, i64::MIN), i64::MAX);
    }

    #[test]
    fn daemon_terminal_lines_escape_controls_and_bidi_fields() {
        let hostile = "保留\n\u{1b}]52;c;payload\u{7}\u{202e}\u{2028}";
        let info = DaemonStatus {
            profile: hostile.into(),
            host: hostile.into(),
            user: hostile.into(),
            started_unix: 5,
            endpoint: hostile.into(),
        };
        let lines = [
            daemon_status_line(&info, 10),
            daemon_absent_line(hostile),
            daemon_down_line(hostile, false),
            terminal_safe_error(&anyhow::anyhow!("failure: {hostile}")),
        ];
        for line in lines {
            assert!(line.contains("保留"));
            assert!(line.contains("\\n"));
            assert!(line.contains("\\u{1b}"));
            assert!(line.contains("\\u{202e}"));
            assert!(line.contains("\\u{2028}"));
            assert!(!line.chars().any(char::is_control));
            assert!(!line.contains('\u{202e}'));
            assert!(!line.contains('\u{2028}'));
        }
        assert_eq!(terminal_safe_field("普通 Unicode"), "普通 Unicode");
        assert_eq!(daemon_down_line(hostile, true), "daemon stopped");
    }

    #[tokio::test]
    async fn daemon_tunnel_setup_sends_the_authorized_root_frame_before_ready() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let spec = TunnelSpec::local(0, 5432);
        let request = Frame::TunnelOpen { spec: spec.clone() };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let server_task = tokio::spawn(async move {
            match ipc::read_frame_limited(&mut server, ipc::MAX_REQUEST_FRAME)
                .await
                .unwrap()
            {
                Some(Frame::TunnelOpen { spec: received }) => assert_eq!(received, spec),
                other => panic!("unexpected tunnel root request: {other:?}"),
            }
            ipc::write_frame_limited(
                &mut server,
                &Frame::TunnelReady {
                    ready: TunnelReady {
                        mode: TunnelMode::Local,
                        bind_host: "127.0.0.1".into(),
                        bind_port: 45123,
                    },
                },
                ipc::MAX_CONTROL_FRAME,
            )
            .await
            .unwrap();
        });

        let ready =
            read_daemon_tunnel_ready_until(&mut client, &request, TunnelMode::Local, deadline)
                .await
                .unwrap();
        assert_eq!(ready.bind_host, "127.0.0.1");
        assert_eq!(ready.bind_port, 45123);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_an_ipc_tunnel_sends_stop_and_waits_for_closed() {
        let (client, mut server) = tokio::io::duplex(8 * 1024);
        let cancellation = CancellationToken::new();
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let worker_cancel = cancellation.clone();
        let worker = tokio::spawn(run_gui_ipc_tunnel(client, event_tx, worker_cancel));

        cancellation.cancel();
        assert!(matches!(
            ipc::read_frame_limited(&mut server, ipc::MAX_CONTROL_FRAME)
                .await
                .unwrap(),
            Some(Frame::TunnelStop)
        ));
        ipc::write_frame_limited(&mut server, &Frame::TunnelClosed, ipc::MAX_CONTROL_FRAME)
            .await
            .unwrap();

        worker.await.unwrap().unwrap();
        assert!(matches!(event_rx.recv().await, Some(TunnelEvent::Closed)));
    }

    #[tokio::test]
    async fn cancelling_an_ipc_tunnel_preserves_a_partially_read_terminal_frame() {
        // Capacity one forces the first write to make progress only as the
        // client's pinned decoder consumes it. Cancellation therefore lands
        // after a partial length header has definitely been read.
        let (client, server) = tokio::io::duplex(1);
        let (mut server_reader, mut server_writer) = tokio::io::split(server);
        let cancellation = CancellationToken::new();
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let worker_cancel = cancellation.clone();
        let worker = tokio::spawn(run_gui_ipc_tunnel(client, event_tx, worker_cancel));

        let json = serde_json::to_vec(&Frame::TunnelClosed).unwrap();
        let mut wire = Vec::with_capacity(4 + json.len());
        wire.extend_from_slice(&(json.len() as u32).to_be_bytes());
        wire.extend_from_slice(&json);
        server_writer.write_all(&wire[..3]).await.unwrap();
        cancellation.cancel();

        let remaining = wire[3..].to_vec();
        let terminal_writer = tokio::spawn(async move {
            server_writer.write_all(&remaining).await.unwrap();
        });
        assert!(matches!(
            ipc::read_frame_limited(&mut server_reader, ipc::MAX_CONTROL_FRAME)
                .await
                .unwrap(),
            Some(Frame::TunnelStop)
        ));
        terminal_writer.await.unwrap();

        worker.await.unwrap().unwrap();
        assert!(matches!(event_rx.recv().await, Some(TunnelEvent::Closed)));
    }

    #[tokio::test]
    async fn command_output_is_flushed_before_the_cli_exits() {
        let output = CommandOutput {
            stdout: b"short stdout".to_vec(),
            stderr: b"short stderr".to_vec(),
            code: Some(0),
        };
        let mut stdout = FlushTrackingWriter::default();
        let mut stderr = FlushTrackingWriter::default();

        write_command_output_to(&output, &mut stdout, &mut stderr)
            .await
            .unwrap();

        assert_eq!(stdout.bytes, output.stdout);
        assert_eq!(stderr.bytes, output.stderr);
        assert!(stdout.flushed);
        assert!(stderr.flushed);
    }

    #[tokio::test]
    async fn shell_input_write_deadline_releases_an_unread_stream() {
        let (mut writer, _unread_peer) = tokio::io::duplex(8);
        let payload = vec![0x41; 1024];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(25);

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            complete_shell_input_write_until(writer.write_all(&payload), deadline),
        )
        .await
        .expect("the shell write helper must enforce its own deadline")
        .unwrap_err();

        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn oversized_shell_input_is_rejected_and_zeroized_before_routing() {
        let mut input = Zeroizing::new(vec![0xa5; MAX_SHELL_INPUT_BYTES + 1]);
        let error = validate_shell_input(&mut input).unwrap_err();
        assert!(error.to_string().contains("shell input exceeds"));
        assert!(input.iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn upload_commit_response_survives_request_deadline_reconciliation() {
        let (mut daemon, mut client) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            ipc::write_frame_limited(
                &mut daemon,
                &Frame::TransferDone { bytes: 37 },
                ipc::MAX_CONTROL_FRAME,
            )
            .await
            .unwrap();
        });
        let cancellation = CancellationToken::new();
        let mut rate_tracker = TransferRateTracker::new(Instant::now());
        let bytes = await_daemon_upload_commit_response_with_grace(
            &mut client,
            super::CommitWait {
                expected: 37,
                request_deadline: tokio::time::Instant::now(),
                cancellation: &cancellation,
                reconciliation_only: true,
                reconciliation_grace: std::time::Duration::from_millis(100),
                rate_tracker: &mut rate_tracker,
                progress_sink: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(bytes, 37);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_post_commit_response_is_typed_as_outcome_unknown() {
        let (mut daemon, mut client) = tokio::io::duplex(1024);
        daemon.write_all(&1_u32.to_be_bytes()).await.unwrap();
        daemon.write_all(b"{").await.unwrap();
        drop(daemon);
        let cancellation = CancellationToken::new();
        let mut rate_tracker = TransferRateTracker::new(Instant::now());
        let error = await_daemon_upload_commit_response_with_grace(
            &mut client,
            super::CommitWait {
                expected: 37,
                request_deadline: tokio::time::Instant::now(),
                cancellation: &cancellation,
                reconciliation_only: true,
                reconciliation_grace: std::time::Duration::from_millis(100),
                rate_tracker: &mut rate_tracker,
                progress_sink: None,
            },
        )
        .await
        .unwrap_err();
        assert!(error.is::<UploadCommitOutcomeUnknown>());
        assert!(error
            .to_string()
            .contains("inspect the target before retry"));
    }

    #[tokio::test]
    async fn lost_shutdown_ack_reconciles_when_the_runtime_lock_disappears() {
        let (mut client, mut daemon) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            assert!(matches!(
                ipc::read_frame_limited(&mut daemon, ipc::MAX_CONTROL_FRAME)
                    .await
                    .unwrap(),
                Some(Frame::Shutdown { .. })
            ));
            // Dropping without Ack models a daemon that consumed Shutdown and
            // released its runtime lock before the response reached us.
        });
        let mut shutdown_sent = false;
        let request = Frame::Shutdown {
            passphrase: "profile-passphrase".into(),
        };
        let exchange = shutdown_daemon_exchange(
            &mut client,
            &request,
            &mut shutdown_sent,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .map(|()| true);
        server.await.unwrap();
        assert!(shutdown_sent);
        assert!(exchange.is_err());

        let contacted = reconcile_shutdown_exchange(exchange, shutdown_sent, async { Ok(()) })
            .await
            .unwrap();
        assert!(contacted);
    }

    #[tokio::test]
    async fn shutdown_submission_tracks_only_a_complete_request_frame() {
        let request = Frame::Shutdown {
            passphrase: "profile-passphrase".into(),
        };
        let expired_deadline = tokio::time::Instant::now() - Duration::from_millis(1);
        let mut expired_writer = FailAfterBytesWriter {
            fail_after: usize::MAX,
            ..FailAfterBytesWriter::default()
        };
        let mut expired_sent = false;
        let expired = write_shutdown_request_until(
            &mut expired_writer,
            &request,
            &mut expired_sent,
            expired_deadline,
        )
        .await
        .unwrap_err();
        assert!(!expired_sent);
        assert_eq!(expired_writer.poll_writes, 0);
        assert!(format!("{expired:#}").contains("deadline"));

        let mut partial_writer = FailAfterBytesWriter {
            fail_after: 1,
            ..FailAfterBytesWriter::default()
        };
        let mut partial_sent = false;
        let partial = write_shutdown_request_until(
            &mut partial_writer,
            &request,
            &mut partial_sent,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert_eq!(partial_writer.accepted, 1);
        assert!(!partial_sent);
        assert!(format!("{partial:#}").contains("broken pipe"));

        let mut flush_writer = FailAfterBytesWriter {
            fail_after: usize::MAX,
            fail_flush: true,
            ..FailAfterBytesWriter::default()
        };
        let mut complete_sent = false;
        let flush = write_shutdown_request_until(
            &mut flush_writer,
            &request,
            &mut complete_sent,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(complete_sent);
        assert_eq!(flush_writer.flushes, 1);
        assert!(format!("{flush:#}").contains("flush failure"));
        assert!(
            reconcile_shutdown_exchange(Err(flush), complete_sent, async { Ok(()) })
                .await
                .unwrap()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn losing_spawn_candidate_accepts_any_published_daemon() {
        let winning_instance = ipc::v6::InstanceId::random();
        let winner = DaemonAccess {
            instance_id: winning_instance,
            secret: ipc::v6::ActivationSecret::random(),
            endpoint: "winning-endpoint".into(),
            pid: 11,
        };
        let mut observation = 0_u8;

        let access = wait_for_published_daemon_until(
            tokio::time::Instant::now() + Duration::from_secs(1),
            move || {
                observation += 1;
                let candidate = match observation {
                    1 => None,
                    _ => Some(winner.clone()),
                };
                std::future::ready(Ok::<_, anyhow::Error>(candidate))
            },
        )
        .await
        .unwrap();

        assert_eq!(access.instance_id.as_hex(), winning_instance.as_hex());
        assert_eq!(access.endpoint, "winning-endpoint");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn absent_daemon_waits_for_the_runtime_state_to_clear() {
        let exited = Arc::new(AtomicBool::new(false));
        let probe_started = Arc::new(Notify::new());
        let exit_flag = Arc::clone(&exited);
        let exit_started = Arc::clone(&probe_started);
        let releaser = tokio::spawn(async move {
            exit_started.notified().await;
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            exit_flag.store(true, Ordering::Release);
        });
        let probe_flag = Arc::clone(&exited);
        let probe_notice = Arc::clone(&probe_started);
        let started = tokio::time::Instant::now();

        wait_for_daemon_absent_until(std::time::Duration::from_secs(1), move |_| {
            let exited = Arc::clone(&probe_flag);
            let probe_started = Arc::clone(&probe_notice);
            async move {
                if exited.load(Ordering::Acquire) {
                    Ok(true)
                } else {
                    probe_started.notify_one();
                    Ok(false)
                }
            }
        })
        .await
        .unwrap();

        releaser.await.unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(60));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_state_clearing_ends_the_shutdown_wait() {
        let observations = Arc::new(AtomicUsize::new(0));
        let observation_count = Arc::clone(&observations);
        let started = tokio::time::Instant::now();
        wait_for_daemon_absent_until(std::time::Duration::from_secs(1), move |_| {
            let observation = observation_count.fetch_add(1, Ordering::Relaxed);
            async move { Ok(observation > 0) }
        })
        .await
        .unwrap();

        assert_eq!(observations.load(Ordering::Relaxed), 2);
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exit_probe_io_error_never_counts_as_shutdown_success() {
        let error = wait_for_daemon_absent_until(std::time::Duration::from_secs(1), |_| async {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
        })
        .await
        .unwrap_err();

        assert!(error.to_string().contains("probe daemon exit"));
    }

    #[test]
    fn daemon_lock_release_wait_covers_bounded_shutdown_cleanup() {
        assert!(DAEMON_LOCK_RELEASE_TIMEOUT >= std::time::Duration::from_secs(10));
        assert!(DAEMON_LOCK_RELEASE_TIMEOUT <= std::time::Duration::from_secs(12));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn agent_transfer_push_requires_exact_transfer_write_scope_before_local_io() {
        let signing = SigningKey::generate(&mut OsRng);
        let grant = serctl_protocol::grant::OperationGrant::new(
            "prod".into(),
            [2_u8; 16],
            vec!["sftp.write".into(), "ssh.exec".into()],
            2,
            &signing.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let local = std::env::temp_dir()
            .join("serctl-agent-scope-must-not-open")
            .join("credential-material.bin");
        let error = agent_transfer_push_until(
            &grant,
            &signing,
            &local,
            "/tmp/agent-scope-test",
            TransferOptions {
                backend: ipc::TransferBackend::Sftp,
                resume: ipc::TransferResumeMode::Never,
                idle_timeout: Duration::from_secs(1),
                deadline: Some(Duration::from_secs(2)),
                progress: None,
            },
        )
        .await
        .unwrap_err();
        assert!(error.is::<AgentTransferWriteScopeRequired>());
        assert_eq!(error.to_string(), "grant does not authorize transfer.write");
        assert!(!error.to_string().contains(local.to_string_lossy().as_ref()));

        let root = ipc::Frame::UploadBegin {
            transfer_id: ipc::TransferId::random(),
            path: "/tmp/agent-scope-test".into(),
            size: 1,
            sha256: "00".repeat(32),
            backend: ipc::TransferBackend::Sftp,
            resume: ipc::TransferResumeMode::Never,
            resume_token: None,
            idle_timeout_ms: 1_000,
            deadline_ms: Some(2_000),
        };
        assert_eq!(
            serctl_protocol::v6::frame_kind(&root),
            AGENT_TRANSFER_WRITE_OPERATION
        );
        assert_ne!(serctl_protocol::v6::frame_kind(&root), "sftp.write");
        assert_ne!(serctl_protocol::v6::frame_kind(&root), "ssh.exec");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn agent_transfer_push_json_error_withholds_local_path_and_credentials() {
        let signing = SigningKey::generate(&mut OsRng);
        let grant = serctl_protocol::grant::OperationGrant::new(
            "prod".into(),
            [2_u8; 16],
            vec![AGENT_TRANSFER_WRITE_OPERATION.into()],
            1,
            &signing.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let marker = "PROFILE_PASSWORD_DO_NOT_LEAK";
        let local = std::env::temp_dir()
            .join(format!(
                "serctl-agent-private-{}-{marker}",
                std::process::id()
            ))
            .join("missing-source.bin");
        let result = dispatch_agent_request(
            &grant,
            &signing,
            AgentRequest::TransferPush {
                request_id: 77,
                local: local.clone(),
                remote: "/tmp/agent-redaction-test".into(),
                backend: Some(ipc::TransferBackend::Sftp),
                resume: Some(ipc::TransferResumeMode::Never),
                idle_timeout_ms: Some(1_000),
                deadline_ms: Some(2_000),
            },
        )
        .await;
        assert_eq!(result.request_id, 77);
        assert!(!result.ok);
        assert_eq!(
            result.error.as_deref(),
            Some("transfer-push failed (local diagnostic detail withheld)")
        );
        assert!(result.data.is_none());

        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains(local.to_string_lossy().as_ref()));
        assert!(!encoded.contains(marker));
        assert!(!encoded.contains("missing-source.bin"));
    }

    #[test]
    fn load_agent_grant_rejects_holder_key_mismatch_without_leaking_key() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "serctl-agent-grant-key-mismatch-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let other = SigningKey::from_bytes(&[8_u8; 32]);
        let grant = serctl_protocol::grant::OperationGrant::new(
            "prod".into(),
            [2_u8; 16],
            vec![AGENT_TRANSFER_WRITE_OPERATION.into()],
            1,
            &other.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let encoded_key = B64.encode(signing.to_bytes());
        let file = AgentGrantFile {
            grant,
            agent_key: encoded_key.clone(),
        };
        let path = base.join("agent-grant.json");
        super::write_agent_grant_file(&path, &serde_json::to_vec(&file).unwrap()).unwrap();

        let error = load_agent_grant(&path).unwrap_err();
        let message = error.to_string();
        assert_eq!(message, "agent grant key does not match its holder binding");
        assert!(!message.contains(&encoded_key));

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn load_agent_grant_rejects_expired_grant_before_request_processing() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "serctl-agent-grant-expired-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let signing = SigningKey::from_bytes(&[9_u8; 32]);
        let ttl_ms = u64::try_from(serctl_protocol::grant::GRANT_DEFAULT_TTL.as_millis()).unwrap();
        let issued_unix_ms = super::now_unix_ms().checked_sub(ttl_ms + 1_000).unwrap();
        let grant = serctl_protocol::grant::OperationGrant::new(
            "prod".into(),
            [2_u8; 16],
            vec![AGENT_TRANSFER_WRITE_OPERATION.into()],
            1,
            &signing.verifying_key(),
            issued_unix_ms,
        )
        .unwrap();
        assert!(grant.is_expired(super::now_unix_ms()));
        let file = AgentGrantFile {
            grant,
            agent_key: B64.encode(signing.to_bytes()),
        };
        let path = base.join("agent-grant.json");
        super::write_agent_grant_file(&path, &serde_json::to_vec(&file).unwrap()).unwrap();

        let error = load_agent_grant(&path).unwrap_err();
        assert_eq!(error.to_string(), "agent grant has expired");

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn agent_stdio_gateway_reports_invalid_request_lines_without_a_daemon() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "serctl-agent-gateway-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let issued_unix_ms = super::now_unix_ms();
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let grant = serctl_protocol::grant::OperationGrant {
            grant_id: [1_u8; 16],
            profile_name: "prod".into(),
            profile_id: [2_u8; 16],
            operations: vec!["ssh.exec".into()],
            budget: 1,
            issued_unix_ms,
            expires_unix_ms: issued_unix_ms
                + u64::try_from(serctl_protocol::grant::GRANT_DEFAULT_TTL.as_millis()).unwrap(),
            holder_key: signing.verifying_key().to_bytes(),
        };
        let file = AgentGrantFile {
            grant,
            agent_key: B64.encode(signing.to_bytes()),
        };
        let path = base.join("agent-grant.json");
        super::write_agent_grant_file(&path, &serde_json::to_vec(&file).unwrap()).unwrap();

        let (mut input, output) = tokio::io::duplex(1024);
        input.write_all(b"not-json\n").await.unwrap();
        input.write_all(b"\n").await.unwrap();
        drop(input);
        let mut captured = Vec::new();
        agent_stdio_loop_with(output, &mut captured, &path)
            .await
            .unwrap();
        let line: serde_json::Value = serde_json::from_slice(&captured).unwrap();
        assert_eq!(line["request_id"], 0);
        assert_eq!(line["ok"], false);
        assert!(line["error"]
            .as_str()
            .is_some_and(|error| error.contains("invalid request")));
        // Empty lines are skipped, so exactly one result line was emitted.
        assert_eq!(captured.iter().filter(|byte| **byte == b'\n').count(), 1);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_runtime_lock_poll_cannot_extend_its_absolute_deadline() {
        let completed = Arc::new(AtomicBool::new(false));
        let worker_completed = Arc::clone(&completed);
        let task = tokio::task::spawn_blocking(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            worker_completed.store(true, Ordering::Release);
            Ok::<_, anyhow::Error>(())
        });
        let started = std::time::Instant::now();
        let error = join_blocking_until(
            task,
            tokio::time::Instant::now() + std::time::Duration::from_millis(25),
            "runtime-lock shutdown poll",
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("exceeded its deadline"));
        assert!(started.elapsed() < std::time::Duration::from_millis(150));
        // An active OS filesystem call cannot be preempted, but this poll is
        // read-only; its late completion cannot mutate lock state.
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !completed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn gui_shell_cancel_preempts_already_queued_input() {
        let (client_io, mut remote_io) = tokio::io::duplex(4096);
        let (rd, wr) = tokio::io::split(client_io);
        let (input_tx, input_rx) = mpsc::channel(4);
        let (event_tx, _event_rx) = mpsc::channel(4);
        let cancellation = CancellationToken::new();
        input_tx
            .send(Zeroizing::new(b"must-not-reach-old-profile".to_vec()))
            .await
            .unwrap();
        cancellation.cancel();

        run_gui_ipc_shell(rd, wr, input_rx, event_tx, cancellation).await;

        let mut received = Vec::new();
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            remote_io.read_to_end(&mut received),
        )
        .await
        .expect("cancelled shell worker must close its IPC stream")
        .unwrap();
        assert_eq!(count, 0);
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn pre_ready_gui_cancellation_drops_guarded_output_before_backpressure_wait() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        event_tx.send(ShellEvent::Closed).await.unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let sent = send_gui_shell_output_or_cancel(
            &event_tx,
            Zeroizing::new(vec![0xa5; 4096]),
            &cancellation,
        )
        .await
        .unwrap();

        assert!(!sent);
        assert!(matches!(event_rx.recv().await, Some(ShellEvent::Closed)));
        assert!(matches!(
            event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn exec_disconnect_before_exit_status_is_an_error() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        ipc::write_frame(
            &mut writer,
            &Frame::ExecOut {
                data: b"partial".to_vec(),
            },
        )
        .await
        .unwrap();
        drop(writer);

        let error = read_exec_response(&mut reader).await.unwrap_err();
        assert!(error.to_string().contains("disconnected"));
    }

    #[tokio::test]
    async fn exec_requires_a_concrete_exit_status() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        ipc::write_frame(&mut writer, &Frame::ExecExit { code: None })
            .await
            .unwrap();
        let error = read_exec_response(&mut reader).await.unwrap_err();
        assert!(error.to_string().contains("without an exit status"));
    }

    #[tokio::test]
    async fn expired_daemon_exec_deadline_does_not_poll_or_write_request() {
        let (mut writer, mut peer) = tokio::io::duplex(1024);
        let mut submission = ExecSubmissionState::BeforeRequest;
        let error = write_daemon_exec_request_until(
            &mut writer,
            "must-not-be-written",
            1,
            tokio::time::Instant::now() - Duration::from_millis(1),
            &mut submission,
        )
        .await
        .unwrap_err();

        assert_eq!(submission, ExecSubmissionState::BeforeRequest);
        assert!(!error.is::<ExecOutcomeUnknown>());
        assert!(
            tokio::time::timeout(Duration::from_millis(25), peer.read_u8())
                .await
                .is_err(),
            "expired request wrote bytes before returning"
        );
    }

    #[tokio::test]
    async fn daemon_exec_pending_writer_is_not_polled_after_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        let mut writer = PendingUntilWriter {
            ready: Box::pin(tokio::time::sleep_until(deadline)),
            accepted: 0,
            poll_writes: 0,
        };
        let mut submission = ExecSubmissionState::BeforeRequest;
        let error = write_daemon_exec_request_until(
            &mut writer,
            "must-not-write-after-deadline",
            200,
            deadline,
            &mut submission,
        )
        .await
        .unwrap_err();

        assert_eq!(writer.poll_writes, 1);
        assert_eq!(writer.accepted, 0);
        assert_eq!(submission, ExecSubmissionState::BeforeRequest);
        assert!(!error.is::<ExecOutcomeUnknown>());
        assert!(error.to_string().contains("deadline"));
    }

    #[tokio::test]
    async fn daemon_exec_zero_byte_write_and_serialization_errors_stay_pre_request() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut broken_pipe = FailAfterBytesWriter::default();
        let mut submission = ExecSubmissionState::BeforeRequest;
        let error = write_daemon_exec_request_until(
            &mut broken_pipe,
            "not-written",
            1_000,
            deadline,
            &mut submission,
        )
        .await
        .unwrap_err();
        assert_eq!(broken_pipe.accepted, 0);
        assert_eq!(broken_pipe.poll_writes, 1);
        assert_eq!(submission, ExecSubmissionState::BeforeRequest);
        assert!(!error.is::<ExecOutcomeUnknown>());
        assert!(error.to_string().contains("broken pipe"));

        let oversized = "x".repeat(ipc::MAX_REQUEST_FRAME + 1);
        let mut never_polled = FailAfterBytesWriter::default();
        let mut serialization_submission = ExecSubmissionState::BeforeRequest;
        let serialization_error = write_daemon_exec_request_until(
            &mut never_polled,
            &oversized,
            1_000,
            deadline,
            &mut serialization_submission,
        )
        .await
        .unwrap_err();
        assert_eq!(never_polled.accepted, 0);
        assert_eq!(never_polled.poll_writes, 0);
        assert_eq!(serialization_submission, ExecSubmissionState::BeforeRequest);
        assert!(!serialization_error.is::<ExecOutcomeUnknown>());
    }

    #[tokio::test]
    async fn daemon_exec_partial_frame_failure_stays_pre_request() {
        let mut one_byte_then_broken_pipe = FailAfterBytesWriter {
            fail_after: 1,
            ..FailAfterBytesWriter::default()
        };
        let mut submission = ExecSubmissionState::BeforeRequest;
        let error = write_daemon_exec_request_until(
            &mut one_byte_then_broken_pipe,
            "partially-written",
            1_000,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &mut submission,
        )
        .await
        .unwrap_err();

        assert_eq!(one_byte_then_broken_pipe.accepted, 1);
        assert_eq!(one_byte_then_broken_pipe.poll_writes, 2);
        assert_eq!(submission, ExecSubmissionState::BeforeRequest);
        assert!(!error.is::<ExecOutcomeUnknown>());
    }

    #[tokio::test]
    async fn daemon_exec_flush_failure_after_complete_frame_is_outcome_unknown() {
        let mut flush_failure = FailAfterBytesWriter {
            fail_after: usize::MAX,
            fail_flush: true,
            ..FailAfterBytesWriter::default()
        };
        let mut submission = ExecSubmissionState::BeforeRequest;
        let error = write_daemon_exec_request_until(
            &mut flush_failure,
            "fully-written",
            1_000,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &mut submission,
        )
        .await
        .unwrap_err();

        assert!(flush_failure.accepted > 4);
        assert_eq!(flush_failure.flushes, 1);
        assert_eq!(submission, ExecSubmissionState::RequestMayHaveReachedRemote);
        assert!(error.is::<ExecOutcomeUnknown>());
        assert!(error
            .to_string()
            .contains("inspect remote side effects before retry"));
    }

    #[tokio::test]
    async fn daemon_create_directory_submission_uses_the_complete_frame_boundary() {
        let mut expired_writer = FailAfterBytesWriter {
            fail_after: usize::MAX,
            ..FailAfterBytesWriter::default()
        };
        let mut expired_submission = CreateDirSubmissionState::BeforeRequest;
        let expired = write_daemon_create_dir_request_until(
            &mut expired_writer,
            "/expired",
            1,
            tokio::time::Instant::now() - Duration::from_millis(1),
            &mut expired_submission,
        )
        .await
        .unwrap_err();
        assert_eq!(expired_writer.poll_writes, 0);
        assert_eq!(expired_submission, CreateDirSubmissionState::BeforeRequest);
        assert!(!expired.is::<CreateDirOutcomeUnknown>());

        let mut partial_writer = FailAfterBytesWriter {
            fail_after: 1,
            ..FailAfterBytesWriter::default()
        };
        let mut partial_submission = CreateDirSubmissionState::BeforeRequest;
        let partial = write_daemon_create_dir_request_until(
            &mut partial_writer,
            "/partial",
            1_000,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &mut partial_submission,
        )
        .await
        .unwrap_err();
        assert_eq!(partial_writer.accepted, 1);
        assert_eq!(partial_submission, CreateDirSubmissionState::BeforeRequest);
        assert!(!partial.is::<CreateDirOutcomeUnknown>());

        let mut flush_writer = FailAfterBytesWriter {
            fail_after: usize::MAX,
            fail_flush: true,
            ..FailAfterBytesWriter::default()
        };
        let mut complete_submission = CreateDirSubmissionState::BeforeRequest;
        let flush = write_daemon_create_dir_request_until(
            &mut flush_writer,
            "/complete",
            1_000,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &mut complete_submission,
        )
        .await
        .unwrap_err();
        assert_eq!(
            complete_submission,
            CreateDirSubmissionState::RequestMayHaveReachedRemote
        );
        assert!(flush.is::<CreateDirOutcomeUnknown>());
        assert!(flush
            .to_string()
            .contains("inspect the remote path before retry"));
    }

    #[tokio::test]
    async fn daemon_create_directory_wire_errors_preserve_definite_and_unknown_outcomes() {
        let mut submission = CreateDirSubmissionState::BeforeRequest;
        submission.request_started();

        let (mut plain_writer, mut plain_reader) = tokio::io::duplex(1024);
        ipc::write_frame(
            &mut plain_writer,
            &Frame::Error {
                msg: "permission denied by SFTP server".into(),
            },
        )
        .await
        .unwrap();
        let plain = read_daemon_create_dir_response_until(
            &mut plain_reader,
            1_000,
            tokio::time::Instant::now() + Duration::from_secs(1),
            submission,
        )
        .await
        .unwrap_err();
        assert!(!plain.is::<CreateDirOutcomeUnknown>());

        let typed_message = submission
            .classify(anyhow::anyhow!("server disconnected after MKDIR"))
            .to_string();
        let (mut typed_writer, mut typed_reader) = tokio::io::duplex(1024);
        ipc::write_frame(&mut typed_writer, &Frame::Error { msg: typed_message })
            .await
            .unwrap();
        let typed = read_daemon_create_dir_response_until(
            &mut typed_reader,
            1_000,
            tokio::time::Instant::now() + Duration::from_secs(1),
            submission,
        )
        .await
        .unwrap_err();
        assert!(typed.is::<CreateDirOutcomeUnknown>());
        assert_eq!(typed.to_string().matches("outcome unknown").count(), 1);
    }

    #[tokio::test]
    async fn daemon_create_directory_lost_or_unexpected_response_is_outcome_unknown() {
        let mut submission = CreateDirSubmissionState::BeforeRequest;
        submission.request_started();

        let (writer, mut eof_reader) = tokio::io::duplex(64);
        drop(writer);
        let eof = read_daemon_create_dir_response_until(
            &mut eof_reader,
            1_000,
            tokio::time::Instant::now() + Duration::from_secs(1),
            submission,
        )
        .await
        .unwrap_err();
        assert!(eof.is::<CreateDirOutcomeUnknown>());

        let (mut unexpected_writer, mut unexpected_reader) = tokio::io::duplex(1024);
        ipc::write_frame(&mut unexpected_writer, &Frame::Status)
            .await
            .unwrap();
        let unexpected = read_daemon_create_dir_response_until(
            &mut unexpected_reader,
            1_000,
            tokio::time::Instant::now() + Duration::from_secs(1),
            submission,
        )
        .await
        .unwrap_err();
        assert!(unexpected.is::<CreateDirOutcomeUnknown>());
    }

    #[tokio::test]
    async fn daemon_plain_exec_error_remains_an_ordinary_rejection() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        ipc::write_frame(
            &mut writer,
            &Frame::Error {
                msg: "buffered-operation capacity is unavailable".into(),
            },
        )
        .await
        .unwrap();

        let mut submission = ExecSubmissionState::BeforeRequest;
        submission.request_started();
        let wire_error = read_exec_response(&mut reader).await.unwrap_err();
        let error = classify_daemon_exec_read_error(submission, wire_error);
        assert!(!error.is::<ExecOutcomeUnknown>());
        assert_eq!(
            error.to_string(),
            "buffered-operation capacity is unavailable"
        );
    }

    #[tokio::test]
    async fn daemon_typed_exec_error_is_restored_without_duplicate_wrapping() {
        let mut submission = ExecSubmissionState::BeforeRequest;
        submission.request_started();
        let wire_message = submission
            .classify(anyhow::anyhow!("remote finish response was lost"))
            .to_string();
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        ipc::write_frame(&mut writer, &Frame::Error { msg: wire_message })
            .await
            .unwrap();

        let wire_error = read_exec_response(&mut reader).await.unwrap_err();
        let error = classify_daemon_exec_read_error(submission, wire_error);
        assert!(error.is::<ExecOutcomeUnknown>());
        assert_eq!(error.to_string().matches("outcome unknown").count(), 1);
        assert_eq!(
            error
                .to_string()
                .matches("inspect remote side effects before retry")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn every_route_rejects_invalid_commands_and_paths_before_io() {
        let timeout = std::time::Duration::from_secs(1);
        let deadline = tokio::time::Instant::now() + timeout;
        let oversized_command = "x".repeat(serctl_core::ssh::MAX_REMOTE_COMMAND_BYTES + 1);
        assert!(exec_capture_with_timeout_inner(
            "profile-that-must-not-be-read",
            &oversized_command,
            None,
            false,
            None,
            timeout,
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("remote command exceeds"));
        assert!(exec_capture_with_timeout_inner(
            "profile-that-must-not-be-read",
            "echo\0hidden",
            None,
            false,
            None,
            timeout,
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("NUL"));

        assert!(list_dir_inner(
            "profile-that-must-not-be-read",
            "bad\0path",
            None,
            None,
            1,
            deadline,
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("NUL"));
        assert!(
            create_dir_inner("profile-that-must-not-be-read", "", None, None, 1, deadline,)
                .await
                .unwrap_err()
                .to_string()
                .contains("remote path")
        );
        assert!(upload_file_with_timeout_inner(
            "profile-that-must-not-be-read",
            std::path::Path::new("unused"),
            "",
            PendingProfileAuthorization {
                passphrase: None,
                prompt_if_missing: false,
                expected_generation: None,
            },
            TransferOptions::legacy(timeout),
            CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("remote path"));
        assert!(download_file_with_timeout_owned(
            "profile-that-must-not-be-read",
            "",
            std::path::Path::new("unused"),
            OwnedPendingProfileAuthorization {
                passphrase: None,
                prompt_if_missing: false,
                expected_generation: None,
            },
            TransferOptions::legacy(timeout),
            CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("remote path"));

        let (stream, mut peer) = tokio::io::duplex(64);
        let (mut reader, mut writer) = tokio::io::split(stream);
        let shell_error = start_ipc_shell_until(
            &mut reader,
            &mut writer,
            0,
            24,
            tokio::time::Instant::now() + timeout,
        )
        .await
        .unwrap_err();
        assert!(shell_error.to_string().contains("shell dimensions"));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), peer.read_u8())
                .await
                .is_err()
        );
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("client-{label}-{}-{nonce}", std::process::id()))
    }

    struct BlockingFsGate {
        entered: AtomicBool,
        released: StdMutex<bool>,
        wake: Condvar,
    }

    impl BlockingFsGate {
        fn new() -> Self {
            Self {
                entered: AtomicBool::new(false),
                released: StdMutex::new(false),
                wake: Condvar::new(),
            }
        }

        fn block(&self) {
            self.entered.store(true, Ordering::Release);
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.wake.wait(released).unwrap();
            }
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.wake.notify_all();
        }
    }

    async fn wait_for_flag(flag: &AtomicBool, label: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !flag.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
    }

    async fn wait_for_path_absent(path: &std::path::Path) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while tokio::fs::try_exists(path).await.unwrap() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("owned partial was not removed: {}", path.display()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_handle_identity_read_obeys_deadline_and_keeps_runtime_live() {
        let dir = unique_test_dir("identity-read-deadline");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("evidence");
        tokio::fs::write(&path, b"evidence").await.unwrap();
        let expected = tokio::fs::File::open(&path)
            .await
            .unwrap()
            .try_into_std()
            .unwrap();
        let actual = tokio::fs::File::open(&path)
            .await
            .unwrap()
            .try_into_std()
            .unwrap();
        let gate = Arc::new(BlockingFsGate::new());
        let reader_gate = Arc::clone(&gate);
        let reads = Arc::new(AtomicUsize::new(0));
        let reader_reads = Arc::clone(&reads);
        let finished = Arc::new(AtomicBool::new(false));
        let reader_finished = Arc::clone(&finished);
        let ticks = Arc::new(AtomicUsize::new(0));
        let heartbeat_ticks = Arc::clone(&ticks);
        let heartbeat_stop = Arc::new(AtomicBool::new(false));
        let heartbeat_stop_worker = Arc::clone(&heartbeat_stop);
        let heartbeat = tokio::spawn(async move {
            while !heartbeat_stop_worker.load(Ordering::Acquire) {
                heartbeat_ticks.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });

        let error = verify_owned_file_identities_until_with(
            expected,
            actual,
            tokio::time::Instant::now() + std::time::Duration::from_millis(80),
            move |_| {
                if reader_reads.fetch_add(1, Ordering::AcqRel) == 0 {
                    reader_gate.block();
                } else {
                    reader_finished.store(true, Ordering::Release);
                }
                Ok(7_u8)
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("exceeded its deadline"));
        assert!(
            ticks.load(Ordering::Relaxed) >= 3,
            "current-thread runtime stalled behind handle identity FFI"
        );
        gate.release();
        wait_for_flag(&finished, "late identity read completion").await;
        heartbeat_stop.store(true, Ordering::Release);
        heartbeat.await.unwrap();
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_upload_open_obeys_deadline_without_blocking_runtime_heartbeat() {
        let dir = unique_test_dir("upload-open-deadline");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let source = dir.join("source");
        tokio::fs::write(&source, b"stable source").await.unwrap();

        let gate = Arc::new(BlockingFsGate::new());
        let worker_gate = Arc::clone(&gate);
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let ticks = Arc::new(AtomicUsize::new(0));
        let heartbeat_ticks = Arc::clone(&ticks);
        let heartbeat_stop = Arc::new(AtomicBool::new(false));
        let heartbeat_stop_worker = Arc::clone(&heartbeat_stop);
        let heartbeat = tokio::spawn(async move {
            while !heartbeat_stop_worker.load(Ordering::Acquire) {
                heartbeat_ticks.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(80);
        let error = open_local_upload_source_with(
            source.clone(),
            deadline,
            &CancellationToken::new(),
            80,
            move |path| {
                worker_gate.block();
                let file = serctl_core::security::open_regular_file_for_read(&path)?;
                let size = file.metadata()?.len();
                worker_finished.store(true, Ordering::Release);
                Ok((file, size))
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("deadline of 80 ms"));
        assert!(
            ticks.load(Ordering::Relaxed) >= 3,
            "current-thread runtime heartbeat stalled behind local open"
        );
        gate.release();
        wait_for_flag(&finished, "late upload open").await;
        heartbeat_stop.store(true, Ordering::Release);
        heartbeat.await.unwrap();
        assert_eq!(tokio::fs::read(&source).await.unwrap(), b"stable source");
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn late_local_partial_after_deadline_is_eventually_removed() {
        let dir = unique_test_dir("partial-late-deadline");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part-random");
        let gate = Arc::new(BlockingFsGate::new());
        let worker_gate = Arc::clone(&gate);
        let created = Arc::new(AtomicBool::new(false));
        let worker_created = Arc::clone(&created);
        let error = create_local_download_partial_with(
            partial.clone(),
            tokio::time::Instant::now() + std::time::Duration::from_millis(60),
            &CancellationToken::new(),
            60,
            move |path| {
                worker_gate.block();
                let partial = UnclaimedLocalPartial::create(path)?;
                worker_created.store(true, Ordering::Release);
                Ok(partial)
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("deadline of 60 ms"));

        gate.release();
        wait_for_flag(&created, "late partial creation").await;
        wait_for_path_absent(&partial).await;
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_at_partial_handoff_keeps_cleanup_ownership() {
        let dir = unique_test_dir("partial-handoff-cancel");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part-random");
        let gate = Arc::new(BlockingFsGate::new());
        let worker_gate = Arc::clone(&gate);
        let created = Arc::new(AtomicBool::new(false));
        let worker_created = Arc::clone(&created);
        let cancellation = CancellationToken::new();
        let outer_cancellation = cancellation.clone();
        let worker_path = partial.clone();
        let outer = tokio::spawn(async move {
            create_local_download_partial_with(
                worker_path,
                tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                &outer_cancellation,
                2_000,
                move |path| {
                    let partial = UnclaimedLocalPartial::create(path)?;
                    worker_created.store(true, Ordering::Release);
                    worker_gate.block();
                    Ok(partial)
                },
            )
            .await
        });

        wait_for_flag(&created, "partial before handoff").await;
        cancellation.cancel();
        gate.release();
        let error = outer.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        wait_for_path_absent(&partial).await;
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_outer_partial_create_future_cleans_a_late_created_file() {
        let dir = unique_test_dir("partial-outer-drop");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part-random");
        let gate = Arc::new(BlockingFsGate::new());
        let worker_gate = Arc::clone(&gate);
        let created = Arc::new(AtomicBool::new(false));
        let worker_created = Arc::clone(&created);
        let worker_path = partial.clone();
        let outer = tokio::spawn(async move {
            create_local_download_partial_with(
                worker_path,
                tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                &CancellationToken::new(),
                2_000,
                move |path| {
                    worker_gate.block();
                    let partial = UnclaimedLocalPartial::create(path)?;
                    worker_created.store(true, Ordering::Release);
                    Ok(partial)
                },
            )
            .await
        });

        wait_for_flag(&gate.entered, "blocked partial create").await;
        outer.abort();
        assert!(outer.await.unwrap_err().is_cancelled());
        gate.release();
        wait_for_flag(&created, "partial after outer drop").await;
        wait_for_path_absent(&partial).await;
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_local_partial_cleanup_has_a_hard_join_deadline() {
        let dir = unique_test_dir("partial-cleanup-join-deadline");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part-random");
        tokio::fs::write(&partial, b"partial").await.unwrap();
        let gate = Arc::new(BlockingFsGate::new());
        let worker_gate = Arc::clone(&gate);
        let removed = Arc::new(AtomicBool::new(false));
        let worker_removed = Arc::clone(&removed);
        let started = tokio::time::Instant::now();

        run_local_partial_cleanup_with(
            partial.clone(),
            std::time::Duration::from_millis(60),
            move |path| {
                worker_gate.block();
                std::fs::remove_file(path).unwrap();
                worker_removed.store(true, Ordering::Release);
            },
        )
        .await;

        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "blocked cleanup worker escaped its async join deadline"
        );
        assert!(tokio::fs::try_exists(&partial).await.unwrap());
        gate.release();
        wait_for_flag(&removed, "detached cleanup completion").await;
        wait_for_path_absent(&partial).await;
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[test]
    fn queued_local_partial_cleanup_is_detached_without_losing_its_path() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let dir = unique_test_dir("partial-cleanup-queued");
            tokio::fs::create_dir_all(&dir).await.unwrap();
            let partial = dir.join("evidence.serctl-part-random");
            tokio::fs::write(&partial, b"partial").await.unwrap();
            let gate = Arc::new(BlockingFsGate::new());
            let blocker_gate = Arc::clone(&gate);
            let blocker = tokio::task::spawn_blocking(move || blocker_gate.block());
            wait_for_flag(&gate.entered, "blocking-pool saturation").await;

            run_local_partial_cleanup_with(
                partial.clone(),
                std::time::Duration::from_millis(60),
                |path| std::fs::remove_file(path).unwrap(),
            )
            .await;

            // A Tokio filesystem probe would itself queue behind the single
            // deliberately saturated blocking worker. This test-only direct
            // metadata read is bounded to the fresh regular test directory.
            assert!(partial.exists(), "queued cleanup unexpectedly ran early");
            gate.release();
            blocker.await.unwrap();
            wait_for_path_absent(&partial).await;
            tokio::fs::remove_dir_all(dir).await.unwrap();
        });
    }

    #[tokio::test]
    async fn local_download_commit_is_atomic_and_no_replace() {
        let dir = unique_test_dir("no-replace");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part");
        let destination = dir.join("evidence");
        tokio::fs::write(&partial, b"downloaded").await.unwrap();

        // Emulate another process creating the destination after the caller's
        // initial existence check but before the completed transfer commits.
        assert!(!destination.exists());
        let expected = tokio::fs::File::open(&partial).await.unwrap();
        tokio::fs::write(&destination, b"concurrent winner")
            .await
            .unwrap();
        let error = commit_local_no_replace_with_hook(
            &partial,
            &destination,
            &expected,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            std::future::ready(()),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("created during download"));
        assert_eq!(
            tokio::fs::read(&destination).await.unwrap(),
            b"concurrent winner"
        );
        assert_eq!(tokio::fs::read(&partial).await.unwrap(), b"downloaded");
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn expired_local_commit_starts_neither_link_worker_nor_hook() {
        let dir = unique_test_dir("expired-local-commit");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part");
        let destination = dir.join("evidence");
        tokio::fs::write(&partial, b"downloaded").await.unwrap();
        let expected = tokio::fs::File::open(&partial).await.unwrap();
        let worker_started = Arc::new(AtomicBool::new(false));
        let link_worker_started = Arc::clone(&worker_started);
        let hook_started = Arc::new(AtomicBool::new(false));
        let after_link_started = Arc::clone(&hook_started);

        let error = commit_local_no_replace_with_hook_and_link(
            &partial,
            &destination,
            &expected,
            tokio::time::Instant::now(),
            async move {
                after_link_started.store(true, Ordering::Release);
            },
            move |_, _| {
                link_worker_started.store(true, Ordering::Release);
                Ok(())
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("expired before it started"));
        assert!(!worker_started.load(Ordering::Acquire));
        assert!(!hook_started.load(Ordering::Acquire));
        assert!(!tokio::fs::try_exists(&destination).await.unwrap());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn protected_download_partial_collision_preserves_the_existing_file() {
        let dir = unique_test_dir("partial-collision");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part-fixed");
        tokio::fs::write(&partial, b"another request owns this")
            .await
            .unwrap();

        let cancellation = CancellationToken::new();
        let error = match create_local_download_partial(
            &partial,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            &cancellation,
            1_000,
        )
        .await
        {
            Ok(_) => panic!("protected create-new unexpectedly replaced a collision"),
            Err(error) => error,
        };
        assert!(error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists));
        assert_eq!(
            tokio::fs::read(&partial).await.unwrap(),
            b"another request owns this"
        );
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn upload_reads_the_once_opened_regular_file_after_path_replacement() {
        let dir = unique_test_dir("stable-upload-source");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let source_path = dir.join("source.bin");
        let moved_path = dir.join("source-original.bin");
        tokio::fs::write(&source_path, b"original bytes")
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let (mut source, size) = open_local_upload_source(
            &source_path,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            &cancellation,
            1_000,
        )
        .await
        .unwrap();

        tokio::fs::rename(&source_path, &moved_path).await.unwrap();
        tokio::fs::write(&source_path, b"replacement")
            .await
            .unwrap();
        let mut received = Vec::new();
        source.read_to_end(&mut received).await.unwrap();
        assert_eq!(size, b"original bytes".len() as u64);
        assert_eq!(received, b"original bytes");
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn upload_source_rejects_a_directory_before_routing() {
        let dir = unique_test_dir("upload-directory-reject");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let error = match open_local_upload_source(
            &dir,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            &CancellationToken::new(),
            1_000,
        )
        .await
        {
            Ok(_) => panic!("directory unexpectedly accepted as an upload source"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("local upload source"));
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn local_download_commit_removes_the_temporary_name() {
        let dir = unique_test_dir("commit");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part");
        let destination = dir.join("evidence");
        tokio::fs::write(&partial, b"downloaded").await.unwrap();
        let expected = tokio::fs::File::open(&partial).await.unwrap();

        let partial_removed = commit_local_no_replace_with_hook(
            &partial,
            &destination,
            &expected,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            std::future::ready(()),
        )
        .await
        .unwrap();

        assert!(partial_removed);
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"downloaded");
        assert!(!partial.exists());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn download_cancel_after_link_does_not_change_committed_success() {
        let dir = unique_test_dir("cancel-after-link");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part");
        let destination = dir.join("evidence");
        tokio::fs::write(&partial, b"downloaded").await.unwrap();
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&partial)
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let linked = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let linked_worker = linked.clone();
        let resume_worker = resume.clone();
        let partial_worker = partial.clone();
        let destination_worker = destination.clone();
        let worker = tokio::spawn(async move {
            finalize_local_download(
                &mut file,
                &partial_worker,
                &destination_worker,
                tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                &worker_cancellation,
                async move {
                    linked_worker.notify_one();
                    resume_worker.notified().await;
                },
            )
            .await
        });

        linked.notified().await;
        assert!(destination.exists());
        cancellation.cancel();
        resume.notify_one();

        assert!(worker.await.unwrap().unwrap());
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"downloaded");
        assert!(!partial.exists());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn download_deadline_after_link_reconciles_as_committed() {
        let dir = unique_test_dir("deadline-after-link");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part");
        let destination = dir.join("evidence");
        tokio::fs::write(&partial, b"downloaded").await.unwrap();
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&partial)
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let commit_deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);

        let partial_removed = finalize_local_download(
            &mut file,
            &partial,
            &destination,
            commit_deadline,
            &cancellation,
            async move {
                // The link is already visible at this hook. Cross the original
                // deadline deliberately to prove post-commit verification and
                // cleanup do not turn a committed download into a timeout.
                tokio::time::sleep(std::time::Duration::from_millis(550)).await;
            },
        )
        .await
        .unwrap();

        assert!(tokio::time::Instant::now() >= commit_deadline);
        assert!(partial_removed);
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"downloaded");
        assert!(!partial.exists());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn dropping_upload_api_cancels_but_does_not_abort_cleanup_worker() {
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let (cleanup_done_tx, cleanup_done_rx) = oneshot::channel();
        let worker = tokio::spawn(async move {
            worker_cancellation.cancelled().await;
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            let _ = cleanup_done_tx.send(());
            Err(anyhow::anyhow!("cancelled after cleanup"))
        });
        let (outer_started_tx, outer_started_rx) = oneshot::channel();
        let outer = tokio::spawn(async move {
            let _ = outer_started_tx.send(());
            await_owned_upload_worker(worker, cancellation).await
        });

        outer_started_rx.await.unwrap();
        outer.abort();
        let _ = outer.await;

        tokio::time::timeout(std::time::Duration::from_secs(1), cleanup_done_rx)
            .await
            .expect("detached upload worker must finish its cleanup")
            .expect("cleanup worker must report completion");
    }

    #[tokio::test]
    async fn dropping_download_api_keeps_owned_local_partial_cleanup_alive() {
        let dir = unique_test_dir("download-drop-cleanup");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let partial = dir.join("evidence.serctl-part-test");
        let worker_path = partial.clone();
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (cleanup_done_tx, cleanup_done_rx) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let (file, mut cleanup) = create_local_download_partial(
                &worker_path,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
                &worker_cancellation,
                1_000,
            )
            .await
            .unwrap();
            let _ = ready_tx.send(());
            worker_cancellation.cancelled().await;
            drop(file);
            cleanup.cleanup().await;
            let _ = cleanup_done_tx.send(());
            Err(anyhow::anyhow!("cancelled after local cleanup"))
        });
        let outer = tokio::spawn(await_owned_upload_worker(worker, cancellation));

        ready_rx.await.unwrap();
        outer.abort();
        let _ = outer.await;
        tokio::time::timeout(std::time::Duration::from_secs(3), cleanup_done_rx)
            .await
            .expect("detached download worker must finish local cleanup")
            .expect("local cleanup worker must report completion");
        assert!(!partial.exists());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[test]
    fn client_rejects_unbounded_sftp_timeouts() {
        assert!(validated_sftp_timeout_ms(std::time::Duration::ZERO).is_err());
        assert!(validated_sftp_timeout_ms(std::time::Duration::from_millis(1)).is_ok());
        assert!(validated_sftp_timeout_ms(std::time::Duration::from_millis(
            serctl_protocol::MAX_SFTP_TIMEOUT_MS + 1
        ))
        .is_err());
    }
}
