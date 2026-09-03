//! russh client wrapper: connect with password auth, exec commands, open PTY shells.
use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use rand::{rngs::OsRng, RngCore};
use russh::{client, keys::ssh_key, Channel, ChannelId, ChannelMsg, ChannelOpenFailure};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{
    Close, File, FileAttributes, Handle, Init, Name, Open, OpenDir, OpenFlags, Packet, ReadDir,
    RealPath, Status, StatusCode, Write, VERSION,
};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::Creds;

const MAX_COMMAND_OUTPUT: usize = serctl_protocol::MAX_COMMAND_OUTPUT;
pub const MAX_REMOTE_COMMAND_BYTES: usize = 64 * 1024;
pub const MAX_REMOTE_PATH_BYTES: usize = 4096;
pub const MAX_SFTP_PACKET_BYTES: usize = 1024 * 1024;
pub const MAX_TRANSFER_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_SHELL_DIMENSION: u32 = 10_000;
const REMOTE_PARTIAL_SUFFIX_BYTES: usize = ".serctl-part-".len() + 32;
const SSH_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(120);
const TRANSPORT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const MIN_FIRST_KEX_WINDOW: Duration = Duration::from_secs(8);
const MIN_RETRY_KEX_WINDOW: Duration = Duration::from_secs(8);
const PRE_AUTH_RETRY_BACKOFF: Duration = Duration::from_millis(1500);
// A peer that closes the transport before sending any SSH bytes can fail far
// earlier than the conservative two-window budget below. Reuse the caller's
// still-unspent absolute deadline for that one narrow case instead of turning
// a prompt, clean EOF into a false "no reconnect" result. This shorter path is
// never available after server bytes, an SSH_MSG_DISCONNECT, or incomplete
// transport cleanup.
const EARLY_EOF_RETRY_BACKOFF: Duration = Duration::from_millis(50);
const MIN_EARLY_EOF_RETRY_WINDOW: Duration = Duration::from_millis(500);
const RETRY_SCHEDULING_MARGIN: Duration = Duration::from_millis(500);
const MIN_TOFU_PIN_WINDOW: Duration = Duration::from_secs(5);
const MIN_PASSWORD_AUTH_WINDOW: Duration = Duration::from_secs(5);
const CHANNEL_OPERATION_TIMEOUT: Duration = Duration::from_millis(350);
const CHANNEL_SIGNAL_GRACE: Duration = Duration::from_millis(100);
// Tunnel wire types and their loopback-only validation live in the protocol
// crate; the SSH engine re-exports them so existing callers keep resolving
// `ssh::TunnelSpec` and friends.
pub use serctl_protocol::{
    RemoteEntry, TunnelMode, TunnelReady, TunnelSpec, ValidatedTunnelSpec,
    DEFAULT_TUNNEL_CONNECTIONS, MAX_TUNNEL_CONNECTIONS, MAX_TUNNEL_HOST_BYTES,
};
/// Aggregate cap shared by every tunnel on one SSH transport. Per-tunnel
/// limits preserve fairness without multiplying the daemon-wide live-flow
/// bound across its long-lived tunnel control connections.
const MAX_SESSION_TUNNEL_FLOWS: usize = 256;
const MAX_REMOTE_FORWARD_PENDING: usize = 32;
const TUNNEL_CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const TUNNEL_REMOTE_TARGET_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS5_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const TUNNEL_STOP_TIMEOUT: Duration = Duration::from_secs(4);
const TUNNEL_SESSION_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_SAFE_SERVER_IDENTIFICATION_BYTES: usize = 128;
static NEXT_TRANSPORT_ATTEMPT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

const TUNNEL_LOOPBACK_HOST: &str = "127.0.0.1";

fn literal_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    let ip = host.parse::<IpAddr>().ok()?;
    let ip = match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        value => value,
    };
    Some(SocketAddr::new(ip, port))
}

async fn connect_ssh_tcp_until(
    host: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> Result<tokio::net::TcpStream> {
    let operation = async {
        if let Some(address) = literal_socket_addr(host, port) {
            let socket = match address {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
            }
            .context("create SSH TCP socket")?;
            Ok::<_, anyhow::Error>(socket.connect(address).await?)
        } else {
            Ok(tokio::net::TcpStream::connect((host, port)).await?)
        }
    };

    match tokio::time::timeout_at(deadline, operation).await {
        Ok(result) => result.context("connect SSH TCP socket"),
        Err(_) => bail!("SSH connection exceeded its deadline"),
    }
}

/// Owns the cancellation lease for one running tunnel. Dropping the handle
/// requests cooperative cleanup; callers that need confirmation should use
/// `stop` or `wait`.
pub struct RunningTunnel {
    ready: TunnelReady,
    cancellation: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
}

impl RunningTunnel {
    pub fn ready(&self) -> &TunnelReady {
        &self.ready
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub async fn wait(mut self) -> Result<()> {
        let mut task = self.task.take().context("tunnel task is missing")?;
        if !self.cancellation.is_cancelled() {
            tokio::select! {
                result = &mut task => return result.context("join SSH tunnel task")?,
                _ = self.cancellation.cancelled() => {}
            }
        }
        match tokio::time::timeout(TUNNEL_STOP_TIMEOUT, &mut task).await {
            Ok(result) => result.context("join SSH tunnel task")?,
            Err(_) => {
                // Dropping an aborted remote-forward worker runs the armed
                // lease guard: it removes the generation-bound registry entry
                // and trips the SSH transport, so no remote listener can be
                // left usable after this bounded stop returns.
                task.abort();
                let _ = task.await;
                bail!("SSH tunnel cleanup exceeded its deadline")
            }
        }
    }

    pub async fn stop(self) -> Result<()> {
        self.cancellation.cancel();
        self.wait().await
    }
}

impl Drop for RunningTunnel {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn validate_tunnel_host(label: &str, host: &str) -> Result<()> {
    ensure!(
        !host.is_empty() && host.len() <= MAX_TUNNEL_HOST_BYTES,
        "{label} must contain 1 to {MAX_TUNNEL_HOST_BYTES} bytes"
    );
    ensure!(host.is_ascii(), "{label} must contain only ASCII bytes");
    ensure!(
        !host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()),
        "{label} contains whitespace or a control byte"
    );
    Ok(())
}

fn remote_forward_channel_is_loopback_only(
    connected_address: &str,
    originator_address: &str,
) -> bool {
    let is_ipv4_localhost = |address: &str| {
        matches!(
            address.parse::<IpAddr>(),
            Ok(IpAddr::V4(value)) if value == Ipv4Addr::LOCALHOST
        )
    };
    is_ipv4_localhost(connected_address) && is_ipv4_localhost(originator_address)
}

// Directory listings are returned as one or more SSH_FXP_NAME packets. The
// high-level russh-sftp `read_dir` API buffers every packet into one Vec before
// returning, so limits applied to its iterator are too late. These limits are
// enforced by the streaming SFTP v3 reader below, before allocating each packet
// body and before retaining each entry.
const MAX_DIRECTORY_PACKET_BYTES: usize = 1024 * 1024;
const MAX_DIRECTORY_ENCODED_BYTES: usize = 8 * 1024 * 1024;
// JSON escapes a one-byte control character as six ASCII bytes. Two MiB of
// retained names/paths plus the fixed metadata for 10k entries remains below
// the 16 MiB IPC response cap even in that worst case; the exact serialized
// length is also checked before returning the listing.
const MAX_DIRECTORY_STRING_BYTES: usize = 2 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 10_000;

#[derive(Clone, Copy)]
struct DirectoryLimits {
    packet_bytes: usize,
    encoded_bytes: usize,
    string_bytes: usize,
    entries: usize,
}

const DIRECTORY_LIMITS: DirectoryLimits = DirectoryLimits {
    packet_bytes: MAX_DIRECTORY_PACKET_BYTES,
    encoded_bytes: MAX_DIRECTORY_ENCODED_BYTES,
    string_bytes: MAX_DIRECTORY_STRING_BYTES,
    entries: MAX_DIRECTORY_ENTRIES,
};

fn command_deadline_error() -> anyhow::Error {
    anyhow::anyhow!("remote command exceeded its deadline")
}

/// A command request may already have been accepted by the remote process even
/// when its reply, output, or exit status is lost. Callers can downcast an
/// `anyhow::Error` to this type to prevent an unsafe automatic retry.
#[derive(Debug)]
pub struct ExecOutcomeUnknown(String);

const EXEC_OUTCOME_UNKNOWN_PREFIX: &str = "remote command outcome unknown:";
const EXEC_OUTCOME_UNKNOWN_GUIDANCE: &str = "inspect remote side effects before retry";

impl fmt::Display for ExecOutcomeUnknown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ExecOutcomeUnknown {}

impl ExecOutcomeUnknown {
    pub fn from_wire_message(message: &str) -> Option<Self> {
        (message.starts_with(EXEC_OUTCOME_UNKNOWN_PREFIX)
            && message.contains(EXEC_OUTCOME_UNKNOWN_GUIDANCE))
        .then(|| Self(message.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExecSubmissionState {
    #[default]
    BeforeRequest,
    RequestMayHaveReachedRemote,
}

impl ExecSubmissionState {
    pub fn request_started(&mut self) {
        *self = Self::RequestMayHaveReachedRemote;
    }

    pub fn classify(self, error: anyhow::Error) -> anyhow::Error {
        if self == Self::BeforeRequest || error.is::<ExecOutcomeUnknown>() {
            return error;
        }
        let detail = format!("{error:#}");
        if let Some(error) = ExecOutcomeUnknown::from_wire_message(&detail) {
            return error.into();
        }
        ExecOutcomeUnknown(format!(
            "{EXEC_OUTCOME_UNKNOWN_PREFIX} {detail}; {EXEC_OUTCOME_UNKNOWN_GUIDANCE}"
        ))
        .into()
    }
}

/// Creating a directory is not safely retryable once the SFTP request may have
/// reached the server. Callers can downcast an `anyhow::Error` to this type and
/// require an explicit inspection before retrying.
#[derive(Debug)]
pub struct CreateDirOutcomeUnknown(String);

const CREATE_DIR_OUTCOME_UNKNOWN_PREFIX: &str = "remote create-directory outcome unknown:";
const CREATE_DIR_OUTCOME_UNKNOWN_GUIDANCE: &str = "inspect the remote path before retry";

impl fmt::Display for CreateDirOutcomeUnknown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CreateDirOutcomeUnknown {}

impl CreateDirOutcomeUnknown {
    pub fn from_wire_message(message: &str) -> Option<Self> {
        (message.starts_with(CREATE_DIR_OUTCOME_UNKNOWN_PREFIX)
            && message.contains(CREATE_DIR_OUTCOME_UNKNOWN_GUIDANCE))
        .then(|| Self(message.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CreateDirSubmissionState {
    #[default]
    BeforeRequest,
    RequestMayHaveReachedRemote,
}

impl CreateDirSubmissionState {
    pub fn request_started(&mut self) {
        *self = Self::RequestMayHaveReachedRemote;
    }

    pub fn classify(self, error: anyhow::Error) -> anyhow::Error {
        if self == Self::BeforeRequest || error.is::<CreateDirOutcomeUnknown>() {
            return error;
        }
        let detail = format!("{error:#}");
        if let Some(error) = CreateDirOutcomeUnknown::from_wire_message(&detail) {
            return error.into();
        }
        CreateDirOutcomeUnknown(format!(
            "{CREATE_DIR_OUTCOME_UNKNOWN_PREFIX} {detail}; {CREATE_DIR_OUTCOME_UNKNOWN_GUIDANCE}"
        ))
        .into()
    }
}

/// Poll an irreversible remote operation only while its absolute deadline is
/// still live. Tokio timeouts poll their inner future before checking the timer,
/// so the explicit check must happen on every poll; the timeout is retained only
/// to arrange a wakeup at the deadline.
pub async fn poll_remote_mutation_until<F, T, E, S, D>(
    deadline: tokio::time::Instant,
    operation: F,
    on_first_poll: S,
    on_deadline: D,
    deadline_message: impl Into<String>,
) -> Result<T>
where
    F: Future<Output = std::result::Result<T, E>>,
    E: Into<anyhow::Error>,
    S: FnOnce(),
    D: FnOnce(),
{
    tokio::pin!(operation);
    let mut on_first_poll = Some(on_first_poll);
    let mut on_deadline = Some(on_deadline);
    let deadline_message = deadline_message.into();
    let poll_deadline_message = deadline_message.clone();
    let guarded = std::future::poll_fn(|context| {
        if tokio::time::Instant::now() >= deadline {
            if let Some(on_deadline) = on_deadline.take() {
                on_deadline();
            }
            return Poll::Ready(Err(anyhow::anyhow!(poll_deadline_message.clone())));
        }
        if let Some(on_first_poll) = on_first_poll.take() {
            on_first_poll();
        }
        match operation.as_mut().poll(context) {
            Poll::Ready(Ok(value)) => Poll::Ready(Ok(value)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Pending => Poll::Pending,
        }
    });

    match tokio::time::timeout_at(deadline, guarded).await {
        Ok(result) => result,
        Err(_) => {
            if let Some(on_deadline) = on_deadline.take() {
                on_deadline();
            }
            Err(anyhow::anyhow!(deadline_message))
        }
    }
}

pub fn is_explicit_sftp_status(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<russh_sftp::client::error::Error>(),
        Some(russh_sftp::client::error::Error::Status(_))
    )
}

/// Whether a russh failure proves that the underlying SSH transport is no
/// longer reusable. In particular, channel confirmation can report
/// `Disconnect` before `Handle::is_closed()` observes the event-loop sender
/// closing; callers must not put that handle back into a session pool.
pub fn is_ssh_transport_terminal_error(error: &anyhow::Error) -> bool {
    let Some(error) = error.downcast_ref::<russh::Error>() else {
        return false;
    };
    match error {
        russh::Error::Disconnect
        | russh::Error::HUP
        | russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout
        | russh::Error::SendError
        | russh::Error::PacketAuth
        | russh::Error::DecryptionError
        | russh::Error::Inconsistent
        | russh::Error::StrictKeyExchangeViolation { .. } => true,
        russh::Error::IO(error) => matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::NotConnected
                | io::ErrorKind::TimedOut
                | io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

async fn await_exec_request_queued_until<F, E>(
    submission: &mut ExecSubmissionState,
    deadline: tokio::time::Instant,
    request: F,
) -> Result<()>
where
    F: Future<Output = std::result::Result<(), E>>,
    E: Into<anyhow::Error>,
{
    tokio::pin!(request);
    let guarded_request = std::future::poll_fn(|context| {
        // Tokio's timeout polls the inner future before checking its timer.
        // Guard every poll so bounded mpsc capacity becoming available at the
        // deadline cannot enqueue a command after its absolute budget.
        if tokio::time::Instant::now() >= deadline {
            return Poll::Ready(Err(command_deadline_error()));
        }
        match request.as_mut().poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Pending => Poll::Pending,
        }
    });
    match tokio::time::timeout_at(deadline, guarded_request).await {
        Ok(Ok(())) => {
            // `russh::Channel::exec` is a cancellation-safe mpsc send. Only
            // its successful completion proves that the transport task took
            // ownership of the request and may deliver it to the peer.
            submission.request_started();
            Ok(())
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Err(command_deadline_error()),
    }
}

/// Enforce one command boundary before choosing either daemon IPC or a direct
/// SSH route. This prevents a missing daemon from bypassing the daemon's
/// resource limit.
pub fn validate_remote_command(command: &str) -> Result<()> {
    ensure!(
        command.len() <= MAX_REMOTE_COMMAND_BYTES,
        "remote command exceeds {MAX_REMOTE_COMMAND_BYTES} bytes"
    );
    ensure!(
        !command.contains('\0'),
        "remote command contains a NUL byte"
    );
    Ok(())
}

/// Enforce one remote-path boundary before choosing either daemon IPC or a
/// direct SFTP route. An empty path is meaningful only for directory listing,
/// where the server resolves it to the current directory.
pub fn validate_remote_path(path: &str, allow_empty: bool) -> Result<()> {
    ensure!(
        (allow_empty || !path.is_empty()) && path.len() <= MAX_REMOTE_PATH_BYTES,
        "remote path is empty or exceeds {MAX_REMOTE_PATH_BYTES} bytes"
    );
    ensure!(!path.contains('\0'), "remote path contains a NUL byte");
    Ok(())
}

pub fn validate_upload_remote_path(path: &str) -> Result<()> {
    validate_remote_path(path, false)?;
    let temporary_len = path
        .len()
        .checked_add(REMOTE_PARTIAL_SUFFIX_BYTES)
        .context("remote upload temporary-path length overflow")?;
    ensure!(
        temporary_len <= MAX_REMOTE_PATH_BYTES,
        "remote upload path leaves no room for its protected temporary suffix"
    );
    Ok(())
}

/// Keep PTY dimensions identical on direct SSH and daemon IPC routes.
pub fn validate_shell_dimensions(cols: u32, rows: u32) -> Result<()> {
    ensure!(
        (1..=MAX_SHELL_DIMENSION).contains(&cols) && (1..=MAX_SHELL_DIMENSION).contains(&rows),
        "shell dimensions must be between 1 and {MAX_SHELL_DIMENSION}"
    );
    Ok(())
}

pub fn temporary_remote_path(path: &str) -> Result<String> {
    validate_upload_remote_path(path)?;
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    Ok(format!("{path}.serctl-part-{}", hex::encode(random)))
}

pub fn protected_upload_file_attributes() -> FileAttributes {
    let mut attributes = FileAttributes::empty();
    attributes.permissions = Some(0o600);
    attributes
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteUploadCommit {
    pub partial_removed: bool,
}

async fn commit_remote_upload_no_replace_with<H, R, U, HF, RF, UF>(
    hardlink: H,
    rename: R,
    unlink_partial: U,
    committed: &AtomicBool,
) -> Result<RemoteUploadCommit>
where
    H: FnOnce() -> HF,
    R: FnOnce() -> RF,
    U: FnOnce() -> UF,
    HF: std::future::Future<Output = Result<bool>>,
    RF: std::future::Future<Output = Result<()>>,
    UF: std::future::Future<Output = Result<()>>,
{
    // Keep the fallback closure injectable so tests can prove it is never
    // invoked. Dropping it without polling is the fail-closed compatibility
    // boundary for servers that lack the hardlink extension.
    let _rename = rename;
    match hardlink().await? {
        true => {
            committed.store(true, Ordering::Release);
            let partial_removed = unlink_partial().await.is_ok();
            Ok(RemoteUploadCommit {
                partial_removed,
            })
        }
        false => bail!(
            "SSH server does not support hardlink@openssh.com; refusing an upload commit whose no-overwrite semantics cannot be proven"
        ),
    }
}

/// Commit a completed remote sibling without overwriting an existing target.
/// Each remote mutation is guarded separately so no SFTP request is polled
/// after the caller's absolute deadline. The OpenSSH hardlink extension is
/// required because SFTP v3 RENAME behavior is not sufficiently consistent
/// across servers to prove no-overwrite semantics.
pub async fn commit_remote_upload_no_replace_until(
    sftp: &SftpSession,
    partial: &str,
    target: &str,
    committed: &AtomicBool,
    deadline: tokio::time::Instant,
    deadline_message: &str,
) -> Result<RemoteUploadCommit> {
    commit_remote_upload_no_replace_with(
        || {
            poll_remote_mutation_until(
                deadline,
                sftp.hardlink(partial, target),
                || {},
                || {},
                deadline_message,
            )
        },
        || {
            poll_remote_mutation_until(
                deadline,
                sftp.rename(partial, target),
                || {},
                || {},
                deadline_message,
            )
        },
        || {
            poll_remote_mutation_until(
                deadline,
                sftp.remove_file(partial),
                || {},
                || {},
                deadline_message,
            )
        },
        committed,
    )
    .await
}

fn secure_client_algorithms() -> russh::Preferred {
    let mut preferred = russh::Preferred::default();
    preferred.key = std::borrow::Cow::Owned(
        preferred
            .key
            .iter()
            .filter(|algorithm| {
                matches!(
                    algorithm,
                    ssh_key::Algorithm::Ed25519
                        | ssh_key::Algorithm::Ecdsa { .. }
                        | ssh_key::Algorithm::Rsa {
                            hash: Some(ssh_key::HashAlg::Sha256 | ssh_key::HashAlg::Sha512)
                        }
                )
            })
            .cloned()
            .collect(),
    );
    preferred
}

struct IncomingRemoteForward {
    channel: Channel<client::Msg>,
    reply: client::ChannelOpenHandle,
}

impl IncomingRemoteForward {
    async fn reject(self, reason: ChannelOpenFailure) {
        self.reply.reject(reason).await;
    }
}

#[derive(Default)]
struct RemoteForwardRegistry {
    state: Mutex<RemoteForwardRegistryState>,
}

#[derive(Default)]
struct RemoteForwardRegistryState {
    next_generation: u64,
    routes: HashMap<u16, RemoteForwardRoute>,
}

struct RemoteForwardRoute {
    generation: u64,
    sender: mpsc::Sender<IncomingRemoteForward>,
}

impl RemoteForwardRegistry {
    fn contains_port(&self, port: u16) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .routes
            .contains_key(&port)
    }

    fn register(
        self: &Arc<Self>,
        port: u16,
        sender: mpsc::Sender<IncomingRemoteForward>,
    ) -> Result<RemoteForwardRegistration> {
        ensure!(port != 0, "remote-forward effective port must not be zero");
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        ensure!(
            !state.routes.contains_key(&port),
            "remote-forward port {port} is already registered on this SSH session"
        );
        state.next_generation = state
            .next_generation
            .checked_add(1)
            .context("remote-forward registration generation exhausted")?;
        let generation = state.next_generation;
        state
            .routes
            .insert(port, RemoteForwardRoute { generation, sender });
        Ok(RemoteForwardRegistration {
            registry: Arc::clone(self),
            port,
            generation,
            armed: true,
        })
    }

    fn sender_for(&self, port: u32) -> Option<mpsc::Sender<IncomingRemoteForward>> {
        let port = u16::try_from(port).ok()?;
        if port == 0 {
            return None;
        }
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .routes
            .get(&port)
            .map(|route| route.sender.clone())
    }

    fn remove_if_generation(&self, port: u16, generation: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state
            .routes
            .get(&port)
            .is_some_and(|route| route.generation == generation)
        {
            state.routes.remove(&port);
            true
        } else {
            false
        }
    }
}

struct RemoteForwardRegistration {
    registry: Arc<RemoteForwardRegistry>,
    port: u16,
    generation: u64,
    armed: bool,
}

impl RemoteForwardRegistration {
    fn remove(&mut self) {
        if self.armed {
            self.registry
                .remove_if_generation(self.port, self.generation);
            self.armed = false;
        }
    }
}

impl Drop for RemoteForwardRegistration {
    fn drop(&mut self) {
        self.remove();
    }
}

pub struct SshHandler {
    expect: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
    disconnect_detail: Arc<Mutex<Option<String>>>,
    activity: Arc<SshTransportActivity>,
    remote_forwards: Arc<RemoteForwardRegistry>,
}

fn safe_ssh_failure_category(
    error: anyhow::Error,
    disconnect_detail: &Arc<Mutex<Option<String>>>,
) -> (anyhow::Error, String) {
    let category = disconnect_detail
        .lock()
        .ok()
        .and_then(|detail| detail.clone())
        .unwrap_or_else(|| match error.downcast_ref::<russh::Error>() {
            Some(russh::Error::Disconnect) => "russh Disconnect".to_owned(),
            Some(russh::Error::HUP) => "russh HUP".to_owned(),
            Some(russh::Error::ConnectionTimeout) => "russh ConnectionTimeout".to_owned(),
            Some(russh::Error::KeepaliveTimeout) => "russh KeepaliveTimeout".to_owned(),
            Some(russh::Error::InactivityTimeout) => "russh InactivityTimeout".to_owned(),
            Some(russh::Error::SendError) => "russh SendError".to_owned(),
            Some(russh::Error::IO(error)) => format!("russh IO::{:?}", error.kind()),
            Some(_) => "russh protocol error".to_owned(),
            None => "local SSH transport error".to_owned(),
        });
    (error, category)
}

fn ssh_phase_failure(
    phase: &'static str,
    error: anyhow::Error,
    disconnect_detail: &Arc<Mutex<Option<String>>>,
) -> anyhow::Error {
    let (error, category) = safe_ssh_failure_category(error, disconnect_detail);
    error.context(format!("{phase} failed: {category}"))
}

fn require_server_fingerprint(observed: Option<String>) -> Result<String> {
    let fingerprint = observed.context("SSH completed without observing a server host key")?;
    ensure!(
        !fingerprint.is_empty(),
        "SSH server host-key fingerprint is empty"
    );
    Ok(fingerprint)
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        self.activity
            .host_key_observed
            .store(true, Ordering::Release);
        let fp = server_public_key
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        *self.seen.lock().unwrap() = Some(fp.clone());
        // first contact: trust-on-first-use, pin afterwards.
        let accept = match &self.expect {
            Some(want) => want == &fp,
            None => true,
        };
        Ok(accept)
    }

    fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send {
        let result = match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => {
                // The server's description and language fields are untrusted
                // free text and may echo credential material. Retain only the
                // bounded protocol enum; never propagate those strings.
                let detail = format!("remote disconnect {:?}", info.reason_code);
                if let Ok(mut recorded) = self.disconnect_detail.lock() {
                    *recorded = Some(detail);
                }
                Ok(())
            }
            client::DisconnectReason::Error(error) => Err(error),
        };
        std::future::ready(result)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let incoming = IncomingRemoteForward { channel, reply };
        // A server configured with OpenSSH GatewayPorts may replace the
        // requested 127.0.0.1 listener with a wildcard listener. Refuse both
        // a non-loopback connected address and every non-loopback originator,
        // so such an externally reachable socket cannot become a usable
        // serctl forwarding path even when the server overrides the bind.
        if !remote_forward_channel_is_loopback_only(connected_address, originator_address) {
            drop(incoming);
            return Ok(());
        }
        let sender = self.remote_forwards.sender_for(connected_port);
        match sender {
            Some(sender) => match sender.try_send(incoming) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(incoming)) => {
                    // This callback runs inside russh's session loop. An
                    // awaited reject sends into a bounded queue drained by
                    // that same loop and can self-deadlock when a hostile
                    // server floods channel-open requests. Dropping the
                    // handle uses russh's non-blocking fail-closed reject.
                    drop(incoming);
                }
                Err(mpsc::error::TrySendError::Closed(incoming)) => {
                    drop(incoming);
                }
            },
            None => {
                drop(incoming);
            }
        }
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn should_accept_unknown_server_channel(
        &mut self,
        _id: ChannelId,
        _channel_type: &str,
    ) -> bool {
        false
    }

    async fn server_channel_open_unknown(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<client::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }
}

pub struct SshSession {
    handle: client::Handle<SshHandler>,
    connection_identity: SshConnectionIdentitySnapshot,
    invalidated: Arc<AtomicBool>,
    transport: TransportControl,
    remote_forwards: Arc<RemoteForwardRegistry>,
    remote_forward_setup: AsyncMutex<()>,
    tunnel_flow_permits: Arc<Semaphore>,
}

/// Authenticated, read-only identity facts for one SSH transport.
///
/// The snapshot deliberately excludes endpoint topology, usernames,
/// authentication material, pre-identification text, and the raw peer banner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshConnectionIdentitySnapshot {
    observed_host_key_sha256: String,
    server_identification: String,
    transport_attempt_id: String,
}

impl SshConnectionIdentitySnapshot {
    fn new_authenticated(
        authenticated: bool,
        observed_host_key_sha256: Option<&str>,
        expected_host_key_sha256: Option<&str>,
        server_identification: Option<&str>,
        transport_attempt_id: Option<&str>,
    ) -> Result<Self> {
        ensure!(
            authenticated,
            "SSH connection identity requires authentication"
        );
        let observed =
            observed_host_key_sha256.context("SSH connection identity has no observed host key")?;
        ensure!(
            is_canonical_sha256_fingerprint(observed),
            "SSH connection identity host key is not a canonical SHA256 fingerprint"
        );
        if let Some(expected) = expected_host_key_sha256 {
            ensure!(
                expected == observed,
                "SSH connection identity host-key pin does not match"
            );
        }
        let identification = server_identification
            .and_then(|value| sanitize_server_identification(value.as_bytes()))
            .context("SSH connection identity has no safe server identification")?;
        let attempt_id = transport_attempt_id
            .filter(|value| is_canonical_transport_attempt_id(value))
            .context("SSH connection identity transport attempt id is invalid")?;
        Ok(Self {
            observed_host_key_sha256: observed.to_owned(),
            server_identification: identification,
            transport_attempt_id: attempt_id.to_owned(),
        })
    }

    pub fn observed_host_key_sha256(&self) -> &str {
        &self.observed_host_key_sha256
    }

    /// This getter exists to make the fail-closed invariant explicit: a
    /// snapshot is constructible only after the accepted key matches the pin
    /// (or the caller-authorized first-use key) and authentication succeeds.
    pub fn pin_match(&self) -> bool {
        true
    }

    pub fn server_identification(&self) -> &str {
        &self.server_identification
    }

    pub fn transport_attempt_id(&self) -> &str {
        &self.transport_attempt_id
    }
}

fn is_canonical_sha256_fingerprint(value: &str) -> bool {
    let Some(payload) = value.strip_prefix("SHA256:") else {
        return false;
    };
    payload.len() == 43
        && payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

fn is_canonical_transport_attempt_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
}

fn new_transport_attempt_id() -> String {
    let sequence = NEXT_TRANSPORT_ATTEMPT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut nonce = [0_u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&nonce);
    bytes[8..].copy_from_slice(&sequence.to_be_bytes());
    hex::encode_upper(bytes)
}

pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<i32>,
}

pub struct RunningCommand {
    channel: russh::Channel<russh::client::Msg>,
    transport: TransportTrip,
    submission: ExecSubmissionState,
}

#[derive(Clone)]
struct TransportTrip {
    invalidated: Arc<AtomicBool>,
    cancel: CancellationToken,
    shutdown: Option<Arc<std::net::TcpStream>>,
    activity: Option<Arc<SshTransportActivity>>,
}

impl TransportTrip {
    fn trip(&self) -> bool {
        self.invalidated.store(true, Ordering::Release);
        if let Some(activity) = &self.activity {
            activity
                .local_shutdown_started
                .store(true, Ordering::Release);
        }
        let io_stopped =
            self.shutdown
                .as_ref()
                .is_some_and(|socket| match socket.shutdown(Shutdown::Both) {
                    Ok(()) => true,
                    Err(error) => matches!(
                        error.kind(),
                        io::ErrorKind::NotConnected
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                    ),
                });
        self.cancel.cancel();
        io_stopped
    }
}

#[derive(Default)]
struct SshTransportActivity {
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    server_identification_observed: AtomicBool,
    server_identification: Mutex<Option<String>>,
    host_key_observed: AtomicBool,
    local_shutdown_started: AtomicBool,
    peer_eof_before_local_shutdown: AtomicBool,
}

#[derive(Debug)]
struct SshAttemptRecord {
    // This record is attached to operator-visible errors. Deliberately omit
    // the resolved peer SocketAddr: profile topology is not required to
    // distinguish the transport phases below and must not leak through Agent
    // or sanitized error paths. `tcp_connected` means only that one resolved
    // endpoint completed TCP connect; it does not identify that endpoint or
    // attribute later silence to sshd, a middlebox, or a server-side policy.
    attempt: u8,
    tcp_connected: bool,
    rx_bytes: u64,
    tx_bytes: u64,
    server_identification_observed: bool,
    host_key_observed: bool,
    peer_eof_before_local_shutdown: bool,
    peer_disconnect_reason: Option<String>,
    elapsed_ms: u64,
    failure_elapsed_ms: u64,
    cleanup_elapsed_ms: u64,
    socket_shutdown_confirmed: bool,
    stream_released: bool,
    failure_category: SshFailureCategory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshFailureCategory {
    TerminalDisconnect,
    TerminalHangup,
    TerminalTimeout,
    TerminalSend,
    TerminalIoClose,
    Io,
    LocalDeadline,
    Protocol,
    HostKey,
    LocalSetup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshPeerObservation {
    TcpNotConnected,
    TcpConnectedNoSshBytes,
    ClientIdentificationSentServerSilent,
    TransportClosedBeforeServerIdentification,
    PeerBytesWithoutValidServerIdentification,
    SshIdentificationObservedNoHostKey,
    RemoteSshDisconnectBeforeHostKey,
    HostKeyObserved,
}

impl fmt::Display for SshPeerObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TcpNotConnected => "tcp_not_connected",
            Self::TcpConnectedNoSshBytes => "tcp_connected_no_ssh_bytes",
            Self::ClientIdentificationSentServerSilent => {
                "client_identification_sent_server_silent"
            }
            Self::TransportClosedBeforeServerIdentification => {
                "transport_closed_before_server_identification"
            }
            Self::PeerBytesWithoutValidServerIdentification => {
                "peer_bytes_without_valid_server_identification"
            }
            Self::SshIdentificationObservedNoHostKey => "ssh_identification_observed_no_host_key",
            Self::RemoteSshDisconnectBeforeHostKey => "remote_ssh_disconnect_before_host_key",
            Self::HostKeyObserved => "host_key_observed",
        })
    }
}

impl SshPeerObservation {
    fn attribution(self) -> &'static str {
        match self {
            Self::TcpNotConnected => "connect_path_failure",
            Self::TcpConnectedNoSshBytes => "no_ssh_traffic_observed",
            Self::ClientIdentificationSentServerSilent => "undetermined_pre_identification_silence",
            Self::TransportClosedBeforeServerIdentification => {
                "undetermined_pre_identification_transport_close"
            }
            Self::PeerBytesWithoutValidServerIdentification => {
                "non_ssh_or_pre_identification_policy_bytes"
            }
            Self::SshIdentificationObservedNoHostKey => "ssh_identification_reached",
            Self::RemoteSshDisconnectBeforeHostKey => "ssh_disconnect_observed",
            Self::HostKeyObserved => "ssh_host_key_reached",
        }
    }
}

fn ssh_pre_auth_transport_phase(server_identification_observed: bool) -> &'static str {
    if server_identification_observed {
        "SSH key exchange phase"
    } else {
        "SSH server identification phase"
    }
}

impl fmt::Display for SshFailureCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TerminalDisconnect => "terminal_disconnect",
            Self::TerminalHangup => "terminal_hangup",
            Self::TerminalTimeout => "terminal_timeout",
            Self::TerminalSend => "terminal_send",
            Self::TerminalIoClose => "terminal_io_close",
            Self::Io => "io",
            Self::LocalDeadline => "local_deadline",
            Self::Protocol => "protocol",
            Self::HostKey => "host_key",
            Self::LocalSetup => "local_setup",
        })
    }
}

impl fmt::Display for SshAttemptRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let peer_disconnect_reason = self.peer_disconnect_reason.as_deref().unwrap_or("none");
        let peer_observation = self.peer_observation();
        write!(
            formatter,
            "SSH attempt {}: peer_observation={} attribution={} tcp_connected={} rx_bytes={} tx_bytes={} server_identification_observed={} host_key_observed={} peer_eof_before_local_shutdown={} peer_disconnect_reason={} failure_elapsed_ms={} cleanup_elapsed_ms={} elapsed_ms={} socket_shutdown_confirmed={} stream_released={} failure={}",
            self.attempt,
            peer_observation,
            peer_observation.attribution(),
            self.tcp_connected,
            self.rx_bytes,
            self.tx_bytes,
            self.server_identification_observed,
            self.host_key_observed,
            self.peer_eof_before_local_shutdown,
            peer_disconnect_reason,
            self.failure_elapsed_ms,
            self.cleanup_elapsed_ms,
            self.elapsed_ms,
            self.socket_shutdown_confirmed,
            self.stream_released,
            self.failure_category
        )
    }
}

impl std::error::Error for SshAttemptRecord {}

impl SshAttemptRecord {
    fn peer_observation(&self) -> SshPeerObservation {
        if !self.tcp_connected {
            SshPeerObservation::TcpNotConnected
        } else if self.host_key_observed {
            SshPeerObservation::HostKeyObserved
        } else if self.peer_disconnect_reason.is_some() {
            SshPeerObservation::RemoteSshDisconnectBeforeHostKey
        } else if self.rx_bytes == 0
            && (self.peer_eof_before_local_shutdown
                || self.failure_category == SshFailureCategory::TerminalIoClose)
        {
            SshPeerObservation::TransportClosedBeforeServerIdentification
        } else if self.server_identification_observed {
            SshPeerObservation::SshIdentificationObservedNoHostKey
        } else if self.rx_bytes > 0 {
            SshPeerObservation::PeerBytesWithoutValidServerIdentification
        } else if self.tx_bytes > 0 {
            SshPeerObservation::ClientIdentificationSentServerSilent
        } else {
            SshPeerObservation::TcpConnectedNoSshBytes
        }
    }

    fn capture(
        attempt: u8,
        started: tokio::time::Instant,
        tcp_connected: bool,
        activity: &SshTransportActivity,
        disconnect_detail: &Arc<Mutex<Option<String>>>,
        cleanup: TransportCleanup,
        failure_category: SshFailureCategory,
    ) -> Self {
        let elapsed = started.elapsed();
        let failure_elapsed = elapsed.saturating_sub(cleanup.elapsed);
        Self {
            attempt,
            tcp_connected,
            rx_bytes: activity.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: activity.tx_bytes.load(Ordering::Relaxed),
            server_identification_observed: activity
                .server_identification_observed
                .load(Ordering::Acquire),
            host_key_observed: activity.host_key_observed.load(Ordering::Acquire),
            peer_eof_before_local_shutdown: activity
                .peer_eof_before_local_shutdown
                .load(Ordering::Acquire),
            peer_disconnect_reason: disconnect_detail
                .lock()
                .ok()
                .and_then(|detail| detail.clone()),
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            failure_elapsed_ms: u64::try_from(failure_elapsed.as_millis()).unwrap_or(u64::MAX),
            cleanup_elapsed_ms: u64::try_from(cleanup.elapsed.as_millis()).unwrap_or(u64::MAX),
            socket_shutdown_confirmed: cleanup.socket_shutdown_confirmed,
            stream_released: cleanup.stream_released,
            failure_category,
        }
    }
}

fn classify_ssh_attempt_failure(error: &anyhow::Error) -> SshFailureCategory {
    fn is_terminal_close(kind: io::ErrorKind) -> bool {
        matches!(
            kind,
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::NotConnected
                | io::ErrorKind::UnexpectedEof
        )
    }

    match error.downcast_ref::<russh::Error>() {
        Some(russh::Error::Disconnect) => SshFailureCategory::TerminalDisconnect,
        Some(russh::Error::HUP) => SshFailureCategory::TerminalHangup,
        Some(
            russh::Error::ConnectionTimeout
            | russh::Error::KeepaliveTimeout
            | russh::Error::InactivityTimeout,
        ) => SshFailureCategory::TerminalTimeout,
        Some(russh::Error::SendError) => SshFailureCategory::TerminalSend,
        Some(russh::Error::IO(error)) if is_terminal_close(error.kind()) => {
            SshFailureCategory::TerminalIoClose
        }
        Some(russh::Error::IO(_)) => SshFailureCategory::Io,
        Some(russh::Error::UnknownKey) => SshFailureCategory::HostKey,
        Some(_) => SshFailureCategory::Protocol,
        None if error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| is_terminal_close(error.kind())) =>
        {
            SshFailureCategory::TerminalIoClose
        }
        None if error.downcast_ref::<io::Error>().is_some() => SshFailureCategory::Io,
        None => SshFailureCategory::LocalSetup,
    }
}

fn attach_ssh_attempt_record(error: anyhow::Error, record: SshAttemptRecord) -> anyhow::Error {
    log::debug!("{record}");
    error.context(record)
}

fn log_successful_ssh_attempt(
    attempt: u8,
    started: tokio::time::Instant,
    activity: &SshTransportActivity,
) {
    log::debug!(
        "SSH attempt {attempt}: tcp_connected=true rx_bytes={} tx_bytes={} server_identification_observed={} host_key_observed={} elapsed_ms={} socket_shutdown_confirmed=false stream_released=false outcome=key_exchange_complete",
        activity.rx_bytes.load(Ordering::Relaxed),
        activity.tx_bytes.load(Ordering::Relaxed),
        activity
            .server_identification_observed
            .load(Ordering::Acquire),
        activity.host_key_observed.load(Ordering::Acquire),
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
    );
}

struct CountedSshStream {
    socket: Option<tokio::net::TcpStream>,
    activity: Arc<SshTransportActivity>,
    identification: IdentificationTracker,
    released: Option<oneshot::Sender<()>>,
}

struct IdentificationTracker {
    line: Vec<u8>,
    oversized: bool,
}

impl Default for IdentificationTracker {
    fn default() -> Self {
        Self {
            line: Vec::with_capacity(255),
            oversized: false,
        }
    }
}

fn sanitize_server_identification(line: &[u8]) -> Option<String> {
    if line.is_empty() || line.len() > 253 || !line.iter().all(|byte| matches!(byte, 0x20..=0x7e)) {
        return None;
    }
    let prefix_len = if line.starts_with(b"SSH-2.0-") {
        b"SSH-2.0-".len()
    } else if line.starts_with(b"SSH-1.99-") {
        b"SSH-1.99-".len()
    } else {
        return None;
    };
    let software_end = line[prefix_len..]
        .iter()
        .position(|byte| *byte == b' ')
        .map_or(line.len(), |offset| prefix_len + offset);
    let software = line.get(prefix_len..software_end)?;
    if software.is_empty()
        || software.len() > MAX_SAFE_SERVER_IDENTIFICATION_BYTES.saturating_sub(prefix_len)
        || !software.iter().all(|byte| matches!(byte, 0x21..=0x7e))
    {
        return None;
    }
    let retained = line.get(..software_end)?;
    std::str::from_utf8(retained).ok().map(str::to_owned)
}

impl IdentificationTracker {
    fn observe(&mut self, bytes: &[u8]) -> Option<String> {
        for byte in bytes {
            if *byte == b'\n' {
                let observed = (!self.oversized && self.line.last() == Some(&b'\r'))
                    .then(|| sanitize_server_identification(&self.line[..self.line.len() - 1]))
                    .flatten();
                *self = Self::default();
                if observed.is_some() {
                    return observed;
                }
                continue;
            }
            if self.line.len() < 254 {
                self.line.push(*byte);
            } else {
                self.oversized = true;
            }
        }
        None
    }
}

impl CountedSshStream {
    fn new(
        socket: tokio::net::TcpStream,
        activity: Arc<SshTransportActivity>,
        released: oneshot::Sender<()>,
    ) -> Self {
        Self {
            socket: Some(socket),
            activity,
            identification: IdentificationTracker::default(),
            released: Some(released),
        }
    }
}

impl AsyncRead for CountedSshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buffer.filled().len();
        let had_capacity = buffer.remaining() > 0;
        let result = Pin::new(
            self.socket
                .as_mut()
                .expect("counted SSH stream polled after socket release"),
        )
        .poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            let received = buffer.filled().len().saturating_sub(filled_before);
            let received_bytes = &buffer.filled()[filled_before..];
            if let Some(identification) = self.identification.observe(received_bytes) {
                if let Ok(mut retained) = self.activity.server_identification.lock() {
                    if retained.is_none() {
                        *retained = Some(identification);
                    }
                    self.activity
                        .server_identification_observed
                        .store(true, Ordering::Release);
                }
            }
            self.activity
                .rx_bytes
                .fetch_add(received as u64, Ordering::Relaxed);
            if had_capacity
                && received == 0
                && !self.activity.local_shutdown_started.load(Ordering::Acquire)
            {
                self.activity
                    .peer_eof_before_local_shutdown
                    .store(true, Ordering::Release);
            }
        }
        result
    }
}

impl AsyncWrite for CountedSshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(
            self.socket
                .as_mut()
                .expect("counted SSH stream polled after socket release"),
        )
        .poll_write(context, buffer);
        if let Poll::Ready(Ok(written)) = result {
            self.activity
                .tx_bytes
                .fetch_add(written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(
            self.socket
                .as_mut()
                .expect("counted SSH stream polled after socket release"),
        )
        .poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(
            self.socket
                .as_mut()
                .expect("counted SSH stream polled after socket release"),
        )
        .poll_shutdown(context)
    }
}

impl Drop for CountedSshStream {
    fn drop(&mut self) {
        // `stream_released` is a retry authorization condition. Drop the
        // transport's owned async socket before publishing the signal; Rust
        // would otherwise drop fields only after this Drop body returns.
        drop(self.socket.take());
        if let Some(released) = self.released.take() {
            let _ = released.send(());
        }
    }
}

/// Channel-open and global-request futures do not expose whether a cancelled
/// wait left state inside russh or on the peer. Keep this guard armed across
/// those awaits so outer task cancellation fails closed by dropping the whole
/// transport instead of leaking an SSH channel or remote listener.
struct TripTransportOnDrop {
    trip: TransportTrip,
    armed: bool,
}

impl TripTransportOnDrop {
    fn new(trip: TransportTrip) -> Self {
        Self { trip, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TripTransportOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.trip.trip();
        }
    }
}

struct TransportControl {
    trip: TransportTrip,
    done: AsyncMutex<Option<oneshot::Receiver<()>>>,
}

#[derive(Clone, Copy, Debug)]
struct TransportCleanup {
    socket_shutdown_confirmed: bool,
    stream_released: bool,
    elapsed: Duration,
}

impl TransportCleanup {
    const NO_LIVE_STREAM: Self = Self {
        socket_shutdown_confirmed: false,
        stream_released: true,
        elapsed: Duration::ZERO,
    };
}

impl TransportControl {
    fn trip(&self) -> TransportTrip {
        self.trip.clone()
    }

    async fn stop_and_wait(&self) -> TransportCleanup {
        let started = tokio::time::Instant::now();
        let socket_shutdown_confirmed = self.trip.trip();
        let Some(done) = self.done.lock().await.take() else {
            return TransportCleanup {
                socket_shutdown_confirmed,
                stream_released: false,
                elapsed: started.elapsed(),
            };
        };
        let stream_released = matches!(
            tokio::time::timeout(TRANSPORT_CLEANUP_TIMEOUT, done).await,
            Ok(Ok(()))
        );
        TransportCleanup {
            socket_shutdown_confirmed,
            stream_released,
            elapsed: started.elapsed(),
        }
    }
}

impl Drop for TransportControl {
    fn drop(&mut self) {
        self.trip.trip();
    }
}

/// Validates each SFTP length prefix before exposing even its four-byte header
/// to russh-sftp. That crate otherwise accepts `u32::MAX` and allocates the
/// advertised body synchronously. Buffering one bounded frame also makes a
/// protocol violation terminal instead of leaving the library desynchronized.
struct BoundedSftpStream<S> {
    inner: S,
    trip: TransportTrip,
    header: [u8; 4],
    header_read: usize,
    body: Vec<u8>,
    body_read: usize,
    emit_pos: usize,
    frame_ready: bool,
    failed: bool,
}

impl<S> BoundedSftpStream<S> {
    fn new(inner: S, trip: TransportTrip) -> Self {
        Self {
            inner,
            trip,
            header: [0; 4],
            header_read: 0,
            body: Vec::new(),
            body_read: 0,
            emit_pos: 0,
            frame_ready: false,
            failed: false,
        }
    }

    fn protocol_failure(&mut self, message: &'static str) -> io::Error {
        self.failed = true;
        self.trip.trip();
        // russh-sftp exits its reader loop only for UnexpectedEof. Returning
        // InvalidData would make its background task spin forever on this same
        // persistent failure state.
        io::Error::new(io::ErrorKind::UnexpectedEof, message)
    }

    fn reset_frame(&mut self) {
        self.header.zeroize();
        self.header_read = 0;
        // `Vec::zeroize` covers both initialized elements and spare capacity.
        // A DATA response may contain credentials or downloaded evidence and
        // must not remain in the reusable allocation after it is emitted.
        self.body.zeroize();
        self.body_read = 0;
        self.emit_pos = 0;
        self.frame_ready = false;
    }
}

impl<S> Drop for BoundedSftpStream<S> {
    fn drop(&mut self) {
        self.header.zeroize();
        self.body.zeroize();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BoundedSftpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SFTP stream closed after a framing violation",
            )));
        }

        loop {
            if this.frame_ready {
                let frame_len = 4 + this.body.len();
                if this.emit_pos == frame_len {
                    this.reset_frame();
                    if output.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
                if output.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }

                let available = frame_len - this.emit_pos;
                let take = available.min(output.remaining());
                let header_remaining = 4_usize.saturating_sub(this.emit_pos);
                if header_remaining > 0 {
                    let header_take = take.min(header_remaining);
                    output.put_slice(&this.header[this.emit_pos..this.emit_pos + header_take]);
                    this.emit_pos += header_take;
                    if header_take == take {
                        return Poll::Ready(Ok(()));
                    }
                }
                let body_pos = this.emit_pos - 4;
                let body_take = take - take.min(header_remaining);
                output.put_slice(&this.body[body_pos..body_pos + body_take]);
                this.emit_pos += body_take;
                return Poll::Ready(Ok(()));
            }

            if this.header_read < 4 {
                let mut header_buf = ReadBuf::new(&mut this.header[this.header_read..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut header_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = header_buf.filled().len();
                        if read == 0 {
                            if this.header_read == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            let error = this.protocol_failure("truncated SFTP frame header");
                            return Poll::Ready(Err(error));
                        }
                        this.header_read += read;
                        if this.header_read < 4 {
                            continue;
                        }
                        let body_len = u32::from_be_bytes(this.header) as usize;
                        if body_len > MAX_SFTP_PACKET_BYTES {
                            let error =
                                this.protocol_failure("SFTP frame exceeds the 1 MiB safety limit");
                            return Poll::Ready(Err(error));
                        }
                        this.body.resize(body_len, 0);
                    }
                }
            }

            if this.body_read < this.body.len() {
                let mut body_buf = ReadBuf::new(&mut this.body[this.body_read..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut body_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = body_buf.filled().len();
                        if read == 0 {
                            let error = this.protocol_failure("truncated SFTP frame body");
                            return Poll::Ready(Err(error));
                        }
                        this.body_read += read;
                    }
                }
            }
            if this.body_read == this.body.len() {
                this.frame_ready = true;
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BoundedSftpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

trait ConfirmedSftpIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ConfirmedSftpIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Raw SFTP v3 upload handle whose `write_confirmed` method returns only after
/// the server's matching STATUS response. This avoids russh-sftp `File`'s
/// queued-WRITE semantics without converting every chunk acknowledgement into
/// an OpenSSH fsync request.
pub struct ConfirmedSftpUpload {
    stream: BoundedSftpStream<Box<dyn ConfirmedSftpIo>>,
    handle: Option<String>,
    next_request_id: u32,
    offset: u64,
}

impl ConfirmedSftpUpload {
    async fn initialize(
        mut stream: BoundedSftpStream<Box<dyn ConfirmedSftpIo>>,
        path: &str,
    ) -> Result<Self> {
        write_sftp_packet(&mut stream, Packet::Init(Init::default())).await?;
        match read_sftp_packet_bounded(&mut stream).await? {
            Packet::Version(version) if version.version == VERSION => {}
            Packet::Version(version) => bail!(
                "SFTP server selected unsupported protocol version {}",
                version.version
            ),
            packet => bail!(
                "SFTP initialization returned unexpected {} packet",
                packet_kind(&packet)
            ),
        }

        let request_id = 1;
        write_sftp_packet(
            &mut stream,
            Packet::Open(Open {
                id: request_id,
                filename: path.to_owned(),
                pflags: OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                attrs: protected_upload_file_attributes(),
            }),
        )
        .await?;
        let handle = expect_upload_handle(
            read_sftp_packet_bounded(&mut stream).await?,
            request_id,
            "open protected upload partial",
        )?
        .handle;
        Ok(Self {
            stream,
            handle: Some(handle),
            next_request_id: request_id,
            offset: 0,
        })
    }

    pub async fn write_confirmed(&mut self, data: &[u8]) -> Result<u64> {
        ensure!(!data.is_empty(), "SFTP upload chunk is empty");
        ensure!(
            data.len() <= serctl_protocol::SFTP_SAFE_CHUNK_BYTES,
            "SFTP upload chunk exceeds the confirmed-write limit"
        );
        let next_offset = self
            .offset
            .checked_add(data.len() as u64)
            .context("SFTP upload offset overflow")?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .context("SFTP upload request id overflow")?;
        let handle = self
            .handle
            .as_ref()
            .context("SFTP upload handle is already closed")?
            .clone();
        write_sftp_packet(
            &mut self.stream,
            Packet::Write(Write {
                id: self.next_request_id,
                handle,
                offset: self.offset,
                data: data.to_vec(),
            }),
        )
        .await?;
        expect_upload_ok_status(
            read_sftp_packet_bounded(&mut self.stream).await?,
            self.next_request_id,
            "write upload chunk",
        )?;
        self.offset = next_offset;
        Ok(self.offset)
    }

    pub async fn close_confirmed(&mut self) -> Result<u64> {
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .context("SFTP upload request id overflow")?;
        let handle = self
            .handle
            .as_ref()
            .context("SFTP upload handle is already closed")?
            .clone();
        write_sftp_packet(
            &mut self.stream,
            Packet::Close(Close {
                id: self.next_request_id,
                handle,
            }),
        )
        .await?;
        expect_upload_ok_status(
            read_sftp_packet_bounded(&mut self.stream).await?,
            self.next_request_id,
            "close upload partial",
        )?;
        self.handle = None;
        Ok(self.offset)
    }
}

/// A key-exchanged SSH transport that has observed and validated the server
/// host key but has not sent any user authentication secret yet.
pub struct StagedSshSession {
    handle: Option<client::Handle<SshHandler>>,
    invalidated: Arc<AtomicBool>,
    transport: Option<TransportControl>,
    remote_forwards: Arc<RemoteForwardRegistry>,
    disconnect_detail: Arc<Mutex<Option<String>>>,
    observed_fingerprint: String,
    expected_fingerprint: Option<String>,
    server_identification: String,
    transport_attempt_id: String,
}

impl StagedSshSession {
    pub fn observed_fingerprint(&self) -> &str {
        &self.observed_fingerprint
    }

    /// Close a pre-authentication transport and wait a bounded interval for
    /// russh to release the underlying TCP socket.
    pub async fn abort(mut self) {
        self.invalidated.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = tokio::time::timeout(
                TRANSPORT_CLEANUP_TIMEOUT,
                handle.disconnect(
                    russh::Disconnect::ByApplication,
                    "host-key pin persistence failed",
                    "en-US",
                ),
            )
            .await;
        }
        if let Some(transport) = self.transport.take() {
            let _ = transport.stop_and_wait().await;
        }
    }

    /// Send password authentication only after the caller has completed any
    /// required first-use host-key persistence.
    pub async fn authenticate_password_until(
        mut self,
        user: &str,
        password: &str,
        deadline: tokio::time::Instant,
    ) -> Result<SshSession> {
        if deadline <= tokio::time::Instant::now() {
            self.abort().await;
            bail!("SSH password authentication phase exceeded its deadline");
        }
        let result = {
            let authentication = self
                .handle
                .as_mut()
                .context("SSH transport is unavailable before authentication")?
                .authenticate_password(user, password);
            tokio::pin!(authentication);
            let guarded_authentication = std::future::poll_fn(|context| {
                // Password authentication begins with the same bounded russh
                // mpsc send as exec. Prevent an authentication attempt (and
                // password disclosure) from being enqueued on a post-deadline
                // repoll.
                if tokio::time::Instant::now() >= deadline {
                    return Poll::Ready(None);
                }
                match authentication.as_mut().poll(context) {
                    Poll::Ready(result) => Poll::Ready(Some(result)),
                    Poll::Pending => Poll::Pending,
                }
            });
            tokio::time::timeout_at(deadline, guarded_authentication).await
        };
        match result {
            Ok(Some(Ok(client::AuthResult::Success))) => {
                let connection_identity = match SshConnectionIdentitySnapshot::new_authenticated(
                    true,
                    Some(&self.observed_fingerprint),
                    self.expected_fingerprint.as_deref(),
                    Some(&self.server_identification),
                    Some(&self.transport_attempt_id),
                ) {
                    Ok(identity) => identity,
                    Err(error) => {
                        self.abort().await;
                        return Err(error);
                    }
                };
                let handle = self
                    .handle
                    .take()
                    .context("SSH transport disappeared after authentication")?;
                let transport = self
                    .transport
                    .take()
                    .context("SSH transport control disappeared after authentication")?;
                Ok(SshSession {
                    handle,
                    connection_identity,
                    invalidated: self.invalidated.clone(),
                    transport,
                    remote_forwards: Arc::clone(&self.remote_forwards),
                    remote_forward_setup: AsyncMutex::new(()),
                    tunnel_flow_permits: Arc::new(Semaphore::new(MAX_SESSION_TUNNEL_FLOWS)),
                })
            }
            Ok(Some(Ok(_))) => {
                self.abort().await;
                bail!("SSH password authentication rejected the stored SSH credential")
            }
            Ok(Some(Err(error))) => {
                let error = ssh_phase_failure(
                    "SSH password authentication phase",
                    error.into(),
                    &self.disconnect_detail,
                );
                self.abort().await;
                Err(error)
            }
            Ok(None) | Err(_) => {
                self.abort().await;
                bail!("SSH password authentication phase exceeded its deadline")
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SshConnectBudget {
    first_attempt_deadline: tokio::time::Instant,
    retry_attempt_deadline: Option<tokio::time::Instant>,
}

fn ssh_connect_budget(
    now: tokio::time::Instant,
    total_deadline: tokio::time::Instant,
    post_kex_window: Duration,
) -> SshConnectBudget {
    let minimum_retry_total = MIN_FIRST_KEX_WINDOW
        + TRANSPORT_CLEANUP_TIMEOUT
        + PRE_AUTH_RETRY_BACKOFF
        + MIN_RETRY_KEX_WINDOW
        + RETRY_SCHEDULING_MARGIN
        + post_kex_window;
    let retry_reserve = TRANSPORT_CLEANUP_TIMEOUT
        + PRE_AUTH_RETRY_BACKOFF
        + MIN_RETRY_KEX_WINDOW
        + RETRY_SCHEDULING_MARGIN
        + post_kex_window;
    let retry_enabled = total_deadline
        .checked_duration_since(now)
        .is_some_and(|remaining| remaining >= minimum_retry_total);

    if retry_enabled {
        SshConnectBudget {
            first_attempt_deadline: total_deadline
                .checked_sub(retry_reserve)
                .expect("validated retry reserve exceeded the total SSH deadline"),
            retry_attempt_deadline: Some(
                total_deadline
                    .checked_sub(post_kex_window)
                    .expect("validated post-KEX reserve exceeded the total SSH deadline"),
            ),
        }
    } else {
        let first_attempt_deadline = total_deadline
            .checked_duration_since(now)
            .filter(|remaining| *remaining >= MIN_FIRST_KEX_WINDOW + post_kex_window)
            .and_then(|_| total_deadline.checked_sub(post_kex_window))
            .unwrap_or(total_deadline);
        SshConnectBudget {
            first_attempt_deadline,
            retry_attempt_deadline: None,
        }
    }
}

fn has_minimum_retry_window_after_backoff(
    now: tokio::time::Instant,
    retry_deadline: tokio::time::Instant,
) -> bool {
    retry_deadline
        .checked_duration_since(now)
        .is_some_and(|remaining| remaining >= PRE_AUTH_RETRY_BACKOFF + MIN_RETRY_KEX_WINDOW)
}

fn has_minimum_retry_window(
    now: tokio::time::Instant,
    retry_deadline: tokio::time::Instant,
) -> bool {
    retry_deadline
        .checked_duration_since(now)
        .is_some_and(|remaining| remaining >= MIN_RETRY_KEX_WINDOW)
}

fn has_early_eof_retry_window_after_backoff(
    now: tokio::time::Instant,
    retry_deadline: tokio::time::Instant,
) -> bool {
    retry_deadline
        .checked_duration_since(now)
        .is_some_and(|remaining| remaining >= EARLY_EOF_RETRY_BACKOFF + MIN_EARLY_EOF_RETRY_WINDOW)
}

fn has_early_eof_retry_window(
    now: tokio::time::Instant,
    retry_deadline: tokio::time::Instant,
) -> bool {
    retry_deadline
        .checked_duration_since(now)
        .is_some_and(|remaining| remaining >= MIN_EARLY_EOF_RETRY_WINDOW)
}

fn should_retry_pre_auth_failure(record: &SshAttemptRecord, error: &anyhow::Error) -> bool {
    if record.host_key_observed
        || record.rx_bytes > 0
        || record.peer_disconnect_reason.is_some()
        || !record.socket_shutdown_confirmed
        || !record.stream_released
    {
        return false;
    }
    is_ssh_transport_terminal_error(error)
        || record.failure_category == SshFailureCategory::LocalDeadline
}

/// Retry exactly one pre-authentication failure without minting a fresh time
/// budget. The first attempt owns an explicit sub-deadline only when the
/// caller supplied enough time for cleanup, a useful retry, and all post-KEX
/// work (TOFU persistence when needed plus password authentication).
async fn connect_key_exchange_with_one_reconnect_until<T, F, Fut>(
    deadline: tokio::time::Instant,
    post_kex_window: Duration,
    mut attempt: F,
) -> Result<(T, bool)>
where
    F: FnMut(u8, tokio::time::Instant) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let budget = ssh_connect_budget(tokio::time::Instant::now(), deadline, post_kex_window);
    match attempt(1, budget.first_attempt_deadline).await {
        Ok(staged) => Ok((staged, false)),
        Err(first) => {
            let Some(record) = first.downcast_ref::<SshAttemptRecord>() else {
                return Err(first);
            };
            let retryable = should_retry_pre_auth_failure(record, &first);
            if !retryable {
                return Err(first);
            }
            let now = tokio::time::Instant::now();
            let (
                retry_deadline,
                retry_backoff,
                uses_reserved_retry_window,
                retry_window_is_complete,
            ) = if let Some(retry_deadline) = budget.retry_attempt_deadline {
                (
                    retry_deadline,
                    PRE_AUTH_RETRY_BACKOFF,
                    true,
                    has_minimum_retry_window_after_backoff(now, retry_deadline),
                )
            } else if record.peer_eof_before_local_shutdown {
                (
                    deadline,
                    EARLY_EOF_RETRY_BACKOFF,
                    false,
                    has_early_eof_retry_window_after_backoff(now, deadline),
                )
            } else {
                return Err(first);
            };
            if !retry_window_is_complete {
                return Err(first);
            }
            let first_category = record.failure_category;
            let first_attempt = record.to_string();
            tokio::time::sleep(retry_backoff).await;
            let now = tokio::time::Instant::now();
            let retry_window_remains = if uses_reserved_retry_window {
                has_minimum_retry_window(now, retry_deadline)
            } else {
                has_early_eof_retry_window(now, retry_deadline)
            };
            if !retry_window_remains {
                return Err(first);
            }
            match attempt(2, retry_deadline).await {
                Ok(staged) => Ok((staged, true)),
                Err(second) => {
                    let (second_category, second_attempt, second_phase) =
                        second.downcast_ref::<SshAttemptRecord>().map_or_else(
                            || {
                                (
                                    "unclassified".to_owned(),
                                    "unavailable".to_owned(),
                                    "SSH pre-authentication transport phase",
                                )
                            },
                            |record| {
                                (
                                    record.failure_category.to_string(),
                                    record.to_string(),
                                    ssh_pre_auth_transport_phase(
                                        record.server_identification_observed,
                                    ),
                                )
                            },
                        );
                    Err(second.context(format!(
                        "{second_phase} failed after one pre-authentication reconnect; first_failure={first_category}; first_attempt=[{first_attempt}]; second_failure={second_category}; second_attempt=[{second_attempt}]"
                    )))
                }
            }
        }
    }
}

impl SshSession {
    pub fn connection_identity(&self) -> &SshConnectionIdentitySnapshot {
        &self.connection_identity
    }

    /// Start the fixed native transfer helper without interpolating any
    /// user-controlled path or argument into the SSH exec command. Paths and
    /// transfer metadata are exchanged only through bounded protocol frames
    /// on the returned stdio stream.
    pub async fn native_transfer_stream_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<russh::ChannelStream<russh::client::Msg>> {
        let mut channel = self.open_exec_until(deadline).await?;
        if let Err(error) = channel
            .request_exec_until("serctl-xfer serve --stdio", deadline)
            .await
        {
            channel.cancel().await;
            return Err(error);
        }
        Ok(channel.into_stream())
    }

    /// Complete TCP connection, SSH key exchange, and host-key validation
    /// without sending a password. A transport-terminal failure before KEX
    /// completes is safe to retry once because authentication has not started;
    /// both attempts share the caller's original absolute deadline.
    pub async fn connect_key_exchange_until(
        creds: &Creds,
        expect: Option<String>,
        deadline: tokio::time::Instant,
    ) -> Result<StagedSshSession> {
        let post_kex_window = MIN_PASSWORD_AUTH_WINDOW
            + if expect.is_none() {
                MIN_TOFU_PIN_WINDOW
            } else {
                Duration::ZERO
            };
        let (staged, _) = connect_key_exchange_with_one_reconnect_until(
            deadline,
            post_kex_window,
            |attempt, attempt_deadline| {
                Self::connect_key_exchange_once_until(
                    creds,
                    expect.clone(),
                    attempt,
                    attempt_deadline,
                )
            },
        )
        .await?;
        Ok(staged)
    }

    /// One pre-authentication transport attempt. Russh owns the counted TCP
    /// stream directly; a duplicated OS socket handle lets timeout cleanup
    /// interrupt blocked I/O without inserting a userspace duplex proxy into
    /// the key-exchange path.
    async fn connect_key_exchange_once_until(
        creds: &Creds,
        expect: Option<String>,
        attempt: u8,
        deadline: tokio::time::Instant,
    ) -> Result<StagedSshSession> {
        let started = tokio::time::Instant::now();
        let transport_attempt_id = new_transport_attempt_id();
        let seen = Arc::new(Mutex::new(None));
        let disconnect_detail = Arc::new(Mutex::new(None));
        let activity = Arc::new(SshTransportActivity::default());
        let remote_forwards = Arc::new(RemoteForwardRegistry::default());
        let cfg = client::Config {
            // This is a second line of defence for pre-authentication stalls.
            // The external absolute deadline is enforced around connect_stream;
            // this timeout also bounds an upstream-internal wait.
            inactivity_timeout: Some(SSH_INACTIVITY_TIMEOUT),
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            preferred: secure_client_algorithms(),
            ..Default::default()
        };
        let cfg = Arc::new(cfg);
        let handler = SshHandler {
            expect: expect.clone(),
            seen: seen.clone(),
            disconnect_detail: Arc::clone(&disconnect_detail),
            activity: Arc::clone(&activity),
            remote_forwards: Arc::clone(&remote_forwards),
        };
        let socket = match connect_ssh_tcp_until(creds.host.as_str(), creds.port, deadline).await {
            Ok(socket) => socket,
            Err(error) => {
                let category = if tokio::time::Instant::now() >= deadline {
                    SshFailureCategory::LocalDeadline
                } else {
                    classify_ssh_attempt_failure(&error)
                };
                let record = SshAttemptRecord::capture(
                    attempt,
                    started,
                    false,
                    &activity,
                    &disconnect_detail,
                    TransportCleanup::NO_LIVE_STREAM,
                    category,
                );
                return Err(attach_ssh_attempt_record(
                    error.context("SSH TCP connection phase failed"),
                    record,
                ));
            }
        };
        if cfg.nodelay {
            socket.set_nodelay(true).context("set SSH TCP_NODELAY")?;
        }

        let socket = match socket.into_std() {
            Ok(socket) => socket,
            Err(error) => {
                let record = SshAttemptRecord::capture(
                    attempt,
                    started,
                    true,
                    &activity,
                    &disconnect_detail,
                    TransportCleanup::NO_LIVE_STREAM,
                    SshFailureCategory::LocalSetup,
                );
                return Err(attach_ssh_attempt_record(
                    anyhow::Error::new(error).context("take ownership of SSH TCP socket"),
                    record,
                ));
            }
        };
        let shutdown_socket = match socket.try_clone() {
            Ok(shutdown_socket) => Arc::new(shutdown_socket),
            Err(error) => {
                let record = SshAttemptRecord::capture(
                    attempt,
                    started,
                    true,
                    &activity,
                    &disconnect_detail,
                    TransportCleanup::NO_LIVE_STREAM,
                    SshFailureCategory::LocalSetup,
                );
                return Err(attach_ssh_attempt_record(
                    anyhow::Error::new(error).context("duplicate SSH TCP shutdown handle"),
                    record,
                ));
            }
        };
        let socket = match tokio::net::TcpStream::from_std(socket) {
            Ok(socket) => socket,
            Err(error) => {
                let record = SshAttemptRecord::capture(
                    attempt,
                    started,
                    true,
                    &activity,
                    &disconnect_detail,
                    TransportCleanup::NO_LIVE_STREAM,
                    SshFailureCategory::LocalSetup,
                );
                return Err(attach_ssh_attempt_record(
                    anyhow::Error::new(error).context("restore asynchronous SSH TCP socket"),
                    record,
                ));
            }
        };

        let invalidated = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let trip = TransportTrip {
            invalidated: invalidated.clone(),
            cancel,
            shutdown: Some(shutdown_socket),
            activity: Some(Arc::clone(&activity)),
        };
        let (done_tx, done_rx) = oneshot::channel();
        let russh_stream = CountedSshStream::new(socket, Arc::clone(&activity), done_tx);
        let transport = TransportControl {
            trip,
            done: AsyncMutex::new(Some(done_rx)),
        };

        let operation = async {
            Ok::<_, anyhow::Error>(client::connect_stream(cfg, russh_stream, handler).await?)
        };
        let handle = match tokio::time::timeout_at(deadline, operation).await {
            Ok(Ok(handle)) => handle,
            Ok(Err(error)) => {
                let category = classify_ssh_attempt_failure(&error);
                let phase = ssh_pre_auth_transport_phase(
                    activity
                        .server_identification_observed
                        .load(Ordering::Acquire),
                );
                let error = ssh_phase_failure(phase, error, &disconnect_detail);
                let cleanup = transport.stop_and_wait().await;
                let record = SshAttemptRecord::capture(
                    attempt,
                    started,
                    true,
                    &activity,
                    &disconnect_detail,
                    cleanup,
                    category,
                );
                return Err(attach_ssh_attempt_record(error, record));
            }
            Err(_) => {
                let cleanup = transport.stop_and_wait().await;
                let phase = ssh_pre_auth_transport_phase(
                    activity
                        .server_identification_observed
                        .load(Ordering::Acquire),
                );
                let record = SshAttemptRecord::capture(
                    attempt,
                    started,
                    true,
                    &activity,
                    &disconnect_detail,
                    cleanup,
                    SshFailureCategory::LocalDeadline,
                );
                return Err(attach_ssh_attempt_record(
                    anyhow::anyhow!("{phase} exceeded its deadline"),
                    record,
                ));
            }
        };
        let observed_fingerprint = seen
            .lock()
            .map_err(|_| anyhow::anyhow!("server-key observation state was poisoned"))?
            .clone();
        let fp = match require_server_fingerprint(observed_fingerprint)
            .context("SSH host-key verification phase failed")
        {
            Ok(fp) => fp,
            Err(error) => {
                let cleanup = transport.stop_and_wait().await;
                let record = SshAttemptRecord::capture(
                    attempt,
                    started,
                    true,
                    &activity,
                    &disconnect_detail,
                    cleanup,
                    SshFailureCategory::HostKey,
                );
                return Err(attach_ssh_attempt_record(error, record));
            }
        };
        let verified_identity_material = (|| -> Result<(Option<String>, String)> {
            if let Some(expected) = expect.as_deref() {
                ensure!(expected == fp, "SSH host-key pin does not match");
            }
            let server_identification = activity
                .server_identification
                .lock()
                .map_err(|_| anyhow::anyhow!("server-identification state was poisoned"))?
                .clone()
                .context("SSH completed without a safe server identification")?;
            Ok((expect.clone(), server_identification))
        })();
        let (expected_fingerprint, server_identification) = match verified_identity_material {
            Ok(material) => material,
            Err(error) => {
                let cleanup = transport.stop_and_wait().await;
                let record = SshAttemptRecord::capture(
                    attempt,
                    started,
                    true,
                    &activity,
                    &disconnect_detail,
                    cleanup,
                    SshFailureCategory::HostKey,
                );
                return Err(attach_ssh_attempt_record(
                    error.context("SSH connection identity verification phase failed"),
                    record,
                ));
            }
        };
        log_successful_ssh_attempt(attempt, started, &activity);
        Ok(StagedSshSession {
            handle: Some(handle),
            invalidated,
            transport: Some(transport),
            remote_forwards,
            disconnect_detail,
            observed_fingerprint: fp,
            expected_fingerprint,
            server_identification,
            transport_attempt_id,
        })
    }

    /// Connect and authenticate within one absolute request deadline. Callers
    /// performing TOFU pin persistence must instead use
    /// `connect_key_exchange_until`, persist the observed fingerprint, and
    /// only then call `authenticate_password_until`.
    pub async fn connect_until(
        creds: &Creds,
        expect: Option<String>,
        deadline: tokio::time::Instant,
    ) -> Result<(SshSession, String)> {
        let staged = Self::connect_key_exchange_until(creds, expect, deadline).await?;
        let fingerprint = staged.observed_fingerprint().to_owned();
        let session = staged
            .authenticate_password_until(&creds.user, &creds.password, deadline)
            .await?;
        Ok((session, fingerprint))
    }

    fn transport_trip(&self) -> TransportTrip {
        self.transport.trip()
    }

    pub async fn terminate_channel(
        &self,
        channel: &mut russh::Channel<russh::client::Msg>,
        signal_process: bool,
    ) -> bool {
        let cleaned = terminate_channel(channel, &self.transport_trip(), signal_process).await;
        if !cleaned {
            self.invalidate().await;
        }
        cleaned
    }

    pub fn is_closed(&self) -> bool {
        self.invalidated.load(Ordering::Acquire) || self.handle.is_closed()
    }

    /// Mark this transport unusable and ask russh to tear it down. Marking it
    /// first makes SessionManager reconnect even if russh has not yet observed
    /// the disconnect on its background task.
    pub async fn invalidate(&self) {
        self.invalidated.store(true, Ordering::Release);
        let _ = tokio::time::timeout(
            TRANSPORT_CLEANUP_TIMEOUT,
            self.handle.disconnect(
                russh::Disconnect::ByApplication,
                "request deadline/cancellation",
                "en-US",
            ),
        )
        .await;
        let _ = self.transport.stop_and_wait().await;
    }

    /// Open a direct-tcpip channel within one absolute deadline. Cancellation
    /// after this future has started is transport-fatal because russh does not
    /// expose whether its channel-open request was already queued.
    pub async fn open_direct_tcpip_until(
        &self,
        target_host: &str,
        target_port: u16,
        originator: SocketAddr,
        deadline: tokio::time::Instant,
    ) -> Result<Channel<client::Msg>> {
        validate_tunnel_host("direct-tcpip target host", target_host)?;
        ensure!(
            target_port != 0,
            "direct-tcpip target port must not be zero"
        );
        ensure!(
            deadline > tokio::time::Instant::now(),
            "direct-tcpip channel-open deadline expired"
        );
        let mut uncertain = TripTransportOnDrop::new(self.transport_trip());
        let deadline_expired = AtomicBool::new(false);
        let opened = poll_remote_mutation_until(
            deadline,
            self.handle.channel_open_direct_tcpip(
                target_host,
                u32::from(target_port),
                originator.ip().to_string(),
                u32::from(originator.port()),
            ),
            || {},
            || deadline_expired.store(true, Ordering::Release),
            "direct-tcpip channel open exceeded its deadline",
        )
        .await;
        match opened {
            Ok(channel) => {
                uncertain.disarm();
                Ok(channel)
            }
            Err(error) if !deadline_expired.load(Ordering::Acquire) => {
                uncertain.disarm();
                Err(error)
            }
            Err(error) => {
                self.invalidate().await;
                uncertain.disarm();
                Err(error)
            }
        }
    }

    async fn request_remote_forward_until(
        &self,
        bind_host: &str,
        bind_port: u16,
        deadline: tokio::time::Instant,
    ) -> Result<u16> {
        validate_tunnel_host("remote tunnel bind host", bind_host)?;
        ensure!(
            deadline > tokio::time::Instant::now(),
            "remote-forward setup deadline expired"
        );
        let mut uncertain = TripTransportOnDrop::new(self.transport_trip());
        let deadline_expired = AtomicBool::new(false);
        let requested = poll_remote_mutation_until(
            deadline,
            self.handle.tcpip_forward(bind_host, u32::from(bind_port)),
            || {},
            || deadline_expired.store(true, Ordering::Release),
            "remote-forward request exceeded its deadline",
        )
        .await;
        match requested {
            Ok(returned_port) => {
                let effective = if bind_port == 0 {
                    u16::try_from(returned_port)
                        .ok()
                        .filter(|port| *port != 0)
                        .context("SSH server did not return a valid allocated forwarding port")?
                } else {
                    ensure!(
                        returned_port == 0,
                        "SSH server returned unexpected data for a fixed forwarding port"
                    );
                    bind_port
                };
                uncertain.disarm();
                Ok(effective)
            }
            Err(error) if !deadline_expired.load(Ordering::Acquire) => {
                uncertain.disarm();
                Err(error)
            }
            Err(error) => {
                self.invalidate().await;
                uncertain.disarm();
                Err(error)
            }
        }
    }

    async fn cancel_remote_forward_until(
        &self,
        bind_host: &str,
        effective_port: u16,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        ensure!(
            effective_port != 0,
            "remote-forward cancel port must not be zero"
        );
        if self.is_closed() {
            return Ok(());
        }
        ensure!(
            deadline > tokio::time::Instant::now(),
            "remote-forward cancellation deadline expired"
        );
        let mut uncertain = TripTransportOnDrop::new(self.transport_trip());
        let cancelled = poll_remote_mutation_until(
            deadline,
            self.handle
                .cancel_tcpip_forward(bind_host, u32::from(effective_port)),
            || {},
            || {},
            "remote-forward cancellation exceeded its deadline",
        )
        .await;
        match cancelled {
            Ok(()) => {
                uncertain.disarm();
                Ok(())
            }
            Err(error) => {
                self.invalidate().await;
                uncertain.disarm();
                Err(error)
            }
        }
    }

    /// Validate and start one local, remote, or dynamic forwarding lease.
    /// The returned handle owns cancellation; daemon reconnect policy remains
    /// an upper-layer concern and can start a replacement tunnel on a new
    /// `Arc<SshSession>` after this one finishes.
    pub async fn start_tunnel(
        self: &Arc<Self>,
        spec: TunnelSpec,
        setup_deadline: tokio::time::Instant,
    ) -> Result<RunningTunnel> {
        ensure!(
            setup_deadline > tokio::time::Instant::now(),
            "SSH tunnel setup deadline expired"
        );
        let validated = ValidatedTunnelSpec::try_from(spec)?;
        let cancellation = CancellationToken::new();
        match validated {
            ValidatedTunnelSpec::Local {
                bind,
                target_port,
                max_connections,
            } => {
                let listener = bind_tunnel_listener_until(bind, setup_deadline).await?;
                let local = listener
                    .local_addr()
                    .context("query local tunnel listener")?;
                let ready = TunnelReady {
                    mode: TunnelMode::Local,
                    bind_host: local.ip().to_string(),
                    bind_port: local.port(),
                };
                let session = Arc::clone(self);
                let session_permits = Arc::clone(&self.tunnel_flow_permits);
                let worker_cancel = cancellation.clone();
                let task = tokio::spawn(async move {
                    run_local_forward(
                        session,
                        listener,
                        target_port,
                        max_connections,
                        session_permits,
                        worker_cancel,
                    )
                    .await
                });
                Ok(RunningTunnel {
                    ready,
                    cancellation,
                    task: Some(task),
                })
            }
            ValidatedTunnelSpec::Dynamic {
                bind,
                max_connections,
            } => {
                let listener = bind_tunnel_listener_until(bind, setup_deadline).await?;
                let local = listener
                    .local_addr()
                    .context("query SOCKS5 tunnel listener")?;
                let ready = TunnelReady {
                    mode: TunnelMode::Dynamic,
                    bind_host: local.ip().to_string(),
                    bind_port: local.port(),
                };
                let session = Arc::clone(self);
                let session_permits = Arc::clone(&self.tunnel_flow_permits);
                let worker_cancel = cancellation.clone();
                let task = tokio::spawn(async move {
                    run_dynamic_forward(
                        session,
                        listener,
                        max_connections,
                        session_permits,
                        worker_cancel,
                    )
                    .await
                });
                Ok(RunningTunnel {
                    ready,
                    cancellation,
                    task: Some(task),
                })
            }
            ValidatedTunnelSpec::Remote {
                bind_port,
                target_port,
                max_connections,
            } => {
                let (lease, incoming, effective_port) = self
                    .setup_remote_forward(bind_port, max_connections, setup_deadline)
                    .await?;
                let ready = TunnelReady {
                    mode: TunnelMode::Remote,
                    bind_host: TUNNEL_LOOPBACK_HOST.to_owned(),
                    bind_port: effective_port,
                };
                let worker_cancel = cancellation.clone();
                let session_permits = Arc::clone(&self.tunnel_flow_permits);
                let task = tokio::spawn(async move {
                    run_remote_forward(
                        lease,
                        incoming,
                        target_port,
                        max_connections,
                        session_permits,
                        worker_cancel,
                    )
                    .await
                });
                Ok(RunningTunnel {
                    ready,
                    cancellation,
                    task: Some(task),
                })
            }
        }
    }

    async fn setup_remote_forward(
        self: &Arc<Self>,
        bind_port: u16,
        max_connections: usize,
        deadline: tokio::time::Instant,
    ) -> Result<(
        RemoteForwardLease,
        mpsc::Receiver<IncomingRemoteForward>,
        u16,
    )> {
        let _setup = self.remote_forward_setup.lock().await;
        if bind_port != 0 {
            ensure!(
                !self.remote_forwards.contains_port(bind_port),
                "remote-forward port {bind_port} is already registered on this SSH session"
            );
        }
        let effective_port = self
            .request_remote_forward_until(TUNNEL_LOOPBACK_HOST, bind_port, deadline)
            .await?;
        if self.remote_forwards.contains_port(effective_port) {
            // A server must not allocate a port already active on this same
            // transport. Cancelling by port could tear down the legitimate
            // older lease, so close the transport to retire both safely.
            self.invalidate().await;
            bail!("SSH server allocated a duplicate remote-forward port");
        }
        let (sender, incoming) = mpsc::channel(max_connections.min(MAX_REMOTE_FORWARD_PENDING));
        let registration = match self.remote_forwards.register(effective_port, sender) {
            Ok(registration) => registration,
            Err(error) => {
                self.invalidate().await;
                return Err(error);
            }
        };
        Ok((
            RemoteForwardLease {
                session: Arc::clone(self),
                bind_host: TUNNEL_LOOPBACK_HOST.to_owned(),
                effective_port,
                registration: Some(registration),
                armed: true,
            },
            incoming,
            effective_port,
        ))
    }

    /// Open a command channel without sending the exec request yet. This is
    /// exposed separately so a daemon can react to IPC disconnects between
    /// channel creation and command startup and still close the channel.
    pub async fn open_exec_until(&self, deadline: tokio::time::Instant) -> Result<RunningCommand> {
        ensure!(
            deadline > tokio::time::Instant::now(),
            "exec channel-open deadline expired"
        );
        let mut uncertain = TripTransportOnDrop::new(self.transport_trip());
        let opened = poll_remote_mutation_until(
            deadline,
            self.handle.channel_open_session(),
            || {},
            || {},
            "exec channel-open deadline expired",
        )
        .await;
        match opened {
            Ok(channel) => {
                uncertain.disarm();
                Ok(RunningCommand {
                    channel,
                    transport: self.transport_trip(),
                    submission: ExecSubmissionState::BeforeRequest,
                })
            }
            Err(error)
                if !is_ssh_transport_terminal_error(&error)
                    && tokio::time::Instant::now() < deadline =>
            {
                // An explicit channel-open rejection is scoped to this
                // channel. Keep the authenticated transport for later work.
                uncertain.disarm();
                Err(error)
            }
            // A transport-terminal result, deadline, or cancellation leaves
            // the guard armed. Its synchronous Drop marks the session closed
            // and shuts down the socket before a pool can reuse this handle.
            Err(error) => Err(error),
        }
    }

    pub async fn start_exec_until(
        &self,
        cmd: &str,
        deadline: tokio::time::Instant,
    ) -> Result<RunningCommand> {
        let mut command = self.open_exec_until(deadline).await?;
        if let Err(error) = command.request_exec_until(cmd, deadline).await {
            command.cancel().await;
            return Err(error);
        }
        Ok(command)
    }

    pub async fn exec_until(
        &self,
        cmd: &str,
        deadline: tokio::time::Instant,
    ) -> Result<ExecResult> {
        let mut command = self.start_exec_until(cmd, deadline).await?;
        match tokio::time::timeout_at(deadline, command.finish()).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error)) => {
                command.cancel().await;
                Err(command.submission.classify(error))
            }
            Err(_) => {
                command.cancel().await;
                Err(command.submission.classify(command_deadline_error()))
            }
        }
    }

    /// Open a session channel, request a PTY + shell. Caller drives `wait()`/`make_writer()`.
    pub async fn pty_shell(
        &self,
        term: &str,
        cols: u32,
        rows: u32,
    ) -> Result<russh::Channel<russh::client::Msg>> {
        validate_shell_dimensions(cols, rows)?;
        let ch = self.handle.channel_open_session().await?;
        ch.request_pty(false, term, cols, rows, 0, 0, &[]).await?;
        ch.request_shell(true).await?;
        Ok(ch)
    }

    /// Open and initialize SFTP within the caller's absolute deadline. Channel
    /// creation and subsystem negotiation are staged so every stage that has a
    /// channel handle can close it explicitly on error. If russh is still
    /// waiting for channel-open or SFTP init, invalidate the whole transport;
    /// those futures do not expose a cancellation-safe channel handle.
    pub async fn sftp_until(&self, deadline: tokio::time::Instant) -> Result<SftpSession> {
        let channel = self.open_sftp_channel_until(deadline).await?;
        let stream = BoundedSftpStream::new(channel.into_stream(), self.transport_trip());
        let config = russh_sftp::client::Config {
            max_packet_len: MAX_SFTP_PACKET_BYTES as u32,
            // Keep any incidental high-level write path to one in-flight
            // request. File-transfer uploads use ConfirmedSftpUpload below,
            // which performs an explicit WRITE/STATUS exchange per chunk.
            max_concurrent_writes: 1,
            ..Default::default()
        };

        match tokio::time::timeout_at(deadline, SftpSession::new_with_config(stream, config)).await
        {
            Ok(Ok(sftp)) => Ok(sftp),
            Ok(Err(error)) => {
                // Initialization errors can leave the background SFTP reader
                // out of phase. Never reuse the daemon transport afterward.
                self.invalidate().await;
                Err(error.into())
            }
            Err(_) => {
                self.invalidate().await;
                bail!("SFTP initialization exceeded its deadline");
            }
        }
    }

    /// Open a create-new 0600 upload partial over a raw SFTP v3 channel. Each
    /// write on the returned handle is a request/STATUS exchange, so callers
    /// can report exact remote confirmation without relying on the high-level
    /// client's in-flight queue or issuing per-chunk fsync.
    pub async fn confirmed_sftp_upload_until(
        &self,
        path: &str,
        deadline: tokio::time::Instant,
    ) -> Result<ConfirmedSftpUpload> {
        validate_upload_remote_path(path)?;
        let channel = self.open_sftp_channel_until(deadline).await?;
        let stream: Box<dyn ConfirmedSftpIo> = Box::new(channel.into_stream());
        let stream = BoundedSftpStream::new(stream, self.transport_trip());
        match tokio::time::timeout_at(deadline, ConfirmedSftpUpload::initialize(stream, path)).await
        {
            Ok(result) => result,
            Err(_) => bail!("SFTP upload initialization exceeded its deadline"),
        }
    }

    pub async fn list_dir_until(
        &self,
        path: &str,
        deadline: tokio::time::Instant,
    ) -> Result<(String, Vec<RemoteEntry>)> {
        ensure!(
            path.len() <= DIRECTORY_LIMITS.string_bytes,
            "SFTP directory path exceeds the {} MiB safety limit",
            DIRECTORY_LIMITS.string_bytes / (1024 * 1024)
        );
        let channel = self.open_sftp_channel_until(deadline).await?;
        let mut stream = channel.into_stream();
        match tokio::time::timeout_at(
            deadline,
            list_dir_streaming(&mut stream, path, DIRECTORY_LIMITS),
        )
        .await
        {
            Ok(Ok(result)) => {
                // Success has already sent SSH_FXP_CLOSE for the directory
                // handle; dropping the stream also closes its SSH channel.
                drop(stream);
                Ok(result)
            }
            Ok(Err(error)) => {
                // The stream may be desynchronized (for example, only an
                // oversized packet's length prefix was consumed), so an SFTP
                // CLOSE cannot be issued reliably. Dropping the channel closes
                // every handle owned by that subsystem, and invalidating the
                // transport guarantees cleanup even if the channel Close
                // notification cannot be queued.
                drop(stream);
                self.invalidate().await;
                Err(error)
            }
            Err(_) => {
                // Dropping ChannelStream requests SSH channel close. Invalidate
                // as well because a timed-out read may have left an unread
                // response and this transport must not be reused by a daemon.
                drop(stream);
                self.invalidate().await;
                bail!("SFTP directory listing exceeded its deadline");
            }
        }
    }

    pub async fn create_dir_until(&self, path: &str, deadline: tokio::time::Instant) -> Result<()> {
        let sftp = self.sftp_until(deadline).await?;
        let mut submission = CreateDirSubmissionState::BeforeRequest;
        let result = poll_remote_mutation_until(
            deadline,
            sftp.create_dir(path),
            || submission.request_started(),
            || {},
            "SFTP create-directory exceeded its deadline",
        )
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_explicit_sftp_status(&error) => {
                // A STATUS response is an explicit server rejection, so its
                // outcome is definite even though the request was submitted.
                Err(error)
            }
            Err(error) => {
                if submission == CreateDirSubmissionState::RequestMayHaveReachedRemote {
                    self.invalidate().await;
                }
                Err(submission.classify(error))
            }
        }
    }

    async fn open_sftp_channel_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<russh::Channel<russh::client::Msg>> {
        ensure!(
            deadline > tokio::time::Instant::now(),
            "SFTP channel setup exceeded its deadline"
        );
        let mut uncertain = TripTransportOnDrop::new(self.transport_trip());
        let opened = poll_remote_mutation_until(
            deadline,
            self.handle.channel_open_session(),
            || {},
            || {},
            "SFTP channel setup exceeded its deadline",
        )
        .await;
        let mut channel = match opened {
            Ok(channel) => {
                uncertain.disarm();
                channel
            }
            Err(error)
                if !is_ssh_transport_terminal_error(&error)
                    && tokio::time::Instant::now() < deadline =>
            {
                uncertain.disarm();
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        match tokio::time::timeout_at(deadline, channel.request_subsystem(true, "sftp")).await {
            Ok(Ok(())) => Ok(channel),
            Ok(Err(error)) => {
                if !terminate_channel(&mut channel, &self.transport_trip(), false).await {
                    self.invalidate().await;
                }
                Err(error.into())
            }
            Err(_) => {
                if !terminate_channel(&mut channel, &self.transport_trip(), false).await {
                    self.invalidate().await;
                }
                bail!("SFTP subsystem setup exceeded its deadline");
            }
        }
    }
}

struct RemoteForwardLease {
    session: Arc<SshSession>,
    bind_host: String,
    effective_port: u16,
    registration: Option<RemoteForwardRegistration>,
    armed: bool,
}

impl RemoteForwardLease {
    async fn stop(mut self) -> Result<()> {
        // Reject new server-initiated channels before asking the server to
        // retire the listener. Existing accepted channels are cancelled by
        // the tunnel-wide cancellation token separately.
        drop(self.registration.take());
        if self.session.is_closed() {
            self.armed = false;
            return Ok(());
        }
        let result = self
            .session
            .cancel_remote_forward_until(
                &self.bind_host,
                self.effective_port,
                tokio::time::Instant::now() + TUNNEL_CHANNEL_OPEN_TIMEOUT,
            )
            .await;
        // cancel_remote_forward_until invalidates the transport on every
        // uncertain/error result, so the Drop fallback is no longer needed.
        self.armed = false;
        result
    }
}

impl Drop for RemoteForwardLease {
    fn drop(&mut self) {
        drop(self.registration.take());
        if self.armed {
            self.session.transport_trip().trip();
        }
    }
}

async fn bind_tunnel_listener_until(
    bind: SocketAddr,
    deadline: tokio::time::Instant,
) -> Result<tokio::net::TcpListener> {
    poll_remote_mutation_until(
        deadline,
        tokio::net::TcpListener::bind(bind),
        || {},
        || {},
        "local tunnel listener setup exceeded its deadline",
    )
    .await
    .context("bind local tunnel listener")
}

async fn bridge_streams<A, B>(
    mut left: A,
    mut right: B,
    cancellation: CancellationToken,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            let _ = tokio::time::timeout(TUNNEL_DRAIN_TIMEOUT, async {
                let _ = left.shutdown().await;
                let _ = right.shutdown().await;
            }).await;
            Ok(())
        }
        result = tokio::io::copy_bidirectional(&mut left, &mut right) => {
            result.context("bridge SSH tunnel stream")?;
            Ok(())
        }
    }
}

async fn serve_local_forward_connection(
    session: Arc<SshSession>,
    socket: tokio::net::TcpStream,
    peer: SocketAddr,
    target_port: u16,
    cancellation: CancellationToken,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + TUNNEL_CHANNEL_OPEN_TIMEOUT;
    let channel = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Ok(()),
        opened = session.open_direct_tcpip_until(
            TUNNEL_LOOPBACK_HOST,
            target_port,
            peer,
            deadline,
        ) => opened?,
    };
    bridge_streams(socket, channel.into_stream(), cancellation).await
}

fn log_tunnel_flow_result(result: Result<()>) {
    if let Err(error) = result {
        log::debug!("SSH tunnel connection ended: {error:#}");
    }
}

fn log_tunnel_join_result(result: std::result::Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        if !error.is_cancelled() {
            log::debug!("SSH tunnel connection task ended: {error}");
        }
    }
}

async fn drain_tunnel_flows(flows: &mut JoinSet<()>) {
    let drained = tokio::time::timeout(TUNNEL_DRAIN_TIMEOUT, async {
        while let Some(joined) = flows.join_next().await {
            log_tunnel_join_result(joined);
        }
    })
    .await;
    if drained.is_err() {
        flows.abort_all();
        while let Some(joined) = flows.join_next().await {
            log_tunnel_join_result(joined);
        }
    }
}

async fn run_local_forward(
    session: Arc<SshSession>,
    listener: tokio::net::TcpListener,
    target_port: u16,
    max_connections: usize,
    session_permits: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut flows = JoinSet::new();
    let mut session_poll = tokio::time::interval(TUNNEL_SESSION_POLL_INTERVAL);
    session_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break Ok(()),
            _ = session_poll.tick() => {
                if session.is_closed() {
                    break Err(anyhow::anyhow!("SSH session closed while local tunnel was active"));
                }
            }
            joined = flows.join_next(), if !flows.is_empty() => {
                if let Some(joined) = joined {
                    log_tunnel_join_result(joined);
                }
            }
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error).context("accept local tunnel connection"),
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    log::debug!("rejecting local tunnel connection: connection limit reached");
                    drop(socket);
                    continue;
                };
                let Ok(session_permit) = Arc::clone(&session_permits).try_acquire_owned() else {
                    log::debug!("rejecting local tunnel connection: SSH-session flow limit reached");
                    drop(socket);
                    continue;
                };
                let flow_session = Arc::clone(&session);
                let flow_cancel = cancellation.clone();
                flows.spawn(async move {
                    let _permit = permit;
                    let _session_permit = session_permit;
                    log_tunnel_flow_result(
                        serve_local_forward_connection(
                            flow_session,
                            socket,
                            peer,
                            target_port,
                            flow_cancel,
                        )
                        .await,
                    );
                });
            }
        }
    };
    cancellation.cancel();
    drop(listener);
    drain_tunnel_flows(&mut flows).await;
    result
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SocksTarget {
    host: String,
    port: u16,
}

async fn socks_read_exact_until<S>(
    stream: &mut S,
    bytes: &mut [u8],
    deadline: tokio::time::Instant,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    match tokio::time::timeout_at(deadline, stream.read_exact(bytes)).await {
        Ok(result) => {
            result.context("read SOCKS5 handshake")?;
            Ok(())
        }
        Err(_) => bail!("SOCKS5 handshake exceeded its deadline"),
    }
}

async fn socks_write_all_until<S>(
    stream: &mut S,
    bytes: &[u8],
    deadline: tokio::time::Instant,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    match tokio::time::timeout_at(deadline, stream.write_all(bytes)).await {
        Ok(result) => result.context("write SOCKS5 response"),
        Err(_) => bail!("SOCKS5 response write exceeded its deadline"),
    }
}

async fn write_socks5_reply<S>(
    stream: &mut S,
    reply: u8,
    deadline: tokio::time::Instant,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    // russh does not expose the remote socket selected by direct-tcpip, so the
    // RFC1928 BND fields are returned as an unspecified IPv4 address/port.
    socks_write_all_until(stream, &[5, reply, 0, 1, 0, 0, 0, 0, 0, 0], deadline).await
}

fn validate_socks_domain(bytes: &[u8]) -> Result<String> {
    ensure!(!bytes.is_empty(), "SOCKS5 domain is empty");
    ensure!(
        bytes.is_ascii(),
        "SOCKS5 domain must contain only ASCII bytes"
    );
    ensure!(
        bytes
            .iter()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') }),
        "SOCKS5 domain contains an unsupported byte"
    );
    let domain = std::str::from_utf8(bytes).context("decode SOCKS5 ASCII domain")?;
    validate_tunnel_host("SOCKS5 domain", domain)?;
    Ok(domain.to_owned())
}

/// Perform only the SOCKS5 negotiation and CONNECT request parsing. A `None`
/// result means the request was rejected with a complete protocol response.
async fn socks5_handshake<S>(
    stream: &mut S,
    deadline: tokio::time::Instant,
) -> Result<Option<SocksTarget>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0_u8; 2];
    socks_read_exact_until(stream, &mut greeting, deadline).await?;
    ensure!(greeting[0] == 5, "unsupported SOCKS version");
    ensure!(greeting[1] != 0, "SOCKS5 greeting contains no methods");
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    socks_read_exact_until(stream, &mut methods, deadline).await?;
    if !methods.contains(&0) {
        socks_write_all_until(stream, &[5, 0xff], deadline).await?;
        return Ok(None);
    }
    socks_write_all_until(stream, &[5, 0], deadline).await?;

    let mut request = [0_u8; 4];
    socks_read_exact_until(stream, &mut request, deadline).await?;
    if request[0] != 5 || request[2] != 0 {
        write_socks5_reply(stream, 1, deadline).await?;
        return Ok(None);
    }
    if request[1] != 1 {
        write_socks5_reply(stream, 7, deadline).await?;
        return Ok(None);
    }

    let host = match request[3] {
        1 => {
            let mut address = [0_u8; 4];
            socks_read_exact_until(stream, &mut address, deadline).await?;
            IpAddr::from(address).to_string()
        }
        4 => {
            let mut address = [0_u8; 16];
            socks_read_exact_until(stream, &mut address, deadline).await?;
            IpAddr::from(address).to_string()
        }
        3 => {
            let mut length = [0_u8; 1];
            socks_read_exact_until(stream, &mut length, deadline).await?;
            if length[0] == 0 {
                write_socks5_reply(stream, 8, deadline).await?;
                return Ok(None);
            }
            let mut domain = vec![0_u8; usize::from(length[0])];
            socks_read_exact_until(stream, &mut domain, deadline).await?;
            match validate_socks_domain(&domain) {
                Ok(domain) => domain,
                Err(_) => {
                    write_socks5_reply(stream, 8, deadline).await?;
                    return Ok(None);
                }
            }
        }
        _ => {
            write_socks5_reply(stream, 8, deadline).await?;
            return Ok(None);
        }
    };
    let mut port = [0_u8; 2];
    socks_read_exact_until(stream, &mut port, deadline).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        write_socks5_reply(stream, 1, deadline).await?;
        return Ok(None);
    }
    Ok(Some(SocksTarget { host, port }))
}

fn socks5_reply_for_ssh_error(error: &anyhow::Error) -> u8 {
    match error.downcast_ref::<russh::Error>() {
        Some(russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)) => 2,
        Some(russh::Error::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed)) => 5,
        Some(russh::Error::ChannelOpenFailure(ChannelOpenFailure::ResourceShortage)) => 1,
        _ if error.to_string().contains("deadline") => 6,
        _ => 1,
    }
}

async fn serve_dynamic_forward_connection(
    session: Arc<SshSession>,
    mut socket: tokio::net::TcpStream,
    peer: SocketAddr,
    cancellation: CancellationToken,
) -> Result<()> {
    let handshake_deadline = tokio::time::Instant::now() + SOCKS5_HANDSHAKE_TIMEOUT;
    let target = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Ok(()),
        result = socks5_handshake(&mut socket, handshake_deadline) => match result? {
            Some(target) => target,
            None => return Ok(()),
        },
    };
    let channel_deadline = tokio::time::Instant::now() + TUNNEL_CHANNEL_OPEN_TIMEOUT;
    let opened = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Ok(()),
        result = session.open_direct_tcpip_until(
            &target.host,
            target.port,
            peer,
            channel_deadline,
        ) => result,
    };
    let channel = match opened {
        Ok(channel) => channel,
        Err(error) => {
            let reply = socks5_reply_for_ssh_error(&error);
            let _ = write_socks5_reply(
                &mut socket,
                reply,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await;
            return Err(error);
        }
    };
    write_socks5_reply(
        &mut socket,
        0,
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await?;
    bridge_streams(socket, channel.into_stream(), cancellation).await
}

async fn run_dynamic_forward(
    session: Arc<SshSession>,
    listener: tokio::net::TcpListener,
    max_connections: usize,
    session_permits: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut flows = JoinSet::new();
    let mut session_poll = tokio::time::interval(TUNNEL_SESSION_POLL_INTERVAL);
    session_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break Ok(()),
            _ = session_poll.tick() => {
                if session.is_closed() {
                    break Err(anyhow::anyhow!("SSH session closed while SOCKS5 tunnel was active"));
                }
            }
            joined = flows.join_next(), if !flows.is_empty() => {
                if let Some(joined) = joined {
                    log_tunnel_join_result(joined);
                }
            }
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error).context("accept SOCKS5 tunnel connection"),
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    log::debug!("rejecting SOCKS5 connection: connection limit reached");
                    drop(socket);
                    continue;
                };
                let Ok(session_permit) = Arc::clone(&session_permits).try_acquire_owned() else {
                    log::debug!("rejecting SOCKS5 connection: SSH-session flow limit reached");
                    drop(socket);
                    continue;
                };
                let flow_session = Arc::clone(&session);
                let flow_cancel = cancellation.clone();
                flows.spawn(async move {
                    let _permit = permit;
                    let _session_permit = session_permit;
                    log_tunnel_flow_result(
                        serve_dynamic_forward_connection(
                            flow_session,
                            socket,
                            peer,
                            flow_cancel,
                        )
                        .await,
                    );
                });
            }
        }
    };
    cancellation.cancel();
    drop(listener);
    drain_tunnel_flows(&mut flows).await;
    result
}

async fn reject_remote_forward_reply(
    session: &SshSession,
    reply: client::ChannelOpenHandle,
    reason: ChannelOpenFailure,
) {
    let mut uncertain = TripTransportOnDrop::new(session.transport_trip());
    if tokio::time::timeout(TUNNEL_REMOTE_TARGET_TIMEOUT, reply.reject(reason))
        .await
        .is_ok()
    {
        uncertain.disarm();
    }
}

async fn serve_remote_forward_connection(
    session: Arc<SshSession>,
    incoming: IncomingRemoteForward,
    target_port: u16,
    cancellation: CancellationToken,
) -> Result<()> {
    let IncomingRemoteForward { channel, reply } = incoming;
    let connect_deadline = tokio::time::Instant::now() + TUNNEL_REMOTE_TARGET_TIMEOUT;
    let socket = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            reject_remote_forward_reply(
                &session,
                reply,
                ChannelOpenFailure::AdministrativelyProhibited,
            ).await;
            return Ok(());
        }
        connected = poll_remote_mutation_until(
            connect_deadline,
            tokio::net::TcpStream::connect((TUNNEL_LOOPBACK_HOST, target_port)),
            || {},
            || {},
            "remote-forward local target connection exceeded its deadline",
        ) => match connected {
            Ok(socket) => socket,
            Err(error) => {
                reject_remote_forward_reply(&session, reply, ChannelOpenFailure::ConnectFailed).await;
                return Err(error).context("connect remote-forward local target");
            }
        },
    };

    let mut uncertain = TripTransportOnDrop::new(session.transport_trip());
    let accepted = poll_remote_mutation_until(
        connect_deadline,
        async {
            reply.accept().await;
            Ok::<(), anyhow::Error>(())
        },
        || {},
        || {},
        "remote-forward channel acceptance exceeded its deadline",
    )
    .await;
    match accepted {
        Ok(()) => uncertain.disarm(),
        Err(error) => {
            session.invalidate().await;
            uncertain.disarm();
            return Err(error);
        }
    }
    bridge_streams(socket, channel.into_stream(), cancellation).await
}

async fn run_remote_forward(
    lease: RemoteForwardLease,
    mut incoming: mpsc::Receiver<IncomingRemoteForward>,
    target_port: u16,
    max_connections: usize,
    session_permits: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> Result<()> {
    let session = Arc::clone(&lease.session);
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut flows = JoinSet::new();
    let mut session_poll = tokio::time::interval(TUNNEL_SESSION_POLL_INTERVAL);
    session_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break Ok(()),
            _ = session_poll.tick() => {
                if session.is_closed() {
                    break Err(anyhow::anyhow!("SSH session closed while remote tunnel was active"));
                }
            }
            joined = flows.join_next(), if !flows.is_empty() => {
                if let Some(joined) = joined {
                    log_tunnel_join_result(joined);
                }
            }
            received = incoming.recv() => {
                let Some(incoming) = received else {
                    break Err(anyhow::anyhow!("remote-forward route closed unexpectedly"));
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    incoming.reject(ChannelOpenFailure::ResourceShortage).await;
                    continue;
                };
                let Ok(session_permit) = Arc::clone(&session_permits).try_acquire_owned() else {
                    incoming.reject(ChannelOpenFailure::ResourceShortage).await;
                    continue;
                };
                let flow_session = Arc::clone(&session);
                let flow_cancel = cancellation.clone();
                flows.spawn(async move {
                    let _permit = permit;
                    let _session_permit = session_permit;
                    log_tunnel_flow_result(
                        serve_remote_forward_connection(
                            flow_session,
                            incoming,
                            target_port,
                            flow_cancel,
                        )
                        .await,
                    );
                });
            }
        }
    };

    // Closing the receiver rejects every queued ChannelOpenHandle by Drop.
    incoming.close();
    cancellation.cancel();
    let cleanup = lease.stop().await;
    drain_tunnel_flows(&mut flows).await;
    result?;
    cleanup
}

struct DirectoryBudget {
    limits: DirectoryLimits,
    encoded_bytes: usize,
    string_bytes: usize,
}

impl DirectoryBudget {
    fn new(limits: DirectoryLimits) -> Self {
        Self {
            limits,
            encoded_bytes: 0,
            string_bytes: 0,
        }
    }

    fn reserve_packet(&mut self, body_bytes: usize) -> Result<()> {
        ensure!(
            body_bytes <= self.limits.packet_bytes,
            "SFTP directory response packet exceeds the {} KiB safety limit",
            self.limits.packet_bytes / 1024
        );
        let framed_bytes = body_bytes
            .checked_add(std::mem::size_of::<u32>())
            .ok_or_else(|| anyhow::anyhow!("SFTP directory response byte count overflow"))?;
        let total = self
            .encoded_bytes
            .checked_add(framed_bytes)
            .ok_or_else(|| anyhow::anyhow!("SFTP directory response byte count overflow"))?;
        ensure!(
            total <= self.limits.encoded_bytes,
            "SFTP directory responses exceed the {} MiB encoded-byte safety limit",
            self.limits.encoded_bytes / (1024 * 1024)
        );
        self.encoded_bytes = total;
        Ok(())
    }

    fn reserve_strings(&mut self, bytes: usize) -> Result<()> {
        let total = self
            .string_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("SFTP directory name byte count overflow"))?;
        ensure!(
            total <= self.limits.string_bytes,
            "SFTP directory names and paths exceed the {} MiB retained-string safety limit",
            self.limits.string_bytes / (1024 * 1024)
        );
        self.string_bytes = total;
        Ok(())
    }
}

async fn list_dir_streaming<S>(
    stream: &mut S,
    path: &str,
    limits: DirectoryLimits,
) -> Result<(String, Vec<RemoteEntry>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut budget = DirectoryBudget::new(limits);

    write_sftp_packet(stream, Packet::Init(Init::default())).await?;
    match read_sftp_packet(stream, &mut budget).await? {
        Packet::Version(version) if version.version == VERSION => {}
        Packet::Version(version) => bail!(
            "SFTP server selected unsupported protocol version {}",
            version.version
        ),
        packet => bail!(
            "SFTP initialization returned unexpected {} packet",
            packet_kind(&packet)
        ),
    }

    let mut request_id = 1_u32;
    write_sftp_packet(
        stream,
        Packet::RealPath(RealPath {
            id: request_id,
            path: path.to_owned(),
        }),
    )
    .await?;
    let canonical = expect_name(
        read_sftp_packet(stream, &mut budget).await?,
        request_id,
        "canonicalize directory",
    )?
    .files
    .into_iter()
    .next()
    .context("SFTP canonicalize-directory response did not contain a path")?
    .filename;
    budget.reserve_strings(canonical.len())?;

    request_id = request_id
        .checked_add(1)
        .context("SFTP directory request id overflow")?;
    write_sftp_packet(
        stream,
        Packet::OpenDir(OpenDir {
            id: request_id,
            path: canonical.clone(),
        }),
    )
    .await?;
    let handle = expect_handle(
        read_sftp_packet(stream, &mut budget).await?,
        request_id,
        "open directory",
    )?
    .handle;

    let mut entries = Vec::new();
    loop {
        request_id = request_id
            .checked_add(1)
            .context("SFTP directory request id overflow")?;
        write_sftp_packet(
            stream,
            Packet::ReadDir(ReadDir {
                id: request_id,
                handle: handle.clone(),
            }),
        )
        .await?;

        match read_sftp_packet(stream, &mut budget).await? {
            Packet::Name(name) => {
                ensure_response_id(name.id, request_id, "read directory")?;
                for file in name.files {
                    push_directory_entry(&mut entries, &canonical, file, &mut budget)?;
                }
            }
            Packet::Status(status) if status.id == request_id => {
                if status.status_code == StatusCode::Eof {
                    break;
                }
                return Err(status_error("read directory", status));
            }
            Packet::Status(status) => {
                ensure_response_id(status.id, request_id, "read directory")?;
                unreachable!();
            }
            packet => bail!(
                "SFTP read-directory request returned unexpected {} packet",
                packet_kind(&packet)
            ),
        }
    }

    request_id = request_id
        .checked_add(1)
        .context("SFTP directory request id overflow")?;
    write_sftp_packet(
        stream,
        Packet::Close(Close {
            id: request_id,
            handle,
        }),
    )
    .await?;
    expect_ok_status(
        read_sftp_packet(stream, &mut budget).await?,
        request_id,
        "close directory",
    )?;

    // Cache the case-folded key once. Recomputing it inside every comparison
    // can otherwise amplify CPU and transient allocations for adversarially
    // long names. Retained input strings are already bounded above.
    entries.sort_by_cached_key(|entry| (!entry.is_dir, entry.name.to_lowercase()));
    // Apply the exact IPC JSON wire budget even on the direct route. JSON can
    // expand control characters sixfold, so a retained-string budget alone
    // cannot guarantee that daemon serialization will fit its response cap.
    let mut frame = serctl_protocol::Frame::DirList {
        path: canonical,
        entries,
        operation_context_id: None,
        revision: 0,
    };
    if let Err(error) =
        serctl_protocol::encoded_frame_len_limited(&frame, serctl_protocol::MAX_RESPONSE_FRAME)
    {
        frame.zeroize_sensitive();
        return Err(error).context("SFTP directory listing exceeds the IPC wire-size limit");
    }
    match frame {
        serctl_protocol::Frame::DirList { path, entries, .. } => Ok((path, entries)),
        _ => unreachable!(),
    }
}

async fn write_sftp_packet<W>(writer: &mut W, packet: Packet) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = Bytes::try_from(packet).context("encode SFTP directory request")?;
    writer
        .write_all(&encoded)
        .await
        .context("write SFTP directory request")?;
    writer
        .flush()
        .await
        .context("flush SFTP directory request")?;
    Ok(())
}

async fn read_sftp_packet<R>(reader: &mut R, budget: &mut DirectoryBudget) -> Result<Packet>
where
    R: AsyncRead + Unpin,
{
    let body_bytes = reader
        .read_u32()
        .await
        .context("read SFTP directory response length")? as usize;
    // Reserve before allocation. An oversized length prefix therefore closes
    // the SSH channel without allocating a server-controlled Vec.
    budget.reserve_packet(body_bytes)?;
    let mut body = vec![0_u8; body_bytes];
    reader
        .read_exact(&mut body)
        .await
        .context("read SFTP directory response body")?;
    let mut body = Bytes::from(body);
    let packet = Packet::try_from(&mut body).context("decode SFTP directory response")?;
    ensure!(
        body.is_empty(),
        "SFTP directory response contains trailing bytes"
    );
    Ok(packet)
}

async fn read_sftp_packet_bounded<R>(reader: &mut R) -> Result<Packet>
where
    R: AsyncRead + Unpin,
{
    let body_bytes = reader
        .read_u32()
        .await
        .context("read SFTP response length")? as usize;
    ensure!(
        body_bytes <= MAX_SFTP_PACKET_BYTES,
        "SFTP response packet exceeds the {} MiB safety limit",
        MAX_SFTP_PACKET_BYTES / (1024 * 1024)
    );
    let mut body = Zeroizing::new(vec![0_u8; body_bytes]);
    reader
        .read_exact(&mut body)
        .await
        .context("read SFTP response body")?;
    let mut encoded = Bytes::copy_from_slice(&body);
    let packet = Packet::try_from(&mut encoded).context("decode SFTP response")?;
    ensure!(encoded.is_empty(), "SFTP response contains trailing bytes");
    Ok(packet)
}

fn explicit_sftp_status(mut status: Status) -> anyhow::Error {
    status.error_message = status
        .error_message
        .chars()
        .flat_map(char::escape_default)
        .collect();
    russh_sftp::client::error::Error::Status(status).into()
}

fn expect_upload_handle(packet: Packet, request_id: u32, operation: &str) -> Result<Handle> {
    match packet {
        Packet::Handle(handle) => {
            ensure_response_id(handle.id, request_id, operation)?;
            Ok(handle)
        }
        Packet::Status(status) => {
            ensure_response_id(status.id, request_id, operation)?;
            Err(explicit_sftp_status(status))
        }
        packet => bail!(
            "SFTP {operation} request returned unexpected {} packet",
            packet_kind(&packet)
        ),
    }
}

fn expect_upload_ok_status(packet: Packet, request_id: u32, operation: &str) -> Result<()> {
    match packet {
        Packet::Status(status) => {
            ensure_response_id(status.id, request_id, operation)?;
            if status.status_code == StatusCode::Ok {
                Ok(())
            } else {
                Err(explicit_sftp_status(status))
            }
        }
        packet => bail!(
            "SFTP {operation} request returned unexpected {} packet",
            packet_kind(&packet)
        ),
    }
}

fn expect_name(packet: Packet, request_id: u32, operation: &str) -> Result<Name> {
    match packet {
        Packet::Name(name) => {
            ensure_response_id(name.id, request_id, operation)?;
            Ok(name)
        }
        Packet::Status(status) => {
            ensure_response_id(status.id, request_id, operation)?;
            Err(status_error(operation, status))
        }
        packet => bail!(
            "SFTP {operation} request returned unexpected {} packet",
            packet_kind(&packet)
        ),
    }
}

fn expect_handle(packet: Packet, request_id: u32, operation: &str) -> Result<Handle> {
    match packet {
        Packet::Handle(handle) => {
            ensure_response_id(handle.id, request_id, operation)?;
            Ok(handle)
        }
        Packet::Status(status) => {
            ensure_response_id(status.id, request_id, operation)?;
            Err(status_error(operation, status))
        }
        packet => bail!(
            "SFTP {operation} request returned unexpected {} packet",
            packet_kind(&packet)
        ),
    }
}

fn expect_ok_status(packet: Packet, request_id: u32, operation: &str) -> Result<()> {
    match packet {
        Packet::Status(status) => {
            ensure_response_id(status.id, request_id, operation)?;
            if status.status_code == StatusCode::Ok {
                Ok(())
            } else {
                Err(status_error(operation, status))
            }
        }
        packet => bail!(
            "SFTP {operation} request returned unexpected {} packet",
            packet_kind(&packet)
        ),
    }
}

fn ensure_response_id(actual: u32, expected: u32, operation: &str) -> Result<()> {
    ensure!(
        actual == expected,
        "SFTP {operation} response id mismatch: expected {expected}, received {actual}"
    );
    Ok(())
}

fn status_error(operation: &str, status: Status) -> anyhow::Error {
    let mut message = String::with_capacity(status.error_message.len());
    for character in status.error_message.chars() {
        if character.is_control() {
            message.extend(character.escape_default());
        } else {
            message.push(character);
        }
    }
    anyhow::anyhow!(
        "SFTP {operation} failed: {}: {}",
        status.status_code,
        message
    )
}

fn packet_kind(packet: &Packet) -> &'static str {
    match packet {
        Packet::Init(_) => "INIT",
        Packet::Version(_) => "VERSION",
        Packet::Open(_) => "OPEN",
        Packet::Close(_) => "CLOSE",
        Packet::Read(_) => "READ",
        Packet::Write(_) => "WRITE",
        Packet::Lstat(_) => "LSTAT",
        Packet::Fstat(_) => "FSTAT",
        Packet::SetStat(_) => "SETSTAT",
        Packet::FSetStat(_) => "FSETSTAT",
        Packet::OpenDir(_) => "OPENDIR",
        Packet::ReadDir(_) => "READDIR",
        Packet::Remove(_) => "REMOVE",
        Packet::MkDir(_) => "MKDIR",
        Packet::RmDir(_) => "RMDIR",
        Packet::RealPath(_) => "REALPATH",
        Packet::Stat(_) => "STAT",
        Packet::Rename(_) => "RENAME",
        Packet::ReadLink(_) => "READLINK",
        Packet::Symlink(_) => "SYMLINK",
        Packet::Status(_) => "STATUS",
        Packet::Handle(_) => "HANDLE",
        Packet::Data(_) => "DATA",
        Packet::Name(_) => "NAME",
        Packet::Attrs(_) => "ATTRS",
        Packet::Extended(_) => "EXTENDED",
        Packet::ExtendedReply(_) => "EXTENDED_REPLY",
    }
}

fn push_directory_entry(
    entries: &mut Vec<RemoteEntry>,
    canonical: &str,
    file: File,
    budget: &mut DirectoryBudget,
) -> Result<()> {
    if file.filename == "." || file.filename == ".." {
        return Ok(());
    }
    ensure!(
        !file.filename.is_empty(),
        "SFTP directory entry name is empty"
    );
    ensure!(
        !file.filename.contains(['/', '\\', '\0']),
        "SFTP directory entry name is not a single path component"
    );
    ensure!(
        entries.len() < budget.limits.entries,
        "SFTP directory contains more than {} entries",
        budget.limits.entries
    );

    let separator_bytes = usize::from(!canonical.is_empty() && !canonical.ends_with('/'));
    let path_bytes = canonical
        .len()
        .checked_add(separator_bytes)
        .and_then(|bytes| bytes.checked_add(file.filename.len()))
        .ok_or_else(|| anyhow::anyhow!("SFTP directory path byte count overflow"))?;
    let retained_bytes = file
        .filename
        .len()
        .checked_add(path_bytes)
        .ok_or_else(|| anyhow::anyhow!("SFTP directory name byte count overflow"))?;
    budget.reserve_strings(retained_bytes)?;

    let path = if canonical.is_empty() {
        file.filename.clone()
    } else if canonical.ends_with('/') {
        format!("{canonical}{}", file.filename)
    } else {
        format!("{canonical}/{}", file.filename)
    };
    entries.push(RemoteEntry {
        name: file.filename,
        path,
        is_dir: file.attrs.is_dir(),
        is_symlink: file.attrs.is_symlink(),
        size: file.attrs.len(),
        modified_unix: file.attrs.mtime,
    });
    Ok(())
}

async fn channel_step<F>(future: F) -> bool
where
    F: std::future::Future<Output = std::result::Result<(), russh::Error>>,
{
    matches!(
        tokio::time::timeout(CHANNEL_OPERATION_TIMEOUT, future).await,
        Ok(Ok(()))
    )
}

async fn wait_channel_closed(channel: &mut russh::Channel<russh::client::Msg>) -> bool {
    matches!(
        tokio::time::timeout(CHANNEL_OPERATION_TIMEOUT, async {
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
            }
        })
        .await,
        Ok(())
    )
}

async fn terminate_channel(
    channel: &mut russh::Channel<russh::client::Msg>,
    transport: &TransportTrip,
    signal_process: bool,
) -> bool {
    let mut clean = true;
    if signal_process {
        clean &= channel_step(channel.signal(russh::Sig::TERM)).await;
        tokio::time::sleep(CHANNEL_SIGNAL_GRACE).await;
        clean &= channel_step(channel.signal(russh::Sig::KILL)).await;
    }
    // EOF and Close each have their own budget and are attempted even if
    // signalling could not be queued. A plain russh Channel has no reliable
    // close-on-Drop semantics, so also wait briefly for the peer's terminal
    // channel notification before considering cleanup acknowledged.
    clean &= channel_step(channel.eof()).await;
    clean &= channel_step(channel.close()).await;
    clean &= wait_channel_closed(channel).await;
    if !clean {
        transport.trip();
    }
    clean
}

impl RunningCommand {
    /// Convert a successfully submitted fixed command into its bidirectional
    /// stdio stream. Dropping the stream closes the SSH channel.
    pub fn into_stream(self) -> russh::ChannelStream<russh::client::Msg> {
        self.channel.into_stream()
    }

    pub async fn request_exec_until(
        &mut self,
        cmd: &str,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        await_exec_request_queued_until(
            &mut self.submission,
            deadline,
            self.channel.exec(true, cmd.to_string()),
        )
        .await
    }

    pub async fn finish(&mut self) -> Result<ExecResult> {
        let submission = self.submission;
        self.finish_after_submission()
            .await
            .map_err(|error| submission.classify(error))
    }

    async fn finish_after_submission(&mut self) -> Result<ExecResult> {
        let mut out = Zeroizing::new(Vec::new());
        let mut err = Zeroizing::new(Vec::new());
        let mut code: Option<i32> = None;
        while let Some(msg) = self.channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => extend_command_output(&mut out, data, err.len())?,
                ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    extend_command_output(&mut err, data, out.len())?
                }
                ChannelMsg::ExtendedData { ref data, ext } => {
                    ensure_command_output_fits(data.len(), out.len(), err.len())?;
                    bail!("remote command returned unsupported extended-data stream {ext}");
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    ensure!(code.is_none(), "remote command sent duplicate exit status");
                    code = Some(
                        i32::try_from(exit_status)
                            .context("remote command exit status exceeds i32 range")?,
                    );
                }
                ChannelMsg::Eof | ChannelMsg::Close => {}
                _ => {}
            }
        }
        let code =
            code.ok_or_else(|| anyhow::anyhow!("remote command closed without exit status"))?;
        Ok(ExecResult {
            stdout: std::mem::take(&mut *out),
            stderr: std::mem::take(&mut *err),
            code: Some(code),
        })
    }

    pub async fn cancel(&mut self) -> bool {
        terminate_channel(&mut self.channel, &self.transport, true).await
    }
}

fn ensure_command_output_fits(incoming: usize, stdout: usize, stderr: usize) -> Result<()> {
    let total = stdout
        .checked_add(stderr)
        .and_then(|size| size.checked_add(incoming))
        .ok_or_else(|| anyhow::anyhow!("remote command output size overflow"))?;
    ensure!(
        total <= MAX_COMMAND_OUTPUT,
        "remote command output exceeds the 8 MiB safety limit"
    );
    Ok(())
}

fn extend_command_output(target: &mut Vec<u8>, data: &[u8], other_len: usize) -> Result<()> {
    ensure_command_output_fits(data.len(), target.len(), other_len)?;
    target.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        attach_ssh_attempt_record, await_exec_request_queued_until, bridge_streams,
        commit_remote_upload_no_replace_with, connect_key_exchange_with_one_reconnect_until,
        extend_command_output, has_minimum_retry_window, has_minimum_retry_window_after_backoff,
        is_explicit_sftp_status, is_ssh_transport_terminal_error, literal_socket_addr,
        new_transport_attempt_id, poll_remote_mutation_until, protected_upload_file_attributes,
        push_directory_entry, read_sftp_packet, read_sftp_packet_bounded,
        remote_forward_channel_is_loopback_only, require_server_fingerprint,
        sanitize_server_identification, secure_client_algorithms, socks5_handshake,
        ssh_connect_budget, status_error, temporary_remote_path, validate_remote_command,
        validate_remote_path, validate_shell_dimensions, validate_upload_remote_path,
        write_sftp_packet, BoundedSftpStream, CreateDirOutcomeUnknown, CreateDirSubmissionState,
        DirectoryBudget, DirectoryLimits, ExecOutcomeUnknown, ExecSubmissionState,
        IdentificationTracker, RemoteForwardRegistry, SocksTarget, SshAttemptRecord,
        SshConnectionIdentitySnapshot, SshFailureCategory, SshSession, TransportTrip, TunnelMode,
        TunnelSpec, ValidatedTunnelSpec, DEFAULT_TUNNEL_CONNECTIONS, DIRECTORY_LIMITS,
        MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_STRING_BYTES, MAX_REMOTE_COMMAND_BYTES,
        MAX_REMOTE_PATH_BYTES, MAX_SFTP_PACKET_BYTES, MAX_SHELL_DIMENSION, MAX_TUNNEL_CONNECTIONS,
        MIN_FIRST_KEX_WINDOW, MIN_PASSWORD_AUTH_WINDOW, MIN_RETRY_KEX_WINDOW,
        PRE_AUTH_RETRY_BACKOFF, REMOTE_PARTIAL_SUFFIX_BYTES, RETRY_SCHEDULING_MARGIN,
        TRANSPORT_CLEANUP_TIMEOUT,
    };
    use crate::vault::Creds;
    use rand::{rngs::OsRng, RngCore as Rand08RngCore};
    use russh::keys::{ssh_key, Algorithm, PrivateKey};
    use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
    use russh::{Channel, ChannelId};
    use russh_sftp::client::{Config as SftpConfig, SftpSession};
    use russh_sftp::protocol::{File, FileAttributes, Packet, Status, StatusCode, Write};
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex as TokioMutex;
    use tokio_util::sync::CancellationToken;

    struct CompatibleOsRng(OsRng);

    impl ssh_key::rand_core::TryRng for CompatibleOsRng {
        type Error = ssh_key::rand_core::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.0.next_u32())
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.0.next_u64())
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0.fill_bytes(dst);
            Ok(())
        }
    }

    impl ssh_key::rand_core::TryCryptoRng for CompatibleOsRng {}

    fn raw_ssh_disconnect_packet(reason_code: u32, description: &[u8]) -> Vec<u8> {
        // RFC 4253 section 11.1: SSH_MSG_DISCONNECT is legal before key
        // exchange completes. Build the initial cleartext packet directly so
        // this regression exercises russh's wire parser and our Handler
        // callback instead of fabricating an SshAttemptRecord.
        let mut payload = vec![1_u8]; // SSH_MSG_DISCONNECT
        payload.extend_from_slice(&reason_code.to_be_bytes());
        payload.extend_from_slice(&(description.len() as u32).to_be_bytes());
        payload.extend_from_slice(description);
        payload.extend_from_slice(&0_u32.to_be_bytes()); // empty language tag

        let block_size = 8;
        let mut padding_len = block_size - ((5 + payload.len()) % block_size);
        if padding_len < 4 {
            padding_len += block_size;
        }
        let packet_len = 1 + payload.len() + padding_len;
        let mut packet = Vec::with_capacity(4 + packet_len);
        packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend_from_slice(&payload);
        packet.resize(4 + packet_len, 0);
        packet
    }

    #[derive(Clone)]
    struct MatrixSshServer {
        channels: Arc<TokioMutex<HashMap<ChannelId, Channel<Msg>>>>,
        observed: tokio::sync::mpsc::UnboundedSender<(u8, Vec<u8>)>,
        authentications: Arc<AtomicUsize>,
        executions: Arc<AtomicUsize>,
    }

    impl russh::server::Handler for MatrixSshServer {
        type Error = anyhow::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            self.authentications.fetch_add(1, Ordering::AcqRel);
            Ok(if user == "matrix" && password == "matrix-password" {
                Auth::Accept
            } else {
                Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            })
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            reply: ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.channels.lock().await.insert(channel.id(), channel);
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            command: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.executions.fetch_add(1, Ordering::AcqRel);
            if command != b"serctl-xfer serve --stdio" {
                session.channel_failure(channel)?;
                return Ok(());
            }
            let channel = self
                .channels
                .lock()
                .await
                .remove(&channel)
                .ok_or_else(|| anyhow::anyhow!("matrix exec channel was not registered"))?;
            session.channel_success(channel.id())?;
            let observed = self.observed.clone();
            tokio::spawn(async move {
                let mut stream = channel.into_stream();
                let result = async {
                    // This small server-first marker models the native Hello
                    // exchange before the first larger client frame.
                    stream.write_all(b"ready").await?;
                    stream.flush().await?;
                    let mut header = [0_u8; 12];
                    stream.read_exact(&mut header).await?;
                    anyhow::ensure!(&header[..4] == b"SCTX", "matrix frame magic mismatch");
                    anyhow::ensure!(
                        u16::from_be_bytes([header[4], header[5]]) == 1,
                        "matrix frame version mismatch"
                    );
                    let body_len =
                        u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
                    anyhow::ensure!(body_len <= 32 * 1024 + 56, "matrix frame is oversized");
                    let mut body = vec![0_u8; body_len];
                    stream.read_exact(&mut body).await?;
                    observed
                        .send((b'e', body))
                        .map_err(|_| anyhow::anyhow!("matrix observer closed"))?;
                    stream.write_u32(body_len as u32).await?;
                    stream.flush().await?;
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(error) = result {
                    eprintln!("matrix SSH server failed: {error:#}");
                }
            });
            Ok(())
        }

        async fn subsystem_request(
            &mut self,
            channel: ChannelId,
            name: &str,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if name != "sftp" {
                session.channel_failure(channel)?;
                return Ok(());
            }
            let channel = self
                .channels
                .lock()
                .await
                .remove(&channel)
                .ok_or_else(|| anyhow::anyhow!("matrix SFTP channel was not registered"))?;
            session.channel_success(channel.id())?;
            let observed = self.observed.clone();
            tokio::spawn(async move {
                let mut stream = channel.into_stream();
                let result = async {
                    stream.write_all(b"ready").await?;
                    stream.flush().await?;
                    let packet = read_sftp_packet_bounded(&mut stream).await?;
                    let Packet::Write(write) = packet else {
                        anyhow::bail!("matrix expected an SFTP WRITE packet")
                    };
                    let body_len = write.data.len();
                    observed
                        .send((b's', write.data))
                        .map_err(|_| anyhow::anyhow!("matrix observer closed"))?;
                    stream.write_u32(body_len as u32).await?;
                    stream.flush().await?;
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(error) = result {
                    eprintln!("matrix SFTP server failed: {error:#}");
                }
            });
            Ok(())
        }
    }

    #[tokio::test]
    async fn full_russh_exec_and_sftp_channels_carry_first_frames_above_two_kib() {
        let mut rng = CompatibleOsRng(OsRng);
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let fingerprint = key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        let config = Arc::new(russh::server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::unbounded_channel();
        let authentications = Arc::new(AtomicUsize::new(0));
        let executions = Arc::new(AtomicUsize::new(0));
        let server_authentications = Arc::clone(&authentications);
        let server_executions = Arc::clone(&executions);
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let handler = MatrixSshServer {
                    channels: Arc::new(TokioMutex::new(HashMap::new())),
                    observed: observed_tx.clone(),
                    authentications: Arc::clone(&server_authentications),
                    executions: Arc::clone(&server_executions),
                };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(error) = russh::server::run_stream(config, socket, handler).await {
                        eprintln!("matrix SSH transport failed: {error:#}");
                    }
                });
            }
        });
        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "matrix".into(),
            password: "matrix-password".into(),
            host_key: Some(fingerprint.clone()),
        };
        let connect_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let (session, observed_fingerprint) =
            SshSession::connect_until(&creds, Some(fingerprint.clone()), connect_deadline)
                .await
                .unwrap();
        assert_eq!(observed_fingerprint, fingerprint);
        let connection_identity = session.connection_identity();
        assert_eq!(
            connection_identity.observed_host_key_sha256(),
            observed_fingerprint
        );
        assert!(connection_identity.pin_match());
        assert!(connection_identity
            .server_identification()
            .starts_with("SSH-2.0-russh"));
        assert_eq!(connection_identity.transport_attempt_id().len(), 32);

        for payload_len in [4, 8, 16, 32].map(|kib| kib * 1024) {
            let payload = (0..payload_len)
                .map(|index| ((index * 17 + payload_len) % 251) as u8)
                .collect::<Vec<_>>();
            let transfer_id = [0x31_u8; 16];
            let offset = 0x0102_0304_0506_0708_u64.to_be_bytes();
            let chunk_hash = [0xa5_u8; 32];
            let mut expected = Vec::with_capacity(56 + payload_len);
            expected.extend_from_slice(&transfer_id);
            expected.extend_from_slice(&offset);
            expected.extend_from_slice(&chunk_hash);
            expected.extend_from_slice(&payload);
            let exchange = async {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                let mut stream = session.native_transfer_stream_until(deadline).await?;
                let mut ready = [0_u8; 5];
                stream.read_exact(&mut ready).await?;
                anyhow::ensure!(&ready == b"ready", "matrix helper marker mismatch");
                // Match native::write_data's separate header/metadata/payload
                // writes. At 32 KiB the complete frame necessarily crosses
                // russh's default 32 KiB channel-packet boundary.
                stream.write_all(b"SCTX").await?;
                stream.write_u16(1).await?;
                stream.write_u8(2).await?;
                stream.write_u8(0).await?;
                stream.write_u32(expected.len() as u32).await?;
                stream.write_all(&transfer_id).await?;
                stream.write_all(&offset).await?;
                stream.write_all(&chunk_hash).await?;
                stream.write_all(&payload).await?;
                stream.flush().await?;
                let acknowledged = stream.read_u32().await? as usize;
                anyhow::ensure!(acknowledged == expected.len(), "matrix ACK length mismatch");
                let (route, observed) = observed_rx
                    .recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("matrix observer closed"))?;
                anyhow::ensure!(route == b'e', "matrix observation route mismatch");
                anyhow::ensure!(observed == expected, "matrix frame body mismatch");
                Ok::<_, anyhow::Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), exchange)
                .await
                .unwrap_or_else(|_| panic!("{payload_len}-byte first frame stalled"))
                .unwrap();
        }

        for payload_len in [4, 8, 16, 32].map(|kib| kib * 1024) {
            let expected = (0..payload_len)
                .map(|index| ((index * 29 + payload_len) % 251) as u8)
                .collect::<Vec<_>>();
            let exchange = async {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                let channel = session.open_sftp_channel_until(deadline).await?;
                let mut stream = channel.into_stream();
                let mut ready = [0_u8; 5];
                stream.read_exact(&mut ready).await?;
                anyhow::ensure!(&ready == b"ready", "matrix SFTP marker mismatch");
                write_sftp_packet(
                    &mut stream,
                    Packet::Write(Write {
                        id: 7,
                        handle: "matrix-handle".into(),
                        offset: 0,
                        data: expected.clone(),
                    }),
                )
                .await?;
                let acknowledged = stream.read_u32().await? as usize;
                anyhow::ensure!(acknowledged == payload_len, "matrix SFTP ACK mismatch");
                let (route, observed) = observed_rx
                    .recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("matrix observer closed"))?;
                anyhow::ensure!(route == b's', "matrix observation route mismatch");
                anyhow::ensure!(observed == expected, "matrix SFTP payload mismatch");
                Ok::<_, anyhow::Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), exchange)
                .await
                .unwrap_or_else(|_| panic!("{payload_len}-byte first SFTP frame stalled"))
                .unwrap();
        }

        session.invalidate().await;
        assert_eq!(authentications.load(Ordering::Acquire), 1);
        assert_eq!(executions.load(Ordering::Acquire), 4);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn server_identification_then_kex_stall_suppresses_retry_and_closes_socket() {
        let mut rng = CompatibleOsRng(OsRng);
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let fingerprint = key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        let config = Arc::new(russh::server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let authentications = Arc::new(AtomicUsize::new(0));
        let executions = Arc::new(AtomicUsize::new(0));
        let server_connections = Arc::clone(&connections);
        let server_authentications = Arc::clone(&authentications);
        let server_executions = Arc::clone(&executions);
        let (observed_tx, _observed_rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            server_connections.fetch_add(1, Ordering::AcqRel);
            first
                .write_all(b"SSH-2.0-serctl-first-kex-stall\r\n")
                .await
                .unwrap();
            first.flush().await.unwrap();
            let mut discarded = Vec::new();
            first.read_to_end(&mut discarded).await.unwrap();

            // Accepting the retry only after EOF on the first socket proves
            // cleanup completed before the second transport was created.
            let (socket, _) = listener.accept().await.unwrap();
            server_connections.fetch_add(1, Ordering::AcqRel);
            let handler = MatrixSshServer {
                channels: Arc::new(TokioMutex::new(HashMap::new())),
                observed: observed_tx,
                authentications: server_authentications,
                executions: server_executions,
            };
            if let Err(error) = russh::server::run_stream(config, socket, handler).await {
                eprintln!("retry matrix SSH transport failed: {error:#}");
            }
        });

        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "matrix".into(),
            password: "matrix-password".into(),
            host_key: Some(fingerprint.clone()),
        };
        let total_budget = MIN_FIRST_KEX_WINDOW
            + TRANSPORT_CLEANUP_TIMEOUT
            + PRE_AUTH_RETRY_BACKOFF
            + MIN_RETRY_KEX_WINDOW
            + RETRY_SCHEDULING_MARGIN
            + MIN_PASSWORD_AUTH_WINDOW
            + Duration::from_secs(1);
        let started = tokio::time::Instant::now();
        let total_deadline = started + total_budget;
        let error = match SshSession::connect_until(&creds, Some(fingerprint), total_deadline).await
        {
            Ok(_) => panic!("stalled first KEX unexpectedly retried before stream release"),
            Err(error) => error,
        };
        let chain = format!("{error:#}");
        assert!(chain.contains("SSH attempt 1:"));
        assert!(chain.contains("peer_observation=ssh_identification_observed_no_host_key"));
        assert!(chain.contains("server_identification_observed=true"));
        assert!(chain.contains("host_key_observed=false"));
        assert!(chain.contains("socket_shutdown_confirmed=true"));
        assert!(chain.contains("failure=local_deadline"));
        assert!(!chain.contains("failed after one pre-authentication reconnect"));
        assert!(tokio::time::Instant::now() < total_deadline);
        assert!(started.elapsed() >= MIN_FIRST_KEX_WINDOW);
        assert_eq!(connections.load(Ordering::Acquire), 1);
        assert_eq!(authentications.load(Ordering::Acquire), 0);
        assert_eq!(executions.load(Ordering::Acquire), 0);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn silent_pre_identification_peer_is_reported_without_claiming_kex_progress() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (banner_seen_tx, banner_seen_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            for _ in 0..256 {
                if peer.read_u8().await.unwrap() == b'\n' {
                    banner_seen_tx.send(()).unwrap();
                    let mut discarded = Vec::new();
                    peer.read_to_end(&mut discarded).await.unwrap();
                    return;
                }
            }
            panic!("client SSH identification exceeded the test bound");
        });
        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "not-used".into(),
            password: "not-used".into(),
            host_key: Some("not-observed".into()),
        };

        let error = match SshSession::connect_key_exchange_once_until(
            &creds,
            creds.host_key.clone(),
            1,
            tokio::time::Instant::now() + Duration::from_millis(250),
        )
        .await
        {
            Ok(_) => panic!("silent pre-identification peer unexpectedly completed key exchange"),
            Err(error) => error,
        };
        banner_seen_rx.await.unwrap();
        let chain = format!("{error:#}");
        assert!(chain.contains("peer_observation=client_identification_sent_server_silent"));
        assert!(chain.contains("attribution=undetermined_pre_identification_silence"));
        assert!(chain.contains("rx_bytes=0 tx_bytes=22"));
        assert!(chain.contains("server_identification_observed=false"));
        assert!(chain.contains("host_key_observed=false"));
        assert!(chain.contains("peer_eof_before_local_shutdown=false"));
        assert!(chain.contains("peer_disconnect_reason=none"));
        assert!(chain.contains("failure=local_deadline"));
        assert!(chain.contains("SSH server identification phase exceeded its deadline"));
        assert!(!chain.contains("SSH key exchange phase exceeded its deadline"));
        assert!(!chain.contains("server_bytes_received_before_host_key"));
        assert!(!chain.contains("127.0.0.1"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn raw_peer_close_then_silence_preserves_attempt_cleanup_and_diagnostics() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut client_identifications = Vec::new();
            for connection in 1..=2 {
                let (mut peer, _) = listener.accept().await.unwrap();
                let mut identification = Vec::new();
                for _ in 0..256 {
                    let byte = peer.read_u8().await.unwrap();
                    identification.push(byte);
                    if byte == b'\n' {
                        break;
                    }
                }
                assert_eq!(
                    identification.last(),
                    Some(&b'\n'),
                    "connection {connection} did not send a complete SSH identification"
                );
                assert_eq!(
                    identification.len(),
                    22,
                    "connection {connection} changed the counted client identification length"
                );
                assert!(
                    identification.starts_with(b"SSH-2.0-russh_")
                        && identification.ends_with(b"\r\n"),
                    "connection {connection} sent an unexpected client identification"
                );
                client_identifications.push(identification);

                if connection == 1 {
                    peer.shutdown().await.unwrap();
                } else {
                    // Send no byte. EOF arrives only after the client's local
                    // KEX deadline trips and releases the second transport.
                    let mut discarded = Vec::new();
                    peer.read_to_end(&mut discarded).await.unwrap();
                }
            }
            client_identifications
        });
        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "not-used".into(),
            password: "not-used".into(),
            host_key: Some("not-observed".into()),
        };
        let total = MIN_FIRST_KEX_WINDOW
            + TRANSPORT_CLEANUP_TIMEOUT
            + PRE_AUTH_RETRY_BACKOFF
            + MIN_RETRY_KEX_WINDOW
            + RETRY_SCHEDULING_MARGIN
            + MIN_PASSWORD_AUTH_WINDOW
            + Duration::from_secs(1);
        let total_deadline = tokio::time::Instant::now() + total;
        let error = connect_key_exchange_with_one_reconnect_until::<(), _, _>(
            total_deadline,
            MIN_PASSWORD_AUTH_WINDOW,
            {
                let creds = creds.clone();
                move |attempt, allocated_deadline| {
                    let creds = creds.clone();
                    async move {
                        // Keep this deterministic regression short without
                        // changing production budgets: the raw-peer attempt
                        // still uses the real connect/KEX/cleanup path, while
                        // its test-only cap is within the allocated deadline.
                        let cap = if attempt == 1 {
                            Duration::from_secs(1)
                        } else {
                            Duration::from_millis(250)
                        };
                        let attempt_deadline =
                            std::cmp::min(allocated_deadline, tokio::time::Instant::now() + cap);
                        SshSession::connect_key_exchange_once_until(
                            &creds,
                            creds.host_key.clone(),
                            attempt,
                            attempt_deadline,
                        )
                        .await
                        .map(|_| ())
                    }
                }
            },
        )
        .await
        .unwrap_err();

        let chain = format!("{error:#}");
        let first_attempt = chain
            .split("first_attempt=[")
            .nth(1)
            .and_then(|suffix| suffix.split("]; second_failure=").next())
            .unwrap_or_else(|| panic!("combined diagnostic omitted the first attempt: {chain}"));
        let second_attempt = chain
            .split("second_attempt=[")
            .nth(1)
            .and_then(|suffix| suffix.split(']').next())
            .unwrap_or_else(|| panic!("combined diagnostic omitted the second attempt: {chain}"));

        assert!(first_attempt.contains("SSH attempt 1:"));
        assert!(first_attempt
            .contains("peer_observation=transport_closed_before_server_identification"));
        assert!(first_attempt.contains("rx_bytes=0 tx_bytes=22"));
        assert!(first_attempt.contains("server_identification_observed=false"));
        assert!(first_attempt.contains("host_key_observed=false"));
        assert!(first_attempt.contains("peer_eof_before_local_shutdown=true"));
        assert!(first_attempt.contains("socket_shutdown_confirmed=true"));
        assert!(first_attempt.contains("stream_released=true"));
        assert!(
            first_attempt.contains("failure=terminal_disconnect")
                || first_attempt.contains("failure=terminal_io_close"),
            "unexpected first-attempt category: {first_attempt}"
        );

        assert!(chain.contains("second_failure=local_deadline"));
        assert!(second_attempt.contains("SSH attempt 2:"));
        assert!(
            second_attempt.contains("peer_observation=client_identification_sent_server_silent")
        );
        assert!(second_attempt.contains("rx_bytes=0 tx_bytes=22"));
        assert!(second_attempt.contains("server_identification_observed=false"));
        assert!(second_attempt.contains("host_key_observed=false"));
        assert!(second_attempt.contains("peer_eof_before_local_shutdown=false"));
        assert!(second_attempt.contains("socket_shutdown_confirmed=true"));
        assert!(second_attempt.contains("stream_released=true"));
        assert!(second_attempt.contains("failure=local_deadline"));
        assert!(tokio::time::Instant::now() < total_deadline);

        let identifications = server.await.unwrap();
        assert_eq!(identifications.len(), 2);
        assert_eq!(identifications[0], identifications[1]);
    }

    #[tokio::test]
    async fn pre_identification_peer_close_is_not_reported_as_server_silence() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (peer, _) = listener.accept().await.unwrap();
            drop(peer);
        });
        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "not-used".into(),
            password: "not-used".into(),
            host_key: Some("not-observed".into()),
        };

        let error = match SshSession::connect_key_exchange_once_until(
            &creds,
            creds.host_key.clone(),
            1,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        {
            Ok(_) => panic!("peer close unexpectedly completed key exchange"),
            Err(error) => error,
        };
        let chain = format!("{error:#}");
        assert!(
            chain.contains("peer_observation=transport_closed_before_server_identification"),
            "unexpected peer-close diagnostic: {chain}"
        );
        assert!(chain.contains("attribution=undetermined_pre_identification_transport_close"));
        assert!(chain.contains("rx_bytes=0"));
        assert!(chain.contains("server_identification_observed=false"));
        assert!(chain.contains("host_key_observed=false"));
        assert!(!chain.contains("peer_observation=client_identification_sent_server_silent"));
        assert!(
            chain.contains("peer_eof_before_local_shutdown=true")
                || chain.contains("failure=terminal_io_close"),
            "transport close was not independently evidenced: {chain}"
        );
        assert!(chain.contains("SSH server identification phase failed"));
        assert!(!chain.contains("SSH key exchange phase failed"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ssh_identification_then_transport_close_is_not_reported_as_missing_banner() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            peer.write_all(b"SSH-2.0-serctl-raw-close\r\n")
                .await
                .unwrap();
            peer.shutdown().await.unwrap();
        });
        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "not-used".into(),
            password: "not-used".into(),
            host_key: Some("not-observed".into()),
        };

        let error = match SshSession::connect_key_exchange_once_until(
            &creds,
            creds.host_key.clone(),
            1,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        {
            Ok(_) => {
                panic!("peer close after SSH identification unexpectedly completed key exchange")
            }
            Err(error) => error,
        };
        let chain = format!("{error:#}");
        assert!(chain.contains("peer_observation=ssh_identification_observed_no_host_key"));
        assert!(chain.contains("attribution=ssh_identification_reached"));
        assert!(chain.contains("server_identification_observed=true"));
        assert!(chain.contains("host_key_observed=false"));
        assert!(
            chain.contains("peer_eof_before_local_shutdown=true")
                || chain.contains("failure=terminal_io_close"),
            "transport close after identification was not independently evidenced: {chain}"
        );
        assert!(!chain.contains("peer_observation=transport_closed_before_server_identification"));
        assert!(!chain.contains("peer_observation=client_identification_sent_server_silent"));
        assert!(chain.contains("SSH key exchange phase failed"));
        assert!(!chain.contains("SSH server identification phase failed"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ssh_identification_then_silence_is_reported_as_no_host_key_progress() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            peer.write_all(b"SSH-2.0-serctl-raw-stall\r\n")
                .await
                .unwrap();
            peer.flush().await.unwrap();
            let mut discarded = Vec::new();
            peer.read_to_end(&mut discarded).await.unwrap();
        });
        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "not-used".into(),
            password: "not-used".into(),
            host_key: Some("not-observed".into()),
        };

        let error = match SshSession::connect_key_exchange_once_until(
            &creds,
            creds.host_key.clone(),
            1,
            tokio::time::Instant::now() + Duration::from_millis(250),
        )
        .await
        {
            Ok(_) => {
                panic!("silent peer after SSH identification unexpectedly completed key exchange")
            }
            Err(error) => error,
        };
        let chain = format!("{error:#}");
        assert!(chain.contains("peer_observation=ssh_identification_observed_no_host_key"));
        assert!(chain.contains("attribution=ssh_identification_reached"));
        assert!(chain.contains("server_identification_observed=true"));
        assert!(chain.contains("host_key_observed=false"));
        assert!(chain.contains("peer_eof_before_local_shutdown=false"));
        assert!(chain.contains("failure=local_deadline"));
        assert!(!chain.contains("peer_observation=client_identification_sent_server_silent"));
        assert!(chain.contains("SSH key exchange phase exceeded its deadline"));
        assert!(!chain.contains("SSH server identification phase exceeded its deadline"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pre_identification_policy_bytes_are_not_reported_as_ssh_kex_progress() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            peer.write_all(b"Access temporarily unavailable\r\n")
                .await
                .unwrap();
            peer.shutdown().await.unwrap();
        });
        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "not-used".into(),
            password: "not-used".into(),
            host_key: Some("not-observed".into()),
        };

        let error = match SshSession::connect_key_exchange_once_until(
            &creds,
            creds.host_key.clone(),
            1,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        {
            Ok(_) => panic!("policy text unexpectedly completed key exchange"),
            Err(error) => error,
        };
        let chain = format!("{error:#}");
        assert!(chain.contains("peer_observation=peer_bytes_without_valid_server_identification"));
        assert!(chain.contains("attribution=non_ssh_or_pre_identification_policy_bytes"));
        assert!(chain.contains("server_identification_observed=false"));
        assert!(chain.contains("host_key_observed=false"));
        assert!(!chain.contains("Access temporarily unavailable"));
        assert!(chain.contains("SSH server identification phase failed"));
        assert!(!chain.contains("SSH key exchange phase failed"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn standard_pre_auth_disconnect_is_sanitized_and_not_retried() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut client_identification = Vec::new();
            for _ in 0..256 {
                let byte = peer.read_u8().await.unwrap();
                client_identification.push(byte);
                if byte == b'\n' {
                    break;
                }
            }
            assert!(client_identification.ends_with(b"\r\n"));
            peer.write_all(b"SSH-2.0-serctl-policy-test\r\n")
                .await
                .unwrap();
            // RFC 4253 reason 12 is too many connections. The description is
            // deliberately sensitive-looking peer-controlled text and must
            // never survive in the serctl diagnostic chain.
            peer.write_all(&raw_ssh_disconnect_packet(
                12,
                b"secret-user blocked from 192.0.2.1",
            ))
            .await
            .unwrap();
            peer.shutdown().await.unwrap();

            tokio::time::timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok()
        });
        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "not-used".into(),
            password: "not-used".into(),
            host_key: Some("not-observed".into()),
        };
        let total = MIN_FIRST_KEX_WINDOW
            + TRANSPORT_CLEANUP_TIMEOUT
            + PRE_AUTH_RETRY_BACKOFF
            + MIN_RETRY_KEX_WINDOW
            + RETRY_SCHEDULING_MARGIN
            + MIN_PASSWORD_AUTH_WINDOW
            + Duration::from_secs(1);

        let error = match SshSession::connect_key_exchange_until(
            &creds,
            creds.host_key.clone(),
            tokio::time::Instant::now() + total,
        )
        .await
        {
            Ok(_) => {
                panic!("standard pre-authentication disconnect unexpectedly reached host-key KEX")
            }
            Err(error) => error,
        };
        let chain = format!("{error:#}");
        assert!(chain.contains("peer_observation=remote_ssh_disconnect_before_host_key"));
        assert!(chain.contains("attribution=ssh_disconnect_observed"));
        assert!(chain.contains("server_identification_observed=true"));
        assert!(chain.contains("host_key_observed=false"));
        assert!(chain.contains("peer_disconnect_reason=remote disconnect TooManyConnections"));
        assert!(!chain.contains("secret-user"));
        assert!(!chain.contains("192.0.2.1"));
        assert!(!chain.contains("failed after one pre-authentication reconnect"));
        assert!(chain.contains("SSH key exchange phase failed"));
        assert!(!chain.contains("SSH server identification phase failed"));
        assert!(
            !server.await.unwrap(),
            "explicit SSH disconnect was retried"
        );
    }

    #[test]
    fn identification_tracker_distinguishes_policy_text_and_chunked_ssh_id() {
        let mut policy = IdentificationTracker::default();
        assert!(policy.observe(b"Not allowed at this time\r\n").is_none());
        assert!(policy.observe(b"SSH").is_none());
        assert_eq!(
            policy.observe(b"-2.0-test\r\nignored"),
            Some("SSH-2.0-test".to_owned())
        );

        let mut pre_banner = IdentificationTracker::default();
        assert!(pre_banner.observe(b"notice\r\nSSH-2.0-test").is_none());
        assert_eq!(pre_banner.observe(b"\r\n"), Some("SSH-2.0-test".to_owned()));

        let mut invalid = IdentificationTracker::default();
        assert!(invalid.observe(b"SSH-\r\n").is_none());
        assert!(invalid.observe(b"SSH-2.0-\r\n").is_none());
        assert!(invalid.observe(b"SSH-2.0-test\n").is_none());
        assert_eq!(
            invalid.observe(b"SSH-1.99-compat\r\n"),
            Some("SSH-1.99-compat".to_owned())
        );

        let mut oversized = IdentificationTracker::default();
        let mut invalid = b"SSH-".to_vec();
        invalid.extend(std::iter::repeat_n(b'x', 252));
        invalid.push(b'\n');
        assert!(oversized.observe(&invalid).is_none());
    }

    #[test]
    fn server_identification_snapshot_is_bounded_and_strictly_sanitized() {
        assert_eq!(
            sanitize_server_identification(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.11"),
            Some("SSH-2.0-OpenSSH_9.6p1".to_owned())
        );
        assert_eq!(
            sanitize_server_identification(b"SSH-2.0-dropbear_2024.85"),
            Some("SSH-2.0-dropbear_2024.85".to_owned())
        );
        assert!(sanitize_server_identification(b"SSH-2.0-OpenSSH_9.6p1\0secret").is_none());
        assert!(sanitize_server_identification(b"SSH-2.0-OpenSSH_9.6p1 comment\x1b").is_none());
        let oversized = format!("SSH-2.0-{}", "x".repeat(121));
        assert!(sanitize_server_identification(oversized.as_bytes()).is_none());
    }

    #[test]
    fn authenticated_connection_identity_is_read_only_and_fail_closed() {
        let fingerprint = format!("SHA256:{}", "A".repeat(43));
        let attempt = new_transport_attempt_id();
        assert!(SshConnectionIdentitySnapshot::new_authenticated(
            false,
            Some(&fingerprint),
            Some(&fingerprint),
            Some("SSH-2.0-OpenSSH_9.6p1"),
            Some(&attempt),
        )
        .is_err());
        assert!(SshConnectionIdentitySnapshot::new_authenticated(
            true,
            None,
            Some(&fingerprint),
            Some("SSH-2.0-OpenSSH_9.6p1"),
            Some(&attempt),
        )
        .is_err());
        assert!(SshConnectionIdentitySnapshot::new_authenticated(
            true,
            Some(&fingerprint),
            Some(&format!("SHA256:{}", "B".repeat(43))),
            Some("SSH-2.0-OpenSSH_9.6p1"),
            Some(&attempt),
        )
        .is_err());
        assert!(SshConnectionIdentitySnapshot::new_authenticated(
            true,
            Some(&fingerprint),
            Some(&fingerprint),
            Some("SSH-2.0-OpenSSH_9.6p1\nraw"),
            Some(&attempt),
        )
        .is_err());

        let snapshot = SshConnectionIdentitySnapshot::new_authenticated(
            true,
            Some(&fingerprint),
            Some(&fingerprint),
            Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu"),
            Some(&attempt),
        )
        .unwrap();
        assert_eq!(snapshot.observed_host_key_sha256(), fingerprint);
        assert!(snapshot.pin_match());
        assert_eq!(snapshot.server_identification(), "SSH-2.0-OpenSSH_9.6p1");
        assert_eq!(snapshot.transport_attempt_id(), attempt);
    }

    #[test]
    fn reconnect_transport_attempt_identity_changes_without_reuse() {
        let first_attempt = new_transport_attempt_id();
        let reconnect_attempt = new_transport_attempt_id();
        assert_ne!(first_attempt, reconnect_attempt);
        assert_eq!(first_attempt.len(), 32);
        assert_eq!(reconnect_attempt.len(), 32);
        assert!(first_attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')));
        assert!(reconnect_attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')));
    }

    #[test]
    fn literal_ssh_addresses_use_their_explicit_socket_family() {
        let expected = SocketAddr::from(([8, 162, 3, 215], 22));
        assert_eq!(literal_socket_addr("8.162.3.215", 22), Some(expected));
        assert_eq!(
            literal_socket_addr("::ffff:8.162.3.215", 22),
            Some(expected)
        );
        assert_eq!(literal_socket_addr("server.example", 22), None);
    }

    #[test]
    fn command_output_is_bounded_across_stdout_and_stderr() {
        let mut output = Vec::new();
        assert!(extend_command_output(&mut output, b"ok", 0).is_ok());
        assert!(extend_command_output(&mut output, b"x", 8 * 1024 * 1024).is_err());
    }

    #[test]
    fn sftp_status_diagnostics_escape_terminal_controls_but_keep_unicode() {
        let error = status_error(
            "read",
            Status {
                id: 1,
                status_code: StatusCode::Failure,
                error_message: "保留\n\u{1b}]8;;https://attacker\u{7}".into(),
                language_tag: String::new(),
            },
        )
        .to_string();
        assert!(error.contains("保留"));
        assert!(error.contains("\\n"));
        assert!(error.contains("\\u{1b}"));
        assert!(!error.chars().any(char::is_control));
    }

    #[test]
    fn route_independent_command_and_path_limits_are_enforced() {
        assert!(validate_remote_command(&"x".repeat(MAX_REMOTE_COMMAND_BYTES)).is_ok());
        assert!(validate_remote_command(&"x".repeat(MAX_REMOTE_COMMAND_BYTES + 1)).is_err());
        assert!(validate_remote_command("echo\0hidden").is_err());
        assert!(validate_remote_path("", true).is_ok());
        assert!(validate_remote_path("", false).is_err());
        assert!(validate_remote_path("bad\0path", true).is_err());
        assert!(validate_remote_path(&"x".repeat(MAX_REMOTE_PATH_BYTES + 1), true).is_err());

        let longest_upload = "x".repeat(MAX_REMOTE_PATH_BYTES - REMOTE_PARTIAL_SUFFIX_BYTES);
        assert!(validate_upload_remote_path(&longest_upload).is_ok());
        assert_eq!(
            temporary_remote_path(&longest_upload).unwrap().len(),
            MAX_REMOTE_PATH_BYTES
        );
        assert!(validate_upload_remote_path(&format!("{longest_upload}x")).is_err());

        assert!(validate_shell_dimensions(1, MAX_SHELL_DIMENSION).is_ok());
        assert!(validate_shell_dimensions(0, 24).is_err());
        assert!(validate_shell_dimensions(80, MAX_SHELL_DIMENSION + 1).is_err());
    }

    #[test]
    fn tunnel_specs_make_external_binding_unrepresentable_and_enforce_limits() {
        let local = TunnelSpec::local(0, 5432);
        assert_eq!(local.mode(), TunnelMode::Local);
        assert_eq!(
            usize::from(local.max_connections),
            DEFAULT_TUNNEL_CONNECTIONS
        );
        local.validate().unwrap();
        match ValidatedTunnelSpec::try_from(local.clone()).unwrap() {
            ValidatedTunnelSpec::Local { bind, .. } => {
                assert_eq!(bind, SocketAddr::from(([127, 0, 0, 1], 0)));
            }
            _ => panic!("local tunnel changed validated mode"),
        }

        let serialized = serde_json::to_value(&local).unwrap();
        let fields = serialized.as_object().unwrap();
        assert_eq!(fields.len(), 4);
        assert!(!fields.contains_key("bind_host"));
        assert!(!fields.contains_key("target_host"));
        assert!(!fields.contains_key("allow_non_loopback"));
        for forbidden in ["bind_host", "target_host", "allow_non_loopback"] {
            let mut legacy = serialized.clone();
            legacy
                .as_object_mut()
                .unwrap()
                .insert(forbidden.into(), serde_json::json!("forbidden"));
            assert!(serde_json::from_value::<TunnelSpec>(legacy).is_err());
        }

        let mut invalid_limit = local.clone();
        invalid_limit.max_connections = 0;
        assert!(invalid_limit.validate().is_err());
        invalid_limit.max_connections = (MAX_TUNNEL_CONNECTIONS + 1) as u16;
        assert!(invalid_limit.validate().is_err());

        let mut zero_target = local.clone();
        zero_target.target_port = 0;
        assert!(zero_target.validate().is_err());

        let remote = TunnelSpec::remote(0, 8080);
        remote.validate().unwrap();
        let dynamic = TunnelSpec::dynamic(0);
        dynamic.validate().unwrap();
        let mut dynamic_with_target = dynamic;
        dynamic_with_target.target_port = 1;
        assert!(dynamic_with_target.validate().is_err());
    }

    #[test]
    fn remote_forward_channels_reject_gateway_ports_and_external_originators() {
        assert!(remote_forward_channel_is_loopback_only(
            "127.0.0.1",
            "127.0.0.1"
        ));
        for (connected, originator) in [
            ("0.0.0.0", "127.0.0.1"),
            ("192.0.2.5", "127.0.0.1"),
            ("127.0.0.1", "192.0.2.7"),
            ("::1", "::1"),
            ("localhost", "127.0.0.1"),
            ("127.0.0.1", "localhost"),
        ] {
            assert!(
                !remote_forward_channel_is_loopback_only(connected, originator),
                "accepted connected={connected:?} originator={originator:?}"
            );
        }
    }

    async fn write_fragmented<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) {
        for byte in bytes {
            writer.write_all(&[*byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn socks5_no_auth_connect_domain_accepts_fragmented_frames() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let handshake = tokio::spawn(async move {
            socks5_handshake(
                &mut server,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
        });

        write_fragmented(&mut client, &[5, 2, 2, 0]).await;
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let domain = b"echo.internal";
        let mut request = vec![5, 1, 0, 3, domain.len() as u8];
        request.extend_from_slice(domain);
        request.extend_from_slice(&8443_u16.to_be_bytes());
        write_fragmented(&mut client, &request).await;

        assert_eq!(
            handshake.await.unwrap().unwrap(),
            Some(SocksTarget {
                host: "echo.internal".into(),
                port: 8443,
            })
        );
    }

    #[tokio::test]
    async fn socks5_parses_ipv4_and_ipv6_connect_targets() {
        for (request, expected) in [
            (
                vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 80],
                SocksTarget {
                    host: "127.0.0.1".into(),
                    port: 80,
                },
            ),
            (
                {
                    let mut request = vec![5, 1, 0, 4];
                    request.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                    request.extend_from_slice(&443_u16.to_be_bytes());
                    request
                },
                SocksTarget {
                    host: "::1".into(),
                    port: 443,
                },
            ),
        ] {
            let (mut client, mut server) = tokio::io::duplex(128);
            let handshake = tokio::spawn(async move {
                socks5_handshake(
                    &mut server,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
            });
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0_u8; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            client.write_all(&request).await.unwrap();
            assert_eq!(handshake.await.unwrap().unwrap(), Some(expected));
        }
    }

    #[tokio::test]
    async fn socks5_rejects_auth_command_address_type_and_slow_handshake() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let no_auth = tokio::spawn(async move {
            socks5_handshake(
                &mut server,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
        });
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selection = [0_u8; 2];
        client.read_exact(&mut selection).await.unwrap();
        assert_eq!(selection, [5, 0xff]);
        assert_eq!(no_auth.await.unwrap().unwrap(), None);

        for (request, expected_reply) in [([5, 2, 0, 1], 7), ([5, 1, 0, 9], 8)] {
            let (mut client, mut server) = tokio::io::duplex(128);
            let rejected = tokio::spawn(async move {
                socks5_handshake(
                    &mut server,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
            });
            client.write_all(&[5, 1, 0]).await.unwrap();
            client.read_exact(&mut selection).await.unwrap();
            client.write_all(&request).await.unwrap();
            let mut response = [0_u8; 10];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response[0], 5);
            assert_eq!(response[1], expected_reply);
            assert_eq!(rejected.await.unwrap().unwrap(), None);
        }

        let (_client, mut server) = tokio::io::duplex(16);
        let error = socks5_handshake(
            &mut server,
            tokio::time::Instant::now() + Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("deadline"));
    }

    #[tokio::test]
    async fn bridge_streams_moves_bytes_both_ways_and_cancels() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client =
            tokio::spawn(async move { tokio::net::TcpStream::connect(address).await.unwrap() });
        let (socket, _) = listener.accept().await.unwrap();
        let mut client = client.await.unwrap();
        let (bridge_side, mut ssh_side) = tokio::io::duplex(128);
        let cancellation = CancellationToken::new();
        let bridge_cancel = cancellation.clone();
        let bridge =
            tokio::spawn(async move { bridge_streams(socket, bridge_side, bridge_cancel).await });

        client.write_all(b"toward-ssh").await.unwrap();
        let mut toward_ssh = [0_u8; 10];
        ssh_side.read_exact(&mut toward_ssh).await.unwrap();
        assert_eq!(&toward_ssh, b"toward-ssh");

        ssh_side.write_all(b"toward-local").await.unwrap();
        let mut toward_local = [0_u8; 12];
        client.read_exact(&mut toward_local).await.unwrap();
        assert_eq!(&toward_local, b"toward-local");

        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), bridge)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[test]
    fn remote_forward_registry_uses_bounded_generation_aware_routes() {
        let registry = Arc::new(RemoteForwardRegistry::default());
        let (first_sender, _first_receiver) = tokio::sync::mpsc::channel(1);
        let mut first = registry.register(41000, first_sender).unwrap();
        let first_generation = first.generation;
        assert!(registry.contains_port(41000));
        assert!(registry.sender_for(41000).is_some());

        let (duplicate_sender, _duplicate_receiver) = tokio::sync::mpsc::channel(1);
        assert!(registry.register(41000, duplicate_sender).is_err());
        first.remove();

        let (second_sender, _second_receiver) = tokio::sync::mpsc::channel(1);
        let second = registry.register(41000, second_sender).unwrap();
        assert_ne!(first_generation, second.generation);
        assert!(!registry.remove_if_generation(41000, first_generation));
        assert!(registry.contains_port(41000));
        drop(second);
        assert!(!registry.contains_port(41000));
        assert!(registry.sender_for(u32::from(u16::MAX) + 1).is_none());
    }

    #[test]
    fn exec_submission_state_only_types_post_request_failures_as_unknown() {
        let pre_request = ExecSubmissionState::BeforeRequest
            .classify(anyhow::anyhow!("connect failed before exec"));
        assert!(!pre_request.is::<ExecOutcomeUnknown>());

        let mut submitted = ExecSubmissionState::BeforeRequest;
        submitted.request_started();
        let post_request = submitted.classify(anyhow::anyhow!("exit status was lost"));
        assert!(post_request.is::<ExecOutcomeUnknown>());
        assert!(post_request.to_string().contains("outcome unknown"));
        assert!(post_request
            .to_string()
            .contains("inspect remote side effects before retry"));

        let classified_once = submitted.classify(post_request);
        assert!(classified_once.is::<ExecOutcomeUnknown>());
        assert_eq!(
            classified_once
                .to_string()
                .matches("outcome unknown")
                .count(),
            1
        );

        let round_tripped_over_ipc =
            submitted.classify(anyhow::anyhow!(classified_once.to_string()));
        assert!(round_tripped_over_ipc.is::<ExecOutcomeUnknown>());
        assert_eq!(
            round_tripped_over_ipc
                .to_string()
                .matches("outcome unknown")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn failed_exec_queue_send_stays_pre_request() {
        let mut submission = ExecSubmissionState::BeforeRequest;
        let error = await_exec_request_queued_until(
            &mut submission,
            tokio::time::Instant::now() + Duration::from_secs(1),
            async { Err::<(), anyhow::Error>(anyhow::anyhow!("injected exec send failure")) },
        )
        .await
        .unwrap_err();

        assert_eq!(submission, ExecSubmissionState::BeforeRequest);
        assert!(!error.is::<ExecOutcomeUnknown>());
        assert!(error.to_string().contains("injected exec send failure"));
    }

    #[tokio::test]
    async fn expired_exec_queue_deadline_does_not_poll_the_send() {
        let polled = Arc::new(AtomicBool::new(false));
        let future_polled = Arc::clone(&polled);
        let request = std::future::poll_fn(move |_| {
            future_polled.store(true, Ordering::Release);
            std::task::Poll::Ready(Ok::<(), anyhow::Error>(()))
        });
        let mut submission = ExecSubmissionState::BeforeRequest;
        let error = await_exec_request_queued_until(
            &mut submission,
            tokio::time::Instant::now() - Duration::from_millis(1),
            request,
        )
        .await
        .unwrap_err();

        assert!(!polled.load(Ordering::Acquire));
        assert_eq!(submission, ExecSubmissionState::BeforeRequest);
        assert!(!error.is::<ExecOutcomeUnknown>());
        assert!(error.to_string().contains("deadline"));
    }

    #[tokio::test]
    async fn pending_exec_queue_send_is_not_repolled_at_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        let polls = Arc::new(AtomicUsize::new(0));
        let future_polls = Arc::clone(&polls);
        let mut ready = Box::pin(tokio::time::sleep_until(deadline));
        let request = std::future::poll_fn(move |context| {
            future_polls.fetch_add(1, Ordering::AcqRel);
            match ready.as_mut().poll(context) {
                Poll::Ready(()) => Poll::Ready(Ok::<(), anyhow::Error>(())),
                Poll::Pending => Poll::Pending,
            }
        });
        let mut submission = ExecSubmissionState::BeforeRequest;
        let error = await_exec_request_queued_until(&mut submission, deadline, request)
            .await
            .unwrap_err();

        assert_eq!(polls.load(Ordering::Acquire), 1);
        assert_eq!(submission, ExecSubmissionState::BeforeRequest);
        assert!(!error.is::<ExecOutcomeUnknown>());
        assert!(error.to_string().contains("deadline"));
    }

    #[test]
    fn create_directory_submission_state_types_only_uncertain_failures() {
        let ordinary = CreateDirSubmissionState::BeforeRequest
            .classify(anyhow::anyhow!("connection failed before MKDIR"));
        assert!(!ordinary.is::<CreateDirOutcomeUnknown>());

        let mut submitted = CreateDirSubmissionState::BeforeRequest;
        submitted.request_started();
        let unknown = submitted.classify(anyhow::anyhow!("SFTP response was lost"));
        assert!(unknown.is::<CreateDirOutcomeUnknown>());
        assert!(unknown
            .to_string()
            .contains("inspect the remote path before retry"));

        let round_trip = submitted.classify(anyhow::anyhow!(unknown.to_string()));
        assert!(round_trip.is::<CreateDirOutcomeUnknown>());
        assert_eq!(round_trip.to_string().matches("outcome unknown").count(), 1);

        let status: anyhow::Error = russh_sftp::client::error::Error::Status(Status {
            id: 7,
            status_code: StatusCode::PermissionDenied,
            error_message: "denied".into(),
            language_tag: String::new(),
        })
        .into();
        assert!(is_explicit_sftp_status(&status));
    }

    #[test]
    fn ssh_transport_terminal_classification_excludes_channel_policy_and_local_deadlines() {
        for error in [
            russh::Error::Disconnect,
            russh::Error::HUP,
            russh::Error::SendError,
            russh::Error::ConnectionTimeout,
            russh::Error::KeepaliveTimeout,
            russh::Error::InactivityTimeout,
        ] {
            let error: anyhow::Error = error.into();
            assert!(is_ssh_transport_terminal_error(&error));
        }

        let contextual_disconnect =
            anyhow::Error::from(russh::Error::Disconnect).context("SSH key exchange phase failed");
        assert!(
            is_ssh_transport_terminal_error(&contextual_disconnect),
            "phase context must not hide the transport-terminal russh cause"
        );

        let rejected: anyhow::Error =
            russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .into();
        assert!(!is_ssh_transport_terminal_error(&rejected));
        assert!(!is_ssh_transport_terminal_error(&anyhow::anyhow!(
            "exec channel-open deadline expired"
        )));
        assert!(!is_ssh_transport_terminal_error(&anyhow::anyhow!(
            "caller supplied operation timeout"
        )));
    }

    #[tokio::test]
    async fn expired_remote_mutation_is_not_polled_or_marked_submitted() {
        let polled = Arc::new(AtomicBool::new(false));
        let future_polled = Arc::clone(&polled);
        let mut submission = CreateDirSubmissionState::BeforeRequest;
        let result = poll_remote_mutation_until(
            tokio::time::Instant::now() - Duration::from_millis(1),
            std::future::poll_fn(move |_| {
                future_polled.store(true, Ordering::Release);
                Poll::Ready(Ok::<(), anyhow::Error>(()))
            }),
            || submission.request_started(),
            || {},
            "SFTP create-directory exceeded its deadline",
        )
        .await;

        let error = result.unwrap_err();
        assert!(!polled.load(Ordering::Acquire));
        assert_eq!(submission, CreateDirSubmissionState::BeforeRequest);
        assert!(!error.is::<CreateDirOutcomeUnknown>());
        assert!(error.to_string().contains("deadline"));
    }

    #[tokio::test]
    async fn pending_remote_mutation_is_not_repolled_after_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        let polls = Arc::new(AtomicUsize::new(0));
        let future_polls = Arc::clone(&polls);
        let mut ready = Box::pin(tokio::time::sleep_until(deadline));
        let operation = std::future::poll_fn(move |context| {
            future_polls.fetch_add(1, Ordering::AcqRel);
            match ready.as_mut().poll(context) {
                Poll::Ready(()) => Poll::Ready(Ok::<(), anyhow::Error>(())),
                Poll::Pending => Poll::Pending,
            }
        });
        let mut submission = CreateDirSubmissionState::BeforeRequest;
        let result = poll_remote_mutation_until(
            deadline,
            operation,
            || submission.request_started(),
            || {},
            "SFTP create-directory exceeded its deadline",
        )
        .await;

        let error = submission.classify(result.unwrap_err());
        assert_eq!(polls.load(Ordering::Acquire), 1);
        assert_eq!(
            submission,
            CreateDirSubmissionState::RequestMayHaveReachedRemote
        );
        assert!(error.is::<CreateDirOutcomeUnknown>());
    }

    #[test]
    fn connection_fails_closed_without_an_observed_server_key() {
        assert!(require_server_fingerprint(None).is_err());
        assert!(require_server_fingerprint(Some(String::new())).is_err());
        assert_eq!(
            require_server_fingerprint(Some("SHA256:test".into())).unwrap(),
            "SHA256:test"
        );
    }

    #[test]
    fn client_host_key_algorithms_exclude_legacy_ssh_rsa() {
        let algorithms = secure_client_algorithms();
        assert!(!algorithms.key.is_empty());
        assert!(algorithms.key.iter().all(|algorithm| matches!(
            algorithm,
            ssh_key::Algorithm::Ed25519
                | ssh_key::Algorithm::Ecdsa { .. }
                | ssh_key::Algorithm::Rsa {
                    hash: Some(ssh_key::HashAlg::Sha256 | ssh_key::HashAlg::Sha512)
                }
        )));
        assert!(!algorithms
            .key
            .iter()
            .any(|algorithm| matches!(algorithm, ssh_key::Algorithm::Rsa { hash: None })));
    }

    #[test]
    fn client_algorithm_policy_keeps_a_modern_openssh_baseline() {
        let algorithms = secure_client_algorithms();

        assert!(algorithms.kex.contains(&russh::kex::CURVE25519));
        assert!(algorithms.key.contains(&ssh_key::Algorithm::Ed25519));
        assert!(algorithms
            .cipher
            .contains(&russh::cipher::CHACHA20_POLY1305));
        assert!(algorithms.cipher.contains(&russh::cipher::AES_256_CTR));
        assert!(algorithms.mac.contains(&russh::mac::HMAC_SHA256_ETM));
        assert!(algorithms.mac.contains(&russh::mac::HMAC_SHA256));
        assert!(algorithms.compression.contains(&russh::compression::NONE));
    }

    #[tokio::test]
    async fn advertised_hardlink_failure_never_falls_back_to_rename() {
        let rename_called = Arc::new(AtomicBool::new(false));
        let unlink_called = Arc::new(AtomicBool::new(false));
        let committed = AtomicBool::new(false);
        let rename_flag = Arc::clone(&rename_called);
        let unlink_flag = Arc::clone(&unlink_called);
        let error = commit_remote_upload_no_replace_with(
            || async { Err(anyhow::anyhow!("target already exists")) },
            move || {
                rename_flag.store(true, Ordering::Release);
                async { Ok(()) }
            },
            move || {
                unlink_flag.store(true, Ordering::Release);
                async { Ok(()) }
            },
            &committed,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("target already exists"));
        assert!(!rename_called.load(Ordering::Acquire));
        assert!(!unlink_called.load(Ordering::Acquire));
        assert!(!committed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn hardlink_commit_unlinks_only_the_owned_partial_name() {
        let rename_called = Arc::new(AtomicBool::new(false));
        let unlink_called = Arc::new(AtomicBool::new(false));
        let committed_state = AtomicBool::new(false);
        let rename_flag = Arc::clone(&rename_called);
        let unlink_flag = Arc::clone(&unlink_called);
        let commit = commit_remote_upload_no_replace_with(
            || async { Ok(true) },
            move || {
                rename_flag.store(true, Ordering::Release);
                async { Ok(()) }
            },
            move || {
                unlink_flag.store(true, Ordering::Release);
                async { Ok(()) }
            },
            &committed_state,
        )
        .await
        .unwrap();

        assert!(commit.partial_removed);
        assert!(!rename_called.load(Ordering::Acquire));
        assert!(unlink_called.load(Ordering::Acquire));
        assert!(committed_state.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn missing_hardlink_extension_fails_closed_without_rename() {
        let rename_called = Arc::new(AtomicBool::new(false));
        let unlink_called = Arc::new(AtomicBool::new(false));
        let committed_state = AtomicBool::new(false);
        let rename_flag = Arc::clone(&rename_called);
        let unlink_flag = Arc::clone(&unlink_called);
        let error = commit_remote_upload_no_replace_with(
            || async { Ok(false) },
            move || {
                rename_flag.store(true, Ordering::Release);
                async { Ok(()) }
            },
            move || {
                unlink_flag.store(true, Ordering::Release);
                async { Ok(()) }
            },
            &committed_state,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("hardlink@openssh.com"));
        assert!(!rename_called.load(Ordering::Acquire));
        assert!(!unlink_called.load(Ordering::Acquire));
        assert!(!committed_state.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn unlink_failure_after_hardlink_is_still_a_committed_upload() {
        let rename_called = Arc::new(AtomicBool::new(false));
        let rename_flag = Arc::clone(&rename_called);
        let committed_state = AtomicBool::new(false);
        let commit = commit_remote_upload_no_replace_with(
            || async { Ok(true) },
            move || {
                rename_flag.store(true, Ordering::Release);
                async { Ok(()) }
            },
            || async { Err(anyhow::anyhow!("temporary unlink failed")) },
            &committed_state,
        )
        .await
        .unwrap();

        assert!(!commit.partial_removed);
        assert!(!rename_called.load(Ordering::Acquire));
        assert!(committed_state.load(Ordering::Acquire));
    }

    #[test]
    fn temporary_remote_names_are_sibling_paths() {
        let path = temporary_remote_path("/srv/data/file.txt").unwrap();
        assert!(path.starts_with("/srv/data/file.txt.serctl-part-"));
        assert!(!path["/srv/data/file.txt.serctl-part-".len()..].contains('/'));
        assert_eq!(protected_upload_file_attributes().permissions, Some(0o600));
    }

    #[tokio::test]
    async fn directory_packet_limit_is_checked_before_body_allocation() {
        let limits = DirectoryLimits {
            packet_bytes: 16,
            encoded_bytes: 64,
            string_bytes: 64,
            entries: 4,
        };
        let mut budget = DirectoryBudget::new(limits);
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&17_u32.to_be_bytes()).await.unwrap();

        let error = tokio::time::timeout(
            Duration::from_millis(100),
            read_sftp_packet(&mut reader, &mut budget),
        )
        .await
        .expect("reader waited for an oversized packet body")
        .unwrap_err();
        assert!(error.to_string().contains("response packet exceeds"));
    }

    #[tokio::test]
    async fn high_level_sftp_guard_rejects_length_before_reading_body() {
        let invalidated = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let trip = TransportTrip {
            invalidated: invalidated.clone(),
            cancel: cancel.clone(),
            shutdown: None,
            activity: None,
        };
        let (mut writer, reader) = tokio::io::duplex(16);
        let mut guarded = BoundedSftpStream::new(reader, trip);
        writer
            .write_all(&((MAX_SFTP_PACKET_BYTES + 1) as u32).to_be_bytes())
            .await
            .unwrap();

        let error = tokio::time::timeout(Duration::from_millis(100), guarded.read_u32())
            .await
            .expect("guard waited for an oversized SFTP body")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(invalidated.load(Ordering::Acquire));
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn sftp_guard_reset_zeroizes_payload_and_spare_capacity() {
        let trip = TransportTrip {
            invalidated: Arc::new(AtomicBool::new(false)),
            cancel: CancellationToken::new(),
            shutdown: None,
            activity: None,
        };
        let (_writer, reader) = tokio::io::duplex(16);
        let mut guarded = BoundedSftpStream::new(reader, trip);
        guarded.header = [0x5a; 4];
        guarded.body = vec![0x5a; 128];
        guarded.body.truncate(32);
        let allocation = guarded.body.as_ptr();
        let capacity = guarded.body.capacity();

        guarded.reset_frame();

        assert_eq!(guarded.header, [0; 4]);
        assert!(guarded.body.is_empty());
        assert_eq!(guarded.body.capacity(), capacity);
        // SAFETY: the allocation remains owned by `guarded.body` with the same
        // capacity, and `Vec<u8>::zeroize` initializes every capacity byte to
        // zero before setting the logical length to zero.
        for index in 0..capacity {
            assert_eq!(unsafe { *allocation.add(index) }, 0);
        }
    }

    #[tokio::test]
    async fn russh_sftp_initialization_trips_guard_before_its_outer_deadline() {
        let invalidated = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let trip = TransportTrip {
            invalidated: invalidated.clone(),
            cancel: cancel.clone(),
            shutdown: None,
            activity: None,
        };
        let (client_io, mut server_io) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let request_len = server_io.read_u32().await.unwrap() as usize;
            let mut request = vec![0_u8; request_len];
            server_io.read_exact(&mut request).await.unwrap();
            server_io
                .write_all(&((MAX_SFTP_PACKET_BYTES + 1) as u32).to_be_bytes())
                .await
                .unwrap();
        });
        let guarded = BoundedSftpStream::new(client_io, trip);
        let config = SftpConfig {
            max_packet_len: MAX_SFTP_PACKET_BYTES as u32,
            ..Default::default()
        };

        let result = tokio::time::timeout(
            Duration::from_millis(250),
            SftpSession::new_with_config(guarded, config),
        )
        .await;
        if let Ok(Ok(_)) = result {
            panic!("oversized SFTP prefix unexpectedly initialized a session");
        }
        // russh-sftp 2.4 may keep its initialization oneshot pending after its
        // reader exits, which is why `sftp_until` also has an outer absolute
        // deadline. The important ordering invariant is that the guard trips
        // the transport as soon as the four-byte prefix arrives, without ever
        // waiting for or allocating the declared body.
        assert!(invalidated.load(Ordering::Acquire));
        assert!(cancel.is_cancelled());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn high_level_sftp_guard_does_not_prefetch_for_empty_readbuf() {
        let invalidated = Arc::new(AtomicBool::new(false));
        let trip = TransportTrip {
            invalidated,
            cancel: CancellationToken::new(),
            shutdown: None,
            activity: None,
        };
        let (mut writer, reader) = tokio::io::duplex(32);
        let mut guarded = BoundedSftpStream::new(reader, trip);
        assert_eq!(guarded.read(&mut []).await.unwrap(), 0);

        writer.write_all(&3_u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"abc").await.unwrap();
        assert_eq!(guarded.read_u32().await.unwrap(), 3);
        let mut body = [0_u8; 3];
        guarded.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"abc");
    }

    #[tokio::test]
    async fn repeated_kex_deadlines_close_every_transport_connection() {
        const ATTEMPTS: usize = 100;
        fn is_peer_closed(error: &std::io::Error) -> bool {
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            )
        }

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (closed_tx, mut closed_rx) = tokio::sync::mpsc::channel(ATTEMPTS);
        let server = tokio::spawn(async move {
            let mut peers = tokio::task::JoinSet::new();
            for _ in 0..ATTEMPTS {
                let (mut peer, _) = listener.accept().await.unwrap();
                let closed_tx = closed_tx.clone();
                peers.spawn(async move {
                    match peer.write_all(b"SSH-2.0-serctl-kex-stall\r\n").await {
                        Ok(()) => {
                            let mut received = Vec::new();
                            if let Err(error) = peer.read_to_end(&mut received).await {
                                assert!(
                                    is_peer_closed(&error),
                                    "transport read failed without proving peer closure: {error}"
                                );
                            }
                        }
                        Err(error) => assert!(
                            is_peer_closed(&error),
                            "transport write failed without proving peer closure: {error}"
                        ),
                    }
                    closed_tx.send(()).await.unwrap();
                });
            }
            while let Some(result) = peers.join_next().await {
                result.unwrap();
            }
        });
        let creds = Creds {
            host: "127.0.0.1".into(),
            port,
            user: "nobody".into(),
            password: "not-used".into(),
            host_key: None,
        };

        for _ in 0..ATTEMPTS {
            let result = SshSession::connect_until(
                &creds,
                None,
                tokio::time::Instant::now() + Duration::from_millis(25),
            )
            .await;
            assert!(result.is_err());
        }
        for _ in 0..ATTEMPTS {
            // The close drain asserts prompt closure, not latency: the 25 ms
            // KEX deadline above is the property under test. The generous cap
            // absorbs scheduling jitter when the whole suite runs in parallel.
            tokio::time::timeout(Duration::from_secs(10), closed_rx.recv())
                .await
                .expect("transport connection was not closed")
                .expect("server close channel ended early");
        }
        server.await.unwrap();
    }

    #[test]
    fn reconnect_budget_reserves_two_kex_windows_cleanup_and_authentication() {
        let now = tokio::time::Instant::now();
        let minimum_retry_total = MIN_FIRST_KEX_WINDOW
            + TRANSPORT_CLEANUP_TIMEOUT
            + PRE_AUTH_RETRY_BACKOFF
            + MIN_RETRY_KEX_WINDOW
            + RETRY_SCHEDULING_MARGIN
            + MIN_PASSWORD_AUTH_WINDOW;
        let total_deadline = now + minimum_retry_total;
        let budget = ssh_connect_budget(now, total_deadline, MIN_PASSWORD_AUTH_WINDOW);

        assert_eq!(budget.first_attempt_deadline, now + MIN_FIRST_KEX_WINDOW);
        assert_eq!(
            budget.retry_attempt_deadline,
            Some(total_deadline - MIN_PASSWORD_AUTH_WINDOW)
        );

        let insufficient_deadline = total_deadline - Duration::from_nanos(1);
        let insufficient = ssh_connect_budget(now, insufficient_deadline, MIN_PASSWORD_AUTH_WINDOW);
        assert_eq!(insufficient.retry_attempt_deadline, None);
        assert_eq!(
            insufficient.first_attempt_deadline,
            insufficient_deadline - MIN_PASSWORD_AUTH_WINDOW
        );

        let short_deadline = now + MIN_FIRST_KEX_WINDOW;
        let short = ssh_connect_budget(now, short_deadline, MIN_PASSWORD_AUTH_WINDOW);
        assert_eq!(short.retry_attempt_deadline, None);
        assert_eq!(short.first_attempt_deadline, short_deadline);

        let retry_deadline = now + PRE_AUTH_RETRY_BACKOFF + MIN_RETRY_KEX_WINDOW;
        assert!(has_minimum_retry_window_after_backoff(now, retry_deadline));
        assert!(!has_minimum_retry_window_after_backoff(
            now + Duration::from_nanos(1),
            retry_deadline
        ));
        assert!(has_minimum_retry_window(
            now + PRE_AUTH_RETRY_BACKOFF,
            retry_deadline
        ));
        assert!(!has_minimum_retry_window(
            now + PRE_AUTH_RETRY_BACKOFF + Duration::from_nanos(1),
            retry_deadline
        ));
    }

    #[tokio::test]
    async fn insufficient_budget_returns_first_terminal_failure_without_reconnect() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let connections = Arc::new(AtomicUsize::new(0));

        let error = connect_key_exchange_with_one_reconnect_until::<(), _, _>(
            deadline,
            MIN_PASSWORD_AUTH_WINDOW,
            {
                let connections = Arc::clone(&connections);
                move |attempt, _attempt_deadline| {
                    connections.fetch_add(1, Ordering::AcqRel);
                    async move {
                        let record = SshAttemptRecord {
                            attempt,
                            tcp_connected: true,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            server_identification_observed: false,
                            host_key_observed: false,
                            peer_eof_before_local_shutdown: true,
                            peer_disconnect_reason: None,
                            elapsed_ms: 1,
                            failure_elapsed_ms: 1,
                            cleanup_elapsed_ms: 0,
                            socket_shutdown_confirmed: true,
                            stream_released: true,
                            failure_category: SshFailureCategory::TerminalDisconnect,
                        };
                        Err(attach_ssh_attempt_record(
                            anyhow::Error::new(russh::Error::Disconnect),
                            record,
                        ))
                    }
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(connections.load(Ordering::Acquire), 1);
        assert!(!format!("{error:#}").contains("failed after one pre-authentication reconnect"));
    }

    #[tokio::test]
    async fn short_deadline_reuses_remaining_budget_after_clean_early_transport_eof() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let connections = Arc::new(AtomicUsize::new(0));

        let result =
            connect_key_exchange_with_one_reconnect_until(deadline, MIN_PASSWORD_AUTH_WINDOW, {
                let connections = Arc::clone(&connections);
                move |attempt, attempt_deadline| {
                    connections.fetch_add(1, Ordering::AcqRel);
                    async move {
                        assert_eq!(attempt_deadline, deadline);
                        if attempt == 1 {
                            let record = SshAttemptRecord {
                                attempt,
                                tcp_connected: true,
                                rx_bytes: 0,
                                tx_bytes: 22,
                                server_identification_observed: false,
                                host_key_observed: false,
                                peer_eof_before_local_shutdown: true,
                                peer_disconnect_reason: None,
                                elapsed_ms: 1,
                                failure_elapsed_ms: 1,
                                cleanup_elapsed_ms: 0,
                                socket_shutdown_confirmed: true,
                                stream_released: true,
                                failure_category: SshFailureCategory::TerminalDisconnect,
                            };
                            Err(attach_ssh_attempt_record(
                                anyhow::Error::new(russh::Error::Disconnect),
                                record,
                            ))
                        } else {
                            Ok(11_u8)
                        }
                    }
                }
            })
            .await
            .unwrap();

        assert_eq!(result, (11, true));
        assert_eq!(connections.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn sufficient_budget_reconnects_once_after_complete_terminal_cleanup() {
        let total = MIN_FIRST_KEX_WINDOW
            + TRANSPORT_CLEANUP_TIMEOUT
            + PRE_AUTH_RETRY_BACKOFF
            + MIN_RETRY_KEX_WINDOW
            + RETRY_SCHEDULING_MARGIN
            + MIN_PASSWORD_AUTH_WINDOW
            + Duration::from_secs(1);
        let deadline = tokio::time::Instant::now() + total;
        let connections = Arc::new(AtomicUsize::new(0));

        let result =
            connect_key_exchange_with_one_reconnect_until(deadline, MIN_PASSWORD_AUTH_WINDOW, {
                let connections = Arc::clone(&connections);
                move |attempt, attempt_deadline| {
                    connections.fetch_add(1, Ordering::AcqRel);
                    async move {
                        assert!(attempt_deadline < deadline);
                        if attempt == 1 {
                            let record = SshAttemptRecord {
                                attempt,
                                tcp_connected: true,
                                rx_bytes: 0,
                                tx_bytes: 32,
                                server_identification_observed: false,
                                host_key_observed: false,
                                peer_eof_before_local_shutdown: true,
                                peer_disconnect_reason: None,
                                elapsed_ms: 1,
                                failure_elapsed_ms: 1,
                                cleanup_elapsed_ms: 0,
                                socket_shutdown_confirmed: true,
                                stream_released: true,
                                failure_category: SshFailureCategory::TerminalDisconnect,
                            };
                            Err(attach_ssh_attempt_record(
                                anyhow::Error::new(russh::Error::Disconnect),
                                record,
                            ))
                        } else {
                            Ok(7_u8)
                        }
                    }
                }
            })
            .await
            .unwrap();

        assert_eq!(result, (7, true));
        assert_eq!(connections.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn reconnect_failure_labels_both_attempts_without_first_failure_mismatch() {
        let total = MIN_FIRST_KEX_WINDOW
            + TRANSPORT_CLEANUP_TIMEOUT
            + PRE_AUTH_RETRY_BACKOFF
            + MIN_RETRY_KEX_WINDOW
            + RETRY_SCHEDULING_MARGIN
            + MIN_PASSWORD_AUTH_WINDOW
            + Duration::from_secs(1);
        let deadline = tokio::time::Instant::now() + total;

        let error = connect_key_exchange_with_one_reconnect_until::<(), _, _>(
            deadline,
            MIN_PASSWORD_AUTH_WINDOW,
            move |attempt, _attempt_deadline| async move {
                let (failure_category, source) = if attempt == 1 {
                    (
                        SshFailureCategory::TerminalDisconnect,
                        anyhow::Error::new(russh::Error::Disconnect),
                    )
                } else {
                    (
                        SshFailureCategory::LocalDeadline,
                        anyhow::anyhow!("SSH server identification phase exceeded its deadline"),
                    )
                };
                let record = SshAttemptRecord {
                    attempt,
                    tcp_connected: true,
                    rx_bytes: 0,
                    tx_bytes: 22,
                    server_identification_observed: false,
                    host_key_observed: false,
                    peer_eof_before_local_shutdown: attempt == 1,
                    peer_disconnect_reason: None,
                    elapsed_ms: 1,
                    failure_elapsed_ms: 1,
                    cleanup_elapsed_ms: 0,
                    socket_shutdown_confirmed: true,
                    stream_released: true,
                    failure_category,
                };
                Err(attach_ssh_attempt_record(source, record))
            },
        )
        .await
        .unwrap_err();

        let chain = format!("{error:#}");
        assert!(chain.contains(
            "SSH server identification phase failed after one pre-authentication reconnect"
        ));
        assert!(
            !chain.contains("SSH key exchange phase failed after one pre-authentication reconnect")
        );
        assert!(chain.contains("first_failure=terminal_disconnect; first_attempt=[SSH attempt 1:"));
        assert!(chain.contains("second_failure=local_deadline; second_attempt=[SSH attempt 2:"));
        assert!(chain.contains(
            "first_attempt=[SSH attempt 1: peer_observation=transport_closed_before_server_identification"
        ));
        assert!(chain.contains(
            "second_attempt=[SSH attempt 2: peer_observation=client_identification_sent_server_silent"
        ));
        assert!(!chain.contains("first_failure=terminal_disconnect: SSH attempt 2:"));
        assert!(!chain.contains("first_attempt=[SSH attempt 2:"));
        assert!(!chain.contains("second_attempt=[SSH attempt 1:"));
    }

    #[tokio::test]
    async fn incomplete_transport_cleanup_suppresses_reconnect() {
        for (socket_shutdown_confirmed, stream_released) in [(false, true), (true, false)] {
            let total = MIN_FIRST_KEX_WINDOW
                + TRANSPORT_CLEANUP_TIMEOUT
                + PRE_AUTH_RETRY_BACKOFF
                + MIN_RETRY_KEX_WINDOW
                + RETRY_SCHEDULING_MARGIN
                + MIN_PASSWORD_AUTH_WINDOW;
            let deadline = tokio::time::Instant::now() + total;
            let connections = Arc::new(AtomicUsize::new(0));

            let error = connect_key_exchange_with_one_reconnect_until::<(), _, _>(
                deadline,
                MIN_PASSWORD_AUTH_WINDOW,
                {
                    let connections = Arc::clone(&connections);
                    move |attempt, _attempt_deadline| {
                        connections.fetch_add(1, Ordering::AcqRel);
                        async move {
                            let record = SshAttemptRecord {
                                attempt,
                                tcp_connected: true,
                                rx_bytes: 0,
                                tx_bytes: 22,
                                server_identification_observed: false,
                                host_key_observed: false,
                                peer_eof_before_local_shutdown: true,
                                peer_disconnect_reason: None,
                                elapsed_ms: 1,
                                failure_elapsed_ms: 1,
                                cleanup_elapsed_ms: 0,
                                socket_shutdown_confirmed,
                                stream_released,
                                failure_category: SshFailureCategory::TerminalDisconnect,
                            };
                            Err(attach_ssh_attempt_record(
                                anyhow::Error::new(russh::Error::Disconnect),
                                record,
                            ))
                        }
                    }
                },
            )
            .await
            .unwrap_err();

            assert_eq!(connections.load(Ordering::Acquire), 1);
            assert!(!format!("{error:#}").contains("failed after one pre-authentication reconnect"));
        }
    }

    #[tokio::test]
    async fn server_bytes_or_explicit_disconnect_reason_suppress_pre_auth_reconnect() {
        for (rx_bytes, peer_disconnect_reason) in [
            (32_u64, None),
            (
                0_u64,
                Some("remote disconnect TooManyConnections".to_owned()),
            ),
        ] {
            // Keep the deadline below the conservative two-window budget so
            // this also proves the early-EOF fallback remains unavailable
            // after any server bytes or an explicit SSH_MSG_DISCONNECT.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            let connections = Arc::new(AtomicUsize::new(0));
            let error = connect_key_exchange_with_one_reconnect_until::<(), _, _>(
                deadline,
                MIN_PASSWORD_AUTH_WINDOW,
                {
                    let connections = Arc::clone(&connections);
                    move |attempt, _attempt_deadline| {
                        connections.fetch_add(1, Ordering::AcqRel);
                        let peer_disconnect_reason = peer_disconnect_reason.clone();
                        async move {
                            let record = SshAttemptRecord {
                                attempt,
                                tcp_connected: true,
                                rx_bytes,
                                tx_bytes: 22,
                                server_identification_observed: false,
                                host_key_observed: false,
                                peer_eof_before_local_shutdown: true,
                                peer_disconnect_reason,
                                elapsed_ms: 1,
                                failure_elapsed_ms: 1,
                                cleanup_elapsed_ms: 0,
                                socket_shutdown_confirmed: true,
                                stream_released: true,
                                failure_category: SshFailureCategory::TerminalDisconnect,
                            };
                            Err(attach_ssh_attempt_record(
                                anyhow::Error::new(russh::Error::Disconnect),
                                record,
                            ))
                        }
                    }
                },
            )
            .await
            .unwrap_err();

            assert_eq!(connections.load(Ordering::Acquire), 1);
            assert!(!format!("{error:#}").contains("failed after one pre-authentication reconnect"));
        }
    }

    #[test]
    fn directory_entry_and_retained_string_budgets_are_enforced() {
        let entry_limits = DirectoryLimits {
            packet_bytes: 64,
            encoded_bytes: 256,
            string_bytes: 64,
            entries: 1,
        };
        let mut budget = DirectoryBudget::new(entry_limits);
        budget.reserve_strings(1).unwrap();
        let mut entries = Vec::new();
        push_directory_entry(
            &mut entries,
            "/",
            File::new("a", FileAttributes::default()),
            &mut budget,
        )
        .unwrap();
        assert_eq!(entries[0].path, "/a");
        let error = push_directory_entry(
            &mut entries,
            "/",
            File::new("b", FileAttributes::default()),
            &mut budget,
        )
        .unwrap_err();
        assert!(error.to_string().contains("more than 1 entries"));

        let string_limits = DirectoryLimits {
            string_bytes: 3,
            ..entry_limits
        };
        let mut budget = DirectoryBudget::new(string_limits);
        budget.reserve_strings(1).unwrap();
        let error = push_directory_entry(
            &mut Vec::new(),
            "/",
            File::new("a", FileAttributes::default()),
            &mut budget,
        )
        .unwrap_err();
        assert!(error.to_string().contains("retained-string safety limit"));
    }

    #[test]
    fn worst_case_control_character_listing_fits_the_ipc_wire_budget() {
        let mut budget = DirectoryBudget::new(DIRECTORY_LIMITS);
        budget.reserve_strings(1).unwrap();
        let mut entries = Vec::with_capacity(MAX_DIRECTORY_ENTRIES);
        // Each one-byte control character expands to six bytes in JSON. At
        // 104 bytes per name, name+absolute-path retention is 209 bytes per
        // entry: 2,090,000 bytes across 10k entries, just below the 2 MiB cap.
        let name = "\u{1}".repeat(104);
        for _ in 0..MAX_DIRECTORY_ENTRIES {
            push_directory_entry(
                &mut entries,
                "/",
                File::new(name.clone(), FileAttributes::default()),
                &mut budget,
            )
            .unwrap();
        }
        assert!(budget.string_bytes <= MAX_DIRECTORY_STRING_BYTES);
        let frame = serctl_protocol::Frame::DirList {
            path: "/".into(),
            entries,
            operation_context_id: None,
            revision: 0,
        };
        let encoded =
            serctl_protocol::encoded_frame_len_limited(&frame, serctl_protocol::MAX_RESPONSE_FRAME)
                .unwrap();
        assert!(encoded <= serctl_protocol::MAX_RESPONSE_FRAME);
    }

    #[test]
    fn directory_encoded_budget_accumulates_across_packets() {
        let limits = DirectoryLimits {
            packet_bytes: 16,
            encoded_bytes: 15,
            string_bytes: 64,
            entries: 4,
        };
        let mut budget = DirectoryBudget::new(limits);
        budget.reserve_packet(4).unwrap();
        let error = budget.reserve_packet(4).unwrap_err();
        assert!(error.to_string().contains("encoded-byte safety limit"));
    }

    #[test]
    fn directory_entries_must_be_single_components() {
        let limits = DirectoryLimits {
            packet_bytes: 64,
            encoded_bytes: 256,
            string_bytes: 256,
            entries: 8,
        };
        for name in ["", "../escape", "/absolute", "nested/name", "nul\0name"] {
            let error = push_directory_entry(
                &mut Vec::new(),
                "/safe",
                File::new(name, FileAttributes::default()),
                &mut DirectoryBudget::new(limits),
            )
            .unwrap_err();
            assert!(error.to_string().contains("entry name"));
        }
    }
}
