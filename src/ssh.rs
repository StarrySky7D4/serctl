//! russh client wrapper: connect with password auth, exec commands, open PTY shells.
use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use rand::{rngs::OsRng, RngCore};
use russh::{client, keys::ssh_key, ChannelMsg};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{
    Close, File, FileAttributes, Handle, Init, Name, OpenDir, Packet, ReadDir, RealPath, Status,
    StatusCode, VERSION,
};
use serde::{Deserialize, Serialize};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::Creds;

const MAX_COMMAND_OUTPUT: usize = crate::ipc::MAX_COMMAND_OUTPUT;
pub const MAX_REMOTE_COMMAND_BYTES: usize = 64 * 1024;
pub const MAX_REMOTE_PATH_BYTES: usize = 4096;
pub const MAX_SFTP_PACKET_BYTES: usize = 1024 * 1024;
pub const MAX_TRANSFER_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const REMOTE_PARTIAL_SUFFIX_BYTES: usize = ".serctl-part-".len() + 32;
const SSH_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(120);
const TRANSPORT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const CHANNEL_OPERATION_TIMEOUT: Duration = Duration::from_millis(350);
const CHANNEL_SIGNAL_GRACE: Duration = Duration::from_millis(100);

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
    pub used_hardlink: bool,
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
    match hardlink().await? {
        true => {
            committed.store(true, Ordering::Release);
            let partial_removed = unlink_partial().await.is_ok();
            Ok(RemoteUploadCommit {
                used_hardlink: true,
                partial_removed,
            })
        }
        false => {
            // SFTP v3 RENAME specifies failure when `newpath` exists. This
            // fallback is used only when the server did not advertise the
            // OpenSSH hardlink extension, and therefore relies on a compliant
            // server implementation for no-replace behavior.
            rename().await?;
            committed.store(true, Ordering::Release);
            Ok(RemoteUploadCommit {
                used_hardlink: false,
                partial_removed: true,
            })
        }
    }
}

/// Commit a completed remote sibling without overwriting an existing target.
/// An advertised hardlink extension is authoritative: any hardlink error is a
/// safe failure and must never fall back to the less strongly implemented v3
/// RENAME operation.
pub async fn commit_remote_upload_no_replace(
    sftp: &SftpSession,
    partial: &str,
    target: &str,
    committed: &AtomicBool,
) -> Result<RemoteUploadCommit> {
    commit_remote_upload_no_replace_with(
        || async { Ok(sftp.hardlink(partial, target).await?) },
        || async { Ok(sftp.rename(partial, target).await?) },
        || async { Ok(sftp.remove_file(partial).await?) },
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

pub struct SshHandler {
    expect: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
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
}

pub struct SshSession {
    handle: client::Handle<SshHandler>,
    invalidated: Arc<AtomicBool>,
    transport: TransportControl,
}

pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<i32>,
}

pub struct RunningCommand {
    channel: russh::Channel<russh::client::Msg>,
    transport: TransportTrip,
}

#[derive(Clone)]
struct TransportTrip {
    invalidated: Arc<AtomicBool>,
    cancel: CancellationToken,
}

impl TransportTrip {
    fn trip(&self) {
        self.invalidated.store(true, Ordering::Release);
        self.cancel.cancel();
    }
}

struct TransportControl {
    trip: TransportTrip,
    done: AsyncMutex<Option<oneshot::Receiver<()>>>,
}

impl TransportControl {
    fn trip(&self) -> TransportTrip {
        self.trip.clone()
    }

    async fn stop_and_wait(&self) -> bool {
        self.trip.trip();
        let Some(done) = self.done.lock().await.take() else {
            return true;
        };
        matches!(
            tokio::time::timeout(TRANSPORT_CLEANUP_TIMEOUT, done).await,
            Ok(Ok(()))
        )
    }
}

impl Drop for TransportControl {
    fn drop(&mut self) {
        self.trip.trip();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified_unix: Option<u32>,
}

async fn run_transport_proxy(
    mut socket: tokio::net::TcpStream,
    mut proxy_stream: tokio::io::DuplexStream,
    cancel: CancellationToken,
    done: oneshot::Sender<()>,
) {
    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut socket, &mut proxy_stream) => {
            if let Err(error) = result {
                log::debug!("SSH transport proxy ended: {error}");
            }
        }
        _ = cancel.cancelled() => {}
    }
    // Waking both halves is what makes cancelling a russh connect future
    // deterministic even when its internal task is blocked in pre-auth KEX.
    let _ = proxy_stream.shutdown().await;
    let _ = socket.shutdown().await;
    let _ = done.send(());
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

/// A key-exchanged SSH transport that has observed and validated the server
/// host key but has not sent any user authentication secret yet.
pub struct StagedSshSession {
    handle: Option<client::Handle<SshHandler>>,
    invalidated: Arc<AtomicBool>,
    transport: Option<TransportControl>,
    observed_fingerprint: String,
}

impl StagedSshSession {
    pub fn observed_fingerprint(&self) -> &str {
        &self.observed_fingerprint
    }

    /// Close a pre-authentication transport and wait a bounded interval for
    /// its proxy to release the underlying TCP socket.
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
            bail!("SSH connection exceeded its deadline");
        }
        let authentication = self
            .handle
            .as_mut()
            .context("SSH transport is unavailable before authentication")?
            .authenticate_password(user, password);
        let result = tokio::time::timeout_at(deadline, authentication).await;
        match result {
            Ok(Ok(client::AuthResult::Success)) => {
                let handle = self
                    .handle
                    .take()
                    .context("SSH transport disappeared after authentication")?;
                let transport = self
                    .transport
                    .take()
                    .context("SSH transport proxy disappeared after authentication")?;
                Ok(SshSession {
                    handle,
                    invalidated: self.invalidated.clone(),
                    transport,
                })
            }
            Ok(Ok(_)) => {
                let error = anyhow::anyhow!("authentication failed for user '{user}'");
                self.abort().await;
                Err(error)
            }
            Ok(Err(error)) => {
                self.abort().await;
                Err(error.into())
            }
            Err(_) => {
                self.abort().await;
                bail!("SSH connection exceeded its deadline")
            }
        }
    }
}

impl SshSession {
    /// Complete TCP connection, SSH key exchange, and host-key validation
    /// without sending a password. The TCP stream is kept behind a
    /// cancellation-aware proxy because russh spawns its session task before
    /// key exchange completes. Cancelling the public `connect_stream` future
    /// alone would otherwise detach that task forever when a peer sends its
    /// banner and then stalls during KEX.
    pub async fn connect_key_exchange_until(
        creds: &Creds,
        expect: Option<String>,
        deadline: tokio::time::Instant,
    ) -> Result<StagedSshSession> {
        let seen = Arc::new(Mutex::new(None));
        let cfg = client::Config {
            // This is a second line of defence for pre-authentication stalls.
            // The external absolute deadline is enforced by the proxy below;
            // this timeout also bounds a detached/upstream-internal wait.
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
        };
        let socket = match tokio::time::timeout_at(
            deadline,
            tokio::net::TcpStream::connect((creds.host.as_str(), creds.port)),
        )
        .await
        {
            Ok(result) => result.context("connect SSH TCP socket")?,
            Err(_) => bail!("SSH connection exceeded its deadline"),
        };
        if cfg.nodelay {
            socket.set_nodelay(true).context("set SSH TCP_NODELAY")?;
        }

        let invalidated = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let trip = TransportTrip {
            invalidated: invalidated.clone(),
            cancel: cancel.clone(),
        };
        let (russh_stream, proxy_stream) = tokio::io::duplex(256 * 1024);
        let (done_tx, done_rx) = oneshot::channel();
        tokio::spawn(run_transport_proxy(socket, proxy_stream, cancel, done_tx));
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
                let _ = transport.stop_and_wait().await;
                return Err(error);
            }
            Err(_) => {
                let _ = transport.stop_and_wait().await;
                bail!("SSH connection exceeded its deadline");
            }
        };
        let observed_fingerprint = seen
            .lock()
            .map_err(|_| anyhow::anyhow!("server-key observation state was poisoned"))?
            .clone();
        let fp = match require_server_fingerprint(observed_fingerprint) {
            Ok(fp) => fp,
            Err(error) => {
                let _ = transport.stop_and_wait().await;
                return Err(error);
            }
        };
        Ok(StagedSshSession {
            handle: Some(handle),
            invalidated,
            transport: Some(transport),
            observed_fingerprint: fp,
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

    /// Open a command channel without sending the exec request yet. This is
    /// exposed separately so a daemon can react to IPC disconnects between
    /// channel creation and command startup and still close the channel.
    pub async fn open_exec_until(&self, deadline: tokio::time::Instant) -> Result<RunningCommand> {
        match tokio::time::timeout_at(deadline, self.handle.channel_open_session()).await {
            Ok(Ok(channel)) => Ok(RunningCommand {
                channel,
                transport: self.transport_trip(),
            }),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => {
                // russh's channel-open future is not cancellation-safe: after
                // its reply receiver is dropped the session can retain the
                // corresponding channel. Discard the transport to release it.
                self.invalidate().await;
                Err(command_deadline_error())
            }
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
                Err(error)
            }
            Err(_) => {
                command.cancel().await;
                Err(command_deadline_error())
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
        match tokio::time::timeout_at(deadline, sftp.create_dir(path)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => {
                self.invalidate().await;
                bail!("SFTP create-directory exceeded its deadline");
            }
        }
    }

    async fn open_sftp_channel_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<russh::Channel<russh::client::Msg>> {
        let mut channel =
            match tokio::time::timeout_at(deadline, self.handle.channel_open_session()).await {
                Ok(Ok(channel)) => channel,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {
                    self.invalidate().await;
                    bail!("SFTP channel setup exceeded its deadline");
                }
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
    let mut frame = crate::ipc::Frame::DirList {
        path: canonical,
        entries,
    };
    if let Err(error) =
        crate::ipc::encoded_frame_len_limited(&frame, crate::ipc::MAX_RESPONSE_FRAME)
    {
        frame.zeroize_sensitive();
        return Err(error).context("SFTP directory listing exceeds the IPC wire-size limit");
    }
    match frame {
        crate::ipc::Frame::DirList { path, entries } => Ok((path, entries)),
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
    pub async fn request_exec_until(
        &mut self,
        cmd: &str,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        match tokio::time::timeout_at(deadline, self.channel.exec(true, cmd.to_string())).await {
            Ok(result) => Ok(result?),
            Err(_) => Err(command_deadline_error()),
        }
    }

    pub async fn finish(&mut self) -> Result<ExecResult> {
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
        commit_remote_upload_no_replace_with, extend_command_output,
        protected_upload_file_attributes, push_directory_entry, read_sftp_packet,
        require_server_fingerprint, secure_client_algorithms, status_error, temporary_remote_path,
        validate_remote_command, validate_remote_path, validate_upload_remote_path,
        BoundedSftpStream, DirectoryBudget, DirectoryLimits, SshSession, TransportTrip,
        DIRECTORY_LIMITS, MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_STRING_BYTES,
        MAX_REMOTE_COMMAND_BYTES, MAX_REMOTE_PATH_BYTES, MAX_SFTP_PACKET_BYTES,
        REMOTE_PARTIAL_SUFFIX_BYTES,
    };
    use crate::vault::Creds;
    use russh::keys::ssh_key;
    use russh_sftp::client::{Config as SftpConfig, SftpSession};
    use russh_sftp::protocol::{File, FileAttributes, Status, StatusCode};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

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

        assert!(commit.used_hardlink);
        assert!(commit.partial_removed);
        assert!(!rename_called.load(Ordering::Acquire));
        assert!(unlink_called.load(Ordering::Acquire));
        assert!(committed_state.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn missing_hardlink_extension_uses_v3_rename_fallback() {
        let rename_called = Arc::new(AtomicBool::new(false));
        let unlink_called = Arc::new(AtomicBool::new(false));
        let committed_state = AtomicBool::new(false);
        let rename_flag = Arc::clone(&rename_called);
        let unlink_flag = Arc::clone(&unlink_called);
        let commit = commit_remote_upload_no_replace_with(
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
        .unwrap();

        assert!(!commit.used_hardlink);
        assert!(commit.partial_removed);
        assert!(rename_called.load(Ordering::Acquire));
        assert!(!unlink_called.load(Ordering::Acquire));
        assert!(committed_state.load(Ordering::Acquire));
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

        assert!(commit.used_hardlink);
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
    async fn repeated_kex_deadlines_close_every_proxy_connection() {
        const ATTEMPTS: usize = 100;
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
                    peer.write_all(b"SSH-2.0-serctl-kex-stall\r\n")
                        .await
                        .unwrap();
                    let mut received = Vec::new();
                    peer.read_to_end(&mut received).await.unwrap();
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
            tokio::time::timeout(Duration::from_secs(2), closed_rx.recv())
                .await
                .expect("proxy connection was not closed")
                .expect("server close channel ended early");
        }
        server.await.unwrap();
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
        let frame = crate::ipc::Frame::DirList {
            path: "/".into(),
            entries,
        };
        let encoded =
            crate::ipc::encoded_frame_len_limited(&frame, crate::ipc::MAX_RESPONSE_FRAME).unwrap();
        assert!(encoded <= crate::ipc::MAX_RESPONSE_FRAME);
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
