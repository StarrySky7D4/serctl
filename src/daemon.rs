//! Daemon: loads a profile, holds one long-lived SSH session, serves IPC.
use crate::vault::{self, now_unix, Creds, LockInfo};
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use russh::ChannelMsg;
use russh_sftp::protocol::OpenFlags;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch, Mutex, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

use crate::ipc;
use crate::ssh::{
    commit_remote_upload_no_replace, protected_upload_file_attributes, temporary_remote_path,
    validate_remote_command, validate_remote_path, validate_upload_remote_path, SshSession,
    MAX_TRANSFER_BYTES,
};

pub(crate) const CONTROL_SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const IPC_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const SHELL_INPUT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const HANDLER_SHUTDOWN_GRACE: Duration = Duration::from_secs(4);
const RUNTIME_LOCK_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const REMOTE_PARTIAL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const REMOTE_PARTIAL_CLEANUP_RETRY: Duration = Duration::from_millis(50);
const POST_AUTH_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SHELL_INPUT_BYTES: usize = 64 * 1024;
const MAX_UPLOAD_CHUNK_BYTES: usize = 64 * 1024;
const BUFFERED_HEAVY_OPERATION_LIMIT: usize = 8;

#[derive(Clone)]
struct ConnInfo {
    profile: String,
    host: String,
    user: String,
    started: i64,
    token: Arc<Zeroizing<String>>,
}

struct RuntimeLockGuard {
    cleanup: Option<RuntimeLockCleanup>,
}

struct RuntimeLockCleanup {
    profile: String,
    token: Arc<Zeroizing<String>>,
    lease: std::fs::File,
}

struct PublishedRuntime {
    listener: Option<ipc::LocalListener>,
    lock_guard: Option<RuntimeLockGuard>,
    token: Arc<Zeroizing<String>>,
}

struct RuntimePublicationCleanup {
    listener: Option<ipc::LocalListener>,
    lock_guard: Option<RuntimeLockGuard>,
}

#[derive(Debug)]
struct IpcResponseWriteFailure(String);

impl fmt::Display for IpcResponseWriteFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for IpcResponseWriteFailure {}

/// Holds the current authenticated SSH session and serializes reconnects.
/// Operations clone the current Arc, so an in-flight request is never moved
/// out from under another request while a replacement connection is created.
struct SessionManager {
    creds: Creds,
    current: RwLock<Arc<SshSession>>,
    reconnect: Mutex<()>,
}

impl SessionManager {
    fn new(creds: Creds, session: SshSession) -> Self {
        Self {
            creds,
            current: RwLock::new(Arc::new(session)),
            reconnect: Mutex::new(()),
        }
    }

    async fn current_until(&self, deadline: Instant) -> Result<Arc<SshSession>> {
        let operation = async {
            let current = self.current.read().await.clone();
            if !current.is_closed() {
                return Ok(current);
            }

            // Multiple IPC requests may observe the disconnect together. Only
            // the first authenticates; dropping a timed-out/disconnected
            // request also drops this guard so other requests are not wedged.
            let _reconnect = self.reconnect.lock().await;
            let current = self.current.read().await.clone();
            if !current.is_closed() {
                return Ok(current);
            }

            let (replacement, _) =
                SshSession::connect_until(&self.creds, self.creds.host_key.clone(), deadline)
                    .await
                    .context("reconnect SSH session")?;
            let replacement = Arc::new(replacement);
            *self.current.write().await = replacement.clone();
            Ok(replacement)
        };

        match tokio::time::timeout_at(deadline, operation).await {
            Ok(result) => result,
            Err(_) => bail!("SSH reconnect exceeded the request deadline"),
        }
    }

    async fn invalidate_current(&self) {
        self.current.read().await.invalidate().await;
    }
}

impl Drop for RuntimeLockGuard {
    fn drop(&mut self) {
        let Some(cleanup) = self.cleanup.take() else {
            return;
        };
        // Future cancellation runs destructors on a Tokio worker. Never put
        // filesystem cleanup on that worker: a stuck local filesystem syscall
        // must not wedge the UI task that is aborting this daemon. The cleanup
        // value owns the lease until token-CAS removal has completed.
        if let Err(error) = std::thread::Builder::new()
            .name("serctl-lock-cleanup".into())
            .spawn(move || {
                if let Err(error) = cleanup.run() {
                    log::warn!("runtime-lock cleanup: {error:#}");
                }
            })
        {
            // Thread creation failure drops `cleanup`, releasing the OS lease.
            // A subsequent startup can then reconcile the token-protected
            // stale record; it can never mistake this process for live.
            log::warn!("could not start runtime-lock cleanup thread: {error}");
        }
    }
}

impl Drop for PublishedRuntime {
    fn drop(&mut self) {
        let cleanup = RuntimePublicationCleanup {
            listener: self.listener.take(),
            lock_guard: self.lock_guard.take(),
        };
        if cleanup.listener.is_none() && cleanup.lock_guard.is_none() {
            return;
        }
        // Unix listener Drop removes its socket and is itself filesystem I/O.
        // Keep both listener teardown and token-CAS lock cleanup off the async
        // worker that is canceling the daemon.
        if let Err(error) = std::thread::Builder::new()
            .name("serctl-publication-cleanup".into())
            .spawn(move || {
                if let Err(error) = cleanup.run() {
                    log::warn!("runtime-publication cleanup: {error:#}");
                }
            })
        {
            log::warn!("could not start runtime-publication cleanup thread: {error}");
        }
    }
}

impl RuntimeLockCleanup {
    fn run(self) -> Result<()> {
        let remove = vault::remove_lock_if_token_while_leased(&self.profile, self.token.as_str());
        let unlock = FileExt::unlock(&self.lease).context("release daemon runtime lease");
        remove.context("remove daemon runtime lock")?;
        unlock?;
        Ok(())
    }
}

impl RuntimeLockGuard {
    fn new(profile: String, token: Arc<Zeroizing<String>>, lease: std::fs::File) -> Self {
        Self {
            cleanup: Some(RuntimeLockCleanup {
                profile,
                token,
                lease,
            }),
        }
    }

    fn cleanup_blocking(mut self) -> Result<()> {
        self.cleanup
            .take()
            .expect("runtime-lock cleanup is missing")
            .run()
    }
}

impl RuntimePublicationCleanup {
    fn run(mut self) -> Result<()> {
        // Listener closure/removal precedes lock retirement, so no connection
        // can be accepted after the discoverable record disappears.
        drop(self.listener.take());
        match self.lock_guard.take() {
            Some(lock_guard) => lock_guard.cleanup_blocking(),
            None => Ok(()),
        }
    }
}

async fn await_owned_blocking_until<T, F>(
    deadline: Instant,
    operation: F,
    description: &'static str,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let mut task = tokio::task::spawn_blocking(operation);
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(result) => result.with_context(|| format!("join {description} worker"))?,
        Err(_) => {
            // Running spawn_blocking jobs cannot be preempted. Aborting the
            // JoinHandle marks a late owned result as canceled, so its Drop
            // performs cleanup on the blocking side instead of publishing a
            // listener/lock that no async daemon will ever service.
            task.abort();
            bail!("{description} exceeded its setup deadline")
        }
    }
}

async fn publish_runtime_until(
    profile: &str,
    lease: std::fs::File,
    deadline: Instant,
) -> Result<PublishedRuntime> {
    let profile = profile.to_owned();
    await_owned_blocking_until(
        deadline,
        move || {
            if Instant::now() >= deadline {
                bail!("daemon runtime publication exceeded its setup deadline");
            }
            let token = Arc::new(Zeroizing::new(vault::new_ipc_token()));
            let listener = ipc::LocalListener::bind(&profile, token.as_str())?;
            // A blocking bind that crossed the setup deadline must never write
            // a discoverable lock. Dropping the listener also removes its Unix
            // socket (or closes its Windows pipe handle).
            if Instant::now() >= deadline {
                bail!("daemon runtime publication exceeded its setup deadline");
            }
            let endpoint = listener.endpoint().to_owned();
            // Arm cleanup before the atomic write. Even a write that commits
            // and then reports an error remains paired with the exclusive
            // lease and token-CAS cleanup.
            let lock_guard = RuntimeLockGuard::new(profile.clone(), Arc::clone(&token), lease);
            let write_result = vault::write_lock(&LockInfo {
                profile,
                protocol: ipc::IPC_PROTOCOL_VERSION,
                pid: std::process::id(),
                port: 0,
                endpoint,
                // Endpoint/user data is returned only after authentication.
                host: String::new(),
                user: String::new(),
                started_unix: now_unix(),
                token: token.as_str().to_owned(),
            });
            if let Err(error) = write_result {
                drop(listener);
                return match lock_guard.cleanup_blocking() {
                    Ok(()) => Err(error).context("publish daemon runtime lock"),
                    Err(cleanup_error) => Err(anyhow::anyhow!(
                        "{error:#}; failed publication cleanup: {cleanup_error:#}"
                    )),
                };
            }
            if Instant::now() >= deadline {
                // We are already on a blocking worker, so complete cleanup
                // here before reporting timeout rather than leave a late lock.
                drop(listener);
                lock_guard.cleanup_blocking()?;
                bail!("daemon runtime publication exceeded its setup deadline");
            }
            Ok(PublishedRuntime {
                listener: Some(listener),
                lock_guard: Some(lock_guard),
                token,
            })
        },
        "daemon runtime publication",
    )
    .await
}

async fn cleanup_published_runtime(mut published: PublishedRuntime) {
    // Stop accepting before retiring the lock. The owned cleanup job keeps the
    // lease through token-CAS removal; timeout detaches that complete job.
    let cleanup = RuntimePublicationCleanup {
        listener: published.listener.take(),
        lock_guard: published.lock_guard.take(),
    };
    let mut task = tokio::task::spawn_blocking(move || cleanup.run());
    match tokio::time::timeout(RUNTIME_LOCK_CLEANUP_TIMEOUT, &mut task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => log::warn!("runtime-lock cleanup: {error:#}"),
        Ok(Err(error)) => log::warn!("runtime-lock cleanup worker: {error}"),
        Err(_) => {
            task.abort();
            log::warn!(
                "runtime-lock cleanup exceeded {} ms; detached owned cleanup remains active",
                RUNTIME_LOCK_CLEANUP_TIMEOUT.as_millis()
            );
        }
    }
}

fn handoff_readiness(ready: Option<oneshot::Sender<()>>) -> std::result::Result<(), ()> {
    match ready {
        Some(ready) => ready.send(()),
        None => Ok(()),
    }
}

pub async fn run(profile: &str, master: Zeroizing<String>) -> Result<()> {
    run_with_ready(profile, master, None).await
}

/// Run a daemon and optionally notify an embedding UI once the IPC listener is
/// ready. Shutdown is coordinated through the async loop, so an in-process
/// daemon never terminates the whole GUI process.
pub async fn run_with_ready(
    profile: &str,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
) -> Result<()> {
    run_with_ready_until(
        profile,
        master,
        ready,
        Instant::now() + CONTROL_SETUP_TIMEOUT,
    )
    .await
}

pub(crate) async fn run_with_ready_until(
    profile: &str,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    setup_deadline: Instant,
) -> Result<()> {
    if setup_deadline <= Instant::now() {
        bail!("daemon startup exceeded its setup deadline");
    }
    // The exclusive profile lease must precede credential decryption. This
    // makes the credential snapshot and daemon lifetime one atomic use period
    // with respect to profile mutation. Both operations are synchronous and
    // may include vault-lock waiting/KDF work, so keep them off the async
    // runtime and bound vault-lock acquisition by the whole setup deadline.
    let profile_owned = profile.to_owned();
    let mut snapshot = tokio::task::spawn_blocking(move || {
        let lease = vault::acquire_runtime_lease(&profile_owned)?;
        let lock_timeout = setup_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("daemon credential snapshot exceeded its setup deadline")?;
        let creds = vault::decrypt_with_lock_timeout(&profile_owned, &master, lock_timeout)?;
        Ok::<_, anyhow::Error>((creds, master, lease))
    });
    let (creds, master, lease) = match tokio::time::timeout_at(setup_deadline, &mut snapshot).await
    {
        Ok(result) => result.context("join daemon credential snapshot worker")??,
        Err(_) => {
            // `spawn_blocking` cannot preempt active filesystem/KDF work. The
            // worker retains the exclusive lease and Zeroizing master until
            // it finishes, so a late snapshot cannot race profile mutation.
            snapshot.abort();
            bail!("daemon credential snapshot exceeded its setup deadline")
        }
    };
    run_with_ready_and_lease(profile, creds, master, ready, lease, setup_deadline).await
}

#[cfg(test)]
pub async fn run_with_ready_creds_for_test(
    profile: &str,
    creds: Creds,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
) -> Result<()> {
    let setup_deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
    let profile_owned = profile.to_owned();
    let mut lease_task =
        tokio::task::spawn_blocking(move || vault::acquire_runtime_lease(&profile_owned));
    let lease = match tokio::time::timeout_at(setup_deadline, &mut lease_task).await {
        Ok(result) => result.context("join daemon test runtime-lease worker")??,
        Err(_) => {
            lease_task.abort();
            bail!("daemon runtime-lease acquisition exceeded its setup deadline")
        }
    };
    run_with_ready_and_lease(profile, creds, master, ready, lease, setup_deadline).await
}

fn recover_invalid_startup_lock_read<T, C, R>(
    read: Result<Option<T>>,
    cleanup: C,
    reread: R,
) -> Result<Option<T>>
where
    C: FnOnce() -> Result<bool>,
    R: FnOnce() -> Result<Option<T>>,
{
    match read {
        Ok(existing) => Ok(existing),
        Err(read_error) => match cleanup() {
            // A successfully removed hashed record may have shadowed a raw
            // legacy Unix lock. Startup already holds the exclusive lifetime
            // lease, but must still reread the full namespace and fail closed
            // on that legacy record rather than start a second daemon.
            Ok(true) => reread(),
            Ok(false) => Err(read_error
                .context("invalid runtime lock was not eligible for safe protocol-v2 recovery")),
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "{read_error:#}; malformed runtime-lock recovery failed: {cleanup_error:#}"
            )),
        },
    }
}

async fn run_with_ready_and_lease(
    profile: &str,
    creds: Creds,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    lease: std::fs::File,
    connect_deadline: Instant,
) -> Result<()> {
    let profile_owned = profile.to_owned();
    let mut lock_read = tokio::task::spawn_blocking(move || {
        let existing = recover_invalid_startup_lock_read(
            vault::read_lock(&profile_owned),
            || vault::remove_invalid_hashed_v2_lock_while_leased(&profile_owned),
            || vault::read_lock(&profile_owned),
        )?;
        Ok::<_, anyhow::Error>((lease, existing))
    });
    let (lease, existing) = match tokio::time::timeout_at(connect_deadline, &mut lock_read).await {
        Ok(result) => result.context("join daemon startup-lock read worker")??,
        Err(_) => {
            // A running worker retains the exclusive lifetime lease until its
            // bounded lock-file I/O completes. Aborting only prevents a queued
            // job from starting.
            lock_read.abort();
            bail!("daemon startup-lock read exceeded its setup deadline")
        }
    };
    if let Some(mut existing) = existing {
        if existing_daemon_is_live(&existing, connect_deadline).await? {
            bail!("a daemon is already running for '{profile}'");
        }
        let profile_owned = profile.to_owned();
        let expected_token = Zeroizing::new(std::mem::take(&mut existing.token));
        let mut stale_cleanup = tokio::task::spawn_blocking(move || {
            let removed =
                vault::remove_lock_if_token_while_leased(&profile_owned, &expected_token)?;
            Ok::<_, anyhow::Error>((lease, removed))
        });
        let (returned_lease, removed) =
            match tokio::time::timeout_at(connect_deadline, &mut stale_cleanup).await {
                Ok(result) => result.context("join daemon stale-lock cleanup worker")??,
                Err(_) => {
                    stale_cleanup.abort();
                    bail!("daemon stale-lock cleanup exceeded its setup deadline")
                }
            };
        if !removed {
            bail!("stale runtime lock changed while daemon startup held the profile lease");
        }
        // Rebind the same exclusive lease returned by the blocking cleanup so
        // it remains held through KEX, pin persistence, authentication, and
        // the complete daemon lifetime.
        let lease = returned_lease;
        return run_after_startup_lock_reconciliation(
            profile,
            creds,
            master,
            ready,
            lease,
            connect_deadline,
        )
        .await;
    }
    run_after_startup_lock_reconciliation(profile, creds, master, ready, lease, connect_deadline)
        .await
}

async fn run_after_startup_lock_reconciliation(
    profile: &str,
    mut creds: Creds,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    lease: std::fs::File,
    connect_deadline: Instant,
) -> Result<()> {
    let expect = creds.host_key.clone();
    let staged = SshSession::connect_key_exchange_until(&creds, expect, connect_deadline).await?;
    let fp = staged.observed_fingerprint().to_owned();
    let lease = if creds.host_key.is_none() {
        let profile_owned = profile.to_owned();
        let persisted_fp = fp.clone();
        let pin_master = Zeroizing::new(master.as_str().to_owned());
        let mut task = tokio::task::spawn_blocking(move || {
            let lock_timeout = connect_deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("daemon host-key pin persistence exceeded its setup deadline")?;
            vault::set_pinned_fp_with_lock_timeout(
                &profile_owned,
                persisted_fp,
                &pin_master,
                lock_timeout,
            )?;
            // Keep the exclusive runtime lease in the worker. If the async
            // setup deadline fires while a blocking filesystem/KDF operation
            // is already running, a late atomic pin cannot race profile
            // replacement or a second unpinned connection.
            Ok::<_, anyhow::Error>(lease)
        });
        let persisted = match tokio::time::timeout_at(connect_deadline, &mut task).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                staged.abort().await;
                return Err(error).context("join daemon host-key pin persistence worker");
            }
            Err(_) => {
                task.abort();
                staged.abort().await;
                bail!("daemon host-key pin persistence exceeded its setup deadline")
            }
        };
        let lease = match persisted {
            Ok(lease) => lease,
            Err(error) => {
                staged.abort().await;
                return Err(error);
            }
        };
        eprintln!("[serctl] pinned host key {fp}");
        creds.host_key = Some(fp);
        lease
    } else {
        lease
    };
    let session = staged
        .authenticate_password_until(&creds.user, &creds.password, connect_deadline)
        .await?;
    // The master password is only needed to decrypt the profile and persist a
    // first-use host-key pin. Do not retain it for the daemon lifetime.
    drop(master);
    let host = creds.host.clone();
    let user = creds.user.clone();
    let session = Arc::new(SessionManager::new(creds, session));

    let mut published = match publish_runtime_until(profile, lease, connect_deadline).await {
        Ok(published) => published,
        Err(error) => {
            // Authentication has already succeeded. Explicitly stop its
            // transport while a late blocking publisher cleans only local
            // resources; the publisher never owns or retains this session.
            session.invalidate_current().await;
            return Err(error);
        }
    };
    let token = Arc::clone(&published.token);
    let endpoint = published
        .listener
        .as_ref()
        .expect("published runtime listener is missing")
        .endpoint()
        .to_owned();
    if handoff_readiness(ready).is_err() {
        // The embedding caller abandoned startup before accepting ownership.
        // Do not leave a successfully published daemon behind.
        session.invalidate_current().await;
        cleanup_published_runtime(published).await;
        bail!("daemon readiness receiver disconnected before publication handoff");
    }

    eprintln!(
        "[serctl] daemon up: profile={profile}  {host}:{ssh} as {user}  ipc={kind}:{endpoint}  (Ctrl-C to stop)",
        host = host,
        ssh = session.creds.port,
        user = user,
        kind = ipc::endpoint_kind(),
    );

    let info = ConnInfo {
        profile: profile.to_string(),
        host,
        user,
        started: now_unix(),
        token,
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut daemon_shutdown = shutdown_rx.clone();
    let connection_slots = Arc::new(Semaphore::new(64));
    let buffered_operation_slots = Arc::new(Semaphore::new(BUFFERED_HEAVY_OPERATION_LIMIT));
    let mut handlers = JoinSet::new();

    let mut listener_error = None;
    loop {
        tokio::select! {
            res = published
                .listener
                .as_mut()
                .expect("published runtime listener is missing")
                .accept() => {
                let stream = match res {
                    Ok(stream) => stream,
                    Err(error) => {
                        listener_error = Some(error.context("accept local IPC connection"));
                        break;
                    }
                };
                let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
                    log::warn!("rejecting IPC connection: connection limit reached");
                    continue;
                };
                log::debug!("local IPC connection accepted");
                let s = session.clone();
                let i = info.clone();
                let shutdown = shutdown_tx.clone();
                let handler_shutdown = shutdown_rx.clone();
                let buffered_operations = Arc::clone(&buffered_operation_slots);
                handlers.spawn(async move {
                    let _permit = permit;
                    handle_conn(
                        s,
                        stream,
                        i,
                        shutdown,
                        handler_shutdown,
                        buffered_operations,
                    )
                    .await
                });
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[serctl] shutting down");
                break;
            }
            changed = daemon_shutdown.changed() => {
                if changed.is_ok() && *daemon_shutdown.borrow() {
                    eprintln!("[serctl] shutdown requested");
                    break;
                }
            }
            joined = handlers.join_next(), if !handlers.is_empty() => {
                log_handler_result(joined);
            }
        }
    }

    // Stop accepting first, then wake every live handler so it can explicitly
    // close remote channels before the daemon drops its runtime lock/session.
    let _ = shutdown_tx.send(true);
    let drained = tokio::time::timeout(HANDLER_SHUTDOWN_GRACE, async {
        while let Some(joined) = handlers.join_next().await {
            log_handler_result(Some(joined));
        }
    })
    .await;
    if drained.is_err() {
        log::warn!("IPC handlers did not stop within shutdown grace; aborting them");
        handlers.abort_all();
        while let Some(joined) = handlers.join_next().await {
            log_handler_result(Some(joined));
        }
    }
    session.invalidate_current().await;
    let result = match listener_error {
        Some(error) => Err(error),
        None => Ok(()),
    };
    cleanup_published_runtime(published).await;
    result
}

fn log_handler_result(joined: Option<Result<Result<()>, tokio::task::JoinError>>) {
    match joined {
        Some(Ok(Err(error))) => log::warn!("ipc handler: {error:#}"),
        Some(Err(error)) if !error.is_cancelled() => log::warn!("ipc handler task: {error}"),
        _ => {}
    }
}

struct ZeroizingResponseFrame(ipc::Frame);

impl Drop for ZeroizingResponseFrame {
    fn drop(&mut self) {
        self.0.zeroize_sensitive();
    }
}

/// Bound every daemon-to-client response write independently, while also
/// preserving the request's absolute deadline. A client that stops reading
/// cannot retain a handler slot until the daemon-wide shutdown grace expires.
async fn write_frame_until<W>(
    writer: &mut W,
    frame: &ipc::Frame,
    request_deadline: Instant,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if request_deadline <= Instant::now() {
        return Err(
            IpcResponseWriteFailure("IPC response write exceeded its deadline".into()).into(),
        );
    }
    let write_deadline = request_deadline.min(Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT);
    let max_frame = match frame {
        ipc::Frame::ShellOut { .. } | ipc::Frame::ShellClosed => ipc::MAX_SHELL_FRAME,
        ipc::Frame::Ack
        | ipc::Frame::TransferDone { .. }
        | ipc::Frame::StatusInfo { .. }
        | ipc::Frame::Error { .. } => ipc::MAX_CONTROL_FRAME,
        _ => ipc::MAX_RESPONSE_FRAME,
    };
    match tokio::time::timeout_at(
        write_deadline,
        ipc::write_frame_limited(writer, frame, max_frame),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            Err(IpcResponseWriteFailure(format!("IPC response write failed: {error:#}")).into())
        }
        Err(_) => {
            Err(IpcResponseWriteFailure("IPC response write exceeded its deadline".into()).into())
        }
    }
}

async fn write_frame_or_shutdown<W>(
    writer: &mut W,
    frame: &ipc::Frame,
    request_deadline: Instant,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if *shutdown.borrow() {
        return Err(IpcResponseWriteFailure(
            "daemon shutting down during IPC response write".into(),
        )
        .into());
    }
    tokio::select! {
        result = write_frame_until(writer, frame, request_deadline) => result,
        _ = shutdown.changed() => Err(IpcResponseWriteFailure(
            "daemon shutting down during IPC response write".into(),
        ).into()),
    }
}

async fn write_owned_frame_or_shutdown<W>(
    writer: &mut W,
    frame: ipc::Frame,
    request_deadline: Instant,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = ZeroizingResponseFrame(frame);
    write_frame_or_shutdown(writer, &frame.0, request_deadline, shutdown).await
}

async fn write_all_until_or_shutdown<W>(
    writer: &mut W,
    data: &[u8],
    write_deadline: Instant,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if *shutdown.borrow() {
        bail!("daemon shutting down during SSH shell input write");
    }
    if write_deadline <= Instant::now() {
        bail!("SSH shell input write exceeded its deadline");
    }
    tokio::select! {
        result = tokio::time::timeout_at(write_deadline, writer.write_all(data)) => match result {
            Ok(result) => result.context("write SSH shell input"),
            Err(_) => bail!("SSH shell input write exceeded its deadline"),
        },
        _ = shutdown.changed() => bail!("daemon shutting down during SSH shell input write"),
    }
}

async fn existing_daemon_is_live(lock: &LockInfo, setup_deadline: Instant) -> Result<bool> {
    let deadline = (Instant::now() + Duration::from_millis(800)).min(setup_deadline);
    if deadline <= Instant::now() {
        bail!("daemon startup exceeded its setup deadline");
    }
    let probe = async {
        ipc::validate_endpoint(&lock.profile, &lock.token, &lock.endpoint)?;
        let mut stream = ipc::connect(&lock.endpoint).await?;
        ipc::validate_server_identity(&stream, lock.pid)?;
        ipc::authenticate_client(&mut stream, &lock.profile, &lock.token, deadline).await?;
        Ok::<bool, anyhow::Error>(true)
    };
    let result = matches!(tokio::time::timeout_at(deadline, probe).await, Ok(Ok(true)));
    if !result && Instant::now() >= setup_deadline {
        bail!("daemon startup exceeded its setup deadline");
    }
    Ok(result)
}

fn validate_request_frame(frame: &ipc::Frame) -> Result<()> {
    match frame {
        ipc::Frame::Exec { cmd, .. } => validate_remote_command(cmd)?,
        ipc::Frame::Shell { cols, rows }
            if !(1..=10_000).contains(cols) || !(1..=10_000).contains(rows) =>
        {
            bail!("shell dimensions must be between 1 and 10000");
        }
        ipc::Frame::ShellInput { data } if data.len() > MAX_SHELL_INPUT_BYTES => {
            bail!("shell input exceeds {MAX_SHELL_INPUT_BYTES} bytes");
        }
        ipc::Frame::ListDir { path, .. } => validate_remote_path(path, true)?,
        ipc::Frame::CreateDir { path, .. } | ipc::Frame::Download { path, .. } => {
            validate_remote_path(path, false)?
        }
        ipc::Frame::UploadBegin { path, size, .. } => {
            validate_upload_remote_path(path)?;
            if *size > MAX_TRANSFER_BYTES {
                bail!(
                    "upload exceeds the {} byte safety limit",
                    MAX_TRANSFER_BYTES
                );
            }
        }
        ipc::Frame::UploadChunk { data } if data.len() > MAX_UPLOAD_CHUNK_BYTES => {
            bail!("upload chunk exceeds {MAX_UPLOAD_CHUNK_BYTES} bytes");
        }
        _ => {}
    }
    Ok(())
}

async fn read_authenticated_request<R>(
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    idle_timeout: Duration,
) -> Result<Option<ipc::Frame>>
where
    R: AsyncRead + Unpin,
{
    let idle_deadline = Instant::now() + idle_timeout;
    tokio::select! {
        result = tokio::time::timeout_at(
            idle_deadline,
            ipc::read_frame_limited(reader, ipc::MAX_REQUEST_FRAME),
        ) => match result {
            Ok(result) => result,
            Err(_) => bail!("authenticated IPC connection exceeded its idle deadline"),
        },
        _ = shutdown.changed() => Ok(None),
    }
}

async fn authenticate_incoming_protocol<S>(
    stream: &mut S,
    profile: &str,
    token: &str,
    deadline: Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ipc::authenticate_server(stream, profile, token, deadline).await
}

/// Exec and directory listing retain their complete result until it has been
/// serialized to IPC. Bound that aggregate independently from the connection
/// limit so many authenticated peers cannot retain hundreds of MiB at once.
/// Waiting for capacity is still part of the request's absolute deadline and
/// is cancelled immediately when its IPC peer or the daemon disappears.
async fn acquire_buffered_operation_slot<R>(
    slots: Arc<Semaphore>,
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<Option<OwnedSemaphorePermit>>
where
    R: AsyncRead + Unpin,
{
    if *shutdown.borrow() {
        return Ok(None);
    }
    tokio::select! {
        biased;
        _ = shutdown.changed() => Ok(None),
        _ = reader.read_u8() => Ok(None),
        result = tokio::time::timeout_at(deadline, slots.acquire_owned()) => match result {
            Ok(Ok(permit)) => Ok(Some(permit)),
            Ok(Err(_)) => bail!("buffered-operation capacity is unavailable"),
            Err(_) => bail!("waiting for buffered-operation capacity exceeded the request deadline"),
        },
    }
}

async fn handle_conn<S>(
    sessions: Arc<SessionManager>,
    mut stream: S,
    info: ConnInfo,
    shutdown: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
    buffered_operation_slots: Arc<Semaphore>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let authentication_deadline = Instant::now() + Duration::from_secs(2);
    let authentication = tokio::select! {
        result = authenticate_incoming_protocol(
            &mut stream,
            &info.profile,
            info.token.as_str(),
            authentication_deadline,
        ) => result,
        _ = shutdown_rx.changed() => return Ok(()),
    };
    if let Err(error) = authentication {
        // Authentication failures are intentionally indistinguishable to the
        // peer: close without sending a structured error oracle.
        log::warn!("rejected local IPC authentication: {error:#}");
        return Ok(());
    }
    let (mut rd, mut wr) = tokio::io::split(stream);
    loop {
        let frame =
            read_authenticated_request(&mut rd, &mut shutdown_rx, POST_AUTH_IDLE_TIMEOUT).await?;
        let Some(mut frame) = frame else {
            break;
        };
        if let Err(error) = validate_request_frame(&frame) {
            frame.zeroize_sensitive();
            write_owned_frame_or_shutdown(
                &mut wr,
                ipc::Frame::Error {
                    msg: error.to_string(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
            continue;
        }
        match frame {
            ipc::Frame::Exec { cmd, timeout_ms } => {
                let cmd = Zeroizing::new(cmd);
                let timeout = match validated_exec_timeout(timeout_ms) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                };
                let deadline = Instant::now() + timeout;
                let _buffered_operation_permit = match acquire_buffered_operation_slot(
                    Arc::clone(&buffered_operation_slots),
                    &mut rd,
                    &mut shutdown_rx,
                    deadline,
                )
                .await
                {
                    Ok(Some(permit)) => permit,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                };
                let session =
                    match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline)
                        .await
                    {
                        Ok(Some(session)) => session,
                        Ok(None) => return Ok(()),
                        Err(error) => {
                            write_owned_frame_or_shutdown(
                                &mut wr,
                                ipc::Frame::Error {
                                    msg: error.to_string(),
                                },
                                deadline,
                                &mut shutdown_rx,
                            )
                            .await?;
                            continue;
                        }
                    };
                let mut command = match tokio::select! {
                    result = session.open_exec_until(deadline) => Some(result),
                    _ = rd.read_u8() => None,
                    _ = shutdown_rx.changed() => None,
                } {
                    Some(Ok(command)) => command,
                    None => {
                        session.invalidate().await;
                        return Ok(());
                    }
                    Some(Err(error)) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                };
                let requested = tokio::select! {
                    result = command.request_exec_until(cmd.as_str(), deadline) => Some(result),
                    _ = rd.read_u8() => None,
                    _ = shutdown_rx.changed() => None,
                };
                match requested {
                    Some(Ok(())) => {}
                    None => {
                        command.cancel().await;
                        return Ok(());
                    }
                    Some(Err(error)) => {
                        command.cancel().await;
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                }
                tokio::select! {
                    result = tokio::time::timeout_at(deadline, command.finish()) => match result {
                        Ok(Ok(result)) => {
                            let code = result.code;
                            let stdout = ZeroizingResponseFrame(ipc::Frame::ExecOut {
                                data: result.stdout,
                            });
                            let stderr = ZeroizingResponseFrame(ipc::Frame::ExecErr {
                                data: result.stderr,
                            });
                            write_frame_or_shutdown(
                                &mut wr,
                                &stdout.0,
                                deadline,
                                &mut shutdown_rx,
                            ).await?;
                            write_frame_or_shutdown(
                                &mut wr,
                                &stderr.0,
                                deadline,
                                &mut shutdown_rx,
                            ).await?;
                            write_frame_or_shutdown(
                                &mut wr,
                                &ipc::Frame::ExecExit { code },
                                deadline,
                                &mut shutdown_rx,
                            ).await?;
                        }
                        Ok(Err(error)) => {
                            command.cancel().await;
                            write_owned_frame_or_shutdown(
                                &mut wr,
                                ipc::Frame::Error { msg: error.to_string() },
                                deadline,
                                &mut shutdown_rx,
                            ).await?;
                        }
                        Err(_) => {
                            command.cancel().await;
                            write_owned_frame_or_shutdown(
                                &mut wr,
                                ipc::Frame::Error {
                                    msg: format!("remote command exceeded its deadline of {} ms", timeout.as_millis()),
                                },
                                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                                &mut shutdown_rx,
                            ).await?;
                        }
                    },
                    _ = rd.read_u8() => {
                        command.cancel().await;
                        return Ok(());
                    }
                    _ = shutdown_rx.changed() => {
                        command.cancel().await;
                        return Ok(());
                    }
                }
            }
            ipc::Frame::Shell { cols, rows } => {
                let deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
                let session =
                    match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline)
                        .await
                    {
                        Ok(Some(session)) => session,
                        Ok(None) => return Ok(()),
                        Err(error) => {
                            write_owned_frame_or_shutdown(
                                &mut wr,
                                ipc::Frame::Error {
                                    msg: error.to_string(),
                                },
                                deadline,
                                &mut shutdown_rx,
                            )
                            .await?;
                            continue;
                        }
                    };
                let shell = tokio::select! {
                    result = tokio::time::timeout_at(
                        deadline,
                        session.pty_shell("xterm-256color", cols, rows),
                    ) => Some(result),
                    _ = rd.read_u8() => None,
                    _ = shutdown_rx.changed() => None,
                };
                let shell = match shell {
                    Some(Ok(result)) => result,
                    Some(Err(_)) => {
                        session.invalidate().await;
                        Err(anyhow::anyhow!("SSH shell setup exceeded its deadline"))
                    }
                    None => {
                        session.invalidate().await;
                        return Ok(());
                    }
                };
                match shell {
                    Ok(mut ch) => {
                        let mut writer = ch.make_writer();
                        let (shell_frame_tx, mut shell_frame_rx) = mpsc::channel(1);
                        let shell_frame_pump = read_shell_frame_pump(&mut rd, shell_frame_tx);
                        tokio::pin!(shell_frame_pump);
                        let mut shell_frame_pump_running = true;
                        let shell_result: Result<()> = async {
                            write_frame_or_shutdown(
                                &mut wr,
                                &ipc::Frame::Ack,
                                deadline,
                                &mut shutdown_rx,
                            )
                            .await?;
                            loop {
                                tokio::select! {
                                    biased;
                                    _ = shutdown_rx.changed() => break,
                                    frame = shell_frame_rx.recv() => match frame.map(ZeroizingShellFrameRead::into_inner) {
                                        Some(Ok(Some(ipc::Frame::ShellInput { data }))) => {
                                            let mut data = Zeroizing::new(data);
                                            if data.len() > MAX_SHELL_INPUT_BYTES {
                                                data.zeroize();
                                                bail!("shell input exceeds {MAX_SHELL_INPUT_BYTES} bytes");
                                            }
                                            let write = write_all_until_or_shutdown(
                                                &mut writer,
                                                &data,
                                                Instant::now() + SHELL_INPUT_WRITE_TIMEOUT,
                                                &mut shutdown_rx,
                                            ).await;
                                            data.zeroize();
                                            write?;
                                        }
                                        Some(Ok(Some(mut frame))) => {
                                            frame.zeroize_sensitive();
                                            bail!("unexpected frame during shell session")
                                        }
                                        Some(Ok(None)) | None => break,
                                        Some(Err(error)) => return Err(error),
                                    },
                                    () = &mut shell_frame_pump, if shell_frame_pump_running => {
                                        // The terminal EOF/error event is queued before
                                        // this future completes; consume it next.
                                        shell_frame_pump_running = false;
                                    },
                                    msg = ch.wait() => match msg {
                                        Some(ChannelMsg::Data { data }) => {
                                            let frame = ZeroizingResponseFrame(
                                                ipc::Frame::ShellOut { data: data.to_vec() }
                                            );
                                            write_frame_or_shutdown(
                                                &mut wr,
                                                &frame.0,
                                                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                                                &mut shutdown_rx,
                                            ).await?;
                                        }
                                        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                                            let frame = ZeroizingResponseFrame(
                                                ipc::Frame::ShellOut { data: data.to_vec() }
                                            );
                                            write_frame_or_shutdown(
                                                &mut wr,
                                                &frame.0,
                                                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                                                &mut shutdown_rx,
                                            ).await?;
                                        }
                                        Some(ChannelMsg::ExtendedData { ext, .. }) => {
                                            bail!("remote shell returned unsupported extended-data type {ext}");
                                        }
                                        Some(ChannelMsg::Eof) | None => {
                                            write_frame_or_shutdown(
                                                &mut wr,
                                                &ipc::Frame::ShellClosed,
                                                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                                                &mut shutdown_rx,
                                            ).await?;
                                            break;
                                        }
                                        _ => {}
                                    },
                                }
                            }
                            Ok(())
                        }
                        .await;
                        zeroize_pending_shell_frames(&mut shell_frame_rx);
                        drop(writer);
                        let _ = session.terminate_channel(&mut ch, true).await;
                        // Shell IPC connections are dedicated sessions. Once
                        // the remote channel ends (or shutdown/cancellation is
                        // observed), close the IPC handler instead of returning
                        // to the top-level frame loop with a consumed watch
                        // notification.
                        return shell_result;
                    }
                    Err(e) => {
                        session.invalidate().await;
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error { msg: e.to_string() },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                    }
                }
            }
            ipc::Frame::Status => {
                let deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
                    Ok(Some(_)) => {}
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                }
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::StatusInfo {
                        profile: info.profile.clone(),
                        host: info.host.clone(),
                        user: info.user.clone(),
                        started_unix: info.started,
                    },
                    deadline,
                    &mut shutdown_rx,
                )
                .await?;
            }
            ipc::Frame::ListDir { path, timeout_ms } => {
                let timeout = match validated_sftp_timeout(timeout_ms) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                };
                let deadline = Instant::now() + timeout;
                let _buffered_operation_permit = match acquire_buffered_operation_slot(
                    Arc::clone(&buffered_operation_slots),
                    &mut rd,
                    &mut shutdown_rx,
                    deadline,
                )
                .await
                {
                    Ok(Some(permit)) => permit,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                };
                let session =
                    match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline)
                        .await
                    {
                        Ok(Some(session)) => session,
                        Ok(None) => return Ok(()),
                        Err(error) => {
                            write_owned_frame_or_shutdown(
                                &mut wr,
                                ipc::Frame::Error {
                                    msg: error.to_string(),
                                },
                                deadline,
                                &mut shutdown_rx,
                            )
                            .await?;
                            continue;
                        }
                    };
                let result = match tokio::select! {
                    result = session.list_dir_until(&path, deadline) => Some(result),
                    _ = rd.read_u8() => None,
                    _ = shutdown_rx.changed() => None,
                } {
                    Some(result) => result,
                    None => {
                        session.invalidate().await;
                        return Ok(());
                    }
                };
                match result {
                    Ok((path, entries)) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::DirList { path, entries },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                    }
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                    }
                }
            }
            ipc::Frame::CreateDir { path, timeout_ms } => {
                let timeout = match validated_sftp_timeout(timeout_ms) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                };
                let deadline = Instant::now() + timeout;
                let session =
                    match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline)
                        .await
                    {
                        Ok(Some(session)) => session,
                        Ok(None) => return Ok(()),
                        Err(error) => {
                            write_owned_frame_or_shutdown(
                                &mut wr,
                                ipc::Frame::Error {
                                    msg: error.to_string(),
                                },
                                deadline,
                                &mut shutdown_rx,
                            )
                            .await?;
                            continue;
                        }
                    };
                let result = match tokio::select! {
                    result = session.create_dir_until(&path, deadline) => Some(result),
                    _ = rd.read_u8() => None,
                    _ = shutdown_rx.changed() => None,
                } {
                    Some(result) => result,
                    None => {
                        session.invalidate().await;
                        return Ok(());
                    }
                };
                match result {
                    Ok(()) => {
                        write_frame_or_shutdown(
                            &mut wr,
                            &ipc::Frame::Ack,
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                    }
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                    }
                }
            }
            ipc::Frame::Download { path, timeout_ms } => {
                let timeout = match validated_sftp_timeout(timeout_ms) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                };
                let deadline = Instant::now() + timeout;
                let session =
                    match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline)
                        .await
                    {
                        Ok(Some(session)) => session,
                        Ok(None) => return Ok(()),
                        Err(error) => {
                            write_owned_frame_or_shutdown(
                                &mut wr,
                                ipc::Frame::Error {
                                    msg: error.to_string(),
                                },
                                deadline,
                                &mut shutdown_rx,
                            )
                            .await?;
                            continue;
                        }
                    };
                let result = match tokio::select! {
                    result = serve_download(&session, &mut wr, &path, timeout_ms, deadline) => Some(result),
                    _ = rd.read_u8() => None,
                    _ = shutdown_rx.changed() => None,
                } {
                    Some(result) => result,
                    None => {
                        session.invalidate().await;
                        return Ok(());
                    }
                };
                if let Err(error) = result {
                    // A timed-out/failed frame may already be partially
                    // written. Close this IPC connection instead of appending
                    // an Error frame to a now-ambiguous byte stream.
                    if error.is::<IpcResponseWriteFailure>() {
                        return Err(error);
                    }
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                }
            }
            ipc::Frame::UploadBegin {
                path,
                size,
                timeout_ms,
            } => {
                let timeout = match validated_sftp_timeout(timeout_ms) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        continue;
                    }
                };
                let deadline = Instant::now() + timeout;
                let session =
                    match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline)
                        .await
                    {
                        Ok(Some(session)) => session,
                        Ok(None) => return Ok(()),
                        Err(error) => {
                            write_owned_frame_or_shutdown(
                                &mut wr,
                                ipc::Frame::Error {
                                    msg: error.to_string(),
                                },
                                deadline,
                                &mut shutdown_rx,
                            )
                            .await?;
                            continue;
                        }
                    };
                let upload = serve_upload(
                    &session,
                    &mut rd,
                    &mut wr,
                    UploadRequest {
                        path: &path,
                        size,
                        timeout_ms,
                        deadline,
                    },
                    &mut shutdown_rx,
                )
                .await;
                if let Err(error) = upload {
                    // See the download path above: never reuse an IPC stream
                    // after a response write may have stopped mid-frame.
                    if error.is::<IpcResponseWriteFailure>() {
                        return Err(error);
                    }
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                }
                // Upload owns the remainder of this authenticated IPC
                // connection. Its frame reader can be cancelled after a
                // partial header/payload by a request deadline, daemon
                // shutdown, or a competing remote SFTP step. Closing the
                // connection after the terminal response prevents the outer
                // request loop from ever treating a partial upload frame as a
                // new request header.
                return Ok(());
            }
            ipc::Frame::Shutdown => {
                write_frame_or_shutdown(
                    &mut wr,
                    &ipc::Frame::Ack,
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await?;
                let _ = shutdown.send(true);
                break;
            }
            mut unexpected => {
                unexpected.zeroize_sensitive();
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error {
                        msg: "unexpected frame".into(),
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn current_or_disconnect<R>(
    sessions: &SessionManager,
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<Option<Arc<SshSession>>>
where
    R: AsyncRead + Unpin,
{
    tokio::select! {
        result = sessions.current_until(deadline) => result.map(Some),
        _ = reader.read_u8() => Ok(None),
        _ = shutdown.changed() => Ok(None),
    }
}

/// Keep a single frame decoder alive while remote shell output, local shell
/// input, and daemon shutdown race. Cancelling and recreating the decoder after
/// a partial header/payload read would permanently desynchronize the dedicated
/// shell connection.
struct ZeroizingShellFrameRead {
    result: Result<Option<ipc::Frame>>,
    drop_observer: Option<Arc<AtomicBool>>,
}

impl ZeroizingShellFrameRead {
    fn new(result: Result<Option<ipc::Frame>>, drop_observer: Option<Arc<AtomicBool>>) -> Self {
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
            observer.store(true, Ordering::Release);
        }
    }
}

async fn read_shell_frame_pump_inner<R>(
    reader: &mut R,
    sender: mpsc::Sender<ZeroizingShellFrameRead>,
    drop_observer: Option<Arc<AtomicBool>>,
    construction_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let result = ipc::read_frame_limited(reader, ipc::MAX_SHELL_FRAME).await;
        let terminal = !matches!(&result, Ok(Some(_)));
        if let Some(observer) = &construction_observer {
            observer.fetch_add(1, Ordering::Release);
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

async fn serve_download<W>(
    session: &SshSession,
    writer: &mut W,
    path: &str,
    timeout_ms: u64,
    deadline: Instant,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let operation = async {
        let sftp = session.sftp_until(deadline).await?;
        let mut file = sftp.open(path).await?;
        let mut transferred = 0_u64;
        let mut buffer = Zeroizing::new(vec![0_u8; 32 * 1024]);
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                file.shutdown().await?;
                write_frame_until(
                    writer,
                    &ipc::Frame::TransferDone { bytes: transferred },
                    deadline,
                )
                .await?;
                return Ok(());
            }
            transferred = transferred
                .checked_add(read as u64)
                .ok_or_else(|| anyhow::anyhow!("download size overflow"))?;
            if transferred > MAX_TRANSFER_BYTES {
                bail!(
                    "download exceeds the {} byte safety limit",
                    MAX_TRANSFER_BYTES
                );
            }
            let frame = ZeroizingResponseFrame(ipc::Frame::FileChunk {
                data: buffer[..read].to_vec(),
            });
            write_frame_until(writer, &frame.0, deadline).await?;
        }
    };
    match tokio::time::timeout_at(deadline, operation).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            // A blocked/broken IPC consumer says nothing about the SSH/SFTP
            // protocol state. The current SFTP request has already completed
            // before its FileChunk is written, and dropping the file/session
            // closes only that channel. Invalidating the daemon-wide shared
            // SSH transport here would let one authenticated client that stops
            // reading a download tear down every unrelated exec/shell/transfer.
            if !error.is::<IpcResponseWriteFailure>() {
                session.invalidate().await;
            }
            Err(error)
        }
        Err(_) => {
            session.invalidate().await;
            bail!("SFTP download exceeded its deadline of {timeout_ms} ms")
        }
    }
}

struct UploadRequest<'a> {
    path: &'a str,
    size: u64,
    timeout_ms: u64,
    deadline: Instant,
}

async fn upload_remote_step<R, F, T>(
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Instant,
    uncertain: &AtomicBool,
    operation: F,
) -> Result<T>
where
    R: AsyncRead + Unpin,
    F: std::future::Future<Output = Result<T>>,
{
    tokio::select! {
        result = tokio::time::timeout_at(deadline, operation) => match result {
            Ok(result) => result,
            Err(_) => {
                uncertain.store(true, Ordering::Release);
                bail!("SFTP upload exceeded its deadline")
            }
        },
        disconnected = reader.read_u8() => {
            uncertain.store(true, Ordering::Release);
            match disconnected {
                Ok(_) => bail!("client sent data before the previous upload chunk was acknowledged"),
                Err(_) => bail!("client disconnected during remote upload operation"),
            }
        },
        _ = shutdown.changed() => {
            uncertain.store(true, Ordering::Release);
            bail!("daemon shutting down during upload")
        },
    }
}

async fn serve_upload<R, W>(
    session: &SshSession,
    reader: &mut R,
    writer: &mut W,
    request: UploadRequest<'_>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let UploadRequest {
        path,
        size,
        timeout_ms,
        deadline,
    } = request;
    let sftp = match tokio::select! {
        result = session.sftp_until(deadline) => Some(result),
        _ = reader.read_u8() => None,
        _ = shutdown.changed() => None,
    } {
        Some(result) => result?,
        None => {
            session.invalidate().await;
            bail!("upload setup canceled before it completed")
        }
    };
    let partial = temporary_remote_path(path)?;
    let mut partial_may_exist = false;
    let invalidate_after_cleanup = AtomicBool::new(false);
    let commit_started = AtomicBool::new(false);
    let remote_committed = AtomicBool::new(false);
    let transfer = async {
        validate_upload_remote_path(path)?;
        if size > MAX_TRANSFER_BYTES {
            bail!(
                "upload exceeds the {} byte safety limit",
                MAX_TRANSFER_BYTES
            );
        }
        if upload_remote_step(
            reader,
            shutdown,
            deadline,
            &invalidate_after_cleanup,
            async { Ok(sftp.try_exists(path).await?) },
        )
        .await?
        {
            bail!("remote destination already exists: {path}");
        }
        // Set this before CREATE: a timed-out request can still be processed by
        // the server after this future is dropped.
        partial_may_exist = true;
        let opened = upload_remote_step(
            reader,
            shutdown,
            deadline,
            &invalidate_after_cleanup,
            async {
                Ok(sftp
                    .open_with_flags_and_attributes(
                        &partial,
                        OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                        protected_upload_file_attributes(),
                    )
                    .await?)
            },
        )
        .await;
        let mut file = match opened {
            Ok(file) => file,
            Err(error) => {
                if !invalidate_after_cleanup.load(Ordering::Acquire) {
                    // A definite EXCLUDE failure means this request never
                    // owned the random partial name. Do not delete it.
                    partial_may_exist = false;
                }
                return Err(error);
            }
        };
        write_frame_until(writer, &ipc::Frame::Ack, deadline).await?;
        let mut transferred = 0_u64;
        loop {
            let frame = tokio::select! {
                result = tokio::time::timeout_at(
                    deadline,
                    ipc::read_frame_limited(reader, ipc::MAX_UPLOAD_FRAME),
                ) => match result {
                    Ok(result) => result?,
                    Err(_) => {
                        invalidate_after_cleanup.store(true, Ordering::Release);
                        bail!("SFTP upload exceeded its deadline of {timeout_ms} ms")
                    }
                },
                _ = shutdown.changed() => {
                    invalidate_after_cleanup.store(true, Ordering::Release);
                    bail!("daemon shutting down during upload")
                },
            };
            match frame {
                Some(ipc::Frame::UploadChunk { data }) => {
                    let mut data = Zeroizing::new(data);
                    if data.is_empty() || data.len() > MAX_UPLOAD_CHUNK_BYTES {
                        data.zeroize();
                        bail!("upload chunk is empty or exceeds {MAX_UPLOAD_CHUNK_BYTES} bytes");
                    }
                    let Some(next) = transferred.checked_add(data.len() as u64) else {
                        data.zeroize();
                        bail!("upload size overflow");
                    };
                    if next > size || next > MAX_TRANSFER_BYTES {
                        data.zeroize();
                        bail!("upload exceeded its declared or configured size");
                    }
                    let write = upload_remote_step(
                        reader,
                        shutdown,
                        deadline,
                        &invalidate_after_cleanup,
                        async {
                            file.write_all(&data).await?;
                            Ok(())
                        },
                    )
                    .await;
                    data.zeroize();
                    write?;
                    transferred = next;
                    write_frame_until(writer, &ipc::Frame::Ack, deadline).await?;
                }
                Some(ipc::Frame::UploadEnd) => break,
                Some(mut frame) => {
                    frame.zeroize_sensitive();
                    bail!("unexpected frame during upload")
                }
                None => {
                    invalidate_after_cleanup.store(true, Ordering::Release);
                    bail!("client disconnected during upload")
                }
            }
        }
        if transferred != size {
            bail!("upload size mismatch: expected {size}, received {transferred}");
        }
        upload_remote_step(
            reader,
            shutdown,
            deadline,
            &invalidate_after_cleanup,
            async {
                file.flush().await?;
                file.shutdown().await?;
                Ok(())
            },
        )
        .await?;
        drop(file);
        if upload_remote_step(
            reader,
            shutdown,
            deadline,
            &invalidate_after_cleanup,
            async { Ok(sftp.try_exists(path).await?) },
        )
        .await?
        {
            bail!("remote destination was created during upload: {path}");
        }
        commit_started.store(true, Ordering::Release);
        let commit = upload_remote_step(
            reader,
            shutdown,
            deadline,
            &invalidate_after_cleanup,
            commit_remote_upload_no_replace(&sftp, &partial, path, &remote_committed),
        )
        .await?;
        if !commit.used_hardlink {
            log::warn!(
                "SFTP server lacks hardlink@openssh.com; upload no-replace commit relies on \
                 compliant SFTP v3 RENAME semantics"
            );
        }
        if commit.partial_removed || cleanup_remote_partial(session, &partial).await {
            partial_may_exist = false;
        } else {
            log::warn!(
                "upload committed to {path}, but remote temporary name {partial} could not be removed"
            );
        }
        Ok(transferred)
    };
    let operation: Result<u64> = match tokio::time::timeout_at(deadline, transfer).await {
        Ok(result) => result,
        Err(_) => {
            invalidate_after_cleanup.store(true, Ordering::Release);
            Err(anyhow::anyhow!(
                "SFTP upload exceeded its deadline of {timeout_ms} ms"
            ))
        }
    };

    drop(sftp);
    let committed = remote_committed.load(Ordering::Acquire);
    if committed {
        if let Err(error) = &operation {
            log::warn!(
                "upload to {path} committed before post-commit cleanup was interrupted: {error:#}"
            );
        }
    }

    // Once a hardlink commit has been acknowledged by the server, cleanup is
    // no longer part of the upload outcome. Reconcile that durable outcome
    // with the client before opening a fresh SFTP channel to remove the owned
    // partial name. Otherwise two bounded cleanup/invalidation steps could
    // consume longer than the client's post-deadline reconciliation window
    // and falsely report an already committed upload as "outcome unknown".
    let committed_response = if committed {
        Some(
            write_frame_until(
                writer,
                &ipc::Frame::TransferDone { bytes: size },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
            )
            .await,
        )
    } else {
        None
    };
    let ipc_response_failed = operation
        .as_ref()
        .err()
        .is_some_and(|error| error.is::<IpcResponseWriteFailure>());
    if operation.is_err() && partial_may_exist && !ipc_response_failed {
        // A failed WRITE/CLOSE can leave protocol state ambiguous even if the
        // future itself completed with an error. A failed IPC Ack is different:
        // it is downstream of the completed SFTP step and must not poison the
        // daemon-wide shared SSH transport.
        invalidate_after_cleanup.store(true, Ordering::Release);
    }
    if operation.is_err() && partial_may_exist && !cleanup_remote_partial(session, &partial).await {
        log::warn!("remote upload partial cleanup failed for {partial}");
        // Cleanup itself is a remote operation. If it cannot establish a
        // definite result, discard the shared transport even when the
        // original failure was only an IPC backpressure failure.
        invalidate_after_cleanup.store(true, Ordering::Release);
    }
    if invalidate_after_cleanup.load(Ordering::Acquire) {
        session.invalidate().await;
    }
    match (operation, committed_response) {
        (_, Some(response)) => response,
        (Ok(transferred), None) => {
            let response_deadline = if deadline > Instant::now() {
                deadline
            } else {
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT
            };
            write_frame_until(
                writer,
                &ipc::Frame::TransferDone { bytes: transferred },
                response_deadline,
            )
            .await
        }
        (Err(error), None)
            if commit_started.load(Ordering::Acquire)
                && invalidate_after_cleanup.load(Ordering::Acquire) =>
        {
            Err(error).context(format!(
                "SFTP upload commit outcome unknown; inspect {path} before retry"
            ))
        }
        (Err(error), None) => Err(error),
    }
}

async fn cleanup_remote_partial(session: &SshSession, partial: &str) -> bool {
    let deadline = Instant::now() + REMOTE_PARTIAL_CLEANUP_TIMEOUT;
    let sftp = match tokio::time::timeout_at(deadline, session.sftp_until(deadline)).await {
        Ok(Ok(sftp)) => sftp,
        Ok(Err(error)) => {
            log::warn!("open fresh SFTP channel for partial cleanup: {error:#}");
            return false;
        }
        Err(_) => {
            log::warn!("opening fresh SFTP channel for partial cleanup timed out");
            return false;
        }
    };

    loop {
        match tokio::time::timeout_at(deadline, sftp.remove_file(partial)).await {
            Ok(Ok(())) => return true,
            Ok(Err(_)) => {
                // A CREATE request canceled at its deadline may finish on the
                // server after the first remove attempt observes no file.
            }
            Err(_) => return false,
        }
        if tokio::time::timeout_at(deadline, tokio::time::sleep(REMOTE_PARTIAL_CLEANUP_RETRY))
            .await
            .is_err()
        {
            return false;
        }
    }
}

fn validated_exec_timeout(timeout_ms: u64) -> Result<std::time::Duration> {
    if !(1..=ipc::MAX_EXEC_TIMEOUT_MS).contains(&timeout_ms) {
        bail!(
            "exec timeout must be between 1 and {} ms",
            ipc::MAX_EXEC_TIMEOUT_MS
        );
    }
    Ok(std::time::Duration::from_millis(timeout_ms))
}

fn validated_sftp_timeout(timeout_ms: u64) -> Result<std::time::Duration> {
    if !(1..=ipc::MAX_SFTP_TIMEOUT_MS).contains(&timeout_ms) {
        bail!(
            "SFTP timeout must be between 1 and {} ms",
            ipc::MAX_SFTP_TIMEOUT_MS
        );
    }
    Ok(std::time::Duration::from_millis(timeout_ms))
}

#[cfg(test)]
mod tests {
    use super::{
        acquire_buffered_operation_slot, authenticate_incoming_protocol,
        await_owned_blocking_until, handoff_readiness, read_authenticated_request,
        read_shell_frame_pump, read_shell_frame_pump_inner, recover_invalid_startup_lock_read,
        validate_request_frame, validated_exec_timeout, validated_sftp_timeout,
        write_all_until_or_shutdown, write_frame_or_shutdown, MAX_UPLOAD_CHUNK_BYTES,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::time::Instant;
    use zeroize::Zeroize;

    #[test]
    fn dropped_readiness_receiver_rejects_handoff_and_cleans_publication_owner() {
        struct FakePublication {
            live: Arc<AtomicBool>,
            lock_published: Arc<AtomicBool>,
            lease_held: Arc<AtomicBool>,
        }

        impl Drop for FakePublication {
            fn drop(&mut self) {
                self.live.store(false, Ordering::SeqCst);
                self.lock_published.store(false, Ordering::SeqCst);
                self.lease_held.store(false, Ordering::SeqCst);
            }
        }

        let live = Arc::new(AtomicBool::new(true));
        let lock_published = Arc::new(AtomicBool::new(true));
        let lease_held = Arc::new(AtomicBool::new(true));
        let publication = FakePublication {
            live: live.clone(),
            lock_published: lock_published.clone(),
            lease_held: lease_held.clone(),
        };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        drop(ready_rx);

        if handoff_readiness(Some(ready_tx)).is_err() {
            drop(publication);
        }

        assert!(!live.load(Ordering::SeqCst));
        assert!(!lock_published.load(Ordering::SeqCst));
        assert!(!lease_held.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn daemon_shell_frame_reader_survives_remote_output_competition_mid_frame() {
        let (mut reader, mut writer) = tokio::io::duplex(1);
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel(1);
        let frame_pump = read_shell_frame_pump(&mut reader, frame_tx);
        tokio::pin!(frame_pump);
        let mut frame_pump_running = true;
        let expected = vec![0x41; 32 * 1024];
        let sent = expected.clone();
        let writer_task = tokio::spawn(async move {
            crate::ipc::write_frame_limited(
                &mut writer,
                &crate::ipc::Frame::ShellInput { data: sent },
                crate::ipc::MAX_SHELL_FRAME,
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
                _ = tokio::task::yield_now() => competing_events += 1,
            }
        };
        writer_task.await.unwrap();
        match &mut received {
            crate::ipc::Frame::ShellInput { data } => {
                assert_eq!(data, &expected);
                data.zeroize();
            }
            other => panic!("unexpected frame from persistent reader: {other:?}"),
        }
        assert!(
            competing_events > 0,
            "test did not exercise competing remote-output scheduling"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_owned_publication_is_cleaned_after_setup_deadline() {
        struct FakePublication {
            published: Arc<AtomicBool>,
            lease_held: Arc<AtomicBool>,
            cleaned: Arc<AtomicBool>,
        }

        impl Drop for FakePublication {
            fn drop(&mut self) {
                self.published.store(false, Ordering::SeqCst);
                self.lease_held.store(false, Ordering::SeqCst);
                self.cleaned.store(true, Ordering::SeqCst);
            }
        }

        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let published = Arc::new(AtomicBool::new(false));
        let lease_held = Arc::new(AtomicBool::new(false));
        let cleaned = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let worker_release = release.clone();
        let worker_published = published.clone();
        let worker_lease = lease_held.clone();
        let worker_cleaned = cleaned.clone();
        let operation = move || {
            worker_started.store(true, Ordering::SeqCst);
            while !worker_release.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            worker_published.store(true, Ordering::SeqCst);
            worker_lease.store(true, Ordering::SeqCst);
            Ok(FakePublication {
                published: worker_published,
                lease_held: worker_lease,
                cleaned: worker_cleaned,
            })
        };

        let wait = tokio::spawn(await_owned_blocking_until(
            Instant::now() + Duration::from_millis(25),
            operation,
            "test publication",
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let error = match wait.await.unwrap() {
            Ok(_) => panic!("late publication unexpectedly met its setup deadline"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("deadline"));

        release.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cleaned.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late publication did not clean its owned result");
        assert!(
            !published.load(Ordering::SeqCst),
            "late lock remained published"
        );
        assert!(
            !lease_held.load(Ordering::SeqCst),
            "late lease remained held"
        );
    }

    #[tokio::test]
    async fn cancelling_full_daemon_shell_pump_zeroizes_its_in_flight_frame() {
        let (reader, mut writer) = tokio::io::duplex(1);
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel(1);
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

        for byte in [0x41, 0x42] {
            crate::ipc::write_frame_limited(
                &mut writer,
                &crate::ipc::Frame::ShellInput {
                    data: vec![byte; 1024],
                },
                crate::ipc::MAX_SHELL_FRAME,
            )
            .await
            .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while constructed.load(Ordering::Acquire) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("daemon pump did not construct its blocked second envelope");

        pump.abort();
        assert!(pump.await.unwrap_err().is_cancelled());
        assert!(
            dropped.load(Ordering::Acquire),
            "cancelling a full daemon pump bypassed in-flight frame cleanup"
        );
        let mut queued = frame_rx.try_recv().unwrap().into_inner().unwrap().unwrap();
        queued.zeroize_sensitive();
    }

    #[tokio::test]
    async fn daemon_protocol_helper_verifies_v2_client_proof() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = crate::vault::new_ipc_token();
        let deadline = Instant::now() + Duration::from_secs(1);
        let (client_result, server_result) = tokio::join!(
            crate::ipc::authenticate_client(&mut client, "prod", &token, deadline),
            authenticate_incoming_protocol(&mut server, "prod", &token, deadline),
        );
        client_result.unwrap();
        server_result.unwrap();
    }

    #[tokio::test]
    async fn invalid_client_proof_is_closed_without_a_structured_error() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = crate::vault::new_ipc_token();
        let deadline = Instant::now() + Duration::from_secs(1);

        let server_task = async move {
            let error = authenticate_incoming_protocol(&mut server, "prod", &token, deadline)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("proof mismatch"));
            // Production handle_conn takes this same error branch and drops
            // the stream without serializing Frame::Error.
            drop(server);
        };
        let client_task = async move {
            crate::ipc::write_frame_limited(
                &mut client,
                &crate::ipc::Frame::AuthHello {
                    version: crate::ipc::IPC_PROTOCOL_VERSION,
                    client_nonce: crate::vault::new_ipc_token(),
                },
                crate::ipc::MAX_AUTH_FRAME,
            )
            .await
            .unwrap();
            assert!(matches!(
                crate::ipc::read_frame_limited(&mut client, crate::ipc::MAX_AUTH_FRAME)
                    .await
                    .unwrap(),
                Some(crate::ipc::Frame::AuthChallenge { .. })
            ));
            crate::ipc::write_frame_limited(
                &mut client,
                &crate::ipc::Frame::AuthResponse {
                    client_proof: crate::vault::new_ipc_token(),
                },
                crate::ipc::MAX_AUTH_FRAME,
            )
            .await
            .unwrap();

            match tokio::time::timeout(
                Duration::from_millis(250),
                crate::ipc::read_frame_limited(&mut client, crate::ipc::MAX_AUTH_FRAME),
            )
            .await
            {
                Ok(Ok(None)) | Ok(Err(_)) => {}
                Ok(Ok(Some(frame))) => {
                    panic!("authentication failure disclosed a response frame: {frame:?}")
                }
                Err(_) => panic!("server did not close a failed authentication promptly"),
            }
        };

        tokio::join!(server_task, client_task);
    }

    #[test]
    fn exec_timeout_is_bounded() {
        assert!(validated_exec_timeout(0).is_err());
        assert!(validated_exec_timeout(1).is_ok());
        assert!(validated_exec_timeout(crate::ipc::MAX_EXEC_TIMEOUT_MS + 1).is_err());
    }

    #[test]
    fn sftp_timeout_is_bounded() {
        assert!(validated_sftp_timeout(0).is_err());
        assert!(validated_sftp_timeout(1).is_ok());
        assert!(validated_sftp_timeout(crate::ipc::MAX_SFTP_TIMEOUT_MS + 1).is_err());
    }

    #[test]
    fn startup_rereads_after_removing_a_shadowing_hashed_lock() {
        let legacy = recover_invalid_startup_lock_read::<u8, _, _>(
            Err(anyhow::anyhow!("malformed hashed lock")),
            || Ok(true),
            || Ok(Some(9)),
        )
        .unwrap();
        assert_eq!(legacy, Some(9));

        let legacy_error = recover_invalid_startup_lock_read::<u8, _, _>(
            Err(anyhow::anyhow!("malformed hashed lock")),
            || Ok(true),
            || Err(anyhow::anyhow!("raw legacy lock is unsupported")),
        )
        .unwrap_err();
        assert!(legacy_error.to_string().contains("raw legacy lock"));
    }

    #[test]
    fn authenticated_request_semantic_limits_are_enforced() {
        assert!(validate_request_frame(&crate::ipc::Frame::Exec {
            cmd: "x".repeat(crate::ssh::MAX_REMOTE_COMMAND_BYTES + 1),
            timeout_ms: 1,
        })
        .is_err());
        assert!(validate_request_frame(&crate::ipc::Frame::UploadChunk {
            data: vec![0; MAX_UPLOAD_CHUNK_BYTES + 1],
        })
        .is_err());
        assert!(validate_request_frame(&crate::ipc::Frame::UploadBegin {
            path: "/tmp/x".into(),
            size: crate::ssh::MAX_TRANSFER_BYTES + 1,
            timeout_ms: 1,
        })
        .is_err());
    }

    #[test]
    fn daemon_and_direct_routes_share_command_and_path_rejections() {
        let oversized_command = "x".repeat(crate::ssh::MAX_REMOTE_COMMAND_BYTES + 1);
        assert!(crate::ssh::validate_remote_command(&oversized_command).is_err());
        assert!(validate_request_frame(&crate::ipc::Frame::Exec {
            cmd: oversized_command,
            timeout_ms: 1,
        })
        .is_err());
        assert!(crate::ssh::validate_remote_command("echo\0hidden").is_err());
        assert!(validate_request_frame(&crate::ipc::Frame::Exec {
            cmd: "echo\0hidden".to_owned(),
            timeout_ms: 1,
        })
        .is_err());

        for invalid_path in [String::new(), "nul\0path".to_owned()] {
            assert!(crate::ssh::validate_remote_path(&invalid_path, false).is_err());
            assert!(validate_request_frame(&crate::ipc::Frame::Download {
                path: invalid_path,
                timeout_ms: 1,
            })
            .is_err());
        }
    }

    #[tokio::test]
    async fn buffered_operation_waiter_resumes_only_after_a_slot_is_released() {
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let (peer, mut reader) = tokio::io::duplex(1);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let waiter_slots = slots.clone();
        let waiter = tokio::spawn(async move {
            acquire_buffered_operation_slot(
                waiter_slots,
                &mut reader,
                &mut shutdown_rx,
                Instant::now() + Duration::from_secs(1),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        drop(held);
        assert!(tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .is_some());
        drop(peer);
        drop(shutdown_tx);
    }

    #[tokio::test]
    async fn authenticated_half_frame_is_closed_at_idle_deadline() {
        let (mut peer, mut reader) = tokio::io::duplex(16);
        peer.write_all(&[0, 0]).await.unwrap();
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let error =
            read_authenticated_request(&mut reader, &mut shutdown_rx, Duration::from_millis(20))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("idle deadline"));
    }

    #[tokio::test]
    async fn ipc_response_write_honors_absolute_deadline() {
        let (mut writer, _unread_peer) = tokio::io::duplex(1);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let error = write_frame_or_shutdown(
            &mut writer,
            &crate::ipc::Frame::ExecOut {
                data: vec![0; 1024],
            },
            Instant::now() + Duration::from_millis(20),
            &mut shutdown_rx,
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("IPC response write exceeded its deadline"));
    }

    #[tokio::test]
    async fn daemon_shutdown_preempts_blocked_ipc_response_write() {
        let (mut writer, _unread_peer) = tokio::io::duplex(1);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let trigger = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            shutdown_tx.send(true).unwrap();
        });

        let error = write_frame_or_shutdown(
            &mut writer,
            &crate::ipc::Frame::ExecOut {
                data: vec![0; 1024],
            },
            Instant::now() + Duration::from_secs(5),
            &mut shutdown_rx,
        )
        .await
        .unwrap_err();
        trigger.await.unwrap();

        assert!(error
            .to_string()
            .contains("daemon shutting down during IPC response write"));
    }

    #[tokio::test]
    async fn ssh_shell_input_write_honors_absolute_deadline() {
        let (mut writer, _unread_peer) = tokio::io::duplex(1);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let error = write_all_until_or_shutdown(
            &mut writer,
            &[0; 1024],
            Instant::now() + Duration::from_millis(20),
            &mut shutdown_rx,
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("SSH shell input write exceeded its deadline"));
    }

    #[tokio::test]
    async fn daemon_shutdown_preempts_blocked_ssh_shell_input_write() {
        let (mut writer, _unread_peer) = tokio::io::duplex(1);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let trigger = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            shutdown_tx.send(true).unwrap();
        });

        let error = write_all_until_or_shutdown(
            &mut writer,
            &[0; 1024],
            Instant::now() + Duration::from_secs(5),
            &mut shutdown_rx,
        )
        .await
        .unwrap_err();
        trigger.await.unwrap();

        assert!(error
            .to_string()
            .contains("daemon shutting down during SSH shell input write"));
    }
}
