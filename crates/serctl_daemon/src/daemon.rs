//! Daemon: the per-user/per-vault credential and SSH broker. The classic
//! per-profile daemon (v5) and the global v6 daemon share the same
//! per-operation dispatch; the global mode additionally owns the runtime
//! descriptor/secret, per-profile credential leases, and the unlock flow.
use anyhow::{bail, ensure, Context, Result};
use russh::ChannelMsg;
use russh_sftp::protocol::OpenFlags;
use serctl_core::daemon_runtime::{self, DaemonRuntimeDescriptor, DESCRIPTOR_SCHEMA_VERSION};
use serctl_core::vault::{self, now_unix, Creds, LockInfo, ProfileCallKey};
use serctl_protocol::v6::{
    frame_kind, ActivationSecret, InstanceId, V6RequestPrelude, V6ServerIo, IPC_PROTOCOL_VERSION_V6,
};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch, Mutex, Notify, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

use serctl_core::ssh::{
    commit_remote_upload_no_replace_until, is_explicit_sftp_status, poll_remote_mutation_until,
    protected_upload_file_attributes, temporary_remote_path, validate_remote_command,
    validate_remote_path, validate_shell_dimensions, validate_upload_remote_path,
    ExecSubmissionState, SshSession, MAX_TRANSFER_BYTES,
};
use serctl_protocol as ipc;

/// Bound for the complete daemon setup (credential snapshot + runtime
/// publication) once a start is requested. The CLI launcher mirrors this value
/// for its own readiness deadline.
pub const CONTROL_SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const IPC_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const SHELL_INPUT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const HANDLER_SHUTDOWN_GRACE: Duration = Duration::from_secs(4);
/// The global broker exits once no live work (connection handler, tunnel,
/// shell, or operation) remains for this long.
pub const IDLE_EXIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const RUNTIME_LOCK_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const REMOTE_PARTIAL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const REMOTE_PARTIAL_CLEANUP_RETRY: Duration = Duration::from_millis(50);
const POST_AUTH_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SHELL_INPUT_BYTES: usize = 64 * 1024;
const MAX_UPLOAD_CHUNK_BYTES: usize = 64 * 1024;
const BUFFERED_HEAVY_OPERATION_LIMIT: usize = 8;
const TUNNEL_CONTROL_LIMIT: usize = 8;
const TUNNEL_COMPLETION_POLL: Duration = Duration::from_millis(100);

fn terminal_safe_field(value: &str) -> String {
    value.escape_debug().to_string()
}

fn terminal_safe_display(value: &(impl fmt::Display + ?Sized)) -> String {
    terminal_safe_field(&value.to_string())
}

fn terminal_safe_error(error: &anyhow::Error) -> String {
    terminal_safe_field(&format!("{error:#}"))
}

fn exec_outcome_unknown_wire_message(error: anyhow::Error) -> String {
    ExecSubmissionState::RequestMayHaveReachedRemote
        .classify(error)
        .to_string()
}

fn exec_request_rejected_wire_message(error: anyhow::Error) -> String {
    error.to_string()
}

fn daemon_up_line(
    profile: &str,
    host: &str,
    ssh_port: u16,
    user: &str,
    endpoint_kind: &str,
    endpoint: &str,
) -> String {
    format!(
        "[serctl] daemon up: profile={}  {}:{ssh_port} as {}  ipc={}:{}  (Ctrl-C to stop)",
        terminal_safe_field(profile),
        terminal_safe_field(host),
        terminal_safe_field(user),
        terminal_safe_field(endpoint_kind),
        terminal_safe_field(endpoint),
    )
}

#[derive(Clone)]
struct ConnInfo {
    profile: String,
    host: String,
    user: String,
    started: i64,
    token: Arc<Zeroizing<String>>,
}

#[derive(Clone)]
struct HandlerContext {
    sessions: Arc<SessionManager>,
    info: ConnInfo,
    shutdown: watch::Sender<bool>,
    buffered_operation_slots: Arc<Semaphore>,
    tunnel_control_slots: Arc<Semaphore>,
    call_key: Arc<ProfileCallKey>,
    /// Hard upper bound for this root operation. Global-v6 handlers set it to
    /// the earliest credential/grant/request deadline; legacy v5 uses `None`.
    authorization_deadline: Option<Instant>,
}

fn status_info_frame(info: &ConnInfo) -> ipc::Frame {
    ipc::Frame::StatusInfo {
        profile: info.profile.clone(),
        host: info.host.clone(),
        user: info.user.clone(),
        started_unix: info.started,
    }
}

struct RuntimeLockGuard {
    cleanup: Option<RuntimeLockCleanup>,
}

struct RuntimeLockCleanup {
    profile: String,
    token: Arc<Zeroizing<String>>,
    lease: vault::ProfileLease,
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
                    log::warn!("runtime-lock cleanup: {}", terminal_safe_error(&error));
                }
            })
        {
            // Thread creation failure drops `cleanup`, releasing the OS lease.
            // A subsequent startup can then reconcile the token-protected
            // stale record; it can never mistake this process for live.
            log::warn!(
                "could not start runtime-lock cleanup thread: {}",
                terminal_safe_display(&error)
            );
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
                    log::warn!(
                        "runtime-publication cleanup: {}",
                        terminal_safe_error(&error)
                    );
                }
            })
        {
            log::warn!(
                "could not start runtime-publication cleanup thread: {}",
                terminal_safe_display(&error)
            );
        }
    }
}

impl RuntimeLockCleanup {
    fn run(self) -> Result<()> {
        let remove = vault::remove_lock_if_token_while_leased(&self.profile, self.token.as_str());
        let unlock = self.lease.unlock().context("release daemon runtime lease");
        remove.context("remove daemon runtime lock")?;
        unlock?;
        Ok(())
    }
}

impl RuntimeLockGuard {
    fn new(profile: String, token: Arc<Zeroizing<String>>, lease: vault::ProfileLease) -> Self {
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
    lease: vault::ProfileLease,
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
            let endpoint = vault::expected_endpoint(&profile, token.as_str())?;
            let listener = ipc::LocalListener::bind(&endpoint)?;
            // The Unix socket is created with default permissions; harden it
            // immediately, before any lock record can name the endpoint.
            #[cfg(unix)]
            serctl_core::security::harden_file(std::path::Path::new(&endpoint))?;
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
        Ok(Ok(Err(error))) => {
            log::warn!("runtime-lock cleanup: {}", terminal_safe_error(&error))
        }
        Ok(Err(error)) => log::warn!(
            "runtime-lock cleanup worker: {}",
            terminal_safe_display(&error)
        ),
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

pub async fn run_with_ready_until(
    profile: &str,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    setup_deadline: Instant,
) -> Result<()> {
    run_with_ready_until_at_optional_generation(profile, master, ready, None, setup_deadline).await
}

/// Start an in-process daemon using a generation-bound UI authorization.
/// The generation check and credential/call-key unwrap happen in one vault
/// snapshot while the exclusive profile lease is held.
pub async fn run_with_ready_until_at_generation(
    profile: &str,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    expected_generation: vault::ProfileIdentity,
    setup_deadline: Instant,
) -> Result<()> {
    run_with_ready_until_at_optional_generation(
        profile,
        master,
        ready,
        Some(expected_generation),
        setup_deadline,
    )
    .await
}

async fn run_with_ready_until_at_optional_generation(
    profile: &str,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    expected_generation: Option<vault::ProfileIdentity>,
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
        let (creds, call_key) = vault::decrypt_with_call_key_with_lock_timeout(
            &profile_owned,
            &master,
            expected_generation,
            lock_timeout,
        )?;
        Ok::<_, anyhow::Error>((creds, call_key, master, lease))
    });
    let (creds, call_key, master, lease) =
        match tokio::time::timeout_at(setup_deadline, &mut snapshot).await {
            Ok(result) => result.context("join daemon credential snapshot worker")??,
            Err(_) => {
                // `spawn_blocking` cannot preempt active filesystem/KDF work. The
                // worker retains the exclusive lease and Zeroizing master until
                // it finishes, so a late snapshot cannot race profile mutation.
                snapshot.abort();
                bail!("daemon credential snapshot exceeded its setup deadline")
            }
        };
    run_with_ready_and_lease(
        profile,
        creds,
        call_key,
        master,
        ready,
        lease,
        setup_deadline,
    )
    .await
}

/// Test entry point: run a daemon over already-decrypted credentials without
/// touching the vault. Kept unconditional so the CLI's cross-crate e2e suite
/// can drive the daemon in-process.
#[doc(hidden)]
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
    let profile_owned = profile.to_owned();
    let key_master = Zeroizing::new(master.as_str().to_owned());
    let mut key_task = tokio::task::spawn_blocking(move || {
        let lock_timeout = setup_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("daemon test call-key snapshot exceeded its setup deadline")?;
        vault::derive_profile_call_key_with_lock_timeout(
            &profile_owned,
            &key_master,
            None,
            lock_timeout,
        )
    });
    let call_key = match tokio::time::timeout_at(setup_deadline, &mut key_task).await {
        Ok(result) => result.context("join daemon test call-key snapshot worker")??,
        Err(_) => {
            key_task.abort();
            bail!("daemon test call-key snapshot exceeded its setup deadline")
        }
    };
    run_with_ready_and_lease(
        profile,
        creds,
        call_key,
        master,
        ready,
        lease,
        setup_deadline,
    )
    .await
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
                .context("invalid runtime lock was not eligible for safe protocol-v5 recovery")),
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "{read_error:#}; malformed runtime-lock recovery failed: {cleanup_error:#}"
            )),
        },
    }
}

async fn run_with_ready_and_lease(
    profile: &str,
    creds: Creds,
    call_key: ProfileCallKey,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    lease: vault::ProfileLease,
    connect_deadline: Instant,
) -> Result<()> {
    let profile_owned = profile.to_owned();
    let mut lock_read = tokio::task::spawn_blocking(move || {
        let existing = recover_invalid_startup_lock_read(
            vault::read_lock(&profile_owned),
            || vault::remove_invalid_hashed_v5_lock_while_leased(&profile_owned),
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
            call_key,
            master,
            ready,
            lease,
            connect_deadline,
        )
        .await;
    }
    run_after_startup_lock_reconciliation(
        profile,
        creds,
        call_key,
        master,
        ready,
        lease,
        connect_deadline,
    )
    .await
}

async fn run_after_startup_lock_reconciliation(
    profile: &str,
    mut creds: Creds,
    call_key: ProfileCallKey,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    lease: vault::ProfileLease,
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
                &lease,
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
        eprintln!("[serctl] pinned host key {}", terminal_safe_field(&fp));
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
    let call_key = Arc::new(call_key);
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
        "{}",
        daemon_up_line(
            profile,
            &host,
            session.creds.port,
            &user,
            ipc::endpoint_kind(),
            &endpoint,
        )
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
    let tunnel_control_slots = Arc::new(Semaphore::new(TUNNEL_CONTROL_LIMIT));
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
                let handler_shutdown = shutdown_rx.clone();
                let context = HandlerContext {
                    sessions: session.clone(),
                    info: info.clone(),
                    shutdown: shutdown_tx.clone(),
                    buffered_operation_slots: Arc::clone(&buffered_operation_slots),
                    tunnel_control_slots: Arc::clone(&tunnel_control_slots),
                    call_key: Arc::clone(&call_key),
                    authorization_deadline: None,
                };
                handlers.spawn(async move {
                    let _permit = permit;
                    handle_conn(stream, handler_shutdown, context).await
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
        Some(Ok(Err(error))) => log::warn!("ipc handler: {}", terminal_safe_error(&error)),
        Some(Err(error)) if !error.is_cancelled() => {
            log::warn!("ipc handler task: {}", terminal_safe_display(&error))
        }
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
        | ipc::Frame::TunnelReady { .. }
        | ipc::Frame::TunnelClosed
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
        serctl_core::vault::validate_endpoint(&lock.profile, &lock.token, &lock.endpoint)?;
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
        ipc::Frame::Shell { cols, rows } => validate_shell_dimensions(*cols, *rows)?,
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
        ipc::Frame::TunnelOpen { spec } => spec.validate()?,
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
    call_key: &ProfileCallKey,
    deadline: Instant,
) -> Result<ipc::AuthContext>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ipc::authenticate_server(stream, profile, token, call_key.as_bytes(), deadline).await
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

/// Tunnel control connections are long lived, so cap them independently from
/// short IPC handlers. A peer that disappears while waiting must not consume a
/// slot or reach SSH/listener setup.
async fn acquire_tunnel_control_slot<R>(
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
            Ok(Err(_)) => bail!("tunnel-control capacity is unavailable"),
            Err(_) => bail!("waiting for tunnel-control capacity exceeded the setup deadline"),
        },
    }
}

async fn handle_conn<S>(
    mut stream: S,
    mut shutdown_rx: watch::Receiver<bool>,
    context: HandlerContext,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let HandlerContext {
        sessions,
        info,
        shutdown,
        buffered_operation_slots,
        tunnel_control_slots,
        call_key,
        authorization_deadline,
    } = context;
    let authentication_deadline = Instant::now() + Duration::from_secs(2);
    let authentication = tokio::select! {
        result = authenticate_incoming_protocol(
            &mut stream,
            &info.profile,
            info.token.as_str(),
            &call_key,
            authentication_deadline,
        ) => result,
        _ = shutdown_rx.changed() => return Ok(()),
    };
    let mut auth_context = match authentication {
        Ok(context) => context,
        Err(error) => {
            // Authentication failures are intentionally indistinguishable to the
            // peer: close without sending a structured error oracle.
            log::warn!(
                "rejected local IPC authentication: {}",
                terminal_safe_error(&error)
            );
            return Ok(());
        }
    };
    let (mut rd, wr) = tokio::io::split(stream);
    let frame =
        read_authenticated_request(&mut rd, &mut shutdown_rx, POST_AUTH_IDLE_TIMEOUT).await?;
    let Some(mut frame) = frame else {
        return Ok(());
    };
    if let Err(error) = auth_context.verify_request(call_key.as_bytes(), &frame) {
        frame.zeroize_sensitive();
        // Authorization failures are deliberately closed without a
        // structured response. In particular, a mismatched intent must
        // not reach validation, SSH, or local listener setup.
        log::warn!(
            "rejected local IPC request authorization: {}",
            terminal_safe_error(&error)
        );
        return Ok(());
    }
    let context = HandlerContext {
        sessions,
        info,
        shutdown,
        buffered_operation_slots,
        tunnel_control_slots,
        call_key,
        authorization_deadline,
    };
    dispatch_root_request(rd, wr, shutdown_rx, context, frame).await
}

/// Dispatch one authenticated, intent-verified root request. The root frame
/// is committed in the handshake (v5 intent commitment or v6 prelude hash);
/// every per-operation branch lives here so both wire generations share the
/// exact same execution semantics. One connection carries exactly one root
/// request: after this returns, the connection closes.
async fn dispatch_root_request<R, W>(
    rd: R,
    wr: W,
    shutdown_rx: watch::Receiver<bool>,
    context: HandlerContext,
    frame: ipc::Frame,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let authorization_deadline = context.authorization_deadline;
    let operation = dispatch_root_request_inner(rd, wr, shutdown_rx, context, frame);
    match authorization_deadline {
        Some(deadline) => match tokio::time::timeout_at(deadline, operation).await {
            Ok(result) => result,
            Err(_) => bail!("profile authorization lease expired"),
        },
        None => operation.await,
    }
}

async fn dispatch_root_request_inner<R, W>(
    mut rd: R,
    mut wr: W,
    mut shutdown_rx: watch::Receiver<bool>,
    context: HandlerContext,
    mut frame: ipc::Frame,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let HandlerContext {
        sessions,
        info,
        shutdown,
        buffered_operation_slots,
        tunnel_control_slots,
        call_key: _call_key,
        authorization_deadline: _,
    } = context;
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
        return Ok(());
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
                    return Ok(());
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
                    return Ok(());
                }
            };
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
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
                        return Ok(());
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
                    return Ok(());
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
                            // A failed/cancelled russh mpsc send never
                            // transfers ownership of the exec request.
                            msg: exec_request_rejected_wire_message(error),
                        },
                        deadline,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
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
                            ipc::Frame::Error {
                                msg: exec_outcome_unknown_wire_message(error),
                            },
                            deadline,
                            &mut shutdown_rx,
                        ).await?;
                    }
                    Err(_) => {
                        command.cancel().await;
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: exec_outcome_unknown_wire_message(anyhow::anyhow!(
                                    "remote command exceeded its deadline of {} ms",
                                    timeout.as_millis()
                                )),
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
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
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
                        return Ok(());
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
            // Status is exact-intent call-key authorized before dispatch.
            // It still reports only daemon lifetime metadata and never
            // probes SSH health or reconnects with the retained password.
            write_owned_frame_or_shutdown(
                &mut wr,
                status_info_frame(&info),
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
                    return Ok(());
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
                    return Ok(());
                }
            };
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
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
                        return Ok(());
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
                    return Ok(());
                }
            };
            let deadline = Instant::now() + timeout;
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
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
                        return Ok(());
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
                    write_frame_or_shutdown(&mut wr, &ipc::Frame::Ack, deadline, &mut shutdown_rx)
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
                    return Ok(());
                }
            };
            let deadline = Instant::now() + timeout;
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
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
                        return Ok(());
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
                    return Ok(());
                }
            };
            let deadline = Instant::now() + timeout;
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
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
                        return Ok(());
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
        ipc::Frame::TunnelOpen { spec } => {
            let deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
            let _tunnel_control_permit = match acquire_tunnel_control_slot(
                Arc::clone(&tunnel_control_slots),
                &mut rd,
                &mut shutdown_rx,
                deadline,
            )
            .await
            {
                Ok(Some(permit)) => permit,
                Ok(None) => return Ok(()),
                Err(error) => {
                    write_tunnel_terminal(&mut wr, &mut shutdown_rx, Err(error)).await?;
                    return Ok(());
                }
            };
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
                    Ok(Some(session)) => session,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_tunnel_terminal(&mut wr, &mut shutdown_rx, Err(error)).await?;
                        return Ok(());
                    }
                };
            // This dedicated IPC connection owns the complete tunnel
            // lifetime. EOF, TunnelStop, or daemon shutdown all cancel it
            // and wait for bounded SSH/listener cleanup.
            return serve_tunnel(session, &mut rd, &mut wr, spec, &mut shutdown_rx, deadline).await;
        }
        ipc::Frame::Shutdown { mut passphrase } => {
            passphrase.zeroize();
            write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::Ack,
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
            let _ = shutdown.send(true);
            return Ok(());
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
    Ok(())
}

// ── Global per-user/per-vault daemon (IPC v6) ──────────────────────────────

/// Bounded credential lease: after this the profile's decrypted credentials
/// and its vault profile lease are released; a later operation must unlock
/// again. Mirrors the design's CredentialLease horizon (design §8.4).
const V6_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const GLOBAL_CONNECTION_LIMIT: usize = 64;
const GRANT_REGISTRY_LIMIT: usize = 1024;
const LEASE_REAPER_INTERVAL: Duration = Duration::from_secs(1);
static GRANT_AUDIT_LOCK: std::sync::LazyLock<StdMutex<()>> =
    std::sync::LazyLock::new(|| StdMutex::new(()));

struct ProfilePoolEntry {
    conn_info: ConnInfo,
    sessions: Arc<SessionManager>,
    call_key: Arc<ProfileCallKey>,
    expires_at: Instant,
    _lease: Arc<vault::ProfileLease>,
}

#[derive(Default)]
struct ProfilePool {
    entries: StdMutex<HashMap<[u8; 16], Arc<ProfilePoolEntry>>>,
}

impl ProfilePool {
    /// Resolve a live credential lease for `profile_id`, dropping the stored
    /// entry (and therefore releasing its vault profile lease) once the
    /// credential lease expires. In-flight holders are independently wrapped
    /// by the same hard authorization deadline before dispatch.
    fn entry_for(&self, profile_id: &[u8; 16]) -> Option<Arc<ProfilePoolEntry>> {
        let mut entries = self.entries.lock().ok()?;
        let expired = entries
            .get(profile_id)
            .is_some_and(|entry| entry.expires_at <= Instant::now());
        if expired {
            entries.remove(profile_id);
        }
        entries.get(profile_id).cloned()
    }

    fn insert(&self, profile_id: [u8; 16], entry: ProfilePoolEntry) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(profile_id, Arc::new(entry));
        }
    }

    fn prune_expired(&self, now: Instant) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, entry| entry.expires_at > now);
        }
    }
}

/// Reference-counted live work: every accepted connection handler and every
/// long-running operation (tunnel, shell, transfer) holds a guard for its
/// lifetime. The broker exits only after the counter stays at zero for the
/// whole idle window, so idle exit can never interrupt work in flight.
#[derive(Default)]
struct IdleTracker {
    work: AtomicUsize,
    changed: Notify,
}

struct IdleGuard {
    tracker: Arc<IdleTracker>,
}

impl IdleTracker {
    fn acquire(self: &Arc<Self>) -> IdleGuard {
        self.work.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_waiters();
        IdleGuard {
            tracker: Arc::clone(self),
        }
    }

    fn is_idle(&self) -> bool {
        self.work.load(Ordering::Acquire) == 0
    }

    /// Complete once the tracker has observed zero work for `timeout`
    /// continuously; a spurious wake re-arms the full window.
    async fn wait_for_idle_exit(self: &Arc<Self>, timeout: Duration) {
        loop {
            let notified = self.changed.notified();
            if self.is_idle() {
                let deadline = Instant::now() + timeout;
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    return;
                }
            } else {
                notified.await;
            }
        }
    }
}

impl Drop for IdleGuard {
    fn drop(&mut self) {
        self.tracker.work.fetch_sub(1, Ordering::AcqRel);
        self.tracker.changed.notify_waiters();
    }
}

/// Operation kinds a grant may authorize. Interactive shells and control
/// operations (unlock, shutdown, grant issuance) are never grantable.
const GRANTABLE_OPERATION_KINDS: &[&str] = &[
    "ssh.exec",
    "daemon.status",
    "sftp.list",
    "sftp.read",
    "sftp.write",
    "forward",
];

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Live registry of issued grants. Grants die with the daemon instance: a
/// restart rebinds every capability to a fresh activation secret.
#[derive(Default)]
struct GrantRegistry {
    grants: StdMutex<HashMap<[u8; 16], Arc<GrantRecord>>>,
}

impl GrantRegistry {
    fn get(&self, grant_id: &[u8; 16]) -> Option<Arc<GrantRecord>> {
        let mut grants = self.grants.lock().ok()?;
        let expired = grants
            .get(grant_id)
            .is_some_and(|record| record.expires_at <= Instant::now());
        if expired {
            grants.remove(grant_id);
        }
        grants.get(grant_id).cloned()
    }

    fn insert(&self, grant: serctl_protocol::grant::OperationGrant) -> Result<()> {
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| anyhow::anyhow!("grant registry lock is poisoned"))?;
        let now = Instant::now();
        grants.retain(|_, record| record.expires_at > now);
        ensure!(
            grants.len() < GRANT_REGISTRY_LIMIT,
            "grant registry is at its capacity"
        );
        ensure!(!grants.contains_key(&grant.grant_id), "grant id collision");
        grants.insert(grant.grant_id, Arc::new(GrantRecord::new(grant, now)));
        Ok(())
    }

    fn prune_expired(&self, now: Instant) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.retain(|_, record| record.expires_at > now);
        }
    }
}

/// One grant plus its remaining budget and audit sink.
struct GrantRecord {
    grant: serctl_protocol::grant::OperationGrant,
    remaining: AtomicUsize,
    expires_at: Instant,
}

#[derive(serde::Serialize)]
struct GrantAuditLine {
    at_unix_ms: u64,
    grant_id: String,
    operation_kind: String,
    profile: String,
    request_id: String,
    outcome: String,
}

impl GrantRecord {
    fn new(grant: serctl_protocol::grant::OperationGrant, issued_at: Instant) -> Self {
        Self {
            remaining: AtomicUsize::new(grant.budget as usize),
            grant,
            expires_at: issued_at + serctl_protocol::grant::GRANT_TTL,
        }
    }

    /// Validate expiry, requested deadline, scope, and proof of possession,
    /// then atomically spend one budget unit.
    fn check_and_spend(&self, prelude: &V6RequestPrelude, now: Instant, now_ms: u64) -> Result<()> {
        let grant = &self.grant;
        ensure!(now < self.expires_at, "grant has expired");
        ensure!(
            prelude.requested_deadline_unix_ms > now_ms
                && prelude.requested_deadline_unix_ms <= grant.expires_unix_ms,
            "requested deadline exceeds the grant expiry"
        );
        ensure!(
            grant.covers(prelude),
            "grant does not authorize this operation kind"
        );
        ensure!(grant.covers_profile(prelude), "grant profile mismatch");
        let signature = prelude
            .pop_signature
            .as_deref()
            .context("grant prelude must carry a proof-of-possession signature")?;
        serctl_protocol::grant::verify_prelude_pop(&grant.holder_key, signature, prelude)?;
        let mut remaining = self.remaining.load(Ordering::Acquire);
        loop {
            if remaining == 0 {
                bail!("grant budget exhausted");
            }
            match self.remaining.compare_exchange_weak(
                remaining,
                remaining - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => remaining = current,
            }
        }
    }

    /// Append one audit line to the protected grant audit log in the runtime
    /// directory. Persistence failures are logged, never fatal: audit must not
    /// become a new failure mode for relayed operations.
    fn audit(&self, prelude: &V6RequestPrelude, outcome: &str) {
        let entry = GrantAuditLine {
            at_unix_ms: now_unix_ms(),
            grant_id: self.grant.grant_id_hex(),
            operation_kind: prelude.operation_kind.clone(),
            profile: prelude
                .profile_name
                .clone()
                .unwrap_or_else(|| self.grant.profile_name.clone()),
            request_id: hex::encode(prelude.request_id),
            outcome: outcome.to_owned(),
        };
        let result = (|| -> Result<()> {
            use std::io::{Seek as _, Write as _};
            let _guard = GRANT_AUDIT_LOCK
                .lock()
                .map_err(|_| anyhow::anyhow!("grant audit lock is poisoned"))?;
            let path = daemon_runtime::grant_audit_path()?;
            let mut file = serctl_core::security::open_or_create_protected_file(&path)
                .context("open protected grant audit log")?;
            file.seek(std::io::SeekFrom::End(0))
                .context("seek to grant audit end")?;
            let line =
                Zeroizing::new(serde_json::to_vec(&entry).context("serialize grant audit entry")?);
            file.write_all(&line).context("append grant audit entry")?;
            file.write_all(b"\n")
                .context("terminate grant audit entry")?;
            file.sync_data().context("sync grant audit entry")?;
            Ok(())
        })();
        if let Err(error) = result {
            log::warn!(
                "grant audit persistence failed: {}",
                terminal_safe_error(&error)
            );
        }
    }
}

/// Issue a grant on behalf of an unlocked issuing profile. The grant's target
/// profile must be the same unlocked profile; the holder key never leaves the
/// daemon and the agent's private key never enters it.
fn issue_grant(
    prelude: &V6RequestPrelude,
    pool: &ProfilePool,
    grants: &GrantRegistry,
    frame: &ipc::Frame,
) -> Result<serctl_protocol::grant::OperationGrant> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::VerifyingKey;

    let ipc::Frame::IssueGrant {
        profile,
        operations,
        budget,
        holder_key,
    } = frame
    else {
        bail!("issue-grant operation kind without an issue-grant frame");
    };
    ensure!(
        prelude.profile_name.as_deref() == Some(profile.as_str()),
        "grant issuance must target the unlocked issuing profile"
    );
    let profile_id = prelude
        .profile_id
        .context("grant issuance requires the issuing profile id")?;
    let entry = pool
        .entry_for(&profile_id)
        .context("profile is locked: unlock it first")?;
    ensure!(
        entry.conn_info.profile == *profile,
        "grant profile name does not match its profile id"
    );
    let profile_proof = prelude
        .profile_proof
        .as_deref()
        .context("grant issuance requires a profile call proof")?;
    serctl_protocol::v6::verify_profile_prelude_proof(
        entry.call_key.as_bytes(),
        profile_proof,
        prelude,
    )?;
    let mut unique = operations.clone();
    unique.sort();
    unique.dedup();
    ensure!(
        !unique.is_empty()
            && unique
                .iter()
                .all(|kind| GRANTABLE_OPERATION_KINDS.contains(&kind.as_str())),
        "grant contains a non-grantable or empty operation kind"
    );
    let decoded = B64
        .decode(holder_key)
        .context("decode grant holder public key")?;
    let key_bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("grant holder key must decode to 32 bytes"))?;
    let holder =
        VerifyingKey::from_bytes(&key_bytes).context("grant holder public key is invalid")?;
    let grant = serctl_protocol::grant::OperationGrant::new(
        profile.clone(),
        profile_id,
        unique,
        *budget,
        &holder,
        now_unix_ms(),
    )?;
    grants.insert(grant.clone())?;
    Ok(grant)
}

/// Connect an authenticated SSH session for freshly decrypted credentials,
/// persisting a first-use host-key pin through the still-held profile lease.
/// Returns the session together with the lease, which remains held by the
/// pool entry for the whole credential-lease lifetime.
async fn connect_unlocked_session(
    name: &str,
    creds: &mut Creds,
    passphrase: &Zeroizing<String>,
    mut lease: vault::ProfileLease,
    deadline: Instant,
) -> Result<(SshSession, vault::ProfileLease)> {
    let expect = creds.host_key.clone();
    let staged = SshSession::connect_key_exchange_until(creds, expect, deadline).await?;
    let fp = staged.observed_fingerprint().to_owned();
    if creds.host_key.is_none() {
        let profile_owned = name.to_owned();
        let persisted_fp = fp.clone();
        let pin_passphrase = Zeroizing::new(passphrase.as_str().to_owned());
        let mut task = tokio::task::spawn_blocking(move || {
            let lock_timeout = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("daemon host-key pin persistence exceeded its setup deadline")?;
            vault::set_pinned_fp_with_lock_timeout(
                &profile_owned,
                persisted_fp,
                &pin_passphrase,
                lock_timeout,
                &lease,
            )?;
            Ok::<_, anyhow::Error>(lease)
        });
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(result) => {
                lease = result.context("join daemon host-key pin persistence worker")??;
            }
            Err(_) => {
                task.abort();
                staged.abort().await;
                bail!("daemon host-key pin persistence exceeded its setup deadline")
            }
        }
        eprintln!("[serctl] pinned host key {}", terminal_safe_field(&fp));
        creds.host_key = Some(fp);
    }
    let session = staged
        .authenticate_password_until(&creds.user, &creds.password, deadline)
        .await?;
    Ok((session, lease))
}

/// Unlock one profile: verify the passphrase, decrypt the credentials, derive
/// the call key, connect SSH (persisting a first-use host-key pin), and
/// publish a bounded credential lease into the pool.
async fn unlock_profile(
    prelude: &V6RequestPrelude,
    pool: &ProfilePool,
    frame: &ipc::Frame,
) -> Result<Zeroizing<String>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let ipc::Frame::Unlock { passphrase } = frame else {
        bail!("unlock operation kind without an unlock frame")
    };
    let passphrase = Zeroizing::new(passphrase.as_str().to_owned());
    let name = prelude
        .profile_name
        .clone()
        .context("unlock requires a profile name in the handshake prelude")?;
    let deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
    let profile_owned = name.clone();
    let key_passphrase = passphrase.clone();
    let mut snapshot = tokio::task::spawn_blocking(move || {
        let lease = vault::acquire_profile_use_lease(&profile_owned)?;
        let lock_timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("daemon unlock exceeded its setup deadline")?;
        let (creds, call_key) = vault::decrypt_with_call_key_with_lock_timeout(
            &profile_owned,
            &key_passphrase,
            None,
            lock_timeout,
        )?;
        let profile_id = vault::list_profile_metadata()?
            .into_iter()
            .find(|metadata| metadata.name == profile_owned)
            .map(|metadata| metadata.profile_id)
            .context("profile disappeared from the vault catalog")?;
        Ok::<_, anyhow::Error>((creds, call_key, profile_id, lease))
    });
    let (mut creds, call_key, profile_id, lease) =
        match tokio::time::timeout_at(deadline, &mut snapshot).await {
            Ok(result) => result.context("join daemon unlock worker")??,
            Err(_) => {
                snapshot.abort();
                bail!("daemon unlock exceeded its setup deadline")
            }
        };
    let (session, lease) =
        connect_unlocked_session(&name, &mut creds, &passphrase, lease, deadline).await?;
    drop(passphrase);
    let encoded_call_key = Zeroizing::new(B64.encode(call_key.as_bytes()));
    let unlocked_at = Instant::now();
    let expires_at = unlocked_at + serctl_protocol::v6::CREDENTIAL_LEASE_TTL;
    let sessions = Arc::new(SessionManager::new(creds.clone(), session));
    let conn_info = ConnInfo {
        profile: name.clone(),
        host: creds.host.clone(),
        user: creds.user.clone(),
        started: now_unix(),
        token: Arc::new(Zeroizing::new(vault::new_ipc_token())),
    };
    pool.insert(
        profile_id,
        ProfilePoolEntry {
            conn_info,
            sessions,
            call_key: Arc::new(call_key),
            expires_at,
            _lease: Arc::new(lease),
        },
    );
    Ok(encoded_call_key)
}

/// Serve one authenticated v6 connection: the root request is the unlock, the
/// catalog listing, a grant issuance, or a data-plane operation against a live
/// credential lease (directly or through a grant).
async fn handle_global_conn<S>(
    io: V6ServerIo<S>,
    prelude: V6RequestPrelude,
    pool: Arc<ProfilePool>,
    grants: Arc<GrantRegistry>,
    shutdown_tx: watch::Sender<bool>,
    buffered_operation_slots: Arc<Semaphore>,
    tunnel_control_slots: Arc<Semaphore>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(io);
    let mut shutdown_rx = shutdown_tx.subscribe();
    let frame =
        read_authenticated_request(&mut rd, &mut shutdown_rx, POST_AUTH_IDLE_TIMEOUT).await?;
    let Some(frame) = frame else {
        return Ok(());
    };

    match frame_kind(&frame) {
        "daemon.unlock" => match unlock_profile(&prelude, &pool, &frame).await {
            Ok(call_key) => {
                let response = ZeroizingResponseFrame(ipc::Frame::ProfileAuthorized {
                    call_key: call_key.as_str().to_owned(),
                });
                write_frame_or_shutdown(
                    &mut wr,
                    &response.0,
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await
            }
            Err(error) => {
                let msg = terminal_safe_error(&error);
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error { msg },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await
            }
        },
        "daemon.list-profiles" => {
            let listing = tokio::task::spawn_blocking(|| {
                vault::list_profile_metadata().map(|metadata| {
                    metadata
                        .into_iter()
                        .map(|profile| ipc::WireProfile {
                            name: profile.name,
                            host: profile.host,
                            port: profile.port,
                            generation: profile.generation,
                            profile_id: hex::encode(profile.profile_id),
                        })
                        .collect()
                })
            })
            .await
            .context("join profile catalog worker")?;
            match listing {
                Ok(profiles) => {
                    write_frame_or_shutdown(
                        &mut wr,
                        &ipc::Frame::ProfileList { profiles },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await
                }
                Err(error) => {
                    let msg = terminal_safe_error(&error);
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error { msg },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await
                }
            }
        }
        "daemon.issue-grant" => match issue_grant(&prelude, &pool, &grants, &frame) {
            Ok(grant) => {
                eprintln!(
                    "[serctl] grant issued: {} for {} ({} ops, budget {})",
                    grant.grant_id_hex(),
                    terminal_safe_field(&grant.profile_name),
                    grant.operations.len(),
                    grant.budget
                );
                write_frame_or_shutdown(
                    &mut wr,
                    &ipc::Frame::GrantIssued {
                        grant_id: grant.grant_id_hex(),
                        expires_unix_ms: grant.expires_unix_ms,
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await
            }
            Err(error) => {
                let msg = terminal_safe_error(&error);
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error { msg },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await
            }
        },
        "daemon.shutdown" => {
            let ipc::Frame::Shutdown { passphrase } = frame else {
                bail!("shutdown operation kind without a shutdown frame")
            };
            let passphrase = Zeroizing::new(passphrase);
            let profile = prelude
                .profile_name
                .as_deref()
                .context("shutdown requires a profile name in the handshake prelude")?
                .to_owned();
            let verify_deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
            let mut verifier = tokio::task::spawn_blocking(move || {
                vault::derive_profile_call_key_with_lock_timeout(
                    &profile,
                    &passphrase,
                    None,
                    CONTROL_SETUP_TIMEOUT,
                )
            });
            let verified = match tokio::time::timeout_at(verify_deadline, &mut verifier).await {
                Ok(result) => result.context("join daemon shutdown verifier")?,
                Err(_) => {
                    verifier.abort();
                    bail!("daemon shutdown authorization exceeded its deadline")
                }
            };
            if let Err(error) = verified {
                let msg = terminal_safe_error(&error);
                return write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error { msg },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await;
            }
            write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::Ack,
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
            let _ = shutdown_tx.send(true);
            Ok(())
        }
        _ => {
            // A grant-bound request names the grant instead of a profile id:
            // the grant's bound profile and budget authorize the operation.
            let grant_record: Option<Arc<GrantRecord>> = if let Some(grant_id) = prelude.grant_id {
                let record = match grants.get(&grant_id) {
                    Some(record) => record,
                    None => {
                        let msg = "grant is unknown or expired".to_owned();
                        return write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error { msg },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await;
                    }
                };
                if let Err(error) = record.check_and_spend(&prelude, Instant::now(), now_unix_ms())
                {
                    let msg = terminal_safe_error(&error);
                    record.audit(&prelude, &format!("rejected: {msg}"));
                    return write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error { msg },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await;
                }
                Some(record)
            } else {
                None
            };
            let profile_id = match (&grant_record, prelude.profile_id) {
                (Some(record), _) => record.grant.profile_id,
                (None, Some(profile_id)) => profile_id,
                (None, None) => {
                    let msg = "profile id is required for this operation".to_owned();
                    return write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error { msg },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await;
                }
            };
            let Some(entry) = pool.entry_for(&profile_id) else {
                let msg = "profile is locked: unlock it first".to_owned();
                return write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error { msg },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await;
            };
            let expected_profile = grant_record
                .as_ref()
                .map(|record| record.grant.profile_name.as_str())
                .or(prelude.profile_name.as_deref())
                .context("profile name is required for this operation")?;
            ensure!(
                entry.conn_info.profile == expected_profile,
                "profile name does not match its profile id"
            );

            if grant_record.is_none() {
                let proof = prelude
                    .profile_proof
                    .as_deref()
                    .context("profile call proof is required")?;
                serctl_protocol::v6::verify_profile_prelude_proof(
                    entry.call_key.as_bytes(),
                    proof,
                    &prelude,
                )?;
            }

            let now = Instant::now();
            let mut authorization_deadline = entry.expires_at;
            if let Some(record) = &grant_record {
                authorization_deadline = authorization_deadline.min(record.expires_at);
                let wall_now = now_unix_ms();
                let remaining_ms = prelude
                    .requested_deadline_unix_ms
                    .checked_sub(wall_now)
                    .context("requested deadline has expired")?;
                let requested_deadline = now
                    .checked_add(Duration::from_millis(remaining_ms))
                    .context("requested deadline exceeds the monotonic clock range")?;
                authorization_deadline = authorization_deadline.min(requested_deadline);
            }
            ensure!(
                authorization_deadline > now,
                "profile authorization lease expired"
            );
            let context = HandlerContext {
                sessions: entry.sessions.clone(),
                info: entry.conn_info.clone(),
                shutdown: shutdown_tx.clone(),
                buffered_operation_slots,
                tunnel_control_slots,
                call_key: entry.call_key.clone(),
                authorization_deadline: Some(authorization_deadline),
            };
            let outcome = dispatch_root_request(rd, wr, shutdown_rx, context, frame).await;
            if let Some(record) = &grant_record {
                record.audit(
                    &prelude,
                    if outcome.is_ok() {
                        "accepted"
                    } else {
                        "rejected: dispatch failure"
                    },
                );
                if outcome.is_ok() {
                    eprintln!(
                        "[serctl] grant relay: {} {} (grant {}, budget left {})",
                        terminal_safe_field(&prelude.operation_kind),
                        terminal_safe_field(&record.grant.profile_name),
                        record.grant.grant_id_hex(),
                        record.remaining.load(Ordering::Acquire)
                    );
                }
            }
            outcome
        }
    }
}

/// Global per-user/per-vault daemon: bind the v6 endpoint, publish the runtime
/// descriptor and activation secret, and serve every profile through
/// on-demand credential leases.
pub async fn run_global(
    instance_id: InstanceId,
    secret: ActivationSecret,
    build_commit: String,
) -> Result<()> {
    run_global_with_idle_timeout(instance_id, secret, build_commit, IDLE_EXIT_TIMEOUT).await
}

/// Global broker with a caller-chosen idle-exit window (tests use short
/// windows; the binary uses `IDLE_EXIT_TIMEOUT`).
pub async fn run_global_with_idle_timeout(
    instance_id: InstanceId,
    secret: ActivationSecret,
    build_commit: String,
    idle_exit_timeout: Duration,
) -> Result<()> {
    let endpoint = daemon_runtime::v6_endpoint(&instance_id)?;
    let mut listener = ipc::LocalListener::bind(&endpoint)?;
    #[cfg(unix)]
    serctl_core::security::harden_file(std::path::Path::new(&endpoint))?;
    daemon_runtime::write_descriptor(&DaemonRuntimeDescriptor {
        version: DESCRIPTOR_SCHEMA_VERSION,
        instance_id: instance_id.as_hex(),
        pid: std::process::id(),
        endpoint,
        protocol_min: IPC_PROTOCOL_VERSION_V6,
        protocol_max: IPC_PROTOCOL_VERSION_V6,
        started_unix: now_unix(),
        build_commit,
    })?;
    daemon_runtime::write_secret(&secret)?;

    let pool = Arc::new(ProfilePool::default());
    let grants = Arc::new(GrantRegistry::default());
    let idle = Arc::new(IdleTracker::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut daemon_shutdown = shutdown_rx.clone();
    let connection_slots = Arc::new(Semaphore::new(GLOBAL_CONNECTION_LIMIT));
    let buffered_operation_slots = Arc::new(Semaphore::new(BUFFERED_HEAVY_OPERATION_LIMIT));
    let tunnel_control_slots = Arc::new(Semaphore::new(TUNNEL_CONTROL_LIMIT));
    let mut handlers = JoinSet::new();
    let reaper_pool = Arc::clone(&pool);
    let reaper_grants = Arc::clone(&grants);
    let mut reaper_shutdown = shutdown_rx.clone();
    let reaper_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(LEASE_REAPER_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = Instant::now();
                    reaper_pool.prune_expired(now);
                    reaper_grants.prune_expired(now);
                }
                changed = reaper_shutdown.changed() => {
                    if changed.is_err() || *reaper_shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    });
    eprintln!(
        "[serctl] daemon up: global broker {} (Ctrl-C to stop)",
        terminal_safe_field(listener.endpoint())
    );

    let result: Result<()> = loop {
        tokio::select! {
            res = listener.accept() => {
                let stream = match res {
                    Ok(stream) => stream,
                    Err(error) => break Err(error.context("accept local IPC connection")),
                };
                let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
                    log::warn!("rejecting IPC connection: connection limit reached");
                    continue;
                };
                let handler_shutdown = shutdown_rx.clone();
                let _ = handler_shutdown; // the global handler subscribes per connection
                let pool = Arc::clone(&pool);
                let grants = Arc::clone(&grants);
                let secret = secret.clone();
                let shutdown_tx = shutdown_tx.clone();
                let buffered_operation_slots = Arc::clone(&buffered_operation_slots);
                let tunnel_control_slots = Arc::clone(&tunnel_control_slots);
                let work_guard = idle.acquire();
                handlers.spawn(async move {
                    let _permit = permit;
                    let _work_guard = work_guard;
                    let deadline = Instant::now() + V6_HANDSHAKE_TIMEOUT;
                    match serctl_protocol::v6::v6_server_handshake(
                        stream,
                        &secret,
                        instance_id,
                        deadline,
                    )
                    .await
                    {
                        Ok((session, prelude)) => {
                            let io = V6ServerIo::new(session);
                            handle_global_conn(
                                io,
                                prelude,
                                pool,
                                grants,
                                shutdown_tx,
                                buffered_operation_slots,
                                tunnel_control_slots,
                            )
                            .await
                        }
                        Err(error) => {
                            log::warn!("rejected IPC v6 handshake: {}", terminal_safe_error(&error));
                            Ok(())
                        }
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[serctl] shutting down");
                break Ok(());
            }
            changed = daemon_shutdown.changed() => {
                if changed.is_ok() && *daemon_shutdown.borrow() {
                    eprintln!("[serctl] shutdown requested");
                    break Ok(());
                }
            }
            _ = idle.wait_for_idle_exit(idle_exit_timeout) => {
                // Re-check under the wake race: work may have arrived exactly
                // as the idle window expired.
                if idle.is_idle() {
                    eprintln!("[serctl] idle for {idle_exit_timeout:?}; exiting");
                    break Ok(());
                }
            }
            joined = handlers.join_next(), if !handlers.is_empty() => {
                log_handler_result(joined);
            }
        }
    };

    let _ = shutdown_tx.send(true);
    let _ = reaper_task.await;
    let drained = tokio::time::timeout(HANDLER_SHUTDOWN_GRACE, async {
        while let Some(joined) = handlers.join_next().await {
            log_handler_result(Some(joined));
        }
    })
    .await;
    if drained.is_err() {
        handlers.abort_all();
        while handlers.join_next().await.is_some() {}
    }
    daemon_runtime::clear_runtime_state()?;
    result
}

async fn write_tunnel_terminal<W>(
    writer: &mut W,
    shutdown: &mut watch::Receiver<bool>,
    outcome: Result<()>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if let Err(error) = outcome {
        write_owned_frame_or_shutdown(
            writer,
            ipc::Frame::Error {
                msg: error.to_string(),
            },
            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
            shutdown,
        )
        .await?;
    }
    write_frame_or_shutdown(
        writer,
        &ipc::Frame::TunnelClosed,
        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
        shutdown,
    )
    .await
}

async fn stop_tunnel_and_report<W, F>(
    writer: &mut W,
    shutdown: &mut watch::Receiver<bool>,
    stop: F,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    F: std::future::Future<Output = Result<()>>,
{
    write_tunnel_terminal(writer, shutdown, stop.await).await
}

enum TunnelControlWait {
    WorkerFinished,
    Shutdown,
    Frame(Option<ipc::Frame>),
}

/// Keep one framed control read alive across completion-poll ticks. Recreating
/// `read_frame_limited` after a tick would cancel a partially-read length
/// prefix or JSON payload and permanently desynchronize the IPC stream.
async fn wait_for_tunnel_control_or_completion<R, F>(
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    poll_interval: Duration,
    mut worker_is_finished: F,
) -> Result<TunnelControlWait>
where
    R: AsyncRead + Unpin,
    F: FnMut() -> bool,
{
    let control_read = ipc::read_frame_limited(reader, ipc::MAX_CONTROL_FRAME);
    tokio::pin!(control_read);
    let mut completion_poll = tokio::time::interval(poll_interval);
    completion_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if worker_is_finished() {
            return Ok(TunnelControlWait::WorkerFinished);
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(TunnelControlWait::Shutdown),
            control = &mut control_read => return Ok(TunnelControlWait::Frame(control?)),
            _ = completion_poll.tick() => {}
        }
    }
}

/// Own one daemon-routed tunnel for exactly the lifetime of its authenticated
/// control connection. Tunnel payload never traverses IPC: this handler only
/// reports readiness and observes stop/EOF/daemon-shutdown signals.
async fn serve_tunnel<R, W>(
    session: Arc<SshSession>,
    reader: &mut R,
    writer: &mut W,
    spec: serctl_core::ssh::TunnelSpec,
    shutdown: &mut watch::Receiver<bool>,
    setup_deadline: Instant,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let tunnel = tokio::select! {
        result = session.start_tunnel(spec, setup_deadline) => Some(result),
        _ = reader.read_u8() => None,
        _ = shutdown.changed() => None,
    };
    let Some(tunnel) = tunnel else {
        return Ok(());
    };
    let tunnel = match tunnel {
        Ok(tunnel) => tunnel,
        Err(error) => return write_tunnel_terminal(writer, shutdown, Err(error)).await,
    };
    let ready = tunnel.ready().clone();
    if let Err(error) = write_frame_or_shutdown(
        writer,
        &ipc::Frame::TunnelReady { ready },
        setup_deadline,
        shutdown,
    )
    .await
    {
        if let Err(cleanup_error) = tunnel.stop().await {
            log::warn!(
                "tunnel cleanup after readiness write failure: {}",
                terminal_safe_error(&cleanup_error)
            );
        }
        return Err(error);
    }

    match wait_for_tunnel_control_or_completion(reader, shutdown, TUNNEL_COMPLETION_POLL, || {
        tunnel.is_finished()
    })
    .await
    {
        Ok(TunnelControlWait::WorkerFinished) => {
            write_tunnel_terminal(writer, shutdown, tunnel.wait().await).await
        }
        Ok(TunnelControlWait::Shutdown) => {
            if let Err(error) = tunnel.stop().await {
                log::warn!(
                    "tunnel cleanup during daemon shutdown: {}",
                    terminal_safe_error(&error)
                );
            }
            Ok(())
        }
        Ok(TunnelControlWait::Frame(Some(ipc::Frame::TunnelStop))) => {
            stop_tunnel_and_report(writer, shutdown, tunnel.stop()).await
        }
        Ok(TunnelControlWait::Frame(Some(mut unexpected))) => {
            unexpected.zeroize_sensitive();
            if let Err(cleanup_error) = tunnel.stop().await {
                log::warn!(
                    "tunnel cleanup after unexpected control frame: {}",
                    terminal_safe_error(&cleanup_error)
                );
            }
            write_tunnel_terminal(
                writer,
                shutdown,
                Err(anyhow::anyhow!("unexpected frame during tunnel session")),
            )
            .await
        }
        Ok(TunnelControlWait::Frame(None)) => {
            if let Err(error) = tunnel.stop().await {
                log::warn!(
                    "tunnel cleanup after IPC EOF: {}",
                    terminal_safe_error(&error)
                );
            }
            Ok(())
        }
        Err(error) => {
            if let Err(cleanup_error) = tunnel.stop().await {
                log::warn!(
                    "tunnel cleanup after IPC read failure: {}",
                    terminal_safe_error(&cleanup_error)
                );
            }
            Err(error).context("read tunnel control frame")
        }
    }
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

async fn upload_remote_step<R, F, T, S>(
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Instant,
    uncertain: &AtomicBool,
    on_first_poll: S,
    operation: F,
) -> Result<T>
where
    R: AsyncRead + Unpin,
    F: std::future::Future<Output = Result<T>>,
    S: FnOnce(),
{
    let guarded_operation = poll_remote_mutation_until(
        deadline,
        operation,
        on_first_poll,
        || uncertain.store(true, Ordering::Release),
        "SFTP upload exceeded its deadline",
    );
    tokio::select! {
        result = guarded_operation => result,
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
            || {},
            async { Ok(sftp.try_exists(path).await?) },
        )
        .await?
        {
            bail!("remote destination already exists: {path}");
        }
        let opened = upload_remote_step(
            reader,
            shutdown,
            deadline,
            &invalidate_after_cleanup,
            || partial_may_exist = true,
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
                if is_explicit_sftp_status(&error) {
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
                        || {},
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
            || {},
            async {
                file.flush().await?;
                Ok(())
            },
        )
        .await?;
        upload_remote_step(
            reader,
            shutdown,
            deadline,
            &invalidate_after_cleanup,
            || {},
            async {
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
            || {},
            async { Ok(sftp.try_exists(path).await?) },
        )
        .await?
        {
            bail!("remote destination was created during upload: {path}");
        }
        if Instant::now() >= deadline {
            invalidate_after_cleanup.store(true, Ordering::Release);
            bail!("SFTP upload exceeded its deadline of {timeout_ms} ms");
        }
        commit_started.store(true, Ordering::Release);
        let commit = upload_remote_step(
            reader,
            shutdown,
            deadline,
            &invalidate_after_cleanup,
            || {},
            commit_remote_upload_no_replace_until(
                &sftp,
                &partial,
                path,
                &remote_committed,
                deadline,
                "SFTP upload exceeded its deadline",
            ),
        )
        .await?;
        if commit.partial_removed || cleanup_remote_partial(session, &partial).await {
            partial_may_exist = false;
        } else {
            log::warn!(
                "upload committed to {}, but remote temporary name {} could not be removed",
                terminal_safe_field(path),
                terminal_safe_field(&partial),
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
                "upload to {} committed before post-commit cleanup was interrupted: {}",
                terminal_safe_field(path),
                terminal_safe_error(error),
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
        log::warn!(
            "remote upload partial cleanup failed for {}",
            terminal_safe_field(&partial)
        );
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
            log::warn!(
                "open fresh SFTP channel for partial cleanup: {}",
                terminal_safe_error(&error)
            );
            return false;
        }
        Err(_) => {
            log::warn!("opening fresh SFTP channel for partial cleanup timed out");
            return false;
        }
    };

    loop {
        match poll_remote_mutation_until(
            deadline,
            sftp.remove_file(partial),
            || {},
            || {},
            "remote partial cleanup exceeded its deadline",
        )
        .await
        {
            Ok(()) => return true,
            Err(_) => {
                // A CREATE request canceled at its deadline may finish on the
                // server after the first remove attempt observes no file.
            }
        }
        if Instant::now() >= deadline {
            return false;
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
        acquire_buffered_operation_slot, acquire_tunnel_control_slot,
        authenticate_incoming_protocol, await_owned_blocking_until, daemon_up_line,
        exec_outcome_unknown_wire_message, exec_request_rejected_wire_message, handoff_readiness,
        ipc, read_authenticated_request, read_shell_frame_pump, read_shell_frame_pump_inner,
        recover_invalid_startup_lock_read, status_info_frame, stop_tunnel_and_report,
        terminal_safe_error, validate_request_frame, validated_exec_timeout,
        validated_sftp_timeout, wait_for_tunnel_control_or_completion, write_all_until_or_shutdown,
        write_frame_or_shutdown, ConnInfo, Creds, TunnelControlWait, MAX_UPLOAD_CHUNK_BYTES,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::time::Instant;
    use zeroize::Zeroize;

    /// `vault::set_test_home` is process-global; the three global-daemon tests
    /// serialize on it for their whole lifetime.
    static TEST_HOME_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn global_daemon_serves_catalog_rejects_bad_unlock_and_shuts_down() {
        use serctl_core::{daemon_runtime, vault};
        use serctl_protocol::v6::{
            v6_client_handshake, ActivationSecret, InstanceId, V6ClientIo, V6RequestPrelude,
            IPC_PROTOCOL_VERSION_V6,
        };
        use std::time::{SystemTime, UNIX_EPOCH};

        let _home_guard = TEST_HOME_LOCK.lock().await;

        let base = std::env::temp_dir().join(format!(
            "serctl-global-daemon-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        vault::set_test_home(Some(base.clone()));

        // Windows profile creation requires an initialized administrator
        // policy with a persisted 2-of-2 recovery share.
        #[cfg(windows)]
        vault::initialize_admin_password("test-administrator-password", |media| {
            std::fs::write(base.join("recovery.bin"), media).map_err(anyhow::Error::from)
        })
        .unwrap();

        vault::create_profile(
            "v6test",
            &Creds {
                host: "127.0.0.1".into(),
                port: 22,
                user: "tester".into(),
                password: "remote-password".into(),
                host_key: None,
            },
            "correct-passphrase",
            Some("test-administrator-password"),
        )
        .unwrap();

        let instance = InstanceId::random();
        let secret = ActivationSecret::random();
        let daemon_task = tokio::spawn(super::run_global(
            instance,
            secret.clone(),
            "testbuild".into(),
        ));

        // Wait for the runtime descriptor: the daemon writes it only after the
        // listener is bound.
        let endpoint = loop {
            if let Some(descriptor) = daemon_runtime::read_descriptor().unwrap() {
                break descriptor.endpoint;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let deadline = Instant::now() + Duration::from_secs(10);

        // Catalog listing needs no unlock and no SSH.
        let stream = loop {
            match ipc::connect(&endpoint).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        let list_frame = ipc::Frame::ListProfiles;
        let list_hash = serctl_protocol::v6::root_request_hash(&list_frame).unwrap();
        let list_prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [1_u8; 16],
            request_id: [2_u8; 16],
            operation_kind: "daemon.list-profiles".into(),
            profile_id: None,
            profile_name: None,
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: list_hash,
        };
        let session = v6_client_handshake(stream, &secret, instance, list_prelude, deadline)
            .await
            .unwrap();
        let mut io = V6ClientIo::new(session);
        ipc::write_frame_limited(&mut io, &list_frame, ipc::MAX_REQUEST_FRAME)
            .await
            .unwrap();
        let reply = ipc::read_frame_limited(&mut io, ipc::MAX_RESPONSE_FRAME)
            .await
            .unwrap()
            .unwrap();
        let ipc::Frame::ProfileList { profiles } = reply else {
            panic!("expected ProfileList, got {reply:?}");
        };
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "v6test");

        // A wrong passphrase fails the unlock before any SSH connection.
        let stream = ipc::connect(&endpoint).await.unwrap();
        let unlock_frame = ipc::Frame::Unlock {
            passphrase: "wrong-passphrase".into(),
        };
        let unlock_hash = serctl_protocol::v6::root_request_hash(&unlock_frame).unwrap();
        let unlock_prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [3_u8; 16],
            request_id: [4_u8; 16],
            operation_kind: "daemon.unlock".into(),
            profile_id: None,
            profile_name: Some("v6test".into()),
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: unlock_hash,
        };
        let session = v6_client_handshake(stream, &secret, instance, unlock_prelude, deadline)
            .await
            .unwrap();
        let mut io = V6ClientIo::new(session);
        ipc::write_frame_limited(&mut io, &unlock_frame, ipc::MAX_REQUEST_FRAME)
            .await
            .unwrap();
        let reply = ipc::read_frame_limited(&mut io, ipc::MAX_RESPONSE_FRAME)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(reply, ipc::Frame::Error { .. }));

        // Possession of the activation secret alone cannot stop the broker.
        let stream = ipc::connect(&endpoint).await.unwrap();
        let rejected_shutdown = ipc::Frame::Shutdown {
            passphrase: "wrong-passphrase".into(),
        };
        let rejected_hash = serctl_protocol::v6::root_request_hash(&rejected_shutdown).unwrap();
        let rejected_prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [5_u8; 16],
            request_id: [6_u8; 16],
            operation_kind: "daemon.shutdown".into(),
            profile_id: None,
            profile_name: Some("v6test".into()),
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: rejected_hash,
        };
        let session = v6_client_handshake(stream, &secret, instance, rejected_prelude, deadline)
            .await
            .unwrap();
        let mut io = V6ClientIo::new(session);
        ipc::write_frame_limited(&mut io, &rejected_shutdown, ipc::MAX_REQUEST_FRAME)
            .await
            .unwrap();
        let reply = ipc::read_frame_limited(&mut io, ipc::MAX_RESPONSE_FRAME)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(reply, ipc::Frame::Error { .. }));
        assert!(daemon_runtime::read_descriptor().unwrap().is_some());

        // A verified profile passphrase closes the daemon and clears runtime state.
        let stream = ipc::connect(&endpoint).await.unwrap();
        let shutdown_frame = ipc::Frame::Shutdown {
            passphrase: "correct-passphrase".into(),
        };
        let shutdown_hash = serctl_protocol::v6::root_request_hash(&shutdown_frame).unwrap();
        let shutdown_prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [7_u8; 16],
            request_id: [8_u8; 16],
            operation_kind: "daemon.shutdown".into(),
            profile_id: None,
            profile_name: Some("v6test".into()),
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: shutdown_hash,
        };
        let session = v6_client_handshake(stream, &secret, instance, shutdown_prelude, deadline)
            .await
            .unwrap();
        let mut io = V6ClientIo::new(session);
        ipc::write_frame_limited(&mut io, &shutdown_frame, ipc::MAX_REQUEST_FRAME)
            .await
            .unwrap();
        let reply = ipc::read_frame_limited(&mut io, ipc::MAX_RESPONSE_FRAME)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(reply, ipc::Frame::Ack));

        tokio::time::timeout(Duration::from_secs(5), daemon_task)
            .await
            .expect("global daemon did not exit after shutdown")
            .unwrap()
            .unwrap();
        assert!(daemon_runtime::read_descriptor().unwrap().is_none());
        assert!(daemon_runtime::read_secret().unwrap().is_none());

        vault::set_test_home(None);
        let _ = std::fs::remove_dir_all(&base);
    }

    async fn v6_io_for(
        endpoint: &str,
        secret: &serctl_protocol::v6::ActivationSecret,
        instance: serctl_protocol::v6::InstanceId,
        prelude: serctl_protocol::v6::V6RequestPrelude,
        deadline: Instant,
    ) -> serctl_protocol::v6::V6ClientIo<ipc::ClientStream> {
        use serctl_protocol::v6::{v6_client_handshake, V6ClientIo};
        let stream = ipc::connect(endpoint).await.unwrap();
        let session = v6_client_handshake(stream, secret, instance, prelude, deadline)
            .await
            .unwrap();
        V6ClientIo::new(session)
    }

    async fn global_test_base() -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let base = std::env::temp_dir().join(format!(
            "serctl-global-daemon-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        serctl_core::vault::set_test_home(Some(base.clone()));
        base
    }

    #[tokio::test]
    async fn global_daemon_exits_after_its_idle_window_with_no_work() {
        use serctl_core::{daemon_runtime, vault};
        use serctl_protocol::v6::{ActivationSecret, InstanceId};

        let _home_guard = TEST_HOME_LOCK.lock().await;
        let base = global_test_base().await;
        let instance = InstanceId::random();
        let secret = ActivationSecret::random();
        let daemon_task = tokio::spawn(super::run_global_with_idle_timeout(
            instance,
            secret,
            "testbuild".into(),
            Duration::from_millis(300),
        ));

        // Wait for publication, then let the idle window expire.
        let publish_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if daemon_runtime::read_descriptor().unwrap().is_some() {
                break;
            }
            if Instant::now() >= publish_deadline {
                panic!("global daemon did not publish its runtime descriptor");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::timeout(Duration::from_secs(5), daemon_task)
            .await
            .expect("global daemon did not idle-exit")
            .unwrap()
            .unwrap();
        assert!(daemon_runtime::read_descriptor().unwrap().is_none());
        assert!(daemon_runtime::read_secret().unwrap().is_none());

        vault::set_test_home(None);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn global_daemon_keeps_serving_while_live_work_holds_the_idle_counter() {
        use serctl_core::{daemon_runtime, vault};
        use serctl_protocol::v6::{
            frame_kind, ActivationSecret, InstanceId, V6RequestPrelude, IPC_PROTOCOL_VERSION_V6,
        };

        let _home_guard = TEST_HOME_LOCK.lock().await;
        let base = global_test_base().await;
        let instance = InstanceId::random();
        let secret = ActivationSecret::random();
        let daemon_task = tokio::spawn(super::run_global_with_idle_timeout(
            instance,
            secret.clone(),
            "testbuild".into(),
            Duration::from_secs(2),
        ));

        let publish_deadline = Instant::now() + Duration::from_secs(5);
        let endpoint = loop {
            if let Some(descriptor) = daemon_runtime::read_descriptor().unwrap() {
                break descriptor.endpoint;
            }
            if Instant::now() >= publish_deadline {
                panic!("global daemon did not publish its runtime descriptor");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        // One open, authenticated connection is live work: it must postpone
        // idle exit well beyond the idle window.
        let list_frame = ipc::Frame::ListProfiles;
        let list_hash = serctl_protocol::v6::root_request_hash(&list_frame).unwrap();
        let prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [1_u8; 16],
            request_id: [2_u8; 16],
            operation_kind: frame_kind(&list_frame).into(),
            profile_id: None,
            profile_name: None,
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: list_hash,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let held = v6_io_for(&endpoint, &secret, instance, prelude, deadline).await;

        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            !daemon_task.is_finished(),
            "broker exited its idle window while a live connection held work"
        );

        drop(held);
        tokio::time::timeout(Duration::from_secs(5), daemon_task)
            .await
            .expect("global daemon did not idle-exit after the last connection closed")
            .unwrap()
            .unwrap();
        assert!(daemon_runtime::read_descriptor().unwrap().is_none());

        vault::set_test_home(None);
        let _ = std::fs::remove_dir_all(&base);
    }

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

    #[test]
    fn authorized_status_response_is_always_daemon_metadata() {
        // This response helper accepts no SessionManager or SshSession. The
        // Status branch therefore cannot inspect health, reconnect, or use the
        // retained password on behalf of its call-key-authorized caller.
        let info = ConnInfo {
            profile: "prod".into(),
            host: "ssh.example".into(),
            user: "alice".into(),
            started: 123,
            token: Arc::new(zeroize::Zeroizing::new("unused-token".into())),
        };
        match status_info_frame(&info) {
            serctl_protocol::Frame::StatusInfo {
                profile,
                host,
                user,
                started_unix,
            } => {
                assert_eq!(profile, "prod");
                assert_eq!(host, "ssh.example");
                assert_eq!(user, "alice");
                assert_eq!(started_unix, 123);
            }
            other => panic!("unexpected authorized status response: {other:?}"),
        }
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
            serctl_protocol::write_frame_limited(
                &mut writer,
                &serctl_protocol::Frame::ShellInput { data: sent },
                serctl_protocol::MAX_SHELL_FRAME,
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
            serctl_protocol::Frame::ShellInput { data } => {
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
            serctl_protocol::write_frame_limited(
                &mut writer,
                &serctl_protocol::Frame::ShellInput {
                    data: vec![byte; 1024],
                },
                serctl_protocol::MAX_SHELL_FRAME,
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
    async fn daemon_protocol_helper_verifies_v5_client_proof() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = serctl_core::vault::new_ipc_token();
        let call_key = serctl_core::vault::ProfileCallKey::from_bytes_for_test([0x5a; 32]);
        let deadline = Instant::now() + Duration::from_secs(1);
        let (client_result, server_result) = tokio::join!(
            serctl_protocol::authenticate_client(&mut client, "prod", &token, deadline),
            authenticate_incoming_protocol(&mut server, "prod", &token, &call_key, deadline),
        );
        client_result.unwrap();
        server_result.unwrap();
    }

    #[tokio::test]
    async fn token_only_daemon_auth_rejects_all_business_requests() {
        for request in [
            serctl_protocol::Frame::Status,
            serctl_protocol::Frame::Shutdown {
                passphrase: "profile-passphrase".into(),
            },
            serctl_protocol::Frame::TunnelOpen {
                spec: serctl_core::ssh::TunnelSpec::local(0, 22),
            },
        ] {
            let (mut client, mut server) = tokio::io::duplex(8 * 1024);
            let token = serctl_core::vault::new_ipc_token();
            let call_key = serctl_core::vault::ProfileCallKey::from_bytes_for_test([0x3c; 32]);
            let deadline = Instant::now() + Duration::from_secs(1);
            let (client_result, server_result) = tokio::join!(
                serctl_protocol::authenticate_client(&mut client, "prod", &token, deadline),
                authenticate_incoming_protocol(&mut server, "prod", &token, &call_key, deadline),
            );
            client_result.unwrap();
            let mut context = server_result.unwrap();
            let error = context
                .verify_request(call_key.as_bytes(), &request)
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("requires master-passphrase authorization"));
        }
    }

    #[tokio::test]
    async fn tunnel_control_waiter_releases_cleanly_on_ipc_eof() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let (mut reader, peer) = tokio::io::duplex(16);
        drop(peer);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let acquired = acquire_tunnel_control_slot(
            Arc::clone(&slots),
            &mut reader,
            &mut shutdown_rx,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(acquired.is_none());
        assert_eq!(slots.available_permits(), 0);
        drop(held);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn fragmented_tunnel_stop_survives_poll_ticks_and_reports_closed() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let client_task = tokio::spawn(async move {
            let payload = serde_json::to_vec(&serctl_protocol::Frame::TunnelStop).unwrap();
            let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(&payload);

            // Split both the length prefix and payload across delays longer
            // than the production completion-poll interval.
            client.write_all(&wire[..2]).await.unwrap();
            client.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            client.write_all(&wire[2..5]).await.unwrap();
            client.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            client.write_all(&wire[5..]).await.unwrap();
            client.flush().await.unwrap();

            serctl_protocol::read_frame_limited(&mut client, serctl_protocol::MAX_CONTROL_FRAME)
                .await
                .unwrap()
        });
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let control = wait_for_tunnel_control_or_completion(
            &mut server,
            &mut shutdown_rx,
            Duration::from_millis(100),
            || false,
        )
        .await
        .unwrap();
        assert!(matches!(
            control,
            TunnelControlWait::Frame(Some(serctl_protocol::Frame::TunnelStop))
        ));

        let cleaned = Arc::new(AtomicBool::new(false));
        let cleanup_flag = Arc::clone(&cleaned);
        stop_tunnel_and_report(&mut server, &mut shutdown_rx, async move {
            cleanup_flag.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), client_task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            response,
            Some(serctl_protocol::Frame::TunnelClosed)
        ));
        assert!(cleaned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn invalid_client_proof_is_closed_without_a_structured_error() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = serctl_core::vault::new_ipc_token();
        let call_key = serctl_core::vault::ProfileCallKey::from_bytes_for_test([0x5a; 32]);
        let deadline = Instant::now() + Duration::from_secs(1);

        let server_task = async move {
            let error =
                authenticate_incoming_protocol(&mut server, "prod", &token, &call_key, deadline)
                    .await
                    .err()
                    .expect("invalid proof unexpectedly authenticated");
            assert!(error.to_string().contains("proof mismatch"));
            // Production handle_conn takes this same error branch and drops
            // the stream without serializing Frame::Error.
            drop(server);
        };
        let client_task = async move {
            serctl_protocol::write_frame_limited(
                &mut client,
                &serctl_protocol::Frame::AuthHello {
                    version: serctl_protocol::IPC_PROTOCOL_VERSION,
                    client_nonce: serctl_core::vault::new_ipc_token(),
                    intent_commitment: None,
                },
                serctl_protocol::MAX_AUTH_FRAME,
            )
            .await
            .unwrap();
            assert!(matches!(
                serctl_protocol::read_frame_limited(&mut client, serctl_protocol::MAX_AUTH_FRAME)
                    .await
                    .unwrap(),
                Some(serctl_protocol::Frame::AuthChallenge { .. })
            ));
            serctl_protocol::write_frame_limited(
                &mut client,
                &serctl_protocol::Frame::AuthResponse {
                    client_proof: serctl_core::vault::new_ipc_token(),
                    client_call_proof: None,
                },
                serctl_protocol::MAX_AUTH_FRAME,
            )
            .await
            .unwrap();

            match tokio::time::timeout(
                Duration::from_millis(250),
                serctl_protocol::read_frame_limited(&mut client, serctl_protocol::MAX_AUTH_FRAME),
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
        assert!(validated_exec_timeout(serctl_protocol::MAX_EXEC_TIMEOUT_MS + 1).is_err());
    }

    #[test]
    fn sftp_timeout_is_bounded() {
        assert!(validated_sftp_timeout(0).is_err());
        assert!(validated_sftp_timeout(1).is_ok());
        assert!(validated_sftp_timeout(serctl_protocol::MAX_SFTP_TIMEOUT_MS + 1).is_err());
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
        assert!(validate_request_frame(&serctl_protocol::Frame::Exec {
            cmd: "x".repeat(serctl_core::ssh::MAX_REMOTE_COMMAND_BYTES + 1),
            timeout_ms: 1,
        })
        .is_err());
        assert!(
            validate_request_frame(&serctl_protocol::Frame::UploadChunk {
                data: vec![0; MAX_UPLOAD_CHUNK_BYTES + 1],
            })
            .is_err()
        );
        assert!(
            validate_request_frame(&serctl_protocol::Frame::UploadBegin {
                path: "/tmp/x".into(),
                size: serctl_core::ssh::MAX_TRANSFER_BYTES + 1,
                timeout_ms: 1,
            })
            .is_err()
        );
    }

    #[test]
    fn daemon_and_direct_routes_share_command_and_path_rejections() {
        let oversized_command = "x".repeat(serctl_core::ssh::MAX_REMOTE_COMMAND_BYTES + 1);
        assert!(serctl_core::ssh::validate_remote_command(&oversized_command).is_err());
        assert!(validate_request_frame(&serctl_protocol::Frame::Exec {
            cmd: oversized_command,
            timeout_ms: 1,
        })
        .is_err());
        assert!(serctl_core::ssh::validate_remote_command("echo\0hidden").is_err());
        assert!(validate_request_frame(&serctl_protocol::Frame::Exec {
            cmd: "echo\0hidden".to_owned(),
            timeout_ms: 1,
        })
        .is_err());

        for invalid_path in [String::new(), "nul\0path".to_owned()] {
            assert!(serctl_core::ssh::validate_remote_path(&invalid_path, false).is_err());
            assert!(validate_request_frame(&serctl_protocol::Frame::Download {
                path: invalid_path,
                timeout_ms: 1,
            })
            .is_err());
        }

        for (cols, rows) in [(0, 24), (80, serctl_core::ssh::MAX_SHELL_DIMENSION + 1)] {
            assert!(serctl_core::ssh::validate_shell_dimensions(cols, rows).is_err());
            assert!(validate_request_frame(&serctl_protocol::Frame::Shell { cols, rows }).is_err());
        }
        assert!(serctl_core::ssh::validate_shell_dimensions(80, 24).is_ok());
        assert!(
            validate_request_frame(&serctl_protocol::Frame::Shell { cols: 80, rows: 24 }).is_ok()
        );
    }

    #[test]
    fn daemon_terminal_diagnostics_escape_controls_and_bidi_fields() {
        let hostile = "保留\n\u{1b}]52;c;payload\u{7}\u{202e}\u{2028}";
        let startup = daemon_up_line(hostile, hostile, 22, hostile, hostile, hostile);
        let diagnostic = terminal_safe_error(&anyhow::anyhow!("failure: {hostile}"));
        for line in [startup, diagnostic] {
            assert!(line.contains("保留"));
            assert!(line.contains("\\n"));
            assert!(line.contains("\\u{1b}"));
            assert!(line.contains("\\u{202e}"));
            assert!(line.contains("\\u{2028}"));
            assert!(!line.chars().any(char::is_control));
            assert!(!line.contains('\u{202e}'));
            assert!(!line.contains('\u{2028}'));
        }
    }

    #[tokio::test]
    async fn daemon_exec_wire_errors_keep_request_send_failures_plain() {
        let rejected = exec_request_rejected_wire_message(anyhow::anyhow!(
            "injected russh exec queue send failure"
        ));
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        serctl_protocol::write_frame(
            &mut writer,
            &serctl_protocol::Frame::Error {
                msg: rejected.clone(),
            },
        )
        .await
        .unwrap();
        let frame =
            serctl_protocol::read_frame_limited(&mut reader, serctl_protocol::MAX_RESPONSE_FRAME)
                .await
                .unwrap()
                .unwrap();
        let serctl_protocol::Frame::Error { msg } = frame else {
            panic!("daemon exec rejection was not encoded as an error frame");
        };
        assert_eq!(msg, rejected);
        assert!(serctl_core::ssh::ExecOutcomeUnknown::from_wire_message(&msg).is_none());

        let uncertain = exec_outcome_unknown_wire_message(anyhow::anyhow!(
            "remote command finish response was lost"
        ));
        assert!(serctl_core::ssh::ExecOutcomeUnknown::from_wire_message(&uncertain).is_some());
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
            &serctl_protocol::Frame::ExecOut {
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
            &serctl_protocol::Frame::ExecOut {
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
