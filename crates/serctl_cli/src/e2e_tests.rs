use crate::client;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore as Rand08RngCore};
use russh::keys::{
    ssh_key::{self, rand_core},
    Algorithm, PrivateKey,
};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, Disconnect};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode, Version,
};
use serctl_core::vault;
use serctl_daemon::daemon;
use serctl_protocol as ipc;
use serctl_transfer_protocol as native;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};
use zeroize::Zeroizing;

const E2E_PROFILE_PASSPHRASE: &str = "daemon-profile-passphrase";
const TOFU_PROFILE_PASSPHRASE: &str = "tofu-profile-passphrase";
const AUTH_DISCONNECT_PROFILE_PASSPHRASE: &str = "auth-disconnect-profile-passphrase";
const KEX_PERSISTENT_PROFILE_PASSPHRASE: &str = "kex-persistent-profile-passphrase";
const DIRECT_PROFILE_PASSPHRASE: &str = "direct-profile-passphrase";
const E2E_ADMINISTRATOR_PASSPHRASE: &str = "e2e-administrator-passphrase";

// Both end-to-end tests redirect the process-global test vault home. Keep
// them serialized while still allowing their mock SSH and daemon tasks to run
// concurrently inside each test.
pub(crate) static TEST_HOME_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const GRANT_SUBPROCESS_TEST_NAME: &str = "e2e_tests::operation_grant_lifecycle_subprocess_helper";
const GRANT_SUBPROCESS_ROLE_ENV: &str = "SERCTL_TEST_GRANT_SUBPROCESS_ROLE";
const GRANT_SUBPROCESS_HOME_ENV: &str = "SERCTL_TEST_GRANT_SUBPROCESS_HOME";
const GRANT_SUBPROCESS_PROFILE: &str = "grant-subprocess-e2e";
const GRANT_SUBPROCESS_PASSPHRASE: &str = "grant-subprocess-profile-passphrase";
const GRANT_SUBPROCESS_FILE: &str = "agent-grant.json";
const GRANT_SUBPROCESS_MARKER: &str = "issued-marker.json";

struct E2eTestHome {
    path: PathBuf,
}

impl E2eTestHome {
    fn create(unique: u128) -> Self {
        #[cfg(unix)]
        let path =
            PathBuf::from("/tmp").join(format!("sctl-e2e-{}-{unique:x}", std::process::id()));
        #[cfg(windows)]
        let path = std::env::current_dir()
            .expect("resolve E2E checkout")
            .join("target")
            .join(format!("e2e-{}-{unique}", std::process::id()));

        #[cfg(windows)]
        std::fs::create_dir_all(path.parent().expect("E2E home has a parent"))
            .expect("create E2E target directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path).expect("create protected E2E home");
        }
        #[cfg(windows)]
        std::fs::create_dir(&path).expect("create isolated E2E home");
        vault::set_test_home(Some(path.clone()));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for E2eTestHome {
    fn drop(&mut self) {
        vault::set_test_home(None);
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "failed to remove isolated E2E home {}: {error}",
                    self.path.display()
                );
            }
        }
    }
}

struct CompatibleOsRng(OsRng);

impl rand_core::TryRng for CompatibleOsRng {
    type Error = rand_core::Infallible;

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

impl rand_core::TryCryptoRng for CompatibleOsRng {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ExecChannel {
    connection: u64,
    channel: ChannelId,
}

#[derive(Clone, Debug)]
struct ExecStart {
    generation: u64,
    command: Vec<u8>,
    channel: ExecChannel,
}

#[derive(Clone, Debug)]
struct UploadPartialOpen {
    generation: u64,
    path: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RemoteForwardKey {
    connection: u64,
    address: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct RemoteForwardEvent {
    generation: u64,
    key: RemoteForwardKey,
}

struct RemoteForwardRegistration {
    generation: u64,
    cancellation: tokio_util::sync::CancellationToken,
    listener_identity: std::net::SocketAddr,
    stopped: tokio::sync::oneshot::Receiver<std::net::SocketAddr>,
}

struct PendingChannelOpen {
    channel: Channel<Msg>,
    reply: ChannelOpenHandle,
}

#[derive(Default)]
struct ExecEvents {
    generation: u64,
    started: Vec<ExecStart>,
    cancelled: HashSet<ExecChannel>,
}

#[derive(Default)]
struct UploadPartialEvents {
    generation: u64,
    opened: Vec<UploadPartialOpen>,
}

#[derive(Default)]
struct RemoteForwardEvents {
    generation: u64,
    started: Vec<RemoteForwardEvent>,
    cancelled: Vec<RemoteForwardEvent>,
    active: HashMap<RemoteForwardKey, RemoteForwardRegistration>,
    accepted: HashMap<u64, u64>,
    bridged: HashMap<u64, u64>,
}

#[derive(Default)]
struct TestState {
    files: Mutex<HashMap<String, Vec<u8>>>,
    next_connection: AtomicU64,
    closed_connections: Mutex<HashSet<u64>>,
    connection_changed: Notify,
    password_auth_attempts: AtomicU64,
    pre_kex_disconnects_remaining: AtomicU64,
    disconnect_next_password_auth: AtomicBool,
    disconnect_next_channel_open: AtomicBool,
    disconnect_two_channel_opens: AtomicBool,
    pending_channel_open: Mutex<Option<PendingChannelOpen>>,
    reject_next_channel_open: AtomicBool,
    hang_next_channel_open: AtomicBool,
    exec_events: Mutex<ExecEvents>,
    exec_changed: Notify,
    sftp_hang: AtomicBool,
    sftp_hung_connection: Mutex<Option<u64>>,
    sftp_hang_changed: Notify,
    sftp_write_hang: AtomicBool,
    sftp_write_delay_ms: AtomicU64,
    sftp_write_hang_at: AtomicU64,
    sftp_write_calls: AtomicU64,
    sftp_open_calls: AtomicU64,
    sftp_stat_calls: AtomicU64,
    sftp_wire_read_bytes: AtomicU64,
    sftp_large_dir: AtomicBool,
    native_negotiated_chunk: AtomicU64,
    native_negotiated_window: AtomicU64,
    native_push_frames: AtomicU64,
    native_push_max_chunk: AtomicU64,
    native_pull_frames: AtomicU64,
    native_pull_max_chunk: AtomicU64,
    native_push_ack_gate: AtomicBool,
    native_push_data_received: Notify,
    native_push_ack_released: Notify,
    native_helpers_finished: AtomicU64,
    native_helper_finished: Notify,
    upload_partial_events: Mutex<UploadPartialEvents>,
    upload_partial_changed: Notify,
    upload_partial_remove_delay: AtomicBool,
    upload_partial_remove_hang: AtomicBool,
    upload_partial_remove_changed: Notify,
    upload_partial_permissions: AtomicU64,
    hardlink_race_target: AtomicBool,
    remote_forward_events: Mutex<RemoteForwardEvents>,
    remote_forward_changed: Notify,
}

impl TestState {
    async fn wait_for_native_push_frames(&self, minimum: u64) -> bool {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let changed = self.native_push_data_received.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.native_push_frames.load(Ordering::SeqCst) >= minimum {
                    break;
                }
                changed.await;
            }
        })
        .await
        .is_ok()
    }

    async fn wait_for_native_push_ack_release(&self) {
        while self.native_push_ack_gate.load(Ordering::SeqCst) {
            let released = self.native_push_ack_released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if !self.native_push_ack_gate.load(Ordering::SeqCst) {
                break;
            }
            released.await;
        }
    }

    async fn wait_for_native_helpers_finished(&self, minimum: u64) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.native_helper_finished.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.native_helpers_finished.load(Ordering::SeqCst) >= minimum {
                    break;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{minimum} native helper session(s) did not finish"));
    }

    async fn record_connection_closed(&self, connection: u64) {
        self.closed_connections.lock().await.insert(connection);
        self.connection_changed.notify_waiters();
    }

    async fn wait_for_connection_closed(&self, connection: u64, context: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.connection_changed.notified();
                if self.closed_connections.lock().await.contains(&connection) {
                    break;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("SSH connection {connection} did not close after {context}"));
    }

    async fn reset_sftp_hang_observation(&self) {
        *self.sftp_hung_connection.lock().await = None;
    }

    async fn record_sftp_hang(&self, connection: Option<u64>) {
        let Some(connection) = connection else {
            return;
        };
        *self.sftp_hung_connection.lock().await = Some(connection);
        self.sftp_hang_changed.notify_waiters();
    }

    async fn wait_for_sftp_hang(&self, context: &str) -> u64 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.sftp_hang_changed.notified();
                if let Some(connection) = *self.sftp_hung_connection.lock().await {
                    break connection;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("SFTP request did not hang during {context}"))
    }

    async fn latest_exec_generation(&self) -> u64 {
        self.exec_events.lock().await.generation
    }

    async fn record_exec_start(&self, channel: ExecChannel, command: &[u8]) {
        let mut events = self.exec_events.lock().await;
        events.generation += 1;
        let generation = events.generation;
        events.started.push(ExecStart {
            generation,
            command: command.to_vec(),
            channel,
        });
        drop(events);
        self.exec_changed.notify_one();
    }

    async fn record_cancel(&self, channel: ExecChannel) {
        self.exec_events.lock().await.cancelled.insert(channel);
        self.exec_changed.notify_one();
    }

    async fn wait_for_exec_start(&self, after: u64, command: &[u8]) -> ExecChannel {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.exec_changed.notified();
                if let Some(channel) = self
                    .exec_events
                    .lock()
                    .await
                    .started
                    .iter()
                    .find(|event| event.generation > after && event.command == command)
                    .map(|event| event.channel)
                {
                    break channel;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "remote command {:?} did not start within the test deadline",
                String::from_utf8_lossy(command)
            )
        })
    }

    async fn assert_no_exec_start(&self, after: u64, command: &[u8], context: &str) {
        let observed = tokio::time::timeout(Duration::from_millis(250), async {
            loop {
                let changed = self.exec_changed.notified();
                if self
                    .exec_events
                    .lock()
                    .await
                    .started
                    .iter()
                    .any(|event| event.generation > after && event.command == command)
                {
                    return;
                }
                changed.await;
            }
        })
        .await;
        assert!(observed.is_err(), "unexpected remote exec during {context}");
    }

    async fn wait_for_cancel(&self, channel: ExecChannel, context: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let changed = self.exec_changed.notified();
                if self.exec_events.lock().await.cancelled.contains(&channel) {
                    break;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("remote channel was not cancelled after {context}"));
    }

    async fn latest_upload_partial_generation(&self) -> u64 {
        self.upload_partial_events.lock().await.generation
    }

    async fn record_upload_partial_open(&self, path: &str) {
        let mut events = self.upload_partial_events.lock().await;
        events.generation += 1;
        let generation = events.generation;
        events.opened.push(UploadPartialOpen {
            generation,
            path: path.to_owned(),
        });
        drop(events);
        self.upload_partial_changed.notify_one();
    }

    async fn wait_for_upload_partial(&self, after: u64, destination: &str) -> String {
        let prefix = format!("{destination}.serctl-part-");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.upload_partial_changed.notified();
                if let Some(path) = self
                    .upload_partial_events
                    .lock()
                    .await
                    .opened
                    .iter()
                    .find(|event| event.generation > after && event.path.starts_with(&prefix))
                    .map(|event| event.path.clone())
                {
                    break path;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "upload partial for {destination:?} did not open within the independent 5 s observation deadline"
            )
        })
    }

    async fn latest_remote_forward_generation(&self) -> u64 {
        self.remote_forward_events.lock().await.generation
    }

    async fn register_remote_forward(
        &self,
        key: RemoteForwardKey,
        cancellation: tokio_util::sync::CancellationToken,
        listener_identity: std::net::SocketAddr,
        stopped: tokio::sync::oneshot::Receiver<std::net::SocketAddr>,
    ) -> anyhow::Result<u64> {
        let mut events = self.remote_forward_events.lock().await;
        if events.active.contains_key(&key) {
            return Err(anyhow::anyhow!(
                "duplicate test remote forward {}:{}",
                key.address,
                key.port
            ));
        }
        events.generation += 1;
        let generation = events.generation;
        events.started.push(RemoteForwardEvent {
            generation,
            key: key.clone(),
        });
        events.active.insert(
            key,
            RemoteForwardRegistration {
                generation,
                cancellation,
                listener_identity,
                stopped,
            },
        );
        drop(events);
        self.remote_forward_changed.notify_waiters();
        Ok(generation)
    }

    async fn finish_remote_forward(&self, key: &RemoteForwardKey, generation: u64) {
        let mut events = self.remote_forward_events.lock().await;
        if events
            .active
            .get(key)
            .is_some_and(|active| active.generation == generation)
        {
            events.active.remove(key);
        }
        drop(events);
        self.remote_forward_changed.notify_waiters();
    }

    async fn cancel_remote_forward(&self, key: &RemoteForwardKey) -> anyhow::Result<bool> {
        let registration = self.remote_forward_events.lock().await.active.remove(key);
        let Some(registration) = registration else {
            return Ok(false);
        };
        registration.cancellation.cancel();
        // The listener task sends this only after dropping its TcpListener.
        // Waiting here makes the SSH cancellation reply an exact cleanup
        // acknowledgement rather than a scheduling hint.
        let stopped_identity = registration
            .stopped
            .await
            .map_err(|_| anyhow::anyhow!("remote-forward listener task dropped its stop proof"))?;
        if stopped_identity != registration.listener_identity || stopped_identity.port() != key.port
        {
            return Err(anyhow::anyhow!(
                "remote-forward listener stop proof identified the wrong socket"
            ));
        }
        let mut events = self.remote_forward_events.lock().await;
        events.cancelled.push(RemoteForwardEvent {
            generation: registration.generation,
            key: key.clone(),
        });
        drop(events);
        self.remote_forward_changed.notify_waiters();
        Ok(true)
    }

    async fn record_remote_forward_accept(&self, generation: u64) {
        let mut events = self.remote_forward_events.lock().await;
        *events.accepted.entry(generation).or_default() += 1;
        drop(events);
        self.remote_forward_changed.notify_waiters();
    }

    async fn record_remote_forward_bridge(&self, generation: u64) {
        let mut events = self.remote_forward_events.lock().await;
        *events.bridged.entry(generation).or_default() += 1;
        drop(events);
        self.remote_forward_changed.notify_waiters();
    }

    async fn remote_forward_flow_counts(&self, generation: u64) -> (u64, u64) {
        let events = self.remote_forward_events.lock().await;
        (
            events.accepted.get(&generation).copied().unwrap_or(0),
            events.bridged.get(&generation).copied().unwrap_or(0),
        )
    }

    async fn wait_for_remote_forward(&self, after: u64, address: &str) -> RemoteForwardEvent {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.remote_forward_changed.notified();
                if let Some(event) = self
                    .remote_forward_events
                    .lock()
                    .await
                    .started
                    .iter()
                    .find(|event| event.generation > after && event.key.address == address)
                    .cloned()
                {
                    return event;
                }
                changed.await;
            }
        })
        .await
        .expect("remote-forward listener was not registered")
    }

    async fn wait_for_remote_forward_cancel(&self, generation: u64) -> RemoteForwardEvent {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.remote_forward_changed.notified();
                if let Some(event) = self
                    .remote_forward_events
                    .lock()
                    .await
                    .cancelled
                    .iter()
                    .find(|event| event.generation == generation)
                    .cloned()
                {
                    return event;
                }
                changed.await;
            }
        })
        .await
        .expect("remote-forward cancellation was not observed")
    }
}

struct TestSsh {
    state: Arc<TestState>,
    connection: u64,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

/// Read the complete client identification and then close before sending any
/// server byte. Russh classifies this pre-banner EOF as `Disconnect`; it is
/// safe to retry because no host key or password has crossed the transport.
async fn close_before_server_identification(mut socket: TcpStream) {
    let client_banner = async {
        for _ in 0..256 {
            if socket.read_u8().await? == b'\n' {
                return Ok::<(), std::io::Error>(());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "client SSH banner exceeded test bound",
        ))
    };
    tokio::time::timeout(Duration::from_secs(1), client_banner)
        .await
        .expect("client did not send its SSH banner")
        .unwrap();
    let _ = socket.shutdown().await;
}

struct ObservedSftpStream<S> {
    inner: S,
    state: Arc<TestState>,
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedSftpStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, std::task::Poll::Ready(Ok(()))) {
            self.state
                .sftp_wire_read_bytes
                .fetch_add((buffer.filled().len() - before) as u64, Ordering::SeqCst);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedSftpStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

async fn run_test_native_helper<S>(mut stream: S, state: Arc<TestState>) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let expected_identity = test_native_expected_identity();
    native::write_handshake_control(
        &mut stream,
        &native::Control::HelperHello {
            version: native::VERSION,
            max_chunk: native::DEFAULT_CHUNK_BYTES,
            max_window: native::MAX_WINDOW_BYTES,
            resume: true,
            sha256: true,
            fsync: true,
            no_replace: true,
            identity: native::HelperRuntimeIdentity {
                name: expected_identity.name,
                binary_size: expected_identity.binary_size,
                sha256: expected_identity.sha256,
                version: expected_identity.version,
            },
        },
        native::HandshakePeer::Helper,
    )
    .await?;
    let (chunk, window) = match native::read_frame(&mut stream).await? {
        Some(native::Frame::Control(native::Control::Hello {
            version,
            max_chunk,
            max_window,
            sha256,
            fsync,
            no_replace,
            ..
        })) if version == native::VERSION && sha256 && fsync && no_replace => (
            max_chunk.min(native::DEFAULT_CHUNK_BYTES),
            max_window.min(native::MAX_WINDOW_BYTES),
        ),
        _ => anyhow::bail!("test native client did not complete the handshake"),
    };
    anyhow::ensure!(chunk > 0 && window >= chunk, "invalid native limits");
    state
        .native_negotiated_chunk
        .store(chunk as u64, Ordering::SeqCst);
    state
        .native_negotiated_window
        .store(window as u64, Ordering::SeqCst);
    match native::read_frame(&mut stream).await? {
        Some(native::Frame::Control(native::Control::BeginPush {
            transfer_id,
            target,
            size,
            sha256,
            ..
        })) => {
            let transfer_id_bytes = native::parse_transfer_id(&transfer_id)?;
            anyhow::ensure!(
                !state.files.lock().await.contains_key(&target),
                "destination already exists"
            );
            native::write_control(
                &mut stream,
                &native::Control::Ready {
                    chunk,
                    window,
                    durable_offset: 0,
                },
            )
            .await?;
            let mut payload = Vec::with_capacity(size as usize);
            loop {
                match native::read_frame(&mut stream).await? {
                    Some(native::Frame::Data(data)) => {
                        anyhow::ensure!(
                            data.transfer_id == transfer_id_bytes
                                && data.offset == payload.len() as u64,
                            "native push offset mismatch"
                        );
                        state.native_push_frames.fetch_add(1, Ordering::SeqCst);
                        state
                            .native_push_max_chunk
                            .fetch_max(data.payload.len() as u64, Ordering::SeqCst);
                        state.native_push_data_received.notify_waiters();
                        payload.extend_from_slice(&data.payload);
                        anyhow::ensure!(payload.len() as u64 <= size, "native push overflow");
                        state.wait_for_native_push_ack_release().await;
                        native::write_control(
                            &mut stream,
                            &native::Control::Ack {
                                confirmed_offset: payload.len() as u64,
                                durable_offset: payload.len() as u64,
                                receiver_window: window,
                            },
                        )
                        .await?;
                    }
                    Some(native::Frame::Control(native::Control::Commit)) => break,
                    Some(native::Frame::Control(control)) => {
                        anyhow::bail!("unexpected native push control: {control:?}")
                    }
                    None => anyhow::bail!("native push stream closed before commit"),
                }
            }
            anyhow::ensure!(payload.len() as u64 == size, "native push size mismatch");
            let actual_sha256 = hex::encode(Sha256::digest(&payload));
            anyhow::ensure!(actual_sha256 == sha256, "native push SHA-256 mismatch");
            let replaced = state.files.lock().await.insert(target, payload);
            anyhow::ensure!(replaced.is_none(), "native no-replace race");
            native::write_control(
                &mut stream,
                &native::Control::Completed {
                    size,
                    sha256: actual_sha256,
                },
            )
            .await?;
        }
        Some(native::Frame::Control(native::Control::BeginPull {
            transfer_id,
            source,
            offset,
        })) => {
            let transfer_id_bytes = native::parse_transfer_id(&transfer_id)?;
            let payload = state
                .files
                .lock()
                .await
                .get(&source)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("native source not found"))?;
            anyhow::ensure!(
                offset <= payload.len() as u64,
                "native pull offset overflow"
            );
            let sha256 = hex::encode(Sha256::digest(&payload));
            native::write_control(
                &mut stream,
                &native::Control::PullReady {
                    chunk,
                    window,
                    size: payload.len() as u64,
                    sha256: sha256.clone(),
                    start_offset: offset,
                },
            )
            .await?;
            let mut confirmed = offset;
            while confirmed < payload.len() as u64 {
                let end = (confirmed as usize + chunk as usize).min(payload.len());
                let data = native::DataFrame::new(
                    transfer_id_bytes,
                    confirmed,
                    payload[confirmed as usize..end].to_vec(),
                )?;
                state.native_pull_frames.fetch_add(1, Ordering::SeqCst);
                state
                    .native_pull_max_chunk
                    .fetch_max(data.payload.len() as u64, Ordering::SeqCst);
                native::write_data(&mut stream, &data).await?;
                match native::read_frame(&mut stream).await? {
                    Some(native::Frame::Control(native::Control::Ack {
                        confirmed_offset,
                        durable_offset,
                        ..
                    })) if confirmed_offset == end as u64 && durable_offset <= confirmed_offset => {
                        confirmed = confirmed_offset;
                    }
                    _ => anyhow::bail!("native pull acknowledgement mismatch"),
                }
            }
            native::write_control(
                &mut stream,
                &native::Control::Completed {
                    size: payload.len() as u64,
                    sha256,
                },
            )
            .await?;
        }
        None => return Ok(()),
        _ => anyhow::bail!("unexpected native transfer root"),
    }
    Ok(())
}

fn test_native_expected_identity() -> ipc::ExpectedNativeHelperIdentity {
    ipc::ExpectedNativeHelperIdentity {
        name: "serctl-xfer".to_owned(),
        binary_size: 123,
        sha256: "ab".repeat(32),
        version: "serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)".to_owned(),
    }
}

async fn run_test_remote_forward_listener(
    listener: TcpListener,
    handle: russh::server::Handle,
    state: Arc<TestState>,
    key: RemoteForwardKey,
    generation: u64,
    cancellation: tokio_util::sync::CancellationToken,
    stopped: tokio::sync::oneshot::Sender<std::net::SocketAddr>,
) {
    let listener_identity = listener
        .local_addr()
        .expect("registered remote-forward listener lost its socket identity");
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((mut socket, peer)) = accepted else {
            break;
        };
        state.record_remote_forward_accept(generation).await;
        let handle = handle.clone();
        let state = Arc::clone(&state);
        let connected_address = key.address.clone();
        let connected_port = u32::from(key.port);
        tokio::spawn(async move {
            let channel = handle
                .channel_open_forwarded_tcpip(
                    connected_address,
                    connected_port,
                    peer.ip().to_string(),
                    u32::from(peer.port()),
                )
                .await;
            if let Ok(channel) = channel {
                state.record_remote_forward_bridge(generation).await;
                let mut channel = channel.into_stream();
                let _ = tokio::io::copy_bidirectional(&mut socket, &mut channel).await;
            }
        });
    }
    drop(listener);
    state.finish_remote_forward(&key, generation).await;
    let _ = stopped.send(listener_identity);
}

impl russh::server::Handler for TestSsh {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.state
            .password_auth_attempts
            .fetch_add(1, Ordering::SeqCst);
        if self
            .state
            .disconnect_next_password_auth
            .swap(false, Ordering::SeqCst)
        {
            anyhow::bail!("injected password-auth transport disconnect");
        }
        Ok(if user == "tester" && password == "password" {
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self
            .state
            .disconnect_two_channel_opens
            .load(Ordering::SeqCst)
        {
            let mut pending = self.state.pending_channel_open.lock().await;
            if pending.is_none() {
                *pending = Some(PendingChannelOpen { channel, reply });
                return Ok(());
            }
            self.state
                .disconnect_two_channel_opens
                .store(false, Ordering::SeqCst);
            let first = pending
                .take()
                .expect("first stale channel-open disappeared");
            session.disconnect(
                Disconnect::ByApplication,
                "test disconnect with two pending channel confirmations",
                "en-US",
            )?;
            drop(first.reply);
            drop(first.channel);
            drop(reply);
            drop(channel);
            return Ok(());
        }
        if self
            .state
            .reject_next_channel_open
            .swap(false, Ordering::SeqCst)
        {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            drop(channel);
            return Ok(());
        }
        if self
            .state
            .hang_next_channel_open
            .swap(false, Ordering::SeqCst)
        {
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(reply);
            drop(channel);
            return Ok(());
        }
        if self
            .state
            .disconnect_next_channel_open
            .swap(false, Ordering::SeqCst)
        {
            session.disconnect(
                Disconnect::ByApplication,
                "test disconnect before channel confirmation",
                "en-US",
            )?;
            drop(reply);
            drop(channel);
            return Ok(());
        }
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let port = u16::try_from(port_to_connect)
            .map_err(|_| anyhow::anyhow!("direct-tcpip port exceeds u16"))?;
        let mut target = match TcpStream::connect((host_to_connect, port)).await {
            Ok(target) => target,
            Err(_) => {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut channel = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut channel, &mut target).await;
        });
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Production must never ask the server to expose a remote-forward
        // listener beyond IPv4 loopback.
        if address != "127.0.0.1" {
            return Ok(false);
        }
        let Ok(requested_port) = u16::try_from(*port) else {
            return Ok(false);
        };
        let listener = match TcpListener::bind((address, requested_port)).await {
            Ok(listener) => listener,
            Err(_) => return Ok(false),
        };
        let listener_identity = listener.local_addr()?;
        let effective_port = listener_identity.port();
        *port = u32::from(effective_port);
        let key = RemoteForwardKey {
            connection: self.connection,
            address: address.to_owned(),
            port: effective_port,
        };
        let cancellation = tokio_util::sync::CancellationToken::new();
        let (stopped_tx, stopped_rx) = tokio::sync::oneshot::channel();
        let generation = self
            .state
            .register_remote_forward(
                key.clone(),
                cancellation.clone(),
                listener_identity,
                stopped_rx,
            )
            .await?;
        tokio::spawn(run_test_remote_forward_listener(
            listener,
            session.handle(),
            Arc::clone(&self.state),
            key,
            generation,
            cancellation,
            stopped_tx,
        ));
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Ok(port) = u16::try_from(port) else {
            return Ok(false);
        };
        self.state
            .cancel_remote_forward(&RemoteForwardKey {
                connection: self.connection,
                address: address.to_owned(),
                port,
            })
            .await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let exec_channel = ExecChannel {
            connection: self.connection,
            channel,
        };
        self.state.record_exec_start(exec_channel, command).await;
        match command {
            b"serctl-xfer serve --stdio" => {
                let channel = self
                    .channels
                    .lock()
                    .await
                    .remove(&channel)
                    .ok_or_else(|| anyhow::anyhow!("native exec channel was not registered"))?;
                let state = Arc::clone(&self.state);
                tokio::spawn(async move {
                    if let Err(error) =
                        run_test_native_helper(channel.into_stream(), Arc::clone(&state)).await
                    {
                        eprintln!("test native helper failed: {error:#}");
                    }
                    state.native_helpers_finished.fetch_add(1, Ordering::SeqCst);
                    state.native_helper_finished.notify_waiters();
                });
            }
            b"ok" => {
                session.data(channel, b"evidence\n".to_vec())?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            b"disconnect" => {
                session.disconnect(Disconnect::ByApplication, "test disconnect", "en-US")?;
                // A transport disconnect ends every channel without a later
                // per-channel EOF callback, so record that terminal state at
                // the point where the test server queues the disconnect.
                self.state.record_cancel(exec_channel).await;
            }
            b"hang" | b"replay-probe" => {}
            b"overflow" => {
                for _ in 0..257 {
                    session.data(channel, vec![b'x'; 32 * 1024])?;
                }
            }
            _ => {
                session.exit_status_request(channel, 7)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state
            .record_cancel(ExecChannel {
                connection: self.connection,
                channel,
            })
            .await;
        session.close(channel)?;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state
            .record_cancel(ExecChannel {
                connection: self.connection,
                channel,
            })
            .await;
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
        let Some(channel) = self.channels.lock().await.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        session.channel_success(channel.id())?;
        let sftp = MemorySftp {
            state: self.state.clone(),
            connection: Some(self.connection),
            handles: HashMap::new(),
            directory_handles: HashMap::new(),
            directories_read: HashSet::new(),
        };
        let stream = ObservedSftpStream {
            inner: channel.into_stream(),
            state: self.state.clone(),
        };
        tokio::spawn(russh_sftp::server::run(stream, sftp));
        Ok(())
    }
}

struct MemorySftp {
    state: Arc<TestState>,
    connection: Option<u64>,
    handles: HashMap<String, String>,
    directory_handles: HashMap<String, String>,
    directories_read: HashSet<String>,
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "ok".into(),
        language_tag: "en-US".into(),
    }
}

impl russh_sftp::server::Handler for MemorySftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        let mut version = Version::new();
        version
            .extensions
            .insert(russh_sftp::extensions::HARDLINK.into(), "1".into());
        Ok(version)
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.state.sftp_open_calls.fetch_add(1, Ordering::SeqCst);
        if self.state.sftp_hang.load(Ordering::SeqCst) {
            self.state.record_sftp_hang(self.connection).await;
            std::future::pending::<()>().await;
        }
        let mut files = self.state.files.lock().await;
        if flags.contains(OpenFlags::CREATE) {
            if flags.contains(OpenFlags::EXCLUDE) && files.contains_key(&filename) {
                return Err(StatusCode::Failure);
            }
            files.entry(filename.clone()).or_default();
            if filename.contains(".serctl-part-") {
                self.state.upload_partial_permissions.store(
                    attrs.permissions.unwrap_or_default() as u64,
                    Ordering::SeqCst,
                );
                self.state.record_upload_partial_open(&filename).await;
            }
        }
        let Some(file) = files.get_mut(&filename) else {
            return Err(StatusCode::NoSuchFile);
        };
        if flags.contains(OpenFlags::TRUNCATE) {
            file.clear();
        }
        let handle = format!("h{id}");
        self.handles.insert(handle.clone(), filename);
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        self.directory_handles.remove(&handle);
        self.directories_read.remove(&handle);
        Ok(ok_status(id))
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let path = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let files = self.state.files.lock().await;
        let file = files.get(path).ok_or(StatusCode::NoSuchFile)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes {
                size: Some(file.len() as u64),
                ..FileAttributes::default()
            },
        })
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let canonical = if path.is_empty() || path == "." {
            "/".to_owned()
        } else if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        Ok(Name {
            id,
            files: vec![File::dummy(canonical)],
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let handle = format!("d{id}");
        self.directory_handles.insert(handle.clone(), path);
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let path = self
            .directory_handles
            .get(&handle)
            .ok_or(StatusCode::Failure)?;
        if !self.directories_read.insert(handle) {
            return Err(StatusCode::Eof);
        }
        if self.state.sftp_large_dir.load(Ordering::SeqCst) {
            return Ok(Name {
                id,
                files: (0..=10_000)
                    .map(|index| File::dummy(format!("entry-{index}")))
                    .collect(),
            });
        }

        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{}/", path.trim_end_matches('/'))
        };
        let files = self.state.files.lock().await;
        let entries = files
            .iter()
            .filter_map(|(file_path, data)| {
                let name = file_path.strip_prefix(&prefix)?;
                if name.is_empty() || name.contains('/') {
                    return None;
                }
                Some(File::new(
                    name,
                    FileAttributes {
                        size: Some(data.len() as u64),
                        ..FileAttributes::default()
                    },
                ))
            })
            .collect();
        Ok(Name { id, files: entries })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let call = self.state.sftp_write_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.state.sftp_write_hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.state.sftp_write_hang_at.load(Ordering::SeqCst) == call {
            std::future::pending::<()>().await;
        }
        let delay_ms = self.state.sftp_write_delay_ms.load(Ordering::SeqCst);
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        let path = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let mut files = self.state.files.lock().await;
        let file = files.get_mut(path).ok_or(StatusCode::NoSuchFile)?;
        let offset = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
        let end = offset.checked_add(data.len()).ok_or(StatusCode::Failure)?;
        if file.len() < end {
            file.resize(end, 0);
        }
        file[offset..end].copy_from_slice(&data);
        Ok(ok_status(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let path = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let files = self.state.files.lock().await;
        let file = files.get(path).ok_or(StatusCode::NoSuchFile)?;
        let offset = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
        if offset >= file.len() {
            return Err(StatusCode::Eof);
        }
        let end = offset.saturating_add(len as usize).min(file.len());
        Ok(Data {
            id,
            data: file[offset..end].to_vec(),
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.state.sftp_stat_calls.fetch_add(1, Ordering::SeqCst);
        if self.state.sftp_hang.load(Ordering::SeqCst) {
            self.state.record_sftp_hang(self.connection).await;
            std::future::pending::<()>().await;
        }
        let files = self.state.files.lock().await;
        let file = files.get(&path).ok_or(StatusCode::NoSuchFile)?;
        let attrs = FileAttributes {
            size: Some(file.len() as u64),
            ..FileAttributes::default()
        };
        Ok(Attrs { id, attrs })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        if filename.contains(".serctl-part-") {
            loop {
                let changed = self.state.upload_partial_remove_changed.notified();
                if !self.state.upload_partial_remove_hang.load(Ordering::SeqCst) {
                    break;
                }
                changed.await;
            }
        }
        if filename.contains(".serctl-part-")
            && self
                .state
                .upload_partial_remove_delay
                .load(Ordering::SeqCst)
        {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        self.state
            .files
            .lock()
            .await
            .remove(&filename)
            .ok_or(StatusCode::NoSuchFile)?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let mut files = self.state.files.lock().await;
        if files.contains_key(&newpath) {
            return Err(StatusCode::Failure);
        }
        let data = files.remove(&oldpath).ok_or(StatusCode::NoSuchFile)?;
        files.insert(newpath, data);
        Ok(ok_status(id))
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        if request != russh_sftp::extensions::HARDLINK {
            return Err(StatusCode::OpUnsupported);
        }
        let mut bytes = data.into();
        let hardlink =
            russh_sftp::de::from_bytes::<russh_sftp::extensions::HardlinkExtension>(&mut bytes)
                .map_err(|_| StatusCode::BadMessage)?;
        let mut files = self.state.files.lock().await;
        if self
            .state
            .hardlink_race_target
            .swap(false, Ordering::SeqCst)
        {
            files.insert(hardlink.newpath.clone(), b"concurrent winner".to_vec());
        }
        if files.contains_key(&hardlink.newpath) {
            return Err(StatusCode::Failure);
        }
        let data = files
            .get(&hardlink.oldpath)
            .cloned()
            .ok_or(StatusCode::NoSuchFile)?;
        files.insert(hardlink.newpath, data);
        Ok(Packet::Status(ok_status(id)))
    }
}

async fn matrix_sftp_session(
    state: Arc<TestState>,
    max_concurrent_writes: usize,
) -> (russh_sftp::client::SftpSession, tokio::task::JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(2 * 1024 * 1024);
    let handler = MemorySftp {
        state,
        connection: None,
        handles: HashMap::new(),
        directory_handles: HashMap::new(),
        directories_read: HashSet::new(),
    };
    let server = tokio::spawn(russh_sftp::server::run(server, handler));
    let client = russh_sftp::client::SftpSession::new_with_config(
        client,
        russh_sftp::client::Config {
            max_packet_len: 256 * 1024,
            max_concurrent_writes,
            request_timeout_secs: 2,
        },
    )
    .await
    .unwrap();
    (client, server)
}

#[tokio::test]
async fn sftp_chunk_window_and_delayed_or_lost_status_matrix() {
    use tokio::io::AsyncWriteExt as _;

    for chunk_bytes in [4, 8, 16, 32].map(|kib| kib * 1024) {
        for max_concurrent_writes in [1, 2, 8] {
            let state = Arc::new(TestState::default());
            state
                .files
                .lock()
                .await
                .insert("/matrix.bin".into(), Vec::new());
            state.sftp_write_delay_ms.store(2, Ordering::SeqCst);
            let (sftp, server) =
                matrix_sftp_session(Arc::clone(&state), max_concurrent_writes).await;
            let mut file = sftp
                .open_with_flags("/matrix.bin", OpenFlags::WRITE | OpenFlags::TRUNCATE)
                .await
                .unwrap();
            let payload = vec![0x5a; chunk_bytes * 4];
            for chunk in payload.chunks(chunk_bytes) {
                file.write_all(chunk).await.unwrap();
            }
            file.shutdown().await.unwrap();
            assert_eq!(
                state.files.lock().await.get("/matrix.bin").unwrap(),
                &payload,
                "chunk={chunk_bytes} window={max_concurrent_writes}"
            );
            sftp.close().await.unwrap();
            server.await.unwrap();
        }
    }

    for max_concurrent_writes in [1, 2, 8] {
        let state = Arc::new(TestState::default());
        state
            .files
            .lock()
            .await
            .insert("/lost-ack.bin".into(), Vec::new());
        state.sftp_write_hang_at.store(1, Ordering::SeqCst);
        let (sftp, server) = matrix_sftp_session(Arc::clone(&state), max_concurrent_writes).await;
        let mut file = sftp
            .open_with_flags("/lost-ack.bin", OpenFlags::WRITE | OpenFlags::TRUNCATE)
            .await
            .unwrap();
        for queued in 0..max_concurrent_writes {
            tokio::time::timeout(
                Duration::from_millis(100),
                file.write_all(&[queued as u8; 4096]),
            )
            .await
            .unwrap_or_else(|_| {
                panic!("WRITE {queued} blocked before the configured window was full")
            })
            .unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), file.write_all(&[0xaa; 4096]))
                .await
                .is_err(),
            "window={max_concurrent_writes} did not block at WRITE N+1 after the first STATUS was lost"
        );
        drop(file);
        drop(sftp);
        server.abort();
        let _ = server.await;
    }
}

async fn assert_tcp_echo(bind_host: &str, bind_port: u16, evidence: &[u8]) {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect((bind_host, bind_port)),
    )
    .await
    .expect("tunnel listener did not accept promptly")
    .unwrap();
    stream.write_all(evidence).await.unwrap();
    let mut echoed = vec![0_u8; evidence.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
        .await
        .expect("tunnel echo did not return promptly")
        .unwrap();
    assert_eq!(echoed, evidence);
}

async fn assert_remote_forward_unusable(
    state: &TestState,
    generation: u64,
    bind_host: &str,
    bind_port: u16,
) {
    let counts_before = state.remote_forward_flow_counts(generation).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    if let Ok(Ok(mut socket)) =
        tokio::time::timeout_at(deadline, TcpStream::connect((bind_host, bind_port))).await
    {
        // Windows may complete a handshake that was already queued before the
        // listener handle was dropped. Prove that such a socket is not a usable
        // orphaned forward by attempting a fresh, unique round trip under the
        // same absolute deadline.
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        if matches!(
            tokio::time::timeout_at(deadline, socket.write_all(&nonce)).await,
            Ok(Ok(()))
        ) {
            let mut response = [0_u8; 32];
            if let Ok(Ok(_)) =
                tokio::time::timeout_at(deadline, socket.read_exact(&mut response)).await
            {
                assert_ne!(
                    response, nonce,
                    "cancelled remote forward still echoed a fresh post-cancel nonce"
                );
                panic!("cancelled remote forward returned a complete post-cancel response");
            }
        }
    }
    assert_eq!(
        state.remote_forward_flow_counts(generation).await,
        counts_before,
        "post-cancel connection created a new remote-forward accept or SSH bridge"
    );
}

async fn assert_socks5_echo(bind_host: &str, bind_port: u16, target_port: u16) {
    let mut stream = TcpStream::connect((bind_host, bind_port)).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);

    let [port_high, port_low] = target_port.to_be_bytes();
    stream
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port_high, port_low])
        .await
        .unwrap();
    let mut response_head = [0_u8; 4];
    stream.read_exact(&mut response_head).await.unwrap();
    assert_eq!(&response_head[..3], &[5, 0, 0]);
    let remaining = match response_head[3] {
        1 => 6,
        4 => 18,
        3 => {
            let length = stream.read_u8().await.unwrap() as usize;
            length + 2
        }
        atyp => panic!("unexpected SOCKS5 response address type {atyp}"),
    };
    let mut bound_address = vec![0_u8; remaining];
    stream.read_exact(&mut bound_address).await.unwrap();

    let evidence = b"dynamic tunnel evidence";
    stream.write_all(evidence).await.unwrap();
    let mut echoed = vec![0_u8; evidence.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
        .await
        .expect("SOCKS5 echo did not return promptly")
        .unwrap();
    assert_eq!(echoed, evidence);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_daemon_exec_timeout_and_transfer_e2e() {
    let _test_home_lock = TEST_HOME_LOCK.lock().await;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let test_home_guard = E2eTestHome::create(unique);
    let test_home = test_home_guard.path().to_owned();
    // Start from a real empty v4 vault. On Windows the administrator policy
    // and the removable-media half of 2-of-2 recovery must exist before the
    // first profile can be created. Keep the media only in this test's memory;
    // the vault never contains enough material to recover a profile alone.
    #[cfg(windows)]
    let mut recovery_media = Zeroizing::new(Vec::new());
    #[cfg(windows)]
    vault::initialize_admin_password(E2E_ADMINISTRATOR_PASSPHRASE, |media| {
        recovery_media.extend_from_slice(media);
        Ok(())
    })
    .unwrap();
    let administrator_passphrase = if cfg!(windows) {
        Some(E2E_ADMINISTRATOR_PASSPHRASE)
    } else {
        None
    };

    let state = Arc::new(TestState::default());
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
    let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = ssh_listener.local_addr().unwrap().port();
    let ssh_state = state.clone();
    let ssh_task = tokio::spawn(async move {
        loop {
            let (socket, _) = ssh_listener.accept().await.unwrap();
            let connection = ssh_state.next_connection.fetch_add(1, Ordering::SeqCst);
            if ssh_state
                .pre_kex_disconnects_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                close_before_server_identification(socket).await;
                ssh_state.record_connection_closed(connection).await;
                continue;
            }
            let handler = TestSsh {
                state: ssh_state.clone(),
                connection,
                channels: Arc::new(Mutex::new(HashMap::new())),
            };
            let config = config.clone();
            let connection_state = ssh_state.clone();
            tokio::spawn(async move {
                let result = match russh::server::run_stream(config, socket, handler).await {
                    Ok(running) => running.await,
                    Err(error) => Err(error),
                };
                if let Err(error) = result {
                    eprintln!("test SSH transport failed: {error:#}");
                }
                connection_state.record_connection_closed(connection).await;
            });
        }
    });
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => read,
                    };
                    if socket.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // A first-use connection is split at the security boundary: KEX observes
    // the host key, pin persistence runs while the exclusive profile lease is
    // held, and only then may password authentication begin. Exercise a real
    // persistence failure and prove the fake SSH server never receives an
    // authentication request on that transport.
    let tofu_profile = "tofu-auth-order";
    let tofu_passphrase = TOFU_PROFILE_PASSPHRASE;
    vault::create_profile(
        tofu_profile,
        &vault::Creds {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "tester".into(),
            password: "password".into(),
            host_key: None,
        },
        tofu_passphrase,
        administrator_passphrase,
    )
    .unwrap();
    let tofu_lease = vault::acquire_runtime_lease(tofu_profile).unwrap();
    let tofu_creds = vault::decrypt(tofu_profile, tofu_passphrase).unwrap();
    let auth_before_failed_pin = state.password_auth_attempts.load(Ordering::SeqCst);
    let staged = serctl_core::ssh::SshSession::connect_key_exchange_until(
        &tofu_creds,
        None,
        tokio::time::Instant::now() + Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(staged.observed_fingerprint(), fingerprint);
    let pin_error = vault::set_pinned_fp_with_lock_timeout(
        tofu_profile,
        fingerprint.clone(),
        "definitely-wrong-master",
        Duration::from_secs(1),
        &tofu_lease,
    )
    .unwrap_err();
    assert!(pin_error.to_string().contains("wrong profile passphrase"));
    staged.abort().await;
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        auth_before_failed_pin,
        "password authentication was sent before the host-key pin persisted"
    );
    assert!(vault::decrypt(tofu_profile, tofu_passphrase)
        .unwrap()
        .host_key
        .is_none());
    drop(tofu_lease);

    let daemon_creds = vault::Creds {
        host: "127.0.0.1".into(),
        port: ssh_port,
        user: "tester".into(),
        password: "password".into(),
        // Exercise the global-daemon first-use TOFU path. Its barrier-backed
        // shared profile lease must permit this identity-preserving pin write
        // before SSH password authentication.
        host_key: None,
    };
    vault::create_profile(
        "e2e",
        &daemon_creds,
        E2E_PROFILE_PASSPHRASE,
        administrator_passphrase,
    )
    .unwrap();
    let auth_disconnect_profile = "auth-disconnect";
    vault::create_profile(
        auth_disconnect_profile,
        &vault::Creds {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "tester".into(),
            password: "password".into(),
            host_key: Some(fingerprint.clone()),
        },
        AUTH_DISCONNECT_PROFILE_PASSPHRASE,
        administrator_passphrase,
    )
    .unwrap();
    let kex_persistent_profile = "kex-persistent";
    vault::create_profile(
        kex_persistent_profile,
        &vault::Creds {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "tester".into(),
            password: "password".into(),
            host_key: Some(fingerprint.clone()),
        },
        KEX_PERSISTENT_PROFILE_PASSPHRASE,
        administrator_passphrase,
    )
    .unwrap();

    let daemon_instance = ipc::v6::InstanceId::random();
    let daemon_secret = ipc::v6::ActivationSecret::random();
    let daemon_endpoint = serctl_core::daemon_runtime::v6_endpoint(&daemon_instance).unwrap();
    #[cfg(unix)]
    assert!(
        daemon_endpoint.len() < 100,
        "E2E Unix socket path is not conservatively below macOS/Linux sun_path limits: {} bytes ({daemon_endpoint})",
        daemon_endpoint.len()
    );
    let mut daemon_task = tokio::spawn(daemon::run_global(
        daemon_instance,
        daemon_secret,
        "e2e-test-commit".to_owned(),
    ));
    let publish_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if serctl_core::daemon_runtime::read_descriptor()
            .unwrap()
            .is_some()
        {
            assert!(
                serctl_core::daemon_runtime::read_secret()
                    .unwrap()
                    .is_some(),
                "global daemon published its readiness descriptor before its activation secret"
            );
            break;
        }
        if daemon_task.is_finished() {
            let outcome = (&mut daemon_task).await;
            panic!(
                "global daemon exited before publishing its runtime descriptor at {daemon_endpoint}: {outcome:?}"
            );
        }
        if tokio::time::Instant::now() >= publish_deadline {
            panic!(
                "global daemon did not publish its runtime descriptor at {daemon_endpoint} ({} bytes; test home {})",
                daemon_endpoint.len(),
                test_home.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let descriptor = serctl_core::daemon_runtime::read_descriptor()
        .unwrap()
        .unwrap();
    assert_eq!(descriptor.pid, std::process::id());
    assert!(!descriptor.endpoint.is_empty());
    assert_eq!(descriptor.protocol_min, ipc::v6::IPC_PROTOCOL_VERSION_V6);

    // A wrong profile passphrase is rejected by the broker during the unlock
    // step, before it can reach SSH. Probe this first: once a profile is
    // unlocked the process-local mirror skips the unlock round trip.
    let wrong_status = client::daemon_status("e2e", "definitely-wrong-master")
        .await
        .unwrap_err();
    let wrong_status_chain = format!("{wrong_status:#}");
    assert!(
        wrong_status_chain.contains("wrong profile passphrase"),
        "wrong-passphrase status probe failed outside broker vault authentication: {}",
        wrong_status_chain.escape_debug()
    );
    let wrong_passphrase_after = state.latest_exec_generation().await;
    let wrong_passphrase = client::exec_capture_with_timeout(
        "e2e",
        "wrong-master-probe",
        Some("definitely-wrong-master"),
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert!(wrong_passphrase
        .to_string()
        .contains("wrong profile passphrase"));
    state
        .assert_no_exec_start(
            wrong_passphrase_after,
            b"wrong-master-probe",
            "wrong-profile-passphrase broker unlock",
        )
        .await;

    // A TCP EOF after the client identification but before any server byte is
    // an initial-connect failure that is safe to retry: no password has been
    // sent. The second transport succeeds under the same absolute deadline.
    let transient_connections = state.next_connection.load(Ordering::SeqCst);
    let transient_auth = state.password_auth_attempts.load(Ordering::SeqCst);
    let transient_exec = state.latest_exec_generation().await;
    state
        .pre_kex_disconnects_remaining
        .store(1, Ordering::SeqCst);
    let transient_output = client::exec_capture_with_timeout(
        tofu_profile,
        "ok",
        Some(tofu_passphrase),
        Duration::from_secs(3),
    )
    .await
    .expect("pre-authentication KEX disconnect did not reconnect once");
    assert_eq!(transient_output.stdout, b"evidence\n");
    assert_eq!(
        state.next_connection.load(Ordering::SeqCst),
        transient_connections + 2,
        "one transient pre-KEX disconnect must use exactly two transports"
    );
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        transient_auth + 1,
        "the failed pre-KEX transport must not receive a password"
    );
    assert_eq!(
        state.latest_exec_generation().await,
        transient_exec + 1,
        "the successful retry must submit the command exactly once"
    );

    // A persistent pre-KEX failure gets the same single retry budget and then
    // returns a phase-specific error. There must be no third connection, auth,
    // or exec side effect.
    let persistent_connections = state.next_connection.load(Ordering::SeqCst);
    let persistent_auth = state.password_auth_attempts.load(Ordering::SeqCst);
    let persistent_exec = state.latest_exec_generation().await;
    state
        .pre_kex_disconnects_remaining
        .store(2, Ordering::SeqCst);
    let persistent_error = client::exec_capture_with_timeout(
        kex_persistent_profile,
        "ok",
        Some(KEX_PERSISTENT_PROFILE_PASSPHRASE),
        Duration::from_secs(3),
    )
    .await
    .unwrap_err();
    let persistent_chain = format!("{persistent_error:#}");
    assert!(
        persistent_chain.contains(
            "SSH server identification phase failed after one pre-authentication reconnect",
        ) && (persistent_chain.contains("failure=terminal_disconnect")
            || persistent_chain.contains("failure=io")),
        "persistent pre-KEX error lost its phase/category: {}",
        persistent_chain.escape_debug()
    );
    assert!(
        persistent_chain.contains("first_attempt=[SSH attempt 1:")
            && persistent_chain.contains("SSH attempt 2:"),
        "persistent pre-KEX error did not keep both attempt numbers: {}",
        persistent_chain.escape_debug()
    );
    assert!(
        !persistent_chain.contains("pre-kex retry probe"),
        "remote disconnect free text escaped into the client diagnostic"
    );
    assert_eq!(
        state.next_connection.load(Ordering::SeqCst),
        persistent_connections + 2,
        "persistent pre-KEX failure exceeded its one-reconnect budget"
    );
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        persistent_auth,
        "persistent pre-KEX failure unexpectedly sent a password"
    );
    assert_eq!(state.latest_exec_generation().await, persistent_exec);

    // Once password authentication starts, disconnect is not replay-safe: it
    // receives context but no reconnect. This profile has never entered the
    // pool, proving the raw error is from initial unlock rather than SessionManager.
    let auth_disconnect_connections = state.next_connection.load(Ordering::SeqCst);
    let auth_disconnect_attempts = state.password_auth_attempts.load(Ordering::SeqCst);
    let auth_disconnect_exec = state.latest_exec_generation().await;
    state
        .disconnect_next_password_auth
        .store(true, Ordering::SeqCst);
    let auth_disconnect = client::exec_capture_with_timeout(
        auth_disconnect_profile,
        "ok",
        Some(AUTH_DISCONNECT_PROFILE_PASSPHRASE),
        Duration::from_secs(3),
    )
    .await
    .unwrap_err();
    let auth_disconnect_chain = format!("{auth_disconnect:#}");
    assert!(
        auth_disconnect_chain.contains("SSH password authentication phase failed")
            || auth_disconnect_chain
                .contains("SSH password authentication rejected the stored SSH credential"),
        "authentication failure lost its bounded phase/result: {}",
        auth_disconnect_chain.escape_debug()
    );
    assert_eq!(
        state.next_connection.load(Ordering::SeqCst),
        auth_disconnect_connections + 1,
        "password-authentication disconnect must not reconnect"
    );
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        auth_disconnect_attempts + 1,
        "password-authentication disconnect must not replay authentication"
    );
    assert_eq!(state.latest_exec_generation().await, auth_disconnect_exec);

    // Unlock through the broker: the pool's credential lease is what blocks
    // vault mutations while a profile is live and unlocked.
    assert!(matches!(
        client::daemon_status("e2e", E2E_PROFILE_PASSPHRASE)
            .await
            .unwrap(),
        Some(client::DaemonStatus { profile, .. }) if profile == "e2e"
    ));
    assert_eq!(
        vault::decrypt("e2e", E2E_PROFILE_PASSPHRASE)
            .unwrap()
            .host_key
            .as_deref(),
        Some(fingerprint.as_str()),
        "global daemon did not persist the first-use host-key pin"
    );

    let mutation_error = vault::update_profile(
        "e2e",
        &vault::Creds {
            host: "changed.example".into(),
            port: 2222,
            user: "other".into(),
            password: "replacement".into(),
            host_key: None,
        },
        E2E_PROFILE_PASSPHRASE,
        None,
    )
    .unwrap_err();
    assert!(mutation_error.to_string().contains("daemon"));
    assert!(vault::remove_profile("e2e", E2E_PROFILE_PASSPHRASE, None)
        .unwrap_err()
        .to_string()
        .contains("daemon"));
    let vault_before_daemon_rekey = std::fs::read(vault::vault_path().unwrap()).unwrap();
    let daemon_rekey_error = vault::change_profile_passphrase(
        "e2e",
        E2E_PROFILE_PASSPHRASE,
        "must-not-commit-daemon-rekey",
        None,
    )
    .unwrap_err();
    assert!(daemon_rekey_error.to_string().contains("daemon"));
    assert_eq!(
        std::fs::read(vault::vault_path().unwrap()).unwrap(),
        vault_before_daemon_rekey,
        "a contended daemon lease allowed profile rekeying to modify the vault"
    );

    // Daemon-routed local forwarding carries data directly over SSH rather
    // than through IPC. Port zero also proves readiness reports the effective
    // listener selected by the operating system.
    let daemon_tunnel = tokio::time::timeout(
        Duration::from_secs(5),
        client::open_gui_tunnel(
            "e2e",
            client::TunnelSpec::local(0, echo_port),
            Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned()),
        ),
    )
    .await
    .expect("daemon local tunnel did not become ready")
    .unwrap();
    let daemon_tunnel_ready = daemon_tunnel.ready().clone();
    assert_eq!(daemon_tunnel_ready.bind_host, "127.0.0.1");
    assert_ne!(daemon_tunnel_ready.bind_port, 0);
    assert_tcp_echo(
        &daemon_tunnel_ready.bind_host,
        daemon_tunnel_ready.bind_port,
        b"daemon local tunnel evidence",
    )
    .await;
    daemon_tunnel.cancel();
    tokio::time::timeout(Duration::from_secs(5), daemon_tunnel.wait())
        .await
        .expect("daemon local tunnel did not stop promptly")
        .unwrap();

    // Remote forwarding binds on the SSH server, then opens a
    // forwarded-tcpip channel back to a target local to serctl. The test
    // server tracks the exact address/allocated port and does not acknowledge
    // cancellation until its listener object has been dropped.
    let remote_forward_after = state.latest_remote_forward_generation().await;
    let daemon_remote_tunnel = tokio::time::timeout(
        Duration::from_secs(5),
        client::open_gui_tunnel(
            "e2e",
            client::TunnelSpec::remote(0, echo_port),
            Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned()),
        ),
    )
    .await
    .expect("daemon remote tunnel did not become ready")
    .unwrap();
    let daemon_remote_ready = daemon_remote_tunnel.ready().clone();
    assert_eq!(daemon_remote_ready.bind_host, "127.0.0.1");
    assert_ne!(
        daemon_remote_ready.bind_port, echo_port,
        "remote readiness reported the local echo target instead of the server listener"
    );
    let remote_forward = state
        .wait_for_remote_forward(remote_forward_after, &daemon_remote_ready.bind_host)
        .await;
    assert_eq!(remote_forward.key.port, daemon_remote_ready.bind_port);
    assert_tcp_echo(
        &daemon_remote_ready.bind_host,
        daemon_remote_ready.bind_port,
        b"daemon remote tunnel evidence",
    )
    .await;
    daemon_remote_tunnel.cancel();
    tokio::time::timeout(Duration::from_secs(5), daemon_remote_tunnel.wait())
        .await
        .expect("daemon remote tunnel did not stop promptly")
        .unwrap();
    let remote_cancel = state
        .wait_for_remote_forward_cancel(remote_forward.generation)
        .await;
    assert_eq!(remote_cancel.key, remote_forward.key);
    assert_remote_forward_unusable(
        &state,
        remote_forward.generation,
        &daemon_remote_ready.bind_host,
        daemon_remote_ready.bind_port,
    )
    .await;

    let output = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(output.stdout, b"evidence\n");
    assert_eq!(output.code, Some(0));

    // A transport can close after SessionManager observes `is_closed=false`
    // but before russh confirms the first session channel. This is the exact
    // pre-submission boundary where retry is safe: no exec request has left
    // the daemon yet. The same client request must invalidate the stale Arc,
    // reconnect once under its original deadline, and then succeed.
    let auth_before_channel_race = state.password_auth_attempts.load(Ordering::SeqCst);
    state
        .disconnect_next_channel_open
        .store(true, Ordering::SeqCst);
    let recovered = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(2),
    )
    .await
    .expect("exec did not reconnect after pre-submission channel-open disconnect");
    assert_eq!(recovered.stdout, b"evidence\n");
    assert_eq!(recovered.code, Some(0));
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        auth_before_channel_race + 1,
        "one channel-open disconnect must create exactly one replacement SSH session"
    );

    // Two requests can observe the same stale session before its close flag is
    // published. Both retry safely, while SessionManager's reconnect mutex must
    // still authenticate only one replacement transport.
    let auth_before_concurrent_race = state.password_auth_attempts.load(Ordering::SeqCst);
    state
        .disconnect_two_channel_opens
        .store(true, Ordering::SeqCst);
    let first = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(2),
    );
    let second = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(2),
    );
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first.unwrap().stdout, b"evidence\n");
    assert_eq!(second.unwrap().stdout, b"evidence\n");
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        auth_before_concurrent_race + 1,
        "concurrent stale-session failures must share one reconnect"
    );
    assert!(state.pending_channel_open.lock().await.is_none());

    // An explicit per-channel rejection is not evidence of a dead transport.
    // It must be returned as-is without reconnecting or retrying the request.
    let auth_before_channel_rejection = state.password_auth_attempts.load(Ordering::SeqCst);
    state.reject_next_channel_open.store(true, Ordering::SeqCst);
    let rejected = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(
        rejected.to_string().contains("AdministrativelyProhibited"),
        "unexpected channel-open rejection: {rejected:#}"
    );
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        auth_before_channel_rejection,
        "an explicit channel rejection must not reconnect"
    );
    let reused_after_rejection = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(1),
    )
    .await
    .expect("explicit channel rejection poisoned a reusable transport");
    assert_eq!(reused_after_rejection.stdout, b"evidence\n");
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        auth_before_channel_rejection,
        "a later request should reuse the explicitly rejecting transport"
    );

    // A local channel-open deadline is not a transport-terminal russh result:
    // it must return promptly without a same-request reconnect. The production
    // retry path passes the original absolute Instant rather than deriving a
    // new duration; the authentication count makes accidental retry visible.
    let auth_before_channel_deadline = state.password_auth_attempts.load(Ordering::SeqCst);
    state.hang_next_channel_open.store(true, Ordering::SeqCst);
    let channel_deadline_started = tokio::time::Instant::now();
    let deadline_error = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_millis(150),
    )
    .await
    .unwrap_err();
    assert!(
        deadline_error.to_string().contains("deadline"),
        "unexpected channel-open deadline error: {deadline_error:#}"
    );
    assert!(
        channel_deadline_started.elapsed() < Duration::from_secs(1),
        "channel-open deadline did not return promptly"
    );
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        auth_before_channel_deadline,
        "a local channel-open deadline must not trigger same-request reconnect"
    );

    let overflow_after = state.latest_exec_generation().await;
    let overflow_task = tokio::spawn(async {
        client::exec_capture_with_timeout(
            "e2e",
            "overflow",
            Some(E2E_PROFILE_PASSPHRASE),
            Duration::from_secs(10),
        )
        .await
    });
    let overflow_channel = state.wait_for_exec_start(overflow_after, b"overflow").await;
    let overflow = overflow_task.await.unwrap().unwrap_err();
    assert!(overflow.is::<serctl_core::ssh::ExecOutcomeUnknown>());
    assert!(
        overflow.to_string().contains("8 MiB safety limit")
            && overflow.to_string().contains("outcome unknown"),
        "unexpected overflow result: {overflow:#}"
    );
    state
        .wait_for_cancel(overflow_channel, "output-limit failure")
        .await;

    let submitted_disconnect_after = state.latest_exec_generation().await;
    let auth_before_submitted_disconnect = state.password_auth_attempts.load(Ordering::SeqCst);
    let disconnected = client::exec_capture_with_timeout(
        "e2e",
        "disconnect",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(disconnected.is::<serctl_core::ssh::ExecOutcomeUnknown>());
    assert!(
        disconnected.to_string().contains("outcome unknown")
            && disconnected
                .to_string()
                .contains("inspect remote side effects before retry")
    );
    assert_eq!(
        state.latest_exec_generation().await,
        submitted_disconnect_after + 1,
        "a submitted exec must never be replayed in the same request"
    );
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        auth_before_submitted_disconnect,
        "post-submission disconnect must return OutcomeUnknown without same-request reconnect"
    );
    let reconnected = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client::exec_capture_with_timeout(
                "e2e",
                "ok",
                Some(E2E_PROFILE_PASSPHRASE),
                Duration::from_secs(1),
            )
            .await
            {
                Ok(output) => break output,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("daemon did not reconnect after the SSH transport closed");
    assert_eq!(reconnected.stdout, b"evidence\n");
    assert_eq!(reconnected.code, Some(0));

    let timeout_after = state.latest_exec_generation().await;
    let timeout_task = tokio::spawn(async {
        client::exec_capture_with_timeout(
            "e2e",
            "hang",
            Some(E2E_PROFILE_PASSPHRASE),
            Duration::from_secs(1),
        )
        .await
    });
    let timeout_channel = state.wait_for_exec_start(timeout_after, b"hang").await;
    let timeout = timeout_task.await.unwrap().unwrap_err();
    assert!(timeout.is::<serctl_core::ssh::ExecOutcomeUnknown>());
    assert!(timeout.to_string().contains("deadline"));
    assert!(timeout
        .to_string()
        .contains("inspect remote side effects before retry"));
    state
        .wait_for_cancel(timeout_channel, "command deadline")
        .await;

    let upload_source = test_home.join("evidence.txt");
    std::fs::write(&upload_source, b"server evidence").unwrap();
    assert_eq!(
        client::upload_with_timeout_and_master(
            "e2e",
            &upload_source,
            "/evidence.txt",
            Duration::from_secs(5),
            Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
        )
        .await
        .unwrap(),
        15
    );
    assert_eq!(
        state.files.lock().await.get("/evidence.txt").unwrap(),
        b"server evidence"
    );
    assert_eq!(
        state.upload_partial_permissions.load(Ordering::SeqCst),
        0o600
    );

    // Regression for the real-world 1,298,223-byte snapshot that previously
    // left a zero-byte partial. This is controlled-server evidence; the
    // separate Local-Linux2 run remains an external acceptance gate.
    vault::create_profile(
        "e2e-large",
        &daemon_creds,
        E2E_PROFILE_PASSPHRASE,
        administrator_passphrase,
    )
    .unwrap();
    vault::set_pinned_fp("e2e-large", fingerprint.clone(), E2E_PROFILE_PASSPHRASE).unwrap();
    let fixed_snapshot = (0..1_298_223_u32)
        .map(|index| ((index.wrapping_mul(31) + 7) % 251) as u8)
        .collect::<Vec<_>>();
    let fixed_source = test_home.join("fixed-snapshot.bin");
    std::fs::write(&fixed_source, &fixed_snapshot).unwrap();
    let baseline_stat = state.sftp_stat_calls.load(Ordering::SeqCst);
    let baseline_open = state.sftp_open_calls.load(Ordering::SeqCst);
    let baseline_write = state.sftp_write_calls.load(Ordering::SeqCst);
    let baseline_wire_bytes = state.sftp_wire_read_bytes.load(Ordering::SeqCst);
    let baseline_partial_opens = state.upload_partial_events.lock().await.opened.len();
    let observed_progress = Arc::new(StdMutex::new(Vec::new()));
    let observed_sink = Arc::clone(&observed_progress);
    let progress_started = StdInstant::now();
    let progress: client::TransferProgressSink = Arc::new(move |progress| {
        observed_sink
            .lock()
            .unwrap()
            .push((progress_started.elapsed(), progress));
    });
    let fixed_result = client::transfer_push_with_master_cancellable(
        "e2e-large",
        &fixed_source,
        "/fixed-snapshot.bin",
        client::TransferOptions {
            backend: ipc::TransferBackend::Sftp,
            expected_helper_identity: None,
            resume: ipc::TransferResumeMode::Never,
            idle_timeout: Duration::from_secs(30),
            deadline: Some(Duration::from_secs(120)),
            progress: Some(progress),
        },
        Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
        tokio_util::sync::CancellationToken::new(),
    )
    .await;
    if let Err(error) = &fixed_result {
        let server_files = state.files.lock().await.keys().cloned().collect::<Vec<_>>();
        let partial_open_delta =
            state.upload_partial_events.lock().await.opened.len() - baseline_partial_opens;
        let observed = observed_progress.lock().unwrap();
        panic!(
            "fixed snapshot upload failed: {error:#}; last progress: {:?}; server stat/open/write delta: {}/{}/{}; partial-open delta: {}; wire-read delta: {}; server files: {:?}",
            observed.last(),
            state.sftp_stat_calls.load(Ordering::SeqCst) - baseline_stat,
            state.sftp_open_calls.load(Ordering::SeqCst) - baseline_open,
            state.sftp_write_calls.load(Ordering::SeqCst) - baseline_write,
            partial_open_delta,
            state.sftp_wire_read_bytes.load(Ordering::SeqCst) - baseline_wire_bytes,
            server_files,
        );
    }
    assert_eq!(fixed_result.unwrap(), fixed_snapshot.len() as u64);
    assert_eq!(
        state.files.lock().await.get("/fixed-snapshot.bin"),
        Some(&fixed_snapshot)
    );
    {
        let observed_progress = observed_progress.lock().unwrap();
        let first = observed_progress.first().expect("missing progress event");
        assert!(first.0 <= Duration::from_millis(500));
        assert!(
            observed_progress
                .iter()
                .any(|(_, progress)| progress.stage == ipc::TransferStage::Negotiating),
            "missing negotiating progress event"
        );
        assert!(observed_progress
            .windows(2)
            .all(|pair| pair[0].1.confirmed_bytes <= pair[1].1.confirmed_bytes));
        let completed = &observed_progress.last().unwrap().1;
        assert_eq!(completed.stage, ipc::TransferStage::Completed);
        assert_eq!(completed.confirmed_bytes, fixed_snapshot.len() as u64);
        assert_eq!(completed.durable_bytes, fixed_snapshot.len() as u64);
        assert_eq!(completed.chunk_bytes, ipc::SFTP_SAFE_CHUNK_BYTES as u32);
        assert_eq!(completed.window_bytes, ipc::SFTP_SAFE_CHUNK_BYTES as u32);
    }

    // Exercise the M3 backend over the same real SSH transport. The server
    // accepts only the fixed helper command and then speaks the bounded raw
    // transfer protocol on that channel; paths never enter the exec string.
    let native_observed_progress = Arc::new(StdMutex::new(Vec::new()));
    let native_observed_sink = Arc::clone(&native_observed_progress);
    let native_progress: client::TransferProgressSink = Arc::new(move |progress| {
        native_observed_sink.lock().unwrap().push(progress);
    });
    let native_options = client::TransferOptions {
        backend: ipc::TransferBackend::Native,
        expected_helper_identity: Some(test_native_expected_identity()),
        resume: ipc::TransferResumeMode::Never,
        idle_timeout: Duration::from_secs(30),
        deadline: Some(Duration::from_secs(120)),
        progress: Some(native_progress),
    };
    let native_push_frames_before = state.native_push_frames.load(Ordering::SeqCst);
    let native_helpers_before = state.native_helpers_finished.load(Ordering::SeqCst);
    state.native_push_ack_gate.store(true, Ordering::SeqCst);
    let native_source = fixed_source.clone();
    let native_push_options = native_options.clone();
    let native_push = tokio::spawn(async move {
        client::transfer_push_with_master_cancellable(
            "e2e-large",
            &native_source,
            "/native-fixed-snapshot.bin",
            native_push_options,
            Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
    });
    let native_received = state
        .wait_for_native_push_frames(native_push_frames_before + 1)
        .await;
    assert!(
        native_received,
        "native helper did not receive its first push frame; negotiated chunk/window={}/{}, client_finished={}, progress={:?}",
        state.native_negotiated_chunk.load(Ordering::SeqCst),
        state.native_negotiated_window.load(Ordering::SeqCst),
        native_push.is_finished(),
        native_observed_progress.lock().unwrap()
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !native_push.is_finished(),
        "native upload advanced before the helper acknowledged its first frame"
    );
    {
        let observed = native_observed_progress.lock().unwrap();
        assert!(!observed.is_empty(), "native upload emitted no progress");
        assert!(
            observed
                .iter()
                .all(|progress| progress.confirmed_bytes == 0),
            "native confirmed bytes advanced before the helper ACK: {observed:?}"
        );
    }
    state.native_push_ack_gate.store(false, Ordering::SeqCst);
    state.native_push_ack_released.notify_waiters();
    assert_eq!(
        native_push
            .await
            .expect("native upload worker panicked")
            .unwrap(),
        fixed_snapshot.len() as u64
    );
    state
        .wait_for_native_helpers_finished(native_helpers_before + 1)
        .await;
    assert_eq!(
        state.files.lock().await.get("/native-fixed-snapshot.bin"),
        Some(&fixed_snapshot)
    );
    let expected_native_frames = fixed_snapshot.len().div_ceil(ipc::NATIVE_IPC_CHUNK_BYTES) as u64;
    assert_eq!(
        state.native_push_frames.load(Ordering::SeqCst) - native_push_frames_before,
        expected_native_frames
    );
    assert_eq!(
        state.native_push_max_chunk.load(Ordering::SeqCst),
        ipc::NATIVE_IPC_CHUNK_BYTES as u64
    );
    assert_eq!(
        state.native_negotiated_chunk.load(Ordering::SeqCst),
        ipc::NATIVE_IPC_CHUNK_BYTES as u64
    );
    assert_eq!(
        state.native_negotiated_window.load(Ordering::SeqCst),
        native::MAX_WINDOW_BYTES as u64
    );
    {
        let observed = native_observed_progress.lock().unwrap();
        assert!(observed
            .windows(2)
            .all(|pair| pair[0].confirmed_bytes <= pair[1].confirmed_bytes));
        let completed = observed.last().expect("missing native completion progress");
        assert_eq!(completed.stage, ipc::TransferStage::Completed);
        assert_eq!(completed.confirmed_bytes, fixed_snapshot.len() as u64);
        assert_eq!(completed.durable_bytes, fixed_snapshot.len() as u64);
        assert_eq!(completed.chunk_bytes, ipc::NATIVE_IPC_CHUNK_BYTES as u32);
        assert_eq!(completed.window_bytes, ipc::NATIVE_IPC_CHUNK_BYTES as u32);
    }
    let native_download = test_home.join("native-fixed-snapshot-download.bin");
    let native_pull_frames_before = state.native_pull_frames.load(Ordering::SeqCst);
    let mut native_pull_options = native_options.clone();
    native_pull_options.progress = None;
    assert_eq!(
        client::transfer_pull_with_master_cancellable(
            "e2e-large",
            "/native-fixed-snapshot.bin",
            &native_download,
            native_pull_options,
            Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap(),
        fixed_snapshot.len() as u64
    );
    assert_eq!(std::fs::read(native_download).unwrap(), fixed_snapshot);
    assert_eq!(
        state.native_pull_frames.load(Ordering::SeqCst) - native_pull_frames_before,
        expected_native_frames
    );
    assert_eq!(
        state.native_pull_max_chunk.load(Ordering::SeqCst),
        ipc::NATIVE_IPC_CHUNK_BYTES as u64
    );

    // Native no-replace remains fail-closed even when the source is identical.
    // The already committed bytes must remain untouched.
    let duplicate_helpers_before = state.native_helpers_finished.load(Ordering::SeqCst);
    let mut native_no_progress = native_options.clone();
    native_no_progress.progress = None;
    let duplicate_error = client::transfer_push_with_master_cancellable(
        "e2e-large",
        &fixed_source,
        "/native-fixed-snapshot.bin",
        native_no_progress.clone(),
        Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(
        duplicate_error.to_string().contains("native")
            || duplicate_error.to_string().contains("helper")
            || duplicate_error.to_string().contains("disconnected"),
        "unexpected native no-replace error: {duplicate_error:#}"
    );
    state
        .wait_for_native_helpers_finished(duplicate_helpers_before + 1)
        .await;
    assert_eq!(
        state.files.lock().await.get("/native-fixed-snapshot.bin"),
        Some(&fixed_snapshot)
    );

    // Withhold the first helper ACK. Confirmed progress must remain at zero,
    // the daemon must report a stall at the idle boundary, and no mock target
    // may become visible because Commit was never reached. Keep the idle
    // window long enough for a cold CI runner to finish the native handshake
    // and IPC handoff; the timeout under test starts before the first data
    // frame, so a sub-second value tests scheduler speed instead of ACK stall.
    let idle_progress = Arc::new(StdMutex::new(Vec::new()));
    let idle_sink = Arc::clone(&idle_progress);
    let idle_progress_sink: client::TransferProgressSink =
        Arc::new(move |progress| idle_sink.lock().unwrap().push(progress));
    let idle_frames_before = state.native_push_frames.load(Ordering::SeqCst);
    let idle_helpers_before = state.native_helpers_finished.load(Ordering::SeqCst);
    state.native_push_ack_gate.store(true, Ordering::SeqCst);
    let idle_source = fixed_source.clone();
    let idle_upload = tokio::spawn(async move {
        client::transfer_push_with_master_cancellable(
            "e2e-large",
            &idle_source,
            "/native-idle-timeout.bin",
            client::TransferOptions {
                backend: ipc::TransferBackend::Native,
                expected_helper_identity: Some(test_native_expected_identity()),
                resume: ipc::TransferResumeMode::Never,
                idle_timeout: Duration::from_secs(5),
                deadline: Some(Duration::from_secs(10)),
                progress: Some(idle_progress_sink),
            },
            Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
    });
    assert!(
        state
            .wait_for_native_push_frames(idle_frames_before + 1)
            .await,
        "native idle test helper did not receive a push frame; client_finished={}, progress={:?}",
        idle_upload.is_finished(),
        idle_progress.lock().unwrap()
    );
    let idle_error = tokio::time::timeout(Duration::from_secs(10), idle_upload)
        .await
        .expect("native idle timeout did not terminate the client")
        .expect("native idle upload worker panicked")
        .unwrap_err();
    state.native_push_ack_gate.store(false, Ordering::SeqCst);
    state.native_push_ack_released.notify_waiters();
    state
        .wait_for_native_helpers_finished(idle_helpers_before + 1)
        .await;
    assert!(
        idle_error.to_string().contains("idle timeout"),
        "unexpected native idle error: {idle_error:#}"
    );
    assert!(idle_progress
        .lock()
        .unwrap()
        .iter()
        .any(|progress| progress.stage == ipc::TransferStage::Stalled));
    assert!(!state
        .files
        .lock()
        .await
        .contains_key("/native-idle-timeout.bin"));

    // Cancellation while the helper ACK is withheld closes the local request
    // without claiming confirmation or exposing a destination.
    let cancel_frames_before = state.native_push_frames.load(Ordering::SeqCst);
    let cancel_helpers_before = state.native_helpers_finished.load(Ordering::SeqCst);
    let cancellation = tokio_util::sync::CancellationToken::new();
    state.native_push_ack_gate.store(true, Ordering::SeqCst);
    let cancel_source = fixed_source.clone();
    let cancel_token = cancellation.clone();
    let cancelled_upload = tokio::spawn(async move {
        client::transfer_push_with_master_cancellable(
            "e2e-large",
            &cancel_source,
            "/native-cancelled.bin",
            client::TransferOptions {
                backend: ipc::TransferBackend::Native,
                expected_helper_identity: Some(test_native_expected_identity()),
                resume: ipc::TransferResumeMode::Never,
                idle_timeout: Duration::from_secs(30),
                deadline: Some(Duration::from_secs(3)),
                progress: None,
            },
            Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
            cancel_token,
        )
        .await
    });
    assert!(
        state
            .wait_for_native_push_frames(cancel_frames_before + 1)
            .await,
        "native cancellation test helper did not receive a push frame"
    );
    cancellation.cancel();
    // Let the helper answer only after cancellation is observable. This lets
    // the daemon leave its helper read and notice the now-closed IPC request;
    // no helper ACK was available when the client chose cancellation.
    state.native_push_ack_gate.store(false, Ordering::SeqCst);
    state.native_push_ack_released.notify_waiters();
    let cancel_error = tokio::time::timeout(Duration::from_secs(5), cancelled_upload)
        .await
        .expect("native cancellation did not terminate the client")
        .expect("native cancellation worker panicked")
        .unwrap_err();
    state
        .wait_for_native_helpers_finished(cancel_helpers_before + 1)
        .await;
    assert!(
        cancel_error.to_string().contains("cancelled"),
        "unexpected native cancellation error: {cancel_error:#}"
    );
    assert!(!state
        .files
        .lock()
        .await
        .contains_key("/native-cancelled.bin"));

    // The hardlink is the durable commit point. If unlinking the owned
    // temporary name then stalls until the request deadline, the daemon must
    // reconcile success before attempting its fresh bounded cleanup. Waiting
    // for cleanup first would exceed the client's 2.25 s commit grace and can
    // turn a successful no-replace upload into an unsafe retry decision.
    state
        .upload_partial_remove_hang
        .store(true, Ordering::SeqCst);
    let committed_during_cleanup = tokio::time::timeout(
        Duration::from_millis(1_500),
        client::upload_with_timeout_and_master(
            "e2e",
            &upload_source,
            "/committed-before-cleanup.txt",
            Duration::from_millis(500),
            Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
        ),
    )
    .await
    .expect("committed upload waited for post-commit remote cleanup")
    .unwrap();
    assert_eq!(committed_during_cleanup, 15);
    assert_eq!(
        state
            .files
            .lock()
            .await
            .get("/committed-before-cleanup.txt")
            .unwrap(),
        b"server evidence"
    );
    state
        .upload_partial_remove_hang
        .store(false, Ordering::SeqCst);
    state.upload_partial_remove_changed.notify_waiters();

    state.hardlink_race_target.store(true, Ordering::SeqCst);
    let _raced_upload = client::upload_with_timeout_and_master(
        "e2e",
        &upload_source,
        "/hardlink-race.txt",
        Duration::from_secs(5),
        Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
    )
    .await
    .unwrap_err();
    assert_eq!(
        state.files.lock().await.get("/hardlink-race.txt").unwrap(),
        b"concurrent winner"
    );

    let (listed_path, entries) = client::list_dir_with_timeout(
        "e2e",
        "/",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(listed_path, "/");
    assert!(entries
        .iter()
        .any(|entry| entry.name == "evidence.txt" && entry.size == 15));

    state.sftp_large_dir.store(true, Ordering::SeqCst);
    let large_directory = client::list_dir_with_timeout(
        "e2e",
        "/",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(
        large_directory
            .to_string()
            .contains("more than 10000 entries"),
        "unexpected large-directory result: {large_directory:#}"
    );
    state.sftp_large_dir.store(false, Ordering::SeqCst);
    let after_large_directory = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(after_large_directory.code, Some(0));

    let download_target = test_home.join("downloaded-evidence.txt");
    assert_eq!(
        client::download_with_timeout_and_master(
            "e2e",
            "/evidence.txt",
            &download_target,
            Duration::from_secs(5),
            Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
        )
        .await
        .unwrap(),
        15
    );
    assert_eq!(std::fs::read(&download_target).unwrap(), b"server evidence");

    state.sftp_hang.store(true, Ordering::SeqCst);
    state.reset_sftp_hang_observation().await;
    let timed_upload_source = upload_source.clone();
    let upload_timeout_task = tokio::spawn(async move {
        client::upload_with_timeout_and_master(
            "e2e",
            &timed_upload_source,
            "/hung-upload.txt",
            Duration::from_millis(500),
            Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
        )
        .await
    });
    let upload_connection = state.wait_for_sftp_hang("timed upload").await;
    let upload_timeout = upload_timeout_task.await.unwrap().unwrap_err();
    assert!(upload_timeout.to_string().contains("deadline"));
    state
        .wait_for_connection_closed(upload_connection, "the SFTP upload timeout")
        .await;

    let timed_download = test_home.join("timed-download.txt");
    state.reset_sftp_hang_observation().await;
    let timed_download_task_path = timed_download.clone();
    let download_timeout_task = tokio::spawn(async move {
        client::download_with_timeout_and_master(
            "e2e",
            "/evidence.txt",
            &timed_download_task_path,
            Duration::from_millis(500),
            Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
        )
        .await
    });
    let download_connection = state.wait_for_sftp_hang("timed download").await;
    let download_timeout = download_timeout_task.await.unwrap().unwrap_err();
    assert!(download_timeout.to_string().contains("deadline"));
    assert!(!timed_download.exists());
    assert!(!std::fs::read_dir(&test_home).unwrap().any(|entry| {
        entry
            .ok()
            .and_then(|entry| entry.file_name().into_string().ok())
            .is_some_and(|name| name.starts_with("timed-download.txt.serctl-part-"))
    }));
    state
        .wait_for_connection_closed(download_connection, "the SFTP download timeout")
        .await;
    state.sftp_hang.store(false, Ordering::SeqCst);
    let after_timeout_generation = state.latest_exec_generation().await;
    let after_timeout = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let recovery_channel = state
        .wait_for_exec_start(after_timeout_generation, b"ok")
        .await;
    assert!(
        recovery_channel.connection > download_connection,
        "post-timeout exec reused closed SSH connection {download_connection}"
    );
    let recovery_starts = state
        .exec_events
        .lock()
        .await
        .started
        .iter()
        .filter(|event| event.generation > after_timeout_generation && event.command == b"ok")
        .count();
    assert_eq!(
        recovery_starts, 1,
        "post-timeout exec was replayed instead of failing closed"
    );
    assert_eq!(after_timeout.stdout, b"evidence\n");
    assert_eq!(after_timeout.code, Some(0));

    let shutdown_after = state.latest_exec_generation().await;
    let shutdown_exec_task = tokio::spawn(client::exec_capture_with_timeout(
        "e2e",
        "hang",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(10),
    ));
    let shutdown_channel = state.wait_for_exec_start(shutdown_after, b"hang").await;

    // Shutdown verifies the selected profile passphrase inside the v6 AEAD
    // channel without opening another SSH connection. The broker drains the
    // in-flight hang, closes its SSH channel, clears its runtime state, and
    // exits.
    assert!(client::down_quiet("e2e", E2E_PROFILE_PASSPHRASE)
        .await
        .unwrap());
    tokio::time::timeout(Duration::from_secs(5), daemon_task)
        .await
        .expect("daemon did not drain active handlers during shutdown")
        .unwrap()
        .unwrap();
    assert!(!client::daemon_is_published().unwrap());
    // The daemon awaits the local channel close, but delivery to the test
    // server's callback crosses the SSH transport task and may be observed a
    // scheduler turn after the daemon future completes.
    state
        .wait_for_cancel(shutdown_channel, "daemon shutdown")
        .await;
    // The pending client exec observes the broker exit as a disconnect error.
    let _ = tokio::time::timeout(Duration::from_secs(5), shutdown_exec_task)
        .await
        .expect("hang exec did not settle after daemon shutdown");

    // The broker identity is per-boot: a fresh instance id and activation
    // secret accompany every startup, so reconnecting after shutdown derives
    // the whole v6 handshake again instead of reusing any session state.
    let daemon_instance = ipc::v6::InstanceId::random();
    let daemon_secret = ipc::v6::ActivationSecret::random();
    let daemon_endpoint = serctl_core::daemon_runtime::v6_endpoint(&daemon_instance).unwrap();
    #[cfg(unix)]
    assert!(
        daemon_endpoint.len() < 100,
        "second E2E Unix socket path exceeds the conservative sun_path budget: {} bytes ({daemon_endpoint})",
        daemon_endpoint.len()
    );
    let mut daemon_task = tokio::spawn(daemon::run_global_with_idle_timeout(
        daemon_instance,
        daemon_secret,
        "e2e-test-commit".to_owned(),
        Duration::from_secs(10),
    ));
    let publish_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if serctl_core::daemon_runtime::read_descriptor()
            .unwrap()
            .is_some()
        {
            break;
        }
        if daemon_task.is_finished() {
            let outcome = (&mut daemon_task).await;
            panic!(
                "second global daemon exited before publishing its runtime descriptor at {daemon_endpoint}: {outcome:?}"
            );
        }
        if tokio::time::Instant::now() >= publish_deadline {
            panic!(
                "second global daemon did not publish its runtime descriptor at {daemon_endpoint} ({} bytes; test home {})",
                daemon_endpoint.len(),
                test_home.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let direct_passphrase = DIRECT_PROFILE_PASSPHRASE;
    let direct_creds = vault::Creds {
        host: "127.0.0.1".into(),
        port: ssh_port,
        user: "tester".into(),
        password: "password".into(),
        host_key: None,
    };
    let direct_use_lease = vault::acquire_profile_use_lease("direct-e2e").unwrap();
    let direct_mutation_error = vault::create_profile(
        "direct-e2e",
        &direct_creds,
        direct_passphrase,
        administrator_passphrase,
    )
    .unwrap_err();
    assert!(direct_mutation_error.to_string().contains("daemon"));
    drop(direct_use_lease);
    vault::create_profile(
        "direct-e2e",
        &direct_creds,
        direct_passphrase,
        administrator_passphrase,
    )
    .unwrap();
    vault::set_pinned_fp("direct-e2e", fingerprint.clone(), direct_passphrase).unwrap();

    let direct_local_tunnel = client::open_gui_tunnel(
        "direct-e2e",
        client::TunnelSpec::local(0, echo_port),
        Zeroizing::new(direct_passphrase.to_owned()),
    )
    .await
    .unwrap();
    let direct_local_ready = direct_local_tunnel.ready().clone();
    assert_eq!(direct_local_ready.bind_host, "127.0.0.1");
    assert_tcp_echo(
        &direct_local_ready.bind_host,
        direct_local_ready.bind_port,
        b"direct local tunnel evidence",
    )
    .await;
    direct_local_tunnel.cancel();
    tokio::time::timeout(Duration::from_secs(5), direct_local_tunnel.wait())
        .await
        .expect("direct local tunnel did not stop promptly")
        .unwrap();

    let direct_dynamic_tunnel = client::open_gui_tunnel(
        "direct-e2e",
        client::TunnelSpec::dynamic(0),
        Zeroizing::new(direct_passphrase.to_owned()),
    )
    .await
    .unwrap();
    let direct_dynamic_ready = direct_dynamic_tunnel.ready().clone();
    assert_eq!(direct_dynamic_ready.bind_host, "127.0.0.1");
    assert_socks5_echo(
        &direct_dynamic_ready.bind_host,
        direct_dynamic_ready.bind_port,
        echo_port,
    )
    .await;
    direct_dynamic_tunnel.cancel();
    tokio::time::timeout(Duration::from_secs(5), direct_dynamic_tunnel.wait())
        .await
        .expect("direct dynamic tunnel did not stop promptly")
        .unwrap();

    let direct_exec = client::exec_capture_with_timeout(
        "direct-e2e",
        "ok",
        Some(direct_passphrase),
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(direct_exec.stdout, b"evidence\n");
    assert_eq!(direct_exec.code, Some(0));

    let direct_hang_after = state.latest_exec_generation().await;
    let direct_hang_task = tokio::spawn(async move {
        client::exec_capture_with_timeout(
            "direct-e2e",
            "hang",
            Some(direct_passphrase),
            Duration::from_secs(3),
        )
        .await
    });
    let direct_hang_channel = state.wait_for_exec_start(direct_hang_after, b"hang").await;
    let direct_hang = direct_hang_task.await.unwrap().unwrap_err();
    assert!(direct_hang.is::<serctl_core::ssh::ExecOutcomeUnknown>());
    assert!(direct_hang
        .to_string()
        .contains("inspect remote side effects before retry"));
    state
        .wait_for_cancel(direct_hang_channel, "direct command deadline")
        .await;

    let direct_disconnect_after = state.latest_exec_generation().await;
    let direct_disconnect_task = tokio::spawn(async move {
        client::exec_capture_with_timeout(
            "direct-e2e",
            "disconnect",
            Some(direct_passphrase),
            Duration::from_secs(3),
        )
        .await
    });
    let direct_disconnect_channel = state
        .wait_for_exec_start(direct_disconnect_after, b"disconnect")
        .await;
    let direct_disconnect = direct_disconnect_task.await.unwrap().unwrap_err();
    assert!(direct_disconnect.is::<serctl_core::ssh::ExecOutcomeUnknown>());
    assert!(direct_disconnect
        .to_string()
        .contains("inspect remote side effects before retry"));
    state
        .wait_for_cancel(direct_disconnect_channel, "direct server disconnect")
        .await;

    let direct_download_target = test_home.join("direct-downloaded-evidence.txt");
    assert_eq!(
        client::download_with_timeout_and_master(
            "direct-e2e",
            "/evidence.txt",
            &direct_download_target,
            Duration::from_secs(5),
            Some(Zeroizing::new(direct_passphrase.to_owned())),
        )
        .await
        .unwrap(),
        15
    );
    assert_eq!(
        std::fs::read(&direct_download_target).unwrap(),
        b"server evidence"
    );
    let no_replace = client::download_with_timeout_and_master(
        "direct-e2e",
        "/evidence.txt",
        &direct_download_target,
        Duration::from_secs(5),
        Some(Zeroizing::new(direct_passphrase.to_owned())),
    )
    .await
    .unwrap_err();
    assert!(no_replace.to_string().contains("already exists"));
    assert_eq!(
        std::fs::read(&direct_download_target).unwrap(),
        b"server evidence"
    );

    let direct_upload_after = state.latest_upload_partial_generation().await;
    state
        .upload_partial_remove_delay
        .store(true, Ordering::SeqCst);
    state.sftp_write_hang.store(true, Ordering::SeqCst);
    let direct_upload_source = upload_source.clone();
    let direct_timeout_task = tokio::spawn(async move {
        client::upload_with_timeout_and_master(
            "direct-e2e",
            &direct_upload_source,
            "/direct-timeout.txt",
            Duration::from_secs(10),
            Some(Zeroizing::new(direct_passphrase.to_owned())),
        )
        .await
    });
    let direct_partial = state
        .wait_for_upload_partial(direct_upload_after, "/direct-timeout.txt")
        .await;
    assert!(direct_partial.starts_with("/direct-timeout.txt.serctl-part-"));
    assert!(state.sftp_write_hang.load(Ordering::SeqCst));
    let direct_timeout = direct_timeout_task.await.unwrap().unwrap_err();
    assert!(direct_timeout.to_string().contains("deadline"));
    // The server deliberately delays REMOVE. Returning with no partial proves
    // cleanup was awaited rather than detached onto the soon-to-die CLI runtime.
    assert!(!state
        .files
        .lock()
        .await
        .keys()
        .any(|path| path.starts_with("/direct-timeout.txt.serctl-part-")));
    assert!(!state.files.lock().await.contains_key("/direct-timeout.txt"));
    state.sftp_write_hang.store(false, Ordering::SeqCst);

    // ── OperationGrant: issuance, relay, scope, budget, PoP, audit ───────
    let grant_path = test_home.join("agent-grant.json");
    let grant = client::issue_grant_until(
        "direct-e2e",
        direct_passphrase,
        vec!["ssh.exec".into(), "sftp.list".into()],
        3,
        &grant_path,
    )
    .await
    .unwrap();
    let (loaded_grant, signing) = client::load_agent_grant(&grant_path).unwrap();
    assert_eq!(loaded_grant.grant_id, grant.grant_id);
    assert_eq!(loaded_grant.operations, vec!["ssh.exec", "sftp.list"]);

    // Grant issuance uses a short-lived authenticated connection. Once that
    // caller has returned, wait longer than this broker's ten-second idle
    // window and reconnect from a fresh client operation. The grant's active
    // reference must keep the daemon and its in-memory registration alive.
    tokio::time::sleep(Duration::from_millis(10_500)).await;
    assert!(
        client::daemon_is_published().unwrap(),
        "broker exited after the grant-issuing client disconnected"
    );

    // A grant relay executes against the daemon's pooled session.
    let exec_value = client::agent_exec_until(&loaded_grant, &signing, "ok", 3_000)
        .await
        .unwrap();
    assert_eq!(
        B64.decode(exec_value["stdout"].as_str().unwrap()).unwrap(),
        b"evidence\n"
    );
    assert_eq!(exec_value["code"], 0);

    // The budget is enforced by the broker: 3 units issued; the second and
    // third relays are accepted, the fourth is rejected without reaching SSH.
    assert!(
        client::agent_exec_until(&loaded_grant, &signing, "ok", 3_000)
            .await
            .is_ok()
    );
    assert!(
        client::agent_exec_until(&loaded_grant, &signing, "ok", 3_000)
            .await
            .is_ok()
    );
    let grant_audit_path = serctl_core::daemon_runtime::grant_audit_path().unwrap();
    // The compatibility JSONL is intentionally non-authoritative and is
    // appended after the terminal response. Wait until all three accepted
    // relays for this grant are visible before taking the negative baseline;
    // otherwise the third append can race the locally denied fourth request.
    let grant_id = loaded_grant.grant_id_hex();
    let audit_before_budget_denial = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let audit = std::fs::read_to_string(&grant_audit_path).unwrap();
            let accepted = audit
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .filter(|entry| {
                    entry.get("grant_id").and_then(serde_json::Value::as_str)
                        == Some(grant_id.as_str())
                        && entry.get("outcome").and_then(serde_json::Value::as_str)
                            == Some("accepted")
                })
                .count();
            if accepted >= 3 {
                break audit;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("three accepted compatibility-audit records were not appended");
    let exec_events_before_budget = state.latest_exec_generation().await;
    let exhausted = client::agent_exec_until(&loaded_grant, &signing, "ok", 3_000)
        .await
        .unwrap_err();
    assert!(exhausted.to_string().contains("grant budget exhausted"));
    let audit_after_budget_denial = std::fs::read_to_string(&grant_audit_path).unwrap();
    assert_eq!(
        audit_after_budget_denial.lines().collect::<Vec<_>>(),
        audit_before_budget_denial.lines().collect::<Vec<_>>(),
        "a locally budget-denied request must not synthesize a daemon audit record"
    );
    state
        .assert_no_exec_start(
            exec_events_before_budget,
            b"ok",
            "budget-exhausted grant relay",
        )
        .await;

    // Scope is enforced: a list-only grant cannot relay an exec.
    let list_grant_path = test_home.join("list-grant.json");
    client::issue_grant_until(
        "direct-e2e",
        direct_passphrase,
        vec!["sftp.list".into()],
        1,
        &list_grant_path,
    )
    .await
    .unwrap();
    let (list_grant, list_signing) = client::load_agent_grant(&list_grant_path).unwrap();
    let audit_before_scope_denial = std::fs::read_to_string(&grant_audit_path).unwrap();
    let exec_events_before_scope_denial = state.latest_exec_generation().await;
    let scope_error = client::agent_exec_until(&list_grant, &list_signing, "ok", 3_000)
        .await
        .unwrap_err();
    let scope_error = scope_error.to_string();
    eprintln!("agent scope-denial evidence: {scope_error}");
    assert!(scope_error.contains("grant does not authorize"));
    let audit_after_scope_denial = std::fs::read_to_string(&grant_audit_path).unwrap();
    assert_eq!(
        audit_after_scope_denial.lines().collect::<Vec<_>>(),
        audit_before_scope_denial.lines().collect::<Vec<_>>(),
        "a locally scope-denied request must not synthesize a daemon audit record"
    );
    state
        .assert_no_exec_start(
            exec_events_before_scope_denial,
            b"ok",
            "locally scope-denied agent exec",
        )
        .await;
    let listing = client::agent_list_until(&list_grant, &list_signing, "/", 3_000)
        .await
        .unwrap();
    assert!(listing["entries"]
        .as_array()
        .is_some_and(|entries| entries.iter().any(|entry| entry["name"] == "evidence.txt")));

    // `sftp.write` remains the create-directory scope. File upload uses the
    // separate transfer.write root intent and never falls through ssh.exec.
    let transfer_grant_path = test_home.join("transfer-grant.json");
    client::issue_grant_until(
        "direct-e2e",
        direct_passphrase,
        vec!["transfer.write".into()],
        1,
        &transfer_grant_path,
    )
    .await
    .unwrap();
    let (transfer_grant, transfer_signing) =
        client::load_agent_grant(&transfer_grant_path).unwrap();
    let transfer_value = client::agent_transfer_push_until(
        &transfer_grant,
        &transfer_signing,
        None,
        &upload_source,
        "/agent-transfer-evidence.txt",
        client::TransferOptions {
            backend: ipc::TransferBackend::Sftp,
            expected_helper_identity: None,
            resume: ipc::TransferResumeMode::Never,
            idle_timeout: Duration::from_millis(3_000),
            deadline: Some(Duration::from_millis(5_000)),
            progress: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(transfer_value["bytes"], 15);
    assert_eq!(transfer_value["backend"], "sftp");
    assert_eq!(
        transfer_value["chunk_bytes"],
        ipc::SFTP_SAFE_CHUNK_BYTES as u64
    );
    assert_eq!(
        transfer_value["window_bytes"],
        ipc::SFTP_SAFE_CHUNK_BYTES as u64
    );
    assert_eq!(
        state
            .files
            .lock()
            .await
            .get("/agent-transfer-evidence.txt")
            .cloned(),
        Some(b"server evidence".to_vec())
    );

    // Proof of possession: a different key cannot relay with a fresh grant.
    // Do not reuse the earlier grant here: its budget is intentionally
    // exhausted above, which would test the tombstone rather than PoP.
    let pop_grant_path = test_home.join("pop-grant.json");
    client::issue_grant_until(
        "direct-e2e",
        direct_passphrase,
        vec!["ssh.exec".into()],
        1,
        &pop_grant_path,
    )
    .await
    .unwrap();
    let (pop_grant, _pop_signing) = client::load_agent_grant(&pop_grant_path).unwrap();
    let other_key = SigningKey::generate(&mut OsRng);
    let exec_events_before_pop_denial = state.latest_exec_generation().await;
    let pop_error = client::agent_exec_until(&pop_grant, &other_key, "ok", 3_000)
        .await
        .unwrap_err();
    let pop_error = pop_error.to_string();
    eprintln!("agent PoP-denial evidence: {pop_error}");
    assert!(pop_error.contains("proof-of-possession"));
    state
        .assert_no_exec_start(
            exec_events_before_pop_denial,
            b"ok",
            "invalid proof-of-possession agent exec",
        )
        .await;

    // The daemon audit trail persists requests that actually reached its
    // authorization boundary. Local scope/budget fail-fast paths above are
    // deliberately absent and separately proven to have no SSH side effect.
    let audit = std::fs::read_to_string(&grant_audit_path).unwrap();
    assert!(
        audit.contains("\"accepted\""),
        "grant audit log is missing accepted relays: {audit}"
    );
    assert!(
        audit.contains("proof-of-possession verification failed"),
        "grant audit log is missing proof-of-possession rejections: {audit}"
    );

    // Profile passphrase rotation is isolated: a use lease blocks rekeying
    // only that profile and leaves the vault byte-identical, while another
    // profile can still rotate independently.
    let vault_path = vault::vault_path().unwrap();
    let before_contended_rekey = std::fs::read(&vault_path).unwrap();
    let rekey_use_lease = vault::acquire_profile_use_lease("direct-e2e").unwrap();
    let rotated_direct_passphrase = "rotated-direct-profile-passphrase";
    let contention = vault::change_profile_passphrase(
        "direct-e2e",
        direct_passphrase,
        rotated_direct_passphrase,
        None,
    )
    .unwrap_err();
    assert!(contention
        .to_string()
        .contains("while it is in use by a direct operation or daemon"));
    assert_eq!(std::fs::read(&vault_path).unwrap(), before_contended_rekey);

    let tofu_identity = vault::verify_profile_identity(tofu_profile, tofu_passphrase).unwrap();
    let rotated_tofu_passphrase = "rotated-tofu-profile-passphrase";
    let rotated_tofu_generation = vault::change_profile_passphrase(
        tofu_profile,
        tofu_passphrase,
        rotated_tofu_passphrase,
        Some(tofu_identity),
    )
    .unwrap();
    assert!(rotated_tofu_generation > tofu_identity.generation);
    assert!(vault::verify_profile_passphrase(tofu_profile, tofu_passphrase).is_err());
    assert_eq!(
        vault::verify_profile_passphrase(tofu_profile, rotated_tofu_passphrase).unwrap(),
        rotated_tofu_generation
    );
    drop(rekey_use_lease);

    // Rotation of a broker-unlocked profile needs the credential lease
    // released: stop the broker (it clears its pool on exit) and observe the
    // descriptor disappear before mutating the vault.
    assert!(client::down_quiet("direct-e2e", direct_passphrase)
        .await
        .unwrap());
    tokio::time::timeout(Duration::from_secs(5), daemon_task)
        .await
        .expect("broker did not stop before profile rotation")
        .unwrap()
        .unwrap();
    assert!(!client::daemon_is_published().unwrap());

    let direct_identity = vault::verify_profile_identity("direct-e2e", direct_passphrase).unwrap();
    let rotated_direct_generation = vault::change_profile_passphrase(
        "direct-e2e",
        direct_passphrase,
        rotated_direct_passphrase,
        Some(direct_identity),
    )
    .unwrap();
    assert!(rotated_direct_generation > direct_identity.generation);
    assert!(vault::verify_profile_passphrase("direct-e2e", direct_passphrase).is_err());
    assert_eq!(
        vault::verify_profile_passphrase("direct-e2e", rotated_direct_passphrase).unwrap(),
        rotated_direct_generation
    );
    assert_eq!(
        vault::verify_profile_passphrase("e2e", E2E_PROFILE_PASSPHRASE).unwrap(),
        vault::list_profile_metadata()
            .unwrap()
            .into_iter()
            .find(|profile| profile.name == "e2e")
            .unwrap()
            .generation
    );
    assert!(
        vault::verify_profile_passphrase("e2e", rotated_direct_passphrase).is_err(),
        "one profile's replacement passphrase unexpectedly authorized another profile"
    );
    #[cfg(windows)]
    let rotated_direct_identity =
        vault::verify_profile_identity("direct-e2e", rotated_direct_passphrase).unwrap();

    #[cfg(windows)]
    {
        // Offline preservation is genuinely 2-of-2: valid media with the
        // wrong administrator password and valid administrator authorization
        // with damaged media both fail without modifying the vault. Only the
        // two valid halves together preserve the SSH credentials under a new
        // independent profile passphrase.
        let before_recovery_failures = std::fs::read(&vault_path).unwrap();
        let recovered_passphrase = "recovered-direct-profile-passphrase";
        let wrong_administrator = vault::recover_profile_with_media(
            "direct-e2e",
            recovery_media.as_slice(),
            Some("definitely-wrong-administrator-password"),
            recovered_passphrase,
            Some(rotated_direct_identity),
        )
        .unwrap_err();
        assert!(wrong_administrator.to_string().contains("administrator"));
        assert_eq!(
            std::fs::read(&vault_path).unwrap(),
            before_recovery_failures
        );

        let mut damaged_media = Zeroizing::new(recovery_media.as_slice().to_vec());
        let damaged_index = damaged_media.len() / 2;
        damaged_media[damaged_index] ^= 0x5a;
        let wrong_media = vault::recover_profile_with_media(
            "direct-e2e",
            damaged_media.as_slice(),
            administrator_passphrase,
            recovered_passphrase,
            Some(rotated_direct_identity),
        )
        .unwrap_err();
        assert!(
            wrong_media.to_string().contains("recovery")
                || wrong_media.to_string().contains("media")
                || wrong_media.to_string().contains("JSON")
        );
        assert_eq!(
            std::fs::read(&vault_path).unwrap(),
            before_recovery_failures
        );

        let recovered = vault::recover_profile_with_media(
            "direct-e2e",
            recovery_media.as_slice(),
            administrator_passphrase,
            recovered_passphrase,
            Some(rotated_direct_identity),
        )
        .unwrap();
        assert!(recovered.generation > rotated_direct_generation);
        assert!(vault::verify_profile_passphrase("direct-e2e", rotated_direct_passphrase).is_err());
        assert_eq!(
            vault::verify_profile_passphrase("direct-e2e", recovered_passphrase).unwrap(),
            recovered.generation
        );
        let recovered_creds = vault::decrypt("direct-e2e", recovered_passphrase).unwrap();
        assert_eq!(recovered_creds.host, direct_creds.host);
        assert_eq!(recovered_creds.port, direct_creds.port);
        assert_eq!(recovered_creds.user, direct_creds.user);
        assert_eq!(recovered_creds.password, direct_creds.password);
        assert_eq!(
            recovered_creds.host_key.as_deref(),
            Some(fingerprint.as_str())
        );
    }

    echo_task.abort();
    ssh_task.abort();
    drop(test_home_guard);
    assert!(
        !test_home.exists(),
        "isolated E2E home was not removed: {}",
        test_home.display()
    );
}

/// Recursively invoked in three separate OS processes by
/// `operation_grant_survives_issuer_exit_and_expires_across_processes`.
///
/// The helper uses only the isolated mock-test home supplied by its parent.
/// Keeping issuance and Agent JSONL consumption in this process role proves
/// the grant is not accidentally backed by process-local CLI state. A normal
/// harness invocation has no role and is a deliberate no-op; the parent E2E
/// exercises every real role. This avoids an ignored result in release test
/// accounting without allowing the helper to act on ambient state.
#[test]
fn operation_grant_lifecycle_subprocess_helper() {
    let role = match std::env::var(GRANT_SUBPROCESS_ROLE_ENV) {
        Ok(role) => role,
        Err(std::env::VarError::NotPresent) => return,
        Err(error) => panic!("read OperationGrant subprocess role: {error}"),
    };
    let home = std::env::var_os(GRANT_SUBPROCESS_HOME_ENV)
        .map(PathBuf::from)
        .expect("missing OperationGrant subprocess home");
    let grant_path = home.join(GRANT_SUBPROCESS_FILE);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build OperationGrant subprocess runtime");

    match role.as_str() {
        "issuer" => runtime.block_on(async {
            let grant = client::issue_grant_with_ttl_until(
                GRANT_SUBPROCESS_PROFILE,
                GRANT_SUBPROCESS_PASSPHRASE,
                vec!["ssh.exec".into()],
                3,
                serctl_protocol::grant::GRANT_MIN_TTL,
                &grant_path,
            )
            .await
            .expect("issue subprocess OperationGrant");
            // This marker deliberately contains only public lifecycle data;
            // the private holder key remains exclusively in the protected
            // grant file consumed by the later Agent process.
            std::fs::write(
                home.join(GRANT_SUBPROCESS_MARKER),
                serde_json::to_vec(&serde_json::json!({
                    "issuer_pid": std::process::id(),
                    "expires_unix_ms": grant.expires_unix_ms,
                }))
                .expect("serialize OperationGrant subprocess marker"),
            )
            .expect("write OperationGrant subprocess marker");
        }),
        "relay" => runtime
            .block_on(client::agent_stdio_loop(&grant_path))
            .expect("run subprocess Agent JSONL gateway"),
        "armed-expired" => {
            // Load while the protected file is still valid, then retain this
            // exact in-memory grant/key pair across the expiry boundary. This
            // closes a different path from the `expired` role below, which
            // proves that a newly started process rejects the file at load.
            let (grant, signing) = client::load_agent_grant(&grant_path)
                .expect("load OperationGrant before its expiry boundary");
            runtime.block_on(async {
                let now_unix_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock precedes Unix epoch")
                    .as_millis() as u64;
                assert!(
                    !grant.is_expired(now_unix_ms),
                    "armed OperationGrant was already expired at subprocess load"
                );
                if let Some(remaining_ms) = grant.expires_unix_ms.checked_sub(now_unix_ms) {
                    tokio::time::sleep(Duration::from_millis(remaining_ms.saturating_add(50)))
                        .await;
                }
                let expired_now_unix_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock precedes Unix epoch")
                    .as_millis() as u64;
                assert!(grant.is_expired(expired_now_unix_ms));
                let error = client::agent_exec_until(&grant, &signing, "ok", 1_000)
                    .await
                    .expect_err("preloaded expired grant unexpectedly reached daemon/SSH");
                assert_eq!(error.to_string(), "operation would exceed the grant expiry");
            });
        }
        "expired" => {
            let error = client::load_agent_grant(&grant_path)
                .expect_err("expired grant unexpectedly loaded");
            assert_eq!(error.to_string(), "agent grant has expired");
        }
        other => panic!("unexpected OperationGrant subprocess role: {other}"),
    }
}

struct GrantSubprocessOutput {
    pid: u32,
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_grant_subprocess(
    role: &'static str,
    home: PathBuf,
    input: Option<&'static [u8]>,
) -> GrantSubprocessOutput {
    tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let mut command = Command::new(std::env::current_exe().expect("resolve CLI test binary"));
        command
            .arg("--exact")
            .arg(GRANT_SUBPROCESS_TEST_NAME)
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(GRANT_SUBPROCESS_ROLE_ENV, role)
            .env(GRANT_SUBPROCESS_HOME_ENV, &home)
            .env("USERPROFILE", &home)
            .env("HOME", &home)
            .env_remove("SERCTL_SSH_PASS")
            .env_remove("SERCTL_PROFILE_PASS")
            .env_remove("SERCTL_ADMIN_PASS")
            .env_remove("SERCTL_LEGACY_MASTER")
            .env_remove("SERCTL_MASTER")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("spawn OperationGrant {role} subprocess: {error}"));
        let pid = child.id();
        if let Some(input) = input {
            let mut stdin = child
                .stdin
                .take()
                .expect("OperationGrant subprocess stdin was not piped");
            stdin
                .write_all(input)
                .expect("write Agent JSONL subprocess input");
            drop(stdin);
        }
        let output = child
            .wait_with_output()
            .unwrap_or_else(|error| panic!("wait for OperationGrant {role} subprocess: {error}"));
        GrantSubprocessOutput {
            pid,
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        }
    })
    .await
    .expect("join OperationGrant subprocess waiter")
}

fn assert_grant_subprocess_success(role: &str, output: &GrantSubprocessOutput) {
    assert!(
        output.status.success(),
        "OperationGrant {role} subprocess {} failed with {}; stdout={}; stderr={}",
        output.pid,
        output.status,
        String::from_utf8_lossy(&output.stdout).escape_debug(),
        String::from_utf8_lossy(&output.stderr).escape_debug(),
    );
}

async fn spawn_published_test_global_daemon(
    build_commit: &'static str,
    idle_exit_timeout: Duration,
) -> (
    ipc::v6::InstanceId,
    ipc::v6::ActivationSecret,
    serctl_core::daemon_runtime::DaemonRuntimeDescriptor,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let instance = ipc::v6::InstanceId::random();
    let secret = ipc::v6::ActivationSecret::random();
    let mut task = tokio::spawn(daemon::run_global_with_idle_timeout(
        instance,
        secret.clone(),
        build_commit.to_owned(),
        idle_exit_timeout,
    ));
    let publish_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(descriptor) = serctl_core::daemon_runtime::read_descriptor().unwrap() {
            assert_eq!(descriptor.instance_id, instance.as_hex());
            return (instance, secret, descriptor, task);
        }
        if task.is_finished() {
            let outcome = (&mut task).await;
            panic!("test global daemon exited before publication: {outcome:?}");
        }
        assert!(
            tokio::time::Instant::now() < publish_deadline,
            "test global daemon did not publish its descriptor"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_loss_after_grant_exec_is_unknown_and_new_instance_never_replays_it() {
    let _test_home_lock = TEST_HOME_LOCK.lock().await;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let test_home_guard = E2eTestHome::create(unique);
    let test_home = test_home_guard.path().to_owned();

    #[cfg(windows)]
    let mut recovery_media = Zeroizing::new(Vec::new());
    #[cfg(windows)]
    vault::initialize_admin_password(E2E_ADMINISTRATOR_PASSPHRASE, |media| {
        recovery_media.extend_from_slice(media);
        Ok(())
    })
    .unwrap();
    let administrator_passphrase = if cfg!(windows) {
        Some(E2E_ADMINISTRATOR_PASSPHRASE)
    } else {
        None
    };

    let state = Arc::new(TestState::default());
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
    let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = ssh_listener.local_addr().unwrap().port();
    let ssh_state = Arc::clone(&state);
    let ssh_task = tokio::spawn(async move {
        loop {
            let (socket, _) = ssh_listener.accept().await.unwrap();
            let connection = ssh_state.next_connection.fetch_add(1, Ordering::SeqCst);
            let handler = TestSsh {
                state: Arc::clone(&ssh_state),
                connection,
                channels: Arc::new(Mutex::new(HashMap::new())),
            };
            let config = Arc::clone(&config);
            let connection_state = Arc::clone(&ssh_state);
            tokio::spawn(async move {
                let result = match russh::server::run_stream(config, socket, handler).await {
                    Ok(running) => running.await,
                    Err(error) => Err(error),
                };
                if let Err(error) = result {
                    eprintln!("daemon-loss mock SSH transport failed: {error:#}");
                }
                connection_state.record_connection_closed(connection).await;
            });
        }
    });

    let profile = "grant-daemon-loss-e2e";
    let passphrase = "grant-daemon-loss-profile-passphrase";
    vault::create_profile(
        profile,
        &vault::Creds {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "tester".into(),
            password: "password".into(),
            host_key: Some(fingerprint),
        },
        passphrase,
        administrator_passphrase,
    )
    .unwrap();

    let (_first_instance, first_secret, first_descriptor, first_daemon) =
        spawn_published_test_global_daemon("grant-daemon-loss-e2e", Duration::from_secs(30)).await;
    let grant_path = test_home.join("daemon-loss-grant.json");
    client::issue_grant_with_ttl_until(
        profile,
        passphrase,
        vec!["ssh.exec".into()],
        2,
        serctl_protocol::grant::GRANT_MIN_TTL,
        &grant_path,
    )
    .await
    .unwrap();
    let (grant, signing) = client::load_agent_grant(&grant_path).unwrap();

    let before_exec = state.latest_exec_generation().await;
    let submitted_grant = grant.clone();
    let submitted_signing = signing.clone();
    let exec = tokio::spawn(async move {
        client::agent_exec_until(&submitted_grant, &submitted_signing, "hang", 10_000).await
    });
    let submitted_channel = state.wait_for_exec_start(before_exec, b"hang").await;
    assert_eq!(state.latest_exec_generation().await, before_exec + 1);

    // Aborting the daemon task models process loss after the authenticated
    // root request reached SSH but before an IPC terminal response existed.
    first_daemon.abort();
    assert!(first_daemon.await.unwrap_err().is_cancelled());
    let error = tokio::time::timeout(Duration::from_secs(5), exec)
        .await
        .expect("client did not settle after daemon loss")
        .unwrap()
        .expect_err("lost daemon response invented exec success");
    assert!(error.is::<serctl_core::ssh::ExecOutcomeUnknown>());
    state
        .wait_for_connection_closed(submitted_channel.connection, "daemon task abort")
        .await;

    // An in-process task abort cannot make this process PID dead. Remove only
    // the exact descriptor/secret owned by the aborted instance under the
    // normal startup lock; this emulates the stale-owner reconciliation that
    // a replacement OS process performs after a real crash.
    let startup_lock = match serctl_core::daemon_runtime::acquire_startup_lock().unwrap() {
        serctl_core::daemon_runtime::StartupLockAcquire::Acquired(lock) => lock,
        serctl_core::daemon_runtime::StartupLockAcquire::Contended => {
            panic!("aborted daemon retained the startup lock")
        }
    };
    assert!(serctl_core::daemon_runtime::cleanup_runtime_if_owner(
        &startup_lock,
        &first_descriptor,
        &first_secret,
    )
    .unwrap());
    drop(startup_lock);

    let (second_instance, _second_secret, second_descriptor, mut second_daemon) =
        spawn_published_test_global_daemon("grant-daemon-loss-e2e", Duration::from_secs(1)).await;
    assert_ne!(second_instance.as_hex(), first_descriptor.instance_id);
    assert_ne!(second_descriptor.instance_id, first_descriptor.instance_id);
    let before_stale_grant = state.latest_exec_generation().await;
    let stale_error = client::agent_exec_until(&grant, &signing, "ok", 1_000)
        .await
        .expect_err("replacement daemon restored an old in-memory grant");
    assert!(!stale_error.is::<serctl_core::ssh::ExecOutcomeUnknown>());
    assert!(
        stale_error
            .to_string()
            .contains("grant is not registered in this daemon instance"),
        "unexpected stale-grant rejection: {stale_error:#}"
    );
    assert_eq!(
        state.latest_exec_generation().await,
        before_stale_grant,
        "replacement daemon replayed the old request or old grant"
    );

    tokio::time::timeout(Duration::from_secs(5), &mut second_daemon)
        .await
        .expect("replacement daemon did not idle-exit")
        .unwrap()
        .unwrap();
    assert!(!client::daemon_is_published().unwrap());
    ssh_task.abort();
    drop(test_home_guard);
    assert!(!test_home.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operation_grant_survives_issuer_exit_and_expires_across_processes() {
    let _test_home_lock = TEST_HOME_LOCK.lock().await;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let test_home_guard = E2eTestHome::create(unique);
    let test_home = test_home_guard.path().to_owned();

    #[cfg(windows)]
    let mut recovery_media = Zeroizing::new(Vec::new());
    #[cfg(windows)]
    vault::initialize_admin_password(E2E_ADMINISTRATOR_PASSPHRASE, |media| {
        recovery_media.extend_from_slice(media);
        Ok(())
    })
    .unwrap();
    let administrator_passphrase = if cfg!(windows) {
        Some(E2E_ADMINISTRATOR_PASSPHRASE)
    } else {
        None
    };

    let state = Arc::new(TestState::default());
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
    let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = ssh_listener.local_addr().unwrap().port();
    let ssh_state = Arc::clone(&state);
    let ssh_task = tokio::spawn(async move {
        loop {
            let (socket, _) = ssh_listener.accept().await.unwrap();
            let connection = ssh_state.next_connection.fetch_add(1, Ordering::SeqCst);
            let handler = TestSsh {
                state: Arc::clone(&ssh_state),
                connection,
                channels: Arc::new(Mutex::new(HashMap::new())),
            };
            let config = Arc::clone(&config);
            let connection_state = Arc::clone(&ssh_state);
            tokio::spawn(async move {
                let result = match russh::server::run_stream(config, socket, handler).await {
                    Ok(running) => running.await,
                    Err(error) => Err(error),
                };
                if let Err(error) = result {
                    eprintln!("OperationGrant mock SSH transport failed: {error:#}");
                }
                connection_state.record_connection_closed(connection).await;
            });
        }
    });

    vault::create_profile(
        GRANT_SUBPROCESS_PROFILE,
        &vault::Creds {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "tester".into(),
            password: "password".into(),
            host_key: Some(fingerprint),
        },
        GRANT_SUBPROCESS_PASSPHRASE,
        administrator_passphrase,
    )
    .unwrap();

    let daemon_instance = ipc::v6::InstanceId::random();
    let daemon_instance_hex = daemon_instance.as_hex();
    let daemon_secret = ipc::v6::ActivationSecret::random();
    let mut daemon_task = tokio::spawn(daemon::run_global_with_idle_timeout(
        daemon_instance,
        daemon_secret,
        "grant-subprocess-e2e".to_owned(),
        Duration::from_secs(5),
    ));
    let publish_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if serctl_core::daemon_runtime::read_descriptor()
            .unwrap()
            .is_some()
        {
            break;
        }
        if daemon_task.is_finished() {
            let outcome = (&mut daemon_task).await;
            panic!("OperationGrant E2E daemon exited before publication: {outcome:?}");
        }
        assert!(
            tokio::time::Instant::now() < publish_deadline,
            "OperationGrant E2E daemon did not publish its descriptor"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let daemon_descriptor = serctl_core::daemon_runtime::read_descriptor()
        .unwrap()
        .expect("OperationGrant E2E daemon descriptor disappeared after publication");
    assert_eq!(daemon_descriptor.instance_id, daemon_instance_hex);
    assert_eq!(daemon_descriptor.pid, std::process::id());

    let issuer = run_grant_subprocess("issuer", test_home.clone(), None).await;
    assert_grant_subprocess_success("issuer", &issuer);
    assert_ne!(issuer.pid, std::process::id());
    assert!(test_home.join(GRANT_SUBPROCESS_FILE).is_file());
    assert!(test_home.join(GRANT_SUBPROCESS_MARKER).is_file());

    // The issuing process has terminated and every ordinary IPC connection
    // has had more than the configured idle window to drain. Only the
    // daemon's in-memory live-grant reference can keep it published here.
    tokio::time::sleep(Duration::from_millis(5_250)).await;
    assert!(
        !daemon_task.is_finished(),
        "daemon lost the live grant after issuer exit"
    );
    assert!(client::daemon_is_published().unwrap());
    assert_eq!(
        serctl_core::daemon_runtime::read_descriptor().unwrap(),
        Some(daemon_descriptor.clone()),
        "issuer exit was followed by an unexpected daemon identity replacement"
    );

    let exec_before_relay = state.latest_exec_generation().await;
    let relay_input: &'static [u8] =
        br#"{"schema_version":1,"op":"exec","request_id":41,"cmd":"ok","timeout_ms":3000}
{"schema_version":1,"op":"exec","request_id":42,"cmd":"ok","timeout_ms":3000}
"#;
    let relay = run_grant_subprocess("relay", test_home.clone(), Some(relay_input)).await;
    assert_grant_subprocess_success("relay", &relay);
    assert_ne!(relay.pid, std::process::id());
    assert_ne!(relay.pid, issuer.pid);
    let relay_lines = String::from_utf8_lossy(&relay.stdout)
        .lines()
        // With `--nocapture`, libtest can print `test <name> ... ` and the
        // gateway's first stdout record on one physical line. Parse only the
        // JSON suffix; later records remain ordinary JSONL lines.
        .filter_map(|line| line.find('{').map(|start| &line[start..]))
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    assert_eq!(
        relay_lines.len(),
        2,
        "unexpected Agent output: {}",
        String::from_utf8_lossy(&relay.stdout).escape_debug()
    );
    for (line, request_id) in relay_lines.iter().zip([41_u64, 42]) {
        assert_eq!(line["schema_version"], 1);
        assert_eq!(line["request_id"], request_id);
        assert_eq!(line["ok"], true);
        assert_eq!(line["data"]["code"], 0);
        assert_eq!(
            B64.decode(line["data"]["stdout"].as_str().unwrap())
                .unwrap(),
            b"evidence\n"
        );
    }
    assert_eq!(
        state.latest_exec_generation().await,
        exec_before_relay + 2,
        "the independent Agent process did not relay exactly two SSH operations"
    );
    assert_eq!(
        serctl_core::daemon_runtime::read_descriptor().unwrap(),
        Some(daemon_descriptor.clone()),
        "continuous Grant requests crossed daemon identities"
    );

    tokio::time::sleep(Duration::from_millis(5_250)).await;
    assert!(
        !daemon_task.is_finished(),
        "daemon dropped the partly spent live grant"
    );

    let marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(test_home.join(GRANT_SUBPROCESS_MARKER)).unwrap())
            .unwrap();
    assert_eq!(marker["issuer_pid"], issuer.pid);
    assert!(marker["expires_unix_ms"].as_u64().is_some());

    // This process loaded the Grant while valid, retained it in memory across
    // expiry, and then attempted an exec. The client-side absolute-expiry
    // guard must reject before IPC/SSH, while the original daemon identity is
    // still published until its reaper releases the active reference.
    let exec_before_armed_expired = state.latest_exec_generation().await;
    let armed_expired = run_grant_subprocess("armed-expired", test_home.clone(), None).await;
    assert_grant_subprocess_success("armed-expired", &armed_expired);
    assert_ne!(armed_expired.pid, std::process::id());
    assert_ne!(armed_expired.pid, issuer.pid);
    assert_ne!(armed_expired.pid, relay.pid);
    assert_eq!(
        state.latest_exec_generation().await,
        exec_before_armed_expired,
        "preloaded expired grant process reached mock SSH"
    );

    // The daemon's one-second reaper plus five-second idle window leaves it
    // running while this fresh process rejects the expired protected grant
    // locally. The mock SSH generation proves denial caused no remote work.
    assert!(client::daemon_is_published().unwrap());
    assert_eq!(
        serctl_core::daemon_runtime::read_descriptor().unwrap(),
        Some(daemon_descriptor),
        "Grant expiry was observed against a replacement daemon identity"
    );
    let exec_before_expired = state.latest_exec_generation().await;
    let expired = run_grant_subprocess("expired", test_home.clone(), None).await;
    assert_grant_subprocess_success("expired", &expired);
    assert_ne!(expired.pid, std::process::id());
    assert_ne!(expired.pid, issuer.pid);
    assert_ne!(expired.pid, relay.pid);
    assert_eq!(
        state.latest_exec_generation().await,
        exec_before_expired,
        "expired grant process reached mock SSH"
    );

    tokio::time::timeout(Duration::from_secs(10), &mut daemon_task)
        .await
        .expect("daemon did not idle-exit after the grant reference expired")
        .unwrap()
        .unwrap();
    assert!(!client::daemon_is_published().unwrap());

    ssh_task.abort();
    drop(test_home_guard);
    assert!(!test_home.exists());
}
