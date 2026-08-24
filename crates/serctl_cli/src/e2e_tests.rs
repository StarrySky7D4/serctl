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
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};
use zeroize::Zeroizing;

const E2E_PROFILE_PASSPHRASE: &str = "daemon-profile-passphrase";
const TOFU_PROFILE_PASSPHRASE: &str = "tofu-profile-passphrase";
const DIRECT_PROFILE_PASSPHRASE: &str = "direct-profile-passphrase";
const E2E_ADMINISTRATOR_PASSPHRASE: &str = "e2e-administrator-passphrase";

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
    password_auth_attempts: AtomicU64,
    exec_events: Mutex<ExecEvents>,
    exec_changed: Notify,
    sftp_hang: AtomicBool,
    sftp_write_hang: AtomicBool,
    sftp_large_dir: AtomicBool,
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
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
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
            handles: HashMap::new(),
            directory_handles: HashMap::new(),
            directories_read: HashSet::new(),
        };
        tokio::spawn(russh_sftp::server::run(channel.into_stream(), sftp));
        Ok(())
    }
}

struct MemorySftp {
    state: Arc<TestState>,
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
        if self.state.sftp_hang.load(Ordering::SeqCst) {
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
        if self.state.sftp_write_hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
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
        if self.state.sftp_hang.load(Ordering::SeqCst) {
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
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let test_home = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!("e2e-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&test_home).unwrap();
    vault::set_test_home(Some(test_home.clone()));
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
            let handler = TestSsh {
                state: ssh_state.clone(),
                connection: ssh_state.next_connection.fetch_add(1, Ordering::SeqCst),
                channels: Arc::new(Mutex::new(HashMap::new())),
            };
            let config = config.clone();
            tokio::spawn(async move {
                let _ = russh::server::run_stream(config, socket, handler).await;
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
        host_key: Some(fingerprint.clone()),
    };
    vault::create_profile(
        "e2e",
        &daemon_creds,
        E2E_PROFILE_PASSPHRASE,
        administrator_passphrase,
    )
    .unwrap();

    let daemon_instance = ipc::v6::InstanceId::random();
    let daemon_secret = ipc::v6::ActivationSecret::random();
    let daemon_task = tokio::spawn(daemon::run_global(
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
            break;
        }
        if tokio::time::Instant::now() >= publish_deadline {
            panic!("global daemon did not publish its runtime descriptor");
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
    assert!(wrong_status
        .to_string()
        .contains("wrong profile passphrase"));
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

    // Unlock through the broker: the pool's credential lease is what blocks
    // vault mutations while a profile is live and unlocked.
    assert!(matches!(
        client::daemon_status("e2e", E2E_PROFILE_PASSPHRASE)
            .await
            .unwrap(),
        Some(client::DaemonStatus { profile, .. }) if profile == "e2e"
    ));

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
    let upload_timeout = client::upload_with_timeout_and_master(
        "e2e",
        &upload_source,
        "/hung-upload.txt",
        Duration::from_millis(500),
        Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
    )
    .await
    .unwrap_err();
    assert!(upload_timeout.to_string().contains("deadline"));

    let timed_download = test_home.join("timed-download.txt");
    let download_timeout = client::download_with_timeout_and_master(
        "e2e",
        "/evidence.txt",
        &timed_download,
        Duration::from_millis(500),
        Some(Zeroizing::new(E2E_PROFILE_PASSPHRASE.to_owned())),
    )
    .await
    .unwrap_err();
    assert!(download_timeout.to_string().contains("deadline"));
    assert!(!timed_download.exists());
    assert!(!std::fs::read_dir(&test_home).unwrap().any(|entry| {
        entry
            .ok()
            .and_then(|entry| entry.file_name().into_string().ok())
            .is_some_and(|name| name.starts_with("timed-download.txt.serctl-part-"))
    }));

    state.sftp_hang.store(false, Ordering::SeqCst);
    let after_timeout = client::exec_capture_with_timeout(
        "e2e",
        "ok",
        Some(E2E_PROFILE_PASSPHRASE),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
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
    let daemon_task = tokio::spawn(daemon::run_global(
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
            break;
        }
        if tokio::time::Instant::now() >= publish_deadline {
            panic!("second global daemon did not publish its runtime descriptor");
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
    let exec_events_before_budget = state.latest_exec_generation().await;
    let exhausted = client::agent_exec_until(&loaded_grant, &signing, "ok", 3_000)
        .await
        .unwrap_err();
    assert!(exhausted.to_string().contains("grant budget exhausted"));
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
    let scope_error = client::agent_exec_until(&list_grant, &list_signing, "ok", 3_000)
        .await
        .unwrap_err();
    assert!(scope_error
        .to_string()
        .contains("does not authorize this operation kind"));
    let listing = client::agent_list_until(&list_grant, &list_signing, "/", 3_000)
        .await
        .unwrap();
    assert!(listing["entries"]
        .as_array()
        .is_some_and(|entries| entries.iter().any(|entry| entry["name"] == "evidence.txt")));

    // Proof of possession: a different key cannot relay with this grant.
    let other_key = SigningKey::generate(&mut OsRng);
    let pop_error = client::agent_exec_until(&loaded_grant, &other_key, "ok", 3_000)
        .await
        .unwrap_err();
    assert!(pop_error
        .to_string()
        .contains("proof-of-possession verification failed"));

    // The audit trail persists accepted relays and rejections.
    let audit_path = serctl_core::daemon_runtime::grant_audit_path().unwrap();
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        audit.contains("\"accepted\""),
        "grant audit log is missing accepted relays: {audit}"
    );
    assert!(
        audit.contains("rejected: grant budget exhausted"),
        "grant audit log is missing budget rejections: {audit}"
    );
    assert!(
        audit.contains("rejected: grant does not authorize this operation kind"),
        "grant audit log is missing scope rejections: {audit}"
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
    vault::set_test_home(None);
    std::fs::remove_dir_all(test_home).unwrap();
}
