use crate::{client, daemon, ipc, vault};
use rand::{rngs::OsRng, RngCore as Rand08RngCore};
use russh::keys::{
    ssh_key::{self, rand_core},
    Algorithm, PrivateKey,
};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, Disconnect};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode, Version,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};
use zeroize::Zeroizing;

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
}

struct TestSsh {
    state: Arc<TestState>,
    connection: u64,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
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

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        match command {
            b"ok" => {
                session.data(channel, b"evidence\n".to_vec())?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            b"disconnect" => {
                let exec_channel = ExecChannel {
                    connection: self.connection,
                    channel,
                };
                self.state.record_exec_start(exec_channel, command).await;
                session.disconnect(Disconnect::ByApplication, "test disconnect", "en-US")?;
                // A transport disconnect ends every channel without a later
                // per-channel EOF callback, so record that terminal state at
                // the point where the test server queues the disconnect.
                self.state.record_cancel(exec_channel).await;
            }
            b"hang" => {
                self.state
                    .record_exec_start(
                        ExecChannel {
                            connection: self.connection,
                            channel,
                        },
                        command,
                    )
                    .await;
            }
            b"overflow" => {
                self.state
                    .record_exec_start(
                        ExecChannel {
                            connection: self.connection,
                            channel,
                        },
                        command,
                    )
                    .await;
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

async fn authenticated_stream(endpoint: &str, token: &str) -> anyhow::Result<ipc::ClientStream> {
    let mut stream = ipc::connect(endpoint).await?;
    ipc::authenticate_client(
        &mut stream,
        "e2e",
        token,
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await?;
    Ok(stream)
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

    // A first-use connection is split at the security boundary: KEX observes
    // the host key, pin persistence runs while the exclusive profile lease is
    // held, and only then may password authentication begin. Exercise a real
    // persistence failure and prove the fake SSH server never receives an
    // authentication request on that transport.
    let tofu_profile = "tofu-auth-order";
    // The vault has one global master verifier; reuse the master used by the
    // later direct-route cases in this integration test.
    let tofu_master = "direct-test-master";
    vault::add_or_update(
        tofu_profile,
        &vault::Creds {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "tester".into(),
            password: "password".into(),
            host_key: None,
        },
        tofu_master,
    )
    .unwrap();
    let tofu_lease = vault::acquire_runtime_lease(tofu_profile).unwrap();
    let tofu_creds = vault::decrypt(tofu_profile, tofu_master).unwrap();
    let auth_before_failed_pin = state.password_auth_attempts.load(Ordering::SeqCst);
    let staged = crate::ssh::SshSession::connect_key_exchange_until(
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
    )
    .unwrap_err();
    assert!(pin_error.to_string().contains("wrong master passphrase"));
    staged.abort().await;
    assert_eq!(
        state.password_auth_attempts.load(Ordering::SeqCst),
        auth_before_failed_pin,
        "password authentication was sent before the host-key pin persisted"
    );
    assert!(vault::decrypt(tofu_profile, tofu_master)
        .unwrap()
        .host_key
        .is_none());
    drop(tofu_lease);

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let daemon_task = tokio::spawn(daemon::run_with_ready_creds_for_test(
        "e2e",
        vault::Creds {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "tester".into(),
            password: "password".into(),
            host_key: Some(fingerprint.clone()),
        },
        Zeroizing::new("unused-test-master".to_owned()),
        Some(ready_tx),
    ));
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let lock = vault::read_lock("e2e").unwrap().unwrap();
    assert_eq!(lock.protocol, ipc::IPC_PROTOCOL_VERSION);
    assert_eq!(lock.port, 0);
    assert!(!lock.endpoint.is_empty());
    let mutation_error = vault::add_or_update(
        "e2e",
        &vault::Creds {
            host: "changed.example".into(),
            port: 2222,
            user: "other".into(),
            password: "replacement".into(),
            host_key: None,
        },
        "unused-test-master",
    )
    .unwrap_err();
    assert!(mutation_error.to_string().contains("daemon"));
    assert!(vault::remove("e2e")
        .unwrap_err()
        .to_string()
        .contains("daemon"));
    #[cfg(windows)]
    assert!(lock.endpoint.starts_with(r"\\.\pipe\serctl-v3-"));
    #[cfg(unix)]
    assert!(std::path::Path::new(&lock.endpoint)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("serctl-v3-") && name.ends_with(".sock")));

    let mut rejected = ipc::connect(&lock.endpoint).await.unwrap();
    let rejected_auth = ipc::authenticate_client(
        &mut rejected,
        "e2e",
        &vault::new_ipc_token(),
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await;
    assert!(rejected_auth.is_err());
    // A client that cannot verify the server proof sends no AuthResponse. If
    // it nevertheless attempts a business frame, the daemon must close the
    // connection without returning a structured authentication oracle.
    ipc::write_frame_limited(&mut rejected, &ipc::Frame::Status, ipc::MAX_REQUEST_FRAME)
        .await
        .unwrap();
    match tokio::time::timeout(
        Duration::from_secs(3),
        ipc::read_frame_limited(&mut rejected, ipc::MAX_RESPONSE_FRAME),
    )
    .await
    {
        Ok(Ok(None)) | Ok(Err(_)) => {}
        Ok(Ok(Some(frame))) => panic!("failed authentication returned a frame: {frame:?}"),
        Err(_) => panic!("daemon did not close failed authentication promptly"),
    }

    let output = client::exec_capture_with_timeout("e2e", "ok", None, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(output.stdout, b"evidence\n");
    assert_eq!(output.code, Some(0));

    let overflow_after = state.latest_exec_generation().await;
    let overflow_task = tokio::spawn(async {
        client::exec_capture_with_timeout("e2e", "overflow", None, Duration::from_secs(10)).await
    });
    let overflow_channel = state.wait_for_exec_start(overflow_after, b"overflow").await;
    let overflow = overflow_task.await.unwrap().unwrap_err();
    assert!(overflow.is::<crate::ssh::ExecOutcomeUnknown>());
    assert!(
        overflow.to_string().contains("8 MiB safety limit")
            && overflow.to_string().contains("outcome unknown"),
        "unexpected overflow result: {overflow:#}"
    );
    state
        .wait_for_cancel(overflow_channel, "output-limit failure")
        .await;

    let disconnected =
        client::exec_capture_with_timeout("e2e", "disconnect", None, Duration::from_secs(1))
            .await
            .unwrap_err();
    assert!(disconnected.is::<crate::ssh::ExecOutcomeUnknown>());
    assert!(
        disconnected.to_string().contains("outcome unknown")
            && disconnected
                .to_string()
                .contains("inspect remote side effects before retry")
    );
    let reconnected = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client::exec_capture_with_timeout("e2e", "ok", None, Duration::from_secs(1)).await
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
        client::exec_capture_with_timeout("e2e", "hang", None, Duration::from_millis(50)).await
    });
    let timeout_channel = state.wait_for_exec_start(timeout_after, b"hang").await;
    let timeout = timeout_task.await.unwrap().unwrap_err();
    assert!(timeout.is::<crate::ssh::ExecOutcomeUnknown>());
    assert!(timeout.to_string().contains("deadline"));
    assert!(timeout
        .to_string()
        .contains("inspect remote side effects before retry"));
    state
        .wait_for_cancel(timeout_channel, "command deadline")
        .await;

    let mut disconnected = authenticated_stream(&lock.endpoint, &lock.token)
        .await
        .unwrap();
    let disconnect_after = state.latest_exec_generation().await;
    ipc::write_frame(
        &mut disconnected,
        &ipc::Frame::Exec {
            cmd: "hang".into(),
            timeout_ms: 10_000,
        },
    )
    .await
    .unwrap();
    let disconnected_channel = state.wait_for_exec_start(disconnect_after, b"hang").await;
    disconnected.shutdown().await.unwrap();
    drop(disconnected);
    state
        .wait_for_cancel(disconnected_channel, "IPC client disconnect")
        .await;

    let daemon_upload_after = state.latest_upload_partial_generation().await;
    state.sftp_write_hang.store(true, Ordering::SeqCst);
    state
        .upload_partial_remove_delay
        .store(true, Ordering::SeqCst);
    let mut timed_upload = authenticated_stream(&lock.endpoint, &lock.token)
        .await
        .unwrap();
    ipc::write_frame(
        &mut timed_upload,
        &ipc::Frame::UploadBegin {
            path: "/daemon-timeout.txt".into(),
            size: 15,
            timeout_ms: 100,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        ipc::read_frame(&mut timed_upload).await.unwrap(),
        Some(ipc::Frame::Ack)
    ));
    let daemon_partial = state
        .wait_for_upload_partial(daemon_upload_after, "/daemon-timeout.txt")
        .await;
    assert!(daemon_partial.starts_with("/daemon-timeout.txt.serctl-part-"));
    ipc::write_frame(
        &mut timed_upload,
        &ipc::Frame::UploadChunk {
            data: b"server evidence".to_vec(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        ipc::read_frame(&mut timed_upload).await.unwrap(),
        Some(ipc::Frame::Ack)
    ));
    ipc::write_frame(&mut timed_upload, &ipc::Frame::UploadEnd)
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), ipc::read_frame(&mut timed_upload))
        .await
        .expect("daemon upload cleanup exceeded its bounded grace")
        .unwrap();
    assert!(
        matches!(
            response,
            Some(ipc::Frame::Error { ref msg }) if msg.contains("deadline")
        ),
        "unexpected timed upload response: {response:?}"
    );
    assert!(!state
        .files
        .lock()
        .await
        .keys()
        .any(|path| path.starts_with("/daemon-timeout.txt.serctl-part-")));
    state.sftp_write_hang.store(false, Ordering::SeqCst);
    state
        .upload_partial_remove_delay
        .store(false, Ordering::SeqCst);

    let upload_source = test_home.join("evidence.txt");
    std::fs::write(&upload_source, b"server evidence").unwrap();
    assert_eq!(
        client::upload_with_timeout_and_master(
            "e2e",
            &upload_source,
            "/evidence.txt",
            Duration::from_secs(5),
            None,
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
            None,
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
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        state.files.lock().await.get("/hardlink-race.txt").unwrap(),
        b"concurrent winner"
    );

    let (listed_path, entries) =
        client::list_dir_with_timeout("e2e", "/", None, Duration::from_secs(2))
            .await
            .unwrap();
    assert_eq!(listed_path, "/");
    assert!(entries
        .iter()
        .any(|entry| entry.name == "evidence.txt" && entry.size == 15));

    state.sftp_large_dir.store(true, Ordering::SeqCst);
    let large_directory = client::list_dir_with_timeout("e2e", "/", None, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        large_directory
            .to_string()
            .contains("more than 10000 entries"),
        "unexpected large-directory result: {large_directory:#}"
    );
    state.sftp_large_dir.store(false, Ordering::SeqCst);
    let after_large_directory =
        client::exec_capture_with_timeout("e2e", "ok", None, Duration::from_secs(1))
            .await
            .unwrap();
    assert_eq!(after_large_directory.code, Some(0));

    // A download client that authenticates and then stops reading must lose
    // only its IPC connection. In particular, filling the local socket/pipe
    // buffer must not turn the daemon's bounded response-write failure into a
    // daemon-wide SSH invalidation that disrupts unrelated requests.
    state
        .files
        .lock()
        .await
        .insert("/ipc-backpressure.bin".into(), vec![b'b'; 12 * 1024 * 1024]);
    let ssh_connections_before_backpressure = state.next_connection.load(Ordering::SeqCst);
    let mut stalled_download = authenticated_stream(&lock.endpoint, &lock.token)
        .await
        .unwrap();
    ipc::write_frame(
        &mut stalled_download,
        &ipc::Frame::Download {
            path: "/ipc-backpressure.bin".into(),
            timeout_ms: 10_000,
        },
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(2_750)).await;
    drop(stalled_download);
    let after_backpressure =
        client::exec_capture_with_timeout("e2e", "ok", None, Duration::from_secs(1))
            .await
            .unwrap();
    assert_eq!(after_backpressure.code, Some(0));
    assert_eq!(
        state.next_connection.load(Ordering::SeqCst),
        ssh_connections_before_backpressure,
        "an IPC-only download failure invalidated the shared SSH transport"
    );
    state.files.lock().await.remove("/ipc-backpressure.bin");

    let download_target = test_home.join("downloaded-evidence.txt");
    assert_eq!(
        client::download_with_timeout_and_master(
            "e2e",
            "/evidence.txt",
            &download_target,
            Duration::from_secs(5),
            None,
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
        Duration::from_millis(50),
        None,
    )
    .await
    .unwrap_err();
    assert!(upload_timeout.to_string().contains("deadline"));

    let timed_download = test_home.join("timed-download.txt");
    let download_timeout = client::download_with_timeout_and_master(
        "e2e",
        "/evidence.txt",
        &timed_download,
        Duration::from_millis(50),
        None,
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
    let after_timeout =
        client::exec_capture_with_timeout("e2e", "ok", None, Duration::from_secs(1))
            .await
            .unwrap();
    assert_eq!(after_timeout.code, Some(0));

    let mut shutdown_exec = authenticated_stream(&lock.endpoint, &lock.token)
        .await
        .unwrap();
    let shutdown_after = state.latest_exec_generation().await;
    ipc::write_frame(
        &mut shutdown_exec,
        &ipc::Frame::Exec {
            cmd: "hang".into(),
            timeout_ms: 10_000,
        },
    )
    .await
    .unwrap();
    let shutdown_channel = state.wait_for_exec_start(shutdown_after, b"hang").await;

    assert!(client::down_quiet("e2e").await.unwrap());
    tokio::time::timeout(Duration::from_secs(5), daemon_task)
        .await
        .expect("daemon did not drain active handlers during shutdown")
        .unwrap()
        .unwrap();
    // The daemon awaits the local channel close, but delivery to the test
    // server's callback crosses the SSH transport task and may be observed a
    // scheduler turn after the daemon future completes.
    state
        .wait_for_cancel(shutdown_channel, "daemon shutdown")
        .await;

    // Missing protocol means the legacy bearer-token handshake. It must fail
    // before even connecting to an endpoint, and diagnostics must not echo the
    // reusable token.
    let legacy_profile = "legacy-lock-e2e";
    let legacy_token = Zeroizing::new(vault::new_ipc_token());
    let mut legacy_listener = ipc::LocalListener::bind(legacy_profile, &legacy_token).unwrap();
    let legacy_endpoint = legacy_listener.endpoint().to_owned();
    #[derive(serde::Serialize)]
    struct LegacyLock<'a> {
        profile: &'a str,
        pid: u32,
        port: u16,
        endpoint: &'a str,
        host: &'a str,
        user: &'a str,
        started_unix: i64,
        token: &'a str,
    }
    let legacy_json = Zeroizing::new(
        serde_json::to_vec(&LegacyLock {
            profile: legacy_profile,
            pid: std::process::id(),
            port: 0,
            endpoint: &legacy_endpoint,
            host: "",
            user: "",
            started_unix: vault::now_unix(),
            token: &legacy_token,
        })
        .unwrap(),
    );
    let legacy_path = vault::lock_path(legacy_profile).unwrap();
    std::fs::write(&legacy_path, &legacy_json).unwrap();
    let legacy_error = client::daemon_status(legacy_profile).await.unwrap_err();
    assert!(legacy_error.to_string().contains("bearer-token IPC"));
    assert!(!legacy_error.to_string().contains(legacy_token.as_str()));
    assert!(
        tokio::time::timeout(Duration::from_millis(75), legacy_listener.accept())
            .await
            .is_err()
    );

    // Protocol v2 used an untagged Error frame for both definite rejection
    // and post-submit uncertainty. A v3 client must reject its lock before
    // connecting, disclose no authentication bytes, and retain the evidence
    // instead of treating it as a malformed current-version lock.
    let old_v2_lock = vault::LockInfo {
        profile: legacy_profile.into(),
        protocol: 2,
        pid: std::process::id(),
        port: 0,
        endpoint: legacy_endpoint.clone(),
        host: String::new(),
        user: String::new(),
        started_unix: vault::now_unix(),
        token: legacy_token.as_str().to_owned(),
    };
    let old_v2_json = Zeroizing::new(serde_json::to_vec(&old_v2_lock).unwrap());
    std::fs::write(&legacy_path, &old_v2_json).unwrap();
    let old_v2_error = client::daemon_status(legacy_profile).await.unwrap_err();
    assert!(old_v2_error
        .to_string()
        .contains("unsupported runtime lock IPC protocol 2"));
    assert!(!old_v2_error.to_string().contains(legacy_token.as_str()));
    assert!(legacy_path.exists());
    assert!(
        tokio::time::timeout(Duration::from_millis(75), legacy_listener.accept())
            .await
            .is_err()
    );

    // A malformed current-v3 lock in the hashed namespace is recoverable only
    // after the client obtains the exclusive runtime lease. Endpoint mismatch
    // is then deleted without connecting or sending authentication bytes.
    let tampered_lock = vault::LockInfo {
        profile: legacy_profile.into(),
        protocol: ipc::IPC_PROTOCOL_VERSION,
        pid: std::process::id(),
        port: 0,
        endpoint: format!("{legacy_endpoint}x"),
        host: String::new(),
        user: String::new(),
        started_unix: vault::now_unix(),
        token: legacy_token.as_str().to_owned(),
    };
    let tampered_json = Zeroizing::new(serde_json::to_vec(&tampered_lock).unwrap());
    std::fs::write(&legacy_path, &tampered_json).unwrap();
    assert!(client::daemon_status(legacy_profile)
        .await
        .unwrap()
        .is_none());
    assert!(!legacy_path.exists());
    assert!(
        tokio::time::timeout(Duration::from_millis(75), legacy_listener.accept())
            .await
            .is_err()
    );

    #[cfg(unix)]
    {
        // The raw v1 name is consulted only after the hashed namespace has no
        // record. A malformed hashed-v3 lock must therefore be removed and
        // followed by a second read, which exposes (and rejects) this legacy
        // bearer-token lock instead of silently falling back to direct SSH.
        let raw_legacy_path = vault::run_dir()
            .unwrap()
            .join(format!("{legacy_profile}.lock"));
        std::fs::write(&raw_legacy_path, &legacy_json).unwrap();
        std::fs::write(&legacy_path, &tampered_json).unwrap();
        let shadowed_legacy = client::daemon_status(legacy_profile).await.unwrap_err();
        assert!(shadowed_legacy.to_string().contains("bearer-token IPC"));
        assert!(!shadowed_legacy.to_string().contains(legacy_token.as_str()));
        assert!(!legacy_path.exists());
        assert!(raw_legacy_path.exists());
        assert!(
            tokio::time::timeout(Duration::from_millis(75), legacy_listener.accept())
                .await
                .is_err()
        );
        std::fs::remove_file(raw_legacy_path).unwrap();
    }

    #[cfg(windows)]
    {
        // Windows exposes the named-pipe server PID reliably. A mismatched
        // protected-lock PID must stop before AuthHello, and a held daemon
        // lease must prevent the client from deleting that lock as stale.
        let profile = "pid-mismatch-e2e";
        let token = Zeroizing::new(vault::new_ipc_token());
        let mut fake_listener = ipc::LocalListener::bind(profile, &token).unwrap();
        let endpoint = fake_listener.endpoint().to_owned();
        let lease = vault::acquire_runtime_lease(profile).unwrap();
        let current_pid = std::process::id();
        let wrong_pid = if current_pid == u32::MAX {
            current_pid - 1
        } else {
            current_pid + 1
        };
        vault::write_lock(&vault::LockInfo {
            profile: profile.into(),
            protocol: ipc::IPC_PROTOCOL_VERSION,
            pid: wrong_pid,
            port: 0,
            endpoint,
            host: String::new(),
            user: String::new(),
            started_unix: vault::now_unix(),
            token: token.as_str().to_owned(),
        })
        .unwrap();

        let pid_error = client::daemon_status(profile).await.unwrap_err();
        assert!(pid_error.to_string().contains("still leased"));
        let mut fake_server = fake_listener.accept().await.unwrap();
        assert!(matches!(
            ipc::read_frame_limited(&mut fake_server, ipc::MAX_AUTH_FRAME).await,
            Ok(None)
        ));
        assert!(vault::read_lock(profile).unwrap().is_some());
        drop(lease);
        assert_eq!(
            vault::reconcile_lock_if_token(profile, &token).unwrap(),
            vault::LockReconcileOutcome::Removed
        );
    }

    let direct_master = "direct-test-master";
    let direct_creds = vault::Creds {
        host: "127.0.0.1".into(),
        port: ssh_port,
        user: "tester".into(),
        password: "password".into(),
        host_key: None,
    };
    let direct_use_lease = vault::acquire_profile_use_lease("direct-e2e").unwrap();
    let direct_mutation_error =
        vault::add_or_update("direct-e2e", &direct_creds, direct_master).unwrap_err();
    assert!(direct_mutation_error.to_string().contains("daemon"));
    drop(direct_use_lease);
    vault::add_or_update("direct-e2e", &direct_creds, direct_master).unwrap();
    vault::set_pinned_fp("direct-e2e", fingerprint, direct_master).unwrap();

    let direct_exec = client::exec_capture_with_timeout(
        "direct-e2e",
        "ok",
        Some(direct_master),
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
            Some(direct_master),
            Duration::from_secs(3),
        )
        .await
    });
    let direct_hang_channel = state.wait_for_exec_start(direct_hang_after, b"hang").await;
    let direct_hang = direct_hang_task.await.unwrap().unwrap_err();
    assert!(direct_hang.is::<crate::ssh::ExecOutcomeUnknown>());
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
            Some(direct_master),
            Duration::from_secs(3),
        )
        .await
    });
    let direct_disconnect_channel = state
        .wait_for_exec_start(direct_disconnect_after, b"disconnect")
        .await;
    let direct_disconnect = direct_disconnect_task.await.unwrap().unwrap_err();
    assert!(direct_disconnect.is::<crate::ssh::ExecOutcomeUnknown>());
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
            Some(Zeroizing::new(direct_master.to_owned())),
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
        Some(Zeroizing::new(direct_master.to_owned())),
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
            Some(Zeroizing::new(direct_master.to_owned())),
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

    ssh_task.abort();
    vault::set_test_home(None);
    std::fs::remove_dir_all(test_home).unwrap();
}
