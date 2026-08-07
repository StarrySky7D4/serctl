use crate::{client, daemon, ipc, vault};
use rand::rngs::OsRng;
use russh::keys::{ssh_key, Algorithm, PrivateKey};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};
use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode, Version,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Default)]
struct TestState {
    files: Mutex<HashMap<String, Vec<u8>>>,
    cancelled: AtomicBool,
    sftp_hang: AtomicBool,
    sftp_write_hang: AtomicBool,
    upload_partial_created: AtomicBool,
}

struct TestSsh {
    state: Arc<TestState>,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl russh::server::Handler for TestSsh {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == "tester" && password == "password" {
            Auth::Accept
        } else {
            Auth::Reject {
                proceed_with_methods: None,
            }
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        Ok(true)
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
                session.data(channel, CryptoVec::from_slice(b"evidence\n"))?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            b"hang" => {}
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
        self.state.cancelled.store(true, Ordering::SeqCst);
        session.close(channel)?;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.cancelled.store(true, Ordering::SeqCst);
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
        };
        tokio::spawn(russh_sftp::server::run(channel.into_stream(), sftp));
        Ok(())
    }
}

struct MemorySftp {
    state: Arc<TestState>,
    handles: HashMap<String, String>,
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
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if self.state.sftp_hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        let mut files = self.state.files.lock().await;
        if flags.contains(OpenFlags::CREATE) {
            files.entry(filename.clone()).or_default();
            if filename.contains(".serctl-part-") {
                self.state
                    .upload_partial_created
                    .store(true, Ordering::SeqCst);
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
        Ok(ok_status(id))
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
}

async fn authenticated_stream(endpoint: &str, token: &str) -> anyhow::Result<ipc::ClientStream> {
    let mut stream = ipc::connect(endpoint).await?;
    ipc::write_frame(
        &mut stream,
        &ipc::Frame::Authenticate {
            token: token.to_owned(),
        },
    )
    .await?;
    anyhow::ensure!(matches!(
        ipc::read_frame(&mut stream).await?,
        Some(ipc::Frame::Ack)
    ));
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
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
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
                channels: Arc::new(Mutex::new(HashMap::new())),
            };
            let config = config.clone();
            tokio::spawn(async move {
                let _ = russh::server::run_stream(config, socket, handler).await;
            });
        }
    });

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let daemon_task = tokio::spawn(daemon::run_with_ready(
        "e2e",
        vault::Creds {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "tester".into(),
            password: "password".into(),
            host_key: Some(fingerprint.clone()),
        },
        "unused-test-master".into(),
        Some(ready_tx),
    ));
    tokio::task::spawn_blocking(move || ready_rx.recv_timeout(Duration::from_secs(5)).unwrap())
        .await
        .unwrap();
    let lock = vault::read_lock("e2e").unwrap().unwrap();
    assert_eq!(lock.port, 0);
    assert!(!lock.endpoint.is_empty());
    #[cfg(windows)]
    assert!(lock.endpoint.starts_with(r"\\.\pipe\serctl-"));
    #[cfg(unix)]
    assert!(lock.endpoint.ends_with(".sock"));

    let mut rejected = ipc::connect(&lock.endpoint).await.unwrap();
    ipc::write_frame(
        &mut rejected,
        &ipc::Frame::Authenticate {
            token: vault::new_ipc_token(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        ipc::read_frame(&mut rejected).await.unwrap(),
        Some(ipc::Frame::Error { .. })
    ));

    let output = client::exec_capture_with_timeout("e2e", "ok", None, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(output.stdout, b"evidence\n");
    assert_eq!(output.code, Some(0));

    let timeout = client::exec_capture_with_timeout("e2e", "hang", None, Duration::from_millis(50))
        .await
        .unwrap_err();
    assert!(timeout.to_string().contains("deadline"));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !state.cancelled.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    state.cancelled.store(false, Ordering::SeqCst);
    let mut disconnected = authenticated_stream(&lock.endpoint, &lock.token)
        .await
        .unwrap();
    ipc::write_frame(
        &mut disconnected,
        &ipc::Frame::Exec {
            cmd: "hang".into(),
            timeout_ms: 10_000,
        },
    )
    .await
    .unwrap();
    disconnected.shutdown().await.unwrap();
    drop(disconnected);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !state.cancelled.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let upload_source = test_home.join("evidence.txt");
    std::fs::write(&upload_source, b"server evidence").unwrap();
    assert_eq!(
        client::upload_file("e2e", &upload_source, "/evidence.txt", None)
            .await
            .unwrap(),
        15
    );
    assert_eq!(
        state.files.lock().await.get("/evidence.txt").unwrap(),
        b"server evidence"
    );

    let download_target = test_home.join("downloaded-evidence.txt");
    assert_eq!(
        client::download_file("e2e", "/evidence.txt", &download_target, None)
            .await
            .unwrap(),
        15
    );
    assert_eq!(std::fs::read(&download_target).unwrap(), b"server evidence");

    state.sftp_hang.store(true, Ordering::SeqCst);
    let upload_timeout = client::upload_file_with_timeout(
        "e2e",
        &upload_source,
        "/hung-upload.txt",
        None,
        Duration::from_millis(50),
    )
    .await
    .unwrap_err();
    assert!(upload_timeout.to_string().contains("deadline"));

    let timed_download = test_home.join("timed-download.txt");
    let download_timeout = client::download_file_with_timeout(
        "e2e",
        "/evidence.txt",
        &timed_download,
        None,
        Duration::from_millis(50),
    )
    .await
    .unwrap_err();
    assert!(download_timeout.to_string().contains("deadline"));
    assert!(!timed_download.exists());
    assert!(!test_home.join("timed-download.txt.serctl-part").exists());

    state.sftp_hang.store(false, Ordering::SeqCst);
    let after_timeout =
        client::exec_capture_with_timeout("e2e", "ok", None, Duration::from_secs(1))
            .await
            .unwrap();
    assert_eq!(after_timeout.code, Some(0));

    assert!(client::down_quiet("e2e").await.unwrap());
    daemon_task.await.unwrap().unwrap();

    let direct_master = "direct-test-master";
    vault::add_or_update(
        "direct-e2e",
        &vault::Creds {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "tester".into(),
            password: "password".into(),
            host_key: None,
        },
        direct_master,
    )
    .unwrap();
    vault::set_pinned_fp("direct-e2e", fingerprint, direct_master).unwrap();
    state.upload_partial_created.store(false, Ordering::SeqCst);
    state.sftp_write_hang.store(true, Ordering::SeqCst);
    let direct_timeout = client::upload_file_with_timeout(
        "direct-e2e",
        &upload_source,
        "/direct-timeout.txt",
        Some(direct_master),
        Duration::from_secs(3),
    )
    .await
    .unwrap_err();
    assert!(direct_timeout.to_string().contains("deadline"));
    assert!(state.upload_partial_created.load(Ordering::SeqCst));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let has_partial = state
                .files
                .lock()
                .await
                .keys()
                .any(|path| path.starts_with("/direct-timeout.txt.serctl-part-"));
            if !has_partial {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!state.files.lock().await.contains_key("/direct-timeout.txt"));

    ssh_task.abort();
    vault::set_test_home(None);
    std::fs::remove_dir_all(test_home).unwrap();
}
