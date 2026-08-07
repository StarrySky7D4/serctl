//! IPC client + direct-connect fallback for exec / shell / status / down.
use anyhow::{anyhow, bail, Context, Result};
use crossterm::{
    event::{Event, KeyCode, KeyEvent, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use russh::ChannelMsg;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::ipc;
use crate::ssh::{temporary_remote_path, RemoteEntry, SshSession};
use crate::vault::{self, now_unix, Creds, LockInfo};

#[derive(Clone, Debug)]
pub struct DaemonStatus {
    pub profile: String,
    pub host: String,
    pub user: String,
    pub started_unix: i64,
    pub port: u16,
}

#[derive(Clone, Debug, Default)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<i32>,
}

#[derive(Debug)]
pub enum ShellEvent {
    Output(Vec<u8>),
    Closed,
    Error(String),
}

pub struct GuiShell {
    pub input: mpsc::Sender<Vec<u8>>,
    pub events: mpsc::Receiver<ShellEvent>,
}

struct DaemonConnection {
    stream: TcpStream,
    lock: LockInfo,
}

async fn connect_daemon(profile: &str) -> Result<Option<DaemonConnection>> {
    let Some(lock) = vault::read_lock(profile)? else {
        return Ok(None);
    };
    if lock.token.is_empty() {
        bail!("legacy daemon has no IPC authentication; restart it with the updated serctl");
    }
    let connected = tokio::time::timeout(
        Duration::from_millis(400),
        TcpStream::connect(("127.0.0.1", lock.port)),
    )
    .await;
    let Ok(Ok(mut stream)) = connected else {
        let _ = vault::remove_lock_if_token(profile, &lock.token);
        return Ok(None);
    };
    let response = tokio::time::timeout(Duration::from_secs(2), async {
        ipc::write_frame(
            &mut stream,
            &ipc::Frame::Authenticate {
                token: lock.token.clone(),
            },
        )
        .await?;
        ipc::read_frame_limited(&mut stream, ipc::MAX_AUTH_FRAME).await
    })
    .await
    .map_err(|_| anyhow!("daemon IPC authentication timed out"))??;
    match response {
        Some(ipc::Frame::Ack) => Ok(Some(DaemonConnection { stream, lock })),
        Some(ipc::Frame::Error { msg }) => bail!(msg),
        _ => bail!("daemon returned an unexpected authentication response"),
    }
}

fn ask_master() -> Result<Zeroizing<String>> {
    if let Ok(m) = std::env::var("SERCTL_MASTER") {
        std::env::remove_var("SERCTL_MASTER");
        return Ok(Zeroizing::new(m));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(
        "master passphrase: ",
    )?))
}

fn ask_decrypt(profile: &str) -> Result<(Creds, Zeroizing<String>)> {
    let master = ask_master()?;
    Ok((vault::decrypt(profile, &master)?, master))
}

async fn direct_connect(profile: &str, creds: &Creds, master: &str) -> Result<SshSession> {
    let expect = creds.host_key.clone();
    let (session, fp) = SshSession::connect(creds, expect).await?;
    if creds.host_key.is_none() && !fp.is_empty() {
        eprintln!("[serctl] pinned host key {fp}");
        vault::set_pinned_fp(profile, fp, master)?;
    }
    Ok(session)
}

pub async fn exec_with_timeout(profile: &str, cmd: &str, timeout: Duration) -> Result<i32> {
    if connect_daemon(profile).await?.is_some() {
        let result = exec_capture_with_timeout(profile, cmd, None, timeout).await?;
        tokio::io::stdout().write_all(&result.stdout).await?;
        tokio::io::stderr().write_all(&result.stderr).await?;
        return result
            .code
            .ok_or_else(|| anyhow!("remote command completed without an exit status"));
    }

    let master = ask_master()?;
    let result = exec_capture_with_timeout(profile, cmd, Some(&master), timeout).await?;
    tokio::io::stdout().write_all(&result.stdout).await?;
    tokio::io::stderr().write_all(&result.stderr).await?;
    result
        .code
        .ok_or_else(|| anyhow!("remote command completed without an exit status"))
}

/// Execute a command without touching process stdio. UI callers provide the
/// master passphrase only when no daemon is available.
pub async fn exec_capture(profile: &str, cmd: &str, master: Option<&str>) -> Result<CommandOutput> {
    exec_capture_with_timeout(
        profile,
        cmd,
        master,
        Duration::from_millis(ipc::DEFAULT_EXEC_TIMEOUT_MS),
    )
    .await
}

pub async fn exec_capture_with_timeout(
    profile: &str,
    cmd: &str,
    master: Option<&str>,
    timeout: Duration,
) -> Result<CommandOutput> {
    let timeout_ms = u64::try_from(timeout.as_millis())
        .ok()
        .filter(|value| (1..=ipc::MAX_EXEC_TIMEOUT_MS).contains(value))
        .ok_or_else(|| anyhow!("exec timeout is outside the supported range"))?;
    if let Some(daemon) = connect_daemon(profile).await? {
        let mut s = daemon.stream;
        ipc::write_frame(
            &mut s,
            &ipc::Frame::Exec {
                cmd: cmd.to_string(),
                timeout_ms,
            },
        )
        .await?;
        read_exec_response(&mut s).await
    } else {
        let master = master.ok_or_else(|| anyhow::anyhow!("master passphrase is required"))?;
        let creds = vault::decrypt(profile, master)?;
        let session = direct_connect(profile, &creds, master).await?;
        let r = session.exec_with_timeout(cmd, timeout).await?;
        Ok(CommandOutput {
            stdout: r.stdout,
            stderr: r.stderr,
            code: r.code,
        })
    }
}

async fn read_exec_response<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<CommandOutput> {
    let mut result = CommandOutput::default();
    loop {
        match ipc::read_frame(reader).await? {
            Some(ipc::Frame::ExecOut { data }) => {
                extend_command_output(&mut result.stdout, &data, result.stderr.len())?;
            }
            Some(ipc::Frame::ExecErr { data }) => {
                extend_command_output(&mut result.stderr, &data, result.stdout.len())?;
            }
            Some(ipc::Frame::ExecExit { code }) => {
                let code =
                    code.ok_or_else(|| anyhow!("remote command completed without an exit status"))?;
                result.code = Some(code);
                return Ok(result);
            }
            Some(ipc::Frame::Error { msg }) => bail!(msg),
            None => bail!("daemon disconnected before returning an exit status"),
            _ => {}
        }
    }
}

pub async fn status(profile: &str) -> Result<()> {
    if let Some(info) = daemon_status(profile).await? {
        let up = now_unix() - info.started_unix;
        println!(
            "daemon: ACTIVE  profile={}  {} as {}  uptime={up}s  ipc=127.0.0.1:{}",
            info.profile, info.host, info.user, info.port
        );
    } else {
        println!("daemon: not running for profile '{profile}'");
    }
    Ok(())
}

pub async fn daemon_status(profile: &str) -> Result<Option<DaemonStatus>> {
    if let Some(daemon) = connect_daemon(profile).await? {
        let port = daemon.lock.port;
        let mut s = daemon.stream;
        ipc::write_frame(&mut s, &ipc::Frame::Status).await?;
        match ipc::read_frame(&mut s).await? {
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
                port,
            })),
            _ => bail!("daemon responded with an unexpected frame"),
        }
    } else {
        Ok(None)
    }
}

pub async fn down(profile: &str) -> Result<()> {
    if down_quiet(profile).await? {
        println!("daemon stopped");
    } else {
        println!("no running daemon for '{profile}' (stale lock cleared)");
    }
    Ok(())
}

/// Stop a daemon without writing to stdout. Returns whether a live daemon was
/// contacted, which makes it suitable for both CLI and GUI frontends.
pub async fn down_quiet(profile: &str) -> Result<bool> {
    if let Some(daemon) = connect_daemon(profile).await? {
        let mut s = daemon.stream;
        ipc::write_frame(&mut s, &ipc::Frame::Shutdown).await?;
        match ipc::read_frame(&mut s).await? {
            Some(ipc::Frame::Ack) => {
                // Give an embedded daemon a chance to leave its accept loop and
                // remove the lock before the hosting UI drops its runtime.
                for _ in 0..20 {
                    if vault::read_lock(profile)?.is_none() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(true)
            }
            _ => bail!("daemon returned an unexpected response"),
        }
    } else {
        Ok(false)
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

pub async fn list_dir(
    profile: &str,
    path: &str,
    master: Option<&str>,
) -> Result<(String, Vec<RemoteEntry>)> {
    if let Some(daemon) = connect_daemon(profile).await? {
        let mut stream = daemon.stream;
        ipc::write_frame(
            &mut stream,
            &ipc::Frame::ListDir {
                path: path.to_owned(),
            },
        )
        .await?;
        return match ipc::read_frame(&mut stream).await? {
            Some(ipc::Frame::DirList { path, entries }) => Ok((path, entries)),
            Some(ipc::Frame::Error { msg }) => bail!(msg),
            _ => bail!("daemon returned an unexpected directory response"),
        };
    }

    let master = master.ok_or_else(|| anyhow!("master passphrase is required"))?;
    let creds = vault::decrypt(profile, master)?;
    direct_connect(profile, &creds, master)
        .await?
        .list_dir(path)
        .await
}

pub async fn create_dir(profile: &str, path: &str, master: Option<&str>) -> Result<()> {
    if let Some(daemon) = connect_daemon(profile).await? {
        let mut stream = daemon.stream;
        ipc::write_frame(
            &mut stream,
            &ipc::Frame::CreateDir {
                path: path.to_owned(),
            },
        )
        .await?;
        return match ipc::read_frame(&mut stream).await? {
            Some(ipc::Frame::Ack) => Ok(()),
            Some(ipc::Frame::Error { msg }) => bail!(msg),
            _ => bail!("daemon returned an unexpected create-directory response"),
        };
    }

    let master = master.ok_or_else(|| anyhow!("master passphrase is required"))?;
    let creds = vault::decrypt(profile, master)?;
    direct_connect(profile, &creds, master)
        .await?
        .create_dir(path)
        .await
}

pub async fn upload_file(
    profile: &str,
    local: &Path,
    remote: &str,
    master: Option<&str>,
) -> Result<u64> {
    let mut source = tokio::fs::File::open(local)
        .await
        .with_context(|| format!("open local file {}", local.display()))?;
    let size = source.metadata().await?.len();
    let mut buffer = vec![0_u8; 32 * 1024];

    if let Some(daemon) = connect_daemon(profile).await? {
        let mut stream = daemon.stream;
        ipc::write_frame(
            &mut stream,
            &ipc::Frame::UploadBegin {
                path: remote.to_owned(),
                size,
            },
        )
        .await?;
        match ipc::read_frame(&mut stream).await? {
            Some(ipc::Frame::Ack) => {}
            Some(ipc::Frame::Error { msg }) => bail!(msg),
            _ => bail!("daemon rejected the upload"),
        }
        loop {
            let read = source.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            ipc::write_frame(
                &mut stream,
                &ipc::Frame::UploadChunk {
                    data: buffer[..read].to_vec(),
                },
            )
            .await?;
        }
        ipc::write_frame(&mut stream, &ipc::Frame::UploadEnd).await?;
        return match ipc::read_frame(&mut stream).await? {
            Some(ipc::Frame::TransferDone { bytes }) if bytes == size => Ok(bytes),
            Some(ipc::Frame::TransferDone { bytes }) => {
                bail!("upload size mismatch: expected {size}, daemon stored {bytes}")
            }
            Some(ipc::Frame::Error { msg }) => bail!(msg),
            _ => bail!("daemon returned an unexpected upload response"),
        };
    }

    let master = master.ok_or_else(|| anyhow!("master passphrase is required"))?;
    let creds = vault::decrypt(profile, master)?;
    let session = direct_connect(profile, &creds, master).await?;
    let sftp = session.sftp().await?;
    if remote.is_empty() || remote.len() > 4096 {
        bail!("remote destination is empty or exceeds 4096 bytes");
    }
    if sftp.try_exists(remote).await? {
        bail!("remote destination already exists: {remote}");
    }
    let partial = temporary_remote_path(remote);
    let transfer: Result<u64> = async {
        let mut destination = sftp.create(&partial).await?;
        let mut transferred = 0_u64;
        loop {
            let read = source.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            destination.write_all(&buffer[..read]).await?;
            transferred += read as u64;
        }
        destination.flush().await?;
        drop(destination);
        if sftp.try_exists(remote).await? {
            bail!("remote destination was created during upload: {remote}");
        }
        sftp.rename(&partial, remote).await?;
        Ok(transferred)
    }
    .await;
    if transfer.is_err() {
        let _ = sftp.remove_file(&partial).await;
    }
    transfer
}

/// CLI upload entry point: reuse an authenticated daemon without prompting,
/// otherwise decrypt the profile for a direct SSH connection.
pub async fn upload(profile: &str, local: &Path, remote: &str) -> Result<u64> {
    if connect_daemon(profile).await?.is_some() {
        upload_file(profile, local, remote, None).await
    } else {
        let master = ask_master()?;
        upload_file(profile, local, remote, Some(&master)).await
    }
}

pub async fn download_file(
    profile: &str,
    remote: &str,
    local: &Path,
    master: Option<&str>,
) -> Result<u64> {
    if tokio::fs::try_exists(local).await? {
        bail!("local destination already exists: {}", local.display());
    }
    let partial = partial_download_path(local);
    let mut destination = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .await
        .with_context(|| format!("create temporary file {}", partial.display()))?;

    let transfer = async {
        let mut received = 0_u64;
        if let Some(daemon) = connect_daemon(profile).await? {
            let mut stream = daemon.stream;
            ipc::write_frame(
                &mut stream,
                &ipc::Frame::Download {
                    path: remote.to_owned(),
                },
            )
            .await?;
            loop {
                match ipc::read_frame(&mut stream).await? {
                    Some(ipc::Frame::FileChunk { data }) => {
                        destination.write_all(&data).await?;
                        received = received
                            .checked_add(data.len() as u64)
                            .ok_or_else(|| anyhow!("download size overflow"))?;
                    }
                    Some(ipc::Frame::TransferDone { bytes }) if bytes == received => {
                        break Ok(bytes);
                    }
                    Some(ipc::Frame::TransferDone { bytes }) => {
                        break Err(anyhow!(
                            "download size mismatch: daemon reported {bytes}, received {received}"
                        ))
                    }
                    Some(ipc::Frame::Error { msg }) => break Err(anyhow!(msg)),
                    None => break Err(anyhow!("daemon disconnected during download")),
                    _ => {}
                }
            }
        } else {
            let master = master.ok_or_else(|| anyhow!("master passphrase is required"))?;
            let creds = vault::decrypt(profile, master)?;
            let session = direct_connect(profile, &creds, master).await?;
            let sftp = session.sftp().await?;
            let mut source = sftp.open(remote).await?;
            let mut buffer = vec![0_u8; 32 * 1024];
            loop {
                let read = source.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                destination.write_all(&buffer[..read]).await?;
                received = received
                    .checked_add(read as u64)
                    .ok_or_else(|| anyhow!("download size overflow"))?;
            }
            Ok(received)
        }
    }
    .await;

    match transfer {
        Ok(bytes) => {
            let finalized: Result<()> = async {
                destination.flush().await?;
                destination.sync_all().await?;
                Ok(())
            }
            .await;
            drop(destination);
            if let Err(error) = finalized {
                let _ = tokio::fs::remove_file(&partial).await;
                return Err(error);
            }
            if let Err(error) = tokio::fs::rename(&partial, local).await {
                let _ = tokio::fs::remove_file(&partial).await;
                return Err(error.into());
            }
            Ok(bytes)
        }
        Err(error) => {
            drop(destination);
            let _ = tokio::fs::remove_file(&partial).await;
            Err(error)
        }
    }
}

/// CLI download entry point matching [`upload`].
pub async fn download(profile: &str, remote: &str, local: &Path) -> Result<u64> {
    if connect_daemon(profile).await?.is_some() {
        download_file(profile, remote, local, None).await
    } else {
        let master = ask_master()?;
        download_file(profile, remote, local, Some(&master)).await
    }
}

fn partial_download_path(local: &Path) -> PathBuf {
    let mut name = local.as_os_str().to_owned();
    name.push(".serctl-part");
    PathBuf::from(name)
}

pub async fn open_gui_shell(profile: &str, master: Option<&str>) -> Result<GuiShell> {
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(64);
    let (event_tx, event_rx) = mpsc::channel::<ShellEvent>(128);

    if let Some(daemon) = connect_daemon(profile).await? {
        let stream = daemon.stream;
        let (mut rd, mut wr) = tokio::io::split(stream);
        ipc::write_frame(
            &mut wr,
            &ipc::Frame::Shell {
                cols: 120,
                rows: 36,
            },
        )
        .await?;
        match ipc::read_frame(&mut rd).await? {
            Some(ipc::Frame::Ack) => {}
            Some(ipc::Frame::Error { msg }) => bail!(msg),
            _ => bail!("daemon returned an unexpected shell response"),
        }
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    input = input_rx.recv() => match input {
                        Some(data) => {
                            if ipc::write_frame(&mut wr, &ipc::Frame::ShellInput { data }).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                    frame = ipc::read_frame(&mut rd) => match frame {
                        Ok(Some(ipc::Frame::ShellOut { data })) => {
                            if event_tx.send(ShellEvent::Output(data)).await.is_err() {
                                break;
                            }
                        }
                        Ok(Some(ipc::Frame::Error { msg })) => {
                            let _ = event_tx.send(ShellEvent::Error(msg)).await;
                            break;
                        }
                        Ok(Some(ipc::Frame::ShellClosed)) | Ok(None) => break,
                        Ok(Some(_)) => {}
                        Err(e) => {
                            let _ = event_tx.send(ShellEvent::Error(e.to_string())).await;
                            break;
                        }
                    }
                }
            }
            let _ = event_tx.send(ShellEvent::Closed).await;
        });
    } else {
        let master = master.ok_or_else(|| anyhow!("master passphrase is required"))?;
        let creds = vault::decrypt(profile, master)?;
        let session = direct_connect(profile, &creds, master).await?;
        let mut channel = session.pty_shell("dumb", 120, 36).await?;
        let mut writer = channel.make_writer();
        tokio::spawn(async move {
            let _session = session;
            loop {
                tokio::select! {
                    input = input_rx.recv() => match input {
                        Some(data) => {
                            if writer.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                    message = channel.wait() => match message {
                        Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. })
                            if event_tx.send(ShellEvent::Output(data.to_vec())).await.is_err() => break,
                        Some(ChannelMsg::Data { .. }) | Some(ChannelMsg::ExtendedData { .. }) => {}
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    }
                }
            }
            let _ = event_tx.send(ShellEvent::Closed).await;
        });
    }

    Ok(GuiShell {
        input: input_tx,
        events: event_rx,
    })
}

fn spawn_stdin_pump() -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        while let Ok(ev) = crossterm::event::read() {
            if let Some(b) = key_to_bytes(&ev) {
                if !b.is_empty() && tx.blocking_send(b).is_err() {
                    break;
                }
            }
        }
    });
    rx
}

pub async fn shell(profile: &str) -> Result<()> {
    if let Some(daemon) = connect_daemon(profile).await? {
        shell_via_ipc(daemon.stream).await
    } else {
        let (creds, master) = ask_decrypt(profile)?;
        let session = direct_connect(profile, &creds, &master).await?;
        shell_direct(&session).await
    }
}

async fn shell_via_ipc(stream: TcpStream) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (cols, rows) = term_size();
    ipc::write_frame(&mut wr, &ipc::Frame::Shell { cols, rows }).await?;
    match ipc::read_frame(&mut rd).await? {
        Some(ipc::Frame::Ack) => {}
        Some(ipc::Frame::Error { msg }) => bail!(msg),
        _ => bail!("daemon returned unexpected response to Shell"),
    }

    enable_raw_mode()?;
    let res = shell_loop_ipc(&mut rd, &mut wr).await;
    let _ = disable_raw_mode();
    res
}

async fn shell_loop_ipc(
    rd: &mut tokio::io::ReadHalf<TcpStream>,
    wr: &mut tokio::io::WriteHalf<TcpStream>,
) -> Result<()> {
    let mut kbrx = spawn_stdin_pump();
    let mut out = tokio::io::stdout();
    loop {
        tokio::select! {
            key = kbrx.recv() => match key {
                Some(b) => {
                    if ipc::write_frame(wr, &ipc::Frame::ShellInput { data: b }).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            fr = ipc::read_frame(rd) => match fr? {
                Some(ipc::Frame::ShellOut { data }) => {
                    let _ = out.write_all(&data).await;
                    let _ = out.flush().await;
                }
                Some(ipc::Frame::ShellClosed) | None => break,
                Some(_) => {}
            },
        }
    }
    Ok(())
}

async fn shell_direct(session: &SshSession) -> Result<()> {
    let (cols, rows) = term_size();
    let mut ch = session.pty_shell("xterm-256color", cols, rows).await?;
    let mut writer = ch.make_writer();
    enable_raw_mode()?;
    let mut kbrx = spawn_stdin_pump();
    let mut out = tokio::io::stdout();
    let result: Result<()> = async {
        loop {
            tokio::select! {
                key = kbrx.recv() => match key {
                    Some(b) => {
                        if writer.write_all(&b).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                msg = ch.wait() => match msg {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        let _ = out.write_all(&data).await;
                        let _ = out.flush().await;
                    }
                    Some(ChannelMsg::Eof) | None => break,
                    _ => {}
                },
            }
        }
        Ok(())
    }
    .await;
    let _ = disable_raw_mode();
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
    use super::read_exec_response;
    use crate::ipc::{self, Frame};

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
}
