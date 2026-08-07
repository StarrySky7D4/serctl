//! Daemon: loads a profile, holds one long-lived SSH session, serves IPC.
use crate::vault::{self, now_unix, Creds, LockInfo};
use anyhow::{bail, Result};
use fs2::FileExt;
use russh::ChannelMsg;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{watch, Semaphore};
use zeroize::Zeroizing;

use crate::ipc;
use crate::ssh::{temporary_remote_path, SshSession};

#[derive(Clone)]
struct ConnInfo {
    profile: String,
    host: String,
    user: String,
    started: i64,
    token: String,
}

struct RuntimeLockGuard {
    profile: String,
    token: String,
    _lease: std::fs::File,
}

impl Drop for RuntimeLockGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self._lease);
        let _ = vault::remove_lock_if_token(&self.profile, &self.token);
    }
}

pub async fn run(profile: &str, creds: Creds, master: String) -> Result<()> {
    run_with_ready(profile, creds, master, None).await
}

/// Run a daemon and optionally notify an embedding UI once the IPC listener is
/// ready. Shutdown is coordinated through the async loop, so an in-process
/// daemon never terminates the whole GUI process.
pub async fn run_with_ready(
    profile: &str,
    creds: Creds,
    master: String,
    ready: Option<std::sync::mpsc::Sender<()>>,
) -> Result<()> {
    let lease = vault::acquire_runtime_lease(profile)?;
    if let Some(existing) = vault::read_lock(profile)? {
        if existing.token.is_empty() {
            bail!("a legacy daemon lock exists for '{profile}'; stop the old daemon first");
        }
        if existing.endpoint.is_empty() {
            bail!("a legacy TCP daemon lock exists for '{profile}'; restart it first");
        }
        if existing_daemon_is_live(&existing).await {
            bail!("a daemon is already running for '{profile}'");
        }
    }
    let master = Zeroizing::new(master);
    let expect = creds.host_key.clone();
    let (session, fp) = SshSession::connect(&creds, expect).await?;
    if creds.host_key.is_none() && !fp.is_empty() {
        vault::set_pinned_fp(profile, fp.clone(), &master)?;
        eprintln!("[serctl] pinned host key {fp}");
    }
    let session = Arc::new(session);

    let token = vault::new_ipc_token();
    let mut listener = ipc::LocalListener::bind(profile, &token)?;
    let endpoint = listener.endpoint().to_owned();
    vault::write_lock(&LockInfo {
        profile: profile.to_string(),
        pid: std::process::id(),
        port: 0,
        endpoint: endpoint.clone(),
        // Endpoint/user data is returned only after authentication. Keeping
        // it out of the runtime lock reduces plaintext metadata exposure.
        host: String::new(),
        user: String::new(),
        started_unix: now_unix(),
        token: token.clone(),
    })?;
    let _lock_guard = RuntimeLockGuard {
        profile: profile.to_owned(),
        token: token.clone(),
        _lease: lease,
    };
    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    eprintln!(
        "[serctl] daemon up: profile={profile}  {host}:{ssh} as {user}  ipc={kind}:{endpoint}  (Ctrl-C to stop)",
        host = creds.host,
        ssh = creds.port,
        user = creds.user,
        kind = ipc::endpoint_kind(),
    );

    let info = ConnInfo {
        profile: profile.to_string(),
        host: creds.host.clone(),
        user: creds.user.clone(),
        started: now_unix(),
        token,
    };
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let connection_slots = Arc::new(Semaphore::new(64));

    loop {
        tokio::select! {
            res = listener.accept() => {
                let stream = res?;
                let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
                    log::warn!("rejecting IPC connection: connection limit reached");
                    continue;
                };
                log::debug!("local IPC connection accepted");
                let s = session.clone();
                let i = info.clone();
                let shutdown = shutdown_tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_conn(s, stream, i, shutdown).await {
                        log::warn!("ipc handler: {e:#}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[serctl] shutting down");
                break;
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    eprintln!("[serctl] shutdown requested");
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn existing_daemon_is_live(lock: &LockInfo) -> bool {
    let probe = async {
        let mut stream = ipc::connect(&lock.endpoint).await?;
        ipc::write_frame(
            &mut stream,
            &ipc::Frame::Authenticate {
                token: lock.token.clone(),
            },
        )
        .await?;
        Ok::<bool, anyhow::Error>(matches!(
            ipc::read_frame_limited(&mut stream, ipc::MAX_AUTH_FRAME).await?,
            Some(ipc::Frame::Ack)
        ))
    };
    matches!(
        tokio::time::timeout(std::time::Duration::from_millis(800), probe).await,
        Ok(Ok(true))
    )
}

async fn handle_conn<S>(
    session: Arc<SshSession>,
    stream: S,
    info: ConnInfo,
    shutdown: watch::Sender<bool>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let authentication = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ipc::read_frame_limited(&mut rd, ipc::MAX_AUTH_FRAME),
    )
    .await
    .map_err(|_| anyhow::anyhow!("IPC authentication timed out"))??;
    match authentication {
        Some(ipc::Frame::Authenticate { token }) if constant_time_token_eq(&token, &info.token) => {
            ipc::write_frame(&mut wr, &ipc::Frame::Ack).await?;
        }
        _ => {
            ipc::write_frame(
                &mut wr,
                &ipc::Frame::Error {
                    msg: "IPC authentication failed".into(),
                },
            )
            .await?;
            return Ok(());
        }
    }
    while let Some(frame) = ipc::read_frame(&mut rd).await? {
        match frame {
            ipc::Frame::Exec { cmd, timeout_ms } => {
                let timeout = match validated_exec_timeout(timeout_ms) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        ipc::write_frame(
                            &mut wr,
                            &ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                        )
                        .await?;
                        continue;
                    }
                };
                let mut command = match session.start_exec(&cmd).await {
                    Ok(command) => command,
                    Err(error) => {
                        ipc::write_frame(
                            &mut wr,
                            &ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                        )
                        .await?;
                        continue;
                    }
                };
                tokio::select! {
                    result = command.finish() => match result {
                        Ok(result) => {
                            ipc::write_frame(&mut wr, &ipc::Frame::ExecOut { data: result.stdout }).await?;
                            ipc::write_frame(&mut wr, &ipc::Frame::ExecErr { data: result.stderr }).await?;
                            ipc::write_frame(&mut wr, &ipc::Frame::ExecExit { code: result.code }).await?;
                        }
                        Err(error) => {
                            ipc::write_frame(&mut wr, &ipc::Frame::Error { msg: error.to_string() }).await?;
                        }
                    },
                    _ = tokio::time::sleep(timeout) => {
                        command.cancel().await;
                        ipc::write_frame(
                            &mut wr,
                            &ipc::Frame::Error {
                                msg: format!("remote command exceeded its deadline of {} ms", timeout.as_millis()),
                            },
                        ).await?;
                    }
                    _ = rd.read_u8() => {
                        command.cancel().await;
                        return Ok(());
                    }
                }
            }
            ipc::Frame::Shell { cols, rows } => {
                match session.pty_shell("xterm-256color", cols, rows).await {
                    Ok(mut ch) => {
                        let mut writer = ch.make_writer();
                        ipc::write_frame(&mut wr, &ipc::Frame::Ack).await?;
                        loop {
                            tokio::select! {
                                msg = ch.wait() => match msg {
                                    Some(ChannelMsg::Data { data })
                                        if ipc::write_frame(&mut wr, &ipc::Frame::ShellOut { data: data.to_vec() }).await.is_err() => break,
                                    Some(ChannelMsg::Data { .. }) => {}
                                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                                        let _ = ipc::write_frame(&mut wr, &ipc::Frame::ShellOut { data: data.to_vec() }).await;
                                    }
                                    Some(ChannelMsg::Eof) | None => {
                                        let _ = ipc::write_frame(&mut wr, &ipc::Frame::ShellClosed).await;
                                        break;
                                    }
                                    _ => {}
                                },
                                frame = ipc::read_frame(&mut rd) => match frame? {
                                    Some(ipc::Frame::ShellInput { data }) => {
                                        if writer.write_all(&data).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(_) => {}
                                    None => break,
                                },
                            }
                        }
                    }
                    Err(e) => {
                        ipc::write_frame(&mut wr, &ipc::Frame::Error { msg: e.to_string() })
                            .await?;
                    }
                }
            }
            ipc::Frame::Status => {
                ipc::write_frame(
                    &mut wr,
                    &ipc::Frame::StatusInfo {
                        profile: info.profile.clone(),
                        host: info.host.clone(),
                        user: info.user.clone(),
                        started_unix: info.started,
                    },
                )
                .await?;
            }
            ipc::Frame::ListDir { path, timeout_ms } => {
                let result = run_sftp_deadline(timeout_ms, session.list_dir(&path)).await;
                match result {
                    Ok((path, entries)) => {
                        ipc::write_frame(&mut wr, &ipc::Frame::DirList { path, entries }).await?;
                    }
                    Err(error) => {
                        ipc::write_frame(
                            &mut wr,
                            &ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                        )
                        .await?;
                    }
                }
            }
            ipc::Frame::CreateDir { path, timeout_ms } => {
                let result = run_sftp_deadline(timeout_ms, session.create_dir(&path)).await;
                match result {
                    Ok(()) => ipc::write_frame(&mut wr, &ipc::Frame::Ack).await?,
                    Err(error) => {
                        ipc::write_frame(
                            &mut wr,
                            &ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                        )
                        .await?;
                    }
                }
            }
            ipc::Frame::Download { path, timeout_ms } => {
                if let Err(error) = serve_download(&session, &mut wr, &path, timeout_ms).await {
                    ipc::write_frame(
                        &mut wr,
                        &ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                    )
                    .await?;
                }
            }
            ipc::Frame::UploadBegin {
                path,
                size,
                timeout_ms,
            } => {
                if let Err(error) =
                    serve_upload(&session, &mut rd, &mut wr, &path, size, timeout_ms).await
                {
                    ipc::write_frame(
                        &mut wr,
                        &ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                    )
                    .await?;
                }
            }
            ipc::Frame::Shutdown => {
                ipc::write_frame(&mut wr, &ipc::Frame::Ack).await?;
                let _ = shutdown.send(true);
                break;
            }
            _ => {
                ipc::write_frame(
                    &mut wr,
                    &ipc::Frame::Error {
                        msg: "unexpected frame".into(),
                    },
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn run_sftp_deadline<T>(
    timeout_ms: u64,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let timeout = validated_sftp_timeout(timeout_ms)?;
    match tokio::time::timeout(timeout, operation).await {
        Ok(result) => result,
        Err(_) => bail!("SFTP operation exceeded its deadline of {timeout_ms} ms"),
    }
}

async fn serve_download<W>(
    session: &SshSession,
    writer: &mut W,
    path: &str,
    timeout_ms: u64,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let timeout = validated_sftp_timeout(timeout_ms)?;
    let operation = async {
        let sftp = session.sftp().await?;
        let mut file = sftp.open(path).await?;
        let mut transferred = 0_u64;
        let mut buffer = vec![0_u8; 32 * 1024];
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                ipc::write_frame(writer, &ipc::Frame::TransferDone { bytes: transferred }).await?;
                return Ok(());
            }
            transferred = transferred
                .checked_add(read as u64)
                .ok_or_else(|| anyhow::anyhow!("download size overflow"))?;
            ipc::write_frame(
                writer,
                &ipc::Frame::FileChunk {
                    data: buffer[..read].to_vec(),
                },
            )
            .await?;
        }
    };
    match tokio::time::timeout(timeout, operation).await {
        Ok(result) => result,
        Err(_) => bail!("SFTP download exceeded its deadline of {timeout_ms} ms"),
    }
}

async fn serve_upload<R, W>(
    session: &SshSession,
    reader: &mut R,
    writer: &mut W,
    path: &str,
    size: u64,
    timeout_ms: u64,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let timeout = validated_sftp_timeout(timeout_ms)?;
    let deadline = tokio::time::Instant::now() + timeout;
    let sftp = match tokio::time::timeout_at(deadline, session.sftp()).await {
        Ok(result) => result?,
        Err(_) => bail!("SFTP upload exceeded its deadline of {timeout_ms} ms"),
    };
    let partial = temporary_remote_path(path);
    let operation: Result<()> = match tokio::time::timeout_at(deadline, async {
        if path.is_empty() || path.len() > 4096 {
            bail!("remote destination is empty or exceeds 4096 bytes");
        }
        if sftp.try_exists(path).await? {
            bail!("remote destination already exists: {path}");
        }
        if sftp.try_exists(&partial).await? {
            bail!("temporary remote destination unexpectedly exists");
        }
        let mut file = sftp.create(&partial).await?;
        ipc::write_frame(writer, &ipc::Frame::Ack).await?;
        let mut transferred = 0_u64;
        let mut failed = None;
        loop {
            match ipc::read_frame(reader).await {
                Ok(Some(ipc::Frame::UploadChunk { data })) => {
                    if failed.is_none() {
                        let next = transferred.checked_add(data.len() as u64);
                        if next.is_none() || next.is_some_and(|value| value > size) {
                            failed = Some("upload exceeded its declared size".to_owned());
                        } else if let Err(error) = file.write_all(&data).await {
                            // Drain until UploadEnd so sender and receiver cannot
                            // deadlock while the deadline is still active.
                            failed = Some(error.to_string());
                        } else if let Some(next) = next {
                            transferred = next;
                        }
                    }
                }
                Ok(Some(ipc::Frame::UploadEnd)) => {
                    if transferred != size {
                        failed = Some(format!(
                            "upload size mismatch: expected {size}, received {transferred}"
                        ));
                    } else if let Err(error) = file.flush().await {
                        failed = Some(error.to_string());
                    }
                    break;
                }
                Ok(Some(_)) => {
                    failed = Some("unexpected frame during upload".into());
                    break;
                }
                Ok(None) => {
                    failed = Some("client disconnected during upload".into());
                    break;
                }
                Err(error) => {
                    failed = Some(error.to_string());
                    break;
                }
            }
        }
        drop(file);
        if failed.is_none() && sftp.try_exists(path).await? {
            failed = Some(format!(
                "remote destination was created during upload: {path}"
            ));
        }
        if let Some(message) = failed {
            bail!(message);
        }
        sftp.rename(&partial, path).await?;
        ipc::write_frame(writer, &ipc::Frame::TransferDone { bytes: transferred }).await?;
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "SFTP upload exceeded its deadline of {timeout_ms} ms"
        )),
    };

    if operation.is_err() {
        let _ = tokio::time::timeout(Duration::from_secs(2), sftp.remove_file(&partial)).await;
    }
    operation
}

fn constant_time_token_eq(actual: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    actual.as_bytes().ct_eq(expected.as_bytes()).into()
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
    use super::{constant_time_token_eq, validated_exec_timeout, validated_sftp_timeout};

    #[test]
    fn ipc_tokens_require_an_exact_match() {
        assert!(constant_time_token_eq("same-token", "same-token"));
        assert!(!constant_time_token_eq("same-tokeN", "same-token"));
        assert!(!constant_time_token_eq("short", "same-token"));
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
}
