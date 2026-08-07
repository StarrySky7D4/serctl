//! russh client wrapper: connect with password auth, exec commands, open PTY shells.
use anyhow::{bail, Result};
use rand::{rngs::OsRng, RngCore};
use russh::{client, keys::ssh_key, ChannelMsg};
use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::vault::Creds;

const MAX_COMMAND_OUTPUT: usize = crate::ipc::MAX_COMMAND_OUTPUT;

pub fn temporary_remote_path(path: &str) -> String {
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    format!("{path}.serctl-part-{}", hex::encode(random))
}

pub struct SshHandler {
    expect: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
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
}

pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<i32>,
}

pub struct RunningCommand {
    channel: russh::Channel<russh::client::Msg>,
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

impl SshSession {
    /// Connect + authenticate. Returns the session and the server key fingerprint
    /// (caller pins it into the vault on first contact).
    pub async fn connect(creds: &Creds, expect: Option<String>) -> Result<(SshSession, String)> {
        let seen = Arc::new(Mutex::new(None));
        let cfg = Arc::new(client::Config::default());
        let handler = SshHandler {
            expect: expect.clone(),
            seen: seen.clone(),
        };
        let mut handle = client::connect(cfg, (creds.host.as_str(), creds.port), handler).await?;
        let authed = handle
            .authenticate_password(&creds.user, &creds.password)
            .await?;
        if !matches!(authed, client::AuthResult::Success) {
            bail!("authentication failed for user '{}'", creds.user);
        }
        let fp = seen.lock().unwrap().clone().unwrap_or_default();
        Ok((SshSession { handle }, fp))
    }

    pub async fn start_exec(&self, cmd: &str) -> Result<RunningCommand> {
        let ch = self.handle.channel_open_session().await?;
        ch.exec(true, cmd.to_string()).await?;
        Ok(RunningCommand { channel: ch })
    }

    pub async fn exec_with_timeout(
        &self,
        cmd: &str,
        timeout: std::time::Duration,
    ) -> Result<ExecResult> {
        let mut command = self.start_exec(cmd).await?;
        match tokio::time::timeout(timeout, command.finish()).await {
            Ok(result) => result,
            Err(_) => {
                command.cancel().await;
                bail!(
                    "remote command exceeded its deadline of {} ms",
                    timeout.as_millis()
                );
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

    /// Open an SFTP subsystem over a fresh channel on this SSH connection.
    pub async fn sftp(&self) -> Result<SftpSession> {
        let channel = self.handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        Ok(SftpSession::new(channel.into_stream()).await?)
    }

    pub async fn list_dir(&self, path: &str) -> Result<(String, Vec<RemoteEntry>)> {
        let sftp = self.sftp().await?;
        let canonical = sftp.canonicalize(path).await?;
        let mut entries = sftp
            .read_dir(&canonical)
            .await?
            .map(|entry| {
                let metadata = entry.metadata();
                let file_type = entry.file_type();
                RemoteEntry {
                    name: entry.file_name(),
                    path: entry.path(),
                    is_dir: file_type.is_dir(),
                    is_symlink: file_type.is_symlink(),
                    size: metadata.len(),
                    modified_unix: metadata.mtime,
                }
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok((canonical, entries))
    }

    pub async fn create_dir(&self, path: &str) -> Result<()> {
        self.sftp().await?.create_dir(path).await?;
        Ok(())
    }
}

impl RunningCommand {
    pub async fn finish(&mut self) -> Result<ExecResult> {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut code = None;
        while let Some(msg) = self.channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => extend_command_output(&mut out, data, err.len())?,
                ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    extend_command_output(&mut err, data, out.len())?
                }
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status as i32),
                ChannelMsg::Eof | ChannelMsg::Close => {}
                _ => {}
            }
        }
        let code =
            code.ok_or_else(|| anyhow::anyhow!("remote command closed without exit status"))?;
        Ok(ExecResult {
            stdout: out,
            stderr: err,
            code: Some(code),
        })
    }

    pub async fn cancel(&mut self) {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let _ = self.channel.eof().await;
            let _ = self.channel.close().await;
        })
        .await;
    }
}

fn extend_command_output(target: &mut Vec<u8>, data: &[u8], other_len: usize) -> Result<()> {
    let total = target
        .len()
        .checked_add(other_len)
        .and_then(|size| size.checked_add(data.len()))
        .ok_or_else(|| anyhow::anyhow!("remote command output size overflow"))?;
    if total > MAX_COMMAND_OUTPUT {
        bail!("remote command output exceeds the 8 MiB safety limit");
    }
    target.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{extend_command_output, temporary_remote_path};

    #[test]
    fn command_output_is_bounded_across_stdout_and_stderr() {
        let mut output = Vec::new();
        assert!(extend_command_output(&mut output, b"ok", 0).is_ok());
        assert!(extend_command_output(&mut output, b"x", 8 * 1024 * 1024).is_err());
    }

    #[test]
    fn temporary_remote_names_are_sibling_paths() {
        let path = temporary_remote_path("/srv/data/file.txt");
        assert!(path.starts_with("/srv/data/file.txt.serctl-part-"));
        assert!(!path["/srv/data/file.txt.serctl-part-".len()..].contains('/'));
    }
}
