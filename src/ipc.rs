//! Authenticated local IPC with one framing protocol over Windows named pipes
//! or Unix domain sockets.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::ssh::RemoteEntry;

const MAX_FRAME: usize = 64 * 1024 * 1024;
pub const MAX_AUTH_FRAME: usize = 4 * 1024;
pub const MAX_COMMAND_OUTPUT: usize = 8 * 1024 * 1024;
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 5 * 60 * 1000;
pub const MAX_EXEC_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_SFTP_TIMEOUT_MS: u64 = 5 * 60 * 1000;
pub const MAX_SFTP_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

fn default_exec_timeout_ms() -> u64 {
    DEFAULT_EXEC_TIMEOUT_MS
}

fn default_sftp_timeout_ms() -> u64 {
    DEFAULT_SFTP_TIMEOUT_MS
}

fn endpoint_id(profile: &str, token: &str) -> String {
    use sha2::{Digest, Sha256};
    // 128 bits keeps the platform endpoint compact (Unix socket paths have a
    // small OS-defined limit) while the full 256-bit capability is still
    // required by the framing protocol.
    hex::encode(Sha256::digest(format!("{profile}\0{token}").as_bytes()))[..32].to_owned()
}

#[cfg(windows)]
pub type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(unix)]
pub type ClientStream = tokio::net::UnixStream;

#[cfg(windows)]
pub struct LocalListener {
    endpoint: String,
    pending: tokio::net::windows::named_pipe::NamedPipeServer,
}

#[cfg(unix)]
pub struct LocalListener {
    endpoint: String,
    listener: tokio::net::UnixListener,
}

#[cfg(windows)]
impl LocalListener {
    pub fn bind(profile: &str, token: &str) -> Result<Self> {
        use tokio::net::windows::named_pipe::ServerOptions;

        let endpoint = format!(r"\\.\pipe\serctl-{}", endpoint_id(profile, token));
        let pending = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&endpoint)
            .with_context(|| format!("create named pipe {endpoint}"))?;
        Ok(Self { endpoint, pending })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn accept(&mut self) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        use tokio::net::windows::named_pipe::ServerOptions;

        self.pending.connect().await?;
        let next = ServerOptions::new()
            .reject_remote_clients(true)
            .create(&self.endpoint)
            .with_context(|| format!("create next named pipe instance {}", self.endpoint))?;
        Ok(std::mem::replace(&mut self.pending, next))
    }
}

#[cfg(unix)]
impl LocalListener {
    pub fn bind(profile: &str, token: &str) -> Result<Self> {
        let endpoint = crate::vault::run_dir()?
            .join(format!("{}.sock", endpoint_id(profile, token)))
            .to_string_lossy()
            .into_owned();
        let path = std::path::Path::new(&endpoint);
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove stale Unix socket"),
        }
        let listener = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("bind Unix socket {endpoint}"))?;
        crate::security::harden_file(path)?;
        Ok(Self { endpoint, listener })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn accept(&mut self) -> Result<tokio::net::UnixStream> {
        Ok(self.listener.accept().await?.0)
    }
}

#[cfg(unix)]
impl Drop for LocalListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.endpoint);
    }
}

#[cfg(windows)]
pub async fn connect(endpoint: &str) -> Result<ClientStream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};

    loop {
        match ClientOptions::new().open(endpoint) {
            Ok(client) => return Ok(client),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(code)
                        if code == ERROR_PIPE_BUSY as i32 || code == ERROR_FILE_NOT_FOUND as i32
                ) =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error).with_context(|| format!("open named pipe {endpoint}")),
        }
    }
}

#[cfg(unix)]
pub async fn connect(endpoint: &str) -> Result<ClientStream> {
    tokio::net::UnixStream::connect(endpoint)
        .await
        .with_context(|| format!("connect Unix socket {endpoint}"))
}

pub fn endpoint_kind() -> &'static str {
    #[cfg(windows)]
    return "named-pipe";
    #[cfg(unix)]
    return "unix-socket";
    #[allow(unreachable_code)]
    "unsupported"
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "t", content = "d")]
pub enum Frame {
    // client -> daemon
    Authenticate {
        token: String,
    },
    Exec {
        cmd: String,
        #[serde(default = "default_exec_timeout_ms")]
        timeout_ms: u64,
    },
    Shell {
        cols: u32,
        rows: u32,
    },
    ShellInput {
        data: Vec<u8>,
    },
    Status,
    Shutdown,
    ListDir {
        path: String,
        #[serde(default = "default_sftp_timeout_ms")]
        timeout_ms: u64,
    },
    CreateDir {
        path: String,
        #[serde(default = "default_sftp_timeout_ms")]
        timeout_ms: u64,
    },
    Download {
        path: String,
        #[serde(default = "default_sftp_timeout_ms")]
        timeout_ms: u64,
    },
    UploadBegin {
        path: String,
        size: u64,
        #[serde(default = "default_sftp_timeout_ms")]
        timeout_ms: u64,
    },
    UploadChunk {
        data: Vec<u8>,
    },
    UploadEnd,
    // daemon -> client
    ExecOut {
        data: Vec<u8>,
    },
    ExecErr {
        data: Vec<u8>,
    },
    ExecExit {
        code: Option<i32>,
    },
    ShellOut {
        data: Vec<u8>,
    },
    ShellClosed,
    StatusInfo {
        profile: String,
        host: String,
        user: String,
        started_unix: i64,
    },
    Ack,
    DirList {
        path: String,
        entries: Vec<RemoteEntry>,
    },
    FileChunk {
        data: Vec<u8>,
    },
    TransferDone {
        bytes: u64,
    },
    Error {
        msg: String,
    },
}

pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, f: &Frame) -> Result<()> {
    let json = serde_json::to_vec(f)?;
    if json.len() > MAX_FRAME {
        bail!("frame too large: {} bytes", json.len());
    }
    let len = (json.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&json).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Option<Frame>> {
    read_frame_limited(r, MAX_FRAME).await
}

pub async fn read_frame_limited<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max_frame: usize,
) -> Result<Option<Frame>> {
    let mut lenbuf = [0u8; 4];
    match r.read_exact(&mut lenbuf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(lenbuf) as usize;
    if len > max_frame {
        bail!("frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(serde_json::from_slice(&buf)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authentication_frame_round_trips() {
        let (mut tx, mut rx) = tokio::io::duplex(1024);
        write_frame(
            &mut tx,
            &Frame::Authenticate {
                token: "capability-token".into(),
            },
        )
        .await
        .unwrap();

        match read_frame(&mut rx).await.unwrap() {
            Some(Frame::Authenticate { token }) => assert_eq!(token, "capability-token"),
            _ => panic!("authentication frame did not round-trip"),
        }
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_payload_allocation() {
        let header = ((MAX_FRAME + 1) as u32).to_be_bytes();
        let mut bytes = header.as_slice();
        assert!(read_frame(&mut bytes).await.is_err());
    }

    #[tokio::test]
    async fn authentication_limit_is_smaller_than_data_limit() {
        let header = ((MAX_AUTH_FRAME + 1) as u32).to_be_bytes();
        let mut bytes = header.as_slice();
        assert!(read_frame_limited(&mut bytes, MAX_AUTH_FRAME)
            .await
            .is_err());
    }
}
