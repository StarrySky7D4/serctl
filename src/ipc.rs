//! Length-prefixed JSON framing for the daemon IPC protocol (127.0.0.1 only).
use anyhow::{bail, Result};
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
