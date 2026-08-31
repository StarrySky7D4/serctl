//! Bounded, versioned binary framing for `serctl-xfer serve --stdio`.
//! Control messages are bounded JSON; file data is carried as raw bytes.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: [u8; 4] = *b"SRXF";
pub const VERSION: u16 = 1;
pub const MAX_CONTROL_BYTES: usize = 64 * 1024;
pub const MAX_CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = MAX_CHUNK_BYTES + 64;
pub const DEFAULT_CHUNK_BYTES: u32 = 256 * 1024;
pub const DEFAULT_WINDOW_BYTES: u32 = 8 * 1024 * 1024;
pub const MAX_WINDOW_BYTES: u32 = 8 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 4 * 1024;
pub const MAX_ERROR_CODE_BYTES: usize = 64;

fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_transfer_id(value: &str) -> Result<()> {
    ensure!(
        is_lower_hex(value, 16),
        "native transfer id must contain 32 lowercase hex characters"
    );
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    ensure!(
        is_lower_hex(value, 32),
        "{label} must contain 64 lowercase hex characters"
    );
    Ok(())
}

fn validate_path(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_PATH_BYTES && !value.contains('\0'),
        "invalid native transfer {label}"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Control = 1,
    Data = 2,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Control {
    Hello {
        version: u16,
        max_chunk: u32,
        max_window: u32,
        resume: bool,
        sha256: bool,
        fsync: bool,
        no_replace: bool,
    },
    BeginPush {
        transfer_id: String,
        target: String,
        size: u64,
        sha256: String,
        /// Hex-encoded 32-byte ownership secret. The helper persists only its
        /// SHA-256 hash in the protected sidecar.
        resume_token: String,
        resume: bool,
    },
    BeginPull {
        transfer_id: String,
        source: String,
        offset: u64,
    },
    Ready {
        chunk: u32,
        window: u32,
        durable_offset: u64,
    },
    PullReady {
        chunk: u32,
        window: u32,
        size: u64,
        sha256: String,
        start_offset: u64,
    },
    Ack {
        confirmed_offset: u64,
        durable_offset: u64,
        receiver_window: u32,
    },
    Commit,
    Completed {
        size: u64,
        sha256: String,
    },
    Cancel,
    Error {
        code: String,
        message: String,
        outcome_unknown: bool,
    },
}

impl fmt::Debug for Control {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello {
                version,
                max_chunk,
                max_window,
                resume,
                sha256,
                fsync,
                no_replace,
            } => formatter
                .debug_struct("Hello")
                .field("version", version)
                .field("max_chunk", max_chunk)
                .field("max_window", max_window)
                .field("resume", resume)
                .field("sha256", sha256)
                .field("fsync", fsync)
                .field("no_replace", no_replace)
                .finish(),
            Self::BeginPush {
                transfer_id,
                target,
                size,
                sha256,
                resume: can_resume,
                ..
            } => formatter
                .debug_struct("BeginPush")
                .field("transfer_id", transfer_id)
                .field("target", target)
                .field("size", size)
                .field("sha256", sha256)
                .field("resume_token", &"[REDACTED]")
                .field("resume", can_resume)
                .finish(),
            Self::BeginPull {
                transfer_id,
                source,
                offset,
            } => formatter
                .debug_struct("BeginPull")
                .field("transfer_id", transfer_id)
                .field("source", source)
                .field("offset", offset)
                .finish(),
            Self::Ready {
                chunk,
                window,
                durable_offset,
            } => formatter
                .debug_struct("Ready")
                .field("chunk", chunk)
                .field("window", window)
                .field("durable_offset", durable_offset)
                .finish(),
            Self::PullReady {
                chunk,
                window,
                size,
                sha256,
                start_offset,
            } => formatter
                .debug_struct("PullReady")
                .field("chunk", chunk)
                .field("window", window)
                .field("size", size)
                .field("sha256", sha256)
                .field("start_offset", start_offset)
                .finish(),
            Self::Ack {
                confirmed_offset,
                durable_offset,
                receiver_window,
            } => formatter
                .debug_struct("Ack")
                .field("confirmed_offset", confirmed_offset)
                .field("durable_offset", durable_offset)
                .field("receiver_window", receiver_window)
                .finish(),
            Self::Commit => formatter.write_str("Commit"),
            Self::Completed { size, sha256 } => formatter
                .debug_struct("Completed")
                .field("size", size)
                .field("sha256", sha256)
                .finish(),
            Self::Cancel => formatter.write_str("Cancel"),
            Self::Error {
                code,
                message,
                outcome_unknown,
            } => formatter
                .debug_struct("Error")
                .field("code", code)
                .field("message", message)
                .field("outcome_unknown", outcome_unknown)
                .finish(),
        }
    }
}

impl Zeroize for Control {
    fn zeroize(&mut self) {
        match self {
            Self::Hello {
                version,
                max_chunk,
                max_window,
                resume,
                sha256,
                fsync,
                no_replace,
            } => {
                version.zeroize();
                max_chunk.zeroize();
                max_window.zeroize();
                resume.zeroize();
                sha256.zeroize();
                fsync.zeroize();
                no_replace.zeroize();
            }
            Self::BeginPush {
                transfer_id,
                target,
                size,
                sha256,
                resume_token,
                resume,
            } => {
                transfer_id.zeroize();
                target.zeroize();
                size.zeroize();
                sha256.zeroize();
                resume_token.zeroize();
                resume.zeroize();
            }
            Self::BeginPull {
                transfer_id,
                source,
                offset,
            } => {
                transfer_id.zeroize();
                source.zeroize();
                offset.zeroize();
            }
            Self::Ready {
                chunk,
                window,
                durable_offset,
            } => {
                chunk.zeroize();
                window.zeroize();
                durable_offset.zeroize();
            }
            Self::PullReady {
                chunk,
                window,
                size,
                sha256,
                start_offset,
            } => {
                chunk.zeroize();
                window.zeroize();
                size.zeroize();
                sha256.zeroize();
                start_offset.zeroize();
            }
            Self::Ack {
                confirmed_offset,
                durable_offset,
                receiver_window,
            } => {
                confirmed_offset.zeroize();
                durable_offset.zeroize();
                receiver_window.zeroize();
            }
            Self::Commit | Self::Cancel => {}
            Self::Completed { size, sha256 } => {
                size.zeroize();
                sha256.zeroize();
            }
            Self::Error {
                code,
                message,
                outcome_unknown,
            } => {
                code.zeroize();
                message.zeroize();
                outcome_unknown.zeroize();
            }
        }
    }
}

impl Control {
    /// Validate all context-free control-frame invariants at the wire boundary.
    /// State-dependent checks (expected offset, transfer id, and negotiated
    /// direction) remain the responsibility of the session state machine.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Hello {
                version,
                max_chunk,
                max_window,
                ..
            } => {
                ensure!(
                    *version == VERSION,
                    "native transfer hello version mismatch"
                );
                ensure!(
                    (1..=MAX_CHUNK_BYTES as u32).contains(max_chunk),
                    "native transfer hello chunk limit is invalid"
                );
                ensure!(
                    *max_window >= *max_chunk && *max_window <= MAX_WINDOW_BYTES,
                    "native transfer hello window limit is invalid"
                );
            }
            Self::BeginPush {
                transfer_id,
                target,
                sha256,
                resume_token,
                ..
            } => {
                validate_transfer_id(transfer_id)?;
                validate_path(target, "target path")?;
                validate_sha256(sha256, "native transfer SHA-256")?;
                validate_sha256(resume_token, "native transfer resume token")?;
            }
            Self::BeginPull {
                transfer_id,
                source,
                ..
            } => {
                validate_transfer_id(transfer_id)?;
                validate_path(source, "source path")?;
            }
            Self::Ready { chunk, window, .. } => {
                validate_limits(*chunk, *window)?;
            }
            Self::PullReady {
                chunk,
                window,
                size,
                sha256,
                start_offset,
            } => {
                validate_limits(*chunk, *window)?;
                ensure!(
                    *start_offset <= *size,
                    "native pull start offset exceeds source size"
                );
                validate_sha256(sha256, "native pull SHA-256")?;
            }
            Self::Ack {
                confirmed_offset,
                durable_offset,
                receiver_window,
            } => {
                ensure!(
                    *durable_offset <= *confirmed_offset,
                    "native transfer durable offset exceeds confirmation"
                );
                ensure!(
                    (1..=MAX_WINDOW_BYTES).contains(receiver_window),
                    "native transfer receiver window is invalid"
                );
            }
            Self::Completed { sha256, .. } => {
                validate_sha256(sha256, "native completion SHA-256")?;
            }
            Self::Error { code, message, .. } => {
                ensure!(
                    !code.is_empty()
                        && code.len() <= MAX_ERROR_CODE_BYTES
                        && code.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'_' | b'-' | b'.')
                        }),
                    "native transfer error code is invalid"
                );
                ensure!(
                    !message.contains('\0'),
                    "native transfer error message contains NUL"
                );
            }
            Self::Commit | Self::Cancel => {}
        }
        Ok(())
    }
}

fn validate_limits(chunk: u32, window: u32) -> Result<()> {
    ensure!(
        (1..=MAX_CHUNK_BYTES as u32).contains(&chunk),
        "native transfer chunk limit is invalid"
    );
    ensure!(
        window >= chunk && window <= MAX_WINDOW_BYTES,
        "native transfer window limit is invalid"
    );
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataFrame {
    pub transfer_id: [u8; 16],
    pub offset: u64,
    pub chunk_sha256: [u8; 32],
    pub payload: Vec<u8>,
}

impl DataFrame {
    pub fn new(transfer_id: [u8; 16], offset: u64, payload: Vec<u8>) -> Result<Self> {
        ensure!(!payload.is_empty(), "native transfer chunk is empty");
        ensure!(
            payload.len() <= MAX_CHUNK_BYTES,
            "native transfer chunk is too large"
        );
        let mut chunk_sha256 = [0_u8; 32];
        chunk_sha256.copy_from_slice(&Sha256::digest(&payload));
        Ok(Self {
            transfer_id,
            offset,
            chunk_sha256,
            payload,
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.payload.is_empty(), "native transfer chunk is empty");
        ensure!(
            self.payload.len() <= MAX_CHUNK_BYTES,
            "native transfer chunk is too large"
        );
        ensure!(
            Sha256::digest(&self.payload).as_slice() == self.chunk_sha256,
            "native transfer chunk SHA-256 mismatch"
        );
        self.end_offset()?;
        Ok(())
    }

    pub fn end_offset(&self) -> Result<u64> {
        self.offset
            .checked_add(self.payload.len() as u64)
            .context("native transfer chunk offset overflow")
    }
}

pub enum Frame {
    Control(Control),
    Data(DataFrame),
}

pub async fn write_control<W: AsyncWrite + Unpin>(writer: &mut W, control: &Control) -> Result<()> {
    control.validate()?;
    let body =
        Zeroizing::new(serde_json::to_vec(control).context("serialize native transfer control")?);
    ensure!(
        body.len() <= MAX_CONTROL_BYTES,
        "native transfer control is too large"
    );
    write_header(writer, FrameKind::Control, body.len()).await?;
    writer.write_all(body.as_slice()).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn write_data<W: AsyncWrite + Unpin>(writer: &mut W, data: &DataFrame) -> Result<()> {
    data.validate()?;
    let body_len = 16 + 8 + 32 + data.payload.len();
    write_header(writer, FrameKind::Data, body_len).await?;
    writer.write_all(&data.transfer_id).await?;
    writer.write_all(&data.offset.to_be_bytes()).await?;
    writer.write_all(&data.chunk_sha256).await?;
    writer.write_all(&data.payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: FrameKind,
    body_len: usize,
) -> Result<()> {
    ensure!(
        body_len <= MAX_FRAME_BYTES,
        "native transfer frame is too large"
    );
    let body_len = u32::try_from(body_len).context("native transfer frame length overflow")?;
    writer.write_all(&MAGIC).await?;
    writer.write_all(&VERSION.to_be_bytes()).await?;
    writer.write_u8(kind as u8).await?;
    writer.write_u8(0).await?;
    writer.write_all(&body_len.to_be_bytes()).await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Frame>> {
    let mut magic = [0_u8; 4];
    let first = reader.read(&mut magic[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut magic[1..]).await?;
    ensure!(magic == MAGIC, "native transfer frame magic mismatch");
    let version = reader.read_u16().await?;
    ensure!(
        version == VERSION,
        "unsupported native transfer protocol version"
    );
    let kind = reader.read_u8().await?;
    let flags = reader.read_u8().await?;
    ensure!(flags == 0, "unknown native transfer frame flags");
    let body_len = reader.read_u32().await? as usize;
    ensure!(
        body_len <= MAX_FRAME_BYTES,
        "native transfer frame is too large"
    );
    match kind {
        value if value == FrameKind::Control as u8 => {
            ensure!(
                body_len <= MAX_CONTROL_BYTES,
                "native transfer control is too large"
            );
            let mut body = Zeroizing::new(vec![0_u8; body_len]);
            reader.read_exact(body.as_mut_slice()).await?;
            let mut control: Control =
                serde_json::from_slice(body.as_slice()).context("parse native transfer control")?;
            if let Err(error) = control.validate() {
                control.zeroize();
                return Err(error);
            }
            Ok(Some(Frame::Control(control)))
        }
        value if value == FrameKind::Data as u8 => {
            ensure!(body_len >= 56, "native transfer data frame is truncated");
            let payload_len = body_len - 56;
            ensure!(
                payload_len <= MAX_CHUNK_BYTES,
                "native transfer chunk is too large"
            );
            let mut transfer_id = [0_u8; 16];
            reader.read_exact(&mut transfer_id).await?;
            let offset = reader.read_u64().await?;
            let mut chunk_sha256 = [0_u8; 32];
            reader.read_exact(&mut chunk_sha256).await?;
            let mut payload = vec![0_u8; payload_len];
            reader.read_exact(&mut payload).await?;
            let data = DataFrame {
                transfer_id,
                offset,
                chunk_sha256,
                payload,
            };
            data.validate()?;
            Ok(Some(Frame::Data(data)))
        }
        _ => bail!("unknown native transfer frame kind"),
    }
}

pub fn parse_transfer_id(value: &str) -> Result<[u8; 16]> {
    validate_transfer_id(value)?;
    let bytes = hex::decode(value).context("native transfer id must be hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("native transfer id must decode to 16 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_push_debug_redacts_and_zeroize_clears_the_ownership_token() {
        let resume_token = "a5".repeat(32);
        let mut control = Control::BeginPush {
            transfer_id: "01".repeat(16),
            target: "/tmp/private-target".to_owned(),
            size: 17,
            sha256: "02".repeat(32),
            resume_token: resume_token.clone(),
            resume: true,
        };

        let rendered = format!("{control:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&resume_token));

        control.zeroize();
        let Control::BeginPush {
            transfer_id,
            target,
            size,
            sha256,
            resume_token,
            resume,
        } = control
        else {
            panic!("control variant changed while zeroizing")
        };
        assert!(transfer_id.is_empty());
        assert!(target.is_empty());
        assert_eq!(size, 0);
        assert!(sha256.is_empty());
        assert!(resume_token.is_empty());
        assert!(!resume);
    }

    #[tokio::test]
    async fn data_round_trip_rejects_gap_hash_and_oversize() {
        let data = DataFrame::new([7; 16], 42, vec![9; 4096]).unwrap();
        let (mut left, mut right) = tokio::io::duplex(16 * 1024);
        let writer = tokio::spawn(async move { write_data(&mut left, &data).await.unwrap() });
        let Frame::Data(decoded) = read_frame(&mut right).await.unwrap().unwrap() else {
            panic!("expected data frame")
        };
        assert_eq!(decoded.offset, 42);
        writer.await.unwrap();

        let mut invalid = DataFrame::new([0; 16], 0, vec![1]).unwrap();
        invalid.chunk_sha256[0] ^= 1;
        assert!(invalid.validate().is_err());
        assert!(DataFrame::new([0; 16], 0, vec![0; MAX_CHUNK_BYTES + 1]).is_err());
    }

    #[tokio::test]
    async fn parser_rejects_unknown_version_kind_and_oversized_length() {
        for header in [
            [
                MAGIC.as_slice(),
                &(VERSION + 1).to_be_bytes(),
                &[1, 0],
                &0_u32.to_be_bytes(),
            ]
            .concat(),
            [
                MAGIC.as_slice(),
                &VERSION.to_be_bytes(),
                &[99, 0],
                &0_u32.to_be_bytes(),
            ]
            .concat(),
            [
                MAGIC.as_slice(),
                &VERSION.to_be_bytes(),
                &[1, 0],
                &((MAX_FRAME_BYTES + 1) as u32).to_be_bytes(),
            ]
            .concat(),
        ] {
            assert!(read_frame(&mut header.as_slice()).await.is_err());
        }
    }

    #[tokio::test]
    async fn control_boundary_rejects_invalid_semantics() {
        for control in [
            Control::Hello {
                version: VERSION,
                max_chunk: 0,
                max_window: 1,
                resume: true,
                sha256: true,
                fsync: true,
                no_replace: true,
            },
            Control::Ack {
                confirmed_offset: 7,
                durable_offset: 8,
                receiver_window: 1,
            },
            Control::BeginPull {
                transfer_id: "AA".repeat(16),
                source: "/tmp/source".to_owned(),
                offset: 0,
            },
            Control::Completed {
                size: 1,
                sha256: "not-a-digest".to_owned(),
            },
        ] {
            let mut sink = tokio::io::sink();
            assert!(write_control(&mut sink, &control).await.is_err());
        }

        let invalid = serde_json::to_vec(&Control::PullReady {
            chunk: 1,
            window: 1,
            size: 1,
            sha256: "00".repeat(32),
            start_offset: 2,
        })
        .unwrap();
        let mut wire = Vec::new();
        wire.extend_from_slice(&MAGIC);
        wire.extend_from_slice(&VERSION.to_be_bytes());
        wire.extend_from_slice(&[FrameKind::Control as u8, 0]);
        wire.extend_from_slice(&(invalid.len() as u32).to_be_bytes());
        wire.extend_from_slice(&invalid);
        assert!(read_frame(&mut wire.as_slice()).await.is_err());
    }

    #[test]
    fn data_frame_rejects_offset_overflow() {
        let frame = DataFrame::new([0; 16], u64::MAX, vec![1]).unwrap();
        assert!(frame.validate().is_err());
        assert!(parse_transfer_id(&"AA".repeat(16)).is_err());
    }
}
