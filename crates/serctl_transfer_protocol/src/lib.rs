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
pub const MAX_HELPER_VERSION_BYTES: usize = 256;
pub const MAX_HELPER_BINARY_BYTES: u64 = 512 * 1024 * 1024;
pub const HELPER_BINARY_NAME: &str = "serctl-xfer";

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRuntimeIdentity {
    pub name: String,
    pub binary_size: u64,
    pub sha256: String,
    pub version: String,
}

impl HelperRuntimeIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.name == HELPER_BINARY_NAME,
            "native helper name mismatch"
        );
        ensure!(
            (1..=MAX_HELPER_BINARY_BYTES).contains(&self.binary_size),
            "native helper binary size is invalid"
        );
        validate_sha256(&self.sha256, "native helper binary SHA-256")?;
        ensure!(
            !self.version.is_empty()
                && self.version.len() <= MAX_HELPER_VERSION_BYTES
                && self.version.is_ascii()
                && !self.version.bytes().any(|byte| byte.is_ascii_control()),
            "native helper version identity is invalid"
        );
        let prefix = format!("{HELPER_BINARY_NAME} ");
        let suffix = format!("; transfer protocol v{VERSION})");
        let body = self
            .version
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(&suffix))
            .context("native helper version identity grammar mismatch")?;
        let (release_version, commit) = body
            .split_once(" (git ")
            .context("native helper version identity grammar mismatch")?;
        ensure!(
            !release_version.is_empty()
                && release_version.len() <= 64
                && release_version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')),
            "native helper release version is invalid"
        );
        let commit_hex = commit.strip_suffix("-dirty").unwrap_or(commit);
        ensure!(
            commit_hex.len() == 12
                && commit_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "native helper commit identity is invalid"
        );
        Ok(())
    }
}

impl Zeroize for HelperRuntimeIdentity {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.binary_size.zeroize();
        self.sha256.zeroize();
        self.version.zeroize();
    }
}

pub fn verify_expected_helper_identity(
    observed: &HelperRuntimeIdentity,
    expected: &HelperRuntimeIdentity,
) -> Result<()> {
    observed.validate()?;
    expected.validate()?;
    ensure!(
        observed == expected,
        "native helper runtime identity does not match exact release provenance"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakePeer {
    Client,
    Helper,
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
    HelperHello {
        version: u16,
        max_chunk: u32,
        max_window: u32,
        resume: bool,
        sha256: bool,
        fsync: bool,
        no_replace: bool,
        identity: HelperRuntimeIdentity,
    },
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
            Self::HelperHello {
                version,
                max_chunk,
                max_window,
                resume,
                sha256,
                fsync,
                no_replace,
                identity,
            } => formatter
                .debug_struct("HelperHello")
                .field("version", version)
                .field("max_chunk", max_chunk)
                .field("max_window", max_window)
                .field("resume", resume)
                .field("sha256", sha256)
                .field("fsync", fsync)
                .field("no_replace", no_replace)
                .field("identity", identity)
                .finish(),
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
            Self::HelperHello {
                version,
                max_chunk,
                max_window,
                resume,
                sha256,
                fsync,
                no_replace,
                identity,
            } => {
                version.zeroize();
                max_chunk.zeroize();
                max_window.zeroize();
                resume.zeroize();
                sha256.zeroize();
                fsync.zeroize();
                no_replace.zeroize();
                identity.zeroize();
            }
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
            Self::HelperHello {
                version,
                max_chunk,
                max_window,
                identity,
                ..
            } => {
                validate_hello_limits(*version, *max_chunk, *max_window)?;
                identity.validate()?;
            }
            Self::Hello {
                version,
                max_chunk,
                max_window,
                ..
            } => {
                validate_hello_limits(*version, *max_chunk, *max_window)?;
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

    pub fn validate_handshake_sender(&self, sender: HandshakePeer) -> Result<()> {
        match (sender, self) {
            (HandshakePeer::Helper, Self::HelperHello { .. })
            | (HandshakePeer::Client, Self::Hello { .. }) => self.validate(),
            (HandshakePeer::Helper, Self::Hello { .. }) => {
                bail!("client hello is not valid from native helper")
            }
            (HandshakePeer::Client, Self::HelperHello { .. }) => {
                bail!("helper identity hello is server-only")
            }
            _ => bail!("non-hello control is invalid during native handshake"),
        }
    }
}

fn validate_hello_limits(version: u16, max_chunk: u32, max_window: u32) -> Result<()> {
    ensure!(version == VERSION, "native transfer hello version mismatch");
    ensure!(
        (1..=MAX_CHUNK_BYTES as u32).contains(&max_chunk),
        "native transfer hello chunk limit is invalid"
    );
    ensure!(
        max_window >= max_chunk && max_window <= MAX_WINDOW_BYTES,
        "native transfer hello window limit is invalid"
    );
    Ok(())
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

/// Validates the contiguous data prefix for one transfer. A rejected frame
/// never advances the expected offset, so callers can fail closed on gaps,
/// replays, a crossed transfer id, an invalid chunk hash, or offset overflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataSequenceValidator {
    transfer_id: [u8; 16],
    next_offset: u64,
}

impl DataSequenceValidator {
    pub fn new(transfer_id: [u8; 16], next_offset: u64) -> Self {
        Self {
            transfer_id,
            next_offset,
        }
    }

    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub fn validate_next(&mut self, data: &DataFrame) -> Result<()> {
        data.validate()?;
        ensure!(
            data.transfer_id == self.transfer_id,
            "native transfer data frame belongs to another transfer"
        );
        ensure!(
            data.offset == self.next_offset,
            "native transfer data offset gap or replay"
        );
        let next_offset = data.end_offset()?;
        self.next_offset = next_offset;
        Ok(())
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

pub async fn write_handshake_control<W: AsyncWrite + Unpin>(
    writer: &mut W,
    control: &Control,
    sender: HandshakePeer,
) -> Result<()> {
    control.validate_handshake_sender(sender)?;
    write_control(writer, control).await
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

    fn helper_identity() -> HelperRuntimeIdentity {
        HelperRuntimeIdentity {
            name: HELPER_BINARY_NAME.to_owned(),
            binary_size: 12_345,
            sha256: "ab".repeat(32),
            version: format!(
                "serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v{VERSION})"
            ),
        }
    }

    async fn encode_data_wire(data: DataFrame) -> Vec<u8> {
        let (mut writer, mut reader) = tokio::io::duplex(256);
        let write_task = tokio::spawn(async move { write_data(&mut writer, &data).await });
        let mut encoded = Vec::new();
        reader.read_to_end(&mut encoded).await.unwrap();
        write_task.await.unwrap().unwrap();
        encoded
    }

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

        let mut sequence = DataSequenceValidator::new([7; 16], 42);
        let first = DataFrame::new([7; 16], 42, vec![1, 2, 3]).unwrap();
        sequence.validate_next(&first).unwrap();
        assert_eq!(sequence.next_offset(), 45);

        assert!(sequence.validate_next(&first).is_err());
        assert_eq!(sequence.next_offset(), 45);
        let gap = DataFrame::new([7; 16], 46, vec![4]).unwrap();
        assert!(sequence.validate_next(&gap).is_err());
        assert_eq!(sequence.next_offset(), 45);
        let crossed = DataFrame::new([8; 16], 45, vec![4]).unwrap();
        assert!(sequence.validate_next(&crossed).is_err());
        assert_eq!(sequence.next_offset(), 45);
        let second = DataFrame::new([7; 16], 45, vec![4]).unwrap();
        sequence.validate_next(&second).unwrap();
        assert_eq!(sequence.next_offset(), 46);
    }

    #[tokio::test]
    async fn sixty_four_kib_data_frame_round_trips_over_fragmented_transport() {
        const IPC_CHUNK_BYTES: usize = 64 * 1024;
        let payload: Vec<u8> = (0..IPC_CHUNK_BYTES)
            .map(|index| (index % 251) as u8)
            .collect();
        let expected = payload.clone();
        let data = DataFrame::new([0x5a; 16], 8192, payload).unwrap();
        // The tiny duplex capacity forces many partial reads/writes, matching
        // russh channel fragmentation instead of assuming one write == one
        // protocol frame.
        let (mut left, mut right) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move { write_data(&mut left, &data).await.unwrap() });
        let Frame::Data(decoded) = read_frame(&mut right).await.unwrap().unwrap() else {
            panic!("expected data frame")
        };
        writer.await.unwrap();
        assert_eq!(decoded.transfer_id, [0x5a; 16]);
        assert_eq!(decoded.offset, 8192);
        assert_eq!(decoded.payload, expected);
        assert_eq!(
            decoded.end_offset().unwrap(),
            (8192 + IPC_CHUNK_BYTES) as u64
        );
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
    async fn deterministic_parser_mutation_corpus_is_bounded_and_fail_closed() {
        const HEADER_BYTES: usize = 12;
        let valid =
            encode_data_wire(DataFrame::new([0x31; 16], 4096, (0_u8..64).collect()).unwrap()).await;
        assert_eq!(valid.len(), HEADER_BYTES + 56 + 64);

        let mut corpus: Vec<(&str, Vec<u8>)> = Vec::new();
        for prefix_len in 1..valid.len() {
            corpus.push(("truncated_prefix", valid[..prefix_len].to_vec()));
        }

        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 0xff;
        corpus.push(("bad_magic", bad_magic));

        let mut unknown_version = valid.clone();
        unknown_version[4..6].copy_from_slice(&(VERSION + 1).to_be_bytes());
        corpus.push(("unknown_version", unknown_version));

        let mut unknown_kind = valid.clone();
        unknown_kind[6] = 0xff;
        corpus.push(("unknown_kind", unknown_kind));

        let mut unknown_flags = valid.clone();
        unknown_flags[7] = 1;
        corpus.push(("unknown_flags", unknown_flags));

        let mut declared_too_large = valid[..HEADER_BYTES].to_vec();
        declared_too_large[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        corpus.push(("declared_u32_max", declared_too_large));

        let mut data_header_too_short = valid[..HEADER_BYTES].to_vec();
        data_header_too_short[8..12].copy_from_slice(&55_u32.to_be_bytes());
        corpus.push(("data_fixed_fields_truncated", data_header_too_short));

        let declared = u32::from_be_bytes(valid[8..12].try_into().unwrap());
        let mut declared_long = valid.clone();
        declared_long[8..12].copy_from_slice(&(declared + 1).to_be_bytes());
        corpus.push(("declared_body_longer_than_input", declared_long));

        let mut declared_short = valid.clone();
        declared_short[8..12].copy_from_slice(&(declared - 1).to_be_bytes());
        corpus.push(("declared_body_shorter_than_input", declared_short));

        let mut bad_chunk_hash = valid.clone();
        bad_chunk_hash[HEADER_BYTES + 16 + 8] ^= 1;
        corpus.push(("chunk_hash_bit_flip", bad_chunk_hash));

        let unknown_control = br#"{"type":"future_control"}"#;
        let mut unknown_control_wire = Vec::new();
        unknown_control_wire.extend_from_slice(&MAGIC);
        unknown_control_wire.extend_from_slice(&VERSION.to_be_bytes());
        unknown_control_wire.extend_from_slice(&[FrameKind::Control as u8, 0]);
        unknown_control_wire.extend_from_slice(&(unknown_control.len() as u32).to_be_bytes());
        unknown_control_wire.extend_from_slice(unknown_control);
        corpus.push(("unknown_control_kind", unknown_control_wire));

        for (index, (name, mutation)) in corpus.into_iter().enumerate() {
            let result = read_frame(&mut mutation.as_slice()).await;
            assert!(result.is_err(), "mutation #{index} '{name}' was accepted");
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
    fn helper_identity_is_bounded_exact_and_server_only() {
        let expected = helper_identity();
        verify_expected_helper_identity(&expected, &expected).unwrap();
        let hello = Control::HelperHello {
            version: VERSION,
            max_chunk: DEFAULT_CHUNK_BYTES,
            max_window: DEFAULT_WINDOW_BYTES,
            resume: true,
            sha256: true,
            fsync: true,
            no_replace: true,
            identity: expected.clone(),
        };
        hello
            .validate_handshake_sender(HandshakePeer::Helper)
            .unwrap();
        assert!(hello
            .validate_handshake_sender(HandshakePeer::Client)
            .is_err());
        let client = Control::Hello {
            version: VERSION,
            max_chunk: DEFAULT_CHUNK_BYTES,
            max_window: DEFAULT_WINDOW_BYTES,
            resume: true,
            sha256: true,
            fsync: true,
            no_replace: true,
        };
        client
            .validate_handshake_sender(HandshakePeer::Client)
            .unwrap();
        assert!(client
            .validate_handshake_sender(HandshakePeer::Helper)
            .is_err());

        for mut invalid in [
            {
                let mut value = expected.clone();
                value.name = "SERCTL-XFER".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.binary_size = 0;
                value
            },
            {
                let mut value = expected.clone();
                value.binary_size = MAX_HELPER_BINARY_BYTES + 1;
                value
            },
            {
                let mut value = expected.clone();
                value.sha256 = "AB".repeat(32);
                value
            },
            {
                let mut value = expected.clone();
                value.version =
                    "serctl-xfer 1.0.0-beta (git 0123456789AB; transfer protocol v1)".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.version = "x".repeat(MAX_HELPER_VERSION_BYTES + 1);
                value
            },
        ] {
            assert!(invalid.validate().is_err());
            invalid.zeroize();
        }

        let mut drift = expected.clone();
        drift.binary_size += 1;
        assert!(verify_expected_helper_identity(&drift, &expected).is_err());
        drift = expected.clone();
        drift.sha256 = "cd".repeat(32);
        assert!(verify_expected_helper_identity(&drift, &expected).is_err());
        drift = expected.clone();
        drift.version = drift.version.replace("1.0.0-beta", "1.0.0-beta.1");
        assert!(verify_expected_helper_identity(&drift, &expected).is_err());
    }

    #[tokio::test]
    async fn helper_identity_parser_rejects_unknown_fields_and_type_confusion() {
        for json in [
            format!(
                r#"{{"type":"helper_hello","version":1,"max_chunk":1,"max_window":1,"resume":true,"sha256":true,"fsync":true,"no_replace":true,"identity":{{"name":"serctl-xfer","binary_size":1,"sha256":"{}","version":"serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)","future":true}}}}"#,
                "ab".repeat(32)
            ),
            format!(
                r#"{{"type":"helper_hello","version":1,"max_chunk":1,"max_window":1,"resume":true,"sha256":true,"fsync":true,"no_replace":true,"identity":{{"name":"serctl-xfer","binary_size":"1","sha256":"{}","version":"serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)"}}}}"#,
                "ab".repeat(32)
            ),
        ] {
            let body = json.into_bytes();
            let mut wire = Vec::new();
            wire.extend_from_slice(&MAGIC);
            wire.extend_from_slice(&VERSION.to_be_bytes());
            wire.extend_from_slice(&[FrameKind::Control as u8, 0]);
            wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
            wire.extend_from_slice(&body);
            assert!(read_frame(&mut wire.as_slice()).await.is_err());
        }
    }

    #[test]
    fn data_frame_rejects_offset_overflow() {
        let frame = DataFrame::new([0; 16], u64::MAX, vec![1]).unwrap();
        assert!(frame.validate().is_err());
        assert!(parse_transfer_id(&"AA".repeat(16)).is_err());
    }
}
