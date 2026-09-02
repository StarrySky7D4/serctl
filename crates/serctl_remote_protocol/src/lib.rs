//! Strict, bounded binary framing for the fixed-command serctl remote helper.
//!
//! Control values are encoded as length-prefixed fields. Output and receipt
//! payloads remain raw bytes: this protocol never base64-encodes data and never
//! accepts a shell command string.

#![forbid(unsafe_code)]

use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::io::{self, Read, Write};
use zeroize::Zeroize;

pub const MAGIC: [u8; 4] = *b"SRRP";
pub const PROTOCOL_VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 20;
pub const MAX_FRAME_PAYLOAD: usize = 128 * 1024;
pub const MAX_OUTPUT_CHUNK: usize = 32 * 1024;
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_PROGRAM_BYTES: usize = 128;
pub const MAX_ARG_COUNT: usize = 64;
pub const MAX_ARG_BYTES: usize = 4 * 1024;
pub const MAX_ARG_TOTAL_BYTES: usize = 16 * 1024;
pub const MAX_ENV_COUNT: usize = 16;
pub const MAX_ENV_NAME_BYTES: usize = 64;
pub const MAX_ENV_VALUE_BYTES: usize = 1024;
pub const MAX_ENV_TOTAL_BYTES: usize = 8 * 1024;
pub const MAX_PATH_BYTES: usize = 4 * 1024;
pub const MAX_RECEIPT_BYTES: usize = 4 * 1024;
pub const MAX_ERROR_CODE_BYTES: usize = 64;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 2 * 1024;
pub const MAX_CANCEL_REASON_BYTES: usize = 256;
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub const FEATURE_CANCEL: u64 = 1 << 0;
pub const FEATURE_RECEIPT_QUERY: u64 = 1 << 1;
pub const SUPPORTED_FEATURE_BITS: u64 = FEATURE_CANCEL | FEATURE_RECEIPT_QUERY;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobId([u8; 16]);

impl JobId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        let mut bytes = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for JobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "JobId({})", hex_lower(&self.0))
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex_lower(&self.0))
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileId([u8; 16]);

impl ProfileId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ProfileId({})", hex_lower(&self.0))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Digest32({})", hex_lower(&self.0))
    }
}

pub struct Secret32([u8; 32]);

impl Secret32 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret32([REDACTED])")
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 1,
    Start = 2,
    Stdout = 3,
    Stderr = 4,
    Heartbeat = 5,
    Cancel = 6,
    Exit = 7,
    Receipt = 8,
    Error = 9,
    QueryReceipt = 10,
}

impl TryFrom<u8> for FrameKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Start),
            3 => Ok(Self::Stdout),
            4 => Ok(Self::Stderr),
            5 => Ok(Self::Heartbeat),
            6 => Ok(Self::Cancel),
            7 => Ok(Self::Exit),
            8 => Ok(Self::Receipt),
            9 => Ok(Self::Error),
            10 => Ok(Self::QueryReceipt),
            _ => Err(ProtocolError::UnknownFrameKind(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelloFrame {
    pub max_frame_payload: u32,
    pub feature_bits: u64,
    /// Zero in the controller's Hello; the Linux helper returns its actual
    /// non-root effective UID so callers never guess an execution identity.
    pub effective_uid: u32,
}

#[derive(Eq, PartialEq)]
pub struct EnvEntry {
    pub name: String,
    pub value: String,
}

impl fmt::Debug for EnvEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvEntry")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for EnvEntry {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

pub struct StartFrame {
    pub job_id: JobId,
    pub profile_id: ProfileId,
    pub profile_generation: u64,
    pub policy_digest: Digest32,
    pub input_digest: Digest32,
    pub remote_deadline_unix_ms: u64,
    pub relay_deadline_unix_ms: u64,
    pub result_retention_unix_ms: u64,
    pub run_as_uid: u32,
    pub max_output_bytes: u64,
    pub program: String,
    pub argv: Vec<String>,
    pub env: Vec<EnvEntry>,
    pub cwd: Option<String>,
    pub policy_json: Vec<u8>,
    pub receipt_token: Secret32,
}

impl fmt::Debug for StartFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartFrame")
            .field("job_id", &self.job_id)
            .field("profile_id", &self.profile_id)
            .field("profile_generation", &self.profile_generation)
            .field("policy_digest", &self.policy_digest)
            .field("input_digest", &self.input_digest)
            .field("remote_deadline_unix_ms", &self.remote_deadline_unix_ms)
            .field("relay_deadline_unix_ms", &self.relay_deadline_unix_ms)
            .field("result_retention_unix_ms", &self.result_retention_unix_ms)
            .field("run_as_uid", &self.run_as_uid)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("program", &self.program)
            .field("argv_count", &self.argv.len())
            .field(
                "env_names",
                &self.env.iter().map(|item| &item.name).collect::<Vec<_>>(),
            )
            .field("cwd", &self.cwd)
            .field("policy_json_bytes", &self.policy_json.len())
            .field("receipt_token", &"[REDACTED]")
            .finish()
    }
}

impl Drop for StartFrame {
    fn drop(&mut self) {
        self.program.zeroize();
        self.argv.zeroize();
        self.cwd.zeroize();
        self.policy_json.zeroize();
    }
}

pub struct OutputFrame {
    pub job_id: JobId,
    pub offset: u64,
    pub data: Vec<u8>,
}

impl fmt::Debug for OutputFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputFrame")
            .field("job_id", &self.job_id)
            .field("offset", &self.offset)
            .field("data_bytes", &self.data.len())
            .finish()
    }
}

impl Drop for OutputFrame {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatFrame {
    pub job_id: JobId,
    pub ordinal: u64,
    pub elapsed_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

pub struct CancelFrame {
    pub job_id: JobId,
    pub reason: String,
}

impl fmt::Debug for CancelFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancelFrame")
            .field("job_id", &self.job_id)
            .field("reason", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CancelFrame {
    fn drop(&mut self) {
        self.reason.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitOutcome {
    Exited(i32),
    Cancelled,
    DeadlineExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitFrame {
    pub job_id: JobId,
    pub outcome: ExitOutcome,
    pub completed_unix_ms: u64,
}

pub struct ReceiptFrame {
    pub job_id: JobId,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for ReceiptFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptFrame")
            .field("job_id", &self.job_id)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

impl Drop for ReceiptFrame {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub struct ErrorFrame {
    pub job_id: Option<JobId>,
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

pub struct QueryReceiptFrame {
    pub job_id: JobId,
    pub profile_id: ProfileId,
    pub profile_generation: u64,
    pub policy_digest: Digest32,
    pub input_digest: Digest32,
    pub receipt_token: Secret32,
}

impl fmt::Debug for QueryReceiptFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryReceiptFrame")
            .field("job_id", &self.job_id)
            .field("profile_id", &self.profile_id)
            .field("profile_generation", &self.profile_generation)
            .field("policy_digest", &self.policy_digest)
            .field("input_digest", &self.input_digest)
            .field("receipt_token", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for ErrorFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErrorFrame")
            .field("job_id", &self.job_id)
            .field("code", &self.code)
            .field("message", &"[REDACTED]")
            .field("retryable", &self.retryable)
            .finish()
    }
}

impl Drop for ErrorFrame {
    fn drop(&mut self) {
        self.code.zeroize();
        self.message.zeroize();
    }
}

#[derive(Debug)]
pub enum Frame {
    Hello(HelloFrame),
    Start(Box<StartFrame>),
    Stdout(OutputFrame),
    Stderr(OutputFrame),
    Heartbeat(HeartbeatFrame),
    Cancel(CancelFrame),
    Exit(ExitFrame),
    Receipt(ReceiptFrame),
    Error(ErrorFrame),
    QueryReceipt(QueryReceiptFrame),
}

impl Frame {
    pub const fn kind(&self) -> FrameKind {
        match self {
            Self::Hello(_) => FrameKind::Hello,
            Self::Start(_) => FrameKind::Start,
            Self::Stdout(_) => FrameKind::Stdout,
            Self::Stderr(_) => FrameKind::Stderr,
            Self::Heartbeat(_) => FrameKind::Heartbeat,
            Self::Cancel(_) => FrameKind::Cancel,
            Self::Exit(_) => FrameKind::Exit,
            Self::Receipt(_) => FrameKind::Receipt,
            Self::Error(_) => FrameKind::Error,
            Self::QueryReceipt(_) => FrameKind::QueryReceipt,
        }
    }
}

/// Compute the domain-separated digest of the typed execution input. The
/// claimed digest itself and the random receipt token are deliberately
/// excluded; policy bytes are represented by their independently verified
/// policy digest.
pub fn compute_start_input_digest(start: &StartFrame) -> Digest32 {
    const DOMAIN: &[u8] = b"serctl-remote-start-v1\0";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(start.job_id.as_bytes());
    hasher.update(start.profile_id.as_bytes());
    hasher.update(start.profile_generation.to_be_bytes());
    hasher.update(start.policy_digest.as_bytes());
    hasher.update(start.remote_deadline_unix_ms.to_be_bytes());
    hasher.update(start.relay_deadline_unix_ms.to_be_bytes());
    hasher.update(start.result_retention_unix_ms.to_be_bytes());
    hasher.update(start.run_as_uid.to_be_bytes());
    hasher.update(start.max_output_bytes.to_be_bytes());
    hash_length_prefixed(&mut hasher, start.program.as_bytes());
    hasher.update((start.argv.len() as u64).to_be_bytes());
    for argument in &start.argv {
        hash_length_prefixed(&mut hasher, argument.as_bytes());
    }
    hasher.update((start.env.len() as u64).to_be_bytes());
    for variable in &start.env {
        hash_length_prefixed(&mut hasher, variable.name.as_bytes());
        hash_length_prefixed(&mut hasher, variable.value.as_bytes());
    }
    match &start.cwd {
        Some(cwd) => {
            hasher.update([1]);
            hash_length_prefixed(&mut hasher, cwd.as_bytes());
        }
        None => hasher.update([0]),
    }
    Digest32::from_bytes(hasher.finalize().into())
}

fn hash_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[derive(Debug)]
pub struct Envelope {
    pub sequence: u64,
    pub frame: Frame,
}

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    BadMagic,
    UnsupportedVersion(u16),
    UnknownFrameKind(u8),
    ReservedFlags(u8),
    FrameTooLarge(usize),
    KindPayloadTooLarge(FrameKind, usize),
    Truncated,
    TrailingBytes,
    InvalidUtf8,
    InvalidValue(&'static str),
    Sequence { expected: u64, actual: u64 },
    InvalidState(&'static str),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::BadMagic => formatter.write_str("invalid remote protocol magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported remote protocol version {version}")
            }
            Self::UnknownFrameKind(kind) => write!(formatter, "unknown frame kind {kind}"),
            Self::ReservedFlags(flags) => write!(formatter, "reserved frame flags set: {flags:#x}"),
            Self::FrameTooLarge(size) => write!(formatter, "frame payload exceeds limit: {size}"),
            Self::KindPayloadTooLarge(kind, size) => {
                write!(formatter, "{kind:?} payload exceeds its limit: {size}")
            }
            Self::Truncated => formatter.write_str("truncated frame payload"),
            Self::TrailingBytes => formatter.write_str("frame payload has trailing bytes"),
            Self::InvalidUtf8 => formatter.write_str("frame contains invalid UTF-8"),
            Self::InvalidValue(field) => write!(formatter, "invalid frame field: {field}"),
            Self::Sequence { expected, actual } => {
                write!(
                    formatter,
                    "frame sequence mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidState(message) => write!(formatter, "invalid frame state: {message}"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    encode_payload(&envelope.frame, &mut payload)?;
    validate_payload_size(envelope.frame.kind(), payload.len())?;
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge(payload.len()))?;

    let mut encoded = Vec::with_capacity(HEADER_BYTES + payload.len());
    encoded.extend_from_slice(&MAGIC);
    encoded.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    encoded.push(envelope.frame.kind() as u8);
    encoded.push(0);
    encoded.extend_from_slice(&envelope.sequence.to_be_bytes());
    encoded.extend_from_slice(&payload_len.to_be_bytes());
    encoded.extend_from_slice(&payload);
    payload.zeroize();
    Ok(encoded)
}

pub fn decode_exact(bytes: &[u8]) -> Result<Envelope, ProtocolError> {
    if bytes.len() < HEADER_BYTES {
        return Err(ProtocolError::Truncated);
    }
    if bytes[..4] != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let kind = FrameKind::try_from(bytes[6])?;
    if bytes[7] != 0 {
        return Err(ProtocolError::ReservedFlags(bytes[7]));
    }
    let sequence = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed header slice"));
    let payload_len =
        u32::from_be_bytes(bytes[16..20].try_into().expect("fixed header slice")) as usize;
    validate_payload_size(kind, payload_len)?;
    let expected = HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(ProtocolError::FrameTooLarge(payload_len))?;
    if bytes.len() < expected {
        return Err(ProtocolError::Truncated);
    }
    if bytes.len() != expected {
        return Err(ProtocolError::TrailingBytes);
    }
    let frame = decode_payload(kind, &bytes[HEADER_BYTES..])?;
    Ok(Envelope { sequence, frame })
}

pub fn read_frame_from<R: Read>(reader: &mut R) -> Result<Option<Envelope>, ProtocolError> {
    let mut header = [0_u8; HEADER_BYTES];
    match reader.read(&mut header[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("single-byte read"),
        Err(error) => return Err(ProtocolError::Io(error)),
    }
    reader.read_exact(&mut header[1..])?;
    if header[..4] != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let kind = FrameKind::try_from(header[6])?;
    if header[7] != 0 {
        return Err(ProtocolError::ReservedFlags(header[7]));
    }
    let payload_len =
        u32::from_be_bytes(header[16..20].try_into().expect("fixed header slice")) as usize;
    validate_payload_size(kind, payload_len)?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload_len);
    bytes.extend_from_slice(&header);
    bytes.resize(HEADER_BYTES + payload_len, 0);
    reader.read_exact(&mut bytes[HEADER_BYTES..])?;
    let result = decode_exact(&bytes);
    bytes.zeroize();
    result.map(Some)
}

pub fn write_frame_to<W: Write>(writer: &mut W, envelope: &Envelope) -> Result<(), ProtocolError> {
    let mut bytes = encode(envelope)?;
    let result = writer.write_all(&bytes).map_err(ProtocolError::Io);
    bytes.zeroize();
    result
}

fn validate_payload_size(kind: FrameKind, size: usize) -> Result<(), ProtocolError> {
    if size > MAX_FRAME_PAYLOAD {
        return Err(ProtocolError::FrameTooLarge(size));
    }
    let kind_limit = match kind {
        FrameKind::Hello => 16,
        FrameKind::Start => MAX_FRAME_PAYLOAD,
        FrameKind::Stdout | FrameKind::Stderr => 24 + MAX_OUTPUT_CHUNK,
        FrameKind::Heartbeat => 48,
        FrameKind::Cancel => 18 + MAX_CANCEL_REASON_BYTES,
        FrameKind::Exit => 29,
        FrameKind::Receipt => 20 + MAX_RECEIPT_BYTES,
        FrameKind::Error => 24 + MAX_ERROR_CODE_BYTES + MAX_ERROR_MESSAGE_BYTES,
        FrameKind::QueryReceipt => 136,
    };
    if size > kind_limit {
        return Err(ProtocolError::KindPayloadTooLarge(kind, size));
    }
    Ok(())
}

fn encode_payload(frame: &Frame, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
    match frame {
        Frame::Hello(value) => {
            if value.max_frame_payload == 0 || value.max_frame_payload as usize > MAX_FRAME_PAYLOAD
            {
                return Err(ProtocolError::InvalidValue("hello max_frame_payload"));
            }
            if value.feature_bits & !SUPPORTED_FEATURE_BITS != 0 {
                return Err(ProtocolError::InvalidValue("hello feature_bits"));
            }
            put_u32(out, value.max_frame_payload);
            put_u64(out, value.feature_bits);
            put_u32(out, value.effective_uid);
        }
        Frame::Start(value) => encode_start(value, out)?,
        Frame::Stdout(value) | Frame::Stderr(value) => {
            validate_range("output data", value.data.len(), 0, MAX_OUTPUT_CHUNK)?;
            put_job_id(out, value.job_id);
            put_u64(out, value.offset);
            out.extend_from_slice(&value.data);
        }
        Frame::Heartbeat(value) => {
            put_job_id(out, value.job_id);
            put_u64(out, value.ordinal);
            put_u64(out, value.elapsed_ms);
            put_u64(out, value.stdout_bytes);
            put_u64(out, value.stderr_bytes);
        }
        Frame::Cancel(value) => {
            put_job_id(out, value.job_id);
            put_string_u16(
                out,
                "cancel reason",
                &value.reason,
                1,
                MAX_CANCEL_REASON_BYTES,
            )?;
        }
        Frame::Exit(value) => {
            put_job_id(out, value.job_id);
            match value.outcome {
                ExitOutcome::Exited(code) => {
                    out.push(0);
                    out.extend_from_slice(&code.to_be_bytes());
                }
                ExitOutcome::Cancelled => {
                    out.push(1);
                    out.extend_from_slice(&0_i32.to_be_bytes());
                }
                ExitOutcome::DeadlineExceeded => {
                    out.push(2);
                    out.extend_from_slice(&0_i32.to_be_bytes());
                }
            }
            put_u64(out, value.completed_unix_ms);
        }
        Frame::Receipt(value) => {
            validate_range("receipt", value.bytes.len(), 1, MAX_RECEIPT_BYTES)?;
            put_job_id(out, value.job_id);
            put_bytes_u32(out, &value.bytes)?;
        }
        Frame::Error(value) => {
            match value.job_id {
                Some(job_id) => {
                    out.push(1);
                    put_job_id(out, job_id);
                }
                None => out.push(0),
            }
            put_string_u16(out, "error code", &value.code, 1, MAX_ERROR_CODE_BYTES)?;
            put_string_u16(
                out,
                "error message",
                &value.message,
                1,
                MAX_ERROR_MESSAGE_BYTES,
            )?;
            out.push(u8::from(value.retryable));
        }
        Frame::QueryReceipt(value) => {
            validate_query_receipt(value)?;
            put_job_id(out, value.job_id);
            out.extend_from_slice(value.profile_id.as_bytes());
            put_u64(out, value.profile_generation);
            out.extend_from_slice(value.policy_digest.as_bytes());
            out.extend_from_slice(value.input_digest.as_bytes());
            out.extend_from_slice(value.receipt_token.as_bytes());
        }
    }
    Ok(())
}

fn encode_start(value: &StartFrame, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
    validate_start(value)?;
    put_job_id(out, value.job_id);
    out.extend_from_slice(value.profile_id.as_bytes());
    put_u64(out, value.profile_generation);
    out.extend_from_slice(value.policy_digest.as_bytes());
    out.extend_from_slice(value.input_digest.as_bytes());
    put_u64(out, value.remote_deadline_unix_ms);
    put_u64(out, value.relay_deadline_unix_ms);
    put_u64(out, value.result_retention_unix_ms);
    put_u32(out, value.run_as_uid);
    put_u64(out, value.max_output_bytes);
    put_string_u16(out, "program", &value.program, 1, MAX_PROGRAM_BYTES)?;
    put_u16(out, value.argv.len() as u16);
    for argument in &value.argv {
        put_string_u16(out, "argument", argument, 0, MAX_ARG_BYTES)?;
    }
    put_u16(out, value.env.len() as u16);
    for variable in &value.env {
        put_string_u16(
            out,
            "environment name",
            &variable.name,
            1,
            MAX_ENV_NAME_BYTES,
        )?;
        put_string_u16(
            out,
            "environment value",
            &variable.value,
            0,
            MAX_ENV_VALUE_BYTES,
        )?;
    }
    match &value.cwd {
        Some(cwd) => {
            out.push(1);
            put_string_u16(out, "cwd", cwd, 1, MAX_PATH_BYTES)?;
        }
        None => out.push(0),
    }
    put_bytes_u32(out, &value.policy_json)?;
    out.extend_from_slice(value.receipt_token.as_bytes());
    Ok(())
}

fn validate_start(value: &StartFrame) -> Result<(), ProtocolError> {
    validate_nonzero("job_id", value.job_id.as_bytes())?;
    validate_nonzero("profile_id", value.profile_id.as_bytes())?;
    validate_nonzero("policy_digest", value.policy_digest.as_bytes())?;
    validate_nonzero("input_digest", value.input_digest.as_bytes())?;
    validate_nonzero("receipt_token", value.receipt_token.as_bytes())?;
    if value.profile_generation == 0 {
        return Err(ProtocolError::InvalidValue("profile_generation"));
    }
    if value.run_as_uid == 0 {
        return Err(ProtocolError::InvalidValue("run_as_uid"));
    }
    if value.remote_deadline_unix_ms == 0
        || value.remote_deadline_unix_ms > value.relay_deadline_unix_ms
        || value.relay_deadline_unix_ms > value.result_retention_unix_ms
    {
        return Err(ProtocolError::InvalidValue("deadlines"));
    }
    if value.max_output_bytes == 0 || value.max_output_bytes > MAX_OUTPUT_BYTES {
        return Err(ProtocolError::InvalidValue("max_output_bytes"));
    }
    validate_text("program", &value.program, 1, MAX_PROGRAM_BYTES)?;
    if value.argv.len() > MAX_ARG_COUNT {
        return Err(ProtocolError::InvalidValue("argv count"));
    }
    let mut argv_bytes = 0_usize;
    for argument in &value.argv {
        validate_text("argument", argument, 0, MAX_ARG_BYTES)?;
        argv_bytes = argv_bytes.saturating_add(argument.len());
    }
    if argv_bytes > MAX_ARG_TOTAL_BYTES {
        return Err(ProtocolError::InvalidValue("argv bytes"));
    }
    if value.env.len() > MAX_ENV_COUNT {
        return Err(ProtocolError::InvalidValue("environment count"));
    }
    let mut env_bytes = 0_usize;
    for variable in &value.env {
        validate_text("environment name", &variable.name, 1, MAX_ENV_NAME_BYTES)?;
        validate_text("environment value", &variable.value, 0, MAX_ENV_VALUE_BYTES)?;
        if variable.name.contains('=') {
            return Err(ProtocolError::InvalidValue("environment name"));
        }
        env_bytes = env_bytes
            .saturating_add(variable.name.len())
            .saturating_add(variable.value.len());
    }
    if env_bytes > MAX_ENV_TOTAL_BYTES {
        return Err(ProtocolError::InvalidValue("environment bytes"));
    }
    if let Some(cwd) = &value.cwd {
        validate_text("cwd", cwd, 1, MAX_PATH_BYTES)?;
    }
    validate_range("policy_json", value.policy_json.len(), 1, MAX_POLICY_BYTES)?;
    Ok(())
}

fn validate_query_receipt(value: &QueryReceiptFrame) -> Result<(), ProtocolError> {
    validate_nonzero("job_id", value.job_id.as_bytes())?;
    validate_nonzero("profile_id", value.profile_id.as_bytes())?;
    validate_nonzero("policy_digest", value.policy_digest.as_bytes())?;
    validate_nonzero("input_digest", value.input_digest.as_bytes())?;
    validate_nonzero("receipt_token", value.receipt_token.as_bytes())?;
    if value.profile_generation == 0 {
        return Err(ProtocolError::InvalidValue("profile_generation"));
    }
    Ok(())
}

fn validate_nonzero(field: &'static str, bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(ProtocolError::InvalidValue(field))
    } else {
        Ok(())
    }
}

fn decode_payload(kind: FrameKind, payload: &[u8]) -> Result<Frame, ProtocolError> {
    let mut reader = PayloadReader::new(payload);
    let frame = match kind {
        FrameKind::Hello => {
            let max_frame_payload = reader.u32()?;
            let feature_bits = reader.u64()?;
            if max_frame_payload == 0 || max_frame_payload as usize > MAX_FRAME_PAYLOAD {
                return Err(ProtocolError::InvalidValue("hello max_frame_payload"));
            }
            if feature_bits & !SUPPORTED_FEATURE_BITS != 0 {
                return Err(ProtocolError::InvalidValue("hello feature_bits"));
            }
            Frame::Hello(HelloFrame {
                max_frame_payload,
                feature_bits,
                effective_uid: reader.u32()?,
            })
        }
        FrameKind::Start => Frame::Start(Box::new(decode_start(&mut reader)?)),
        FrameKind::Stdout | FrameKind::Stderr => {
            let output = OutputFrame {
                job_id: reader.job_id()?,
                offset: reader.u64()?,
                data: reader.remaining_bounded(MAX_OUTPUT_CHUNK)?.to_vec(),
            };
            if kind == FrameKind::Stdout {
                Frame::Stdout(output)
            } else {
                Frame::Stderr(output)
            }
        }
        FrameKind::Heartbeat => Frame::Heartbeat(HeartbeatFrame {
            job_id: reader.job_id()?,
            ordinal: reader.u64()?,
            elapsed_ms: reader.u64()?,
            stdout_bytes: reader.u64()?,
            stderr_bytes: reader.u64()?,
        }),
        FrameKind::Cancel => Frame::Cancel(CancelFrame {
            job_id: reader.job_id()?,
            reason: reader.string_u16("cancel reason", 1, MAX_CANCEL_REASON_BYTES)?,
        }),
        FrameKind::Exit => {
            let job_id = reader.job_id()?;
            let kind = reader.u8()?;
            let code = reader.i32()?;
            let outcome = match (kind, code) {
                (0, code) => ExitOutcome::Exited(code),
                (1, 0) => ExitOutcome::Cancelled,
                (2, 0) => ExitOutcome::DeadlineExceeded,
                _ => return Err(ProtocolError::InvalidValue("exit outcome")),
            };
            Frame::Exit(ExitFrame {
                job_id,
                outcome,
                completed_unix_ms: reader.u64()?,
            })
        }
        FrameKind::Receipt => Frame::Receipt(ReceiptFrame {
            job_id: reader.job_id()?,
            bytes: reader.bytes_u32("receipt", 1, MAX_RECEIPT_BYTES)?,
        }),
        FrameKind::Error => {
            let job_id = match reader.u8()? {
                0 => None,
                1 => Some(reader.job_id()?),
                _ => return Err(ProtocolError::InvalidValue("error job presence")),
            };
            let code = reader.string_u16("error code", 1, MAX_ERROR_CODE_BYTES)?;
            let message = reader.string_u16("error message", 1, MAX_ERROR_MESSAGE_BYTES)?;
            let retryable = match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(ProtocolError::InvalidValue("error retryable")),
            };
            Frame::Error(ErrorFrame {
                job_id,
                code,
                message,
                retryable,
            })
        }
        FrameKind::QueryReceipt => {
            let job_id = reader.job_id()?;
            let profile_id = ProfileId::from_bytes(reader.array()?);
            let profile_generation = reader.u64()?;
            if profile_generation == 0 {
                return Err(ProtocolError::InvalidValue("profile_generation"));
            }
            let query = QueryReceiptFrame {
                job_id,
                profile_id,
                profile_generation,
                policy_digest: Digest32::from_bytes(reader.array()?),
                input_digest: Digest32::from_bytes(reader.array()?),
                receipt_token: Secret32::new(reader.array()?),
            };
            validate_query_receipt(&query)?;
            Frame::QueryReceipt(query)
        }
    };
    reader.finish()?;
    Ok(frame)
}

fn decode_start(reader: &mut PayloadReader<'_>) -> Result<StartFrame, ProtocolError> {
    let job_id = reader.job_id()?;
    let profile_id = ProfileId::from_bytes(reader.array()?);
    let profile_generation = reader.u64()?;
    let policy_digest = Digest32::from_bytes(reader.array()?);
    let input_digest = Digest32::from_bytes(reader.array()?);
    let remote_deadline_unix_ms = reader.u64()?;
    let relay_deadline_unix_ms = reader.u64()?;
    let result_retention_unix_ms = reader.u64()?;
    let run_as_uid = reader.u32()?;
    let max_output_bytes = reader.u64()?;
    let program = reader.string_u16("program", 1, MAX_PROGRAM_BYTES)?;
    let argument_count = reader.u16()? as usize;
    if argument_count > MAX_ARG_COUNT {
        return Err(ProtocolError::InvalidValue("argv count"));
    }
    let mut argv = Vec::with_capacity(argument_count);
    let mut argv_bytes = 0_usize;
    for _ in 0..argument_count {
        let argument = reader.string_u16("argument", 0, MAX_ARG_BYTES)?;
        argv_bytes = argv_bytes.saturating_add(argument.len());
        argv.push(argument);
    }
    if argv_bytes > MAX_ARG_TOTAL_BYTES {
        return Err(ProtocolError::InvalidValue("argv bytes"));
    }
    let environment_count = reader.u16()? as usize;
    if environment_count > MAX_ENV_COUNT {
        return Err(ProtocolError::InvalidValue("environment count"));
    }
    let mut env = Vec::with_capacity(environment_count);
    let mut env_bytes = 0_usize;
    for _ in 0..environment_count {
        let name = reader.string_u16("environment name", 1, MAX_ENV_NAME_BYTES)?;
        if name.contains('=') {
            return Err(ProtocolError::InvalidValue("environment name"));
        }
        let value = reader.string_u16("environment value", 0, MAX_ENV_VALUE_BYTES)?;
        env_bytes = env_bytes
            .saturating_add(name.len())
            .saturating_add(value.len());
        env.push(EnvEntry { name, value });
    }
    if env_bytes > MAX_ENV_TOTAL_BYTES {
        return Err(ProtocolError::InvalidValue("environment bytes"));
    }
    let cwd = match reader.u8()? {
        0 => None,
        1 => Some(reader.string_u16("cwd", 1, MAX_PATH_BYTES)?),
        _ => return Err(ProtocolError::InvalidValue("cwd presence")),
    };
    let policy_json = reader.bytes_u32("policy_json", 1, MAX_POLICY_BYTES)?;
    let receipt_token = Secret32::new(reader.array()?);
    let start = StartFrame {
        job_id,
        profile_id,
        profile_generation,
        policy_digest,
        input_digest,
        remote_deadline_unix_ms,
        relay_deadline_unix_ms,
        result_retention_unix_ms,
        run_as_uid,
        max_output_bytes,
        program,
        argv,
        env,
        cwd,
        policy_json,
        receipt_token,
    };
    validate_start(&start)?;
    Ok(start)
}

fn put_job_id(out: &mut Vec<u8>, job_id: JobId) {
    out.extend_from_slice(job_id.as_bytes());
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes_u32(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ProtocolError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| ProtocolError::FrameTooLarge(bytes.len()))?;
    put_u32(out, length);
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_string_u16(
    out: &mut Vec<u8>,
    field: &'static str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ProtocolError> {
    validate_text(field, value, minimum, maximum)?;
    let length = u16::try_from(value.len()).map_err(|_| ProtocolError::InvalidValue(field))?;
    put_u16(out, length);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ProtocolError> {
    validate_range(field, value.len(), minimum, maximum)?;
    if value.as_bytes().contains(&0) || value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidValue(field));
    }
    Ok(())
}

fn validate_range(
    field: &'static str,
    length: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), ProtocolError> {
    if !(minimum..=maximum).contains(&length) {
        return Err(ProtocolError::InvalidValue(field));
    }
    Ok(())
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> PayloadReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ProtocolError::Truncated)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ProtocolError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProtocolError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn i32(&mut self) -> Result<i32, ProtocolError> {
        Ok(i32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn job_id(&mut self) -> Result<JobId, ProtocolError> {
        Ok(JobId::from_bytes(self.array()?))
    }

    fn bytes_u32(
        &mut self,
        field: &'static str,
        minimum: usize,
        maximum: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        let length = self.u32()? as usize;
        validate_range(field, length, minimum, maximum)?;
        Ok(self.take(length)?.to_vec())
    }

    fn string_u16(
        &mut self,
        field: &'static str,
        minimum: usize,
        maximum: usize,
    ) -> Result<String, ProtocolError> {
        let length = self.u16()? as usize;
        validate_range(field, length, minimum, maximum)?;
        let value =
            std::str::from_utf8(self.take(length)?).map_err(|_| ProtocolError::InvalidUtf8)?;
        validate_text(field, value, minimum, maximum)?;
        Ok(value.to_owned())
    }

    fn remaining_bounded(&mut self, maximum: usize) -> Result<&'a [u8], ProtocolError> {
        let remaining = self.bytes.len().saturating_sub(self.cursor);
        validate_range("remaining payload", remaining, 0, maximum)?;
        self.take(remaining)
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerPhase {
    Hello,
    Ready,
    Running,
    Terminal,
}

/// Strict validator for controller-to-helper frames. It deliberately cannot
/// validate helper output; using the wrong directional validator fails before
/// any state transition.
#[derive(Debug)]
pub struct ControllerSessionValidator {
    next_sequence: u64,
    phase: ControllerPhase,
    job_id: Option<JobId>,
}

impl Default for ControllerSessionValidator {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            phase: ControllerPhase::Hello,
            job_id: None,
        }
    }
}

impl ControllerSessionValidator {
    pub fn validate(&mut self, envelope: &Envelope) -> Result<(), ProtocolError> {
        validate_sequence(self.next_sequence, envelope.sequence)?;
        let next = next_sequence(self.next_sequence)?;
        match (self.phase, &envelope.frame) {
            (ControllerPhase::Hello, Frame::Hello(hello)) if hello.effective_uid == 0 => {
                self.phase = ControllerPhase::Ready;
            }
            (ControllerPhase::Ready, Frame::Start(start)) => {
                self.job_id = Some(start.job_id);
                self.phase = ControllerPhase::Running;
            }
            (ControllerPhase::Ready, Frame::QueryReceipt(query)) => {
                self.job_id = Some(query.job_id);
                self.phase = ControllerPhase::Terminal;
            }
            (ControllerPhase::Running, Frame::Cancel(cancel))
                if self.job_id == Some(cancel.job_id) =>
            {
                self.phase = ControllerPhase::Terminal;
            }
            _ => {
                return Err(ProtocolError::InvalidState(
                    "illegal controller-to-helper frame transition",
                ));
            }
        }
        self.next_sequence = next;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HelperMode {
    Job { max_output_bytes: u64 },
    ReceiptQuery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HelperPhase {
    Hello,
    Streaming,
    ReceiptAuthenticationPending,
    ReceiptAuthenticated,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedTerminal {
    pub outcome: ExitOutcome,
    pub completed_unix_ms: u64,
}

/// Strict validator for helper-to-controller frames. Receipt bytes are not
/// trusted by this framing crate. After a Receipt frame, the caller must verify
/// its MAC and bindings in `serctl-jobs`, then pass the exact bytes and verified
/// terminal fields to `authenticate_receipt` before any Exit can be accepted.
#[derive(Debug)]
pub struct HelperSessionValidator {
    next_sequence: u64,
    phase: HelperPhase,
    mode: HelperMode,
    job_id: JobId,
    stdout_offset: u64,
    stderr_offset: u64,
    heartbeat_ordinal: u64,
    heartbeat_elapsed_ms: u64,
    pending_receipt_digest: Option<[u8; 32]>,
    authenticated_terminal: Option<AuthenticatedTerminal>,
}

impl HelperSessionValidator {
    pub fn for_job(job_id: JobId, max_output_bytes: u64) -> Result<Self, ProtocolError> {
        if max_output_bytes == 0 || max_output_bytes > MAX_OUTPUT_BYTES {
            return Err(ProtocolError::InvalidValue("max_output_bytes"));
        }
        Ok(Self::new(job_id, HelperMode::Job { max_output_bytes }))
    }

    pub fn for_receipt_query(job_id: JobId) -> Self {
        Self::new(job_id, HelperMode::ReceiptQuery)
    }

    fn new(job_id: JobId, mode: HelperMode) -> Self {
        Self {
            next_sequence: 0,
            phase: HelperPhase::Hello,
            mode,
            job_id,
            stdout_offset: 0,
            stderr_offset: 0,
            heartbeat_ordinal: 0,
            heartbeat_elapsed_ms: 0,
            pending_receipt_digest: None,
            authenticated_terminal: None,
        }
    }

    pub fn validate(&mut self, envelope: &Envelope) -> Result<(), ProtocolError> {
        validate_sequence(self.next_sequence, envelope.sequence)?;
        let next = next_sequence(self.next_sequence)?;
        match (self.phase, &envelope.frame) {
            (HelperPhase::Hello, Frame::Hello(hello)) if hello.effective_uid != 0 => {
                if matches!(self.mode, HelperMode::ReceiptQuery)
                    && hello.feature_bits & FEATURE_RECEIPT_QUERY == 0
                {
                    return Err(ProtocolError::InvalidState(
                        "helper does not advertise receipt query support",
                    ));
                }
                self.phase = HelperPhase::Streaming;
            }
            (HelperPhase::Streaming, Frame::Stdout(output))
                if matches!(self.mode, HelperMode::Job { .. }) =>
            {
                self.validate_job(output.job_id)?;
                self.stdout_offset = advance_output_offset(
                    "stdout offset gap or replay",
                    self.stdout_offset,
                    output,
                )?;
                self.validate_output_budget()?;
            }
            (HelperPhase::Streaming, Frame::Stderr(output))
                if matches!(self.mode, HelperMode::Job { .. }) =>
            {
                self.validate_job(output.job_id)?;
                self.stderr_offset = advance_output_offset(
                    "stderr offset gap or replay",
                    self.stderr_offset,
                    output,
                )?;
                self.validate_output_budget()?;
            }
            (HelperPhase::Streaming, Frame::Heartbeat(heartbeat))
                if matches!(self.mode, HelperMode::Job { .. }) =>
            {
                self.validate_job(heartbeat.job_id)?;
                if heartbeat.ordinal <= self.heartbeat_ordinal
                    || heartbeat.elapsed_ms < self.heartbeat_elapsed_ms
                    || heartbeat.stdout_bytes != self.stdout_offset
                    || heartbeat.stderr_bytes != self.stderr_offset
                {
                    return Err(ProtocolError::InvalidState("non-monotonic heartbeat"));
                }
                self.heartbeat_ordinal = heartbeat.ordinal;
                self.heartbeat_elapsed_ms = heartbeat.elapsed_ms;
            }
            (HelperPhase::Streaming, Frame::Receipt(receipt)) => {
                self.validate_job(receipt.job_id)?;
                self.pending_receipt_digest = Some(Sha256::digest(&receipt.bytes).into());
                self.phase = HelperPhase::ReceiptAuthenticationPending;
            }
            (HelperPhase::Streaming, Frame::Error(error)) => {
                if let Some(job_id) = error.job_id {
                    self.validate_job(job_id)?;
                }
                self.phase = HelperPhase::Terminal;
            }
            (HelperPhase::ReceiptAuthenticated, Frame::Exit(exit)) => {
                self.validate_job(exit.job_id)?;
                if self.authenticated_terminal
                    != Some(AuthenticatedTerminal {
                        outcome: exit.outcome,
                        completed_unix_ms: exit.completed_unix_ms,
                    })
                {
                    return Err(ProtocolError::InvalidState(
                        "Exit does not match authenticated receipt",
                    ));
                }
                self.phase = HelperPhase::Terminal;
            }
            _ => {
                return Err(ProtocolError::InvalidState(
                    "illegal helper-to-controller frame transition",
                ));
            }
        }
        self.next_sequence = next;
        Ok(())
    }

    pub fn authenticate_receipt(
        &mut self,
        receipt_bytes: &[u8],
        terminal: AuthenticatedTerminal,
    ) -> Result<(), ProtocolError> {
        if self.phase != HelperPhase::ReceiptAuthenticationPending {
            return Err(ProtocolError::InvalidState(
                "no receipt is pending authentication",
            ));
        }
        let supplied: [u8; 32] = Sha256::digest(receipt_bytes).into();
        if self.pending_receipt_digest != Some(supplied) {
            return Err(ProtocolError::InvalidState(
                "authenticated receipt bytes do not match pending frame",
            ));
        }
        self.pending_receipt_digest = None;
        self.authenticated_terminal = Some(terminal);
        self.phase = HelperPhase::ReceiptAuthenticated;
        Ok(())
    }

    fn validate_job(&self, job_id: JobId) -> Result<(), ProtocolError> {
        if self.job_id == job_id {
            Ok(())
        } else {
            Err(ProtocolError::InvalidState("job identifier mismatch"))
        }
    }

    fn validate_output_budget(&self) -> Result<(), ProtocolError> {
        let HelperMode::Job { max_output_bytes } = self.mode else {
            return Err(ProtocolError::InvalidState("receipt query emitted output"));
        };
        if self.stdout_offset.saturating_add(self.stderr_offset) > max_output_bytes {
            return Err(ProtocolError::InvalidState("output budget exceeded"));
        }
        Ok(())
    }
}

fn validate_sequence(expected: u64, actual: u64) -> Result<(), ProtocolError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ProtocolError::Sequence { expected, actual })
    }
}

fn next_sequence(current: u64) -> Result<u64, ProtocolError> {
    current
        .checked_add(1)
        .ok_or(ProtocolError::InvalidState("sequence exhausted"))
}

fn advance_output_offset(
    error: &'static str,
    expected: u64,
    output: &OutputFrame,
) -> Result<u64, ProtocolError> {
    if output.offset != expected {
        return Err(ProtocolError::InvalidState(error));
    }
    expected
        .checked_add(output.data.len() as u64)
        .ok_or(ProtocolError::InvalidState("output offset overflow"))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_start() -> StartFrame {
        StartFrame {
            job_id: JobId::from_bytes([1; 16]),
            profile_id: ProfileId::from_bytes([2; 16]),
            profile_generation: 7,
            policy_digest: Digest32::from_bytes([3; 32]),
            input_digest: Digest32::from_bytes([4; 32]),
            remote_deadline_unix_ms: 100,
            relay_deadline_unix_ms: 200,
            result_retention_unix_ms: 300,
            run_as_uid: 1000,
            max_output_bytes: 4096,
            program: "printf".to_owned(),
            argv: vec!["%s".to_owned(), "; touch /tmp/pwned".to_owned()],
            env: vec![EnvEntry {
                name: "LANG".to_owned(),
                value: "C".to_owned(),
            }],
            cwd: Some("/srv/app".to_owned()),
            policy_json: br#"{"schema_version":1}"#.to_vec(),
            receipt_token: Secret32::new([9; 32]),
        }
    }

    #[test]
    fn start_round_trip_keeps_arguments_distinct() {
        let encoded = encode(&Envelope {
            sequence: 1,
            frame: Frame::Start(Box::new(sample_start())),
        })
        .unwrap();
        let decoded = decode_exact(&encoded).unwrap();
        let Frame::Start(start) = decoded.frame else {
            panic!("expected start");
        };
        assert_eq!(start.program, "printf");
        assert_eq!(start.argv, ["%s", "; touch /tmp/pwned"]);
        assert_eq!(start.env[0].name, "LANG");
        assert_eq!(start.receipt_token.as_bytes(), &[9; 32]);
    }

    #[test]
    fn raw_output_is_not_base64_encoded() {
        let raw = vec![0, 1, 0xff, b'\n'];
        let encoded = encode(&Envelope {
            sequence: 2,
            frame: Frame::Stdout(OutputFrame {
                job_id: JobId::from_bytes([1; 16]),
                offset: 0,
                data: raw.clone(),
            }),
        })
        .unwrap();
        assert!(encoded.ends_with(&raw));
        let decoded = decode_exact(&encoded).unwrap();
        let Frame::Stdout(output) = decoded.frame else {
            panic!("expected stdout");
        };
        assert_eq!(output.data, raw);
    }

    #[test]
    fn parser_rejects_unknown_version_kind_flags_and_trailing_bytes() {
        let hello = encode(&Envelope {
            sequence: 0,
            frame: Frame::Hello(HelloFrame {
                max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                feature_bits: 0,
                effective_uid: 0,
            }),
        })
        .unwrap();
        let mut invalid = hello.clone();
        invalid[5] = 2;
        assert!(matches!(
            decode_exact(&invalid),
            Err(ProtocolError::UnsupportedVersion(_))
        ));
        invalid = hello.clone();
        invalid[6] = 127;
        assert!(matches!(
            decode_exact(&invalid),
            Err(ProtocolError::UnknownFrameKind(127))
        ));
        invalid = hello.clone();
        invalid[7] = 1;
        assert!(matches!(
            decode_exact(&invalid),
            Err(ProtocolError::ReservedFlags(1))
        ));
        invalid = hello.clone();
        invalid[31] = 0x80;
        assert!(matches!(
            decode_exact(&invalid),
            Err(ProtocolError::InvalidValue("hello feature_bits"))
        ));
        invalid = hello;
        invalid.push(0);
        assert!(matches!(
            decode_exact(&invalid),
            Err(ProtocolError::TrailingBytes)
        ));
    }

    #[test]
    fn parser_rejects_truncation_and_declared_oversize_before_allocation() {
        let encoded = encode(&Envelope {
            sequence: 0,
            frame: Frame::Hello(HelloFrame {
                max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                feature_bits: 0,
                effective_uid: 0,
            }),
        })
        .unwrap();
        assert!(matches!(
            decode_exact(&encoded[..encoded.len() - 1]),
            Err(ProtocolError::Truncated)
        ));
        let mut header = [0_u8; HEADER_BYTES];
        header[..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        header[6] = FrameKind::Start as u8;
        header[16..20].copy_from_slice(&((MAX_FRAME_PAYLOAD as u32) + 1).to_be_bytes());
        assert!(matches!(
            decode_exact(&header),
            Err(ProtocolError::FrameTooLarge(_))
        ));
    }

    #[test]
    fn deterministic_parser_mutation_corpus_is_bounded_and_fail_closed() {
        let valid = encode(&Envelope {
            sequence: 0,
            frame: Frame::Hello(HelloFrame {
                max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                feature_bits: 0,
                effective_uid: 1000,
            }),
        })
        .unwrap();
        assert_eq!(valid.len(), HEADER_BYTES + 16);

        let mut corpus: Vec<(&str, Vec<u8>)> = (0..valid.len())
            .map(|prefix_len| ("truncated_prefix", valid[..prefix_len].to_vec()))
            .collect();

        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 0xff;
        corpus.push(("bad_magic", bad_magic));

        let mut unknown_version = valid.clone();
        unknown_version[4..6].copy_from_slice(&(PROTOCOL_VERSION + 1).to_be_bytes());
        corpus.push(("unknown_version", unknown_version));

        let mut unknown_kind = valid.clone();
        unknown_kind[6] = 0xff;
        corpus.push(("unknown_kind", unknown_kind));

        let mut unknown_flags = valid.clone();
        unknown_flags[7] = 1;
        corpus.push(("unknown_flags", unknown_flags));

        let mut declared_u32_max = valid[..HEADER_BYTES].to_vec();
        declared_u32_max[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        corpus.push(("declared_u32_max", declared_u32_max));

        let mut kind_limit_exceeded = valid[..HEADER_BYTES].to_vec();
        kind_limit_exceeded[16..20].copy_from_slice(&17_u32.to_be_bytes());
        corpus.push(("hello_kind_limit_exceeded", kind_limit_exceeded));

        let declared = u32::from_be_bytes(valid[16..20].try_into().unwrap());
        let mut declared_long = valid.clone();
        declared_long[16..20].copy_from_slice(&(declared + 1).to_be_bytes());
        corpus.push(("declared_body_longer_than_input", declared_long));

        let mut declared_short = valid.clone();
        declared_short[16..20].copy_from_slice(&(declared - 1).to_be_bytes());
        corpus.push(("declared_body_shorter_than_input", declared_short));

        let mut trailing = valid;
        trailing.push(0);
        corpus.push(("trailing_byte", trailing));

        for (index, (name, mutation)) in corpus.into_iter().enumerate() {
            let outcome = std::panic::catch_unwind(|| decode_exact(&mutation));
            assert!(outcome.is_ok(), "mutation #{index} '{name}' panicked");
            assert!(
                outcome.unwrap().is_err(),
                "mutation #{index} '{name}' was accepted"
            );
        }

        let mut oversized_reader = std::io::Cursor::new({
            let mut header = [0_u8; HEADER_BYTES];
            header[..4].copy_from_slice(&MAGIC);
            header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
            header[6] = FrameKind::Start as u8;
            header[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
            header
        });
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            read_frame_from(&mut oversized_reader)
        }));
        assert!(
            outcome.is_ok(),
            "streaming oversized-length rejection panicked"
        );
        assert!(matches!(
            outcome.unwrap(),
            Err(ProtocolError::FrameTooLarge(_))
        ));
        assert_eq!(oversized_reader.position(), HEADER_BYTES as u64);
    }

    #[test]
    fn deterministic_session_mutations_reject_sequence_offset_gap_and_replay() {
        let job_id = JobId::from_bytes([1; 16]);
        let mut validator = HelperSessionValidator::for_job(job_id, 4096).unwrap();
        validator
            .validate(&Envelope {
                sequence: 0,
                frame: Frame::Hello(HelloFrame {
                    max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                    feature_bits: 0,
                    effective_uid: 1000,
                }),
            })
            .unwrap();
        validator
            .validate(&Envelope {
                sequence: 1,
                frame: Frame::Stdout(OutputFrame {
                    job_id,
                    offset: 0,
                    data: vec![1, 2],
                }),
            })
            .unwrap();

        for offset in [0, 3] {
            assert!(matches!(
                validator.validate(&Envelope {
                    sequence: 2,
                    frame: Frame::Stdout(OutputFrame {
                        job_id,
                        offset,
                        data: vec![3],
                    }),
                }),
                Err(ProtocolError::InvalidState("stdout offset gap or replay"))
            ));
        }

        validator
            .validate(&Envelope {
                sequence: 2,
                frame: Frame::Stdout(OutputFrame {
                    job_id,
                    offset: 2,
                    data: vec![3],
                }),
            })
            .unwrap();
        for sequence in [2, 4] {
            assert!(matches!(
                validator.validate(&Envelope {
                    sequence,
                    frame: Frame::Heartbeat(HeartbeatFrame {
                        job_id,
                        ordinal: 1,
                        elapsed_ms: 1,
                        stdout_bytes: 3,
                        stderr_bytes: 0,
                    }),
                }),
                Err(ProtocolError::Sequence {
                    expected: 3,
                    actual
                }) if actual == sequence
            ));
        }
    }

    #[test]
    fn parser_rejects_invalid_utf8_and_collection_overflow() {
        let mut encoded = encode(&Envelope {
            sequence: 1,
            frame: Frame::Start(Box::new(sample_start())),
        })
        .unwrap();
        // Program starts after the fixed 140-byte Start prefix and its u16 length.
        let program_start = HEADER_BYTES + 140 + 2;
        encoded[program_start] = 0xff;
        assert!(matches!(
            decode_exact(&encoded),
            Err(ProtocolError::InvalidUtf8)
        ));

        let mut start = sample_start();
        start.argv = (0..=MAX_ARG_COUNT).map(|_| "x".to_owned()).collect();
        assert!(matches!(
            encode(&Envelope {
                sequence: 1,
                frame: Frame::Start(Box::new(start)),
            }),
            Err(ProtocolError::InvalidValue("argv count"))
        ));
    }

    #[test]
    fn validator_rejects_replay_gaps_and_output_offset_gaps() {
        let hello = Envelope {
            sequence: 0,
            frame: Frame::Hello(HelloFrame {
                max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                feature_bits: 0,
                effective_uid: 0,
            }),
        };
        let mut validator = ControllerSessionValidator::default();
        validator.validate(&hello).unwrap();
        assert!(matches!(
            validator.validate(&hello),
            Err(ProtocolError::Sequence {
                expected: 1,
                actual: 0
            })
        ));

        let mut validator =
            HelperSessionValidator::for_job(JobId::from_bytes([1; 16]), 4096).unwrap();
        validator
            .validate(&Envelope {
                sequence: 0,
                frame: Frame::Hello(HelloFrame {
                    max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                    feature_bits: 0,
                    effective_uid: 1000,
                }),
            })
            .unwrap();
        assert!(matches!(
            validator.validate(&Envelope {
                sequence: 1,
                frame: Frame::Stdout(OutputFrame {
                    job_id: JobId::from_bytes([1; 16]),
                    offset: 9,
                    data: vec![1],
                }),
            }),
            Err(ProtocolError::InvalidState("stdout offset gap or replay"))
        ));
    }

    #[test]
    fn heartbeat_is_strictly_monotonic() {
        let mut validator =
            HelperSessionValidator::for_job(JobId::from_bytes([1; 16]), 4096).unwrap();
        validator
            .validate(&Envelope {
                sequence: 0,
                frame: Frame::Hello(HelloFrame {
                    max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                    feature_bits: 0,
                    effective_uid: 1000,
                }),
            })
            .unwrap();
        validator
            .validate(&Envelope {
                sequence: 1,
                frame: Frame::Heartbeat(HeartbeatFrame {
                    job_id: JobId::from_bytes([1; 16]),
                    ordinal: 1,
                    elapsed_ms: 10,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                }),
            })
            .unwrap();
        assert!(matches!(
            validator.validate(&Envelope {
                sequence: 2,
                frame: Frame::Heartbeat(HeartbeatFrame {
                    job_id: JobId::from_bytes([1; 16]),
                    ordinal: 1,
                    elapsed_ms: 11,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                }),
            }),
            Err(ProtocolError::InvalidState("non-monotonic heartbeat"))
        ));
    }

    #[test]
    fn receipt_query_is_fixed_identity_and_token_proof_only() {
        let envelope = Envelope {
            sequence: 1,
            frame: Frame::QueryReceipt(QueryReceiptFrame {
                job_id: JobId::from_bytes([1; 16]),
                profile_id: ProfileId::from_bytes([2; 16]),
                profile_generation: 7,
                policy_digest: Digest32::from_bytes([3; 32]),
                input_digest: Digest32::from_bytes([4; 32]),
                receipt_token: Secret32::new([5; 32]),
            }),
        };
        let encoded = encode(&envelope).unwrap();
        let decoded = decode_exact(&encoded).unwrap();
        let Frame::QueryReceipt(query) = decoded.frame else {
            panic!("expected receipt query");
        };
        assert_eq!(query.job_id, JobId::from_bytes([1; 16]));
        assert_eq!(query.profile_generation, 7);
        assert_eq!(query.receipt_token.as_bytes(), &[5; 32]);

        let mut validator = ControllerSessionValidator::default();
        validator
            .validate(&Envelope {
                sequence: 0,
                frame: Frame::Hello(HelloFrame {
                    max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                    feature_bits: 0,
                    effective_uid: 0,
                }),
            })
            .unwrap();
        validator.validate(&envelope).unwrap();
    }

    #[test]
    fn directional_validators_reject_frames_from_the_other_direction() {
        let job_id = JobId::from_bytes([1; 16]);
        let mut controller = ControllerSessionValidator::default();
        controller
            .validate(&Envelope {
                sequence: 0,
                frame: Frame::Hello(HelloFrame {
                    max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                    feature_bits: 0,
                    effective_uid: 0,
                }),
            })
            .unwrap();
        assert!(matches!(
            controller.validate(&Envelope {
                sequence: 1,
                frame: Frame::Stdout(OutputFrame {
                    job_id,
                    offset: 0,
                    data: vec![1],
                }),
            }),
            Err(ProtocolError::InvalidState(
                "illegal controller-to-helper frame transition"
            ))
        ));

        let mut helper = HelperSessionValidator::for_job(job_id, 4096).unwrap();
        helper
            .validate(&Envelope {
                sequence: 0,
                frame: Frame::Hello(HelloFrame {
                    max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                    feature_bits: FEATURE_CANCEL | FEATURE_RECEIPT_QUERY,
                    effective_uid: 1000,
                }),
            })
            .unwrap();
        assert!(matches!(
            helper.validate(&Envelope {
                sequence: 1,
                frame: Frame::Start(Box::new(sample_start())),
            }),
            Err(ProtocolError::InvalidState(
                "illegal helper-to-controller frame transition"
            ))
        ));
    }

    #[test]
    fn exit_is_rejected_until_exact_receipt_bytes_are_authenticated() {
        let job_id = JobId::from_bytes([1; 16]);
        let receipt_bytes = b"authenticated receipt".to_vec();
        let terminal = AuthenticatedTerminal {
            outcome: ExitOutcome::Exited(0),
            completed_unix_ms: 1234,
        };
        let mut validator = HelperSessionValidator::for_job(job_id, 4096).unwrap();
        validator
            .validate(&Envelope {
                sequence: 0,
                frame: Frame::Hello(HelloFrame {
                    max_frame_payload: MAX_FRAME_PAYLOAD as u32,
                    feature_bits: FEATURE_CANCEL | FEATURE_RECEIPT_QUERY,
                    effective_uid: 1000,
                }),
            })
            .unwrap();
        validator
            .validate(&Envelope {
                sequence: 1,
                frame: Frame::Receipt(ReceiptFrame {
                    job_id,
                    bytes: receipt_bytes.clone(),
                }),
            })
            .unwrap();

        let exit = || Envelope {
            sequence: 2,
            frame: Frame::Exit(ExitFrame {
                job_id,
                outcome: ExitOutcome::Exited(0),
                completed_unix_ms: 1234,
            }),
        };
        assert!(validator.validate(&exit()).is_err());
        assert!(validator
            .authenticate_receipt(b"wrong receipt", terminal)
            .is_err());
        validator
            .authenticate_receipt(&receipt_bytes, terminal)
            .unwrap();

        assert!(validator
            .validate(&Envelope {
                sequence: 2,
                frame: Frame::Exit(ExitFrame {
                    job_id,
                    outcome: ExitOutcome::Exited(1),
                    completed_unix_ms: 1234,
                }),
            })
            .is_err());
        validator.validate(&exit()).unwrap();
    }
}
