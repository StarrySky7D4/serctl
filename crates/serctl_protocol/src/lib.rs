//! Authenticated local IPC with one framing protocol over Windows named pipes
//! or Unix domain sockets.
//!
//! Two wire generations exist side by side during the Phase 2 migration:
//! - v5 (this crate's historical per-profile protocol) remains the default
//!   until the daemon/CLI cut over;
//! - [`v6`] is the per-user/per-vault global-daemon protocol: per-boot
//!   activation-secret mutual authentication, HKDF direction keys, and
//!   ChaCha20-Poly1305 AEAD frames with strict sequence counters.
pub mod grant;
pub mod v6;
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

pub const IPC_PROTOCOL_VERSION: u16 = 5;
pub const MAX_FRAME: usize = 64 * 1024 * 1024;
pub const MAX_AUTH_FRAME: usize = 4 * 1024;
pub const MAX_CONTROL_FRAME: usize = 16 * 1024;
pub const MAX_REQUEST_FRAME: usize = 512 * 1024;
pub const MAX_UPLOAD_FRAME: usize = 128 * 1024;
pub const MAX_SHELL_FRAME: usize = 128 * 1024;
pub const MAX_RESPONSE_FRAME: usize = 16 * 1024 * 1024;
/// Largest file-data payload carried by one local IPC frame for the native
/// transfer backend. This is deliberately independent from the much smaller
/// SFTP safety cap: native frames have their own bounded parser, per-chunk
/// digest, and cumulative helper acknowledgement.
pub const NATIVE_IPC_CHUNK_BYTES: usize = 32 * 1024;
pub const MAX_COMMAND_OUTPUT: usize = 8 * 1024 * 1024;
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 5 * 60 * 1000;
pub const MAX_EXEC_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_SFTP_TIMEOUT_MS: u64 = 5 * 60 * 1000;
pub const MAX_SFTP_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_TRANSFER_IDLE_TIMEOUT_MS: u64 = 30 * 1000;
pub const TRANSFER_PROGRESS_SCHEMA_VERSION: u16 = 1;
pub const TUNNEL_STATUS_SCHEMA_VERSION: u16 = 1;
pub const SFTP_SAFE_CHUNK_BYTES: usize = 2 * 1024;
pub const NATIVE_HELPER_BINARY_NAME: &str = "serctl-xfer";
pub const NATIVE_HELPER_PROTOCOL_VERSION: u16 = 1;
pub const MAX_NATIVE_HELPER_BINARY_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_NATIVE_HELPER_VERSION_BYTES: usize = 256;

fn default_exec_timeout_ms() -> u64 {
    DEFAULT_EXEC_TIMEOUT_MS
}

fn default_sftp_timeout_ms() -> u64 {
    DEFAULT_SFTP_TIMEOUT_MS
}

fn default_transfer_idle_timeout_ms() -> u64 {
    DEFAULT_TRANSFER_IDLE_TIMEOUT_MS
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// Opaque, random identifier for one transfer. It is deliberately unrelated
/// to a path, profile name, or credential so progress snapshots can be shown
/// without disclosing sensitive request fields.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TransferId(String);

impl<'de> Deserialize<'de> for TransferId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Opaque daemon-authenticated binding for one accepted operation. The value
/// is derived by the daemon from a private per-boot key and canonical request,
/// profile, connection-attempt, and object material; callers may only echo it
/// back for scoped status/cancellation requests.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OperationContextId(String);

impl<'de> Deserialize<'de> for OperationContextId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl OperationContextId {
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "operation context id must contain 64 lowercase hex characters"
        );
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Zeroize for OperationContextId {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl TransferId {
    pub fn random() -> Self {
        let mut bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            value.len() == 32,
            "transfer id must contain 32 lowercase hex characters"
        );
        ensure!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "transfer id must contain 32 lowercase hex characters"
        );
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque daemon-instance-local identifier for one managed tunnel. It never
/// contains a profile name, endpoint, or credential-derived material.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TunnelId(String);

impl<'de> Deserialize<'de> for TunnelId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl TunnelId {
    pub fn random() -> Self {
        let mut bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "tunnel id must contain 32 lowercase hex characters"
        );
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Push,
    Pull,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStage {
    Preflight,
    Hash,
    Negotiating,
    Transferring,
    Verifying,
    Committing,
    Cleanup,
    Completed,
    Failed,
    Cancelled,
    Stalled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferBackend {
    Auto,
    Native,
    Sftp,
    SftpFallback,
}

/// Exact public identity expected from the fixed Linux native-transfer helper.
///
/// This record is part of the authenticated transfer root request. Formal
/// runners may populate it only from the verified downloaded Linux platform
/// provenance; it is never a path from which the daemon reads bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedNativeHelperIdentity {
    pub name: String,
    pub binary_size: u64,
    pub sha256: String,
    pub version: String,
}

impl ExpectedNativeHelperIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.name == NATIVE_HELPER_BINARY_NAME,
            "expected native helper name mismatch"
        );
        ensure!(
            (1..=MAX_NATIVE_HELPER_BINARY_BYTES).contains(&self.binary_size),
            "expected native helper binary size is invalid"
        );
        ensure!(
            self.sha256.len() == 64
                && self
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "expected native helper SHA-256 must contain 64 lowercase hex characters"
        );
        ensure!(
            !self.version.is_empty()
                && self.version.len() <= MAX_NATIVE_HELPER_VERSION_BYTES
                && self.version.is_ascii()
                && !self.version.bytes().any(|byte| byte.is_ascii_control()),
            "expected native helper version identity is invalid"
        );
        let prefix = format!("{NATIVE_HELPER_BINARY_NAME} ");
        let suffix = format!("; transfer protocol v{NATIVE_HELPER_PROTOCOL_VERSION})");
        let body = self
            .version
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(&suffix))
            .context("expected native helper version identity grammar mismatch")?;
        let (release_version, commit) = body
            .split_once(" (git ")
            .context("expected native helper version identity grammar mismatch")?;
        ensure!(
            !release_version.is_empty()
                && release_version.len() <= 64
                && release_version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')),
            "expected native helper release version is invalid"
        );
        let commit_hex = commit.strip_suffix("-dirty").unwrap_or(commit);
        ensure!(
            commit_hex.len() == 12
                && commit_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "expected native helper commit identity is invalid"
        );
        Ok(())
    }
}

impl Zeroize for ExpectedNativeHelperIdentity {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.binary_size.zeroize();
        self.sha256.zeroize();
        self.version.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferResumeMode {
    Auto,
    Never,
}

/// Sanitized cumulative progress. `confirmed_bytes` advances only after the
/// receiver has acknowledged the corresponding bytes. The client fills in
/// rate and ETA fields from monotonic observations; daemon snapshots keep
/// those fields at zero/None.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferProgress {
    pub schema_version: u16,
    pub event: String,
    pub transfer_id: TransferId,
    /// Present for Grant-backed operations after the daemon has accepted the
    /// root intent against an authenticated SSH transport. Direct interactive
    /// profile operations intentionally remain compatible with `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_context_id: Option<OperationContextId>,
    /// Daemon-owned monotonic revision of this retained transfer snapshot.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub revision: u64,
    pub direction: TransferDirection,
    pub stage: TransferStage,
    pub total_bytes: u64,
    pub confirmed_bytes: u64,
    pub durable_bytes: u64,
    pub window_bps: f64,
    pub average_bps: f64,
    pub eta_ms: Option<u64>,
    pub backend: TransferBackend,
    /// Negotiated payload size. Zero means negotiation has not completed.
    pub chunk_bytes: u32,
    /// Maximum remotely outstanding payload bytes. Zero means unknown.
    pub window_bytes: u32,
    pub updated_unix_ms: u64,
}

impl TransferProgress {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == TRANSFER_PROGRESS_SCHEMA_VERSION,
            "unsupported transfer progress schema version"
        );
        ensure!(
            self.confirmed_bytes <= self.total_bytes,
            "confirmed bytes exceed total"
        );
        ensure!(
            self.durable_bytes <= self.confirmed_bytes,
            "durable bytes exceed confirmed"
        );
        ensure!(
            self.operation_context_id.is_none() || self.revision > 0,
            "context-bound transfer progress requires a positive revision"
        );
        ensure!(
            self.window_bps.is_finite() && self.window_bps >= 0.0,
            "window rate must be finite and non-negative"
        );
        ensure!(
            self.average_bps.is_finite() && self.average_bps >= 0.0,
            "average rate must be finite and non-negative"
        );
        ensure!(
            !self.event.is_empty()
                && self.event.len() <= 64
                && !self.event.chars().any(char::is_control),
            "transfer progress event is invalid"
        );
        Ok(())
    }
}

/// Validate a profile name that can appear in a local IPC endpoint or lock
/// record. This rule is shared by the CLI, the daemon, and the vault, so it
/// lives in the wire crate rather than in any one owner.
pub fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        bail!("profile name must contain 1 to 128 bytes");
    }
    if name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
    {
        bail!("profile name contains unsafe path characters");
    }
    Ok(())
}

/// Aggregate cap shared by every tunnel on one SSH transport.
pub const DEFAULT_TUNNEL_CONNECTIONS: usize = 32;
pub const MAX_TUNNEL_CONNECTIONS: usize = 128;
/// Longest host name the wire format accepts in a tunnel request.
pub const MAX_TUNNEL_HOST_BYTES: usize = 255;

fn default_tunnel_connections_u16() -> u16 {
    DEFAULT_TUNNEL_CONNECTIONS as u16
}

/// The SSH forwarding primitive used by a tunnel.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    Local,
    Remote,
    Dynamic,
}

/// A validated-at-startup SSH tunnel request.
///
/// Addresses are deliberately absent from this public type: local and dynamic
/// listeners bind only to IPv4 loopback, remote listeners ask the SSH server
/// to bind only to IPv4 loopback, and fixed L/R targets are IPv4 loopback on
/// the opposite side of the SSH connection. This makes external exposure
/// impossible to request through the CLI, UI, or IPC wire format.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelSpec {
    pub mode: TunnelMode,
    pub bind_port: u16,
    #[serde(default)]
    pub target_port: u16,
    #[serde(default = "default_tunnel_connections_u16")]
    pub max_connections: u16,
}

impl TunnelSpec {
    /// Test constructor; the real CLI/UI builds the struct directly.
    #[doc(hidden)]
    pub fn local(bind_port: u16, target_port: u16) -> Self {
        Self {
            mode: TunnelMode::Local,
            bind_port,
            target_port,
            max_connections: DEFAULT_TUNNEL_CONNECTIONS as u16,
        }
    }

    /// Test constructor; the real CLI/UI builds the struct directly.
    #[doc(hidden)]
    pub fn remote(bind_port: u16, target_port: u16) -> Self {
        Self {
            mode: TunnelMode::Remote,
            bind_port,
            target_port,
            max_connections: DEFAULT_TUNNEL_CONNECTIONS as u16,
        }
    }

    /// Test constructor; the real CLI/UI builds the struct directly.
    #[doc(hidden)]
    pub fn dynamic(bind_port: u16) -> Self {
        Self {
            mode: TunnelMode::Dynamic,
            bind_port,
            target_port: 0,
            max_connections: DEFAULT_TUNNEL_CONNECTIONS as u16,
        }
    }

    pub fn mode(&self) -> TunnelMode {
        self.mode
    }

    pub fn validate(&self) -> Result<()> {
        ValidatedTunnelSpec::try_from(self.clone()).map(drop)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TunnelReady {
    pub mode: TunnelMode,
    pub bind_host: String,
    pub bind_port: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelStage {
    Ready,
    Cancelling,
    Closed,
    Unknown,
}

/// Sanitized snapshot for a daemon-managed tunnel. Both exposed endpoints are
/// mechanically restricted to IPv4 loopback; no remote host or profile name
/// is carried in a status response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelStatus {
    pub schema_version: u16,
    pub tunnel_id: TunnelId,
    pub profile_id: String,
    pub profile_generation: u64,
    pub mode: TunnelMode,
    pub bind_host: String,
    pub bind_port: u16,
    pub target_host: Option<String>,
    pub target_port: u16,
    pub deadline_unix_ms: u64,
    pub stage: TunnelStage,
    pub updated_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_context_id: Option<OperationContextId>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub revision: u64,
}

impl TunnelStatus {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == TUNNEL_STATUS_SCHEMA_VERSION,
            "unsupported tunnel status schema version"
        );
        TunnelId::parse(self.tunnel_id.as_str())?;
        ensure!(
            self.profile_id.len() == 32
                && self
                    .profile_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "tunnel profile id must contain 32 lowercase hex characters"
        );
        ensure!(
            self.profile_generation > 0,
            "tunnel profile generation is invalid"
        );
        ensure!(
            self.bind_host == "127.0.0.1",
            "tunnel bind host must be IPv4 loopback"
        );
        ensure!(self.bind_port > 0, "tunnel bind port must be non-zero");
        match self.mode {
            TunnelMode::Local | TunnelMode::Remote => {
                ensure!(
                    self.target_host.as_deref() == Some("127.0.0.1"),
                    "fixed tunnel target host must be IPv4 loopback"
                );
                ensure!(
                    self.target_port > 0,
                    "fixed tunnel target port must be non-zero"
                );
            }
            TunnelMode::Dynamic => {
                ensure!(
                    self.target_host.is_none(),
                    "dynamic tunnel has no fixed target host"
                );
                ensure!(
                    self.target_port == 0,
                    "dynamic tunnel has no fixed target port"
                );
            }
        }
        ensure!(self.deadline_unix_ms > 0, "tunnel deadline is invalid");
        ensure!(self.updated_unix_ms > 0, "tunnel update time is invalid");
        ensure!(
            self.operation_context_id.is_some() == (self.revision > 0),
            "tunnel operation context and revision must appear together"
        );
        Ok(())
    }
}

/// One directory listing entry transferred over the IPC wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified_unix: Option<u32>,
}

/// The loopback-only validated form of a [`TunnelSpec`].
#[derive(Clone, Debug)]
pub enum ValidatedTunnelSpec {
    Local {
        bind: std::net::SocketAddr,
        target_port: u16,
        max_connections: usize,
    },
    Remote {
        bind_port: u16,
        target_port: u16,
        max_connections: usize,
    },
    Dynamic {
        bind: std::net::SocketAddr,
        max_connections: usize,
    },
}

fn validate_tunnel_connections(max_connections: usize) -> Result<()> {
    ensure!(
        (1..=MAX_TUNNEL_CONNECTIONS).contains(&max_connections),
        "tunnel connection limit must be between 1 and {MAX_TUNNEL_CONNECTIONS}"
    );
    Ok(())
}

fn tunnel_loopback_addr(port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], port))
}

impl TryFrom<TunnelSpec> for ValidatedTunnelSpec {
    type Error = anyhow::Error;

    fn try_from(spec: TunnelSpec) -> Result<Self> {
        let TunnelSpec {
            mode,
            bind_port,
            target_port,
            max_connections,
        } = spec;
        let max_connections = usize::from(max_connections);
        validate_tunnel_connections(max_connections)?;
        match mode {
            TunnelMode::Local => {
                ensure!(
                    target_port != 0,
                    "local-forward target port must not be zero"
                );
                Ok(Self::Local {
                    bind: tunnel_loopback_addr(bind_port),
                    target_port,
                    max_connections,
                })
            }
            TunnelMode::Remote => {
                ensure!(
                    target_port != 0,
                    "remote-forward target port must not be zero"
                );
                Ok(Self::Remote {
                    bind_port,
                    target_port,
                    max_connections,
                })
            }
            TunnelMode::Dynamic => {
                ensure!(
                    target_port == 0,
                    "dynamic forwarding target port must be zero"
                );
                Ok(Self::Dynamic {
                    bind: tunnel_loopback_addr(bind_port),
                    max_connections,
                })
            }
        }
    }
}

const ENDPOINT_DOMAIN: &[u8] = b"serctl/ipc/endpoint/v5\0";
const SERVER_PROOF_DOMAIN: &[u8] = b"serctl/ipc/auth/server-token/v5\0";
const CLIENT_PROOF_DOMAIN: &[u8] = b"serctl/ipc/auth/client-token/v5\0";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"serctl/ipc/request-intent/v5\0";
const INTENT_COMMITMENT_DOMAIN: &[u8] = b"serctl/ipc/intent-commitment/v5\0";
const SERVER_CALL_PROOF_DOMAIN: &[u8] = b"serctl/ipc/auth/server-call/v5\0";
const CLIENT_CALL_PROOF_DOMAIN: &[u8] = b"serctl/ipc/auth/client-call/v5\0";

/// Encode binary frame fields once as canonical Base64 instead of serde's
/// default integer arrays. Besides shrinking the wire representation, this
/// makes the byte-based frame limits meaningful for arbitrary binary data.
mod base64_bytes {
    use super::B64;
    use base64::Engine;
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};
    use zeroize::{Zeroize, Zeroizing};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = Zeroizing::new(B64.encode(bytes));
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        let mut decoded = B64.decode(encoded.as_bytes()).map_err(D::Error::custom)?;
        let canonical = Zeroizing::new(B64.encode(decoded.as_slice()));
        if canonical.as_bytes() != encoded.as_bytes() {
            decoded.zeroize();
            return Err(D::Error::custom(
                "binary frame payload must use canonical padded Base64",
            ));
        }
        Ok(decoded)
    }
}

fn endpoint_id(profile: &str, token: &str) -> Result<String> {
    validate_profile_name(profile)?;
    let token = decode_base64_32("IPC token", token)?;
    Ok(endpoint_id_with_token(profile, &token))
}

fn endpoint_id_with_token(profile: &str, token: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(ENDPOINT_DOMAIN);
    digest.update(IPC_PROTOCOL_VERSION.to_be_bytes());
    digest.update((profile.len() as u32).to_be_bytes());
    digest.update(profile.as_bytes());
    digest.update(token);
    // 128 bits keeps the platform endpoint compact (Unix socket paths have a
    // small OS-defined limit). Authentication still requires the full
    // 256-bit capability and never sends it on the wire.
    hex::encode(digest.finalize())[..32].to_owned()
}

/// Derive an endpoint without touching directory metadata. Callers must pass a
/// runtime directory they already validated through `vault::run_dir`; this is
/// used by stale-lock cleanup to keep filesystem-security failures distinct
/// from malformed v5 lock contents. On Windows the runtime directory is unused
/// because the endpoint is a named-pipe path.
#[cfg(unix)]
pub fn expected_endpoint_in_runtime_dir(
    profile: &str,
    token: &str,
    runtime_dir: &std::path::Path,
) -> Result<String> {
    let id = endpoint_id(profile, token)?;
    let path = runtime_dir.join(format!("serctl-v5-{id}.sock"));
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("serctl runtime path is not valid UTF-8"))
}

#[cfg(windows)]
pub fn expected_endpoint_in_runtime_dir(
    profile: &str,
    token: &str,
    _runtime_dir: &std::path::Path,
) -> Result<String> {
    let id = endpoint_id(profile, token)?;
    Ok(format!(r"\\.\pipe\serctl-v5-{id}"))
}

#[cfg(not(any(unix, windows)))]
pub fn expected_endpoint_in_runtime_dir(
    _profile: &str,
    _token: &str,
    _runtime_dir: &std::path::Path,
) -> Result<String> {
    bail!("local IPC endpoints are unsupported on this platform")
}

/// Verify that a recorded endpoint equals the endpoint derived for the given
/// profile/token pair under the given (already validated) runtime directory.
pub fn validate_endpoint_in_runtime_dir(
    profile: &str,
    token: &str,
    runtime_dir: &std::path::Path,
    endpoint: &str,
) -> Result<()> {
    let expected = expected_endpoint_in_runtime_dir(profile, token, runtime_dir)?;
    validate_endpoint_bytes(&expected, endpoint)
}

pub fn validate_endpoint_bytes(expected: &str, endpoint: &str) -> Result<()> {
    if endpoint.as_bytes() != expected.as_bytes() {
        bail!("runtime lock contains an unexpected local IPC endpoint");
    }
    Ok(())
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
    pub fn bind(endpoint: &str) -> Result<Self> {
        let endpoint = endpoint.to_owned();
        let pending = create_named_pipe_instance(&endpoint, true)?;
        Ok(Self { endpoint, pending })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn accept(&mut self) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        self.pending.connect().await?;
        let next = create_named_pipe_instance(&self.endpoint, false)?;
        Ok(std::mem::replace(&mut self.pending, next))
    }
}

#[cfg(windows)]
const PIPE_SECURITY_SDDL: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)";

#[cfg(windows)]
struct LocalSecurityDescriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl LocalSecurityDescriptor {
    fn owner_only_pipe() -> Result<Self> {
        use std::ptr::null_mut;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };

        let wide = PIPE_SECURITY_SDDL
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(std::io::Error::last_os_error())
                .context("create named-pipe security descriptor");
        }
        Ok(Self(descriptor))
    }
}

#[cfg(windows)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0);
        }
    }
}

#[cfg(windows)]
fn create_named_pipe_instance(
    endpoint: &str,
    first: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ffi::c_void;
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let descriptor = LocalSecurityDescriptor::owner_only_pipe()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    let pipe = unsafe {
        options.create_with_security_attributes_raw(
            endpoint,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
    .with_context(|| format!("create named pipe {endpoint}"))?;
    Ok(pipe)
}

#[cfg(unix)]
impl LocalListener {
    /// Bind a Unix-domain socket at `endpoint`. The caller owns the runtime
    /// directory and applies the platform permission hardening through
    /// `serctl_core::security::harden_file` after the bind succeeds.
    pub fn bind(endpoint: &str) -> Result<Self> {
        let endpoint = endpoint.to_owned();
        let path = std::path::Path::new(&endpoint);
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove stale Unix socket"),
        }
        let listener = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("bind Unix socket {endpoint}"))?;
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

/// Validate that a connected client stream terminates at the daemon recorded
/// in the protected runtime lock. This is an identity cross-check in addition
/// to the cryptographic handshake, not a replacement for it. Unix targets
/// whose socket credential API cannot expose the peer PID fail closed.
#[cfg(windows)]
pub fn validate_server_identity(stream: &ClientStream, expected_pid: u32) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let mut actual_pid = 0_u32;
    let ok = unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle() as _, &mut actual_pid) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("query named-pipe server process");
    }
    if actual_pid == 0 || actual_pid != expected_pid {
        bail!("named-pipe server PID does not match the protected runtime lock");
    }
    Ok(())
}

#[cfg(unix)]
pub fn validate_server_identity(stream: &ClientStream, expected_pid: u32) -> Result<()> {
    let credentials = stream
        .peer_cred()
        .context("query Unix-socket peer credentials")?;
    let effective_uid = unsafe { libc::geteuid() };
    validate_unix_peer_identity(
        credentials.uid() as u64,
        credentials.pid().map(|pid| pid as i64),
        effective_uid as u64,
        expected_pid,
    )
}

#[cfg(any(unix, test))]
fn validate_unix_peer_identity(
    actual_uid: u64,
    actual_pid: Option<i64>,
    expected_uid: u64,
    expected_pid: u32,
) -> Result<()> {
    if actual_uid != expected_uid {
        bail!("Unix-socket peer is not owned by the current user");
    }

    // Some Unix targets can authenticate a socket peer's UID but cannot
    // expose its PID. UID-only acceptance would let another process owned by
    // the same account impersonate the daemon, so unsupported targets fail
    // closed instead of silently weakening the runtime-lock identity check.
    let actual_pid = actual_pid.context("Unix-socket peer PID is unavailable on this platform")?;
    let actual_pid =
        u32::try_from(actual_pid).context("Unix-socket peer returned an invalid process ID")?;
    if actual_pid == 0 || actual_pid != expected_pid {
        bail!("Unix-socket peer PID does not match the protected runtime lock");
    }
    Ok(())
}

pub fn endpoint_kind() -> &'static str {
    #[cfg(windows)]
    return "named-pipe";
    #[cfg(unix)]
    return "unix-socket";
    #[allow(unreachable_code)]
    "unsupported"
}

/// Sanitized profile catalog row transferred over the v6 wire: identity and
/// connection metadata only, never secrets.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireProfile {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub generation: u64,
    /// Lowercase hex of the 16-byte profile id.
    pub profile_id: String,
}

pub const MAX_SSH_SERVER_IDENTIFICATION_BYTES: usize = 128;

/// Closed, bounded identity of one authenticated SSH transport. This type
/// intentionally has no endpoint, username, path, pre-banner, or raw-banner
/// field.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SshConnectionIdentity {
    pub profile_id: [u8; 16],
    pub profile_generation: u64,
    pub observed_host_key_sha256: String,
    pub pin_match: bool,
    pub server_identification: String,
    pub transport_attempt_id: String,
    /// Present only for a Grant-backed accepted root operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_context_id: Option<OperationContextId>,
    /// Daemon-owned revision of this one-shot result. It is `1` when the
    /// operation context is present and `0` on the ordinary CLI path.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub revision: u64,
}

impl SshConnectionIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.profile_generation > 0,
            "SSH connection identity profile generation must be positive"
        );
        let fingerprint = self
            .observed_host_key_sha256
            .strip_prefix("SHA256:")
            .context("SSH connection identity host key must start with SHA256:")?;
        ensure!(
            fingerprint.len() == 43
                && fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')),
            "SSH connection identity host key must be canonical SHA256 Base64"
        );
        ensure!(
            self.pin_match,
            "SSH connection identity must represent a matching host-key pin"
        );
        ensure!(
            self.operation_context_id.is_some() == (self.revision > 0),
            "SSH connection identity context and revision are inconsistent"
        );
        ensure!(
            self.server_identification.len() <= MAX_SSH_SERVER_IDENTIFICATION_BYTES
                && (self.server_identification.starts_with("SSH-2.0-")
                    || self.server_identification.starts_with("SSH-1.99-"))
                && self
                    .server_identification
                    .bytes()
                    .all(|byte| matches!(byte, 0x21..=0x7e)),
            "SSH connection identity server identification is unsafe or oversized"
        );
        ensure!(
            self.transport_attempt_id.len() == 32
                && self
                    .transport_attempt_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')),
            "SSH connection identity transport attempt id must be 32 uppercase hex characters"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "t", content = "d", deny_unknown_fields)]
pub enum Frame {
    // client -> daemon
    AuthHello {
        version: u16,
        client_nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        intent_commitment: Option<String>,
    },
    AuthResponse {
        client_proof: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_call_proof: Option<String>,
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
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    Status,
    /// v6 global-control operation. The passphrase is carried only inside the
    /// authenticated AEAD stream and is verified locally without opening SSH.
    Shutdown {
        passphrase: String,
    },
    /// v6 root operation: verify a profile passphrase and open a bounded
    /// credential lease for the profile named in the handshake prelude.
    Unlock {
        passphrase: String,
    },
    /// v6 response: an opaque, profile-bound authorization key returned only
    /// after a successful passphrase verification. It authorizes ordinary
    /// requests from this frontend without disclosing vault or SSH keys.
    ProfileAuthorized {
        call_key: String,
    },
    /// v6 root operation: return the daemon's sanitized profile catalog.
    ListProfiles,
    /// v6 root operation: issue a bounded OperationGrant for an agent
    /// frontend. Requires the issuing connection to hold an unlocked profile.
    IssueGrant {
        profile: String,
        operations: Vec<String>,
        budget: u32,
        /// Explicit capability lifetime in seconds. Both client and daemon
        /// enforce the protocol policy bounds.
        ttl_secs: u32,
        /// Base64 Ed25519 public key of the grant holder.
        holder_key: String,
    },
    /// v6 response: the issued grant id and its absolute expiry.
    GrantIssued {
        grant_id: String,
        /// Exact vault generation captured by the daemon from the bound pool
        /// entry. The client must persist this value rather than a catalog
        /// snapshot taken before unlock.
        profile_generation: u64,
        issued_unix_ms: u64,
        expires_unix_ms: u64,
    },
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
        transfer_id: TransferId,
        path: String,
        /// SHA-256 commitment to the caller-selected local destination.
        /// The raw local path never crosses IPC, but a grant proof binds this
        /// download to one exact local target instead of only the remote
        /// source. Legacy/profile-passphrase clients may omit it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local_target_sha256: Option<String>,
        backend: TransferBackend,
        resume: TransferResumeMode,
        /// Locally durable prefix requested for native pull resume.
        resume_offset: u64,
        /// Prior remote identity proof from the protected download journal.
        expected_size: Option<u64>,
        expected_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_helper_identity: Option<Box<ExpectedNativeHelperIdentity>>,
        #[serde(default = "default_transfer_idle_timeout_ms")]
        idle_timeout_ms: u64,
        deadline_ms: Option<u64>,
    },
    UploadBegin {
        transfer_id: TransferId,
        path: String,
        size: u64,
        /// Lowercase SHA-256 of the stable local source handle.
        sha256: String,
        backend: TransferBackend,
        resume: TransferResumeMode,
        /// Random per-transfer ownership secret. Present only for
        /// `resume=auto`; it is protected by the IPC AEAD and never persisted
        /// by the daemon or remote helper in recoverable form.
        resume_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_helper_identity: Option<Box<ExpectedNativeHelperIdentity>>,
        #[serde(default = "default_transfer_idle_timeout_ms")]
        idle_timeout_ms: u64,
        deadline_ms: Option<u64>,
    },
    UploadChunk {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    UploadEnd,
    TransferStatus {
        transfer_id: Option<TransferId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_context_id: Option<OperationContextId>,
    },
    TransferCancel {
        transfer_id: TransferId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_context_id: Option<OperationContextId>,
    },
    TunnelOpen {
        spec: TunnelSpec,
    },
    TunnelStop,
    ManagedTunnelOpen {
        spec: TunnelSpec,
        deadline_unix_ms: u64,
    },
    ManagedTunnelStatus {
        tunnel_id: Option<TunnelId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_context_id: Option<OperationContextId>,
    },
    ManagedTunnelCancel {
        tunnel_id: TunnelId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_context_id: Option<OperationContextId>,
    },
    ConnectionIdentity {
        profile_id: [u8; 16],
        profile_generation: u64,
    },
    // daemon -> client
    AuthChallenge {
        version: u16,
        server_nonce: String,
        server_proof: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server_call_proof: Option<String>,
    },
    AuthAccepted,
    ExecOut {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    ExecErr {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    ExecExit {
        code: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_context_id: Option<OperationContextId>,
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        revision: u64,
    },
    ShellOut {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    ShellClosed,
    /// v6 response: sanitized profile catalog (no secrets).
    ProfileList {
        profiles: Vec<WireProfile>,
    },
    StatusInfo {
        profile: String,
        host: String,
        user: String,
        started_unix: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_context_id: Option<OperationContextId>,
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        revision: u64,
    },
    Ack,
    CreateDirAccepted {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_context_id: Option<OperationContextId>,
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        revision: u64,
    },
    /// Client-to-daemon cumulative acknowledgement for native downloads.
    /// `confirmed_bytes` means the bytes were accepted by the stable local
    /// handle; `durable_bytes` advances only after local sync and journal
    /// persistence, and therefore may lag behind confirmation.
    TransferAck {
        confirmed_bytes: u64,
        durable_bytes: u64,
    },
    DirList {
        path: String,
        entries: Vec<RemoteEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_context_id: Option<OperationContextId>,
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        revision: u64,
    },
    FileChunk {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    TransferDone {
        bytes: u64,
    },
    TransferDigest {
        transfer_id: TransferId,
        sha256: String,
    },
    TransferProgress {
        progress: TransferProgress,
    },
    TransferStatusInfo {
        transfers: Vec<TransferProgress>,
    },
    TransferCancelAccepted {
        progress: TransferProgress,
    },
    TunnelReady {
        ready: TunnelReady,
    },
    TunnelClosed,
    ManagedTunnelOpened {
        status: TunnelStatus,
    },
    ManagedTunnelStatusInfo {
        tunnels: Vec<TunnelStatus>,
    },
    ManagedTunnelTerminal {
        status: TunnelStatus,
    },
    ConnectionIdentityInfo {
        identity: SshConnectionIdentity,
    },
    Error {
        msg: String,
    },
}

impl Frame {
    /// Erase every owned string or byte payload carried by this frame. Frame
    /// deliberately does not implement Drop because client and daemon handlers
    /// move fields out while dispatching; callers can use this method in
    /// rejected, cancelled, or otherwise unexpected-frame branches.
    pub fn zeroize_sensitive(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for Frame {
    fn zeroize(&mut self) {
        match self {
            Frame::AuthHello {
                client_nonce,
                intent_commitment,
                ..
            } => {
                client_nonce.zeroize();
                intent_commitment.zeroize();
            }
            Frame::AuthResponse {
                client_proof,
                client_call_proof,
            } => {
                client_proof.zeroize();
                client_call_proof.zeroize();
            }
            Frame::Exec { cmd, .. } => cmd.zeroize(),
            Frame::ProfileAuthorized { call_key } => call_key.zeroize(),
            Frame::ShellInput { data }
            | Frame::UploadChunk { data }
            | Frame::ExecOut { data }
            | Frame::ExecErr { data }
            | Frame::ShellOut { data }
            | Frame::FileChunk { data } => data.zeroize(),
            Frame::ListDir { path, .. } | Frame::CreateDir { path, .. } => path.zeroize(),
            Frame::Download {
                path,
                local_target_sha256,
                expected_sha256,
                expected_helper_identity,
                ..
            } => {
                path.zeroize();
                local_target_sha256.zeroize();
                expected_sha256.zeroize();
                if let Some(mut expected) = expected_helper_identity.take() {
                    expected.zeroize();
                }
            }
            Frame::UploadBegin {
                path,
                sha256,
                resume_token,
                expected_helper_identity,
                ..
            } => {
                path.zeroize();
                sha256.zeroize();
                resume_token.zeroize();
                if let Some(mut expected) = expected_helper_identity.take() {
                    expected.zeroize();
                }
            }
            Frame::TransferDigest { sha256, .. } => sha256.zeroize(),
            Frame::TunnelReady { ready } => ready.bind_host.zeroize(),
            Frame::ManagedTunnelOpened { status } | Frame::ManagedTunnelTerminal { status } => {
                status.profile_id.zeroize();
                status.bind_host.zeroize();
                status.target_host.zeroize();
                status.operation_context_id.zeroize();
            }
            Frame::ManagedTunnelStatusInfo { tunnels } => {
                for status in tunnels.iter_mut() {
                    status.profile_id.zeroize();
                    status.bind_host.zeroize();
                    status.target_host.zeroize();
                    status.operation_context_id.zeroize();
                }
                tunnels.clear();
            }
            Frame::AuthChallenge {
                server_nonce,
                server_proof,
                server_call_proof,
                ..
            } => {
                server_nonce.zeroize();
                server_proof.zeroize();
                server_call_proof.zeroize();
            }
            Frame::StatusInfo {
                profile,
                host,
                user,
                operation_context_id,
                ..
            } => {
                profile.zeroize();
                host.zeroize();
                user.zeroize();
                operation_context_id.zeroize();
            }
            Frame::DirList {
                path,
                entries,
                operation_context_id,
                ..
            } => {
                path.zeroize();
                for entry in entries.iter_mut() {
                    entry.name.zeroize();
                    entry.path.zeroize();
                }
                entries.clear();
                operation_context_id.zeroize();
            }
            Frame::Error { msg } => msg.zeroize(),
            Frame::Unlock { passphrase } | Frame::Shutdown { passphrase } => passphrase.zeroize(),
            Frame::IssueGrant {
                profile,
                operations,
                holder_key,
                ..
            } => {
                profile.zeroize();
                operations.zeroize();
                holder_key.zeroize();
            }
            Frame::GrantIssued { grant_id, .. } => grant_id.zeroize(),
            Frame::TransferStatus {
                operation_context_id,
                ..
            }
            | Frame::TransferCancel {
                operation_context_id,
                ..
            }
            | Frame::ManagedTunnelStatus {
                operation_context_id,
                ..
            }
            | Frame::ManagedTunnelCancel {
                operation_context_id,
                ..
            } => operation_context_id.zeroize(),
            Frame::ProfileList { profiles } => {
                for entry in profiles.iter_mut() {
                    entry.name.zeroize();
                    entry.host.zeroize();
                    entry.profile_id.zeroize();
                }
                profiles.clear();
            }
            Frame::TransferStatusInfo { transfers } => {
                for transfer in transfers.iter_mut() {
                    transfer.event.zeroize();
                    transfer.operation_context_id.zeroize();
                }
                transfers.clear();
            }
            Frame::TransferProgress { progress } | Frame::TransferCancelAccepted { progress } => {
                progress.event.zeroize();
                progress.operation_context_id.zeroize();
            }
            Frame::ConnectionIdentityInfo { identity } => {
                identity.observed_host_key_sha256.zeroize();
                identity.server_identification.zeroize();
                identity.transport_attempt_id.zeroize();
                identity.operation_context_id.zeroize();
            }
            Frame::ExecExit {
                operation_context_id,
                ..
            }
            | Frame::CreateDirAccepted {
                operation_context_id,
                ..
            } => operation_context_id.zeroize(),
            Frame::Shell { .. }
            | Frame::TunnelOpen { .. }
            | Frame::ManagedTunnelOpen { .. }
            | Frame::AuthAccepted
            | Frame::Status
            | Frame::ListProfiles
            | Frame::UploadEnd
            | Frame::TunnelStop
            | Frame::TunnelClosed
            | Frame::ConnectionIdentity { .. }
            | Frame::ShellClosed
            | Frame::Ack
            | Frame::TransferAck { .. }
            | Frame::TransferDone { .. } => {}
        }
    }
}

/// Authentication never returns a Frame to a business dispatcher, so it can
/// use a local RAII guard without preventing those dispatchers from moving
/// fields out of ordinary Frames. This covers authentication errors, timeout,
/// and future cancellation while a sensitive frame is still in scope.
struct ZeroizingAuthFrame(Frame);

impl Drop for ZeroizingAuthFrame {
    fn drop(&mut self) {
        self.0.zeroize_sensitive();
    }
}

type HmacSha256 = Hmac<Sha256>;

fn decode_base64_32(label: &str, encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    let decoded = Zeroizing::new(
        B64.decode(encoded)
            .with_context(|| format!("decode {label}"))?,
    );
    if decoded.len() != 32 {
        bail!("{label} must contain exactly 32 bytes");
    }
    let mut value = Zeroizing::new([0_u8; 32]);
    value.copy_from_slice(&decoded);
    let canonical = Zeroizing::new(B64.encode(value.as_ref()));
    if canonical.as_bytes() != encoded.as_bytes() {
        bail!("{label} must use canonical padded Base64");
    }
    Ok(value)
}

fn random_nonce() -> Zeroizing<[u8; 32]> {
    let mut nonce = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut *nonce);
    nonce
}

fn finish_mac(mac: HmacSha256) -> Zeroizing<[u8; 32]> {
    let mut digest = mac.finalize().into_bytes();
    let mut value = Zeroizing::new([0_u8; 32]);
    value.copy_from_slice(&digest);
    let digest_bytes: &mut [u8] = digest.as_mut();
    digest_bytes.zeroize();
    value
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| anyhow::anyhow!("IPC request field exceeds the canonical intent limit"))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn update_expected_native_helper_identity(
    digest: &mut Sha256,
    expected: Option<&ExpectedNativeHelperIdentity>,
) -> Result<()> {
    let Some(expected) = expected else {
        digest.update([0]);
        return Ok(());
    };
    expected.validate()?;
    digest.update([1]);
    update_length_prefixed(digest, expected.name.as_bytes())?;
    digest.update(expected.binary_size.to_be_bytes());
    update_length_prefixed(digest, expected.sha256.as_bytes())?;
    update_length_prefixed(digest, expected.version.as_bytes())?;
    Ok(())
}

/// Hash only complete root requests. Streaming continuation and response
/// frames can inherit an already-authorized root operation but can never be
/// authorized independently.
fn canonical_request_digest(frame: &Frame) -> Result<Zeroizing<[u8; 32]>> {
    let mut digest = Sha256::new();
    digest.update(REQUEST_DIGEST_DOMAIN);
    digest.update(IPC_PROTOCOL_VERSION.to_be_bytes());
    match frame {
        Frame::Exec { cmd, timeout_ms } => {
            digest.update([1]);
            update_length_prefixed(&mut digest, cmd.as_bytes())?;
            digest.update(timeout_ms.to_be_bytes());
        }
        Frame::Shell { cols, rows } => {
            digest.update([2]);
            digest.update(cols.to_be_bytes());
            digest.update(rows.to_be_bytes());
        }
        Frame::Status => digest.update([3]),
        Frame::Shutdown { passphrase } => {
            digest.update([4]);
            update_length_prefixed(&mut digest, passphrase.as_bytes())?;
        }
        Frame::Unlock { passphrase } => {
            digest.update([10]);
            update_length_prefixed(&mut digest, passphrase.as_bytes())?;
        }
        Frame::ListProfiles => digest.update([11]),
        Frame::ListDir { path, timeout_ms } => {
            digest.update([5]);
            update_length_prefixed(&mut digest, path.as_bytes())?;
            digest.update(timeout_ms.to_be_bytes());
        }
        Frame::CreateDir { path, timeout_ms } => {
            digest.update([6]);
            update_length_prefixed(&mut digest, path.as_bytes())?;
            digest.update(timeout_ms.to_be_bytes());
        }
        Frame::Download {
            transfer_id,
            path,
            local_target_sha256,
            backend,
            resume,
            resume_offset,
            expected_size,
            expected_sha256,
            expected_helper_identity,
            idle_timeout_ms,
            deadline_ms,
        } => {
            digest.update([7]);
            update_length_prefixed(&mut digest, transfer_id.as_str().as_bytes())?;
            update_length_prefixed(&mut digest, path.as_bytes())?;
            update_length_prefixed(
                &mut digest,
                local_target_sha256
                    .as_deref()
                    .unwrap_or_default()
                    .as_bytes(),
            )?;
            digest.update([*backend as u8, *resume as u8]);
            digest.update(resume_offset.to_be_bytes());
            digest.update(expected_size.unwrap_or(0).to_be_bytes());
            update_length_prefixed(
                &mut digest,
                expected_sha256.as_deref().unwrap_or_default().as_bytes(),
            )?;
            update_expected_native_helper_identity(
                &mut digest,
                expected_helper_identity.as_deref(),
            )?;
            digest.update(idle_timeout_ms.to_be_bytes());
            digest.update(deadline_ms.unwrap_or(0).to_be_bytes());
        }
        Frame::UploadBegin {
            transfer_id,
            path,
            size,
            sha256,
            backend,
            resume,
            resume_token,
            expected_helper_identity,
            idle_timeout_ms,
            deadline_ms,
        } => {
            digest.update([8]);
            update_length_prefixed(&mut digest, transfer_id.as_str().as_bytes())?;
            update_length_prefixed(&mut digest, path.as_bytes())?;
            digest.update(size.to_be_bytes());
            update_length_prefixed(&mut digest, sha256.as_bytes())?;
            digest.update([*backend as u8, *resume as u8]);
            update_length_prefixed(
                &mut digest,
                resume_token.as_deref().unwrap_or_default().as_bytes(),
            )?;
            update_expected_native_helper_identity(
                &mut digest,
                expected_helper_identity.as_deref(),
            )?;
            digest.update(idle_timeout_ms.to_be_bytes());
            digest.update(deadline_ms.unwrap_or(0).to_be_bytes());
        }
        Frame::TunnelOpen { spec } => {
            digest.update([9]);
            digest.update([match spec.mode {
                TunnelMode::Local => 1,
                TunnelMode::Remote => 2,
                TunnelMode::Dynamic => 3,
            }]);
            digest.update(spec.bind_port.to_be_bytes());
            digest.update(spec.target_port.to_be_bytes());
            digest.update(spec.max_connections.to_be_bytes());
        }
        Frame::TransferStatus {
            transfer_id,
            operation_context_id,
        } => {
            digest.update([12]);
            if let Some(transfer_id) = transfer_id {
                update_length_prefixed(&mut digest, transfer_id.as_str().as_bytes())?;
            } else {
                update_length_prefixed(&mut digest, &[])?;
            }
            if let Some(operation_context_id) = operation_context_id {
                update_length_prefixed(&mut digest, operation_context_id.as_str().as_bytes())?;
            } else {
                update_length_prefixed(&mut digest, &[])?;
            }
        }
        Frame::TransferCancel {
            transfer_id,
            operation_context_id,
        } => {
            digest.update([13]);
            update_length_prefixed(&mut digest, transfer_id.as_str().as_bytes())?;
            if let Some(operation_context_id) = operation_context_id {
                update_length_prefixed(&mut digest, operation_context_id.as_str().as_bytes())?;
            } else {
                update_length_prefixed(&mut digest, &[])?;
            }
        }
        Frame::ManagedTunnelOpen {
            spec,
            deadline_unix_ms,
        } => {
            digest.update([14]);
            digest.update([match spec.mode {
                TunnelMode::Local => 1,
                TunnelMode::Remote => 2,
                TunnelMode::Dynamic => 3,
            }]);
            digest.update(spec.bind_port.to_be_bytes());
            digest.update(spec.target_port.to_be_bytes());
            digest.update(spec.max_connections.to_be_bytes());
            digest.update(deadline_unix_ms.to_be_bytes());
        }
        Frame::ManagedTunnelStatus {
            tunnel_id,
            operation_context_id,
        } => {
            digest.update([15]);
            update_length_prefixed(
                &mut digest,
                tunnel_id
                    .as_ref()
                    .map(TunnelId::as_str)
                    .unwrap_or_default()
                    .as_bytes(),
            )?;
            update_length_prefixed(
                &mut digest,
                operation_context_id
                    .as_ref()
                    .map(OperationContextId::as_str)
                    .unwrap_or_default()
                    .as_bytes(),
            )?;
        }
        Frame::ManagedTunnelCancel {
            tunnel_id,
            operation_context_id,
        } => {
            digest.update([16]);
            update_length_prefixed(&mut digest, tunnel_id.as_str().as_bytes())?;
            update_length_prefixed(
                &mut digest,
                operation_context_id
                    .as_ref()
                    .map(OperationContextId::as_str)
                    .unwrap_or_default()
                    .as_bytes(),
            )?;
        }
        Frame::ConnectionIdentity {
            profile_id,
            profile_generation,
        } => {
            digest.update([17]);
            digest.update(profile_id);
            digest.update(profile_generation.to_be_bytes());
        }
        _ => bail!("IPC frame is not an authorizable root request"),
    }
    let mut finalized = digest.finalize();
    let mut value = Zeroizing::new([0_u8; 32]);
    value.copy_from_slice(&finalized);
    let finalized_bytes: &mut [u8] = finalized.as_mut();
    finalized_bytes.zeroize();
    Ok(value)
}

fn request_intent_commitment(call_key: &[u8; 32], frame: &Frame) -> Result<Zeroizing<[u8; 32]>> {
    let request_digest = canonical_request_digest(frame)?;
    let mut mac = HmacSha256::new_from_slice(call_key)
        .map_err(|_| anyhow::anyhow!("invalid IPC call authorization key"))?;
    mac.update(INTENT_COMMITMENT_DOMAIN);
    mac.update(&IPC_PROTOCOL_VERSION.to_be_bytes());
    mac.update(request_digest.as_ref());
    Ok(finish_mac(mac))
}

#[expect(
    clippy::too_many_arguments,
    reason = "keeping every authenticated transcript field explicit prevents accidental omission"
)]
fn proof_mac(
    key: &[u8; 32],
    domain: &[u8],
    version: u16,
    profile: &str,
    endpoint_id: &str,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    intent_commitment: Option<&[u8; 32]>,
) -> Result<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid IPC authentication key"))?;
    mac.update(domain);
    mac.update(&version.to_be_bytes());
    mac.update(&(profile.len() as u32).to_be_bytes());
    mac.update(profile.as_bytes());
    mac.update(&(endpoint_id.len() as u32).to_be_bytes());
    mac.update(endpoint_id.as_bytes());
    mac.update(client_nonce);
    mac.update(server_nonce);
    match intent_commitment {
        Some(commitment) => {
            mac.update(&[1]);
            mac.update(commitment);
        }
        None => mac.update(&[0]),
    }
    Ok(mac)
}

#[expect(
    clippy::too_many_arguments,
    reason = "keeping every authenticated transcript field explicit prevents accidental omission"
)]
fn encoded_proof(
    key: &[u8; 32],
    domain: &[u8],
    version: u16,
    profile: &str,
    endpoint_id: &str,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    intent_commitment: Option<&[u8; 32]>,
) -> Result<String> {
    let proof = proof_mac(
        key,
        domain,
        version,
        profile,
        endpoint_id,
        client_nonce,
        server_nonce,
        intent_commitment,
    )?;
    Ok(B64.encode(finish_mac(proof).as_ref()))
}

#[expect(
    clippy::too_many_arguments,
    reason = "keeping every authenticated transcript field explicit prevents accidental omission"
)]
fn verify_proof(
    key: &[u8; 32],
    domain: &[u8],
    version: u16,
    profile: &str,
    endpoint_id: &str,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    intent_commitment: Option<&[u8; 32]>,
    encoded: &str,
) -> Result<()> {
    let provided = decode_base64_32("IPC authentication proof", encoded)?;
    let expected = finish_mac(proof_mac(
        key,
        domain,
        version,
        profile,
        endpoint_id,
        client_nonce,
        server_nonce,
        intent_commitment,
    )?);
    if !bool::from(expected.as_ref().ct_eq(provided.as_ref())) {
        bail!("IPC authentication proof mismatch");
    }
    Ok(())
}

/// A server-side authorization transcript. Sensitive transcript material is
/// held only in zeroizing buffers. Verification consumes the context so one
/// successful handshake cannot authorize a second root request.
pub struct AuthContext {
    intent_commitment: Option<Zeroizing<[u8; 32]>>,
    request_verified: bool,
}

impl AuthContext {
    pub fn verify_request(&mut self, call_key: &[u8; 32], request: &Frame) -> Result<()> {
        if std::mem::replace(&mut self.request_verified, true) {
            bail!("IPC authorization context was already consumed");
        }
        let Some(provided) = self.intent_commitment.as_ref() else {
            bail!("IPC request requires master-passphrase authorization");
        };
        let expected = request_intent_commitment(call_key, request)?;
        if !bool::from(expected.as_ref().ct_eq(provided.as_ref())) {
            bail!("IPC request authorization failed");
        }
        Ok(())
    }
}

async fn write_auth_frame<S>(stream: &mut S, frame: &Frame, deadline: Instant) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    tokio::time::timeout_at(deadline, write_frame_limited(stream, frame, MAX_AUTH_FRAME))
        .await
        .map_err(|_| anyhow::anyhow!("IPC authentication timed out"))??;
    Ok(())
}

async fn read_auth_frame<S>(stream: &mut S, deadline: Instant) -> Result<Frame>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout_at(deadline, read_frame_limited(stream, MAX_AUTH_FRAME))
        .await
        .map_err(|_| anyhow::anyhow!("IPC authentication timed out"))??
        .ok_or_else(|| anyhow::anyhow!("IPC peer disconnected during authentication"))
}

/// Authenticate a local IPC server before disclosing any reusable capability
/// or sending a business request. Every I/O step shares the caller-provided
/// absolute deadline.
pub async fn authenticate_client<S>(
    stream: &mut S,
    profile: &str,
    token: &str,
    deadline: Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    authenticate_client_inner(stream, profile, token, None, None, deadline).await
}

/// Mutually authenticate a daemon and authorize exactly one root request with
/// a profile-scoped key. The request itself is not sent by this function. A
/// client only returns after it has verified the daemon's call-key proof and
/// received `AuthAccepted`, so a wrong master or fake daemon sees zero business
/// request bytes.
pub async fn authenticate_client_for_request<S>(
    stream: &mut S,
    profile: &str,
    token: &str,
    call_key: &[u8; 32],
    request: &Frame,
    deadline: Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    authenticate_client_inner(
        stream,
        profile,
        token,
        Some(call_key),
        Some(request),
        deadline,
    )
    .await
}

async fn authenticate_client_inner<S>(
    stream: &mut S,
    profile: &str,
    token: &str,
    call_key: Option<&[u8; 32]>,
    request: Option<&Frame>,
    deadline: Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_profile_name(profile)?;
    let intent_commitment = match (call_key, request) {
        (Some(call_key), Some(request)) => Some(request_intent_commitment(call_key, request)?),
        (None, None) => None,
        _ => bail!("incomplete IPC call-authorization inputs"),
    };
    let token = decode_base64_32("IPC token", token)?;
    let endpoint_id = endpoint_id_with_token(profile, &token);
    let client_nonce = random_nonce();
    let hello = ZeroizingAuthFrame(Frame::AuthHello {
        version: IPC_PROTOCOL_VERSION,
        client_nonce: B64.encode(client_nonce.as_ref()),
        intent_commitment: intent_commitment
            .as_ref()
            .map(|commitment| B64.encode(commitment.as_ref())),
    });
    write_auth_frame(stream, &hello.0, deadline).await?;

    let mut challenge = ZeroizingAuthFrame(read_auth_frame(stream, deadline).await?);
    let (server_nonce, server_proof, server_call_proof) = match &mut challenge.0 {
        Frame::AuthChallenge {
            version: IPC_PROTOCOL_VERSION,
            server_nonce,
            server_proof,
            server_call_proof,
        } => (
            Zeroizing::new(std::mem::take(server_nonce)),
            Zeroizing::new(std::mem::take(server_proof)),
            server_call_proof.take().map(Zeroizing::new),
        ),
        Frame::AuthChallenge { version, .. } => {
            bail!("unsupported IPC authentication version {version}")
        }
        _ => bail!("unexpected IPC server authentication frame"),
    };
    let server_nonce = decode_base64_32("IPC server nonce", &server_nonce)?;
    if bool::from(client_nonce.as_ref().ct_eq(server_nonce.as_ref())) {
        bail!("IPC server reused the client nonce");
    }
    verify_proof(
        &token,
        SERVER_PROOF_DOMAIN,
        IPC_PROTOCOL_VERSION,
        profile,
        &endpoint_id,
        &client_nonce,
        &server_nonce,
        intent_commitment.as_deref(),
        &server_proof,
    )?;

    let client_call_proof = match (call_key, intent_commitment.as_ref(), server_call_proof) {
        (Some(call_key), Some(commitment), Some(server_call_proof)) => {
            verify_proof(
                call_key,
                SERVER_CALL_PROOF_DOMAIN,
                IPC_PROTOCOL_VERSION,
                profile,
                &endpoint_id,
                &client_nonce,
                &server_nonce,
                Some(commitment),
                &server_call_proof,
            )?;
            Some(encoded_proof(
                call_key,
                CLIENT_CALL_PROOF_DOMAIN,
                IPC_PROTOCOL_VERSION,
                profile,
                &endpoint_id,
                &client_nonce,
                &server_nonce,
                Some(commitment),
            )?)
        }
        (None, None, None) => None,
        _ => bail!("IPC call-authorization challenge mismatch"),
    };

    let response = ZeroizingAuthFrame(Frame::AuthResponse {
        client_proof: encoded_proof(
            &token,
            CLIENT_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            profile,
            &endpoint_id,
            &client_nonce,
            &server_nonce,
            intent_commitment.as_deref(),
        )?,
        client_call_proof,
    });
    write_auth_frame(stream, &response.0, deadline).await?;
    let accepted = ZeroizingAuthFrame(read_auth_frame(stream, deadline).await?);
    if !matches!(&accepted.0, Frame::AuthAccepted) {
        bail!("unexpected IPC authorization completion frame");
    }
    Ok(())
}

/// Authenticate a local IPC client using a nonce challenge. No business frame
/// is returned to the caller until the client proof has been verified.
pub async fn authenticate_server<S>(
    stream: &mut S,
    profile: &str,
    token: &str,
    call_key: &[u8; 32],
    deadline: Instant,
) -> Result<AuthContext>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_profile_name(profile)?;
    let token = decode_base64_32("IPC token", token)?;
    let endpoint_id = endpoint_id_with_token(profile, &token);
    let mut hello = ZeroizingAuthFrame(read_auth_frame(stream, deadline).await?);
    let (client_nonce, intent_commitment) = match &mut hello.0 {
        Frame::AuthHello {
            version: IPC_PROTOCOL_VERSION,
            client_nonce,
            intent_commitment,
        } => (
            Zeroizing::new(std::mem::take(client_nonce)),
            intent_commitment.take().map(Zeroizing::new),
        ),
        Frame::AuthHello { version, .. } => {
            bail!("unsupported IPC authentication version {version}")
        }
        _ => bail!("unexpected IPC client authentication frame"),
    };
    let client_nonce = decode_base64_32("IPC client nonce", &client_nonce)?;
    let intent_commitment = intent_commitment
        .as_ref()
        .map(|commitment| decode_base64_32("IPC request intent commitment", commitment))
        .transpose()?;
    let mut server_nonce = random_nonce();
    while bool::from(client_nonce.as_ref().ct_eq(server_nonce.as_ref())) {
        server_nonce = random_nonce();
    }
    let server_proof = encoded_proof(
        &token,
        SERVER_PROOF_DOMAIN,
        IPC_PROTOCOL_VERSION,
        profile,
        &endpoint_id,
        &client_nonce,
        &server_nonce,
        intent_commitment.as_deref(),
    )?;
    let server_call_proof = intent_commitment
        .as_ref()
        .map(|commitment| {
            encoded_proof(
                call_key,
                SERVER_CALL_PROOF_DOMAIN,
                IPC_PROTOCOL_VERSION,
                profile,
                &endpoint_id,
                &client_nonce,
                &server_nonce,
                Some(commitment),
            )
        })
        .transpose()?;
    let challenge = ZeroizingAuthFrame(Frame::AuthChallenge {
        version: IPC_PROTOCOL_VERSION,
        server_nonce: B64.encode(server_nonce.as_ref()),
        server_proof,
        server_call_proof,
    });
    write_auth_frame(stream, &challenge.0, deadline).await?;

    let mut response = ZeroizingAuthFrame(read_auth_frame(stream, deadline).await?);
    let (client_proof, client_call_proof) = match &mut response.0 {
        Frame::AuthResponse {
            client_proof,
            client_call_proof,
        } => (
            Zeroizing::new(std::mem::take(client_proof)),
            client_call_proof.take().map(Zeroizing::new),
        ),
        _ => bail!("unexpected IPC client proof frame"),
    };
    verify_proof(
        &token,
        CLIENT_PROOF_DOMAIN,
        IPC_PROTOCOL_VERSION,
        profile,
        &endpoint_id,
        &client_nonce,
        &server_nonce,
        intent_commitment.as_deref(),
        &client_proof,
    )?;
    match (intent_commitment.as_ref(), client_call_proof) {
        (Some(commitment), Some(client_call_proof)) => verify_proof(
            call_key,
            CLIENT_CALL_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            profile,
            &endpoint_id,
            &client_nonce,
            &server_nonce,
            Some(commitment),
            &client_call_proof,
        )?,
        (None, None) => {}
        _ => bail!("IPC call-authorization response mismatch"),
    }
    write_auth_frame(stream, &Frame::AuthAccepted, deadline).await?;
    Ok(AuthContext {
        intent_commitment,
        request_verified: false,
    })
}

/// Write one frame with the default wire cap. Kept public (and unconditional)
/// because cross-crate tests exercise typed framing through it.
#[doc(hidden)]
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> Result<()> {
    write_frame_limited(w, f, MAX_FRAME).await
}
pub async fn write_frame_limited<W: AsyncWrite + Unpin>(
    w: &mut W,
    f: &Frame,
    max_frame: usize,
) -> Result<()> {
    write_frame_limited_with_written_callback(w, f, max_frame, || {}).await
}

/// Write one complete framed payload and invoke `on_frame_written` after the
/// length prefix and payload have both been accepted by `AsyncWrite`, but
/// before flushing. Cancellation or an error during serialization or either
/// write never invokes the callback; a later flush failure does.
pub async fn write_frame_limited_with_written_callback<W, F>(
    w: &mut W,
    f: &Frame,
    max_frame: usize,
    on_frame_written: F,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    F: FnOnce(),
{
    // Frames can contain command output, shell input, and file contents. Keep
    // the transient serialized copy in a zeroizing allocation so success,
    // I/O failure, and cancellation all erase it through RAII.
    let json = serialize_frame_bounded(f, max_frame)?;
    let wire_len = u32::try_from(json.len()).context("frame exceeds the u32 wire length")?;
    let len = wire_len.to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&json).await?;
    on_frame_written();
    w.flush().await?;
    Ok(())
}

struct BoundedFrameCounter {
    length: usize,
    maximum: usize,
    exceeded: bool,
}

impl BoundedFrameCounter {
    fn new(maximum: usize) -> Self {
        Self {
            length: 0,
            maximum,
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedFrameCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(length) = self.length.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame length overflow",
            ));
        };
        if length > self.maximum {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame exceeds configured limit",
            ));
        }
        self.length = length;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct PreallocatedFrameBuffer {
    bytes: Zeroizing<Vec<u8>>,
    expected: usize,
}

impl PreallocatedFrameBuffer {
    fn new(expected: usize) -> Result<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(expected)
            .map_err(|error| anyhow::anyhow!("reserve bounded frame buffer: {error}"))?;
        Ok(Self { bytes, expected })
    }
}

impl std::io::Write for PreallocatedFrameBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(new_len) = self.bytes.len().checked_add(bytes.len()) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame length overflow",
            ));
        };
        if new_len > self.expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame length changed between sizing and serialization",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn encoded_frame_len_limited(frame: &Frame, maximum: usize) -> Result<usize> {
    let mut counter = BoundedFrameCounter::new(maximum);
    if let Err(error) = serde_json::to_writer(&mut counter, frame) {
        if counter.exceeded {
            bail!("frame too large: exceeds {maximum} bytes");
        }
        return Err(error.into());
    }
    Ok(counter.length)
}

fn serialize_frame_bounded(frame: &Frame, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let expected = encoded_frame_len_limited(frame, maximum)?;
    let mut sink = PreallocatedFrameBuffer::new(expected)?;
    serde_json::to_writer(&mut sink, frame)?;
    if sink.bytes.len() != expected {
        bail!("frame length changed between sizing and serialization");
    }
    Ok(sink.bytes)
}

/// Read one frame with the default wire cap. Kept public (and unconditional)
/// because cross-crate tests exercise typed framing through it.
#[doc(hidden)]
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
    read_frame_limited(r, MAX_FRAME).await
}

pub async fn read_frame_limited<R: AsyncRead + Unpin>(
    r: &mut R,
    max_frame: usize,
) -> Result<Option<Frame>> {
    let mut lenbuf = [0u8; 4];
    // Only EOF before the first header byte is a clean frame-stream close.
    // Treat a one-to-three-byte prefix as corruption: mapping every
    // UnexpectedEof to `None` makes a truncated frame indistinguishable from
    // an orderly peer shutdown and can let higher-level state machines accept
    // an incomplete terminal exchange.
    if r.read(&mut lenbuf[..1]).await? == 0 {
        return Ok(None);
    }
    r.read_exact(&mut lenbuf[1..])
        .await
        .context("IPC peer disconnected during frame length prefix")?;
    let len = u32::from_be_bytes(lenbuf) as usize;
    if len > max_frame {
        bail!("frame too large: {len} bytes");
    }
    // Deserialization creates the owned Frame value; erase the raw JSON copy
    // on every return path because it can contain the same sensitive payload.
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf).await?;
    Ok(Some(serde_json::from_slice(&buf)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_token() -> String {
        B64.encode([0x5a_u8; 32])
    }

    fn test_call_key() -> [u8; 32] {
        [0xa5_u8; 32]
    }

    fn expected_native_helper_identity() -> ExpectedNativeHelperIdentity {
        ExpectedNativeHelperIdentity {
            name: NATIVE_HELPER_BINARY_NAME.to_owned(),
            binary_size: 123,
            sha256: "ab".repeat(32),
            version: "serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)".to_owned(),
        }
    }

    #[test]
    fn expected_native_helper_identity_is_closed_bounded_and_canonical() {
        expected_native_helper_identity().validate().unwrap();
        for mut invalid in [
            {
                let mut value = expected_native_helper_identity();
                value.name = "serctl-xfer.exe".to_owned();
                value
            },
            {
                let mut value = expected_native_helper_identity();
                value.binary_size = 0;
                value
            },
            {
                let mut value = expected_native_helper_identity();
                value.sha256 = "AB".repeat(32);
                value
            },
            {
                let mut value = expected_native_helper_identity();
                value.version = value.version.replace("0123456789ab", "0123456789AB");
                value
            },
        ] {
            assert!(invalid.validate().is_err());
            invalid.zeroize();
        }
        for json in [
            format!(
                r#"{{"name":"serctl-xfer","binary_size":123,"sha256":"{}","version":"serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)","future":true}}"#,
                "ab".repeat(32)
            ),
            format!(
                r#"{{"name":"serctl-xfer","binary_size":"123","sha256":"{}","version":"serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)"}}"#,
                "ab".repeat(32)
            ),
        ] {
            assert!(serde_json::from_str::<ExpectedNativeHelperIdentity>(&json).is_err());
        }
    }

    fn connection_identity(server_identification: &str, attempt: &str) -> SshConnectionIdentity {
        SshConnectionIdentity {
            profile_id: [7_u8; 16],
            profile_generation: 9,
            observed_host_key_sha256: format!("SHA256:{}", "A".repeat(43)),
            pin_match: true,
            server_identification: server_identification.to_owned(),
            transport_attempt_id: attempt.to_owned(),
            operation_context_id: None,
            revision: 0,
        }
    }

    #[test]
    fn ssh_connection_identity_wire_is_closed_bounded_and_sanitized() {
        for server in ["SSH-2.0-OpenSSH_9.6p1", "SSH-2.0-dropbear_2024.85"] {
            let identity = connection_identity(server, &"A".repeat(32));
            identity.validate().unwrap();
            let frame = Frame::ConnectionIdentityInfo { identity };
            assert!(encoded_frame_len_limited(&frame, MAX_CONTROL_FRAME).is_ok());
            let json = serde_json::to_string(&frame).unwrap();
            for forbidden in ["host\"", "user", "password", "path", "raw_banner"] {
                assert!(!json.contains(forbidden));
            }
        }

        for invalid in [
            connection_identity("SSH-2.0-OpenSSH_9.6p1\nraw", &"A".repeat(32)),
            connection_identity(&format!("SSH-2.0-{}", "x".repeat(121)), &"A".repeat(32)),
            connection_identity("SSH-2.0-OpenSSH_9.6p1", &"a".repeat(32)),
        ] {
            assert!(invalid.validate().is_err());
        }
        let mut mismatch = connection_identity("SSH-2.0-OpenSSH_9.6p1", &"A".repeat(32));
        mismatch.pin_match = false;
        assert!(mismatch.validate().is_err());

        let mut context_bound = connection_identity("SSH-2.0-OpenSSH_9.6p1", &"A".repeat(32));
        context_bound.operation_context_id =
            Some(OperationContextId::parse(&"ab".repeat(32)).unwrap());
        context_bound.revision = 1;
        context_bound.validate().unwrap();
        let encoded = serde_json::to_string(&Frame::ConnectionIdentityInfo {
            identity: context_bound.clone(),
        })
        .unwrap();
        assert!(encoded.contains(&format!("\"operation_context_id\":\"{}\"", "ab".repeat(32))));
        assert!(encoded.contains("\"revision\":1"));
        context_bound.revision = 0;
        assert!(context_bound.validate().is_err());
        context_bound.operation_context_id = None;
        context_bound.revision = 1;
        assert!(context_bound.validate().is_err());

        let mut value = serde_json::to_value(Frame::ConnectionIdentityInfo {
            identity: connection_identity("SSH-2.0-OpenSSH_9.6p1", &"A".repeat(32)),
        })
        .unwrap();
        value["d"]["identity"]["raw_banner"] = serde_json::json!("secret");
        assert!(serde_json::from_value::<Frame>(value).is_err());
    }

    #[test]
    fn ssh_connection_identity_intent_binds_profile_generation_and_attempt_changes() {
        let key = test_call_key();
        let request = Frame::ConnectionIdentity {
            profile_id: [7_u8; 16],
            profile_generation: 9,
        };
        assert_eq!(v6::frame_kind(&request), "ssh.connection-identity");
        let commitment = request_intent_commitment(&key, &request).unwrap();
        for substituted in [
            Frame::ConnectionIdentity {
                profile_id: [8_u8; 16],
                profile_generation: 9,
            },
            Frame::ConnectionIdentity {
                profile_id: [7_u8; 16],
                profile_generation: 10,
            },
        ] {
            assert_ne!(
                commitment.as_ref(),
                request_intent_commitment(&key, &substituted)
                    .unwrap()
                    .as_ref()
            );
        }

        let first = connection_identity("SSH-2.0-OpenSSH_9.6p1", &"A".repeat(32));
        let reconnected = connection_identity("SSH-2.0-OpenSSH_9.6p1", &"B".repeat(32));
        first.validate().unwrap();
        reconnected.validate().unwrap();
        assert_ne!(first.transport_attempt_id, reconnected.transport_attempt_id);
    }

    #[test]
    fn operation_context_is_canonical_and_transfer_control_intent_bound() {
        let context = OperationContextId::parse(&"ab".repeat(32)).unwrap();
        for invalid in ["", &"AB".repeat(32), &"ab".repeat(31), &"gg".repeat(32)] {
            assert!(OperationContextId::parse(invalid).is_err());
        }
        let transfer_id = TransferId::parse("01".repeat(16).as_str()).unwrap();
        let status_without = Frame::TransferStatus {
            transfer_id: Some(transfer_id.clone()),
            operation_context_id: None,
        };
        let status_with = Frame::TransferStatus {
            transfer_id: Some(transfer_id.clone()),
            operation_context_id: Some(context.clone()),
        };
        assert_ne!(
            v6::root_request_hash(&status_without).unwrap(),
            v6::root_request_hash(&status_with).unwrap()
        );
        let cancel = Frame::TransferCancel {
            transfer_id,
            operation_context_id: Some(context),
        };
        assert_ne!(
            v6::root_request_hash(&status_with).unwrap(),
            v6::root_request_hash(&cancel).unwrap()
        );
    }

    #[test]
    fn transfer_id_deserialization_enforces_canonical_shape() {
        let valid: TransferId =
            serde_json::from_str("\"00000000000000000000000000000001\"").unwrap();
        assert_eq!(valid.as_str(), "00000000000000000000000000000001");
        for invalid in [
            "\"short\"",
            "\"0000000000000000000000000000000A\"",
            "\"0000000000000000000000000000000g\"",
        ] {
            assert!(serde_json::from_str::<TransferId>(invalid).is_err());
        }
    }

    #[test]
    fn managed_tunnel_id_status_and_operation_scope_are_closed_and_loopback_only() {
        let tunnel_id = TunnelId::parse("00112233445566778899aabbccddeeff").unwrap();
        for invalid in [
            "short",
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566778899aabbccddee/g",
        ] {
            assert!(TunnelId::parse(invalid).is_err());
        }

        let status = TunnelStatus {
            schema_version: TUNNEL_STATUS_SCHEMA_VERSION,
            tunnel_id: tunnel_id.clone(),
            profile_id: "11223344556677889900aabbccddeeff".into(),
            profile_generation: 3,
            mode: TunnelMode::Local,
            bind_host: "127.0.0.1".into(),
            bind_port: 8080,
            target_host: Some("127.0.0.1".into()),
            target_port: 22,
            deadline_unix_ms: 1_900_000_000_000,
            stage: TunnelStage::Ready,
            updated_unix_ms: 1_800_000_000_000,
            operation_context_id: Some(OperationContextId::parse(&"ab".repeat(32)).unwrap()),
            revision: 1,
        };
        status.validate().unwrap();
        let mut exposed = status.clone();
        exposed.bind_host = "0.0.0.0".into();
        assert!(exposed.validate().is_err());
        let mut remote_target = status.clone();
        remote_target.target_host = Some("192.0.2.1".into());
        assert!(remote_target.validate().is_err());
        let mut missing_context = status.clone();
        missing_context.operation_context_id = None;
        assert!(missing_context.validate().is_err());
        let mut missing_revision = status.clone();
        missing_revision.revision = 0;
        assert!(missing_revision.validate().is_err());

        for (spec, expected) in [
            (TunnelSpec::local(8080, 22), "forward.local/open"),
            (TunnelSpec::remote(8080, 22), "forward.remote/open"),
            (TunnelSpec::dynamic(8080), "forward.dynamic/open"),
        ] {
            assert_eq!(
                v6::frame_kind(&Frame::ManagedTunnelOpen {
                    spec,
                    deadline_unix_ms: status.deadline_unix_ms,
                }),
                expected
            );
        }
        assert_eq!(
            v6::frame_kind(&Frame::ManagedTunnelStatus {
                tunnel_id: Some(tunnel_id.clone()),
                operation_context_id: None,
            }),
            "forward.status"
        );
        assert_eq!(
            v6::frame_kind(&Frame::ManagedTunnelCancel {
                tunnel_id,
                operation_context_id: None,
            }),
            "forward.cancel"
        );
    }

    #[test]
    fn managed_tunnel_intent_binds_mode_deadline_and_identifier() {
        let key = test_call_key();
        let first = Frame::ManagedTunnelOpen {
            spec: TunnelSpec::local(8080, 22),
            deadline_unix_ms: 1_900_000_000_000,
        };
        let changed_deadline = Frame::ManagedTunnelOpen {
            spec: TunnelSpec::local(8080, 22),
            deadline_unix_ms: 1_900_000_000_001,
        };
        let changed_mode = Frame::ManagedTunnelOpen {
            spec: TunnelSpec::remote(8080, 22),
            deadline_unix_ms: 1_900_000_000_000,
        };
        let baseline = request_intent_commitment(&key, &first).unwrap();
        assert_ne!(
            baseline.as_ref(),
            request_intent_commitment(&key, &changed_deadline)
                .unwrap()
                .as_ref()
        );
        assert_ne!(
            baseline.as_ref(),
            request_intent_commitment(&key, &changed_mode)
                .unwrap()
                .as_ref()
        );

        let left = Frame::ManagedTunnelCancel {
            tunnel_id: TunnelId::parse("00000000000000000000000000000001").unwrap(),
            operation_context_id: Some(OperationContextId::parse(&"ab".repeat(32)).unwrap()),
        };
        let right = Frame::ManagedTunnelCancel {
            tunnel_id: TunnelId::parse("00000000000000000000000000000002").unwrap(),
            operation_context_id: Some(OperationContextId::parse(&"ab".repeat(32)).unwrap()),
        };
        assert_ne!(
            request_intent_commitment(&key, &left).unwrap().as_ref(),
            request_intent_commitment(&key, &right).unwrap().as_ref()
        );

        let forged_context = Frame::ManagedTunnelCancel {
            tunnel_id: TunnelId::parse("00000000000000000000000000000001").unwrap(),
            operation_context_id: Some(OperationContextId::parse(&"cd".repeat(32)).unwrap()),
        };
        assert_ne!(
            request_intent_commitment(&key, &left).unwrap().as_ref(),
            request_intent_commitment(&key, &forged_context)
                .unwrap()
                .as_ref()
        );

        let status_discovery = Frame::ManagedTunnelStatus {
            tunnel_id: Some(TunnelId::parse("00000000000000000000000000000001").unwrap()),
            operation_context_id: None,
        };
        let status_bound = Frame::ManagedTunnelStatus {
            tunnel_id: Some(TunnelId::parse("00000000000000000000000000000001").unwrap()),
            operation_context_id: Some(OperationContextId::parse(&"ab".repeat(32)).unwrap()),
        };
        assert_ne!(
            request_intent_commitment(&key, &status_discovery)
                .unwrap()
                .as_ref(),
            request_intent_commitment(&key, &status_bound)
                .unwrap()
                .as_ref()
        );
    }

    #[test]
    fn managed_tunnel_status_all_is_bounded_for_daemon_registry_caps() {
        let tunnels = (0..24)
            .map(|index| TunnelStatus {
                schema_version: TUNNEL_STATUS_SCHEMA_VERSION,
                tunnel_id: TunnelId::parse(&format!("{index:032x}")).unwrap(),
                profile_id: "11223344556677889900aabbccddeeff".into(),
                profile_generation: u64::MAX,
                mode: TunnelMode::Remote,
                bind_host: "127.0.0.1".into(),
                bind_port: u16::MAX,
                target_host: Some("127.0.0.1".into()),
                target_port: u16::MAX,
                deadline_unix_ms: u64::MAX,
                stage: TunnelStage::Unknown,
                updated_unix_ms: u64::MAX,
                operation_context_id: Some(
                    OperationContextId::parse(&format!("{index:064x}")).unwrap(),
                ),
                revision: u64::MAX,
            })
            .collect();
        let frame = Frame::ManagedTunnelStatusInfo { tunnels };
        assert!(serialize_frame_bounded(&frame, MAX_CONTROL_FRAME).is_ok());
    }

    #[tokio::test]
    async fn v5_token_only_mutual_authentication_completes() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = test_token();
        let call_key = test_call_key();
        let deadline = Instant::now() + Duration::from_secs(1);
        let (client_result, server_result) = tokio::join!(
            authenticate_client(&mut client, "prod", &token, deadline),
            authenticate_server(&mut server, "prod", &token, &call_key, deadline),
        );
        client_result.unwrap();
        server_result.unwrap();
    }

    #[tokio::test]
    async fn v5_call_key_authentication_authorizes_exactly_one_request() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = test_token();
        let call_key = test_call_key();
        let request = Frame::Exec {
            cmd: "printf authorized".into(),
            timeout_ms: 7_000,
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        let (client_result, server_result) = tokio::join!(
            authenticate_client_for_request(
                &mut client,
                "prod",
                &token,
                &call_key,
                &request,
                deadline,
            ),
            authenticate_server(&mut server, "prod", &token, &call_key, deadline),
        );
        client_result.unwrap();
        let mut context = server_result.unwrap();
        context.verify_request(&call_key, &request).unwrap();
        assert!(context.verify_request(&call_key, &request).is_err());
    }

    #[tokio::test]
    async fn wrong_call_key_sends_neither_response_proof_nor_business_frame() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = test_token();
        let correct_key = test_call_key();
        let wrong_key = [0x11_u8; 32];
        let request = Frame::Exec {
            cmd: "must-not-be-sent".into(),
            timeout_ms: 1_000,
        };
        let deadline = Instant::now() + Duration::from_millis(100);
        let (client_result, server_result) = tokio::join!(
            authenticate_client_for_request(
                &mut client,
                "prod",
                &token,
                &wrong_key,
                &request,
                deadline,
            ),
            authenticate_server(&mut server, "prod", &token, &correct_key, deadline),
        );
        assert!(client_result.is_err());
        let server_error = server_result
            .err()
            .expect("server unexpectedly accepted proof");
        assert!(
            server_error.to_string().contains("timed out")
                || server_error.to_string().contains("disconnected"),
            "server observed an unexpected client frame: {server_error:#}"
        );
    }

    #[tokio::test]
    async fn intent_commitment_rejects_a_different_request_before_dispatch() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = test_token();
        let call_key = test_call_key();
        let authorized = Frame::Exec {
            cmd: "safe".into(),
            timeout_ms: 1_000,
        };
        let substituted = Frame::Exec {
            cmd: "different".into(),
            timeout_ms: 1_000,
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        let (client_result, server_result) = tokio::join!(
            authenticate_client_for_request(
                &mut client,
                "prod",
                &token,
                &call_key,
                &authorized,
                deadline,
            ),
            authenticate_server(&mut server, "prod", &token, &call_key, deadline),
        );
        client_result.unwrap();
        let mut context = server_result.unwrap();
        assert!(context.verify_request(&call_key, &substituted).is_err());
        assert!(context.verify_request(&call_key, &authorized).is_err());
    }

    #[test]
    fn token_only_context_rejects_every_root_request() {
        for request in [
            Frame::Status,
            Frame::Shutdown {
                passphrase: "profile-passphrase".into(),
            },
            Frame::Exec {
                cmd: "unauthorized".into(),
                timeout_ms: 1,
            },
        ] {
            let mut context = AuthContext {
                intent_commitment: None,
                request_verified: false,
            };
            let error = context
                .verify_request(&test_call_key(), &request)
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("requires master-passphrase authorization"));
        }
    }

    #[tokio::test]
    async fn status_and_shutdown_require_exact_call_key_intents() {
        for request in [
            Frame::Status,
            Frame::Shutdown {
                passphrase: "profile-passphrase".into(),
            },
        ] {
            let (mut client, mut server) = tokio::io::duplex(8 * 1024);
            let token = test_token();
            let call_key = test_call_key();
            let deadline = Instant::now() + Duration::from_secs(1);
            let (client_result, server_result) = tokio::join!(
                authenticate_client_for_request(
                    &mut client,
                    "prod",
                    &token,
                    &call_key,
                    &request,
                    deadline,
                ),
                authenticate_server(&mut server, "prod", &token, &call_key, deadline),
            );
            client_result.unwrap();
            let mut context = server_result.unwrap();
            context.verify_request(&call_key, &request).unwrap();
        }
    }

    #[test]
    fn canonical_intents_cover_every_field_and_reject_continuation_frames() {
        let key = test_call_key();
        assert_ne!(
            request_intent_commitment(&key, &Frame::Status)
                .unwrap()
                .as_ref(),
            request_intent_commitment(
                &key,
                &Frame::Shutdown {
                    passphrase: "profile-passphrase".into(),
                },
            )
            .unwrap()
            .as_ref(),
        );
        let first = Frame::UploadBegin {
            transfer_id: TransferId::parse("00000000000000000000000000000001").unwrap(),
            path: "/tmp/file".into(),
            size: 17,
            sha256: "00".repeat(32),
            backend: TransferBackend::Sftp,
            resume: TransferResumeMode::Never,
            resume_token: None,
            expected_helper_identity: None,
            idle_timeout_ms: 5_000,
            deadline_ms: Some(10_000),
        };
        let changed_size = Frame::UploadBegin {
            transfer_id: TransferId::parse("00000000000000000000000000000001").unwrap(),
            path: "/tmp/file".into(),
            size: 18,
            sha256: "00".repeat(32),
            backend: TransferBackend::Sftp,
            resume: TransferResumeMode::Never,
            resume_token: None,
            expected_helper_identity: None,
            idle_timeout_ms: 5_000,
            deadline_ms: Some(10_000),
        };
        let changed_timeout = Frame::UploadBegin {
            transfer_id: TransferId::parse("00000000000000000000000000000001").unwrap(),
            path: "/tmp/file".into(),
            size: 17,
            sha256: "00".repeat(32),
            backend: TransferBackend::Sftp,
            resume: TransferResumeMode::Never,
            resume_token: None,
            expected_helper_identity: None,
            idle_timeout_ms: 5_001,
            deadline_ms: Some(10_000),
        };
        assert_ne!(
            request_intent_commitment(&key, &first).unwrap().as_ref(),
            request_intent_commitment(&key, &changed_size)
                .unwrap()
                .as_ref()
        );
        let mut helper_bound = first.clone();
        let Frame::UploadBegin {
            expected_helper_identity,
            ..
        } = &mut helper_bound
        else {
            unreachable!()
        };
        *expected_helper_identity = Some(Box::new(expected_native_helper_identity()));
        assert_ne!(
            request_intent_commitment(&key, &first).unwrap().as_ref(),
            request_intent_commitment(&key, &helper_bound)
                .unwrap()
                .as_ref()
        );
        let mut helper_hash_drift = helper_bound.clone();
        let Frame::UploadBegin {
            expected_helper_identity: Some(expected),
            ..
        } = &mut helper_hash_drift
        else {
            unreachable!()
        };
        expected.sha256 = "cd".repeat(32);
        assert_ne!(
            request_intent_commitment(&key, &helper_bound)
                .unwrap()
                .as_ref(),
            request_intent_commitment(&key, &helper_hash_drift)
                .unwrap()
                .as_ref()
        );
        assert_ne!(
            request_intent_commitment(&key, &first).unwrap().as_ref(),
            request_intent_commitment(&key, &changed_timeout)
                .unwrap()
                .as_ref()
        );
        assert!(request_intent_commitment(
            &key,
            &Frame::UploadChunk {
                data: b"continuation".to_vec(),
            },
        )
        .is_err());
        assert!(request_intent_commitment(&key, &Frame::UploadEnd).is_err());
        assert!(request_intent_commitment(
            &key,
            &Frame::TransferAck {
                confirmed_bytes: 17,
                durable_bytes: 16,
            },
        )
        .is_err());
        assert!(request_intent_commitment(
            &key,
            &Frame::ShellInput {
                data: b"continuation".to_vec(),
            },
        )
        .is_err());

        let tunnel = TunnelSpec {
            mode: TunnelMode::Local,
            bind_port: 8080,
            target_port: 5432,
            max_connections: 16,
        };
        let baseline = request_intent_commitment(
            &key,
            &Frame::TunnelOpen {
                spec: tunnel.clone(),
            },
        )
        .unwrap();
        let mut variations = Vec::new();
        let mut changed = tunnel.clone();
        changed.mode = TunnelMode::Remote;
        variations.push(changed);
        let mut changed = tunnel.clone();
        changed.bind_port += 1;
        variations.push(changed);
        let mut changed = tunnel.clone();
        changed.target_port += 1;
        variations.push(changed);
        let mut changed = tunnel.clone();
        changed.max_connections += 1;
        variations.push(changed);
        for changed in variations {
            let commitment =
                request_intent_commitment(&key, &Frame::TunnelOpen { spec: changed }).unwrap();
            assert_ne!(baseline.as_ref(), commitment.as_ref());
        }
        assert!(request_intent_commitment(&key, &Frame::TunnelStop).is_err());

        let download_with = |resume_offset, expected_size, expected_sha256: &str| Frame::Download {
            transfer_id: TransferId::parse("00000000000000000000000000000002").unwrap(),
            path: "/tmp/source".into(),
            local_target_sha256: Some("33".repeat(32)),
            backend: TransferBackend::Native,
            resume: TransferResumeMode::Auto,
            resume_offset,
            expected_size: Some(expected_size),
            expected_sha256: Some(expected_sha256.repeat(32)),
            expected_helper_identity: None,
            idle_timeout_ms: 5_000,
            deadline_ms: Some(10_000),
        };
        let download = download_with(4_096, 8_192, "11");
        let download_commitment = request_intent_commitment(&key, &download).unwrap();
        for changed in [
            download_with(4_097, 8_192, "11"),
            download_with(4_096, 8_193, "11"),
            download_with(4_096, 8_192, "22"),
        ] {
            assert_ne!(
                download_commitment.as_ref(),
                request_intent_commitment(&key, &changed).unwrap().as_ref(),
            );
        }
        let mut changed_local_target = download_with(4_096, 8_192, "11");
        let Frame::Download {
            local_target_sha256,
            ..
        } = &mut changed_local_target
        else {
            unreachable!()
        };
        *local_target_sha256 = Some("44".repeat(32));
        assert_ne!(
            download_commitment.as_ref(),
            request_intent_commitment(&key, &changed_local_target)
                .unwrap()
                .as_ref(),
        );
    }

    #[test]
    fn transfer_progress_is_bounded_monotonic_shape_without_paths() {
        let progress = TransferProgress {
            schema_version: TRANSFER_PROGRESS_SCHEMA_VERSION,
            event: "progress".into(),
            transfer_id: TransferId::parse("00000000000000000000000000000001").unwrap(),
            operation_context_id: Some(OperationContextId::parse(&"ab".repeat(32)).unwrap()),
            revision: 1,
            direction: TransferDirection::Push,
            stage: TransferStage::Transferring,
            total_bytes: 1024,
            confirmed_bytes: 512,
            durable_bytes: 0,
            window_bps: 128.0,
            average_bps: 64.0,
            eta_ms: Some(4_000),
            backend: TransferBackend::Sftp,
            chunk_bytes: SFTP_SAFE_CHUNK_BYTES as u32,
            window_bytes: SFTP_SAFE_CHUNK_BYTES as u32,
            updated_unix_ms: 1,
        };
        progress.validate().unwrap();
        let encoded = serde_json::to_string(&progress).unwrap();
        assert!(!encoded.contains("/tmp"));
        let mut invalid = progress.clone();
        invalid.confirmed_bytes = invalid.total_bytes + 1;
        assert!(invalid.validate().is_err());
        let mut invalid = progress;
        invalid.window_bps = f64::NAN;
        assert!(invalid.validate().is_err());
        invalid.window_bps = 0.0;
        invalid.event = "x\nforged".into();
        assert!(invalid.validate().is_err());
    }

    #[tokio::test]
    async fn fake_server_sees_only_random_hello_and_gets_no_response() {
        let (mut client, mut fake_server) = tokio::io::duplex(8 * 1024);
        let token = test_token();
        let token_for_server = token.clone();
        let deadline = Instant::now() + Duration::from_secs(1);

        let client_task = authenticate_client(&mut client, "prod", &token, deadline);
        let server_task = async move {
            let mut header = [0_u8; 4];
            fake_server.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes(header) as usize;
            assert!(length <= MAX_AUTH_FRAME);
            let mut payload = vec![0_u8; length];
            fake_server.read_exact(&mut payload).await.unwrap();
            let mut wire = header.to_vec();
            wire.extend_from_slice(&payload);
            assert!(
                !wire
                    .windows(token_for_server.len())
                    .any(|window| window == token_for_server.as_bytes()),
                "client disclosed its reusable token before server proof"
            );
            match serde_json::from_slice::<Frame>(&payload).unwrap() {
                Frame::AuthHello {
                    version,
                    client_nonce,
                    intent_commitment,
                } => {
                    assert_eq!(version, IPC_PROTOCOL_VERSION);
                    assert!(intent_commitment.is_none());
                    decode_base64_32("test client nonce", &client_nonce).unwrap();
                }
                _ => panic!("client sent a non-hello frame before server authentication"),
            }

            write_frame_limited(
                &mut fake_server,
                &Frame::AuthChallenge {
                    version: IPC_PROTOCOL_VERSION,
                    server_nonce: B64.encode([0x33_u8; 32]),
                    server_proof: B64.encode([0_u8; 32]),
                    server_call_proof: None,
                },
                MAX_AUTH_FRAME,
            )
            .await
            .unwrap();
            let unexpected = tokio::time::timeout(
                Duration::from_millis(75),
                read_frame_limited(&mut fake_server, MAX_AUTH_FRAME),
            )
            .await;
            assert!(
                unexpected.is_err(),
                "client sent a proof or business frame to an unauthenticated server"
            );
        };

        let (client_result, ()) = tokio::join!(client_task, server_task);
        assert!(client_result.is_err());
    }

    #[test]
    fn proofs_bind_role_nonce_version_profile_and_endpoint() {
        let token = decode_base64_32("test token", &test_token()).unwrap();
        let client_nonce = [1_u8; 32];
        let server_nonce = [2_u8; 32];
        let other_client_nonce = [3_u8; 32];
        let other_server_nonce = [4_u8; 32];
        let prod_endpoint = endpoint_id_with_token("prod", &token);
        let stage_endpoint = endpoint_id_with_token("stage", &token);
        let proof = encoded_proof(
            &token,
            SERVER_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            &prod_endpoint,
            &client_nonce,
            &server_nonce,
            None,
        )
        .unwrap();

        verify_proof(
            &token,
            SERVER_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            &prod_endpoint,
            &client_nonce,
            &server_nonce,
            None,
            &proof,
        )
        .unwrap();
        assert!(verify_proof(
            &token,
            CLIENT_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            &prod_endpoint,
            &client_nonce,
            &server_nonce,
            None,
            &proof,
        )
        .is_err());
        assert!(verify_proof(
            &token,
            SERVER_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            &prod_endpoint,
            &other_client_nonce,
            &server_nonce,
            None,
            &proof,
        )
        .is_err());
        assert!(verify_proof(
            &token,
            SERVER_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            &prod_endpoint,
            &client_nonce,
            &other_server_nonce,
            None,
            &proof,
        )
        .is_err());
        assert!(verify_proof(
            &token,
            SERVER_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION - 1,
            "prod",
            &prod_endpoint,
            &client_nonce,
            &server_nonce,
            None,
            &proof,
        )
        .is_err());
        assert!(verify_proof(
            &token,
            SERVER_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "stage",
            &stage_endpoint,
            &client_nonce,
            &server_nonce,
            None,
            &proof,
        )
        .is_err());
        assert!(verify_proof(
            &token,
            SERVER_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            "different-endpoint-id",
            &client_nonce,
            &server_nonce,
            None,
            &proof,
        )
        .is_err());
    }

    #[test]
    fn call_proofs_bind_commitment_and_reject_replay_on_new_nonces() {
        let key = test_call_key();
        let client_nonce = [1_u8; 32];
        let server_nonce = [2_u8; 32];
        let replay_server_nonce = [3_u8; 32];
        let commitment = [4_u8; 32];
        let changed_commitment = [5_u8; 32];
        let token = decode_base64_32("test token", &test_token()).unwrap();
        let endpoint = endpoint_id_with_token("prod", &token);
        let proof = encoded_proof(
            &key,
            CLIENT_CALL_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            &endpoint,
            &client_nonce,
            &server_nonce,
            Some(&commitment),
        )
        .unwrap();

        verify_proof(
            &key,
            CLIENT_CALL_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            &endpoint,
            &client_nonce,
            &server_nonce,
            Some(&commitment),
            &proof,
        )
        .unwrap();
        assert!(verify_proof(
            &key,
            CLIENT_CALL_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            &endpoint,
            &client_nonce,
            &replay_server_nonce,
            Some(&commitment),
            &proof,
        )
        .is_err());
        assert!(verify_proof(
            &key,
            CLIENT_CALL_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION,
            "prod",
            &endpoint,
            &client_nonce,
            &server_nonce,
            Some(&changed_commitment),
            &proof,
        )
        .is_err());
        assert!(verify_proof(
            &key,
            CLIENT_CALL_PROOF_DOMAIN,
            IPC_PROTOCOL_VERSION - 1,
            "prod",
            &endpoint,
            &client_nonce,
            &server_nonce,
            Some(&commitment),
            &proof,
        )
        .is_err());
    }

    #[tokio::test]
    async fn protocol_downgrade_is_rejected() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        write_frame_limited(
            &mut client,
            &Frame::AuthHello {
                version: IPC_PROTOCOL_VERSION - 1,
                client_nonce: B64.encode([7_u8; 32]),
                intent_commitment: None,
            },
            MAX_AUTH_FRAME,
        )
        .await
        .unwrap();
        let error = authenticate_server(
            &mut server,
            "prod",
            &test_token(),
            &test_call_key(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .err()
        .expect("server unexpectedly accepted a downgraded protocol");
        assert!(error
            .to_string()
            .contains("unsupported IPC authentication version"));
    }

    #[tokio::test]
    async fn client_rejects_v4_challenge_without_sending_a_response() {
        let (mut client, mut old_server) = tokio::io::duplex(1024);
        let token = test_token();
        let deadline = Instant::now() + Duration::from_secs(1);
        let client_task = authenticate_client(&mut client, "prod", &token, deadline);
        let old_server_task = async {
            let hello = read_frame_limited(&mut old_server, MAX_AUTH_FRAME)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                hello,
                Frame::AuthHello {
                    version: IPC_PROTOCOL_VERSION,
                    ..
                }
            ));
            write_frame_limited(
                &mut old_server,
                &Frame::AuthChallenge {
                    version: IPC_PROTOCOL_VERSION - 1,
                    server_nonce: B64.encode([0x33_u8; 32]),
                    server_proof: B64.encode([0x44_u8; 32]),
                    server_call_proof: None,
                },
                MAX_AUTH_FRAME,
            )
            .await
            .unwrap();
            assert!(tokio::time::timeout(
                Duration::from_millis(75),
                read_frame_limited(&mut old_server, MAX_AUTH_FRAME),
            )
            .await
            .is_err());
        };

        let (client_result, ()) = tokio::join!(client_task, old_server_task);
        assert!(client_result
            .unwrap_err()
            .to_string()
            .contains("unsupported IPC authentication version 4"));
    }

    #[tokio::test]
    async fn authentication_uses_one_absolute_deadline() {
        let (mut client, _silent_server) = tokio::io::duplex(1024);
        let deadline = Instant::now() + Duration::from_millis(20);
        let error = authenticate_client(&mut client, "prod", &test_token(), deadline)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn malformed_or_partial_intent_hello_fails_before_a_challenge() {
        let (mut malformed_client, mut malformed_server) = tokio::io::duplex(1024);
        write_frame_limited(
            &mut malformed_client,
            &Frame::AuthHello {
                version: IPC_PROTOCOL_VERSION,
                client_nonce: B64.encode([7_u8; 32]),
                intent_commitment: Some("not-canonical-base64".into()),
            },
            MAX_AUTH_FRAME,
        )
        .await
        .unwrap();
        let malformed = authenticate_server(
            &mut malformed_server,
            "prod",
            &test_token(),
            &test_call_key(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .err()
        .expect("server accepted malformed intent commitment");
        assert!(malformed.to_string().contains("intent commitment"));

        let (mut partial_client, mut partial_server) = tokio::io::duplex(1024);
        let hello = serde_json::to_vec(&Frame::AuthHello {
            version: IPC_PROTOCOL_VERSION,
            client_nonce: B64.encode([8_u8; 32]),
            intent_commitment: Some(B64.encode([9_u8; 32])),
        })
        .unwrap();
        let declared = u32::try_from(hello.len()).unwrap().to_be_bytes();
        partial_client.write_all(&declared).await.unwrap();
        partial_client
            .write_all(&hello[..hello.len() - 1])
            .await
            .unwrap();
        partial_client.shutdown().await.unwrap();
        let partial = authenticate_server(
            &mut partial_server,
            "prod",
            &test_token(),
            &test_call_key(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .err()
        .expect("server accepted a partial authentication frame");
        assert!(partial.to_string().contains("early eof"));
    }

    #[test]
    fn base64_values_are_canonical_and_exactly_32_bytes() {
        assert!(decode_base64_32("nonce", &B64.encode([1_u8; 31])).is_err());
        assert!(decode_base64_32("nonce", &B64.encode([1_u8; 33])).is_err());
        let mut unpadded = B64.encode([1_u8; 32]);
        unpadded.pop();
        assert!(decode_base64_32("nonce", &unpadded).is_err());
        assert!(decode_base64_32("nonce", &B64.encode([1_u8; 32])).is_ok());
    }

    #[test]
    fn endpoint_ids_are_domain_bound_lower_hex_and_compared_exactly() {
        let token = test_token();
        let prod = endpoint_id("prod", &token).unwrap();
        let stage = endpoint_id("stage", &token).unwrap();
        assert_ne!(prod, stage);
        assert_eq!(prod.len(), 32);
        assert!(prod
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        let endpoint =
            expected_endpoint_in_runtime_dir("prod", &token, std::path::Path::new("")).unwrap();
        assert!(endpoint.contains("serctl-v5-"));
        validate_endpoint_bytes("expected", "expected").unwrap();
        assert!(validate_endpoint_bytes("expected", "EXPECTED").is_err());
        assert!(validate_endpoint_bytes("expected", "expected ").is_err());
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

    #[tokio::test]
    async fn only_empty_stream_is_a_clean_frame_eof() {
        let mut empty = &[][..];
        assert!(read_frame_limited(&mut empty, MAX_AUTH_FRAME)
            .await
            .unwrap()
            .is_none());

        for prefix_len in 1..4 {
            let header = 1_u32.to_be_bytes();
            let mut truncated = &header[..prefix_len];
            let error = read_frame_limited(&mut truncated, MAX_AUTH_FRAME)
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("frame length prefix"),
                "unexpected error for {prefix_len}-byte prefix: {error:#}"
            );
        }
    }

    #[test]
    fn bounded_serializer_stops_at_limit_during_hostile_escaping() {
        let frame = Frame::Error {
            // Each NUL expands to a six-byte JSON escape. The serializer must
            // stop at the configured wire limit rather than build the full
            // multi-megabyte escaped representation first.
            msg: "\0".repeat(1024 * 1024),
        };
        let maximum = 4 * 1024;
        let mut counter = BoundedFrameCounter::new(maximum);
        let error = serde_json::to_writer(&mut counter, &frame).unwrap_err();

        assert!(counter.exceeded, "unexpected serialization error: {error}");
        assert!(counter.length <= maximum);
        assert!(serialize_frame_bounded(&frame, maximum).is_err());
    }

    #[test]
    fn sensitive_frame_payloads_have_one_explicit_zeroize_path() {
        let mut exec = Frame::Exec {
            cmd: "password-bearing command".into(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
        };
        exec.zeroize_sensitive();
        match exec {
            Frame::Exec { cmd, .. } => assert!(cmd.is_empty()),
            _ => unreachable!(),
        }

        let mut output = Frame::FileChunk {
            data: b"sensitive output".to_vec(),
        };
        output.zeroize_sensitive();
        match output {
            Frame::FileChunk { data } => assert!(data.is_empty()),
            _ => unreachable!(),
        }

        let mut authentication = Frame::AuthResponse {
            client_proof: "token-proof".into(),
            client_call_proof: Some("call-proof".into()),
        };
        authentication.zeroize_sensitive();
        match authentication {
            Frame::AuthResponse {
                client_proof,
                client_call_proof,
            } => {
                assert!(client_proof.is_empty());
                assert!(client_call_proof.as_deref().is_none_or(str::is_empty));
            }
            _ => unreachable!(),
        }

        let mut hello = Frame::AuthHello {
            version: IPC_PROTOCOL_VERSION,
            client_nonce: "nonce".into(),
            intent_commitment: Some("commitment".into()),
        };
        hello.zeroize_sensitive();
        match hello {
            Frame::AuthHello {
                client_nonce,
                intent_commitment,
                ..
            } => {
                assert!(client_nonce.is_empty());
                assert!(intent_commitment.as_deref().is_none_or(str::is_empty));
            }
            _ => unreachable!(),
        }

        let mut tunnel = Frame::TunnelOpen {
            spec: TunnelSpec {
                mode: TunnelMode::Local,
                bind_port: 8080,
                target_port: 22,
                max_connections: 4,
            },
        };
        tunnel.zeroize_sensitive();
        match tunnel {
            Frame::TunnelOpen { spec } => {
                assert_eq!(spec.bind_port, 8080);
                assert_eq!(spec.target_port, 22);
            }
            _ => unreachable!(),
        }

        let mut ready = Frame::TunnelReady {
            ready: TunnelReady {
                mode: TunnelMode::Local,
                bind_host: "sensitive-ready-bind".into(),
                bind_port: 8080,
            },
        };
        ready.zeroize_sensitive();
        match ready {
            Frame::TunnelReady { ready } => assert!(ready.bind_host.is_empty()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn binary_payloads_use_canonical_base64_and_fit_wire_limits() {
        let transfer_payload = vec![0xff; NATIVE_IPC_CHUNK_BYTES];
        for (frame, maximum) in [
            (
                Frame::UploadChunk {
                    data: transfer_payload.clone(),
                },
                MAX_UPLOAD_FRAME,
            ),
            (
                Frame::FileChunk {
                    data: transfer_payload.clone(),
                },
                MAX_RESPONSE_FRAME,
            ),
            (
                Frame::ShellInput {
                    data: transfer_payload.clone(),
                },
                MAX_SHELL_FRAME,
            ),
        ] {
            let encoded = serialize_frame_bounded(&frame, maximum).unwrap();
            assert!(encoded.len() <= maximum);
            let decoded: Frame = serde_json::from_slice(&encoded).unwrap();
            let data = match decoded {
                Frame::UploadChunk { data }
                | Frame::FileChunk { data }
                | Frame::ShellInput { data } => data,
                _ => panic!("binary frame changed variant during roundtrip"),
            };
            assert_eq!(data, transfer_payload);
        }

        // The aggregate exec-output limit permits arbitrary 8 MiB output. Its
        // Base64 wire representation must fit the 16 MiB response-frame cap.
        let output = Frame::ExecOut {
            data: vec![0xff; MAX_COMMAND_OUTPUT],
        };
        let encoded = serialize_frame_bounded(&output, MAX_RESPONSE_FRAME).unwrap();
        assert!(encoded.len() <= MAX_RESPONSE_FRAME);
        match serde_json::from_slice::<Frame>(&encoded).unwrap() {
            Frame::ExecOut { data } => {
                assert_eq!(data.len(), MAX_COMMAND_OUTPUT);
                assert!(data.iter().all(|byte| *byte == 0xff));
            }
            _ => panic!("exec output changed variant during roundtrip"),
        }

        assert!(serde_json::from_str::<Frame>(r#"{"t":"ShellInput","d":{"data":"/w"}}"#).is_err());
        assert!(
            serde_json::from_str::<Frame>(r#"{"t":"ShellInput","d":{"data":"/x=="}}"#).is_err()
        );
    }

    #[test]
    fn ipc_frame_rejects_unknown_authorization_fields() {
        assert!(serde_json::from_str::<Frame>(
            r#"{"t":"Exec","d":{"cmd":"id","timeout_ms":1000,"timeout_mz":999999}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Frame>(
            r#"{"t":"IssueGrant","d":{"profile":"prod","operations":["ssh.exec"],"budget":1,"ttl_secs":60,"holder_key":"key","future_scope":"admin"}}"#
        )
        .is_err());
    }

    #[test]
    fn worst_case_valid_status_metadata_fits_control_not_auth_limit() {
        let status = Frame::StatusInfo {
            profile: "p".repeat(128),
            host: "\"".repeat(1024),
            user: "\\".repeat(1024),
            started_unix: i64::MIN,
            operation_context_id: Some(OperationContextId::parse(&"ab".repeat(32)).unwrap()),
            revision: u64::MAX,
        };
        let encoded = serialize_frame_bounded(&status, MAX_CONTROL_FRAME).unwrap();
        assert!(encoded.len() > MAX_AUTH_FRAME);
        assert!(encoded.len() <= MAX_CONTROL_FRAME);
    }

    #[test]
    fn tunnel_control_frames_fit_the_control_limit() {
        let open = Frame::TunnelOpen {
            spec: TunnelSpec {
                mode: TunnelMode::Remote,
                bind_port: u16::MAX,
                target_port: u16::MAX,
                max_connections: MAX_TUNNEL_CONNECTIONS as u16,
            },
        };
        let ready = Frame::TunnelReady {
            ready: TunnelReady {
                mode: TunnelMode::Remote,
                bind_host: "b".repeat(MAX_TUNNEL_HOST_BYTES),
                bind_port: u16::MAX,
            },
        };
        for frame in [open, ready, Frame::TunnelStop, Frame::TunnelClosed] {
            assert!(serialize_frame_bounded(&frame, MAX_CONTROL_FRAME).is_ok());
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn protected_named_pipe_allows_owner_and_exposes_server_pid() {
        assert!(!PIPE_SECURITY_SDDL.contains(";;;WD"));
        assert!(!PIPE_SECURITY_SDDL.contains(";;;AN"));
        assert!(PIPE_SECURITY_SDDL.contains(";;;OW"));

        let profile = format!("pipe-test-{}", std::process::id());
        let token = test_token();
        let endpoint =
            expected_endpoint_in_runtime_dir(&profile, &token, std::path::Path::new("")).unwrap();
        let mut listener = LocalListener::bind(&endpoint).unwrap();
        let endpoint = listener.endpoint().to_owned();
        let client = tokio::time::timeout(Duration::from_secs(1), connect(&endpoint))
            .await
            .unwrap()
            .unwrap();
        validate_server_identity(&client, std::process::id()).unwrap();
        let first = listener.accept().await.unwrap();

        // accept() creates a fresh pending instance through the same secured
        // SECURITY_ATTRIBUTES path, so verify the second instance too.
        let second_client = tokio::time::timeout(Duration::from_secs(1), connect(&endpoint))
            .await
            .unwrap()
            .unwrap();
        validate_server_identity(&second_client, std::process::id()).unwrap();
        let second = listener.accept().await.unwrap();
        drop((client, first, second_client, second));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_peer_identity_checks_uid_and_pid() {
        let path = std::env::temp_dir().join(format!(
            "serctl-peer-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let server = listener.accept().await.unwrap().0;
        validate_server_identity(&client, std::process::id()).unwrap();
        drop((client, server, listener));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn unix_peer_identity_fails_closed_without_pid() {
        let uid = 1_000_u64;
        let expected_pid = std::process::id();
        let different_pid = expected_pid.wrapping_add(1);

        assert_eq!(
            validate_unix_peer_identity(uid, None, uid, expected_pid)
                .unwrap_err()
                .to_string(),
            "Unix-socket peer PID is unavailable on this platform"
        );
        assert!(
            validate_unix_peer_identity(uid, Some(i64::from(expected_pid)), uid, expected_pid)
                .is_ok()
        );
        assert!(validate_unix_peer_identity(
            uid,
            Some(i64::from(different_pid)),
            uid,
            expected_pid
        )
        .is_err());
        assert!(validate_unix_peer_identity(uid, Some(0), uid, expected_pid).is_err());
        assert!(validate_unix_peer_identity(
            uid + 1,
            Some(i64::from(expected_pid)),
            uid,
            expected_pid
        )
        .is_err());
    }
}
