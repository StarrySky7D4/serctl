//! Encrypted credential vault + protected runtime lock files.
//!
//! Version 4 gives every profile an independent passphrase, KDF, random
//! incarnation identifier, and random
//! key package.  The passphrase-derived KEK wraps `{ DEK, AuthSeed,
//! generation }`; it never encrypts SSH credentials directly.  This keeps
//! password rotation and offline recovery separate from the payload key and
//! makes IPC authorization profile- and generation-scoped.

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Block as Argon2Block, Params, Version};
use base64::{
    engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NO_PAD},
    Engine,
};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::security;

#[cfg(test)]
static TEST_HOME: std::sync::LazyLock<std::sync::RwLock<Option<PathBuf>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(None));

#[cfg(target_os = "linux")]
static LINUX_ADMIN_TARGET_HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
#[cfg(target_os = "linux")]
static LINUX_ADMIN_TARGET_VAULT_DIR: std::sync::OnceLock<File> = std::sync::OnceLock::new();
#[cfg(target_os = "linux")]
static LINUX_ADMIN_TARGET_AUTHORIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

const VAULT_FORMAT: u32 = 4;
const LEGACY_VAULT_FORMAT: u32 = 2;
const PROFILE_FORMAT_AAD: u8 = 2;
const PROFILE_FORMAT_ENVELOPE: u8 = 4;
const VERIFIER_TEXT: &[u8] = b"serctl-vault-verifier-v2";
const VERIFIER_AAD: &[u8] = b"serctl/vault/verifier/v2";
const PROFILE_CALL_KEY_DOMAIN: &[u8] = b"serctl/ipc/profile-call-key/v5\0";
const PROFILE_KEY_AAD_DOMAIN: &str = "serctl/profile-key-package/v4";
const PROFILE_PAYLOAD_AAD_DOMAIN: &str = "serctl/profile-payload/v4";
const RECOVERY_CONFIG_TAG_DOMAIN: &[u8] = b"serctl/profile-recovery-config-tag/v4\0";
const ADMIN_MARKER: &[u8] = b"serctl/windows-admin-policy/v4";
const ADMIN_AAD_DOMAIN: &str = "serctl/admin-local-recovery-share/v4";
const MAX_VAULT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOCK_BYTES: u64 = 64 * 1024;
const MAX_PROFILES: usize = 10_000;
const MIN_NEW_MASTER_BYTES: usize = 12;
const VAULT_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const VAULT_LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
#[cfg(windows)]
const LOCK_OPEN_ACCESS_DENIED_RETRIES: usize = 3;
#[cfg(windows)]
const LOCK_OPEN_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(5);

#[derive(Serialize, Deserialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Creds {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    #[serde(default)]
    pub host_key: Option<String>,
}

/// A profile-scoped IPC authorization key derived from the profile's random
/// AuthSeed. It is deliberately neither serializable nor printable and must
/// never be written to the vault or a runtime lock. The daemon retains only
/// this domain-separated key, never the profile passphrase, DEK, or AuthSeed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct ProfileCallKey(Zeroizing<[u8; 32]>);

impl ProfileCallKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Authenticated profile metadata paired with its non-exportable IPC call
/// key. This remains test-only compatibility coverage for the legacy v2 batch
/// authorization path; v4 authorizes each profile independently.
#[cfg(test)]
pub(crate) struct AuthorizedProfileMetadata {
    pub(crate) name: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) call_key: ProfileCallKey,
}

/// A profile-specific runtime/use lock coupled to the vault-wide rekey
/// barrier. Both handles stay live for the complete daemon/direct/mutation
/// lifetime, so an exclusive master rotation cannot overlap credential use.
pub(crate) struct ProfileLease {
    name: String,
    exclusive: bool,
    profile: File,
    barrier: File,
}

impl ProfileLease {
    /// Explicit release is used by daemon teardown so lock cleanup errors are
    /// observable. Drop remains the crash/cancellation-safe fallback.
    pub(crate) fn unlock(self) -> Result<()> {
        let profile = FileExt::unlock(&self.profile).context("release profile runtime lease");
        let barrier = FileExt::unlock(&self.barrier).context("release vault runtime barrier");
        profile?;
        barrier
    }

    fn require_exclusive_profile(&self, expected: &str) -> Result<()> {
        if self.name != expected || !self.exclusive {
            bail!("exclusive profile lease does not authorize mutation of '{expected}'");
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncProfile {
    pub host: String,
    pub port: u16,
    /// Per-record format. Missing/zero means the legacy unauthenticated format.
    #[serde(default)]
    pub format: u8,
    /// base64 ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: String,
    /// base64 ciphertext of `Secret`.
    pub ct: String,
    /// Legacy plaintext host key; new records keep this inside `Secret`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    /// Monotonic authorization epoch. A cached UI grant or daemon key is
    /// invalid as soon as this changes.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub generation: u64,
    /// Random logical-object incarnation. It is regenerated only when a
    /// profile is newly created/migrated and prevents delete/recreate from
    /// reviving an old generation-bound authorization.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_id: String,
    /// Per-profile Argon2id salt and policy. Present only in format 4.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_salt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_kdf: Option<KdfConfig>,
    /// Passphrase-KEK envelope containing the random DEK/AuthSeed package.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_nonce: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_ct: String,
    /// Optional public-key recovery envelope for the same key package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_envelope: Option<crate::recovery::RecoveryEnvelope>,
    /// HMAC-SHA256 under this profile's AuthSeed over the complete canonical
    /// recovery configuration. It prevents a local administrator from
    /// replacing only the public recovery key and waiting for a later profile
    /// update to seal fresh credentials to an attacker-controlled key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_config_tag: Option<String>,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KdfConfig {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_bytes: usize,
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
            output_bytes: 32,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SealedVerifier {
    pub nonce: String,
    pub ct: String,
}

#[derive(Serialize, Deserialize)]
pub struct VaultFile {
    #[serde(default)]
    pub version: u32,
    /// base64 Argon2id salt (vault-global).
    pub salt: String,
    #[serde(default)]
    pub kdf: Option<KdfConfig>,
    #[serde(default)]
    pub verifier: Option<SealedVerifier>,
    /// Windows stores only an administrator-password wrapped local recovery
    /// share.  It never stores a complete recovery key or a profile DEK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<AdminPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<crate::recovery::RecoveryConfig>,
    /// Reserved legacy field. v4 writers never populate it. Keeping the
    /// deserializer slot lets us reject experimental files explicitly rather
    /// than silently ignoring a locally stored recovery share.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_recovery_share: Option<String>,
    pub profiles: BTreeMap<String, EncProfile>,
}

impl Default for VaultFile {
    fn default() -> Self {
        Self {
            version: VAULT_FORMAT,
            salt: String::new(),
            kdf: None,
            verifier: None,
            admin: None,
            recovery: None,
            root_recovery_share: None,
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AdminPolicy {
    pub salt: String,
    pub kdf: KdfConfig,
    pub nonce: String,
    pub ct: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProfileIdentity {
    pub profile_id: [u8; 16],
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileMetadata {
    pub name: String,
    pub host: String,
    pub port: u16,
    /// Live optimistic-concurrency/cache epoch. Because the vault is an
    /// ordinary file this does not claim rollback protection against an
    /// administrator restoring an older complete vault snapshot.
    pub generation: u64,
    pub profile_id: [u8; 16],
}

impl ProfileMetadata {
    pub fn identity(&self) -> ProfileIdentity {
        ProfileIdentity {
            profile_id: self.profile_id,
            generation: self.generation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogSnapshot {
    pub format: u32,
    pub needs_migration: bool,
    pub admin_initialized: bool,
    pub recovery_initialized: bool,
    pub profiles: Vec<ProfileMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminStatus {
    Uninitialized {
        platform_requires_password: bool,
    },
    Ready {
        platform_requires_password: bool,
        recovery_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultMigrationState {
    EmptyV4 {
        admin_initialized: bool,
    },
    LegacyV2 {
        profiles: Vec<String>,
    },
    ReadyV4 {
        admin_initialized: bool,
        profiles: usize,
        recovery_configured: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrationProgress {
    Validating,
    WaitingForExclusiveAccess,
    AuthenticatedLegacyVault,
    MigratingProfile {
        completed: usize,
        total: usize,
        profile: String,
    },
    PersistingRecoveryMedia,
    CommittingVault,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct AdminSecret {
    marker: Vec<u8>,
    local_share: [u8; 32],
    recovery_config_digest: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct LockInfo {
    pub profile: String,
    /// IPC wire protocol spoken by the daemon that owns this lock. Missing
    /// means legacy bearer-token authentication and is always rejected.
    #[serde(default)]
    pub protocol: u16,
    pub pid: u32,
    /// Legacy loopback TCP port. New daemons leave this at zero.
    #[serde(default, skip_serializing_if = "is_zero_port")]
    pub port: u16,
    /// Platform-local endpoint: Windows named pipe or Unix socket path.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    /// Kept for reading v1 lock files. New lock files omit remote metadata.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    pub started_unix: i64,
    /// Random capability required before any IPC command is accepted.
    #[serde(default)]
    pub token: String,
}

fn is_zero_port(port: &u16) -> bool {
    *port == 0
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Secret {
    user: String,
    password: String,
    #[serde(default)]
    host_key: Option<String>,
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn home_dir() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_HOME.read().expect("test home lock poisoned").clone() {
        return Ok(path);
    }
    #[cfg(target_os = "linux")]
    if let Some(path) = LINUX_ADMIN_TARGET_HOME.get() {
        return Ok(path.clone());
    }
    #[cfg(windows)]
    if let Some(p) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(p));
    }
    bail!("cannot determine home directory")
}

/// Return the directory identity used for containment checks without
/// re-resolving a delegated Linux target through its original NSS pathname.
/// Normal callers retain the non-creating historical behavior.
pub(crate) fn vault_dir_for_external_path_validation() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    if let Some(directory) = LINUX_ADMIN_TARGET_VAULT_DIR.get() {
        use std::os::fd::AsRawFd;

        return Ok(PathBuf::from(format!(
            "/proc/self/fd/{}",
            directory.as_raw_fd()
        )));
    }
    Ok(home_dir()?.join(".serctl"))
}

#[cfg(test)]
pub(crate) fn set_test_home(path: Option<PathBuf>) {
    *TEST_HOME.write().expect("test home lock poisoned") = path;
}

pub fn dir() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    if let Some(directory) = LINUX_ADMIN_TARGET_VAULT_DIR.get() {
        use std::os::fd::AsRawFd;

        // Anchor every privileged target-user operation to the exact
        // directory handle verified before privilege drop. Re-resolving the
        // NSS home text would let the target account rename/replace .serctl
        // between validation and the destructive reset.
        security::harden_open_directory(directory)?;
        return Ok(PathBuf::from(format!(
            "/proc/self/fd/{}",
            directory.as_raw_fd()
        )));
    }
    let path = home_dir()?.join(".serctl");
    std::fs::create_dir_all(&path)?;
    security::harden_directory(&path)?;
    Ok(path)
}

pub fn vault_path() -> Result<PathBuf> {
    Ok(dir()?.join("vault.json"))
}

pub fn run_dir() -> Result<PathBuf> {
    // Validate and harden the `.serctl` parent as its own final component
    // before touching `run`, so a pre-created parent link/reparse point is
    // rejected rather than traversed by create_dir_all.
    let path = dir()?.join("run");
    std::fs::create_dir_all(&path)?;
    security::harden_directory(&path)?;
    Ok(path)
}

/// Resolve the runtime directory without creating it or rewriting its ACL.
/// Read-only lock polling and daemon teardown must not contend over directory
/// security metadata on Windows.
fn run_dir_path() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    if LINUX_ADMIN_TARGET_VAULT_DIR.get().is_some() {
        return Ok(dir()?.join("run"));
    }
    Ok(home_dir()?.join(".serctl").join("run"))
}

/// Lock filenames are hashes, so even legacy profile names cannot escape the
/// run directory or target reserved Windows device names.
pub fn lock_path(profile: &str) -> Result<PathBuf> {
    Ok(run_dir()?.join(lock_filename(profile)))
}

fn existing_lock_path(profile: &str) -> Result<PathBuf> {
    Ok(run_dir_path()?.join(lock_filename(profile)))
}

fn lock_filename(profile: &str) -> String {
    let digest = Sha256::digest(profile.as_bytes());
    format!("{}.lock", hex::encode(digest))
}

fn runtime_lease_path(profile: &str) -> Result<PathBuf> {
    let digest = Sha256::digest(profile.as_bytes());
    Ok(run_dir()?.join(format!("{}.lease", hex::encode(digest))))
}

fn existing_runtime_lease_path(profile: &str) -> Result<PathBuf> {
    let digest = Sha256::digest(profile.as_bytes());
    Ok(run_dir_path()?.join(format!("{}.lease", hex::encode(digest))))
}

fn runtime_barrier_path() -> Result<PathBuf> {
    Ok(run_dir()?.join("vault-runtime-v1.barrier"))
}

fn open_runtime_barrier_file() -> Result<File> {
    let path = runtime_barrier_path()?;
    security::open_or_create_protected_file(&path)
        .with_context(|| format!("open vault runtime barrier {}", path.display()))
}

fn open_runtime_lease_file(profile: &str) -> Result<File> {
    let path = runtime_lease_path(profile)?;
    security::open_or_create_protected_file(&path)
        .with_context(|| format!("open runtime lease {}", path.display()))
}

fn open_existing_runtime_lease_file(profile: &str) -> Result<Option<File>> {
    let path = existing_runtime_lease_path(profile)?;
    security::open_existing_protected_file(&path)
        .with_context(|| format!("open existing runtime lease {}", path.display()))
}

fn acquire_runtime_barrier_shared() -> Result<File> {
    let barrier = open_runtime_barrier_file()?;
    match FileExt::try_lock_shared(&barrier) {
        Ok(()) => Ok(barrier),
        Err(error) if is_lock_contention(&error) => {
            bail!("vault master rotation is in progress; retry the profile operation")
        }
        Err(error) => Err(error).context("acquire shared vault runtime barrier"),
    }
}

fn acquire_runtime_barrier_exclusive() -> Result<File> {
    let barrier = open_runtime_barrier_file()?;
    match barrier.try_lock_exclusive() {
        Ok(()) => Ok(barrier),
        Err(error) if is_lock_contention(&error) => {
            bail!("cannot rotate the vault master while a profile is in use or being modified")
        }
        Err(error) => Err(error).context("acquire exclusive vault runtime barrier"),
    }
}

fn is_lock_contention(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION as i32) {
        return true;
    }
    false
}

/// Whether the daemon's exclusive lifetime lease is still held. A shared
/// probe deliberately coexists with direct profile-use leases while remaining
/// mutually exclusive with daemon startup/runtime ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeLeaseLiveness {
    Released,
    Held,
}

/// Probe daemon lease liveness without retaining a lock. A successful shared
/// acquisition is explicitly unlocked before the stable handle is dropped;
/// contention is the only condition classified as `Held`, and every other I/O
/// failure remains fail-closed.
pub fn probe_runtime_lease_liveness(profile: &str) -> Result<RuntimeLeaseLiveness> {
    let file = open_runtime_lease_file(profile)?;
    probe_runtime_lease_liveness_with(
        || FileExt::try_lock_shared(&file),
        || FileExt::unlock(&file),
    )
}

fn probe_runtime_lease_liveness_with<T, U>(try_shared: T, unlock: U) -> Result<RuntimeLeaseLiveness>
where
    T: FnOnce() -> std::io::Result<()>,
    U: FnOnce() -> std::io::Result<()>,
{
    match try_shared() {
        Ok(()) => {
            unlock().context("release daemon runtime-lease liveness probe")?;
            Ok(RuntimeLeaseLiveness::Released)
        }
        Err(error) if is_lock_contention(&error) => Ok(RuntimeLeaseLiveness::Held),
        Err(error) => Err(error).context("probe daemon runtime lease liveness"),
    }
}

/// Acquire the lifetime lease for one profile daemon. The OS releases this
/// automatically if the daemon exits or crashes.
pub(crate) fn acquire_runtime_lease(profile: &str) -> Result<ProfileLease> {
    validate_profile_name(profile)?;
    // Global-before-profile is the single lock order used by every current
    // operation. Rekey takes only the exclusive global side before the vault
    // file lock, eliminating the former O(profile-count) handle requirement.
    let barrier = acquire_runtime_barrier_shared()?;
    let file = open_runtime_lease_file(profile)?;
    match file.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if is_lock_contention(&error) => {
            bail!("a daemon is already starting or running for '{profile}'");
        }
        Err(error) => return Err(error).context("acquire daemon runtime lease"),
    }
    Ok(ProfileLease {
        name: profile.to_owned(),
        exclusive: true,
        profile: file,
        barrier,
    })
}

/// Hold a shared lease while a direct (non-daemon) operation is using a
/// profile snapshot. Multiple direct operations may coexist, but daemon
/// startup and credential mutation require the exclusive form above.
pub(crate) fn acquire_profile_use_lease(profile: &str) -> Result<ProfileLease> {
    validate_profile_name(profile)?;
    let barrier = acquire_runtime_barrier_shared()?;
    let file = open_runtime_lease_file(profile)?;
    match FileExt::try_lock_shared(&file) {
        Ok(()) => {}
        Err(error) if is_lock_contention(&error) => {
            bail!("profile '{profile}' is being changed or used by a daemon");
        }
        Err(error) => return Err(error).context("acquire direct profile-use lease"),
    }
    Ok(ProfileLease {
        name: profile.to_owned(),
        exclusive: false,
        profile: file,
        barrier,
    })
}

fn acquire_profile_mutation_lease(profile: &str) -> Result<ProfileLease> {
    validate_profile_name(profile)?;
    let barrier = acquire_runtime_barrier_shared()?;
    let profile_file = acquire_profile_mutation_lease_with(
        profile,
        || open_runtime_lease_file(profile),
        FileExt::try_lock_exclusive,
    )?;
    Ok(ProfileLease {
        name: profile.to_owned(),
        exclusive: true,
        profile: profile_file,
        barrier,
    })
}

fn acquire_profile_mutation_lease_with<T>(
    profile: &str,
    open: impl FnOnce() -> Result<T>,
    try_lock_exclusive: impl FnOnce(&T) -> std::io::Result<()>,
) -> Result<T> {
    let lease = open().with_context(|| format!("open mutation lease for profile '{profile}'"))?;
    match try_lock_exclusive(&lease) {
        Ok(()) => Ok(lease),
        Err(error) if is_lock_contention(&error) => bail!(
            "cannot modify profile '{profile}' while it is in use by a direct operation or daemon"
        ),
        Err(error) => {
            Err(error).with_context(|| format!("acquire mutation lease for profile '{profile}'"))
        }
    }
}

fn acquire_rename_leases(old_name: &str, new_name: &str) -> Result<(ProfileLease, ProfileLease)> {
    // A stable acquisition order prevents concurrent cross-renames from
    // deadlocking while also excluding daemon startup for both names.
    if old_name < new_name {
        let old = acquire_profile_mutation_lease(old_name)?;
        let new = acquire_profile_mutation_lease(new_name)?;
        Ok((old, new))
    } else {
        let new = acquire_profile_mutation_lease(new_name)?;
        let old = acquire_profile_mutation_lease(old_name)?;
        Ok((old, new))
    }
}

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

pub fn new_ipc_token() -> String {
    let mut token = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut *token);
    B64.encode(token.as_ref())
}

pub fn load_vault() -> Result<VaultFile> {
    load_vault_with_lock_timeout(VAULT_LOCK_WAIT_TIMEOUT)
}

fn load_vault_with_lock_timeout(lock_timeout: Duration) -> Result<VaultFile> {
    let lock = open_vault_lock()?;
    lock_vault_with_timeout(
        &lock,
        VaultLockMode::Shared,
        lock_timeout.min(VAULT_LOCK_WAIT_TIMEOUT),
    )?;
    load_vault_unlocked()
}

fn load_vault_unlocked() -> Result<VaultFile> {
    let path = vault_path()?;
    let Some(mut file) = security::open_existing_protected_file(&path)
        .with_context(|| format!("open encrypted vault {}", path.display()))?
    else {
        return Ok(VaultFile::default());
    };
    let metadata_len = file
        .metadata()
        .with_context(|| format!("inspect encrypted vault {}", path.display()))?
        .len();
    let bytes = read_bounded_handle(
        &mut file,
        metadata_len,
        MAX_VAULT_BYTES,
        BoundedReadAllocation::MetadataLength,
        "vault exceeds the 16 MiB safety limit",
    )
    .with_context(|| format!("read encrypted vault {}", path.display()))?;
    let vault: VaultFile = serde_json::from_slice(&bytes).context("parse encrypted vault")?;
    validate_loaded_vault(&vault)?;
    Ok(vault)
}

fn open_vault_lock() -> Result<File> {
    let path = dir()?.join("vault.lock");
    security::open_or_create_protected_file(&path)
        .with_context(|| format!("open vault lock {}", path.display()))
}

fn save_vault_unlocked(vault: &VaultFile) -> Result<()> {
    // Never persist an in-memory state that this binary would reject on its
    // next load. This closes every mutation path, including future callers,
    // against creating a self-locking vault.
    validate_loaded_vault(vault).context("refuse to save an invalid encrypted vault")?;
    let path = vault_path()?;
    let bytes = serialize_json_zeroizing(
        vault,
        MAX_VAULT_BYTES as usize,
        JsonStyle::Pretty,
        "vault exceeds the 16 MiB safety limit",
    )?;
    security::write_protected_atomic(&path, &bytes)
}

fn vault_state_digest(vault: &VaultFile) -> Result<[u8; 32]> {
    // Hash a canonical in-memory serialization, rather than the source file's
    // whitespace, so the comparison represents semantic vault state. The
    // serialized bytes contain ciphertext only and are still erased promptly
    // by the Zeroizing guard.
    let serialized = serialize_json_zeroizing(
        vault,
        MAX_VAULT_BYTES as usize,
        JsonStyle::Compact,
        "vault exceeds the 16 MiB safety limit",
    )?;
    Ok(Sha256::digest(serialized.as_slice()).into())
}

fn validate_loaded_vault(vault: &VaultFile) -> Result<()> {
    if vault.version == 3 {
        bail!("pre-release vault format v3 is incompatible with v4 profile identities; use the matching older build to export it or restore a backup, then rebuild the vault")
    }
    if !matches!(vault.version, 0 | LEGACY_VAULT_FORMAT | VAULT_FORMAT) {
        bail!("unsupported vault format version {}", vault.version);
    }
    if vault.profiles.len() > MAX_PROFILES {
        bail!("vault contains too many profiles");
    }
    for (name, profile) in &vault.profiles {
        validate_profile_name(name)
            .with_context(|| format!("vault contains unsafe profile name '{name}'"))?;
        let valid_record_format = if vault.version == VAULT_FORMAT {
            profile.format == PROFILE_FORMAT_ENVELOPE
        } else {
            matches!(profile.format, 0 | PROFILE_FORMAT_AAD)
        };
        if !valid_record_format {
            bail!("profile '{name}' uses an unsupported encrypted format");
        }
        validate_endpoint_fields(&profile.host, profile.port)
            .with_context(|| format!("profile '{name}' contains an unsafe endpoint"))?;
        if let Some(host_key) = profile.host_key.as_deref() {
            if host_key.is_empty() || host_key.len() > 1024 || contains_control_character(host_key)
            {
                bail!("profile '{name}' contains an unsafe legacy host-key value");
            }
        }
        if profile.format == PROFILE_FORMAT_ENVELOPE {
            if profile.generation == 0
                || profile.profile_id.is_empty()
                || profile.profile_salt.is_empty()
                || profile.profile_kdf.is_none()
                || profile.key_nonce.is_empty()
                || profile.key_ct.is_empty()
                || profile.host_key.is_some()
            {
                bail!("profile '{name}' has an incomplete v4 key envelope");
            }
            decode_profile_id(&profile.profile_id)
                .with_context(|| format!("decode profile '{name}' identity"))?;
            let salt = B64
                .decode(&profile.profile_salt)
                .with_context(|| format!("decode profile '{name}' salt"))?;
            if salt.len() != 16 {
                bail!("profile '{name}' salt must be exactly 16 bytes");
            }
            validate_kdf(profile.profile_kdf.as_ref().expect("checked above"))?;
            decode_nonce(&profile.key_nonce)
                .with_context(|| format!("decode profile '{name}' key-envelope nonce"))?;
            decode_nonce(&profile.nonce)
                .with_context(|| format!("decode profile '{name}' payload nonce"))?;
            if profile.key_ct.len() > MAX_VAULT_BYTES as usize
                || profile.ct.len() > MAX_VAULT_BYTES as usize
            {
                bail!("profile '{name}' ciphertext exceeds its safety limit");
            }
            match (
                &vault.recovery,
                &profile.recovery_envelope,
                &profile.recovery_config_tag,
            ) {
                (Some(_), Some(envelope), Some(tag)) => {
                    crate::recovery::validate_recovery_envelope(envelope)
                        .with_context(|| format!("validate profile '{name}' recovery envelope"))?;
                    decode_recovery_config_tag(tag).with_context(|| {
                        format!("validate profile '{name}' recovery configuration tag")
                    })?;
                }
                (Some(_), _, _) => {
                    bail!("profile '{name}' is missing its configured recovery envelope or tag")
                }
                (None, Some(_), _) | (None, _, Some(_)) => {
                    bail!("profile '{name}' has recovery material without vault recovery configuration")
                }
                (None, None, None) => {}
            }
        }
    }
    if let Some(config) = &vault.kdf {
        validate_kdf(config)?;
    }
    if vault.version == VAULT_FORMAT
        && (!vault.salt.is_empty() || vault.kdf.is_some() || vault.verifier.is_some())
    {
        bail!("v4 vault must not retain a vault-global passphrase verifier or KDF");
    }
    if vault.version != VAULT_FORMAT
        && (vault.admin.is_some()
            || vault.recovery.is_some()
            || vault.root_recovery_share.is_some())
    {
        bail!("legacy vault must not contain v4 administrator or recovery fields");
    }
    if let Some(recovery) = &vault.recovery {
        crate::recovery::validate_recovery_config(recovery)
            .context("validate vault recovery configuration")?;
    }
    if let Some(policy) = &vault.admin {
        validate_kdf(&policy.kdf).context("validate administrator KDF")?;
        let salt = B64
            .decode(&policy.salt)
            .context("decode administrator salt")?;
        if salt.len() != 16 {
            bail!("administrator salt must be exactly 16 bytes");
        }
        decode_nonce(&policy.nonce).context("decode administrator envelope nonce")?;
        if policy.ct.is_empty() || policy.ct.len() > 8192 {
            bail!("administrator envelope is empty or oversized");
        }
    }
    if vault.root_recovery_share.is_some() {
        bail!("vault must never contain a complete local root recovery share");
    }
    #[cfg(windows)]
    {
        if vault.version == VAULT_FORMAT && (vault.admin.is_some() != vault.recovery.is_some()) {
            bail!("Windows administrator and recovery policies must be initialized together");
        }
        if vault.version == VAULT_FORMAT && !vault.profiles.is_empty() && vault.admin.is_none() {
            bail!("Windows v4 profiles require an initialized administrator/recovery policy");
        }
    }
    #[cfg(unix)]
    {
        if vault.admin.is_some() {
            bail!("Linux vault must use root authorization, not a stored administrator password");
        }
        if vault.recovery.is_some() {
            bail!("Linux offline recovery is unavailable until a root-owned system share store and explicit target-user boundary are configured");
        }
    }
    Ok(())
}

fn mutate_vault<T>(mutator: impl FnOnce(&mut VaultFile) -> Result<T>) -> Result<T> {
    mutate_vault_with_lock_timeout(VAULT_LOCK_WAIT_TIMEOUT, mutator)
}

fn mutate_vault_with_lock_timeout<T>(
    lock_timeout: Duration,
    mutator: impl FnOnce(&mut VaultFile) -> Result<T>,
) -> Result<T> {
    let lock = open_vault_lock()?;
    lock_vault_with_timeout(
        &lock,
        VaultLockMode::Exclusive,
        lock_timeout.min(VAULT_LOCK_WAIT_TIMEOUT),
    )?;
    let mut vault = load_vault_unlocked()?;
    let result = mutator(&mut vault)?;
    validate_loaded_vault(&vault).context("vault mutation produced an invalid state")?;
    save_vault_unlocked(&vault)?;
    Ok(result)
}

#[derive(Clone, Copy)]
enum VaultLockMode {
    Shared,
    Exclusive,
}

fn lock_vault_with_timeout(file: &File, mode: VaultLockMode, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let label = match mode {
        VaultLockMode::Shared => "shared",
        VaultLockMode::Exclusive => "exclusive",
    };
    loop {
        let result = match mode {
            VaultLockMode::Shared => FileExt::try_lock_shared(file),
            VaultLockMode::Exclusive => file.try_lock_exclusive(),
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error)
                if is_lock_contention(&error)
                    || error.kind() == std::io::ErrorKind::Interrupted =>
            {
                let now = Instant::now();
                if now >= deadline {
                    bail!(
                        "timed out waiting for encrypted vault {label} lock after {} ms",
                        timeout.as_millis()
                    );
                }
                std::thread::sleep(VAULT_LOCK_RETRY_DELAY.min(deadline - now));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("acquire encrypted vault {label} lock"));
            }
        }
    }
}

#[derive(Clone, Copy)]
enum JsonStyle {
    Compact,
    Pretty,
}

struct BoundedJsonCounter {
    length: usize,
    maximum: usize,
    exceeded: bool,
}

impl BoundedJsonCounter {
    fn new(maximum: usize) -> Self {
        Self {
            length: 0,
            maximum,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(length) = self.length.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "JSON length overflow",
            ));
        };
        if length > self.maximum {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "JSON exceeds configured limit",
            ));
        }
        self.length = length;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct PreallocatedZeroizingJson {
    bytes: Zeroizing<Vec<u8>>,
    expected: usize,
}

impl PreallocatedZeroizingJson {
    fn new(expected: usize) -> Result<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(expected)
            .map_err(|error| anyhow!("reserve sensitive JSON buffer: {error}"))?;
        Ok(Self { bytes, expected })
    }
}

impl Write for PreallocatedZeroizingJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(length) = self.bytes.len().checked_add(bytes.len()) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sensitive JSON length overflow",
            ));
        };
        if length > self.expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sensitive JSON length changed between sizing and serialization",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_json<T: Serialize, W: Write>(writer: W, value: &T, style: JsonStyle) -> Result<()> {
    match style {
        JsonStyle::Compact => serde_json::to_writer(writer, value)?,
        JsonStyle::Pretty => serde_json::to_writer_pretty(writer, value)?,
    }
    Ok(())
}

/// Size without retaining plaintext, then serialize directly into a
/// zeroizing allocation whose full capacity already exists before the first
/// sensitive byte is written. This prevents Vec growth from leaving freed
/// heap allocations containing prior plaintext copies.
fn serialize_json_zeroizing<T: Serialize>(
    value: &T,
    maximum: usize,
    style: JsonStyle,
    limit_error: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut counter = BoundedJsonCounter::new(maximum);
    if let Err(error) = write_json(&mut counter, value, style) {
        if counter.exceeded {
            return Err(anyhow!(limit_error));
        }
        return Err(error);
    }

    let expected = counter.length;
    let mut sink = PreallocatedZeroizingJson::new(expected)?;
    write_json(&mut sink, value, style)?;
    if sink.bytes.len() != expected {
        bail!("sensitive JSON length changed between sizing and serialization");
    }
    Ok(sink.bytes)
}

fn validate_kdf(config: &KdfConfig) -> Result<()> {
    if !(8 * 1024..=256 * 1024).contains(&config.memory_kib)
        || !(1..=10).contains(&config.iterations)
        || !(1..=16).contains(&config.parallelism)
        || config.output_bytes != 32
    {
        bail!("vault contains unsafe or unsupported KDF parameters");
    }
    Ok(())
}

fn new_profile_kdf() -> KdfConfig {
    #[cfg(test)]
    {
        KdfConfig {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
            output_bytes: 32,
        }
    }
    #[cfg(not(test))]
    {
        KdfConfig::default()
    }
}

fn derive_key(master: &[u8], salt: &[u8], config: &KdfConfig) -> Result<Zeroizing<[u8; 32]>> {
    validate_kdf(config)?;
    if salt.len() != 16 {
        bail!("vault salt must be exactly 16 bytes");
    }
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(config.output_bytes),
    )
    .map_err(|e| anyhow!(e))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    // `Argon2::hash_password_into` owns an ordinary `Vec<Block>` and does not
    // erase the memory matrix when it returns. Allocate the exact matrix here
    // under a Zeroizing guard instead. The argon2 `zeroize` feature additionally
    // erases its internal initial/block hashes; using `Argon2Block` here makes
    // that feature a compile-time requirement rather than a manifest-only
    // promise.
    let block_count = argon.params().block_count();
    let mut memory = Zeroizing::new(Vec::<Argon2Block>::new());
    memory
        .try_reserve_exact(block_count)
        .map_err(|error| anyhow!("reserve Argon2 working memory: {error}"))?;
    memory.resize(block_count, Argon2Block::default());
    argon
        .hash_password_into_with_memory(master, salt, output.as_mut(), memory.as_mut_slice())
        .map_err(|e| anyhow!(e))?;
    Ok(output)
}

fn vault_key(vault: &VaultFile, master: &str) -> Result<Zeroizing<[u8; 32]>> {
    let salt = B64.decode(&vault.salt).context("decode vault salt")?;
    let config = vault.kdf.clone().unwrap_or_default();
    derive_key(master.as_bytes(), &salt, &config)
}

#[cfg(test)]
fn profile_call_key(vault_key: &[u8; 32], profile: &str) -> Result<ProfileCallKey> {
    validate_profile_name(profile)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(vault_key)
        .map_err(|_| anyhow!("invalid vault key for profile call authorization"))?;
    mac.update(PROFILE_CALL_KEY_DOMAIN);
    mac.update(&(profile.len() as u32).to_be_bytes());
    mac.update(profile.as_bytes());
    let mut digest = mac.finalize().into_bytes();
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    Ok(ProfileCallKey(key))
}

fn decode_nonce(encoded: &str) -> Result<[u8; 12]> {
    let bytes = B64.decode(encoded).context("decode AEAD nonce")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("AEAD nonce must be exactly 12 bytes"))
}

fn profile_aad(name: &str, host: &str, port: u16) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(
        "serctl/profile/v2",
        name,
        host,
        port,
    ))?)
}

fn reject_legacy_profile_for_network(name: &str, encrypted: &EncProfile) -> Result<()> {
    match encrypted.format {
        PROFILE_FORMAT_AAD => Ok(()),
        0 => bail!(
            "legacy profile '{name}' has unauthenticated endpoint metadata and cannot be used; \
             delete and recreate it, or replace its credentials through an explicit offline migration"
        ),
        _ => bail!("profile '{name}' uses an unsupported encrypted format"),
    }
}

/// Decrypt a v2 profile for normal use. The format check intentionally runs
/// before nonce/ciphertext decoding so no legacy credential can be returned,
/// even if an attacker has modified its host, port, pin, or encrypted body.
fn decrypt_profile_with_key(name: &str, encrypted: &EncProfile, key: &[u8; 32]) -> Result<Creds> {
    reject_legacy_profile_for_network(name, encrypted)?;
    let creds = decrypt_profile_payload_with_key(name, encrypted, key)?;
    validate_decrypted_creds(&creds)
        .with_context(|| format!("profile '{name}' decrypted to unsafe credential fields"))?;
    Ok(creds)
}

/// Raw legacy decryption exists only to verify a master passphrase before an
/// offline replacement. Callers must never return this plaintext for SSH or
/// inherit its unauthenticated host-key pin.
fn decrypt_profile_payload_with_key(
    name: &str,
    encrypted: &EncProfile,
    key: &[u8; 32],
) -> Result<Creds> {
    let nonce = decode_nonce(&encrypted.nonce)?;
    let ciphertext = B64.decode(&encrypted.ct).context("decode ciphertext")?;
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = match encrypted.format {
        PROFILE_FORMAT_AAD => {
            let aad = profile_aad(name, &encrypted.host, encrypted.port)?;
            cipher.decrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
        }
        0 => cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref()),
        _ => bail!("profile '{name}' uses an unsupported encrypted format"),
    }
    .map_err(|_| anyhow!("decrypt failed (wrong master passphrase or tampered profile)"))?;
    let plaintext = Zeroizing::new(plaintext);
    let mut secret: Secret = serde_json::from_slice(&plaintext)?;
    let host_key = if encrypted.format == PROFILE_FORMAT_AAD {
        secret.host_key.take()
    } else {
        encrypted
            .host_key
            .clone()
            .or_else(|| secret.host_key.take())
    };
    Ok(Creds {
        host: encrypted.host.clone(),
        port: encrypted.port,
        user: std::mem::take(&mut secret.user),
        password: std::mem::take(&mut secret.password),
        host_key,
    })
}

#[cfg(test)]
fn encrypt_profile(name: &str, creds: &Creds, key: &[u8; 32]) -> Result<EncProfile> {
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let secret = Secret {
        user: creds.user.clone(),
        password: creds.password.clone(),
        host_key: creds.host_key.clone(),
    };
    let plaintext = serialize_json_zeroizing(
        &secret,
        MAX_VAULT_BYTES as usize,
        JsonStyle::Compact,
        "encrypted profile plaintext exceeds the 16 MiB safety limit",
    )?;
    let aad = profile_aad(name, &creds.host, creds.port)?;
    let cipher = ChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("encrypt failed"))?;
    Ok(EncProfile {
        host: creds.host.clone(),
        port: creds.port,
        format: PROFILE_FORMAT_AAD,
        nonce: B64.encode(nonce),
        ct: B64.encode(ciphertext),
        host_key: None,
        generation: 0,
        profile_id: String::new(),
        profile_salt: String::new(),
        profile_kdf: None,
        key_nonce: String::new(),
        key_ct: String::new(),
        recovery_envelope: None,
        recovery_config_tag: None,
    })
}

fn profile_key_aad(
    name: &str,
    profile_id: &[u8; 16],
    host: &str,
    port: u16,
    generation: u64,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(
        PROFILE_KEY_AAD_DOMAIN,
        name,
        profile_id,
        host,
        port,
        generation,
    ))?)
}

fn profile_payload_aad(
    name: &str,
    profile_id: &[u8; 16],
    host: &str,
    port: u16,
    generation: u64,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(
        PROFILE_PAYLOAD_AAD_DOMAIN,
        name,
        profile_id,
        host,
        port,
        generation,
    ))?)
}

fn canonical_recovery_config(
    config: &crate::recovery::RecoveryConfig,
) -> Result<Zeroizing<Vec<u8>>> {
    crate::recovery::validate_recovery_config(config)?;
    serialize_json_zeroizing(
        config,
        4096,
        JsonStyle::Compact,
        "recovery configuration exceeds its safety limit",
    )
}

fn recovery_config_digest(config: &crate::recovery::RecoveryConfig) -> Result<[u8; 32]> {
    let canonical = canonical_recovery_config(config)?;
    Ok(Sha256::digest(canonical.as_slice()).into())
}

fn recovery_config_tag(
    auth_seed: &[u8; 32],
    config: &crate::recovery::RecoveryConfig,
) -> Result<String> {
    let canonical = canonical_recovery_config(config)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(auth_seed)
        .map_err(|_| anyhow!("initialize recovery configuration authenticator"))?;
    mac.update(RECOVERY_CONFIG_TAG_DOMAIN);
    mac.update(canonical.as_slice());
    Ok(B64.encode(mac.finalize().into_bytes()))
}

fn decode_recovery_config_tag(encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    if encoded.len() != 44 {
        bail!("recovery configuration tag must canonically encode 32 bytes");
    }
    let decoded = Zeroizing::new(
        B64.decode(encoded)
            .context("decode recovery configuration tag")?,
    );
    if decoded.len() != 32 || B64.encode(decoded.as_slice()).as_bytes() != encoded.as_bytes() {
        bail!("recovery configuration tag must canonically encode 32 bytes");
    }
    let mut tag = Zeroizing::new([0_u8; 32]);
    tag.copy_from_slice(decoded.as_slice());
    Ok(tag)
}

fn encode_profile_id(profile_id: &[u8; 16]) -> String {
    B64_NO_PAD.encode(profile_id)
}

fn decode_profile_id(encoded: &str) -> Result<[u8; 16]> {
    let decoded = B64_NO_PAD
        .decode(encoded)
        .context("decode profile identity")?;
    if decoded.len() != 16 || B64_NO_PAD.encode(&decoded).as_bytes() != encoded.as_bytes() {
        bail!("profile identity must canonically encode exactly 16 bytes");
    }
    let mut profile_id = [0_u8; 16];
    profile_id.copy_from_slice(&decoded);
    Ok(profile_id)
}

fn profile_identity(encrypted: &EncProfile) -> Result<ProfileIdentity> {
    Ok(ProfileIdentity {
        profile_id: decode_profile_id(&encrypted.profile_id)?,
        generation: encrypted.generation,
    })
}

fn verify_recovery_binding(
    encrypted: &EncProfile,
    package: &crate::recovery::KeyPackage,
    recovery: Option<&crate::recovery::RecoveryConfig>,
) -> Result<()> {
    use subtle::ConstantTimeEq;

    match (
        recovery,
        encrypted.recovery_envelope.as_ref(),
        encrypted.recovery_config_tag.as_ref(),
    ) {
        (None, None, None) => Ok(()),
        (Some(config), Some(_), Some(encoded)) => {
            let provided = decode_recovery_config_tag(encoded)?;
            let expected_encoded = Zeroizing::new(recovery_config_tag(&package.auth_seed, config)?);
            let expected = decode_recovery_config_tag(&expected_encoded)?;
            if !bool::from(provided.ct_eq(&*expected)) {
                bail!("profile recovery configuration authentication failed");
            }
            Ok(())
        }
        _ => bail!("profile recovery configuration is incomplete or inconsistent"),
    }
}

fn new_profile_id() -> [u8; 16] {
    let mut profile_id = [0_u8; 16];
    OsRng.fill_bytes(&mut profile_id);
    profile_id
}

fn new_key_package(profile_id: [u8; 16], generation: u64) -> crate::recovery::KeyPackage {
    let mut package = crate::recovery::KeyPackage {
        profile_id,
        generation,
        dek: [0_u8; 32],
        auth_seed: [0_u8; 32],
    };
    OsRng.fill_bytes(&mut package.dek);
    OsRng.fill_bytes(&mut package.auth_seed);
    package
}

fn profile_kek(encrypted: &EncProfile, passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    validate_master_passphrase(passphrase)?;
    let salt = B64
        .decode(&encrypted.profile_salt)
        .context("decode profile KDF salt")?;
    let kdf = encrypted
        .profile_kdf
        .as_ref()
        .ok_or_else(|| anyhow!("profile is missing its independent KDF policy"))?;
    derive_key(passphrase.as_bytes(), &salt, kdf)
}

fn unwrap_profile_package(
    name: &str,
    encrypted: &EncProfile,
    passphrase: &str,
) -> Result<crate::recovery::KeyPackage> {
    if encrypted.format != PROFILE_FORMAT_ENVELOPE || encrypted.generation == 0 {
        bail!("profile '{name}' requires explicit v2-to-v4 migration");
    }
    let kek = profile_kek(encrypted, passphrase)?;
    let nonce = decode_nonce(&encrypted.key_nonce)?;
    let ciphertext = B64
        .decode(&encrypted.key_ct)
        .context("decode profile key envelope")?;
    let profile_id = decode_profile_id(&encrypted.profile_id)?;
    let aad = profile_key_aad(
        name,
        &profile_id,
        &encrypted.host,
        encrypted.port,
        encrypted.generation,
    )?;
    let plaintext = ChaCha20Poly1305::new(kek.as_ref().into())
        .decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("wrong profile passphrase or tampered key envelope"))?;
    let plaintext = Zeroizing::new(plaintext);
    let package: crate::recovery::KeyPackage =
        serde_json::from_slice(&plaintext).context("decode profile key package")?;
    if package.profile_id != profile_id || package.generation != encrypted.generation {
        bail!("profile key package identity mismatch");
    }
    Ok(package)
}

fn decrypt_profile_v3_with_package(
    name: &str,
    encrypted: &EncProfile,
    package: &crate::recovery::KeyPackage,
) -> Result<Creds> {
    let profile_id = decode_profile_id(&encrypted.profile_id)?;
    if package.profile_id != profile_id || package.generation != encrypted.generation {
        bail!("profile key package identity mismatch");
    }
    let nonce = decode_nonce(&encrypted.nonce)?;
    let ciphertext = B64
        .decode(&encrypted.ct)
        .context("decode profile payload ciphertext")?;
    let aad = profile_payload_aad(
        name,
        &profile_id,
        &encrypted.host,
        encrypted.port,
        encrypted.generation,
    )?;
    let plaintext = ChaCha20Poly1305::new((&package.dek).into())
        .decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("profile payload authentication failed"))?;
    let plaintext = Zeroizing::new(plaintext);
    let mut secret: Secret = serde_json::from_slice(&plaintext)?;
    let creds = Creds {
        host: encrypted.host.clone(),
        port: encrypted.port,
        user: std::mem::take(&mut secret.user),
        password: std::mem::take(&mut secret.password),
        host_key: secret.host_key.take(),
    };
    validate_decrypted_creds(&creds)
        .with_context(|| format!("profile '{name}' decrypted to unsafe credential fields"))?;
    Ok(creds)
}

fn wrap_profile_v3(
    name: &str,
    creds: &Creds,
    passphrase: &str,
    package: &crate::recovery::KeyPackage,
    recovery: Option<&crate::recovery::RecoveryConfig>,
) -> Result<EncProfile> {
    validate_new_master_passphrase(passphrase)?;
    if package.generation == 0 {
        bail!("profile generation must be non-zero");
    }
    let kdf = new_profile_kdf();
    let mut salt = [0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kek = derive_key(passphrase.as_bytes(), &salt, &kdf)?;

    let mut key_nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut key_nonce);
    let package_json = serialize_json_zeroizing(
        package,
        4096,
        JsonStyle::Compact,
        "profile key package exceeds its safety limit",
    )?;
    let key_aad = profile_key_aad(
        name,
        &package.profile_id,
        &creds.host,
        creds.port,
        package.generation,
    )?;
    let key_ct = ChaCha20Poly1305::new(kek.as_ref().into())
        .encrypt(
            Nonce::from_slice(&key_nonce),
            chacha20poly1305::aead::Payload {
                msg: &package_json,
                aad: &key_aad,
            },
        )
        .map_err(|_| anyhow!("encrypt profile key envelope failed"))?;

    let mut payload_nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut payload_nonce);
    let secret = Secret {
        user: creds.user.clone(),
        password: creds.password.clone(),
        host_key: creds.host_key.clone(),
    };
    let plaintext = serialize_json_zeroizing(
        &secret,
        MAX_VAULT_BYTES as usize,
        JsonStyle::Compact,
        "encrypted profile plaintext exceeds the 16 MiB safety limit",
    )?;
    let payload_aad = profile_payload_aad(
        name,
        &package.profile_id,
        &creds.host,
        creds.port,
        package.generation,
    )?;
    let payload_ct = ChaCha20Poly1305::new((&package.dek).into())
        .encrypt(
            Nonce::from_slice(&payload_nonce),
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: &payload_aad,
            },
        )
        .map_err(|_| anyhow!("encrypt profile payload failed"))?;
    let recovery_envelope = recovery
        .map(|config| {
            crate::recovery::seal_package(
                config,
                name,
                &package.profile_id,
                package.generation,
                package,
            )
        })
        .transpose()?;
    let recovery_config_tag = recovery
        .map(|config| recovery_config_tag(&package.auth_seed, config))
        .transpose()?;
    Ok(EncProfile {
        host: creds.host.clone(),
        port: creds.port,
        format: PROFILE_FORMAT_ENVELOPE,
        nonce: B64.encode(payload_nonce),
        ct: B64.encode(payload_ct),
        host_key: None,
        generation: package.generation,
        profile_id: encode_profile_id(&package.profile_id),
        profile_salt: B64.encode(salt),
        profile_kdf: Some(kdf),
        key_nonce: B64.encode(key_nonce),
        key_ct: B64.encode(key_ct),
        recovery_envelope,
        recovery_config_tag,
    })
}

fn authenticate_profile_v3(
    name: &str,
    encrypted: &EncProfile,
    passphrase: &str,
    recovery: Option<&crate::recovery::RecoveryConfig>,
) -> Result<(crate::recovery::KeyPackage, Creds)> {
    let package = unwrap_profile_package(name, encrypted, passphrase)?;
    verify_recovery_binding(encrypted, &package, recovery)?;
    let credentials = decrypt_profile_v3_with_package(name, encrypted, &package)?;
    Ok((package, credentials))
}

fn profile_call_key_v3(
    auth_seed: &[u8; 32],
    profile: &str,
    profile_id: &[u8; 16],
    generation: u64,
) -> Result<ProfileCallKey> {
    validate_profile_name(profile)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(auth_seed)
        .map_err(|_| anyhow!("invalid profile authorization seed"))?;
    mac.update(PROFILE_CALL_KEY_DOMAIN);
    mac.update(&(profile.len() as u32).to_be_bytes());
    mac.update(profile.as_bytes());
    mac.update(profile_id);
    mac.update(&generation.to_be_bytes());
    let mut digest = mac.finalize().into_bytes();
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    Ok(ProfileCallKey(key))
}

fn verify_master(vault: &VaultFile, key: &[u8; 32]) -> Result<()> {
    let Some(verifier) = &vault.verifier else {
        // Legacy vaults had no verifier. Successfully decrypting one existing
        // record proves the master passphrase before any mutation is allowed.
        if let Some((name, profile)) = vault.profiles.iter().next() {
            let _ = decrypt_profile_payload_with_key(name, profile, key)?;
        }
        return Ok(());
    };
    let nonce = decode_nonce(&verifier.nonce)?;
    let ciphertext = B64.decode(&verifier.ct)?;
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: VERIFIER_AAD,
            },
        )
        .map_err(|_| anyhow!("wrong master passphrase or tampered vault verifier"))?;
    if plaintext != VERIFIER_TEXT {
        bail!("invalid vault verifier");
    }
    Ok(())
}

#[cfg(test)]
fn ensure_verifier(vault: &mut VaultFile, key: &[u8; 32]) -> Result<()> {
    if vault.verifier.is_some() {
        return Ok(());
    }
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: VERIFIER_TEXT,
                aad: VERIFIER_AAD,
            },
        )
        .map_err(|_| anyhow!("encrypt vault verifier failed"))?;
    vault.verifier = Some(SealedVerifier {
        nonce: B64.encode(nonce),
        ct: B64.encode(ciphertext),
    });
    Ok(())
}

fn validate_master_passphrase(master: &str) -> Result<()> {
    if master.is_empty() || master.len() > 16 * 1024 {
        bail!("master passphrase must contain 1 to 16384 bytes");
    }
    Ok(())
}

fn validate_new_master_passphrase(master: &str) -> Result<()> {
    validate_master_passphrase(master)?;
    if master.len() < MIN_NEW_MASTER_BYTES {
        bail!("a new vault master passphrase must contain at least {MIN_NEW_MASTER_BYTES} bytes");
    }
    Ok(())
}

fn validate_profile_update(name: &str, creds: &Creds, master: &str) -> Result<()> {
    validate_profile_name(name)?;
    validate_master_passphrase(master)?;
    if creds.host.is_empty()
        || creds.host.len() > 1024
        || creds.port == 0
        || creds.user.is_empty()
        || creds.user.len() > 1024
        || creds.password.is_empty()
        || creds.password.len() > 1024 * 1024
    {
        bail!("host, port, user, or password is empty or exceeds its safety limit");
    }
    if contains_control_character(&creds.host) || contains_control_character(&creds.user) {
        bail!("host and user must not contain control characters");
    }
    if let Some(host_key) = creds.host_key.as_deref() {
        validate_explicit_host_key_fingerprint(host_key)?;
    }
    Ok(())
}

fn validate_explicit_host_key_fingerprint(fingerprint: &str) -> Result<()> {
    // A SHA-256 digest is exactly 32 bytes and therefore exactly 43 Base64
    // characters without padding. Check the bound before decoding so hostile
    // UI/CLI input cannot trigger a large temporary allocation.
    if fingerprint.len() != "SHA256:".len() + 43 {
        bail!("expected host-key fingerprint must be SHA256: plus 43 unpadded Base64 characters");
    }
    let encoded = fingerprint
        .strip_prefix("SHA256:")
        .ok_or_else(|| anyhow!("expected host-key fingerprint must start with SHA256:"))?;
    let digest = B64_NO_PAD
        .decode(encoded)
        .map_err(|_| anyhow!("expected host-key fingerprint has invalid unpadded Base64"))?;
    if digest.len() != 32 || B64_NO_PAD.encode(&digest) != encoded {
        bail!("expected host-key fingerprint must canonically encode exactly 32 SHA-256 bytes");
    }
    Ok(())
}

fn contains_control_character(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn validate_endpoint_fields(host: &str, port: u16) -> Result<()> {
    if host.is_empty() || host.len() > 1024 || port == 0 || contains_control_character(host) {
        bail!("host must contain 1 to 1024 non-control bytes and port must be non-zero");
    }
    Ok(())
}

fn validate_decrypted_creds(creds: &Creds) -> Result<()> {
    validate_endpoint_fields(&creds.host, creds.port)?;
    if creds.user.is_empty()
        || creds.user.len() > 1024
        || contains_control_character(&creds.user)
        || creds.password.is_empty()
        || creds.password.len() > 1024 * 1024
    {
        bail!("decrypted user or password is empty, oversized, or unsafe");
    }
    if let Some(host_key) = creds.host_key.as_deref() {
        if host_key.is_empty() || host_key.len() > 1024 || contains_control_character(host_key) {
            bail!("decrypted host-key fingerprint is empty, oversized, or unsafe");
        }
    }
    Ok(())
}

#[cfg(test)]
fn enforce_new_vault_master_policy(vault: &VaultFile, master: &str) -> Result<()> {
    // If neither a verifier nor an encrypted record exists, there is no prior
    // master passphrase whose compatibility needs to be preserved.
    if vault.verifier.is_none() && vault.profiles.is_empty() && master.len() < MIN_NEW_MASTER_BYTES
    {
        bail!("a new vault master passphrase must contain at least {MIN_NEW_MASTER_BYTES} bytes");
    }
    Ok(())
}

#[cfg(test)]
fn authenticated_pin_for_replacement(
    name: &str,
    encrypted: &EncProfile,
    key: &[u8; 32],
    replacement: &Creds,
) -> Result<Option<String>> {
    if encrypted.format == PROFILE_FORMAT_AAD {
        let mut credentials = decrypt_profile_with_key(name, encrypted, key)?;
        if credentials.host.as_bytes() == replacement.host.as_bytes()
            && credentials.port == replacement.port
        {
            match (credentials.host_key.take(), replacement.host_key.as_deref()) {
                (Some(existing), Some(requested))
                    if existing.as_bytes() != requested.as_bytes() =>
                {
                    bail!(
                        "refusing to replace the authenticated host-key pin for unchanged endpoint"
                    )
                }
                (Some(existing), _) => Ok(Some(existing)),
                (None, Some(requested)) => Ok(Some(requested.to_owned())),
                (None, None) => Ok(None),
            }
        } else {
            // A host key authenticates exactly one SSH endpoint. Carrying it
            // to a different host or port would be unsafe. An explicit new
            // fingerprint, however, is already bound to the replacement
            // endpoint by the new record's AEAD associated data.
            Ok(replacement.host_key.clone())
        }
    } else {
        // Prove that this is an authentic legacy ciphertext before accepting
        // the downgrade-only migration path. Without this check, flipping a
        // modern record's unauthenticated `format` byte from 2 to 0 would skip
        // its AAD verification during add/update or rename, silently erase the
        // authenticated host-key pin, and reopen TOFU on the next connection.
        // Genuine legacy endpoint metadata and pins remain unauthenticated and
        // therefore are deliberately not inherited by the replacement.
        let _legacy_credentials = decrypt_profile_payload_with_key(name, encrypted, key)?;
        Ok(replacement.host_key.clone())
    }
}

#[cfg(test)]
fn selected_pin_for_update(
    name: &str,
    encrypted: Option<&EncProfile>,
    key: &[u8; 32],
    replacement: &Creds,
) -> Result<Option<String>> {
    match encrypted {
        Some(encrypted) => authenticated_pin_for_replacement(name, encrypted, key, replacement),
        None => Ok(replacement.host_key.clone()),
    }
}

fn enforce_profile_capacity_for_upsert(vault: &VaultFile, name: &str) -> Result<()> {
    if !vault.profiles.contains_key(name) && vault.profiles.len() >= MAX_PROFILES {
        bail!("vault cannot contain more than {MAX_PROFILES} profiles");
    }
    Ok(())
}

fn require_v3(vault: &VaultFile) -> Result<()> {
    if vault.version != VAULT_FORMAT {
        bail!(
            "vault format {} requires explicit v2-to-v4 migration",
            vault.version
        );
    }
    Ok(())
}

fn require_identity(encrypted: &EncProfile, expected: Option<ProfileIdentity>) -> Result<()> {
    if let Some(expected) = expected {
        let found = profile_identity(encrypted)?;
        if found != expected {
            bail!(
                "profile changed concurrently (expected identity {}:{}, found {}:{})",
                encode_profile_id(&expected.profile_id),
                expected.generation,
                encode_profile_id(&found.profile_id),
                found.generation,
            );
        }
    }
    Ok(())
}

fn next_generation(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or_else(|| anyhow!("profile generation is exhausted"))
}

fn admin_aad(recovery_id: &str) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(ADMIN_AAD_DOMAIN, recovery_id))?)
}

#[cfg(windows)]
fn seal_admin_policy(
    administrator_passphrase: &str,
    recovery: &crate::recovery::RecoveryConfig,
    local_share: &[u8; 32],
) -> Result<AdminPolicy> {
    validate_new_master_passphrase(administrator_passphrase)
        .context("validate new administrator password")?;
    let mut salt = [0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kdf = KdfConfig::default();
    let kek = derive_key(administrator_passphrase.as_bytes(), &salt, &kdf)?;
    let secret = AdminSecret {
        marker: ADMIN_MARKER.to_vec(),
        local_share: *local_share,
        recovery_config_digest: recovery_config_digest(recovery)?,
    };
    let plaintext = serialize_json_zeroizing(
        &secret,
        4096,
        JsonStyle::Compact,
        "administrator policy exceeds its safety limit",
    )?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let aad = admin_aad(&recovery.recovery_id)?;
    let ciphertext = ChaCha20Poly1305::new(kek.as_ref().into())
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("encrypt administrator authorization policy failed"))?;
    Ok(AdminPolicy {
        salt: B64.encode(salt),
        kdf,
        nonce: B64.encode(nonce),
        ct: B64.encode(ciphertext),
    })
}

#[cfg(windows)]
fn open_admin_policy(
    vault: &VaultFile,
    administrator_passphrase: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    validate_master_passphrase(administrator_passphrase)
        .context("validate administrator password")?;
    let policy = vault
        .admin
        .as_ref()
        .ok_or_else(|| anyhow!("administrator password is not initialized"))?;
    let recovery = vault
        .recovery
        .as_ref()
        .ok_or_else(|| anyhow!("administrator policy is missing recovery configuration"))?;
    let salt = B64
        .decode(&policy.salt)
        .context("decode administrator KDF salt")?;
    let kek = derive_key(administrator_passphrase.as_bytes(), &salt, &policy.kdf)?;
    let nonce = decode_nonce(&policy.nonce)?;
    let ciphertext = B64
        .decode(&policy.ct)
        .context("decode administrator authorization policy")?;
    let aad = admin_aad(&recovery.recovery_id)?;
    let plaintext = ChaCha20Poly1305::new(kek.as_ref().into())
        .decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("wrong administrator password or tampered administrator policy"))?;
    let plaintext = Zeroizing::new(plaintext);
    let secret: AdminSecret =
        serde_json::from_slice(&plaintext).context("decode administrator policy")?;
    if secret.marker.as_slice() != ADMIN_MARKER {
        bail!("administrator policy marker is invalid");
    }
    let expected_digest = recovery_config_digest(recovery)?;
    use subtle::ConstantTimeEq;
    if !bool::from(secret.recovery_config_digest.ct_eq(&expected_digest)) {
        bail!("administrator policy does not authenticate the current recovery configuration");
    }
    Ok(Zeroizing::new(secret.local_share))
}

#[cfg(unix)]
fn require_linux_root() -> Result<()> {
    #[cfg(target_os = "linux")]
    let delegated = LINUX_ADMIN_TARGET_AUTHORIZED.load(std::sync::atomic::Ordering::Acquire);
    #[cfg(not(target_os = "linux"))]
    let delegated = false;
    if unsafe { libc::geteuid() } != 0 && !delegated {
        bail!("this administrator operation requires effective uid 0");
    }
    Ok(())
}

/// Resolve one Linux account through NSS while still privileged, bind this
/// one-command process to that account's home, and irreversibly drop every
/// real/effective/saved group and user id before any vault bytes are opened.
///
/// This is deliberately unavailable as a general path override. The caller
/// supplies an account name, never a UID, HOME, SUDO_USER, or arbitrary path;
/// NSS is the sole source of the target UID/GID/home tuple. The returned
/// process can perform administrator-only *destructive reset* through the
/// in-process authorization bit, but filesystem access is enforced as the
/// target user and root privileges cannot be regained.
#[cfg(target_os = "linux")]
pub fn enter_linux_admin_target_user(username: &str) -> Result<()> {
    use std::ffi::{CStr, CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    if unsafe { libc::geteuid() } != 0 {
        bail!("--target-user requires effective uid 0");
    }
    if LINUX_ADMIN_TARGET_HOME.get().is_some() {
        bail!("a Linux administrator target is already active");
    }
    if username.is_empty()
        || username.len() > 256
        || username
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
    {
        bail!("target user name is empty, oversized, or unsafe");
    }
    let requested = CString::new(username).map_err(|_| anyhow!("target user name contains NUL"))?;
    let mut capacity = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        value if value > 0 => usize::try_from(value).unwrap_or(16 * 1024),
        _ => 16 * 1024,
    }
    .clamp(1024, 1024 * 1024);
    let (uid, gid, home) = loop {
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; capacity];
        let status = unsafe {
            libc::getpwnam_r(
                requested.as_ptr(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && capacity < 1024 * 1024 {
            capacity = (capacity * 2).min(1024 * 1024);
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status))
                .context("resolve target user through NSS");
        }
        if result.is_null() || entry.pw_dir.is_null() || entry.pw_name.is_null() {
            bail!("target user does not exist");
        }
        let resolved_name = unsafe { CStr::from_ptr(entry.pw_name) }.to_bytes();
        if resolved_name != username.as_bytes() {
            bail!("NSS returned a different target account name");
        }
        let home_bytes = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
        let home = PathBuf::from(OsStr::from_bytes(home_bytes));
        break (entry.pw_uid, entry.pw_gid, home);
    };
    if uid == 0 {
        bail!("--target-user must identify a non-root account");
    }
    if !home.is_absolute() || home == Path::new("/") {
        bail!("target user's NSS home must be an absolute non-root path");
    }

    let home_handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&home)
        .with_context(|| format!("open NSS home for target user '{username}'"))?;
    let home_metadata = home_handle
        .metadata()
        .context("inspect target home handle")?;
    if !home_metadata.file_type().is_dir()
        || (home_metadata.uid() != uid && home_metadata.uid() != 0)
        || home_metadata.permissions().mode() & 0o022 != 0
    {
        bail!("target home must be a non-symlink directory owned by the target or root and not group/world writable");
    }
    // Resolve the vault as a single child of the already-verified NSS home
    // handle. Reopening `home.join(".serctl")` would re-traverse attacker-
    // mutable ancestors and could bind the administrative reset to a
    // different target-owned directory than the home object just checked.
    let vault_component = CString::new(".serctl").expect("literal has no NUL");
    let vault_fd = unsafe {
        libc::openat(
            home_handle.as_raw_fd(),
            vault_component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if vault_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("open target user's existing .serctl directory relative to verified home");
    }
    // SAFETY: openat returned a new owned descriptor on success.
    let vault_handle = unsafe { File::from_raw_fd(vault_fd) };
    let vault_metadata = vault_handle
        .metadata()
        .context("inspect target .serctl directory handle")?;
    if !vault_metadata.file_type().is_dir()
        || vault_metadata.uid() != uid
        || vault_metadata.permissions().mode() & 0o077 != 0
    {
        bail!("target .serctl directory must be owned by the target user and inaccessible to group/other");
    }
    drop(home_handle);

    // Disable every mechanism that could deliberately retain privilege over
    // the subsequent setresuid transition. All calls are fail-closed because
    // this path claims an irreversible drop before touching vault bytes.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("disable retained Linux capabilities");
    }
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("clear ambient Linux capabilities");
    }
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("drop supplementary groups");
    }
    if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("drop Linux group identity");
    }
    if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("drop Linux user identity");
    }
    if unsafe { libc::getuid() } != uid
        || unsafe { libc::geteuid() } != uid
        || unsafe { libc::getgid() } != gid
        || unsafe { libc::getegid() } != gid
    {
        bail!("Linux target identity could not be verified after privilege drop");
    }
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
        || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("verify saved Linux identities after privilege drop");
    }
    if (real_uid, effective_uid, saved_uid) != (uid, uid, uid)
        || (real_gid, effective_gid, saved_gid) != (gid, gid, gid)
    {
        bail!("saved Linux identity remains privileged after target-user drop");
    }
    let mut capability_header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let empty_capabilities = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    let capset_status = unsafe {
        libc::syscall(
            libc::SYS_capset,
            (&raw mut capability_header).cast::<libc::c_void>(),
            empty_capabilities.as_ptr(),
        )
    };
    if capset_status != 0 {
        return Err(std::io::Error::last_os_error()).context("clear Linux capability sets");
    }
    let mut observed_capabilities = empty_capabilities;
    let capget_status = unsafe {
        libc::syscall(
            libc::SYS_capget,
            (&raw mut capability_header).cast::<libc::c_void>(),
            observed_capabilities.as_mut_ptr(),
        )
    };
    if capget_status != 0 {
        return Err(std::io::Error::last_os_error()).context("verify Linux capability sets");
    }
    if observed_capabilities.iter().any(|capabilities| {
        capabilities.effective != 0 || capabilities.permitted != 0 || capabilities.inheritable != 0
    }) {
        bail!("Linux capabilities remain after target-user privilege drop");
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("enable Linux no-new-privileges mode");
    }
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        bail!("Linux no-new-privileges mode could not be verified");
    }

    // Revalidate the retained object as the target identity, and prove the
    // procfs path used by all subsequent path-based helpers resolves to this
    // same directory object. The original pathname may disappear later; the
    // retained descriptor remains the sole authority.
    security::harden_open_directory(&vault_handle)?;
    let anchored_path = PathBuf::from(format!("/proc/self/fd/{}", vault_handle.as_raw_fd()));
    let anchored = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(&anchored_path)
        .context("open retained target vault directory through procfs")?;
    let retained_metadata = vault_handle
        .metadata()
        .context("reinspect retained target vault directory")?;
    let anchored_metadata = anchored
        .metadata()
        .context("inspect procfs-anchored target vault directory")?;
    if retained_metadata.dev() != anchored_metadata.dev()
        || retained_metadata.ino() != anchored_metadata.ino()
        || retained_metadata.uid() != uid
        || retained_metadata.permissions().mode() & 0o7777 != 0o700
    {
        bail!("target vault directory handle could not be anchored after privilege drop");
    }
    drop(anchored);
    // Publish the delegated target only after every irreversible-drop and
    // handle-binding check succeeds. An early error must not redirect later
    // ordinary vault calls to an unbound target pathname.
    LINUX_ADMIN_TARGET_HOME
        .set(home)
        .map_err(|_| anyhow!("a Linux administrator target is already active"))?;
    LINUX_ADMIN_TARGET_VAULT_DIR
        .set(vault_handle)
        .map_err(|_| anyhow!("a Linux administrator target vault is already active"))?;
    LINUX_ADMIN_TARGET_AUTHORIZED.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

fn authorize_administrator_from_vault(
    vault: &VaultFile,
    administrator_passphrase: Option<&str>,
) -> Result<()> {
    #[cfg(windows)]
    {
        let passphrase = administrator_passphrase
            .ok_or_else(|| anyhow!("administrator password is required"))?;
        let local_share = open_admin_policy(vault, passphrase)?;
        drop(local_share);
        Ok(())
    }
    #[cfg(unix)]
    {
        let _ = vault;
        let _ = administrator_passphrase;
        require_linux_root()
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = vault;
        let _ = administrator_passphrase;
        bail!("administrator authorization is unsupported on this platform")
    }
}

pub fn admin_status() -> Result<AdminStatus> {
    let vault = load_vault()?;
    require_v3(&vault)?;
    #[cfg(windows)]
    {
        match (&vault.admin, &vault.recovery) {
            (None, None) => Ok(AdminStatus::Uninitialized {
                platform_requires_password: true,
            }),
            (Some(_), Some(recovery)) => Ok(AdminStatus::Ready {
                platform_requires_password: true,
                recovery_id: recovery.recovery_id.clone(),
            }),
            _ => bail!("vault contains an incomplete administrator/recovery policy"),
        }
    }
    #[cfg(unix)]
    {
        match &vault.recovery {
            Some(recovery) => Ok(AdminStatus::Ready {
                platform_requires_password: false,
                recovery_id: recovery.recovery_id.clone(),
            }),
            None => Ok(AdminStatus::Uninitialized {
                platform_requires_password: false,
            }),
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = vault;
        bail!("administrator authorization is unsupported on this platform")
    }
}

pub fn verify_admin_password(administrator_passphrase: Option<&str>) -> Result<()> {
    let vault = load_vault()?;
    require_v3(&vault)?;
    authorize_administrator_from_vault(&vault, administrator_passphrase)
}

/// Initialize the Windows administrator password and vault-wide recovery in
/// one logical transaction.  The removable-media half is durably persisted by
/// the caller before the vault is committed; a later vault-write failure can
/// therefore leave only a harmless orphan medium, never a vault whose only
/// recovery share was lost before it became visible.
#[cfg(windows)]
pub fn initialize_admin_password<F>(new_password: &str, persist_media: F) -> Result<()>
where
    F: FnOnce(&[u8]) -> Result<()>,
{
    validate_new_master_passphrase(new_password).context("validate new administrator password")?;
    let _barrier = acquire_runtime_barrier_exclusive()?;
    mutate_vault(|vault| {
        require_v3(vault)?;
        if vault.admin.is_some() || vault.recovery.is_some() || vault.root_recovery_share.is_some()
        {
            bail!("administrator/recovery policy is already initialized");
        }
        let (config, local_share, media) = crate::recovery::generate_recovery()?;
        let admin = seal_admin_policy(new_password, &config, &local_share)?;
        let mut replacement = vault.profiles.clone();
        // Existing profiles cannot acquire a recovery envelope without their
        // individual passphrases. Requiring an empty vault prevents a false
        // assurance that administrator recovery covers only some profiles.
        if !replacement.is_empty() {
            bail!(
                "initialize administrator recovery before creating profiles, or migrate explicitly"
            );
        }
        persist_media(&media).context("persist new recovery media before vault initialization")?;
        vault.admin = Some(admin);
        vault.recovery = Some(config);
        vault.root_recovery_share = None;
        // Make the no-profile expectation explicit across the callback.
        vault.profiles = std::mem::take(&mut replacement);
        Ok(())
    })
}

#[cfg(not(windows))]
pub fn initialize_admin_password<F>(_new_password: &str, _persist_media: F) -> Result<()>
where
    F: FnOnce(&[u8]) -> Result<()>,
{
    bail!("Linux uses effective uid 0 instead of a stored administrator password")
}

#[cfg(unix)]
pub fn initialize_linux_recovery<F>(persist_media: F) -> Result<()>
where
    F: FnOnce(&[u8]) -> Result<()>,
{
    let _ = persist_media;
    require_linux_root()?;
    bail!("Linux offline recovery is fail-closed until a root-owned system share store and explicit target-user vault boundary are configured")
}

#[cfg(not(unix))]
pub fn initialize_linux_recovery<F>(_persist_media: F) -> Result<()>
where
    F: FnOnce(&[u8]) -> Result<()>,
{
    bail!("Linux root recovery is unavailable on this platform")
}

#[cfg(windows)]
pub fn change_admin_password(old_password: &str, new_password: &str) -> Result<()> {
    validate_master_passphrase(old_password)?;
    validate_new_master_passphrase(new_password)?;
    // Authenticate before the exclusive barrier so an unauthenticated caller
    // learns no runtime contention state.
    let snapshot = load_vault()?;
    require_v3(&snapshot)?;
    let local_share = open_admin_policy(&snapshot, old_password)?;
    let recovery = snapshot
        .recovery
        .as_ref()
        .ok_or_else(|| anyhow!("recovery is not initialized"))?
        .clone();
    let expected_digest = vault_state_digest(&snapshot)?;
    drop(snapshot);
    let _barrier = acquire_runtime_barrier_exclusive()?;
    mutate_vault(|vault| {
        let current_digest = vault_state_digest(vault)?;
        use subtle::ConstantTimeEq;
        if !bool::from(expected_digest.ct_eq(&current_digest)) {
            bail!("vault changed while administrator authorization was being acquired; retry");
        }
        vault.admin = Some(seal_admin_policy(new_password, &recovery, &local_share)?);
        Ok(())
    })
}

#[cfg(not(windows))]
pub fn change_admin_password(_old_password: &str, _new_password: &str) -> Result<()> {
    bail!("Linux uses effective uid 0 instead of a stored administrator password")
}

fn local_recovery_share(
    vault: &VaultFile,
    administrator_passphrase: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>> {
    #[cfg(windows)]
    {
        let passphrase = administrator_passphrase
            .ok_or_else(|| anyhow!("administrator password is required"))?;
        open_admin_policy(vault, passphrase)
    }
    #[cfg(unix)]
    {
        let _ = administrator_passphrase;
        require_linux_root()?;
        let _ = vault;
        bail!("Linux offline recovery is fail-closed until a root-owned system share store and explicit target-user vault boundary are configured")
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = vault;
        let _ = administrator_passphrase;
        bail!("recovery is unsupported on this platform")
    }
}

fn metadata(name: &str, encrypted: &EncProfile) -> ProfileMetadata {
    ProfileMetadata {
        name: name.to_owned(),
        host: encrypted.host.clone(),
        port: encrypted.port,
        generation: encrypted.generation,
        profile_id: decode_profile_id(&encrypted.profile_id)
            .expect("validated v4 profile identity remains canonical"),
    }
}

/// Read the non-secret catalog used by the first-run/migration UI.  Endpoint
/// metadata is intentionally classified as local catalog data, not as a
/// credential; protected-file owner/ACL validation still runs before it is
/// returned.  A v2 catalog is never eligible for a network operation.
pub fn catalog_snapshot() -> Result<CatalogSnapshot> {
    let vault = load_vault()?;
    let needs_migration = match vault.version {
        0 | LEGACY_VAULT_FORMAT => true,
        VAULT_FORMAT => false,
        3 => bail!("pre-release vault format v3 is incompatible with v4 profile identities; use the matching older build to export it or restore a backup, then rebuild the vault"),
        version => bail!("unsupported vault format version {version}"),
    };
    let profiles = vault
        .profiles
        .iter()
        .map(|(name, encrypted)| ProfileMetadata {
            name: name.clone(),
            host: encrypted.host.clone(),
            port: encrypted.port,
            generation: if encrypted.format == PROFILE_FORMAT_ENVELOPE {
                encrypted.generation
            } else {
                0
            },
            profile_id: if encrypted.format == PROFILE_FORMAT_ENVELOPE {
                decode_profile_id(&encrypted.profile_id)
                    .expect("validated v4 profile identity remains canonical")
            } else {
                [0_u8; 16]
            },
        })
        .collect();
    Ok(CatalogSnapshot {
        format: vault.version,
        needs_migration,
        admin_initialized: vault.admin.is_some(),
        recovery_initialized: vault.recovery.is_some(),
        profiles,
    })
}

pub fn list_profile_metadata() -> Result<Vec<ProfileMetadata>> {
    let snapshot = catalog_snapshot()?;
    if snapshot.needs_migration {
        bail!("vault requires explicit v2-to-v4 migration before profiles can be used");
    }
    Ok(snapshot.profiles)
}

pub fn migration_state() -> Result<VaultMigrationState> {
    let snapshot = catalog_snapshot()?;
    if snapshot.needs_migration {
        return Ok(VaultMigrationState::LegacyV2 {
            profiles: snapshot.profiles.into_iter().map(|row| row.name).collect(),
        });
    }
    if snapshot.profiles.is_empty() {
        return Ok(VaultMigrationState::EmptyV4 {
            admin_initialized: snapshot.admin_initialized,
        });
    }
    Ok(VaultMigrationState::ReadyV4 {
        admin_initialized: snapshot.admin_initialized,
        profiles: snapshot.profiles.len(),
        recovery_configured: snapshot.recovery_initialized,
    })
}

pub fn legacy_profile_names() -> Result<Vec<String>> {
    match migration_state()? {
        VaultMigrationState::LegacyV2 { profiles } => Ok(profiles),
        _ => bail!("vault is not a legacy v2 vault"),
    }
}

pub fn verify_profile_identity(name: &str, passphrase: &str) -> Result<ProfileIdentity> {
    validate_profile_name(name)?;
    validate_master_passphrase(passphrase)?;
    let vault = load_vault()?;
    require_v3(&vault)?;
    let encrypted = vault
        .profiles
        .get(name)
        .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
    let (_, authenticated) =
        authenticate_profile_v3(name, encrypted, passphrase, vault.recovery.as_ref())?;
    // Authenticate the payload too.  A valid KEK envelope alone must not turn
    // a corrupted profile into an authorized daemon or UI grant.
    drop(authenticated);
    profile_identity(encrypted)
}

#[cfg(test)]
pub fn verify_profile_passphrase(name: &str, passphrase: &str) -> Result<u64> {
    Ok(verify_profile_identity(name, passphrase)?.generation)
}

/// Create a new independent profile.  `administrator_passphrase` is consumed
/// only by the authorization policy; it is never involved in the profile KEK
/// or key package and therefore cannot decrypt the resulting record.
pub fn create_profile(
    name: &str,
    creds: &Creds,
    profile_passphrase: &str,
    administrator_passphrase: Option<&str>,
) -> Result<ProfileMetadata> {
    validate_profile_update(name, creds, profile_passphrase)?;
    validate_new_master_passphrase(profile_passphrase)?;
    #[cfg(windows)]
    let authorized_digest = {
        let snapshot = load_vault()?;
        require_v3(&snapshot)?;
        authorize_administrator_from_vault(&snapshot, administrator_passphrase)?;
        if snapshot.profiles.contains_key(name) {
            bail!("profile '{name}' already exists");
        }
        vault_state_digest(&snapshot)?
    };
    #[cfg(not(windows))]
    let _ = administrator_passphrase;
    let _runtime_lease = acquire_profile_mutation_lease(name)?;
    mutate_vault(|vault| {
        require_v3(vault)?;
        #[cfg(windows)]
        {
            use subtle::ConstantTimeEq;
            if !bool::from(authorized_digest.ct_eq(&vault_state_digest(vault)?)) {
                bail!("vault changed while administrator authorization was being acquired; retry");
            }
        }
        if vault.profiles.contains_key(name) {
            bail!("profile '{name}' already exists");
        }
        enforce_profile_capacity_for_upsert(vault, name)?;
        let package = new_key_package(new_profile_id(), 1);
        let encrypted = wrap_profile_v3(
            name,
            creds,
            profile_passphrase,
            &package,
            vault.recovery.as_ref(),
        )?;
        let row = metadata(name, &encrypted);
        vault.profiles.insert(name.to_owned(), encrypted);
        Ok(row)
    })
}

pub fn update_profile(
    name: &str,
    creds: &Creds,
    profile_passphrase: &str,
    expected_identity: Option<ProfileIdentity>,
) -> Result<ProfileMetadata> {
    validate_profile_update(name, creds, profile_passphrase)?;
    let _runtime_lease = acquire_profile_mutation_lease(name)?;
    mutate_vault(|vault| {
        require_v3(vault)?;
        let previous = vault
            .profiles
            .get(name)
            .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
        require_identity(previous, expected_identity)?;
        let (_, old_creds) =
            authenticate_profile_v3(name, previous, profile_passphrase, vault.recovery.as_ref())?;
        let mut updated = creds.clone();
        updated.host_key =
            if old_creds.host.as_bytes() == creds.host.as_bytes() && old_creds.port == creds.port {
                match (old_creds.host_key.as_deref(), creds.host_key.as_deref()) {
                    (Some(existing), Some(requested))
                        if existing.as_bytes() != requested.as_bytes() =>
                    {
                        bail!(
                        "refusing to replace the authenticated host-key pin for unchanged endpoint"
                    )
                    }
                    (Some(existing), _) => Some(existing.to_owned()),
                    (None, requested) => requested.map(str::to_owned),
                }
            } else {
                creds.host_key.clone()
            };
        let package = new_key_package(
            decode_profile_id(&previous.profile_id)?,
            next_generation(previous.generation)?,
        );
        let encrypted = wrap_profile_v3(
            name,
            &updated,
            profile_passphrase,
            &package,
            vault.recovery.as_ref(),
        )?;
        let row = metadata(name, &encrypted);
        vault.profiles.insert(name.to_owned(), encrypted);
        Ok(row)
    })
}

pub fn rename_profile_v3(
    old_name: &str,
    new_name: &str,
    creds: &Creds,
    profile_passphrase: &str,
    expected_identity: Option<ProfileIdentity>,
) -> Result<ProfileMetadata> {
    validate_profile_name(old_name)?;
    validate_profile_update(new_name, creds, profile_passphrase)?;
    if old_name == new_name {
        bail!("source and destination profile names must differ");
    }
    let (_old_lease, _new_lease) = acquire_rename_leases(old_name, new_name)?;
    mutate_vault(|vault| {
        require_v3(vault)?;
        if vault.profiles.contains_key(new_name) {
            bail!("profile '{new_name}' already exists");
        }
        let previous = vault
            .profiles
            .get(old_name)
            .ok_or_else(|| anyhow!("profile '{old_name}' not found"))?;
        require_identity(previous, expected_identity)?;
        let (_, old_creds) = authenticate_profile_v3(
            old_name,
            previous,
            profile_passphrase,
            vault.recovery.as_ref(),
        )?;
        let mut updated = creds.clone();
        updated.host_key =
            if old_creds.host.as_bytes() == creds.host.as_bytes() && old_creds.port == creds.port {
                match (old_creds.host_key.as_deref(), creds.host_key.as_deref()) {
                    (Some(existing), Some(requested))
                        if existing.as_bytes() != requested.as_bytes() =>
                    {
                        bail!(
                        "refusing to replace the authenticated host-key pin for unchanged endpoint"
                    )
                    }
                    (Some(existing), _) => Some(existing.to_owned()),
                    (None, requested) => requested.map(str::to_owned),
                }
            } else {
                creds.host_key.clone()
            };
        let new_package = new_key_package(
            decode_profile_id(&previous.profile_id)?,
            next_generation(previous.generation)?,
        );
        let encrypted = wrap_profile_v3(
            new_name,
            &updated,
            profile_passphrase,
            &new_package,
            vault.recovery.as_ref(),
        )?;
        let row = metadata(new_name, &encrypted);
        vault.profiles.remove(old_name);
        vault.profiles.insert(new_name.to_owned(), encrypted);
        Ok(row)
    })
}

pub fn remove_profile(
    name: &str,
    profile_passphrase: &str,
    expected_identity: Option<ProfileIdentity>,
) -> Result<bool> {
    validate_profile_name(name)?;
    validate_master_passphrase(profile_passphrase)?;
    let _runtime_lease = acquire_profile_mutation_lease(name)?;
    mutate_vault(|vault| {
        require_v3(vault)?;
        let Some(encrypted) = vault.profiles.get(name) else {
            return Ok(false);
        };
        require_identity(encrypted, expected_identity)?;
        let (_, authenticated) =
            authenticate_profile_v3(name, encrypted, profile_passphrase, vault.recovery.as_ref())?;
        drop(authenticated);
        Ok(vault.profiles.remove(name).is_some())
    })
}

pub fn change_profile_passphrase(
    name: &str,
    old_passphrase: &str,
    new_passphrase: &str,
    expected_identity: Option<ProfileIdentity>,
) -> Result<u64> {
    validate_profile_name(name)?;
    validate_master_passphrase(old_passphrase)?;
    validate_new_master_passphrase(new_passphrase)?;
    let _runtime_lease = acquire_profile_mutation_lease(name)?;
    mutate_vault(|vault| {
        require_v3(vault)?;
        let previous = vault
            .profiles
            .get(name)
            .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
        require_identity(previous, expected_identity)?;
        let (_, credentials) =
            authenticate_profile_v3(name, previous, old_passphrase, vault.recovery.as_ref())?;
        let generation = next_generation(previous.generation)?;
        let new_package = new_key_package(decode_profile_id(&previous.profile_id)?, generation);
        let encrypted = wrap_profile_v3(
            name,
            &credentials,
            new_passphrase,
            &new_package,
            vault.recovery.as_ref(),
        )?;
        vault.profiles.insert(name.to_owned(), encrypted);
        Ok(generation)
    })
}

pub fn generate_profile_passphrase() -> Zeroizing<String> {
    let mut random = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(random.as_mut());
    Zeroizing::new(B64_NO_PAD.encode(random.as_ref()))
}

/// Administratively discard an unrecoverable profile and replace it with new
/// credentials.  This operation deliberately never attempts to unwrap or
/// preserve the old DEK; possession of the administrator password alone is
/// therefore not a local data-recovery capability.
pub fn admin_reset_profile(
    name: &str,
    replacement: &Creds,
    new_profile_passphrase: &str,
    administrator_passphrase: Option<&str>,
    expected_identity: Option<ProfileIdentity>,
) -> Result<ProfileMetadata> {
    validate_profile_update(name, replacement, new_profile_passphrase)?;
    validate_new_master_passphrase(new_profile_passphrase)?;
    // Authenticate before lease contention is observable.
    let snapshot = load_vault()?;
    require_v3(&snapshot)?;
    authorize_administrator_from_vault(&snapshot, administrator_passphrase)?;
    let previous = snapshot
        .profiles
        .get(name)
        .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
    require_identity(previous, expected_identity)?;
    let expected_digest = vault_state_digest(&snapshot)?;
    drop(snapshot);

    let _runtime_lease = acquire_profile_mutation_lease(name)?;
    mutate_vault(|vault| {
        use subtle::ConstantTimeEq;
        let current_digest = vault_state_digest(vault)?;
        if !bool::from(expected_digest.ct_eq(&current_digest)) {
            bail!("vault changed while administrator authorization was being acquired; retry");
        }
        let previous = vault
            .profiles
            .get(name)
            .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
        let package = new_key_package(
            decode_profile_id(&previous.profile_id)?,
            next_generation(previous.generation)?,
        );
        let encrypted = wrap_profile_v3(
            name,
            replacement,
            new_profile_passphrase,
            &package,
            vault.recovery.as_ref(),
        )?;
        let row = metadata(name, &encrypted);
        vault.profiles.insert(name.to_owned(), encrypted);
        Ok(row)
    })
}

/// Preserve a profile through the 2-of-2 offline recovery path, then install
/// an independent replacement passphrase and fresh DEK/AuthSeed.  The caller
/// never receives the old key package, credentials, or old passphrase.
pub fn recover_profile_with_media(
    name: &str,
    media_bytes: &[u8],
    administrator_passphrase: Option<&str>,
    new_profile_passphrase: &str,
    expected_identity: Option<ProfileIdentity>,
) -> Result<ProfileMetadata> {
    validate_profile_name(name)?;
    validate_new_master_passphrase(new_profile_passphrase)?;
    // Administrator/root authorization precedes parsing attacker-controlled
    // media or disclosing lease contention.
    let snapshot = load_vault()?;
    require_v3(&snapshot)?;
    let local_share = local_recovery_share(&snapshot, administrator_passphrase)?;
    let recovery = snapshot
        .recovery
        .as_ref()
        .ok_or_else(|| anyhow!("offline recovery is not initialized"))?;
    let encrypted = snapshot
        .profiles
        .get(name)
        .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
    require_identity(encrypted, expected_identity)?;
    let envelope = encrypted
        .recovery_envelope
        .as_ref()
        .ok_or_else(|| anyhow!("profile has no offline recovery envelope"))?;
    let old_package = crate::recovery::open_package(
        recovery,
        name,
        &decode_profile_id(&encrypted.profile_id)?,
        encrypted.generation,
        envelope,
        &local_share,
        media_bytes,
    )?;
    verify_recovery_binding(encrypted, &old_package, Some(recovery))?;
    let credentials = decrypt_profile_v3_with_package(name, encrypted, &old_package)?;
    let expected_digest = vault_state_digest(&snapshot)?;
    let generation = next_generation(encrypted.generation)?;
    let profile_id = decode_profile_id(&encrypted.profile_id)?;
    drop(snapshot);

    let _runtime_lease = acquire_profile_mutation_lease(name)?;
    mutate_vault(|vault| {
        use subtle::ConstantTimeEq;
        if !bool::from(expected_digest.ct_eq(&vault_state_digest(vault)?)) {
            bail!("vault changed while offline recovery was being authorized; retry");
        }
        let package = new_key_package(profile_id, generation);
        let encrypted = wrap_profile_v3(
            name,
            &credentials,
            new_profile_passphrase,
            &package,
            vault.recovery.as_ref(),
        )?;
        let row = metadata(name, &encrypted);
        vault.profiles.insert(name.to_owned(), encrypted);
        Ok(row)
    })
}

/// Rotate the vault-wide 2-of-2 recovery key and atomically replace every
/// profile recovery envelope.  New media is persisted before the vault
/// commit, so failure can produce only an orphan medium.  No profile
/// passphrase or SSH credential is returned.
pub fn rotate_recovery<F>(
    old_media: &[u8],
    administrator_passphrase: Option<&str>,
    persist_new_media: F,
) -> Result<String>
where
    F: FnOnce(&[u8]) -> Result<()>,
{
    #[cfg(unix)]
    {
        let _ = old_media;
        let _ = administrator_passphrase;
        let _ = persist_new_media;
        require_linux_root()?;
        bail!("Linux offline recovery is fail-closed until a root-owned system share store and explicit target-user vault boundary are configured");
    }
    #[cfg(windows)]
    {
        // Verify administrator/root authority before parsing media or revealing
        // global runtime-barrier contention.
        let snapshot = load_vault()?;
        require_v3(&snapshot)?;
        let old_local_share = local_recovery_share(&snapshot, administrator_passphrase)?;
        let old_recovery = snapshot
            .recovery
            .as_ref()
            .ok_or_else(|| anyhow!("offline recovery is not initialized"))?;
        let (new_config, new_local_share, new_media) = crate::recovery::generate_recovery()?;
        let mut envelopes = BTreeMap::new();
        for (name, encrypted) in &snapshot.profiles {
            let envelope = encrypted
                .recovery_envelope
                .as_ref()
                .ok_or_else(|| anyhow!("profile '{name}' has no recovery envelope"))?;
            let package = crate::recovery::open_package(
                old_recovery,
                name,
                &decode_profile_id(&encrypted.profile_id)?,
                encrypted.generation,
                envelope,
                &old_local_share,
                old_media,
            )
            .with_context(|| format!("recover profile '{name}' before recovery rotation"))?;
            verify_recovery_binding(encrypted, &package, Some(old_recovery)).with_context(
                || format!("authenticate profile '{name}' recovery configuration before rotation"),
            )?;
            let authenticated = decrypt_profile_v3_with_package(name, encrypted, &package)
                .with_context(|| {
                    format!("authenticate profile '{name}' payload before recovery rotation")
                })?;
            drop(authenticated);
            envelopes.insert(
                name.clone(),
                (
                    crate::recovery::seal_package(
                        &new_config,
                        name,
                        &package.profile_id,
                        package.generation,
                        &package,
                    )?,
                    recovery_config_tag(&package.auth_seed, &new_config)?,
                ),
            );
            drop(package);
        }
        let expected_digest = vault_state_digest(&snapshot)?;
        drop(snapshot);

        let _barrier = acquire_runtime_barrier_exclusive()?;
        mutate_vault(|vault| {
            use subtle::ConstantTimeEq;
            if !bool::from(expected_digest.ct_eq(&vault_state_digest(vault)?)) {
                bail!("vault changed while recovery rotation was acquiring its runtime barrier; retry");
            }
            ensure_no_legacy_profile_lease_contention(&vault.profiles)?;
            let new_admin = {
                let passphrase = administrator_passphrase
                    .ok_or_else(|| anyhow!("administrator password is required"))?;
                Some(seal_admin_policy(
                    passphrase,
                    &new_config,
                    &new_local_share,
                )?)
            };
            persist_new_media(&new_media)
                .context("persist rotated recovery media before vault commit")?;
            for (name, (envelope, tag)) in envelopes {
                let profile = vault
                    .profiles
                    .get_mut(&name)
                    .expect("authenticated snapshot profile remains present");
                profile.recovery_envelope = Some(envelope);
                profile.recovery_config_tag = Some(tag);
            }
            vault.recovery = Some(new_config.clone());
            vault.admin = new_admin;
            vault.root_recovery_share = None;
            Ok(new_config.recovery_id.clone())
        })
    }
}

#[cfg(test)]
fn rename_profile_in_vault(
    vault: &mut VaultFile,
    old_name: &str,
    new_name: &str,
    creds: &Creds,
    key: &[u8; 32],
) -> Result<Option<String>> {
    if vault.profiles.contains_key(new_name) {
        bail!("profile '{new_name}' already exists");
    }

    let encrypted = vault
        .profiles
        .get(old_name)
        .ok_or_else(|| anyhow!("profile '{old_name}' not found"))?;
    let previous_pin = authenticated_pin_for_replacement(old_name, encrypted, key, creds)?;
    let mut updated = creds.clone();
    updated.host_key = previous_pin.clone();
    let renamed = encrypt_profile(new_name, &updated, key)?;
    ensure_verifier(vault, key)?;

    vault.profiles.remove(old_name);
    vault.profiles.insert(new_name.to_owned(), renamed);
    Ok(previous_pin)
}

#[cfg(test)]
pub fn decrypt(name: &str, master: &str) -> Result<Creds> {
    decrypt_with_lock_timeout(name, master, None, VAULT_LOCK_WAIT_TIMEOUT)
}

/// Decrypt a profile while bounding only acquisition of the shared vault-file
/// lock. Callers that invoke this from async code should run it on a blocking
/// worker and retain their own end-to-end deadline; local filesystem I/O and
/// Argon2 itself are synchronous and cannot be preempted by this timeout.
pub(crate) fn decrypt_with_lock_timeout(
    name: &str,
    profile_passphrase: &str,
    expected_identity: Option<ProfileIdentity>,
    lock_timeout: Duration,
) -> Result<Creds> {
    let vault = load_vault_with_lock_timeout(lock_timeout)?;
    // Network use is a v3-only capability. A v2 record may be decrypted only
    // inside the explicit all-or-nothing migration transaction; accepting a
    // v2 AAD record here would silently preserve the old shared-master model.
    require_v3(&vault)?;
    let encrypted = vault
        .profiles
        .get(name)
        .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
    require_identity(encrypted, expected_identity)?;
    authenticate_profile_v3(name, encrypted, profile_passphrase, vault.recovery.as_ref())
        .map(|(_, credentials)| credentials)
}

/// Decrypt the daemon's credential snapshot and derive its profile-scoped IPC
/// call-authorization key from the same Argon2 result. The returned key is
/// domain-separated from the vault encryption key; neither the master
/// passphrase nor the vault key needs to survive daemon setup.
pub(crate) fn decrypt_with_call_key_with_lock_timeout(
    name: &str,
    master: &str,
    expected_identity: Option<ProfileIdentity>,
    lock_timeout: Duration,
) -> Result<(Creds, ProfileCallKey)> {
    validate_profile_name(name)?;
    validate_master_passphrase(master)?;
    let vault = load_vault_with_lock_timeout(lock_timeout)?;
    decrypt_with_call_key_from_vault(&vault, name, master, expected_identity)
}

fn decrypt_with_call_key_from_vault(
    vault: &VaultFile,
    name: &str,
    profile_passphrase: &str,
    expected_identity: Option<ProfileIdentity>,
) -> Result<(Creds, ProfileCallKey)> {
    require_v3(vault)?;
    let encrypted = vault
        .profiles
        .get(name)
        .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
    require_identity(encrypted, expected_identity)?;
    let (package, creds) =
        authenticate_profile_v3(name, encrypted, profile_passphrase, vault.recovery.as_ref())?;
    let call_key = profile_call_key_v3(
        &package.auth_seed,
        name,
        &package.profile_id,
        package.generation,
    )?;
    Ok((creds, call_key))
}

/// Verify the master passphrase against the requested modern profile and
/// return only its domain-separated IPC call key. Although authenticating the
/// target ciphertext necessarily decrypts it transiently, the credential
/// value remains under `ZeroizeOnDrop` and is never returned to the caller.
pub(crate) fn derive_profile_call_key_with_lock_timeout(
    name: &str,
    master: &str,
    expected_identity: Option<ProfileIdentity>,
    lock_timeout: Duration,
) -> Result<ProfileCallKey> {
    validate_profile_name(name)?;
    validate_master_passphrase(master)?;
    let vault = load_vault_with_lock_timeout(lock_timeout)?;
    derive_profile_call_key_from_vault(&vault, name, master, expected_identity)
}

fn derive_profile_call_key_from_vault(
    vault: &VaultFile,
    name: &str,
    profile_passphrase: &str,
    expected_identity: Option<ProfileIdentity>,
) -> Result<ProfileCallKey> {
    require_v3(vault)?;
    let encrypted = vault
        .profiles
        .get(name)
        .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
    require_identity(encrypted, expected_identity)?;
    let (package, authenticated) =
        authenticate_profile_v3(name, encrypted, profile_passphrase, vault.recovery.as_ref())?;
    drop(authenticated);
    profile_call_key_v3(
        &package.auth_seed,
        name,
        &package.profile_id,
        package.generation,
    )
}

#[cfg(test)]
pub fn set_pinned_fp(name: &str, fingerprint: String, master: &str) -> Result<()> {
    let lease = acquire_profile_mutation_lease(name)?;
    set_pinned_fp_with_lock_timeout(name, fingerprint, master, VAULT_LOCK_WAIT_TIMEOUT, &lease)
}

/// Persist a TOFU pin while bounding only acquisition of the exclusive
/// vault-file lock. See `decrypt_with_lock_timeout` for the synchronous-I/O and
/// KDF caveat; the mutation itself remains atomic once the lock is acquired.
pub(crate) fn set_pinned_fp_with_lock_timeout(
    name: &str,
    fingerprint: String,
    master: &str,
    lock_timeout: Duration,
    profile_lease: &ProfileLease,
) -> Result<()> {
    // Require the caller's barrier-backed lifetime lease instead of acquiring
    // a second barrier after the profile lock. This preserves the one global-
    // before-profile-before-vault lock order.
    profile_lease.require_exclusive_profile(name)?;
    mutate_vault_with_lock_timeout(lock_timeout, |vault| {
        require_v3(vault)?;
        let encrypted = vault
            .profiles
            .get(name)
            .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
        let (package, mut creds) =
            authenticate_profile_v3(name, encrypted, master, vault.recovery.as_ref())?;
        if !apply_host_pin(&mut creds, fingerprint)? {
            return Ok(());
        }
        // First-use TOFU persistence happens after the caller has already
        // derived this profile's IPC call key. Rewrapping the authenticated
        // package with fresh nonces preserves that live authorization;
        // rotating AuthSeed/generation here would strand the just-started
        // daemon with an immediately stale key. User-visible credential,
        // passphrase, recovery and administrative mutations still create a
        // fresh package and advance generation.
        let replacement = wrap_profile_v3(name, &creds, master, &package, vault.recovery.as_ref())?;
        vault.profiles.insert(name.to_owned(), replacement);
        Ok(())
    })
}

fn apply_host_pin(creds: &mut Creds, fingerprint: String) -> Result<bool> {
    if fingerprint.is_empty()
        || fingerprint.len() > 1024
        || contains_control_character(&fingerprint)
    {
        bail!("host-key fingerprint is empty, oversized, or contains control characters");
    }
    if let Some(existing) = &creds.host_key {
        if existing != &fingerprint {
            bail!("host key was pinned concurrently to a different fingerprint");
        }
        return Ok(false);
    }
    creds.host_key = Some(fingerprint);
    Ok(true)
}

#[cfg(test)]
fn verify_master_passphrase_from_vault(vault: &VaultFile, master: &str) -> Result<()> {
    if vault.verifier.is_none() && vault.profiles.is_empty() {
        return enforce_new_vault_master_policy(vault, master);
    }
    let key = vault_key(vault, master)?;
    verify_master(vault, &key)
}

fn verify_established_master_for_rekey(vault: &VaultFile, master: &str) -> Result<()> {
    if vault.verifier.is_none() && vault.profiles.is_empty() {
        bail!("the empty vault has no established master passphrase to change");
    }
    let key = vault_key(vault, master)?;
    verify_master(vault, &key)
}

fn ensure_no_legacy_profile_lease_contention(
    profiles: &BTreeMap<String, EncProfile>,
) -> Result<()> {
    // Current binaries hold the vault-wide barrier before taking a profile
    // lease. Older binaries do not know that barrier, so while the vault lock
    // is exclusive we also probe their per-profile locks one at a time. This
    // keeps descriptor use O(1): an old operation that already has plaintext
    // is detected, while one starting after its profile was probed cannot read
    // the vault until this rekey commits and will fail old-master verification.
    for name in profiles.keys() {
        let Some(lease) = open_existing_runtime_lease_file(name)? else {
            continue;
        };
        match lease.try_lock_exclusive() {
            Ok(()) => FileExt::unlock(&lease)
                .with_context(|| format!("release compatibility probe for profile '{name}'"))?,
            Err(error) if is_lock_contention(&error) => bail!(
                "cannot rotate the vault master while profile '{name}' is in use; stop older serctl processes and retry"
            ),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("probe compatibility lease for profile '{name}'"));
            }
        }
    }
    Ok(())
}

/// Build a complete replacement vault without mutating the authenticated
/// source. Profiles are authenticated and transformed one at a time; a
/// legacy, malformed, or tampered record drops the uncommitted replacement
/// and aborts the whole operation.
#[cfg(test)]
fn build_rekeyed_vault(vault: &VaultFile, old_master: &str, new_master: &str) -> Result<VaultFile> {
    validate_master_passphrase(old_master)?;
    validate_new_master_passphrase(new_master)?;

    if vault.verifier.is_none() && vault.profiles.is_empty() {
        bail!("the empty vault has no established master passphrase to change");
    }

    let old_key = vault_key(vault, old_master)?;
    verify_master(vault, &old_key)?;

    let mut salt = [0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut replacement = VaultFile {
        version: LEGACY_VAULT_FORMAT,
        salt: B64.encode(salt),
        kdf: Some(KdfConfig::default()),
        verifier: None,
        admin: None,
        recovery: None,
        root_recovery_share: None,
        profiles: BTreeMap::new(),
    };
    let new_key = vault_key(&replacement, new_master)?;
    for (name, encrypted) in &vault.profiles {
        // Authenticate, re-encrypt, and erase one profile before moving to
        // the next. Rekey never retains a vault-sized aggregate of plaintext
        // credentials in memory.
        let credentials = decrypt_profile_with_key(name, encrypted, &old_key)
            .with_context(|| format!("authenticate profile '{name}' before master rotation"))?;
        let reencrypted = encrypt_profile(name, &credentials, &new_key)?;
        drop(credentials);
        replacement.profiles.insert(name.clone(), reencrypted);
    }
    ensure_verifier(&mut replacement, &new_key)?;
    validate_loaded_vault(&replacement)?;
    Ok(replacement)
}

/// Explicit, all-or-nothing migration from the shared-master v2 format to v4
/// independent profile passphrases and vault-wide 2-of-2 recovery.  No lazy or
/// partial migration is permitted: either every authenticated v2 record is
/// transformed and the new medium is persisted, or the v2 vault is untouched.
pub fn migrate_v2_with_progress<F, P>(
    old_master: &str,
    new_profile_passphrases: &BTreeMap<String, Zeroizing<String>>,
    new_administrator_password: Option<&str>,
    persist_media: F,
    mut progress: P,
) -> Result<usize>
where
    F: FnOnce(&[u8]) -> Result<()>,
    P: FnMut(MigrationProgress),
{
    progress(MigrationProgress::Validating);
    validate_master_passphrase(old_master)?;
    for (name, passphrase) in new_profile_passphrases {
        validate_profile_name(name)?;
        validate_new_master_passphrase(passphrase)
            .with_context(|| format!("validate new passphrase for profile '{name}'"))?;
    }
    #[cfg(windows)]
    let administrator_password = {
        let password = new_administrator_password
            .ok_or_else(|| anyhow!("a new Windows administrator password is required"))?;
        validate_new_master_passphrase(password).context("validate new administrator password")?;
        password
    };
    #[cfg(unix)]
    {
        let _ = new_administrator_password;
        let _ = persist_media;
        require_linux_root()?;
        bail!("Linux v2 migration with offline recovery is fail-closed until a root-owned system share store and explicit target-user vault boundary are configured");
    }
    #[cfg(windows)]
    {
        // Authenticate the old master before disclosing global lease contention.
        let snapshot = load_vault()?;
        if !matches!(snapshot.version, 0 | LEGACY_VAULT_FORMAT) {
            bail!("vault is not a legacy v2 vault");
        }
        verify_established_master_for_rekey(&snapshot, old_master)?;
        if snapshot.profiles.len() != new_profile_passphrases.len()
            || snapshot
                .profiles
                .keys()
                .any(|name| !new_profile_passphrases.contains_key(name))
        {
            bail!("migration requires exactly one new independent passphrase for every v2 profile");
        }
        let expected_digest = vault_state_digest(&snapshot)?;
        drop(snapshot);

        progress(MigrationProgress::WaitingForExclusiveAccess);
        let _runtime_barrier = acquire_runtime_barrier_exclusive()?;
        let vault_lock = open_vault_lock()?;
        lock_vault_with_timeout(
            &vault_lock,
            VaultLockMode::Exclusive,
            VAULT_LOCK_WAIT_TIMEOUT,
        )?;
        let current = load_vault_unlocked()?;
        use subtle::ConstantTimeEq;
        if !bool::from(expected_digest.ct_eq(&vault_state_digest(&current)?)) {
            bail!("vault changed while migration was acquiring its runtime barrier; retry");
        }
        ensure_no_legacy_profile_lease_contention(&current.profiles)?;
        let old_key = vault_key(&current, old_master)?;
        verify_master(&current, &old_key)?;
        progress(MigrationProgress::AuthenticatedLegacyVault);

        let (recovery, local_share, media) = crate::recovery::generate_recovery()?;
        let admin = Some(seal_admin_policy(
            administrator_password,
            &recovery,
            &local_share,
        )?);
        let root_recovery_share: Option<String> = None;

        let mut replacement = VaultFile {
            version: VAULT_FORMAT,
            salt: String::new(),
            kdf: None,
            verifier: None,
            admin,
            recovery: Some(recovery.clone()),
            root_recovery_share,
            profiles: BTreeMap::new(),
        };
        let profile_total = current.profiles.len();
        for (profile_index, (name, encrypted)) in current.profiles.iter().enumerate() {
            progress(MigrationProgress::MigratingProfile {
                completed: profile_index,
                total: profile_total,
                profile: name.clone(),
            });
            if encrypted.format != PROFILE_FORMAT_AAD {
                bail!(
                "legacy profile '{name}' lacks authenticated endpoint metadata; replace it explicitly instead of migrating it"
            );
            }
            let credentials = decrypt_profile_with_key(name, encrypted, &old_key)
                .with_context(|| format!("authenticate v2 profile '{name}' before migration"))?;
            let package = new_key_package(new_profile_id(), 1);
            let passphrase = new_profile_passphrases
                .get(name)
                .expect("exact profile-passphrase set checked above");
            let migrated =
                wrap_profile_v3(name, &credentials, passphrase, &package, Some(&recovery))?;
            replacement.profiles.insert(name.clone(), migrated);
        }
        validate_loaded_vault(&replacement)?;
        progress(MigrationProgress::PersistingRecoveryMedia);
        persist_media(&media).context("persist v4 recovery media before vault migration commit")?;
        let profile_count = replacement.profiles.len();
        progress(MigrationProgress::CommittingVault);
        save_vault_unlocked(&replacement).context(
            "commit migrated vault atomically; a failure may leave only an orphan recovery medium",
        )?;
        Ok(profile_count)
    }
}

#[cfg(test)]
fn list_with_master_from_vault(
    vault: VaultFile,
    master: &str,
) -> Result<Vec<(String, String, u16)>> {
    verify_master_passphrase_from_vault(&vault, master)?;
    Ok(vault
        .profiles
        .into_iter()
        .map(|(name, profile)| (name, profile.host, profile.port))
        .collect())
}

#[cfg(test)]
fn list_with_profile_call_keys_from_vault(
    vault: &VaultFile,
    master: &str,
) -> Result<Vec<AuthorizedProfileMetadata>> {
    if vault.verifier.is_none() && vault.profiles.is_empty() {
        enforce_new_vault_master_policy(vault, master)?;
        return Ok(Vec::new());
    }

    // One vault-global Argon2 derivation authorizes every record in this
    // immutable snapshot. Per-profile call keys are cheap domain-separated
    // HMACs and never expose or retain the vault encryption key.
    let key = vault_key(vault, master)?;
    verify_master(vault, &key)?;
    let mut profiles = Vec::with_capacity(vault.profiles.len());
    for (name, encrypted) in &vault.profiles {
        let authenticated = decrypt_profile_with_key(name, encrypted, &key)
            .with_context(|| format!("authenticate profile '{name}' for status refresh"))?;
        let host = authenticated.host.clone();
        let port = authenticated.port;
        drop(authenticated);
        profiles.push(AuthorizedProfileMetadata {
            name: name.clone(),
            host,
            port,
            call_key: profile_call_key(&key, name)?,
        });
    }
    Ok(profiles)
}

#[cfg(test)]
fn remove_with_master_from_vault(vault: &mut VaultFile, name: &str, master: &str) -> Result<bool> {
    let key = vault_key(vault, master)?;
    verify_master(vault, &key)?;
    if let Some(encrypted) = vault.profiles.get(name) {
        // Removal also supports authentic legacy records, but never trusts or
        // returns their unauthenticated endpoint metadata.
        let authenticated = decrypt_profile_payload_with_key(name, encrypted, &key)?;
        drop(authenticated);
    }
    Ok(vault.profiles.remove(name).is_some())
}

pub fn write_lock(info: &LockInfo) -> Result<()> {
    validate_runtime_lock_info(&info.profile, info)?;
    let path = lock_path(&info.profile)?;
    let serialized = serialize_json_zeroizing(
        info,
        MAX_LOCK_BYTES as usize,
        JsonStyle::Pretty,
        "runtime lock exceeds the 64 KiB safety limit",
    )?;
    security::write_protected_atomic(&path, &serialized)
}

pub fn read_lock(profile: &str) -> Result<Option<LockInfo>> {
    validate_profile_name(profile)?;
    let path = existing_lock_path(profile)?;
    let bytes = match read_lock_file(&path)? {
        Some(bytes) => bytes,
        None => match read_legacy_lock(profile)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        },
    };
    let info: LockInfo = serde_json::from_slice(&bytes)?;
    validate_runtime_lock_info(profile, &info)?;
    Ok(Some(info))
}

fn validate_runtime_lock_info(expected_profile: &str, info: &LockInfo) -> Result<()> {
    if info.profile != expected_profile {
        bail!("runtime lock profile mismatch");
    }
    match info.protocol {
        crate::ipc::IPC_PROTOCOL_VERSION => {}
        0 => bail!(
            "legacy runtime lock uses bearer-token IPC; stop it and restart with protocol {}",
            crate::ipc::IPC_PROTOCOL_VERSION
        ),
        version => bail!("unsupported runtime lock IPC protocol {version}"),
    }
    if info.pid == 0 {
        bail!("runtime lock contains an invalid daemon PID");
    }
    crate::ipc::validate_endpoint(expected_profile, &info.token, &info.endpoint)
        .context("validate runtime lock endpoint and capability")?;
    if info.port != 0 || !info.host.is_empty() || !info.user.is_empty() {
        bail!("protocol-v5 runtime lock contains forbidden remote metadata");
    }
    Ok(())
}

/// Open and consume one stable file handle. In particular, do not probe the
/// path with `exists` or path-based `metadata` first: lock removal/replacement
/// between those calls is normal during daemon shutdown.
fn read_lock_file(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(mut file) = open_lock_file_for_read(path)
        .with_context(|| format!("open runtime lock {}", path.display()))?
    else {
        return Ok(None);
    };
    let metadata_len = file
        .metadata()
        .with_context(|| format!("inspect runtime lock {}", path.display()))?
        .len();
    read_lock_handle_after_metadata(&mut file, metadata_len)
        .with_context(|| format!("read runtime lock {}", path.display()))
        .map(Some)
}

#[cfg(windows)]
fn open_lock_file_for_read(path: &Path) -> Result<Option<File>> {
    let mut access_denied_retries = 0;

    loop {
        match security::open_existing_protected_file(path) {
            Ok(file) => return Ok(file),
            Err(error)
                if error.chain().any(|source| {
                    source.downcast_ref::<std::io::Error>().is_some_and(|io| {
                        io.kind() == std::io::ErrorKind::PermissionDenied
                            && io.raw_os_error() == Some(5)
                    })
                }) && access_denied_retries < LOCK_OPEN_ACCESS_DENIED_RETRIES =>
            {
                // Windows can report ERROR_ACCESS_DENIED while an atomically
                // replaced/deleted file is still delete-pending. Retry only
                // that exact status, for at most 15 ms total; persistent ACL
                // failures are returned to the caller unchanged.
                access_denied_retries += 1;
                std::thread::sleep(LOCK_OPEN_RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(windows))]
fn open_lock_file_for_read(path: &Path) -> Result<Option<File>> {
    security::open_existing_protected_file(path)
}

#[cfg(windows)]
fn read_legacy_lock(_profile: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    // Raw legacy names can resolve to DOS devices, alternate path spellings,
    // or trailing-dot/space aliases. Windows therefore accepts only the
    // hashed runtime-lock namespace.
    Ok(None)
}

#[cfg(not(windows))]
fn read_legacy_lock(profile: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    // Unix retains read-only detection of a v1 daemon so a v5 client will not
    // start a second instance. Safe opening still rejects links, FIFOs, and
    // devices.
    read_lock_file(&run_dir_path()?.join(format!("{profile}.lock")))
}

fn read_lock_handle_after_metadata(
    file: &mut File,
    metadata_len: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    read_bounded_handle(
        file,
        metadata_len,
        MAX_LOCK_BYTES,
        BoundedReadAllocation::FullLimit,
        "runtime lock exceeds the 64 KiB safety limit",
    )
}

#[derive(Clone, Copy)]
enum BoundedReadAllocation {
    MetadataLength,
    FullLimit,
}

fn read_bounded_handle(
    file: &mut File,
    metadata_len: u64,
    maximum: u64,
    allocation: BoundedReadAllocation,
    limit_error: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    if metadata_len > maximum {
        bail!(limit_error);
    }
    let read_limit = maximum
        .checked_add(1)
        .ok_or_else(|| anyhow!("bounded read limit overflow"))?;
    let capacity_u64 = match allocation {
        BoundedReadAllocation::MetadataLength => metadata_len,
        BoundedReadAllocation::FullLimit => read_limit,
    };
    let capacity = usize::try_from(capacity_u64).context("bounded read allocation is too large")?;

    // Arm the zeroizing guard before the first read. Runtime lock files carry
    // the live IPC capability, so an I/O failure or a file that grows past the
    // limit must not drop a partially-filled ordinary Vec into the allocator.
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error| anyhow!("reserve bounded read buffer: {error}"))?;
    match allocation {
        BoundedReadAllocation::MetadataLength => {
            file.take(read_limit).read_to_end(&mut bytes)?;
        }
        BoundedReadAllocation::FullLimit => {
            // Resize once before reading and fill the existing allocation in
            // place. A metadata-small lock that grows while open can therefore
            // never make Vec reallocate and free a token-bearing prefix before
            // the Zeroizing guard gets a chance to erase it.
            bytes.resize(capacity, 0);
            let mut filled = 0;
            while filled < capacity {
                match file.read(&mut bytes[filled..]) {
                    Ok(0) => break,
                    Ok(read) => filled += read,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            bytes.truncate(filled);
        }
    }
    if bytes.len() as u64 > maximum {
        bail!(limit_error);
    }
    Ok(bytes)
}

/// Remove a malformed lock from the hashed protocol-v5 namespace, but only
/// after acquiring the same exclusive lifetime lease used by daemon startup.
/// Security/open/read failures and locks from other protocol versions remain
/// fail-closed. The legacy raw-name namespace is never inspected or removed.
pub fn remove_invalid_hashed_v5_lock(profile: &str) -> Result<bool> {
    let lease = open_runtime_lease_file(profile)?;
    with_exclusive_runtime_cleanup(&lease, || {
        remove_invalid_hashed_v5_lock_while_leased(profile)
    })
}

/// Variant for daemon startup, whose caller already owns the profile's
/// exclusive runtime lease. This mirrors `remove_lock_if_token_while_leased`;
/// callers must keep that lease handle alive for the full call.
pub(crate) fn remove_invalid_hashed_v5_lock_while_leased(profile: &str) -> Result<bool> {
    validate_profile_name(profile)?;
    // Validate/harden the directory before classifying contents. Any owner,
    // ACL, reparse, or directory I/O error exits before deletion is possible.
    let runtime_dir = run_dir()?;
    let path = runtime_dir.join(lock_filename(profile));
    let Some(bytes) = read_lock_file(&path)? else {
        return Ok(false);
    };
    if !hashed_v5_lock_is_invalid(profile, &bytes, &runtime_dir)? {
        return Ok(false);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("remove malformed hashed runtime lock"),
    }
}

fn hashed_v5_lock_is_invalid(
    expected_profile: &str,
    bytes: &[u8],
    verified_runtime_dir: &Path,
) -> Result<bool> {
    let info: LockInfo = match serde_json::from_slice(bytes) {
        Ok(info) => info,
        Err(_) => return Ok(true),
    };
    if info.protocol != crate::ipc::IPC_PROTOCOL_VERSION {
        bail!(
            "runtime lock protocol {} is not eligible for protocol-v5 malformed-lock cleanup",
            info.protocol
        );
    }
    if info.profile != expected_profile
        || info.pid == 0
        || info.port != 0
        || !info.host.is_empty()
        || !info.user.is_empty()
    {
        return Ok(true);
    }

    let decoded_token = match B64.decode(info.token.as_bytes()) {
        Ok(token) => Zeroizing::new(token),
        Err(_) => return Ok(true),
    };
    if decoded_token.len() != 32 {
        return Ok(true);
    }
    let canonical_token = Zeroizing::new(B64.encode(decoded_token.as_slice()));
    if canonical_token.as_bytes() != info.token.as_bytes() {
        return Ok(true);
    }
    let expected_endpoint = crate::ipc::expected_endpoint_in_runtime_dir(
        expected_profile,
        &info.token,
        verified_runtime_dir,
    )?;
    Ok(expected_endpoint.as_bytes() != info.endpoint.as_bytes())
}

/// Result of reconciling an unreachable daemon's protected runtime lock.
///
/// The variants remain distinct because only `Removed` and `Absent` permit a
/// caller to fall back to a direct connection. `Changed` means a replacement
/// daemon published a different capability, while `Contended` means a daemon
/// or direct profile user still owns the lifetime lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockReconcileOutcome {
    Removed,
    Absent,
    Changed,
    Contended,
}

/// Reconcile a v5 runtime lock only if it still belongs to the expected daemon.
/// This prevents stale-client cleanup from deleting a newly replaced lock and
/// distinguishes a normal shutdown (the lock is already absent) from lease
/// contention or a changed lock. The exclusive lease is held across the stable
/// handle read, token comparison, and any deletion.
pub fn reconcile_lock_if_token(
    profile: &str,
    expected_token: &str,
) -> Result<LockReconcileOutcome> {
    let lease = open_runtime_lease_file(profile)?;
    reconcile_under_exclusive_runtime_lease(&lease, || {
        reconcile_lock_if_token_while_leased(profile, expected_token)
    })
}

fn reconcile_under_exclusive_runtime_lease(
    lease: &File,
    reconcile: impl FnOnce() -> Result<LockReconcileOutcome>,
) -> Result<LockReconcileOutcome> {
    match lease.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if is_lock_contention(&error) => return Ok(LockReconcileOutcome::Contended),
        Err(error) => return Err(error.into()),
    }
    reconcile()
}

/// Run stale-lock cleanup only while this handle owns the profile's exclusive
/// lifetime lease. The closure form makes it impossible for callers of this
/// helper to perform deletion on the contended path.
fn with_exclusive_runtime_cleanup(
    lease: &File,
    cleanup: impl FnOnce() -> Result<bool>,
) -> Result<bool> {
    match lease.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if is_lock_contention(&error) => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    cleanup()
}

/// Remove the caller's runtime lock while it still owns the exclusive lease.
/// Keeping removal before lease release closes the handoff window in which a
/// replacement daemon could observe the retiring daemon's lock record.
pub(crate) fn remove_lock_if_token_while_leased(
    profile: &str,
    expected_token: &str,
) -> Result<bool> {
    Ok(matches!(
        reconcile_lock_if_token_while_leased(profile, expected_token)?,
        LockReconcileOutcome::Removed
    ))
}

fn reconcile_lock_if_token_while_leased(
    profile: &str,
    expected_token: &str,
) -> Result<LockReconcileOutcome> {
    use subtle::ConstantTimeEq;

    let path = existing_lock_path(profile)?;
    let Some(bytes) = read_lock_file(&path)? else {
        return Ok(LockReconcileOutcome::Absent);
    };
    let info: LockInfo = serde_json::from_slice(&bytes)?;
    validate_runtime_lock_info(profile, &info)?;
    let matches_profile = info.profile == profile;
    let matches_token: bool = info
        .token
        .as_bytes()
        .ct_eq(expected_token.as_bytes())
        .into();
    if !matches_profile || !matches_token {
        return Ok(LockReconcileOutcome::Changed);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(LockReconcileOutcome::Removed),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(LockReconcileOutcome::Absent)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_creds() -> Creds {
        Creds {
            host: "server.example".into(),
            port: 2222,
            user: "deploy".into(),
            password: "correct horse battery staple".into(),
            host_key: Some("SHA256:server-fingerprint".into()),
        }
    }

    #[test]
    fn v3_profiles_have_independent_kdfs_packages_and_call_keys() {
        let first_passphrase = "first-independent-profile-passphrase";
        let second_passphrase = "second-independent-profile-passphrase";
        let first_package = new_key_package([1_u8; 16], 1);
        let second_package = new_key_package([2_u8; 16], 1);
        let first = wrap_profile_v3(
            "first",
            &sample_creds(),
            first_passphrase,
            &first_package,
            None,
        )
        .unwrap();
        let second = wrap_profile_v3(
            "second",
            &sample_creds(),
            second_passphrase,
            &second_package,
            None,
        )
        .unwrap();

        assert_eq!(first.format, PROFILE_FORMAT_ENVELOPE);
        assert_ne!(first.profile_salt, second.profile_salt);
        assert!(unwrap_profile_package("first", &first, second_passphrase).is_err());
        assert!(unwrap_profile_package("second", &second, first_passphrase).is_err());

        let opened_first = unwrap_profile_package("first", &first, first_passphrase).unwrap();
        let opened_second = unwrap_profile_package("second", &second, second_passphrase).unwrap();
        assert_eq!(
            decrypt_profile_v3_with_package("first", &first, &opened_first)
                .unwrap()
                .password,
            sample_creds().password
        );
        let first_call = profile_call_key_v3(
            &opened_first.auth_seed,
            "first",
            &opened_first.profile_id,
            opened_first.generation,
        )
        .unwrap();
        let second_call = profile_call_key_v3(
            &opened_second.auth_seed,
            "second",
            &opened_second.profile_id,
            opened_second.generation,
        )
        .unwrap();
        assert_ne!(first_call.as_bytes(), second_call.as_bytes());
        assert_ne!(opened_first.dek, opened_second.dek);
        assert_ne!(opened_first.auth_seed, opened_second.auth_seed);
    }

    #[test]
    fn v3_generation_is_bound_to_both_envelopes_and_invalidates_old_authorization() {
        let passphrase = "independent-profile-passphrase";
        let profile_id = [3_u8; 16];
        let old_package = new_key_package(profile_id, 7);
        let encrypted =
            wrap_profile_v3("prod", &sample_creds(), passphrase, &old_package, None).unwrap();
        let old_call = profile_call_key_v3(
            &old_package.auth_seed,
            "prod",
            &old_package.profile_id,
            old_package.generation,
        )
        .unwrap();

        let new_package = new_key_package(profile_id, 8);
        let rotated =
            wrap_profile_v3("prod", &sample_creds(), passphrase, &new_package, None).unwrap();
        let new_call = profile_call_key_v3(
            &new_package.auth_seed,
            "prod",
            &new_package.profile_id,
            new_package.generation,
        )
        .unwrap();
        assert_ne!(old_call.as_bytes(), new_call.as_bytes());
        assert!(decrypt_profile_v3_with_package("prod", &rotated, &old_package).is_err());

        let mut tampered = encrypted.clone();
        tampered.generation = 8;
        assert!(unwrap_profile_package("prod", &tampered, passphrase).is_err());
        assert!(decrypt_profile_v3_with_package("prod", &tampered, &old_package).is_err());
    }

    #[test]
    fn same_name_generation_and_passphrase_recreation_rejects_old_identity_and_call_key() {
        let passphrase = "same-independent-profile-passphrase";
        let old_package = new_key_package([0x31; 16], 1);
        let old = wrap_profile_v3("prod", &sample_creds(), passphrase, &old_package, None).unwrap();
        let mut recreated_package = old_package.clone();
        recreated_package.profile_id = [0x52; 16];
        let recreated = wrap_profile_v3(
            "prod",
            &sample_creds(),
            passphrase,
            &recreated_package,
            None,
        )
        .unwrap();

        assert!(require_identity(&recreated, Some(profile_identity(&old).unwrap())).is_err());
        assert!(unwrap_profile_package("prod", &recreated, passphrase).is_ok());
        assert!(decrypt_profile_v3_with_package("prod", &recreated, &old_package).is_err());

        let old_call = profile_call_key_v3(
            &old_package.auth_seed,
            "prod",
            &old_package.profile_id,
            old_package.generation,
        )
        .unwrap();
        let recreated_call = profile_call_key_v3(
            &recreated_package.auth_seed,
            "prod",
            &recreated_package.profile_id,
            recreated_package.generation,
        )
        .unwrap();
        assert_ne!(old_call.as_bytes(), recreated_call.as_bytes());
    }

    #[test]
    fn v3_tofu_pin_rewrap_preserves_the_live_call_key_and_generation() {
        let passphrase = "independent-profile-passphrase";
        let package = new_key_package([4_u8; 16], 11);
        let mut unpinned = sample_creds();
        unpinned.host_key = None;
        let mut encrypted = wrap_profile_v3("prod", &unpinned, passphrase, &package, None).unwrap();
        let before = profile_call_key_v3(
            &package.auth_seed,
            "prod",
            &package.profile_id,
            package.generation,
        )
        .unwrap();
        let mut credentials =
            decrypt_profile_v3_with_package("prod", &encrypted, &package).unwrap();
        assert!(apply_host_pin(&mut credentials, "SHA256:new-pin".into()).unwrap());
        encrypted = wrap_profile_v3("prod", &credentials, passphrase, &package, None).unwrap();

        let reopened = unwrap_profile_package("prod", &encrypted, passphrase).unwrap();
        let after = profile_call_key_v3(
            &reopened.auth_seed,
            "prod",
            &reopened.profile_id,
            reopened.generation,
        )
        .unwrap();
        assert_eq!(encrypted.generation, 11);
        assert_eq!(before.as_bytes(), after.as_bytes());
        assert_eq!(
            decrypt_profile_v3_with_package("prod", &encrypted, &reopened)
                .unwrap()
                .host_key
                .as_deref(),
            Some("SHA256:new-pin")
        );
    }

    #[test]
    fn v3_recovery_requires_both_shares_and_never_contains_the_profile_passphrase() {
        let passphrase = "profile-passphrase-not-in-recovery";
        let package = new_key_package([5_u8; 16], 3);
        let (config, local_share, media) = crate::recovery::generate_recovery().unwrap();
        let encrypted = wrap_profile_v3(
            "recoverable",
            &sample_creds(),
            passphrase,
            &package,
            Some(&config),
        )
        .unwrap();
        let envelope = encrypted.recovery_envelope.as_ref().unwrap();
        let recovered = crate::recovery::open_package(
            &config,
            "recoverable",
            &package.profile_id,
            3,
            envelope,
            &local_share,
            &media,
        )
        .unwrap();
        assert_eq!(recovered.dek, package.dek);
        assert_eq!(recovered.auth_seed, package.auth_seed);
        assert!(!String::from_utf8_lossy(&media).contains(passphrase));
        assert!(!encrypted.key_ct.contains(passphrase));

        let wrong_local = [0x5a_u8; 32];
        assert!(crate::recovery::open_package(
            &config,
            "recoverable",
            &package.profile_id,
            3,
            envelope,
            &wrong_local,
            &media,
        )
        .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_admin_password_wraps_only_one_recovery_share_and_not_profile_keys() {
        let admin_password = "independent-windows-admin-password";
        let profile_password = "independent-profile-password";
        let (config, local_share, media) = crate::recovery::generate_recovery().unwrap();
        let policy = seal_admin_policy(admin_password, &config, &local_share).unwrap();
        let vault = VaultFile {
            admin: Some(policy),
            recovery: Some(config.clone()),
            ..VaultFile::default()
        };
        let opened_share = open_admin_policy(&vault, admin_password).unwrap();
        assert_eq!(&*opened_share, &*local_share);
        assert!(open_admin_policy(&vault, "wrong-administrator-password").is_err());

        let package = new_key_package([6_u8; 16], 1);
        let encrypted = wrap_profile_v3(
            "prod",
            &sample_creds(),
            profile_password,
            &package,
            Some(&config),
        )
        .unwrap();
        assert!(unwrap_profile_package("prod", &encrypted, admin_password).is_err());
        let envelope = encrypted.recovery_envelope.as_ref().unwrap();
        assert!(crate::recovery::open_package(
            &config,
            "prod",
            &package.profile_id,
            1,
            envelope,
            &[0x11_u8; 32],
            &media,
        )
        .is_err());

        let serialized = serde_json::to_vec(&vault).unwrap();
        assert!(!String::from_utf8_lossy(&serialized).contains(&B64.encode(local_share.as_ref())));
    }

    #[cfg(windows)]
    #[test]
    fn recovery_public_key_substitution_is_rejected_by_admin_and_profile_bindings() {
        let admin_password = "independent-windows-admin-password";
        let profile_password = "independent-profile-password";
        let (config, local_share, _media) = crate::recovery::generate_recovery().unwrap();
        let policy = seal_admin_policy(admin_password, &config, &local_share).unwrap();
        let package = new_key_package([7_u8; 16], 4);
        let encrypted = wrap_profile_v3(
            "prod",
            &sample_creds(),
            profile_password,
            &package,
            Some(&config),
        )
        .unwrap();
        let mut vault = VaultFile {
            admin: Some(policy),
            recovery: Some(config.clone()),
            ..VaultFile::default()
        };
        vault.profiles.insert("prod".into(), encrypted.clone());

        let (attacker_config, _, _) = crate::recovery::generate_recovery().unwrap();
        vault.recovery.as_mut().unwrap().public_key = attacker_config.public_key.clone();
        assert!(open_admin_policy(&vault, admin_password)
            .unwrap_err()
            .to_string()
            .contains("does not authenticate"));
        let substituted = authenticate_profile_v3(
            "prod",
            vault.profiles.get("prod").unwrap(),
            profile_password,
            vault.recovery.as_ref(),
        );
        let substituted_error = substituted.err().expect("substituted key must fail closed");
        assert!(substituted_error
            .to_string()
            .contains("authentication failed"));

        let mut tag_tampered = encrypted.clone();
        let mut tag = B64
            .decode(tag_tampered.recovery_config_tag.as_ref().unwrap())
            .unwrap();
        tag[0] ^= 1;
        tag_tampered.recovery_config_tag = Some(B64.encode(tag));
        assert!(
            authenticate_profile_v3("prod", &tag_tampered, profile_password, Some(&config),)
                .is_err()
        );

        let other_package = new_key_package([8_u8; 16], 4);
        let other = wrap_profile_v3(
            "other",
            &sample_creds(),
            "other-independent-passphrase",
            &other_package,
            Some(&config),
        )
        .unwrap();
        let mut replayed = encrypted;
        replayed.recovery_config_tag = other.recovery_config_tag;
        assert!(
            authenticate_profile_v3("prod", &replayed, profile_password, Some(&config)).is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_v3_rejects_profiles_without_admin_recovery_and_any_root_share() {
        let package = new_key_package([9_u8; 16], 1);
        let encrypted = wrap_profile_v3(
            "prod",
            &sample_creds(),
            "independent-profile-password",
            &package,
            None,
        )
        .unwrap();
        let mut vault = VaultFile::default();
        vault.profiles.insert("prod".into(), encrypted);
        assert!(validate_loaded_vault(&vault)
            .unwrap_err()
            .to_string()
            .contains("administrator/recovery"));

        let vault = VaultFile {
            root_recovery_share: Some(B64.encode([9_u8; 32])),
            ..VaultFile::default()
        };
        assert!(validate_loaded_vault(&vault)
            .unwrap_err()
            .to_string()
            .contains("must never contain"));
    }

    fn legacy_profile(key: &[u8; 32]) -> EncProfile {
        let nonce = [23_u8; 12];
        let secret = Secret {
            user: "legacy-user".into(),
            password: "legacy-password".into(),
            host_key: None,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&secret).unwrap());
        let cipher = ChaCha20Poly1305::new(key.into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();
        EncProfile {
            host: "legacy.example".into(),
            port: 22,
            format: 0,
            nonce: B64.encode(nonce),
            ct: B64.encode(ciphertext),
            host_key: Some("SHA256:legacy-pin".into()),
            generation: 0,
            profile_id: String::new(),
            profile_salt: String::new(),
            profile_kdf: None,
            key_nonce: String::new(),
            key_ct: String::new(),
            recovery_envelope: None,
            recovery_config_tag: None,
        }
    }

    #[test]
    fn profile_aad_changes_with_endpoint() {
        assert_ne!(
            profile_aad("prod", "host-a", 22).unwrap(),
            profile_aad("prod", "host-b", 22).unwrap()
        );
        assert_ne!(
            profile_aad("prod", "host-a", 22).unwrap(),
            profile_aad("stage", "host-a", 22).unwrap()
        );
    }

    fn modern_test_vault(master: &str) -> VaultFile {
        let mut vault = VaultFile {
            version: LEGACY_VAULT_FORMAT,
            salt: B64.encode([0x31_u8; 16]),
            kdf: Some(KdfConfig {
                memory_kib: 8 * 1024,
                iterations: 1,
                parallelism: 1,
                output_bytes: 32,
            }),
            verifier: None,
            admin: None,
            recovery: None,
            root_recovery_share: None,
            profiles: BTreeMap::new(),
        };
        let key = vault_key(&vault, master).unwrap();
        vault.profiles.insert(
            "prod".into(),
            encrypt_profile("prod", &sample_creds(), &key).unwrap(),
        );
        let mut stage = sample_creds();
        stage.host = "stage.example".into();
        vault.profiles.insert(
            "stage".into(),
            encrypt_profile("stage", &stage, &key).unwrap(),
        );
        ensure_verifier(&mut vault, &key).unwrap();
        vault
    }

    #[test]
    fn v3_call_key_entrypoints_require_independent_passphrases_and_reject_v2() {
        let prod_passphrase = "prod-independent-profile-passphrase";
        let stage_passphrase = "stage-independent-profile-passphrase";
        let mut vault = VaultFile::default();
        let prod_package = new_key_package([10_u8; 16], 1);
        let mut stage_creds = sample_creds();
        stage_creds.host = "stage.example".into();
        let stage_package = new_key_package([11_u8; 16], 1);
        vault.profiles.insert(
            "prod".into(),
            wrap_profile_v3(
                "prod",
                &sample_creds(),
                prod_passphrase,
                &prod_package,
                None,
            )
            .unwrap(),
        );
        vault.profiles.insert(
            "stage".into(),
            wrap_profile_v3(
                "stage",
                &stage_creds,
                stage_passphrase,
                &stage_package,
                None,
            )
            .unwrap(),
        );

        let prod_identity = ProfileIdentity {
            profile_id: prod_package.profile_id,
            generation: 1,
        };
        let stage_identity = ProfileIdentity {
            profile_id: stage_package.profile_id,
            generation: 1,
        };
        let (creds, daemon_key) =
            decrypt_with_call_key_from_vault(&vault, "prod", prod_passphrase, Some(prod_identity))
                .unwrap();
        let client_key = derive_profile_call_key_from_vault(
            &vault,
            "prod",
            prod_passphrase,
            Some(prod_identity),
        )
        .unwrap();
        let stage_key = derive_profile_call_key_from_vault(
            &vault,
            "stage",
            stage_passphrase,
            Some(stage_identity),
        )
        .unwrap();

        assert_eq!(creds.password, sample_creds().password);
        assert_eq!(daemon_key.as_bytes(), client_key.as_bytes());
        assert_ne!(daemon_key.as_bytes(), stage_key.as_bytes());
        assert!(derive_profile_call_key_from_vault(
            &vault,
            "prod",
            stage_passphrase,
            Some(prod_identity),
        )
        .is_err());
        assert!(derive_profile_call_key_from_vault(
            &vault,
            "prod",
            prod_passphrase,
            Some(ProfileIdentity {
                profile_id: prod_identity.profile_id,
                generation: 2,
            }),
        )
        .is_err());
        assert!(derive_profile_call_key_from_vault(
            &vault,
            "prod",
            prod_passphrase,
            Some(ProfileIdentity {
                profile_id: [99_u8; 16],
                generation: 1,
            }),
        )
        .is_err());
        assert!(
            derive_profile_call_key_from_vault(&vault, "missing", prod_passphrase, None,).is_err()
        );

        let legacy = modern_test_vault("legacy-shared-master-passphrase");
        let error = decrypt_with_call_key_from_vault(
            &legacy,
            "prod",
            "legacy-shared-master-passphrase",
            None,
        )
        .err()
        .expect("v2 call-key derivation must require explicit migration");
        assert!(error.to_string().contains("explicit v2-to-v4 migration"));
        assert!(derive_profile_call_key_from_vault(
            &legacy,
            "prod",
            "legacy-shared-master-passphrase",
            None,
        )
        .is_err());
    }

    #[test]
    fn authenticated_remove_verifies_master_target_and_absence() {
        let master = "test-master-passphrase";
        let mut vault = modern_test_vault(master);

        assert!(remove_with_master_from_vault(&mut vault, "prod", "wrong-master").is_err());
        assert!(vault.profiles.contains_key("prod"));
        assert!(remove_with_master_from_vault(&mut vault, "prod", master).unwrap());
        assert!(!vault.profiles.contains_key("prod"));
        assert!(!remove_with_master_from_vault(&mut vault, "missing", master).unwrap());
        assert!(remove_with_master_from_vault(&mut vault, "missing", "wrong-master").is_err());

        let stage = vault.profiles.get_mut("stage").unwrap();
        let mut ciphertext = B64.decode(&stage.ct).unwrap();
        ciphertext[0] ^= 1;
        stage.ct = B64.encode(ciphertext);
        assert!(remove_with_master_from_vault(&mut vault, "stage", master).is_err());
        assert!(vault.profiles.contains_key("stage"));
    }

    #[test]
    fn authenticated_list_requires_the_established_vault_master() {
        let master = "test-master-passphrase";
        let rows = list_with_master_from_vault(modern_test_vault(master), master)
            .expect("correct master must authorize profile metadata");
        assert_eq!(
            rows,
            vec![
                ("prod".into(), "server.example".into(), 2222),
                ("stage".into(), "stage.example".into(), 2222),
            ]
        );

        let wrong =
            list_with_master_from_vault(modern_test_vault(master), "wrong-master-passphrase")
                .expect_err("wrong master must not reveal profile metadata");
        assert!(wrong.to_string().contains("wrong master passphrase"));

        let empty = list_with_master_from_vault(VaultFile::default(), master)
            .expect("a policy-compliant master may authorize an empty vault");
        assert!(empty.is_empty());
        let weak_empty = list_with_master_from_vault(VaultFile::default(), "short")
            .expect_err("an empty vault must enforce the first-master policy");
        assert!(weak_empty.to_string().contains("at least 12 bytes"));
    }

    #[test]
    fn batch_profile_authorization_uses_one_vault_key_and_authenticates_all_records() {
        let master = "test-master-passphrase";
        let vault = modern_test_vault(master);
        let profiles = list_with_profile_call_keys_from_vault(&vault, master).unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].name, "prod");
        assert_eq!(profiles[0].host, "server.example");
        assert_eq!(profiles[0].port, 2222);
        assert_eq!(profiles[1].name, "stage");
        assert_eq!(profiles[1].host, "stage.example");

        let encryption_key = vault_key(&vault, master).unwrap();
        let prod_key = profile_call_key(&encryption_key, "prod").unwrap();
        assert_eq!(profiles[0].call_key.as_bytes(), prod_key.as_bytes());
        assert_ne!(
            profiles[0].call_key.as_bytes(),
            profiles[1].call_key.as_bytes()
        );
        assert!(list_with_profile_call_keys_from_vault(&vault, "wrong-master-passphrase").is_err());
    }

    #[test]
    fn batch_profile_authorization_is_all_or_nothing_for_legacy_or_tampered_records() {
        let master = "test-master-passphrase";
        let mut tampered = modern_test_vault(master);
        let stage = tampered.profiles.get_mut("stage").unwrap();
        let mut ciphertext = B64.decode(&stage.ct).unwrap();
        ciphertext[0] ^= 1;
        stage.ct = B64.encode(ciphertext);
        let error = list_with_profile_call_keys_from_vault(&tampered, master)
            .err()
            .expect("one tampered record must abort the entire batch");
        assert!(error
            .to_string()
            .contains("authenticate profile 'stage' for status refresh"));

        let mut legacy = modern_test_vault(master);
        let key = vault_key(&legacy, master).unwrap();
        legacy
            .profiles
            .insert("legacy".into(), legacy_profile(&key));
        let legacy_error = list_with_profile_call_keys_from_vault(&legacy, master)
            .err()
            .expect("legacy metadata must not be returned by batch authorization");
        assert!(format!("{legacy_error:#}").contains("legacy profile"));

        let empty = list_with_profile_call_keys_from_vault(
            &VaultFile::default(),
            "prospective-master-passphrase",
        )
        .unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn rekey_authenticates_every_profile_and_builds_one_complete_replacement() {
        let old_master = "test-master-passphrase";
        let new_master = "replacement-master-passphrase";
        let vault = modern_test_vault(old_master);
        let old_salt = vault.salt.clone();

        let replacement = build_rekeyed_vault(&vault, old_master, new_master)
            .expect("all modern profiles should rotate together");

        assert_eq!(replacement.version, LEGACY_VAULT_FORMAT);
        assert_ne!(replacement.salt, old_salt);
        let kdf = replacement.kdf.as_ref().expect("new KDF configuration");
        let defaults = KdfConfig::default();
        assert_eq!(kdf.memory_kib, defaults.memory_kib);
        assert_eq!(kdf.iterations, defaults.iterations);
        assert_eq!(kdf.parallelism, defaults.parallelism);
        assert_eq!(kdf.output_bytes, defaults.output_bytes);
        assert_eq!(replacement.profiles.len(), vault.profiles.len());

        verify_master_passphrase_from_vault(&replacement, new_master)
            .expect("new master must authenticate the replacement");
        assert!(verify_master_passphrase_from_vault(&replacement, old_master).is_err());
        let new_key = vault_key(&replacement, new_master).unwrap();
        let prod =
            decrypt_profile_with_key("prod", replacement.profiles.get("prod").unwrap(), &new_key)
                .unwrap();
        assert_eq!(prod.host, sample_creds().host);
        assert_eq!(prod.password, sample_creds().password);
        assert_eq!(prod.host_key, sample_creds().host_key);
    }

    #[test]
    fn rekey_failure_never_mutates_the_source_vault() {
        let old_master = "test-master-passphrase";
        let mut vault = modern_test_vault(old_master);
        let stage = vault.profiles.get_mut("stage").unwrap();
        let mut ciphertext = B64.decode(&stage.ct).unwrap();
        ciphertext[0] ^= 1;
        stage.ct = B64.encode(ciphertext);
        let before = serde_json::to_vec(&vault).unwrap();

        let tampered = build_rekeyed_vault(&vault, old_master, "replacement-master-passphrase")
            .err()
            .expect("one tampered profile must abort the entire rotation");
        assert!(tampered
            .to_string()
            .contains("authenticate profile 'stage'"));
        assert_eq!(serde_json::to_vec(&vault).unwrap(), before);

        let wrong = build_rekeyed_vault(
            &vault,
            "wrong-master-passphrase",
            "replacement-master-passphrase",
        )
        .err()
        .expect("the old master must be verified");
        assert!(wrong.to_string().contains("wrong master passphrase"));
        assert_eq!(serde_json::to_vec(&vault).unwrap(), before);
    }

    #[test]
    fn rekey_rejects_legacy_records_weak_new_secrets_and_unestablished_vaults() {
        let old_master = "test-master-passphrase";
        let mut legacy = modern_test_vault(old_master);
        let old_key = vault_key(&legacy, old_master).unwrap();
        legacy
            .profiles
            .insert("legacy".into(), legacy_profile(&old_key));
        let error = build_rekeyed_vault(&legacy, old_master, "replacement-master-passphrase")
            .err()
            .expect("legacy endpoint metadata must never be blessed by rekey");
        assert!(format!("{error:#}").contains("legacy profile"));

        let modern = modern_test_vault(old_master);
        let weak = build_rekeyed_vault(&modern, old_master, "too-short")
            .err()
            .expect("a rotated master must satisfy the new-vault policy");
        assert!(weak.to_string().contains("at least 12 bytes"));

        let empty = build_rekeyed_vault(
            &VaultFile::default(),
            old_master,
            "replacement-master-passphrase",
        )
        .err()
        .expect("an empty unestablished vault has no old master to verify");
        assert!(empty.to_string().contains("no established master"));
    }

    #[test]
    fn empty_vault_authorization_enforces_first_master_policy_and_nothing_else() {
        let master = "test-master-passphrase";
        verify_master_passphrase_from_vault(&VaultFile::default(), master)
            .expect("a strong prospective first master must authorize empty-vault setup");
        let weak = verify_master_passphrase_from_vault(&VaultFile::default(), "short")
            .expect_err("empty-vault authorization must enforce new-master strength");
        assert!(weak.to_string().contains("at least 12 bytes"));

        let mut not_empty = VaultFile::default();
        not_empty
            .profiles
            .insert("legacy".into(), legacy_profile(&[7_u8; 32]));
        assert!(verify_master_passphrase_from_vault(&not_empty, master).is_err());
    }

    #[test]
    fn unsafe_profile_names_are_rejected() {
        for name in ["", ".", "..", "../escape", r"..\escape", "C:drive"] {
            assert!(validate_profile_name(name).is_err(), "accepted {name:?}");
        }
        assert!(validate_profile_name("生产-01_test").is_ok());
    }

    #[test]
    fn nonce_length_is_checked_without_panicking() {
        assert!(decode_nonce(&B64.encode([1_u8; 11])).is_err());
        assert!(decode_nonce(&B64.encode([1_u8; 12])).is_ok());
    }

    #[test]
    fn lock_paths_cannot_contain_profile_text() {
        let filename = lock_filename("../../escape");
        assert!(!filename.contains('/'));
        assert!(!filename.contains('\\'));
        assert!(!filename.contains("escape"));
    }

    #[test]
    fn opened_lock_handle_is_stable_when_path_is_replaced() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "serctl-lock-handle-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("runtime.lock");
        let retired = directory.join("runtime.lock.retired");
        let original = br#"{"profile":"old"}"#;
        let replacement = br#"{"profile":"new"}"#;
        std::fs::write(&path, original).unwrap();

        let mut file = security::open_existing_protected_file(&path)
            .unwrap()
            .unwrap();
        let metadata_len = file.metadata().unwrap().len();
        std::fs::rename(&path, &retired).unwrap();
        std::fs::write(&path, replacement).unwrap();

        let bytes = read_lock_handle_after_metadata(&mut file, metadata_len).unwrap();
        assert_eq!(bytes.as_slice(), original);

        drop(file);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn lock_reader_enforces_limit_after_metadata_check() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "serctl-lock-growth-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("runtime.lock");
        std::fs::write(&path, b"{}").unwrap();

        let mut file = File::open(&path).unwrap();
        let metadata_len = file.metadata().unwrap().len();
        std::fs::write(&path, vec![b'x'; (MAX_LOCK_BYTES + 1) as usize]).unwrap();

        let error = read_lock_handle_after_metadata(&mut file, metadata_len).unwrap_err();
        assert!(error.to_string().contains("64 KiB"));

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn lock_reader_preallocates_the_full_limit_before_a_growing_read() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "serctl-lock-no-reallocation-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("runtime.lock");
        std::fs::write(&path, b"{}").unwrap();

        let mut file = File::open(&path).unwrap();
        let metadata_len = file.metadata().unwrap().len();
        let grown_len = (MAX_LOCK_BYTES / 2) as usize;
        std::fs::write(&path, vec![b'x'; grown_len]).unwrap();

        let bytes = read_lock_handle_after_metadata(&mut file, metadata_len).unwrap();
        assert_eq!(bytes.len(), grown_len);
        assert!(bytes.capacity() >= (MAX_LOCK_BYTES + 1) as usize);

        drop((bytes, file));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn bounded_reader_rechecks_growth_after_metadata() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "serctl-bounded-reader-{}-{unique}",
            std::process::id()
        ));
        std::fs::write(&path, b"ok").unwrap();
        let mut file = File::open(&path).unwrap();
        let metadata_len = file.metadata().unwrap().len();
        std::fs::write(&path, b"too-large").unwrap();

        let error = read_bounded_handle(
            &mut file,
            metadata_len,
            4,
            BoundedReadAllocation::MetadataLength,
            "limit reached",
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "limit reached");

        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn sensitive_json_is_sized_before_the_zeroizing_buffer_is_written() {
        let secret = Secret {
            user: "operator".into(),
            password: "secret\0with\njson escapes".into(),
            host_key: Some("SHA256:test".into()),
        };
        let serialized =
            serialize_json_zeroizing(&secret, 16 * 1024, JsonStyle::Compact, "test JSON limit")
                .unwrap();
        assert!(serialized.capacity() >= serialized.len());
        let decoded: Secret = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(decoded.password, secret.password);

        let oversized = Secret {
            user: secret.user.clone(),
            password: "\0".repeat(1024),
            host_key: secret.host_key.clone(),
        };
        let error = serialize_json_zeroizing(&oversized, 64, JsonStyle::Compact, "test JSON limit")
            .unwrap_err();
        assert_eq!(error.to_string(), "test JSON limit");
    }

    #[test]
    fn vault_file_lock_wait_is_bounded() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "serctl-vault-lock-timeout-{}-{unique}",
            std::process::id()
        ));
        let owner = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let contender = File::options().read(true).write(true).open(&path).unwrap();
        lock_vault_with_timeout(&owner, VaultLockMode::Exclusive, Duration::from_millis(20))
            .unwrap();

        let error =
            lock_vault_with_timeout(&contender, VaultLockMode::Shared, Duration::from_millis(20))
                .unwrap_err();
        assert!(error.to_string().contains("timed out"));

        FileExt::unlock(&owner).unwrap();
        lock_vault_with_timeout(&contender, VaultLockMode::Shared, Duration::from_millis(20))
            .unwrap();
        FileExt::unlock(&contender).unwrap();
        drop((owner, contender));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomic_secret_file_is_durably_committed_with_protection() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("atomic-secret-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        security::harden_directory(&directory).unwrap();
        let path = directory.join("vault.json");
        security::write_protected_atomic(&path, b"{}").unwrap();

        let committed = security::open_existing_protected_file(&path)
            .unwrap()
            .unwrap();
        assert_eq!(committed.metadata().unwrap().len(), 2);
        drop(committed);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn legacy_tcp_lock_remains_detectable() {
        let lock: LockInfo = serde_json::from_str(
            r#"{"profile":"prod","pid":7,"port":4321,"host":"","user":"","started_unix":1,"token":""}"#,
        )
        .unwrap();
        assert_eq!(lock.protocol, 0);
        assert_eq!(lock.port, 4321);
        assert!(lock.endpoint.is_empty());
    }

    #[test]
    fn runtime_lock_protocol_and_capability_fail_closed() {
        let secret_token = "must-never-appear-in-a-runtime-lock-error";
        let mut lock = LockInfo {
            profile: "prod".into(),
            protocol: 0,
            pid: 7,
            port: 0,
            endpoint: String::new(),
            host: String::new(),
            user: String::new(),
            started_unix: 1,
            token: secret_token.into(),
        };
        let legacy = validate_runtime_lock_info("prod", &lock).unwrap_err();
        assert!(legacy.to_string().contains("bearer-token IPC"));
        assert!(!legacy.to_string().contains(secret_token));

        lock.protocol = 3;
        let old_v3 = validate_runtime_lock_info("prod", &lock).unwrap_err();
        assert!(old_v3
            .to_string()
            .contains("unsupported runtime lock IPC protocol 3"));
        assert!(!old_v3.to_string().contains(secret_token));

        lock.protocol = crate::ipc::IPC_PROTOCOL_VERSION + 1;
        let unknown = validate_runtime_lock_info("prod", &lock).unwrap_err();
        assert!(unknown.to_string().contains("unsupported runtime lock"));
        assert!(!unknown.to_string().contains(secret_token));

        lock.protocol = crate::ipc::IPC_PROTOCOL_VERSION;
        lock.endpoint = "not-the-derived-endpoint".into();
        lock.token = "not-base64".into();
        let invalid = validate_runtime_lock_info("prod", &lock).unwrap_err();
        assert!(invalid.to_string().contains("capability"));
    }

    #[test]
    fn malformed_hashed_lock_cleanup_classification_is_v5_only() {
        let runtime_dir = std::env::temp_dir();
        let token = new_ipc_token();
        let endpoint =
            crate::ipc::expected_endpoint_in_runtime_dir("prod", &token, &runtime_dir).unwrap();
        let mut lock = LockInfo {
            profile: "prod".into(),
            protocol: crate::ipc::IPC_PROTOCOL_VERSION,
            pid: 7,
            port: 0,
            endpoint,
            host: String::new(),
            user: String::new(),
            started_unix: 1,
            token,
        };
        let valid = serde_json::to_vec(&lock).unwrap();
        assert!(!hashed_v5_lock_is_invalid("prod", &valid, &runtime_dir).unwrap());
        assert!(hashed_v5_lock_is_invalid("prod", b"{broken", &runtime_dir).unwrap());

        lock.pid = 0;
        let invalid_v5 = serde_json::to_vec(&lock).unwrap();
        assert!(hashed_v5_lock_is_invalid("prod", &invalid_v5, &runtime_dir).unwrap());

        lock.protocol = 4;
        let old_v4 = serde_json::to_vec(&lock).unwrap();
        assert!(hashed_v5_lock_is_invalid("prod", &old_v4, &runtime_dir).is_err());

        lock.protocol = crate::ipc::IPC_PROTOCOL_VERSION + 1;
        let future = serde_json::to_vec(&lock).unwrap();
        assert!(hashed_v5_lock_is_invalid("prod", &future, &runtime_dir).is_err());
    }

    #[test]
    fn stale_lock_cleanup_never_runs_without_the_exclusive_lease() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "runtime-cleanup-lease-{}-{unique}",
                std::process::id()
            ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("profile.lease");
        let owner = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        owner.try_lock_exclusive().unwrap();
        let contender = File::options().read(true).write(true).open(&path).unwrap();

        let cleanup_called = std::cell::Cell::new(false);
        assert!(!with_exclusive_runtime_cleanup(&contender, || {
            cleanup_called.set(true);
            Ok(true)
        })
        .unwrap());
        assert!(!cleanup_called.get());

        drop(owner);
        assert!(with_exclusive_runtime_cleanup(&contender, || {
            cleanup_called.set(true);
            Ok(true)
        })
        .unwrap());
        assert!(cleanup_called.get());

        drop(contender);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn runtime_lock_reconciliation_keeps_all_lease_outcomes_distinct() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "runtime-reconcile-lease-{}-{unique}",
                std::process::id()
            ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("profile.lease");
        let owner = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        owner.try_lock_exclusive().unwrap();
        let contender = File::options().read(true).write(true).open(&path).unwrap();

        let reconciliation_called = std::cell::Cell::new(false);
        assert_eq!(
            reconcile_under_exclusive_runtime_lease(&contender, || {
                reconciliation_called.set(true);
                Ok(LockReconcileOutcome::Absent)
            })
            .unwrap(),
            LockReconcileOutcome::Contended
        );
        assert!(!reconciliation_called.get());

        drop(owner);
        for expected in [
            LockReconcileOutcome::Absent,
            LockReconcileOutcome::Changed,
            LockReconcileOutcome::Removed,
        ] {
            assert_eq!(
                reconcile_under_exclusive_runtime_lease(&contender, || Ok(expected)).unwrap(),
                expected
            );
            FileExt::unlock(&contender).unwrap();
        }

        drop(contender);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn runtime_lease_liveness_probe_distinguishes_held_and_released() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "serctl-runtime-liveness-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("runtime.lease");
        let owner = File::create(&path).unwrap();
        let contender = File::open(&path).unwrap();
        owner.try_lock_exclusive().unwrap();

        assert_eq!(
            probe_runtime_lease_liveness_with(
                || FileExt::try_lock_shared(&contender),
                || FileExt::unlock(&contender),
            )
            .unwrap(),
            RuntimeLeaseLiveness::Held
        );
        FileExt::unlock(&owner).unwrap();
        assert_eq!(
            probe_runtime_lease_liveness_with(
                || FileExt::try_lock_shared(&contender),
                || FileExt::unlock(&contender),
            )
            .unwrap(),
            RuntimeLeaseLiveness::Released
        );

        drop((owner, contender));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn runtime_lease_liveness_probe_fails_closed_on_io_errors() {
        let probe_error = probe_runtime_lease_liveness_with(
            || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            || Ok(()),
        )
        .unwrap_err();
        assert!(probe_error
            .to_string()
            .contains("probe daemon runtime lease liveness"));

        let unlock_error = probe_runtime_lease_liveness_with(
            || Ok(()),
            || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        )
        .unwrap_err();
        assert!(unlock_error
            .to_string()
            .contains("release daemon runtime-lease liveness probe"));
    }

    #[test]
    fn mutation_lease_reports_contention_without_mislabeling_open_errors() {
        let contention = acquire_profile_mutation_lease_with(
            "busy",
            || Ok(()),
            |_| Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        )
        .unwrap_err();
        assert!(contention
            .to_string()
            .contains("while it is in use by a direct operation or daemon"));

        let open_error = acquire_profile_mutation_lease_with::<()>(
            "unreadable",
            || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into()),
            |_| Ok(()),
        )
        .unwrap_err();
        let open_chain = format!("{open_error:#}");
        assert!(open_chain.contains("open mutation lease for profile 'unreadable'"));
        assert!(!open_chain.contains("while it is in use"));
    }

    #[test]
    fn v2_profile_encrypts_host_key_and_authenticates_metadata() {
        let key = [7_u8; 32];
        let encrypted = encrypt_profile("prod", &sample_creds(), &key).unwrap();
        let serialized = serde_json::to_string(&encrypted).unwrap();
        assert!(!serialized.contains("server-fingerprint"));

        let decrypted = decrypt_profile_with_key("prod", &encrypted, &key).unwrap();
        assert_eq!(decrypted.user, "deploy");
        assert_eq!(decrypted.password, "correct horse battery staple");
        assert_eq!(
            decrypted.host_key.as_deref(),
            Some("SHA256:server-fingerprint")
        );

        let mut changed_host = encrypted.clone();
        changed_host.host = "attacker.example".into();
        assert!(decrypt_profile_with_key("prod", &changed_host, &key).is_err());
        assert!(decrypt_profile_with_key("renamed", &encrypted, &key).is_err());
    }

    #[test]
    fn wrong_key_and_tampered_verifier_are_rejected() {
        let key = [11_u8; 32];
        let mut vault = VaultFile::default();
        ensure_verifier(&mut vault, &key).unwrap();
        assert!(verify_master(&vault, &[12_u8; 32]).is_err());

        let verifier = vault.verifier.as_mut().unwrap();
        let mut ciphertext = B64.decode(&verifier.ct).unwrap();
        ciphertext[0] ^= 1;
        verifier.ct = B64.encode(ciphertext);
        assert!(verify_master(&vault, &key).is_err());
    }

    #[test]
    fn legacy_profile_is_rejected_before_any_credentials_are_returned() {
        let key = [19_u8; 32];
        let encrypted = legacy_profile(&key);

        // Raw access is restricted to master verification for an explicit
        // offline replacement and must not be called from network paths.
        let offline = decrypt_profile_payload_with_key("legacy", &encrypted, &key).unwrap();
        assert_eq!(offline.user, "legacy-user");

        let mut variants = Vec::new();
        let mut changed_host = encrypted.clone();
        changed_host.host = "attacker.example".into();
        variants.push(changed_host);
        let mut changed_port = encrypted.clone();
        changed_port.port = 2200;
        variants.push(changed_port);
        let mut changed_pin = encrypted.clone();
        changed_pin.host_key = Some("SHA256:attacker".into());
        variants.push(changed_pin);
        let mut malformed_body = encrypted;
        malformed_body.nonce = "not-base64".into();
        malformed_body.ct = "not-base64".into();
        variants.push(malformed_body);

        for variant in variants {
            let error = match decrypt_profile_with_key("legacy", &variant, &key) {
                Err(error) => error,
                Ok(_) => panic!("legacy credentials escaped the network-use guard"),
            };
            let message = error.to_string();
            assert!(message.contains("legacy profile"), "{message}");
            assert!(message.contains("delete and recreate"), "{message}");
        }
    }

    #[test]
    fn legacy_host_pin_is_not_inherited_but_an_explicit_replacement_pin_is_allowed() {
        let key = [29_u8; 32];
        let encrypted = legacy_profile(&key);
        let mut unpinned_replacement = sample_creds();
        unpinned_replacement.host_key = None;
        assert_eq!(
            authenticated_pin_for_replacement("legacy", &encrypted, &key, &unpinned_replacement,)
                .unwrap(),
            None
        );

        let mut vault = VaultFile::default();
        vault.profiles.insert("legacy".into(), encrypted.clone());
        let pin = rename_profile_in_vault(
            &mut vault,
            "legacy",
            "replacement",
            &unpinned_replacement,
            &key,
        )
        .unwrap();
        assert_eq!(pin, None);
        let replacement = vault.profiles.get("replacement").unwrap();
        let decrypted = decrypt_profile_with_key("replacement", replacement, &key).unwrap();
        assert_eq!(decrypted.host_key, None);

        let mut explicitly_pinned = sample_creds();
        explicitly_pinned.host_key = Some("SHA256:new-explicit-pin".into());
        assert_eq!(
            authenticated_pin_for_replacement("legacy", &encrypted, &key, &explicitly_pinned,)
                .unwrap(),
            explicitly_pinned.host_key
        );
    }

    #[test]
    fn offline_replacement_rejects_a_v2_record_downgraded_to_legacy() {
        let key = [30_u8; 32];
        let mut downgraded = encrypt_profile("prod", &sample_creds(), &key).unwrap();
        downgraded.format = 0;

        let error = authenticated_pin_for_replacement("prod", &downgraded, &key, &sample_creds())
            .unwrap_err();

        assert!(error.to_string().contains("decrypt failed"));
    }

    #[test]
    fn unsupported_vault_and_record_versions_are_rejected() {
        let mut vault = VaultFile {
            version: VAULT_FORMAT + 1,
            ..VaultFile::default()
        };
        assert!(validate_loaded_vault(&vault).is_err());

        vault.version = VAULT_FORMAT;
        let key = [31_u8; 32];
        let mut encrypted = encrypt_profile("prod", &sample_creds(), &key).unwrap();
        encrypted.format = PROFILE_FORMAT_AAD + 1;
        vault.profiles.insert("prod".into(), encrypted);
        assert!(validate_loaded_vault(&vault).is_err());
    }

    #[test]
    fn loaded_vault_revalidates_names_endpoints_and_control_characters() {
        let key = [32_u8; 32];
        let encrypted = encrypt_profile("prod", &sample_creds(), &key).unwrap();
        let mut vault = VaultFile::default();
        vault.profiles.insert("../escape".into(), encrypted.clone());
        assert!(validate_loaded_vault(&vault).is_err());

        vault.profiles.clear();
        let mut unsafe_host = encrypted;
        unsafe_host.host = "server.example\nterminal-injection".into();
        vault.profiles.insert("prod".into(), unsafe_host);
        assert!(validate_loaded_vault(&vault).is_err());
    }

    #[test]
    fn profile_limit_accepts_exact_capacity_but_never_a_new_record_beyond_it() {
        let key = [41_u8; 32];
        let encrypted = encrypt_profile("template", &sample_creds(), &key).unwrap();
        let mut vault = VaultFile {
            version: LEGACY_VAULT_FORMAT,
            ..VaultFile::default()
        };
        for index in 0..MAX_PROFILES {
            vault
                .profiles
                .insert(format!("profile-{index:05}"), encrypted.clone());
        }

        validate_loaded_vault(&vault).expect("the exact documented profile limit is valid");
        enforce_profile_capacity_for_upsert(&vault, "profile-00000")
            .expect("an existing profile may still be updated at the limit");
        let overflow = enforce_profile_capacity_for_upsert(&vault, "overflow")
            .expect_err("a new profile beyond the limit must be rejected before save");
        assert!(overflow.to_string().contains("10000"));

        vault.profiles.insert("overflow".into(), encrypted);
        assert!(validate_loaded_vault(&vault)
            .unwrap_err()
            .to_string()
            .contains("too many profiles"));
        vault.profiles.remove("overflow");
        vault.profiles.remove("profile-09999");
        enforce_profile_capacity_for_upsert(&vault, "replacement")
            .expect("one free slot must accept one new profile");
    }

    #[test]
    fn decrypted_user_control_characters_are_rejected() {
        let key = [33_u8; 32];
        let mut creds = sample_creds();
        creds.user = "deploy\nspoof".into();
        let encrypted = encrypt_profile("prod", &creds, &key).unwrap();
        assert!(decrypt_profile_with_key("prod", &encrypted, &key).is_err());
    }

    #[test]
    fn new_vault_requires_a_reasonable_master_but_existing_vaults_remain_compatible() {
        let mut vault = VaultFile::default();
        assert!(enforce_new_vault_master_policy(&vault, "short").is_err());
        assert!(enforce_new_vault_master_policy(&vault, "twelve-bytes!").is_ok());

        vault.verifier = Some(SealedVerifier {
            nonce: String::new(),
            ct: String::new(),
        });
        assert!(enforce_new_vault_master_policy(&vault, "old").is_ok());
    }

    #[test]
    fn concurrent_host_pin_cannot_be_replaced() {
        let mut creds = sample_creds();
        assert!(!apply_host_pin(&mut creds, "SHA256:server-fingerprint".into()).unwrap());
        assert!(apply_host_pin(&mut creds, "SHA256:attacker".into()).is_err());
        assert_eq!(creds.host_key.as_deref(), Some("SHA256:server-fingerprint"));
    }

    #[test]
    fn explicit_host_pin_requires_a_safe_sha256_value() {
        let mut creds = sample_creds();
        for invalid in [
            "",
            "MD5:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            " SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "SHA256:not-a-complete-digest",
        ] {
            creds.host_key = Some(invalid.into());
            assert!(validate_profile_update("prod", &creds, "existing-master").is_err());
        }
        creds.host_key = Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        validate_profile_update("prod", &creds, "existing-master").unwrap();
    }

    #[test]
    fn new_or_unpinned_profile_accepts_an_explicit_host_pin() {
        let key = [36_u8; 32];
        let requested = sample_creds();
        assert_eq!(
            selected_pin_for_update("new", None, &key, &requested).unwrap(),
            requested.host_key
        );

        let mut unpinned = sample_creds();
        unpinned.host_key = None;
        let encrypted = encrypt_profile("prod", &unpinned, &key).unwrap();
        assert_eq!(
            selected_pin_for_update("prod", Some(&encrypted), &key, &requested).unwrap(),
            requested.host_key
        );
    }

    #[test]
    fn updating_or_renaming_across_endpoint_uses_only_an_explicit_new_pin() {
        let key = [37_u8; 32];
        let mut vault = VaultFile::default();
        let original = encrypt_profile("old-name", &sample_creds(), &key).unwrap();
        vault.profiles.insert("old-name".into(), original.clone());
        let updated = Creds {
            host: "new-server.example".into(),
            port: 2200,
            user: "operator".into(),
            password: "updated-password".into(),
            host_key: Some("SHA256:untrusted-replacement".into()),
        };

        // add_or_update and rename both use this endpoint-bound decision.
        assert_eq!(
            authenticated_pin_for_replacement("old-name", &original, &key, &updated).unwrap(),
            updated.host_key
        );

        let pin =
            rename_profile_in_vault(&mut vault, "old-name", "new-name", &updated, &key).unwrap();

        assert_eq!(pin.as_deref(), Some("SHA256:untrusted-replacement"));
        let encrypted = vault.profiles.get("new-name").unwrap();
        let decrypted = decrypt_profile_with_key("new-name", encrypted, &key).unwrap();
        assert_eq!(decrypted.host, "new-server.example");
        assert_eq!(decrypted.port, 2200);
        assert_eq!(decrypted.user, "operator");
        assert_eq!(decrypted.password, "updated-password");
        assert_eq!(decrypted.host_key, pin);
        assert!(decrypt_profile_with_key("old-name", encrypted, &key).is_err());

        let mut changed_again = decrypted;
        changed_again.host = "third-server.example".into();
        changed_again.host_key = None;
        assert_eq!(
            authenticated_pin_for_replacement("new-name", encrypted, &key, &changed_again).unwrap(),
            None
        );
    }

    #[test]
    fn same_endpoint_pin_is_preserved_or_must_match_exactly() {
        let key = [39_u8; 32];
        let mut vault = VaultFile::default();
        vault.profiles.insert(
            "old-name".into(),
            encrypt_profile("old-name", &sample_creds(), &key).unwrap(),
        );
        let mut updated = sample_creds();
        updated.user = "operator".into();
        updated.password = "updated-password".into();
        updated.host_key = None;

        let pin =
            rename_profile_in_vault(&mut vault, "old-name", "new-name", &updated, &key).unwrap();

        assert_eq!(pin.as_deref(), Some("SHA256:server-fingerprint"));
        let decrypted =
            decrypt_profile_with_key("new-name", vault.profiles.get("new-name").unwrap(), &key)
                .unwrap();
        assert_eq!(
            decrypted.host_key.as_deref(),
            Some("SHA256:server-fingerprint")
        );

        let mut matching = decrypted.clone();
        matching.host_key = Some("SHA256:server-fingerprint".into());
        assert_eq!(
            authenticated_pin_for_replacement(
                "new-name",
                vault.profiles.get("new-name").unwrap(),
                &key,
                &matching,
            )
            .unwrap()
            .as_deref(),
            Some("SHA256:server-fingerprint")
        );

        matching.host_key = Some("SHA256:different-host-key".into());
        assert!(authenticated_pin_for_replacement(
            "new-name",
            vault.profiles.get("new-name").unwrap(),
            &key,
            &matching,
        )
        .is_err());
    }

    #[test]
    fn renaming_profile_rejects_destination_conflict_without_mutation() {
        let key = [41_u8; 32];
        let mut vault = VaultFile::default();
        vault.profiles.insert(
            "source".into(),
            encrypt_profile("source", &sample_creds(), &key).unwrap(),
        );
        let mut destination_creds = sample_creds();
        destination_creds.host = "destination.example".into();
        vault.profiles.insert(
            "destination".into(),
            encrypt_profile("destination", &destination_creds, &key).unwrap(),
        );
        let before = serde_json::to_vec(&vault).unwrap();

        let error =
            rename_profile_in_vault(&mut vault, "source", "destination", &sample_creds(), &key)
                .unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(serde_json::to_vec(&vault).unwrap(), before);
    }

    #[test]
    fn renaming_profile_replaces_only_the_source_record() {
        let key = [43_u8; 32];
        let mut vault = VaultFile::default();
        vault.profiles.insert(
            "source".into(),
            encrypt_profile("source", &sample_creds(), &key).unwrap(),
        );
        let mut untouched_creds = sample_creds();
        untouched_creds.host = "untouched.example".into();
        let untouched = encrypt_profile("untouched", &untouched_creds, &key).unwrap();
        vault.profiles.insert("untouched".into(), untouched.clone());

        rename_profile_in_vault(&mut vault, "source", "destination", &sample_creds(), &key)
            .unwrap();

        assert_eq!(vault.profiles.len(), 2);
        assert!(!vault.profiles.contains_key("source"));
        assert!(vault.profiles.contains_key("destination"));
        assert_eq!(
            serde_json::to_vec(vault.profiles.get("untouched").unwrap()).unwrap(),
            serde_json::to_vec(&untouched).unwrap()
        );
    }
}
