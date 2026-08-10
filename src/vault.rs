//! Encrypted credential vault + protected runtime lock files.
//!
//! Version 2 binds every secret to its profile name and endpoint with AEAD
//! associated data. Legacy records can be replaced after offline master-key
//! verification, but are never returned for SSH/network use because their
//! endpoint and host-key metadata was not authenticated.

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Block as Argon2Block, Params, Version};
use atomic_write_file::AtomicWriteFile;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use fs2::FileExt;
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

const VAULT_FORMAT: u32 = 2;
const PROFILE_FORMAT_AAD: u8 = 2;
const VERIFIER_TEXT: &[u8] = b"serctl-vault-verifier-v2";
const VERIFIER_AAD: &[u8] = b"serctl/vault/verifier/v2";
const MAX_VAULT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOCK_BYTES: u64 = 64 * 1024;
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
    pub profiles: BTreeMap<String, EncProfile>,
}

impl Default for VaultFile {
    fn default() -> Self {
        Self {
            version: VAULT_FORMAT,
            salt: String::new(),
            kdf: Some(KdfConfig::default()),
            verifier: None,
            profiles: BTreeMap::new(),
        }
    }
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
    #[cfg(windows)]
    if let Some(p) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(p));
    }
    bail!("cannot determine home directory")
}

#[cfg(test)]
pub(crate) fn set_test_home(path: Option<PathBuf>) {
    *TEST_HOME.write().expect("test home lock poisoned") = path;
}

pub fn dir() -> Result<PathBuf> {
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

fn open_runtime_lease_file(profile: &str) -> Result<File> {
    let path = runtime_lease_path(profile)?;
    security::open_or_create_protected_file(&path)
        .with_context(|| format!("open runtime lease {}", path.display()))
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
pub fn acquire_runtime_lease(profile: &str) -> Result<File> {
    let file = open_runtime_lease_file(profile)?;
    match file.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if is_lock_contention(&error) => {
            bail!("a daemon is already starting or running for '{profile}'");
        }
        Err(error) => return Err(error).context("acquire daemon runtime lease"),
    }
    Ok(file)
}

/// Hold a shared lease while a direct (non-daemon) operation is using a
/// profile snapshot. Multiple direct operations may coexist, but daemon
/// startup and credential mutation require the exclusive form above.
pub fn acquire_profile_use_lease(profile: &str) -> Result<File> {
    let file = open_runtime_lease_file(profile)?;
    match FileExt::try_lock_shared(&file) {
        Ok(()) => {}
        Err(error) if is_lock_contention(&error) => {
            bail!("profile '{profile}' is being changed or used by a daemon");
        }
        Err(error) => return Err(error).context("acquire direct profile-use lease"),
    }
    Ok(file)
}

fn acquire_profile_mutation_lease(profile: &str) -> Result<File> {
    acquire_runtime_lease(profile).with_context(|| {
        format!(
            "cannot modify profile '{profile}' while it is in use by a direct operation or daemon"
        )
    })
}

fn acquire_rename_leases(old_name: &str, new_name: &str) -> Result<(File, File)> {
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
    let path = vault_path()?;
    let bytes = serialize_json_zeroizing(
        vault,
        MAX_VAULT_BYTES as usize,
        JsonStyle::Pretty,
        "vault exceeds the 16 MiB safety limit",
    )?;
    let mut file = AtomicWriteFile::open(&path)?;
    security::harden_open_file(file.as_file())?;
    file.write_all(&bytes)?;
    file.commit()?;
    Ok(())
}

fn validate_loaded_vault(vault: &VaultFile) -> Result<()> {
    if !matches!(vault.version, 0 | VAULT_FORMAT) {
        bail!("unsupported vault format version {}", vault.version);
    }
    if vault.profiles.len() > 10_000 {
        bail!("vault contains too many profiles");
    }
    for (name, profile) in &vault.profiles {
        validate_profile_name(name)
            .with_context(|| format!("vault contains unsafe profile name '{name}'"))?;
        if !matches!(profile.format, 0 | PROFILE_FORMAT_AAD) {
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
    }
    if let Some(config) = &vault.kdf {
        validate_kdf(config)?;
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
    })
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

fn prepare_vault(vault: &mut VaultFile) {
    if vault.salt.is_empty() {
        let mut salt = [0_u8; 16];
        OsRng.fill_bytes(&mut salt);
        vault.salt = B64.encode(salt);
    }
    if vault.kdf.is_none() {
        vault.kdf = Some(KdfConfig::default());
    }
    vault.version = VAULT_FORMAT;
}

fn validate_profile_update(name: &str, creds: &Creds, master: &str) -> Result<()> {
    validate_profile_name(name)?;
    if master.is_empty() || master.len() > 16 * 1024 {
        bail!("master passphrase must contain 1 to 16384 bytes");
    }
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
        if host_key.is_empty() || host_key.len() > 1024 || contains_control_character(host_key) {
            bail!("host-key fingerprint is empty, oversized, or contains control characters");
        }
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

fn enforce_new_vault_master_policy(vault: &VaultFile, master: &str) -> Result<()> {
    // If neither a verifier nor an encrypted record exists, there is no prior
    // master passphrase whose compatibility needs to be preserved.
    if vault.verifier.is_none() && vault.profiles.is_empty() && master.len() < MIN_NEW_MASTER_BYTES
    {
        bail!("a new vault master passphrase must contain at least {MIN_NEW_MASTER_BYTES} bytes");
    }
    Ok(())
}

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
            Ok(credentials.host_key.take())
        } else {
            // A host key authenticates exactly one SSH endpoint. Carrying it
            // to a different host or port would make the updated profile both
            // unusable and misleading about which endpoint was trusted.
            Ok(None)
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
        Ok(None)
    }
}

/// Add/update a profile. Legacy records are upgraded to authenticated v2.
pub fn add_or_update(name: &str, creds: &Creds, master: &str) -> Result<Option<String>> {
    validate_profile_update(name, creds, master)?;
    let _runtime_lease = acquire_profile_mutation_lease(name)?;
    mutate_vault(|vault| {
        enforce_new_vault_master_policy(vault, master)?;
        prepare_vault(vault);
        let key = vault_key(vault, master)?;
        verify_master(vault, &key)?;
        let previous_pin = match vault.profiles.get(name) {
            Some(profile) => authenticated_pin_for_replacement(name, profile, &key, creds)?,
            None => None,
        };
        let mut updated = creds.clone();
        updated.host_key = previous_pin.clone();
        vault
            .profiles
            .insert(name.to_owned(), encrypt_profile(name, &updated, &key)?);
        ensure_verifier(vault, &key)?;
        Ok(previous_pin)
    })
}

/// Atomically rename and update a profile, retaining its pinned host key only
/// when the authenticated SSH host and port remain byte-for-byte unchanged.
///
/// The destination must not already exist. The old record is decrypted using
/// its original name as AEAD associated data, then encrypted using the new
/// name and updated endpoint before the vault is committed once.
pub fn rename_profile(
    old_name: &str,
    new_name: &str,
    creds: &Creds,
    master: &str,
) -> Result<Option<String>> {
    validate_profile_name(old_name)?;
    validate_profile_update(new_name, creds, master)?;
    if old_name == new_name {
        bail!("source and destination profile names must differ");
    }
    let (_old_runtime_lease, _new_runtime_lease) = acquire_rename_leases(old_name, new_name)?;

    mutate_vault(|vault| {
        prepare_vault(vault);
        let key = vault_key(vault, master)?;
        verify_master(vault, &key)?;
        rename_profile_in_vault(vault, old_name, new_name, creds, &key)
    })
}

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
    decrypt_with_lock_timeout(name, master, VAULT_LOCK_WAIT_TIMEOUT)
}

/// Decrypt a profile while bounding only acquisition of the shared vault-file
/// lock. Callers that invoke this from async code should run it on a blocking
/// worker and retain their own end-to-end deadline; local filesystem I/O and
/// Argon2 itself are synchronous and cannot be preempted by this timeout.
pub(crate) fn decrypt_with_lock_timeout(
    name: &str,
    master: &str,
    lock_timeout: Duration,
) -> Result<Creds> {
    let vault = load_vault_with_lock_timeout(lock_timeout)?;
    let encrypted = vault
        .profiles
        .get(name)
        .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
    reject_legacy_profile_for_network(name, encrypted)?;
    let key = vault_key(&vault, master)?;
    verify_master(&vault, &key)?;
    decrypt_profile_with_key(name, encrypted, &key)
}

#[cfg(test)]
pub fn set_pinned_fp(name: &str, fingerprint: String, master: &str) -> Result<()> {
    set_pinned_fp_with_lock_timeout(name, fingerprint, master, VAULT_LOCK_WAIT_TIMEOUT)
}

/// Persist a TOFU pin while bounding only acquisition of the exclusive
/// vault-file lock. See `decrypt_with_lock_timeout` for the synchronous-I/O and
/// KDF caveat; the mutation itself remains atomic once the lock is acquired.
pub(crate) fn set_pinned_fp_with_lock_timeout(
    name: &str,
    fingerprint: String,
    master: &str,
    lock_timeout: Duration,
) -> Result<()> {
    mutate_vault_with_lock_timeout(lock_timeout, |vault| {
        prepare_vault(vault);
        let key = vault_key(vault, master)?;
        verify_master(vault, &key)?;
        let encrypted = vault
            .profiles
            .get(name)
            .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
        let mut creds = decrypt_profile_with_key(name, encrypted, &key)?;
        if !apply_host_pin(&mut creds, fingerprint)? {
            return Ok(());
        }
        vault
            .profiles
            .insert(name.to_owned(), encrypt_profile(name, &creds, &key)?);
        ensure_verifier(vault, &key)?;
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

pub fn list() -> Result<Vec<(String, String, u16)>> {
    Ok(load_vault()?
        .profiles
        .into_iter()
        .map(|(name, profile)| (name, profile.host, profile.port))
        .collect())
}

pub fn remove(name: &str) -> Result<bool> {
    let _runtime_lease = acquire_profile_mutation_lease(name)?;
    mutate_vault(|vault| Ok(vault.profiles.remove(name).is_some()))
}

pub fn write_lock(info: &LockInfo) -> Result<()> {
    validate_runtime_lock_info(&info.profile, info)?;
    let path = lock_path(&info.profile)?;
    let mut file = AtomicWriteFile::open(&path)?;
    security::harden_open_file(file.as_file())?;
    let serialized = serialize_json_zeroizing(
        info,
        MAX_LOCK_BYTES as usize,
        JsonStyle::Pretty,
        "runtime lock exceeds the 64 KiB safety limit",
    )?;
    file.write_all(&serialized)?;
    file.commit()?;
    Ok(())
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
        bail!("protocol-v2 runtime lock contains forbidden remote metadata");
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
    // Unix retains read-only detection of a v1 daemon so a v2 client will not
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

/// Remove a malformed lock from the hashed protocol-v2 namespace, but only
/// after acquiring the same exclusive lifetime lease used by daemon startup.
/// Security/open/read failures and locks from other protocol versions remain
/// fail-closed. The legacy raw-name namespace is never inspected or removed.
pub fn remove_invalid_hashed_v2_lock(profile: &str) -> Result<bool> {
    let lease = open_runtime_lease_file(profile)?;
    with_exclusive_runtime_cleanup(&lease, || {
        remove_invalid_hashed_v2_lock_while_leased(profile)
    })
}

/// Variant for daemon startup, whose caller already owns the profile's
/// exclusive runtime lease. This mirrors `remove_lock_if_token_while_leased`;
/// callers must keep that lease handle alive for the full call.
pub(crate) fn remove_invalid_hashed_v2_lock_while_leased(profile: &str) -> Result<bool> {
    validate_profile_name(profile)?;
    // Validate/harden the directory before classifying contents. Any owner,
    // ACL, reparse, or directory I/O error exits before deletion is possible.
    let runtime_dir = run_dir()?;
    let path = runtime_dir.join(lock_filename(profile));
    let Some(bytes) = read_lock_file(&path)? else {
        return Ok(false);
    };
    if !hashed_v2_lock_is_invalid(profile, &bytes, &runtime_dir)? {
        return Ok(false);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("remove malformed hashed runtime lock"),
    }
}

fn hashed_v2_lock_is_invalid(
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
            "runtime lock protocol {} is not eligible for protocol-v2 malformed-lock cleanup",
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

/// Reconcile a v2 runtime lock only if it still belongs to the expected daemon.
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
    fn atomic_secret_file_is_hardened_before_commit() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("atomic-secret-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("vault.json");
        let mut file = AtomicWriteFile::open(&path).unwrap();

        security::harden_open_file(file.as_file()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                file.as_file().metadata().unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
        file.write_all(b"{}").unwrap();
        file.commit().unwrap();

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
    fn malformed_hashed_lock_cleanup_classification_is_v2_only() {
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
        assert!(!hashed_v2_lock_is_invalid("prod", &valid, &runtime_dir).unwrap());
        assert!(hashed_v2_lock_is_invalid("prod", b"{broken", &runtime_dir).unwrap());

        lock.pid = 0;
        let invalid_v2 = serde_json::to_vec(&lock).unwrap();
        assert!(hashed_v2_lock_is_invalid("prod", &invalid_v2, &runtime_dir).unwrap());

        lock.protocol = crate::ipc::IPC_PROTOCOL_VERSION + 1;
        let future = serde_json::to_vec(&lock).unwrap();
        assert!(hashed_v2_lock_is_invalid("prod", &future, &runtime_dir).is_err());
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
    fn legacy_host_pin_is_not_inherited_by_offline_replacement() {
        let key = [29_u8; 32];
        let encrypted = legacy_profile(&key);
        assert_eq!(
            authenticated_pin_for_replacement("legacy", &encrypted, &key, &sample_creds()).unwrap(),
            None
        );

        let mut vault = VaultFile::default();
        vault.profiles.insert("legacy".into(), encrypted);
        let pin =
            rename_profile_in_vault(&mut vault, "legacy", "replacement", &sample_creds(), &key)
                .unwrap();
        assert_eq!(pin, None);
        let replacement = vault.profiles.get("replacement").unwrap();
        let decrypted = decrypt_profile_with_key("replacement", replacement, &key).unwrap();
        assert_eq!(decrypted.host_key, None);
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
    fn updating_or_renaming_across_endpoint_clears_host_pin_and_rebinds_aad() {
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
            None
        );

        let pin =
            rename_profile_in_vault(&mut vault, "old-name", "new-name", &updated, &key).unwrap();

        assert_eq!(pin, None);
        let encrypted = vault.profiles.get("new-name").unwrap();
        let decrypted = decrypt_profile_with_key("new-name", encrypted, &key).unwrap();
        assert_eq!(decrypted.host, "new-server.example");
        assert_eq!(decrypted.port, 2200);
        assert_eq!(decrypted.user, "operator");
        assert_eq!(decrypted.password, "updated-password");
        assert_eq!(decrypted.host_key, None);
        assert!(decrypt_profile_with_key("old-name", encrypted, &key).is_err());
    }

    #[test]
    fn renaming_same_endpoint_preserves_authenticated_host_pin() {
        let key = [39_u8; 32];
        let mut vault = VaultFile::default();
        vault.profiles.insert(
            "old-name".into(),
            encrypt_profile("old-name", &sample_creds(), &key).unwrap(),
        );
        let mut updated = sample_creds();
        updated.user = "operator".into();
        updated.password = "updated-password".into();
        updated.host_key = Some("SHA256:untrusted-replacement".into());

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
