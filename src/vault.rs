//! Encrypted credential vault + protected runtime lock files.
//!
//! Version 2 binds every secret to its profile name and endpoint with AEAD
//! associated data. Version 1 records remain readable and are upgraded when
//! they are next modified with the correct master passphrase.

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use atomic_write_file::AtomicWriteFile;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
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

#[derive(Serialize, Deserialize, Clone)]
pub struct LockInfo {
    pub profile: String,
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
    let path = dir()?.join("run");
    std::fs::create_dir_all(&path)?;
    security::harden_directory(&path)?;
    Ok(path)
}

/// Lock filenames are hashes, so even legacy profile names cannot escape the
/// run directory or target reserved Windows device names.
pub fn lock_path(profile: &str) -> Result<PathBuf> {
    Ok(run_dir()?.join(lock_filename(profile)))
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
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    security::harden_file(&path)?;
    Ok(file)
}

/// Acquire the lifetime lease for one profile daemon. The OS releases this
/// automatically if the daemon exits or crashes.
pub fn acquire_runtime_lease(profile: &str) -> Result<File> {
    let file = open_runtime_lease_file(profile)?;
    match file.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            bail!("a daemon is already starting or running for '{profile}'");
        }
        Err(error) => return Err(error).context("acquire daemon runtime lease"),
    }
    Ok(file)
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
    let mut token = [0_u8; 32];
    OsRng.fill_bytes(&mut token);
    B64.encode(token)
}

pub fn load_vault() -> Result<VaultFile> {
    let lock = open_vault_lock()?;
    FileExt::lock_shared(&lock)?;
    load_vault_unlocked()
}

fn load_vault_unlocked() -> Result<VaultFile> {
    let path = vault_path()?;
    if !path.exists() {
        return Ok(VaultFile::default());
    }
    if std::fs::metadata(&path)?.len() > MAX_VAULT_BYTES {
        bail!("vault exceeds the 16 MiB safety limit");
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let vault: VaultFile = serde_json::from_str(&text).context("parse encrypted vault")?;
    validate_loaded_vault(&vault)?;
    Ok(vault)
}

fn open_vault_lock() -> Result<File> {
    let path = dir()?.join("vault.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    security::harden_file(&path)?;
    Ok(file)
}

fn save_vault_unlocked(vault: &VaultFile) -> Result<()> {
    let path = vault_path()?;
    let bytes = serde_json::to_vec_pretty(vault)?;
    if bytes.len() as u64 > MAX_VAULT_BYTES {
        bail!("vault exceeds the 16 MiB safety limit");
    }
    let mut file = AtomicWriteFile::open(&path)?;
    file.write_all(&bytes)?;
    file.commit()?;
    security::harden_file(&path)?;
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
        if !matches!(profile.format, 0 | PROFILE_FORMAT_AAD) {
            bail!("profile '{name}' uses an unsupported encrypted format");
        }
    }
    if let Some(config) = &vault.kdf {
        validate_kdf(config)?;
    }
    Ok(())
}

fn mutate_vault<T>(mutator: impl FnOnce(&mut VaultFile) -> Result<T>) -> Result<T> {
    let lock = open_vault_lock()?;
    FileExt::lock_exclusive(&lock)?;
    let mut vault = load_vault_unlocked()?;
    let result = mutator(&mut vault)?;
    save_vault_unlocked(&vault)?;
    Ok(result)
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

fn derive_key(master: &[u8], salt: &[u8], config: &KdfConfig) -> Result<[u8; 32]> {
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
    let mut output = [0_u8; 32];
    argon
        .hash_password_into(master, salt, &mut output)
        .map_err(|e| anyhow!(e))?;
    Ok(output)
}

fn vault_key(vault: &VaultFile, master: &str) -> Result<Zeroizing<[u8; 32]>> {
    let salt = B64.decode(&vault.salt).context("decode vault salt")?;
    let config = vault.kdf.clone().unwrap_or_default();
    Ok(Zeroizing::new(derive_key(
        master.as_bytes(),
        &salt,
        &config,
    )?))
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

fn decrypt_profile_with_key(name: &str, encrypted: &EncProfile, key: &[u8; 32]) -> Result<Creds> {
    let nonce = decode_nonce(&encrypted.nonce)?;
    let ciphertext = B64.decode(&encrypted.ct).context("decode ciphertext")?;
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = if encrypted.format == PROFILE_FORMAT_AAD {
        let aad = profile_aad(name, &encrypted.host, encrypted.port)?;
        cipher.decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
    } else {
        cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
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
    let plaintext = Zeroizing::new(serde_json::to_vec(&secret)?);
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
            let _ = decrypt_profile_with_key(name, profile, key)?;
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

/// Add/update a profile. Legacy records are upgraded to authenticated v2.
pub fn add_or_update(name: &str, creds: &Creds, master: &str) -> Result<Option<String>> {
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
    mutate_vault(|vault| {
        prepare_vault(vault);
        let key = vault_key(vault, master)?;
        verify_master(vault, &key)?;
        let previous_pin = vault
            .profiles
            .get(name)
            .map(|profile| decrypt_profile_with_key(name, profile, &key))
            .transpose()?
            .and_then(|mut profile| profile.host_key.take());
        let mut updated = creds.clone();
        updated.host_key = previous_pin.clone();
        vault
            .profiles
            .insert(name.to_owned(), encrypt_profile(name, &updated, &key)?);
        ensure_verifier(vault, &key)?;
        Ok(previous_pin)
    })
}

pub fn decrypt(name: &str, master: &str) -> Result<Creds> {
    let vault = load_vault()?;
    let encrypted = vault
        .profiles
        .get(name)
        .ok_or_else(|| anyhow!("profile '{name}' not found"))?;
    let key = vault_key(&vault, master)?;
    verify_master(&vault, &key)?;
    decrypt_profile_with_key(name, encrypted, &key)
}

pub fn set_pinned_fp(name: &str, fingerprint: String, master: &str) -> Result<()> {
    mutate_vault(|vault| {
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
    mutate_vault(|vault| Ok(vault.profiles.remove(name).is_some()))
}

pub fn write_lock(info: &LockInfo) -> Result<()> {
    if B64.decode(&info.token).map(|v| v.len()).unwrap_or(0) != 32 {
        bail!("IPC token must contain 32 random bytes");
    }
    if info.endpoint.is_empty() {
        bail!("local IPC endpoint cannot be empty");
    }
    let path = lock_path(&info.profile)?;
    let mut file = AtomicWriteFile::open(&path)?;
    file.write_all(&serde_json::to_vec_pretty(info)?)?;
    file.commit()?;
    security::harden_file(&path)?;
    Ok(())
}

pub fn read_lock(profile: &str) -> Result<Option<LockInfo>> {
    let mut path = lock_path(profile)?;
    if !path.exists() {
        // Detect a daemon created by v1 so the updated client can refuse its
        // unauthenticated IPC instead of silently starting a second daemon.
        if validate_profile_name(profile).is_ok() {
            let legacy = run_dir()?.join(format!("{profile}.lock"));
            if legacy.exists() {
                path = legacy;
            } else {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }
    }
    if std::fs::metadata(&path)?.len() > MAX_LOCK_BYTES {
        bail!("runtime lock exceeds the 64 KiB safety limit");
    }
    let text = std::fs::read_to_string(&path)?;
    let info: LockInfo = serde_json::from_str(&text)?;
    if info.profile != profile {
        bail!("runtime lock profile mismatch");
    }
    if !info.token.is_empty() && B64.decode(&info.token).map(|v| v.len()).unwrap_or(0) != 32 {
        bail!("runtime lock contains an invalid IPC token");
    }
    Ok(Some(info))
}

/// Remove a v2 runtime lock only if it still belongs to the expected daemon.
/// This prevents stale-client cleanup from deleting a newly replaced lock.
pub fn remove_lock_if_token(profile: &str, expected_token: &str) -> Result<bool> {
    use subtle::ConstantTimeEq;

    let lease = open_runtime_lease_file(profile)?;
    match lease.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    let path = lock_path(profile)?;
    if !path.exists() {
        return Ok(false);
    }
    if std::fs::metadata(&path)?.len() > MAX_LOCK_BYTES {
        bail!("runtime lock exceeds the 64 KiB safety limit");
    }
    let info: LockInfo = serde_json::from_slice(&std::fs::read(&path)?)?;
    let matches_profile = info.profile == profile;
    let matches_token: bool = info
        .token
        .as_bytes()
        .ct_eq(expected_token.as_bytes())
        .into();
    if !matches_profile || !matches_token {
        return Ok(false);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
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
    fn legacy_tcp_lock_remains_detectable() {
        let lock: LockInfo = serde_json::from_str(
            r#"{"profile":"prod","pid":7,"port":4321,"host":"","user":"","started_unix":1,"token":""}"#,
        )
        .unwrap();
        assert_eq!(lock.port, 4321);
        assert!(lock.endpoint.is_empty());
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
    fn legacy_profile_remains_readable() {
        let key = [19_u8; 32];
        let nonce = [23_u8; 12];
        let secret = Secret {
            user: "legacy-user".into(),
            password: "legacy-password".into(),
            host_key: None,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&secret).unwrap());
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();
        let encrypted = EncProfile {
            host: "legacy.example".into(),
            port: 22,
            format: 0,
            nonce: B64.encode(nonce),
            ct: B64.encode(ciphertext),
            host_key: Some("SHA256:legacy-pin".into()),
        };

        let decrypted = decrypt_profile_with_key("legacy", &encrypted, &key).unwrap();
        assert_eq!(decrypted.user, "legacy-user");
        assert_eq!(decrypted.password, "legacy-password");
        assert_eq!(decrypted.host_key.as_deref(), Some("SHA256:legacy-pin"));
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
    fn concurrent_host_pin_cannot_be_replaced() {
        let mut creds = sample_creds();
        assert!(!apply_host_pin(&mut creds, "SHA256:server-fingerprint".into()).unwrap());
        assert!(apply_host_pin(&mut creds, "SHA256:attacker".into()).is_err());
        assert_eq!(creds.host_key.as_deref(), Some("SHA256:server-fingerprint"));
    }
}
