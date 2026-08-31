//! Per-user/per-vault global-daemon runtime state: the startup singleton lock,
//! the protected runtime descriptor and activation-secret files, endpoint
//! derivation, and stale-state cleanup.
//!
//! Design §10.2 / §13.1 of the split design document:
//! - the descriptor records the endpoint, PID, instance ID, protocol range,
//!   startup time, and build — never secrets;
//! - the activation secret lives in a separate, current-user-only protected
//!   file, removed when the daemon exits;
//! - startup and stale cleanup are serialized by the singleton lock, and
//!   stale files are removed only by the lock holder after the recorded PID
//!   is confirmed dead (PID verification is best-effort and documented as
//!   such: it cannot defend against PID reuse by a privileged local process).

use crate::security;
use crate::vault;
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use serctl_protocol::v6::{ActivationSecret, InstanceId, IPC_PROTOCOL_VERSION_V8};
use serde::{Deserialize, Serialize};
use std::fs::File;
#[cfg(any(unix, test))]
use std::path::Path;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Schema version of the runtime descriptor file.
pub const DESCRIPTOR_SCHEMA_VERSION: u8 = 1;
/// Size cap for the descriptor file on disk.
pub const MAX_DESCRIPTOR_BYTES: usize = 4 * 1024;
/// Size cap for the activation secret file on disk (44 Base64 characters).
pub const MAX_SECRET_BYTES: usize = 128;

const DESCRIPTOR_NAME: &str = "daemon.json";
const SECRET_NAME: &str = "daemon.secret";
const STARTUP_LOCK_NAME: &str = "daemon-startup.lock";
const GRANT_AUDIT_NAME: &str = "grant-audit.jsonl";

/// Non-secret identity of one running daemon instance, persisted for the CLI
/// and cleaned up on daemon exit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonRuntimeDescriptor {
    pub version: u8,
    /// Lowercase hex of the daemon instance id.
    pub instance_id: String,
    pub pid: u32,
    pub endpoint: String,
    pub protocol_min: u16,
    pub protocol_max: u16,
    pub started_unix: i64,
    /// Short git commit of the daemon build, supplied by the daemon binary.
    pub build_commit: String,
}

impl DaemonRuntimeDescriptor {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == DESCRIPTOR_SCHEMA_VERSION,
            "unsupported daemon runtime descriptor version {}",
            self.version
        );
        InstanceId::from_hex(&self.instance_id)
            .context("daemon runtime descriptor carries an invalid instance id")?;
        ensure!(self.pid != 0, "daemon runtime descriptor carries pid 0");
        ensure!(
            !self.endpoint.is_empty() && self.endpoint.len() <= 512,
            "daemon runtime descriptor carries an invalid endpoint"
        );
        ensure!(
            self.protocol_min <= self.protocol_max
                && self.protocol_min <= IPC_PROTOCOL_VERSION_V8
                && IPC_PROTOCOL_VERSION_V8 <= self.protocol_max,
            "daemon runtime descriptor protocol range does not cover IPC v{IPC_PROTOCOL_VERSION_V8}"
        );
        ensure!(
            !self.build_commit.is_empty() && self.build_commit.len() <= 128,
            "daemon runtime descriptor carries an invalid build commit"
        );
        Ok(())
    }
}

pub fn descriptor_path() -> Result<PathBuf> {
    Ok(vault::run_dir()?.join(DESCRIPTOR_NAME))
}

pub fn secret_path() -> Result<PathBuf> {
    Ok(vault::run_dir()?.join(SECRET_NAME))
}

/// Append-only grant relay audit log. Survives daemon restarts so the trail
/// outlives the grants themselves.
pub fn grant_audit_path() -> Result<PathBuf> {
    Ok(vault::run_dir()?.join(GRANT_AUDIT_NAME))
}

pub fn startup_lock_path() -> Result<PathBuf> {
    Ok(vault::run_dir()?.join(STARTUP_LOCK_NAME))
}

fn descriptor_path_if_present() -> Result<Option<PathBuf>> {
    let path = vault::run_dir_path()?.join(DESCRIPTOR_NAME);
    Ok(path.exists().then_some(path))
}

fn secret_path_if_present() -> Result<Option<PathBuf>> {
    let path = vault::run_dir_path()?.join(SECRET_NAME);
    Ok(path.exists().then_some(path))
}

/// Derive the daemon's per-boot local endpoint from its instance id. On
/// Windows this is a named-pipe path; on Unix it is a socket path under the
/// runtime directory.
pub fn v6_endpoint(instance_id: &InstanceId) -> Result<String> {
    #[cfg(windows)]
    {
        Ok(format!(r"\\.\pipe\serctl-v6-{}", instance_id.as_hex()))
    }
    #[cfg(unix)]
    {
        let path = vault::run_dir()?.join(format!("serctl-v6-{}.sock", instance_id.as_hex()));
        path.to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow::anyhow!("serctl runtime path is not valid UTF-8"))
    }
    #[cfg(not(any(windows, unix)))]
    {
        anyhow::bail!("local IPC endpoints are unsupported on this platform")
    }
}

/// The serialized startup singleton. Held only while starting or cleaning up
/// the daemon, never for the daemon's lifetime: concurrent frontends connect
/// without taking it. The file handle IS the lock; it stays open until drop.
pub struct StartupLock {
    _file: File,
}

/// Outcome of one singleton-lock attempt.
pub enum StartupLockAcquire {
    /// This caller serializes daemon startup (or stale cleanup).
    Acquired(StartupLock),
    /// Another caller holds the lock; retry after it releases.
    Contended,
}

/// Whether a failed lock attempt means another holder exists (as opposed to a
/// real I/O failure). Windows reports same-process re-locks as
/// `ERROR_LOCK_VIOLATION` (33) instead of `WouldBlock`; Unix uses EWOULDBLOCK.
fn is_lock_contention(error: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        const ERROR_LOCK_VIOLATION: i32 = 33;
        error.kind() == std::io::ErrorKind::WouldBlock
            || error.raw_os_error() == Some(ERROR_LOCK_VIOLATION)
    }
    #[cfg(not(windows))]
    {
        error.kind() == std::io::ErrorKind::WouldBlock
    }
}

/// Try to take the startup singleton without blocking. The lock file itself is
/// created with the platform protected-file rules so the lock cannot be
/// planted or removed by another local user.
pub fn acquire_startup_lock() -> Result<StartupLockAcquire> {
    let path = startup_lock_path()?;
    let file = security::open_or_create_protected_file(&path)?;
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(StartupLockAcquire::Acquired(StartupLock { _file: file })),
        Err(error) if is_lock_contention(&error) => Ok(StartupLockAcquire::Contended),
        Err(error) => Err(error).context("lock the daemon startup singleton"),
    }
}

/// Atomically persist the runtime descriptor through the protected-file
/// machinery. The daemon writes this only after its listener is bound, so a
/// descriptor on disk always names a reachable endpoint.
pub fn write_descriptor(descriptor: &DaemonRuntimeDescriptor) -> Result<()> {
    descriptor.validate()?;
    let json = Zeroizing::new(
        serde_json::to_vec(descriptor).context("serialize daemon runtime descriptor")?,
    );
    security::write_protected_atomic(&descriptor_path()?, &json)
}

/// Read and validate the current runtime descriptor, or `None` when no
/// descriptor exists.
pub fn read_descriptor() -> Result<Option<DaemonRuntimeDescriptor>> {
    let Some(path) = descriptor_path_if_present()? else {
        return Ok(None);
    };
    let bytes = std::fs::read(&path).context("read daemon runtime descriptor")?;
    ensure!(
        bytes.len() <= MAX_DESCRIPTOR_BYTES,
        "daemon runtime descriptor exceeds its size cap"
    );
    let descriptor: DaemonRuntimeDescriptor =
        serde_json::from_slice(&bytes).context("parse daemon runtime descriptor")?;
    descriptor.validate()?;
    Ok(Some(descriptor))
}

/// Atomically persist the activation secret in the protected, current-user-only
/// secret file.
pub fn write_secret(secret: &ActivationSecret) -> Result<()> {
    let encoded = secret.to_base64();
    security::write_protected_atomic(&secret_path()?, encoded.as_bytes())
}

/// Read the activation secret, or `None` when no secret file exists.
pub fn read_secret() -> Result<Option<ActivationSecret>> {
    let Some(path) = secret_path_if_present()? else {
        return Ok(None);
    };
    let bytes = std::fs::read(&path).context("read daemon activation secret")?;
    ensure!(
        bytes.len() <= MAX_SECRET_BYTES,
        "daemon activation secret file exceeds its size cap"
    );
    let encoded = std::str::from_utf8(&bytes).context("daemon activation secret is not UTF-8")?;
    let secret = ActivationSecret::from_base64(encoded.trim())?;
    Ok(Some(secret))
}

/// Remove the descriptor and secret files. Idempotent; used by daemon exit and
/// stale cleanup.
pub fn clear_runtime_state() -> Result<()> {
    for path in [descriptor_path()?, secret_path()?] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove daemon runtime state"),
        }
    }
    Ok(())
}

/// Best-effort liveness of a recorded PID. Documented limitation: a local
/// privileged process can always arrange PID reuse; this check only prevents
/// accidental deletion of a live daemon's state.
pub fn pid_is_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        if pid == 0 {
            return false;
        }
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        unsafe {
            CloseHandle(handle);
        }
        true
    }
    #[cfg(unix)]
    {
        if pid == 0 {
            return false;
        }
        let result = unsafe { libc::kill(pid as i32, 0) };
        if result == 0 {
            return true;
        }
        // EPERM means the process exists but belongs to someone else.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

/// Remove stale runtime state, but only while holding the startup singleton
/// and only after the recorded PID is confirmed dead. Returns whether cleanup
/// happened.
pub fn cleanup_stale_runtime_if_dead(_lock: &StartupLock) -> Result<bool> {
    let Some(descriptor) = read_descriptor()? else {
        return Ok(false);
    };
    if pid_is_alive(descriptor.pid) {
        return Ok(false);
    }
    clear_runtime_state()?;
    // The Unix listener removes its socket on drop, but a crashed daemon
    // leaves the stale socket behind; the endpoint names it.
    #[cfg(unix)]
    {
        let path = Path::new(&descriptor.endpoint);
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove stale daemon Unix socket"),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// The whole vault test surface shares one process-global test home, so
    /// every test that swaps it must serialize against the others.
    static TEST_HOME_LOCK: Mutex<()> = Mutex::new(());

    fn test_home() -> (std::sync::MutexGuard<'static, ()>, PathBuf) {
        let guard = TEST_HOME_LOCK.lock().unwrap();
        let base = std::env::temp_dir().join(format!(
            "serctl-runtime-state-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        vault::set_test_home(Some(base.clone()));
        (guard, base)
    }

    fn clear_home(base: &Path) {
        vault::set_test_home(None);
        let _ = std::fs::remove_dir_all(base);
    }

    fn descriptor() -> DaemonRuntimeDescriptor {
        let instance = InstanceId::random();
        DaemonRuntimeDescriptor {
            version: DESCRIPTOR_SCHEMA_VERSION,
            instance_id: instance.as_hex(),
            pid: std::process::id(),
            endpoint: v6_endpoint(&instance).unwrap(),
            protocol_min: IPC_PROTOCOL_VERSION_V8,
            protocol_max: IPC_PROTOCOL_VERSION_V8,
            started_unix: 1_700_000_000,
            build_commit: "testbuild".into(),
        }
    }

    /// A PID that is guaranteed dead: spawn a trivially exiting child, wait
    /// for it to reap, then use its id.
    fn dead_pid() -> u32 {
        #[cfg(windows)]
        let mut command = {
            let mut c = std::process::Command::new("cmd");
            c.arg("/c").arg("exit");
            c
        };
        #[cfg(unix)]
        let mut command = {
            let mut c = std::process::Command::new("true");
            c
        };
        #[cfg(not(any(windows, unix)))]
        let mut command = std::process::Command::new("echo");
        let mut child = command.spawn().unwrap();
        let id = child.id();
        let _ = child.wait();
        id
    }

    #[test]
    fn descriptor_round_trips_and_validates() {
        let (_guard, base) = test_home();
        let descriptor = descriptor();
        write_descriptor(&descriptor).unwrap();
        let read = read_descriptor().unwrap().unwrap();
        assert_eq!(read.instance_id, descriptor.instance_id);
        assert_eq!(read.endpoint, descriptor.endpoint);
        assert_eq!(read.pid, descriptor.pid);

        let mut bad = descriptor.clone();
        bad.version = 2;
        assert!(bad.validate().is_err());
        let mut bad = descriptor.clone();
        bad.protocol_min = IPC_PROTOCOL_VERSION_V8 + 1;
        let error = bad.validate().unwrap_err().to_string();
        assert!(error.contains("IPC v8"));
        assert!(!error.contains("IPC v6"));
        let mut bad = descriptor.clone();
        bad.protocol_max = IPC_PROTOCOL_VERSION_V8 - 1;
        assert!(bad.validate().is_err());
        let mut bad = descriptor.clone();
        bad.protocol_min = IPC_PROTOCOL_VERSION_V8 + 1;
        bad.protocol_max = IPC_PROTOCOL_VERSION_V8 - 1;
        assert!(bad.validate().is_err());
        let mut compatible_range = descriptor.clone();
        compatible_range.protocol_min = IPC_PROTOCOL_VERSION_V8 - 1;
        compatible_range.protocol_max = IPC_PROTOCOL_VERSION_V8 + 1;
        compatible_range.validate().unwrap();
        let mut bad = descriptor.clone();
        bad.instance_id = "not-hex".into();
        assert!(bad.validate().is_err());
        clear_home(&base);
    }

    #[test]
    fn old_protocol_descriptor_fails_closed_without_deleting_runtime_state() {
        let (_guard, base) = test_home();
        let mut old = descriptor();
        old.pid = dead_pid();
        old.protocol_min = IPC_PROTOCOL_VERSION_V8 - 1;
        old.protocol_max = IPC_PROTOCOL_VERSION_V8 - 1;

        // `write_descriptor` correctly refuses this record, so emulate the
        // protected file left by an older, matching binary without weakening
        // its existing file permissions.
        let valid = descriptor();
        write_descriptor(&valid).unwrap();
        let descriptor_bytes = serde_json::to_vec(&old).unwrap();
        let descriptor_path = descriptor_path().unwrap();
        std::fs::write(&descriptor_path, &descriptor_bytes).unwrap();

        let secret = ActivationSecret::random();
        write_secret(&secret).unwrap();
        let secret_path = secret_path().unwrap();
        let secret_bytes = std::fs::read(&secret_path).unwrap();

        let read_error = read_descriptor().unwrap_err().to_string();
        assert!(read_error.contains("IPC v8"));

        let lock = match acquire_startup_lock().unwrap() {
            StartupLockAcquire::Acquired(lock) => lock,
            StartupLockAcquire::Contended => panic!("lock contended in test"),
        };
        let cleanup_error = cleanup_stale_runtime_if_dead(&lock)
            .unwrap_err()
            .to_string();
        assert!(cleanup_error.contains("IPC v8"));
        assert_eq!(std::fs::read(&descriptor_path).unwrap(), descriptor_bytes);
        assert_eq!(std::fs::read(&secret_path).unwrap(), secret_bytes);
        assert_eq!(
            read_secret().unwrap().unwrap().as_bytes(),
            secret.as_bytes()
        );

        clear_home(&base);
    }

    #[test]
    fn absent_descriptor_reads_as_none() {
        let (_guard, base) = test_home();
        assert!(read_descriptor().unwrap().is_none());
        clear_home(&base);
    }

    #[test]
    fn secret_round_trips_and_rejects_corruption() {
        let (_guard, base) = test_home();
        let secret = ActivationSecret::random();
        write_secret(&secret).unwrap();
        let read = read_secret().unwrap().unwrap();
        assert_eq!(read.as_bytes(), secret.as_bytes());

        // Corrupt the file: no longer canonical Base64.
        let path = secret_path().unwrap();
        std::fs::write(&path, b"not-base64").unwrap();
        assert!(read_secret().is_err());
        clear_home(&base);
    }

    #[test]
    fn startup_lock_excludes_a_second_holder() {
        let (_guard, base) = test_home();
        let first = acquire_startup_lock().unwrap();
        assert!(matches!(first, StartupLockAcquire::Acquired(_)));
        let second = acquire_startup_lock().unwrap();
        assert!(matches!(second, StartupLockAcquire::Contended));
        drop(first);
        let third = acquire_startup_lock().unwrap();
        assert!(matches!(third, StartupLockAcquire::Acquired(_)));
        clear_home(&base);
    }

    #[test]
    fn stale_cleanup_removes_only_dead_daemon_state() {
        let (_guard, base) = test_home();
        // Dead pid: cleanup happens.
        let mut dead = descriptor();
        dead.pid = dead_pid();
        write_descriptor(&dead).unwrap();
        write_secret(&ActivationSecret::random()).unwrap();
        let lock = match acquire_startup_lock().unwrap() {
            StartupLockAcquire::Acquired(lock) => lock,
            StartupLockAcquire::Contended => panic!("lock contended in test"),
        };
        assert!(cleanup_stale_runtime_if_dead(&lock).unwrap());
        assert!(read_descriptor().unwrap().is_none());
        assert!(read_secret().unwrap().is_none());

        // Alive pid (ours): cleanup refuses.
        let alive = descriptor();
        write_descriptor(&alive).unwrap();
        assert!(!cleanup_stale_runtime_if_dead(&lock).unwrap());
        assert!(read_descriptor().unwrap().is_some());
        clear_home(&base);
    }

    #[test]
    fn clear_runtime_state_is_idempotent() {
        let (_guard, base) = test_home();
        clear_runtime_state().unwrap();
        clear_runtime_state().unwrap();
        clear_home(&base);
    }

    #[test]
    fn endpoint_is_instance_bound() {
        let (_guard, base) = test_home();
        let a = InstanceId::random();
        let b = InstanceId::random();
        let endpoint_a = v6_endpoint(&a).unwrap();
        let endpoint_b = v6_endpoint(&b).unwrap();
        assert!(endpoint_a.contains(&a.as_hex()));
        assert!(endpoint_b.contains(&b.as_hex()));
        assert_ne!(endpoint_a, endpoint_b);
        clear_home(&base);
    }
}
