//! Explicit, profile-scoped recovery for an authenticated audit ledger.
//!
//! This path is deliberately offline with respect to the target profile: an
//! exclusive profile lease is held from passphrase verification through the
//! final ledger operation and optional anchor export. Recovery never guesses a
//! remote terminal state; it can only append authenticated `Unknown` outcomes
//! for pending Intents. It also never auto-reconciles a lagging checkpoint:
//! that needs a future anchor-aware core receipt rather than an implicit retry.

use anyhow::{anyhow, bail, ensure, Context, Result};
use serctl_core::audit::{AuditCheckpoint, AuditInspection, AuditLedger, PendingResolution};
use serctl_core::{security, vault};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AUDIT_AUTHORIZATION_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_AUDIT_ANCHOR_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditStatusView {
    pub checkpoint: AuditCheckpoint,
    pub pending_intents: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditResolutionView {
    pub status: AuditStatusView,
    pub resolved_as_unknown: usize,
}

pub(crate) fn inspect_profile_audit(
    profile: &str,
    profile_passphrase: &str,
    anchor_path: Option<&Path>,
    anchor_output_path: Option<&Path>,
) -> Result<AuditStatusView> {
    with_profile_audit_ledger(
        profile,
        profile_passphrase,
        anchor_path,
        |ledger, anchor| {
            let status = status_view(ledger.inspect(anchor)?)?;
            if let Some(path) = anchor_output_path {
                write_audit_anchor_create_new(path, &status.checkpoint).context(
                    "audit ledger verification completed, but authenticated anchor export failed",
                )?;
            }
            Ok(CompletedAuditOperation {
                value: status,
                unlock_failure_context: if anchor_output_path.is_some() {
                    "audit ledger verification and anchor export completed, but the exclusive profile lease could not be released cleanly"
                } else {
                    "audit ledger verification completed, but the exclusive profile lease could not be released cleanly"
                },
            })
        },
    )
}

pub(crate) fn resolve_profile_audit_as_unknown(
    profile: &str,
    profile_passphrase: &str,
    anchor_path: Option<&Path>,
    anchor_output_path: Option<&Path>,
    acknowledged: bool,
) -> Result<AuditResolutionView> {
    ensure!(
        acknowledged,
        "refusing audit recovery without explicit acknowledgement that pending operations will remain unknown"
    );
    with_profile_audit_ledger(
        profile,
        profile_passphrase,
        anchor_path,
        |ledger, anchor| {
            let before = ledger.inspect(anchor)?;
            if before.pending_intents == 0 {
                let status = status_view(before)?;
                if let Some(path) = anchor_output_path {
                    write_audit_anchor_create_new(path, &status.checkpoint).context(
                        "audit ledger was already complete, but authenticated anchor export failed",
                    )?;
                }
                return Ok(CompletedAuditOperation {
                    value: AuditResolutionView {
                        status,
                        resolved_as_unknown: 0,
                    },
                    unlock_failure_context: if anchor_output_path.is_some() {
                        "audit ledger was already complete and its anchor was exported, but the exclusive profile lease could not be released cleanly"
                    } else {
                        "audit ledger was already complete, but the exclusive profile lease could not be released cleanly"
                    },
                });
            }
            let expected = before.pending_intents;
            let resolution = ledger
                .resolve_pending_as_unknown(now_unix_ms()?, anchor)
                .map_err(|error| {
                    anyhow!(
                        "audit recovery returned without a terminal receipt; zero or more Unknown outcomes may already be durable, so do not infer rollback or retry blindly: {error:#}"
                    )
                })?;
            let resolved = resolution.resolved;
            let view = resolution_view(ledger, resolution).map_err(|error| {
                anyhow!(
                    "audit recovery reported {resolved} durable Unknown outcome(s), but post-recovery verification failed; keep the profile quarantined and do not retry blindly: {error:#}"
                )
            })?;
            ensure!(
                resolved == expected,
                "audit recovery durably appended {resolved} Unknown outcome(s), but the authenticated preflight expected {expected}; keep the profile quarantined"
            );
            if let Some(path) = anchor_output_path {
                write_audit_anchor_create_new(path, &view.status.checkpoint).with_context(|| {
                    format!(
                        "audit recovery durably appended {resolved} Unknown outcome(s), but post-recovery anchor export failed"
                    )
                })?;
            }
            Ok(CompletedAuditOperation {
                value: view,
                unlock_failure_context: if anchor_output_path.is_some() {
                    "audit recovery and post-recovery anchor export completed durably, but the exclusive profile lease could not be released cleanly"
                } else {
                    "audit recovery completed durably, but the exclusive profile lease could not be released cleanly"
                },
            })
        },
    )
}

/// Export only the authenticated checkpoint, never a credential or key. The
/// destination must not exist so an operator cannot silently replace a prior
/// offline anchor with a newer or older snapshot.
pub(crate) fn write_audit_anchor_create_new(
    path: &Path,
    checkpoint: &AuditCheckpoint,
) -> Result<()> {
    let mut encoded = serde_json::to_vec(checkpoint).context("encode audit anchor")?;
    ensure!(
        !encoded.is_empty() && encoded.len().saturating_add(1) as u64 <= MAX_AUDIT_ANCHOR_BYTES,
        "encoded audit anchor exceeds the supported size"
    );
    encoded.push(b'\n');
    write_audit_anchor_create_new_with(
        path,
        &encoded,
        |file, bytes| {
            file.write_all(bytes).context("write audit anchor")?;
            file.sync_all().context("sync audit anchor")
        },
        sync_anchor_parent,
    )
}

fn write_audit_anchor_create_new_with<P, S>(
    path: &Path,
    encoded: &[u8],
    persist: P,
    sync_parent: S,
) -> Result<()>
where
    P: FnOnce(&mut File, &[u8]) -> Result<()>,
    S: Fn(&File) -> Result<()>,
{
    write_audit_anchor_create_new_with_checks(
        path,
        encoded,
        persist,
        sync_parent,
        ensure_anchor_parent_identity,
    )
}

fn write_audit_anchor_create_new_with_checks<P, S, C>(
    path: &Path,
    encoded: &[u8],
    persist: P,
    sync_parent: S,
    ensure_parent_identity: C,
) -> Result<()>
where
    P: FnOnce(&mut File, &[u8]) -> Result<()>,
    S: Fn(&File) -> Result<()>,
    C: Fn(&Path, &File) -> Result<()>,
{
    ensure!(
        !encoded.is_empty() && encoded.len() as u64 <= MAX_AUDIT_ANCHOR_BYTES,
        "encoded audit anchor exceeds the supported size"
    );
    let (parent_path, parent) = open_anchor_parent(path)?;
    ensure_parent_identity(&parent_path, &parent)?;
    let file = create_new_anchor_file(path)?;
    let mut rollback = AnchorCreateRollback::new(path, file);
    let persistence = (|| {
        validate_anchor_file_handle(rollback.file(), "audit anchor output")?;
        ensure_anchor_path_identity(
            path,
            rollback.file(),
            "audit anchor output changed before it was written",
        )?;
        persist(rollback.file_mut(), encoded)?;
        verify_persisted_anchor_bytes(rollback.file_mut(), encoded)?;
        ensure_anchor_path_identity(
            path,
            rollback.file(),
            "audit anchor output was replaced while it was written",
        )?;
        ensure_parent_identity(&parent_path, &parent)?;
        sync_parent(&parent).context("sync audit anchor parent directory")?;
        verify_persisted_anchor_bytes(rollback.file_mut(), encoded)?;
        ensure_anchor_path_identity(
            path,
            rollback.file(),
            "audit anchor output was replaced while its parent was synchronized",
        )?;
        // The caller-visible parent can be rebound during the directory sync
        // while an attacker places a hard link to this same anchor inode under
        // the replacement parent. File identity alone would still match, so a
        // final parent-handle comparison is required before reporting success.
        ensure_parent_identity(&parent_path, &parent)
    })();
    match persistence {
        Ok(()) => {
            rollback.commit();
            Ok(())
        }
        Err(error) => rollback.fail(error, &parent, &sync_parent),
    }
}

fn create_new_anchor_file(path: &Path) -> Result<File> {
    // An anchor is an authenticated public checkpoint, not recovery material
    // or a credential. Keep CREATE_NEW/no-follow semantics portable to offline
    // FAT/exFAT media instead of requiring the protected-file DACL API, which
    // those filesystems cannot represent. On Windows the file therefore
    // inherits its directory ACL; authenticity is enforced by the checkpoint
    // MAC and rollback strength still depends on external custody.
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!("audit anchor output already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect audit anchor output {}", path.display()))
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
        };
        options
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("create new audit anchor {}", path.display()))?;
    Ok(file)
}

struct AnchorCreateRollback {
    path: PathBuf,
    file: Option<File>,
    armed: bool,
}

impl AnchorCreateRollback {
    fn new(path: &Path, file: File) -> Self {
        Self {
            path: path.to_owned(),
            file: Some(file),
            armed: true,
        }
    }

    fn file(&self) -> &File {
        self.file
            .as_ref()
            .expect("armed audit-anchor rollback must retain its file handle")
    }

    fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("armed audit-anchor rollback must retain its file handle")
    }

    fn commit(mut self) {
        self.armed = false;
        drop(self.file.take());
    }

    fn fail<S>(
        mut self,
        persistence_error: anyhow::Error,
        parent: &File,
        sync_parent: &S,
    ) -> Result<()>
    where
        S: Fn(&File) -> Result<()>,
    {
        let cleanup = remove_created_anchor_if_same(&self.path, self.file());
        self.armed = false;
        drop(self.file.take());
        let path_absent_before_sync = verify_anchor_path_absent_after_rollback(&self.path);
        let cleanup_sync = sync_parent(parent);
        let path_absent_after_sync = verify_anchor_path_absent_after_rollback(&self.path);
        match (
            cleanup,
            path_absent_before_sync,
            cleanup_sync,
            path_absent_after_sync,
        ) {
            (Ok(()), Ok(()), Ok(()), Ok(())) => Err(persistence_error),
            (cleanup, path_absent_before_sync, cleanup_sync, path_absent_after_sync) => Err(anyhow!(
                "{persistence_error:#}; audit anchor export did not commit, but rollback could not be proven durable (remove={}; path_absent_before_sync={}; parent_sync={}; path_absent_after_sync={})",
                format_cleanup_result(cleanup),
                format_cleanup_result(path_absent_before_sync),
                format_cleanup_result(cleanup_sync),
                format_cleanup_result(path_absent_after_sync),
            )),
        }
    }
}

impl Drop for AnchorCreateRollback {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_created_anchor_if_same(
                &self.path,
                self.file
                    .as_ref()
                    .expect("armed audit-anchor rollback must retain its file handle"),
            );
        }
        drop(self.file.take());
    }
}

fn format_cleanup_result(result: Result<()>) -> String {
    match result {
        Ok(()) => "ok".to_owned(),
        Err(error) => format!("{error:#}"),
    }
}

fn verify_persisted_anchor_bytes(file: &mut File, expected: &[u8]) -> Result<()> {
    file.seek(SeekFrom::Start(0))
        .context("rewind audit anchor for verification")?;
    let mut persisted = vec![0_u8; expected.len()];
    file.read_exact(&mut persisted)
        .context("read back audit anchor for verification")?;
    let mut trailing = [0_u8; 1];
    ensure!(
        file.read(&mut trailing)? == 0 && persisted == expected,
        "audit anchor write verification failed"
    );
    Ok(())
}

fn verify_anchor_path_absent_after_rollback(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("reinspect failed audit anchor {}", path.display()))
        }
        Ok(metadata) => {
            let kind = if metadata.file_type().is_symlink() {
                "a link or reparse replacement"
            } else if metadata.file_type().is_file() {
                "a file entry, possibly a replacement"
            } else {
                "a non-file replacement"
            };
            bail!(
                "audit anchor pathname still contains {kind}; refusing to remove an object that is not proven to be the failed create-new anchor"
            )
        }
    }
}

fn anchor_parent_path(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.file_name().is_some(),
        "audit anchor path has no file name"
    );
    Ok(path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_owned())
}

fn open_anchor_parent(path: &Path) -> Result<(PathBuf, File)> {
    let parent_path = anchor_parent_path(path)?;
    let before = std::fs::symlink_metadata(&parent_path).with_context(|| {
        format!(
            "inspect audit anchor parent {} before opening",
            parent_path.display()
        )
    })?;
    if !before.file_type().is_dir() || before.file_type().is_symlink() {
        bail!("audit anchor parent is not a regular non-link directory");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        ensure!(
            before.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "audit anchor parent must not be a reparse point"
        );
    }
    let parent = open_anchor_parent_handle(&parent_path)?;
    Ok((parent_path, parent))
}

fn open_anchor_parent_handle(parent_path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let parent = options
        .open(parent_path)
        .with_context(|| format!("open audit anchor parent {}", parent_path.display()))?;
    let metadata = parent
        .metadata()
        .context("inspect audit anchor parent handle")?;
    if !metadata.file_type().is_dir() {
        bail!("audit anchor parent handle is not a directory");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        ensure!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "audit anchor parent handle is a reparse point"
        );
    }
    Ok(parent)
}

fn ensure_anchor_parent_identity(path: &Path, parent: &File) -> Result<()> {
    let path_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reinspect audit anchor parent {}", path.display()))?;
    if !path_metadata.file_type().is_dir() || path_metadata.file_type().is_symlink() {
        bail!("audit anchor parent changed to a link or non-directory");
    }
    let current = open_anchor_parent_handle(path)?;
    ensure_same_open_file_identity(
        parent,
        &current,
        "audit anchor parent directory entry changed during export",
    )
}

fn ensure_anchor_path_identity(path: &Path, expected: &File, message: &str) -> Result<()> {
    let path_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reinspect audit anchor path {}", path.display()))?;
    validate_anchor_path_metadata(&path_metadata, "audit anchor path")?;
    let current = open_anchor_identity_handle(path)?;
    ensure_same_open_file_identity(expected, &current, message)
}

fn open_anchor_identity_handle(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        options
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open audit anchor identity handle {}", path.display()))?;
    validate_anchor_file_handle(&file, "audit anchor identity")?;
    Ok(file)
}

#[cfg(unix)]
fn ensure_same_open_file_identity(before: &File, after: &File, message: &str) -> Result<()> {
    ensure_same_file_identity(&before.metadata()?, &after.metadata()?, message)
}

#[cfg(windows)]
fn ensure_same_open_file_identity(before: &File, after: &File, message: &str) -> Result<()> {
    ensure!(
        windows_file_identity(before)? == windows_file_identity(after)?,
        "{message}"
    );
    Ok(())
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    let inspected =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, information.as_mut_ptr()) };
    if inspected == 0 {
        return Err(std::io::Error::last_os_error()).context("read Windows file identity");
    }
    let information = unsafe { information.assume_init() };
    Ok((
        information.dwVolumeSerialNumber,
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    ))
}

#[cfg(not(any(unix, windows)))]
fn ensure_same_open_file_identity(_before: &File, _after: &File, _message: &str) -> Result<()> {
    bail!("audit anchor parent identity validation is unsupported on this platform")
}

#[cfg(unix)]
fn sync_anchor_parent(parent: &File) -> Result<()> {
    parent
        .sync_all()
        .context("durably sync audit anchor parent directory")
}

#[cfg(windows)]
fn sync_anchor_parent(parent: &File) -> Result<()> {
    match parent.sync_all() {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::Unsupported
            ) =>
        {
            // Windows does not expose a portable directory-fsync contract.
            // The file itself has already been flushed with sync_all; opening
            // and flushing the pinned non-reparse directory is best effort.
            Ok(())
        }
        Err(error) => Err(error).context("best-effort sync audit anchor parent directory"),
    }
}

#[cfg(not(any(unix, windows)))]
fn sync_anchor_parent(_parent: &File) -> Result<()> {
    bail!("durable audit anchor export is unsupported on this platform")
}

#[cfg(unix)]
fn remove_created_anchor_if_same(path: &Path, file: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let expected = file.metadata().context("inspect created audit anchor")?;
    let actual = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                expected.nlink() == 0,
                "created audit anchor disappeared from its pathname but remains linked, so rollback cannot remove a possible renamed or hard-linked copy"
            );
            return Ok(());
        }
        Err(error) => return Err(error).context("inspect failed audit anchor for rollback"),
    };
    ensure_same_file_identity(
        &expected,
        &actual,
        "refusing to remove a replaced audit anchor during rollback",
    )?;
    std::fs::remove_file(path).context("remove failed audit anchor")?;
    ensure!(
        file.metadata()
            .context("reinspect unlinked audit anchor")?
            .nlink()
            == 0,
        "created audit anchor still has another hard link after rollback"
    );
    Ok(())
}

#[cfg(windows)]
fn remove_created_anchor_if_same(_path: &Path, file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let deleted = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as _,
            FileDispositionInfo,
            (&raw const disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if deleted == 0 {
        Err(std::io::Error::last_os_error()).context("remove failed audit anchor by handle")
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn remove_created_anchor_if_same(path: &Path, _file: &File) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove failed audit anchor"),
    }
}

fn with_profile_audit_ledger<T>(
    profile: &str,
    profile_passphrase: &str,
    anchor_path: Option<&Path>,
    operation: impl FnOnce(&AuditLedger, Option<&AuditCheckpoint>) -> Result<CompletedAuditOperation<T>>,
) -> Result<T> {
    vault::validate_profile_name(profile)?;
    // The exclusive lifetime lease conflicts with every active shared profile
    // use lease. A concurrently running global broker may remain idle, but it
    // cannot unlock this profile until recovery releases the lease.
    let lease = vault::acquire_runtime_lease(profile)
        .context("acquire exclusive profile audit-recovery lease")?;
    let result = (|| {
        let metadata = vault::list_profile_metadata()?
            .into_iter()
            .find(|candidate| candidate.name == profile)
            .with_context(|| format!("profile '{profile}' not found"))?;
        let identity = metadata.identity();
        let call_key = vault::derive_profile_audit_recovery_key_with_lock_timeout(
            &lease,
            profile,
            profile_passphrase,
            Some(identity),
            AUDIT_AUTHORIZATION_LOCK_TIMEOUT,
        )?;
        let directory = vault::run_dir()?.join("audit");
        std::fs::create_dir_all(&directory).context("create profile audit directory")?;
        security::harden_directory(&directory).context("harden profile audit directory")?;
        let ledger = AuditLedger::from_profile_call_key(&directory, identity, &call_key)?;
        let anchor = anchor_path.map(read_anchor).transpose()?;
        operation(&ledger, anchor.as_ref())
    })();
    let unlock = lease
        .unlock()
        .context("release exclusive profile audit-recovery lease");
    match (result, unlock) {
        (Ok(completed), Ok(())) => Ok(completed.value),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock_error)) => Err(anyhow!(
            "{error:#}; additionally, the exclusive profile audit-recovery lease could not be released cleanly: {unlock_error:#}"
        )),
        (Ok(completed), Err(error)) => Err(error).context(completed.unlock_failure_context),
    }
}

struct CompletedAuditOperation<T> {
    value: T,
    unlock_failure_context: &'static str,
}

fn status_view(inspection: AuditInspection) -> Result<AuditStatusView> {
    ensure!(
        inspection.checkpoint.schema_version == serctl_core::audit::AUDIT_SCHEMA_VERSION,
        "authenticated audit checkpoint schema changed unexpectedly"
    );
    Ok(AuditStatusView {
        checkpoint: inspection.checkpoint,
        pending_intents: inspection.pending_intents,
    })
}

fn resolution_view(
    ledger: &AuditLedger,
    resolution: PendingResolution,
) -> Result<AuditResolutionView> {
    let after = ledger.inspect(Some(&resolution.checkpoint))?;
    ensure!(
        after.pending_intents == 0,
        "audit recovery did not close every pending Intent as Unknown"
    );
    Ok(AuditResolutionView {
        status: status_view(after)?,
        resolved_as_unknown: resolution.resolved,
    })
}

fn read_anchor(path: &Path) -> Result<AuditCheckpoint> {
    let before = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect audit anchor {} before opening", path.display()))?;
    validate_anchor_path_metadata(&before, "audit anchor")?;
    ensure_anchor_size(before.len())?;
    let file = open_anchor_file_for_read(path)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect audit anchor {}", path.display()))?;
    validate_anchor_file_handle(&file, "audit anchor")?;
    ensure_anchor_size(metadata.len())?;
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    (&file)
        .take(MAX_AUDIT_ANCHOR_BYTES + 1)
        .read_to_end(&mut encoded)
        .context("read audit anchor")?;
    let after = file
        .metadata()
        .with_context(|| format!("reinspect audit anchor {}", path.display()))?;
    ensure!(
        encoded.len() as u64 == metadata.len()
            && after.len() == metadata.len()
            && encoded.len() as u64 <= MAX_AUDIT_ANCHOR_BYTES,
        "audit anchor changed size while it was read"
    );
    ensure_anchor_path_identity(
        path,
        &file,
        "audit anchor pathname changed while it was read",
    )?;
    serde_json::from_slice(&encoded).context("decode audit anchor")
}

fn ensure_anchor_size(length: u64) -> Result<()> {
    ensure!(
        length > 0 && length <= MAX_AUDIT_ANCHOR_BYTES,
        "audit anchor size is outside the supported range"
    );
    Ok(())
}

fn open_anchor_file_for_read(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).with_context(|| {
        format!(
            "open audit anchor {} without following links",
            path.display()
        )
    })?;
    validate_anchor_file_handle(&file, "audit anchor")?;
    Ok(file)
}

fn validate_anchor_path_metadata(metadata: &std::fs::Metadata, label: &str) -> Result<()> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("{label} is not a regular non-link file");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("{label} must not be a reparse point");
        }
    }
    Ok(())
}

fn validate_anchor_file_handle(file: &File, label: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {label} handle"))?;
    validate_anchor_path_metadata(&metadata, label)
}

#[cfg(unix)]
fn ensure_same_file_identity(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
    message: &str,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "{message}"
    );
    Ok(())
}

fn now_unix_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock predates the Unix epoch")?
            .as_millis(),
    )
    .context("current Unix time exceeds the supported range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serctl_core::audit::{AuditDecision, AuditEvent, AuditPhase};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_file(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "serctl-audit-anchor-{label}-{}-{}-{}",
            std::process::id(),
            now_unix_ms().unwrap(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        ))
    }

    fn checkpoint() -> AuditCheckpoint {
        AuditCheckpoint {
            schema_version: serctl_core::audit::AUDIT_SCHEMA_VERSION,
            profile_id: hex::encode([9_u8; 16]),
            profile_generation: 7,
            sequence: 11,
            record_hash: hex::encode([8_u8; 32]),
            mac: hex::encode([6_u8; 32]),
        }
    }

    struct IsolatedAuditHome {
        path: PathBuf,
    }

    impl IsolatedAuditHome {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "serctl-cli-audit-recovery-{}-{}-{}",
                std::process::id(),
                now_unix_ms().unwrap(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700).create(&path).unwrap();
            }
            #[cfg(not(unix))]
            std::fs::create_dir(&path).unwrap();
            vault::set_test_home(Some(path.clone()));
            Self { path }
        }
    }

    impl Drop for IsolatedAuditHome {
        fn drop(&mut self) {
            vault::set_test_home(None);
            if let Err(error) = std::fs::remove_dir_all(&self.path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    panic!(
                        "remove isolated audit-recovery home {}: {error}",
                        self.path.display()
                    );
                }
            }
        }
    }

    #[test]
    fn high_level_audit_recovery_contract_uses_only_isolated_state() {
        let home = IsolatedAuditHome::new();
        let profile = "audit-recovery-contract";
        let passphrase = "isolated-profile-passphrase";
        #[cfg(windows)]
        let administrator_passphrase = "isolated-administrator-passphrase";
        #[cfg(windows)]
        {
            let media_path = home.path.join("recovery-media.json");
            vault::initialize_admin_password(administrator_passphrase, |media| {
                std::fs::write(&media_path, media).context("write isolated recovery media")
            })
            .unwrap();
        }
        let credentials = vault::Creds {
            host: "audit.invalid".to_owned(),
            port: 22,
            user: "isolated-user".to_owned(),
            password: "isolated-password".to_owned(),
            host_key: None,
        };
        let metadata = vault::create_profile(profile, &credentials, passphrase, {
            #[cfg(windows)]
            {
                Some(administrator_passphrase)
            }
            #[cfg(not(windows))]
            {
                None
            }
        })
        .unwrap();
        let identity = metadata.identity();

        let wrong_password = inspect_profile_audit(profile, "wrong-passphrase", None, None)
            .expect_err("wrong profile passphrase must fail closed");
        assert!(wrong_password
            .to_string()
            .contains("wrong profile passphrase"));

        let use_lease = vault::acquire_profile_use_lease(profile).unwrap();
        let contention = inspect_profile_audit(profile, passphrase, None, None)
            .expect_err("shared profile use must block exclusive audit recovery");
        assert!(contention
            .to_string()
            .contains("acquire exclusive profile audit-recovery lease"));
        assert!(vault::derive_profile_audit_recovery_key_with_lock_timeout(
            &use_lease,
            profile,
            passphrase,
            Some(identity),
            AUDIT_AUTHORIZATION_LOCK_TIMEOUT,
        )
        .is_err());
        use_lease.unlock().unwrap();

        let anchor_path = home.path.join("matching-anchor.json");
        let initial = inspect_profile_audit(profile, passphrase, None, Some(&anchor_path)).unwrap();
        assert_eq!(initial.pending_intents, 0);
        assert_eq!(read_anchor(&anchor_path).unwrap(), initial.checkpoint);
        let anchored =
            inspect_profile_audit(profile, passphrase, Some(&anchor_path), None).unwrap();
        assert_eq!(anchored, initial);

        let wrong_anchor_path = home.path.join("wrong-anchor.json");
        let mut wrong_anchor = initial.checkpoint.clone();
        wrong_anchor.record_hash = hex::encode([0x77_u8; 32]);
        write_audit_anchor_create_new(&wrong_anchor_path, &wrong_anchor).unwrap();
        assert!(
            inspect_profile_audit(profile, passphrase, Some(&wrong_anchor_path), None).is_err()
        );

        let existing_output = home.path.join("existing-anchor.json");
        let sentinel = b"existing anchor must not be overwritten";
        std::fs::write(&existing_output, sentinel).unwrap();
        assert!(inspect_profile_audit(profile, passphrase, None, Some(&existing_output)).is_err());
        assert_eq!(std::fs::read(&existing_output).unwrap(), sentinel);

        let call_key = vault::derive_profile_call_key_with_lock_timeout(
            profile,
            passphrase,
            Some(identity),
            AUDIT_AUTHORIZATION_LOCK_TIMEOUT,
        )
        .unwrap();
        let ledger = AuditLedger::from_profile_call_key(
            &vault::run_dir().unwrap().join("audit"),
            identity,
            &call_key,
        )
        .unwrap();
        ledger
            .append(&AuditEvent {
                profile_id: hex::encode(identity.profile_id),
                profile_generation: identity.generation,
                request_id: [0x41_u8; 16],
                at_unix_ms: 1_900_800_000_000,
                operation_kind: "ssh.exec".to_owned(),
                phase: AuditPhase::Intent,
                decision: AuditDecision::Pending,
                policy_digest: hex::encode([0x42_u8; 32]),
                intent_digest: hex::encode([0x43_u8; 32]),
                result_digest: None,
                reason_code: "authorized".to_owned(),
            })
            .unwrap();
        assert_eq!(
            inspect_profile_audit(profile, passphrase, None, None)
                .unwrap()
                .pending_intents,
            1
        );
        assert!(resolve_profile_audit_as_unknown(profile, passphrase, None, None, false).is_err());
        let resolved =
            resolve_profile_audit_as_unknown(profile, passphrase, None, None, true).unwrap();
        assert_eq!(resolved.resolved_as_unknown, 1);
        assert_eq!(resolved.status.pending_intents, 0);
        let repeated =
            resolve_profile_audit_as_unknown(profile, passphrase, None, None, true).unwrap();
        assert_eq!(repeated.resolved_as_unknown, 0);
        assert_eq!(repeated.status, resolved.status);

        let mut corrupted = std::fs::read(ledger.log_path()).unwrap();
        corrupted[0] ^= 1;
        std::fs::write(ledger.log_path(), corrupted).unwrap();
        assert!(inspect_profile_audit(profile, passphrase, None, None).is_err());
    }

    #[test]
    fn anchor_reader_is_bounded_and_strict() {
        let path = temp_file("strict");
        let mut file = File::create(&path).unwrap();
        file.write_all(br#"{"schema_version":1}"#).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(read_anchor(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn acknowledgement_is_required_before_profile_or_ledger_access() {
        let error = resolve_profile_audit_as_unknown(
            "does-not-exist",
            "not-a-real-passphrase",
            None,
            None,
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("explicit acknowledgement"));
    }

    #[test]
    fn anchor_export_is_create_new_and_roundtrips() {
        let path = temp_file("export");
        let checkpoint = checkpoint();
        write_audit_anchor_create_new(&path, &checkpoint).unwrap();
        assert_eq!(read_anchor(&path).unwrap(), checkpoint);
        assert!(write_audit_anchor_create_new(&path, &checkpoint).is_err());
        assert_eq!(read_anchor(&path).unwrap(), checkpoint);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn partial_write_failure_rolls_back_create_new_anchor() {
        let path = temp_file("partial-write");
        let error = write_audit_anchor_create_new_with(
            &path,
            b"not-a-complete-anchor",
            |file, _| {
                file.write_all(b"partial")?;
                bail!("injected anchor write failure")
            },
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected anchor write failure"));
        assert!(!path.exists(), "partial anchor must be rolled back");
    }

    #[test]
    fn unwinding_writer_rolls_back_create_new_anchor() {
        let path = temp_file("writer-panic");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = write_audit_anchor_create_new_with(
                &path,
                b"not-a-complete-anchor",
                |file, _| {
                    file.write_all(b"partial")?;
                    panic!("injected anchor writer panic")
                },
                |_| Ok(()),
            );
        }));
        assert!(outcome.is_err());
        assert!(!path.exists(), "unwound anchor must be rolled back");
    }

    #[test]
    fn parent_sync_failure_rolls_back_persisted_anchor() {
        let path = temp_file("parent-sync");
        let error = write_audit_anchor_create_new_with(
            &path,
            b"complete-but-not-committed",
            |file, bytes| {
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            },
            |_| bail!("injected parent sync failure"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected parent sync failure"));
        assert!(!path.exists(), "uncommitted anchor must be rolled back");
    }

    #[test]
    fn replacement_created_during_rollback_sync_is_preserved_and_reported() {
        let path = temp_file("rollback-sync-replacement");
        let replacement = b"replacement-created-during-rollback-sync";
        let error = write_audit_anchor_create_new_with(
            &path,
            b"anchor-that-will-not-commit",
            |file, _| {
                file.write_all(b"partial")?;
                bail!("injected persistence failure")
            },
            |_| {
                let mut replacement_file = File::create(&path)?;
                replacement_file.write_all(replacement)?;
                replacement_file.sync_all()?;
                Ok(())
            },
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("rollback could not be proven durable"));
        assert!(message.contains("path_absent_after_sync="));
        assert_eq!(std::fs::read(&path).unwrap(), replacement);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn write_readback_mismatch_rolls_back_create_new_anchor() {
        let path = temp_file("readback-mismatch");
        let error = write_audit_anchor_create_new_with(
            &path,
            b"expected-anchor-bytes",
            |file, _| {
                file.write_all(b"different-anchor-byte")?;
                file.sync_all()?;
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("audit anchor write verification failed"));
        assert!(!path.exists(), "mismatched anchor must be rolled back");
    }

    #[test]
    fn replaced_output_is_rejected_without_removing_the_replacement() {
        let path = temp_file("replacement");
        let displaced = temp_file("replacement-displaced");
        let replacement = b"replacement-owned-by-another-writer";
        let error = write_audit_anchor_create_new_with(
            &path,
            b"authenticated-anchor-bytes",
            |file, bytes| {
                file.write_all(bytes)?;
                file.sync_all()?;
                std::fs::rename(&path, &displaced)?;
                let mut replacement_file = File::create(&path)?;
                replacement_file.write_all(replacement)?;
                replacement_file.sync_all()?;
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("audit anchor output was replaced while it was written"));
        assert!(message.contains("rollback could not be proven durable"));
        assert_eq!(std::fs::read(&path).unwrap(), replacement);

        std::fs::remove_file(&path).unwrap();
        if displaced.exists() {
            std::fs::remove_file(displaced).unwrap();
        }
    }

    #[test]
    fn replacement_during_parent_sync_is_rejected_and_preserved() {
        use std::cell::Cell;

        let path = temp_file("parent-sync-replacement");
        let displaced = temp_file("parent-sync-replacement-displaced");
        let replacement = b"replacement-created-during-parent-sync";
        let sync_calls = Cell::new(0_u8);
        let error = write_audit_anchor_create_new_with(
            &path,
            b"authenticated-anchor-bytes",
            |file, bytes| {
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            },
            |_| {
                let call = sync_calls.get();
                sync_calls.set(call.saturating_add(1));
                if call == 0 {
                    std::fs::rename(&path, &displaced)?;
                    let mut replacement_file = File::create(&path)?;
                    replacement_file.write_all(replacement)?;
                    replacement_file.sync_all()?;
                }
                Ok(())
            },
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("replaced while its parent was synchronized"));
        assert!(message.contains("rollback could not be proven durable"));
        assert_eq!(std::fs::read(&path).unwrap(), replacement);

        std::fs::remove_file(&path).unwrap();
        if displaced.exists() {
            std::fs::remove_file(displaced).unwrap();
        }
    }

    #[test]
    fn final_parent_identity_failure_rolls_back_create_new_anchor() {
        use std::cell::Cell;

        let path = temp_file("final-parent-identity");
        let parent_checks = Cell::new(0_u8);
        let error = write_audit_anchor_create_new_with_checks(
            &path,
            b"authenticated-anchor-bytes",
            |file, bytes| {
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            },
            |_| Ok(()),
            |_, _| {
                let check = parent_checks.get();
                parent_checks.set(check.saturating_add(1));
                if check == 2 {
                    bail!("injected final parent identity mismatch")
                }
                Ok(())
            },
        )
        .expect_err("export skipped its final parent identity check");

        assert_eq!(parent_checks.get(), 3);
        assert!(
            format!("{error:#}").contains("injected final parent identity mismatch"),
            "{error:#}"
        );
        assert!(!path.exists(), "uncommitted anchor must be rolled back");
    }

    #[cfg(unix)]
    #[test]
    fn parent_rebind_with_same_anchor_inode_cannot_report_export_success() {
        use std::cell::Cell;

        let root = temp_file("parent-rebind-same-inode-root");
        let parent = root.join("anchor-parent");
        let displaced_parent = root.join("anchor-parent-displaced");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("anchor.json");
        let displaced_path = displaced_parent.join("anchor.json");
        let sync_calls = Cell::new(0_u8);

        let error = write_audit_anchor_create_new_with(
            &path,
            b"authenticated-anchor-bytes",
            |file, bytes| {
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            },
            |_| {
                let call = sync_calls.get();
                sync_calls.set(call.saturating_add(1));
                if call == 0 {
                    std::fs::rename(&parent, &displaced_parent)?;
                    std::fs::create_dir(&parent)?;
                    std::fs::hard_link(&displaced_path, &path)?;
                }
                Ok(())
            },
        )
        .expect_err("a rebound parent with the same anchor inode was accepted");

        let message = format!("{error:#}");
        assert!(
            message.contains("parent directory entry changed during export"),
            "{message}"
        );
        assert!(
            message.contains("rollback could not be proven durable"),
            "{message}"
        );
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(&displaced_path).unwrap(),
            b"authenticated-anchor-bytes"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn renamed_output_cannot_be_reported_as_a_proven_rollback() {
        let path = temp_file("renamed");
        let displaced = temp_file("renamed-displaced");
        let error = write_audit_anchor_create_new_with(
            &path,
            b"authenticated-anchor-bytes",
            |file, bytes| {
                file.write_all(bytes)?;
                file.sync_all()?;
                std::fs::rename(&path, &displaced)?;
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("rollback could not be proven durable"));
        assert!(message.contains("remains linked"));
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(&displaced).unwrap(),
            b"authenticated-anchor-bytes"
        );
        std::fs::remove_file(displaced).unwrap();
    }

    #[test]
    fn concurrent_create_new_anchor_has_exactly_one_winner() {
        use std::sync::{Arc, Barrier};

        let path = Arc::new(temp_file("concurrent"));
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                write_audit_anchor_create_new(&path, &checkpoint())
            }));
        }
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert_eq!(read_anchor(&path).unwrap(), checkpoint());
        std::fs::remove_file(path.as_ref()).unwrap();
    }

    #[test]
    fn anchor_reader_rejects_empty_oversized_and_non_regular_paths() {
        let empty = temp_file("empty");
        File::create(&empty).unwrap();
        assert!(read_anchor(&empty).is_err());
        std::fs::remove_file(&empty).unwrap();

        let oversized = temp_file("oversized");
        let file = File::create(&oversized).unwrap();
        file.set_len(MAX_AUDIT_ANCHOR_BYTES + 1).unwrap();
        drop(file);
        assert!(read_anchor(&oversized).is_err());
        std::fs::remove_file(&oversized).unwrap();

        let directory = temp_file("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(read_anchor(&directory).is_err());
        assert!(write_audit_anchor_create_new(&directory, &checkpoint()).is_err());
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn anchor_reader_rejects_symlink_and_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let target = temp_file("symlink-target");
        write_audit_anchor_create_new(&target, &checkpoint()).unwrap();
        let link = temp_file("symlink");
        symlink(&target, &link).unwrap();
        assert!(read_anchor(&link).is_err());
        assert!(write_audit_anchor_create_new(&link, &checkpoint()).is_err());
        assert_eq!(read_anchor(&target).unwrap(), checkpoint());

        let fifo = temp_file("fifo");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(read_anchor(&fifo).is_err());
        assert!(write_audit_anchor_create_new(&fifo, &checkpoint()).is_err());

        std::fs::remove_file(fifo).unwrap();
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(target).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn anchor_reader_rejects_reparse_file_when_supported() {
        use std::os::windows::fs::symlink_file;

        let target = temp_file("reparse-target");
        write_audit_anchor_create_new(&target, &checkpoint()).unwrap();
        let link = temp_file("reparse");
        if symlink_file(&target, &link).is_ok() {
            assert!(read_anchor(&link).is_err());
            assert!(write_audit_anchor_create_new(&link, &checkpoint()).is_err());
            assert_eq!(read_anchor(&target).unwrap(), checkpoint());
            std::fs::remove_file(link).unwrap();
        }
        std::fs::remove_file(target).unwrap();
    }
}
