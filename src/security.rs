//! Platform-specific protection for files containing credentials or IPC
//! capabilities. Security-sensitive persistence fails closed if permissions
//! cannot be tightened.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::path::Path;

/// Open an existing security-sensitive file without following a final-path
/// symlink/reparse point, tighten its permissions on that same object, and
/// return the stable handle. A missing path is the only condition mapped to
/// `None`.
pub fn open_existing_protected_file(path: &Path) -> Result<Option<File>> {
    match open_protected_file(path, false) {
        Ok(file) => Ok(Some(file)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Open or create a security-sensitive regular file and harden the exact
/// object represented by the returned handle.
pub fn open_or_create_protected_file(path: &Path) -> Result<File> {
    open_protected_file(path, true)
}

/// Atomically create a new security-sensitive regular file and return a
/// stable read/write handle to it. The file is owner-only from the instant it
/// is created; an existing path is never opened or modified.
pub fn create_new_protected_file(path: &Path) -> Result<File> {
    create_new_protected_file_with_validation(path, validate_new_protected_file)
}

/// Replace a security-sensitive file atomically and durably. On Unix,
/// `AtomicWriteFile::commit` syncs both the temporary file and its parent
/// directory. Windows uses an explicit write-through rename because the
/// generic `AtomicWriteFile` implementation only calls `fs::rename` there.
#[cfg(unix)]
pub fn write_protected_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    use atomic_write_file::AtomicWriteFile;
    use std::io::Write;

    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic temporary file for {}", path.display()))?;
    harden_open_file(file.as_file())?;
    file.write_all(contents)
        .with_context(|| format!("write atomic temporary file for {}", path.display()))?;
    file.commit()
        .with_context(|| format!("commit protected atomic file {}", path.display()))
}

#[cfg(windows)]
pub fn write_protected_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    write_protected_atomic_windows_with(path, contents, move_file_write_through)
}

#[cfg(not(any(unix, windows)))]
pub fn write_protected_atomic(_path: &Path, _contents: &[u8]) -> Result<()> {
    bail!("durable protected atomic writes are unsupported on this platform")
}

fn create_new_protected_file_with_validation<F>(path: &Path, validate: F) -> Result<File>
where
    F: FnOnce(&File) -> Result<()>,
{
    let file = create_new_protected_file_platform(path)?;
    // Arm rollback immediately after CREATE_NEW. This guard also runs while
    // unwinding, before the stable handle is closed, so an injected/future
    // validation panic cannot strand a ghost security-sensitive file.
    let rollback = CreatedFileRollback::new(path, file);
    match validate(rollback.file()) {
        Ok(()) => Ok(rollback.commit()),
        Err(validation_error) => rollback.fail(validation_error),
    }
}

struct CreatedFileRollback<'a> {
    path: &'a Path,
    file: Option<File>,
    armed: bool,
}

impl<'a> CreatedFileRollback<'a> {
    fn new(path: &'a Path, file: File) -> Self {
        Self {
            path,
            file: Some(file),
            armed: true,
        }
    }

    fn file(&self) -> &File {
        self.file
            .as_ref()
            .expect("armed created-file rollback must retain its handle")
    }

    fn commit(mut self) -> File {
        self.armed = false;
        self.file
            .take()
            .expect("committed created file must retain its handle")
    }

    fn fail(mut self, validation_error: anyhow::Error) -> Result<File> {
        let cleanup = remove_created_file_if_same(self.path, self.file());
        self.armed = false;
        drop(self.file.take());
        match cleanup {
            Ok(()) => Err(validation_error),
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "{validation_error:#}; remove newly-created file after validation failure: {cleanup_error}"
            )),
        }
    }
}

impl Drop for CreatedFileRollback<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_created_file_if_same(
                self.path,
                self.file
                    .as_ref()
                    .expect("armed created-file rollback must retain its handle"),
            );
        }
        drop(self.file.take());
    }
}

#[cfg(unix)]
fn remove_created_file_if_same(path: &Path, file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let expected = file.metadata()?;
    let actual = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        // Never unlink an obvious replacement. Unix has no portable unlink-by-
        // handle primitive, so the final identity-check-to-unlink interval is
        // protected by serctl's owner-only parent-directory boundary. Another
        // process running as the same UID already has equivalent authority to
        // rename/delete these objects and remains outside this local boundary.
        return Ok(());
    }
    std::fs::remove_file(path)
}

#[cfg(windows)]
fn remove_created_file_if_same(_path: &Path, file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    // Delete the exact kernel object represented by the still-open stable
    // handle. A concurrently replaced pathname is therefore never targeted.
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let succeeded = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as _,
            FileDispositionInfo,
            (&raw const disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn remove_created_file_if_same(path: &Path, _file: &File) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn create_new_protected_file_platform(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("create protected file {}", path.display()))
}

#[cfg(unix)]
fn validate_new_protected_file(file: &File) -> Result<()> {
    harden_open_file(file)
}

/// Open a source file for reading through a stable handle without changing
/// its permissions. Non-blocking open plus a handle-based type check prevents
/// FIFOs, devices, and directories from being accepted as regular input.
#[cfg(unix)]
pub fn open_regular_file_for_read(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    // Deliberately omit O_NOFOLLOW: ordinary symlinks to regular source files
    // are useful for upload and the final object is checked with fstat(2).
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open regular file for reading {}", path.display()))?;
    let metadata = file.metadata().context("inspect source file handle")?;
    if !metadata.file_type().is_file() {
        bail!("source path is not a regular file");
    }
    Ok(file)
}

#[cfg(windows)]
fn create_new_protected_file_platform(path: &Path) -> Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    // Supplying this protected DACL to CreateFileW is essential: creating with
    // inherited/default permissions and tightening it afterwards would expose
    // credentials during a real security window.
    let descriptor = LocalSecurityDescriptor::from_sddl(PROTECTED_FILE_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let raw = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("create protected file {}", path.display()));
    }
    Ok(unsafe { File::from_raw_handle(raw as _) })
}

#[cfg(windows)]
fn validate_new_protected_file(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;

    verify_regular_non_reparse_file(file, "protected path")?;
    verify_current_user_owns_handle(file.as_raw_handle() as _)?;
    verify_protected_dacl_on_handle(file.as_raw_handle() as _, PROTECTED_FILE_SDDL, "file")
}

#[cfg(windows)]
pub fn open_regular_file_for_read(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let file = OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("open regular file for reading {}", path.display()))?;
    verify_regular_non_reparse_file(&file, "source path")?;
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn create_new_protected_file_platform(_path: &Path) -> Result<File> {
    bail!("secure file creation is unsupported on this platform")
}

#[cfg(not(any(unix, windows)))]
fn validate_new_protected_file(_file: &File) -> Result<()> {
    bail!("secure file validation is unsupported on this platform")
}

#[cfg(not(any(unix, windows)))]
pub fn open_regular_file_for_read(_path: &Path) -> Result<File> {
    bail!("safe regular-file opening is unsupported on this platform")
}

#[cfg(unix)]
fn open_protected_file(path: &Path, create: bool) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(create)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .with_context(|| format!("open protected file {}", path.display()))?;
    harden_open_file(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn open_protected_file(path: &Path, create: bool) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        READ_CONTROL, WRITE_DAC,
    };

    let mut options = OpenOptions::new();
    let mut access = GENERIC_READ | READ_CONTROL | WRITE_DAC;
    if create {
        access |= GENERIC_WRITE;
    }
    options
        .read(true)
        .write(create)
        .create(create)
        .truncate(false)
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .with_context(|| format!("open protected file {}", path.display()))?;
    harden_open_file(&file)?;
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_protected_file(_path: &Path, _create: bool) -> Result<File> {
    bail!("secure file opening is unsupported on this platform")
}

#[cfg(windows)]
const PROTECTED_FILE_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

#[cfg(windows)]
const PROTECTED_DIRECTORY_SDDL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

#[cfg(windows)]
fn write_protected_atomic_windows_with<F>(path: &Path, contents: &[u8], move_file: F) -> Result<()>
where
    F: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    use std::io::Write;

    if path.file_name().is_none() {
        bail!("protected atomic destination has no file name");
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    // Keep the verified parent object open without FILE_SHARE_DELETE for the
    // whole transaction. This prevents its pathname from being renamed or
    // replaced between validation, temporary-file creation, and commit.
    let directory = open_verified_atomic_parent(parent)?;
    let mut temporary = create_protected_atomic_temporary(parent)?;
    temporary
        .file_mut()
        .write_all(contents)
        .with_context(|| format!("write protected atomic temporary for {}", path.display()))?;
    temporary
        .file()
        .sync_all()
        .with_context(|| format!("sync protected atomic temporary for {}", path.display()))?;

    let move_result = move_file(temporary.path(), path);
    match move_result {
        Ok(()) => {
            temporary.mark_moved();
            drop(directory);
            Ok(())
        }
        Err(move_error) => {
            let cleanup = temporary.remove();
            drop(directory);
            match cleanup {
                Ok(()) => Err(move_error).with_context(|| {
                    format!("write-through commit protected atomic file {}", path.display())
                }),
                Err(cleanup_error) => Err(anyhow::anyhow!(
                    "write-through commit protected atomic file {}: {}; remove protected atomic temporary after failed commit: {}",
                    path.display(),
                    move_error,
                    cleanup_error
                )),
            }
        }
    }
}

#[cfg(windows)]
fn open_verified_atomic_parent(path: &Path) -> Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    };

    let directory = OpenOptions::new()
        .read(true)
        .access_mode(READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("open protected atomic parent {}", path.display()))?;
    let metadata = directory
        .metadata()
        .context("inspect protected atomic parent handle")?;
    if !metadata.file_type().is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!("protected atomic parent is not a non-reparse directory");
    }
    verify_current_user_owns_handle(directory.as_raw_handle() as _)?;
    verify_protected_dacl_on_handle(
        directory.as_raw_handle() as _,
        PROTECTED_DIRECTORY_SDDL,
        "atomic parent directory",
    )?;
    Ok(directory)
}

#[cfg(windows)]
fn create_protected_atomic_temporary(parent: &Path) -> Result<ProtectedAtomicTemporary> {
    use rand::{rngs::OsRng, RngCore};

    for _ in 0..128 {
        let mut random = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .context("generate protected atomic temporary name")?;
        let path = parent.join(format!(
            ".serctl-atomic-{:032x}.tmp",
            u128::from_le_bytes(random)
        ));
        match create_new_protected_file(&path) {
            Ok(file) => return Ok(ProtectedAtomicTemporary::new(path, file)),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("create protected atomic temporary in {}", parent.display())
                });
            }
        }
    }
    bail!("could not allocate a unique protected atomic temporary file")
}

#[cfg(windows)]
fn move_file_write_through(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
struct ProtectedAtomicTemporary {
    path: std::path::PathBuf,
    file: Option<File>,
    armed: bool,
}

#[cfg(windows)]
impl ProtectedAtomicTemporary {
    fn new(path: std::path::PathBuf, file: File) -> Self {
        Self {
            path,
            file: Some(file),
            armed: true,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn file(&self) -> &File {
        self.file
            .as_ref()
            .expect("armed protected atomic temporary must retain its handle")
    }

    fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("armed protected atomic temporary must retain its handle")
    }

    fn mark_moved(mut self) {
        self.armed = false;
        drop(self.file.take());
    }

    fn remove(mut self) -> std::io::Result<()> {
        drop(self.file.take());
        self.armed = false;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[cfg(windows)]
impl Drop for ProtectedAtomicTemporary {
    fn drop(&mut self) {
        if self.armed {
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(windows)]
struct LocalSecurityDescriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl LocalSecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self> {
        use std::ptr::null_mut;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };

        let sddl_wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut descriptor = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("convert serctl file security descriptor");
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
fn verify_regular_non_reparse_file(file: &File, object_kind: &str) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {object_kind} handle"))?;
    if !metadata.file_type().is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!("{object_kind} is not a regular non-reparse file");
    }
    Ok(())
}

#[cfg(unix)]
pub fn harden_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open protected directory {}", path.display()))?;
    harden_open_directory(&directory)?;
    Ok(())
}

#[cfg(unix)]
fn harden_open_directory(directory: &File) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = directory
        .metadata()
        .context("inspect protected directory handle")?;
    if !metadata.file_type().is_dir() {
        bail!("protected directory path is not a directory");
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        bail!("protected directory is not owned by the current user");
    }
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .context("set protected directory mode")?;
    let hardened = directory
        .metadata()
        .context("verify protected directory mode")?;
    if !hardened.file_type().is_dir()
        || hardened.uid() != effective_uid
        || hardened.mode() & 0o7777 != 0o700
    {
        bail!("protected directory permissions could not be verified as owner-only 0700");
    }
    Ok(())
}

#[cfg(unix)]
pub fn harden_file(path: &Path) -> Result<()> {
    // This path-based compatibility helper also protects Unix-domain socket
    // nodes. Credential and lock files use the stable-handle APIs above.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
pub fn harden_open_file(file: &File) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = file.metadata().context("inspect protected file handle")?;
    if !metadata.file_type().is_file() {
        bail!("protected path is not a regular file");
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        bail!("protected file is not owned by the current user");
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .context("set protected file mode")?;
    let hardened = file.metadata().context("verify protected file mode")?;
    if !hardened.file_type().is_file() || hardened.mode() & 0o7777 != 0o600 {
        bail!("protected file permissions could not be verified as 0600");
    }
    Ok(())
}

#[cfg(windows)]
pub fn harden_directory(path: &Path) -> Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    let directory = OpenOptions::new()
        .read(true)
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("open protected directory {}", path.display()))?;
    let metadata = directory
        .metadata()
        .context("inspect protected directory handle")?;
    if !metadata.file_type().is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!("protected directory path is not a non-reparse directory");
    }
    verify_current_user_owns_handle(directory.as_raw_handle() as _)?;
    // OI/CI makes newly-created vault and lock files inherit this protected
    // DACL. SYSTEM and Administrators retain recovery access.
    apply_protected_dacl_to_handle(
        directory.as_raw_handle() as _,
        PROTECTED_DIRECTORY_SDDL,
        "directory",
    )
}

#[cfg(all(windows, test))]
pub fn harden_file(path: &Path) -> Result<()> {
    drop(open_protected_file(path, false)?);
    Ok(())
}

#[cfg(windows)]
pub fn harden_open_file(file: &File) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    let metadata = file.metadata().context("inspect protected file handle")?;
    if !metadata.file_type().is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!("protected path is not a regular non-reparse file");
    }

    // AtomicWriteFile's temporary handle need not have WRITE_DAC. ReOpenFile
    // obtains security rights to the same kernel file object, rather than
    // resolving the path again and reintroducing a replacement race.
    let raw = unsafe {
        ReOpenFile(
            file.as_raw_handle() as _,
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("reopen protected file handle");
    }
    let security_handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    verify_current_user_owns_handle(security_handle.as_raw_handle() as _)?;
    apply_protected_dacl_to_handle(
        security_handle.as_raw_handle() as _,
        "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
        "file",
    )
}

#[cfg(windows)]
fn owner_matches_token_sids(
    object_owner: windows_sys::Win32::Security::PSID,
    token_user: windows_sys::Win32::Security::PSID,
    token_default_owner: windows_sys::Win32::Security::PSID,
) -> bool {
    use windows_sys::Win32::Security::EqualSid;

    if object_owner.is_null() {
        return false;
    }
    (!token_user.is_null() && unsafe { EqualSid(object_owner, token_user) } != 0)
        || (!token_default_owner.is_null()
            && unsafe { EqualSid(object_owner, token_default_owner) } != 0)
}

#[cfg(windows)]
fn verify_current_user_owns_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<()> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenOwner, TokenUser, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut owner = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("read protected object owner");
    }

    let result = (|| {
        if descriptor.is_null() || owner.is_null() {
            bail!("protected object owner verification returned no owner SID");
        }

        let mut token_handle = null_mut();
        let opened =
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) };
        if opened == 0 {
            return Err(std::io::Error::last_os_error()).context("open current process token");
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token_handle as _) };

        let mut required = 0_u32;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle() as _,
                TokenUser,
                null_mut(),
                0,
                &mut required,
            );
        }
        if required < std::mem::size_of::<TOKEN_USER>() as u32 {
            bail!("current process token did not expose a user SID");
        }
        let word_size = std::mem::size_of::<usize>();
        let word_count = (required as usize).div_ceil(word_size);
        let mut token_buffer = vec![0_usize; word_count];
        let read = unsafe {
            GetTokenInformation(
                token.as_raw_handle() as _,
                TokenUser,
                token_buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        };
        if read == 0 {
            return Err(std::io::Error::last_os_error()).context("read current process user SID");
        }
        let token_user = unsafe { &*(token_buffer.as_ptr().cast::<TOKEN_USER>()) };
        if owner_matches_token_sids(owner, token_user.User.Sid, null_mut()) {
            return Ok(());
        }

        // Elevated Windows tokens commonly use BUILTIN\Administrators as
        // their default owner even though TokenUser remains the individual
        // account SID. Objects created by this exact token therefore need to
        // be accepted when their owner matches TokenOwner. This does not
        // broaden the administrator trust boundary: protected DACLs already
        // grant BUILTIN\Administrators and SYSTEM explicit recovery access.
        let mut owner_required = 0_u32;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle() as _,
                TokenOwner,
                null_mut(),
                0,
                &mut owner_required,
            );
        }
        if owner_required < std::mem::size_of::<TOKEN_OWNER>() as u32 {
            bail!("current process token did not expose a default owner SID");
        }
        let owner_word_count = (owner_required as usize).div_ceil(word_size);
        let mut owner_buffer = vec![0_usize; owner_word_count];
        let owner_read = unsafe {
            GetTokenInformation(
                token.as_raw_handle() as _,
                TokenOwner,
                owner_buffer.as_mut_ptr().cast(),
                owner_required,
                &mut owner_required,
            )
        };
        if owner_read == 0 {
            return Err(std::io::Error::last_os_error())
                .context("read current process default owner SID");
        }
        let token_owner = unsafe { &*(owner_buffer.as_ptr().cast::<TOKEN_OWNER>()) };
        if !owner_matches_token_sids(owner, token_user.User.Sid, token_owner.Owner) {
            bail!("protected object is not owned by the current user or token owner");
        }
        Ok(())
    })();

    unsafe {
        LocalFree(descriptor);
    }
    result
}

#[cfg(windows)]
fn apply_protected_dacl_to_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
    sddl: &str,
    object_kind: &str,
) -> Result<()> {
    use anyhow::anyhow;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let descriptor = LocalSecurityDescriptor::from_sddl(sddl)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    let read =
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) };
    if read == 0 || present == 0 || dacl.is_null() {
        return Err(anyhow!("security descriptor did not contain a DACL"));
    }

    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .with_context(|| format!("protect ACL for {object_kind} handle"));
    }
    verify_protected_dacl_on_handle(handle, sddl, object_kind)
}

#[cfg(windows)]
fn verify_protected_dacl_on_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
    sddl: &str,
    object_kind: &str,
) -> Result<()> {
    use anyhow::anyhow;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };

    let expected = LocalSecurityDescriptor::from_sddl(sddl)?;
    let mut expected_present = 0;
    let mut expected_defaulted = 0;
    let mut expected_dacl = null_mut();
    let read = unsafe {
        GetSecurityDescriptorDacl(
            expected.0,
            &mut expected_present,
            &mut expected_dacl,
            &mut expected_defaulted,
        )
    };
    if read == 0 || expected_present == 0 || expected_dacl.is_null() {
        return Err(anyhow!("security descriptor did not contain a DACL"));
    }

    let mut actual_dacl = null_mut();
    let mut actual_descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut actual_dacl,
            null_mut(),
            &mut actual_descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .with_context(|| format!("read back protected {object_kind} ACL"));
    }

    let result = (|| {
        if actual_descriptor.is_null() || actual_dacl.is_null() {
            bail!("protected {object_kind} ACL verification returned no DACL");
        }
        let mut control = 0_u16;
        let mut revision = 0_u32;
        let read =
            unsafe { GetSecurityDescriptorControl(actual_descriptor, &mut control, &mut revision) };
        if read == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("inspect protected {object_kind} ACL control flags"));
        }
        if control & SE_DACL_PROTECTED == 0 {
            bail!("protected {object_kind} ACL did not remain inheritance-protected");
        }
        let expected_size = unsafe { (*expected_dacl).AclSize as usize };
        let actual_size = unsafe { (*actual_dacl).AclSize as usize };
        let expected_bytes =
            unsafe { std::slice::from_raw_parts(expected_dacl.cast::<u8>(), expected_size) };
        let actual_bytes =
            unsafe { std::slice::from_raw_parts(actual_dacl.cast::<u8>(), actual_size) };
        if expected_bytes != actual_bytes {
            bail!("protected {object_kind} ACL did not match the required owner-only descriptor");
        }
        Ok(())
    })();
    unsafe {
        LocalFree(actual_descriptor);
    }
    result
}

#[cfg(not(any(unix, windows)))]
pub fn harden_directory(_path: &Path) -> Result<()> {
    anyhow::bail!("secure directory permissions are unsupported on this platform")
}

#[cfg(all(not(any(unix, windows)), test))]
pub fn harden_file(_path: &Path) -> Result<()> {
    anyhow::bail!("secure file permissions are unsupported on this platform")
}

#[cfg(not(any(unix, windows)))]
pub fn harden_open_file(_file: &File) -> Result<()> {
    anyhow::bail!("secure file permissions are unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_directory(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("{prefix}-{}-{unique}", std::process::id()))
    }

    #[cfg(windows)]
    #[test]
    fn windows_owner_check_accepts_user_or_token_default_owner_only() {
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

        struct LocalSid(windows_sys::Win32::Security::PSID);
        impl Drop for LocalSid {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        fn sid(value: &str) -> LocalSid {
            let wide = value.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let mut parsed = null_mut();
            let converted = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut parsed) };
            assert_ne!(converted, 0, "failed to parse test SID {value}");
            assert!(!parsed.is_null());
            LocalSid(parsed)
        }

        let user = sid("S-1-5-18");
        let default_owner = sid("S-1-5-32-544");
        let unrelated = sid("S-1-5-19");

        assert!(owner_matches_token_sids(user.0, user.0, default_owner.0));
        assert!(owner_matches_token_sids(
            default_owner.0,
            user.0,
            default_owner.0
        ));
        assert!(!owner_matches_token_sids(
            unrelated.0,
            user.0,
            default_owner.0
        ));
    }

    #[test]
    fn protected_create_is_atomic_hardened_and_preserves_collisions() {
        let directory = unique_test_directory("protected-create-new");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secret.json");

        let mut handle = create_new_protected_file(&path).unwrap();
        handle.write_all(b"original secret").unwrap();
        handle.sync_all().unwrap();
        assert!(handle.metadata().unwrap().file_type().is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = handle.metadata().unwrap();
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            verify_current_user_owns_handle(handle.as_raw_handle() as _).unwrap();
            verify_protected_dacl_on_handle(
                handle.as_raw_handle() as _,
                PROTECTED_FILE_SDDL,
                "test file",
            )
            .unwrap();
        }
        drop(handle);

        let collision = create_new_protected_file(&path).unwrap_err();
        assert_eq!(
            collision
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"original secret");

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn protected_create_removes_its_file_when_post_creation_validation_fails() {
        let directory = unique_test_directory("protected-create-post-validation");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("must-not-survive");

        let error = create_new_protected_file_with_validation(&path, |file| {
            // Exercise the real platform validation before injecting a later
            // failure, matching a future hardening/read-back step failing
            // after CREATE_NEW has already installed the pathname.
            validate_new_protected_file(file)?;
            bail!("injected post-creation validation failure")
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("injected post-creation validation failure"));
        assert!(!path.exists(), "failed secure create left a ghost file");
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn protected_create_rollback_runs_during_validation_unwind() {
        let directory = unique_test_directory("protected-create-validation-unwind");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("must-not-survive");

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = create_new_protected_file_with_validation(&path, |file| {
                validate_new_protected_file(file)?;
                panic!("injected validation unwind");
            });
        }));

        assert!(unwind.is_err(), "injected validator did not unwind");
        assert!(!path.exists(), "validation unwind left a ghost file");
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn protected_create_rollback_preserves_a_replacement_path() {
        let directory = unique_test_directory("protected-create-replacement");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("created");
        let moved = directory.join("created-moved");

        let error = create_new_protected_file_with_validation(&path, |file| {
            validate_new_protected_file(file)?;
            std::fs::rename(&path, &moved)?;
            std::fs::write(&path, b"replacement owned by another operation")?;
            bail!("injected validation failure after replacement")
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("injected validation failure after replacement"));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"replacement owned by another operation"
        );
        std::fs::remove_file(path).unwrap();
        if moved.exists() {
            // Unix cannot portably unlink by handle; a same-UID actor that
            // renames the object during the documented identity/unlink trust
            // interval can retain this moved name. Windows handle deletion
            // removes the exact moved object when the guard closes it.
            std::fs::remove_file(moved).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn regular_source_open_succeeds_without_changing_permissions() {
        let directory = unique_test_directory("regular-source-open");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("source.bin");
        std::fs::write(&path, b"source data").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }

        let handle = open_regular_file_for_read(&path).unwrap();
        assert!(handle.metadata().unwrap().file_type().is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                handle.metadata().unwrap().permissions().mode() & 0o7777,
                0o640
            );
        }
        drop(handle);

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn regular_source_open_rejects_fifo_and_directory_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, Instant};

        let directory = unique_test_directory("regular-source-special");
        std::fs::create_dir_all(&directory).unwrap();
        let fifo = directory.join("fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        let status = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
        assert_eq!(
            status,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let started = Instant::now();
        let fifo_error = open_regular_file_for_read(&fifo).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(fifo_error.to_string().contains("regular file"));

        let started = Instant::now();
        let directory_error = open_regular_file_for_read(&directory).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(directory_error.to_string().contains("regular file"));

        std::fs::remove_file(fifo).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn regular_source_open_follows_symlink_to_regular_file() {
        use std::os::unix::fs::symlink;

        let directory = unique_test_directory("regular-source-link");
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target");
        let link = directory.join("link");
        std::fs::write(&target, b"source data").unwrap();
        symlink(&target, &link).unwrap();

        let handle = open_regular_file_for_read(&link).unwrap();
        assert!(handle.metadata().unwrap().file_type().is_file());
        drop(handle);

        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(target).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn hardening_succeeds_for_new_directory_and_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("security-test-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        harden_directory(&directory).unwrap();

        let file = directory.join("secret.json");
        std::fs::write(&file, b"test").unwrap();
        harden_file(&file).unwrap();
        assert!(file.is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }

        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn protected_atomic_write_propagates_injected_commit_failure_and_cleans_up() {
        let directory = unique_test_directory("protected-atomic-injected-failure");
        std::fs::create_dir_all(&directory).unwrap();
        harden_directory(&directory).unwrap();
        let path = directory.join("secret.json");
        std::fs::write(&path, b"old secret").unwrap();

        let error = write_protected_atomic_windows_with(&path, b"new secret", |_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected write-through commit failure",
            ))
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("injected write-through commit failure"));
        assert_eq!(std::fs::read(&path).unwrap(), b"old secret");
        assert_eq!(
            std::fs::read_dir(&directory).unwrap().count(),
            1,
            "failed atomic commit left a credential-bearing temporary file"
        );

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn protected_atomic_write_through_move_succeeds_on_windows() {
        let directory = unique_test_directory("protected-atomic-write-through");
        std::fs::create_dir_all(&directory).unwrap();
        harden_directory(&directory).unwrap();
        let path = directory.join("secret.json");
        std::fs::write(&path, b"old secret").unwrap();

        write_protected_atomic(&path, b"new secret").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new secret");
        let committed = open_existing_protected_file(&path).unwrap().unwrap();
        validate_new_protected_file(&committed).unwrap();
        drop(committed);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn protected_open_uses_one_regular_file_handle() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("protected-open-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secret.json");
        std::fs::write(&path, b"secret").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        }

        let handle = open_existing_protected_file(&path).unwrap().unwrap();
        assert!(handle.metadata().unwrap().file_type().is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                handle.metadata().unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }

        drop(handle);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn protected_open_rejects_symlink_and_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("protected-special-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target");
        let link = directory.join("link");
        let fifo = directory.join("fifo");
        std::fs::write(&target, b"secret").unwrap();
        symlink(&target, &link).unwrap();

        let link_error = open_existing_protected_file(&link).unwrap_err();
        assert!(link_error.to_string().contains("open protected file"));

        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        let status = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
        assert_eq!(
            status,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
        let fifo_error = open_existing_protected_file(&fifo).unwrap_err();
        assert!(fifo_error.to_string().contains("regular file"));

        std::fs::remove_file(fifo).unwrap();
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(target).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn protected_directory_rejects_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "protected-directory-link-{}-{unique}",
                std::process::id()
            ));
        let target = parent.join("target");
        let link = parent.join("link");
        std::fs::create_dir_all(&target).unwrap();
        symlink(&target, &link).unwrap();

        let error = harden_directory(&link).unwrap_err();
        assert!(error.to_string().contains("open protected directory"));

        std::fs::remove_file(link).unwrap();
        std::fs::remove_dir(target).unwrap();
        std::fs::remove_dir(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn protected_open_rejects_file_reparse_points_when_creation_is_available() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("protected-reparse-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target");
        let link = directory.join("link");
        std::fs::write(&target, b"secret").unwrap();
        match symlink_file(&target, &link) {
            Ok(()) => {
                let error = open_existing_protected_file(&link).unwrap_err();
                assert!(error.to_string().contains("non-reparse"));
                let source_error = open_regular_file_for_read(&link).unwrap_err();
                assert!(source_error.to_string().contains("non-reparse"));
                std::fs::remove_file(&link).unwrap();
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(1314) =>
            {
                // Windows symlink creation needs Developer Mode or the
                // SeCreateSymbolicLink privilege. The production rejection
                // still compiles and is exercised on capable CI workers.
                eprintln!("skipping file-reparse branch: symlink privilege unavailable");
            }
            Err(error) => panic!("create test symlink: {error}"),
        }
        std::fs::remove_file(target).unwrap();

        let directory_target = directory.join("directory-target");
        let directory_link = directory.join("directory-link");
        std::fs::create_dir(&directory_target).unwrap();
        match symlink_dir(&directory_target, &directory_link) {
            Ok(()) => {
                let error = harden_directory(&directory_link).unwrap_err();
                assert!(error.to_string().contains("non-reparse"));
                std::fs::remove_dir(&directory_link).unwrap();
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(1314) =>
            {
                eprintln!("skipping directory-reparse branch: symlink privilege unavailable");
            }
            Err(error) => panic!("create test directory symlink: {error}"),
        }
        std::fs::remove_dir(directory_target).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn regular_source_open_rejects_directory_and_device() {
        let directory = unique_test_directory("regular-source-windows-special");
        std::fs::create_dir_all(&directory).unwrap();

        assert!(open_regular_file_for_read(&directory).is_err());
        assert!(open_regular_file_for_read(&directory.join("NUL")).is_err());

        std::fs::remove_dir(directory).unwrap();
    }
}
