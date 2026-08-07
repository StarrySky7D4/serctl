//! Platform-specific protection for files containing credentials or IPC
//! capabilities. Security-sensitive persistence fails closed if permissions
//! cannot be tightened.

use anyhow::Result;
use std::path::Path;

#[cfg(unix)]
pub fn harden_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
pub fn harden_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
pub fn harden_directory(path: &Path) -> Result<()> {
    // OI/CI makes newly-created vault and lock files inherit this protected
    // DACL. OW is the actual object owner; SYSTEM and Administrators retain
    // recovery access.
    apply_protected_dacl(path, "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
}

#[cfg(windows)]
pub fn harden_file(path: &Path) -> Result<()> {
    apply_protected_dacl(path, "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
}

#[cfg(windows)]
fn apply_protected_dacl(path: &Path, sddl: &str) -> Result<()> {
    use anyhow::{anyhow, Context};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    let sddl_wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error()).context("convert serctl security descriptor");
    }

    let result = (|| {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = null_mut();
        let read = unsafe {
            GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
        };
        if read == 0 || present == 0 || dacl.is_null() {
            return Err(anyhow!("security descriptor did not contain a DACL"));
        }

        let mut path_wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let status = unsafe {
            SetNamedSecurityInfoW(
                path_wide.as_mut_ptr(),
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
                .with_context(|| format!("protect ACL for {}", path.display()));
        }
        Ok(())
    })();

    unsafe {
        LocalFree(descriptor);
    }
    result
}

#[cfg(not(any(unix, windows)))]
pub fn harden_directory(_path: &Path) -> Result<()> {
    anyhow::bail!("secure directory permissions are unsupported on this platform")
}

#[cfg(not(any(unix, windows)))]
pub fn harden_file(_path: &Path) -> Result<()> {
    anyhow::bail!("secure file permissions are unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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

        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
