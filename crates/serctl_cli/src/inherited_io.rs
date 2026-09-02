//! Bounded, single-consumption access to objects inherited from a caller.
//!
//! The numeric descriptor/handle is intentionally the only argv material.
//! Converting it to `File` transfers ownership to this process: every success
//! and error path closes the inherited object exactly once, and no path is
//! resolved or reopened.

use anyhow::{bail, ensure, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, Write};
use zeroize::Zeroizing;

pub const MAX_PROFILE_PASSPHRASE_BYTES: usize = 16 * 1024;

fn parse_numeric_object(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("inherited object identifier is not a valid decimal integer"))
}

#[cfg(unix)]
fn take_file(value: &str) -> Result<File> {
    use std::os::fd::FromRawFd;

    let raw = i32::try_from(parse_numeric_object(value)?).map_err(|_| {
        anyhow::anyhow!("inherited object identifier is outside the platform range")
    })?;
    // Never let a secret-source argument consume the process control streams.
    ensure!(
        raw > libc::STDERR_FILENO,
        "inherited object identifier is reserved"
    );
    let valid = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if valid == -1 {
        bail!("inherited object is not open in this process");
    }
    // SAFETY: F_GETFD established that this descriptor is open. The API
    // contract transfers its sole ownership to serctl at this point.
    Ok(unsafe { File::from_raw_fd(raw) })
}

#[cfg(windows)]
fn take_file(value: &str) -> Result<File> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GetHandleInformation, INVALID_HANDLE_VALUE};

    let raw = usize::try_from(parse_numeric_object(value)?).map_err(|_| {
        anyhow::anyhow!("inherited object identifier is outside the platform range")
    })?;
    ensure!(
        raw != 0 && raw != INVALID_HANDLE_VALUE as usize,
        "inherited object identifier is reserved"
    );
    let mut flags = 0u32;
    if unsafe { GetHandleInformation(raw as _, &mut flags) } == 0 {
        bail!("inherited object is not open in this process");
    }
    // SAFETY: GetHandleInformation established that this HANDLE is live. The
    // API contract transfers its sole ownership to serctl at this point.
    Ok(unsafe { File::from_raw_handle(raw as _) })
}

#[cfg(not(any(unix, windows)))]
fn take_file(_value: &str) -> Result<File> {
    bail!("inherited objects are unsupported on this platform")
}

pub fn read_bounded(value: &str, maximum: usize, kind: &'static str) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = take_file(value)?;
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read inherited {kind}"))?;
    ensure!(
        bytes.len() <= maximum,
        "inherited {kind} exceeds its safety limit"
    );
    Ok(bytes)
}

pub fn read_profile_passphrase(value: &str) -> Result<Zeroizing<String>> {
    let mut bytes = read_bounded(value, MAX_PROFILE_PASSPHRASE_BYTES, "profile passphrase")?;
    if bytes.ends_with(b"\r\n") {
        let new_len = bytes.len() - 2;
        bytes.truncate(new_len);
    } else if bytes.ends_with(b"\n") {
        let new_len = bytes.len() - 1;
        bytes.truncate(new_len);
    }
    ensure!(!bytes.is_empty(), "profile passphrase is required");
    ensure!(
        !bytes
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n')),
        "inherited profile passphrase contains a forbidden line delimiter"
    );
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("inherited profile passphrase is not valid UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn take_output_file(value: &str) -> Result<File> {
    let mut file = take_file(value)?;
    serctl_core::security::harden_open_file(&file)
        .context("validate inherited grant output object")?;
    let metadata = file
        .metadata()
        .context("inspect inherited grant output object")?;
    ensure!(
        metadata.is_file(),
        "inherited grant output is not a regular file"
    );
    ensure!(metadata.len() == 0, "inherited grant output is not empty");
    ensure!(
        file.stream_position()
            .context("inspect inherited grant output position")?
            == 0,
        "inherited grant output is not positioned at its beginning"
    );
    Ok(file)
}

pub fn write_all_durable(mut file: File, bytes: &[u8]) -> Result<()> {
    file.write_all(bytes)
        .context("write inherited grant output")?;
    file.flush().context("flush inherited grant output")?;
    file.sync_all().context("sync inherited grant output")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::SeekFrom;

    fn temporary_file() -> (std::path::PathBuf, File) {
        let unique = format!(
            "serctl-inherited-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        let file = serctl_core::security::create_new_protected_file(&path).unwrap();
        (path, file)
    }

    #[cfg(unix)]
    fn pipe_reader_with(bytes: &[u8]) -> String {
        use std::os::fd::{FromRawFd, IntoRawFd};
        let mut descriptors = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let reader = unsafe { File::from_raw_fd(descriptors[0]) };
        let mut writer = unsafe { File::from_raw_fd(descriptors[1]) };
        writer.write_all(bytes).unwrap();
        drop(writer);
        reader.into_raw_fd().to_string()
    }

    #[cfg(windows)]
    fn pipe_reader_with(bytes: &[u8]) -> String {
        use std::os::windows::io::{FromRawHandle, IntoRawHandle};
        use windows_sys::Win32::System::Pipes::CreatePipe;

        let mut reader = std::ptr::null_mut();
        let mut writer = std::ptr::null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null(), 0) },
            0
        );
        let reader = unsafe { File::from_raw_handle(reader as _) };
        let mut writer = unsafe { File::from_raw_handle(writer as _) };
        writer.write_all(bytes).unwrap();
        drop(writer);
        (reader.into_raw_handle() as usize).to_string()
    }

    #[test]
    fn profile_passphrase_consumes_anonymous_pipe_to_eof() {
        let value = pipe_reader_with(b"pipe secret\n");
        assert_eq!(
            read_profile_passphrase(&value).unwrap().as_str(),
            "pipe secret"
        );
        let error = read_profile_passphrase(&value).unwrap_err().to_string();
        assert!(!error.contains(&value));
    }

    #[test]
    fn profile_passphrase_strips_one_line_ending_and_rejects_embedded_lines() {
        let (path, mut file) = temporary_file();
        file.write_all(b"correct horse\r\n").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let value = raw_file_value(file);
        assert_eq!(
            read_profile_passphrase(&value).unwrap().as_str(),
            "correct horse"
        );
        std::fs::remove_file(path).unwrap();

        let (path, mut file) = temporary_file();
        file.write_all(b"first\nsecond").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let value = raw_file_value(file);
        assert!(read_profile_passphrase(&value).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn profile_passphrase_is_bounded_and_identifier_errors_do_not_echo_value() {
        let error = read_profile_passphrase("not-a-handle")
            .unwrap_err()
            .to_string();
        assert!(!error.contains("not-a-handle"));

        let (path, mut file) = temporary_file();
        file.write_all(&vec![b'x'; MAX_PROFILE_PASSPHRASE_BYTES + 1])
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let value = raw_file_value(file);
        assert!(read_profile_passphrase(&value).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn inherited_output_requires_empty_start_and_writes_same_object() {
        let (path, file) = temporary_file();
        let observer = file.try_clone().unwrap();
        let value = raw_file_value(file);
        let output = take_output_file(&value).unwrap();
        write_all_durable(output, b"grant").unwrap();
        let mut observer = observer;
        observer.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        observer.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"grant");
        drop(observer);
        std::fs::remove_file(path).unwrap();

        let (path, mut nonempty) = temporary_file();
        nonempty.write_all(b"occupied").unwrap();
        nonempty.seek(SeekFrom::Start(0)).unwrap();
        let value = raw_file_value(nonempty);
        assert!(take_output_file(&value).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    fn raw_file_value(file: File) -> String {
        use std::os::fd::IntoRawFd;
        file.into_raw_fd().to_string()
    }

    #[cfg(windows)]
    fn raw_file_value(file: File) -> String {
        use std::os::windows::io::IntoRawHandle;
        (file.into_raw_handle() as usize).to_string()
    }
}
