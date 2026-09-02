#![cfg(windows)]

use std::io::{Seek, SeekFrom, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Command, Stdio};
use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};

#[test]
fn agent_consumes_an_inherited_grant_handle_without_reopening_a_path() {
    let unique = format!(
        "serctl-inherited-child-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    let mut grant = serctl_core::security::create_new_protected_file(&path).unwrap();
    let secret_marker = "child-only-grant-secret-marker";
    grant.write_all(secret_marker.as_bytes()).unwrap();
    grant.seek(SeekFrom::Start(0)).unwrap();
    let raw = grant.as_raw_handle() as usize;
    assert_ne!(
        unsafe {
            SetHandleInformation(
                grant.as_raw_handle() as _,
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            )
        },
        0
    );

    // Piped stdio makes CreateProcess inherit the explicitly inheritable
    // object. The child receives only its non-secret numeric HANDLE in argv.
    let output = Command::new(env!("CARGO_BIN_EXE_serctl_cli"))
        .args(["agent", "--grant-handle", &raw.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    drop(grant);
    std::fs::remove_file(path).unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("parse agent grant file"), "{stderr}");
    assert!(!stderr.contains(secret_marker));
    assert!(!stderr.contains(&raw.to_string()));
}
