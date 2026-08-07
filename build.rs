use std::process::Command;

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let mut commit = git_output(&["rev-parse", "--short=12", "HEAD"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let clean = Command::new("git")
        .args(["diff", "--quiet", "--ignore-submodules", "HEAD", "--"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !clean {
        commit.push_str("-dirty");
    }
    println!("cargo:rustc-env=SERCTL_BUILD_COMMIT={commit}");
}
