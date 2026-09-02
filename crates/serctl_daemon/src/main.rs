//! serctl_daemon entry point.
//!
//! The CLI never passes secrets through argv or the environment: it spawns
//! this binary with `--profile NAME` and writes the profile passphrase as one
//! length-framed bootstrap frame to the inherited stdin pipe. The frame is
//! read before any other work, held in a zeroizing buffer, and dropped as
//! soon as the runtime takes ownership.

use anyhow::{bail, Context, Result};
use std::io::Read as _;
use zeroize::{Zeroize, Zeroizing};

const BOOTSTRAP_FRAME_MAGIC: &[u8; 4] = b"SD01";
const MAX_BOOTSTRAP_PASSPHRASE_BYTES: usize = 4096;

fn main() {
    if let Err(error) = try_main() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let raw_args: Vec<_> = std::env::args_os().skip(1).collect();
    if raw_args.as_slice() == [std::ffi::OsStr::new("--version")] {
        println!("{}", daemon_version_line());
        return Ok(());
    }
    let mut profile: Option<String> = None;
    let mut global_instance: Option<String> = None;
    let mut expected_generation: Option<serctl_core::vault::ProfileIdentity> = None;
    let mut args = raw_args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg
            .to_str()
            .context("daemon arguments must be valid UTF-8")?
            .to_owned();
        match arg.as_str() {
            "--profile" => {
                profile = Some(
                    args.next()
                        .context("--profile requires a value")?
                        .to_str()
                        .context("profile name must be valid UTF-8")?
                        .to_owned(),
                );
            }
            "--global-instance" => {
                global_instance = Some(
                    args.next()
                        .context("--global-instance requires a value")?
                        .to_str()
                        .context("instance id must be valid UTF-8")?
                        .to_owned(),
                );
            }
            "--expected-generation" => {
                let raw = args
                    .next()
                    .context("--expected-generation requires a value")?
                    .to_str()
                    .context("generation must be valid UTF-8")?
                    .to_owned();
                let mut split = raw.splitn(2, ':');
                let hex_id = split.next().unwrap_or_default();
                let generation: u64 = split
                    .next()
                    .context("generation must use PROFILEID_HEX:GENERATION form")?
                    .parse()
                    .context("generation must be a number")?;
                let decoded = hex::decode(hex_id).context("profile id must be hex")?;
                let profile_id: [u8; 16] = decoded
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("profile id must decode to 16 bytes"))?;
                expected_generation = Some(serctl_core::vault::ProfileIdentity {
                    profile_id,
                    generation,
                });
            }
            other => bail!("unknown daemon argument: {other}"),
        }
    }
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"));
    let _ = logger.try_init();

    // Global per-user/per-vault mode: the launcher generates the instance id
    // (argv, non-secret) and the activation secret (stdin bootstrap frame).
    if let Some(instance_hex) = global_instance {
        bail_on_incompatible(&profile, &expected_generation)?;
        let instance = serctl_protocol::v6::InstanceId::from_hex(&instance_hex)?;
        let secret = read_secret_bootstrap_frame()?;
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(serctl_daemon::daemon::run_global(
                instance,
                secret,
                env!("SERCTL_BUILD_COMMIT").to_owned(),
            ));
    }

    let profile = profile.context("missing required --profile argument")?;
    serctl_core::vault::validate_profile_name(&profile)?;

    let master = read_bootstrap_frame()?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            match expected_generation {
                None => serctl_daemon::daemon::run(&profile, master).await,
                Some(generation) => {
                    serctl_daemon::daemon::run_with_ready_until_at_generation(
                        &profile,
                        master,
                        None,
                        generation,
                        tokio::time::Instant::now() + serctl_daemon::daemon::CONTROL_SETUP_TIMEOUT,
                    )
                    .await
                }
            }
        })
}

fn daemon_version_line() -> String {
    let version = serctl_protocol::v6::IPC_PROTOCOL_VERSION_V9;
    format!(
        "serctl_daemon {} (git {}; IPC v{}..=v{}; {})",
        env!("CARGO_PKG_VERSION"),
        env!("SERCTL_BUILD_COMMIT"),
        version,
        version,
        serctl_core::vault::VAULT_STORAGE_VERSION_CONTRACT
    )
}

fn bail_on_incompatible(
    profile: &Option<String>,
    expected_generation: &Option<serctl_core::vault::ProfileIdentity>,
) -> Result<()> {
    if profile.is_some() || expected_generation.is_some() {
        bail!("--global-instance cannot be combined with per-profile daemon arguments");
    }
    Ok(())
}

/// Read one bootstrap frame from the inherited stdin pipe: magic, 32-bit
/// little-endian length, payload. Fails closed on any truncation or extra
/// data so a malformed launcher can never half-authenticate a profile.
fn read_bootstrap_frame() -> Result<Zeroizing<String>> {
    let payload = read_bootstrap_payload(MAX_BOOTSTRAP_PASSPHRASE_BYTES, BOOTSTRAP_FRAME_MAGIC)?;
    let master = std::str::from_utf8(&payload)
        .context("daemon bootstrap passphrase is not valid UTF-8")?
        .to_owned();
    Ok(Zeroizing::new(master))
}

/// Read the v6 global-mode bootstrap frame carrying the activation secret.
fn read_secret_bootstrap_frame() -> Result<serctl_protocol::v6::ActivationSecret> {
    let payload = read_bootstrap_payload(128, SECRET_FRAME_MAGIC)?;
    let encoded = std::str::from_utf8(&payload)
        .context("daemon activation secret is not valid UTF-8")?
        .trim();
    serctl_protocol::v6::ActivationSecret::from_base64(encoded)
}

const SECRET_FRAME_MAGIC: &[u8; 4] = b"SD02";

fn read_bootstrap_payload(max_bytes: usize, magic: &[u8; 4]) -> Result<Zeroizing<Vec<u8>>> {
    let mut stdin = std::io::stdin();
    let mut header = [0_u8; 8];
    stdin
        .read_exact(&mut header)
        .context("read daemon bootstrap header from the launcher pipe")?;
    let mut header = Zeroizing::new(header);
    if &header[..4] != magic {
        bail!("daemon bootstrap frame has an unexpected magic value");
    }
    let length = u32::from_le_bytes(header[4..8].try_into().expect("fixed-size header")) as usize;
    header.zeroize();
    if !(1..=max_bytes).contains(&length) {
        bail!("daemon bootstrap payload length {length} is out of range");
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    stdin
        .read_exact(&mut payload)
        .context("read daemon bootstrap payload from the launcher pipe")?;
    let mut trailing = [0_u8; 1];
    match stdin.read(&mut trailing) {
        Ok(0) | Err(_) => {}
        Ok(_) => bail!("daemon bootstrap frame has trailing data"),
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::daemon_version_line;

    #[test]
    fn version_reports_build_identity_and_supported_ipc_range() {
        let line = daemon_version_line();
        assert_eq!(
            line,
            format!(
                "serctl_daemon {} (git {}; IPC v9..=v9; {})",
                env!("CARGO_PKG_VERSION"),
                env!("SERCTL_BUILD_COMMIT"),
                serctl_core::vault::VAULT_STORAGE_VERSION_CONTRACT
            )
        );
    }
}
