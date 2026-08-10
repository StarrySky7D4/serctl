//! serctl — persistent SSH control suite.
//!
//! Encrypted credential vault + long-lived connection daemon + local IPC so
//! every `exec`/`shell` reuses one authenticated SSH session without re-exposing
//! the password on the command line.
mod client;
mod daemon;
mod ipc;
mod security;
mod ssh;
mod ui;
mod vault;

#[cfg(test)]
mod e2e_tests;

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const CLI_FAILURE_EXIT_CODE: i32 = 1;

const BUILD_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("SERCTL_BUILD_COMMIT"),
    ")"
);

#[derive(Parser)]
#[command(
    name = "serctl",
    version = BUILD_VERSION,
    long_version = BUILD_VERSION,
    about = "Persistent SSH control suite: encrypted creds + long-lived daemon + IPC"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open the Winit-based desktop workspace (also the default with no command).
    Ui,
    /// Add or update a profile (password + master passphrase are read interactively).
    Add {
        name: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value_t = 22)]
        port: u16,
    },
    /// List saved profiles (host/port only — secrets stay sealed).
    List,
    /// Remove a profile.
    Remove { name: String },
    /// Start the connection daemon for a profile (foreground; Ctrl-C to stop).
    Up { name: Option<String> },
    /// Run a remote command (reuses the daemon if up, otherwise direct connect).
    Exec {
        name: String,
        /// Hard deadline for the remote command.
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    /// Upload a local file without overwriting an existing remote file.
    Upload {
        name: String,
        local: PathBuf,
        remote: String,
        /// Hard deadline for the complete SFTP operation.
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
    },
    /// Download a remote file without overwriting an existing local file.
    Download {
        name: String,
        remote: String,
        local: PathBuf,
        /// Hard deadline for the complete SFTP operation.
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
    },
    /// Open an interactive PTY shell (reuses the daemon if up).
    Shell { name: Option<String> },
    /// Show daemon status.
    Status { name: Option<String> },
    /// Stop a running daemon.
    Down { name: Option<String> },
}

fn nm(n: Option<String>) -> String {
    n.unwrap_or_else(|| "default".to_string())
}

fn prompt(label: &'static str) -> Result<String> {
    use std::io::Write;
    print!("{label}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let value = s.trim().to_string();
    s.zeroize();
    Ok(value)
}

#[derive(Default)]
struct StartupSecrets {
    ssh_password: Option<Zeroizing<String>>,
    master: Option<Zeroizing<String>>,
}

type SupportedSecretEnvs = (Option<Zeroizing<String>>, Option<Zeroizing<String>>);

impl StartupSecrets {
    /// Consume secret environment variables before the multi-thread runtime is
    /// created. Mutating the process environment after other threads exist is
    /// not sound on Unix platforms.
    fn take_for(cmd: &Cmd) -> Result<Self> {
        // Always remove supported secret variables, including for a command
        // that does not consume them. Otherwise an unrelated runtime branch
        // would leave credentials exposed in the process environment.
        Ok(Self::from_captured(cmd, take_supported_secret_envs()?))
    }

    fn from_captured(cmd: &Cmd, captured: SupportedSecretEnvs) -> Self {
        let (ssh_password, master) = captured;
        match cmd {
            Cmd::Add { .. } => Self {
                ssh_password,
                master,
            },
            Cmd::Up { .. }
            | Cmd::Exec { .. }
            | Cmd::Upload { .. }
            | Cmd::Download { .. }
            | Cmd::Shell { .. } => Self {
                master,
                ..Self::default()
            },
            Cmd::Ui | Cmd::List | Cmd::Remove { .. } | Cmd::Status { .. } | Cmd::Down { .. } => {
                Self::default()
            }
        }
    }
}

fn decode_secret_env(
    name: &str,
    value: Option<std::ffi::OsString>,
) -> Result<Option<Zeroizing<String>>> {
    let Some(value) = value else { return Ok(None) };
    let value = value
        .into_string()
        .map_err(|_| anyhow!("{name} is not valid Unicode"))?;
    Ok(Some(Zeroizing::new(value)))
}

trait SecretEnvAccess {
    fn get(&mut self, name: &str) -> Option<std::ffi::OsString>;
    fn remove(&mut self, name: &str);
}

struct ProcessSecretEnv;

impl SecretEnvAccess for ProcessSecretEnv {
    fn get(&mut self, name: &str) -> Option<std::ffi::OsString> {
        std::env::var_os(name)
    }

    fn remove(&mut self, name: &str) {
        std::env::remove_var(name);
    }
}

fn take_supported_secret_envs_from(env: &mut impl SecretEnvAccess) -> Result<SupportedSecretEnvs> {
    // Snapshot both values and remove both names before attempting a fallible
    // Unicode conversion. An invalid first value must not leave the other
    // credential inherited by the process until the error path exits.
    let ssh_password = env.get("SERCTL_SSH_PASS");
    let master = env.get("SERCTL_MASTER");
    if ssh_password.is_some() {
        env.remove("SERCTL_SSH_PASS");
    }
    if master.is_some() {
        env.remove("SERCTL_MASTER");
    }

    // Evaluate both conversions before returning either error, so a valid
    // sibling value is wrapped in Zeroizing and cleared on the error path.
    let ssh_password = decode_secret_env("SERCTL_SSH_PASS", ssh_password);
    let master = decode_secret_env("SERCTL_MASTER", master);
    match (ssh_password, master) {
        (Ok(ssh_password), Ok(master)) => Ok((ssh_password, master)),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn take_supported_secret_envs() -> Result<SupportedSecretEnvs> {
    // SAFETY CONTRACT: main calls this helper only before constructing Tokio's
    // multi-thread runtime. Keep all ProcessSecretEnv call sites in that
    // single-threaded phase.
    take_supported_secret_envs_from(&mut ProcessSecretEnv)
}

fn supplied_or_prompt(
    supplied: Option<Zeroizing<String>>,
    prompt: &str,
) -> Result<Zeroizing<String>> {
    match supplied {
        Some(value) => Ok(value),
        None => Ok(Zeroizing::new(rpassword::prompt_password(prompt)?)),
    }
}

fn terminal_safe_field(value: &str) -> String {
    value.escape_debug().to_string()
}

fn terminal_safe_error(error: &anyhow::Error) -> String {
    terminal_safe_field(&format!("{error:#}"))
}

#[derive(Debug, PartialEq, Eq)]
struct ClapDiagnostic {
    text: String,
    use_stderr: bool,
    exit_code: i32,
}

fn terminal_safe_clap_diagnostic(error: &clap::Error) -> ClapDiagnostic {
    let trusted_layout = matches!(
        error.kind(),
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
    );
    ClapDiagnostic {
        text: if trusted_layout {
            error.to_string()
        } else {
            terminal_safe_field(&error.to_string())
        },
        use_stderr: error.use_stderr(),
        exit_code: error.exit_code(),
    }
}

fn exit_with_clap_diagnostic(error: clap::Error) -> ! {
    use std::io::Write as _;

    let diagnostic = terminal_safe_clap_diagnostic(&error);
    if diagnostic.use_stderr {
        let _ = writeln!(std::io::stderr().lock(), "{}", diagnostic.text);
    } else {
        let _ = writeln!(std::io::stdout().lock(), "{}", diagnostic.text);
    }
    std::process::exit(diagnostic.exit_code);
}

fn saved_profile_message(name: &str) -> String {
    format!("saved profile '{}'", terminal_safe_field(name))
}

fn removed_profile_message(name: &str) -> String {
    format!("removed '{}'", terminal_safe_field(name))
}

fn missing_profile_message(name: &str) -> String {
    format!("no profile '{}'", terminal_safe_field(name))
}

fn upload_success_message(bytes: u64, remote: &str) -> String {
    format!("uploaded {bytes} bytes to {}", terminal_safe_field(remote))
}

fn download_success_message(bytes: u64, local: &Path) -> String {
    format!(
        "downloaded {bytes} bytes to {}",
        terminal_safe_field(&local.display().to_string())
    )
}

#[cfg(any(unix, test))]
fn unix_exit_code(remote: i32) -> i32 {
    if remote == 0 {
        return 0;
    }
    if (1..=255).contains(&remote) {
        remote
    } else {
        // Unix only preserves the low eight bits. Never let a non-zero
        // remote status such as 256 turn into local success.
        1
    }
}

fn local_exit_code(remote: i32) -> i32 {
    #[cfg(unix)]
    {
        unix_exit_code(remote)
    }
    #[cfg(not(unix))]
    {
        remote
    }
}

fn main() {
    if let Err(error) = try_main() {
        eprintln!("error: {}", terminal_safe_error(&error));
        std::process::exit(CLI_FAILURE_EXIT_CODE);
    }
}

fn try_main() -> Result<()> {
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"));
    logger.format(|buffer, record| {
        use std::io::Write as _;

        let message = terminal_safe_field(&record.args().to_string());
        writeln!(buffer, "{}: {message}", record.level())
    });
    let _ = logger.try_init();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => exit_with_clap_diagnostic(error),
    };
    let cmd = cli.cmd.unwrap_or(Cmd::Ui);
    let secrets = StartupSecrets::take_for(&cmd)?;
    if matches!(&cmd, Cmd::Ui) {
        drop(secrets);
        return ui::run();
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_cli(cmd, secrets))
}

async fn run_cli(cmd: Cmd, mut secrets: StartupSecrets) -> Result<()> {
    match cmd {
        Cmd::Ui => unreachable!("UI is handled before starting the CLI runtime"),
        Cmd::Add {
            name,
            host,
            user,
            port,
        } => {
            let name = nm(name);
            let host = match host {
                Some(h) => h,
                None => prompt("host: ")?,
            };
            let user = match user {
                Some(u) => u,
                None => prompt("user: ")?,
            };
            let password = supplied_or_prompt(secrets.ssh_password.take(), "password: ")?;
            let master = supplied_or_prompt(secrets.master.take(), "master passphrase: ")?;
            vault::add_or_update(
                &name,
                &vault::Creds {
                    host,
                    port,
                    user,
                    password: password.to_string(),
                    host_key: None,
                },
                &master,
            )?;
            println!("{}", saved_profile_message(&name));
        }
        Cmd::List => {
            let rows = vault::list()?;
            if rows.is_empty() {
                println!("(no profiles)");
            } else {
                for (n, h, p) in rows {
                    println!(
                        "{}\t{}:{p}",
                        terminal_safe_field(&n),
                        terminal_safe_field(&h)
                    );
                }
            }
        }
        Cmd::Remove { name } => {
            if vault::remove(&name)? {
                println!("{}", removed_profile_message(&name));
            } else {
                println!("{}", missing_profile_message(&name));
            }
        }
        Cmd::Up { name } => {
            let name = nm(name);
            let master = supplied_or_prompt(secrets.master.take(), "master passphrase: ")?;
            daemon::run(&name, master).await?;
        }
        Cmd::Exec {
            name,
            timeout_secs,
            mut cmd,
        } => {
            if cmd.is_empty() {
                bail!("no command given");
            }
            let timeout = std::time::Duration::from_secs(timeout_secs);
            let command = Zeroizing::new(cmd.join(" "));
            cmd.zeroize();
            let code = client::exec_with_timeout_and_master(
                &name,
                command.as_str(),
                timeout,
                secrets.master.take(),
            )
            .await?;
            drop(command);
            drop(secrets.ssh_password.take());
            std::process::exit(local_exit_code(code));
        }
        Cmd::Upload {
            name,
            local,
            remote,
            timeout_secs,
        } => {
            let timeout = std::time::Duration::from_secs(timeout_secs);
            let bytes = client::upload_with_timeout_and_master(
                &name,
                &local,
                &remote,
                timeout,
                secrets.master.take(),
            )
            .await?;
            println!("{}", upload_success_message(bytes, &remote));
        }
        Cmd::Download {
            name,
            remote,
            local,
            timeout_secs,
        } => {
            let timeout = std::time::Duration::from_secs(timeout_secs);
            let bytes = client::download_with_timeout_and_master(
                &name,
                &remote,
                &local,
                timeout,
                secrets.master.take(),
            )
            .await?;
            println!("{}", download_success_message(bytes, &local));
        }
        Cmd::Shell { name } => {
            client::shell_with_master(&nm(name), secrets.master.take()).await?;
        }
        Cmd::Status { name } => {
            client::status(&nm(name)).await?;
        }
        Cmd::Down { name } => {
            client::down(&nm(name)).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::{
        download_success_message, local_exit_code, missing_profile_message,
        removed_profile_message, saved_profile_message, take_supported_secret_envs_from,
        terminal_safe_clap_diagnostic, terminal_safe_error, terminal_safe_field, unix_exit_code,
        upload_success_message, Cli, Cmd, SecretEnvAccess, StartupSecrets, CLI_FAILURE_EXIT_CODE,
    };
    use clap::Parser;
    use std::{collections::BTreeMap, ffi::OsString, path::Path};

    #[derive(Default)]
    struct MemorySecretEnv {
        values: BTreeMap<String, OsString>,
        removals: Vec<String>,
    }

    impl SecretEnvAccess for MemorySecretEnv {
        fn get(&mut self, name: &str) -> Option<OsString> {
            self.values.get(name).cloned()
        }

        fn remove(&mut self, name: &str) {
            self.values.remove(name);
            self.removals.push(name.to_owned());
        }
    }

    #[cfg(unix)]
    fn invalid_unicode_env_value() -> OsString {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![0xff])
    }

    #[cfg(windows)]
    fn invalid_unicode_env_value() -> OsString {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[0xd800])
    }

    #[test]
    fn upload_and_download_commands_parse_for_evidence_workflows() {
        let upload = Cli::try_parse_from([
            "serctl",
            "upload",
            "prod",
            "evidence.json",
            "/tmp/evidence.json",
        ])
        .unwrap();
        assert!(matches!(upload.cmd, Some(Cmd::Upload { .. })));

        let download = Cli::try_parse_from([
            "serctl",
            "download",
            "prod",
            "/tmp/evidence.json",
            "evidence.json",
        ])
        .unwrap();
        assert!(matches!(download.cmd, Some(Cmd::Download { .. })));
    }

    #[test]
    fn startup_capture_snapshots_and_removes_both_supported_secrets() {
        let mut env = MemorySecretEnv::default();
        env.values
            .insert("SERCTL_SSH_PASS".into(), "test-ssh-password".into());
        env.values
            .insert("SERCTL_MASTER".into(), "test-master-passphrase".into());

        let captured = take_supported_secret_envs_from(&mut env).expect("capture startup secrets");
        let secrets = StartupSecrets::from_captured(
            &Cmd::Add {
                name: None,
                host: None,
                user: None,
                port: 22,
            },
            captured,
        );

        assert!(env.values.is_empty());
        assert_eq!(
            env.removals,
            ["SERCTL_SSH_PASS".to_owned(), "SERCTL_MASTER".to_owned()]
        );
        assert_eq!(
            secrets.ssh_password.as_deref().map(|value| value.as_str()),
            Some("test-ssh-password")
        );
        assert_eq!(
            secrets.master.as_deref().map(|value| value.as_str()),
            Some("test-master-passphrase")
        );
    }

    #[test]
    fn invalid_first_secret_still_removes_the_second_before_returning_error() {
        let mut env = MemorySecretEnv::default();
        env.values
            .insert("SERCTL_SSH_PASS".into(), invalid_unicode_env_value());
        env.values
            .insert("SERCTL_MASTER".into(), "test-master-passphrase".into());

        let error = take_supported_secret_envs_from(&mut env)
            .expect_err("invalid secret must fail capture");

        assert!(error.to_string().contains("SERCTL_SSH_PASS"));
        assert!(env.values.is_empty());
        assert_eq!(
            env.removals,
            ["SERCTL_SSH_PASS".to_owned(), "SERCTL_MASTER".to_owned()]
        );
    }

    #[test]
    fn exec_timeout_option_parses_before_remote_command() {
        let cli = Cli::try_parse_from([
            "serctl",
            "exec",
            "prod",
            "--timeout-secs",
            "12",
            "--",
            "sleep",
            "30",
        ])
        .unwrap();
        match cli.cmd {
            Some(Cmd::Exec { timeout_secs, .. }) => assert_eq!(timeout_secs, 12),
            _ => panic!("exec command was not parsed"),
        }
    }

    #[test]
    fn nonzero_remote_status_never_becomes_local_success() {
        assert_eq!(local_exit_code(0), 0);
        for status in [1, 7, 255, 256, 512, -1, i32::MIN, i32::MAX] {
            assert_ne!(
                local_exit_code(status),
                0,
                "remote status {status} became local success"
            );
        }
        #[cfg(unix)]
        {
            assert_eq!(local_exit_code(7), 7);
            assert_eq!(local_exit_code(256), 1);
        }
        assert_eq!(unix_exit_code(0), 0);
        assert_eq!(unix_exit_code(7), 7);
        assert_eq!(unix_exit_code(255), 255);
        assert_eq!(unix_exit_code(256), 1);
        assert_eq!(unix_exit_code(512), 1);
        assert_eq!(unix_exit_code(-1), 1);
    }

    #[test]
    fn list_fields_escape_terminal_control_sequences() {
        let value = "prod\tbad\r\n\u{1b}]52;c;payload\u{7}\u{2028}spoof\u{202e}txt";
        let escaped = terminal_safe_field(value);
        assert_eq!(
            escaped,
            "prod\\tbad\\r\\n\\u{1b}]52;c;payload\\u{7}\\u{2028}spoof\\u{202e}txt"
        );
        assert!(!escaped.chars().any(char::is_control));
        assert!(!escaped.contains('\u{2028}'));
        assert!(!escaped.contains('\u{202e}'));
    }

    #[test]
    fn terminal_error_diagnostic_escapes_controls_and_uses_nonzero_exit() {
        let error = anyhow::anyhow!("remote SFTP error\n\u{1b}]52;c;payload\u{7}");
        let diagnostic = terminal_safe_error(&error);

        assert_eq!(diagnostic, "remote SFTP error\\n\\u{1b}]52;c;payload\\u{7}");
        assert!(!diagnostic.chars().any(char::is_control));
        assert_ne!(CLI_FAILURE_EXIT_CODE, 0);
    }

    #[test]
    fn dynamic_success_fields_are_terminal_safe() {
        let dynamic = "prod\n\u{1b}]52;c;payload\u{7}";
        let messages = [
            saved_profile_message(dynamic),
            removed_profile_message(dynamic),
            missing_profile_message(dynamic),
            upload_success_message(17, dynamic),
            download_success_message(17, Path::new(dynamic)),
        ];

        for message in messages {
            assert!(!message.chars().any(char::is_control), "{message:?}");
            assert!(message.contains("\\n"), "{message:?}");
            assert!(message.contains("\\u{1b}"), "{message:?}");
        }
    }

    #[test]
    fn clap_diagnostics_escape_untrusted_arguments_and_preserve_exit_semantics() {
        let invalid = match Cli::try_parse_from([
            "serctl",
            "bad\n\u{1b}]52;c;payload\u{7}\u{2028}spoof\u{202e}txt",
        ]) {
            Ok(_) => panic!("invalid subcommand unexpectedly parsed"),
            Err(error) => error,
        };
        let invalid = terminal_safe_clap_diagnostic(&invalid);
        assert!(invalid.use_stderr);
        assert_ne!(invalid.exit_code, 0);
        assert!(!invalid.text.chars().any(char::is_control));
        assert!(invalid.text.contains("\\n"));
        assert!(invalid.text.contains("\\u{2028}"));
        assert!(invalid.text.contains("\\u{202e}"));

        let help = match Cli::try_parse_from(["serctl", "--help"]) {
            Ok(_) => panic!("help unexpectedly parsed as a command"),
            Err(error) => error,
        };
        let help = terminal_safe_clap_diagnostic(&help);
        assert!(!help.use_stderr);
        assert_eq!(help.exit_code, 0);
        assert!(help.text.contains('\n'));
    }
}
