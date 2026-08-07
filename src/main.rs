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

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zeroize::Zeroizing;

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

fn prompt(label: &str) -> Result<String> {
    use std::io::Write;
    print!("{label}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

fn secret_from_env_or_prompt(env_name: &str, prompt: &str) -> Result<Zeroizing<String>> {
    if let Ok(value) = std::env::var(env_name) {
        std::env::remove_var(env_name);
        Ok(Zeroizing::new(value))
    } else {
        Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
    }
}

fn main() -> Result<()> {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .try_init();
    let cli = Cli::parse();
    let Some(cmd) = cli.cmd else {
        return ui::run();
    };
    if matches!(cmd, Cmd::Ui) {
        return ui::run();
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_cli(cmd))
}

async fn run_cli(cmd: Cmd) -> Result<()> {
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
            let password = secret_from_env_or_prompt("SERCTL_SSH_PASS", "password: ")?;
            let master = secret_from_env_or_prompt("SERCTL_MASTER", "master passphrase: ")?;
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
            println!("saved profile '{name}'");
        }
        Cmd::List => {
            let rows = vault::list()?;
            if rows.is_empty() {
                println!("(no profiles)");
            } else {
                for (n, h, p) in rows {
                    println!("{n}\t{h}:{p}");
                }
            }
        }
        Cmd::Remove { name } => {
            if vault::remove(&name)? {
                println!("removed '{name}'");
            } else {
                println!("no profile '{name}'");
            }
        }
        Cmd::Up { name } => {
            let name = nm(name);
            let master = secret_from_env_or_prompt("SERCTL_MASTER", "master passphrase: ")?;
            let creds = vault::decrypt(&name, &master)?;
            daemon::run(&name, creds, master.to_string()).await?;
        }
        Cmd::Exec {
            name,
            timeout_secs,
            cmd,
        } => {
            if cmd.is_empty() {
                bail!("no command given");
            }
            let timeout = std::time::Duration::from_secs(timeout_secs);
            let code = client::exec_with_timeout(&name, &cmd.join(" "), timeout).await?;
            std::process::exit(code);
        }
        Cmd::Upload {
            name,
            local,
            remote,
            timeout_secs,
        } => {
            let bytes = client::upload_with_timeout(
                &name,
                &local,
                &remote,
                std::time::Duration::from_secs(timeout_secs),
            )
            .await?;
            println!("uploaded {bytes} bytes to {remote}");
        }
        Cmd::Download {
            name,
            remote,
            local,
            timeout_secs,
        } => {
            let bytes = client::download_with_timeout(
                &name,
                &remote,
                &local,
                std::time::Duration::from_secs(timeout_secs),
            )
            .await?;
            println!("downloaded {bytes} bytes to {}", local.display());
        }
        Cmd::Shell { name } => {
            client::shell(&nm(name)).await?;
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
    use super::{Cli, Cmd};
    use clap::Parser;

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
}
