//! serctl — persistent SSH control suite.
//!
//! Encrypted credential vault + long-lived connection daemon + local IPC so
//! every `exec`/`shell` reuses one authenticated SSH session without re-exposing
//! the password on the command line.
mod client;
mod launcher;
mod ui;
use serctl_core::security;
use serctl_core::vault;

#[cfg(test)]
mod e2e_tests;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{
    collections::BTreeMap,
    io::IsTerminal,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

const CLI_FAILURE_EXIT_CODE: i32 = 1;
const MAX_RECOVERY_MEDIA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GENERATED_PASSPHRASE_FILE_BYTES: usize = 16 * 1024 + 1;

const BUILD_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("SERCTL_BUILD_COMMIT"),
    ")"
);

#[derive(Parser)]
#[command(
    name = "serctl_cli",
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
    /// Add or update a profile using its independent passphrase.
    ///
    /// Creating a profile requires administrator authorization on Windows;
    /// updating an existing profile requires only that profile's passphrase.
    Add {
        name: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Expected SSH host-key fingerprint, in `SHA256:...` form.
        #[arg(long, value_name = "SHA256:FINGERPRINT")]
        host_key_sha256: Option<String>,
    },
    /// List saved profiles (host/port only — secrets stay sealed).
    List,
    /// Remove a profile.
    Remove { name: String },
    /// Initialize or verify the Windows administrator password.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Manage one profile's independent passphrase.
    ProfilePassword {
        name: String,
        #[command(subcommand)]
        command: ProfilePasswordCommand,
    },
    /// Manage the vault-wide 2-of-2 offline recovery policy.
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    /// Start the global broker in the foreground; profiles unlock per request.
    Up { name: Option<String> },
    /// Run a remote command through the on-demand global broker.
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
    /// Observable, cancellable file transfer with remote-confirmed progress.
    Transfer {
        #[command(subcommand)]
        command: TransferCommand,
    },
    /// Open an interactive PTY shell through the on-demand global broker.
    Shell { name: Option<String> },
    /// Run a loopback-only SSH TCP tunnel in the foreground until Ctrl+C.
    Tunnel {
        name: String,
        #[command(subcommand)]
        tunnel: TunnelCommand,
    },
    /// Show daemon status.
    Status { name: Option<String> },
    /// Stop a running daemon after verifying one profile passphrase.
    Down { name: Option<String> },
    /// Issue a policy-bounded OperationGrant for an agent frontend.
    GrantIssue {
        name: String,
        /// Comma-separated protocol operation kinds, such as ssh.exec,
        /// sftp.list, sftp.write (create-dir only), or transfer.write.
        #[arg(long, value_delimiter = ',')]
        operations: Vec<String>,
        /// Maximum number of relayed operations (1..=1000).
        #[arg(long, default_value_t = 32)]
        budget: u32,
        /// Capability lifetime in whole minutes (1..=40; default 30).
        #[arg(
            long,
            default_value_t = 30,
            value_parser = clap::value_parser!(u32).range(1..=40)
        )]
        ttl_minutes: u32,
        /// File to write the grant plus its agent private key to.
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Run the agent stdio gateway: JSONL requests on stdin, JSONL relay
    /// results on stdout, authenticated by an issued OperationGrant.
    Agent {
        /// Grant file previously written by `grant-issue`.
        #[arg(long, value_name = "FILE")]
        grant: PathBuf,
    },
}

#[derive(Subcommand)]
enum TransferCommand {
    /// Push a local file to a new remote destination.
    Push(TransferPushArgs),
    /// Pull a remote file to a new local destination.
    Pull(TransferPullArgs),
    /// Read sanitized transfer snapshots for one profile.
    Status {
        name: String,
        transfer_id: Option<String>,
        #[arg(long)]
        watch: bool,
        #[arg(long)]
        json: bool,
    },
    /// Cancel one active transfer owned by this profile.
    Cancel { name: String, transfer_id: String },
}

#[derive(Args)]
struct TransferPushArgs {
    name: String,
    local: PathBuf,
    remote: String,
    #[command(flatten)]
    options: TransferCliOptions,
}

#[derive(Args)]
struct TransferPullArgs {
    name: String,
    remote: String,
    local: PathBuf,
    #[command(flatten)]
    options: TransferCliOptions,
}

#[derive(Args)]
struct TransferCliOptions {
    /// Backend selection: auto probes native then reports an explicit SFTP fallback.
    #[arg(long, value_enum, default_value_t = CliTransferBackend::Auto)]
    backend: CliTransferBackend,
    /// Resume policy. `auto` requires the native backend and fails closed if unavailable.
    #[arg(long, value_enum, default_value_t = CliResumeMode::Never)]
    resume: CliResumeMode,
    /// Fail after this many seconds without newly confirmed remote bytes.
    #[arg(long, default_value_t = 30)]
    idle_timeout_secs: u64,
    /// Optional hard deadline for the complete transfer, independent of idle time.
    #[arg(long)]
    deadline_secs: Option<u64>,
    /// Progress output: terminal display, stable NDJSON, quiet, or TTY auto-detection.
    #[arg(long, value_enum, default_value_t = CliProgressMode::Auto)]
    progress: CliProgressMode,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliTransferBackend {
    Auto,
    Native,
    Sftp,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliResumeMode {
    Auto,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CliProgressMode {
    Auto,
    Tty,
    Json,
    Quiet,
}

impl From<CliTransferBackend> for serctl_protocol::TransferBackend {
    fn from(value: CliTransferBackend) -> Self {
        match value {
            CliTransferBackend::Auto => Self::Auto,
            CliTransferBackend::Native => Self::Native,
            CliTransferBackend::Sftp => Self::Sftp,
        }
    }
}

impl From<CliResumeMode> for serctl_protocol::TransferResumeMode {
    fn from(value: CliResumeMode) -> Self {
        match value {
            CliResumeMode::Auto => Self::Auto,
            CliResumeMode::Never => Self::Never,
        }
    }
}

fn effective_progress_mode(mode: CliProgressMode) -> CliProgressMode {
    if mode == CliProgressMode::Auto {
        if std::io::stderr().is_terminal() {
            CliProgressMode::Tty
        } else {
            CliProgressMode::Json
        }
    } else {
        mode
    }
}

fn transfer_progress_percent(progress: &serctl_protocol::TransferProgress) -> f64 {
    if progress.stage == serctl_protocol::TransferStage::Completed {
        100.0
    } else if progress.total_bytes == 0 {
        0.0
    } else {
        (progress.confirmed_bytes as f64 * 100.0 / progress.total_bytes as f64).min(99.9)
    }
}

fn transfer_progress_sink(mode: CliProgressMode) -> Option<client::TransferProgressSink> {
    let mode = effective_progress_mode(mode);
    match mode {
        CliProgressMode::Quiet => None,
        CliProgressMode::Json => Some(Arc::new(|progress| {
            if let Ok(line) = serde_json::to_string(&progress) {
                println!("{line}");
            }
        })),
        CliProgressMode::Tty => Some(Arc::new(|progress| {
            let eta = progress
                .eta_ms
                .map(|value| format!("{:.1}s", value as f64 / 1000.0))
                .unwrap_or_else(|| "--".to_owned());
            eprint!(
                "\r{:?}  {:>5.1}%  {}/{}  win {:.1} KiB/s  avg {:.1} KiB/s  ETA {}  backend={} chunk={} window={} id={}      ",
                progress.stage,
                transfer_progress_percent(&progress),
                progress.confirmed_bytes,
                progress.total_bytes,
                progress.window_bps / 1024.0,
                progress.average_bps / 1024.0,
                eta,
                transfer_backend_name(progress.backend),
                progress.chunk_bytes,
                progress.window_bytes,
                progress.transfer_id.as_str(),
            );
            if matches!(
                progress.stage,
                serctl_protocol::TransferStage::Completed
                    | serctl_protocol::TransferStage::Failed
                    | serctl_protocol::TransferStage::Cancelled
            ) {
                eprintln!();
            }
        })),
        CliProgressMode::Auto => unreachable!("auto progress mode must be resolved"),
    }
}

fn transfer_backend_name(backend: serctl_protocol::TransferBackend) -> &'static str {
    match backend {
        serctl_protocol::TransferBackend::Auto => "auto",
        serctl_protocol::TransferBackend::Native => "native",
        serctl_protocol::TransferBackend::Sftp => "sftp",
        serctl_protocol::TransferBackend::SftpFallback => "sftp_fallback",
    }
}

fn transfer_client_options(options: &TransferCliOptions) -> client::TransferOptions {
    client::TransferOptions {
        backend: options.backend.into(),
        resume: options.resume.into(),
        idle_timeout: std::time::Duration::from_secs(options.idle_timeout_secs),
        deadline: options.deadline_secs.map(std::time::Duration::from_secs),
        progress: transfer_progress_sink(options.progress),
    }
}

fn transfer_is_terminal(stage: serctl_protocol::TransferStage) -> bool {
    matches!(
        stage,
        serctl_protocol::TransferStage::Completed
            | serctl_protocol::TransferStage::Failed
            | serctl_protocol::TransferStage::Cancelled
    )
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Show whether administrator authorization has been initialized.
    Status,
    /// Initialize the administrator password. Windows only.
    Init {
        /// New 2-of-2 offline recovery share. The path must not already exist.
        #[arg(long, value_name = "FILE")]
        recovery_media: PathBuf,
    },
    /// Verify administrator authorization without changing state.
    Verify,
    /// Replace the administrator password after verifying the current one.
    ChangePassword,
}

#[derive(Subcommand)]
enum ProfilePasswordCommand {
    /// Change the passphrase after proving the current profile passphrase.
    Change,
    /// Generate and install a new random passphrase after proving the current one.
    ///
    /// The new passphrase is durably written before the vault is changed, so
    /// an output failure can never strand the profile behind an unseen value.
    RotateRandom {
        #[arg(long, value_name = "FILE")]
        random_output: PathBuf,
    },
    /// Administratively recover or replace a profile passphrase.
    ///
    /// `--media` preserves sealed SSH credentials through the 2-of-2 recovery
    /// path. `--replace-credentials` discards them and requires new values;
    /// the administrator password alone can never reveal or preserve them.
    AdminReset {
        /// Linux root: NSS account whose vault will be destructively reset.
        /// The process irreversibly drops to this account before opening it.
        #[arg(long, value_name = "USER")]
        target_user: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Expected SSH host-key fingerprint, in `SHA256:...` form.
        #[arg(long, value_name = "SHA256:FINGERPRINT")]
        host_key_sha256: Option<String>,
        /// Offline share used to preserve and rewrap the current credentials.
        #[arg(long, value_name = "FILE", conflicts_with = "replace_credentials")]
        media: Option<PathBuf>,
        /// Discard the old encrypted credentials and require a full replacement.
        #[arg(long, conflicts_with = "media", required_unless_present = "media")]
        replace_credentials: bool,
        /// Generate the replacement profile passphrase instead of prompting.
        #[arg(long, requires = "random_output")]
        random: bool,
        /// Protected create-new file that receives the random passphrase
        /// before the vault mutation is allowed to commit.
        #[arg(long, value_name = "FILE", requires = "random")]
        random_output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum RecoveryCommand {
    /// Initialize vault-wide offline recovery. Unix root only.
    Init {
        #[arg(value_name = "NEW_MEDIA")]
        media: PathBuf,
    },
    /// Replace the vault-wide offline share and every profile recovery envelope.
    Rotate {
        #[arg(long, value_name = "FILE")]
        old_media: PathBuf,
        #[arg(long, value_name = "FILE")]
        new_media: PathBuf,
    },
    /// Migrate a legacy v2 vault to independent profile passphrases.
    MigrateV2 {
        /// New 2-of-2 offline recovery share. The path must not already exist.
        #[arg(long, value_name = "FILE")]
        recovery_media: PathBuf,
    },
}

#[derive(Args)]
struct TunnelCommonArgs {
    /// Loopback listener port. Use 0 to let the operating system choose one.
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// Maximum number of simultaneously forwarded TCP connections.
    #[arg(long, default_value_t = 32)]
    max_connections: u16,
}

#[derive(Subcommand)]
enum TunnelCommand {
    /// Listen on local 127.0.0.1 and reach the SSH host's 127.0.0.1 port.
    Local {
        #[command(flatten)]
        common: TunnelCommonArgs,
        /// Port on 127.0.0.1 of the already connected SSH host.
        #[arg(long)]
        target_port: u16,
    },
    /// Listen on the SSH host's 127.0.0.1 and reach this machine's loopback port.
    Remote {
        #[command(flatten)]
        common: TunnelCommonArgs,
        /// Port on this serctl machine's 127.0.0.1.
        #[arg(long)]
        target_port: u16,
    },
    /// Dynamic SOCKS5 forwarding, listening only on local 127.0.0.1.
    Dynamic {
        #[command(flatten)]
        common: TunnelCommonArgs,
    },
}

impl TunnelCommand {
    fn into_spec(self) -> client::TunnelSpec {
        let (mode, common, target_port) = match self {
            Self::Local {
                common,
                target_port,
            } => (client::TunnelMode::Local, common, target_port),
            Self::Remote {
                common,
                target_port,
            } => (client::TunnelMode::Remote, common, target_port),
            Self::Dynamic { common } => (client::TunnelMode::Dynamic, common, 0),
        };
        client::TunnelSpec {
            mode,
            bind_port: common.port,
            target_port,
            max_connections: common.max_connections,
        }
    }
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

fn validate_external_secret_path(path: &Path, existing: bool, label: &str) -> Result<()> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        bail!("{label} must use an absolute file path");
    }
    let candidate = if existing {
        std::fs::canonicalize(path)
            .with_context(|| format!("resolve existing {label} {}", path.display()))?
    } else {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| anyhow!("{label} has no parent directory"))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("{label} has no file name"))?;
        std::fs::canonicalize(parent)
            .with_context(|| format!("resolve {label} directory {}", parent.display()))?
            .join(file_name)
    };
    let configured_vault_dir = vault::vault_dir_for_external_path_validation()?;
    if !configured_vault_dir.is_absolute() {
        bail!("vault directory must be absolute while validating {label}");
    }
    let vault_dir = match std::fs::canonicalize(&configured_vault_dir) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => configured_vault_dir,
        Err(error) => {
            return Err(error)
                .context("resolve vault directory while validating external secret path")
        }
    };
    if candidate.starts_with(&vault_dir) {
        bail!("{label} must not be stored inside the serctl vault directory");
    }
    Ok(())
}

/// Recovery media contains only one half of the vault's 2-of-2 recovery
/// material, so it is intentionally portable to removable filesystems that
/// do not implement Unix modes or Windows ACLs. CREATE_NEW plus handle-based
/// regular-file validation prevents silent overwrite and special-file output.
fn create_new_recovery_media_file(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = options
        .open(path)
        .with_context(|| format!("create new recovery media {}", path.display()))?;
    let metadata = file
        .metadata()
        .context("inspect newly-created recovery-media handle")?;
    if !metadata.file_type().is_file() {
        bail!("recovery-media destination is not a regular file");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("recovery-media destination must not be a reparse point");
        }
    }
    Ok(file)
}

fn persist_new_recovery_media(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::{Read, Seek, Write};
    use subtle::ConstantTimeEq;

    validate_external_secret_path(path, false, "recovery-media output")?;
    if contents.is_empty() || contents.len() as u64 > MAX_RECOVERY_MEDIA_BYTES {
        bail!("recovery-media payload is empty or exceeds the 4 MiB safety limit");
    }
    let mut file = create_new_recovery_media_file(path)?;
    file.write_all(contents).with_context(|| {
        format!(
            "write recovery media {}; a partial file may remain",
            path.display()
        )
    })?;
    file.sync_all().with_context(|| {
        format!(
            "sync recovery media {}; a partial file may remain",
            path.display()
        )
    })?;

    // Detect short/removable-media writes before allowing the vault-side
    // transaction to commit. The callback's caller retains the new vault
    // material until this verification succeeds.
    file.rewind()
        .context("rewind recovery media for verification")?;
    let mut persisted = Zeroizing::new(vec![0_u8; contents.len()]);
    file.read_exact(&mut persisted)
        .context("read back recovery media for verification")?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 || !bool::from(persisted.as_slice().ct_eq(contents)) {
        bail!("recovery-media write verification failed");
    }
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)
            .with_context(|| format!("open recovery-media directory {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("sync recovery-media directory {}", parent.display()))?;
    }
    Ok(())
}

/// Persist a generated profile passphrase before changing the vault. The
/// protected create-new file contains exactly UTF-8 `passphrase + "\n"` so it
/// remains easy to import into a password manager without a JSON parser.
fn persist_generated_profile_passphrase(path: &Path, passphrase: &str) -> Result<()> {
    use std::io::{Read, Seek, Write};
    use subtle::ConstantTimeEq;

    validate_external_secret_path(path, false, "random-passphrase output")?;
    if passphrase.is_empty() || passphrase.len() + 1 > MAX_GENERATED_PASSPHRASE_FILE_BYTES {
        bail!("generated profile passphrase is empty or exceeds its safety limit");
    }
    #[cfg(unix)]
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("random-passphrase output has no parent directory"))?;
    let mut expected = Zeroizing::new(Vec::with_capacity(passphrase.len() + 1));
    expected.extend_from_slice(passphrase.as_bytes());
    expected.push(b'\n');

    let mut file = security::create_new_protected_file(path).with_context(|| {
        format!(
            "create protected random-passphrase output {}",
            path.display()
        )
    })?;
    file.write_all(expected.as_slice()).with_context(|| {
        format!(
            "write random-passphrase output {}; a partial protected file may remain",
            path.display()
        )
    })?;
    file.sync_all().with_context(|| {
        format!(
            "sync random-passphrase output {}; a partial protected file may remain",
            path.display()
        )
    })?;
    file.rewind()
        .context("rewind random-passphrase output for verification")?;
    let mut persisted = Zeroizing::new(vec![0_u8; expected.len()]);
    file.read_exact(&mut persisted)
        .context("read back random-passphrase output for verification")?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0
        || !bool::from(persisted.as_slice().ct_eq(expected.as_slice()))
    {
        bail!("random-passphrase output write verification failed");
    }
    #[cfg(unix)]
    std::fs::File::open(parent)
        .with_context(|| {
            format!(
                "open random-passphrase output directory {}",
                parent.display()
            )
        })?
        .sync_all()
        .with_context(|| {
            format!(
                "sync random-passphrase output directory {}",
                parent.display()
            )
        })?;
    Ok(())
}

fn commit_generated_profile_passphrase_with<T>(
    path: &Path,
    persist: impl FnOnce(&Path, &str) -> Result<()>,
    commit: impl FnOnce(&str) -> Result<T>,
) -> Result<T> {
    let generated = vault::generate_profile_passphrase();
    persist(path, &generated)?;
    commit(&generated)
}

fn commit_generated_profile_passphrase<T>(
    path: &Path,
    commit: impl FnOnce(&str) -> Result<T>,
) -> Result<T> {
    commit_generated_profile_passphrase_with(path, persist_generated_profile_passphrase, commit)
}

fn read_recovery_media(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;

    validate_external_secret_path(path, true, "recovery media")?;
    let mut file = security::open_regular_file_for_read(path)?;
    let declared = file.metadata()?.len();
    if declared == 0 || declared > MAX_RECOVERY_MEDIA_BYTES {
        bail!("recovery media is empty or exceeds the 4 MiB safety limit");
    }
    let mut contents = Zeroizing::new(Vec::with_capacity(declared as usize));
    (&mut file)
        .take(MAX_RECOVERY_MEDIA_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.is_empty() || contents.len() as u64 > MAX_RECOVERY_MEDIA_BYTES {
        bail!("recovery media changed size while it was being read");
    }
    Ok(contents)
}

#[derive(Default)]
struct StartupSecrets {
    ssh_password: Option<Zeroizing<String>>,
    profile_passphrase: Option<Zeroizing<String>>,
    admin_password: Option<Zeroizing<String>>,
    legacy_master: Option<Zeroizing<String>>,
}

#[derive(Default)]
struct SupportedSecretEnvs {
    ssh_password: Option<Zeroizing<String>>,
    profile_passphrase: Option<Zeroizing<String>>,
    admin_password: Option<Zeroizing<String>>,
    legacy_master: Option<Zeroizing<String>>,
    /// Backward-compatible `SERCTL_MASTER`. It is interpreted only after the
    /// command is known: as a profile passphrase for normal v4 operations or
    /// as the old vault master for `recovery migrate-v2`.
    compatibility_master: Option<Zeroizing<String>>,
}

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
        let SupportedSecretEnvs {
            ssh_password,
            profile_passphrase,
            admin_password,
            legacy_master,
            compatibility_master,
        } = captured;
        let profile_passphrase = profile_passphrase.or_else(|| {
            if matches!(
                cmd,
                Cmd::Recovery {
                    command: RecoveryCommand::MigrateV2 { .. }
                }
            ) {
                None
            } else {
                compatibility_master
                    .as_ref()
                    .map(|value| Zeroizing::new(value.as_str().to_owned()))
            }
        });
        let legacy_master = legacy_master.or_else(|| {
            if matches!(
                cmd,
                Cmd::Recovery {
                    command: RecoveryCommand::MigrateV2 { .. }
                }
            ) {
                compatibility_master
            } else {
                None
            }
        });
        match cmd {
            Cmd::Add { .. } => Self {
                ssh_password,
                profile_passphrase,
                admin_password,
                ..Self::default()
            },
            Cmd::Up { .. }
            | Cmd::Exec { .. }
            | Cmd::Upload { .. }
            | Cmd::Download { .. }
            | Cmd::Transfer { .. }
            | Cmd::Shell { .. }
            | Cmd::Tunnel { .. }
            | Cmd::Remove { .. }
            | Cmd::Status { .. }
            | Cmd::Down { .. }
            | Cmd::GrantIssue { .. } => Self {
                profile_passphrase,
                ..Self::default()
            },
            Cmd::Agent { .. } | Cmd::Ui => Self::default(),
            Cmd::Admin { command } => match command {
                AdminCommand::Status => Self::default(),
                AdminCommand::Init { .. } | AdminCommand::Verify | AdminCommand::ChangePassword => {
                    Self {
                        admin_password,
                        ..Self::default()
                    }
                }
            },
            Cmd::List => Self::default(),
            Cmd::ProfilePassword { command, .. } => match command {
                ProfilePasswordCommand::Change | ProfilePasswordCommand::RotateRandom { .. } => {
                    Self {
                        profile_passphrase,
                        ..Self::default()
                    }
                }
                ProfilePasswordCommand::AdminReset { .. } => Self {
                    ssh_password,
                    admin_password,
                    ..Self::default()
                },
            },
            Cmd::Recovery { command } => match command {
                RecoveryCommand::Init { .. } | RecoveryCommand::Rotate { .. } => Self {
                    admin_password,
                    ..Self::default()
                },
                RecoveryCommand::MigrateV2 { .. } => Self {
                    admin_password,
                    legacy_master,
                    ..Self::default()
                },
            },
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
    // Snapshot and remove every supported secret before attempting any
    // fallible Unicode conversion. An invalid first value must not leave a
    // sibling credential inherited by the process until the error path exits.
    const NAMES: [&str; 5] = [
        "SERCTL_SSH_PASS",
        "SERCTL_PROFILE_PASS",
        "SERCTL_ADMIN_PASS",
        "SERCTL_LEGACY_MASTER",
        "SERCTL_MASTER",
    ];
    let captured = NAMES.map(|name| {
        let value = env.get(name);
        if value.is_some() {
            env.remove(name);
        }
        value
    });

    // Evaluate all conversions before returning the first error. Successfully
    // converted siblings are Zeroizing and are cleared as the Results drop.
    let [ssh_password, profile_passphrase, admin_password, legacy_master, compatibility_master] =
        captured;
    let ssh_password = decode_secret_env(NAMES[0], ssh_password);
    let profile_passphrase = decode_secret_env(NAMES[1], profile_passphrase);
    let admin_password = decode_secret_env(NAMES[2], admin_password);
    let legacy_master = decode_secret_env(NAMES[3], legacy_master);
    let compatibility_master = decode_secret_env(NAMES[4], compatibility_master);
    match (
        ssh_password,
        profile_passphrase,
        admin_password,
        legacy_master,
        compatibility_master,
    ) {
        (
            Ok(ssh_password),
            Ok(profile_passphrase),
            Ok(admin_password),
            Ok(legacy_master),
            Ok(compatibility_master),
        ) => Ok(SupportedSecretEnvs {
            ssh_password,
            profile_passphrase,
            admin_password,
            legacy_master,
            compatibility_master,
        }),
        (Err(error), _, _, _, _)
        | (_, Err(error), _, _, _)
        | (_, _, Err(error), _, _)
        | (_, _, _, Err(error), _)
        | (_, _, _, _, Err(error)) => Err(error),
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

fn required_profile_passphrase(supplied: Option<Zeroizing<String>>) -> Result<Zeroizing<String>> {
    let passphrase = supplied_or_prompt(supplied, "profile passphrase: ")?;
    if passphrase.is_empty() {
        bail!("profile passphrase is required");
    }
    Ok(passphrase)
}

fn required_legacy_master(supplied: Option<Zeroizing<String>>) -> Result<Zeroizing<String>> {
    let master = supplied_or_prompt(supplied, "legacy vault master passphrase: ")?;
    if master.is_empty() {
        bail!("legacy vault master passphrase is required");
    }
    Ok(master)
}

#[cfg(windows)]
fn administrator_authorization(
    supplied: Option<Zeroizing<String>>,
) -> Result<Option<Zeroizing<String>>> {
    let password = supplied_or_prompt(supplied, "administrator password: ")?;
    if password.is_empty() {
        bail!("administrator password is required");
    }
    Ok(Some(password))
}

#[cfg(unix)]
fn administrator_authorization(
    supplied: Option<Zeroizing<String>>,
) -> Result<Option<Zeroizing<String>>> {
    // Never accept a password as a substitute for root on Unix. The vault
    // performs the authoritative euid=0 check; discarding the captured value
    // here avoids accidentally creating a second Unix administrator secret.
    drop(supplied);
    Ok(None)
}

#[cfg(windows)]
fn new_profile_administrator_authorization(
    supplied: Option<Zeroizing<String>>,
) -> Result<Option<Zeroizing<String>>> {
    let authorization = administrator_authorization(supplied)?;
    vault::verify_admin_password(authorization.as_deref().map(String::as_str))?;
    Ok(authorization)
}

#[cfg(not(windows))]
fn new_profile_administrator_authorization(
    supplied: Option<Zeroizing<String>>,
) -> Result<Option<Zeroizing<String>>> {
    drop(supplied);
    Ok(None)
}

fn prompt_confirmed_secret(
    prompt_label: &str,
    confirmation_label: &str,
) -> Result<Zeroizing<String>> {
    use subtle::ConstantTimeEq;

    let value = Zeroizing::new(rpassword::prompt_password(prompt_label)?);
    if value.is_empty() {
        bail!("a non-empty passphrase is required");
    }
    let confirmation = Zeroizing::new(rpassword::prompt_password(confirmation_label)?);
    if !bool::from(value.as_bytes().ct_eq(confirmation.as_bytes())) {
        bail!("passphrases do not match");
    }
    drop(confirmation);
    Ok(value)
}

fn prompted_credentials(
    host: Option<String>,
    user: Option<String>,
    port: u16,
    host_key: Option<String>,
    supplied_ssh_password: Option<Zeroizing<String>>,
) -> Result<vault::Creds> {
    let host = match host {
        Some(host) => host,
        None => prompt("host: ")?,
    };
    let user = match user {
        Some(user) => user,
        None => prompt("user: ")?,
    };
    let password = supplied_or_prompt(supplied_ssh_password, "SSH password: ")?;
    Ok(vault::Creds {
        host,
        port,
        user,
        password: password.to_string(),
        host_key,
    })
}

fn profile_metadata(name: &str) -> Result<Option<vault::ProfileMetadata>> {
    vault::validate_profile_name(name)?;
    Ok(vault::list_profile_metadata()?
        .into_iter()
        .find(|profile| profile.name == name))
}

fn required_profile_metadata(name: &str) -> Result<vault::ProfileMetadata> {
    profile_metadata(name)?.ok_or_else(|| anyhow!("profile '{name}' not found"))
}

fn profile_identity(metadata: &vault::ProfileMetadata) -> vault::ProfileIdentity {
    vault::ProfileIdentity {
        profile_id: metadata.profile_id,
        generation: metadata.generation,
    }
}

fn new_profile_passphrase() -> Result<Zeroizing<String>> {
    prompt_confirmed_secret(
        "new profile passphrase: ",
        "confirm new profile passphrase: ",
    )
}

#[cfg(windows)]
fn new_administrator_password(
    supplied: Option<Zeroizing<String>>,
) -> Result<Option<Zeroizing<String>>> {
    match supplied {
        Some(password) if password.is_empty() => bail!("administrator password is required"),
        Some(password) => Ok(Some(password)),
        None => Ok(Some(prompt_confirmed_secret(
            "new administrator password: ",
            "confirm new administrator password: ",
        )?)),
    }
}

#[cfg(not(windows))]
fn new_administrator_password(
    supplied: Option<Zeroizing<String>>,
) -> Result<Option<Zeroizing<String>>> {
    drop(supplied);
    Ok(None)
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
    let text = clap_diagnostic_without_trailing_line_endings(&diagnostic.text);
    if diagnostic.use_stderr {
        let _ = writeln!(std::io::stderr().lock(), "{text}");
    } else {
        let _ = writeln!(std::io::stdout().lock(), "{text}");
    }
    std::process::exit(diagnostic.exit_code);
}

fn clap_diagnostic_without_trailing_line_endings(text: &str) -> &str {
    text.trim_end_matches(['\r', '\n'])
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

fn grant_issued_message(
    grant_id: &str,
    ttl_minutes: u32,
    expires_unix_ms: u64,
    output: &Path,
) -> String {
    format!(
        "grant {} issued with TTL {} minutes (expires_unix_ms={}); agent credentials written to {}",
        terminal_safe_field(grant_id),
        ttl_minutes,
        expires_unix_ms,
        terminal_safe_field(&output.display().to_string())
    )
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
    reject_unsupported_platform_command(&cmd)?;
    let secrets = StartupSecrets::take_for(&cmd)?;
    if matches!(&cmd, Cmd::Ui) {
        drop(secrets);
        return ui::run();
    }
    enter_linux_admin_target_for_command(&cmd)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_cli(cmd, secrets))
}

fn reject_unsupported_platform_command(command: &Cmd) -> Result<()> {
    #[cfg(not(windows))]
    match command {
        Cmd::Recovery {
            command: RecoveryCommand::MigrateV2 { .. },
        } => {
            bail!("v2-to-v4 migration is Windows-only until Linux has a root-owned recovery share store and explicit target-user boundary")
        }
        Cmd::ProfilePassword {
            command: ProfilePasswordCommand::AdminReset { media: Some(_), .. },
            ..
        } => {
            bail!("credential-preserving offline recovery is currently Windows-only; Linux root may use --replace-credentials with --target-user")
        }
        _ => {}
    }
    #[cfg(target_os = "linux")]
    if matches!(
        command,
        Cmd::ProfilePassword {
            command: ProfilePasswordCommand::AdminReset {
                target_user: None,
                ..
            },
            ..
        }
    ) {
        bail!("Linux administrator reset requires --target-user USER");
    }
    #[cfg(not(target_os = "linux"))]
    if matches!(
        command,
        Cmd::ProfilePassword {
            command: ProfilePasswordCommand::AdminReset {
                target_user: Some(_),
                ..
            },
            ..
        }
    ) {
        bail!("--target-user is supported only for Linux root administrator reset");
    }
    Ok(())
}

/// Bind a Linux root administrative reset to one NSS-resolved account before
/// Tokio can create worker threads. Other platforms reject the Linux-only
/// selector instead of silently ignoring it.
fn enter_linux_admin_target_for_command(command: &Cmd) -> Result<()> {
    let Cmd::ProfilePassword {
        command: ProfilePasswordCommand::AdminReset { target_user, .. },
        ..
    } = command
    else {
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        let target_user = target_user
            .as_deref()
            .ok_or_else(|| anyhow!("Linux administrator reset requires --target-user USER"))?;
        vault::enter_linux_admin_target_user(target_user)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if target_user.is_some() {
            bail!("--target-user is supported only for Linux root administrator reset");
        }
        Ok(())
    }
}

fn run_admin_command(command: AdminCommand, secrets: &mut StartupSecrets) -> Result<()> {
    match command {
        AdminCommand::Status => {
            if let vault::VaultMigrationState::LegacyV2 { profiles } = vault::migration_state()? {
                println!(
                    "legacy v2 vault requires explicit migration ({} profile(s))",
                    profiles.len()
                );
            } else {
                match vault::admin_status()? {
                    vault::AdminStatus::Uninitialized {
                        platform_requires_password,
                    } => println!(
                        "administrator/recovery policy is not initialized (stored password required: {platform_requires_password})"
                    ),
                    vault::AdminStatus::Ready {
                        platform_requires_password,
                        recovery_id,
                    } => println!(
                        "administrator/recovery policy is ready\tstored-password={platform_requires_password}\trecovery-id={}",
                        terminal_safe_field(&recovery_id)
                    ),
                }
            }
        }
        AdminCommand::Init { recovery_media } => {
            #[cfg(windows)]
            {
                let password = new_administrator_password(secrets.admin_password.take())?
                    .expect("Windows administrator initialization returns a password");
                vault::initialize_admin_password(&password, |media| {
                    persist_new_recovery_media(&recovery_media, media)
                })?;
                println!(
                    "initialized administrator policy; recovery media written to {}",
                    terminal_safe_field(&recovery_media.display().to_string())
                );
            }
            #[cfg(not(windows))]
            {
                drop(recovery_media);
                drop(secrets.admin_password.take());
                bail!("stored administrator passwords are Windows-only; Linux root destructive reset uses --target-user and offline recovery remains fail-closed")
            }
        }
        AdminCommand::Verify => {
            let authorization = administrator_authorization(secrets.admin_password.take())?;
            vault::verify_admin_password(authorization.as_deref().map(String::as_str))?;
            println!("administrator authorization verified");
        }
        AdminCommand::ChangePassword => {
            #[cfg(windows)]
            {
                let old = administrator_authorization(secrets.admin_password.take())?
                    .expect("Windows administrator authorization returns a password");
                let new = prompt_confirmed_secret(
                    "new administrator password: ",
                    "confirm new administrator password: ",
                )?;
                vault::change_admin_password(&old, &new)?;
                println!("changed administrator password");
            }
            #[cfg(not(windows))]
            {
                drop(secrets.admin_password.take());
                bail!("Linux uses effective uid 0 and has no stored administrator password")
            }
        }
    }
    Ok(())
}

fn run_profile_password_command(
    name: String,
    command: ProfilePasswordCommand,
    secrets: &mut StartupSecrets,
) -> Result<()> {
    match command {
        ProfilePasswordCommand::Change => {
            let identity = profile_identity(&required_profile_metadata(&name)?);
            let old = required_profile_passphrase(secrets.profile_passphrase.take())?;
            let new = prompt_confirmed_secret(
                "new profile passphrase: ",
                "confirm new profile passphrase: ",
            )?;
            let generation = vault::change_profile_passphrase(&name, &old, &new, Some(identity))?;
            println!(
                "changed passphrase for '{}' (generation {generation})",
                terminal_safe_field(&name)
            );
        }
        ProfilePasswordCommand::RotateRandom { random_output } => {
            let identity = profile_identity(&required_profile_metadata(&name)?);
            let old = required_profile_passphrase(secrets.profile_passphrase.take())?;
            let generation = commit_generated_profile_passphrase(&random_output, |new| {
                vault::change_profile_passphrase(&name, &old, new, Some(identity))
            })?;
            println!(
                "rotated passphrase for '{}' (generation {generation}); random passphrase written to {}",
                terminal_safe_field(&name),
                terminal_safe_field(&random_output.display().to_string())
            );
        }
        ProfilePasswordCommand::AdminReset {
            target_user: _,
            host,
            user,
            port,
            host_key_sha256,
            media,
            replace_credentials,
            random,
            random_output,
        } => {
            let authorization = administrator_authorization(secrets.admin_password.take())?;
            // Authenticate before reading attacker-controlled removable media
            // or prompting for replacement SSH credentials.
            vault::verify_admin_password(authorization.as_deref().map(String::as_str))?;
            let identity = profile_identity(&required_profile_metadata(&name)?);

            if let Some(media) = media {
                if host.is_some() || user.is_some() || host_key_sha256.is_some() {
                    bail!("--host, --user, and --host-key-sha256 require --replace-credentials")
                }
                drop(secrets.ssh_password.take());
                let media = read_recovery_media(&media)?;
                if random {
                    let random_output = random_output
                        .as_deref()
                        .expect("clap requires --random-output with --random");
                    let row = commit_generated_profile_passphrase(random_output, |new| {
                        vault::recover_profile_with_media(
                            &name,
                            &media,
                            authorization.as_deref().map(String::as_str),
                            new,
                            Some(identity),
                        )
                    })?;
                    println!(
                        "recovered '{}' with preserved credentials (generation {}); random passphrase written to {}",
                        terminal_safe_field(&name),
                        row.generation,
                        terminal_safe_field(&random_output.display().to_string())
                    );
                } else {
                    let new = new_profile_passphrase()?;
                    let row = vault::recover_profile_with_media(
                        &name,
                        &media,
                        authorization.as_deref().map(String::as_str),
                        &new,
                        Some(identity),
                    )?;
                    println!(
                        "recovered '{}' with preserved credentials (generation {})",
                        terminal_safe_field(&name),
                        row.generation
                    );
                }
            } else {
                if !replace_credentials {
                    bail!("admin reset requires --media or --replace-credentials");
                }
                let credentials = prompted_credentials(
                    host,
                    user,
                    port,
                    host_key_sha256,
                    secrets.ssh_password.take(),
                )?;
                let row = if random {
                    let random_output = random_output
                        .as_deref()
                        .expect("clap requires --random-output with --random");
                    commit_generated_profile_passphrase(random_output, |new| {
                        vault::admin_reset_profile(
                            &name,
                            &credentials,
                            new,
                            authorization.as_deref().map(String::as_str),
                            Some(identity),
                        )
                    })?
                } else {
                    let new = new_profile_passphrase()?;
                    vault::admin_reset_profile(
                        &name,
                        &credentials,
                        &new,
                        authorization.as_deref().map(String::as_str),
                        Some(identity),
                    )?
                };
                println!(
                    "replaced credentials and passphrase for '{}' (generation {}){}",
                    terminal_safe_field(&name),
                    row.generation,
                    random_output
                        .as_ref()
                        .map_or_else(String::new, |path| format!(
                            "; random passphrase written to {}",
                            terminal_safe_field(&path.display().to_string())
                        ))
                );
            }
        }
    }
    Ok(())
}

fn run_recovery_command(command: RecoveryCommand, secrets: &mut StartupSecrets) -> Result<()> {
    match command {
        RecoveryCommand::Init { media } => {
            drop(secrets.admin_password.take());
            vault::initialize_linux_recovery(|contents| {
                persist_new_recovery_media(&media, contents)
            })?;
            println!(
                "initialized offline recovery; media written to {}",
                terminal_safe_field(&media.display().to_string())
            );
        }
        RecoveryCommand::Rotate {
            old_media,
            new_media,
        } => {
            let authorization = administrator_authorization(secrets.admin_password.take())?;
            vault::verify_admin_password(authorization.as_deref().map(String::as_str))?;
            let old = read_recovery_media(&old_media)?;
            let recovery_id = vault::rotate_recovery(
                &old,
                authorization.as_deref().map(String::as_str),
                |contents| persist_new_recovery_media(&new_media, contents),
            )?;
            println!(
                "rotated recovery policy to {} and wrote new media to {}",
                terminal_safe_field(&recovery_id),
                terminal_safe_field(&new_media.display().to_string())
            );
            eprintln!(
                "the old recovery medium is no longer valid; retire it after verifying the new medium is safely stored"
            );
        }
        RecoveryCommand::MigrateV2 { recovery_media } => {
            // Reject an unusable destination before prompting for or moving
            // any migration secret and before running multiple expensive KDFs.
            validate_external_secret_path(
                &recovery_media,
                false,
                "migration recovery-media output",
            )?;
            if recovery_media.exists() {
                bail!("migration recovery-media output already exists; it will not be overwritten");
            }
            let old_master = required_legacy_master(secrets.legacy_master.take())?;
            let profile_names = vault::legacy_profile_names()?;
            let mut profile_passphrases = BTreeMap::new();
            for name in profile_names {
                let safe_name = terminal_safe_field(&name);
                let passphrase = prompt_confirmed_secret(
                    &format!("new independent passphrase for '{safe_name}': "),
                    &format!("confirm passphrase for '{safe_name}': "),
                )?;
                profile_passphrases.insert(name, passphrase);
            }
            let administrator = new_administrator_password(secrets.admin_password.take())?;
            let count = vault::migrate_v2_with_progress(
                &old_master,
                &profile_passphrases,
                administrator.as_deref().map(String::as_str),
                |contents| persist_new_recovery_media(&recovery_media, contents),
                |progress| match progress {
                    vault::MigrationProgress::Validating => {
                        eprintln!("[migration] validating inputs")
                    }
                    vault::MigrationProgress::WaitingForExclusiveAccess => {
                        eprintln!("[migration] acquiring exclusive vault access")
                    }
                    vault::MigrationProgress::AuthenticatedLegacyVault => {
                        eprintln!("[migration] legacy vault authenticated")
                    }
                    vault::MigrationProgress::MigratingProfile {
                        completed,
                        total,
                        profile,
                    } => eprintln!(
                        "[migration] profile {}/{}: {}",
                        completed.saturating_add(1),
                        total,
                        terminal_safe_field(&profile)
                    ),
                    vault::MigrationProgress::PersistingRecoveryMedia => {
                        eprintln!("[migration] persisting and verifying recovery media")
                    }
                    vault::MigrationProgress::CommittingVault => {
                        eprintln!("[migration] committing the v4 vault atomically")
                    }
                },
            )?;
            println!(
                "migrated {count} profile(s) to independent passphrases; recovery media written to {}",
                terminal_safe_field(&recovery_media.display().to_string())
            );
        }
    }
    Ok(())
}

async fn run_cli(cmd: Cmd, mut secrets: StartupSecrets) -> Result<()> {
    match cmd {
        Cmd::Ui => unreachable!("UI is handled before starting the CLI runtime"),
        Cmd::Add {
            name,
            host,
            user,
            port,
            host_key_sha256,
        } => {
            let name = nm(name);
            let existing = profile_metadata(&name)?;
            let administrator = if existing.is_none() {
                new_profile_administrator_authorization(secrets.admin_password.take())?
            } else {
                drop(secrets.admin_password.take());
                None
            };
            let credentials = prompted_credentials(
                host,
                user,
                port,
                host_key_sha256,
                secrets.ssh_password.take(),
            )?;
            let passphrase = required_profile_passphrase(secrets.profile_passphrase.take())?;
            if let Some(existing) = existing {
                vault::update_profile(
                    &name,
                    &credentials,
                    &passphrase,
                    Some(profile_identity(&existing)),
                )?;
            } else {
                vault::create_profile(
                    &name,
                    &credentials,
                    &passphrase,
                    administrator.as_deref().map(String::as_str),
                )?;
            }
            println!("{}", saved_profile_message(&name));
        }
        Cmd::List => {
            let rows = vault::list_profile_metadata()?;
            if rows.is_empty() {
                println!("(no profiles)");
            } else {
                for row in rows {
                    println!(
                        "{}\t{}:{}\tgeneration={}",
                        terminal_safe_field(&row.name),
                        terminal_safe_field(&row.host),
                        row.port,
                        row.generation
                    );
                }
            }
        }
        Cmd::Remove { name } => {
            let identity = profile_identity(&required_profile_metadata(&name)?);
            let passphrase = required_profile_passphrase(secrets.profile_passphrase.take())?;
            if vault::remove_profile(&name, &passphrase, Some(identity))? {
                println!("{}", removed_profile_message(&name));
            } else {
                println!("{}", missing_profile_message(&name));
            }
        }
        Cmd::Admin { command } => run_admin_command(command, &mut secrets)?,
        Cmd::ProfilePassword { name, command } => {
            run_profile_password_command(name, command, &mut secrets)?
        }
        Cmd::Recovery { command } => run_recovery_command(command, &mut secrets)?,
        Cmd::Up { name } => {
            // The broker is per-user/per-vault global; the legacy per-profile
            // argument is accepted for compatibility but no longer scopes the
            // daemon, and no passphrase is needed (profiles unlock per request).
            let _ = name;
            if client::daemon_is_published()? {
                bail!("the daemon is already running");
            }
            // The daemon is a sibling binary; this CLI process supervises it
            // in the foreground and mirrors its exit status.
            let code = launcher::run_global_daemon_foreground().await?;
            std::process::exit(code);
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
            let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
            let code = client::exec_with_timeout_and_master(
                &name,
                command.as_str(),
                timeout,
                Some(master),
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
            let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
            let bytes = client::upload_with_timeout_and_master(
                &name,
                &local,
                &remote,
                timeout,
                Some(master),
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
            let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
            let bytes = client::download_with_timeout_and_master(
                &name,
                &remote,
                &local,
                timeout,
                Some(master),
            )
            .await?;
            println!("{}", download_success_message(bytes, &local));
        }
        Cmd::Transfer { command } => match command {
            TransferCommand::Push(args) => {
                let progress_mode = effective_progress_mode(args.options.progress);
                let options = transfer_client_options(&args.options);
                let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
                let bytes = client::transfer_push_with_master_cancellable(
                    &args.name,
                    &args.local,
                    &args.remote,
                    options,
                    Some(master),
                    tokio_util::sync::CancellationToken::new(),
                )
                .await?;
                if progress_mode == CliProgressMode::Quiet {
                    let _ = bytes;
                }
            }
            TransferCommand::Pull(args) => {
                let progress_mode = effective_progress_mode(args.options.progress);
                let options = transfer_client_options(&args.options);
                let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
                let bytes = client::transfer_pull_with_master_cancellable(
                    &args.name,
                    &args.remote,
                    &args.local,
                    options,
                    Some(master),
                    tokio_util::sync::CancellationToken::new(),
                )
                .await?;
                if progress_mode == CliProgressMode::Quiet {
                    let _ = bytes;
                }
            }
            TransferCommand::Status {
                name,
                transfer_id,
                watch,
                json,
            } => {
                let transfer_id = transfer_id
                    .as_deref()
                    .map(serctl_protocol::TransferId::parse)
                    .transpose()?;
                let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
                loop {
                    let snapshots =
                        client::transfer_status(&name, &master, transfer_id.clone()).await?;
                    if json {
                        for snapshot in &snapshots {
                            println!("{}", serde_json::to_string(snapshot)?);
                        }
                    } else if snapshots.is_empty() {
                        println!("no retained transfers for this profile");
                    } else {
                        for snapshot in &snapshots {
                            println!(
                                "{} {:?} {:?} {}/{} backend={} chunk={} window={}",
                                snapshot.transfer_id.as_str(),
                                snapshot.direction,
                                snapshot.stage,
                                snapshot.confirmed_bytes,
                                snapshot.total_bytes,
                                transfer_backend_name(snapshot.backend),
                                snapshot.chunk_bytes,
                                snapshot.window_bytes,
                            );
                        }
                    }
                    if snapshots.is_empty()
                        || !watch
                        || snapshots
                            .iter()
                            .all(|snapshot| transfer_is_terminal(snapshot.stage))
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
            TransferCommand::Cancel { name, transfer_id } => {
                let transfer_id = serctl_protocol::TransferId::parse(&transfer_id)?;
                let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
                client::transfer_cancel(&name, &master, transfer_id).await?;
                println!("transfer cancellation requested");
            }
        },
        Cmd::Shell { name } => {
            let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
            client::shell_with_master(&nm(name), Some(master)).await?;
        }
        Cmd::Tunnel { name, tunnel } => {
            let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
            client::tunnel_with_master(&name, tunnel.into_spec(), master).await?;
        }
        Cmd::Status { name } => {
            let name = nm(name);
            let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
            client::status(&name, &master).await?;
        }
        Cmd::Down { name } => {
            let name = nm(name);
            let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
            client::down(&name, &master).await?;
        }
        Cmd::GrantIssue {
            name,
            operations,
            budget,
            ttl_minutes,
            output,
        } => {
            let master = required_profile_passphrase(secrets.profile_passphrase.take())?;
            let grant = client::issue_grant_with_ttl_until(
                &name,
                &master,
                operations,
                budget,
                Duration::from_secs(u64::from(ttl_minutes).saturating_mul(60)),
                &output,
            )
            .await?;
            println!(
                "{}",
                grant_issued_message(
                    &grant.grant_id_hex(),
                    ttl_minutes,
                    grant.expires_unix_ms,
                    &output,
                )
            );
        }
        Cmd::Agent { grant } => {
            client::agent_stdio_loop(&grant).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    #[cfg(not(windows))]
    use super::reject_unsupported_platform_command;
    use super::{
        clap_diagnostic_without_trailing_line_endings, commit_generated_profile_passphrase_with,
        download_success_message, enter_linux_admin_target_for_command, local_exit_code,
        missing_profile_message, persist_generated_profile_passphrase, persist_new_recovery_media,
        read_recovery_media, removed_profile_message, required_profile_passphrase,
        saved_profile_message, take_supported_secret_envs_from, terminal_safe_clap_diagnostic,
        terminal_safe_error, terminal_safe_field, transfer_backend_name, unix_exit_code,
        upload_success_message, AdminCommand, Cli, Cmd, ProfilePasswordCommand, RecoveryCommand,
        SecretEnvAccess, StartupSecrets, SupportedSecretEnvs, TransferCommand,
        CLI_FAILURE_EXIT_CODE, MAX_RECOVERY_MEDIA_BYTES,
    };
    use clap::Parser;
    use std::{collections::BTreeMap, ffi::OsString, path::Path};

    #[derive(Default)]
    struct MemorySecretEnv {
        values: BTreeMap<String, OsString>,
        removals: Vec<String>,
    }

    #[test]
    fn human_transfer_backend_names_match_the_json_contract() {
        use serctl_protocol::TransferBackend;

        assert_eq!(transfer_backend_name(TransferBackend::Auto), "auto");
        assert_eq!(transfer_backend_name(TransferBackend::Native), "native");
        assert_eq!(transfer_backend_name(TransferBackend::Sftp), "sftp");
        assert_eq!(
            transfer_backend_name(TransferBackend::SftpFallback),
            "sftp_fallback"
        );
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

    fn unique_test_path(label: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("{label}-{}-{unique}", std::process::id()))
    }

    #[test]
    fn recovery_media_is_bounded_verified_and_never_overwritten() {
        let directory = unique_test_path("cli-recovery-media");
        std::fs::create_dir_all(&directory).unwrap();
        let media = directory.join("vault.srrec");
        let payload = b"test 2-of-2 recovery share";

        persist_new_recovery_media(&media, payload).unwrap();
        assert_eq!(read_recovery_media(&media).unwrap().as_slice(), payload);

        let collision = persist_new_recovery_media(&media, b"replacement").unwrap_err();
        assert!(format!("{collision:#}").contains("create new recovery media"));
        assert_eq!(std::fs::read(&media).unwrap(), payload);

        let oversized_path = directory.join("oversized.srrec");
        let oversized = vec![0_u8; MAX_RECOVERY_MEDIA_BYTES as usize + 1];
        assert!(persist_new_recovery_media(&oversized_path, &oversized).is_err());
        assert!(!oversized_path.exists());
        assert!(persist_new_recovery_media(Path::new("relative.srrec"), payload).is_err());
        assert!(read_recovery_media(Path::new("relative.srrec")).is_err());
        let forbidden_vault_media = super::vault::home_dir()
            .unwrap()
            .join(".serctl")
            .join(format!("forbidden-media-{}.srrec", std::process::id()));
        assert!(persist_new_recovery_media(&forbidden_vault_media, payload).is_err());
        assert!(!forbidden_vault_media.exists());

        std::fs::remove_file(media).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn generated_passphrase_is_verified_before_commit_and_never_overwritten() {
        let directory = unique_test_path("cli-random-passphrase");
        std::fs::create_dir_all(&directory).unwrap();
        let output = directory.join("profile-passphrase.txt");
        let passphrase = "generated-profile-passphrase";

        persist_generated_profile_passphrase(&output, passphrase).unwrap();
        assert_eq!(
            std::fs::read(&output).unwrap(),
            b"generated-profile-passphrase\n"
        );
        assert!(persist_generated_profile_passphrase(&output, "replacement-passphrase").is_err());
        assert_eq!(
            std::fs::read(&output).unwrap(),
            b"generated-profile-passphrase\n"
        );

        let committed = std::cell::Cell::new(false);
        let injected = commit_generated_profile_passphrase_with(
            &directory.join("injected.txt"),
            |_path, _generated| Err(std::io::Error::other("injected persistence failure").into()),
            |_generated| {
                committed.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(injected
            .to_string()
            .contains("injected persistence failure"));
        assert!(!committed.get(), "vault mutation ran after output failure");

        std::fs::remove_file(output).unwrap();
        std::fs::remove_dir(directory).unwrap();
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

        let transfer = Cli::try_parse_from([
            "serctl",
            "transfer",
            "push",
            "prod",
            "evidence.json",
            "/tmp/evidence.json",
            "--backend",
            "sftp",
            "--resume",
            "never",
            "--idle-timeout-secs",
            "30",
            "--progress",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            transfer.cmd,
            Some(Cmd::Transfer {
                command: TransferCommand::Push(_)
            })
        ));

        let status = Cli::try_parse_from([
            "serctl",
            "transfer",
            "status",
            "prod",
            "00000000000000000000000000000001",
            "--watch",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            status.cmd,
            Some(Cmd::Transfer {
                command: TransferCommand::Status {
                    watch: true,
                    json: true,
                    ..
                }
            })
        ));
    }

    #[test]
    fn grant_ttl_cli_accepts_forty_minutes_and_rejects_policy_overflow() {
        let parsed = Cli::try_parse_from([
            "serctl",
            "grant-issue",
            "prod",
            "--operations",
            "ssh.exec",
            "--ttl-minutes",
            "40",
            "--output",
            "grant.json",
        ])
        .unwrap();
        assert!(matches!(
            parsed.cmd,
            Some(Cmd::GrantIssue {
                ttl_minutes: 40,
                ..
            })
        ));

        for invalid in ["0", "41"] {
            assert!(Cli::try_parse_from([
                "serctl",
                "grant-issue",
                "prod",
                "--operations",
                "ssh.exec",
                "--ttl-minutes",
                invalid,
                "--output",
                "grant.json",
            ])
            .is_err());
        }
    }

    #[test]
    fn independent_password_and_recovery_commands_parse() {
        let admin = Cli::try_parse_from(["serctl", "admin", "change-password"]).unwrap();
        assert!(matches!(
            admin.cmd,
            Some(Cmd::Admin {
                command: AdminCommand::ChangePassword
            })
        ));

        let change = Cli::try_parse_from(["serctl", "profile-password", "prod", "change"]).unwrap();
        assert!(matches!(
            change.cmd,
            Some(Cmd::ProfilePassword {
                name,
                command: ProfilePasswordCommand::Change
            }) if name == "prod"
        ));

        let rotate = Cli::try_parse_from([
            "serctl",
            "profile-password",
            "prod",
            "rotate-random",
            "--random-output",
            "profile-passphrase.txt",
        ])
        .unwrap();
        assert!(matches!(
            rotate.cmd,
            Some(Cmd::ProfilePassword {
                command: ProfilePasswordCommand::RotateRandom { .. },
                ..
            })
        ));
        assert!(
            Cli::try_parse_from(["serctl", "profile-password", "prod", "rotate-random",]).is_err()
        );

        let reset = Cli::try_parse_from([
            "serctl",
            "profile-password",
            "prod",
            "admin-reset",
            "--host",
            "server.example",
            "--user",
            "deploy",
            "--replace-credentials",
            "--random",
            "--random-output",
            "profile-passphrase.txt",
        ])
        .unwrap();
        assert!(matches!(
            reset.cmd,
            Some(Cmd::ProfilePassword {
                command: ProfilePasswordCommand::AdminReset { random: true, .. },
                ..
            })
        ));

        let recovery =
            Cli::try_parse_from(["serctl", "admin", "init", "--recovery-media", "vault.srrec"])
                .unwrap();
        assert!(matches!(
            recovery.cmd,
            Some(Cmd::Admin {
                command: AdminCommand::Init { .. }
            })
        ));

        assert!(Cli::try_parse_from([
            "serctl",
            "profile-password",
            "prod",
            "admin-reset",
            "--media",
            "vault.srrec",
            "--replace-credentials",
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["serctl", "profile-password", "prod", "admin-reset",]).is_err()
        );
        assert!(Cli::try_parse_from([
            "serctl",
            "profile-password",
            "prod",
            "admin-reset",
            "--replace-credentials",
            "--random",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "serctl",
            "profile-password",
            "prod",
            "admin-reset",
            "--replace-credentials",
            "--random-output",
            "profile-passphrase.txt",
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["serctl", "recovery", "restore", "--media", "vault.srrec",])
                .is_err()
        );

        assert!(Cli::try_parse_from(["serctl", "change-master"]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_admin_reset_requires_target_user_before_runtime_start() {
        let command = Cli::try_parse_from([
            "serctl",
            "profile-password",
            "prod",
            "admin-reset",
            "--replace-credentials",
        ])
        .unwrap()
        .cmd
        .unwrap();
        let error = enter_linux_admin_target_for_command(&command).unwrap_err();
        assert!(error.to_string().contains("--target-user"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_rejects_target_user_instead_of_ignoring_it() {
        let command = Cli::try_parse_from([
            "serctl",
            "profile-password",
            "prod",
            "admin-reset",
            "--replace-credentials",
            "--target-user",
            "alice",
        ])
        .unwrap()
        .cmd
        .unwrap();
        let error = enter_linux_admin_target_for_command(&command).unwrap_err();
        assert!(error.to_string().contains("Linux"));
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_linux_recovery_paths_fail_before_secret_capture() {
        let migration = Cli::try_parse_from([
            "serctl",
            "recovery",
            "migrate-v2",
            "--recovery-media",
            "media.srrec",
        ])
        .unwrap()
        .cmd
        .unwrap();
        assert!(reject_unsupported_platform_command(&migration).is_err());

        let preserve = Cli::try_parse_from([
            "serctl",
            "profile-password",
            "prod",
            "admin-reset",
            "--media",
            "media.srrec",
            "--target-user",
            "alice",
        ])
        .unwrap()
        .cmd
        .unwrap();
        assert!(reject_unsupported_platform_command(&preserve).is_err());
    }

    #[test]
    fn add_accepts_an_explicit_sha256_host_key_pin() {
        let cli = Cli::try_parse_from([
            "serctl",
            "add",
            "prod",
            "--host",
            "server.example",
            "--user",
            "deploy",
            "--host-key-sha256",
            "SHA256:expected-host-key",
        ])
        .unwrap();
        let Some(Cmd::Add {
            host_key_sha256, ..
        }) = cli.cmd
        else {
            panic!("add command was not parsed");
        };
        assert_eq!(host_key_sha256.as_deref(), Some("SHA256:expected-host-key"));
    }

    #[test]
    fn tunnel_modes_parse_with_loopback_only_endpoints() {
        let local =
            Cli::try_parse_from(["serctl", "tunnel", "prod", "local", "--target-port", "5432"])
                .unwrap();
        let Some(Cmd::Tunnel { tunnel, .. }) = local.cmd else {
            panic!("local tunnel command was not parsed");
        };
        let spec = tunnel.into_spec();
        assert_eq!(spec.mode, crate::client::TunnelMode::Local);
        assert_eq!(spec.bind_port, 0);
        assert_eq!(spec.max_connections, 32);
        assert_eq!(spec.target_port, 5432);

        let dynamic = Cli::try_parse_from([
            "serctl",
            "tunnel",
            "prod",
            "dynamic",
            "--port",
            "1080",
            "--max-connections",
            "64",
        ])
        .unwrap();
        let Some(Cmd::Tunnel { tunnel, .. }) = dynamic.cmd else {
            panic!("dynamic tunnel command was not parsed");
        };
        let spec = tunnel.into_spec();
        assert_eq!(spec.mode, crate::client::TunnelMode::Dynamic);
        assert_eq!(spec.bind_port, 1080);
        assert_eq!(spec.max_connections, 64);
        assert_eq!(spec.target_port, 0);

        assert!(
            Cli::try_parse_from(["serctl", "tunnel", "prod", "dynamic", "--bind", "0.0.0.0",])
                .is_err()
        );
        assert!(Cli::try_parse_from(["serctl", "tunnel", "prod", "dynamic", "--expose"]).is_err());
        assert!(Cli::try_parse_from([
            "serctl",
            "tunnel",
            "prod",
            "local",
            "--target-host",
            "db.internal",
            "--target-port",
            "5432",
        ])
        .is_err());
    }

    #[test]
    fn empty_supplied_profile_passphrase_is_rejected_without_prompting() {
        let error = required_profile_passphrase(Some(zeroize::Zeroizing::new(String::new())))
            .expect_err("empty profile passphrase must fail");
        assert!(error.to_string().contains("profile passphrase is required"));
    }

    #[test]
    fn profile_operations_capture_only_the_profile_secret() {
        for command in [
            Cmd::Remove {
                name: "prod".into(),
            },
            Cmd::Tunnel {
                name: "prod".into(),
                tunnel: super::TunnelCommand::Dynamic {
                    common: super::TunnelCommonArgs {
                        port: 0,
                        max_connections: 32,
                    },
                },
            },
        ] {
            let secrets = StartupSecrets::from_captured(
                &command,
                SupportedSecretEnvs {
                    profile_passphrase: Some(zeroize::Zeroizing::new("profile-secret".into())),
                    admin_password: Some(zeroize::Zeroizing::new("admin-secret".into())),
                    ..SupportedSecretEnvs::default()
                },
            );
            assert_eq!(
                secrets.profile_passphrase.as_deref().map(String::as_str),
                Some("profile-secret")
            );
            assert!(secrets.admin_password.is_none());
        }
    }

    #[test]
    fn secret_routing_separates_admin_profile_and_legacy_authority() {
        let admin = StartupSecrets::from_captured(
            &Cmd::Admin {
                command: AdminCommand::Verify,
            },
            SupportedSecretEnvs {
                profile_passphrase: Some(zeroize::Zeroizing::new("profile-secret".into())),
                admin_password: Some(zeroize::Zeroizing::new("admin-secret".into())),
                legacy_master: Some(zeroize::Zeroizing::new("legacy-secret".into())),
                ..SupportedSecretEnvs::default()
            },
        );
        assert_eq!(
            admin.admin_password.as_deref().map(String::as_str),
            Some("admin-secret")
        );
        assert!(admin.profile_passphrase.is_none());
        assert!(admin.legacy_master.is_none());

        for command in [
            Cmd::List,
            Cmd::Admin {
                command: AdminCommand::Status,
            },
        ] {
            let public = StartupSecrets::from_captured(
                &command,
                SupportedSecretEnvs {
                    profile_passphrase: Some(zeroize::Zeroizing::new("profile-secret".into())),
                    admin_password: Some(zeroize::Zeroizing::new("admin-secret".into())),
                    ..SupportedSecretEnvs::default()
                },
            );
            assert!(public.profile_passphrase.is_none());
            assert!(public.admin_password.is_none());
        }

        let migration = StartupSecrets::from_captured(
            &Cmd::Recovery {
                command: RecoveryCommand::MigrateV2 {
                    recovery_media: "vault.srrec".into(),
                },
            },
            SupportedSecretEnvs {
                compatibility_master: Some(zeroize::Zeroizing::new("legacy-secret".into())),
                ..SupportedSecretEnvs::default()
            },
        );
        assert_eq!(
            migration.legacy_master.as_deref().map(String::as_str),
            Some("legacy-secret")
        );
        assert!(migration.profile_passphrase.is_none());

        let ui_secrets = StartupSecrets::from_captured(
            &Cmd::Ui,
            SupportedSecretEnvs {
                ssh_password: Some(zeroize::Zeroizing::new("ssh-secret".into())),
                profile_passphrase: Some(zeroize::Zeroizing::new("profile-secret".into())),
                admin_password: Some(zeroize::Zeroizing::new("admin-secret".into())),
                legacy_master: Some(zeroize::Zeroizing::new("legacy-secret".into())),
                ..SupportedSecretEnvs::default()
            },
        );
        assert!(ui_secrets.ssh_password.is_none());
        assert!(ui_secrets.profile_passphrase.is_none());
        assert!(ui_secrets.admin_password.is_none());
        assert!(ui_secrets.legacy_master.is_none());
    }

    #[test]
    fn startup_capture_snapshots_and_removes_supported_secrets() {
        let mut env = MemorySecretEnv::default();
        env.values
            .insert("SERCTL_SSH_PASS".into(), "test-ssh-password".into());
        env.values.insert(
            "SERCTL_PROFILE_PASS".into(),
            "test-profile-passphrase".into(),
        );
        env.values
            .insert("SERCTL_ADMIN_PASS".into(), "test-admin-password".into());
        env.values
            .insert("SERCTL_LEGACY_MASTER".into(), "test-legacy-master".into());
        env.values
            .insert("SERCTL_MASTER".into(), "compatibility-master".into());

        let captured = take_supported_secret_envs_from(&mut env).expect("capture startup secrets");
        let secrets = StartupSecrets::from_captured(
            &Cmd::Add {
                name: None,
                host: None,
                user: None,
                port: 22,
                host_key_sha256: None,
            },
            captured,
        );

        assert!(env.values.is_empty());
        assert_eq!(
            env.removals,
            [
                "SERCTL_SSH_PASS".to_owned(),
                "SERCTL_PROFILE_PASS".to_owned(),
                "SERCTL_ADMIN_PASS".to_owned(),
                "SERCTL_LEGACY_MASTER".to_owned(),
                "SERCTL_MASTER".to_owned(),
            ]
        );
        assert_eq!(
            secrets.ssh_password.as_deref().map(|value| value.as_str()),
            Some("test-ssh-password")
        );
        assert_eq!(
            secrets
                .profile_passphrase
                .as_deref()
                .map(|value| value.as_str()),
            Some("test-profile-passphrase")
        );
        assert_eq!(
            secrets
                .admin_password
                .as_deref()
                .map(|value| value.as_str()),
            Some("test-admin-password")
        );
        assert!(secrets.legacy_master.is_none());
    }

    #[test]
    fn invalid_first_secret_still_removes_the_second_before_returning_error() {
        let mut env = MemorySecretEnv::default();
        env.values
            .insert("SERCTL_SSH_PASS".into(), invalid_unicode_env_value());
        env.values
            .insert("SERCTL_ADMIN_PASS".into(), "test-admin-password".into());

        let error = match take_supported_secret_envs_from(&mut env) {
            Ok(_) => panic!("invalid secret unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("SERCTL_SSH_PASS"));
        assert!(env.values.is_empty());
        assert_eq!(
            env.removals,
            ["SERCTL_SSH_PASS".to_owned(), "SERCTL_ADMIN_PASS".to_owned()]
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
        assert!(!clap_diagnostic_without_trailing_line_endings(&help.text).ends_with(['\r', '\n']));
    }
}
