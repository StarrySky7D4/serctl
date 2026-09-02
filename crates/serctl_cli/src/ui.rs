//! Desktop frontend. Eframe supplies the renderer and drives its native window
//! through Winit; all blocking vault/SSH work stays off the Winit event loop.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use eframe::egui::{self, Color32, FontFamily, FontId, RichText, TextEdit};
use tokio::runtime::Runtime;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use crate::client;
use crate::launcher::DAEMON_STARTUP_TIMEOUT;
use serctl_core::{security, ssh::RemoteEntry, vault};

const MAX_CONCURRENT_STATUS_PROBES: usize = 8;
const TRANSFER_EXIT_GRACE: Duration = Duration::from_secs(6);
const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
const PROFILE_REFRESH_TIMEOUT: Duration = Duration::from_secs(32);
const ABORT_JOIN_GRACE: Duration = Duration::from_millis(250);
// Client/daemon cleanup has an internal 7-second bound. Keep a margin so this
// outer UI join observes that fail-closed abort instead of detaching it first.
const TUNNEL_EXIT_GRACE: Duration = Duration::from_secs(8);
const MAX_UI_TUNNEL_CONNECTIONS: u16 = 128;
const UI_AUTHORIZATION_TTL: Duration = Duration::from_secs(5 * 60);
const UI_AUTHORIZATION_VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
const UI_ADMIN_AUTHORIZATION_TTL: Duration = Duration::from_secs(2 * 60);
const UI_DIRECTORY_REFRESH_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RECOVERY_MEDIA_FILE_BYTES: u64 = 4 * 1024 * 1024;
const PROFILE_HEADER_HEIGHT: f32 = 52.0;

/// Recovery media is intentionally portable, but it must still be created as
/// a new regular, non-link object through a stable read/write handle. This is
/// kept equivalent to the CLI path so a UI-created medium has the same safety
/// and durability guarantees.
fn create_new_recovery_media_file(path: &Path) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
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
        .with_context(|| format!("创建新的恢复介质 {}", path.display()))?;
    let metadata = file.metadata().context("检查新恢复介质的文件句柄")?;
    if !metadata.file_type().is_file() {
        bail!("恢复介质目标不是普通文件");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("恢复介质目标不能是重解析点");
        }
    }
    Ok(file)
}

fn persist_recovery_media_new(path: &Path, media: &[u8]) -> Result<()> {
    use subtle::ConstantTimeEq;

    crate::validate_external_secret_path(path, false, "UI recovery-media output")?;
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(anyhow!("恢复介质必须使用绝对文件路径"));
    }
    if media.is_empty() || media.len() as u64 > MAX_RECOVERY_MEDIA_FILE_BYTES {
        bail!("恢复介质内容为空或超过 4 MiB 安全上限");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("恢复介质路径没有父目录"))?;
    if !parent.is_dir() {
        return Err(anyhow!("恢复介质的父目录不存在"));
    }
    let mut file = create_new_recovery_media_file(path)?;
    file.write_all(media)
        .with_context(|| format!("写入恢复介质 {}；可能残留部分文件", path.display()))?;
    file.sync_all()
        .with_context(|| format!("同步恢复介质 {}；可能残留部分文件", path.display()))?;

    // Verify the exact bytes through the same stable handle before the vault
    // transaction is allowed to commit. This catches short/removable-media
    // writes without reopening an attacker-replaceable pathname.
    file.rewind().context("回绕恢复介质以执行写后校验")?;
    let mut persisted = Zeroizing::new(vec![0_u8; media.len()]);
    file.read_exact(&mut persisted)
        .context("回读恢复介质以执行写后校验")?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 || !bool::from(persisted.as_slice().ct_eq(media)) {
        bail!("恢复介质写后校验失败");
    }

    #[cfg(unix)]
    {
        std::fs::File::open(parent)
            .with_context(|| format!("打开恢复介质目录 {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("同步恢复介质目录 {}", parent.display()))?;
    }
    Ok(())
}

fn read_recovery_media(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    crate::validate_external_secret_path(path, true, "UI recovery media")?;
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(anyhow!("恢复介质必须使用绝对文件路径"));
    }
    let mut file = security::open_regular_file_for_read(path)
        .map_err(|error| anyhow!("安全打开恢复介质失败：{error}"))?;
    let declared = file
        .metadata()
        .map_err(|error| anyhow!("检查恢复介质大小失败：{error}"))?
        .len();
    if declared == 0 || declared > MAX_RECOVERY_MEDIA_FILE_BYTES {
        bail!("恢复介质为空或超过 4 MiB 安全上限");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(declared as usize));
    (&mut file)
        .take(MAX_RECOVERY_MEDIA_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow!("读取恢复介质失败：{error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECOVERY_MEDIA_FILE_BYTES {
        bail!("读取期间恢复介质大小发生变化");
    }
    Ok(bytes)
}

#[derive(Default)]
struct UiAuthorization {
    passphrase: Option<Zeroizing<String>>,
    expires_at: Option<Instant>,
}

impl UiAuthorization {
    fn grant(&mut self, passphrase: Zeroizing<String>, verified_at: Instant) {
        self.revoke();
        self.passphrase = Some(passphrase);
        self.expires_at = Some(verified_at + UI_AUTHORIZATION_TTL);
    }

    fn revoke(&mut self) {
        drop(self.passphrase.take());
        self.expires_at = None;
    }

    fn is_expired_at(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }

    fn remaining_at(&self, now: Instant) -> Option<Duration> {
        self.expires_at
            .filter(|expires_at| *expires_at > now)
            .map(|expires_at| expires_at - now)
    }

    fn passphrase(&self) -> Option<Zeroizing<String>> {
        self.passphrase
            .as_ref()
            .map(|passphrase| Zeroizing::new(passphrase.as_str().to_owned()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProfileAuthorizationKey {
    profile: String,
    profile_id: [u8; 16],
    generation: u64,
}

#[derive(Default)]
struct UiAuthorizations {
    grants: BTreeMap<ProfileAuthorizationKey, UiAuthorization>,
}

impl UiAuthorizations {
    fn grant(
        &mut self,
        profile: String,
        identity: vault::ProfileIdentity,
        passphrase: Zeroizing<String>,
        verified_at: Instant,
    ) {
        self.revoke_profile(profile.as_str());
        let mut authorization = UiAuthorization::default();
        authorization.grant(passphrase, verified_at);
        self.grants.insert(
            ProfileAuthorizationKey {
                profile,
                profile_id: identity.profile_id,
                generation: identity.generation,
            },
            authorization,
        );
    }

    fn get(
        &self,
        profile: &str,
        identity: vault::ProfileIdentity,
        now: Instant,
    ) -> Option<&UiAuthorization> {
        self.grants
            .get(&ProfileAuthorizationKey {
                profile: profile.to_owned(),
                profile_id: identity.profile_id,
                generation: identity.generation,
            })
            .filter(|authorization| !authorization.is_expired_at(now))
    }

    fn passphrase(
        &self,
        profile: &str,
        identity: vault::ProfileIdentity,
        now: Instant,
    ) -> Option<Zeroizing<String>> {
        self.get(profile, identity, now)?.passphrase()
    }

    fn remaining_at(
        &self,
        profile: &str,
        identity: vault::ProfileIdentity,
        now: Instant,
    ) -> Option<Duration> {
        self.get(profile, identity, now)?.remaining_at(now)
    }

    fn revoke_profile(&mut self, profile: &str) -> bool {
        let keys = self
            .grants
            .keys()
            .filter(|key| key.profile == profile)
            .cloned()
            .collect::<Vec<_>>();
        let removed = !keys.is_empty();
        for mut key in keys {
            self.grants.remove(&key);
            key.profile.zeroize();
        }
        removed
    }

    fn revoke_all(&mut self) {
        for (mut key, mut authorization) in std::mem::take(&mut self.grants) {
            key.profile.zeroize();
            authorization.revoke();
        }
    }

    fn expire_at(&mut self, now: Instant) -> Vec<ProfileAuthorizationKey> {
        let expired = self
            .grants
            .iter()
            .filter(|(_, authorization)| authorization.is_expired_at(now))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &expired {
            self.grants.remove(key);
        }
        expired
    }

    fn retain_current_profiles(&mut self, profiles: &[ProfileRow]) -> bool {
        let stale = self
            .grants
            .keys()
            .filter(|key| {
                !profiles.iter().any(|profile| {
                    profile.name == key.profile
                        && profile.generation == key.generation
                        && profile.profile_id == key.profile_id
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        let removed = !stale.is_empty();
        for mut key in stale {
            self.grants.remove(&key);
            key.profile.zeroize();
        }
        removed
    }
}

struct AuthorizationGrant {
    profile: String,
    identity: vault::ProfileIdentity,
    passphrase: Zeroizing<String>,
    verified_at: Instant,
}

#[derive(Default)]
struct AdminAuthorization {
    passphrase: Option<Zeroizing<String>>,
    expires_at: Option<Instant>,
}

impl AdminAuthorization {
    fn grant(&mut self, passphrase: Option<Zeroizing<String>>, verified_at: Instant) {
        self.revoke();
        self.passphrase = passphrase;
        self.expires_at = Some(verified_at + UI_ADMIN_AUTHORIZATION_TTL);
    }

    fn revoke(&mut self) {
        drop(self.passphrase.take());
        self.expires_at = None;
    }

    fn is_valid_at(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|expires_at| now < expires_at)
    }

    fn remaining_at(&self, now: Instant) -> Option<Duration> {
        self.expires_at
            .filter(|expires_at| *expires_at > now)
            .map(|expires_at| expires_at - now)
    }

    fn passphrase_at(&self, now: Instant) -> Option<Option<Zeroizing<String>>> {
        self.is_valid_at(now).then(|| {
            self.passphrase
                .as_ref()
                .map(|passphrase| Zeroizing::new(passphrase.as_str().to_owned()))
        })
    }
}

struct AdminAuthorizationGrant {
    passphrase: Option<Zeroizing<String>>,
    verified_at: Instant,
}

async fn verify_ui_admin_authorization(
    passphrase: Option<Zeroizing<String>>,
    deadline: tokio::time::Instant,
) -> Result<AdminAuthorizationGrant, String> {
    let mut task = tokio::task::spawn_blocking(move || {
        vault::verify_admin_password(passphrase.as_deref().map(String::as_str))
            .map(|_| passphrase)
            .map_err(|error| error.to_string())
    });
    let passphrase = match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(Ok(Ok(passphrase))) => passphrase,
        Ok(Ok(Err(error))) => return Err(error),
        Ok(Err(error)) => return Err(format!("超管授权任务失败：{error}")),
        Err(_) => {
            task.abort();
            return Err("超管授权超过 30 秒等待上限".into());
        }
    };
    Ok(AdminAuthorizationGrant {
        passphrase,
        verified_at: Instant::now(),
    })
}

type VaultProfileRows = Vec<vault::ProfileMetadata>;

struct SensitiveProfileListResult(Option<Result<VaultProfileRows, String>>);

impl SensitiveProfileListResult {
    fn new(result: Result<VaultProfileRows, String>) -> Self {
        Self(Some(result))
    }

    fn into_result(mut self) -> Result<VaultProfileRows, String> {
        self.0.take().expect("profile-list result is empty")
    }
}

impl Drop for SensitiveProfileListResult {
    fn drop(&mut self) {
        let Some(result) = &mut self.0 else {
            return;
        };
        match result {
            Ok(rows) => {
                for row in rows.iter_mut() {
                    row.name.zeroize();
                    row.host.zeroize();
                }
                rows.clear();
            }
            Err(error) => error.zeroize(),
        }
    }
}

async fn await_blocking_until<T: Send + 'static>(
    mut task: tokio::task::JoinHandle<T>,
    deadline: tokio::time::Instant,
    description: &'static str,
) -> Result<T, String> {
    if deadline <= tokio::time::Instant::now() {
        task.abort();
        return Err(format!("{description}超过主机刷新操作的绝对等待上限"));
    }
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("{description}任务失败：{error}")),
        Err(_) => {
            // A queued blocking operation is canceled. A running one remains
            // detached, but its owned SensitiveProfileListResult zeroizes any
            // late result when the abandoned JoinHandle output is dropped.
            task.abort();
            Err(format!("{description}超过主机刷新操作的绝对等待上限"))
        }
    }
}

async fn load_vault_profile_rows(
    deadline: tokio::time::Instant,
) -> Result<VaultProfileRows, String> {
    let task = tokio::task::spawn_blocking(|| {
        SensitiveProfileListResult::new(
            vault::list_profile_metadata().map_err(|error| error.to_string()),
        )
    });
    await_blocking_until(task, deadline, "读取主机配置")
        .await?
        .into_result()
}

#[derive(Clone)]
struct ProfileRow {
    name: String,
    host: String,
    port: u16,
    generation: u64,
    profile_id: [u8; 16],
    daemon: Option<client::DaemonStatus>,
}

impl ProfileRow {
    fn identity(&self) -> vault::ProfileIdentity {
        vault::ProfileIdentity {
            profile_id: self.profile_id,
            generation: self.generation,
        }
    }
}

fn spawn_status_probe<R, P, F>(probes: &mut JoinSet<ProfileRow>, row: R, probe: P)
where
    R: Send + 'static,
    P: FnOnce(R) -> F + Send + 'static,
    F: std::future::Future<Output = ProfileRow> + Send + 'static,
{
    probes.spawn(probe(row));
}

async fn load_profile_rows_with_probe<R, P, F>(
    rows: Vec<R>,
    deadline: tokio::time::Instant,
    probe: P,
) -> Result<Vec<ProfileRow>, String>
where
    R: Send + 'static,
    P: Fn(R) -> F + Clone + Send + 'static,
    F: std::future::Future<Output = ProfileRow> + Send + 'static,
{
    if deadline <= tokio::time::Instant::now() {
        return Err("主机状态刷新超过绝对等待上限".into());
    }
    let row_count = rows.len();
    let mut remaining = rows.into_iter();
    let mut probes = JoinSet::new();
    for row in remaining.by_ref().take(MAX_CONCURRENT_STATUS_PROBES) {
        spawn_status_probe(&mut probes, row, probe.clone());
    }

    let mut result = Vec::with_capacity(row_count);
    while !probes.is_empty() {
        let joined = match tokio::time::timeout_at(deadline, probes.join_next()).await {
            Ok(Some(joined)) => joined,
            Ok(None) => break,
            Err(_) => {
                probes.abort_all();
                return Err("主机状态刷新超过绝对等待上限".into());
            }
        };
        let row = match joined {
            Ok(row) => row,
            Err(error) => {
                probes.abort_all();
                return Err(format!("主机状态查询任务失败：{error}"));
            }
        };
        result.push(row);
        if let Some(row) = remaining.next() {
            spawn_status_probe(&mut probes, row, probe.clone());
        }
    }
    result.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

async fn load_profile_rows(
    rows: VaultProfileRows,
    authorizations: Vec<(String, vault::ProfileIdentity, Zeroizing<String>)>,
    deadline: tokio::time::Instant,
) -> Result<Vec<ProfileRow>, String> {
    let authorizations = authorizations
        .into_iter()
        .map(|(name, identity, passphrase)| ((name, identity), passphrase))
        .collect::<BTreeMap<_, _>>();
    let rows = rows
        .into_iter()
        .map(|row| {
            let passphrase: Option<Zeroizing<String>> = authorizations
                .get(&(row.name.clone(), row.identity()))
                .map(|passphrase| Zeroizing::new(passphrase.as_str().to_owned()));
            (row, passphrase)
        })
        .collect();
    load_profile_rows_with_probe(rows, deadline, move |(row, passphrase)| async move {
        // Merely opening/refeshing the UI must never contact a daemon or the
        // network for a profile whose independent passphrase is not cached.
        let daemon = match passphrase {
            Some(passphrase) => {
                client::daemon_status_probe_at_generation(&row.name, &passphrase, row.identity())
                    .await
                    .unwrap_or(None)
            }
            None => None,
        };
        ProfileRow {
            name: row.name,
            host: row.host,
            port: row.port,
            generation: row.generation,
            profile_id: row.profile_id,
            daemon,
        }
    })
    .await
}

async fn verify_ui_authorization(
    profile: String,
    expected_identity: vault::ProfileIdentity,
    passphrase: Zeroizing<String>,
    deadline: tokio::time::Instant,
) -> Result<AuthorizationGrant, String> {
    let mut task = tokio::task::spawn_blocking(move || {
        vault::verify_profile_identity(&profile, passphrase.as_str())
            .and_then(|identity| {
                if identity == expected_identity {
                    Ok((profile, identity, passphrase))
                } else {
                    Err(anyhow!(
                        "profile changed while authorization was being verified"
                    ))
                }
            })
            .map_err(|error| error.to_string())
    });
    let (profile, identity, passphrase) = match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(Ok(Ok(grant))) => grant,
        Ok(Ok(Err(error))) => return Err(error),
        Ok(Err(error)) => return Err(format!("独立口令验证任务失败：{error}")),
        Err(_) => {
            task.abort();
            return Err("独立口令验证超过 30 秒等待上限".into());
        }
    };
    Ok(AuthorizationGrant {
        profile,
        identity,
        passphrase,
        verified_at: Instant::now(),
    })
}

enum UiMessage {
    Authorization {
        operation: OperationContext,
        result: Result<AuthorizationGrant, String>,
    },
    AdminAuthorization {
        operation: OperationContext,
        result: Result<AdminAuthorizationGrant, String>,
    },
    AdminStatus {
        operation: OperationContext,
        result: Result<vault::AdminStatus, String>,
    },
    AdminInitialized {
        operation: OperationContext,
        result: Result<String, String>,
    },
    AdminPasswordChanged {
        operation: OperationContext,
        result: Result<(), String>,
    },
    RecoveryRotated {
        operation: OperationContext,
        result: Result<String, String>,
    },
    ProfileRecovered {
        operation: OperationContext,
        profile: String,
        result: Result<u64, String>,
    },
    ProfileReset {
        operation: OperationContext,
        profile: String,
        result: Result<u64, String>,
    },
    #[cfg(windows)]
    Migrated {
        operation: OperationContext,
        result: Result<usize, String>,
    },
    #[cfg(any(windows, test))]
    MigrationProgress {
        operation_id: u64,
        progress: vault::MigrationProgress,
    },
    Profiles {
        operation: OperationContext,
        epoch: u64,
        result: Result<Vec<ProfileRow>, String>,
    },
    Saved {
        operation: OperationContext,
        original_name: Option<String>,
        result: Result<String, String>,
    },
    ProfilePassphraseChanged {
        operation: OperationContext,
        profile: String,
        result: Result<u64, String>,
    },
    Removed {
        operation: OperationContext,
        result: Result<String, String>,
    },
    Command {
        operation: OperationContext,
        result: Result<client::CommandOutput, String>,
    },
    DaemonStarted {
        operation: OperationContext,
        profile: String,
        instance: u64,
        result: Result<bool, String>,
    },
    DaemonStopped {
        operation: OperationContext,
        profile: String,
        instance: Option<u64>,
        result: Result<(), String>,
    },
    /// Reserved for broker-exit notifications (e.g. idle exit). The global
    /// daemon outlives the UI, so nothing sends it yet.
    #[allow(dead_code)]
    DaemonEnded {
        operation: OperationContext,
        profile: String,
        instance: u64,
        error: String,
    },
    Directory {
        operation: OperationContext,
        request: DirectoryRequest,
        result: Result<(String, Vec<RemoteEntry>), String>,
    },
    DirectoryCreated {
        operation: OperationContext,
        context: DirectoryRequest,
        result: Result<String, String>,
    },
    Transfer {
        operation: OperationContext,
        refresh: Option<DirectoryRequest>,
        result: Result<String, String>,
    },
    TransferProgress {
        operation_id: u64,
        progress: serctl_protocol::TransferProgress,
    },
    ShellOpened {
        operation: OperationContext,
        result: Result<(String, client::GuiShell), String>,
    },
    TunnelStarted {
        operation: OperationContext,
        context: TunnelContext,
        spec: client::TunnelSpec,
        result: Result<client::GuiTunnel, String>,
    },
    TunnelEnded {
        context: TunnelContext,
        result: Result<(), String>,
    },
    #[cfg(test)]
    ZeroizeProbe(Arc<std::sync::atomic::AtomicBool>),
}

impl UiMessage {
    fn zeroize_sensitive(&mut self) {
        match self {
            Self::Authorization { operation, result } => {
                zeroize_operation_context(operation);
                match result {
                    Ok(grant) => {
                        grant.profile.zeroize();
                        grant.passphrase.zeroize();
                    }
                    Err(error) => error.zeroize(),
                }
            }
            Self::AdminAuthorization { operation, result } => {
                zeroize_operation_context(operation);
                match result {
                    Ok(grant) => {
                        if let Some(passphrase) = grant.passphrase.as_mut() {
                            passphrase.zeroize();
                        }
                    }
                    Err(error) => error.zeroize(),
                }
            }
            Self::AdminStatus { operation, result } => {
                zeroize_operation_context(operation);
                if let Err(error) = result {
                    error.zeroize();
                }
            }
            Self::AdminInitialized { operation, result } => {
                zeroize_operation_context(operation);
                zeroize_string_result(result);
            }
            Self::AdminPasswordChanged { operation, result } => {
                zeroize_operation_context(operation);
                if let Err(error) = result {
                    error.zeroize();
                }
            }
            Self::RecoveryRotated { operation, result } => {
                zeroize_operation_context(operation);
                zeroize_string_result(result);
            }
            Self::ProfileRecovered {
                operation,
                profile,
                result,
            }
            | Self::ProfileReset {
                operation,
                profile,
                result,
            } => {
                zeroize_operation_context(operation);
                profile.zeroize();
                if let Err(error) = result {
                    error.zeroize();
                }
            }
            #[cfg(windows)]
            Self::Migrated { operation, result } => {
                zeroize_operation_context(operation);
                if let Err(error) = result {
                    error.zeroize();
                }
            }
            #[cfg(any(windows, test))]
            Self::MigrationProgress { progress, .. } => {
                if let vault::MigrationProgress::MigratingProfile { profile, .. } = progress {
                    profile.zeroize();
                }
            }
            Self::Profiles {
                operation, result, ..
            } => {
                zeroize_operation_context(operation);
                zeroize_profile_result(result);
            }
            Self::Saved {
                operation,
                original_name,
                result,
            } => {
                zeroize_operation_context(operation);
                zeroize_option_string(original_name);
                zeroize_string_result(result);
            }
            Self::ProfilePassphraseChanged {
                operation,
                profile,
                result,
            } => {
                zeroize_operation_context(operation);
                profile.zeroize();
                if let Err(error) = result {
                    error.zeroize();
                }
            }
            Self::Removed { operation, result } => {
                zeroize_operation_context(operation);
                zeroize_string_result(result);
            }
            Self::Command { operation, result } => {
                zeroize_operation_context(operation);
                match result {
                    Ok(output) => {
                        output.stdout.zeroize();
                        output.stderr.zeroize();
                    }
                    Err(error) => error.zeroize(),
                }
            }
            Self::DaemonStarted {
                operation,
                profile,
                result,
                ..
            } => {
                zeroize_operation_context(operation);
                profile.zeroize();
                if let Err(error) = result {
                    error.zeroize();
                }
            }
            Self::DaemonStopped {
                operation,
                profile,
                result,
                ..
            } => {
                zeroize_operation_context(operation);
                profile.zeroize();
                if let Err(error) = result {
                    error.zeroize();
                }
            }
            Self::DaemonEnded {
                operation,
                profile,
                error,
                ..
            } => {
                zeroize_operation_context(operation);
                profile.zeroize();
                error.zeroize();
            }
            Self::Directory {
                operation,
                request,
                result,
            } => {
                zeroize_operation_context(operation);
                zeroize_directory_request(request);
                zeroize_directory_result(result);
            }
            Self::DirectoryCreated {
                operation,
                context,
                result,
            } => {
                zeroize_operation_context(operation);
                zeroize_directory_request(context);
                zeroize_string_result(result);
            }
            Self::Transfer {
                operation,
                refresh,
                result,
            } => {
                zeroize_operation_context(operation);
                if let Some(refresh) = refresh {
                    zeroize_directory_request(refresh);
                }
                zeroize_string_result(result);
            }
            Self::TransferProgress { progress, .. } => {
                progress.event.zeroize();
            }
            Self::ShellOpened { operation, result } => {
                zeroize_operation_context(operation);
                match result {
                    Ok((profile, shell)) => {
                        profile.zeroize();
                        shell.cancel();
                    }
                    Err(error) => error.zeroize(),
                }
            }
            Self::TunnelStarted {
                operation,
                context,
                spec,
                result,
            } => {
                zeroize_operation_context(operation);
                zeroize_tunnel_context(context);
                zeroize_tunnel_spec(spec);
                match result {
                    Ok(tunnel) => tunnel.cancel(),
                    Err(error) => error.zeroize(),
                }
            }
            Self::TunnelEnded { context, result } => {
                zeroize_tunnel_context(context);
                if let Err(error) = result {
                    error.zeroize();
                }
            }
            #[cfg(test)]
            Self::ZeroizeProbe(probe) => {
                probe.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
}

fn zeroize_profile_row(row: &mut ProfileRow) {
    row.name.zeroize();
    row.host.zeroize();
    if let Some(status) = &mut row.daemon {
        status.profile.zeroize();
        status.host.zeroize();
        status.user.zeroize();
        status.endpoint.zeroize();
    }
}

fn zeroize_profile_result(result: &mut Result<Vec<ProfileRow>, String>) {
    match result {
        Ok(rows) => {
            for row in rows.iter_mut() {
                zeroize_profile_row(row);
            }
            rows.clear();
        }
        Err(error) => error.zeroize(),
    }
}

fn zeroize_operation_context(operation: &mut OperationContext) {
    zeroize_option_string(&mut operation.profile);
}

fn zeroize_directory_request(request: &mut DirectoryRequest) {
    request.profile.zeroize();
    request.path.zeroize();
}

fn zeroize_tunnel_context(context: &mut TunnelContext) {
    context.profile.zeroize();
}

fn zeroize_tunnel_spec(_spec: &mut client::TunnelSpec) {}

fn clone_tunnel_spec(spec: &client::TunnelSpec) -> client::TunnelSpec {
    client::TunnelSpec {
        mode: spec.mode,
        bind_port: spec.bind_port,
        target_port: spec.target_port,
        max_connections: spec.max_connections,
    }
}

fn zeroize_remote_entries(entries: &mut Vec<RemoteEntry>) {
    for entry in entries.iter_mut() {
        entry.name.zeroize();
        entry.path.zeroize();
    }
    entries.clear();
}

fn zeroize_directory_result(result: &mut Result<(String, Vec<RemoteEntry>), String>) {
    match result {
        Ok((path, entries)) => {
            path.zeroize();
            zeroize_remote_entries(entries);
        }
        Err(error) => error.zeroize(),
    }
}

fn zeroize_string_result(result: &mut Result<String, String>) {
    match result {
        Ok(value) | Err(value) => value.zeroize(),
    }
}

fn sensitive_text_edit_id(name: &'static str) -> egui::Id {
    egui::Id::new(("serctl-sensitive-text-edit", name))
}

fn reset_text_edit_undo_state(ctx: &egui::Context, id: egui::Id) {
    let mut state = egui::widgets::text_edit::TextEditState::load(ctx, id).unwrap_or_default();
    state.set_undoer(egui::util::undoer::Undoer::with_settings(
        egui::util::undoer::Settings {
            max_undos: 0,
            ..Default::default()
        },
    ));
    state.store(ctx, id);
}

fn add_ephemeral_text_edit(
    ui: &mut egui::Ui,
    name: &'static str,
    edit: TextEdit<'_>,
) -> egui::Response {
    let id = sensitive_text_edit_id(name);
    reset_text_edit_undo_state(ui.ctx(), id);
    let response = ui.add(edit.id(id));
    reset_text_edit_undo_state(ui.ctx(), id);
    response
}

fn add_sized_ephemeral_text_edit(
    ui: &mut egui::Ui,
    size: impl Into<egui::Vec2>,
    name: &'static str,
    edit: TextEdit<'_>,
) -> egui::Response {
    let id = sensitive_text_edit_id(name);
    reset_text_edit_undo_state(ui.ctx(), id);
    let response = ui.add_sized(size, edit.id(id));
    reset_text_edit_undo_state(ui.ctx(), id);
    response
}

struct MaskedSecretTextBuffer<'a> {
    secret: &'a mut String,
    masked: String,
}

impl<'a> MaskedSecretTextBuffer<'a> {
    fn new(secret: &'a mut String) -> Self {
        Self {
            masked: "*".repeat(secret.chars().count()),
            secret,
        }
    }

    fn byte_index(text: &str, char_index: usize) -> usize {
        text.char_indices()
            .nth(char_index)
            .map_or(text.len(), |(byte_index, _)| byte_index)
    }

    fn replace_secret_range(
        secret: &mut String,
        char_range: Range<egui::text::CharIndex>,
        replacement: &str,
    ) {
        assert!(char_range.start <= char_range.end);
        let start = Self::byte_index(secret, char_range.start.0);
        let end = Self::byte_index(secret, char_range.end.0);
        let mut next = String::with_capacity(secret.len() - (end - start) + replacement.len());
        next.push_str(&secret[..start]);
        next.push_str(replacement);
        next.push_str(&secret[end..]);
        secret.zeroize();
        *secret = next;
    }
}

impl egui::TextBuffer for MaskedSecretTextBuffer<'_> {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        &self.masked
    }

    fn insert_text(&mut self, text: &str, char_index: egui::text::CharIndex) -> usize {
        let inserted = text.chars().count();
        Self::replace_secret_range(self.secret, char_index..char_index, text);
        self.masked.insert_str(char_index.0, &"*".repeat(inserted));
        inserted
    }

    fn delete_char_range(&mut self, char_range: Range<egui::text::CharIndex>) {
        Self::replace_secret_range(self.secret, char_range.clone(), "");
        self.masked
            .replace_range(char_range.start.0..char_range.end.0, "");
    }

    fn replace_with(&mut self, _text: &str) {
        // TextEdit invokes replace_with only for undo/redo. Its undo state sees
        // masks, never the real value, so applying that state would replace a
        // passphrase with asterisks. Secret fields deliberately disable undo.
    }

    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<MaskedSecretTextBuffer<'static>>()
    }
}

fn add_secret_password_edit(
    ui: &mut egui::Ui,
    enabled: bool,
    name: &'static str,
    secret: &mut String,
    hint: &str,
) -> egui::Response {
    let id = sensitive_text_edit_id(name);
    add_secret_password_edit_with_id(ui, enabled, id, secret, hint)
}

fn add_secret_password_edit_with_width(
    ui: &mut egui::Ui,
    enabled: bool,
    name: &'static str,
    secret: &mut String,
    hint: &str,
    desired_width: f32,
) -> egui::Response {
    let id = sensitive_text_edit_id(name);
    reset_text_edit_undo_state(ui.ctx(), id);
    let mut buffer = MaskedSecretTextBuffer::new(secret);
    let response = ui.add_enabled(
        enabled,
        TextEdit::singleline(&mut buffer)
            .id(id)
            .password(true)
            .hint_text(hint)
            .desired_width(desired_width.max(0.0)),
    );
    drop(buffer);
    reset_text_edit_undo_state(ui.ctx(), id);
    response
}

fn add_secret_password_edit_with_id(
    ui: &mut egui::Ui,
    enabled: bool,
    id: egui::Id,
    secret: &mut String,
    hint: &str,
) -> egui::Response {
    reset_text_edit_undo_state(ui.ctx(), id);
    let mut buffer = MaskedSecretTextBuffer::new(secret);
    let response = ui.add_enabled(
        enabled,
        TextEdit::singleline(&mut buffer)
            .id(id)
            .password(true)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
    drop(buffer);
    // The no-undo state contains only the same-length mask even while the
    // widget runs. Clear that non-secret transient immediately as well.
    reset_text_edit_undo_state(ui.ctx(), id);
    response
}

struct SensitiveUiMessage(Option<UiMessage>);

impl SensitiveUiMessage {
    fn new(message: UiMessage) -> Self {
        Self(Some(message))
    }

    fn message_mut(&mut self) -> &mut UiMessage {
        self.0.as_mut().expect("UI message envelope is empty")
    }
}

impl Drop for SensitiveUiMessage {
    fn drop(&mut self) {
        if let Some(message) = &mut self.0 {
            message.zeroize_sensitive();
        }
    }
}

#[derive(Clone)]
struct UiMessageSender(mpsc::Sender<SensitiveUiMessage>);

impl UiMessageSender {
    fn send(&self, message: UiMessage) -> Result<(), ()> {
        self.0
            .send(SensitiveUiMessage::new(message))
            .map_err(|_| ())
    }
}

struct UiMessageReceiver(mpsc::Receiver<SensitiveUiMessage>);

impl UiMessageReceiver {
    fn try_recv(&self) -> Result<SensitiveUiMessage, mpsc::TryRecvError> {
        self.0.try_recv()
    }
}

fn ui_message_channel() -> (UiMessageSender, UiMessageReceiver) {
    let (tx, rx) = mpsc::channel();
    (UiMessageSender(tx), UiMessageReceiver(rx))
}

fn schedule_active_operation_poll(ctx: &egui::Context, active: bool) {
    if active {
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

#[cfg(any(windows, test))]
fn send_migration_progress(
    tx: &UiMessageSender,
    repaint: &egui::Context,
    operation_id: u64,
    progress: vault::MigrationProgress,
) {
    if tx
        .send(UiMessage::MigrationProgress {
            operation_id,
            progress,
        })
        .is_ok()
    {
        repaint.request_repaint();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OperationContext {
    id: u64,
    profile: Option<String>,
    profile_generation: u64,
    profile_identity: Option<vault::ProfileIdentity>,
}

impl OperationContext {
    fn with_profile_identity(mut self, identity: vault::ProfileIdentity) -> Self {
        self.profile_identity = Some(identity);
        self
    }
}

#[derive(Default)]
struct UiOperations {
    next_id: u64,
    profile_generation: u64,
    refresh_epoch: u64,
    next_daemon_instance: u64,
    next_tunnel_instance: u64,
    active: BTreeMap<u64, Zeroizing<String>>,
}

impl UiOperations {
    fn begin(&mut self, profile: Option<String>, activity: String) -> OperationContext {
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("UI operation identifier exhausted");
        let operation = OperationContext {
            id: self.next_id,
            profile,
            profile_generation: self.profile_generation,
            profile_identity: None,
        };
        self.active.insert(operation.id, Zeroizing::new(activity));
        operation
    }

    fn finish(&mut self, operation: &OperationContext) -> bool {
        self.active.remove(&operation.id).is_some()
    }

    #[cfg(any(windows, test))]
    fn update_activity(&mut self, operation_id: u64, activity: String) -> bool {
        let Some(current) = self.active.get_mut(&operation_id) else {
            return false;
        };
        current.zeroize();
        *current = Zeroizing::new(activity);
        true
    }

    fn is_busy(&self) -> bool {
        !self.active.is_empty()
    }

    fn activity(&self) -> Option<&str> {
        self.active
            .iter()
            .next_back()
            .map(|(_, value)| value.as_str())
    }

    fn advance_profile_generation(&mut self) {
        self.profile_generation = self
            .profile_generation
            .checked_add(1)
            .expect("profile generation exhausted");
        for activity in self.active.values_mut() {
            activity.zeroize();
            activity.push_str("正在结束先前操作…");
        }
    }

    fn is_current(&self, selected: Option<&str>, operation: &OperationContext) -> bool {
        operation.profile_generation == self.profile_generation
            && operation
                .profile
                .as_deref()
                .is_none_or(|profile| selected == Some(profile))
    }

    fn next_refresh_epoch(&mut self) -> u64 {
        self.refresh_epoch = self
            .refresh_epoch
            .checked_add(1)
            .expect("profile refresh epoch exhausted");
        self.refresh_epoch
    }

    fn next_daemon_instance(&mut self) -> u64 {
        self.next_daemon_instance = self
            .next_daemon_instance
            .checked_add(1)
            .expect("daemon instance identifier exhausted");
        self.next_daemon_instance
    }

    fn next_tunnel_instance(&mut self) -> u64 {
        self.next_tunnel_instance = self
            .next_tunnel_instance
            .checked_add(1)
            .expect("tunnel instance identifier exhausted");
        self.next_tunnel_instance
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DirectoryRequest {
    profile: String,
    path: String,
    generation: u64,
    profile_generation: u64,
    profile_identity: vault::ProfileIdentity,
}

#[derive(Default)]
struct DirectoryRequests {
    generation: u64,
}

impl DirectoryRequests {
    fn advance(&mut self) -> u64 {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("directory request generation exhausted");
        self.generation
    }

    fn begin(
        &mut self,
        profile: String,
        path: String,
        profile_generation: u64,
        profile_identity: vault::ProfileIdentity,
    ) -> DirectoryRequest {
        DirectoryRequest {
            profile,
            path,
            generation: self.advance(),
            profile_generation,
            profile_identity,
        }
    }

    fn context(
        &self,
        profile: String,
        path: String,
        profile_generation: u64,
        profile_identity: vault::ProfileIdentity,
    ) -> DirectoryRequest {
        DirectoryRequest {
            profile,
            path,
            generation: self.generation,
            profile_generation,
            profile_identity,
        }
    }

    fn invalidate(&mut self) {
        self.advance();
    }

    fn is_current(
        &self,
        selected: Option<&str>,
        profile_generation: u64,
        profile_identity: Option<vault::ProfileIdentity>,
        request: &DirectoryRequest,
    ) -> bool {
        selected == Some(request.profile.as_str())
            && self.generation == request.generation
            && profile_generation == request.profile_generation
            && profile_identity == Some(request.profile_identity)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum WorkspaceTab {
    #[default]
    Command,
    Files,
    Bash,
    Tunnel,
}

#[derive(Default)]
struct ProfileEditor {
    visible: bool,
    original_name: Option<String>,
    expected_identity: Option<vault::ProfileIdentity>,
    name: String,
    host: String,
    port: String,
    user: String,
    password: String,
    host_key_sha256: String,
    profile_passphrase: String,
    profile_passphrase_confirmation: String,
}

#[derive(Default)]
struct SecurityDialog {
    visible: bool,
    profile: String,
    expected_identity: Option<vault::ProfileIdentity>,
    current_passphrase: String,
    new_passphrase: String,
    new_passphrase_confirmation: String,
    random_passphrase_once: Option<Zeroizing<String>>,
    pending_random_action: Option<PendingRandomProfileAction>,
    pending_random_identity: Option<vault::ProfileIdentity>,
    random_saved_confirmation: bool,
    recovery_media_path: String,
    destructive_confirm_text: String,
    replacement_host: String,
    replacement_port: String,
    replacement_user: String,
    replacement_ssh_password: String,
    replacement_profile_passphrase: String,
    replacement_profile_passphrase_confirmation: String,
}

impl SecurityDialog {
    fn clear(&mut self) {
        self.visible = false;
        self.profile.zeroize();
        self.expected_identity = None;
        self.current_passphrase.zeroize();
        self.new_passphrase.zeroize();
        self.new_passphrase_confirmation.zeroize();
        drop(self.random_passphrase_once.take());
        self.pending_random_action = None;
        self.pending_random_identity = None;
        self.random_saved_confirmation = false;
        self.recovery_media_path.zeroize();
        self.destructive_confirm_text.zeroize();
        self.replacement_host.zeroize();
        self.replacement_port.zeroize();
        self.replacement_user.zeroize();
        self.replacement_ssh_password.zeroize();
        self.replacement_profile_passphrase.zeroize();
        self.replacement_profile_passphrase_confirmation.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingRandomProfileAction {
    RotatePassphrase,
    PreserveRecovery,
    DestructiveReset,
}

impl PendingRandomProfileAction {
    fn description(self) -> &'static str {
        match self {
            Self::RotatePassphrase => "随机轮转独立口令",
            Self::PreserveRecovery => "使用离线介质保留凭据并恢复",
            Self::DestructiveReset => "永久丢弃原凭据并随机重置",
        }
    }

    fn commit_label(self) -> &'static str {
        match self {
            Self::RotatePassphrase => "确认已保存并执行口令轮转",
            Self::PreserveRecovery => "确认已保存并执行保留式恢复",
            Self::DestructiveReset => "确认已保存并执行破坏性重置",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SecuritySection {
    #[default]
    ProfilePassphrase,
    PreserveRecovery,
    DestructiveReset,
}

#[derive(Default)]
struct AdminDialog {
    visible: bool,
    status: Option<vault::AdminStatus>,
    password_input: String,
    new_password: String,
    new_password_confirmation: String,
    media_path: String,
    old_media_path: String,
    new_media_path: String,
}

impl AdminDialog {
    fn clear_secrets(&mut self) {
        self.password_input.zeroize();
        self.new_password.zeroize();
        self.new_password_confirmation.zeroize();
    }

    fn close(&mut self) {
        self.visible = false;
        self.clear_secrets();
        self.media_path.zeroize();
        self.old_media_path.zeroize();
        self.new_media_path.zeroize();
    }
}

#[derive(Default)]
struct MigrationWizard {
    visible: bool,
    profiles: Vec<String>,
    old_master: String,
    profile_passphrases: BTreeMap<String, String>,
    profile_confirmations: BTreeMap<String, String>,
    administrator_password: String,
    administrator_confirmation: String,
    recovery_media_path: String,
}

impl MigrationWizard {
    fn clear_secrets(&mut self) {
        self.old_master.zeroize();
        for value in self.profile_passphrases.values_mut() {
            value.zeroize();
        }
        for value in self.profile_confirmations.values_mut() {
            value.zeroize();
        }
        self.profile_passphrases.clear();
        self.profile_confirmations.clear();
        self.administrator_password.zeroize();
        self.administrator_confirmation.zeroize();
    }

    fn reset_profiles(&mut self, profiles: Vec<String>) {
        self.clear_secrets();
        self.profiles = profiles;
        for profile in &self.profiles {
            self.profile_passphrases
                .insert(profile.clone(), String::new());
            self.profile_confirmations
                .insert(profile.clone(), String::new());
        }
        self.visible = true;
    }
}

struct PendingTransfer {
    cancellation: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
    progress: Option<serctl_protocol::TransferProgress>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TunnelContext {
    profile: String,
    profile_generation: u64,
    profile_identity: vault::ProfileIdentity,
    instance: u64,
}

struct ActiveTunnel {
    context: TunnelContext,
    spec: client::TunnelSpec,
    bind_port: u16,
    last_error: Option<String>,
    tunnel: client::GuiTunnel,
}

struct PendingTunnelStart {
    context: TunnelContext,
    operation: OperationContext,
    handle: tokio::task::JoinHandle<()>,
}

struct PendingTunnelStop {
    context: TunnelContext,
    handle: tokio::task::JoinHandle<()>,
}

fn tunnel_context_is_current(
    selected: Option<&str>,
    profile_generation: u64,
    profile_identity: Option<vault::ProfileIdentity>,
    context: &TunnelContext,
) -> bool {
    selected == Some(context.profile.as_str())
        && profile_generation == context.profile_generation
        && profile_identity == Some(context.profile_identity)
}

fn tunnel_start_may_be_adopted(
    selected: Option<&str>,
    profile_generation: u64,
    profile_identity: Option<vault::ProfileIdentity>,
    pending: Option<&TunnelContext>,
    active: Option<&TunnelContext>,
    incoming: &TunnelContext,
) -> bool {
    tunnel_context_is_current(selected, profile_generation, profile_identity, incoming)
        && pending == Some(incoming)
        && active.is_none()
}

fn tunnel_end_matches_pending(pending: Option<&TunnelContext>, incoming: &TunnelContext) -> bool {
    pending == Some(incoming)
}

#[cfg(test)]
enum DaemonReadiness<T> {
    Ready,
    Ended(std::result::Result<T, tokio::task::JoinError>),
    Closed(tokio::sync::oneshot::error::RecvError),
    TimedOut,
}

#[cfg(test)]
async fn wait_for_daemon_readiness<T>(
    ready: tokio::sync::oneshot::Receiver<()>,
    daemon_task: &mut tokio::task::JoinHandle<T>,
    deadline: tokio::time::Instant,
) -> DaemonReadiness<T> {
    tokio::select! {
        // If a short-lived daemon both publishes readiness and exits in one
        // scheduler turn, publish Started before observing Ended.
        biased;
        ready = tokio::time::timeout_at(deadline, ready) => match ready {
            Ok(Ok(())) => DaemonReadiness::Ready,
            Ok(Err(error)) => DaemonReadiness::Closed(error),
            Err(_) => DaemonReadiness::TimedOut,
        },
        ended = &mut *daemon_task => DaemonReadiness::Ended(ended),
    }
}

struct RuntimeShutdownGuard(Option<Runtime>);

impl RuntimeShutdownGuard {
    fn new(runtime: Runtime) -> Self {
        Self(Some(runtime))
    }

    fn runtime(&self) -> &Runtime {
        self.0.as_ref().expect("UI runtime shutdown guard is empty")
    }

    fn shutdown_timeout(mut self, grace: Duration) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_timeout(grace);
        }
    }
}

impl Drop for RuntimeShutdownGuard {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

impl ProfileEditor {
    fn zeroize_sensitive_state(&mut self) {
        zeroize_option_string(&mut self.original_name);
        self.expected_identity = None;
        self.name.zeroize();
        self.host.zeroize();
        self.port.zeroize();
        self.user.zeroize();
        self.password.zeroize();
        self.host_key_sha256.zeroize();
        self.profile_passphrase.zeroize();
        self.profile_passphrase_confirmation.zeroize();
    }

    fn clear(&mut self) {
        self.zeroize_sensitive_state();
        self.visible = false;
        self.port.push_str("22");
    }
}

fn zeroize_option_string(value: &mut Option<String>) {
    if let Some(mut value) = value.take() {
        value.zeroize();
    }
}

fn zeroize_admin_status(status: &mut Option<vault::AdminStatus>) {
    if let Some(vault::AdminStatus::Ready { recovery_id, .. }) = status.as_mut() {
        recovery_id.zeroize();
    }
    *status = None;
}

fn zeroize_migration_state(state: &mut Option<vault::VaultMigrationState>) {
    if let Some(vault::VaultMigrationState::LegacyV2 { profiles }) = state.as_mut() {
        for profile in profiles.iter_mut() {
            profile.zeroize();
        }
        profiles.clear();
    }
    *state = None;
}

pub fn run() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("serctl-ui-worker")
        .build()?;

    // Keeping the window dimensions as Winit logical units documents the DPI
    // contract at the platform boundary; eframe performs the Winit integration.
    let size = winit::dpi::LogicalSize::new(1120.0_f64, 720.0_f64);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("serctl · SSH 工作台")
            .with_inner_size([size.width as f32, size.height as f32])
            .with_min_inner_size([860.0, 560.0]),
        centered: true,
        persist_window: false,
        ..Default::default()
    };

    eframe::run_native(
        "serctl",
        options,
        Box::new(move |cc| Ok(Box::new(SerctlApp::new(cc, runtime)))),
    )
    .map_err(|e| anyhow!(e.to_string()))
}

struct SerctlApp {
    // Runtime is exclusively owned so shutdown can be bounded. Dropping a
    // Runtime normally waits forever for spawn_blocking work.
    runtime: Option<Runtime>,
    tx: UiMessageSender,
    rx: UiMessageReceiver,
    profiles: Vec<ProfileRow>,
    owned_daemons: BTreeMap<String, u64>,
    selected: Option<String>,
    editor: ProfileEditor,
    security_dialog: SecurityDialog,
    security_section: SecuritySection,
    admin_dialog: AdminDialog,
    admin_authorization: AdminAuthorization,
    /// Non-secret continuation: the editor remains the sole owner of the
    /// unsaved host/profile secrets while Windows admin setup is completed.
    pending_create_after_admin: bool,
    migration: MigrationWizard,
    migration_state: Option<vault::VaultMigrationState>,
    delete_candidate: Option<String>,
    command: String,
    profile_passphrase_input: String,
    authorizations: UiAuthorizations,
    output: String,
    exit_code: Option<i32>,
    workspace_tab: WorkspaceTab,
    directory_requests: DirectoryRequests,
    remote_path: String,
    remote_entries: Vec<RemoteEntry>,
    selected_remote: Option<RemoteEntry>,
    new_directory: String,
    local_upload: String,
    remote_upload: String,
    local_download: String,
    transfer_resume: bool,
    shell: Option<client::GuiShell>,
    shell_profile: Option<String>,
    shell_input: String,
    shell_bytes: Vec<u8>,
    shell_output: String,
    tunnel_mode: client::TunnelMode,
    tunnel_bind_port: String,
    tunnel_target_port: String,
    tunnel_max_connections: String,
    tunnel: Option<ActiveTunnel>,
    pending_tunnel_start: Option<PendingTunnelStart>,
    pending_tunnel_stops: BTreeMap<u64, PendingTunnelStop>,
    operations: UiOperations,
    pending_transfers: BTreeMap<u64, PendingTransfer>,
    notice: Option<(String, bool)>,
}

impl SerctlApp {
    fn new(cc: &eframe::CreationContext<'_>, runtime: Runtime) -> Self {
        configure_appearance(&cc.egui_ctx);
        let (tx, rx) = ui_message_channel();
        let mut app = Self::with_channels(runtime, tx, rx);
        // Metadata refresh is local-only. Status probes are skipped for every
        // profile that does not already have a generation-bound UI grant.
        app.refresh_migration_state();
        app.refresh(&cc.egui_ctx);
        app
    }

    fn with_channels(runtime: Runtime, tx: UiMessageSender, rx: UiMessageReceiver) -> Self {
        Self {
            runtime: Some(runtime),
            tx,
            rx,
            profiles: Vec::new(),
            owned_daemons: BTreeMap::new(),
            selected: None,
            editor: ProfileEditor {
                port: "22".into(),
                ..ProfileEditor::default()
            },
            security_dialog: SecurityDialog::default(),
            security_section: SecuritySection::default(),
            admin_dialog: AdminDialog::default(),
            admin_authorization: AdminAuthorization::default(),
            pending_create_after_admin: false,
            migration: MigrationWizard::default(),
            migration_state: None,
            delete_candidate: None,
            command: "uname -a && whoami".into(),
            profile_passphrase_input: String::new(),
            authorizations: UiAuthorizations::default(),
            output: "选择一个主机，然后执行命令。".into(),
            exit_code: None,
            workspace_tab: WorkspaceTab::Command,
            directory_requests: DirectoryRequests::default(),
            remote_path: ".".into(),
            remote_entries: Vec::new(),
            selected_remote: None,
            new_directory: String::new(),
            local_upload: String::new(),
            remote_upload: String::new(),
            local_download: String::new(),
            transfer_resume: false,
            shell: None,
            shell_profile: None,
            shell_input: String::new(),
            shell_bytes: Vec::new(),
            shell_output: "尚未打开 Bash 会话。".into(),
            tunnel_mode: client::TunnelMode::Local,
            tunnel_bind_port: "0".into(),
            tunnel_target_port: String::new(),
            tunnel_max_connections: "32".into(),
            tunnel: None,
            pending_tunnel_start: None,
            pending_tunnel_stops: BTreeMap::new(),
            operations: UiOperations::default(),
            pending_transfers: BTreeMap::new(),
            notice: None,
        }
    }

    fn runtime(&self) -> &Runtime {
        self.runtime
            .as_ref()
            .expect("UI runtime is unavailable during shutdown")
    }

    fn set_notice(&mut self, message: String, error: bool) {
        if let Some((mut previous, _)) = self.notice.take() {
            previous.zeroize();
        }
        self.notice = Some((message, error));
    }

    fn refresh_migration_state(&mut self) {
        match vault::migration_state() {
            Ok(state) => {
                if let vault::VaultMigrationState::LegacyV2 { profiles } = &state {
                    if self.migration.profiles != *profiles {
                        self.migration.reset_profiles(profiles.clone());
                    } else {
                        self.migration.visible = true;
                    }
                }
                self.migration_state = Some(state);
            }
            Err(error) => self.set_notice(format!("读取 vault 状态失败：{error}"), true),
        }
    }

    fn admin_passphrase_for_operation(&mut self) -> Option<Option<Zeroizing<String>>> {
        let now = Instant::now();
        if self
            .admin_authorization
            .expires_at
            .is_some_and(|expires_at| now >= expires_at)
        {
            self.admin_authorization.revoke();
            self.set_notice("超管授权已过期并清零".into(), true);
            return None;
        }
        let passphrase = self.admin_authorization.passphrase_at(now);
        if passphrase.is_none() {
            self.set_notice("此管理操作需要先取得超管授权".into(), true);
        }
        passphrase
    }

    fn expire_admin_authorization(&mut self, now: Instant) -> bool {
        if !self
            .admin_authorization
            .expires_at
            .is_some_and(|expires_at| now >= expires_at)
        {
            return false;
        }
        self.admin_authorization.revoke();
        true
    }

    fn authorize_admin(&mut self, ctx: &egui::Context) {
        let requires_password =
            self.admin_dialog
                .status
                .as_ref()
                .is_some_and(|status| match status {
                    vault::AdminStatus::Uninitialized {
                        platform_requires_password,
                    }
                    | vault::AdminStatus::Ready {
                        platform_requires_password,
                        ..
                    } => *platform_requires_password,
                });
        if requires_password && self.admin_dialog.password_input.is_empty() {
            self.set_notice("请输入超管密码".into(), true);
            return;
        }
        let passphrase = requires_password
            .then(|| Zeroizing::new(std::mem::take(&mut self.admin_dialog.password_input)));
        let operation = self.operations.begin(None, "正在验证超管授权…".into());
        let deadline = tokio::time::Instant::now() + UI_AUTHORIZATION_VERIFY_TIMEOUT;
        self.send_future(ctx, async move {
            UiMessage::AdminAuthorization {
                operation,
                result: verify_ui_admin_authorization(passphrase, deadline).await,
            }
        });
    }

    fn open_admin_dialog(&mut self, ctx: &egui::Context) {
        self.admin_dialog.close();
        zeroize_admin_status(&mut self.admin_dialog.status);
        self.admin_dialog.visible = true;
        let operation = self.operations.begin(None, "正在读取安全策略…".into());
        self.send_future(ctx, async move {
            let result = tokio::task::spawn_blocking(vault::admin_status)
                .await
                .map_err(|error| error.to_string())
                .and_then(|result| result.map_err(|error| error.to_string()));
            UiMessage::AdminStatus { operation, result }
        });
    }

    fn initialize_admin_and_recovery(&mut self, ctx: &egui::Context) {
        if self.admin_dialog.media_path.trim().is_empty() {
            self.set_notice("请输入可移动介质上的新恢复文件绝对路径".into(), true);
            return;
        }
        #[cfg(windows)]
        let password = {
            if self.admin_dialog.new_password.is_empty()
                || self.admin_dialog.new_password != self.admin_dialog.new_password_confirmation
            {
                self.set_notice("请填写一致的新超管密码".into(), true);
                return;
            }
            let password = Zeroizing::new(std::mem::take(&mut self.admin_dialog.new_password));
            self.admin_dialog.new_password_confirmation.zeroize();
            password
        };
        #[cfg(not(windows))]
        {
            // Linux administrator authorization is the already-verified root
            // identity; do not retain or move an irrelevant password field.
            self.admin_dialog.new_password.zeroize();
            self.admin_dialog.new_password_confirmation.zeroize();
        }
        let media_path = PathBuf::from(self.admin_dialog.media_path.trim());
        let display_path = self.admin_dialog.media_path.clone();
        let operation = self
            .operations
            .begin(None, "正在初始化超管与离线恢复…".into());
        self.send_future(ctx, async move {
            let result = tokio::task::spawn_blocking(move || {
                #[cfg(windows)]
                vault::initialize_admin_password(&password, |media| {
                    persist_recovery_media_new(&media_path, media)
                })?;
                #[cfg(not(windows))]
                vault::initialize_linux_recovery(|media| {
                    persist_recovery_media_new(&media_path, media)
                })?;
                Ok::<_, anyhow::Error>(display_path)
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result.map_err(|error| error.to_string()));
            UiMessage::AdminInitialized { operation, result }
        });
    }

    fn change_admin_password(&mut self, ctx: &egui::Context) {
        let Some(Some(old)) = self.admin_passphrase_for_operation() else {
            return;
        };
        if self.admin_dialog.new_password.is_empty()
            || self.admin_dialog.new_password != self.admin_dialog.new_password_confirmation
        {
            self.set_notice("请填写一致的新超管密码".into(), true);
            return;
        }
        let new = Zeroizing::new(std::mem::take(&mut self.admin_dialog.new_password));
        self.admin_dialog.new_password_confirmation.zeroize();
        let operation = self.operations.begin(None, "正在更改超管密码…".into());
        self.send_future(ctx, async move {
            let result =
                tokio::task::spawn_blocking(move || vault::change_admin_password(&old, &new))
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|result| result.map_err(|error| error.to_string()));
            UiMessage::AdminPasswordChanged { operation, result }
        });
    }

    fn rotate_recovery_media(&mut self, ctx: &egui::Context) {
        let Some(admin) = self.admin_passphrase_for_operation() else {
            return;
        };
        let old_path = PathBuf::from(self.admin_dialog.old_media_path.trim());
        let new_path = PathBuf::from(self.admin_dialog.new_media_path.trim());
        if old_path.as_os_str().is_empty() || new_path.as_os_str().is_empty() {
            self.set_notice("请填写旧介质和新介质的绝对路径".into(), true);
            return;
        }
        let display_path = self.admin_dialog.new_media_path.clone();
        let operation = self.operations.begin(None, "正在轮转离线恢复介质…".into());
        self.send_future(ctx, async move {
            let result = tokio::task::spawn_blocking(move || {
                let old_media = read_recovery_media(&old_path)?;
                vault::rotate_recovery(
                    &old_media,
                    admin.as_deref().map(String::as_str),
                    |media| persist_recovery_media_new(&new_path, media),
                )?;
                Ok::<_, anyhow::Error>(display_path)
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result.map_err(|error| error.to_string()));
            UiMessage::RecoveryRotated { operation, result }
        });
    }

    fn profile_identity(&self, profile: &str) -> Option<vault::ProfileIdentity> {
        self.profiles
            .iter()
            .find(|row| row.name == profile)
            .map(ProfileRow::identity)
    }

    fn security_dialog_identity(&mut self, profile: &str) -> Option<vault::ProfileIdentity> {
        let expected = self.security_dialog.expected_identity;
        if expected.is_none() || self.profile_identity(profile) != expected {
            self.discard_pending_random_profile_action();
            self.set_notice(
                "安全操作所针对的主机配置已变化，请关闭对话框、刷新后重试".into(),
                true,
            );
            return None;
        }
        expected
    }

    fn profile_is_authorized_at(
        &self,
        profile: &str,
        identity: vault::ProfileIdentity,
        now: Instant,
    ) -> bool {
        self.authorizations.get(profile, identity, now).is_some()
    }

    fn required_authorized_profile_passphrase(
        &mut self,
        profile: &str,
    ) -> Option<Zeroizing<String>> {
        self.required_authorized_profile_grant(profile)
            .map(|(_, passphrase)| passphrase)
    }

    fn required_authorized_profile_grant(
        &mut self,
        profile: &str,
    ) -> Option<(vault::ProfileIdentity, Zeroizing<String>)> {
        let now = Instant::now();
        let Some(identity) = self.profile_identity(profile) else {
            self.set_notice("主机配置已变化，请刷新后重试".into(), true);
            return None;
        };
        let key = ProfileAuthorizationKey {
            profile: profile.to_owned(),
            profile_id: identity.profile_id,
            generation: identity.generation,
        };
        let target_was_cached = self.authorizations.grants.contains_key(&key);
        self.expire_authorizations_and_protected_sessions(now);
        let passphrase = self.authorizations.passphrase(profile, identity, now);
        if passphrase.is_none() && !target_was_cached {
            self.set_notice(format!("此操作需要先授权 {profile} 的独立口令"), true);
        }
        passphrase.map(|passphrase| (identity, passphrase))
    }

    fn authorize(&mut self, ctx: &egui::Context) {
        let Some(profile) = self.selected.clone() else {
            self.set_notice("请先选择一台主机".into(), true);
            return;
        };
        let Some(identity) = self.profile_identity(&profile) else {
            self.set_notice("主机配置已变化，请刷新后重试".into(), true);
            return;
        };
        if self.profile_passphrase_input.is_empty() {
            self.set_notice("请输入该主机的独立口令".into(), true);
            return;
        }
        let passphrase = Zeroizing::new(std::mem::take(&mut self.profile_passphrase_input));
        let deadline = tokio::time::Instant::now() + UI_AUTHORIZATION_VERIFY_TIMEOUT;
        let operation = self
            .operations
            .begin(
                Some(profile.clone()),
                format!("正在验证 {profile} 的独立口令…"),
            )
            .with_profile_identity(identity);
        self.send_future(ctx, async move {
            UiMessage::Authorization {
                operation,
                result: verify_ui_authorization(profile, identity, passphrase, deadline).await,
            }
        });
    }

    fn revoke_profile_authorization(&mut self, profile: &str) {
        self.profile_passphrase_input.zeroize();
        self.security_dialog.clear();
        self.authorizations.revoke_profile(profile);
        self.clear_protected_profile_workspace(profile);
        self.set_notice(
            format!("{profile} 的独立口令授权已撤销，相关长会话已关闭"),
            false,
        );
    }

    fn revoke_all_authorizations(&mut self) {
        self.profile_passphrase_input.zeroize();
        self.authorizations.revoke_all();
        self.clear_all_protected_sessions();
        self.set_notice("全部独立口令授权已撤销，长会话与传输已停止".into(), false);
    }

    fn expire_authorizations_and_protected_sessions(&mut self, now: Instant) -> bool {
        let mut expired = self.authorizations.expire_at(now);
        if expired.is_empty() {
            return false;
        }
        self.profile_passphrase_input.zeroize();
        for key in &expired {
            self.clear_protected_profile_workspace(&key.profile);
        }
        for key in &mut expired {
            key.profile.zeroize();
        }
        self.set_notice(
            "一个或多个主机的独立口令授权已过期；缓存已清零，相关长会话已停止".into(),
            true,
        );
        true
    }

    fn clear_protected_profile_workspace(&mut self, profile: &str) {
        // Reject a late status snapshot that was authorized before this
        // profile grant was revoked or expired.
        self.operations.next_refresh_epoch();
        if let Some(row) = self.profiles.iter_mut().find(|row| row.name == profile) {
            if let Some(mut status) = row.daemon.take() {
                status.profile.zeroize();
                status.host.zeroize();
                status.user.zeroize();
                status.endpoint.zeroize();
            }
        }
        for transfer in self.pending_transfers.values() {
            transfer.cancellation.cancel();
        }
        if self.shell_profile.as_deref() == Some(profile) {
            self.close_shell();
        }
        if self
            .pending_tunnel_start
            .as_ref()
            .is_some_and(|pending| pending.context.profile == profile)
        {
            self.cancel_pending_tunnel_start();
        }
        if self
            .tunnel
            .as_ref()
            .is_some_and(|active| active.context.profile == profile)
        {
            self.stop_active_tunnel();
        }
        if self.selected.as_deref() == Some(profile) {
            self.invalidate_directory_context();
            self.output.zeroize();
            self.output = "独立口令授权后可执行远程操作。".into();
        }
        if self.security_dialog.profile == profile {
            self.security_dialog.clear();
        }
        self.editor.clear();
        zeroize_option_string(&mut self.delete_candidate);
    }

    fn clear_all_protected_sessions(&mut self) {
        for transfer in self.pending_transfers.values() {
            transfer.cancellation.cancel();
        }
        self.close_shell();
        self.cancel_pending_tunnel_start();
        self.stop_active_tunnel();
        self.invalidate_directory_context();
        self.output.zeroize();
        self.output = "选择主机并验证其独立口令。".into();
        self.editor.clear();
        zeroize_option_string(&mut self.delete_candidate);
    }

    fn send_future<F>(&self, ctx: &egui::Context, future: F)
    where
        F: std::future::Future<Output = UiMessage> + Send + 'static,
    {
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        // A click can enqueue work after the status panel for the current
        // frame has already been painted. Request the next frame now instead
        // of waiting for the operation's final message.
        ctx.request_repaint();
        self.runtime().spawn(async move {
            let message = future.await;
            let _ = tx.send(message);
            ctx.request_repaint();
        });
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        if matches!(
            self.migration_state,
            Some(vault::VaultMigrationState::LegacyV2 { .. })
        ) {
            return;
        }
        self.expire_authorizations_and_protected_sessions(Instant::now());
        let authorization_snapshots = self
            .authorizations
            .grants
            .iter()
            .filter_map(|(key, authorization)| {
                authorization.passphrase().map(|passphrase| {
                    (
                        key.profile.clone(),
                        vault::ProfileIdentity {
                            profile_id: key.profile_id,
                            generation: key.generation,
                        },
                        passphrase,
                    )
                })
            })
            .collect::<Vec<_>>();
        // Capture one deadline at the UI invocation boundary. Vault lock/KDF
        // work and every bounded wave of daemon probes share this budget.
        let deadline = tokio::time::Instant::now() + PROFILE_REFRESH_TIMEOUT;
        let epoch = self.operations.next_refresh_epoch();
        let operation = self.operations.begin(None, "正在刷新主机状态…".into());
        self.send_future(ctx, async move {
            let rows = match load_vault_profile_rows(deadline).await {
                Ok(rows) => rows,
                Err(e) => {
                    return UiMessage::Profiles {
                        operation,
                        epoch,
                        result: Err(e),
                    }
                }
            };
            UiMessage::Profiles {
                operation,
                epoch,
                result: load_profile_rows(rows, authorization_snapshots, deadline).await,
            }
        });
    }

    #[cfg(any(windows, test))]
    fn submit_v2_migration(&mut self, _ctx: &egui::Context) {
        // Validation errors are produced after the status panel has already
        // been painted for the click frame. Always schedule another frame so
        // an immediate failure is visible instead of looking like a dead
        // button.
        _ctx.request_repaint();
        #[cfg(unix)]
        self.set_notice(
            "Linux v2 迁移当前失败关闭；未配置 root-owned 系统 share store，不会采集或提交迁移秘密"
                .into(),
            true,
        );
        #[cfg(windows)]
        self.submit_v2_migration_windows(_ctx);
    }

    #[cfg(windows)]
    fn submit_v2_migration_windows(&mut self, ctx: &egui::Context) {
        if self.migration.old_master.is_empty() {
            self.set_notice("请输入旧 v2 共享主口令".into(), true);
            return;
        }
        if self.migration.recovery_media_path.trim().is_empty() {
            self.set_notice("请输入新恢复介质的绝对文件路径".into(), true);
            return;
        }
        let media_path = PathBuf::from(self.migration.recovery_media_path.trim());
        if let Err(error) = crate::validate_external_secret_path(
            &media_path,
            false,
            "UI migration recovery-media output",
        ) {
            self.set_notice(format!("恢复介质路径不可用：{error}"), true);
            return;
        }
        if !media_path.is_absolute() {
            self.set_notice("恢复介质必须使用绝对文件路径".into(), true);
            return;
        }
        let Some(parent) = media_path.parent() else {
            self.set_notice("恢复介质路径没有父目录".into(), true);
            return;
        };
        if !parent.is_dir() {
            self.set_notice("恢复介质的父目录不存在".into(), true);
            return;
        }
        if media_path.exists() {
            self.set_notice("恢复介质文件已存在；迁移不会覆盖它".into(), true);
            return;
        }
        let profiles = self.migration.profiles.clone();
        let all_valid = profiles.iter().all(|profile| {
            let passphrase = self.migration.profile_passphrases.get(profile);
            let confirmation = self.migration.profile_confirmations.get(profile);
            passphrase.is_some_and(|value| !value.is_empty()) && passphrase == confirmation
        });
        if !all_valid {
            self.set_notice("每个 profile 都必须填写两次一致的新独立口令".into(), true);
            return;
        }
        if self.migration.administrator_password.is_empty()
            || self.migration.administrator_password != self.migration.administrator_confirmation
        {
            self.set_notice("请填写两次一致的新超管密码".into(), true);
            return;
        }

        let old_master = Zeroizing::new(std::mem::take(&mut self.migration.old_master));
        let mut new_passphrases = BTreeMap::new();
        for profile in &profiles {
            let value = self
                .migration
                .profile_passphrases
                .get_mut(profile)
                .expect("migration profile passphrase is present");
            new_passphrases.insert(profile.clone(), Zeroizing::new(std::mem::take(value)));
            if let Some(confirmation) = self.migration.profile_confirmations.get_mut(profile) {
                confirmation.zeroize();
            }
        }
        let administrator_password =
            Zeroizing::new(std::mem::take(&mut self.migration.administrator_password));
        self.migration.administrator_confirmation.zeroize();
        if let Some((mut previous, _)) = self.notice.take() {
            previous.zeroize();
        }
        let operation = self
            .operations
            .begin(None, format!("正在原子迁移 {} 个 profile…", profiles.len()));
        let operation_id = operation.id;
        let tx = self.tx.clone();
        let progress_repaint = ctx.clone();
        self.send_future(ctx, async move {
            let result = tokio::task::spawn_blocking(move || {
                let progress_tx = tx.clone();
                vault::migrate_v2_with_progress(
                    &old_master,
                    &new_passphrases,
                    Some(administrator_password.as_str()),
                    |media| persist_recovery_media_new(&media_path, media),
                    move |progress| {
                        send_migration_progress(
                            &progress_tx,
                            &progress_repaint,
                            operation_id,
                            progress,
                        );
                    },
                )
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result.map_err(|error| error.to_string()));
            UiMessage::Migrated { operation, result }
        });
    }

    fn tunnel_for_profile_is_active_or_stopping(&self, profile: &str) -> bool {
        self.pending_tunnel_start
            .as_ref()
            .is_some_and(|pending| pending.context.profile == profile)
            || self
                .tunnel
                .as_ref()
                .is_some_and(|active| active.context.profile == profile)
            || self
                .pending_tunnel_stops
                .values()
                .any(|pending| pending.context.profile == profile)
    }

    fn save_profile(&mut self, ctx: &egui::Context) {
        let affected_profile = self
            .editor
            .original_name
            .clone()
            .or_else(|| self.selected.clone());
        if let Some(profile) = affected_profile
            .as_deref()
            .filter(|profile| self.tunnel_for_profile_is_active_or_stopping(profile))
        {
            self.set_notice(
                format!("请先显式停止 {profile} 的隧道，确认清理完成后再保存"),
                true,
            );
            return;
        }
        let port = match self.editor.port.parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => {
                self.set_notice("端口必须是 1–65535 之间的数字".into(), true);
                return;
            }
        };
        if self.editor.name.trim().is_empty()
            || self.editor.host.trim().is_empty()
            || self.editor.user.trim().is_empty()
            || self.editor.password.is_empty()
        {
            self.set_notice("请完整填写名称、地址、用户和密码".into(), true);
            return;
        }
        let name = self.editor.name.trim().to_owned();
        let original_name = self.editor.original_name.clone();
        let saved_original_name = original_name.clone();
        let expected_identity = self.editor.expected_identity;
        #[cfg(windows)]
        let creating = original_name.is_none();
        if let Some(original) = original_name.as_deref() {
            if expected_identity.is_none() || self.profile_identity(original) != expected_identity {
                self.set_notice("主机配置已变化，请关闭编辑器、刷新后重试".into(), true);
                return;
            }
        }
        #[cfg(windows)]
        let administrator_passphrase = if creating {
            let Some(passphrase) = self.admin_passphrase_for_operation() else {
                self.pending_create_after_admin = true;
                self.open_admin_dialog(ctx);
                return;
            };
            passphrase
        } else {
            None
        };
        // Linux profile creation is an ordinary per-user operation. Root is
        // required only for the explicitly administrative reset paths.
        #[cfg(not(windows))]
        let administrator_passphrase: Option<Zeroizing<String>> = None;
        let (profile_passphrase, creating) = match original_name.as_deref() {
            Some(original) => {
                let Some(passphrase) = self.required_authorized_profile_passphrase(original) else {
                    return;
                };
                (passphrase, false)
            }
            None => {
                if self.editor.profile_passphrase.is_empty() {
                    self.set_notice("请为新主机设置独立口令".into(), true);
                    return;
                }
                if self.editor.profile_passphrase != self.editor.profile_passphrase_confirmation {
                    self.set_notice("两次输入的独立口令不一致".into(), true);
                    return;
                }
                (
                    Zeroizing::new(std::mem::take(&mut self.editor.profile_passphrase)),
                    true,
                )
            }
        };
        self.editor.profile_passphrase_confirmation.zeroize();
        let host_key = match self.editor.host_key_sha256.trim() {
            "" => None,
            fingerprint => Some(fingerprint.to_owned()),
        };
        self.editor.host_key_sha256.zeroize();
        let creds = vault::Creds {
            host: self.editor.host.trim().to_owned(),
            port,
            user: self.editor.user.trim().to_owned(),
            password: std::mem::take(&mut self.editor.password),
            host_key,
        };
        let mut operation = self
            .operations
            .begin(self.selected.clone(), format!("正在保存 {name}…"));
        if let Some(identity) = expected_identity {
            operation = operation.with_profile_identity(identity);
        }
        self.send_future(ctx, async move {
            let saved_name = name.clone();
            let result = tokio::task::spawn_blocking(move || -> Result<String> {
                if creating {
                    vault::create_profile(
                        &name,
                        &creds,
                        &profile_passphrase,
                        administrator_passphrase.as_deref().map(String::as_str),
                    )?;
                } else if let Some(old) = original_name.as_deref().filter(|old| *old != name) {
                    vault::rename_profile_v3(
                        old,
                        &name,
                        &creds,
                        &profile_passphrase,
                        expected_identity,
                    )?;
                } else {
                    vault::update_profile(&name, &creds, &profile_passphrase, expected_identity)?;
                }
                Ok(name)
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string()));
            UiMessage::Saved {
                operation,
                original_name: saved_original_name,
                result: result.map(|_| saved_name),
            }
        });
    }

    fn remove_profile(&mut self, ctx: &egui::Context, name: String) {
        if self.tunnel_for_profile_is_active_or_stopping(&name) {
            self.delete_candidate = Some(name);
            self.set_notice(
                "请先显式停止该主机的隧道，确认清理完成后再删除".into(),
                true,
            );
            return;
        }
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&name)
        else {
            self.delete_candidate = Some(name);
            return;
        };
        let operation = self
            .operations
            .begin(Some(name.clone()), format!("正在删除 {name}…"))
            .with_profile_identity(expected_generation);
        self.send_future(ctx, async move {
            let display_name = name.clone();
            if let Err(e) =
                client::down_quiet_at_generation(&name, &master, expected_generation).await
            {
                return UiMessage::Removed {
                    operation,
                    result: Err(format!("停止连接失败：{e}")),
                };
            }
            let result = tokio::task::spawn_blocking(move || {
                vault::remove_profile(&name, &master, Some(expected_generation))
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string()))
            .and_then(|removed| {
                if removed {
                    Ok(display_name)
                } else {
                    Err("主机配置已不存在".into())
                }
            });
            UiMessage::Removed { operation, result }
        });
    }

    fn open_security_dialog(&mut self, profile: &ProfileRow) {
        self.security_dialog.clear();
        self.security_section = SecuritySection::ProfilePassphrase;
        self.security_dialog.visible = true;
        self.security_dialog.profile = profile.name.clone();
        self.security_dialog.expected_identity = Some(profile.identity());
        self.security_dialog.replacement_host = profile.host.clone();
        self.security_dialog.replacement_port = profile.port.to_string();
    }

    fn change_profile_passphrase(&mut self, ctx: &egui::Context) {
        if self.security_dialog.current_passphrase.is_empty()
            || self.security_dialog.new_passphrase.is_empty()
        {
            self.set_notice("请完整填写当前独立口令和新独立口令".into(), true);
            return;
        }
        if self.security_dialog.new_passphrase != self.security_dialog.new_passphrase_confirmation {
            self.set_notice("两次输入的新独立口令不一致".into(), true);
            return;
        }
        let new = Zeroizing::new(std::mem::take(&mut self.security_dialog.new_passphrase));
        self.security_dialog.new_passphrase_confirmation.zeroize();
        let profile = self.security_dialog.profile.clone();
        let Some(expected_identity) = self.security_dialog_identity(&profile) else {
            return;
        };
        self.submit_profile_passphrase_change(ctx, new, expected_identity);
    }

    fn submit_profile_passphrase_change(
        &mut self,
        ctx: &egui::Context,
        new: Zeroizing<String>,
        expected_identity: vault::ProfileIdentity,
    ) {
        let profile = self.security_dialog.profile.clone();
        if self.tunnel_for_profile_is_active_or_stopping(&profile)
            || self.shell_profile.as_deref() == Some(profile.as_str())
            || self.owned_daemons.contains_key(&profile)
        {
            self.set_notice(
                "请先断开该 profile 的 daemon、Bash 与隧道再轮转口令".into(),
                true,
            );
            return;
        }
        if self.security_dialog.current_passphrase.is_empty() {
            self.set_notice("请输入当前独立口令".into(), true);
            return;
        }
        if self.profile_identity(&profile) != Some(expected_identity) {
            self.set_notice("主机配置已变化，请刷新后重试".into(), true);
            return;
        }
        let old = Zeroizing::new(std::mem::take(&mut self.security_dialog.current_passphrase));
        self.authorizations.revoke_profile(&profile);
        let operation = self
            .operations
            .begin(
                Some(profile.clone()),
                format!("正在轮转 {profile} 的独立口令…"),
            )
            .with_profile_identity(expected_identity);
        self.send_future(ctx, async move {
            let task_profile = profile.clone();
            let task = tokio::task::spawn_blocking(move || {
                vault::change_profile_passphrase(&task_profile, &old, &new, Some(expected_identity))
            });
            let result = task
                .await
                .map_err(|error| error.to_string())
                .and_then(|result| result.map_err(|error| error.to_string()));
            UiMessage::ProfilePassphraseChanged {
                operation,
                profile,
                result,
            }
        });
    }

    fn stage_random_profile_passphrase(&mut self, action: PendingRandomProfileAction) {
        if self.security_dialog.random_passphrase_once.is_some() {
            self.set_notice("已有一个尚未提交的一次性随机口令".into(), true);
            return;
        }
        let profile = self.security_dialog.profile.clone();
        let Some(identity) = self.security_dialog_identity(&profile) else {
            return;
        };
        self.security_dialog.random_passphrase_once = Some(vault::generate_profile_passphrase());
        self.security_dialog.pending_random_action = Some(action);
        self.security_dialog.pending_random_identity = Some(identity);
        self.security_dialog.random_saved_confirmation = false;
        self.set_notice(
            format!(
                "已生成用于{}的新口令；vault 尚未修改，关闭或取消将只清零该口令",
                action.description()
            ),
            false,
        );
    }

    fn discard_pending_random_profile_action(&mut self) -> bool {
        let had_pending = self.security_dialog.random_passphrase_once.is_some()
            || self.security_dialog.pending_random_action.is_some();
        drop(self.security_dialog.random_passphrase_once.take());
        self.security_dialog.pending_random_action = None;
        self.security_dialog.pending_random_identity = None;
        self.security_dialog.random_saved_confirmation = false;
        had_pending
    }

    fn commit_pending_random_profile_action(&mut self, ctx: &egui::Context) {
        if !self.security_dialog.random_saved_confirmation {
            self.set_notice("请先确认已将一次性随机口令保存到安全位置".into(), true);
            return;
        }
        let Some(action) = self.security_dialog.pending_random_action.take() else {
            self.discard_pending_random_profile_action();
            self.set_notice("随机口令状态已失效，请重新生成".into(), true);
            return;
        };
        let Some(expected_identity) = self.security_dialog.pending_random_identity.take() else {
            self.discard_pending_random_profile_action();
            self.set_notice("随机口令目标身份已失效，请重新生成".into(), true);
            return;
        };
        let Some(generated) = self.security_dialog.random_passphrase_once.take() else {
            self.security_dialog.random_saved_confirmation = false;
            self.set_notice("随机口令状态已失效，请重新生成".into(), true);
            return;
        };
        self.security_dialog.random_saved_confirmation = false;
        let profile = self.security_dialog.profile.clone();
        if self.security_dialog.expected_identity != Some(expected_identity)
            || self.profile_identity(&profile) != Some(expected_identity)
        {
            self.set_notice("主机配置已变化，未提交随机口令操作".into(), true);
            return;
        }
        match action {
            PendingRandomProfileAction::RotatePassphrase => {
                self.submit_profile_passphrase_change(ctx, generated, expected_identity);
            }
            PendingRandomProfileAction::PreserveRecovery => {
                self.submit_profile_recovery(ctx, generated, expected_identity);
            }
            PendingRandomProfileAction::DestructiveReset => {
                self.submit_destructive_profile_reset(ctx, generated, expected_identity);
            }
        }
    }

    fn prepare_random_profile_passphrase_rotation(&mut self) {
        let profile = self.security_dialog.profile.clone();
        if self.tunnel_for_profile_is_active_or_stopping(&profile)
            || self.shell_profile.as_deref() == Some(profile.as_str())
            || self.owned_daemons.contains_key(&profile)
        {
            self.set_notice(
                "请先断开该 profile 的 daemon、Bash 与隧道再轮转口令".into(),
                true,
            );
            return;
        }
        if self.security_dialog.current_passphrase.is_empty() {
            self.set_notice("请输入当前独立口令".into(), true);
            return;
        }
        if self.security_dialog_identity(&profile).is_none() {
            return;
        }
        self.stage_random_profile_passphrase(PendingRandomProfileAction::RotatePassphrase);
    }

    fn recover_profile_preserving_credentials(&mut self, ctx: &egui::Context) {
        if self.security_dialog.new_passphrase.is_empty()
            || self.security_dialog.new_passphrase
                != self.security_dialog.new_passphrase_confirmation
        {
            self.set_notice("请填写一致的新 profile 独立口令".into(), true);
            return;
        }
        let new = Zeroizing::new(std::mem::take(&mut self.security_dialog.new_passphrase));
        self.security_dialog.new_passphrase_confirmation.zeroize();
        let profile = self.security_dialog.profile.clone();
        let Some(expected_identity) = self.security_dialog_identity(&profile) else {
            return;
        };
        self.submit_profile_recovery(ctx, new, expected_identity);
    }

    fn prepare_random_profile_recovery(&mut self) {
        let profile = self.security_dialog.profile.clone();
        if self.tunnel_for_profile_is_active_or_stopping(&profile)
            || self.shell_profile.as_deref() == Some(profile.as_str())
            || self.owned_daemons.contains_key(&profile)
        {
            self.set_notice(
                "请先断开该 profile 的 daemon、Bash 与隧道再恢复".into(),
                true,
            );
            return;
        }
        if self.admin_passphrase_for_operation().is_none() {
            return;
        }
        if self.security_dialog.recovery_media_path.trim().is_empty() {
            self.set_notice("请选择该 vault 对应的离线恢复介质绝对路径".into(), true);
            return;
        }
        if self.security_dialog_identity(&profile).is_none() {
            return;
        }
        self.stage_random_profile_passphrase(PendingRandomProfileAction::PreserveRecovery);
    }

    fn submit_profile_recovery(
        &mut self,
        ctx: &egui::Context,
        new: Zeroizing<String>,
        expected_identity: vault::ProfileIdentity,
    ) {
        let profile = self.security_dialog.profile.clone();
        if self.tunnel_for_profile_is_active_or_stopping(&profile)
            || self.shell_profile.as_deref() == Some(profile.as_str())
            || self.owned_daemons.contains_key(&profile)
        {
            self.set_notice(
                "请先断开该 profile 的 daemon、Bash 与隧道再恢复".into(),
                true,
            );
            return;
        }
        let Some(admin) = self.admin_passphrase_for_operation() else {
            return;
        };
        if self.security_dialog.recovery_media_path.trim().is_empty() {
            self.set_notice("请选择该 vault 对应的离线恢复介质绝对路径".into(), true);
            return;
        }
        if self.profile_identity(&profile) != Some(expected_identity) {
            self.set_notice("主机配置已变化，请刷新后重试".into(), true);
            return;
        }
        let media_path = PathBuf::from(self.security_dialog.recovery_media_path.trim());
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在离线恢复 {profile}…"))
            .with_profile_identity(expected_identity);
        self.send_future(ctx, async move {
            let task_profile = profile.clone();
            let result = tokio::task::spawn_blocking(move || {
                let media = read_recovery_media(&media_path)?;
                vault::recover_profile_with_media(
                    &task_profile,
                    &media,
                    admin.as_deref().map(String::as_str),
                    &new,
                    Some(expected_identity),
                )
                .map(|row| row.generation)
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result.map_err(|error| error.to_string()));
            UiMessage::ProfileRecovered {
                operation,
                profile,
                result,
            }
        });
    }

    fn destructively_reset_profile(&mut self, ctx: &egui::Context) {
        if self
            .security_dialog
            .replacement_profile_passphrase
            .is_empty()
            || self.security_dialog.replacement_profile_passphrase
                != self
                    .security_dialog
                    .replacement_profile_passphrase_confirmation
        {
            self.set_notice("请填写一致的新独立口令".into(), true);
            return;
        }
        let new = Zeroizing::new(std::mem::take(
            &mut self.security_dialog.replacement_profile_passphrase,
        ));
        self.security_dialog
            .replacement_profile_passphrase_confirmation
            .zeroize();
        let profile = self.security_dialog.profile.clone();
        let Some(expected_identity) = self.security_dialog_identity(&profile) else {
            return;
        };
        self.submit_destructive_profile_reset(ctx, new, expected_identity);
    }

    fn prepare_random_destructive_profile_reset(&mut self) {
        let profile = self.security_dialog.profile.clone();
        if self.tunnel_for_profile_is_active_or_stopping(&profile)
            || self.shell_profile.as_deref() == Some(profile.as_str())
            || self.owned_daemons.contains_key(&profile)
        {
            self.set_notice(
                "请先断开该 profile 的 daemon、Bash 与隧道再重置".into(),
                true,
            );
            return;
        }
        let Some(_admin) = self.admin_passphrase_for_operation() else {
            return;
        };
        if self.security_dialog.destructive_confirm_text != profile {
            self.set_notice("请输入完整 profile 名称以确认不可恢复重置".into(), true);
            return;
        }
        match self.security_dialog.replacement_port.parse::<u16>() {
            Ok(port) if port > 0 => {}
            _ => {
                self.set_notice("替换 SSH 端口必须为 1–65535".into(), true);
                return;
            }
        }
        if self.security_dialog.replacement_host.trim().is_empty()
            || self.security_dialog.replacement_user.trim().is_empty()
            || self.security_dialog.replacement_ssh_password.is_empty()
        {
            self.set_notice("请完整填写替换 SSH 凭据".into(), true);
            return;
        }
        if self.security_dialog_identity(&profile).is_none() {
            return;
        }
        self.stage_random_profile_passphrase(PendingRandomProfileAction::DestructiveReset);
    }

    fn submit_destructive_profile_reset(
        &mut self,
        ctx: &egui::Context,
        new: Zeroizing<String>,
        expected_identity: vault::ProfileIdentity,
    ) {
        let profile = self.security_dialog.profile.clone();
        if self.tunnel_for_profile_is_active_or_stopping(&profile)
            || self.shell_profile.as_deref() == Some(profile.as_str())
            || self.owned_daemons.contains_key(&profile)
        {
            self.set_notice(
                "请先断开该 profile 的 daemon、Bash 与隧道再重置".into(),
                true,
            );
            return;
        }
        let Some(admin) = self.admin_passphrase_for_operation() else {
            return;
        };
        if self.security_dialog.destructive_confirm_text != profile {
            self.set_notice("请输入完整 profile 名称以确认不可恢复重置".into(), true);
            return;
        }
        let port = match self.security_dialog.replacement_port.parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => {
                self.set_notice("替换 SSH 端口必须为 1–65535".into(), true);
                return;
            }
        };
        if self.security_dialog.replacement_host.trim().is_empty()
            || self.security_dialog.replacement_user.trim().is_empty()
            || self.security_dialog.replacement_ssh_password.is_empty()
        {
            self.set_notice("请完整填写替换 SSH 凭据".into(), true);
            return;
        }
        if self.profile_identity(&profile) != Some(expected_identity) {
            self.set_notice("主机配置已变化，请刷新后重试".into(), true);
            return;
        }
        let creds = vault::Creds {
            host: self.security_dialog.replacement_host.trim().to_owned(),
            port,
            user: self.security_dialog.replacement_user.trim().to_owned(),
            password: std::mem::take(&mut self.security_dialog.replacement_ssh_password),
            host_key: None,
        };
        self.security_dialog.destructive_confirm_text.zeroize();
        let operation = self
            .operations
            .begin(
                Some(profile.clone()),
                format!("正在不可恢复地替换 {profile}…"),
            )
            .with_profile_identity(expected_identity);
        self.send_future(ctx, async move {
            let task_profile = profile.clone();
            let result = tokio::task::spawn_blocking(move || {
                vault::admin_reset_profile(
                    &task_profile,
                    &creds,
                    &new,
                    admin.as_deref().map(String::as_str),
                    Some(expected_identity),
                )
                .map(|row| row.generation)
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result.map_err(|error| error.to_string()));
            UiMessage::ProfileReset {
                operation,
                profile,
                result,
            }
        });
    }

    fn execute(&mut self, ctx: &egui::Context, profile: String) {
        let command = Zeroizing::new(self.command.trim().to_owned());
        if command.is_empty() {
            self.set_notice("请输入要执行的命令".into(), true);
            return;
        }
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&profile)
        else {
            return;
        };
        self.command.zeroize();
        self.output.zeroize();
        self.exit_code = None;
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在 {profile} 上执行…"))
            .with_profile_identity(expected_generation);
        self.send_future(ctx, async move {
            UiMessage::Command {
                operation,
                result: client::exec_capture_at_generation(
                    &profile,
                    command.as_str(),
                    &master,
                    expected_generation,
                )
                .await
                .map_err(|e| e.to_string()),
            }
        });
    }

    fn refresh_directory(&mut self, ctx: &egui::Context, profile: String, path: String) {
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&profile)
        else {
            return;
        };
        let request = self.directory_requests.begin(
            profile,
            path,
            self.operations.profile_generation,
            expected_generation,
        );
        let request_profile = request.profile.clone();
        let request_path = request.path.clone();
        let operation = self
            .operations
            .begin(
                Some(request_profile.clone()),
                format!(
                    "正在读取 {request_path}…（最长 {} 秒）",
                    UI_DIRECTORY_REFRESH_TIMEOUT.as_secs()
                ),
            )
            .with_profile_identity(expected_generation);
        self.send_future(ctx, async move {
            let result = client::list_dir_at_generation(
                &request_profile,
                &request_path,
                &master,
                expected_generation,
                UI_DIRECTORY_REFRESH_TIMEOUT,
            )
            .await
            .map_err(|e| e.to_string());
            UiMessage::Directory {
                operation,
                request,
                result,
            }
        });
    }

    fn create_remote_directory(&mut self, ctx: &egui::Context, profile: String) {
        let name = self.new_directory.trim().to_owned();
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            self.set_notice("目录名称不能为空，也不能包含路径分隔符".into(), true);
            return;
        }
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&profile)
        else {
            return;
        };
        let path = join_remote_path(&self.remote_path, &name);
        let current = self.remote_path.clone();
        let context = self.directory_requests.context(
            profile.clone(),
            current.clone(),
            self.operations.profile_generation,
            expected_generation,
        );
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在创建目录 {path}…"))
            .with_profile_identity(expected_generation);
        self.send_future(ctx, async move {
            let result =
                client::create_dir_at_generation(&profile, &path, &master, expected_generation)
                    .await
                    .map(|_| "目录已创建".to_owned())
                    .map_err(|e| e.to_string());
            UiMessage::DirectoryCreated {
                operation,
                context,
                result,
            }
        });
    }

    fn upload(&mut self, ctx: &egui::Context, profile: String) {
        let local = std::path::PathBuf::from(self.local_upload.trim());
        if self.local_upload.trim().is_empty() {
            self.set_notice("请输入本地文件路径".into(), true);
            return;
        }
        let remote = if self.remote_upload.trim().is_empty() {
            let Some(name) = local.file_name().and_then(|name| name.to_str()) else {
                self.set_notice("无法从本地路径取得文件名".into(), true);
                return;
            };
            join_remote_path(&self.remote_path, name)
        } else if self.remote_upload.starts_with('/') {
            self.remote_upload.trim().to_owned()
        } else {
            join_remote_path(&self.remote_path, self.remote_upload.trim())
        };
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&profile)
        else {
            return;
        };
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在上传到 {remote}…"))
            .with_profile_identity(expected_generation);
        let operation_id = operation.id;
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let resume = if self.transfer_resume {
            serctl_protocol::TransferResumeMode::Auto
        } else {
            serctl_protocol::TransferResumeMode::Never
        };
        let tx = self.tx.clone();
        let repaint = ctx.clone();
        let handle = self.runtime().spawn(async move {
            let progress_tx = tx.clone();
            let progress_repaint = repaint.clone();
            let progress: client::TransferProgressSink = Arc::new(move |progress| {
                let _ = progress_tx.send(UiMessage::TransferProgress {
                    operation_id,
                    progress,
                });
                progress_repaint.request_repaint();
            });
            let result = client::transfer_push_at_generation_cancellable(
                &profile,
                &local,
                &remote,
                client::TransferOptions {
                    backend: serctl_protocol::TransferBackend::Auto,
                    expected_helper_identity: None,
                    resume,
                    idle_timeout: Duration::from_millis(
                        serctl_protocol::DEFAULT_TRANSFER_IDLE_TIMEOUT_MS,
                    ),
                    deadline: None,
                    progress: Some(progress),
                },
                master,
                expected_generation,
                worker_cancellation,
            )
            .await
            .map(|bytes| format!("上传完成：{}", format_bytes(bytes)))
            .map_err(|e| e.to_string());
            let _ = tx.send(UiMessage::Transfer {
                operation,
                refresh: None,
                result,
            });
            repaint.request_repaint();
        });
        self.pending_transfers.insert(
            operation_id,
            PendingTransfer {
                cancellation,
                handle,
                progress: None,
            },
        );
    }

    fn download(&mut self, ctx: &egui::Context, profile: String) {
        let Some(entry) = self.selected_remote.clone() else {
            self.set_notice("请先选择一个远程文件".into(), true);
            return;
        };
        if entry.is_dir {
            self.set_notice("目录暂不支持整体下载，请选择文件".into(), true);
            return;
        }
        if self.local_download.trim().is_empty() {
            self.set_notice("请输入本地保存路径".into(), true);
            return;
        }
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&profile)
        else {
            return;
        };
        let local = std::path::PathBuf::from(self.local_download.trim());
        let remote = entry.path;
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在下载 {remote}…"))
            .with_profile_identity(expected_generation);
        let operation_id = operation.id;
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let resume = if self.transfer_resume {
            serctl_protocol::TransferResumeMode::Auto
        } else {
            serctl_protocol::TransferResumeMode::Never
        };
        let tx = self.tx.clone();
        let repaint = ctx.clone();
        let handle = self.runtime().spawn(async move {
            let progress_tx = tx.clone();
            let progress_repaint = repaint.clone();
            let progress: client::TransferProgressSink = Arc::new(move |progress| {
                let _ = progress_tx.send(UiMessage::TransferProgress {
                    operation_id,
                    progress,
                });
                progress_repaint.request_repaint();
            });
            let result = client::transfer_pull_at_generation_cancellable(
                &profile,
                &remote,
                &local,
                client::TransferOptions {
                    backend: serctl_protocol::TransferBackend::Auto,
                    expected_helper_identity: None,
                    resume,
                    idle_timeout: Duration::from_millis(
                        serctl_protocol::DEFAULT_TRANSFER_IDLE_TIMEOUT_MS,
                    ),
                    deadline: None,
                    progress: Some(progress),
                },
                master,
                expected_generation,
                worker_cancellation,
            )
            .await
            .map(|bytes| format!("下载完成：{}", format_bytes(bytes)))
            .map_err(|e| e.to_string());
            let _ = tx.send(UiMessage::Transfer {
                operation,
                refresh: None,
                result,
            });
            repaint.request_repaint();
        });
        self.pending_transfers.insert(
            operation_id,
            PendingTransfer {
                cancellation,
                handle,
                progress: None,
            },
        );
    }

    fn start_shell(&mut self, ctx: &egui::Context, profile: String) {
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&profile)
        else {
            return;
        };
        let operation = self
            .operations
            .begin(
                Some(profile.clone()),
                format!("正在打开 {profile} 的 Bash…"),
            )
            .with_profile_identity(expected_generation);
        self.send_future(ctx, async move {
            UiMessage::ShellOpened {
                operation,
                result: client::open_gui_shell_at_generation(
                    &profile,
                    &master,
                    expected_generation,
                )
                .await
                .map(|shell| (profile, shell))
                .map_err(|e| e.to_string()),
            }
        });
    }

    fn build_tunnel_spec(&mut self) -> Option<client::TunnelSpec> {
        let bind_port = match self.tunnel_bind_port.trim().parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                self.set_notice("隧道监听端口必须是 0–65535 之间的数字".into(), true);
                return None;
            }
        };
        let max_connections = match self.tunnel_max_connections.trim().parse::<u16>() {
            Ok(value) if (1..=MAX_UI_TUNNEL_CONNECTIONS).contains(&value) => value,
            _ => {
                self.set_notice(
                    format!("隧道最大连接数必须是 1–{MAX_UI_TUNNEL_CONNECTIONS} 之间的数字"),
                    true,
                );
                return None;
            }
        };
        let target_port = if self.tunnel_mode == client::TunnelMode::Dynamic {
            0
        } else {
            match self.tunnel_target_port.trim().parse::<u16>() {
                Ok(port) if port > 0 => port,
                _ => {
                    self.set_notice("隧道目标端口必须是 1–65535 之间的数字".into(), true);
                    return None;
                }
            }
        };

        Some(client::TunnelSpec {
            mode: self.tunnel_mode,
            bind_port,
            target_port,
            max_connections,
        })
    }

    fn start_tunnel(&mut self, ctx: &egui::Context, profile: String) {
        if self.tunnel.is_some()
            || self.pending_tunnel_start.is_some()
            || !self.pending_tunnel_stops.is_empty()
        {
            self.set_notice(
                "一次只能运行一个隧道；请先等待当前隧道完全停止".into(),
                true,
            );
            return;
        }
        let Some(spec) = self.build_tunnel_spec() else {
            return;
        };
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&profile)
        else {
            return;
        };
        let operation = self
            .operations
            .begin(
                Some(profile.clone()),
                format!("正在启动 {profile} 的 SSH 隧道…"),
            )
            .with_profile_identity(expected_generation);
        let context = TunnelContext {
            profile: profile.clone(),
            profile_generation: self.operations.profile_generation,
            profile_identity: expected_generation,
            instance: self.operations.next_tunnel_instance(),
        };
        let task_operation = operation.clone();
        let task_context = context.clone();
        let task_spec = clone_tunnel_spec(&spec);
        let tx = self.tx.clone();
        let repaint = ctx.clone();
        let handle = self.runtime().spawn(async move {
            let result = client::open_gui_tunnel_at_generation(
                &profile,
                task_spec,
                master,
                expected_generation,
            )
            .await
            .map_err(|error| error.to_string());
            let _ = tx.send(UiMessage::TunnelStarted {
                operation: task_operation,
                context: task_context,
                spec,
                result,
            });
            repaint.request_repaint();
        });
        self.pending_tunnel_start = Some(PendingTunnelStart {
            context,
            operation,
            handle,
        });
    }

    fn cancel_pending_tunnel_start(&mut self) {
        let Some(mut pending) = self.pending_tunnel_start.take() else {
            return;
        };
        self.operations.finish(&pending.operation);
        zeroize_operation_context(&mut pending.operation);
        pending.handle.abort();
        let context = pending.context;
        let pending_context = context.clone();
        let instance = context.instance;
        let tx = self.tx.clone();
        let handle = self.runtime().spawn(async move {
            let result = match tokio::time::timeout(TUNNEL_EXIT_GRACE, pending.handle).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) if error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("隧道启动清理超过 8 秒等待上限".into()),
            };
            let _ = tx.send(UiMessage::TunnelEnded { context, result });
        });
        self.pending_tunnel_stops.insert(
            instance,
            PendingTunnelStop {
                context: pending_context,
                handle,
            },
        );
    }

    fn stop_active_tunnel(&mut self) {
        let Some(mut active) = self.tunnel.take() else {
            return;
        };
        active.tunnel.cancel();
        let context = active.context;
        let pending_context = context.clone();
        let instance = context.instance;
        zeroize_tunnel_spec(&mut active.spec);
        zeroize_option_string(&mut active.last_error);
        let tx = self.tx.clone();
        let handle = self.runtime().spawn(async move {
            let result = match tokio::time::timeout(TUNNEL_EXIT_GRACE, active.tunnel.wait()).await {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("隧道停止超过 8 秒等待上限；后台任务已取消".into()),
            };
            let _ = tx.send(UiMessage::TunnelEnded { context, result });
        });
        self.pending_tunnel_stops.insert(
            instance,
            PendingTunnelStop {
                context: pending_context,
                handle,
            },
        );
    }

    fn stop_tunnel_for_profile(&mut self, _ctx: &egui::Context, profile: &str) {
        if self
            .pending_tunnel_start
            .as_ref()
            .is_some_and(|pending| pending.context.profile == profile)
        {
            self.cancel_pending_tunnel_start();
        }
        if self
            .tunnel
            .as_ref()
            .is_some_and(|active| active.context.profile == profile)
        {
            self.stop_active_tunnel();
        }
    }

    fn receive_tunnel_events(&mut self, ctx: &egui::Context) {
        let mut closed = false;
        if let Some(active) = &mut self.tunnel {
            while let Ok(event) = active.tunnel.events.try_recv() {
                match event {
                    client::TunnelEvent::Ready {
                        mut bind_host,
                        bind_port,
                    } => {
                        bind_host.zeroize();
                        active.bind_port = bind_port;
                    }
                    client::TunnelEvent::Error(mut error) => {
                        zeroize_option_string(&mut active.last_error);
                        active.last_error = Some(std::mem::take(&mut error));
                    }
                    client::TunnelEvent::Closed => closed = true,
                }
            }
        }
        if closed {
            self.stop_active_tunnel();
        }
        if self.tunnel.is_some()
            || self.pending_tunnel_start.is_some()
            || !self.pending_tunnel_stops.is_empty()
        {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn send_shell_bytes(&mut self, mut bytes: Vec<u8>) {
        let Some(shell) = &self.shell else {
            bytes.zeroize();
            self.set_notice("请先打开 Bash 会话".into(), true);
            return;
        };
        if let Err(error) = shell.input.try_send(Zeroizing::new(bytes)) {
            let mut rejected = error.into_inner();
            rejected.zeroize();
            self.set_notice("Bash 输入队列不可用".into(), true);
        }
    }

    fn receive_shell_events(&mut self, ctx: &egui::Context) {
        let mut closed = false;
        let mut close_error = None;
        if let Some(shell) = &mut self.shell {
            while let Ok(event) = shell.events.try_recv() {
                match event {
                    client::ShellEvent::Output(mut data) => {
                        self.shell_bytes.extend_from_slice(&data);
                        data.zeroize();
                    }
                    client::ShellEvent::Error(error) => {
                        close_error = Some(error);
                        closed = true;
                    }
                    client::ShellEvent::Closed => closed = true,
                }
            }
            if self.shell_bytes.len() > 2 * 1024 * 1024 {
                let keep_from = self.shell_bytes.len() - 1024 * 1024;
                let retained = self.shell_bytes.len() - keep_from;
                self.shell_bytes.copy_within(keep_from.., 0);
                self.shell_bytes[retained..].zeroize();
                self.shell_bytes.truncate(retained);
            }
            self.shell_output.zeroize();
            self.shell_output = terminal_text(&self.shell_bytes);
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        if closed {
            self.close_shell();
            let (message, error) = match close_error {
                Some(mut error) => {
                    let message = format!("Bash: {error}");
                    error.zeroize();
                    (message, true)
                }
                None => ("Bash 会话已关闭".into(), false),
            };
            self.set_notice(message, error);
        }
    }

    fn start_daemon(&mut self, ctx: &egui::Context, profile: String) {
        let startup_deadline = tokio::time::Instant::now() + DAEMON_STARTUP_TIMEOUT;
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&profile)
        else {
            return;
        };
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在连接 {profile}…"))
            .with_profile_identity(expected_generation);
        let instance = self.operations.next_daemon_instance();
        let tx = self.tx.clone();
        let repaint = ctx.clone();
        self.runtime().spawn(async move {
            // The broker is per-user/per-vault global and outlives this UI:
            // "connecting" a profile only requires the broker to be published
            // (launching it on demand) and the profile to unlock against it.
            // The authorized Status probe doubles as the readiness signal.
            let result = match tokio::time::timeout_at(
                startup_deadline,
                client::daemon_status_at_generation(&profile, &master, expected_generation),
            )
            .await
            {
                Ok(Ok(Some(_))) => Ok(true),
                Ok(Ok(None)) => Err("连接未能启动：daemon 未发布运行时描述符".into()),
                Ok(Err(error)) => Err(format!("连接未能启动：{error}")),
                Err(_) => Err("连接未能在 30 秒内就绪".into()),
            };
            drop(master);
            let _ = tx.send(UiMessage::DaemonStarted {
                operation,
                profile,
                instance,
                result,
            });
            repaint.request_repaint();
        });
    }

    fn stop_daemon(&mut self, ctx: &egui::Context, profile: String) {
        let Some((expected_generation, master)) = self.required_authorized_profile_grant(&profile)
        else {
            return;
        };
        self.stop_tunnel_for_profile(ctx, &profile);
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在断开 {profile}…"))
            .with_profile_identity(expected_generation);
        let instance = self.owned_daemons.get(&profile).copied();
        self.send_future(ctx, async move {
            let result = client::down_quiet_at_generation(&profile, &master, expected_generation)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            UiMessage::DaemonStopped {
                operation,
                profile,
                instance,
                result,
            }
        });
    }

    fn receive_messages(&mut self, ctx: &egui::Context) {
        while let Ok(mut message) = self.rx.try_recv() {
            match message.message_mut() {
                UiMessage::Authorization { operation, result } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if !current {
                        continue;
                    }
                    match std::mem::replace(result, Err(String::new())) {
                        Ok(grant) => {
                            let profile = grant.profile.clone();
                            self.authorizations.grant(
                                grant.profile,
                                grant.identity,
                                grant.passphrase,
                                grant.verified_at,
                            );
                            self.set_notice(
                                format!("{profile} 的独立口令授权已生效，有效期 5 分钟"),
                                false,
                            );
                            self.refresh(ctx);
                            ctx.request_repaint();
                        }
                        Err(mut error) => {
                            let message = format!("独立口令验证失败：{error}");
                            error.zeroize();
                            self.set_notice(message, true);
                        }
                    }
                }
                UiMessage::AdminAuthorization { operation, result } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if !current {
                        self.pending_create_after_admin = false;
                        continue;
                    }
                    match std::mem::replace(result, Err(String::new())) {
                        Ok(grant) => {
                            self.admin_authorization
                                .grant(grant.passphrase, grant.verified_at);
                            if self.pending_create_after_admin
                                && self.editor.visible
                                && self.editor.original_name.is_none()
                            {
                                self.pending_create_after_admin = false;
                                self.admin_dialog.close();
                                self.set_notice(
                                    "超管授权已生效，正在继续保存新主机…".into(),
                                    false,
                                );
                                self.save_profile(ctx);
                            } else {
                                self.pending_create_after_admin = false;
                                self.set_notice("超管授权已生效，有效期 2 分钟".into(), false);
                            }
                        }
                        Err(mut error) => {
                            let message = format!("超管授权失败：{error}");
                            error.zeroize();
                            self.set_notice(message, true);
                        }
                    }
                }
                UiMessage::AdminStatus { operation, result } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if !current {
                        continue;
                    }
                    match result {
                        Ok(status) => self.admin_dialog.status = Some(status.clone()),
                        Err(error) => self.set_notice(std::mem::take(error), true),
                    }
                }
                UiMessage::AdminInitialized { operation, result } => {
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    match result {
                        Ok(path) => {
                            self.admin_dialog.clear_secrets();
                            self.admin_authorization.revoke();
                            self.set_notice(
                                if self.pending_create_after_admin {
                                    format!(
                                        "超管与离线恢复已初始化；恢复介质已写入 {path}。请授权超管密码，随后将自动继续保存主机"
                                    )
                                } else {
                                    format!("超管与离线恢复已初始化；恢复介质已写入 {path}")
                                },
                                false,
                            );
                            self.open_admin_dialog(ctx);
                            self.refresh_migration_state();
                        }
                        Err(error) => self.set_notice(std::mem::take(error), true),
                    }
                }
                UiMessage::AdminPasswordChanged { operation, result } => {
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    self.admin_authorization.revoke();
                    match result {
                        Ok(()) => {
                            self.admin_dialog.clear_secrets();
                            self.set_notice("超管密码已更改；请重新授权".into(), false);
                        }
                        Err(error) => self.set_notice(std::mem::take(error), true),
                    }
                }
                UiMessage::RecoveryRotated { operation, result } => {
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    self.admin_authorization.revoke();
                    match result {
                        Ok(path) => self.set_notice(
                            if self.pending_create_after_admin {
                                format!(
                                    "恢复介质已轮转并写入 {path}；旧介质已失效。请重新授权，随后将自动继续保存主机"
                                )
                            } else {
                                format!("恢复介质已轮转并写入 {path}；旧介质已失效")
                            },
                            false,
                        ),
                        Err(error) => self.set_notice(std::mem::take(error), true),
                    }
                }
                UiMessage::ProfileRecovered {
                    operation,
                    profile,
                    result,
                }
                | UiMessage::ProfileReset {
                    operation,
                    profile,
                    result,
                } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    self.authorizations.revoke_profile(profile.as_str());
                    self.admin_authorization.revoke();
                    match result {
                        Ok(_) => {
                            self.clear_protected_profile_workspace(profile.as_str());
                            self.security_dialog.clear();
                            if current {
                                self.set_notice(
                                    format!("{profile} 已重置；请使用新独立口令授权"),
                                    false,
                                );
                            }
                            self.refresh(ctx);
                        }
                        Err(error) if current => {
                            self.set_notice(std::mem::take(error), true);
                        }
                        Err(_) => {}
                    }
                    profile.zeroize();
                }
                #[cfg(windows)]
                UiMessage::Migrated { operation, result } => {
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    match result {
                        Ok(count) => {
                            self.migration.clear_secrets();
                            self.migration.visible = false;
                            self.set_notice(format!("已原子迁移 {count} 个 profile"), false);
                            self.refresh_migration_state();
                            self.refresh(ctx);
                        }
                        Err(error) => self.set_notice(std::mem::take(error), true),
                    }
                }
                #[cfg(any(windows, test))]
                UiMessage::MigrationProgress {
                    operation_id,
                    progress,
                } => {
                    let mut activity = match progress {
                        vault::MigrationProgress::Validating => "正在校验迁移输入…".to_owned(),
                        vault::MigrationProgress::WaitingForExclusiveAccess => {
                            "正在取得凭证库独占访问权…".to_owned()
                        }
                        vault::MigrationProgress::AuthenticatedLegacyVault => {
                            "旧主口令验证完成，正在准备 v4 恢复策略…".to_owned()
                        }
                        vault::MigrationProgress::MigratingProfile {
                            completed,
                            total,
                            profile,
                        } => format!(
                            "正在迁移 profile {}/{}：{}",
                            completed.saturating_add(1),
                            total,
                            profile
                        ),
                        vault::MigrationProgress::PersistingRecoveryMedia => {
                            "正在写入并校验离线恢复介质…".to_owned()
                        }
                        vault::MigrationProgress::CommittingVault => {
                            "正在原子提交 v4 凭证库…".to_owned()
                        }
                    };
                    let updated = self
                        .operations
                        .update_activity(*operation_id, activity.clone());
                    if updated {
                        ctx.request_repaint();
                    }
                    activity.zeroize();
                }
                UiMessage::Profiles {
                    operation,
                    epoch,
                    result,
                } => {
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if *epoch != self.operations.refresh_epoch {
                        zeroize_profile_result(result);
                        continue;
                    }
                    match result {
                        Ok(rows) => {
                            let endpoint_changed = self.selected.as_ref().is_some_and(|name| {
                                let previous =
                                    self.profiles.iter().find(|profile| &profile.name == name);
                                let refreshed = rows.iter().find(|profile| &profile.name == name);
                                previous.is_some()
                                    && match (previous, refreshed) {
                                        (Some(previous), Some(refreshed)) => {
                                            previous.host != refreshed.host
                                                || previous.port != refreshed.port
                                                || previous.identity() != refreshed.identity()
                                        }
                                        (Some(_), None) => true,
                                        _ => false,
                                    }
                            });
                            let security_dialog_stale = self.security_dialog.visible
                                && self
                                    .security_dialog
                                    .expected_identity
                                    .is_none_or(|expected| {
                                        rows.iter()
                                            .find(|row| row.name == self.security_dialog.profile)
                                            .is_none_or(|row| row.identity() != expected)
                                    });
                            let editor_stale = self.editor.visible
                                && self.editor.original_name.as_ref().is_some_and(|name| {
                                    self.editor.expected_identity.is_none_or(|expected| {
                                        rows.iter()
                                            .find(|row| &row.name == name)
                                            .is_none_or(|row| row.identity() != expected)
                                    })
                                });
                            for profile in &mut self.profiles {
                                zeroize_profile_row(profile);
                            }
                            self.profiles.clear();
                            self.profiles.append(rows);
                            if security_dialog_stale {
                                self.security_dialog.clear();
                            }
                            if editor_stale {
                                self.editor.clear();
                            }
                            let grants_invalidated =
                                self.authorizations.retain_current_profiles(&self.profiles);
                            if grants_invalidated {
                                let selected_lost_authorization =
                                    self.selected.clone().filter(|selected| {
                                        self.profile_identity(selected).is_some_and(|identity| {
                                            !self.profile_is_authorized_at(
                                                selected,
                                                identity,
                                                Instant::now(),
                                            )
                                        })
                                    });
                                if let Some(mut selected) = selected_lost_authorization {
                                    self.clear_protected_profile_workspace(&selected);
                                    selected.zeroize();
                                }
                            }
                            if self.selected.as_ref().is_none_or(|name| {
                                !self.profiles.iter().any(|profile| &profile.name == name)
                            }) {
                                let selected = self.profiles.first().map(|p| p.name.clone());
                                self.select_profile(selected);
                            } else if endpoint_changed {
                                self.invalidate_profile_context();
                            }
                        }
                        Err(error) => self.set_notice(std::mem::take(error), true),
                    }
                }
                UiMessage::Saved {
                    operation,
                    original_name,
                    result,
                } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    match result {
                        Ok(name) => {
                            self.pending_create_after_admin = false;
                            if let Some(original) = original_name.as_deref() {
                                self.authorizations.revoke_profile(original);
                            }
                            self.authorizations.revoke_profile(name.as_str());
                            let selected_was_updated = self.selected.as_deref()
                                == Some(name.as_str())
                                || original_name
                                    .as_deref()
                                    .is_some_and(|old| self.selected.as_deref() == Some(old));
                            self.remove_cached_profile_rows(
                                original_name.as_deref(),
                                name.as_str(),
                            );
                            if current || selected_was_updated {
                                // The vault mutation has already committed. Invalidate the old
                                // endpoint/user context immediately instead of relying on the
                                // follow-up profile refresh, which can time out or fail.
                                self.invalidate_profile_context();
                            }
                            if current {
                                self.editor.clear();
                                self.select_profile(Some(name.clone()));
                                self.set_notice(format!("已保存 {name}"), false);
                            }
                            self.refresh(ctx);
                        }
                        Err(error) if current => {
                            self.set_notice(std::mem::take(error), true);
                        }
                        Err(_) => {}
                    }
                }
                UiMessage::ProfilePassphraseChanged {
                    operation,
                    profile,
                    result,
                } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    self.authorizations.revoke_profile(profile.as_str());
                    match result {
                        Ok(_) => {
                            self.clear_protected_profile_workspace(profile.as_str());
                            if current {
                                self.security_dialog.clear();
                                self.set_notice(
                                    format!("{profile} 的独立口令已轮转；请使用新口令重新授权"),
                                    false,
                                );
                            }
                            self.refresh(ctx);
                        }
                        Err(error) if current => {
                            self.set_notice(std::mem::take(error), true);
                        }
                        Err(_) => {}
                    }
                    profile.zeroize();
                }
                UiMessage::Removed { operation, result } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    match result {
                        Ok(name) => {
                            self.authorizations.revoke_profile(name.as_str());
                            if let Some((mut owned_name, _)) =
                                self.owned_daemons.remove_entry(name.as_str())
                            {
                                owned_name.zeroize();
                            }
                            if self.shell_profile.as_deref() == Some(name.as_str()) {
                                self.close_shell();
                            }
                            if current {
                                self.select_profile(None);
                                self.set_notice(format!("已删除 {name}"), false);
                            }
                            self.refresh(ctx);
                        }
                        Err(error) if current => {
                            self.set_notice(std::mem::take(error), true);
                        }
                        Err(_) => {}
                    }
                }
                UiMessage::Command { operation, result } => {
                    let current = self.protected_operation_is_current_at(operation, Instant::now());
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if !current {
                        continue;
                    }
                    match result {
                        Ok(result) => {
                            let mut output = command_output_text(&result.stdout, &result.stderr);
                            self.output.zeroize();
                            self.output = if output.is_empty() {
                                "（命令没有输出）".into()
                            } else {
                                std::mem::take(&mut *output)
                            };
                            self.exit_code = result.code;
                        }
                        Err(error) => {
                            self.output.zeroize();
                            self.output = format!("执行失败：{error}");
                            self.set_notice(std::mem::take(error), true);
                        }
                    }
                }
                UiMessage::DaemonStarted {
                    operation,
                    profile,
                    instance,
                    result,
                } => {
                    let current = self.protected_operation_is_current_at(operation, Instant::now());
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    match result {
                        Ok(owned) => {
                            if *owned {
                                record_owned_daemon(
                                    &mut self.owned_daemons,
                                    profile.clone(),
                                    *instance,
                                );
                            }
                            if current {
                                self.set_notice(format!("{profile} 已连接"), false);
                            }
                            self.refresh(ctx);
                        }
                        Err(error) if current => {
                            self.set_notice(std::mem::take(error), true);
                        }
                        Err(_) => {}
                    }
                }
                UiMessage::DaemonStopped {
                    operation,
                    profile,
                    instance,
                    result,
                } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    match result {
                        Ok(()) => {
                            let lifecycle_current = match *instance {
                                Some(instance) => remove_owned_daemon(
                                    &mut self.owned_daemons,
                                    profile.as_str(),
                                    instance,
                                ),
                                None => !self.owned_daemons.contains_key(profile.as_str()),
                            };
                            if lifecycle_current
                                && self.shell_profile.as_deref() == Some(profile.as_str())
                            {
                                self.close_shell();
                            }
                            if lifecycle_current {
                                self.stop_tunnel_for_profile(ctx, profile.as_str());
                            }
                            if current && lifecycle_current {
                                self.set_notice(format!("{profile} 已断开"), false);
                            }
                            self.refresh(ctx);
                        }
                        Err(error) if current => {
                            self.set_notice(std::mem::take(error), true);
                        }
                        Err(_) => {}
                    }
                }
                UiMessage::DaemonEnded {
                    operation,
                    profile,
                    instance,
                    error,
                } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if remove_owned_daemon(&mut self.owned_daemons, profile.as_str(), *instance) {
                        if self.shell_profile.as_deref() == Some(profile.as_str()) {
                            self.close_shell();
                        }
                        self.stop_tunnel_for_profile(ctx, profile.as_str());
                        if current {
                            self.set_notice(format!("{profile}: {error}"), true);
                        }
                        self.refresh(ctx);
                    }
                }
                UiMessage::Directory {
                    operation,
                    request,
                    result,
                } => {
                    let current = self.protected_operation_is_current_at(operation, Instant::now())
                        && self.directory_request_is_current(request);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if current {
                        match result {
                            Ok((path, entries)) => {
                                self.remote_path.zeroize();
                                self.remote_path = std::mem::take(path);
                                self.clear_remote_entries();
                                self.remote_entries.append(entries);
                            }
                            Err(error) => {
                                self.set_notice(std::mem::take(error), true);
                            }
                        }
                    }
                }
                UiMessage::DirectoryCreated {
                    operation,
                    context,
                    result,
                } => {
                    let current = self.protected_operation_is_current_at(operation, Instant::now())
                        && self.directory_request_is_current(context);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if current {
                        match result {
                            Ok(path) => {
                                self.new_directory.zeroize();
                                self.set_notice(std::mem::take(path), false);
                            }
                            Err(error) => {
                                self.set_notice(std::mem::take(error), true);
                            }
                        }
                    }
                }
                UiMessage::TransferProgress {
                    operation_id,
                    progress,
                } => {
                    if let Some(transfer) = self.pending_transfers.get_mut(operation_id) {
                        transfer.progress = Some(progress.clone());
                    }
                }
                UiMessage::Transfer {
                    operation,
                    refresh,
                    result,
                } => {
                    self.pending_transfers.remove(&operation.id);
                    let current = self.protected_operation_is_current_at(operation, Instant::now());
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if current {
                        match result {
                            Ok(message) => {
                                self.set_notice(std::mem::take(message), false);
                            }
                            Err(error) => {
                                self.set_notice(std::mem::take(error), true);
                            }
                        }
                        if let Some(mut context) = refresh.take() {
                            zeroize_directory_request(&mut context);
                        }
                    }
                }
                UiMessage::ShellOpened { operation, result } => {
                    let current = self.protected_operation_is_current_at(operation, Instant::now());
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if !current {
                        if let Ok((profile, shell)) = result {
                            profile.zeroize();
                            shell.cancel();
                        }
                        continue;
                    }
                    match std::mem::replace(result, Err(String::new())) {
                        Ok((profile, shell)) => {
                            let mut profile = Zeroizing::new(profile);
                            self.close_shell();
                            self.shell = Some(shell);
                            self.shell_profile = Some(std::mem::take(&mut *profile));
                            self.shell_output.zeroize();
                            self.shell_output = "Bash 会话已打开。".into();
                            self.set_notice("Bash 会话已打开".into(), false);
                        }
                        Err(error) => self.set_notice(error, true),
                    }
                }
                UiMessage::TunnelStarted {
                    operation,
                    context,
                    spec,
                    result,
                } => {
                    let current = self.protected_operation_is_current_at(operation, Instant::now());
                    let adopt = tunnel_start_may_be_adopted(
                        self.selected.as_deref(),
                        self.operations.profile_generation,
                        self.profile_identity(&context.profile),
                        self.pending_tunnel_start
                            .as_ref()
                            .map(|pending| &pending.context),
                        self.tunnel.as_ref().map(|active| &active.context),
                        context,
                    );
                    let pending_matches = self
                        .pending_tunnel_start
                        .as_ref()
                        .is_some_and(|pending| pending.context == *context);
                    if pending_matches {
                        if let Some(mut pending) = self.pending_tunnel_start.take() {
                            zeroize_tunnel_context(&mut pending.context);
                            zeroize_operation_context(&mut pending.operation);
                        }
                    }
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if !current || !adopt {
                        if let Ok(tunnel) = result {
                            tunnel.cancel();
                        }
                        continue;
                    }
                    match std::mem::replace(result, Err(String::new())) {
                        Ok(tunnel) => {
                            let ready = tunnel.ready();
                            let bind_port = ready.bind_port;
                            self.tunnel = Some(ActiveTunnel {
                                context: context.clone(),
                                spec: clone_tunnel_spec(spec),
                                bind_port,
                                last_error: None,
                                tunnel,
                            });
                            self.set_notice("SSH 隧道已启动".into(), false);
                        }
                        Err(error) => self.set_notice(error, true),
                    }
                }
                UiMessage::TunnelEnded { context, result } => {
                    let current = tunnel_context_is_current(
                        self.selected.as_deref(),
                        self.operations.profile_generation,
                        self.profile_identity(&context.profile),
                        context,
                    );
                    let matched = self
                        .pending_tunnel_stops
                        .remove(&context.instance)
                        .is_some_and(|mut pending| {
                            let matched =
                                tunnel_end_matches_pending(Some(&pending.context), context);
                            zeroize_tunnel_context(&mut pending.context);
                            matched
                        });
                    zeroize_tunnel_context(context);
                    if !matched || !current {
                        continue;
                    }
                    match result {
                        Ok(()) => self.set_notice("SSH 隧道已停止".into(), false),
                        Err(error) => self.set_notice(std::mem::take(error), true),
                    }
                }
                #[cfg(test)]
                UiMessage::ZeroizeProbe(_) => {
                    panic!("exercise reducer unwind with a sensitive message")
                }
            }
        }
    }

    fn open_editor(&mut self, profile: Option<ProfileRow>) {
        self.pending_create_after_admin = false;
        self.editor.clear();
        self.editor.visible = true;
        if let Some(mut profile) = profile {
            self.editor.original_name = Some(profile.name.clone());
            self.editor.expected_identity = Some(profile.identity());
            self.editor.name = std::mem::take(&mut profile.name);
            self.editor.host = std::mem::take(&mut profile.host);
            self.editor.port = profile.port.to_string();
            zeroize_profile_row(&mut profile);
        }
    }

    fn selected_profile(&self) -> Option<ProfileRow> {
        let selected = self.selected.as_ref()?;
        self.profiles.iter().find(|p| &p.name == selected).cloned()
    }

    fn select_profile(&mut self, selected: Option<String>) {
        if self.selected != selected {
            zeroize_option_string(&mut self.selected);
            self.selected = selected;
            self.invalidate_profile_context();
        }
    }

    fn invalidate_profile_context(&mut self) {
        // A tunnel is a live local capability. Revoke it before advancing the
        // profile generation so no hidden listener survives a profile switch.
        self.cancel_pending_tunnel_start();
        self.stop_active_tunnel();
        self.operations.advance_profile_generation();
        for transfer in self.pending_transfers.values() {
            transfer.cancellation.cancel();
        }
        self.invalidate_directory_context();

        self.remote_path.zeroize();
        self.remote_path = ".".into();
        self.command.zeroize();
        self.command = "uname -a && whoami".into();
        self.profile_passphrase_input.zeroize();
        self.security_dialog.clear();
        self.output.zeroize();
        self.output = "选择一个主机，然后执行命令。".into();
        self.exit_code = None;
        self.new_directory.zeroize();
        self.local_upload.zeroize();
        self.remote_upload.zeroize();
        self.local_download.zeroize();
        self.close_shell();
        self.tunnel_mode = client::TunnelMode::Local;
        self.tunnel_bind_port.zeroize();
        self.tunnel_bind_port = "0".into();
        self.tunnel_target_port.zeroize();
        self.tunnel_max_connections.zeroize();
        self.tunnel_max_connections = "32".into();
        self.workspace_tab = WorkspaceTab::Command;

        if let Some(mut candidate) = self.delete_candidate.take() {
            candidate.zeroize();
        }
        if let Some((mut message, _)) = self.notice.take() {
            message.zeroize();
        }
    }

    fn invalidate_directory_context(&mut self) {
        self.directory_requests.invalidate();
        self.clear_remote_entries();
    }

    fn clear_remote_entries(&mut self) {
        for entry in &mut self.remote_entries {
            entry.name.zeroize();
            entry.path.zeroize();
        }
        self.remote_entries.clear();
        if let Some(mut entry) = self.selected_remote.take() {
            entry.name.zeroize();
            entry.path.zeroize();
        }
    }

    fn remove_cached_profile_rows(&mut self, original_name: Option<&str>, saved_name: &str) {
        self.profiles.retain_mut(|profile| {
            let remove = profile.name == saved_name
                || original_name.is_some_and(|original| profile.name == original);
            if remove {
                zeroize_profile_row(profile);
            }
            !remove
        });
    }

    fn close_shell(&mut self) {
        if let Some(shell) = self.shell.take() {
            shell.cancel();
        }
        zeroize_option_string(&mut self.shell_profile);
        self.shell_input.zeroize();
        self.shell_bytes.zeroize();
        self.shell_output.zeroize();
        self.shell_output = "尚未打开 Bash 会话。".into();
    }

    fn zeroize_sensitive_state(&mut self) {
        for transfer in self.pending_transfers.values() {
            transfer.cancellation.cancel();
        }
        for profile in &mut self.profiles {
            profile.name.zeroize();
            profile.host.zeroize();
            if let Some(status) = &mut profile.daemon {
                status.profile.zeroize();
                status.host.zeroize();
                status.user.zeroize();
                status.endpoint.zeroize();
            }
        }
        self.profiles.clear();
        for (mut profile, _) in std::mem::take(&mut self.owned_daemons) {
            profile.zeroize();
        }
        zeroize_option_string(&mut self.selected);
        self.editor.zeroize_sensitive_state();
        self.security_dialog.clear();
        self.admin_dialog.close();
        self.pending_create_after_admin = false;
        zeroize_admin_status(&mut self.admin_dialog.status);
        self.admin_authorization.revoke();
        self.migration.clear_secrets();
        for profile in &mut self.migration.profiles {
            profile.zeroize();
        }
        self.migration.profiles.clear();
        self.migration.recovery_media_path.zeroize();
        zeroize_migration_state(&mut self.migration_state);
        zeroize_option_string(&mut self.delete_candidate);
        self.command.zeroize();
        self.profile_passphrase_input.zeroize();
        self.authorizations.revoke_all();
        self.output.zeroize();
        self.remote_path.zeroize();
        self.clear_remote_entries();
        self.new_directory.zeroize();
        self.local_upload.zeroize();
        self.remote_upload.zeroize();
        self.local_download.zeroize();
        if let Some(shell) = self.shell.take() {
            shell.cancel();
        }
        zeroize_option_string(&mut self.shell_profile);
        self.shell_input.zeroize();
        self.shell_bytes.zeroize();
        self.shell_output.zeroize();
        self.tunnel_bind_port.zeroize();
        self.tunnel_target_port.zeroize();
        self.tunnel_max_connections.zeroize();
        if let Some(mut pending) = self.pending_tunnel_start.take() {
            pending.handle.abort();
            zeroize_tunnel_context(&mut pending.context);
            zeroize_operation_context(&mut pending.operation);
        }
        if let Some(mut active) = self.tunnel.take() {
            active.tunnel.cancel();
            zeroize_tunnel_context(&mut active.context);
            zeroize_tunnel_spec(&mut active.spec);
            zeroize_option_string(&mut active.last_error);
        }
        for (_, mut pending) in std::mem::take(&mut self.pending_tunnel_stops) {
            pending.handle.abort();
            zeroize_tunnel_context(&mut pending.context);
        }
        for activity in self.operations.active.values_mut() {
            activity.zeroize();
        }
        self.operations.active.clear();
        if let Some((mut notice, _)) = self.notice.take() {
            notice.zeroize();
        }
    }

    fn operation_is_current(&self, operation: &OperationContext) -> bool {
        self.operations
            .is_current(self.selected.as_deref(), operation)
            && operation.profile_identity.is_none_or(|expected| {
                operation
                    .profile
                    .as_deref()
                    .and_then(|profile| self.profile_identity(profile))
                    == Some(expected)
            })
    }

    fn protected_operation_is_current_at(
        &self,
        operation: &OperationContext,
        now: Instant,
    ) -> bool {
        if !self.operation_is_current(operation) {
            return false;
        }
        let (Some(profile), Some(identity)) =
            (operation.profile.as_deref(), operation.profile_identity)
        else {
            return false;
        };
        self.authorizations.get(profile, identity, now).is_some()
    }

    fn directory_request_is_current(&self, request: &DirectoryRequest) -> bool {
        self.directory_requests.is_current(
            self.selected.as_deref(),
            self.operations.profile_generation,
            self.profile_identity(&request.profile),
            request,
        )
    }

    fn authorization_controls(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        busy: bool,
        profile: Option<&ProfileRow>,
    ) {
        self.expire_authorizations_and_protected_sessions(Instant::now());
        let remaining = profile.and_then(|profile| {
            self.authorizations
                .remaining_at(&profile.name, profile.identity(), Instant::now())
        });
        if remaining.is_some() {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("主机独立授权").strong());
                match (profile, remaining) {
                    (Some(profile), Some(remaining)) => {
                        let seconds = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
                        let minutes = seconds / 60;
                        let seconds = seconds % 60;
                        ui.label(
                            RichText::new(format!(
                                "● {} 已授权 · 剩余 {minutes:02}:{seconds:02}",
                                profile.name
                            ))
                                .color(Color32::from_rgb(76, 205, 140)),
                        );
                    }
                    (Some(profile), None) => {
                        ui.label(
                            RichText::new(format!("○ {} 未授权", profile.name))
                                .color(Color32::GRAY),
                        );
                    }
                    (None, _) => {
                        ui.label(RichText::new("选择主机后授权").color(Color32::GRAY));
                    }
                }
                if remaining.is_some()
                    && ui.add_enabled(!busy, egui::Button::new("撤销此主机")).clicked()
                {
                    if let Some(profile) = profile {
                        self.revoke_profile_authorization(&profile.name);
                    }
                }
                if self.authorizations.grants.len() > 1
                    && ui
                        .add_enabled(!busy, egui::Button::new("全部锁定"))
                        .clicked()
                {
                    self.revoke_all_authorizations();
                }
            });
            if profile.is_some() {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    // An infinite-width field consumes the whole row before the
                    // authorization button is laid out. Reserve that trailing
                    // space explicitly so the group cannot widen the panel and
                    // push controls beyond the viewport.
                    let button_width = 96.0;
                    let field_width =
                        (ui.available_width() - button_width - ui.spacing().item_spacing.x)
                            .max(0.0);
                    let response = add_secret_password_edit_with_width(
                        ui,
                        !busy,
                        "profile-workspace-passphrase",
                        &mut self.profile_passphrase_input,
                        if remaining.is_some() {
                            "重新输入该主机独立口令"
                        } else {
                            "输入该主机独立口令"
                        },
                        field_width,
                    );
                    let authorize = ui.add_enabled(
                        !busy,
                        egui::Button::new(if remaining.is_some() {
                            "重新授权"
                        } else {
                            "授权 5 分钟"
                        })
                        .min_size(egui::vec2(button_width, 0.0)),
                    );
                    if !busy
                        && (authorize.clicked()
                            || (response.lost_focus()
                                && ui.input(|input| input.key_pressed(egui::Key::Enter))))
                    {
                        self.authorize(ctx);
                    }
                });
            }
            ui.label(
                RichText::new(
                    "授权只适用于当前 profile 与当前 generation；有效期固定 5 分钟且不会因操作续期。",
                )
                .small()
                .color(Color32::GRAY),
            );
        });
    }

    fn sidebar(&mut self, root: &mut egui::Ui) {
        let ctx = root.ctx().clone();
        self.expire_authorizations_and_protected_sessions(Instant::now());
        let mut profiles = self.profiles.clone();
        let busy = self.operations.is_busy();
        egui::Panel::left("profiles")
            .resizable(false)
            .exact_size(270.0)
            .show(root, |ui| {
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("◈")
                            .size(28.0)
                            .color(Color32::from_rgb(90, 164, 255)),
                    );
                    ui.vertical(|ui| {
                        ui.label(RichText::new("serctl").size(22.0).strong());
                        ui.label(RichText::new("SSH 工作台").small().color(Color32::GRAY));
                    });
                });
                ui.add_space(20.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, egui::Button::new("＋ 新建主机"))
                        .clicked()
                    {
                        self.open_editor(None);
                    }
                    if ui
                        .add_enabled(!busy, egui::Button::new("⟳"))
                        .on_hover_text("刷新本地目录；仅探测已授权主机的状态")
                        .clicked()
                    {
                        self.refresh(&ctx);
                    }
                    if ui
                        .add_enabled(!busy, egui::Button::new("安全与恢复"))
                        .clicked()
                    {
                        self.pending_create_after_admin = false;
                        self.open_admin_dialog(&ctx);
                    }
                });
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);

                if self.profiles.is_empty() {
                    ui.label(RichText::new("尚无主机配置").color(Color32::GRAY));
                }
                for profile in &profiles {
                    let selected = self.selected.as_deref() == Some(&profile.name);
                    let remaining = self.authorizations.remaining_at(
                        &profile.name,
                        profile.identity(),
                        Instant::now(),
                    );
                    let authorized = remaining.is_some();
                    let status = if !authorized {
                        "◆"
                    } else if profile.daemon.is_some() {
                        "●"
                    } else {
                        "○"
                    };
                    let color = if !authorized {
                        Color32::from_gray(105)
                    } else if profile.daemon.is_some() {
                        Color32::from_rgb(76, 205, 140)
                    } else {
                        Color32::from_gray(115)
                    };
                    let authorization_label = remaining.map_or_else(
                        || "已锁定".to_owned(),
                        |remaining| {
                            let seconds =
                                remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
                            format!("授权 {:02}:{:02}", seconds / 60, seconds % 60)
                        },
                    );
                    let mut label = format!(
                        "{status}  {}  · {authorization_label}\n     {}:{}",
                        profile.name, profile.host, profile.port
                    );
                    let clicked = ui
                        .selectable_label(
                            selected,
                            RichText::new(label.as_str()).color(if selected {
                                Color32::WHITE
                            } else {
                                color
                            }),
                        )
                        .clicked();
                    label.zeroize();
                    if clicked {
                        self.select_profile(Some(profile.name.clone()));
                    }
                    ui.add_space(3.0);
                }
            });
        for profile in &mut profiles {
            zeroize_profile_row(profile);
        }
        profiles.clear();
    }

    fn central_panel(&mut self, root: &mut egui::Ui) {
        let ctx = root.ctx().clone();
        self.expire_authorizations_and_protected_sessions(Instant::now());
        let busy = self.operations.is_busy();
        let mut profile = self.selected_profile();
        egui::CentralPanel::default().show(root, |ui| {
            ui.add_space(18.0);
            self.authorization_controls(ui, &ctx, busy, profile.as_ref());
            ui.add_space(14.0);
            let profile_authorized = profile.as_ref().is_some_and(|profile| {
                self.profile_is_authorized_at(&profile.name, profile.identity(), Instant::now())
            });
            if profile.is_some() && !profile_authorized {
                ui.vertical_centered(|ui| {
                    ui.add_space(110.0);
                    ui.label(RichText::new("此主机工作区已锁定").size(24.0));
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("验证该主机的独立口令后，才会查询其连接状态或执行远程操作。")
                            .color(Color32::GRAY),
                    );
                });
                return;
            }
            let Some(profile) = profile.as_ref() else {
                ui.vertical_centered(|ui| {
                    ui.add_space(110.0);
                    ui.label(RichText::new("选择或新建一台主机").size(24.0));
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("凭据会加密保存在本机，不会出现在命令行参数中。\n")
                            .color(Color32::GRAY),
                    );
                    if ui
                        .add_enabled(!busy, egui::Button::new("新建主机"))
                        .clicked()
                    {
                        self.open_editor(None);
                    }
                });
                return;
            };

            // Lay out the actions from the right edge first. Keep this scope at
            // the height of the two-line title: `with_layout` consumes all
            // available space, which would vertically center this row in the
            // entire workspace and push the tabs to the bottom of the window.
            let header_width = ui.available_width();
            let header = ui.allocate_ui_with_layout(
                egui::vec2(header_width, PROFILE_HEADER_HEIGHT),
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| {
                    if ui.add_enabled(!busy, egui::Button::new("删除")).clicked() {
                        self.delete_candidate = Some(profile.name.clone());
                    }
                    if ui
                        .add_enabled(!busy && profile.daemon.is_none(), egui::Button::new("安全"))
                        .on_hover_text("轮转此 profile 的独立口令")
                        .clicked()
                    {
                        self.open_security_dialog(profile);
                    }
                    let edit = ui
                        .add_enabled(!busy && profile.daemon.is_none(), egui::Button::new("编辑"));
                    let edit_clicked = edit.clicked();
                    if profile.daemon.is_some() {
                        edit.on_hover_text("请先断开连接，再编辑此配置");
                    }
                    if edit_clicked {
                        self.open_editor(Some(profile.clone()));
                    }
                    if profile.daemon.is_some() {
                        if ui.add_enabled(!busy, egui::Button::new("断开")).clicked() {
                            self.stop_daemon(&ctx, profile.name.clone());
                        }
                        ui.label(RichText::new("● 已连接").color(Color32::from_rgb(76, 205, 140)));
                    } else {
                        if ui.add_enabled(!busy, egui::Button::new("连接")).clicked() {
                            self.start_daemon(&ctx, profile.name.clone());
                        }
                        ui.label(RichText::new("○ 未连接").color(Color32::GRAY));
                    }
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.vertical(|ui| {
                            ui.heading(&profile.name);
                            let mut endpoint = format!("{}:{}", profile.host, profile.port);
                            ui.label(RichText::new(endpoint.as_str()).color(Color32::GRAY));
                            endpoint.zeroize();
                        });
                    });
                },
            );
            debug_assert!(header.response.rect.height() <= PROFILE_HEADER_HEIGHT);
            ui.add_space(18.0);
            ui.separator();
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Command, "命令");
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Files, "文件");
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Bash, "Bash");
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Tunnel, "隧道");
            });
            ui.separator();
            ui.add_space(8.0);
            match self.workspace_tab {
                WorkspaceTab::Command => self.command_workspace(ui, &ctx, profile),
                WorkspaceTab::Files => self.files_workspace(ui, &ctx, profile),
                WorkspaceTab::Bash => self.bash_workspace(ui, &ctx, profile),
                WorkspaceTab::Tunnel => self.tunnel_workspace(ui, &ctx, profile),
            }
        });
        if let Some(mut profile) = profile.take() {
            zeroize_profile_row(&mut profile);
        }
    }

    fn command_workspace(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, profile: &ProfileRow) {
        let busy = self.operations.is_busy();
        ui.label(RichText::new("命令").strong());
        ui.horizontal(|ui| {
            let response = add_sized_ephemeral_text_edit(
                ui,
                [ui.available_width() - 92.0, 34.0],
                "command",
                TextEdit::singleline(&mut self.command)
                    .font(FontId::monospace(14.0))
                    .hint_text("输入远程命令"),
            );
            let run = ui.add_enabled(
                !busy,
                egui::Button::new("▶ 执行").min_size([78.0, 34.0].into()),
            );
            if !busy
                && (run.clicked()
                    || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))))
            {
                self.execute(ctx, profile.name.clone());
            }
        });
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("输出").strong());
            if let Some(code) = self.exit_code {
                let color = if code == 0 {
                    Color32::from_rgb(76, 205, 140)
                } else {
                    Color32::from_rgb(245, 104, 104)
                };
                ui.label(RichText::new(format!("退出码 {code}")).color(color));
            }
            if ui.small_button("清空").clicked() {
                self.output.zeroize();
                self.exit_code = None;
            }
        });
        add_ephemeral_text_edit(
            ui,
            "command-output",
            TextEdit::multiline(&mut self.output)
                .font(FontId::monospace(13.0))
                .code_editor()
                .desired_rows(15)
                .desired_width(f32::INFINITY),
        );
    }

    fn files_workspace(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, profile: &ProfileRow) {
        let busy = self.operations.is_busy();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("↑"))
                .on_hover_text("上级目录")
                .clicked()
            {
                let parent = remote_parent(&self.remote_path);
                self.refresh_directory(ctx, profile.name.clone(), parent);
            }
            let path_response = add_sized_ephemeral_text_edit(
                ui,
                [ui.available_width() - 84.0, 30.0],
                "remote-directory",
                TextEdit::singleline(&mut self.remote_path)
                    .font(FontId::monospace(13.0))
                    .hint_text("远程目录"),
            );
            if path_response.changed() {
                self.invalidate_directory_context();
            }
            let refresh = ui.add_enabled(!busy, egui::Button::new("刷新"));
            if !busy
                && (refresh.clicked()
                    || (path_response.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter))))
            {
                self.refresh_directory(ctx, profile.name.clone(), self.remote_path.clone());
            }
        });
        ui.horizontal(|ui| {
            ui.label("新建目录");
            add_ephemeral_text_edit(
                ui,
                "new-directory",
                TextEdit::singleline(&mut self.new_directory),
            );
            if ui
                .add_enabled(!busy, egui::Button::new("添加目录"))
                .clicked()
            {
                self.create_remote_directory(ctx, profile.name.clone());
            }
        });
        ui.add_space(6.0);

        let mut navigate = None;
        let mut select = None;
        let row_height = ui.spacing().interact_size.y;
        let column_spacing = ui.spacing().item_spacing.x;
        let type_width = 90.0;
        let size_width = 90.0;
        // Reserve the scrollbar as well as the two fixed columns. Keeping the
        // widths stable prevents long names from changing the visible range.
        let name_width =
            (ui.available_width() - type_width - size_width - column_spacing * 2.0 - 20.0)
                .max(90.0);
        ui.horizontal(|ui| {
            ui.add_sized(
                [name_width, row_height],
                egui::Label::new(RichText::new("名称").strong()).truncate(),
            );
            ui.add_sized(
                [type_width, row_height],
                egui::Label::new(RichText::new("类型").strong()).truncate(),
            );
            ui.add_sized(
                [size_width, row_height],
                egui::Label::new(RichText::new("大小").strong()).truncate(),
            );
        });
        // A remote directory may legally contain up to 10,000 entries. Do not
        // clone or lay out the entire result on every frame: only materialize
        // the rows intersecting the scroll viewport and defer mutations until
        // the immutable directory-list borrow has ended.
        egui::ScrollArea::vertical().max_height(245.0).show_rows(
            ui,
            row_height,
            self.remote_entries.len(),
            |ui, row_range| {
                for index in row_range {
                    let entry = &self.remote_entries[index];
                    ui.horizontal(|ui| {
                        let selected = self
                            .selected_remote
                            .as_ref()
                            .is_some_and(|selected| selected.path == entry.path);
                        let icon = if entry.is_dir { "▣" } else { "▤" };
                        let mut label = format!("{icon}  {}", entry.name);
                        let response = ui.add_sized(
                            [name_width, row_height],
                            egui::Button::selectable(selected, label.as_str()).truncate(),
                        );
                        label.zeroize();
                        if response.clicked() {
                            select = Some(entry.clone());
                        }
                        if !busy && response.double_clicked() && entry.is_dir {
                            navigate = Some(entry.path.clone());
                        }
                        let kind = if entry.is_dir {
                            "目录"
                        } else if entry.is_symlink {
                            "链接"
                        } else {
                            "文件"
                        };
                        ui.add_sized([type_width, row_height], egui::Label::new(kind).truncate());
                        let size = if entry.is_dir {
                            "—".into()
                        } else {
                            format_bytes(entry.size)
                        };
                        ui.add_sized([size_width, row_height], egui::Label::new(size).truncate());
                    });
                }
            },
        );
        if let Some(entry) = select {
            if !entry.is_dir && self.local_download.is_empty() {
                self.local_download = entry.name.clone();
            }
            if let Some(mut previous) = self.selected_remote.take() {
                previous.name.zeroize();
                previous.path.zeroize();
            }
            self.selected_remote = Some(entry);
        }
        if let Some(path) = navigate {
            self.refresh_directory(ctx, profile.name.clone(), path);
        }

        ui.separator();
        for (operation_id, transfer) in &self.pending_transfers {
            let Some(progress) = transfer.progress.as_ref() else {
                continue;
            };
            let fraction = if progress.stage == serctl_protocol::TransferStage::Completed {
                1.0
            } else if progress.total_bytes == 0 {
                0.0
            } else {
                (progress.confirmed_bytes as f32 / progress.total_bytes as f32).min(0.999)
            };
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(format!("传输 {}", progress.transfer_id.as_str()));
                    ui.label(format!("{:?}", progress.stage));
                    ui.label(format!("backend={:?}", progress.backend));
                    ui.label(format!(
                        "chunk={} / window={}",
                        format_bytes(u64::from(progress.chunk_bytes)),
                        format_bytes(u64::from(progress.window_bytes))
                    ));
                    if ui.small_button("取消").clicked() {
                        transfer.cancellation.cancel();
                    }
                });
                ui.add(
                    egui::ProgressBar::new(fraction)
                        .show_percentage()
                        .text(format!(
                            "{} / {}",
                            format_bytes(progress.confirmed_bytes),
                            format_bytes(progress.total_bytes)
                        )),
                );
                let eta = progress
                    .eta_ms
                    .map(|value| format!("{:.1} 秒", value as f64 / 1000.0))
                    .unwrap_or_else(|| "—".to_owned());
                ui.small(format!(
                    "窗口 {:.1} KiB/s · 平均 {:.1} KiB/s · ETA {} · operation {}",
                    progress.window_bps / 1024.0,
                    progress.average_bps / 1024.0,
                    eta,
                    operation_id,
                ));
            });
        }
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.transfer_resume, "启用断点续传");
            ui.label(
                RichText::new(if self.transfer_resume {
                    "需要远端 serctl-xfer；源文件或远端身份变化会安全拒绝"
                } else {
                    "兼容模式：失败后清理本次 partial，不保留恢复点"
                })
                .small()
                .color(Color32::GRAY),
            );
        });
        egui::Grid::new("file_transfer")
            .num_columns(4)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("上传");
                add_ephemeral_text_edit(
                    ui,
                    "local-upload",
                    TextEdit::singleline(&mut self.local_upload)
                        .hint_text("本地文件完整路径")
                        .desired_width(260.0),
                );
                add_ephemeral_text_edit(
                    ui,
                    "remote-upload",
                    TextEdit::singleline(&mut self.remote_upload)
                        .hint_text("远程文件名（可选）")
                        .desired_width(180.0),
                );
                if ui.add_enabled(!busy, egui::Button::new("上传")).clicked() {
                    self.upload(ctx, profile.name.clone());
                }
                ui.end_row();

                ui.label("下载");
                ui.label(
                    self.selected_remote
                        .as_ref()
                        .map(|entry| entry.name.as_str())
                        .unwrap_or("未选择远程文件"),
                );
                add_ephemeral_text_edit(
                    ui,
                    "local-download",
                    TextEdit::singleline(&mut self.local_download)
                        .hint_text("本地保存完整路径")
                        .desired_width(180.0),
                );
                if ui.add_enabled(!busy, egui::Button::new("下载")).clicked() {
                    self.download(ctx, profile.name.clone());
                }
                ui.end_row();
            });
        ui.label(
            RichText::new("双击目录进入；下载不会覆盖已存在的本地文件。")
                .small()
                .color(Color32::GRAY),
        );
    }

    fn bash_workspace(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, profile: &ProfileRow) {
        let busy = self.operations.is_busy();
        let active =
            self.shell.is_some() && self.shell_profile.as_deref() == Some(profile.name.as_str());
        ui.horizontal(|ui| {
            if !active {
                if ui
                    .add_enabled(!busy, egui::Button::new("打开 Bash"))
                    .clicked()
                {
                    self.start_shell(ctx, profile.name.clone());
                }
            } else {
                ui.label(RichText::new("● Bash 已连接").color(Color32::from_rgb(76, 205, 140)));
                if ui.small_button("Ctrl+C").clicked() {
                    self.send_shell_bytes(vec![3]);
                }
                if ui.small_button("Ctrl+D").clicked() {
                    self.send_shell_bytes(vec![4]);
                }
                if ui.small_button("关闭").clicked() {
                    self.close_shell();
                }
            }
            if ui.small_button("清屏").clicked() {
                self.shell_bytes.zeroize();
                self.shell_output.zeroize();
            }
        });
        add_ephemeral_text_edit(
            ui,
            "shell-output",
            TextEdit::multiline(&mut self.shell_output)
                .font(FontId::monospace(13.0))
                .code_editor()
                .interactive(false)
                .desired_rows(16)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            let response = add_sized_ephemeral_text_edit(
                ui,
                [ui.available_width() - 80.0, 32.0],
                "shell-input",
                TextEdit::singleline(&mut self.shell_input)
                    .font(FontId::monospace(13.0))
                    .hint_text("输入 Bash 命令并回车"),
            );
            let send = ui.add_enabled(active && !busy, egui::Button::new("发送"));
            if (send.clicked()
                || (response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter))))
                && active
                && !busy
            {
                let mut bytes = std::mem::take(&mut self.shell_input).into_bytes();
                bytes.push(b'\r');
                self.send_shell_bytes(bytes);
                response.request_focus();
            }
        });
    }

    fn tunnel_workspace(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, profile: &ProfileRow) {
        let busy = self.operations.is_busy();
        let starting = self
            .pending_tunnel_start
            .as_ref()
            .is_some_and(|pending| pending.context.profile == profile.name);
        let running = self
            .tunnel
            .as_ref()
            .is_some_and(|active| active.context.profile == profile.name);
        let stopping = !self.pending_tunnel_stops.is_empty();
        let editable = !busy && !starting && !running && !stopping;

        ui.horizontal(|ui| {
            ui.label(RichText::new("模式").strong());
            ui.add_enabled_ui(editable, |ui| {
                ui.selectable_value(&mut self.tunnel_mode, client::TunnelMode::Local, "本地 L");
                ui.selectable_value(&mut self.tunnel_mode, client::TunnelMode::Remote, "远程 R");
                ui.selectable_value(
                    &mut self.tunnel_mode,
                    client::TunnelMode::Dynamic,
                    "动态 D / SOCKS5",
                );
            });
        });
        ui.add_space(8.0);
        ui.add_enabled_ui(editable, |ui| {
            egui::Grid::new("tunnel-form")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("监听地址");
                    ui.label(
                        RichText::new("127.0.0.1（强制回环）")
                            .color(Color32::from_rgb(76, 205, 140)),
                    );
                    ui.end_row();
                    ui.label("监听端口");
                    add_ephemeral_text_edit(
                        ui,
                        "tunnel-bind-port",
                        TextEdit::singleline(&mut self.tunnel_bind_port)
                            .hint_text("0 表示自动选择"),
                    );
                    ui.end_row();
                    if self.tunnel_mode != client::TunnelMode::Dynamic {
                        ui.label(if self.tunnel_mode == client::TunnelMode::Local {
                            "SSH 主机目标端口"
                        } else {
                            "本机目标端口"
                        });
                        add_ephemeral_text_edit(
                            ui,
                            "tunnel-target-port",
                            TextEdit::singleline(&mut self.tunnel_target_port)
                                .desired_width(100.0)
                                .hint_text("1–65535"),
                        );
                        ui.end_row();
                    }
                    ui.label("最大连接数");
                    add_ephemeral_text_edit(
                        ui,
                        "tunnel-max-connections",
                        TextEdit::singleline(&mut self.tunnel_max_connections).hint_text("32"),
                    );
                    ui.end_row();
                });
        });
        ui.label(
            RichText::new(match self.tunnel_mode {
                client::TunnelMode::Local => {
                    "L：本机 127.0.0.1 → 已连接 SSH 主机的 127.0.0.1:目标端口"
                }
                client::TunnelMode::Remote => "R：SSH 主机 127.0.0.1 → 本机 127.0.0.1:目标端口",
                client::TunnelMode::Dynamic => {
                    "D：在本机 127.0.0.1 启动 SOCKS5；不接受外部网络连接"
                }
            })
            .small()
            .color(Color32::GRAY),
        );
        ui.add_space(10.0);

        if let Some(active) = self
            .tunnel
            .as_ref()
            .filter(|active| active.context.profile == profile.name)
        {
            let mut status = format!("● 正在监听 127.0.0.1:{}", active.bind_port);
            ui.label(RichText::new(status.as_str()).color(Color32::from_rgb(76, 205, 140)));
            status.zeroize();
            if let Some(error) = active.last_error.as_deref() {
                ui.label(RichText::new(format!("最近错误：{error}")).color(Color32::YELLOW));
            }
        } else if starting {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("正在验证此主机的独立口令并启动隧道…");
            });
        } else if stopping {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("正在停止隧道并回收连接…");
            });
        } else {
            ui.label(RichText::new("○ 隧道未运行").color(Color32::GRAY));
        }

        ui.horizontal(|ui| {
            if running || starting {
                if ui
                    .add_enabled(!stopping, egui::Button::new("停止隧道"))
                    .clicked()
                {
                    self.stop_tunnel_for_profile(ctx, &profile.name);
                }
            } else if ui
                .add_enabled(editable, egui::Button::new("启动隧道"))
                .clicked()
            {
                self.start_tunnel(ctx, profile.name.clone());
            }
        });
        ui.label(
            RichText::new(
                "启动需要此 profile 当前 generation 的 5 分钟独立授权；隧道始终仅监听回环地址。",
            )
            .small()
            .color(Color32::GRAY),
        );
    }

    fn migration_overlay(&mut self, ctx: &egui::Context) -> bool {
        let Some(vault::VaultMigrationState::LegacyV2 { .. }) = &self.migration_state else {
            return false;
        };
        self.migration.visible = true;
        #[cfg(unix)]
        {
            // Do not render editable secret fields for a platform on which
            // migration is deliberately unavailable. This makes the
            // "fails before collecting secrets" boundary true in memory as
            // well as at the submit handler.
            self.migration.clear_secrets();
            egui::Window::new("必须迁移凭证库")
                .collapsible(false)
                .resizable(false)
                .default_width(560.0)
                .show(ctx, |ui| {
                    ui.label(RichText::new("v2 共享主口令 → v4 每主机独立口令与随机身份").size(20.0).strong());
                    ui.label(
                        RichText::new(
                            "Linux 迁移当前失败关闭：必须先配置 root-owned 系统 share store 与明确的目标用户边界。此界面不会采集旧主口令或新 profile 口令。",
                        )
                        .color(Color32::YELLOW),
                    );
                });
            true
        }
        #[cfg(windows)]
        {
            let busy = self.operations.is_busy();
            let profiles = self.migration.profiles.clone();
            let ready = profiles
                .iter()
                .filter(|profile| {
                    let value = self.migration.profile_passphrases.get(*profile);
                    let confirmation = self.migration.profile_confirmations.get(*profile);
                    value.is_some_and(|value| !value.is_empty()) && value == confirmation
                })
                .count();
            let mut submit = false;
            egui::Window::new("必须迁移凭证库")
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.label(RichText::new("v2 共享主口令 → v4 每主机独立口令与随机身份").size(20.0).strong());
                ui.label(
                    RichText::new(
                        "迁移一次性、全有或全无：任何 profile 缺少新口令或认证失败时，旧 vault 保持不变。迁移期间不会连接任何远端主机。",
                    )
                    .color(Color32::GRAY),
                );
                if let Some((notice, error)) = self.notice.as_ref() {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(notice)
                            .color(if *error {
                                Color32::from_rgb(245, 104, 104)
                            } else {
                                Color32::from_rgb(76, 205, 140)
                            })
                            .strong(),
                    );
                }
                ui.add_space(10.0);
                ui.label(format!("输入完成：{ready}/{} 个 profile", profiles.len()));
                ui.add(egui::ProgressBar::new(if profiles.is_empty() {
                    1.0
                } else {
                    ready as f32 / profiles.len() as f32
                }));
                if busy {
                    ui.add_space(8.0);
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(
                                self.operations
                                    .activity()
                                    .unwrap_or("正在执行离线迁移…"),
                            );
                        });
                        ui.label(
                            RichText::new(
                                "正在执行高强度 Argon2 校验与重加密；窗口仍可响应，请勿关闭。",
                            )
                            .small()
                            .color(Color32::GRAY),
                        );
                    });
                }
                ui.add_space(8.0);
                ui.label("旧 v2 共享主口令");
                add_secret_password_edit(
                    ui,
                    !busy,
                    "migration-old-master",
                    &mut self.migration.old_master,
                    "仅用于本次离线迁移",
                );
                ui.separator();
                egui::ScrollArea::vertical().max_height(245.0).show(ui, |ui| {
                    for profile in &profiles {
                        ui.group(|ui| {
                            ui.label(RichText::new(profile).strong());
                            let value = self
                                .migration
                                .profile_passphrases
                                .get_mut(profile)
                                .expect("migration profile passphrase exists");
                            add_secret_password_edit_with_id(
                                ui,
                                !busy,
                                egui::Id::new(("migration-profile-passphrase", profile)),
                                value,
                                "新独立口令（至少 12 字节）",
                            );
                            let confirmation = self
                                .migration
                                .profile_confirmations
                                .get_mut(profile)
                                .expect("migration profile confirmation exists");
                            add_secret_password_edit_with_id(
                                ui,
                                !busy,
                                egui::Id::new(("migration-profile-confirmation", profile)),
                                confirmation,
                                "再次输入",
                            );
                        });
                    }
                });
                ui.separator();
                ui.label(RichText::new("Windows 超管密码").strong());
                add_secret_password_edit(
                    ui,
                    !busy,
                    "migration-admin-password",
                    &mut self.migration.administrator_password,
                    "设置新超管密码",
                );
                add_secret_password_edit(
                    ui,
                    !busy,
                    "migration-admin-confirmation",
                    &mut self.migration.administrator_confirmation,
                    "再次输入超管密码",
                );
                ui.label("新离线恢复介质文件");
                add_ephemeral_text_edit(
                    ui,
                    "migration-media-path",
                    TextEdit::singleline(&mut self.migration.recovery_media_path)
                        .hint_text("U 盘上的绝对路径；不会覆盖已有文件"),
                );
                ui.add_space(10.0);
                submit = ui
                    .add_enabled(
                        !busy,
                        egui::Button::new("验证全部内容并原子迁移"),
                    )
                    .clicked();
            });
            if submit {
                self.submit_v2_migration(ctx);
            }
            true
        }
    }

    fn admin_overlay(&mut self, ctx: &egui::Context) {
        if !self.admin_dialog.visible {
            return;
        }
        let busy = self.operations.is_busy();
        let status = self.admin_dialog.status.clone();
        let remaining = self.admin_authorization.remaining_at(Instant::now());
        if remaining.is_some() {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        let mut visible = true;
        let mut cancel = false;
        let mut authorize = false;
        let mut initialize = false;
        let mut change_password = false;
        let mut rotate_recovery = false;
        egui::Window::new("安全与恢复")
            .open(&mut visible)
            .collapsible(false)
            .resizable(true)
            .default_width(540.0)
            .show(ctx, |ui| {
                ui.heading("超管与离线恢复");
                ui.label(
                    RichText::new(
                        "超管只能设置、重置或轮转 profile 口令，不能查看已有口令。恢复旧凭据必须同时提供匹配的离线介质。",
                    )
                    .color(Color32::GRAY),
                );
                ui.label(
                    RichText::new(
                        "本地 profile 名称和 endpoint 属于目录元数据，在工作区锁定时仍可见；SSH 凭据不会显示。",
                    )
                    .small()
                    .color(Color32::GRAY),
                );
                if self.pending_create_after_admin {
                    ui.add_space(6.0);
                    ui.group(|ui| {
                        ui.label(
                            RichText::new("正在等待超管授权以继续保存新主机")
                                .strong()
                                .color(Color32::from_rgb(120, 190, 255)),
                        );
                        ui.label(
                            RichText::new(
                                "新主机内容仍保留在编辑器内，尚未写入 vault。完成初始化并授权后会自动继续保存；轮转恢复介质后需要重新授权。",
                            )
                            .small(),
                        );
                    });
                }
                ui.separator();
                match status.as_ref() {
                    None => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("正在读取安全策略…");
                        });
                    }
                    Some(vault::AdminStatus::Uninitialized {
                        platform_requires_password: true,
                    }) => {
                        ui.label(
                            RichText::new("○ 尚未初始化 Windows 超管与恢复策略")
                                .color(Color32::YELLOW),
                        );
                        ui.label("必须先初始化，之后才能创建首个 profile。");
                        add_secret_password_edit(
                            ui,
                            !busy,
                            "admin-init-new-password",
                            &mut self.admin_dialog.new_password,
                            "新超管密码（至少 12 字节）",
                        );
                        add_secret_password_edit(
                            ui,
                            !busy,
                            "admin-init-confirmation",
                            &mut self.admin_dialog.new_password_confirmation,
                            "再次输入",
                        );
                        add_ephemeral_text_edit(
                            ui,
                            "admin-init-media-path",
                            TextEdit::singleline(&mut self.admin_dialog.media_path)
                                .hint_text("U 盘上的新文件绝对路径；不会覆盖已有文件"),
                        );
                        ui.label(
                            RichText::new(
                                "介质文件只是 2-of-2 的一半，单独不能解密；请在确认 U 盘路径后再初始化。",
                            )
                            .small()
                            .color(Color32::GRAY),
                        );
                        initialize = ui
                            .add_enabled(
                                !busy,
                                egui::Button::new(if self.pending_create_after_admin {
                                    "初始化恢复策略（随后授权）"
                                } else {
                                    "初始化并写入恢复介质"
                                }),
                            )
                            .clicked();
                    }
                    Some(vault::AdminStatus::Uninitialized {
                        platform_requires_password: false,
                    }) => {
                        ui.label("Linux 管理授权使用有效 UID 0，不设置独立超管密码。");
                        ui.label(
                            RichText::new(
                                "离线恢复当前失败关闭：尚未配置 root-owned 系统 share store 与目标用户 vault 边界。",
                            )
                            .color(Color32::YELLOW),
                        );
                        authorize = ui
                            .add_enabled(!busy, egui::Button::new("验证 root 授权 2 分钟"))
                            .clicked();
                    }
                    Some(vault::AdminStatus::Ready {
                        platform_requires_password,
                        recovery_id,
                    }) => {
                        let id_prefix = recovery_id.chars().take(12).collect::<String>();
                        ui.label(
                            RichText::new(format!("● 恢复策略已配置 · ID {id_prefix}…"))
                                .color(Color32::from_rgb(76, 205, 140)),
                        );
                        match remaining {
                            Some(remaining) => {
                                let seconds = remaining.as_secs()
                                    + u64::from(remaining.subsec_nanos() > 0);
                                ui.label(format!(
                                    "超管授权剩余 {:02}:{:02}（固定 2 分钟，不续期）",
                                    seconds / 60,
                                    seconds % 60
                                ));
                                if ui.small_button("立即撤销超管授权").clicked() {
                                    self.admin_authorization.revoke();
                                }
                            }
                            None => {
                                if *platform_requires_password {
                                    add_secret_password_edit(
                                        ui,
                                        !busy,
                                        "admin-authorization-password",
                                        &mut self.admin_dialog.password_input,
                                        "输入超管密码",
                                    );
                                }
                                let authorize_label = if self.pending_create_after_admin {
                                    if *platform_requires_password {
                                        "授权并继续保存新主机"
                                    } else {
                                        "验证 root 授权并继续保存新主机"
                                    }
                                } else if *platform_requires_password {
                                    "授权 2 分钟"
                                } else {
                                    "验证 root 授权 2 分钟"
                                };
                                authorize = ui
                                    .add_enabled(!busy, egui::Button::new(authorize_label))
                                    .clicked();
                            }
                        }
                        if *platform_requires_password {
                            ui.separator();
                            ui.label(RichText::new("更改超管密码").strong());
                            add_secret_password_edit(
                                ui,
                                !busy && remaining.is_some(),
                                "admin-change-new-password",
                                &mut self.admin_dialog.new_password,
                                "新超管密码",
                            );
                            add_secret_password_edit(
                                ui,
                                !busy && remaining.is_some(),
                                "admin-change-confirmation",
                                &mut self.admin_dialog.new_password_confirmation,
                                "再次输入",
                            );
                            change_password = ui
                                .add_enabled(
                                    !busy && remaining.is_some(),
                                    egui::Button::new("更改超管密码"),
                                )
                                .clicked();
                            ui.separator();
                            ui.label(RichText::new("轮转离线恢复介质").strong());
                            add_ephemeral_text_edit(
                                ui,
                                "admin-old-media-path",
                                TextEdit::singleline(&mut self.admin_dialog.old_media_path)
                                    .hint_text("当前恢复介质绝对路径"),
                            );
                            add_ephemeral_text_edit(
                                ui,
                                "admin-new-media-path",
                                TextEdit::singleline(&mut self.admin_dialog.new_media_path)
                                    .hint_text("新介质文件绝对路径；不会覆盖"),
                            );
                            rotate_recovery = ui
                                .add_enabled(
                                    !busy && remaining.is_some(),
                                    egui::Button::new("验证旧介质并轮转"),
                                )
                                .clicked();
                        }
                    }
                }
                ui.separator();
                if ui.button("关闭").clicked() {
                    cancel = true;
                }
            });
        if authorize {
            self.authorize_admin(ctx);
        }
        if initialize {
            self.initialize_admin_and_recovery(ctx);
        }
        if change_password {
            self.change_admin_password(ctx);
        }
        if rotate_recovery {
            self.rotate_recovery_media(ctx);
        }
        if (cancel || !visible) && busy {
            self.admin_dialog.visible = true;
            self.set_notice("请等待当前安全操作完成后再关闭窗口".into(), true);
        } else if cancel || !visible {
            if self.pending_create_after_admin {
                self.pending_create_after_admin = false;
                self.set_notice(
                    "已取消授权后的自动保存；新主机内容仍保留在编辑器，可再次点击保存".into(),
                    false,
                );
            }
            self.admin_dialog.close();
        }
    }

    fn overlays(&mut self, ctx: &egui::Context) {
        if self.migration_overlay(ctx) {
            return;
        }
        self.admin_overlay(ctx);
        if self.admin_dialog.visible {
            return;
        }
        if self.security_dialog.visible {
            let mut visible = true;
            let mut rotate_manual = false;
            let mut rotate_random = false;
            #[cfg(windows)]
            let mut preserve = false;
            #[cfg(not(windows))]
            let preserve = false;
            #[cfg(windows)]
            let mut preserve_random = false;
            #[cfg(not(windows))]
            let preserve_random = false;
            let mut destructive_reset = false;
            let mut destructive_random = false;
            let mut open_admin = false;
            let mut commit_random = false;
            let mut discard_random = false;
            let mut cancel = false;
            egui::Window::new("Profile 安全")
                .open(&mut visible)
                .collapsible(false)
                .resizable(true)
                .default_width(520.0)
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new(format!("{} · 安全操作", self.security_dialog.profile))
                            .strong(),
                    );
                    ui.label(
                        RichText::new(
                            "任何成功的口令变更都会推进 vault generation，并立即撤销该 profile 的旧授权。",
                        )
                        .small()
                        .color(Color32::GRAY),
                    );
                    ui.horizontal(|ui| {
                        ui.selectable_value(
                            &mut self.security_section,
                            SecuritySection::ProfilePassphrase,
                            "口令轮转",
                        );
                        ui.selectable_value(
                            &mut self.security_section,
                            SecuritySection::PreserveRecovery,
                            "保留式恢复",
                        );
                        ui.selectable_value(
                            &mut self.security_section,
                            SecuritySection::DestructiveReset,
                            "破坏性重置",
                        );
                    });
                    ui.separator();
                    if let Some(random) = self.security_dialog.random_passphrase_once.as_ref() {
                        let action = self
                            .security_dialog
                            .pending_random_action
                            .unwrap_or(PendingRandomProfileAction::RotatePassphrase);
                        ui.label(
                            RichText::new(format!(
                                "待确认：{}（vault 尚未修改）",
                                action.description()
                            ))
                            .color(Color32::YELLOW)
                            .strong(),
                        );
                        ui.label(
                            RichText::new(
                                "先离线保存下列口令，再勾选确认并提交。关闭或取消会清零口令且不会修改 vault。",
                            )
                            .small()
                            .color(Color32::GRAY),
                        );
                        ui.monospace(random.as_str());
                        ui.checkbox(
                            &mut self.security_dialog.random_saved_confirmation,
                            "我已将新口令保存到安全位置",
                        );
                        ui.horizontal(|ui| {
                            commit_random = ui
                                .add_enabled(
                                    self.security_dialog.random_saved_confirmation
                                        && !self.operations.is_busy(),
                                    egui::Button::new(action.commit_label()),
                                )
                                .clicked();
                            discard_random = ui
                                .add_enabled(
                                    !self.operations.is_busy(),
                                    egui::Button::new("取消并清零（不修改 vault）"),
                                )
                                .clicked();
                        });
                    } else {
                        match self.security_section {
                        SecuritySection::ProfilePassphrase => {
                            ui.label("当前独立口令");
                            add_secret_password_edit(
                                ui,
                                !self.operations.is_busy(),
                                "profile-security-current",
                                &mut self.security_dialog.current_passphrase,
                                "当前口令",
                            );
                            ui.add_space(6.0);
                            ui.label("手动设置");
                            add_secret_password_edit(
                                ui,
                                !self.operations.is_busy(),
                                "profile-security-new",
                                &mut self.security_dialog.new_passphrase,
                                "至少 12 字节",
                            );
                            add_secret_password_edit(
                                ui,
                                !self.operations.is_busy(),
                                "profile-security-confirmation",
                                &mut self.security_dialog.new_passphrase_confirmation,
                                "再次输入",
                            );
                            ui.horizontal(|ui| {
                                rotate_manual = ui
                                    .add_enabled(
                                        !self.operations.is_busy(),
                                        egui::Button::new("设置新独立口令"),
                                    )
                                    .clicked();
                                rotate_random = ui
                                    .add_enabled(
                                        !self.operations.is_busy(),
                                        egui::Button::new("生成随机口令（先确认后轮转）"),
                                    )
                                    .clicked();
                            });
                        }
                        SecuritySection::PreserveRecovery => {
                            ui.label(
                                RichText::new(
                                    "保留原 SSH 凭据：必须同时使用超管/root 授权与匹配的离线介质。普通管理员密码单独无法解密。",
                                )
                                .color(Color32::from_rgb(76, 205, 140)),
                            );
                            #[cfg(unix)]
                            ui.label(
                                RichText::new(
                                    "Linux 离线恢复当前失败关闭，直到配置 root-owned 系统 share store。",
                                )
                                .color(Color32::YELLOW),
                            );
                            #[cfg(windows)]
                            {
                                let admin_valid =
                                    self.admin_authorization.is_valid_at(Instant::now());
                                if !admin_valid {
                                    open_admin = ui.button("先取得超管授权…").clicked();
                                }
                                ui.label("离线恢复介质");
                                add_ephemeral_text_edit(
                                    ui,
                                    "profile-recovery-media-path",
                                    TextEdit::singleline(
                                        &mut self.security_dialog.recovery_media_path,
                                    )
                                    .hint_text("U 盘介质文件绝对路径"),
                                );
                                add_secret_password_edit(
                                    ui,
                                    !self.operations.is_busy(),
                                    "profile-recovery-new-passphrase",
                                    &mut self.security_dialog.new_passphrase,
                                    "恢复后的新独立口令",
                                );
                                add_secret_password_edit(
                                    ui,
                                    !self.operations.is_busy(),
                                    "profile-recovery-confirmation",
                                    &mut self.security_dialog.new_passphrase_confirmation,
                                    "再次输入",
                                );
                                ui.horizontal(|ui| {
                                    preserve = ui
                                        .add_enabled(
                                            !self.operations.is_busy() && admin_valid,
                                            egui::Button::new("使用手动口令恢复"),
                                        )
                                        .clicked();
                                    preserve_random = ui
                                        .add_enabled(
                                            !self.operations.is_busy() && admin_valid,
                                            egui::Button::new("生成随机口令（先确认后恢复）"),
                                        )
                                        .clicked();
                                });
                            }
                        }
                        SecuritySection::DestructiveReset => {
                            ui.label(
                                RichText::new(
                                    "危险：此操作永久丢弃原 SSH 凭据、主机指纹和旧密钥包。无法撤销，也不使用恢复介质。",
                                )
                                .color(Color32::from_rgb(245, 104, 104))
                                .strong(),
                            );
                            let admin_valid = self.admin_authorization.is_valid_at(Instant::now());
                            if !admin_valid {
                                open_admin = ui.button("先取得超管/root 授权…").clicked();
                            }
                            egui::Grid::new("destructive-reset-form")
                                .num_columns(2)
                                .show(ui, |ui| {
                                    ui.label("替换地址");
                                    ui.text_edit_singleline(
                                        &mut self.security_dialog.replacement_host,
                                    );
                                    ui.end_row();
                                    ui.label("端口");
                                    ui.text_edit_singleline(
                                        &mut self.security_dialog.replacement_port,
                                    );
                                    ui.end_row();
                                    ui.label("SSH 用户");
                                    ui.text_edit_singleline(
                                        &mut self.security_dialog.replacement_user,
                                    );
                                    ui.end_row();
                                    ui.label("新 SSH 密码");
                                    add_secret_password_edit(
                                        ui,
                                        !self.operations.is_busy(),
                                        "destructive-reset-ssh-password",
                                        &mut self.security_dialog.replacement_ssh_password,
                                        "替换凭据",
                                    );
                                    ui.end_row();
                                    ui.label("新独立口令");
                                    add_secret_password_edit(
                                        ui,
                                        !self.operations.is_busy(),
                                        "destructive-reset-profile-passphrase",
                                        &mut self
                                            .security_dialog
                                            .replacement_profile_passphrase,
                                        "至少 12 字节",
                                    );
                                    ui.end_row();
                                    ui.label("确认新口令");
                                    add_secret_password_edit(
                                        ui,
                                        !self.operations.is_busy(),
                                        "destructive-reset-profile-confirmation",
                                        &mut self
                                            .security_dialog
                                            .replacement_profile_passphrase_confirmation,
                                        "再次输入",
                                    );
                                    ui.end_row();
                                });
                            ui.label(format!(
                                "输入 profile 名称“{}”确认永久替换",
                                self.security_dialog.profile
                            ));
                            ui.text_edit_singleline(
                                &mut self.security_dialog.destructive_confirm_text,
                            );
                            let confirmed = self.security_dialog.destructive_confirm_text
                                == self.security_dialog.profile;
                            ui.horizontal(|ui| {
                                destructive_reset = ui
                                    .add_enabled(
                                        !self.operations.is_busy() && admin_valid && confirmed,
                                        egui::Button::new(
                                            RichText::new("使用手动口令永久替换")
                                                .color(Color32::from_rgb(245, 104, 104)),
                                        ),
                                    )
                                    .clicked();
                                destructive_random = ui
                                    .add_enabled(
                                        !self.operations.is_busy() && admin_valid && confirmed,
                                        egui::Button::new(
                                            RichText::new("生成随机口令（确认后永久替换）")
                                                .color(Color32::from_rgb(245, 104, 104)),
                                        ),
                                    )
                                    .clicked();
                            });
                        }
                        }
                    }
                    ui.separator();
                    if ui.button("关闭").clicked() {
                        cancel = true;
                    }
                });
            if rotate_manual {
                self.change_profile_passphrase(ctx);
            }
            if rotate_random {
                self.prepare_random_profile_passphrase_rotation();
            }
            if preserve {
                self.recover_profile_preserving_credentials(ctx);
            }
            if preserve_random {
                self.prepare_random_profile_recovery();
            }
            if destructive_reset {
                self.destructively_reset_profile(ctx);
            }
            if destructive_random {
                self.prepare_random_destructive_profile_reset();
            }
            if open_admin {
                self.pending_create_after_admin = false;
                self.open_admin_dialog(ctx);
            }
            if commit_random {
                self.commit_pending_random_profile_action(ctx);
            }
            if discard_random {
                self.discard_pending_random_profile_action();
                self.set_notice("已清零未提交的随机口令；vault 未修改".into(), false);
            } else if (cancel || !visible) && self.operations.is_busy() {
                self.security_dialog.visible = true;
                self.set_notice("请等待当前 profile 安全操作完成".into(), true);
            } else if cancel || !visible {
                let discarded = self.discard_pending_random_profile_action();
                self.security_dialog.clear();
                if discarded {
                    self.set_notice("已取消并清零随机口令；vault 未修改".into(), false);
                }
            }
        }

        if self.editor.visible {
            let mut visible = true;
            egui::Window::new(if self.editor.original_name.is_some() {
                "编辑主机"
            } else {
                "新建主机"
            })
            .open(&mut visible)
            .collapsible(false)
            .resizable(false)
            .default_width(420.0)
            .show(ctx, |ui| {
                egui::Grid::new("profile_form")
                    .num_columns(2)
                    .spacing([12.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("名称");
                        add_ephemeral_text_edit(
                            ui,
                            "profile-name",
                            TextEdit::singleline(&mut self.editor.name),
                        );
                        ui.end_row();
                        ui.label("地址");
                        add_ephemeral_text_edit(
                            ui,
                            "profile-host",
                            TextEdit::singleline(&mut self.editor.host),
                        );
                        ui.end_row();
                        ui.label("端口");
                        add_ephemeral_text_edit(
                            ui,
                            "profile-port",
                            TextEdit::singleline(&mut self.editor.port),
                        );
                        ui.end_row();
                        ui.label("用户");
                        add_ephemeral_text_edit(
                            ui,
                            "profile-user",
                            TextEdit::singleline(&mut self.editor.user),
                        );
                        ui.end_row();
                        ui.label("SSH 密码");
                        add_secret_password_edit(
                            ui,
                            true,
                            "profile-password",
                            &mut self.editor.password,
                            "",
                        );
                        ui.end_row();
                        ui.label("预期主机指纹（可选）");
                        add_ephemeral_text_edit(
                            ui,
                            "profile-host-key-sha256",
                            TextEdit::singleline(&mut self.editor.host_key_sha256)
                                .hint_text("SHA256:..."),
                        );
                        ui.end_row();
                        if self.editor.original_name.is_none() {
                            ui.label("主机独立口令");
                            add_secret_password_edit(
                                ui,
                                true,
                                "profile-independent-passphrase",
                                &mut self.editor.profile_passphrase,
                                "至少 12 字节；仅用于此主机",
                            );
                            ui.end_row();
                            ui.label("确认独立口令");
                            add_secret_password_edit(
                                ui,
                                true,
                                "profile-independent-passphrase-confirmation",
                                &mut self.editor.profile_passphrase_confirmation,
                                "再次输入",
                            );
                            ui.end_row();
                        }
                    });
                ui.add_space(8.0);
                ui.label(RichText::new(if self.editor.original_name.is_some() {
                    "保存要求此 profile 当前 generation 的有效独立授权；保存成功会使旧授权立即失效。编辑配置时需重新输入 SSH 用户和密码。"
                } else {
                    "每台主机使用独立口令；它不会授权其他 profile。口令不明文保存，也不能查看或还原。"
                }).small().color(Color32::GRAY));
                ui.add_space(10.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.operations.is_busy(), egui::Button::new("保存"))
                        .clicked()
                    {
                        self.save_profile(ctx);
                    }
                    if ui.button("取消").clicked() {
                        self.pending_create_after_admin = false;
                        self.editor.clear();
                    }
                });
            });
            if !visible {
                self.pending_create_after_admin = false;
                self.editor.clear();
            }
        }

        if let Some(mut name) = self.delete_candidate.clone() {
            egui::Window::new("确认删除")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    let mut prompt = format!("确定删除主机“{name}”吗？此操作无法撤销。");
                    ui.label(prompt.as_str());
                    prompt.zeroize();
                    ui.label("删除需要该主机当前 generation 的有效独立口令授权。");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("取消").clicked() {
                            zeroize_option_string(&mut self.delete_candidate);
                        }
                        if ui
                            .add_enabled(!self.operations.is_busy(), egui::Button::new("删除"))
                            .clicked()
                        {
                            zeroize_option_string(&mut self.delete_candidate);
                            self.remove_profile(ctx, name.clone());
                        }
                    });
                });
            name.zeroize();
        }
    }

    fn status_panel(&mut self, root: &mut egui::Ui) {
        if let Some(mut activity) = self.operations.activity().map(str::to_owned) {
            egui::Panel::bottom("activity").show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(&activity);
                    if !self.pending_transfers.is_empty() && ui.small_button("取消传输").clicked()
                    {
                        for transfer in self.pending_transfers.values() {
                            transfer.cancellation.cancel();
                        }
                    }
                });
            });
            activity.zeroize();
        } else if let Some((mut message, error)) = self.notice.clone() {
            egui::Panel::bottom("notice").show(root, |ui| {
                ui.horizontal(|ui| {
                    let color = if error {
                        Color32::from_rgb(245, 104, 104)
                    } else {
                        Color32::from_rgb(76, 205, 140)
                    };
                    ui.label(RichText::new(message.as_str()).color(color));
                    if ui.small_button("×").clicked() {
                        if let Some((mut notice, _)) = self.notice.take() {
                            notice.zeroize();
                        }
                    }
                });
            });
            message.zeroize();
        }
    }
}

impl eframe::App for SerctlApp {
    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let now = Instant::now();
        if self.expire_authorizations_and_protected_sessions(now)
            || self.expire_admin_authorization(now)
        {
            ctx.request_repaint();
        }
        self.receive_messages(ctx);
        self.receive_shell_events(ctx);
        self.receive_tunnel_events(ctx);
        // Native event-loop wakeups are best effort. Poll while an operation
        // is active so progress/completion messages cannot remain queued
        // indefinitely after the worker has gone idle.
        schedule_active_operation_poll(ctx, self.operations.is_busy());
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if matches!(
            self.migration_state,
            Some(vault::VaultMigrationState::LegacyV2 { .. })
        ) {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(90.0);
                    ui.heading("凭证库必须先完成离线迁移");
                    ui.label("迁移提交前，主机工作区和所有网络操作均保持禁用。");
                });
            });
            self.status_panel(ui);
            self.overlays(&ctx);
            return;
        }
        if self.admin_dialog.visible
            || self.security_dialog.visible
            || self.editor.visible
            || self.delete_candidate.is_some()
        {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(100.0);
                    ui.label(RichText::new("安全对话框打开期间工作区暂停").color(Color32::GRAY));
                });
            });
            self.status_panel(ui);
            self.overlays(&ctx);
            return;
        }
        self.sidebar(ui);
        self.status_panel(ui);
        self.central_panel(ui);
        self.overlays(&ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Arm cooperative cleanup before moving the handles out of the app.
        // If a later allocation or runtime call unwinds, every worker has
        // already observed cancellation even though async completion cannot be
        // guaranteed on an abnormal exit.
        for transfer in self.pending_transfers.values() {
            transfer.cancellation.cancel();
        }
        if let Some(pending) = &self.pending_tunnel_start {
            pending.handle.abort();
        }
        if let Some(active) = &self.tunnel {
            active.tunnel.cancel();
        }
        let transfers = std::mem::take(&mut self.pending_transfers);
        let tunnel_start = self.pending_tunnel_start.take();
        let tunnel = self.tunnel.take();
        let tunnel_stops = std::mem::take(&mut self.pending_tunnel_stops);
        let owned = std::mem::take(&mut self.owned_daemons);
        // Shutdown is independently authorized for each profile. Never reuse
        // one profile's passphrase for another daemon and never retain a
        // separate cleanup credential past that profile's fixed UI TTL.
        let now = Instant::now();
        let shutdown_authorizations = owned
            .keys()
            .filter_map(|profile| {
                let identity = self.profile_identity(profile)?;
                self.authorizations
                    .passphrase(profile, identity, now)
                    .map(|passphrase| (profile.clone(), (identity, passphrase)))
            })
            .collect::<BTreeMap<_, _>>();
        self.zeroize_sensitive_state();
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let runtime = RuntimeShutdownGuard::new(runtime);
        runtime.runtime().block_on(async move {
            let aborted = cancel_pending_transfers_and_wait(transfers, TRANSFER_EXIT_GRACE).await;
            if aborted > 0 {
                eprintln!(
                    "[serctl] {aborted} transfer worker(s) exceeded the shutdown cleanup grace"
                );
            }
            let aborted_tunnels = cancel_tunnels_and_wait(
                tunnel_start,
                tunnel,
                tunnel_stops,
                TUNNEL_EXIT_GRACE,
            )
            .await;
            if aborted_tunnels > 0 {
                eprintln!(
                    "[serctl] {aborted_tunnels} tunnel worker(s) exceeded the shutdown cleanup grace"
                );
            }
            let mut shutdowns = JoinSet::new();
            for (mut profile, _) in owned {
                if let Some((identity, master)) = shutdown_authorizations.get(&profile) {
                    let master = Zeroizing::new(master.as_str().to_owned());
                    let identity = *identity;
                    shutdowns.spawn(async move {
                        let _ = client::down_quiet_at_generation(
                            &profile,
                            &master,
                            identity,
                        )
                        .await;
                        profile.zeroize();
                    });
                } else {
                    profile.zeroize();
                }
            }
            while shutdowns.join_next().await.is_some() {
                // Each down_quiet call has its own hard deadline; running them
                // concurrently avoids multiplying shutdown latency by profile count.
            }
        });
        runtime.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE);
    }
}

impl Drop for SerctlApp {
    fn drop(&mut self) {
        self.zeroize_sensitive_state();
        if let Some(runtime) = self.runtime.take() {
            // Panic/unwind cannot safely drive async cleanup. Avoid Runtime's
            // default unbounded wait for an uninterruptible spawn_blocking call.
            runtime.shutdown_background();
        }
    }
}

async fn cancel_pending_transfers_and_wait(
    pending: BTreeMap<u64, PendingTransfer>,
    grace: Duration,
) -> usize {
    let mut pending = pending.into_values().collect::<Vec<_>>();
    for transfer in &pending {
        transfer.cancellation.cancel();
    }

    let deadline = tokio::time::Instant::now() + grace;
    let mut aborted = 0;
    let mut needs_abort_join = vec![false; pending.len()];
    for (index, transfer) in pending.iter_mut().enumerate() {
        if tokio::time::timeout_at(deadline, &mut transfer.handle)
            .await
            .is_err()
        {
            aborted += 1;
            transfer.handle.abort();
            needs_abort_join[index] = true;
        }
    }
    // Cancellation destructors and spawn_blocking jobs are not guaranteed to
    // finish. Observe cooperative cleanup briefly, but use one shared absolute
    // upper bound so shutdown latency cannot grow with the transfer count.
    let abort_deadline = tokio::time::Instant::now() + ABORT_JOIN_GRACE;
    for (transfer, needs_join) in pending.iter_mut().zip(needs_abort_join) {
        if needs_join {
            let _ = wait_for_task_until(&mut transfer.handle, abort_deadline).await;
        }
    }
    aborted
}

async fn cancel_tunnels_and_wait(
    pending_start: Option<PendingTunnelStart>,
    active: Option<ActiveTunnel>,
    pending_stops: BTreeMap<u64, PendingTunnelStop>,
    grace: Duration,
) -> usize {
    let mut handles = Vec::with_capacity(
        usize::from(pending_start.is_some()) + usize::from(active.is_some()) + pending_stops.len(),
    );
    if let Some(mut pending) = pending_start {
        pending.handle.abort();
        zeroize_tunnel_context(&mut pending.context);
        zeroize_operation_context(&mut pending.operation);
        handles.push(pending.handle);
    }
    if let Some(mut active) = active {
        active.tunnel.cancel();
        zeroize_tunnel_context(&mut active.context);
        zeroize_tunnel_spec(&mut active.spec);
        zeroize_option_string(&mut active.last_error);
        handles.push(tokio::spawn(async move {
            let _ = active.tunnel.wait().await;
        }));
    }
    for (_, mut pending) in pending_stops {
        zeroize_tunnel_context(&mut pending.context);
        handles.push(pending.handle);
    }

    let deadline = tokio::time::Instant::now() + grace;
    let mut aborted = 0;
    let mut needs_abort_join = vec![false; handles.len()];
    for (index, handle) in handles.iter_mut().enumerate() {
        if tokio::time::timeout_at(deadline, &mut *handle)
            .await
            .is_err()
        {
            aborted += 1;
            handle.abort();
            needs_abort_join[index] = true;
        }
    }
    let abort_deadline = tokio::time::Instant::now() + ABORT_JOIN_GRACE;
    for (handle, needs_join) in handles.iter_mut().zip(needs_abort_join) {
        if needs_join {
            let _ = wait_for_task_until(handle, abort_deadline).await;
        }
    }
    aborted
}

fn record_owned_daemon(
    owned: &mut BTreeMap<String, u64>,
    mut profile: String,
    instance: u64,
) -> bool {
    if let Some(current) = owned.get_mut(&profile) {
        if *current > instance {
            profile.zeroize();
            return false;
        }
        *current = instance;
        profile.zeroize();
        return true;
    }
    owned.insert(profile, instance);
    true
}

fn remove_owned_daemon(owned: &mut BTreeMap<String, u64>, profile: &str, instance: u64) -> bool {
    if owned.get(profile).copied() != Some(instance) {
        return false;
    }
    if let Some((mut stored_profile, _)) = owned.remove_entry(profile) {
        stored_profile.zeroize();
    }
    true
}

async fn wait_for_task_until<T>(
    task: &mut tokio::task::JoinHandle<T>,
    deadline: tokio::time::Instant,
) -> bool {
    tokio::time::timeout_at(deadline, task).await.is_ok()
}

#[cfg(test)]
async fn abort_and_wait<T>(task: &mut tokio::task::JoinHandle<T>) -> bool {
    task.abort();
    wait_for_task_until(task, tokio::time::Instant::now() + ABORT_JOIN_GRACE).await
}

fn configure_appearance(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = Color32::from_rgb(20, 23, 29);
    visuals.window_fill = Color32::from_rgb(27, 31, 39);
    visuals.selection.bg_fill = Color32::from_rgb(47, 105, 180);
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    ctx.set_style_of(egui::Theme::Dark, style);

    let candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simhei.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/System/Library/Fonts/PingFang.ttc",
    ];
    if let Some(data) = candidates.iter().find_map(|path| std::fs::read(path).ok()) {
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "serctl-cjk".into(),
            Arc::new(egui::FontData::from_owned(data)),
        );
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .insert(0, "serctl-cjk".into());
        }
        ctx.set_fonts(fonts);
    }
}

fn join_remote_path(base: &str, name: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.is_empty() {
        format!("/{name}")
    } else {
        format!("{base}/{name}")
    }
}

fn remote_parent(path: &str) -> String {
    let path = path.trim_end_matches('/');
    if path.is_empty() || path == "/" {
        return "/".into();
    }
    match path.rfind('/') {
        Some(0) => "/".into(),
        Some(index) => path[..index].to_owned(),
        None => ".".into(),
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn append_lossy_text(output: &mut String, input: &[u8]) {
    let text = Zeroizing::new(String::from_utf8_lossy(input).into_owned());
    output.push_str(text.as_str());
}

fn command_output_text(stdout: &[u8], stderr: &[u8]) -> Zeroizing<String> {
    let mut output = Zeroizing::new(String::new());
    append_lossy_text(&mut output, stdout);
    if !stderr.is_empty() {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str("[stderr]\n");
        append_lossy_text(&mut output, stderr);
    }
    output
}

fn terminal_text(input: &[u8]) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Text,
        Escape,
        Csi,
        Osc,
        OscEscape,
    }

    let mut state = State::Text;
    let mut output = Zeroizing::new(Vec::with_capacity(input.len()));
    for &byte in input {
        state = match state {
            State::Text => match byte {
                0x1b => State::Escape,
                0x08 => {
                    output.pop();
                    State::Text
                }
                b'\r' => State::Text,
                b'\n' | b'\t' | 0x20..=0xff => {
                    output.push(byte);
                    State::Text
                }
                _ => State::Text,
            },
            State::Escape => match byte {
                b'[' => State::Csi,
                b']' => State::Osc,
                _ => State::Text,
            },
            State::Csi => {
                if (0x40..=0x7e).contains(&byte) {
                    State::Text
                } else {
                    State::Csi
                }
            }
            State::Osc => match byte {
                0x07 => State::Text,
                0x1b => State::OscEscape,
                _ => State::Osc,
            },
            State::OscEscape => {
                if byte == b'\\' {
                    State::Text
                } else {
                    State::Osc
                }
            }
        };
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn test_app() -> (SerctlApp, UiMessageSender) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let (tx, rx) = ui_message_channel();
        (SerctlApp::with_channels(runtime, tx.clone(), rx), tx)
    }

    #[test]
    fn transfer_resume_is_explicitly_opt_in() {
        let (app, _) = test_app();
        assert!(!app.transfer_resume);
    }

    fn test_identity(generation: u64) -> vault::ProfileIdentity {
        vault::ProfileIdentity {
            profile_id: [generation as u8; 16],
            generation,
        }
    }

    fn add_test_profile(app: &mut SerctlApp, name: &str, generation: u64) {
        app.profiles.push(ProfileRow {
            name: name.into(),
            host: "example.test".into(),
            port: 22,
            generation,
            profile_id: test_identity(generation).profile_id,
            daemon: None,
        });
    }

    fn grant_test_profile(
        app: &mut SerctlApp,
        name: &str,
        generation: u64,
        passphrase: &str,
        verified_at: Instant,
    ) {
        app.authorizations.grant(
            name.into(),
            test_identity(generation),
            Zeroizing::new(passphrase.into()),
            verified_at,
        );
    }

    fn queue_shell_open_result(
        tx: &UiMessageSender,
        operation: OperationContext,
        profile: &str,
    ) -> CancellationToken {
        let (input, _input_rx) = tokio::sync::mpsc::channel(1);
        let (_event_tx, events) = tokio::sync::mpsc::channel(1);
        let cancellation = CancellationToken::new();
        let observed = cancellation.clone();
        tx.send(UiMessage::ShellOpened {
            operation,
            result: Ok((
                profile.to_owned(),
                client::GuiShell {
                    input,
                    events,
                    cancellation,
                },
            )),
        })
        .expect("queue shell-open result");
        observed
    }

    #[test]
    fn connected_profile_header_does_not_consume_the_workspace_height() {
        let (mut app, _) = test_app();
        add_test_profile(&mut app, "alpha", 1);
        app.profiles[0].daemon = Some(client::DaemonStatus {
            profile: "alpha".into(),
            host: "example.test".into(),
            user: "tester".into(),
            started_unix: 0,
            endpoint: "test-endpoint".into(),
        });
        app.selected = Some("alpha".into());
        grant_test_profile(&mut app, "alpha", 1, "test-passphrase", Instant::now());

        let ctx = egui::Context::default();
        let workspace_rect =
            egui::Rect::from_min_size(egui::pos2(270.0, 0.0), egui::vec2(850.0, 720.0));
        let mut command_rect = None;
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1120.0, 720.0),
            )),
            ..Default::default()
        };
        let _ = ctx.run_ui(input, |_ui| {
            let mut root = egui::Ui::new(
                ctx.clone(),
                egui::Id::new("profile-header-layout-test"),
                egui::UiBuilder::new().max_rect(workspace_rect),
            );
            app.central_panel(&mut root);
            command_rect = ctx
                .read_response(sensitive_text_edit_id("command"))
                .map(|response| response.rect);
        });

        let command_rect = command_rect.expect("command workspace was not laid out");
        assert!(
            command_rect.bottom() < workspace_rect.bottom(),
            "profile header pushed the command workspace below the viewport: {command_rect:?}"
        );
        assert!(
            command_rect.top() < 400.0,
            "profile header consumed the remaining workspace height: {command_rect:?}"
        );
    }

    #[test]
    fn large_directory_workspace_only_materializes_visible_rows() {
        let (mut app, _) = test_app();
        add_test_profile(&mut app, "alpha", 1);
        app.selected = Some("alpha".into());
        for index in 0..10_000 {
            app.remote_entries.push(RemoteEntry {
                name: format!("entry-{index}"),
                path: format!("/tmp/entry-{index}"),
                is_dir: false,
                is_symlink: false,
                size: index,
                modified_unix: None,
            });
        }
        let profile = app.profiles[0].clone();
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1120.0, 720.0),
            )),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |_ui| {
            let mut root = egui::Ui::new(
                ctx.clone(),
                egui::Id::new("large-directory-layout-test"),
                egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(850.0, 640.0),
                )),
            );
            app.files_workspace(&mut root, &ctx, &profile);
        });

        assert_eq!(app.remote_entries.len(), 10_000);
        assert!(
            output.shapes.len() < 1_000,
            "large directory rendered every row instead of the visible viewport: {} shapes",
            output.shapes.len()
        );
    }

    #[test]
    fn recovery_media_io_is_bounded_verified_regular_and_never_overwritten() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("ui-recovery-media-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let media_path = directory.join("vault.srrec");
        let payload = b"test 2-of-2 recovery share";

        persist_recovery_media_new(&media_path, payload).unwrap();
        assert_eq!(
            read_recovery_media(&media_path).unwrap().as_slice(),
            payload
        );

        let collision = persist_recovery_media_new(&media_path, b"replacement").unwrap_err();
        assert!(format!("{collision:#}").contains("创建新的恢复介质"));
        assert_eq!(std::fs::read(&media_path).unwrap(), payload);

        // Guard the UI/CLI contract: valid media above the former 4 KiB UI
        // ceiling remains accepted under the shared 4 MiB safety bound.
        let above_old_ui_limit_path = directory.join("above-old-ui-limit.srrec");
        let above_old_ui_limit = vec![0x5a_u8; 8 * 1024];
        persist_recovery_media_new(&above_old_ui_limit_path, &above_old_ui_limit).unwrap();
        assert_eq!(
            read_recovery_media(&above_old_ui_limit_path)
                .unwrap()
                .as_slice(),
            above_old_ui_limit
        );

        let oversized_path = directory.join("oversized.srrec");
        let oversized = vec![0_u8; MAX_RECOVERY_MEDIA_FILE_BYTES as usize + 1];
        assert!(persist_recovery_media_new(&oversized_path, &oversized).is_err());
        assert!(!oversized_path.exists());
        std::fs::write(&oversized_path, &oversized).unwrap();
        assert!(read_recovery_media(&oversized_path).is_err());

        let empty_path = directory.join("empty.srrec");
        std::fs::write(&empty_path, []).unwrap();
        assert!(read_recovery_media(&empty_path).is_err());
        assert!(read_recovery_media(&directory).is_err());

        std::fs::remove_file(media_path).unwrap();
        std::fs::remove_file(above_old_ui_limit_path).unwrap();
        std::fs::remove_file(oversized_path).unwrap();
        std::fs::remove_file(empty_path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn recovery_media_paths_inside_the_vault_directory_are_rejected() {
        let vault_directory = vault::home_dir().unwrap().join(".serctl");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let forbidden_output = vault_directory.join(format!(
            "ui-recovery-must-not-create-{}-{unique}.srrec",
            std::process::id()
        ));

        let output_error =
            persist_recovery_media_new(&forbidden_output, b"offline recovery share").unwrap_err();
        assert!(!forbidden_output.exists());
        let input_error = read_recovery_media(&vault_directory).unwrap_err();

        // If the configured directory already exists, both paths reach the
        // shared CLI/UI containment check. If it does not, canonicalizing its
        // parent/input still fails closed before any file can be created or read.
        if vault_directory.exists() {
            assert!(format!("{output_error:#}")
                .contains("must not be stored inside the serctl vault directory"));
            assert!(format!("{input_error:#}")
                .contains("must not be stored inside the serctl vault directory"));
        }
    }

    #[test]
    fn editor_clear_restores_default_port() {
        let mut editor = ProfileEditor {
            visible: true,
            port: "2200".into(),
            password: "secret".into(),
            host_key_sha256: "SHA256:expected-host-key".into(),
            ..ProfileEditor::default()
        };
        editor.clear();
        assert!(!editor.visible);
        assert_eq!(editor.port, "22");
        assert!(editor.password.is_empty());
        assert!(editor.host_key_sha256.is_empty());
        assert!(editor.profile_passphrase.is_empty());
        assert!(editor.profile_passphrase_confirmation.is_empty());
    }

    #[test]
    fn local_catalog_refresh_can_be_scheduled_without_any_profile_authorization() {
        let (mut app, _) = test_app();
        assert!(app.authorizations.grants.is_empty());
        assert!(app.profiles.is_empty());
        assert!(app.selected.is_none());
        assert_eq!(app.operations.refresh_epoch, 0);
        assert!(app.operations.active.is_empty());

        app.refresh(&egui::Context::default());
        assert_eq!(app.operations.refresh_epoch, 1);
        assert!(app.operations.is_busy());
    }

    #[test]
    fn authorization_has_a_fixed_non_sliding_five_minute_ttl() {
        let mut authorization = UiAuthorization::default();
        let verified_at = Instant::now();
        authorization.grant(Zeroizing::new("authorized-master".into()), verified_at);
        let expires_at = authorization.expires_at.expect("expiry");

        let first = authorization
            .passphrase()
            .expect("authorization should still be valid");
        assert_eq!(
            authorization.remaining_at(verified_at + Duration::from_secs(60)),
            Some(Duration::from_secs(4 * 60))
        );
        let second = authorization
            .passphrase()
            .expect("authorization should still be valid");
        assert_eq!(
            authorization.remaining_at(verified_at + Duration::from_secs(4 * 60)),
            Some(Duration::from_secs(60))
        );
        assert_eq!(first.as_str(), "authorized-master");
        assert_eq!(second.as_str(), "authorized-master");
        assert_eq!(authorization.expires_at, Some(expires_at));
        assert!(authorization.is_expired_at(verified_at + UI_AUTHORIZATION_TTL));
        assert_eq!(
            authorization.remaining_at(verified_at + UI_AUTHORIZATION_TTL),
            None
        );
    }

    #[test]
    fn administrator_authorization_has_a_fixed_two_minute_ttl() {
        let verified_at = Instant::now();
        let mut authorization = AdminAuthorization::default();
        authorization.grant(
            Some(Zeroizing::new("administrator-passphrase".into())),
            verified_at,
        );

        assert_eq!(
            authorization.remaining_at(verified_at + Duration::from_secs(30)),
            Some(Duration::from_secs(90))
        );
        assert!(authorization
            .passphrase_at(verified_at + Duration::from_secs(119))
            .is_some());
        assert!(authorization
            .passphrase_at(verified_at + UI_ADMIN_AUTHORIZATION_TTL)
            .is_none());
        authorization.revoke();
        assert!(authorization.passphrase.is_none());
    }

    #[cfg(windows)]
    fn fill_new_profile_editor(app: &mut SerctlApp) {
        app.editor.visible = true;
        app.editor.name = "new-device".into();
        app.editor.host = "new-device.example".into();
        app.editor.port = "22".into();
        app.editor.user = "alice".into();
        app.editor.password = "ssh-password".into();
        app.editor.profile_passphrase = "independent-profile-passphrase".into();
        app.editor.profile_passphrase_confirmation = "independent-profile-passphrase".into();
    }

    #[cfg(windows)]
    #[test]
    fn new_profile_save_waits_for_admin_without_losing_editor_secrets() {
        let (mut app, _) = test_app();
        fill_new_profile_editor(&mut app);

        app.save_profile(&egui::Context::default());

        assert!(app.pending_create_after_admin);
        assert!(app.admin_dialog.visible);
        assert_eq!(app.editor.password, "ssh-password");
        assert_eq!(
            app.editor.profile_passphrase,
            "independent-profile-passphrase"
        );
    }

    #[cfg(windows)]
    #[test]
    fn admin_authorization_resumes_pending_new_profile_save() {
        let (mut app, tx) = test_app();
        fill_new_profile_editor(&mut app);
        app.pending_create_after_admin = true;
        app.admin_dialog.visible = true;
        let verified_at = Instant::now();
        let operation = app.operations.begin(None, "authorize administrator".into());
        tx.send(UiMessage::AdminAuthorization {
            operation,
            result: Ok(AdminAuthorizationGrant {
                passphrase: Some(Zeroizing::new("administrator-passphrase".into())),
                verified_at,
            }),
        })
        .expect("queue administrator authorization success");

        app.receive_messages(&egui::Context::default());

        assert!(!app.pending_create_after_admin);
        assert!(!app.admin_dialog.visible);
        assert!(app.admin_authorization.is_valid_at(verified_at));
        assert!(
            app.operations.is_busy(),
            "save operation should be scheduled"
        );
        assert!(app.editor.password.is_empty());
        assert!(app.editor.profile_passphrase.is_empty());
        assert!(app
            .operations
            .activity()
            .is_some_and(|activity| activity.contains("正在保存 new-device")));
    }

    #[test]
    fn authorized_profile_passphrase_is_copied_without_consuming_the_grant() {
        let (mut app, _) = test_app();
        add_test_profile(&mut app, "alpha", 7);
        grant_test_profile(&mut app, "alpha", 7, "cached-alpha", Instant::now());
        let first = app
            .required_authorized_profile_passphrase("alpha")
            .expect("first copy");
        let second = app
            .required_authorized_profile_passphrase("alpha")
            .expect("second copy");
        assert_eq!(first.as_str(), "cached-alpha");
        assert_eq!(second.as_str(), "cached-alpha");
        assert_eq!(app.authorizations.grants.len(), 1);
    }

    #[test]
    fn remote_operation_grant_captures_persistent_catalog_generation_not_ui_epoch() {
        let (mut app, _) = test_app();
        add_test_profile(&mut app, "alpha", 7);
        grant_test_profile(&mut app, "alpha", 7, "cached-alpha", Instant::now());
        app.operations.profile_generation = 91;

        let (identity, passphrase) = app
            .required_authorized_profile_grant("alpha")
            .expect("generation-bound remote-operation grant");

        assert_eq!(identity, test_identity(7));
        assert_ne!(identity.generation, app.operations.profile_generation);
        assert_eq!(passphrase.as_str(), "cached-alpha");

        // A same-name catalog replacement immediately makes the old grant
        // unusable even before the asynchronous refresh reducer removes it.
        app.profiles[0].generation = 8;
        assert!(app.required_authorized_profile_grant("alpha").is_none());
    }

    #[test]
    fn profile_authorization_is_bound_to_name_generation_and_random_identity() {
        let mut authorizations = UiAuthorizations::default();
        let verified_at = Instant::now();
        authorizations.grant(
            "alpha".into(),
            test_identity(7),
            Zeroizing::new("alpha-passphrase".into()),
            verified_at,
        );

        assert!(authorizations
            .passphrase("alpha", test_identity(7), verified_at)
            .is_some());
        assert!(authorizations
            .passphrase("alpha", test_identity(8), verified_at)
            .is_none());
        assert!(authorizations
            .passphrase("beta", test_identity(7), verified_at)
            .is_none());
        let recreated = vault::ProfileIdentity {
            profile_id: [0xa5; 16],
            generation: 7,
        };
        assert!(
            authorizations
                .passphrase("alpha", recreated, verified_at)
                .is_none(),
            "same-name/same-generation recreation must not revive an old grant"
        );
    }

    #[test]
    fn catalog_refresh_removes_grants_for_deleted_or_changed_generations() {
        let mut authorizations = UiAuthorizations::default();
        let now = Instant::now();
        authorizations.grant(
            "alpha".into(),
            test_identity(1),
            Zeroizing::new("alpha-passphrase".into()),
            now,
        );
        authorizations.grant(
            "beta".into(),
            test_identity(3),
            Zeroizing::new("beta-passphrase".into()),
            now,
        );
        let rows = vec![ProfileRow {
            name: "alpha".into(),
            host: "new.example".into(),
            port: 22,
            generation: 2,
            profile_id: test_identity(2).profile_id,
            daemon: None,
        }];

        assert!(authorizations.retain_current_profiles(&rows));
        assert!(authorizations.grants.is_empty());
    }

    #[test]
    fn revoking_one_profile_does_not_revoke_another_profile() {
        let mut authorizations = UiAuthorizations::default();
        let now = Instant::now();
        authorizations.grant(
            "alpha".into(),
            test_identity(1),
            Zeroizing::new("alpha-passphrase".into()),
            now,
        );
        authorizations.grant(
            "beta".into(),
            test_identity(4),
            Zeroizing::new("beta-passphrase".into()),
            now,
        );

        assert!(authorizations.revoke_profile("alpha"));
        assert!(authorizations
            .passphrase("alpha", test_identity(1), now)
            .is_none());
        assert!(authorizations
            .passphrase("beta", test_identity(4), now)
            .is_some());
    }

    #[test]
    fn randomized_profile_passphrase_is_staged_then_cancelled_without_commit() {
        let (mut app, _) = test_app();
        add_test_profile(&mut app, "alpha", 1);
        app.selected = Some("alpha".into());
        app.open_security_dialog(&app.profiles[0].clone());
        grant_test_profile(&mut app, "alpha", 1, "old-alpha-passphrase", Instant::now());

        app.security_dialog.current_passphrase = "old-alpha-passphrase".into();
        app.prepare_random_profile_passphrase_rotation();

        assert_eq!(
            app.security_dialog.pending_random_action,
            Some(PendingRandomProfileAction::RotatePassphrase)
        );
        assert!(app.security_dialog.random_passphrase_once.is_some());
        assert!(!app.security_dialog.random_saved_confirmation);
        assert!(
            !app.operations.is_busy(),
            "generation must not commit at staging"
        );
        assert!(app
            .authorizations
            .passphrase("alpha", test_identity(1), Instant::now())
            .is_some());
        assert!(app
            .notice
            .as_ref()
            .is_some_and(|(notice, _)| !notice.contains(
                app.security_dialog
                    .random_passphrase_once
                    .as_deref()
                    .expect("staged passphrase")
                    .as_str()
            )));

        assert!(app.discard_pending_random_profile_action());
        assert!(app.security_dialog.random_passphrase_once.is_none());
        assert!(app.security_dialog.pending_random_action.is_none());
        assert!(
            !app.operations.is_busy(),
            "cancel must not schedule a commit"
        );
        assert!(app
            .authorizations
            .passphrase("alpha", test_identity(1), Instant::now())
            .is_some());
    }

    #[cfg(unix)]
    #[test]
    fn linux_v2_migration_rejects_before_consuming_any_secret() {
        let (mut app, _) = test_app();
        app.migration.reset_profiles(vec!["alpha".into()]);
        app.migration.old_master = "legacy-master-passphrase".into();
        app.migration
            .profile_passphrases
            .insert("alpha".into(), "new-alpha-passphrase".into());
        app.migration
            .profile_confirmations
            .insert("alpha".into(), "new-alpha-passphrase".into());
        app.migration.recovery_media_path = "/tmp/new-recovery-media.srrec".into();

        let ctx = egui::Context::default();
        app.submit_v2_migration(&ctx);

        assert!(!app.operations.is_busy());
        assert!(ctx.has_requested_repaint());
        assert_eq!(app.migration.old_master, "legacy-master-passphrase");
        assert_eq!(
            app.migration
                .profile_passphrases
                .get("alpha")
                .map(String::as_str),
            Some("new-alpha-passphrase")
        );
        assert!(app.notice.as_ref().is_some_and(|(notice, error)| {
            *error && notice.contains("不会采集或提交迁移秘密")
        }));
    }

    #[cfg(windows)]
    #[test]
    fn incomplete_v2_migration_never_schedules_a_partial_commit() {
        let (mut app, _) = test_app();
        app.migration
            .reset_profiles(vec!["alpha".into(), "beta".into()]);
        app.migration.old_master = "legacy-master-passphrase".into();
        app.migration.recovery_media_path = std::env::temp_dir()
            .join(format!(
                "serctl-recovery-incomplete-{}-{}.json",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .display()
            .to_string();
        app.migration
            .profile_passphrases
            .insert("alpha".into(), "new-alpha-passphrase".into());
        app.migration
            .profile_confirmations
            .insert("alpha".into(), "new-alpha-passphrase".into());
        #[cfg(windows)]
        {
            app.migration.administrator_password = "new-administrator-passphrase".into();
            app.migration.administrator_confirmation = "new-administrator-passphrase".into();
        }

        let ctx = egui::Context::default();
        app.submit_v2_migration(&ctx);

        assert!(!app.operations.is_busy());
        assert!(ctx.has_requested_repaint());
        assert_eq!(app.migration.old_master, "legacy-master-passphrase");
        assert!(app
            .notice
            .as_ref()
            .is_some_and(|(notice, error)| *error && notice.contains("每个 profile")));
    }

    #[cfg(windows)]
    #[test]
    fn migration_rejects_an_existing_media_path_before_consuming_secrets() {
        let (mut app, _) = test_app();
        app.migration.reset_profiles(vec!["alpha".into()]);
        app.migration.old_master = "legacy-master-passphrase".into();
        app.migration
            .profile_passphrases
            .insert("alpha".into(), "new-alpha-passphrase".into());
        app.migration
            .profile_confirmations
            .insert("alpha".into(), "new-alpha-passphrase".into());
        app.migration.administrator_password = "new-administrator-passphrase".into();
        app.migration.administrator_confirmation = "new-administrator-passphrase".into();
        let media_path = std::env::temp_dir().join(format!(
            "serctl-existing-migration-media-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&media_path, b"existing").unwrap();
        app.migration.recovery_media_path = media_path.display().to_string();

        app.submit_v2_migration(&egui::Context::default());

        assert!(!app.operations.is_busy());
        assert_eq!(app.migration.old_master, "legacy-master-passphrase");
        assert_eq!(
            app.migration
                .profile_passphrases
                .get("alpha")
                .map(String::as_str),
            Some("new-alpha-passphrase")
        );
        assert!(app
            .notice
            .as_ref()
            .is_some_and(|(notice, error)| { *error && notice.contains("不会覆盖") }));
        std::fs::remove_file(media_path).unwrap();
    }

    #[test]
    fn migration_progress_updates_the_visible_activity_without_finishing_it() {
        let (mut app, tx) = test_app();
        let operation = app
            .operations
            .begin(None, "正在原子迁移 3 个 profile…".into());
        let ctx = egui::Context::default();
        send_migration_progress(
            &tx,
            &ctx,
            operation.id,
            vault::MigrationProgress::MigratingProfile {
                completed: 1,
                total: 3,
                profile: "NewAPI-Serv".into(),
            },
        );
        assert!(ctx.has_requested_repaint());

        app.receive_messages(&ctx);

        assert!(app.operations.is_busy());
        assert_eq!(
            app.operations.activity(),
            Some("正在迁移 profile 2/3：NewAPI-Serv")
        );
        assert!(app.operations.finish(&operation));
    }

    #[test]
    fn expired_profile_authorization_is_cleared_and_operations_are_rejected() {
        let (mut app, _) = test_app();
        add_test_profile(&mut app, "alpha", 1);
        grant_test_profile(
            &mut app,
            "alpha",
            1,
            "expired-alpha",
            Instant::now() - UI_AUTHORIZATION_TTL,
        );
        assert!(app
            .required_authorized_profile_passphrase("alpha")
            .is_none());
        assert!(app.authorizations.grants.is_empty());
        assert!(app
            .notice
            .as_ref()
            .is_some_and(|(message, error)| *error && message.contains("过期")));
    }

    #[test]
    fn late_shell_open_after_authorization_expiry_is_cancelled_and_not_adopted() {
        let (mut app, tx) = test_app();
        add_test_profile(&mut app, "alpha", 1);
        app.selected = Some("alpha".into());
        grant_test_profile(
            &mut app,
            "alpha",
            1,
            "expired-alpha",
            Instant::now() - UI_AUTHORIZATION_TTL,
        );
        let operation = app
            .operations
            .begin(Some("alpha".into()), "opening shell".into())
            .with_profile_identity(test_identity(1));
        let command_operation = app
            .operations
            .begin(Some("alpha".into()), "running command".into())
            .with_profile_identity(test_identity(1));

        assert!(app.expire_authorizations_and_protected_sessions(Instant::now()));
        let cancellation = queue_shell_open_result(&tx, operation, "alpha");
        tx.send(UiMessage::Command {
            operation: command_operation,
            result: Ok(client::CommandOutput {
                stdout: b"late remote secret".to_vec(),
                stderr: Vec::new(),
                code: Some(0),
                operation_context_id: None,
                revision: 0,
            }),
        })
        .expect("queue late command result");
        app.receive_messages(&egui::Context::default());

        assert!(app.shell.is_none());
        assert!(app.shell_profile.is_none());
        assert!(cancellation.is_cancelled());
        assert!(!app.output.contains("late remote secret"));
        assert_eq!(app.exit_code, None);
        assert!(!app.operations.is_busy());
    }

    #[test]
    fn late_shell_open_after_explicit_revoke_is_cancelled_and_not_adopted() {
        let (mut app, tx) = test_app();
        add_test_profile(&mut app, "alpha", 1);
        app.selected = Some("alpha".into());
        grant_test_profile(&mut app, "alpha", 1, "authorized-alpha", Instant::now());
        let operation = app
            .operations
            .begin(Some("alpha".into()), "opening shell".into())
            .with_profile_identity(test_identity(1));

        app.revoke_profile_authorization("alpha");
        let cancellation = queue_shell_open_result(&tx, operation, "alpha");
        app.receive_messages(&egui::Context::default());

        assert!(app.shell.is_none());
        assert!(app.shell_profile.is_none());
        assert!(cancellation.is_cancelled());
        assert!(!app.operations.is_busy());
    }

    #[test]
    fn expired_authorization_cannot_schedule_a_daemon_stop() {
        let (mut app, _) = test_app();
        add_test_profile(&mut app, "alpha", 1);
        grant_test_profile(
            &mut app,
            "alpha",
            1,
            "expired-alpha",
            Instant::now() - UI_AUTHORIZATION_TTL,
        );

        app.stop_daemon(&egui::Context::default(), "alpha".into());

        assert!(!app.operations.is_busy());
        assert!(app.authorizations.grants.is_empty());
        assert!(app
            .notice
            .as_ref()
            .is_some_and(|(message, error)| *error && message.contains("过期")));
    }

    #[test]
    fn expiry_clears_workspace_and_stops_shell_transfer_and_pending_tunnel() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let (mut app, _) = test_app();
        grant_test_profile(
            &mut app,
            "alpha",
            1,
            "expired-alpha",
            Instant::now() - UI_AUTHORIZATION_TTL,
        );
        app.profiles.push(ProfileRow {
            name: "alpha".into(),
            host: "secret.example".into(),
            port: 22,
            generation: 1,
            profile_id: test_identity(1).profile_id,
            daemon: None,
        });
        app.selected = Some("alpha".into());
        app.output = "remote secret".into();
        app.remote_entries.push(RemoteEntry {
            name: "secret.txt".into(),
            path: "/secret.txt".into(),
            is_dir: false,
            is_symlink: false,
            size: 1,
            modified_unix: None,
        });

        let (shell_input, _shell_input_rx) = tokio::sync::mpsc::channel(1);
        let (_shell_event_tx, shell_events) = tokio::sync::mpsc::channel(1);
        let shell_cancellation = CancellationToken::new();
        let observed_shell_cancellation = shell_cancellation.clone();
        app.shell = Some(client::GuiShell {
            input: shell_input,
            events: shell_events,
            cancellation: shell_cancellation,
        });
        app.shell_profile = Some("alpha".into());

        let transfer_cancellation = CancellationToken::new();
        let observed_transfer_cancellation = transfer_cancellation.clone();
        let transfer_handle = app.runtime().spawn(std::future::pending::<()>());
        app.pending_transfers.insert(
            77,
            PendingTransfer {
                cancellation: transfer_cancellation,
                handle: transfer_handle,
                progress: None,
            },
        );

        let tunnel_task_dropped = Arc::new(AtomicBool::new(false));
        let task_drop = tunnel_task_dropped.clone();
        let tunnel_handle = app.runtime().spawn(async move {
            let _drop = DropFlag(task_drop);
            std::future::pending::<()>().await;
        });
        app.runtime().block_on(tokio::task::yield_now());
        let tunnel_operation = app
            .operations
            .begin(Some("alpha".into()), "starting tunnel".into());
        app.pending_tunnel_start = Some(PendingTunnelStart {
            context: TunnelContext {
                profile: "alpha".into(),
                profile_generation: app.operations.profile_generation,
                profile_identity: test_identity(1),
                instance: 9,
            },
            operation: tunnel_operation,
            handle: tunnel_handle,
        });

        assert!(app.expire_authorizations_and_protected_sessions(Instant::now()));
        app.runtime().block_on(tokio::task::yield_now());

        assert!(app.authorizations.grants.is_empty());
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.selected.as_deref(), Some("alpha"));
        assert!(app.remote_entries.is_empty());
        assert!(!app.output.contains("remote secret"));
        assert!(app.shell.is_none());
        assert!(observed_shell_cancellation.is_cancelled());
        assert!(observed_transfer_cancellation.is_cancelled());
        assert!(app.pending_tunnel_start.is_none());
        assert!(!app.pending_tunnel_stops.is_empty());
        assert!(tunnel_task_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn wrong_profile_passphrase_result_does_not_create_an_authorization() {
        let (mut app, tx) = test_app();
        let operation = app.operations.begin(None, "verify".into());
        tx.send(UiMessage::Authorization {
            operation,
            result: Err("独立口令错误".into()),
        })
        .expect("queue authorization failure");
        app.receive_messages(&egui::Context::default());
        assert!(app.authorizations.grants.is_empty());
        assert!(app
            .notice
            .as_ref()
            .is_some_and(|(message, error)| *error && message.contains("验证失败")));
    }

    #[test]
    fn successful_verification_grants_and_explicit_revoke_clears_authorization() {
        let (mut app, tx) = test_app();
        add_test_profile(&mut app, "alpha", 3);
        app.selected = Some("alpha".into());
        let verified_at = Instant::now();
        let operation = app.operations.begin(Some("alpha".into()), "verify".into());
        tx.send(UiMessage::Authorization {
            operation,
            result: Ok(AuthorizationGrant {
                profile: "alpha".into(),
                identity: test_identity(3),
                passphrase: Zeroizing::new("verified-alpha".into()),
                verified_at,
            }),
        })
        .expect("queue authorization success");
        app.receive_messages(&egui::Context::default());
        let grant = app
            .authorizations
            .get("alpha", test_identity(3), verified_at)
            .expect("profile grant");
        assert_eq!(
            grant.passphrase.as_deref().map(String::as_str),
            Some("verified-alpha")
        );
        assert_eq!(grant.expires_at, Some(verified_at + UI_AUTHORIZATION_TTL));
        assert_eq!(app.operations.refresh_epoch, 1);
        assert!(app.operations.is_busy());

        app.revoke_profile_authorization("alpha");
        assert!(app.authorizations.grants.is_empty());
    }

    #[test]
    fn profile_mutations_require_a_current_authorization() {
        let (mut app, _) = test_app();
        add_test_profile(&mut app, "alpha", 1);
        app.selected = Some("alpha".into());
        app.editor.visible = true;
        app.editor.original_name = Some("alpha".into());
        app.editor.expected_identity = Some(test_identity(1));
        app.editor.name = "alpha".into();
        app.editor.host = "example.test".into();
        app.editor.port = "22".into();
        app.editor.user = "alice".into();
        app.editor.password = "ssh-secret".into();
        app.save_profile(&egui::Context::default());
        assert!(!app.operations.is_busy());
        assert_eq!(app.editor.password, "ssh-secret");
        assert!(app
            .notice
            .as_ref()
            .is_some_and(|(message, error)| *error && message.contains("独立口令")));

        app.notice = None;
        app.remove_profile(&egui::Context::default(), "alpha".into());
        assert_eq!(app.delete_candidate.as_deref(), Some("alpha"));
        assert!(!app.operations.is_busy());
        assert!(app
            .notice
            .as_ref()
            .is_some_and(|(message, error)| *error && message.contains("授权")));
    }

    #[test]
    fn tunnel_form_contains_only_loopback_ports_and_limits() {
        let (mut app, _) = test_app();
        app.tunnel_mode = client::TunnelMode::Local;
        app.tunnel_bind_port = "0".into();
        app.tunnel_target_port = "5432".into();
        let spec = app.build_tunnel_spec().expect("valid loopback spec");
        assert_eq!(spec.mode, client::TunnelMode::Local);
        assert_eq!(spec.bind_port, 0);
        assert_eq!(spec.target_port, 5432);
        assert_eq!(spec.max_connections, 32);
    }

    #[test]
    fn tunnel_reducer_rejects_cross_profile_generation_and_old_instances() {
        let current = TunnelContext {
            profile: "alpha".into(),
            profile_generation: 7,
            profile_identity: test_identity(3),
            instance: 9,
        };
        let old_instance = TunnelContext {
            instance: 8,
            ..current.clone()
        };
        let old_generation = TunnelContext {
            profile_generation: 6,
            ..current.clone()
        };
        let other_profile = TunnelContext {
            profile: "beta".into(),
            ..current.clone()
        };

        assert!(tunnel_start_may_be_adopted(
            Some("alpha"),
            7,
            Some(current.profile_identity),
            Some(&current),
            None,
            &current,
        ));
        assert!(!tunnel_start_may_be_adopted(
            Some("alpha"),
            7,
            Some(current.profile_identity),
            Some(&current),
            None,
            &old_instance,
        ));
        assert!(!tunnel_start_may_be_adopted(
            Some("alpha"),
            7,
            Some(old_generation.profile_identity),
            Some(&old_generation),
            None,
            &old_generation,
        ));
        assert!(!tunnel_start_may_be_adopted(
            Some("alpha"),
            7,
            Some(other_profile.profile_identity),
            Some(&other_profile),
            None,
            &other_profile,
        ));
        assert!(!tunnel_start_may_be_adopted(
            Some("alpha"),
            7,
            Some(current.profile_identity),
            Some(&current),
            Some(&old_instance),
            &current,
        ));
        assert!(tunnel_end_matches_pending(Some(&current), &current));
        assert!(!tunnel_end_matches_pending(Some(&current), &old_instance));
    }

    #[test]
    fn sensitive_state_cleanup_covers_editor_output_shell_and_paths() {
        let (mut app, _) = test_app();
        app.profiles.push(ProfileRow {
            name: "secret-profile".into(),
            host: "secret-host".into(),
            port: 22,
            generation: 1,
            profile_id: test_identity(1).profile_id,
            daemon: Some(client::DaemonStatus {
                profile: "secret-profile".into(),
                host: "secret-host".into(),
                user: "secret-user".into(),
                started_unix: 1,
                endpoint: "secret-endpoint".into(),
            }),
        });
        app.owned_daemons.insert("secret-profile".into(), 7);
        app.selected = Some("secret-profile".into());
        app.editor.original_name = Some("secret-profile".into());
        app.editor.name = "secret-profile".into();
        app.editor.host = "secret-host".into();
        app.editor.port = "2222".into();
        app.editor.user = "secret-user".into();
        app.editor.password = "secret-password".into();
        app.editor.host_key_sha256 = "SHA256:secret-host-key".into();
        app.editor.profile_passphrase = "new-secret-profile-passphrase".into();
        app.editor.profile_passphrase_confirmation = "new-secret-profile-passphrase".into();
        app.security_dialog.visible = true;
        app.security_dialog.profile = "secret-profile".into();
        app.security_dialog.random_passphrase_once = Some(Zeroizing::new("random-secret".into()));
        app.security_dialog.recovery_media_path = "X:\\secret-recovery.json".into();
        app.admin_dialog.visible = true;
        app.admin_dialog.password_input = "secret-admin-password".into();
        app.admin_dialog.media_path = "X:\\secret-media.json".into();
        app.admin_authorization.grant(
            Some(Zeroizing::new("cached-secret-admin".into())),
            Instant::now(),
        );
        app.migration.old_master = "secret-legacy-master".into();
        app.migration
            .profile_passphrases
            .insert("secret-profile".into(), "secret-new-passphrase".into());
        app.migration.recovery_media_path = "X:\\migration-media.json".into();
        app.delete_candidate = Some("secret-profile".into());
        app.command = "printf secret-command".into();
        app.profile_passphrase_input = "secret-profile-passphrase".into();
        grant_test_profile(
            &mut app,
            "secret-profile",
            1,
            "cached-secret-profile-passphrase",
            Instant::now(),
        );
        app.output = "secret-output".into();
        app.remote_path = "/secret/path".into();
        app.remote_entries.push(RemoteEntry {
            name: "secret-name".into(),
            path: "/secret/path/file".into(),
            is_dir: false,
            is_symlink: false,
            size: 1,
            modified_unix: None,
        });
        app.selected_remote = app.remote_entries.first().cloned();
        app.new_directory = "secret-directory".into();
        app.local_upload = "secret-local-upload".into();
        app.remote_upload = "secret-remote-upload".into();
        app.local_download = "secret-local-download".into();
        app.shell_profile = Some("secret-profile".into());
        app.shell_input = "secret-shell-input".into();
        app.shell_bytes = b"secret-shell-bytes".to_vec();
        app.shell_output = "secret-shell-output".into();
        app.tunnel_bind_port = "12345".into();
        app.tunnel_target_port = "5432".into();
        app.tunnel_max_connections = "17".into();
        app.operations
            .active
            .insert(1, Zeroizing::new("secret activity".into()));
        app.notice = Some(("secret notice".into(), true));

        app.zeroize_sensitive_state();
        app.zeroize_sensitive_state();

        assert!(app.profiles.is_empty());
        assert!(app.owned_daemons.is_empty());
        assert!(app.selected.is_none());
        assert!(app.editor.original_name.is_none());
        assert!(app.editor.name.is_empty());
        assert!(app.editor.host.is_empty());
        assert!(app.editor.port.is_empty());
        assert!(app.editor.user.is_empty());
        assert!(app.editor.password.is_empty());
        assert!(app.editor.host_key_sha256.is_empty());
        assert!(app.editor.profile_passphrase.is_empty());
        assert!(app.editor.profile_passphrase_confirmation.is_empty());
        assert!(!app.security_dialog.visible);
        assert!(app.security_dialog.random_passphrase_once.is_none());
        assert!(app.security_dialog.recovery_media_path.is_empty());
        assert!(!app.admin_dialog.visible);
        assert!(app.admin_dialog.password_input.is_empty());
        assert!(app.admin_dialog.media_path.is_empty());
        assert!(app.admin_authorization.passphrase.is_none());
        assert!(app.migration.old_master.is_empty());
        assert!(app.migration.profile_passphrases.is_empty());
        assert!(app.migration.recovery_media_path.is_empty());
        assert!(app.delete_candidate.is_none());
        assert!(app.command.is_empty());
        assert!(app.profile_passphrase_input.is_empty());
        assert!(app.authorizations.grants.is_empty());
        assert!(app.output.is_empty());
        assert!(app.remote_path.is_empty());
        assert!(app.remote_entries.is_empty());
        assert!(app.selected_remote.is_none());
        assert!(app.new_directory.is_empty());
        assert!(app.local_upload.is_empty());
        assert!(app.remote_upload.is_empty());
        assert!(app.local_download.is_empty());
        assert!(app.shell_profile.is_none());
        assert!(app.shell_input.is_empty());
        assert!(app.shell_bytes.is_empty());
        assert!(app.shell_output.is_empty());
        assert!(app.tunnel_bind_port.is_empty());
        assert!(app.tunnel_target_port.is_empty());
        assert!(app.tunnel_max_connections.is_empty());
        assert!(app.tunnel.is_none());
        assert!(app.pending_tunnel_start.is_none());
        assert!(app.pending_tunnel_stops.is_empty());
        assert!(app.operations.active.is_empty());
        assert!(app.notice.is_none());
    }

    #[test]
    fn ui_message_zeroize_covers_paths_entries_and_errors() {
        let mut directory = UiMessage::Directory {
            operation: OperationContext {
                id: 1,
                profile: Some("secret-profile".into()),
                profile_generation: 2,
                profile_identity: Some(test_identity(2)),
            },
            request: DirectoryRequest {
                profile: "secret-profile".into(),
                path: "/secret/request".into(),
                generation: 3,
                profile_generation: 2,
                profile_identity: test_identity(2),
            },
            result: Ok((
                "/secret/result".into(),
                vec![RemoteEntry {
                    name: "secret-name".into(),
                    path: "/secret/result/file".into(),
                    is_dir: false,
                    is_symlink: false,
                    size: 1,
                    modified_unix: None,
                }],
            )),
        };

        directory.zeroize_sensitive();

        let UiMessage::Directory {
            operation,
            request,
            result,
        } = directory
        else {
            panic!("message variant changed");
        };
        assert!(operation.profile.is_none());
        assert!(request.profile.is_empty());
        assert!(request.path.is_empty());
        let (path, entries) = result.expect("directory result");
        assert!(path.is_empty());
        assert!(entries.is_empty());

        let mut transfer = UiMessage::Transfer {
            operation: OperationContext {
                id: 4,
                profile: Some("secret-profile".into()),
                profile_generation: 2,
                profile_identity: Some(test_identity(2)),
            },
            refresh: Some(DirectoryRequest {
                profile: "secret-profile".into(),
                path: "/secret/refresh".into(),
                generation: 5,
                profile_generation: 2,
                profile_identity: test_identity(2),
            }),
            result: Err("secret remote error".into()),
        };

        transfer.zeroize_sensitive();

        let UiMessage::Transfer {
            operation,
            refresh,
            result,
        } = transfer
        else {
            panic!("message variant changed");
        };
        assert!(operation.profile.is_none());
        let refresh = refresh.expect("refresh context");
        assert!(refresh.profile.is_empty());
        assert!(refresh.path.is_empty());
        assert_eq!(result, Err(String::new()));
    }

    #[test]
    fn queued_and_rejected_messages_run_the_zeroize_envelope() {
        let queued = Arc::new(AtomicBool::new(false));
        let (tx, rx) = ui_message_channel();
        tx.send(UiMessage::ZeroizeProbe(queued.clone()))
            .expect("queue probe");
        drop(rx);
        assert!(queued.load(Ordering::SeqCst));

        let rejected = Arc::new(AtomicBool::new(false));
        let (tx, rx) = ui_message_channel();
        drop(rx);
        assert!(tx.send(UiMessage::ZeroizeProbe(rejected.clone())).is_err());
        assert!(rejected.load(Ordering::SeqCst));
    }

    #[test]
    fn reducer_unwind_keeps_message_zeroize_envelope_armed() {
        let zeroized = Arc::new(AtomicBool::new(false));
        let (mut app, tx) = test_app();
        tx.send(UiMessage::ZeroizeProbe(zeroized.clone()))
            .expect("queue reducer unwind probe");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            app.receive_messages(&egui::Context::default());
        }));

        assert!(result.is_err());
        assert!(zeroized.load(Ordering::SeqCst));
    }

    #[test]
    fn masked_secret_buffer_edits_unicode_without_exposing_it_to_text_edit() {
        let mut secret = "a密🔑z".to_owned();
        {
            let mut buffer = MaskedSecretTextBuffer::new(&mut secret);
            assert_eq!(egui::TextBuffer::as_str(&buffer), "****");

            assert_eq!(
                egui::TextBuffer::insert_text(&mut buffer, "Ω🙂", egui::text::CharIndex(2)),
                2
            );
            assert_eq!(egui::TextBuffer::as_str(&buffer), "******");
            egui::TextBuffer::delete_char_range(
                &mut buffer,
                egui::text::CharIndex(1)..egui::text::CharIndex(4),
            );
            assert_eq!(egui::TextBuffer::as_str(&buffer), "***");

            // Even a stale framework undo record can contain only a mask, and
            // replace_with is intentionally a no-op for secret fields.
            egui::TextBuffer::replace_with(&mut buffer, "********");
            assert_eq!(egui::TextBuffer::as_str(&buffer), "***");
        }
        assert_eq!(secret, "a🔑z");
        secret.zeroize();
    }

    #[test]
    fn secret_text_edit_state_has_no_undo_or_plaintext() {
        use egui::text::{CCursor, CCursorRange};

        let ctx = egui::Context::default();
        let id = sensitive_text_edit_id("undo-state-test");
        let mut state = egui::widgets::text_edit::TextEditState::default();
        let mut seeded = egui::util::undoer::Undoer::default();
        let cursor = CCursorRange::one(CCursor::new(0));
        let mut seeded_value = (cursor, "plain-secret".to_owned());
        seeded.add_undo(&seeded_value);
        state.set_undoer(seeded);
        state.store(&ctx, id);
        let mut before_reset = egui::widgets::text_edit::TextEditState::load(&ctx, id)
            .expect("seeded state")
            .undoer();
        let different = (cursor, String::new());
        assert_eq!(
            before_reset.undo(&different).map(|(_, text)| text.as_str()),
            Some("plain-secret")
        );

        reset_text_edit_undo_state(&ctx, id);

        let loaded =
            egui::widgets::text_edit::TextEditState::load(&ctx, id).expect("reset text edit state");
        let mut undoer = loaded.undoer();
        let current = (cursor, "****".to_owned());
        assert!(undoer.undo(&current).is_none());
        seeded_value.1.zeroize();
    }

    #[test]
    fn panic_unwind_runs_app_drop_and_cancels_shell() {
        let shell_cancellation = CancellationToken::new();
        let observed_shell_cancellation = shell_cancellation.clone();
        let transfer_cancellation = CancellationToken::new();
        let observed_transfer_cancellation = transfer_cancellation.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (mut app, _) = test_app();
            let (shell_input, _shell_input_rx) = tokio::sync::mpsc::channel(1);
            let (_shell_event_tx, shell_events) = tokio::sync::mpsc::channel(1);
            app.shell = Some(client::GuiShell {
                input: shell_input,
                events: shell_events,
                cancellation: shell_cancellation,
            });
            let transfer_handle = app.runtime().spawn(std::future::pending::<()>());
            app.pending_transfers.insert(
                1,
                PendingTransfer {
                    cancellation: transfer_cancellation,
                    handle: transfer_handle,
                    progress: None,
                },
            );
            app.profile_passphrase_input = "secret-profile-passphrase".into();
            panic!("exercise SerctlApp::drop during unwind");
        }));

        assert!(result.is_err());
        assert!(observed_shell_cancellation.is_cancelled());
        assert!(observed_transfer_cancellation.is_cancelled());
    }

    #[test]
    fn normal_exit_bounds_runtime_wait_for_blocking_work() {
        let (mut app, _) = test_app();
        let transfer_cancellation = CancellationToken::new();
        let observed_transfer_cancellation = transfer_cancellation.clone();
        let worker_cancellation = transfer_cancellation.clone();
        let transfer_handle = app.runtime().spawn(async move {
            worker_cancellation.cancelled().await;
        });
        app.pending_transfers.insert(
            1,
            PendingTransfer {
                cancellation: transfer_cancellation,
                handle: transfer_handle,
                progress: None,
            },
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let _worker = app.runtime().spawn_blocking(move || {
            started_tx.send(()).expect("signal blocking worker start");
            let _ = release_rx.recv();
            let _ = finished_tx.send(());
        });
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("blocking worker did not start");

        let started = std::time::Instant::now();
        eframe::App::on_exit(&mut app, None);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(3),
            "runtime shutdown exceeded its bounded grace: {elapsed:?}"
        );
        assert!(observed_transfer_cancellation.is_cancelled());
        release_tx.send(()).expect("release leaked blocking worker");
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("blocking worker did not finish after release");
    }

    #[test]
    fn profiles_are_kept_in_stable_name_order() {
        let mut map = BTreeMap::new();
        map.insert("b", 2);
        map.insert("a", 1);
        assert_eq!(map.keys().cloned().collect::<Vec<_>>(), ["a", "b"]);
    }

    #[test]
    fn remote_path_helpers_handle_root() {
        assert_eq!(join_remote_path("/", "tmp"), "/tmp");
        assert_eq!(join_remote_path("/home/user/", "logs"), "/home/user/logs");
        assert_eq!(remote_parent("/home/user"), "/home");
        assert_eq!(remote_parent("/"), "/");
    }

    #[test]
    fn directory_requests_require_latest_generation_and_selected_profile() {
        let mut requests = DirectoryRequests::default();
        let identity = test_identity(9);
        let first = requests.begin("alpha".into(), "/one".into(), 4, identity);
        let second = requests.begin("alpha".into(), "/two".into(), 4, identity);

        assert!(second.generation > first.generation);
        assert!(!requests.is_current(Some("alpha"), 4, Some(identity), &first));
        assert!(requests.is_current(Some("alpha"), 4, Some(identity), &second));
        assert!(!requests.is_current(Some("beta"), 4, Some(identity), &second));
        assert!(!requests.is_current(Some("alpha"), 5, Some(identity), &second));
        assert!(!requests.is_current(Some("alpha"), 4, Some(test_identity(10)), &second));

        requests.invalidate();
        assert!(!requests.is_current(Some("alpha"), 4, Some(identity), &second));
    }

    #[test]
    fn directory_refresh_timeout_is_shorter_than_bulk_transfer_timeout() {
        assert_eq!(UI_DIRECTORY_REFRESH_TIMEOUT, Duration::from_secs(20));
        assert!(
            UI_DIRECTORY_REFRESH_TIMEOUT
                < Duration::from_millis(serctl_protocol::DEFAULT_SFTP_TIMEOUT_MS)
        );
    }

    #[test]
    fn stale_completion_cannot_clear_a_newer_busy_operation() {
        let mut operations = UiOperations::default();
        let first = operations.begin(Some("alpha".into()), "first".into());
        let second = operations.begin(Some("alpha".into()), "second".into());

        assert!(operations.finish(&first));
        assert!(operations.is_busy());
        assert_eq!(operations.activity(), Some("second"));
        assert!(!operations.finish(&first));
        assert!(operations.is_busy());
        assert!(operations.finish(&second));
        assert!(!operations.is_busy());
    }

    #[test]
    fn profile_generation_rejects_cross_profile_and_returned_stale_results() {
        let mut operations = UiOperations::default();
        let alpha = operations.begin(Some("alpha".into()), "alpha".into());
        assert!(operations.is_current(Some("alpha"), &alpha));
        assert!(!operations.is_current(Some("beta"), &alpha));

        operations.advance_profile_generation();
        assert!(!operations.is_current(Some("alpha"), &alpha));
        assert_eq!(operations.activity(), Some("正在结束先前操作…"));
        let returned_to_alpha = operations.begin(Some("alpha".into()), "new alpha".into());
        assert!(operations.is_current(Some("alpha"), &returned_to_alpha));
        assert!(!operations.is_current(Some("alpha"), &alpha));
    }

    #[test]
    fn only_latest_profile_refresh_epoch_is_current() {
        let mut operations = UiOperations::default();
        let first = operations.next_refresh_epoch();
        let second = operations.next_refresh_epoch();
        assert!(first < second);
        assert_ne!(first, operations.refresh_epoch);
        assert_eq!(second, operations.refresh_epoch);
    }

    #[test]
    fn reducer_ignores_a_command_returning_after_profile_switch() {
        let (mut app, tx) = test_app();
        app.selected = Some("alpha".into());
        let operation = app
            .operations
            .begin(Some("alpha".into()), "alpha command".into());
        app.select_profile(Some("beta".into()));

        tx.send(UiMessage::Command {
            operation,
            result: Ok(client::CommandOutput {
                stdout: b"alpha secret".to_vec(),
                stderr: Vec::new(),
                code: Some(0),
                operation_context_id: None,
                revision: 0,
            }),
        })
        .expect("queue stale command result");
        app.receive_messages(&egui::Context::default());

        assert_eq!(app.selected.as_deref(), Some("beta"));
        assert!(!app.output.contains("alpha secret"));
        assert_eq!(app.exit_code, None);
        assert!(!app.operations.is_busy());
    }

    #[test]
    fn reducer_ignores_an_older_profile_refresh_arriving_last() {
        let (mut app, tx) = test_app();
        let old_epoch = app.operations.next_refresh_epoch();
        let old_operation = app.operations.begin(None, "old refresh".into());
        let new_epoch = app.operations.next_refresh_epoch();
        let new_operation = app.operations.begin(None, "new refresh".into());

        tx.send(UiMessage::Profiles {
            operation: new_operation,
            epoch: new_epoch,
            result: Ok(vec![ProfileRow {
                name: "new".into(),
                host: "new.example".into(),
                port: 22,
                generation: 2,
                profile_id: test_identity(2).profile_id,
                daemon: None,
            }]),
        })
        .expect("queue new refresh");
        tx.send(UiMessage::Profiles {
            operation: old_operation,
            epoch: old_epoch,
            result: Ok(vec![ProfileRow {
                name: "old".into(),
                host: "old.example".into(),
                port: 22,
                generation: 1,
                profile_id: test_identity(1).profile_id,
                daemon: None,
            }]),
        })
        .expect("queue old refresh");
        app.receive_messages(&egui::Context::default());

        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].name, "new");
        assert_eq!(app.selected.as_deref(), Some("new"));
        assert!(!app.operations.is_busy());
    }

    #[test]
    fn saved_same_name_invalidates_old_context_even_if_refresh_fails() {
        let (mut app, tx) = test_app();
        app.profiles.push(ProfileRow {
            name: "alpha".into(),
            host: "old.example".into(),
            port: 22,
            generation: 1,
            profile_id: test_identity(1).profile_id,
            daemon: None,
        });
        app.selected = Some("alpha".into());
        app.workspace_tab = WorkspaceTab::Files;
        app.remote_path = "/old/private".into();
        app.remote_entries.push(RemoteEntry {
            name: "old-secret.txt".into(),
            path: "/old/private/old-secret.txt".into(),
            is_dir: false,
            is_symlink: false,
            size: 17,
            modified_unix: None,
        });
        app.selected_remote = app.remote_entries.first().cloned();
        app.output = "output from old.example".into();
        app.exit_code = Some(0);
        let generation_before_save = app.operations.profile_generation;
        let save = app
            .operations
            .begin(Some("alpha".into()), "save alpha".into());

        tx.send(UiMessage::Saved {
            operation: save,
            original_name: Some("alpha".into()),
            result: Ok("alpha".into()),
        })
        .expect("queue successful same-name save");
        app.receive_messages(&egui::Context::default());

        assert!(app.operations.profile_generation > generation_before_save);
        assert_eq!(app.selected.as_deref(), Some("alpha"));
        assert!(
            app.selected_profile().is_none(),
            "old endpoint row survived save"
        );
        assert!(!app.output.contains("old.example"));
        assert!(app.remote_entries.is_empty());
        assert!(app.selected_remote.is_none());
        assert_eq!(app.remote_path, ".");
        assert_eq!(app.workspace_tab, WorkspaceTab::Command);

        // `Saved` starts the real follow-up refresh. Inject its failure without
        // driving the test runtime; the reducer must not resurrect old state or
        // make the stale endpoint actionable after busy state clears.
        let refresh = OperationContext {
            id: app.operations.next_id,
            profile: None,
            profile_generation: app.operations.profile_generation,
            profile_identity: None,
        };
        tx.send(UiMessage::Profiles {
            operation: refresh,
            epoch: app.operations.refresh_epoch,
            result: Err("refresh failed".into()),
        })
        .expect("queue failed profile refresh");
        app.receive_messages(&egui::Context::default());

        assert!(!app.operations.is_busy());
        assert!(app.selected_profile().is_none());
        assert!(app.profiles.iter().all(|profile| profile.name != "alpha"));
        assert!(app.remote_entries.is_empty());
        assert!(!app.output.contains("old.example"));
    }

    #[test]
    fn stale_daemon_events_cannot_replace_or_remove_new_instance() {
        let mut owned = BTreeMap::new();
        assert!(record_owned_daemon(&mut owned, "alpha".into(), 1));
        assert!(record_owned_daemon(&mut owned, "alpha".into(), 2));
        assert!(!record_owned_daemon(&mut owned, "alpha".into(), 1));
        assert_eq!(owned.get("alpha"), Some(&2));

        assert!(!remove_owned_daemon(&mut owned, "alpha", 1));
        assert_eq!(owned.get("alpha"), Some(&2));
        assert!(remove_owned_daemon(&mut owned, "alpha", 2));
        assert!(!owned.contains_key("alpha"));
    }

    #[test]
    fn switching_profiles_zeroizes_and_resets_profile_scoped_state() {
        let (mut app, _) = test_app();
        app.selected = Some("alpha".into());
        app.command = "cat /secret".into();
        app.profile_passphrase_input = "alpha-passphrase-input".into();
        grant_test_profile(
            &mut app,
            "alpha",
            1,
            "cached-alpha-passphrase",
            Instant::now(),
        );
        app.output = "remote secret".into();
        app.exit_code = Some(17);
        app.remote_path = "/private".into();
        app.new_directory = "sensitive-dir".into();
        app.local_upload = "C:\\secret.txt".into();
        app.remote_upload = "/tmp/secret.txt".into();
        app.local_download = "C:\\download.txt".into();
        app.shell_input = "export TOKEN=secret".into();
        app.shell_bytes = b"terminal secret".to_vec();
        app.shell_output = "terminal secret".into();
        app.tunnel_mode = client::TunnelMode::Remote;
        app.tunnel_bind_port = "8443".into();
        app.tunnel_target_port = "443".into();
        app.tunnel_max_connections = "64".into();
        let (shell_input, _shell_input_rx) = tokio::sync::mpsc::channel(1);
        let (_shell_event_tx, shell_events) = tokio::sync::mpsc::channel(1);
        let shell_cancellation = CancellationToken::new();
        let observed_shell_cancellation = shell_cancellation.clone();
        app.shell = Some(client::GuiShell {
            input: shell_input,
            events: shell_events,
            cancellation: shell_cancellation,
        });
        app.shell_profile = Some("alpha".into());
        app.workspace_tab = WorkspaceTab::Bash;
        let upload_cancellation = CancellationToken::new();
        let observed_cancellation = upload_cancellation.clone();
        let upload_handle = app.runtime().spawn(std::future::pending::<()>());
        app.pending_transfers.insert(
            99,
            PendingTransfer {
                cancellation: upload_cancellation,
                handle: upload_handle,
                progress: None,
            },
        );

        app.select_profile(Some("beta".into()));

        assert_eq!(app.selected.as_deref(), Some("beta"));
        assert_eq!(app.command, "uname -a && whoami");
        assert!(app.profile_passphrase_input.is_empty());
        assert_eq!(app.authorizations.grants.len(), 1);
        assert!(!app.output.contains("remote secret"));
        assert_eq!(app.exit_code, None);
        assert_eq!(app.remote_path, ".");
        assert!(app.new_directory.is_empty());
        assert!(app.local_upload.is_empty());
        assert!(app.remote_upload.is_empty());
        assert!(app.local_download.is_empty());
        assert!(app.shell_input.is_empty());
        assert!(app.shell_bytes.is_empty());
        assert!(!app.shell_output.contains("terminal secret"));
        assert!(app.shell.is_none());
        assert!(app.shell_profile.is_none());
        assert!(observed_shell_cancellation.is_cancelled());
        assert_eq!(app.tunnel_mode, client::TunnelMode::Local);
        assert_eq!(app.tunnel_bind_port, "0");
        assert!(app.tunnel_target_port.is_empty());
        assert_eq!(app.tunnel_max_connections, "32");
        assert_eq!(app.workspace_tab, WorkspaceTab::Command);
        assert!(observed_cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn abort_and_wait_observes_task_cleanup() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let started = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let task_started = started.clone();
        let task_dropped = dropped.clone();
        let mut task = tokio::spawn(async move {
            let _drop_flag = DropFlag(task_dropped);
            task_started.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        });

        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        assert!(abort_and_wait(&mut task).await);

        assert!(task.is_finished());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn daemon_readiness_deadline_survives_a_saturated_blocking_pool() {
        struct ReleaseOnDrop(Arc<AtomicBool>);

        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        struct FakeDaemonPublication {
            live: Arc<AtomicBool>,
            lock_published: Arc<AtomicBool>,
            lease_held: Arc<AtomicBool>,
        }

        impl Drop for FakeDaemonPublication {
            fn drop(&mut self) {
                self.live.store(false, Ordering::SeqCst);
                self.lock_published.store(false, Ordering::SeqCst);
                self.lease_held.store(false, Ordering::SeqCst);
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("build saturated-pool test runtime");
        runtime.block_on(async {
            let blocker_started = Arc::new(AtomicBool::new(false));
            let blocker_release = Arc::new(AtomicBool::new(false));
            let _release_on_drop = ReleaseOnDrop(blocker_release.clone());
            let worker_started = blocker_started.clone();
            let worker_release = blocker_release.clone();
            let blocker = tokio::task::spawn_blocking(move || {
                worker_started.store(true, Ordering::SeqCst);
                while !worker_release.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                while !blocker_started.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("blocking-pool gate did not start");

            let invocation = tokio::time::Instant::now();
            let deadline = invocation + Duration::from_millis(40);
            let live = Arc::new(AtomicBool::new(false));
            let lock_published = Arc::new(AtomicBool::new(false));
            let lease_held = Arc::new(AtomicBool::new(false));
            let daemon_live = live.clone();
            let daemon_lock = lock_published.clone();
            let daemon_lease = lease_held.clone();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let mut daemon_task = tokio::spawn(async move {
                let _ready_tx = ready_tx;
                daemon_live.store(true, Ordering::SeqCst);
                daemon_lock.store(true, Ordering::SeqCst);
                daemon_lease.store(true, Ordering::SeqCst);
                let _publication = FakeDaemonPublication {
                    live: daemon_live,
                    lock_published: daemon_lock,
                    lease_held: daemon_lease,
                };
                std::future::pending::<()>().await;
            });

            let outcome = wait_for_daemon_readiness(ready_rx, &mut daemon_task, deadline).await;
            assert!(matches!(outcome, DaemonReadiness::TimedOut));
            assert!(
                invocation.elapsed() < Duration::from_secs(1),
                "readiness deadline waited for blocking-pool capacity"
            );
            assert!(abort_and_wait(&mut daemon_task).await);
            assert!(
                !live.load(Ordering::SeqCst),
                "daemon remained live but unowned"
            );
            assert!(
                !lock_published.load(Ordering::SeqCst),
                "daemon lock publication survived cancellation"
            );
            assert!(
                !lease_held.load(Ordering::SeqCst),
                "daemon lifetime lease survived cancellation"
            );

            blocker_release.store(true, Ordering::SeqCst);
            blocker.await.expect("blocking-pool gate panicked");
        });
        runtime.shutdown_timeout(Duration::from_secs(1));
    }

    #[tokio::test]
    async fn daemon_readiness_signal_wins_if_ready_and_ended_are_simultaneous() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        ready_tx.send(()).expect("send readiness");
        let mut daemon_task = tokio::spawn(async { 7_u8 });
        while !daemon_task.is_finished() {
            tokio::task::yield_now().await;
        }

        let outcome = wait_for_daemon_readiness(
            ready_rx,
            &mut daemon_task,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;

        assert!(matches!(outcome, DaemonReadiness::Ready));
        assert_eq!(daemon_task.await.expect("join completed daemon"), 7);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn profile_refresh_absolute_deadline_cancels_a_full_pending_probe_wave() {
        struct ProbeDrop(Arc<AtomicUsize>);

        impl Drop for ProbeDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let started = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let rows = (0..(MAX_CONCURRENT_STATUS_PROBES + 9))
            .map(|index| (format!("profile-{index}"), "host.example".into(), 22))
            .collect();
        let invocation = tokio::time::Instant::now();
        let deadline = invocation + Duration::from_millis(40);
        let probe_started = started.clone();
        let probe_cancelled = cancelled.clone();

        let result = load_profile_rows_with_probe(rows, deadline, move |(name, host, port)| {
            let started = probe_started.clone();
            let cancelled = probe_cancelled.clone();
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                let _drop = ProbeDrop(cancelled);
                std::future::pending::<()>().await;
                ProfileRow {
                    name,
                    host,
                    port,
                    generation: 1,
                    profile_id: test_identity(1).profile_id,
                    daemon: None,
                }
            }
        })
        .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("pending status probes unexpectedly completed"),
        };

        assert!(error.contains("绝对等待上限"), "{error}");
        assert!(
            invocation.elapsed() < Duration::from_secs(1),
            "profile waves accumulated beyond the absolute deadline"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while cancelled.load(Ordering::SeqCst) < started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending status probes were not cancelled");
        assert_eq!(started.load(Ordering::SeqCst), MAX_CONCURRENT_STATUS_PROBES);
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            MAX_CONCURRENT_STATUS_PROBES
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_and_wait_detaches_uninterruptible_blocking_work_at_deadline() {
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let worker_release = release.clone();
        let worker_finished = finished.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            worker_started.store(true, Ordering::SeqCst);
            while !worker_release.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            worker_finished.store(true, Ordering::SeqCst);
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let before = std::time::Instant::now();
        assert!(!abort_and_wait(&mut task).await);
        assert!(before.elapsed() < Duration::from_secs(1));

        release.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !finished.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn transfer_shutdown_waits_for_cooperative_cleanup() {
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let cleaned = Arc::new(AtomicBool::new(false));
        let worker_cleaned = cleaned.clone();
        let handle = tokio::spawn(async move {
            worker_cancellation.cancelled().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
            worker_cleaned.store(true, Ordering::SeqCst);
        });
        let mut pending = BTreeMap::new();
        pending.insert(
            1,
            PendingTransfer {
                cancellation,
                handle,
                progress: None,
            },
        );

        let aborted = cancel_pending_transfers_and_wait(pending, Duration::from_secs(1)).await;

        assert_eq!(aborted, 0);
        assert!(cleaned.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transfer_shutdown_detaches_blocking_worker_after_shared_abort_grace() {
        let cancellation = CancellationToken::new();
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let worker_release = release.clone();
        let worker_finished = finished.clone();
        let handle = tokio::task::spawn_blocking(move || {
            worker_started.store(true, Ordering::SeqCst);
            while !worker_release.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            worker_finished.store(true, Ordering::SeqCst);
        });
        let mut pending = BTreeMap::new();
        pending.insert(
            1,
            PendingTransfer {
                cancellation,
                handle,
                progress: None,
            },
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let before = std::time::Instant::now();
        let aborted = cancel_pending_transfers_and_wait(pending, Duration::from_millis(20)).await;
        assert_eq!(aborted, 1);
        assert!(before.elapsed() < Duration::from_secs(1));

        release.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !finished.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_blocking_work_does_not_stall_a_single_runtime_worker() {
        struct ReleaseOnDrop(Arc<AtomicBool>);

        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let _release_on_drop = ReleaseOnDrop(release.clone());
        let worker_started = started.clone();
        let worker_release = release.clone();
        let worker_finished = finished.clone();
        let blocking = tokio::task::spawn_blocking(move || {
            worker_started.store(true, Ordering::SeqCst);
            while !worker_release.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            worker_finished.store(true, Ordering::SeqCst);
        });
        let bounded = tokio::spawn(await_blocking_until(
            blocking,
            tokio::time::Instant::now() + Duration::from_millis(25),
            "测试阻塞操作",
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("spawn_blocking work stalled the current-thread runtime");
        let error = bounded
            .await
            .expect("bounded wait task panicked")
            .expect_err("blocking operation unexpectedly completed");
        assert!(error.contains("等待上限"), "{error}");

        release.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !finished.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached blocking task did not finish after release");
    }

    #[test]
    fn terminal_text_removes_common_ansi_sequences() {
        assert_eq!(terminal_text(b"\x1b[32mok\x1b[0m\r\n"), "ok\n");
        assert_eq!(terminal_text(b"ab\x08c"), "ac");
        assert_eq!(terminal_text(b"secret\xff"), "secret\u{fffd}");
    }

    #[test]
    fn command_output_lossy_conversion_handles_invalid_utf8() {
        assert_eq!(
            command_output_text(b"stdout\xff", b"stderr\xfe").as_str(),
            "stdout\u{fffd}\n[stderr]\nstderr\u{fffd}"
        );
    }
}
