//! Daemon: the per-user/per-vault credential and SSH broker. The classic
//! per-profile daemon (v5) and the global v6 daemon share the same
//! per-operation dispatch; the global mode additionally owns the runtime
//! descriptor/secret, per-profile credential leases, and the unlock flow.
use anyhow::{bail, ensure, Context, Result};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use russh::ChannelMsg;
use serctl_core::audit::{AuditDecision, AuditEvent, AuditLedger, AuditPhase};
use serctl_core::daemon_runtime::{self, DaemonRuntimeDescriptor, DESCRIPTOR_SCHEMA_VERSION};
use serctl_core::vault::{self, now_unix, Creds, LockInfo, ProfileCallKey};
use serctl_protocol::v6::{
    frame_kind, ActivationSecret, InstanceId, V6RequestPrelude, V6ServerIo, IPC_PROTOCOL_VERSION_V6,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch, Mutex, Notify, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use serctl_core::ssh::{
    commit_remote_upload_no_replace_until, is_explicit_sftp_status,
    is_ssh_transport_terminal_error, poll_remote_mutation_until, temporary_remote_path,
    validate_remote_command, validate_remote_path, validate_shell_dimensions,
    validate_upload_remote_path, ExecSubmissionState, RunningCommand, RunningTunnel, SshSession,
    MAX_TRANSFER_BYTES,
};
use serctl_protocol as ipc;
use serctl_transfer_protocol as native;

/// Bound for the complete daemon setup (credential snapshot + runtime
/// publication) once a start is requested. The CLI launcher mirrors this value
/// for its own readiness deadline.
pub const CONTROL_SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const IPC_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const SHELL_INPUT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const HANDLER_SHUTDOWN_GRACE: Duration = Duration::from_secs(4);
/// The global broker exits once no live work (connection handler, tunnel,
/// shell, or operation) remains for this long.
pub const IDLE_EXIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const RUNTIME_LOCK_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const REMOTE_PARTIAL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const REMOTE_PARTIAL_CLEANUP_RETRY: Duration = Duration::from_millis(50);
const POST_AUTH_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SHELL_INPUT_BYTES: usize = 64 * 1024;
const MAX_UPLOAD_CHUNK_BYTES: usize = ipc::NATIVE_IPC_CHUNK_BYTES;
const BUFFERED_HEAVY_OPERATION_LIMIT: usize = 8;
const TUNNEL_CONTROL_LIMIT: usize = 8;
const TUNNEL_COMPLETION_POLL: Duration = Duration::from_millis(100);
const TRANSFER_RECORD_RETENTION: Duration = Duration::from_secs(15 * 60);
/// Active transfers retain cancellation state and may live for a full request
/// deadline. Bound them independently from the IPC connection count so a
/// caller cannot turn the progress registry into unbounded resident state.
const MAX_ACTIVE_TRANSFERS_PER_PROFILE: usize = 8;
/// Keep sixteen of the daemon's sixty-four connection slots available for
/// status, cancellation, and unrelated control requests at peak transfer use.
const MAX_ACTIVE_TRANSFERS_GLOBAL: usize = 48;
/// A status-all response is a single 16 KiB control frame. Eight active plus
/// sixteen completed records fit below that bound even when every validated
/// progress field uses its largest JSON representation. Finished records are
/// additionally capped globally so many short-lived profiles cannot retain an
/// unbounded amount of daemon memory during the fifteen-minute retention
/// window.
const MAX_COMPLETED_TRANSFERS_PER_PROFILE: usize = 16;
const MAX_COMPLETED_TRANSFERS_GLOBAL: usize = 256;
const MANAGED_TUNNEL_RECORD_RETENTION: Duration = Duration::from_secs(15 * 60);
const MAX_ACTIVE_MANAGED_TUNNELS_PER_PROFILE: usize = 8;
const MAX_ACTIVE_MANAGED_TUNNELS_GLOBAL: usize = 32;
const MAX_COMPLETED_MANAGED_TUNNELS_PER_PROFILE: usize = 16;
const MAX_COMPLETED_MANAGED_TUNNELS_GLOBAL: usize = 128;
const MANAGED_TUNNEL_CANCEL_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Default)]
struct TransferCancellation {
    cancelled: AtomicBool,
    changed: Notify,
}

impl TransferCancellation {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            let changed = self.changed.notified();
            if self.is_cancelled() {
                return;
            }
            changed.await;
        }
    }
}

struct TransferRecord {
    profile: String,
    progress: ipc::TransferProgress,
    cancellation: Arc<TransferCancellation>,
    finished_at: Option<Instant>,
    finished_order: Option<usize>,
    context_discovered: bool,
}

#[derive(Default)]
struct TransferRegistry {
    records: StdMutex<HashMap<String, TransferRecord>>,
    next_finished_order: AtomicUsize,
}

impl TransferRegistry {
    fn prune_locked(records: &mut HashMap<String, TransferRecord>, now: Instant) {
        records.retain(|_, record| {
            record
                .finished_at
                .is_none_or(|finished| now.duration_since(finished) < TRANSFER_RECORD_RETENTION)
        });
    }

    fn remove_oldest_finished_locked(
        records: &mut HashMap<String, TransferRecord>,
        profile: Option<&str>,
    ) -> bool {
        let oldest = records
            .iter()
            .filter(|(_, record)| {
                record.finished_at.is_some()
                    && profile.is_none_or(|profile| record.profile == profile)
            })
            .min_by(|(left_id, left), (right_id, right)| {
                left.finished_order
                    .cmp(&right.finished_order)
                    .then_with(|| left_id.cmp(right_id))
            })
            .map(|(transfer_id, _)| transfer_id.clone());
        oldest.is_some_and(|transfer_id| records.remove(&transfer_id).is_some())
    }

    fn enforce_finished_caps_locked(records: &mut HashMap<String, TransferRecord>, profile: &str) {
        while records
            .values()
            .filter(|record| record.profile == profile && record.finished_at.is_some())
            .count()
            > MAX_COMPLETED_TRANSFERS_PER_PROFILE
        {
            let removed = Self::remove_oldest_finished_locked(records, Some(profile));
            debug_assert!(removed);
            if !removed {
                break;
            }
        }
        while records
            .values()
            .filter(|record| record.finished_at.is_some())
            .count()
            > MAX_COMPLETED_TRANSFERS_GLOBAL
        {
            let removed = Self::remove_oldest_finished_locked(records, None);
            debug_assert!(removed);
            if !removed {
                break;
            }
        }
    }

    fn replace_progress(
        record: &mut TransferRecord,
        profile: &str,
        progress: ipc::TransferProgress,
    ) -> Result<()> {
        ensure!(record.profile == profile, "transfer profile mismatch");
        ensure!(
            progress.confirmed_bytes >= record.progress.confirmed_bytes,
            "transfer confirmation moved backwards"
        );
        ensure!(
            progress.operation_context_id == record.progress.operation_context_id,
            "transfer operation context changed"
        );
        let mut progress = progress;
        progress.revision = record
            .progress
            .revision
            .checked_add(1)
            .context("transfer revision is exhausted")?;
        record.progress = progress;
        Ok(())
    }

    fn begin(
        &self,
        profile: &str,
        progress: ipc::TransferProgress,
    ) -> Result<Arc<TransferCancellation>> {
        progress.validate()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("transfer registry lock is poisoned"))?;
        Self::prune_locked(&mut records, Instant::now());
        ensure!(
            records
                .values()
                .filter(|record| record.finished_at.is_none())
                .count()
                < MAX_ACTIVE_TRANSFERS_GLOBAL,
            "global active transfer capacity is exhausted"
        );
        ensure!(
            records
                .values()
                .filter(|record| record.profile == profile && record.finished_at.is_none())
                .count()
                < MAX_ACTIVE_TRANSFERS_PER_PROFILE,
            "profile active transfer capacity is exhausted"
        );
        ensure!(
            !records.contains_key(progress.transfer_id.as_str()),
            "transfer id is already registered"
        );
        let cancellation = Arc::new(TransferCancellation::default());
        records.insert(
            progress.transfer_id.as_str().to_owned(),
            TransferRecord {
                profile: profile.to_owned(),
                progress,
                cancellation: Arc::clone(&cancellation),
                finished_at: None,
                finished_order: None,
                context_discovered: false,
            },
        );
        Ok(cancellation)
    }

    fn update(&self, profile: &str, progress: ipc::TransferProgress) -> Result<()> {
        progress.validate()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("transfer registry lock is poisoned"))?;
        let record = records
            .get_mut(progress.transfer_id.as_str())
            .context("transfer is not registered")?;
        Self::replace_progress(record, profile, progress)
    }

    fn finish(&self, profile: &str, progress: ipc::TransferProgress) -> Result<()> {
        progress.validate()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("transfer registry lock is poisoned"))?;
        let now = Instant::now();
        Self::prune_locked(&mut records, now);
        let finished_order = self
            .next_finished_order
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |order| {
                order.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("transfer completion order is exhausted"))?;
        {
            let record = records
                .get_mut(progress.transfer_id.as_str())
                .context("transfer is not registered")?;
            Self::replace_progress(record, profile, progress)?;
            record.finished_at = Some(now);
            record.finished_order = Some(finished_order);
        }
        Self::enforce_finished_caps_locked(&mut records, profile);
        Ok(())
    }

    fn snapshots(
        &self,
        profile: &str,
        transfer_id: Option<&ipc::TransferId>,
        operation_context_id: Option<&ipc::OperationContextId>,
        enforce_context_discovery: bool,
    ) -> Result<Vec<ipc::TransferProgress>> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("transfer registry lock is poisoned"))?;
        Self::prune_locked(&mut records, Instant::now());
        let mut snapshots = Vec::new();
        for record in records.values_mut().filter(|record| {
            record.profile == profile
                && transfer_id.is_none_or(|id| id.as_str() == record.progress.transfer_id.as_str())
        }) {
            if record.progress.operation_context_id.is_some() {
                match operation_context_id {
                    Some(expected) => ensure!(
                        record.progress.operation_context_id.as_ref() == Some(expected),
                        "transfer operation context does not match this daemon instance and object"
                    ),
                    None if enforce_context_discovery && record.context_discovered => {
                        bail!("transfer operation context is required after initial discovery")
                    }
                    None if enforce_context_discovery => record.context_discovered = true,
                    None => {}
                }
            }
            snapshots.push(record.progress.clone());
        }
        snapshots.sort_by(|left, right| left.transfer_id.as_str().cmp(right.transfer_id.as_str()));
        ensure!(
            operation_context_id.is_none() || snapshots.len() == 1,
            "transfer operation context does not match this daemon instance and object"
        );
        let frame = ipc::Frame::TransferStatusInfo {
            transfers: snapshots.clone(),
        };
        ipc::encoded_frame_len_limited(&frame, ipc::MAX_CONTROL_FRAME - 1)
            .context("transfer status snapshot exceeds the control-frame bound")?;
        Ok(snapshots)
    }

    fn cancel(
        &self,
        profile: &str,
        transfer_id: &ipc::TransferId,
        operation_context_id: Option<&ipc::OperationContextId>,
    ) -> Result<ipc::TransferProgress> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("transfer registry lock is poisoned"))?;
        let record = records
            .get(transfer_id.as_str())
            .context("transfer was not found for this profile")?;
        ensure!(
            record.profile == profile,
            "transfer was not found for this profile"
        );
        if let Some(expected) = operation_context_id {
            ensure!(
                record.progress.operation_context_id.as_ref() == Some(expected),
                "transfer operation context does not match this daemon instance and object"
            );
        }
        ensure!(record.finished_at.is_none(), "transfer is no longer active");
        record.cancellation.cancel();
        let record = records
            .get_mut(transfer_id.as_str())
            .context("transfer disappeared during cancellation")?;
        record.progress.revision = record
            .progress
            .revision
            .checked_add(1)
            .context("transfer revision is exhausted")?;
        record.progress.event = "cancel_requested".to_owned();
        record.progress.updated_unix_ms = now_unix_ms();
        Ok(record.progress.clone())
    }
}

struct OperationContextKey(Zeroizing<[u8; 32]>);

#[derive(Clone, Copy)]
struct OperationContextBinding {
    instance_id: InstanceId,
    grant_id: [u8; 16],
    request_id: [u8; 16],
    profile: vault::ProfileIdentity,
    root_request_hash: [u8; 32],
}

impl OperationContextKey {
    fn random() -> Self {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(&mut *bytes);
        Self(bytes)
    }

    fn derive(
        &self,
        binding: OperationContextBinding,
        transport_attempt_id: &str,
        object_id: &str,
        action: &str,
    ) -> Result<ipc::OperationContextId> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .map_err(|_| anyhow::anyhow!("initialize operation context HMAC"))?;
        mac.update(b"serctl/operation-context/hmac-sha256/v1\0");
        mac.update(&binding.instance_id.0);
        mac.update(&binding.grant_id);
        mac.update(&binding.request_id);
        mac.update(&binding.profile.profile_id);
        mac.update(&binding.profile.generation.to_be_bytes());
        mac.update(&binding.root_request_hash);
        for value in [
            transport_attempt_id.as_bytes(),
            object_id.as_bytes(),
            action.as_bytes(),
        ] {
            mac.update(&(value.len() as u64).to_be_bytes());
            mac.update(value);
        }
        ipc::OperationContextId::parse(&hex::encode(mac.finalize().into_bytes()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedTunnelOwner {
    profile_id: [u8; 16],
    generation: u64,
}

struct ManagedTunnelRecord {
    owner: ManagedTunnelOwner,
    status: ipc::TunnelStatus,
    cancellation: CancellationToken,
    completion: Arc<Notify>,
    finished_at: Option<Instant>,
    finished_order: Option<usize>,
    context_discovered: bool,
    _idle_guard: Option<IdleGuard>,
    _profile_entry: Option<Arc<ProfilePoolEntry>>,
}

#[derive(Default)]
struct ManagedTunnelRegistry {
    records: StdMutex<HashMap<String, ManagedTunnelRecord>>,
    next_finished_order: AtomicUsize,
}

impl ManagedTunnelRegistry {
    fn prune_locked(records: &mut HashMap<String, ManagedTunnelRecord>, now: Instant) {
        records.retain(|_, record| {
            record.finished_at.is_none_or(|finished| {
                now.saturating_duration_since(finished) < MANAGED_TUNNEL_RECORD_RETENTION
            })
        });
    }

    fn remove_oldest_finished_locked(
        records: &mut HashMap<String, ManagedTunnelRecord>,
        owner: Option<&ManagedTunnelOwner>,
    ) -> bool {
        let oldest = records
            .iter()
            .filter(|(_, record)| {
                record.finished_at.is_some() && owner.is_none_or(|owner| record.owner == *owner)
            })
            .min_by(|(left_id, left), (right_id, right)| {
                left.finished_order
                    .cmp(&right.finished_order)
                    .then_with(|| left_id.cmp(right_id))
            })
            .map(|(id, _)| id.clone());
        oldest.is_some_and(|id| records.remove(&id).is_some())
    }

    fn enforce_finished_caps_locked(
        records: &mut HashMap<String, ManagedTunnelRecord>,
        owner: &ManagedTunnelOwner,
    ) {
        while records
            .values()
            .filter(|record| record.owner == *owner && record.finished_at.is_some())
            .count()
            > MAX_COMPLETED_MANAGED_TUNNELS_PER_PROFILE
        {
            if !Self::remove_oldest_finished_locked(records, Some(owner)) {
                break;
            }
        }
        while records
            .values()
            .filter(|record| record.finished_at.is_some())
            .count()
            > MAX_COMPLETED_MANAGED_TUNNELS_GLOBAL
        {
            if !Self::remove_oldest_finished_locked(records, None) {
                break;
            }
        }
    }

    fn begin(
        &self,
        owner: ManagedTunnelOwner,
        status: ipc::TunnelStatus,
        cancellation: CancellationToken,
        idle_guard: IdleGuard,
        profile_entry: Option<Arc<ProfilePoolEntry>>,
    ) -> Result<Arc<Notify>> {
        status.validate()?;
        ensure!(
            status.profile_id == hex::encode(owner.profile_id)
                && status.profile_generation == owner.generation,
            "tunnel status identity does not match its owner"
        );
        ensure!(
            status.stage == ipc::TunnelStage::Ready,
            "new tunnel must enter the registry ready"
        );
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("managed tunnel registry lock is poisoned"))?;
        Self::prune_locked(&mut records, Instant::now());
        ensure!(
            records
                .values()
                .filter(|record| record.finished_at.is_none())
                .count()
                < MAX_ACTIVE_MANAGED_TUNNELS_GLOBAL,
            "global active tunnel capacity is exhausted"
        );
        ensure!(
            records
                .values()
                .filter(|record| record.owner == owner && record.finished_at.is_none())
                .count()
                < MAX_ACTIVE_MANAGED_TUNNELS_PER_PROFILE,
            "profile active tunnel capacity is exhausted"
        );
        ensure!(
            !records.contains_key(status.tunnel_id.as_str()),
            "tunnel id is already registered"
        );
        let completion = Arc::new(Notify::new());
        records.insert(
            status.tunnel_id.as_str().to_owned(),
            ManagedTunnelRecord {
                owner,
                status,
                cancellation,
                completion: Arc::clone(&completion),
                finished_at: None,
                finished_order: None,
                context_discovered: false,
                _idle_guard: Some(idle_guard),
                _profile_entry: profile_entry,
            },
        );
        Ok(completion)
    }

    fn finish_worker(
        &self,
        owner: &ManagedTunnelOwner,
        tunnel_id: &ipc::TunnelId,
        stage: ipc::TunnelStage,
    ) -> Result<()> {
        ensure!(
            matches!(stage, ipc::TunnelStage::Closed | ipc::TunnelStage::Unknown),
            "managed tunnel terminal stage is invalid"
        );
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("managed tunnel registry lock is poisoned"))?;
        let now = Instant::now();
        Self::prune_locked(&mut records, now);
        let finished_order = self
            .next_finished_order
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |order| {
                order.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("managed tunnel completion order is exhausted"))?;
        let completion = {
            let record = records
                .get_mut(tunnel_id.as_str())
                .context("tunnel is not registered")?;
            ensure!(
                record.owner == *owner,
                "tunnel was not found for this profile"
            );
            if record.finished_at.is_some() {
                return Ok(());
            }
            record.status.stage = stage;
            record.status.updated_unix_ms = now_unix_ms();
            if record.status.operation_context_id.is_some() {
                record.status.revision = record
                    .status
                    .revision
                    .checked_add(1)
                    .context("managed tunnel revision is exhausted")?;
            }
            record.finished_at = Some(now);
            record.finished_order = Some(finished_order);
            record._idle_guard.take();
            Arc::clone(&record.completion)
        };
        Self::enforce_finished_caps_locked(&mut records, owner);
        completion.notify_waiters();
        Ok(())
    }

    fn snapshots(
        &self,
        owner: &ManagedTunnelOwner,
        tunnel_id: Option<&ipc::TunnelId>,
        operation_context_id: Option<&ipc::OperationContextId>,
        enforce_context_discovery: bool,
    ) -> Result<Vec<ipc::TunnelStatus>> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("managed tunnel registry lock is poisoned"))?;
        Self::prune_locked(&mut records, Instant::now());
        let mut snapshots = Vec::new();
        for record in records.values_mut().filter(|record| {
            record.owner == *owner
                && tunnel_id.is_none_or(|id| id.as_str() == record.status.tunnel_id.as_str())
        }) {
            if record.status.operation_context_id.is_some() {
                match operation_context_id {
                    Some(expected) => ensure!(
                        record.status.operation_context_id.as_ref() == Some(expected),
                        "managed tunnel operation context does not match this daemon instance and object"
                    ),
                    None if enforce_context_discovery && record.context_discovered => {
                        bail!("managed tunnel operation context is required after initial discovery")
                    }
                    None if enforce_context_discovery => record.context_discovered = true,
                    None => {}
                }
            }
            snapshots.push(record.status.clone());
        }
        snapshots.sort_by(|left, right| left.tunnel_id.as_str().cmp(right.tunnel_id.as_str()));
        ensure!(
            operation_context_id.is_none() || snapshots.len() == 1,
            "managed tunnel operation context does not match this daemon instance and object"
        );
        ipc::encoded_frame_len_limited(
            &ipc::Frame::ManagedTunnelStatusInfo {
                tunnels: snapshots.clone(),
            },
            ipc::MAX_CONTROL_FRAME - 1,
        )
        .context("managed tunnel status snapshot exceeds the control-frame bound")?;
        Ok(snapshots)
    }

    fn request_cancel(
        &self,
        owner: &ManagedTunnelOwner,
        tunnel_id: &ipc::TunnelId,
        operation_context_id: Option<&ipc::OperationContextId>,
    ) -> Result<(ipc::TunnelStatus, Arc<Notify>)> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("managed tunnel registry lock is poisoned"))?;
        let record = records
            .get_mut(tunnel_id.as_str())
            .context("tunnel was not found for this profile")?;
        ensure!(
            record.owner == *owner,
            "tunnel was not found for this profile"
        );
        if record.status.operation_context_id.is_some() {
            let expected = operation_context_id
                .context("managed tunnel operation context is required for cancellation")?;
            ensure!(
                record.status.operation_context_id.as_ref() == Some(expected),
                "managed tunnel operation context does not match this daemon instance and object"
            );
        }
        if record.finished_at.is_none() && record.status.stage != ipc::TunnelStage::Cancelling {
            record.status.stage = ipc::TunnelStage::Cancelling;
            record.status.updated_unix_ms = now_unix_ms();
            if record.status.operation_context_id.is_some() {
                record.status.revision = record
                    .status
                    .revision
                    .checked_add(1)
                    .context("managed tunnel revision is exhausted")?;
            }
            record.cancellation.cancel();
        }
        Ok((record.status.clone(), Arc::clone(&record.completion)))
    }

    async fn cancel_and_wait(
        &self,
        owner: &ManagedTunnelOwner,
        tunnel_id: &ipc::TunnelId,
        operation_context_id: Option<&ipc::OperationContextId>,
        deadline: Instant,
    ) -> Result<ipc::TunnelStatus> {
        let (initial, completion) = self.request_cancel(owner, tunnel_id, operation_context_id)?;
        if matches!(
            initial.stage,
            ipc::TunnelStage::Closed | ipc::TunnelStage::Unknown
        ) {
            return Ok(initial);
        }
        loop {
            let notified = completion.notified();
            let current = self
                .snapshots(owner, Some(tunnel_id), operation_context_id, false)?
                .into_iter()
                .next()
                .context("tunnel was not found for this profile")?;
            if matches!(
                current.stage,
                ipc::TunnelStage::Closed | ipc::TunnelStage::Unknown
            ) {
                return Ok(current);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                self.finish_worker(owner, tunnel_id, ipc::TunnelStage::Unknown)?;
                return self
                    .snapshots(owner, Some(tunnel_id), operation_context_id, false)?
                    .into_iter()
                    .next()
                    .context("tunnel was not found for this profile");
            }
        }
    }

    async fn shutdown_all(&self, deadline: Instant) {
        let active = match self.records.lock() {
            Ok(mut records) => {
                Self::prune_locked(&mut records, Instant::now());
                records
                    .values_mut()
                    .filter(|record| record.finished_at.is_none())
                    .map(|record| {
                        record.status.stage = ipc::TunnelStage::Cancelling;
                        record.status.updated_unix_ms = now_unix_ms();
                        if record.status.operation_context_id.is_some() {
                            record.status.revision = record.status.revision.saturating_add(1);
                        }
                        record.cancellation.cancel();
                        (
                            record.owner.clone(),
                            record.status.tunnel_id.clone(),
                            record.status.operation_context_id.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
            }
            Err(_) => return,
        };
        for (owner, tunnel_id, operation_context_id) in active {
            if self
                .cancel_and_wait(&owner, &tunnel_id, operation_context_id.as_ref(), deadline)
                .await
                .is_err()
            {
                let _ = self.finish_worker(&owner, &tunnel_id, ipc::TunnelStage::Unknown);
            }
        }
    }
}

fn managed_tunnel_status(
    owner: &ManagedTunnelOwner,
    tunnel_id: ipc::TunnelId,
    spec: &ipc::TunnelSpec,
    ready: &ipc::TunnelReady,
    deadline_unix_ms: u64,
    operation_context_id: Option<ipc::OperationContextId>,
) -> Result<ipc::TunnelStatus> {
    ensure!(
        ready.mode == spec.mode(),
        "SSH tunnel readiness mode does not match the request"
    );
    let target_host = match spec.mode() {
        ipc::TunnelMode::Local | ipc::TunnelMode::Remote => Some("127.0.0.1".to_owned()),
        ipc::TunnelMode::Dynamic => None,
    };
    let status = ipc::TunnelStatus {
        schema_version: ipc::TUNNEL_STATUS_SCHEMA_VERSION,
        tunnel_id,
        profile_id: hex::encode(owner.profile_id),
        profile_generation: owner.generation,
        mode: ready.mode,
        bind_host: ready.bind_host.clone(),
        bind_port: ready.bind_port,
        target_host,
        target_port: spec.target_port,
        deadline_unix_ms,
        stage: ipc::TunnelStage::Ready,
        updated_unix_ms: now_unix_ms(),
        revision: u64::from(operation_context_id.is_some()),
        operation_context_id,
    };
    status.validate()?;
    Ok(status)
}

fn spawn_managed_tunnel_worker(
    registry: Arc<ManagedTunnelRegistry>,
    owner: ManagedTunnelOwner,
    tunnel_id: ipc::TunnelId,
    tunnel: RunningTunnel,
    deadline: Instant,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let cancellation = tunnel.cancellation_token();
        let wait = tunnel.wait();
        tokio::pin!(wait);
        let result = tokio::select! {
            result = &mut wait => result,
            _ = tokio::time::sleep_until(deadline) => {
                cancellation.cancel();
                wait.await
            }
            _ = shutdown.changed() => {
                cancellation.cancel();
                wait.await
            }
        };
        let stage = if result.is_ok() {
            ipc::TunnelStage::Closed
        } else {
            ipc::TunnelStage::Unknown
        };
        if let Err(error) = registry.finish_worker(&owner, &tunnel_id, stage) {
            log::warn!(
                "managed tunnel terminal registry update failed: {}",
                terminal_safe_error(&error)
            );
        }
    });
}

fn resolved_sftp_backend(requested: ipc::TransferBackend) -> Result<ipc::TransferBackend> {
    match requested {
        ipc::TransferBackend::Auto => Ok(ipc::TransferBackend::SftpFallback),
        ipc::TransferBackend::Sftp | ipc::TransferBackend::SftpFallback => {
            Ok(ipc::TransferBackend::Sftp)
        }
        ipc::TransferBackend::Native => {
            bail!("native transfer helper is unavailable; use --backend auto or sftp")
        }
    }
}

struct NativeTransferChannel {
    stream: russh::ChannelStream<russh::client::Msg>,
    chunk_bytes: u32,
    window_bytes: u32,
    resume: bool,
}

#[derive(Debug)]
struct NativeHelperUnavailable(anyhow::Error);

impl std::fmt::Display for NativeHelperUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native transfer helper is unavailable: {}",
            self.0
        )
    }
}

impl std::error::Error for NativeHelperUnavailable {}

fn expected_native_helper_identity(
    expected: &ipc::ExpectedNativeHelperIdentity,
) -> Result<native::HelperRuntimeIdentity> {
    expected.validate()?;
    let identity = native::HelperRuntimeIdentity {
        name: expected.name.clone(),
        binary_size: expected.binary_size,
        sha256: expected.sha256.clone(),
        version: expected.version.clone(),
    };
    identity.validate()?;
    Ok(identity)
}

fn negotiated_native_limits(max_chunk: u32, max_window: u32) -> Result<(u32, u32)> {
    let chunk_bytes = max_chunk
        .min(native::DEFAULT_CHUNK_BYTES)
        .min(ipc::NATIVE_IPC_CHUNK_BYTES as u32);
    let window_bytes = max_window.min(native::MAX_WINDOW_BYTES);
    ensure!(
        chunk_bytes > 0,
        "native helper advertised a zero chunk size"
    );
    ensure!(
        window_bytes >= chunk_bytes,
        "native helper window is smaller than one chunk"
    );
    Ok((chunk_bytes, window_bytes))
}

enum NegotiatedTransferBackend {
    Native(Box<NativeTransferChannel>),
    Sftp,
}

async fn open_native_transfer_channel(
    session: &SshSession,
    expected: &ipc::ExpectedNativeHelperIdentity,
    deadline: Instant,
) -> Result<NativeTransferChannel> {
    let stream = session
        .native_transfer_stream_until(deadline)
        .await
        .map_err(NativeHelperUnavailable)?;
    let (stream, chunk_bytes, window_bytes, resume) =
        negotiate_native_stream(stream, expected, deadline).await?;
    Ok(NativeTransferChannel {
        stream,
        chunk_bytes,
        window_bytes,
        resume,
    })
}

async fn negotiate_native_stream<S>(
    mut stream: S,
    expected: &ipc::ExpectedNativeHelperIdentity,
    deadline: Instant,
) -> Result<(S, u32, u32, bool)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let expected = expected_native_helper_identity(expected)?;
    let hello = tokio::time::timeout_at(deadline, native::read_frame(&mut stream))
        .await
        .map_err(|_| {
            NativeHelperUnavailable(anyhow::anyhow!(
                "native helper handshake exceeded its deadline"
            ))
        })??;
    let Some(native::Frame::Control(control)) = hello else {
        return Err(NativeHelperUnavailable(anyhow::anyhow!(
            "native helper closed before its identity hello"
        ))
        .into());
    };
    control.validate_handshake_sender(native::HandshakePeer::Helper)?;
    let native::Control::HelperHello {
        version,
        max_chunk,
        max_window,
        resume,
        sha256,
        fsync,
        no_replace,
        identity,
    } = control
    else {
        bail!("native helper did not send its server-only identity hello")
    };
    native::verify_expected_helper_identity(&identity, &expected)?;
    ensure!(version == native::VERSION, "native helper version mismatch");
    ensure!(
        sha256 && fsync && no_replace,
        "native helper lacks required integrity or commit features"
    );
    // SFTP's confirmed-WRITE cap does not apply to this independently framed
    // helper protocol. The native path uses a bounded 32 KiB IPC payload and
    // retains the separately negotiated receiver/durability window. Its
    // transfer loops still wait for the helper's cumulative ACK before
    // acknowledging the corresponding local IPC chunk.
    let (chunk_bytes, window_bytes) = negotiated_native_limits(max_chunk, max_window)?;
    native::write_handshake_control(
        &mut stream,
        &native::Control::Hello {
            version: native::VERSION,
            max_chunk: chunk_bytes,
            max_window: window_bytes,
            resume,
            sha256: true,
            fsync: true,
            no_replace: true,
        },
        native::HandshakePeer::Client,
    )
    .await
    .map_err(NativeHelperUnavailable)?;
    Ok((stream, chunk_bytes, window_bytes, resume))
}

async fn negotiate_transfer_backend(
    session: &SshSession,
    requested: ipc::TransferBackend,
    resume: ipc::TransferResumeMode,
    expected_helper_identity: Option<&ipc::ExpectedNativeHelperIdentity>,
    deadline: Instant,
) -> Result<(ipc::TransferBackend, NegotiatedTransferBackend)> {
    if should_probe_native_helper(requested, expected_helper_identity)? {
        let probe_deadline = if requested == ipc::TransferBackend::Auto {
            deadline.min(Instant::now() + Duration::from_secs(2))
        } else {
            deadline
        };
        match open_native_transfer_channel(
            session,
            expected_helper_identity.expect("identity presence checked above"),
            probe_deadline,
        )
        .await
        {
            Ok(channel) => {
                if resume == ipc::TransferResumeMode::Auto && !channel.resume {
                    bail!("native helper does not support resume=auto")
                }
                return Ok((
                    ipc::TransferBackend::Native,
                    NegotiatedTransferBackend::Native(Box::new(channel)),
                ));
            }
            Err(error)
                if requested == ipc::TransferBackend::Auto
                    && error.is::<NativeHelperUnavailable>() =>
            {
                log::debug!("native transfer probe fell back to SFTP: {error:#}");
            }
            Err(error) => return Err(error).context("native transfer helper is unavailable"),
        }
    }
    ensure!(
        resume == ipc::TransferResumeMode::Never,
        "resume=auto requires a compatible native transfer helper"
    );
    Ok((
        resolved_sftp_backend(requested)?,
        NegotiatedTransferBackend::Sftp,
    ))
}

fn should_probe_native_helper(
    requested: ipc::TransferBackend,
    expected: Option<&ipc::ExpectedNativeHelperIdentity>,
) -> Result<bool> {
    validate_expected_helper_for_backend(requested, expected)?;
    Ok(matches!(
        requested,
        ipc::TransferBackend::Auto | ipc::TransferBackend::Native
    ) && expected.is_some())
}

fn transfer_progress(
    transfer_id: ipc::TransferId,
    direction: ipc::TransferDirection,
    stage: ipc::TransferStage,
    total_bytes: u64,
    confirmed_bytes: u64,
    durable_bytes: u64,
    backend: ipc::TransferBackend,
) -> ipc::TransferProgress {
    let (chunk_bytes, window_bytes) = match backend {
        ipc::TransferBackend::Sftp | ipc::TransferBackend::SftpFallback => {
            let chunk = ipc::SFTP_SAFE_CHUNK_BYTES as u32;
            (chunk, chunk)
        }
        ipc::TransferBackend::Auto | ipc::TransferBackend::Native => (0, 0),
    };
    ipc::TransferProgress {
        schema_version: ipc::TRANSFER_PROGRESS_SCHEMA_VERSION,
        event: "progress".to_owned(),
        transfer_id,
        operation_context_id: None,
        revision: 0,
        direction,
        stage,
        total_bytes,
        confirmed_bytes,
        durable_bytes,
        window_bps: 0.0,
        average_bps: 0.0,
        eta_ms: None,
        backend,
        chunk_bytes,
        window_bytes,
        updated_unix_ms: now_unix_ms(),
    }
}

fn terminal_transfer_progress(
    mut progress: ipc::TransferProgress,
    stage: ipc::TransferStage,
    event: &str,
) -> ipc::TransferProgress {
    progress.stage = stage;
    progress.event = event.to_owned();
    progress.updated_unix_ms = now_unix_ms();
    progress
}

fn finish_transfer_setup(
    registry: &TransferRegistry,
    profile: &str,
    progress: ipc::TransferProgress,
    stage: ipc::TransferStage,
    event: &str,
) -> Result<()> {
    registry.finish(profile, terminal_transfer_progress(progress, stage, event))
}

fn is_transfer_stall_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string().to_ascii_lowercase();
        message.contains("timeout") || message.contains("deadline")
    })
}

fn terminal_safe_field(value: &str) -> String {
    value.escape_debug().to_string()
}

fn terminal_safe_display(value: &(impl fmt::Display + ?Sized)) -> String {
    terminal_safe_field(&value.to_string())
}

fn terminal_safe_error(error: &anyhow::Error) -> String {
    terminal_safe_field(&format!("{error:#}"))
}

fn exec_outcome_unknown_wire_message(error: anyhow::Error) -> String {
    ExecSubmissionState::RequestMayHaveReachedRemote
        .classify(error)
        .to_string()
}

fn exec_request_rejected_wire_message(error: anyhow::Error) -> String {
    error.to_string()
}

fn daemon_up_line(
    profile: &str,
    host: &str,
    ssh_port: u16,
    user: &str,
    endpoint_kind: &str,
    endpoint: &str,
) -> String {
    format!(
        "[serctl] daemon up: profile={}  {}:{ssh_port} as {}  ipc={}:{}  (Ctrl-C to stop)",
        terminal_safe_field(profile),
        terminal_safe_field(host),
        terminal_safe_field(user),
        terminal_safe_field(endpoint_kind),
        terminal_safe_field(endpoint),
    )
}

#[derive(Clone)]
struct ConnInfo {
    profile: String,
    profile_id: Option<[u8; 16]>,
    profile_generation: Option<u64>,
    host: String,
    user: String,
    started: i64,
    token: Arc<Zeroizing<String>>,
}

impl ConnInfo {
    fn transfer_owner_key(&self) -> String {
        self.profile_id.as_ref().map_or_else(
            || format!("legacy-name:{}", self.profile),
            |profile_id| {
                format!(
                    "profile-id:{}:generation:{}",
                    hex::encode(profile_id),
                    self.profile_generation.unwrap_or_default()
                )
            },
        )
    }

    fn managed_tunnel_owner(&self) -> Result<ManagedTunnelOwner> {
        Ok(ManagedTunnelOwner {
            profile_id: self
                .profile_id
                .context("managed tunnels require a generation-bound profile id")?,
            generation: self
                .profile_generation
                .context("managed tunnels require a generation-bound profile")?,
        })
    }
}

#[derive(Clone)]
struct HandlerContext {
    sessions: Arc<SessionManager>,
    info: ConnInfo,
    shutdown: watch::Sender<bool>,
    buffered_operation_slots: Arc<Semaphore>,
    tunnel_control_slots: Arc<Semaphore>,
    transfers: Arc<TransferRegistry>,
    managed_tunnels: Arc<ManagedTunnelRegistry>,
    idle: Arc<IdleTracker>,
    profile_entry: Option<Arc<ProfilePoolEntry>>,
    call_key: Arc<ProfileCallKey>,
    /// Hard upper bound for this root operation. Global-v6 handlers set it to
    /// the earliest credential/grant/request deadline; legacy v5 uses `None`.
    authorization_deadline: Option<Instant>,
}

fn status_info_frame(
    info: &ConnInfo,
    operation_context_id: Option<ipc::OperationContextId>,
    revision: u64,
) -> ipc::Frame {
    ipc::Frame::StatusInfo {
        profile: info.profile.clone(),
        host: info.host.clone(),
        user: info.user.clone(),
        started_unix: info.started,
        operation_context_id,
        revision,
    }
}

fn accepted_operation_context(
    session: &SshSession,
    object_id: &str,
    action: &str,
) -> Result<(Option<ipc::OperationContextId>, u64)> {
    let operation_context_id = match ACTIVE_GRANT_AUDIT.try_with(|audit| {
        audit.operation_context_id(
            session.connection_identity().transport_attempt_id(),
            object_id,
            action,
        )
    }) {
        Ok(result) => Some(result?),
        Err(_) => None,
    };
    let revision = u64::from(operation_context_id.is_some());
    Ok((operation_context_id, revision))
}

fn accepted_operation_context_without_ssh(
    object_id: &str,
    action: &str,
) -> Result<(Option<ipc::OperationContextId>, u64)> {
    let operation_context_id = match ACTIVE_GRANT_AUDIT
        .try_with(|audit| audit.operation_context_id("no-ssh-transport", object_id, action))
    {
        Ok(result) => Some(result?),
        Err(_) => None,
    };
    let revision = u64::from(operation_context_id.is_some());
    Ok((operation_context_id, revision))
}

fn connection_identity_frame(info: &ConnInfo, session: &SshSession) -> Result<ipc::Frame> {
    let snapshot = session.connection_identity();
    let (operation_context_id, revision) = accepted_operation_context(
        session,
        "authenticated-transport",
        "ssh.connection-identity/accepted",
    )?;
    let identity = ipc::SshConnectionIdentity {
        profile_id: info
            .profile_id
            .context("SSH connection identity requires a bound profile id")?,
        profile_generation: info
            .profile_generation
            .context("SSH connection identity requires a bound profile generation")?,
        observed_host_key_sha256: snapshot.observed_host_key_sha256().to_owned(),
        pin_match: snapshot.pin_match(),
        server_identification: snapshot.server_identification().to_owned(),
        transport_attempt_id: snapshot.transport_attempt_id().to_owned(),
        operation_context_id,
        revision,
    };
    identity.validate()?;
    Ok(ipc::Frame::ConnectionIdentityInfo { identity })
}

struct RuntimeLockGuard {
    cleanup: Option<RuntimeLockCleanup>,
}

struct RuntimeLockCleanup {
    profile: String,
    token: Arc<Zeroizing<String>>,
    lease: vault::ProfileLease,
}

struct PublishedRuntime {
    listener: Option<ipc::LocalListener>,
    lock_guard: Option<RuntimeLockGuard>,
    token: Arc<Zeroizing<String>>,
}

struct RuntimePublicationCleanup {
    listener: Option<ipc::LocalListener>,
    lock_guard: Option<RuntimeLockGuard>,
}

#[derive(Debug)]
struct IpcResponseWriteFailure(String);

impl fmt::Display for IpcResponseWriteFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for IpcResponseWriteFailure {}

/// Holds the current authenticated SSH session and serializes reconnects.
/// Operations clone the current Arc, so an in-flight request is never moved
/// out from under another request while a replacement connection is created.
struct SessionManager {
    creds: Creds,
    current: RwLock<Arc<SshSession>>,
    reconnect: Mutex<()>,
}

impl SessionManager {
    fn new(creds: Creds, session: SshSession) -> Self {
        Self {
            creds,
            current: RwLock::new(Arc::new(session)),
            reconnect: Mutex::new(()),
        }
    }

    async fn current_until(&self, deadline: Instant) -> Result<Arc<SshSession>> {
        let operation = async {
            let current = self.current.read().await.clone();
            if !current.is_closed() {
                return Ok(current);
            }

            // Multiple IPC requests may observe the disconnect together. Only
            // the first authenticates; dropping a timed-out/disconnected
            // request also drops this guard so other requests are not wedged.
            let _reconnect = self.reconnect.lock().await;
            let current = self.current.read().await.clone();
            if !current.is_closed() {
                return Ok(current);
            }

            let (replacement, _) =
                SshSession::connect_until(&self.creds, self.creds.host_key.clone(), deadline)
                    .await
                    .context("reconnect SSH session")?;
            let replacement = Arc::new(replacement);
            *self.current.write().await = replacement.clone();
            Ok(replacement)
        };

        match tokio::time::timeout_at(deadline, operation).await {
            Ok(result) => result,
            Err(_) => bail!("SSH reconnect exceeded the request deadline"),
        }
    }

    /// Acquire an exec channel before any command has been submitted. A russh
    /// channel-confirmation disconnect can race ahead of `Handle::is_closed()`;
    /// the core channel-open guard marks that exact Arc unusable, then this
    /// method reconnects under the original absolute deadline and retries the
    /// side-effect-free channel acquisition exactly once.
    async fn open_exec_until(
        &self,
        deadline: Instant,
    ) -> Result<(RunningCommand, Arc<SshSession>)> {
        let current = self.current_until(deadline).await?;
        match current.open_exec_until(deadline).await {
            Ok(command) => Ok((command, current)),
            Err(error) if is_ssh_transport_terminal_error(&error) => {
                ensure!(
                    deadline > Instant::now(),
                    "SSH reconnect exceeded the request deadline"
                );
                let replacement = self.current_until(deadline).await?;
                let command = replacement
                    .open_exec_until(deadline)
                    .await
                    .context("open exec channel after SSH reconnect")?;
                Ok((command, replacement))
            }
            Err(error) => Err(error),
        }
    }

    async fn invalidate_current(&self) {
        self.current.read().await.invalidate().await;
    }
}

impl Drop for RuntimeLockGuard {
    fn drop(&mut self) {
        let Some(cleanup) = self.cleanup.take() else {
            return;
        };
        // Future cancellation runs destructors on a Tokio worker. Never put
        // filesystem cleanup on that worker: a stuck local filesystem syscall
        // must not wedge the UI task that is aborting this daemon. The cleanup
        // value owns the lease until token-CAS removal has completed.
        if let Err(error) = std::thread::Builder::new()
            .name("serctl-lock-cleanup".into())
            .spawn(move || {
                if let Err(error) = cleanup.run() {
                    log::warn!("runtime-lock cleanup: {}", terminal_safe_error(&error));
                }
            })
        {
            // Thread creation failure drops `cleanup`, releasing the OS lease.
            // A subsequent startup can then reconcile the token-protected
            // stale record; it can never mistake this process for live.
            log::warn!(
                "could not start runtime-lock cleanup thread: {}",
                terminal_safe_display(&error)
            );
        }
    }
}

impl Drop for PublishedRuntime {
    fn drop(&mut self) {
        let cleanup = RuntimePublicationCleanup {
            listener: self.listener.take(),
            lock_guard: self.lock_guard.take(),
        };
        if cleanup.listener.is_none() && cleanup.lock_guard.is_none() {
            return;
        }
        // Unix listener Drop removes its socket and is itself filesystem I/O.
        // Keep both listener teardown and token-CAS lock cleanup off the async
        // worker that is canceling the daemon.
        if let Err(error) = std::thread::Builder::new()
            .name("serctl-publication-cleanup".into())
            .spawn(move || {
                if let Err(error) = cleanup.run() {
                    log::warn!(
                        "runtime-publication cleanup: {}",
                        terminal_safe_error(&error)
                    );
                }
            })
        {
            log::warn!(
                "could not start runtime-publication cleanup thread: {}",
                terminal_safe_display(&error)
            );
        }
    }
}

impl RuntimeLockCleanup {
    fn run(self) -> Result<()> {
        let remove = vault::remove_lock_if_token_while_leased(&self.profile, self.token.as_str());
        let unlock = self.lease.unlock().context("release daemon runtime lease");
        remove.context("remove daemon runtime lock")?;
        unlock?;
        Ok(())
    }
}

impl RuntimeLockGuard {
    fn new(profile: String, token: Arc<Zeroizing<String>>, lease: vault::ProfileLease) -> Self {
        Self {
            cleanup: Some(RuntimeLockCleanup {
                profile,
                token,
                lease,
            }),
        }
    }

    fn cleanup_blocking(mut self) -> Result<()> {
        self.cleanup
            .take()
            .expect("runtime-lock cleanup is missing")
            .run()
    }
}

impl RuntimePublicationCleanup {
    fn run(mut self) -> Result<()> {
        // Listener closure/removal precedes lock retirement, so no connection
        // can be accepted after the discoverable record disappears.
        drop(self.listener.take());
        match self.lock_guard.take() {
            Some(lock_guard) => lock_guard.cleanup_blocking(),
            None => Ok(()),
        }
    }
}

async fn await_owned_blocking_until<T, F>(
    deadline: Instant,
    operation: F,
    description: &'static str,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let mut task = tokio::task::spawn_blocking(operation);
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(result) => result.with_context(|| format!("join {description} worker"))?,
        Err(_) => {
            // Running spawn_blocking jobs cannot be preempted. Aborting the
            // JoinHandle marks a late owned result as canceled, so its Drop
            // performs cleanup on the blocking side instead of publishing a
            // listener/lock that no async daemon will ever service.
            task.abort();
            bail!("{description} exceeded its setup deadline")
        }
    }
}

async fn publish_runtime_until(
    profile: &str,
    lease: vault::ProfileLease,
    deadline: Instant,
) -> Result<PublishedRuntime> {
    let profile = profile.to_owned();
    await_owned_blocking_until(
        deadline,
        move || {
            if Instant::now() >= deadline {
                bail!("daemon runtime publication exceeded its setup deadline");
            }
            let token = Arc::new(Zeroizing::new(vault::new_ipc_token()));
            let endpoint = vault::expected_endpoint(&profile, token.as_str())?;
            let listener = ipc::LocalListener::bind(&endpoint)?;
            // The Unix socket is created with default permissions; harden it
            // immediately, before any lock record can name the endpoint.
            #[cfg(unix)]
            serctl_core::security::harden_file(std::path::Path::new(&endpoint))?;
            // A blocking bind that crossed the setup deadline must never write
            // a discoverable lock. Dropping the listener also removes its Unix
            // socket (or closes its Windows pipe handle).
            if Instant::now() >= deadline {
                bail!("daemon runtime publication exceeded its setup deadline");
            }
            let endpoint = listener.endpoint().to_owned();
            // Arm cleanup before the atomic write. Even a write that commits
            // and then reports an error remains paired with the exclusive
            // lease and token-CAS cleanup.
            let lock_guard = RuntimeLockGuard::new(profile.clone(), Arc::clone(&token), lease);
            let write_result = vault::write_lock(&LockInfo {
                profile,
                protocol: ipc::IPC_PROTOCOL_VERSION,
                pid: std::process::id(),
                port: 0,
                endpoint,
                // Endpoint/user data is returned only after authentication.
                host: String::new(),
                user: String::new(),
                started_unix: now_unix(),
                token: token.as_str().to_owned(),
            });
            if let Err(error) = write_result {
                drop(listener);
                return match lock_guard.cleanup_blocking() {
                    Ok(()) => Err(error).context("publish daemon runtime lock"),
                    Err(cleanup_error) => Err(anyhow::anyhow!(
                        "{error:#}; failed publication cleanup: {cleanup_error:#}"
                    )),
                };
            }
            if Instant::now() >= deadline {
                // We are already on a blocking worker, so complete cleanup
                // here before reporting timeout rather than leave a late lock.
                drop(listener);
                lock_guard.cleanup_blocking()?;
                bail!("daemon runtime publication exceeded its setup deadline");
            }
            Ok(PublishedRuntime {
                listener: Some(listener),
                lock_guard: Some(lock_guard),
                token,
            })
        },
        "daemon runtime publication",
    )
    .await
}

async fn cleanup_published_runtime(mut published: PublishedRuntime) {
    // Stop accepting before retiring the lock. The owned cleanup job keeps the
    // lease through token-CAS removal; timeout detaches that complete job.
    let cleanup = RuntimePublicationCleanup {
        listener: published.listener.take(),
        lock_guard: published.lock_guard.take(),
    };
    let mut task = tokio::task::spawn_blocking(move || cleanup.run());
    match tokio::time::timeout(RUNTIME_LOCK_CLEANUP_TIMEOUT, &mut task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            log::warn!("runtime-lock cleanup: {}", terminal_safe_error(&error))
        }
        Ok(Err(error)) => log::warn!(
            "runtime-lock cleanup worker: {}",
            terminal_safe_display(&error)
        ),
        Err(_) => {
            task.abort();
            log::warn!(
                "runtime-lock cleanup exceeded {} ms; detached owned cleanup remains active",
                RUNTIME_LOCK_CLEANUP_TIMEOUT.as_millis()
            );
        }
    }
}

fn handoff_readiness(ready: Option<oneshot::Sender<()>>) -> std::result::Result<(), ()> {
    match ready {
        Some(ready) => ready.send(()),
        None => Ok(()),
    }
}

pub async fn run(profile: &str, master: Zeroizing<String>) -> Result<()> {
    run_with_ready(profile, master, None).await
}

/// Run a daemon and optionally notify an embedding UI once the IPC listener is
/// ready. Shutdown is coordinated through the async loop, so an in-process
/// daemon never terminates the whole GUI process.
pub async fn run_with_ready(
    profile: &str,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
) -> Result<()> {
    run_with_ready_until(
        profile,
        master,
        ready,
        Instant::now() + CONTROL_SETUP_TIMEOUT,
    )
    .await
}

pub async fn run_with_ready_until(
    profile: &str,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    setup_deadline: Instant,
) -> Result<()> {
    run_with_ready_until_at_optional_generation(profile, master, ready, None, setup_deadline).await
}

/// Start an in-process daemon using a generation-bound UI authorization.
/// The generation check and credential/call-key unwrap happen in one vault
/// snapshot while the exclusive profile lease is held.
pub async fn run_with_ready_until_at_generation(
    profile: &str,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    expected_generation: vault::ProfileIdentity,
    setup_deadline: Instant,
) -> Result<()> {
    run_with_ready_until_at_optional_generation(
        profile,
        master,
        ready,
        Some(expected_generation),
        setup_deadline,
    )
    .await
}

async fn run_with_ready_until_at_optional_generation(
    profile: &str,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    expected_generation: Option<vault::ProfileIdentity>,
    setup_deadline: Instant,
) -> Result<()> {
    if setup_deadline <= Instant::now() {
        bail!("daemon startup exceeded its setup deadline");
    }
    // The exclusive profile lease must precede credential decryption. This
    // makes the credential snapshot and daemon lifetime one atomic use period
    // with respect to profile mutation. Both operations are synchronous and
    // may include vault-lock waiting/KDF work, so keep them off the async
    // runtime and bound vault-lock acquisition by the whole setup deadline.
    let profile_owned = profile.to_owned();
    let mut snapshot = tokio::task::spawn_blocking(move || {
        let lease = vault::acquire_runtime_lease(&profile_owned)?;
        let lock_timeout = setup_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("daemon credential snapshot exceeded its setup deadline")?;
        let (creds, call_key) = vault::decrypt_with_call_key_with_lock_timeout(
            &profile_owned,
            &master,
            expected_generation,
            lock_timeout,
        )?;
        Ok::<_, anyhow::Error>((creds, call_key, master, lease))
    });
    let (creds, call_key, master, lease) =
        match tokio::time::timeout_at(setup_deadline, &mut snapshot).await {
            Ok(result) => result.context("join daemon credential snapshot worker")??,
            Err(_) => {
                // `spawn_blocking` cannot preempt active filesystem/KDF work. The
                // worker retains the exclusive lease and Zeroizing master until
                // it finishes, so a late snapshot cannot race profile mutation.
                snapshot.abort();
                bail!("daemon credential snapshot exceeded its setup deadline")
            }
        };
    run_with_ready_and_lease(
        profile,
        creds,
        call_key,
        master,
        ready,
        lease,
        setup_deadline,
    )
    .await
}

/// Test entry point: run a daemon over already-decrypted credentials without
/// touching the vault. Kept unconditional so the CLI's cross-crate e2e suite
/// can drive the daemon in-process.
#[doc(hidden)]
pub async fn run_with_ready_creds_for_test(
    profile: &str,
    creds: Creds,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
) -> Result<()> {
    let setup_deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
    let profile_owned = profile.to_owned();
    let mut lease_task =
        tokio::task::spawn_blocking(move || vault::acquire_runtime_lease(&profile_owned));
    let lease = match tokio::time::timeout_at(setup_deadline, &mut lease_task).await {
        Ok(result) => result.context("join daemon test runtime-lease worker")??,
        Err(_) => {
            lease_task.abort();
            bail!("daemon runtime-lease acquisition exceeded its setup deadline")
        }
    };
    let profile_owned = profile.to_owned();
    let key_master = Zeroizing::new(master.as_str().to_owned());
    let mut key_task = tokio::task::spawn_blocking(move || {
        let lock_timeout = setup_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("daemon test call-key snapshot exceeded its setup deadline")?;
        vault::derive_profile_call_key_with_lock_timeout(
            &profile_owned,
            &key_master,
            None,
            lock_timeout,
        )
    });
    let call_key = match tokio::time::timeout_at(setup_deadline, &mut key_task).await {
        Ok(result) => result.context("join daemon test call-key snapshot worker")??,
        Err(_) => {
            key_task.abort();
            bail!("daemon test call-key snapshot exceeded its setup deadline")
        }
    };
    run_with_ready_and_lease(
        profile,
        creds,
        call_key,
        master,
        ready,
        lease,
        setup_deadline,
    )
    .await
}

fn recover_invalid_startup_lock_read<T, C, R>(
    read: Result<Option<T>>,
    cleanup: C,
    reread: R,
) -> Result<Option<T>>
where
    C: FnOnce() -> Result<bool>,
    R: FnOnce() -> Result<Option<T>>,
{
    match read {
        Ok(existing) => Ok(existing),
        Err(read_error) => match cleanup() {
            // A successfully removed hashed record may have shadowed a raw
            // legacy Unix lock. Startup already holds the exclusive lifetime
            // lease, but must still reread the full namespace and fail closed
            // on that legacy record rather than start a second daemon.
            Ok(true) => reread(),
            Ok(false) => Err(read_error
                .context("invalid runtime lock was not eligible for safe protocol-v5 recovery")),
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "{read_error:#}; malformed runtime-lock recovery failed: {cleanup_error:#}"
            )),
        },
    }
}

async fn run_with_ready_and_lease(
    profile: &str,
    creds: Creds,
    call_key: ProfileCallKey,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    lease: vault::ProfileLease,
    connect_deadline: Instant,
) -> Result<()> {
    let profile_owned = profile.to_owned();
    let mut lock_read = tokio::task::spawn_blocking(move || {
        let existing = recover_invalid_startup_lock_read(
            vault::read_lock(&profile_owned),
            || vault::remove_invalid_hashed_v5_lock_while_leased(&profile_owned),
            || vault::read_lock(&profile_owned),
        )?;
        Ok::<_, anyhow::Error>((lease, existing))
    });
    let (lease, existing) = match tokio::time::timeout_at(connect_deadline, &mut lock_read).await {
        Ok(result) => result.context("join daemon startup-lock read worker")??,
        Err(_) => {
            // A running worker retains the exclusive lifetime lease until its
            // bounded lock-file I/O completes. Aborting only prevents a queued
            // job from starting.
            lock_read.abort();
            bail!("daemon startup-lock read exceeded its setup deadline")
        }
    };
    if let Some(mut existing) = existing {
        if existing_daemon_is_live(&existing, connect_deadline).await? {
            bail!("a daemon is already running for '{profile}'");
        }
        let profile_owned = profile.to_owned();
        let expected_token = Zeroizing::new(std::mem::take(&mut existing.token));
        let mut stale_cleanup = tokio::task::spawn_blocking(move || {
            let removed =
                vault::remove_lock_if_token_while_leased(&profile_owned, &expected_token)?;
            Ok::<_, anyhow::Error>((lease, removed))
        });
        let (returned_lease, removed) =
            match tokio::time::timeout_at(connect_deadline, &mut stale_cleanup).await {
                Ok(result) => result.context("join daemon stale-lock cleanup worker")??,
                Err(_) => {
                    stale_cleanup.abort();
                    bail!("daemon stale-lock cleanup exceeded its setup deadline")
                }
            };
        if !removed {
            bail!("stale runtime lock changed while daemon startup held the profile lease");
        }
        // Rebind the same exclusive lease returned by the blocking cleanup so
        // it remains held through KEX, pin persistence, authentication, and
        // the complete daemon lifetime.
        let lease = returned_lease;
        return run_after_startup_lock_reconciliation(
            profile,
            creds,
            call_key,
            master,
            ready,
            lease,
            connect_deadline,
        )
        .await;
    }
    run_after_startup_lock_reconciliation(
        profile,
        creds,
        call_key,
        master,
        ready,
        lease,
        connect_deadline,
    )
    .await
}

async fn run_after_startup_lock_reconciliation(
    profile: &str,
    mut creds: Creds,
    call_key: ProfileCallKey,
    master: Zeroizing<String>,
    ready: Option<oneshot::Sender<()>>,
    lease: vault::ProfileLease,
    connect_deadline: Instant,
) -> Result<()> {
    let expect = creds.host_key.clone();
    let staged = SshSession::connect_key_exchange_until(&creds, expect, connect_deadline).await?;
    let fp = staged.observed_fingerprint().to_owned();
    let lease = if creds.host_key.is_none() {
        let profile_owned = profile.to_owned();
        let persisted_fp = fp.clone();
        let pin_master = Zeroizing::new(master.as_str().to_owned());
        let mut task = tokio::task::spawn_blocking(move || {
            let lock_timeout = connect_deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("daemon host-key pin persistence exceeded its setup deadline")?;
            vault::set_pinned_fp_with_lock_timeout(
                &profile_owned,
                persisted_fp,
                &pin_master,
                lock_timeout,
                &lease,
            )?;
            // Keep the exclusive runtime lease in the worker. If the async
            // setup deadline fires while a blocking filesystem/KDF operation
            // is already running, a late atomic pin cannot race profile
            // replacement or a second unpinned connection.
            Ok::<_, anyhow::Error>(lease)
        });
        let persisted = match tokio::time::timeout_at(connect_deadline, &mut task).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                staged.abort().await;
                return Err(error).context("join daemon host-key pin persistence worker");
            }
            Err(_) => {
                task.abort();
                staged.abort().await;
                bail!("daemon host-key pin persistence exceeded its setup deadline")
            }
        };
        let lease = match persisted {
            Ok(lease) => lease,
            Err(error) => {
                staged.abort().await;
                return Err(error);
            }
        };
        eprintln!("[serctl] pinned host key {}", terminal_safe_field(&fp));
        creds.host_key = Some(fp);
        lease
    } else {
        lease
    };
    let session = staged
        .authenticate_password_until(&creds.user, &creds.password, connect_deadline)
        .await?;
    // The master password is only needed to decrypt the profile and persist a
    // first-use host-key pin. Do not retain it for the daemon lifetime.
    drop(master);
    let call_key = Arc::new(call_key);
    let host = creds.host.clone();
    let user = creds.user.clone();
    let session = Arc::new(SessionManager::new(creds, session));

    let mut published = match publish_runtime_until(profile, lease, connect_deadline).await {
        Ok(published) => published,
        Err(error) => {
            // Authentication has already succeeded. Explicitly stop its
            // transport while a late blocking publisher cleans only local
            // resources; the publisher never owns or retains this session.
            session.invalidate_current().await;
            return Err(error);
        }
    };
    let token = Arc::clone(&published.token);
    let endpoint = published
        .listener
        .as_ref()
        .expect("published runtime listener is missing")
        .endpoint()
        .to_owned();
    if handoff_readiness(ready).is_err() {
        // The embedding caller abandoned startup before accepting ownership.
        // Do not leave a successfully published daemon behind.
        session.invalidate_current().await;
        cleanup_published_runtime(published).await;
        bail!("daemon readiness receiver disconnected before publication handoff");
    }

    eprintln!(
        "{}",
        daemon_up_line(
            profile,
            &host,
            session.creds.port,
            &user,
            ipc::endpoint_kind(),
            &endpoint,
        )
    );

    let info = ConnInfo {
        profile: profile.to_string(),
        profile_id: None,
        profile_generation: None,
        host,
        user,
        started: now_unix(),
        token,
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut daemon_shutdown = shutdown_rx.clone();
    let connection_slots = Arc::new(Semaphore::new(64));
    let buffered_operation_slots = Arc::new(Semaphore::new(BUFFERED_HEAVY_OPERATION_LIMIT));
    let tunnel_control_slots = Arc::new(Semaphore::new(TUNNEL_CONTROL_LIMIT));
    let transfers = Arc::new(TransferRegistry::default());
    let managed_tunnels = Arc::new(ManagedTunnelRegistry::default());
    let idle = Arc::new(IdleTracker::default());
    let mut handlers = JoinSet::new();

    let mut listener_error = None;
    loop {
        tokio::select! {
            res = published
                .listener
                .as_mut()
                .expect("published runtime listener is missing")
                .accept() => {
                let stream = match res {
                    Ok(stream) => stream,
                    Err(error) => {
                        listener_error = Some(error.context("accept local IPC connection"));
                        break;
                    }
                };
                let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
                    log::warn!("rejecting IPC connection: connection limit reached");
                    continue;
                };
                log::debug!("local IPC connection accepted");
                let handler_shutdown = shutdown_rx.clone();
                let context = HandlerContext {
                    sessions: session.clone(),
                    info: info.clone(),
                    shutdown: shutdown_tx.clone(),
                    buffered_operation_slots: Arc::clone(&buffered_operation_slots),
                    tunnel_control_slots: Arc::clone(&tunnel_control_slots),
                    transfers: Arc::clone(&transfers),
                    managed_tunnels: Arc::clone(&managed_tunnels),
                    idle: Arc::clone(&idle),
                    profile_entry: None,
                    call_key: Arc::clone(&call_key),
                    authorization_deadline: None,
                };
                handlers.spawn(async move {
                    let _permit = permit;
                    handle_conn(stream, handler_shutdown, context).await
                });
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[serctl] shutting down");
                break;
            }
            changed = daemon_shutdown.changed() => {
                if changed.is_ok() && *daemon_shutdown.borrow() {
                    eprintln!("[serctl] shutdown requested");
                    break;
                }
            }
            joined = handlers.join_next(), if !handlers.is_empty() => {
                log_handler_result(joined);
            }
        }
    }

    // Stop accepting first, then wake every live handler so it can explicitly
    // close remote channels before the daemon drops its runtime lock/session.
    let _ = shutdown_tx.send(true);
    let drained = tokio::time::timeout(HANDLER_SHUTDOWN_GRACE, async {
        while let Some(joined) = handlers.join_next().await {
            log_handler_result(Some(joined));
        }
    })
    .await;
    if drained.is_err() {
        log::warn!("IPC handlers did not stop within shutdown grace; aborting them");
        handlers.abort_all();
        while let Some(joined) = handlers.join_next().await {
            log_handler_result(Some(joined));
        }
    }
    session.invalidate_current().await;
    let result = match listener_error {
        Some(error) => Err(error),
        None => Ok(()),
    };
    cleanup_published_runtime(published).await;
    result
}

fn log_handler_result(joined: Option<Result<Result<()>, tokio::task::JoinError>>) {
    match joined {
        Some(Ok(Err(error))) => log::warn!("ipc handler: {}", terminal_safe_error(&error)),
        Some(Err(error)) if !error.is_cancelled() => {
            log::warn!("ipc handler task: {}", terminal_safe_display(&error))
        }
        _ => {}
    }
}

struct ZeroizingResponseFrame(ipc::Frame);

impl Drop for ZeroizingResponseFrame {
    fn drop(&mut self) {
        self.0.zeroize_sensitive();
    }
}

/// Bound every daemon-to-client response write independently, while also
/// preserving the request's absolute deadline. A client that stops reading
/// cannot retain a handler slot until the daemon-wide shutdown grace expires.
async fn write_frame_until<W>(
    writer: &mut W,
    frame: &ipc::Frame,
    request_deadline: Instant,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let active_audit = ACTIVE_GRANT_AUDIT.try_with(Arc::clone).ok();
    let replacement = match active_audit {
        Some(audit) => audit.before_terminal_frame(frame).await,
        None => None,
    };
    let replacement = replacement.map(ZeroizingResponseFrame);
    let frame = replacement
        .as_ref()
        .map_or(frame, |replacement| &replacement.0);
    if request_deadline <= Instant::now() {
        return Err(
            IpcResponseWriteFailure("IPC response write exceeded its deadline".into()).into(),
        );
    }
    let write_deadline = request_deadline.min(Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT);
    let max_frame = match frame {
        ipc::Frame::ShellOut { .. } | ipc::Frame::ShellClosed => ipc::MAX_SHELL_FRAME,
        ipc::Frame::Ack
        | ipc::Frame::TransferAck { .. }
        | ipc::Frame::TransferDone { .. }
        | ipc::Frame::TransferDigest { .. }
        | ipc::Frame::TransferProgress { .. }
        | ipc::Frame::TransferStatusInfo { .. }
        | ipc::Frame::TransferCancelAccepted { .. }
        | ipc::Frame::StatusInfo { .. }
        | ipc::Frame::TunnelReady { .. }
        | ipc::Frame::TunnelClosed
        | ipc::Frame::ManagedTunnelOpened { .. }
        | ipc::Frame::ManagedTunnelStatusInfo { .. }
        | ipc::Frame::ManagedTunnelTerminal { .. }
        | ipc::Frame::ConnectionIdentityInfo { .. }
        | ipc::Frame::Error { .. } => ipc::MAX_CONTROL_FRAME,
        _ => ipc::MAX_RESPONSE_FRAME,
    };
    match tokio::time::timeout_at(
        write_deadline,
        ipc::write_frame_limited(writer, frame, max_frame),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            Err(IpcResponseWriteFailure(format!("IPC response write failed: {error:#}")).into())
        }
        Err(_) => {
            Err(IpcResponseWriteFailure("IPC response write exceeded its deadline".into()).into())
        }
    }
}

const AUDIT_STATE_PENDING: usize = 0;
const AUDIT_STATE_FINALIZING: usize = 1;
const AUDIT_STATE_COMPLETE: usize = 2;
const AUDIT_STATE_FAILED: usize = 3;

tokio::task_local! {
    /// Present only while dispatching one authenticated Grant root request.
    /// The central response writer uses it to durably append the authoritative
    /// Outcome before releasing a terminal response to the client.
    static ACTIVE_GRANT_AUDIT: Arc<GrantAuditOperation>;
}

struct GrantAuditOperation {
    ledger: Arc<AuditLedger>,
    quarantined: Arc<AtomicBool>,
    profile: vault::ProfileIdentity,
    request_id: [u8; 16],
    operation_kind: String,
    policy_digest: String,
    intent_digest: String,
    instance_id: InstanceId,
    grant_id: [u8; 16],
    operation_context_key: Arc<OperationContextKey>,
    deadline: Instant,
    state: AtomicUsize,
}

struct AuditTerminal {
    decision: AuditDecision,
    reason_code: &'static str,
    result_material: Vec<u8>,
}

impl GrantAuditOperation {
    fn new(
        record: &GrantRecord,
        prelude: &V6RequestPrelude,
        deadline: Instant,
        instance_id: InstanceId,
        operation_context_key: Arc<OperationContextKey>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ledger: Arc::clone(&record.entry.authoritative_audit),
            quarantined: Arc::clone(&record.entry.quarantined),
            profile: record.entry.identity,
            request_id: prelude.request_id,
            operation_kind: prelude.operation_kind.clone(),
            policy_digest: record.policy_digest(),
            intent_digest: hex::encode(prelude.root_request_hash),
            instance_id,
            grant_id: record.grant.grant_id,
            operation_context_key,
            deadline,
            state: AtomicUsize::new(AUDIT_STATE_PENDING),
        })
    }

    fn operation_context_id(
        &self,
        transport_attempt_id: &str,
        object_id: &str,
        action: &str,
    ) -> Result<ipc::OperationContextId> {
        self.operation_context_key.derive(
            OperationContextBinding {
                instance_id: self.instance_id,
                grant_id: self.grant_id,
                request_id: self.request_id,
                profile: self.profile,
                root_request_hash: hex::decode(&self.intent_digest)
                    .context("decode retained root request commitment")?
                    .try_into()
                    .map_err(|_| {
                        anyhow::anyhow!("retained root request commitment length changed")
                    })?,
            },
            transport_attempt_id,
            object_id,
            action,
        )
    }

    fn event(
        &self,
        phase: AuditPhase,
        decision: AuditDecision,
        reason_code: &str,
        result_digest: Option<String>,
    ) -> AuditEvent {
        AuditEvent {
            profile_id: hex::encode(self.profile.profile_id),
            profile_generation: self.profile.generation,
            request_id: self.request_id,
            at_unix_ms: now_unix_ms(),
            operation_kind: self.operation_kind.clone(),
            phase,
            decision,
            policy_digest: self.policy_digest.clone(),
            intent_digest: self.intent_digest.clone(),
            result_digest,
            reason_code: reason_code.to_owned(),
        }
    }

    async fn append(&self, event: AuditEvent) -> Result<()> {
        ensure!(
            self.deadline > Instant::now(),
            "authoritative audit persistence deadline expired"
        );
        let ledger = Arc::clone(&self.ledger);
        let mut worker = tokio::task::spawn_blocking(move || ledger.append(&event).map(|_| ()));
        match tokio::time::timeout_at(self.deadline, &mut worker).await {
            Ok(result) => result.context("join authoritative audit persistence")?,
            Err(_) => {
                worker.abort();
                bail!("authoritative audit persistence exceeded its deadline")
            }
        }
    }

    async fn record_intent(&self) -> Result<()> {
        let result = self
            .append(self.event(
                AuditPhase::Intent,
                AuditDecision::Pending,
                "intent.recorded",
                None,
            ))
            .await;
        if result.is_err() {
            self.quarantined.store(true, Ordering::Release);
        }
        result.context("persist authoritative grant intent")
    }

    fn outcome_digest(&self, terminal: &AuditTerminal) -> String {
        let mut digest = Sha256::new();
        digest.update(b"serctl/audit/grant-result/v1\0");
        digest.update(self.intent_digest.as_bytes());
        digest.update(match terminal.decision {
            AuditDecision::Allowed => b"allowed".as_slice(),
            AuditDecision::Denied => b"denied".as_slice(),
            AuditDecision::Succeeded => b"succeeded".as_slice(),
            AuditDecision::Failed => b"failed".as_slice(),
            AuditDecision::Unknown => b"unknown".as_slice(),
            AuditDecision::Pending => b"pending".as_slice(),
        });
        digest.update(terminal.reason_code.as_bytes());
        digest.update((terminal.result_material.len() as u64).to_be_bytes());
        digest.update(&terminal.result_material);
        hex::encode(digest.finalize())
    }

    async fn record_outcome(&self, terminal: AuditTerminal) -> Result<()> {
        match self.state.compare_exchange(
            AUDIT_STATE_PENDING,
            AUDIT_STATE_FINALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(AUDIT_STATE_COMPLETE) => return Ok(()),
            Err(AUDIT_STATE_FAILED) => bail!("authoritative audit outcome persistence failed"),
            Err(_) => bail!("authoritative audit outcome is already being finalized"),
        }
        let result_digest = self.outcome_digest(&terminal);
        let result = self
            .append(self.event(
                AuditPhase::Outcome,
                terminal.decision,
                terminal.reason_code,
                Some(result_digest),
            ))
            .await;
        match result {
            Ok(()) => {
                self.state.store(AUDIT_STATE_COMPLETE, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.state.store(AUDIT_STATE_FAILED, Ordering::Release);
                self.quarantined.store(true, Ordering::Release);
                Err(error).context("persist authoritative grant outcome")
            }
        }
    }

    fn terminal_for_frame(&self, frame: &ipc::Frame) -> Option<AuditTerminal> {
        if let ipc::Frame::Error { msg } = frame {
            let normalized = msg.to_ascii_lowercase();
            let outcome_unknown = normalized.contains("outcome unknown")
                || normalized.contains("outcome is unknown")
                || normalized.contains("may have reached remote");
            return Some(AuditTerminal {
                decision: if outcome_unknown {
                    AuditDecision::Unknown
                } else {
                    AuditDecision::Failed
                },
                reason_code: if outcome_unknown {
                    "dispatch.outcome_unknown"
                } else {
                    "dispatch.failed"
                },
                result_material: Vec::new(),
            });
        }
        match (self.operation_kind.as_str(), frame) {
            ("ssh.exec", ipc::Frame::ExecExit { code: Some(0), .. }) => Some(AuditTerminal {
                decision: AuditDecision::Succeeded,
                reason_code: "dispatch.succeeded",
                result_material: 0_i32.to_be_bytes().to_vec(),
            }),
            (
                "ssh.exec",
                ipc::Frame::ExecExit {
                    code: Some(code), ..
                },
            ) => Some(AuditTerminal {
                decision: AuditDecision::Failed,
                reason_code: "dispatch.remote_failure",
                result_material: code.to_be_bytes().to_vec(),
            }),
            ("ssh.exec", ipc::Frame::ExecExit { code: None, .. }) => Some(AuditTerminal {
                decision: AuditDecision::Unknown,
                reason_code: "dispatch.outcome_unknown",
                result_material: Vec::new(),
            }),
            ("daemon.status", ipc::Frame::StatusInfo { .. })
            | ("ssh.connection-identity", ipc::Frame::ConnectionIdentityInfo { .. })
            | ("sftp.list", ipc::Frame::DirList { .. })
            | ("sftp.write", ipc::Frame::CreateDirAccepted { .. })
            | ("transfer.status", ipc::Frame::TransferStatusInfo { .. })
            | ("transfer.cancel", ipc::Frame::TransferCancelAccepted { .. })
            | ("forward.local/open", ipc::Frame::ManagedTunnelOpened { .. })
            | ("forward.remote/open", ipc::Frame::ManagedTunnelOpened { .. })
            | ("forward.dynamic/open", ipc::Frame::ManagedTunnelOpened { .. })
            | ("forward.status", ipc::Frame::ManagedTunnelStatusInfo { .. })
            | ("transfer.write", ipc::Frame::TransferDone { .. }) => Some(AuditTerminal {
                decision: AuditDecision::Succeeded,
                reason_code: "dispatch.succeeded",
                result_material: match frame {
                    ipc::Frame::TransferDone { bytes } => bytes.to_be_bytes().to_vec(),
                    _ => Vec::new(),
                },
            }),
            (
                "transfer.read",
                ipc::Frame::TransferProgress {
                    progress:
                        ipc::TransferProgress {
                            stage: ipc::TransferStage::Completed,
                            ..
                        },
                },
            ) => Some(AuditTerminal {
                decision: AuditDecision::Succeeded,
                reason_code: "dispatch.succeeded",
                result_material: match frame {
                    ipc::Frame::TransferProgress { progress } => {
                        progress.confirmed_bytes.to_be_bytes().to_vec()
                    }
                    _ => unreachable!("matched completed transfer progress"),
                },
            }),
            (
                "forward.cancel",
                ipc::Frame::ManagedTunnelTerminal {
                    status:
                        ipc::TunnelStatus {
                            stage: ipc::TunnelStage::Closed,
                            ..
                        },
                },
            ) => Some(AuditTerminal {
                decision: AuditDecision::Succeeded,
                reason_code: "dispatch.succeeded",
                result_material: Vec::new(),
            }),
            (
                "forward.cancel",
                ipc::Frame::ManagedTunnelTerminal {
                    status:
                        ipc::TunnelStatus {
                            stage: ipc::TunnelStage::Unknown,
                            ..
                        },
                },
            ) => Some(AuditTerminal {
                decision: AuditDecision::Unknown,
                reason_code: "dispatch.outcome_unknown",
                result_material: Vec::new(),
            }),
            _ => None,
        }
    }

    async fn before_terminal_frame(&self, frame: &ipc::Frame) -> Option<ipc::Frame> {
        let terminal = self.terminal_for_frame(frame)?;
        if self.record_outcome(terminal).await.is_ok() {
            None
        } else {
            Some(ipc::Frame::Error {
                msg: "operation outcome is unknown because authoritative audit persistence failed; profile quarantined".to_owned(),
            })
        }
    }

    async fn record_denied(&self, reason_code: &'static str) -> Result<()> {
        self.record_outcome(AuditTerminal {
            decision: AuditDecision::Denied,
            reason_code,
            result_material: Vec::new(),
        })
        .await
    }

    async fn finalize_unknown_if_pending(&self) -> Result<()> {
        match self.state.load(Ordering::Acquire) {
            AUDIT_STATE_PENDING => {
                self.record_outcome(AuditTerminal {
                    decision: AuditDecision::Unknown,
                    reason_code: "dispatch.no_terminal_result",
                    result_material: Vec::new(),
                })
                .await
            }
            AUDIT_STATE_COMPLETE => Ok(()),
            AUDIT_STATE_FAILED => bail!("authoritative audit outcome persistence failed"),
            AUDIT_STATE_FINALIZING => {
                self.state.store(AUDIT_STATE_FAILED, Ordering::Release);
                self.quarantined.store(true, Ordering::Release);
                bail!("authoritative audit outcome finalization was interrupted")
            }
            _ => bail!("authoritative audit state is invalid"),
        }
    }
}

fn operation_allowed_while_quarantined(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "daemon.status"
            | "ssh.connection-identity"
            | "sftp.list"
            | "transfer.read"
            | "transfer.status"
    ) || operation_kind.starts_with("audit.")
}

async fn write_frame_or_shutdown<W>(
    writer: &mut W,
    frame: &ipc::Frame,
    request_deadline: Instant,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if *shutdown.borrow() {
        return Err(IpcResponseWriteFailure(
            "daemon shutting down during IPC response write".into(),
        )
        .into());
    }
    tokio::select! {
        result = write_frame_until(writer, frame, request_deadline) => result,
        _ = shutdown.changed() => Err(IpcResponseWriteFailure(
            "daemon shutting down during IPC response write".into(),
        ).into()),
    }
}

async fn write_owned_frame_or_shutdown<W>(
    writer: &mut W,
    frame: ipc::Frame,
    request_deadline: Instant,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = ZeroizingResponseFrame(frame);
    write_frame_or_shutdown(writer, &frame.0, request_deadline, shutdown).await
}

async fn write_all_until_or_shutdown<W>(
    writer: &mut W,
    data: &[u8],
    write_deadline: Instant,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if *shutdown.borrow() {
        bail!("daemon shutting down during SSH shell input write");
    }
    if write_deadline <= Instant::now() {
        bail!("SSH shell input write exceeded its deadline");
    }
    tokio::select! {
        result = tokio::time::timeout_at(write_deadline, writer.write_all(data)) => match result {
            Ok(result) => result.context("write SSH shell input"),
            Err(_) => bail!("SSH shell input write exceeded its deadline"),
        },
        _ = shutdown.changed() => bail!("daemon shutting down during SSH shell input write"),
    }
}

async fn existing_daemon_is_live(lock: &LockInfo, setup_deadline: Instant) -> Result<bool> {
    let deadline = (Instant::now() + Duration::from_millis(800)).min(setup_deadline);
    if deadline <= Instant::now() {
        bail!("daemon startup exceeded its setup deadline");
    }
    let probe = async {
        serctl_core::vault::validate_endpoint(&lock.profile, &lock.token, &lock.endpoint)?;
        let mut stream = ipc::connect(&lock.endpoint).await?;
        ipc::validate_server_identity(&stream, lock.pid)?;
        ipc::authenticate_client(&mut stream, &lock.profile, &lock.token, deadline).await?;
        Ok::<bool, anyhow::Error>(true)
    };
    let result = matches!(tokio::time::timeout_at(deadline, probe).await, Ok(Ok(true)));
    if !result && Instant::now() >= setup_deadline {
        bail!("daemon startup exceeded its setup deadline");
    }
    Ok(result)
}

fn validate_request_frame(frame: &ipc::Frame) -> Result<()> {
    match frame {
        ipc::Frame::Exec { cmd, .. } => validate_remote_command(cmd)?,
        ipc::Frame::Shell { cols, rows } => validate_shell_dimensions(*cols, *rows)?,
        ipc::Frame::ShellInput { data } if data.len() > MAX_SHELL_INPUT_BYTES => {
            bail!("shell input exceeds {MAX_SHELL_INPUT_BYTES} bytes");
        }
        ipc::Frame::ListDir { path, .. } => validate_remote_path(path, true)?,
        ipc::Frame::CreateDir { path, .. } => validate_remote_path(path, false)?,
        ipc::Frame::ConnectionIdentity {
            profile_generation, ..
        } => ensure!(
            *profile_generation > 0,
            "SSH connection identity request generation must be positive"
        ),
        ipc::Frame::Download {
            path,
            local_target_sha256,
            backend,
            resume,
            resume_offset,
            expected_size,
            expected_sha256,
            expected_helper_identity,
            idle_timeout_ms,
            deadline_ms,
            ..
        } => {
            validate_remote_path(path, false)?;
            if let Some(commitment) = local_target_sha256 {
                ensure!(
                    commitment.len() == 64
                        && commitment
                            .bytes()
                            .all(|byte| { byte.is_ascii_digit() || matches!(byte, b'a'..=b'f') }),
                    "download local-target commitment must be 64 lowercase hex characters"
                );
            }
            validate_transfer_timeouts(*idle_timeout_ms, *deadline_ms)?;
            validate_expected_helper_for_backend(*backend, expected_helper_identity.as_deref())?;
            match (resume, resume_offset, expected_size, expected_sha256) {
                (ipc::TransferResumeMode::Never, 0, None, None) => {}
                (ipc::TransferResumeMode::Auto, 0, None, None) => {}
                (ipc::TransferResumeMode::Auto, offset, Some(size), Some(sha256))
                    if *offset <= *size
                        && sha256.len() == 64
                        && sha256
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')) => {}
                _ => bail!("download resume metadata is incomplete or inconsistent"),
            }
        }
        ipc::Frame::UploadBegin {
            path,
            size,
            sha256,
            backend,
            resume,
            resume_token,
            expected_helper_identity,
            idle_timeout_ms,
            deadline_ms,
            ..
        } => {
            validate_upload_remote_path(path)?;
            ensure!(
                sha256.len() == 64
                    && sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
                "upload SHA-256 must be 64 lowercase hex characters"
            );
            validate_transfer_timeouts(*idle_timeout_ms, *deadline_ms)?;
            validate_expected_helper_for_backend(*backend, expected_helper_identity.as_deref())?;
            match (resume, resume_token) {
                (ipc::TransferResumeMode::Never, None) => {}
                (ipc::TransferResumeMode::Auto, Some(token))
                    if token.len() == 64
                        && token
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')) => {}
                (ipc::TransferResumeMode::Never, Some(_)) => {
                    bail!("resume=never must not carry a resume token")
                }
                (ipc::TransferResumeMode::Auto, _) => {
                    bail!("resume=auto requires a 64-character ownership token")
                }
            }
            if *size > MAX_TRANSFER_BYTES {
                bail!(
                    "upload exceeds the {} byte safety limit",
                    MAX_TRANSFER_BYTES
                );
            }
        }
        ipc::Frame::UploadChunk { data } if data.len() > MAX_UPLOAD_CHUNK_BYTES => {
            bail!("upload chunk exceeds {MAX_UPLOAD_CHUNK_BYTES} bytes");
        }
        ipc::Frame::TunnelOpen { spec } => spec.validate()?,
        ipc::Frame::ManagedTunnelOpen {
            spec,
            deadline_unix_ms,
        } => {
            spec.validate()?;
            let now = now_unix_ms();
            ensure!(*deadline_unix_ms > now, "tunnel deadline has expired");
            ensure!(
                deadline_unix_ms.saturating_sub(now) <= ipc::MAX_EXEC_TIMEOUT_MS,
                "tunnel deadline is outside the supported range"
            );
        }
        _ => {}
    }
    Ok(())
}

fn validate_grant_frame_binding(frame: &ipc::Frame) -> Result<()> {
    if matches!(
        frame,
        ipc::Frame::Download {
            local_target_sha256: None,
            ..
        }
    ) {
        bail!("grant-authorized downloads require a local-target commitment");
    }
    if let ipc::Frame::TransferCancel {
        operation_context_id: None,
        ..
    } = frame
    {
        bail!("grant-authorized transfer cancellation requires an operation context id");
    }
    Ok(())
}

fn validate_connection_identity_binding(
    frame: &ipc::Frame,
    identity: vault::ProfileIdentity,
) -> Result<()> {
    if let ipc::Frame::ConnectionIdentity {
        profile_id,
        profile_generation,
    } = frame
    {
        ensure!(
            *profile_id == identity.profile_id && *profile_generation == identity.generation,
            "SSH connection identity request does not match the authorized profile generation"
        );
    }
    Ok(())
}

fn validate_expected_helper_for_backend(
    backend: ipc::TransferBackend,
    expected: Option<&ipc::ExpectedNativeHelperIdentity>,
) -> Result<()> {
    if let Some(expected) = expected {
        expected.validate()?;
    }
    match (backend, expected) {
        (ipc::TransferBackend::Native, None) => {
            bail!("backend=native requires an exact expected Linux helper identity")
        }
        (ipc::TransferBackend::Sftp | ipc::TransferBackend::SftpFallback, Some(_)) => {
            bail!("an expected native helper identity is invalid for an explicit SFTP backend")
        }
        _ => Ok(()),
    }
}

fn validate_transfer_timeouts(idle_timeout_ms: u64, deadline_ms: Option<u64>) -> Result<()> {
    ensure!(
        (1..=ipc::MAX_SFTP_TIMEOUT_MS).contains(&idle_timeout_ms),
        "transfer idle timeout is outside the supported range"
    );
    if let Some(deadline_ms) = deadline_ms {
        ensure!(
            (1..=ipc::MAX_SFTP_TIMEOUT_MS).contains(&deadline_ms),
            "transfer deadline is outside the supported range"
        );
    }
    Ok(())
}

async fn read_authenticated_request<R>(
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    idle_timeout: Duration,
) -> Result<Option<ipc::Frame>>
where
    R: AsyncRead + Unpin,
{
    let idle_deadline = Instant::now() + idle_timeout;
    tokio::select! {
        result = tokio::time::timeout_at(
            idle_deadline,
            ipc::read_frame_limited(reader, ipc::MAX_REQUEST_FRAME),
        ) => match result {
            Ok(result) => result,
            Err(_) => bail!("authenticated IPC connection exceeded its idle deadline"),
        },
        _ = shutdown.changed() => Ok(None),
    }
}

async fn authenticate_incoming_protocol<S>(
    stream: &mut S,
    profile: &str,
    token: &str,
    call_key: &ProfileCallKey,
    deadline: Instant,
) -> Result<ipc::AuthContext>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ipc::authenticate_server(stream, profile, token, call_key.as_bytes(), deadline).await
}

/// Exec and directory listing retain their complete result until it has been
/// serialized to IPC. Bound that aggregate independently from the connection
/// limit so many authenticated peers cannot retain hundreds of MiB at once.
/// Waiting for capacity is still part of the request's absolute deadline and
/// is cancelled immediately when its IPC peer or the daemon disappears.
async fn acquire_buffered_operation_slot<R>(
    slots: Arc<Semaphore>,
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<Option<OwnedSemaphorePermit>>
where
    R: AsyncRead + Unpin,
{
    if *shutdown.borrow() {
        return Ok(None);
    }
    tokio::select! {
        biased;
        _ = shutdown.changed() => Ok(None),
        _ = reader.read_u8() => Ok(None),
        result = tokio::time::timeout_at(deadline, slots.acquire_owned()) => match result {
            Ok(Ok(permit)) => Ok(Some(permit)),
            Ok(Err(_)) => bail!("buffered-operation capacity is unavailable"),
            Err(_) => bail!("waiting for buffered-operation capacity exceeded the request deadline"),
        },
    }
}

/// Tunnel control connections are long lived, so cap them independently from
/// short IPC handlers. A peer that disappears while waiting must not consume a
/// slot or reach SSH/listener setup.
async fn acquire_tunnel_control_slot<R>(
    slots: Arc<Semaphore>,
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<Option<OwnedSemaphorePermit>>
where
    R: AsyncRead + Unpin,
{
    if *shutdown.borrow() {
        return Ok(None);
    }
    tokio::select! {
        biased;
        _ = shutdown.changed() => Ok(None),
        _ = reader.read_u8() => Ok(None),
        result = tokio::time::timeout_at(deadline, slots.acquire_owned()) => match result {
            Ok(Ok(permit)) => Ok(Some(permit)),
            Ok(Err(_)) => bail!("tunnel-control capacity is unavailable"),
            Err(_) => bail!("waiting for tunnel-control capacity exceeded the setup deadline"),
        },
    }
}

async fn handle_conn<S>(
    mut stream: S,
    mut shutdown_rx: watch::Receiver<bool>,
    context: HandlerContext,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let HandlerContext {
        sessions,
        info,
        shutdown,
        buffered_operation_slots,
        tunnel_control_slots,
        transfers,
        managed_tunnels,
        idle,
        profile_entry,
        call_key,
        authorization_deadline,
    } = context;
    let authentication_deadline = Instant::now() + Duration::from_secs(2);
    let authentication = tokio::select! {
        result = authenticate_incoming_protocol(
            &mut stream,
            &info.profile,
            info.token.as_str(),
            &call_key,
            authentication_deadline,
        ) => result,
        _ = shutdown_rx.changed() => return Ok(()),
    };
    let mut auth_context = match authentication {
        Ok(context) => context,
        Err(error) => {
            // Authentication failures are intentionally indistinguishable to the
            // peer: close without sending a structured error oracle.
            log::warn!(
                "rejected local IPC authentication: {}",
                terminal_safe_error(&error)
            );
            return Ok(());
        }
    };
    let (mut rd, wr) = tokio::io::split(stream);
    let frame =
        read_authenticated_request(&mut rd, &mut shutdown_rx, POST_AUTH_IDLE_TIMEOUT).await?;
    let Some(mut frame) = frame else {
        return Ok(());
    };
    if let Err(error) = auth_context.verify_request(call_key.as_bytes(), &frame) {
        frame.zeroize_sensitive();
        // Authorization failures are deliberately closed without a
        // structured response. In particular, a mismatched intent must
        // not reach validation, SSH, or local listener setup.
        log::warn!(
            "rejected local IPC request authorization: {}",
            terminal_safe_error(&error)
        );
        return Ok(());
    }
    let context = HandlerContext {
        sessions,
        info,
        shutdown,
        buffered_operation_slots,
        tunnel_control_slots,
        transfers,
        managed_tunnels,
        idle,
        profile_entry,
        call_key,
        authorization_deadline,
    };
    dispatch_root_request(rd, wr, shutdown_rx, context, frame).await
}

/// Dispatch one authenticated, intent-verified root request. The root frame
/// is committed in the handshake (v5 intent commitment or v6 prelude hash);
/// every per-operation branch lives here so both wire generations share the
/// exact same execution semantics. One connection carries exactly one root
/// request: after this returns, the connection closes.
async fn dispatch_root_request<R, W>(
    rd: R,
    wr: W,
    shutdown_rx: watch::Receiver<bool>,
    context: HandlerContext,
    frame: ipc::Frame,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let authorization_deadline = context.authorization_deadline;
    let sessions = Arc::clone(&context.sessions);
    let operation = dispatch_root_request_inner(rd, wr, shutdown_rx, context, frame);
    match authorization_deadline {
        Some(deadline) => match tokio::time::timeout_at(deadline, operation).await {
            Ok(result) => result,
            Err(_) => {
                // A cancelled SFTP/SSH future can trip its transport slightly
                // after this outer authorization timer fires. Invalidate now
                // so a following request cannot race onto that ambiguous
                // session before the bounded stream reports closure.
                sessions.invalidate_current().await;
                bail!("profile authorization lease expired")
            }
        },
        None => operation.await,
    }
}

async fn dispatch_root_request_inner<R, W>(
    mut rd: R,
    mut wr: W,
    mut shutdown_rx: watch::Receiver<bool>,
    context: HandlerContext,
    mut frame: ipc::Frame,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let HandlerContext {
        sessions,
        info,
        shutdown,
        buffered_operation_slots,
        tunnel_control_slots,
        transfers,
        managed_tunnels,
        idle,
        profile_entry,
        call_key: _call_key,
        authorization_deadline,
    } = context;
    let transfer_owner = info.transfer_owner_key();
    if let Err(error) = validate_request_frame(&frame) {
        frame.zeroize_sensitive();
        write_owned_frame_or_shutdown(
            &mut wr,
            ipc::Frame::Error {
                msg: error.to_string(),
            },
            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
            &mut shutdown_rx,
        )
        .await?;
        return Ok(());
    }
    match frame {
        ipc::Frame::ConnectionIdentity {
            profile_id,
            profile_generation,
        } => {
            ensure!(
                info.profile_id == Some(profile_id)
                    && info.profile_generation == Some(profile_generation),
                "SSH connection identity request does not match the dispatch profile generation"
            );
            let deadline = authorization_deadline
                .context("SSH connection identity requires bounded authorization")?
                .min(Instant::now() + CONTROL_SETUP_TIMEOUT);
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
                    Ok(Some(session)) => session,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: terminal_safe_error(&error),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let response = connection_identity_frame(&info, &session)?;
            write_frame_or_shutdown(
                &mut wr,
                &response,
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
        }
        ipc::Frame::Exec { cmd, timeout_ms } => {
            let cmd = Zeroizing::new(cmd);
            let timeout = match validated_exec_timeout(timeout_ms) {
                Ok(timeout) => timeout,
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let deadline = Instant::now() + timeout;
            let _buffered_operation_permit = match acquire_buffered_operation_slot(
                Arc::clone(&buffered_operation_slots),
                &mut rd,
                &mut shutdown_rx,
                deadline,
            )
            .await
            {
                Ok(Some(permit)) => permit,
                Ok(None) => return Ok(()),
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let command = match tokio::select! {
                result = sessions.open_exec_until(deadline) => Some(result),
                _ = rd.read_u8() => None,
                _ = shutdown_rx.changed() => None,
            } {
                Some(Ok(command)) => command,
                None => return Ok(()),
                Some(Err(error)) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        deadline,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let (mut command, command_session) = command;
            let (operation_context_id, revision) = accepted_operation_context(
                &command_session,
                "remote-command",
                "ssh.exec/accepted",
            )?;
            let requested = tokio::select! {
                result = command.request_exec_until(cmd.as_str(), deadline) => Some(result),
                _ = rd.read_u8() => None,
                _ = shutdown_rx.changed() => None,
            };
            match requested {
                Some(Ok(())) => {}
                None => {
                    command.cancel().await;
                    return Ok(());
                }
                Some(Err(error)) => {
                    command.cancel().await;
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            // A failed/cancelled russh mpsc send never
                            // transfers ownership of the exec request.
                            msg: exec_request_rejected_wire_message(error),
                        },
                        deadline,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            }
            tokio::select! {
                result = tokio::time::timeout_at(deadline, command.finish()) => match result {
                    Ok(Ok(result)) => {
                        let code = result.code;
                        let stdout = ZeroizingResponseFrame(ipc::Frame::ExecOut {
                            data: result.stdout,
                        });
                        let stderr = ZeroizingResponseFrame(ipc::Frame::ExecErr {
                            data: result.stderr,
                        });
                        write_frame_or_shutdown(
                            &mut wr,
                            &stdout.0,
                            deadline,
                            &mut shutdown_rx,
                        ).await?;
                        write_frame_or_shutdown(
                            &mut wr,
                            &stderr.0,
                            deadline,
                            &mut shutdown_rx,
                        ).await?;
                        write_frame_or_shutdown(
                            &mut wr,
                            &ipc::Frame::ExecExit {
                                code,
                                operation_context_id,
                                revision,
                            },
                            deadline,
                            &mut shutdown_rx,
                        ).await?;
                    }
                    Ok(Err(error)) => {
                        command.cancel().await;
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: exec_outcome_unknown_wire_message(error),
                            },
                            deadline,
                            &mut shutdown_rx,
                        ).await?;
                    }
                    Err(_) => {
                        command.cancel().await;
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: exec_outcome_unknown_wire_message(anyhow::anyhow!(
                                    "remote command exceeded its deadline of {} ms",
                                    timeout.as_millis()
                                )),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        ).await?;
                    }
                },
                _ = rd.read_u8() => {
                    command.cancel().await;
                    return Ok(());
                }
                _ = shutdown_rx.changed() => {
                    command.cancel().await;
                    return Ok(());
                }
            }
        }
        ipc::Frame::Shell { cols, rows } => {
            let deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
                    Ok(Some(session)) => session,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let shell = tokio::select! {
                result = tokio::time::timeout_at(
                    deadline,
                    session.pty_shell("xterm-256color", cols, rows),
                ) => Some(result),
                _ = rd.read_u8() => None,
                _ = shutdown_rx.changed() => None,
            };
            let shell = match shell {
                Some(Ok(result)) => result,
                Some(Err(_)) => {
                    session.invalidate().await;
                    Err(anyhow::anyhow!("SSH shell setup exceeded its deadline"))
                }
                None => {
                    session.invalidate().await;
                    return Ok(());
                }
            };
            match shell {
                Ok(mut ch) => {
                    let mut writer = ch.make_writer();
                    let (shell_frame_tx, mut shell_frame_rx) = mpsc::channel(1);
                    let shell_frame_pump = read_shell_frame_pump(&mut rd, shell_frame_tx);
                    tokio::pin!(shell_frame_pump);
                    let mut shell_frame_pump_running = true;
                    let shell_result: Result<()> = async {
                            write_frame_or_shutdown(
                                &mut wr,
                                &ipc::Frame::Ack,
                                deadline,
                                &mut shutdown_rx,
                            )
                            .await?;
                            loop {
                                tokio::select! {
                                    biased;
                                    _ = shutdown_rx.changed() => break,
                                    frame = shell_frame_rx.recv() => match frame.map(ZeroizingShellFrameRead::into_inner) {
                                        Some(Ok(Some(ipc::Frame::ShellInput { data }))) => {
                                            let mut data = Zeroizing::new(data);
                                            if data.len() > MAX_SHELL_INPUT_BYTES {
                                                data.zeroize();
                                                bail!("shell input exceeds {MAX_SHELL_INPUT_BYTES} bytes");
                                            }
                                            let write = write_all_until_or_shutdown(
                                                &mut writer,
                                                &data,
                                                Instant::now() + SHELL_INPUT_WRITE_TIMEOUT,
                                                &mut shutdown_rx,
                                            ).await;
                                            data.zeroize();
                                            write?;
                                        }
                                        Some(Ok(Some(mut frame))) => {
                                            frame.zeroize_sensitive();
                                            bail!("unexpected frame during shell session")
                                        }
                                        Some(Ok(None)) | None => break,
                                        Some(Err(error)) => return Err(error),
                                    },
                                    () = &mut shell_frame_pump, if shell_frame_pump_running => {
                                        // The terminal EOF/error event is queued before
                                        // this future completes; consume it next.
                                        shell_frame_pump_running = false;
                                    },
                                    msg = ch.wait() => match msg {
                                        Some(ChannelMsg::Data { data }) => {
                                            let frame = ZeroizingResponseFrame(
                                                ipc::Frame::ShellOut { data: data.to_vec() }
                                            );
                                            write_frame_or_shutdown(
                                                &mut wr,
                                                &frame.0,
                                                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                                                &mut shutdown_rx,
                                            ).await?;
                                        }
                                        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                                            let frame = ZeroizingResponseFrame(
                                                ipc::Frame::ShellOut { data: data.to_vec() }
                                            );
                                            write_frame_or_shutdown(
                                                &mut wr,
                                                &frame.0,
                                                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                                                &mut shutdown_rx,
                                            ).await?;
                                        }
                                        Some(ChannelMsg::ExtendedData { ext, .. }) => {
                                            bail!("remote shell returned unsupported extended-data type {ext}");
                                        }
                                        Some(ChannelMsg::Eof) | None => {
                                            write_frame_or_shutdown(
                                                &mut wr,
                                                &ipc::Frame::ShellClosed,
                                                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                                                &mut shutdown_rx,
                                            ).await?;
                                            break;
                                        }
                                        _ => {}
                                    },
                                }
                            }
                            Ok(())
                        }
                        .await;
                    zeroize_pending_shell_frames(&mut shell_frame_rx);
                    drop(writer);
                    let _ = session.terminate_channel(&mut ch, true).await;
                    // Shell IPC connections are dedicated sessions. Once
                    // the remote channel ends (or shutdown/cancellation is
                    // observed), close the IPC handler instead of returning
                    // to the top-level frame loop with a consumed watch
                    // notification.
                    return shell_result;
                }
                Err(e) => {
                    session.invalidate().await;
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error { msg: e.to_string() },
                        deadline,
                        &mut shutdown_rx,
                    )
                    .await?;
                }
            }
        }
        ipc::Frame::Status => {
            let deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
            // Status is exact-intent call-key authorized before dispatch.
            // It still reports only daemon lifetime metadata and never
            // probes SSH health or reconnects with the retained password.
            let (operation_context_id, revision) = accepted_operation_context_without_ssh(
                "daemon-lifetime-metadata",
                "daemon.status/accepted",
            )?;
            write_owned_frame_or_shutdown(
                &mut wr,
                status_info_frame(&info, operation_context_id, revision),
                deadline,
                &mut shutdown_rx,
            )
            .await?;
        }
        ipc::Frame::TransferStatus {
            transfer_id,
            operation_context_id,
        } => {
            if operation_context_id.is_some() {
                ensure!(
                    transfer_id.is_some(),
                    "transfer context requires one transfer id"
                );
            }
            let snapshots = match transfers.snapshots(
                &transfer_owner,
                transfer_id.as_ref(),
                operation_context_id.as_ref(),
                ACTIVE_GRANT_AUDIT.try_with(|_| ()).is_ok(),
            ) {
                Ok(snapshots) => snapshots,
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            if transfer_id.is_some() && snapshots.is_empty() {
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error {
                        msg: "transfer outcome unknown: object is not registered in this daemon instance"
                            .to_owned(),
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await?;
                return Ok(());
            }
            write_owned_frame_or_shutdown(
                &mut wr,
                ipc::Frame::TransferStatusInfo {
                    transfers: snapshots,
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
        }
        ipc::Frame::TransferCancel {
            transfer_id,
            operation_context_id,
        } => match transfers.cancel(&transfer_owner, &transfer_id, operation_context_id.as_ref()) {
            Ok(progress) => {
                write_frame_or_shutdown(
                    &mut wr,
                    &ipc::Frame::TransferCancelAccepted { progress },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await?;
            }
            Err(error) => {
                let message = if error.to_string().contains("was not found") {
                    "transfer outcome unknown: object is not registered in this daemon instance"
                        .to_owned()
                } else {
                    error.to_string()
                };
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error { msg: message },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await?;
            }
        },
        ipc::Frame::ListDir { path, timeout_ms } => {
            let timeout = match validated_sftp_timeout(timeout_ms) {
                Ok(timeout) => timeout,
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let deadline = Instant::now() + timeout;
            let _buffered_operation_permit = match acquire_buffered_operation_slot(
                Arc::clone(&buffered_operation_slots),
                &mut rd,
                &mut shutdown_rx,
                deadline,
            )
            .await
            {
                Ok(Some(permit)) => permit,
                Ok(None) => return Ok(()),
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
                    Ok(Some(session)) => session,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let (operation_context_id, revision) =
                accepted_operation_context(&session, "directory-listing", "sftp.list/accepted")?;
            let result = match tokio::select! {
                result = session.list_dir_until(&path, deadline) => Some(result),
                _ = rd.read_u8() => None,
                _ = shutdown_rx.changed() => None,
            } {
                Some(result) => result,
                None => {
                    session.invalidate().await;
                    return Ok(());
                }
            };
            match result {
                Ok((path, entries)) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::DirList {
                            path,
                            entries,
                            operation_context_id,
                            revision,
                        },
                        deadline,
                        &mut shutdown_rx,
                    )
                    .await?;
                }
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        deadline,
                        &mut shutdown_rx,
                    )
                    .await?;
                }
            }
        }
        ipc::Frame::CreateDir { path, timeout_ms } => {
            let timeout = match validated_sftp_timeout(timeout_ms) {
                Ok(timeout) => timeout,
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let deadline = Instant::now() + timeout;
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
                    Ok(Some(session)) => session,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let (operation_context_id, revision) =
                accepted_operation_context(&session, &path, "sftp.write/create-dir/accepted")?;
            let result = match tokio::select! {
                result = session.create_dir_until(&path, deadline) => Some(result),
                _ = rd.read_u8() => None,
                _ = shutdown_rx.changed() => None,
            } {
                Some(result) => result,
                None => {
                    session.invalidate().await;
                    return Ok(());
                }
            };
            match result {
                Ok(()) => {
                    if operation_context_id.is_some() {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::CreateDirAccepted {
                                operation_context_id,
                                revision,
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                    } else {
                        write_frame_or_shutdown(
                            &mut wr,
                            &ipc::Frame::Ack,
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                    }
                }
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        deadline,
                        &mut shutdown_rx,
                    )
                    .await?;
                }
            }
        }
        ipc::Frame::Download {
            transfer_id,
            path,
            local_target_sha256: _,
            backend,
            resume,
            resume_offset,
            expected_size,
            expected_sha256,
            expected_helper_identity,
            idle_timeout_ms,
            deadline_ms,
        } => {
            let mut initial = transfer_progress(
                transfer_id.clone(),
                ipc::TransferDirection::Pull,
                ipc::TransferStage::Negotiating,
                0,
                0,
                0,
                backend,
            );
            let timeout =
                match validated_sftp_timeout(deadline_ms.unwrap_or(ipc::MAX_SFTP_TIMEOUT_MS)) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let deadline = Instant::now() + timeout;
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
                    Ok(Some(session)) => session,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            initial.operation_context_id = ACTIVE_GRANT_AUDIT
                .try_with(|audit| {
                    audit.operation_context_id(
                        session.connection_identity().transport_attempt_id(),
                        transfer_id.as_str(),
                        "transfer.read/accepted",
                    )
                })
                .ok()
                .transpose()?;
            initial.revision = u64::from(initial.operation_context_id.is_some());
            if initial.operation_context_id.is_some() {
                initial.event = "accepted".to_owned();
            }
            let cancellation = transfers.begin(&transfer_owner, initial.clone())?;
            if let Err(error) = write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::TransferProgress {
                    progress: initial.clone(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await
            {
                finish_transfer_setup(
                    &transfers,
                    &transfer_owner,
                    initial,
                    ipc::TransferStage::Failed,
                    "failed",
                )?;
                return Err(error);
            }
            let (actual_backend, negotiated) = match negotiate_transfer_backend(
                &session,
                backend,
                resume,
                expected_helper_identity.as_deref(),
                deadline.min(Instant::now() + Duration::from_millis(idle_timeout_ms)),
            )
            .await
            {
                Ok(negotiated) => negotiated,
                Err(error) => {
                    finish_transfer_setup(
                        &transfers,
                        &transfer_owner,
                        initial,
                        ipc::TransferStage::Failed,
                        "failed",
                    )?;
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            initial.backend = actual_backend;
            match &negotiated {
                NegotiatedTransferBackend::Native(channel) => {
                    initial.chunk_bytes = channel.chunk_bytes;
                    // Native transfer is currently one data frame per helper
                    // acknowledgement. Report the effective in-flight window,
                    // not the larger receiver/durability negotiation ceiling.
                    initial.window_bytes = channel.chunk_bytes;
                }
                NegotiatedTransferBackend::Sftp => {
                    initial.chunk_bytes = ipc::SFTP_SAFE_CHUNK_BYTES as u32;
                    initial.window_bytes = ipc::SFTP_SAFE_CHUNK_BYTES as u32;
                }
            }
            initial.updated_unix_ms = now_unix_ms();
            transfers.update(&transfer_owner, initial.clone())?;
            write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::TransferProgress {
                    progress: initial.clone(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
            let request = DownloadServeRequest {
                path: &path,
                resume_offset,
                expected_size,
                expected_sha256: expected_sha256.as_deref(),
                timeout_ms: idle_timeout_ms,
                idle_timeout: Duration::from_millis(idle_timeout_ms),
                deadline,
                registry: &transfers,
                profile: &transfer_owner,
                progress: initial,
                cancellation,
            };
            let result = match negotiated {
                NegotiatedTransferBackend::Native(channel) => {
                    serve_native_download(*channel, &mut rd, &mut wr, request, &mut shutdown_rx)
                        .await
                }
                NegotiatedTransferBackend::Sftp => {
                    serve_download(&session, &mut rd, &mut wr, request, &mut shutdown_rx).await
                }
            };
            if let Err(error) = result {
                // A timed-out/failed frame may already be partially
                // written. Close this IPC connection instead of appending
                // an Error frame to a now-ambiguous byte stream.
                if error.is::<IpcResponseWriteFailure>() {
                    return Err(error);
                }
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error {
                        msg: error.to_string(),
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await?;
            }
        }
        ipc::Frame::UploadBegin {
            transfer_id,
            path,
            size,
            sha256,
            backend,
            resume,
            resume_token,
            expected_helper_identity,
            idle_timeout_ms,
            deadline_ms,
        } => {
            let mut initial = transfer_progress(
                transfer_id,
                ipc::TransferDirection::Push,
                ipc::TransferStage::Negotiating,
                size,
                0,
                0,
                backend,
            );
            let timeout =
                match validated_sftp_timeout(deadline_ms.unwrap_or(ipc::MAX_SFTP_TIMEOUT_MS)) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let deadline = Instant::now() + timeout;
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
                    Ok(Some(session)) => session,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            deadline,
                            &mut shutdown_rx,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            initial.operation_context_id = ACTIVE_GRANT_AUDIT
                .try_with(|audit| {
                    audit.operation_context_id(
                        session.connection_identity().transport_attempt_id(),
                        initial.transfer_id.as_str(),
                        "transfer.write/accepted",
                    )
                })
                .ok()
                .transpose()?;
            initial.revision = u64::from(initial.operation_context_id.is_some());
            if initial.operation_context_id.is_some() {
                initial.event = "accepted".to_owned();
            }
            let cancellation = transfers.begin(&transfer_owner, initial.clone())?;
            if let Err(error) = write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::TransferProgress {
                    progress: initial.clone(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await
            {
                finish_transfer_setup(
                    &transfers,
                    &transfer_owner,
                    initial,
                    ipc::TransferStage::Failed,
                    "failed",
                )?;
                return Err(error);
            }
            let (actual_backend, negotiated) = match negotiate_transfer_backend(
                &session,
                backend,
                resume,
                expected_helper_identity.as_deref(),
                deadline.min(Instant::now() + Duration::from_millis(idle_timeout_ms)),
            )
            .await
            {
                Ok(negotiated) => negotiated,
                Err(error) => {
                    finish_transfer_setup(
                        &transfers,
                        &transfer_owner,
                        initial,
                        ipc::TransferStage::Failed,
                        "failed",
                    )?;
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            initial.backend = actual_backend;
            match &negotiated {
                NegotiatedTransferBackend::Native(channel) => {
                    initial.chunk_bytes = channel.chunk_bytes;
                    // Native transfer is currently one data frame per helper
                    // acknowledgement. Report the effective in-flight window,
                    // not the larger receiver/durability negotiation ceiling.
                    initial.window_bytes = channel.chunk_bytes;
                }
                NegotiatedTransferBackend::Sftp => {
                    initial.chunk_bytes = ipc::SFTP_SAFE_CHUNK_BYTES as u32;
                    initial.window_bytes = ipc::SFTP_SAFE_CHUNK_BYTES as u32;
                }
            }
            initial.updated_unix_ms = now_unix_ms();
            transfers.update(&transfer_owner, initial.clone())?;
            write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::TransferProgress {
                    progress: initial.clone(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
            let request = UploadRequest {
                path: &path,
                size,
                sha256: &sha256,
                resume,
                resume_token: resume_token.as_deref(),
                timeout_ms: idle_timeout_ms,
                idle_timeout: Duration::from_millis(idle_timeout_ms),
                deadline,
                registry: &transfers,
                profile: &transfer_owner,
                progress: initial,
                cancellation,
            };
            let upload = match negotiated {
                NegotiatedTransferBackend::Native(channel) => {
                    serve_native_upload(*channel, &mut rd, &mut wr, request, &mut shutdown_rx).await
                }
                NegotiatedTransferBackend::Sftp => {
                    serve_upload(&session, &mut rd, &mut wr, request, &mut shutdown_rx).await
                }
            };
            if let Err(error) = upload {
                // See the download path above: never reuse an IPC stream
                // after a response write may have stopped mid-frame.
                if error.is::<IpcResponseWriteFailure>() {
                    return Err(error);
                }
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error {
                        msg: error.to_string(),
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await?;
            }
            // Upload owns the remainder of this authenticated IPC
            // connection. Its frame reader can be cancelled after a
            // partial header/payload by a request deadline, daemon
            // shutdown, or a competing remote SFTP step. Closing the
            // connection after the terminal response prevents the outer
            // request loop from ever treating a partial upload frame as a
            // new request header.
            return Ok(());
        }
        ipc::Frame::ManagedTunnelOpen {
            spec,
            deadline_unix_ms,
        } => {
            let owner = info.managed_tunnel_owner()?;
            let setup_deadline = authorization_deadline
                .unwrap_or_else(|| Instant::now() + CONTROL_SETUP_TIMEOUT)
                .min(Instant::now() + CONTROL_SETUP_TIMEOUT);
            let _tunnel_control_permit = match acquire_tunnel_control_slot(
                Arc::clone(&tunnel_control_slots),
                &mut rd,
                &mut shutdown_rx,
                setup_deadline,
            )
            .await
            {
                Ok(Some(permit)) => permit,
                Ok(None) => return Ok(()),
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, setup_deadline)
                    .await
                {
                    Ok(Some(session)) => session,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: error.to_string(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let tunnel = match session.start_tunnel(spec.clone(), setup_deadline).await {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error {
                            msg: error.to_string(),
                        },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let tunnel_id = ipc::TunnelId::random();
            let action = match spec.mode() {
                ipc::TunnelMode::Local => "forward.local/open/accepted",
                ipc::TunnelMode::Remote => "forward.remote/open/accepted",
                ipc::TunnelMode::Dynamic => "forward.dynamic/open/accepted",
            };
            let (operation_context_id, _) =
                accepted_operation_context(&session, tunnel_id.as_str(), action)?;
            let status = managed_tunnel_status(
                &owner,
                tunnel_id.clone(),
                &spec,
                tunnel.ready(),
                deadline_unix_ms,
                operation_context_id,
            )?;
            let remaining_ms = deadline_unix_ms.saturating_sub(now_unix_ms()).max(1);
            let tunnel_deadline = Instant::now() + Duration::from_millis(remaining_ms);
            let cancellation = tunnel.cancellation_token();
            if let Err(error) = managed_tunnels.begin(
                owner.clone(),
                status.clone(),
                cancellation,
                idle.acquire(),
                profile_entry,
            ) {
                let cleanup = tunnel.stop().await;
                if cleanup.is_err() {
                    sessions.invalidate_current().await;
                }
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error {
                        msg: error.to_string(),
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await?;
                return Ok(());
            }
            spawn_managed_tunnel_worker(
                Arc::clone(&managed_tunnels),
                owner,
                tunnel_id,
                tunnel,
                tunnel_deadline,
                shutdown_rx.clone(),
            );
            write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::ManagedTunnelOpened { status },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
        }
        ipc::Frame::ManagedTunnelStatus {
            tunnel_id,
            operation_context_id,
        } => {
            let owner = info.managed_tunnel_owner()?;
            ensure!(
                operation_context_id.is_none() || tunnel_id.is_some(),
                "managed tunnel operation context requires an exact tunnel id"
            );
            let tunnels = managed_tunnels.snapshots(
                &owner,
                tunnel_id.as_ref(),
                operation_context_id.as_ref(),
                tunnel_id.is_some(),
            )?;
            if tunnel_id.is_some() && tunnels.is_empty() {
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error {
                        msg: "tunnel was not found for this profile".to_owned(),
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await?;
                return Ok(());
            }
            write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::ManagedTunnelStatusInfo { tunnels },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
        }
        ipc::Frame::ManagedTunnelCancel {
            tunnel_id,
            operation_context_id,
        } => {
            let owner = info.managed_tunnel_owner()?;
            let cancel_deadline = authorization_deadline
                .unwrap_or_else(|| Instant::now() + MANAGED_TUNNEL_CANCEL_TIMEOUT)
                .min(Instant::now() + MANAGED_TUNNEL_CANCEL_TIMEOUT);
            let status = managed_tunnels
                .cancel_and_wait(
                    &owner,
                    &tunnel_id,
                    operation_context_id.as_ref(),
                    cancel_deadline,
                )
                .await?;
            write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::ManagedTunnelTerminal { status },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
        }
        ipc::Frame::TunnelOpen { spec } => {
            let deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
            let _tunnel_control_permit = match acquire_tunnel_control_slot(
                Arc::clone(&tunnel_control_slots),
                &mut rd,
                &mut shutdown_rx,
                deadline,
            )
            .await
            {
                Ok(Some(permit)) => permit,
                Ok(None) => return Ok(()),
                Err(error) => {
                    write_tunnel_terminal(&mut wr, &mut shutdown_rx, Err(error)).await?;
                    return Ok(());
                }
            };
            let session =
                match current_or_disconnect(&sessions, &mut rd, &mut shutdown_rx, deadline).await {
                    Ok(Some(session)) => session,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        write_tunnel_terminal(&mut wr, &mut shutdown_rx, Err(error)).await?;
                        return Ok(());
                    }
                };
            // This dedicated IPC connection owns the complete tunnel
            // lifetime. EOF, TunnelStop, or daemon shutdown all cancel it
            // and wait for bounded SSH/listener cleanup.
            return serve_tunnel(session, &mut rd, &mut wr, spec, &mut shutdown_rx, deadline).await;
        }
        ipc::Frame::Shutdown { mut passphrase } => {
            passphrase.zeroize();
            write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::Ack,
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
            let _ = shutdown.send(true);
            return Ok(());
        }
        mut unexpected => {
            unexpected.zeroize_sensitive();
            write_owned_frame_or_shutdown(
                &mut wr,
                ipc::Frame::Error {
                    msg: "unexpected frame".into(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
        }
    }
    Ok(())
}

// ── Global per-user/per-vault daemon (IPC v6) ──────────────────────────────

/// Bounded credential lease: after this the profile's decrypted credentials
/// and its vault profile lease are released; a later operation must unlock
/// again. Mirrors the design's CredentialLease horizon (design §8.4).
const V6_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const GLOBAL_CONNECTION_LIMIT: usize = 64;
const GRANT_REGISTRY_LIMIT: usize = 1024;
const LEASE_REAPER_INTERVAL: Duration = Duration::from_secs(1);
static GRANT_AUDIT_LOCK: std::sync::LazyLock<StdMutex<()>> =
    std::sync::LazyLock::new(|| StdMutex::new(()));

struct ProfilePoolEntry {
    identity: vault::ProfileIdentity,
    conn_info: ConnInfo,
    sessions: Arc<SessionManager>,
    call_key: Arc<ProfileCallKey>,
    authoritative_audit: Arc<AuditLedger>,
    quarantined: Arc<AtomicBool>,
    expires_at: Instant,
    _lease: Arc<vault::ProfileLease>,
}

trait GrantProfileBinding {
    fn identity(&self) -> vault::ProfileIdentity;
    fn profile_name(&self) -> &str;
}

impl GrantProfileBinding for ProfilePoolEntry {
    fn identity(&self) -> vault::ProfileIdentity {
        self.identity
    }

    fn profile_name(&self) -> &str {
        &self.conn_info.profile
    }
}

#[derive(Default)]
struct ProfilePool {
    entries: StdMutex<HashMap<[u8; 16], Arc<ProfilePoolEntry>>>,
}

impl ProfilePool {
    /// Resolve a live credential lease for `profile_id`, dropping the stored
    /// entry (and therefore releasing its vault profile lease) once the
    /// credential lease expires. In-flight holders are independently wrapped
    /// by the same hard authorization deadline before dispatch.
    fn entry_for(&self, profile_id: &[u8; 16]) -> Option<Arc<ProfilePoolEntry>> {
        let mut entries = self.entries.lock().ok()?;
        let expired = entries
            .get(profile_id)
            .is_some_and(|entry| entry.expires_at <= Instant::now());
        if expired {
            entries.remove(profile_id);
        }
        entries.get(profile_id).cloned()
    }

    fn insert(&self, profile_id: [u8; 16], entry: ProfilePoolEntry) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(profile_id, Arc::new(entry));
        }
    }

    fn prune_expired(&self, now: Instant) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, entry| entry.expires_at > now);
        }
    }
}

/// Reference-counted live work: every accepted connection handler, every
/// long-running operation (tunnel, shell, transfer), and every unexpired grant
/// holds a guard for its lifetime. The broker exits only after the counter
/// stays at zero for the whole idle window, so idle exit can never interrupt
/// work in flight or discard a capability it issued while that capability is
/// still valid.
#[derive(Default)]
struct IdleTracker {
    work: AtomicUsize,
    changed: Notify,
}

struct IdleGuard {
    tracker: Arc<IdleTracker>,
}

impl IdleTracker {
    fn acquire(self: &Arc<Self>) -> IdleGuard {
        self.work.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_waiters();
        IdleGuard {
            tracker: Arc::clone(self),
        }
    }

    fn is_idle(&self) -> bool {
        self.work.load(Ordering::Acquire) == 0
    }

    /// Complete once the tracker has observed zero work for `timeout`
    /// continuously; a spurious wake re-arms the full window.
    async fn wait_for_idle_exit(self: &Arc<Self>, timeout: Duration) {
        loop {
            let notified = self.changed.notified();
            if self.is_idle() {
                let deadline = Instant::now() + timeout;
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    return;
                }
            } else {
                notified.await;
            }
        }
    }
}

impl Drop for IdleGuard {
    fn drop(&mut self) {
        self.tracker.work.fetch_sub(1, Ordering::AcqRel);
        self.tracker.changed.notify_waiters();
    }
}

/// Exact data-plane operation kinds accepted by the authenticated daemon.
/// Interactive shells and control operations (unlock, shutdown, grant issuance)
/// are never grantable. Tunnel scopes deliberately distinguish mode and
/// lifecycle action so one Grant cannot be replayed as a broader forward.
const GRANTABLE_OPERATION_KINDS: &[&str] = &[
    "ssh.exec",
    "ssh.connection-identity",
    "daemon.status",
    "sftp.list",
    "sftp.write",
    "transfer.read",
    "transfer.write",
    "transfer.status",
    "transfer.cancel",
    "forward.local/open",
    "forward.remote/open",
    "forward.dynamic/open",
    "forward.status",
    "forward.cancel",
];

const UNKNOWN_GRANT_ERROR: &str = "grant is not registered in this daemon instance; the daemon may have restarted, so reissue the grant";

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Live registry of issued grants. Grants die with the daemon instance: a
/// restart rebinds every capability to a fresh activation secret.
const GRANT_TERMINAL_TOMBSTONE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrantTerminalKind {
    Exhausted,
    Expired,
}

struct GrantTombstone {
    kind: GrantTerminalKind,
    expires_at: Instant,
    forget_at: Instant,
}

struct GrantRegistryState<E> {
    live: HashMap<[u8; 16], Arc<GrantRecord<E>>>,
    tombstones: HashMap<[u8; 16], GrantTombstone>,
}

enum GrantLookup<E> {
    Live(Arc<GrantRecord<E>>),
    Exhausted,
    Expired,
    Unknown,
}

struct GrantRegistry<E = ProfilePoolEntry> {
    state: StdMutex<GrantRegistryState<E>>,
    idle: Arc<IdleTracker>,
}

impl<E: GrantProfileBinding> GrantRegistry<E> {
    fn new(idle: Arc<IdleTracker>) -> Self {
        Self {
            state: StdMutex::new(GrantRegistryState {
                live: HashMap::new(),
                tombstones: HashMap::new(),
            }),
            idle,
        }
    }

    fn prune_locked(state: &mut GrantRegistryState<E>, now: Instant) {
        state
            .tombstones
            .retain(|_, tombstone| tombstone.forget_at > now);
        let expired_ids: Vec<_> = state
            .live
            .iter()
            .filter_map(|(grant_id, record)| (record.expires_at <= now).then_some(*grant_id))
            .collect();
        for grant_id in expired_ids {
            let Some(record) = state.live.remove(&grant_id) else {
                continue;
            };
            let forget_at = record
                .expires_at
                .checked_add(GRANT_TERMINAL_TOMBSTONE_TTL)
                .unwrap_or(record.expires_at);
            if forget_at > now {
                state.tombstones.insert(
                    grant_id,
                    GrantTombstone {
                        kind: GrantTerminalKind::Expired,
                        expires_at: record.expires_at,
                        forget_at,
                    },
                );
            }
        }
    }

    fn lookup(&self, grant_id: &[u8; 16], now: Instant) -> GrantLookup<E> {
        let Ok(mut state) = self.state.lock() else {
            return GrantLookup::Unknown;
        };
        Self::prune_locked(&mut state, now);
        if let Some(record) = state.live.get(grant_id) {
            return GrantLookup::Live(Arc::clone(record));
        }
        match state.tombstones.get(grant_id) {
            Some(tombstone)
                if tombstone.kind == GrantTerminalKind::Exhausted && now < tombstone.expires_at =>
            {
                GrantLookup::Exhausted
            }
            Some(_) => GrantLookup::Expired,
            None => GrantLookup::Unknown,
        }
    }

    fn insert(&self, grant: serctl_protocol::grant::OperationGrant, entry: Arc<E>) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("grant registry lock is poisoned"))?;
        let now = Instant::now();
        Self::prune_locked(&mut state, now);
        ensure!(
            state.live.len() + state.tombstones.len() < GRANT_REGISTRY_LIMIT,
            "grant registry is at its capacity"
        );
        ensure!(
            !state.live.contains_key(&grant.grant_id)
                && !state.tombstones.contains_key(&grant.grant_id),
            "grant id collision"
        );
        let idle_guard = self.idle.acquire();
        let record = GrantRecord::new(grant, entry, now, idle_guard)?;
        state.live.insert(record.grant.grant_id, Arc::new(record));
        Ok(())
    }

    fn mark_terminal_if_same(
        &self,
        grant_id: &[u8; 16],
        expected: &Arc<GrantRecord<E>>,
        kind: GrantTerminalKind,
        now: Instant,
    ) {
        if let Ok(mut state) = self.state.lock() {
            Self::prune_locked(&mut state, now);
            let should_remove = state
                .live
                .get(grant_id)
                .is_some_and(|current| Arc::ptr_eq(current, expected));
            if should_remove {
                let record = state
                    .live
                    .remove(grant_id)
                    .expect("grant checked under the registry lock");
                let forget_at = record
                    .expires_at
                    .checked_add(GRANT_TERMINAL_TOMBSTONE_TTL)
                    .unwrap_or(record.expires_at);
                state.tombstones.insert(
                    *grant_id,
                    GrantTombstone {
                        kind,
                        expires_at: record.expires_at,
                        forget_at,
                    },
                );
            }
        }
    }

    fn prune_expired(&self, now: Instant) {
        if let Ok(mut state) = self.state.lock() {
            Self::prune_locked(&mut state, now);
        }
    }
}

/// One grant plus its remaining budget and audit sink.
struct GrantRecord<E = ProfilePoolEntry> {
    grant: serctl_protocol::grant::OperationGrant,
    /// Exact credential/session/profile-use lease captured at issuance. Grant
    /// requests never remap through the mutable profile pool.
    entry: Arc<E>,
    remaining: AtomicUsize,
    expires_at: Instant,
    _idle_guard: IdleGuard,
}

#[derive(serde::Serialize)]
struct GrantAuditLine {
    at_unix_ms: u64,
    grant_id: String,
    operation_kind: String,
    profile: String,
    request_id: String,
    outcome: String,
}

impl<E: GrantProfileBinding> GrantRecord<E> {
    fn new(
        grant: serctl_protocol::grant::OperationGrant,
        entry: Arc<E>,
        issued_at: Instant,
        idle_guard: IdleGuard,
    ) -> Result<Self> {
        let ttl = grant.policy_ttl()?;
        ensure!(
            entry.identity().profile_id == grant.profile_id,
            "grant profile id does not match its bound profile entry"
        );
        ensure!(
            entry.identity().generation == grant.profile_generation,
            "grant profile generation does not match its bound profile entry"
        );
        ensure!(
            entry.profile_name() == grant.profile_name,
            "grant profile name does not match its bound profile entry"
        );
        let expires_at = issued_at
            .checked_add(ttl)
            .context("grant monotonic expiry overflow")?;
        Ok(Self {
            remaining: AtomicUsize::new(grant.budget as usize),
            grant,
            entry,
            expires_at,
            _idle_guard: idle_guard,
        })
    }

    /// Validate immutable binding, expiry, requested deadline, scope, and
    /// proof of possession without consuming budget. The caller must durably
    /// persist the authoritative Intent before calling `spend_budget`.
    fn validate_request(
        &self,
        prelude: &V6RequestPrelude,
        now: Instant,
        now_ms: u64,
    ) -> Result<()> {
        let grant = &self.grant;
        // Recheck the immutable binding before touching the atomic budget. It
        // makes accidental construction or future refactors fail closed and
        // gives generation/name/id mismatch deterministic pre-spend semantics.
        ensure!(
            self.entry.identity().profile_id == grant.profile_id,
            "grant profile id does not match its bound profile entry"
        );
        ensure!(
            self.entry.identity().generation == grant.profile_generation,
            "grant profile generation does not match its bound profile entry"
        );
        ensure!(
            self.entry.profile_name() == grant.profile_name,
            "grant profile name does not match its bound profile entry"
        );
        ensure!(now < self.expires_at, "grant has expired");
        ensure!(
            prelude.requested_deadline_unix_ms > now_ms
                && prelude.requested_deadline_unix_ms <= grant.expires_unix_ms,
            "requested deadline exceeds the grant expiry"
        );
        ensure!(
            grant.covers(prelude),
            "grant does not authorize this operation kind"
        );
        ensure!(grant.covers_profile(prelude), "grant profile mismatch");
        let signature = prelude
            .pop_signature
            .as_deref()
            .context("grant prelude must carry a proof-of-possession signature")?;
        serctl_protocol::grant::verify_prelude_pop(&grant.holder_key, signature, prelude)?;
        Ok(())
    }

    /// Atomically spend one budget unit after authoritative Intent
    /// persistence. Returns true when this request consumed the final unit.
    fn spend_budget(&self) -> Result<bool> {
        let mut remaining = self.remaining.load(Ordering::Acquire);
        loop {
            if remaining == 0 {
                bail!("grant budget exhausted");
            }
            match self.remaining.compare_exchange_weak(
                remaining,
                remaining - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(remaining == 1),
                Err(current) => remaining = current,
            }
        }
    }

    fn policy_digest(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"serctl/audit/grant-policy/v1\0");
        digest.update(self.grant.grant_id);
        digest.update(self.grant.profile_id);
        digest.update(self.grant.profile_generation.to_be_bytes());
        digest.update(self.grant.budget.to_be_bytes());
        digest.update(self.grant.issued_unix_ms.to_be_bytes());
        digest.update(self.grant.expires_unix_ms.to_be_bytes());
        for operation in &self.grant.operations {
            digest.update((operation.len() as u64).to_be_bytes());
            digest.update(operation.as_bytes());
        }
        hex::encode(digest.finalize())
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Append to the legacy compatibility diagnostic. This JSONL is explicitly
    /// non-authoritative: authorization and quarantine are driven only by the
    /// profile-scoped HMAC-checkpointed `AuditLedger`.
    fn compatibility_audit(&self, prelude: &V6RequestPrelude, outcome: &str) {
        let entry = GrantAuditLine {
            at_unix_ms: now_unix_ms(),
            grant_id: self.grant.grant_id_hex(),
            operation_kind: prelude.operation_kind.clone(),
            profile: prelude
                .profile_name
                .clone()
                .unwrap_or_else(|| self.grant.profile_name.clone()),
            request_id: hex::encode(prelude.request_id),
            outcome: outcome.to_owned(),
        };
        let result = (|| -> Result<()> {
            use std::io::{Seek as _, Write as _};
            let _guard = GRANT_AUDIT_LOCK
                .lock()
                .map_err(|_| anyhow::anyhow!("grant audit lock is poisoned"))?;
            let path = daemon_runtime::grant_audit_path()?;
            let mut file = serctl_core::security::open_or_create_protected_file(&path)
                .context("open protected grant audit log")?;
            file.seek(std::io::SeekFrom::End(0))
                .context("seek to grant audit end")?;
            let line =
                Zeroizing::new(serde_json::to_vec(&entry).context("serialize grant audit entry")?);
            file.write_all(&line).context("append grant audit entry")?;
            file.write_all(b"\n")
                .context("terminate grant audit entry")?;
            file.sync_data().context("sync grant audit entry")?;
            Ok(())
        })();
        if let Err(error) = result {
            log::warn!(
                "grant audit persistence failed: {}",
                terminal_safe_error(&error)
            );
        }
    }
}

/// Issue a grant on behalf of an unlocked issuing profile. The grant's target
/// profile must be the same unlocked profile; the holder key never leaves the
/// daemon and the agent's private key never enters it.
fn issue_grant(
    prelude: &V6RequestPrelude,
    pool: &ProfilePool,
    grants: &GrantRegistry,
    frame: &ipc::Frame,
) -> Result<serctl_protocol::grant::OperationGrant> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::VerifyingKey;

    let ipc::Frame::IssueGrant {
        profile,
        operations,
        budget,
        ttl_secs,
        holder_key,
    } = frame
    else {
        bail!("issue-grant operation kind without an issue-grant frame");
    };
    ensure!(
        prelude.profile_name.as_deref() == Some(profile.as_str()),
        "grant issuance must target the unlocked issuing profile"
    );
    let profile_id = prelude
        .profile_id
        .context("grant issuance requires the issuing profile id")?;
    let entry = pool
        .entry_for(&profile_id)
        .context("profile is locked: unlock it first")?;
    ensure!(
        entry.conn_info.profile == *profile,
        "grant profile name does not match its profile id"
    );
    let profile_proof = prelude
        .profile_proof
        .as_deref()
        .context("grant issuance requires a profile call proof")?;
    serctl_protocol::v6::verify_profile_prelude_proof(
        entry.call_key.as_bytes(),
        profile_proof,
        prelude,
    )?;
    let mut unique = operations.clone();
    unique.sort();
    unique.dedup();
    ensure!(
        !unique.is_empty()
            && unique
                .iter()
                .all(|kind| GRANTABLE_OPERATION_KINDS.contains(&kind.as_str())),
        "grant contains a non-grantable or empty operation kind"
    );
    let decoded = B64
        .decode(holder_key)
        .context("decode grant holder public key")?;
    let key_bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("grant holder key must decode to 32 bytes"))?;
    let holder =
        VerifyingKey::from_bytes(&key_bytes).context("grant holder public key is invalid")?;
    let grant = serctl_protocol::grant::OperationGrant::new_with_ttl(
        profile.clone(),
        serctl_protocol::grant::GrantProfileIdentity::new(profile_id, entry.identity.generation),
        unique,
        *budget,
        &holder,
        now_unix_ms(),
        Duration::from_secs(u64::from(*ttl_secs)),
    )?;
    grants.insert(grant.clone(), entry)?;
    Ok(grant)
}

/// Connect an authenticated SSH session for freshly decrypted credentials,
/// persisting a first-use host-key pin through the still-held profile lease.
/// Returns the session together with the lease, which remains held by the
/// pool entry for the whole credential-lease lifetime.
async fn connect_unlocked_session(
    name: &str,
    creds: &mut Creds,
    passphrase: &Zeroizing<String>,
    mut lease: vault::ProfileLease,
    deadline: Instant,
) -> Result<(SshSession, vault::ProfileLease)> {
    let expect = creds.host_key.clone();
    let staged = SshSession::connect_key_exchange_until(creds, expect, deadline).await?;
    let fp = staged.observed_fingerprint().to_owned();
    if creds.host_key.is_none() {
        let profile_owned = name.to_owned();
        let persisted_fp = fp.clone();
        let pin_passphrase = Zeroizing::new(passphrase.as_str().to_owned());
        let mut task = tokio::task::spawn_blocking(move || {
            let lock_timeout = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("daemon host-key pin persistence exceeded its setup deadline")?;
            vault::set_pinned_fp_with_lock_timeout(
                &profile_owned,
                persisted_fp,
                &pin_passphrase,
                lock_timeout,
                &lease,
            )?;
            Ok::<_, anyhow::Error>(lease)
        });
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(result) => {
                lease = result.context("join daemon host-key pin persistence worker")??;
            }
            Err(_) => {
                task.abort();
                staged.abort().await;
                bail!("daemon host-key pin persistence exceeded its setup deadline")
            }
        }
        eprintln!("[serctl] pinned host key {}", terminal_safe_field(&fp));
        creds.host_key = Some(fp);
    }
    let session = staged
        .authenticate_password_until(&creds.user, &creds.password, deadline)
        .await?;
    Ok((session, lease))
}

/// Unlock one profile: verify the passphrase, decrypt the credentials, derive
/// the call key, connect SSH (persisting a first-use host-key pin), and
/// publish a bounded credential lease into the pool.
async fn unlock_profile(
    prelude: &V6RequestPrelude,
    pool: &ProfilePool,
    frame: &ipc::Frame,
) -> Result<Zeroizing<String>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let ipc::Frame::Unlock { passphrase } = frame else {
        bail!("unlock operation kind without an unlock frame")
    };
    let passphrase = Zeroizing::new(passphrase.as_str().to_owned());
    let name = prelude
        .profile_name
        .clone()
        .context("unlock requires a profile name in the handshake prelude")?;
    let deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
    let profile_owned = name.clone();
    let key_passphrase = passphrase.clone();
    let mut snapshot = tokio::task::spawn_blocking(move || {
        // The global pool permits independent CLI processes to re-verify and
        // share one live profile session, while the shared use lease still
        // excludes ordinary profile mutation for the credential lifetime.
        let lease = vault::acquire_profile_use_lease(&profile_owned)?;
        let lock_timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("daemon unlock exceeded its setup deadline")?;
        let (creds, call_key) = vault::decrypt_with_call_key_with_lock_timeout(
            &profile_owned,
            &key_passphrase,
            None,
            lock_timeout,
        )?;
        let identity = vault::list_profile_metadata()?
            .into_iter()
            .find(|metadata| metadata.name == profile_owned)
            .map(|metadata| metadata.identity())
            .context("profile disappeared from the vault catalog")?;
        // The authenticated ledger must be usable before any SSH connection
        // is opened. A bit flip, truncation, wrong generation or wrong
        // ProfileCallKey therefore fails this unlock before business access.
        let audit_directory = vault::run_dir()?.join("audit");
        std::fs::create_dir_all(&audit_directory).context("create profile audit directory")?;
        let authoritative_audit = Arc::new(AuditLedger::from_profile_call_key(
            &audit_directory,
            identity,
            &call_key,
        )?);
        authoritative_audit
            .verify_complete(None)
            .context("verify authenticated profile audit ledger")?;
        Ok::<_, anyhow::Error>((creds, call_key, identity, lease, authoritative_audit))
    });
    let (mut creds, call_key, identity, lease, authoritative_audit) =
        match tokio::time::timeout_at(deadline, &mut snapshot).await {
            Ok(result) => result.context("join daemon unlock worker")??,
            Err(_) => {
                snapshot.abort();
                bail!("daemon unlock exceeded its setup deadline")
            }
        };
    let (session, lease) =
        connect_unlocked_session(&name, &mut creds, &passphrase, lease, deadline).await?;
    drop(passphrase);
    let encoded_call_key = Zeroizing::new(B64.encode(call_key.as_bytes()));
    let unlocked_at = Instant::now();
    let expires_at = unlocked_at + serctl_protocol::v6::CREDENTIAL_LEASE_TTL;
    let sessions = Arc::new(SessionManager::new(creds.clone(), session));
    let conn_info = ConnInfo {
        profile: name.clone(),
        profile_id: Some(identity.profile_id),
        profile_generation: Some(identity.generation),
        host: creds.host.clone(),
        user: creds.user.clone(),
        started: now_unix(),
        token: Arc::new(Zeroizing::new(vault::new_ipc_token())),
    };
    pool.insert(
        identity.profile_id,
        ProfilePoolEntry {
            identity,
            conn_info,
            sessions,
            call_key: Arc::new(call_key),
            authoritative_audit,
            quarantined: Arc::new(AtomicBool::new(false)),
            expires_at,
            _lease: Arc::new(lease),
        },
    );
    Ok(encoded_call_key)
}

/// Serve one authenticated v6 connection: the root request is the unlock, the
/// catalog listing, a grant issuance, or a data-plane operation against a live
/// credential lease (directly or through a grant).
struct GlobalHandlerContext {
    pool: Arc<ProfilePool>,
    grants: Arc<GrantRegistry>,
    shutdown_tx: watch::Sender<bool>,
    buffered_operation_slots: Arc<Semaphore>,
    tunnel_control_slots: Arc<Semaphore>,
    transfers: Arc<TransferRegistry>,
    managed_tunnels: Arc<ManagedTunnelRegistry>,
    idle: Arc<IdleTracker>,
    instance_id: InstanceId,
    operation_context_key: Arc<OperationContextKey>,
}

async fn handle_global_conn<S>(
    io: V6ServerIo<S>,
    prelude: V6RequestPrelude,
    context: GlobalHandlerContext,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let GlobalHandlerContext {
        pool,
        grants,
        shutdown_tx,
        buffered_operation_slots,
        tunnel_control_slots,
        transfers,
        managed_tunnels,
        idle,
        instance_id,
        operation_context_key,
    } = context;
    let (mut rd, mut wr) = tokio::io::split(io);
    let mut shutdown_rx = shutdown_tx.subscribe();
    let frame =
        read_authenticated_request(&mut rd, &mut shutdown_rx, POST_AUTH_IDLE_TIMEOUT).await?;
    let Some(frame) = frame else {
        return Ok(());
    };

    match frame_kind(&frame) {
        "daemon.unlock" => match unlock_profile(&prelude, &pool, &frame).await {
            Ok(call_key) => {
                let response = ZeroizingResponseFrame(ipc::Frame::ProfileAuthorized {
                    call_key: call_key.as_str().to_owned(),
                });
                write_frame_or_shutdown(
                    &mut wr,
                    &response.0,
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await
            }
            Err(error) => {
                let msg = terminal_safe_error(&error);
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error { msg },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await
            }
        },
        "daemon.list-profiles" => {
            let listing = tokio::task::spawn_blocking(|| {
                vault::list_profile_metadata().map(|metadata| {
                    metadata
                        .into_iter()
                        .map(|profile| ipc::WireProfile {
                            name: profile.name,
                            host: profile.host,
                            port: profile.port,
                            generation: profile.generation,
                            profile_id: hex::encode(profile.profile_id),
                        })
                        .collect()
                })
            })
            .await
            .context("join profile catalog worker")?;
            match listing {
                Ok(profiles) => {
                    write_frame_or_shutdown(
                        &mut wr,
                        &ipc::Frame::ProfileList { profiles },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await
                }
                Err(error) => {
                    let msg = terminal_safe_error(&error);
                    write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error { msg },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await
                }
            }
        }
        "daemon.issue-grant" => match issue_grant(&prelude, &pool, &grants, &frame) {
            Ok(grant) => {
                eprintln!(
                    "[serctl] grant issued: {} for {} ({} ops, budget {})",
                    grant.grant_id_hex(),
                    terminal_safe_field(&grant.profile_name),
                    grant.operations.len(),
                    grant.budget
                );
                write_frame_or_shutdown(
                    &mut wr,
                    &ipc::Frame::GrantIssued {
                        grant_id: grant.grant_id_hex(),
                        profile_generation: grant.profile_generation,
                        issued_unix_ms: grant.issued_unix_ms,
                        expires_unix_ms: grant.expires_unix_ms,
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await
            }
            Err(error) => {
                let msg = terminal_safe_error(&error);
                write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error { msg },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await
            }
        },
        "daemon.shutdown" => {
            let ipc::Frame::Shutdown { passphrase } = frame else {
                bail!("shutdown operation kind without a shutdown frame")
            };
            let passphrase = Zeroizing::new(passphrase);
            let profile = prelude
                .profile_name
                .as_deref()
                .context("shutdown requires a profile name in the handshake prelude")?
                .to_owned();
            let verify_deadline = Instant::now() + CONTROL_SETUP_TIMEOUT;
            let mut verifier = tokio::task::spawn_blocking(move || {
                vault::derive_profile_call_key_with_lock_timeout(
                    &profile,
                    &passphrase,
                    None,
                    CONTROL_SETUP_TIMEOUT,
                )
            });
            let verified = match tokio::time::timeout_at(verify_deadline, &mut verifier).await {
                Ok(result) => result.context("join daemon shutdown verifier")?,
                Err(_) => {
                    verifier.abort();
                    bail!("daemon shutdown authorization exceeded its deadline")
                }
            };
            if let Err(error) = verified {
                let msg = terminal_safe_error(&error);
                return write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error { msg },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await;
            }
            write_frame_or_shutdown(
                &mut wr,
                &ipc::Frame::Ack,
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                &mut shutdown_rx,
            )
            .await?;
            let _ = shutdown_tx.send(true);
            Ok(())
        }
        _ => {
            // A grant-bound request names the grant instead of a profile id:
            // the grant's bound profile and budget authorize the operation.
            let grant_record: Option<Arc<GrantRecord>> = if let Some(grant_id) = prelude.grant_id {
                let record = match grants.lookup(&grant_id, Instant::now()) {
                    GrantLookup::Live(record) => record,
                    terminal => {
                        let msg = match terminal {
                            GrantLookup::Exhausted => "grant budget exhausted".to_owned(),
                            GrantLookup::Expired => "grant has expired".to_owned(),
                            GrantLookup::Unknown => UNKNOWN_GRANT_ERROR.to_owned(),
                            GrantLookup::Live(_) => unreachable!("matched live grant above"),
                        };
                        return write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error { msg },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await;
                    }
                };
                let check_now = Instant::now();
                if let Err(error) = record.validate_request(&prelude, check_now, now_unix_ms()) {
                    if record.is_expired(check_now) {
                        grants.mark_terminal_if_same(
                            &grant_id,
                            &record,
                            GrantTerminalKind::Expired,
                            check_now,
                        );
                    }
                    let msg = terminal_safe_error(&error);
                    record.compatibility_audit(&prelude, &format!("rejected: {msg}"));
                    return write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error { msg },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await;
                }
                if let Err(error) = validate_grant_frame_binding(&frame) {
                    let msg = terminal_safe_error(&error);
                    record
                        .compatibility_audit(&prelude, "rejected: missing local-target commitment");
                    return write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error { msg },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await;
                }
                Some(record)
            } else {
                None
            };
            let entry = match (&grant_record, prelude.profile_id) {
                (Some(record), _) => Arc::clone(&record.entry),
                (None, Some(profile_id)) => match pool.entry_for(&profile_id) {
                    Some(entry) => entry,
                    None => {
                        let msg = "profile is locked: unlock it first".to_owned();
                        return write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error { msg },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await;
                    }
                },
                (None, None) => {
                    let msg = "profile id is required for this operation".to_owned();
                    return write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error { msg },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await;
                }
            };
            let expected_profile = grant_record
                .as_ref()
                .map(|record| record.grant.profile_name.as_str())
                .or(prelude.profile_name.as_deref())
                .context("profile name is required for this operation")?;
            ensure!(
                entry.conn_info.profile == expected_profile,
                "profile name does not match its profile id"
            );
            validate_connection_identity_binding(&frame, entry.identity)?;

            if grant_record.is_none() {
                let proof = prelude
                    .profile_proof
                    .as_deref()
                    .context("profile call proof is required")?;
                serctl_protocol::v6::verify_profile_prelude_proof(
                    entry.call_key.as_bytes(),
                    proof,
                    &prelude,
                )?;
            }

            let now = Instant::now();
            let mut authorization_deadline = grant_record
                .as_ref()
                .map_or(entry.expires_at, |record| record.expires_at);
            if grant_record.is_some() {
                let wall_now = now_unix_ms();
                let remaining_ms = prelude
                    .requested_deadline_unix_ms
                    .checked_sub(wall_now)
                    .context("requested deadline has expired")?;
                let requested_deadline = now
                    .checked_add(Duration::from_millis(remaining_ms))
                    .context("requested deadline exceeds the monotonic clock range")?;
                authorization_deadline = authorization_deadline.min(requested_deadline);
            }
            ensure!(
                authorization_deadline > now,
                "profile authorization lease expired"
            );

            // A Grant root becomes dispatchable only after its authenticated
            // Intent is durable. Validation above is budget-free, so an audit
            // failure cannot consume capability budget or reach SSH/local
            // business side effects.
            let grant_audit = if let Some(record) = &grant_record {
                let audit = GrantAuditOperation::new(
                    record,
                    &prelude,
                    authorization_deadline,
                    instance_id,
                    Arc::clone(&operation_context_key),
                );
                if let Err(error) = audit.record_intent().await {
                    let msg = terminal_safe_error(&error);
                    record.compatibility_audit(
                        &prelude,
                        "rejected: authoritative intent persistence failed",
                    );
                    return write_owned_frame_or_shutdown(
                        &mut wr,
                        ipc::Frame::Error { msg },
                        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                        &mut shutdown_rx,
                    )
                    .await;
                }
                Some(audit)
            } else {
                None
            };

            if entry.quarantined.load(Ordering::Acquire)
                && !operation_allowed_while_quarantined(&prelude.operation_kind)
            {
                let msg = "profile is quarantined; mutation operations are disabled".to_owned();
                if let Some(audit) = &grant_audit {
                    if audit
                        .record_denied("quarantine.mutation_denied")
                        .await
                        .is_err()
                    {
                        return write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error {
                                msg: "profile audit is unavailable; operation denied and outcome unknown"
                                    .to_owned(),
                            },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await;
                    }
                }
                if let Some(record) = &grant_record {
                    record.compatibility_audit(&prelude, "rejected: profile quarantined");
                }
                return write_owned_frame_or_shutdown(
                    &mut wr,
                    ipc::Frame::Error { msg },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                    &mut shutdown_rx,
                )
                .await;
            }

            if let (Some(record), Some(grant_id)) = (&grant_record, prelude.grant_id) {
                let spend_now = Instant::now();
                match record.spend_budget() {
                    Ok(exhausted_after_spend) => {
                        if exhausted_after_spend {
                            // The accepted request and audit context retain the
                            // exact entry. The registry releases its credential
                            // reference as soon as the final unit is claimed.
                            grants.mark_terminal_if_same(
                                &grant_id,
                                record,
                                GrantTerminalKind::Exhausted,
                                spend_now,
                            );
                        }
                    }
                    Err(error) => {
                        grants.mark_terminal_if_same(
                            &grant_id,
                            record,
                            GrantTerminalKind::Exhausted,
                            spend_now,
                        );
                        let audit_result = match &grant_audit {
                            Some(audit) => audit.record_denied("grant.budget_exhausted").await,
                            None => Ok(()),
                        };
                        let msg = if audit_result.is_ok() {
                            terminal_safe_error(&error)
                        } else {
                            "profile audit is unavailable; operation denied and outcome unknown"
                                .to_owned()
                        };
                        record.compatibility_audit(&prelude, "rejected: grant budget exhausted");
                        return write_owned_frame_or_shutdown(
                            &mut wr,
                            ipc::Frame::Error { msg },
                            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                            &mut shutdown_rx,
                        )
                        .await;
                    }
                }
            }

            let context = HandlerContext {
                sessions: entry.sessions.clone(),
                info: entry.conn_info.clone(),
                shutdown: shutdown_tx.clone(),
                buffered_operation_slots,
                tunnel_control_slots,
                transfers,
                managed_tunnels,
                idle,
                profile_entry: Some(Arc::clone(&entry)),
                call_key: entry.call_key.clone(),
                authorization_deadline: Some(authorization_deadline),
            };
            let outcome = if let Some(audit) = &grant_audit {
                ACTIVE_GRANT_AUDIT
                    .scope(
                        Arc::clone(audit),
                        dispatch_root_request(rd, wr, shutdown_rx, context, frame),
                    )
                    .await
            } else {
                dispatch_root_request(rd, wr, shutdown_rx, context, frame).await
            };
            let audit_finalization = match &grant_audit {
                Some(audit) => audit.finalize_unknown_if_pending().await,
                None => Ok(()),
            };
            if let Some(record) = &grant_record {
                record.compatibility_audit(
                    &prelude,
                    if audit_finalization.is_err() {
                        "authoritative outcome persistence failed; profile quarantined"
                    } else if outcome.is_ok() {
                        "accepted"
                    } else {
                        "rejected: dispatch failure"
                    },
                );
                if outcome.is_ok() {
                    eprintln!(
                        "[serctl] grant relay: {} {} (grant {}, budget left {})",
                        terminal_safe_field(&prelude.operation_kind),
                        terminal_safe_field(&record.grant.profile_name),
                        record.grant.grant_id_hex(),
                        record.remaining.load(Ordering::Acquire)
                    );
                }
            }
            audit_finalization?;
            outcome
        }
    }
}

/// Global per-user/per-vault daemon: bind the v6 endpoint, publish the runtime
/// descriptor and activation secret, and serve every profile through
/// on-demand credential leases.
pub async fn run_global(
    instance_id: InstanceId,
    secret: ActivationSecret,
    build_commit: String,
) -> Result<()> {
    run_global_with_idle_timeout(instance_id, secret, build_commit, IDLE_EXIT_TIMEOUT).await
}

/// Global broker with a caller-chosen idle-exit window (tests use short
/// windows; the binary uses `IDLE_EXIT_TIMEOUT`).
pub async fn run_global_with_idle_timeout(
    instance_id: InstanceId,
    secret: ActivationSecret,
    build_commit: String,
    idle_exit_timeout: Duration,
) -> Result<()> {
    // The daemon, not its launcher, owns global-startup arbitration. A CLI can
    // crash after spawning us, so holding the singleton in the parent would
    // leave a window where two children can publish. Keep this lock through
    // listener bind and readiness publication, then release it before serving.
    let lock_deadline = std::time::Instant::now() + CONTROL_SETUP_TIMEOUT;
    let startup_lock = tokio::task::spawn_blocking(move || {
        daemon_runtime::acquire_startup_lock_until(lock_deadline)
    })
    .await
    .context("join global daemon startup-lock acquisition")??;
    if let Some(existing) = daemon_runtime::reconcile_runtime(&startup_lock)? {
        bail!(
            "a global daemon is already running (pid {}, instance {})",
            existing.pid,
            existing.instance_id
        );
    }
    let endpoint = daemon_runtime::v6_endpoint(&instance_id)?;
    let mut listener = ipc::LocalListener::bind(&endpoint)?;
    #[cfg(unix)]
    serctl_core::security::harden_file(std::path::Path::new(&endpoint))?;
    let runtime_descriptor = DaemonRuntimeDescriptor {
        version: DESCRIPTOR_SCHEMA_VERSION,
        instance_id: instance_id.as_hex(),
        pid: std::process::id(),
        endpoint: endpoint.clone(),
        protocol_min: IPC_PROTOCOL_VERSION_V6,
        protocol_max: IPC_PROTOCOL_VERSION_V6,
        started_unix: now_unix(),
        build_commit,
    };
    daemon_runtime::publish_runtime(&startup_lock, &runtime_descriptor, &secret)?;
    drop(startup_lock);

    let idle = Arc::new(IdleTracker::default());
    let pool = Arc::new(ProfilePool::default());
    let grants = Arc::new(GrantRegistry::new(Arc::clone(&idle)));
    let transfers = Arc::new(TransferRegistry::default());
    let managed_tunnels = Arc::new(ManagedTunnelRegistry::default());
    let operation_context_key = Arc::new(OperationContextKey::random());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut daemon_shutdown = shutdown_rx.clone();
    let connection_slots = Arc::new(Semaphore::new(GLOBAL_CONNECTION_LIMIT));
    let buffered_operation_slots = Arc::new(Semaphore::new(BUFFERED_HEAVY_OPERATION_LIMIT));
    let tunnel_control_slots = Arc::new(Semaphore::new(TUNNEL_CONTROL_LIMIT));
    let mut handlers = JoinSet::new();
    let reaper_pool = Arc::clone(&pool);
    let reaper_grants = Arc::clone(&grants);
    let mut reaper_shutdown = shutdown_rx.clone();
    let reaper_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(LEASE_REAPER_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = Instant::now();
                    reaper_pool.prune_expired(now);
                    reaper_grants.prune_expired(now);
                }
                changed = reaper_shutdown.changed() => {
                    if changed.is_err() || *reaper_shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    });
    eprintln!(
        "[serctl] daemon up: global broker {} (Ctrl-C to stop)",
        terminal_safe_field(listener.endpoint())
    );

    let result: Result<()> = loop {
        tokio::select! {
            res = listener.accept() => {
                let stream = match res {
                    Ok(stream) => stream,
                    Err(error) => break Err(error.context("accept local IPC connection")),
                };
                let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
                    log::warn!("rejecting IPC connection: connection limit reached");
                    continue;
                };
                let handler_shutdown = shutdown_rx.clone();
                let _ = handler_shutdown; // the global handler subscribes per connection
                let pool = Arc::clone(&pool);
                let grants = Arc::clone(&grants);
                let transfers = Arc::clone(&transfers);
                let managed_tunnels = Arc::clone(&managed_tunnels);
                let idle_for_handler = Arc::clone(&idle);
                let secret = secret.clone();
                let shutdown_tx = shutdown_tx.clone();
                let buffered_operation_slots = Arc::clone(&buffered_operation_slots);
                let tunnel_control_slots = Arc::clone(&tunnel_control_slots);
                let operation_context_key = Arc::clone(&operation_context_key);
                let work_guard = idle.acquire();
                handlers.spawn(async move {
                    let _permit = permit;
                    let _work_guard = work_guard;
                    let deadline = Instant::now() + V6_HANDSHAKE_TIMEOUT;
                    match serctl_protocol::v6::v6_server_handshake(
                        stream,
                        &secret,
                        instance_id,
                        deadline,
                    )
                    .await
                    {
                        Ok((session, prelude)) => {
                            let io = V6ServerIo::new(session);
                            handle_global_conn(io, prelude, GlobalHandlerContext {
                                pool,
                                grants,
                                shutdown_tx,
                                buffered_operation_slots,
                                tunnel_control_slots,
                                transfers,
                                managed_tunnels,
                                idle: idle_for_handler,
                                instance_id,
                                operation_context_key,
                            })
                            .await
                        }
                        Err(error) => {
                            log::warn!("rejected IPC v6 handshake: {}", terminal_safe_error(&error));
                            Ok(())
                        }
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[serctl] shutting down");
                break Ok(());
            }
            changed = daemon_shutdown.changed() => {
                if changed.is_ok() && *daemon_shutdown.borrow() {
                    eprintln!("[serctl] shutdown requested");
                    break Ok(());
                }
            }
            _ = idle.wait_for_idle_exit(idle_exit_timeout) => {
                // Re-check under the wake race: work may have arrived exactly
                // as the idle window expired.
                if idle.is_idle() {
                    eprintln!("[serctl] idle for {idle_exit_timeout:?}; exiting");
                    break Ok(());
                }
            }
            joined = handlers.join_next(), if !handlers.is_empty() => {
                log_handler_result(joined);
            }
        }
    };

    let _ = shutdown_tx.send(true);
    managed_tunnels
        .shutdown_all(Instant::now() + MANAGED_TUNNEL_CANCEL_TIMEOUT)
        .await;
    let _ = reaper_task.await;
    let drained = tokio::time::timeout(HANDLER_SHUTDOWN_GRACE, async {
        while let Some(joined) = handlers.join_next().await {
            log_handler_result(Some(joined));
        }
    })
    .await;
    if drained.is_err() {
        handlers.abort_all();
        while handlers.join_next().await.is_some() {}
    }
    let cleanup_deadline = std::time::Instant::now() + CONTROL_SETUP_TIMEOUT;
    let cleanup_lock = tokio::task::spawn_blocking(move || {
        daemon_runtime::acquire_startup_lock_until(cleanup_deadline)
    })
    .await
    .context("join global daemon owner-cleanup lock acquisition")??;
    daemon_runtime::cleanup_runtime_if_owner(&cleanup_lock, &runtime_descriptor, &secret)?;
    result
}

async fn write_tunnel_terminal<W>(
    writer: &mut W,
    shutdown: &mut watch::Receiver<bool>,
    outcome: Result<()>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if let Err(error) = outcome {
        write_owned_frame_or_shutdown(
            writer,
            ipc::Frame::Error {
                msg: error.to_string(),
            },
            Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
            shutdown,
        )
        .await?;
    }
    write_frame_or_shutdown(
        writer,
        &ipc::Frame::TunnelClosed,
        Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
        shutdown,
    )
    .await
}

async fn stop_tunnel_and_report<W, F>(
    writer: &mut W,
    shutdown: &mut watch::Receiver<bool>,
    stop: F,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    F: std::future::Future<Output = Result<()>>,
{
    write_tunnel_terminal(writer, shutdown, stop.await).await
}

enum TunnelControlWait {
    WorkerFinished,
    Shutdown,
    Frame(Option<ipc::Frame>),
}

/// Keep one framed control read alive across completion-poll ticks. Recreating
/// `read_frame_limited` after a tick would cancel a partially-read length
/// prefix or JSON payload and permanently desynchronize the IPC stream.
async fn wait_for_tunnel_control_or_completion<R, F>(
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    poll_interval: Duration,
    mut worker_is_finished: F,
) -> Result<TunnelControlWait>
where
    R: AsyncRead + Unpin,
    F: FnMut() -> bool,
{
    let control_read = ipc::read_frame_limited(reader, ipc::MAX_CONTROL_FRAME);
    tokio::pin!(control_read);
    let mut completion_poll = tokio::time::interval(poll_interval);
    completion_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if worker_is_finished() {
            return Ok(TunnelControlWait::WorkerFinished);
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(TunnelControlWait::Shutdown),
            control = &mut control_read => return Ok(TunnelControlWait::Frame(control?)),
            _ = completion_poll.tick() => {}
        }
    }
}

/// Own one daemon-routed tunnel for exactly the lifetime of its authenticated
/// control connection. Tunnel payload never traverses IPC: this handler only
/// reports readiness and observes stop/EOF/daemon-shutdown signals.
async fn serve_tunnel<R, W>(
    session: Arc<SshSession>,
    reader: &mut R,
    writer: &mut W,
    spec: serctl_core::ssh::TunnelSpec,
    shutdown: &mut watch::Receiver<bool>,
    setup_deadline: Instant,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let tunnel = tokio::select! {
        result = session.start_tunnel(spec, setup_deadline) => Some(result),
        _ = reader.read_u8() => None,
        _ = shutdown.changed() => None,
    };
    let Some(tunnel) = tunnel else {
        return Ok(());
    };
    let tunnel = match tunnel {
        Ok(tunnel) => tunnel,
        Err(error) => return write_tunnel_terminal(writer, shutdown, Err(error)).await,
    };
    let ready = tunnel.ready().clone();
    if let Err(error) = write_frame_or_shutdown(
        writer,
        &ipc::Frame::TunnelReady { ready },
        setup_deadline,
        shutdown,
    )
    .await
    {
        if let Err(cleanup_error) = tunnel.stop().await {
            log::warn!(
                "tunnel cleanup after readiness write failure: {}",
                terminal_safe_error(&cleanup_error)
            );
        }
        return Err(error);
    }

    match wait_for_tunnel_control_or_completion(reader, shutdown, TUNNEL_COMPLETION_POLL, || {
        tunnel.is_finished()
    })
    .await
    {
        Ok(TunnelControlWait::WorkerFinished) => {
            write_tunnel_terminal(writer, shutdown, tunnel.wait().await).await
        }
        Ok(TunnelControlWait::Shutdown) => {
            if let Err(error) = tunnel.stop().await {
                log::warn!(
                    "tunnel cleanup during daemon shutdown: {}",
                    terminal_safe_error(&error)
                );
            }
            Ok(())
        }
        Ok(TunnelControlWait::Frame(Some(ipc::Frame::TunnelStop))) => {
            stop_tunnel_and_report(writer, shutdown, tunnel.stop()).await
        }
        Ok(TunnelControlWait::Frame(Some(mut unexpected))) => {
            unexpected.zeroize_sensitive();
            if let Err(cleanup_error) = tunnel.stop().await {
                log::warn!(
                    "tunnel cleanup after unexpected control frame: {}",
                    terminal_safe_error(&cleanup_error)
                );
            }
            write_tunnel_terminal(
                writer,
                shutdown,
                Err(anyhow::anyhow!("unexpected frame during tunnel session")),
            )
            .await
        }
        Ok(TunnelControlWait::Frame(None)) => {
            if let Err(error) = tunnel.stop().await {
                log::warn!(
                    "tunnel cleanup after IPC EOF: {}",
                    terminal_safe_error(&error)
                );
            }
            Ok(())
        }
        Err(error) => {
            if let Err(cleanup_error) = tunnel.stop().await {
                log::warn!(
                    "tunnel cleanup after IPC read failure: {}",
                    terminal_safe_error(&cleanup_error)
                );
            }
            Err(error).context("read tunnel control frame")
        }
    }
}

async fn current_or_disconnect<R>(
    sessions: &SessionManager,
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<Option<Arc<SshSession>>>
where
    R: AsyncRead + Unpin,
{
    tokio::select! {
        result = sessions.current_until(deadline) => result.map(Some),
        _ = reader.read_u8() => Ok(None),
        _ = shutdown.changed() => Ok(None),
    }
}

/// Keep a single frame decoder alive while remote shell output, local shell
/// input, and daemon shutdown race. Cancelling and recreating the decoder after
/// a partial header/payload read would permanently desynchronize the dedicated
/// shell connection.
struct ZeroizingShellFrameRead {
    result: Result<Option<ipc::Frame>>,
    drop_observer: Option<Arc<AtomicBool>>,
}

impl ZeroizingShellFrameRead {
    fn new(result: Result<Option<ipc::Frame>>, drop_observer: Option<Arc<AtomicBool>>) -> Self {
        Self {
            result,
            drop_observer,
        }
    }

    fn into_inner(mut self) -> Result<Option<ipc::Frame>> {
        std::mem::replace(&mut self.result, Ok(None))
    }
}

impl Drop for ZeroizingShellFrameRead {
    fn drop(&mut self) {
        if let Ok(Some(frame)) = &mut self.result {
            frame.zeroize_sensitive();
        }
        if let Some(observer) = &self.drop_observer {
            observer.store(true, Ordering::Release);
        }
    }
}

async fn read_shell_frame_pump_inner<R>(
    reader: &mut R,
    sender: mpsc::Sender<ZeroizingShellFrameRead>,
    drop_observer: Option<Arc<AtomicBool>>,
    construction_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let result = ipc::read_frame_limited(reader, ipc::MAX_SHELL_FRAME).await;
        let terminal = !matches!(&result, Ok(Some(_)));
        if let Some(observer) = &construction_observer {
            observer.fetch_add(1, Ordering::Release);
        }
        let envelope = ZeroizingShellFrameRead::new(result, drop_observer.clone());
        if sender.send(envelope).await.is_err() || terminal {
            break;
        }
    }
}

async fn read_shell_frame_pump<R>(reader: &mut R, sender: mpsc::Sender<ZeroizingShellFrameRead>)
where
    R: AsyncRead + Unpin,
{
    read_shell_frame_pump_inner(reader, sender, None, None).await;
}

fn zeroize_pending_shell_frames(receiver: &mut mpsc::Receiver<ZeroizingShellFrameRead>) {
    receiver.close();
    while receiver.try_recv().is_ok() {}
}

struct DownloadServeRequest<'a> {
    path: &'a str,
    resume_offset: u64,
    expected_size: Option<u64>,
    expected_sha256: Option<&'a str>,
    timeout_ms: u64,
    idle_timeout: Duration,
    deadline: Instant,
    registry: &'a TransferRegistry,
    profile: &'a str,
    progress: ipc::TransferProgress,
    cancellation: Arc<TransferCancellation>,
}

async fn read_native_transfer_frame<S>(
    stream: &mut S,
    cancellation: &TransferCancellation,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Instant,
    timeout_message: &'static str,
) -> Result<native::Frame>
where
    S: AsyncRead + Unpin,
{
    tokio::select! {
        result = tokio::time::timeout_at(deadline, native::read_frame(stream)) => {
            result.map_err(|_| anyhow::anyhow!(timeout_message))??
                .context("native transfer helper closed its protocol stream")
        },
        _ = cancellation.cancelled() => bail!("transfer cancelled"),
        _ = shutdown.changed() => bail!("daemon shutting down during native transfer"),
    }
}

async fn write_native_control_until<S>(
    stream: &mut S,
    control: &native::Control,
    deadline: Instant,
    timeout_message: &'static str,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    tokio::time::timeout_at(deadline, native::write_control(stream, control))
        .await
        .map_err(|_| anyhow::anyhow!(timeout_message))??;
    Ok(())
}

async fn write_native_data_until<S>(
    stream: &mut S,
    data: &native::DataFrame,
    deadline: Instant,
    timeout_message: &'static str,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    tokio::time::timeout_at(deadline, native::write_data(stream, data))
        .await
        .map_err(|_| anyhow::anyhow!(timeout_message))??;
    Ok(())
}

fn native_helper_error(code: &str, message: &str, outcome_unknown: bool) -> anyhow::Error {
    if outcome_unknown {
        anyhow::anyhow!("native helper error {code}: {message}; remote outcome is unknown")
    } else {
        anyhow::anyhow!("native helper error {code}: {message}")
    }
}

async fn serve_native_download<R, W>(
    channel: NativeTransferChannel,
    reader: &mut R,
    writer: &mut W,
    request: DownloadServeRequest<'_>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let DownloadServeRequest {
        path,
        resume_offset,
        expected_size,
        expected_sha256,
        timeout_ms,
        idle_timeout,
        deadline,
        registry,
        profile,
        mut progress,
        cancellation,
    } = request;
    let NativeTransferChannel {
        mut stream,
        chunk_bytes,
        window_bytes,
        ..
    } = channel;
    let transfer_id = native::parse_transfer_id(progress.transfer_id.as_str())?;
    let mut progress_deadline = deadline.min(Instant::now() + idle_timeout);
    let operation = async {
        write_native_control_until(
            &mut stream,
            &native::Control::BeginPull {
                transfer_id: progress.transfer_id.as_str().to_owned(),
                source: path.to_owned(),
                offset: resume_offset,
            },
            progress_deadline,
            "native download idle timeout elapsed",
        )
        .await?;
        let (total, expected_sha256, start_offset) = match read_native_transfer_frame(
            &mut stream,
            &cancellation,
            shutdown,
            progress_deadline,
            "native download idle timeout elapsed",
        )
        .await?
        {
            native::Frame::Control(native::Control::PullReady {
                chunk,
                window,
                size,
                sha256,
                start_offset,
            }) => {
                ensure!(
                    chunk > 0 && chunk <= chunk_bytes,
                    "native helper exceeded the negotiated chunk size"
                );
                ensure!(
                    window >= chunk && window <= window_bytes,
                    "native helper exceeded the negotiated window"
                );
                ensure!(
                    size <= MAX_TRANSFER_BYTES,
                    "download exceeds the configured safety limit"
                );
                ensure!(
                    start_offset == resume_offset,
                    "native helper returned an unexpected resume offset"
                );
                if let Some(expected_size) = expected_size {
                    ensure!(
                        size == expected_size,
                        "remote source size changed since the resume journal was written"
                    );
                }
                if let Some(expected_sha256) = expected_sha256 {
                    ensure!(
                        sha256 == expected_sha256,
                        "remote source SHA-256 changed since the resume journal was written"
                    );
                }
                progress.chunk_bytes = chunk;
                progress.window_bytes = chunk;
                (size, sha256, start_offset)
            }
            native::Frame::Control(native::Control::Error {
                code,
                message,
                outcome_unknown,
            }) => return Err(native_helper_error(&code, &message, outcome_unknown)),
            _ => bail!("native helper did not accept the download request"),
        };
        ensure!(
            expected_sha256.len() == 64
                && expected_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "native helper returned an invalid SHA-256"
        );
        progress.total_bytes = total;
        progress.confirmed_bytes = start_offset;
        progress.durable_bytes = start_offset;
        progress.stage = ipc::TransferStage::Transferring;
        if start_offset > 0 {
            progress.event = "resumed".to_owned();
        }
        progress.updated_unix_ms = now_unix_ms();
        registry.update(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        progress.event = "progress".to_owned();
        write_frame_until(
            writer,
            &ipc::Frame::TransferDigest {
                transfer_id: progress.transfer_id.clone(),
                sha256: expected_sha256.clone(),
            },
            progress_deadline,
        )
        .await?;

        let mut received = start_offset;
        let mut client_durable = start_offset;
        let mut received_hasher = Sha256::new();
        let mut last_progress_write = Instant::now();
        loop {
            match read_native_transfer_frame(
                &mut stream,
                &cancellation,
                shutdown,
                progress_deadline,
                "native download idle timeout elapsed",
            )
            .await?
            {
                native::Frame::Data(data) => {
                    ensure!(
                        data.transfer_id == transfer_id,
                        "native download transfer id mismatch"
                    );
                    ensure!(
                        data.offset == received,
                        "native download offset gap, replay, or reordering"
                    );
                    ensure!(
                        data.payload.len() <= chunk_bytes as usize,
                        "native download chunk exceeded the negotiated limit"
                    );
                    let next = received
                        .checked_add(data.payload.len() as u64)
                        .context("native download size overflow")?;
                    ensure!(next <= total, "native download exceeded its declared size");
                    received_hasher.update(&data.payload);
                    write_frame_until(
                        writer,
                        &ipc::Frame::FileChunk { data: data.payload },
                        progress_deadline,
                    )
                    .await?;
                    match tokio::select! {
                        result = tokio::time::timeout_at(
                            progress_deadline,
                            ipc::read_frame_limited(reader, ipc::MAX_CONTROL_FRAME),
                        ) => result.map_err(|_| anyhow::anyhow!("native download idle timeout elapsed"))??,
                        _ = cancellation.cancelled() => bail!("transfer cancelled"),
                        _ = shutdown.changed() => bail!("daemon shutting down during native download"),
                    } {
                        Some(ipc::Frame::TransferAck {
                            confirmed_bytes,
                            durable_bytes,
                        }) => {
                            ensure!(
                                confirmed_bytes == next,
                                "client confirmed an unexpected native download offset"
                            );
                            ensure!(
                                durable_bytes >= client_durable && durable_bytes <= confirmed_bytes,
                                "client reported an invalid native download durable offset"
                            );
                            client_durable = durable_bytes;
                        }
                        Some(mut unexpected) => {
                            unexpected.zeroize_sensitive();
                            bail!("client did not acknowledge the native download chunk")
                        }
                        None => bail!("client disconnected during native download"),
                    }
                    received = next;
                    write_native_control_until(
                        &mut stream,
                        &native::Control::Ack {
                            confirmed_offset: received,
                            durable_offset: client_durable,
                            receiver_window: window_bytes,
                        },
                        progress_deadline,
                        "native download idle timeout elapsed",
                    )
                    .await?;
                    progress.confirmed_bytes = received;
                    progress.durable_bytes = client_durable;
                    progress.updated_unix_ms = now_unix_ms();
                    registry.update(profile, progress.clone())?;
                    progress_deadline = deadline.min(Instant::now() + idle_timeout);
                    if last_progress_write.elapsed() >= Duration::from_millis(250) {
                        write_frame_until(
                            writer,
                            &ipc::Frame::TransferProgress {
                                progress: progress.clone(),
                            },
                            progress_deadline,
                        )
                        .await?;
                        last_progress_write = Instant::now();
                    }
                }
                native::Frame::Control(native::Control::Completed { size, sha256 }) => {
                    ensure!(
                        size == total && received == total,
                        "native download size mismatch"
                    );
                    let suffix_sha256 = hex::encode(received_hasher.finalize());
                    ensure!(
                        sha256 == expected_sha256
                            && (start_offset > 0 || suffix_sha256 == expected_sha256),
                        "native download SHA-256 mismatch"
                    );
                    break;
                }
                native::Frame::Control(native::Control::Error {
                    code,
                    message,
                    outcome_unknown,
                }) => return Err(native_helper_error(&code, &message, outcome_unknown)),
                _ => bail!("unexpected native download frame"),
            }
        }
        progress.stage = ipc::TransferStage::Verifying;
        progress.updated_unix_ms = now_unix_ms();
        registry.update(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferDone { bytes: total },
            progress_deadline,
        )
        .await?;
        match tokio::select! {
            result = tokio::time::timeout_at(
                progress_deadline,
                ipc::read_frame_limited(reader, ipc::MAX_CONTROL_FRAME),
            ) => result.map_err(|_| anyhow::anyhow!("native download idle timeout elapsed"))??,
            _ = cancellation.cancelled() => bail!("transfer cancelled"),
            _ = shutdown.changed() => bail!("daemon shutting down during native download"),
        } {
            Some(ipc::Frame::Ack) => {}
            Some(mut unexpected) => {
                unexpected.zeroize_sensitive();
                bail!("client did not confirm the native download commit")
            }
            None => bail!("client disconnected before confirming the native download commit"),
        }
        progress.durable_bytes = total;
        progress = terminal_transfer_progress(
            progress.clone(),
            ipc::TransferStage::Completed,
            "completed",
        );
        registry.finish(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        Ok(())
    };
    match tokio::time::timeout_at(deadline, operation).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            if !cancellation.is_cancelled() && is_transfer_stall_error(&error) {
                progress.stage = ipc::TransferStage::Stalled;
                progress.event = "stalled".to_owned();
                progress.updated_unix_ms = now_unix_ms();
                registry.update(profile, progress.clone())?;
                let _ = write_frame_until(
                    writer,
                    &ipc::Frame::TransferProgress {
                        progress: progress.clone(),
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                )
                .await;
            }
            let (stage, event) = if cancellation.is_cancelled() {
                (ipc::TransferStage::Cancelled, "cancelled")
            } else {
                (ipc::TransferStage::Failed, "failed")
            };
            progress = terminal_transfer_progress(progress, stage, event);
            registry.finish(profile, progress)?;
            Err(error)
        }
        Err(_) => {
            progress.stage = ipc::TransferStage::Stalled;
            progress.event = "stalled".to_owned();
            progress.updated_unix_ms = now_unix_ms();
            registry.update(profile, progress.clone())?;
            let _ = write_frame_until(
                writer,
                &ipc::Frame::TransferProgress {
                    progress: progress.clone(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
            )
            .await;
            progress = terminal_transfer_progress(progress, ipc::TransferStage::Failed, "failed");
            registry.finish(profile, progress)?;
            bail!("native download exceeded its deadline of {timeout_ms} ms")
        }
    }
}

async fn serve_download<R, W>(
    session: &SshSession,
    reader: &mut R,
    writer: &mut W,
    request: DownloadServeRequest<'_>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let DownloadServeRequest {
        path,
        resume_offset: _,
        expected_size: _,
        expected_sha256: _,
        timeout_ms,
        idle_timeout,
        deadline,
        registry,
        profile,
        mut progress,
        cancellation,
    } = request;
    let mut progress_deadline = deadline.min(Instant::now() + idle_timeout);
    let operation = async {
        let sftp = session.sftp_until(progress_deadline).await?;
        let mut file = tokio::time::timeout_at(progress_deadline, sftp.open(path))
            .await
            .map_err(|_| anyhow::anyhow!("SFTP download idle timeout elapsed"))??;
        let total = tokio::time::timeout_at(progress_deadline, file.metadata())
            .await
            .map_err(|_| anyhow::anyhow!("SFTP download idle timeout elapsed"))??
            .len();
        ensure!(
            total <= MAX_TRANSFER_BYTES,
            "download exceeds the {} byte safety limit",
            MAX_TRANSFER_BYTES
        );
        progress.total_bytes = total;
        progress.stage = ipc::TransferStage::Transferring;
        progress.updated_unix_ms = now_unix_ms();
        registry.update(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        let mut transferred = 0_u64;
        let mut sent_hasher = Sha256::new();
        let mut last_progress_write = Instant::now();
        let mut buffer = Zeroizing::new(vec![0_u8; ipc::SFTP_SAFE_CHUNK_BYTES]);
        loop {
            let read = tokio::select! {
                result = tokio::time::timeout_at(progress_deadline, file.read(&mut buffer)) => {
                    result.map_err(|_| anyhow::anyhow!("SFTP download idle timeout elapsed"))??
                },
                _ = cancellation.cancelled() => bail!("transfer cancelled"),
                _ = shutdown.changed() => bail!("daemon shutting down during download"),
            };
            if read == 0 {
                tokio::time::timeout_at(progress_deadline, file.shutdown())
                    .await
                    .map_err(|_| anyhow::anyhow!("SFTP download idle timeout elapsed"))??;
                break;
            }
            let next = transferred
                .checked_add(read as u64)
                .ok_or_else(|| anyhow::anyhow!("download size overflow"))?;
            if next > total || next > MAX_TRANSFER_BYTES {
                bail!("remote source size changed during download or exceeded the safety limit");
            }
            let frame = ZeroizingResponseFrame(ipc::Frame::FileChunk {
                data: buffer[..read].to_vec(),
            });
            sent_hasher.update(&buffer[..read]);
            write_frame_until(writer, &frame.0, progress_deadline).await?;
            let acknowledgement = tokio::select! {
                result = tokio::time::timeout_at(
                    progress_deadline,
                    ipc::read_frame_limited(reader, ipc::MAX_CONTROL_FRAME),
                ) => match result {
                    Ok(result) => result?,
                    Err(_) => bail!("SFTP download exceeded its deadline of {timeout_ms} ms"),
                },
                _ = cancellation.cancelled() => bail!("transfer cancelled"),
                _ = shutdown.changed() => bail!("daemon shutting down during download"),
            };
            match acknowledgement {
                Some(ipc::Frame::TransferAck {
                    confirmed_bytes,
                    durable_bytes,
                }) => {
                    ensure!(
                        confirmed_bytes == next && durable_bytes <= confirmed_bytes,
                        "client acknowledged an invalid downloaded offset"
                    );
                    progress.durable_bytes = durable_bytes;
                }
                Some(mut unexpected) => {
                    unexpected.zeroize_sensitive();
                    bail!("client did not acknowledge the downloaded chunk")
                }
                None => bail!("client disconnected during download"),
            }
            transferred = next;
            progress.confirmed_bytes = transferred;
            progress.updated_unix_ms = now_unix_ms();
            registry.update(profile, progress.clone())?;
            progress_deadline = deadline.min(Instant::now() + idle_timeout);
            if last_progress_write.elapsed() >= Duration::from_millis(250) {
                write_frame_until(
                    writer,
                    &ipc::Frame::TransferProgress {
                        progress: progress.clone(),
                    },
                    progress_deadline,
                )
                .await?;
                last_progress_write = Instant::now();
            }
        }
        ensure!(
            transferred == total,
            "remote source size changed during download"
        );
        progress.stage = ipc::TransferStage::Verifying;
        progress.updated_unix_ms = now_unix_ms();
        registry.update(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferDigest {
                transfer_id: progress.transfer_id.clone(),
                sha256: hex::encode(sent_hasher.finalize()),
            },
            progress_deadline,
        )
        .await?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferDone { bytes: transferred },
            progress_deadline,
        )
        .await?;
        // The client sends this final Ack only after its protected temporary
        // file has been verified and committed with no-overwrite semantics.
        match tokio::select! {
            result = tokio::time::timeout_at(
                progress_deadline,
                ipc::read_frame_limited(reader, ipc::MAX_CONTROL_FRAME),
            ) => match result {
                Ok(result) => result?,
                Err(_) => bail!("SFTP download exceeded its deadline of {timeout_ms} ms"),
            },
            _ = cancellation.cancelled() => bail!("transfer cancelled"),
            _ = shutdown.changed() => bail!("daemon shutting down during download"),
        } {
            Some(ipc::Frame::Ack) => {}
            Some(mut unexpected) => {
                unexpected.zeroize_sensitive();
                bail!("client did not confirm the local no-overwrite commit")
            }
            None => bail!("client disconnected before confirming the local commit"),
        }
        progress.durable_bytes = total;
        progress = terminal_transfer_progress(
            progress.clone(),
            ipc::TransferStage::Completed,
            "completed",
        );
        registry.finish(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        Ok(())
    };
    match tokio::time::timeout_at(deadline, operation).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            if !cancellation.is_cancelled() && is_transfer_stall_error(&error) {
                progress.stage = ipc::TransferStage::Stalled;
                progress.event = "stalled".to_owned();
                progress.updated_unix_ms = now_unix_ms();
                registry.update(profile, progress.clone())?;
                let _ = write_frame_until(
                    writer,
                    &ipc::Frame::TransferProgress {
                        progress: progress.clone(),
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                )
                .await;
            }
            let stage = if cancellation.is_cancelled() {
                ipc::TransferStage::Cancelled
            } else {
                ipc::TransferStage::Failed
            };
            let event = if cancellation.is_cancelled() {
                "cancelled"
            } else {
                "failed"
            };
            progress = terminal_transfer_progress(progress, stage, event);
            registry.finish(profile, progress)?;
            // A blocked/broken IPC consumer says nothing about the SSH/SFTP
            // protocol state. The current SFTP request has already completed
            // before its FileChunk is written, and dropping the file/session
            // closes only that channel. Invalidating the daemon-wide shared
            // SSH transport here would let one authenticated client that stops
            // reading a download tear down every unrelated exec/shell/transfer.
            if !error.is::<IpcResponseWriteFailure>() {
                session.invalidate().await;
            }
            Err(error)
        }
        Err(_) => {
            progress.stage = ipc::TransferStage::Stalled;
            progress.event = "stalled".to_owned();
            progress.updated_unix_ms = now_unix_ms();
            registry.update(profile, progress.clone())?;
            let _ = write_frame_until(
                writer,
                &ipc::Frame::TransferProgress {
                    progress: progress.clone(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
            )
            .await;
            progress = terminal_transfer_progress(progress, ipc::TransferStage::Failed, "failed");
            registry.finish(profile, progress)?;
            session.invalidate().await;
            bail!("SFTP download exceeded its deadline of {timeout_ms} ms")
        }
    }
}

struct UploadRequest<'a> {
    path: &'a str,
    size: u64,
    sha256: &'a str,
    resume: ipc::TransferResumeMode,
    resume_token: Option<&'a str>,
    timeout_ms: u64,
    idle_timeout: Duration,
    deadline: Instant,
    registry: &'a TransferRegistry,
    profile: &'a str,
    progress: ipc::TransferProgress,
    cancellation: Arc<TransferCancellation>,
}

async fn serve_native_upload<R, W>(
    channel: NativeTransferChannel,
    reader: &mut R,
    writer: &mut W,
    request: UploadRequest<'_>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let UploadRequest {
        path,
        size,
        sha256,
        resume,
        resume_token,
        timeout_ms,
        idle_timeout,
        deadline,
        registry,
        profile,
        mut progress,
        cancellation,
    } = request;
    let NativeTransferChannel {
        mut stream,
        chunk_bytes,
        window_bytes,
        ..
    } = channel;
    let transfer_id = native::parse_transfer_id(progress.transfer_id.as_str())?;
    let mut progress_deadline = deadline.min(Instant::now() + idle_timeout);
    let mut commit_sent = false;
    let operation = async {
        validate_upload_remote_path(path)?;
        ensure!(
            size <= MAX_TRANSFER_BYTES,
            "upload exceeds the configured safety limit"
        );
        let ephemeral_token;
        let effective_resume_token = if let Some(token) = resume_token {
            token
        } else {
            ephemeral_token = Zeroizing::new(format!(
                "{}{}",
                ipc::TransferId::random().as_str(),
                ipc::TransferId::random().as_str()
            ));
            ephemeral_token.as_str()
        };
        let begin_push = Zeroizing::new(native::Control::BeginPush {
            transfer_id: progress.transfer_id.as_str().to_owned(),
            target: path.to_owned(),
            size,
            sha256: sha256.to_owned(),
            resume_token: effective_resume_token.to_owned(),
            resume: resume == ipc::TransferResumeMode::Auto,
        });
        write_native_control_until(
            &mut stream,
            &begin_push,
            progress_deadline,
            "native upload idle timeout elapsed",
        )
        .await?;
        let (helper_chunk, helper_window, mut confirmed, mut durable) =
            match read_native_transfer_frame(
                &mut stream,
                &cancellation,
                shutdown,
                progress_deadline,
                "native upload idle timeout elapsed",
            )
            .await?
            {
                native::Frame::Control(native::Control::Ready {
                    chunk,
                    window,
                    durable_offset,
                }) => {
                    ensure!(
                        chunk > 0 && chunk <= chunk_bytes,
                        "native helper exceeded the negotiated chunk size"
                    );
                    ensure!(
                        window >= chunk && window <= window_bytes,
                        "native helper exceeded the negotiated window"
                    );
                    ensure!(
                        durable_offset <= size,
                        "native helper returned a resume offset beyond the source size"
                    );
                    if resume == ipc::TransferResumeMode::Never {
                        ensure!(
                            durable_offset == 0,
                            "native helper resumed a resume=never upload"
                        );
                    }
                    (chunk, window, durable_offset, durable_offset)
                }
                native::Frame::Control(native::Control::Error {
                    code,
                    message,
                    outcome_unknown,
                }) => return Err(native_helper_error(&code, &message, outcome_unknown)),
                _ => bail!("native helper did not accept the upload request"),
            };
        progress.chunk_bytes = helper_chunk;
        progress.window_bytes = helper_chunk;
        progress.stage = ipc::TransferStage::Transferring;
        progress.confirmed_bytes = confirmed;
        progress.durable_bytes = durable;
        if confirmed > 0 {
            progress.event = "resumed".to_owned();
        }
        progress.updated_unix_ms = now_unix_ms();
        registry.update(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        progress.event = "progress".to_owned();
        write_frame_until(writer, &ipc::Frame::Ack, progress_deadline).await?;
        let mut last_progress_write = Instant::now();
        loop {
            let frame = tokio::select! {
                result = tokio::time::timeout_at(
                    progress_deadline,
                    ipc::read_frame_limited(reader, ipc::MAX_UPLOAD_FRAME),
                ) => result.map_err(|_| anyhow::anyhow!("native upload idle timeout elapsed"))??,
                _ = shutdown.changed() => bail!("daemon shutting down during native upload"),
                _ = cancellation.cancelled() => bail!("transfer cancelled"),
            };
            match frame {
                Some(ipc::Frame::UploadChunk { data }) => {
                    let mut data = Zeroizing::new(data);
                    ensure!(
                        !data.is_empty() && data.len() <= helper_chunk as usize,
                        "native upload chunk exceeds the negotiated size"
                    );
                    let next = confirmed
                        .checked_add(data.len() as u64)
                        .context("native upload size overflow")?;
                    ensure!(next <= size, "native upload exceeded its declared size");
                    let native_data =
                        native::DataFrame::new(transfer_id, confirmed, std::mem::take(&mut *data))?;
                    write_native_data_until(
                        &mut stream,
                        &native_data,
                        progress_deadline,
                        "native upload idle timeout elapsed",
                    )
                    .await?;
                    match read_native_transfer_frame(
                        &mut stream,
                        &cancellation,
                        shutdown,
                        progress_deadline,
                        "native upload idle timeout elapsed",
                    )
                    .await?
                    {
                        native::Frame::Control(native::Control::Ack {
                            confirmed_offset,
                            durable_offset,
                            receiver_window,
                        }) => {
                            ensure!(
                                confirmed_offset == next,
                                "native upload acknowledgement offset mismatch"
                            );
                            ensure!(
                                durable_offset >= durable && durable_offset <= confirmed_offset,
                                "native upload durable offset is invalid"
                            );
                            ensure!(
                                receiver_window >= helper_chunk && receiver_window <= helper_window,
                                "native helper returned an invalid receiver window"
                            );
                            confirmed = confirmed_offset;
                            durable = durable_offset;
                        }
                        native::Frame::Control(native::Control::Error {
                            code,
                            message,
                            outcome_unknown,
                        }) => return Err(native_helper_error(&code, &message, outcome_unknown)),
                        _ => bail!("native upload acknowledgement mismatch"),
                    }
                    progress.stage = ipc::TransferStage::Transferring;
                    progress.confirmed_bytes = confirmed;
                    progress.durable_bytes = durable;
                    progress.updated_unix_ms = now_unix_ms();
                    registry.update(profile, progress.clone())?;
                    progress_deadline = deadline.min(Instant::now() + idle_timeout);
                    if last_progress_write.elapsed() >= Duration::from_millis(250) {
                        write_frame_until(
                            writer,
                            &ipc::Frame::TransferProgress {
                                progress: progress.clone(),
                            },
                            progress_deadline,
                        )
                        .await?;
                        last_progress_write = Instant::now();
                    }
                    write_frame_until(writer, &ipc::Frame::Ack, progress_deadline).await?;
                }
                Some(ipc::Frame::UploadEnd) => break,
                Some(mut unexpected) => {
                    unexpected.zeroize_sensitive();
                    bail!("unexpected frame during native upload")
                }
                None => bail!("client disconnected during native upload"),
            }
        }
        ensure!(confirmed == size, "native upload size mismatch");
        progress.stage = ipc::TransferStage::Verifying;
        progress.updated_unix_ms = now_unix_ms();
        registry.update(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        commit_sent = true;
        progress.stage = ipc::TransferStage::Committing;
        progress.updated_unix_ms = now_unix_ms();
        registry.update(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        write_native_control_until(
            &mut stream,
            &native::Control::Commit,
            progress_deadline,
            "native upload commit outcome unknown after timeout",
        )
        .await?;
        match read_native_transfer_frame(
            &mut stream,
            &cancellation,
            shutdown,
            progress_deadline,
            "native upload commit outcome unknown after timeout",
        )
        .await?
        {
            native::Frame::Control(native::Control::Completed {
                size: completed_size,
                sha256: completed_sha256,
            }) => {
                ensure!(
                    completed_size == size && completed_sha256 == sha256,
                    "native upload completion proof mismatch"
                );
            }
            native::Frame::Control(native::Control::Error {
                code,
                message,
                outcome_unknown,
            }) => return Err(native_helper_error(&code, &message, outcome_unknown)),
            _ => bail!("native helper did not confirm the upload commit"),
        }
        progress.confirmed_bytes = size;
        progress.durable_bytes = size;
        progress = terminal_transfer_progress(
            progress.clone(),
            ipc::TransferStage::Completed,
            "completed",
        );
        registry.finish(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferDone { bytes: size },
            progress_deadline,
        )
        .await?;
        Ok(())
    };
    let result = tokio::time::timeout_at(deadline, operation).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            if !cancellation.is_cancelled() && is_transfer_stall_error(&error) {
                progress.stage = ipc::TransferStage::Stalled;
                progress.event = "stalled".to_owned();
                progress.updated_unix_ms = now_unix_ms();
                registry.update(profile, progress.clone())?;
                let _ = write_frame_until(
                    writer,
                    &ipc::Frame::TransferProgress {
                        progress: progress.clone(),
                    },
                    Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
                )
                .await;
            }
            let (stage, event) = if commit_sent {
                (ipc::TransferStage::Failed, "outcome_unknown")
            } else if cancellation.is_cancelled() {
                (ipc::TransferStage::Cancelled, "cancelled")
            } else {
                (ipc::TransferStage::Failed, "failed")
            };
            progress = terminal_transfer_progress(progress, stage, event);
            registry.finish(profile, progress)?;
            if commit_sent {
                Err(error).context(format!(
                    "native upload commit outcome unknown; inspect {path} before retry"
                ))
            } else {
                Err(error)
            }
        }
        Err(_) => {
            progress.stage = ipc::TransferStage::Stalled;
            progress.event = "stalled".to_owned();
            progress.updated_unix_ms = now_unix_ms();
            registry.update(profile, progress.clone())?;
            let _ = write_frame_until(
                writer,
                &ipc::Frame::TransferProgress {
                    progress: progress.clone(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
            )
            .await;
            progress = terminal_transfer_progress(
                progress,
                ipc::TransferStage::Failed,
                if commit_sent {
                    "outcome_unknown"
                } else {
                    "failed"
                },
            );
            registry.finish(profile, progress)?;
            if commit_sent {
                bail!("native upload commit outcome unknown after its deadline of {timeout_ms} ms")
            }
            bail!("native upload exceeded its deadline of {timeout_ms} ms")
        }
    }
}

async fn upload_remote_step<R, F, T, S>(
    reader: &mut R,
    shutdown: &mut watch::Receiver<bool>,
    cancellation: &TransferCancellation,
    deadline: Instant,
    uncertain: &AtomicBool,
    on_first_poll: S,
    operation: F,
) -> Result<T>
where
    R: AsyncRead + Unpin,
    F: std::future::Future<Output = Result<T>>,
    S: FnOnce(),
{
    let guarded_operation = poll_remote_mutation_until(
        deadline,
        operation,
        on_first_poll,
        || uncertain.store(true, Ordering::Release),
        "SFTP upload exceeded its deadline",
    );
    tokio::select! {
        result = guarded_operation => result,
        disconnected = reader.read_u8() => {
            uncertain.store(true, Ordering::Release);
            match disconnected {
                Ok(_) => bail!("client sent data before the previous upload chunk was acknowledged"),
                Err(_) => bail!("client disconnected during remote upload operation"),
            }
        },
        _ = shutdown.changed() => {
            uncertain.store(true, Ordering::Release);
            bail!("daemon shutting down during upload")
        },
        _ = cancellation.cancelled() => {
            uncertain.store(true, Ordering::Release);
            bail!("transfer cancelled")
        },
    }
}

async fn serve_upload<R, W>(
    session: &SshSession,
    reader: &mut R,
    writer: &mut W,
    request: UploadRequest<'_>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let UploadRequest {
        path,
        size,
        sha256,
        resume: _,
        resume_token: _,
        timeout_ms,
        idle_timeout,
        deadline,
        registry,
        profile,
        mut progress,
        cancellation,
    } = request;
    let mut progress_deadline = deadline.min(Instant::now() + idle_timeout);
    let sftp = match tokio::select! {
        result = session.sftp_until(progress_deadline) => Some(result),
        _ = reader.read_u8() => None,
        _ = shutdown.changed() => None,
    } {
        Some(result) => result?,
        None => {
            session.invalidate().await;
            bail!("upload setup canceled before it completed")
        }
    };
    let partial = temporary_remote_path(path)?;
    let mut partial_may_exist = false;
    let invalidate_after_cleanup = AtomicBool::new(false);
    let commit_started = AtomicBool::new(false);
    let remote_committed = AtomicBool::new(false);
    let transfer = async {
        validate_upload_remote_path(path)?;
        if size > MAX_TRANSFER_BYTES {
            bail!(
                "upload exceeds the {} byte safety limit",
                MAX_TRANSFER_BYTES
            );
        }
        if upload_remote_step(
            reader,
            shutdown,
            &cancellation,
            progress_deadline,
            &invalidate_after_cleanup,
            || {},
            async { Ok(sftp.try_exists(path).await?) },
        )
        .await?
        {
            bail!("remote destination already exists: {path}");
        }
        let opened = upload_remote_step(
            reader,
            shutdown,
            &cancellation,
            progress_deadline,
            &invalidate_after_cleanup,
            || partial_may_exist = true,
            session.confirmed_sftp_upload_until(&partial, progress_deadline),
        )
        .await;
        let mut file = match opened {
            Ok(file) => file,
            Err(error) => {
                if is_explicit_sftp_status(&error) {
                    // A definite EXCLUDE failure means this request never
                    // owned the random partial name. Do not delete it.
                    partial_may_exist = false;
                }
                return Err(error);
            }
        };
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        write_frame_until(writer, &ipc::Frame::Ack, progress_deadline).await?;
        let mut transferred = 0_u64;
        let mut received_hasher = Sha256::new();
        let mut last_progress_write = Instant::now();
        loop {
            let frame = tokio::select! {
                result = tokio::time::timeout_at(
                    progress_deadline,
                    ipc::read_frame_limited(reader, ipc::MAX_UPLOAD_FRAME),
                ) => match result {
                    Ok(result) => result?,
                    Err(_) => {
                        invalidate_after_cleanup.store(true, Ordering::Release);
                        bail!("SFTP upload exceeded its deadline of {timeout_ms} ms")
                    }
                },
                _ = shutdown.changed() => {
                    invalidate_after_cleanup.store(true, Ordering::Release);
                    bail!("daemon shutting down during upload")
                },
                _ = cancellation.cancelled() => {
                    invalidate_after_cleanup.store(true, Ordering::Release);
                    bail!("transfer cancelled")
                },
            };
            match frame {
                Some(ipc::Frame::UploadChunk { data }) => {
                    let mut data = Zeroizing::new(data);
                    if data.is_empty() || data.len() > MAX_UPLOAD_CHUNK_BYTES {
                        data.zeroize();
                        bail!("upload chunk is empty or exceeds {MAX_UPLOAD_CHUNK_BYTES} bytes");
                    }
                    let Some(next) = transferred.checked_add(data.len() as u64) else {
                        data.zeroize();
                        bail!("upload size overflow");
                    };
                    if next > size || next > MAX_TRANSFER_BYTES {
                        data.zeroize();
                        bail!("upload exceeded its declared or configured size");
                    }
                    let write = upload_remote_step(
                        reader,
                        shutdown,
                        &cancellation,
                        progress_deadline,
                        &invalidate_after_cleanup,
                        || {},
                        file.write_confirmed(&data),
                    )
                    .await;
                    let confirmed = write?;
                    ensure!(
                        confirmed == next,
                        "SFTP upload confirmation offset mismatch"
                    );
                    received_hasher.update(data.as_slice());
                    data.zeroize();
                    transferred = next;
                    progress.stage = ipc::TransferStage::Transferring;
                    progress.confirmed_bytes = transferred;
                    progress.updated_unix_ms = now_unix_ms();
                    registry.update(profile, progress.clone())?;
                    progress_deadline = deadline.min(Instant::now() + idle_timeout);
                    if last_progress_write.elapsed() >= Duration::from_millis(250) {
                        write_frame_until(
                            writer,
                            &ipc::Frame::TransferProgress {
                                progress: progress.clone(),
                            },
                            progress_deadline,
                        )
                        .await?;
                        last_progress_write = Instant::now();
                    }
                    write_frame_until(writer, &ipc::Frame::Ack, progress_deadline).await?;
                }
                Some(ipc::Frame::UploadEnd) => break,
                Some(mut frame) => {
                    frame.zeroize_sensitive();
                    bail!("unexpected frame during upload")
                }
                None => {
                    invalidate_after_cleanup.store(true, Ordering::Release);
                    bail!("client disconnected during upload")
                }
            }
        }
        if transferred != size {
            bail!("upload size mismatch: expected {size}, received {transferred}");
        }
        ensure!(
            hex::encode(received_hasher.finalize()) == sha256,
            "upload source changed after preflight hashing"
        );
        let closed_at = upload_remote_step(
            reader,
            shutdown,
            &cancellation,
            progress_deadline,
            &invalidate_after_cleanup,
            || {},
            file.close_confirmed(),
        )
        .await?;
        ensure!(
            closed_at == transferred,
            "SFTP upload close offset mismatch"
        );
        drop(file);
        progress.stage = ipc::TransferStage::Verifying;
        progress.confirmed_bytes = transferred;
        progress.updated_unix_ms = now_unix_ms();
        registry.update(profile, progress.clone())?;
        progress_deadline = deadline.min(Instant::now() + idle_timeout);
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        let mut verify_file = upload_remote_step(
            reader,
            shutdown,
            &cancellation,
            progress_deadline,
            &invalidate_after_cleanup,
            || {},
            async { Ok(sftp.open(&partial).await?) },
        )
        .await?;
        let mut remote_hasher = Sha256::new();
        // Verification is read-only and has no queued-WRITE acknowledgement
        // ambiguity. Use the bounded upload-frame payload cap to avoid one
        // extra SFTP round trip per conservative upload chunk on
        // higher-latency servers.
        let mut verify_buffer = Zeroizing::new(vec![0_u8; MAX_UPLOAD_CHUNK_BYTES]);
        let mut verified_bytes = 0_u64;
        loop {
            let read = upload_remote_step(
                reader,
                shutdown,
                &cancellation,
                progress_deadline,
                &invalidate_after_cleanup,
                || {},
                async { Ok(verify_file.read(&mut verify_buffer).await?) },
            )
            .await?;
            if read == 0 {
                break;
            }
            remote_hasher.update(&verify_buffer[..read]);
            verified_bytes = verified_bytes
                .checked_add(read as u64)
                .context("remote verification byte count overflow")?;
            ensure!(
                verified_bytes <= size,
                "remote partial grew during verification"
            );
        }
        verify_file.shutdown().await?;
        ensure!(
            verified_bytes == size,
            "remote partial size changed during verification"
        );
        ensure!(
            hex::encode(remote_hasher.finalize()) == sha256,
            "remote partial SHA-256 mismatch"
        );
        if upload_remote_step(
            reader,
            shutdown,
            &cancellation,
            progress_deadline,
            &invalidate_after_cleanup,
            || {},
            async { Ok(sftp.try_exists(path).await?) },
        )
        .await?
        {
            bail!("remote destination was created during upload: {path}");
        }
        if Instant::now() >= progress_deadline {
            invalidate_after_cleanup.store(true, Ordering::Release);
            bail!("SFTP upload exceeded its deadline of {timeout_ms} ms");
        }
        commit_started.store(true, Ordering::Release);
        progress.stage = ipc::TransferStage::Committing;
        progress.updated_unix_ms = now_unix_ms();
        registry.update(profile, progress.clone())?;
        write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            progress_deadline,
        )
        .await?;
        let commit = upload_remote_step(
            reader,
            shutdown,
            &cancellation,
            progress_deadline,
            &invalidate_after_cleanup,
            || {},
            commit_remote_upload_no_replace_until(
                &sftp,
                &partial,
                path,
                &remote_committed,
                progress_deadline,
                "SFTP upload exceeded its deadline",
            ),
        )
        .await?;
        if commit.partial_removed || cleanup_remote_partial(session, &partial).await {
            partial_may_exist = false;
        } else {
            log::warn!(
                "upload committed to {}, but remote temporary name {} could not be removed",
                terminal_safe_field(path),
                terminal_safe_field(&partial),
            );
        }
        Ok(transferred)
    };
    let operation: Result<u64> = match tokio::time::timeout_at(deadline, transfer).await {
        Ok(result) => result,
        Err(_) => {
            invalidate_after_cleanup.store(true, Ordering::Release);
            Err(anyhow::anyhow!(
                "SFTP upload exceeded its deadline of {timeout_ms} ms"
            ))
        }
    };

    drop(sftp);
    let committed = remote_committed.load(Ordering::Acquire);
    if committed {
        progress.confirmed_bytes = size;
        progress.durable_bytes = size;
        progress = terminal_transfer_progress(progress, ipc::TransferStage::Completed, "completed");
        registry.finish(profile, progress.clone())?;
    } else if operation.is_err() {
        if !cancellation.is_cancelled()
            && operation
                .as_ref()
                .err()
                .is_some_and(is_transfer_stall_error)
        {
            progress.stage = ipc::TransferStage::Stalled;
            progress.event = "stalled".to_owned();
            progress.updated_unix_ms = now_unix_ms();
            registry.update(profile, progress.clone())?;
            let _ = write_frame_until(
                writer,
                &ipc::Frame::TransferProgress {
                    progress: progress.clone(),
                },
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT,
            )
            .await;
        }
        let stage = if cancellation.is_cancelled() {
            ipc::TransferStage::Cancelled
        } else {
            ipc::TransferStage::Failed
        };
        let event = if cancellation.is_cancelled() {
            "cancelled"
        } else {
            "failed"
        };
        progress = terminal_transfer_progress(progress, stage, event);
        registry.finish(profile, progress.clone())?;
    }
    if committed {
        if let Err(error) = &operation {
            log::warn!(
                "upload to {} committed before post-commit cleanup was interrupted: {}",
                terminal_safe_field(path),
                terminal_safe_error(error),
            );
        }
    }

    // Once a hardlink commit has been acknowledged by the server, cleanup is
    // no longer part of the upload outcome. Reconcile that durable outcome
    // with the client before opening a fresh SFTP channel to remove the owned
    // partial name. Otherwise two bounded cleanup/invalidation steps could
    // consume longer than the client's post-deadline reconciliation window
    // and falsely report an already committed upload as "outcome unknown".
    let committed_response = if committed {
        let response_deadline = Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT;
        let progress_response = write_frame_until(
            writer,
            &ipc::Frame::TransferProgress {
                progress: progress.clone(),
            },
            response_deadline,
        )
        .await;
        Some(match progress_response {
            Ok(()) => {
                write_frame_until(
                    writer,
                    &ipc::Frame::TransferDone { bytes: size },
                    response_deadline,
                )
                .await
            }
            Err(error) => Err(error),
        })
    } else {
        None
    };
    let ipc_response_failed = operation
        .as_ref()
        .err()
        .is_some_and(|error| error.is::<IpcResponseWriteFailure>());
    if operation.is_err() && partial_may_exist && !ipc_response_failed {
        // A failed WRITE/CLOSE can leave protocol state ambiguous even if the
        // future itself completed with an error. A failed IPC Ack is different:
        // it is downstream of the completed SFTP step and must not poison the
        // daemon-wide shared SSH transport.
        invalidate_after_cleanup.store(true, Ordering::Release);
    }
    if operation.is_err() && partial_may_exist && !cleanup_remote_partial(session, &partial).await {
        log::warn!(
            "remote upload partial cleanup failed for {}",
            terminal_safe_field(&partial)
        );
        // Cleanup itself is a remote operation. If it cannot establish a
        // definite result, discard the shared transport even when the
        // original failure was only an IPC backpressure failure.
        invalidate_after_cleanup.store(true, Ordering::Release);
    }
    if invalidate_after_cleanup.load(Ordering::Acquire) {
        session.invalidate().await;
    }
    match (operation, committed_response) {
        (_, Some(response)) => response,
        (Ok(transferred), None) => {
            let response_deadline = if deadline > Instant::now() {
                deadline
            } else {
                Instant::now() + IPC_RESPONSE_WRITE_TIMEOUT
            };
            write_frame_until(
                writer,
                &ipc::Frame::TransferDone { bytes: transferred },
                response_deadline,
            )
            .await
        }
        (Err(error), None)
            if commit_started.load(Ordering::Acquire)
                && invalidate_after_cleanup.load(Ordering::Acquire) =>
        {
            Err(error).context(format!(
                "SFTP upload commit outcome unknown; inspect {path} before retry"
            ))
        }
        (Err(error), None) => Err(error),
    }
}

async fn cleanup_remote_partial(session: &SshSession, partial: &str) -> bool {
    let deadline = Instant::now() + REMOTE_PARTIAL_CLEANUP_TIMEOUT;
    let sftp = match tokio::time::timeout_at(deadline, session.sftp_until(deadline)).await {
        Ok(Ok(sftp)) => sftp,
        Ok(Err(error)) => {
            log::warn!(
                "open fresh SFTP channel for partial cleanup: {}",
                terminal_safe_error(&error)
            );
            return false;
        }
        Err(_) => {
            log::warn!("opening fresh SFTP channel for partial cleanup timed out");
            return false;
        }
    };

    loop {
        match poll_remote_mutation_until(
            deadline,
            sftp.remove_file(partial),
            || {},
            || {},
            "remote partial cleanup exceeded its deadline",
        )
        .await
        {
            Ok(()) => return true,
            Err(_) => {
                // A CREATE request canceled at its deadline may finish on the
                // server after the first remove attempt observes no file.
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        if tokio::time::timeout_at(deadline, tokio::time::sleep(REMOTE_PARTIAL_CLEANUP_RETRY))
            .await
            .is_err()
        {
            return false;
        }
    }
}

fn validated_exec_timeout(timeout_ms: u64) -> Result<std::time::Duration> {
    if !(1..=ipc::MAX_EXEC_TIMEOUT_MS).contains(&timeout_ms) {
        bail!(
            "exec timeout must be between 1 and {} ms",
            ipc::MAX_EXEC_TIMEOUT_MS
        );
    }
    Ok(std::time::Duration::from_millis(timeout_ms))
}

fn validated_sftp_timeout(timeout_ms: u64) -> Result<std::time::Duration> {
    if !(1..=ipc::MAX_SFTP_TIMEOUT_MS).contains(&timeout_ms) {
        bail!(
            "SFTP timeout must be between 1 and {} ms",
            ipc::MAX_SFTP_TIMEOUT_MS
        );
    }
    Ok(std::time::Duration::from_millis(timeout_ms))
}

#[cfg(test)]
mod tests {
    use super::{
        acquire_buffered_operation_slot, acquire_tunnel_control_slot,
        authenticate_incoming_protocol, await_owned_blocking_until, daemon_up_line,
        exec_outcome_unknown_wire_message, exec_request_rejected_wire_message, handoff_readiness,
        ipc, native, negotiate_native_stream, negotiated_native_limits, read_authenticated_request,
        read_shell_frame_pump, read_shell_frame_pump_inner, recover_invalid_startup_lock_read,
        should_probe_native_helper, status_info_frame, stop_tunnel_and_report, terminal_safe_error,
        transfer_progress, validate_connection_identity_binding, validate_grant_frame_binding,
        validate_request_frame, validated_exec_timeout, validated_sftp_timeout,
        wait_for_tunnel_control_or_completion, write_all_until_or_shutdown,
        write_frame_or_shutdown, ConnInfo, Creds, GrantAuditOperation, GrantLookup,
        GrantProfileBinding, GrantRecord, GrantRegistry, GrantTerminalKind, IdleTracker,
        InstanceId, ManagedTunnelOwner, ManagedTunnelRegistry, OperationContextBinding,
        OperationContextKey, TransferRegistry, TunnelControlWait, AUDIT_STATE_COMPLETE,
        AUDIT_STATE_PENDING, GRANTABLE_OPERATION_KINDS, GRANT_TERMINAL_TOMBSTONE_TTL,
        MAX_ACTIVE_MANAGED_TUNNELS_PER_PROFILE, MAX_ACTIVE_TRANSFERS_GLOBAL,
        MAX_ACTIVE_TRANSFERS_PER_PROFILE, MAX_COMPLETED_TRANSFERS_GLOBAL,
        MAX_COMPLETED_TRANSFERS_PER_PROFILE, MAX_UPLOAD_CHUNK_BYTES, TRANSFER_RECORD_RETENTION,
        UNKNOWN_GRANT_ERROR,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;
    use zeroize::Zeroize;

    /// `vault::set_test_home` is process-global; the three global-daemon tests
    /// serialize on it for their whole lifetime.
    static TEST_HOME_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn expected_native_helper_identity() -> ipc::ExpectedNativeHelperIdentity {
        ipc::ExpectedNativeHelperIdentity {
            name: "serctl-xfer".to_owned(),
            binary_size: 123,
            sha256: "ab".repeat(32),
            version: "serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)".to_owned(),
        }
    }

    #[test]
    fn native_probe_requires_an_exact_backend_appropriate_identity() {
        let expected = expected_native_helper_identity();
        assert!(!should_probe_native_helper(ipc::TransferBackend::Auto, None).unwrap());
        assert!(should_probe_native_helper(ipc::TransferBackend::Auto, Some(&expected)).unwrap());
        assert!(should_probe_native_helper(ipc::TransferBackend::Native, Some(&expected)).unwrap());
        assert!(should_probe_native_helper(ipc::TransferBackend::Native, None).is_err());
        assert!(should_probe_native_helper(ipc::TransferBackend::Sftp, Some(&expected)).is_err());
    }

    #[tokio::test]
    async fn helper_identity_mismatch_precedes_every_client_or_target_frame() {
        let expected = expected_native_helper_identity();
        let mut observed = expected.clone();
        observed.sha256 = "cd".repeat(32);
        let (client, mut helper) = tokio::io::duplex(16 * 1024);
        let helper_task = tokio::spawn(async move {
            native::write_handshake_control(
                &mut helper,
                &native::Control::HelperHello {
                    version: native::VERSION,
                    max_chunk: native::DEFAULT_CHUNK_BYTES,
                    max_window: native::MAX_WINDOW_BYTES,
                    resume: true,
                    sha256: true,
                    fsync: true,
                    no_replace: true,
                    identity: native::HelperRuntimeIdentity {
                        name: observed.name,
                        binary_size: observed.binary_size,
                        sha256: observed.sha256,
                        version: observed.version,
                    },
                },
                native::HandshakePeer::Helper,
            )
            .await
            .unwrap();
            native::read_frame(&mut helper).await.unwrap()
        });
        let error =
            negotiate_native_stream(client, &expected, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("exact release provenance"));
        assert!(helper_task.await.unwrap().is_none());
    }

    struct TestGrantEntry {
        profile_id: [u8; 16],
        generation: AtomicUsize,
        profile: String,
    }

    impl GrantProfileBinding for TestGrantEntry {
        fn identity(&self) -> serctl_core::vault::ProfileIdentity {
            serctl_core::vault::ProfileIdentity {
                profile_id: self.profile_id,
                generation: self.generation.load(Ordering::Acquire) as u64,
            }
        }

        fn profile_name(&self) -> &str {
            &self.profile
        }
    }

    fn signed_grant_prelude(
        grant: &serctl_protocol::grant::OperationGrant,
        signing: &ed25519_dalek::SigningKey,
    ) -> serctl_protocol::v6::V6RequestPrelude {
        signed_grant_prelude_for_operation(grant, signing, "daemon.status")
    }

    fn signed_grant_prelude_for_operation(
        grant: &serctl_protocol::grant::OperationGrant,
        signing: &ed25519_dalek::SigningKey,
        operation_kind: &str,
    ) -> serctl_protocol::v6::V6RequestPrelude {
        let mut prelude = serctl_protocol::v6::V6RequestPrelude {
            protocol_version: serctl_protocol::v6::IPC_PROTOCOL_VERSION_V6,
            client_session_id: [1_u8; 16],
            request_id: [2_u8; 16],
            operation_kind: operation_kind.into(),
            profile_id: None,
            profile_name: Some(grant.profile_name.clone()),
            grant_id: Some(grant.grant_id),
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: grant.expires_unix_ms - 1,
            root_request_hash: [3_u8; 32],
        };
        prelude.pop_signature =
            Some(serctl_protocol::grant::sign_prelude_pop(signing, &prelude).unwrap());
        prelude
    }

    #[cfg(unix)]
    static TEST_HOME_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    /// Owns the process-global test-home override and its private directory.
    /// The lock remains held until cleanup so a panic cannot leak either state
    /// into the next global-daemon test.
    struct GlobalTestHome {
        base: std::path::PathBuf,
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }

    impl GlobalTestHome {
        async fn create() -> Self {
            let lock = TEST_HOME_LOCK.lock().await;
            let base = create_global_test_base();
            serctl_core::vault::set_test_home(Some(base.clone()));
            Self { base, _lock: lock }
        }

        #[cfg(windows)]
        fn path(&self) -> &std::path::Path {
            &self.base
        }
    }

    impl Drop for GlobalTestHome {
        fn drop(&mut self) {
            serctl_core::vault::set_test_home(None);
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[cfg(unix)]
    fn create_global_test_base() -> std::path::PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock predates the Unix epoch")
            .as_nanos();
        for _ in 0..64 {
            let sequence = TEST_HOME_SEQUENCE.fetch_add(1, Ordering::Relaxed) as u128;
            let nonce = stamp.wrapping_add(sequence) as u32;
            let base = std::path::Path::new("/tmp")
                .join(format!("sctl-dmn-{:x}-{nonce:08x}", std::process::id()));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&base) {
                Ok(()) => return base,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!(
                    "failed to atomically create global-daemon test home {}: {error}",
                    base.display()
                ),
            }
        }
        panic!("failed to allocate a unique global-daemon test home under /tmp");
    }

    #[cfg(not(unix))]
    fn create_global_test_base() -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Preserve the established Windows temp-directory layout. Named pipes
        // are not constrained by Unix sockaddr_un::sun_path.
        let base = std::env::temp_dir().join(format!(
            "serctl-global-daemon-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock predates the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap_or_else(|error| {
            panic!(
                "failed to create global-daemon test home {}: {error}",
                base.display()
            )
        });
        base
    }

    #[cfg(unix)]
    fn assert_global_test_endpoint_fits(endpoint: &str) {
        // macOS has the narrowest supported sockaddr_un::sun_path (104 bytes,
        // including its trailing NUL). Keeping the assertion at that boundary
        // also leaves Linux comfortably below its 108-byte limit.
        const MACOS_SUN_PATH_CAPACITY: usize = 104;
        assert!(
            endpoint.len() < MACOS_SUN_PATH_CAPACITY,
            "global-daemon test endpoint is {} bytes and does not fit Unix sun_path: {endpoint}",
            endpoint.len()
        );
    }

    #[cfg(not(unix))]
    fn assert_global_test_endpoint_fits(_endpoint: &str) {}

    struct GlobalDaemonTask {
        handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    impl GlobalDaemonTask {
        fn new(handle: tokio::task::JoinHandle<anyhow::Result<()>>) -> Self {
            Self { handle }
        }

        fn is_finished(&self) -> bool {
            self.handle.is_finished()
        }

        async fn assert_running(&mut self, context: &str) {
            if !self.handle.is_finished() {
                return;
            }
            match (&mut self.handle).await {
                Ok(Ok(())) => panic!("{context}: daemon exited successfully before readiness"),
                Ok(Err(error)) => panic!("{context}: daemon exited with error: {error:#}"),
                Err(error) => panic!("{context}: daemon task failed: {error}"),
            }
        }

        async fn wait_for_exit(&mut self, timeout: Duration, context: &str) {
            match tokio::time::timeout(timeout, &mut self.handle).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => panic!("{context}: daemon exited with error: {error:#}"),
                Ok(Err(error)) => panic!("{context}: daemon task failed: {error}"),
                Err(_) => panic!("{context}"),
            }
        }
    }

    impl Drop for GlobalDaemonTask {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn wait_for_global_descriptor(
        daemon_task: &mut GlobalDaemonTask,
        timeout: Duration,
    ) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            match serctl_core::daemon_runtime::read_descriptor() {
                Ok(Some(descriptor)) => {
                    assert_global_test_endpoint_fits(&descriptor.endpoint);
                    return descriptor.endpoint;
                }
                Ok(None) => {}
                Err(error) => panic!("failed to read global-daemon runtime descriptor: {error:#}"),
            }
            daemon_task
                .assert_running("global daemon exited before publishing its runtime descriptor")
                .await;
            if Instant::now() >= deadline {
                panic!("global daemon did not publish its runtime descriptor within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn connect_global_until(
        daemon_task: &mut GlobalDaemonTask,
        endpoint: &str,
        timeout: Duration,
    ) -> ipc::ClientStream {
        let deadline = Instant::now() + timeout;
        let mut last_error = None;
        loop {
            daemon_task
                .assert_running("global daemon exited before an IPC connection was established")
                .await;
            let now = Instant::now();
            if now >= deadline {
                panic!(
                    "failed to connect to global daemon within {timeout:?}; last error: {}",
                    last_error
                        .as_deref()
                        .unwrap_or("connection attempt timed out")
                );
            }
            let attempt_timeout = (deadline - now).min(Duration::from_millis(100));
            match tokio::time::timeout(attempt_timeout, ipc::connect(endpoint)).await {
                Ok(Ok(stream)) => return stream,
                Ok(Err(error)) => last_error = Some(format!("{error:#}")),
                Err(_) => last_error = Some("connection attempt timed out".into()),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn grantable_operations_match_the_authenticated_daemon_data_plane() {
        assert_eq!(
            GRANTABLE_OPERATION_KINDS,
            &[
                "ssh.exec",
                "ssh.connection-identity",
                "daemon.status",
                "sftp.list",
                "sftp.write",
                "transfer.read",
                "transfer.write",
                "transfer.status",
                "transfer.cancel",
                "forward.local/open",
                "forward.remote/open",
                "forward.dynamic/open",
                "forward.status",
                "forward.cancel",
            ]
        );
    }

    fn managed_tunnel_test_status(
        owner: &ManagedTunnelOwner,
        id_suffix: usize,
    ) -> ipc::TunnelStatus {
        ipc::TunnelStatus {
            schema_version: ipc::TUNNEL_STATUS_SCHEMA_VERSION,
            tunnel_id: ipc::TunnelId::parse(&format!("{id_suffix:032x}")).unwrap(),
            profile_id: hex::encode(owner.profile_id),
            profile_generation: owner.generation,
            mode: ipc::TunnelMode::Local,
            bind_host: "127.0.0.1".into(),
            bind_port: 2200 + u16::try_from(id_suffix).unwrap(),
            target_host: Some("127.0.0.1".into()),
            target_port: 22,
            deadline_unix_ms: 1_900_000_000_000,
            stage: ipc::TunnelStage::Ready,
            updated_unix_ms: 1_800_000_000_000,
            operation_context_id: Some(
                ipc::OperationContextId::parse(&format!("{id_suffix:064x}")).unwrap(),
            ),
            revision: 1,
        }
    }

    #[tokio::test]
    async fn managed_tunnel_registry_is_generation_scoped_cancelled_and_replay_safe() {
        let registry = Arc::new(ManagedTunnelRegistry::default());
        let idle = Arc::new(IdleTracker::default());
        let owner = ManagedTunnelOwner {
            profile_id: [0x31; 16],
            generation: 7,
        };
        let stale = ManagedTunnelOwner {
            profile_id: owner.profile_id,
            generation: 6,
        };
        let other = ManagedTunnelOwner {
            profile_id: [0x32; 16],
            generation: 7,
        };
        let status = managed_tunnel_test_status(&owner, 1);
        let tunnel_id = status.tunnel_id.clone();
        let operation_context_id = status.operation_context_id.clone().unwrap();
        let cancellation = CancellationToken::new();
        registry
            .begin(
                owner.clone(),
                status,
                cancellation.clone(),
                idle.acquire(),
                None,
            )
            .unwrap();
        assert!(
            !idle.is_idle(),
            "active tunnel must retain daemon idle ownership"
        );
        let discovered = registry
            .snapshots(&owner, Some(&tunnel_id), None, true)
            .unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(
            discovered[0].operation_context_id.as_ref(),
            Some(&operation_context_id)
        );
        assert_eq!(discovered[0].revision, 1);
        assert!(registry
            .snapshots(&owner, Some(&tunnel_id), None, true)
            .is_err());
        let forged_context = ipc::OperationContextId::parse(&"ff".repeat(32)).unwrap();
        assert!(registry
            .snapshots(&owner, Some(&tunnel_id), Some(&forged_context), true,)
            .is_err());
        assert!(registry.request_cancel(&owner, &tunnel_id, None).is_err());
        assert!(registry
            .request_cancel(&owner, &tunnel_id, Some(&forged_context))
            .is_err());
        assert!(registry
            .snapshots(&stale, None, None, false)
            .unwrap()
            .is_empty());
        assert!(registry
            .snapshots(&other, None, None, false)
            .unwrap()
            .is_empty());
        assert!(registry
            .request_cancel(&stale, &tunnel_id, Some(&operation_context_id))
            .is_err());
        assert!(registry
            .request_cancel(&other, &tunnel_id, Some(&operation_context_id))
            .is_err());

        let worker_registry = Arc::clone(&registry);
        let worker_owner = owner.clone();
        let worker_id = tunnel_id.clone();
        tokio::spawn(async move {
            cancellation.cancelled().await;
            worker_registry
                .finish_worker(&worker_owner, &worker_id, ipc::TunnelStage::Closed)
                .unwrap();
        });
        let terminal = registry
            .cancel_and_wait(
                &owner,
                &tunnel_id,
                Some(&operation_context_id),
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(terminal.stage, ipc::TunnelStage::Closed);
        assert_eq!(terminal.revision, 3);
        assert!(
            idle.is_idle(),
            "terminal tunnel must release daemon idle ownership"
        );

        // A replayed cancel is idempotent and cannot re-arm a terminal tunnel.
        let replay = registry
            .cancel_and_wait(
                &owner,
                &tunnel_id,
                Some(&operation_context_id),
                Instant::now() + Duration::from_millis(50),
            )
            .await
            .unwrap();
        assert_eq!(replay.stage, ipc::TunnelStage::Closed);
    }

    #[test]
    fn managed_tunnel_registry_enforces_profile_capacity_and_unknown_terminal() {
        let registry = ManagedTunnelRegistry::default();
        let idle = Arc::new(IdleTracker::default());
        let owner = ManagedTunnelOwner {
            profile_id: [0x41; 16],
            generation: 9,
        };
        for index in 1..=MAX_ACTIVE_MANAGED_TUNNELS_PER_PROFILE {
            registry
                .begin(
                    owner.clone(),
                    managed_tunnel_test_status(&owner, index),
                    CancellationToken::new(),
                    idle.acquire(),
                    None,
                )
                .unwrap();
        }
        let overflow =
            managed_tunnel_test_status(&owner, MAX_ACTIVE_MANAGED_TUNNELS_PER_PROFILE + 1);
        assert!(registry
            .begin(
                owner.clone(),
                overflow,
                CancellationToken::new(),
                idle.acquire(),
                None,
            )
            .is_err());

        let first = ipc::TunnelId::parse("00000000000000000000000000000001").unwrap();
        let first_context = ipc::OperationContextId::parse(&format!("{:064x}", 1)).unwrap();
        registry
            .finish_worker(&owner, &first, ipc::TunnelStage::Unknown)
            .unwrap();
        assert_eq!(
            registry
                .snapshots(&owner, Some(&first), Some(&first_context), false)
                .unwrap()
                .pop()
                .unwrap()
                .stage,
            ipc::TunnelStage::Unknown
        );
    }

    fn test_grant_audit(
        directory: &std::path::Path,
        request_id: u8,
        operation_kind: &str,
    ) -> (
        Arc<GrantAuditOperation>,
        Arc<serctl_core::audit::AuditLedger>,
        Arc<AtomicBool>,
    ) {
        let identity = serctl_core::vault::ProfileIdentity {
            profile_id: [0x51; 16],
            generation: 13,
        };
        let key = serctl_core::vault::ProfileCallKey::from_bytes_for_test([0x61; 32]);
        let ledger = Arc::new(
            serctl_core::audit::AuditLedger::from_profile_call_key(directory, identity, &key)
                .unwrap(),
        );
        match (
            ledger.log_path().try_exists().unwrap(),
            ledger.checkpoint_path().try_exists().unwrap(),
        ) {
            (false, false) => {
                ledger
                    .initialize_generation(
                        None,
                        "grant-audit-test",
                        "grant-audit-test",
                        1_900_000_500_000,
                    )
                    .unwrap();
            }
            (true, true) => {}
            _ => panic!("test audit generation is only partially initialized"),
        }
        let quarantined = Arc::new(AtomicBool::new(false));
        let audit = Arc::new(GrantAuditOperation {
            ledger: Arc::clone(&ledger),
            quarantined: Arc::clone(&quarantined),
            profile: identity,
            request_id: [request_id; 16],
            operation_kind: operation_kind.into(),
            policy_digest: hex::encode([0x71; 32]),
            intent_digest: hex::encode([request_id; 32]),
            instance_id: InstanceId([0x44; 16]),
            grant_id: [0x55; 16],
            operation_context_key: Arc::new(OperationContextKey::random()),
            deadline: Instant::now() + Duration::from_secs(5),
            state: AtomicUsize::new(AUDIT_STATE_PENDING),
        });
        (audit, ledger, quarantined)
    }

    #[tokio::test]
    async fn authoritative_intent_is_durable_before_dispatch_side_effect() {
        let directory = create_global_test_base();
        let (audit, ledger, quarantined) = test_grant_audit(&directory, 1, "sftp.write");
        let side_effect = AtomicBool::new(false);

        audit.record_intent().await.unwrap();
        assert_eq!(ledger.verify(None).unwrap().sequence, 2);
        assert!(!side_effect.load(Ordering::Acquire));

        side_effect.store(true, Ordering::Release);
        assert!(audit
            .before_terminal_frame(&ipc::Frame::CreateDirAccepted {
                operation_context_id: Some(
                    ipc::OperationContextId::parse(&"ab".repeat(32)).unwrap(),
                ),
                revision: 1,
            })
            .await
            .is_none());
        assert_eq!(ledger.verify(None).unwrap().sequence, 3);
        assert!(side_effect.load(Ordering::Acquire));
        assert!(!quarantined.load(Ordering::Acquire));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn transfer_read_audit_waits_for_verified_local_commit_terminal() {
        let directory = create_global_test_base();
        let (audit, ledger, quarantined) = test_grant_audit(&directory, 19, "transfer.read");
        audit.record_intent().await.unwrap();

        // TransferDone means the daemon finished sending verified remote
        // bytes, not that the client durably committed its protected local
        // destination. It must not close the authoritative audit outcome.
        assert!(audit
            .before_terminal_frame(&ipc::Frame::TransferDone { bytes: 4096 })
            .await
            .is_none());
        assert_eq!(audit.state.load(Ordering::Acquire), AUDIT_STATE_PENDING);
        assert_eq!(ledger.verify(None).unwrap().sequence, 2);

        let mut completed = super::transfer_progress(
            ipc::TransferId::parse("00112233445566778899aabbccddeeff").unwrap(),
            ipc::TransferDirection::Pull,
            ipc::TransferStage::Completed,
            4096,
            4096,
            4096,
            ipc::TransferBackend::Sftp,
        );
        completed.event = "completed".into();
        assert!(audit
            .before_terminal_frame(&ipc::Frame::TransferProgress {
                progress: completed,
            })
            .await
            .is_none());
        assert_eq!(audit.state.load(Ordering::Acquire), AUDIT_STATE_COMPLETE);
        assert_eq!(ledger.verify(None).unwrap().sequence, 3);
        assert!(!quarantined.load(Ordering::Acquire));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn authoritative_intent_io_failure_quarantines_before_any_side_effect() {
        let directory = create_global_test_base();
        let (audit, ledger, quarantined) = test_grant_audit(&directory, 2, "sftp.write");
        std::fs::remove_file(ledger.log_path()).unwrap();
        std::fs::create_dir(ledger.log_path()).unwrap();
        let side_effect = AtomicBool::new(false);

        let dispatch = async {
            audit.record_intent().await?;
            side_effect.store(true, Ordering::Release);
            Ok::<(), anyhow::Error>(())
        };
        assert!(dispatch.await.is_err());
        assert!(!side_effect.load(Ordering::Acquire));
        assert!(quarantined.load(Ordering::Acquire));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn authoritative_intent_failure_does_not_consume_grant_budget() {
        use ed25519_dalek::SigningKey;
        use serctl_protocol::grant::{GrantProfileIdentity, OperationGrant};

        let holder = SigningKey::from_bytes(&[0x62; 32]);
        let entry = Arc::new(TestGrantEntry {
            profile_id: [0x63; 16],
            generation: AtomicUsize::new(17),
            profile: "audit-budget-test".into(),
        });
        let grant = OperationGrant::new(
            entry.profile.clone(),
            GrantProfileIdentity::new(entry.profile_id, 17),
            vec!["daemon.status".into()],
            1,
            &holder.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let request = signed_grant_prelude(&grant, &holder);
        let idle = Arc::new(IdleTracker::default());
        let record = GrantRecord::new(grant, entry, Instant::now(), idle.acquire()).unwrap();
        record
            .validate_request(&request, Instant::now(), super::now_unix_ms())
            .unwrap();

        let directory = create_global_test_base();
        let (audit, ledger, _) = test_grant_audit(&directory, 6, "daemon.status");
        std::fs::remove_file(ledger.log_path()).unwrap();
        std::fs::create_dir(ledger.log_path()).unwrap();
        if audit.record_intent().await.is_ok() {
            record.spend_budget().unwrap();
        }
        assert_eq!(record.remaining.load(Ordering::Acquire), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn bitflip_and_truncation_quarantine_before_a_following_dispatch() {
        for (request_id, mode) in [(3_u8, "bitflip"), (4_u8, "truncate")] {
            let directory = create_global_test_base();
            let (first, ledger, _) = test_grant_audit(&directory, request_id, "daemon.status");
            first.record_intent().await.unwrap();
            let mut bytes = std::fs::read(ledger.log_path()).unwrap();
            if mode == "bitflip" {
                bytes[0] ^= 1;
            } else {
                bytes.pop();
            }
            std::fs::write(ledger.log_path(), bytes).unwrap();
            let (following, _, quarantined) =
                test_grant_audit(&directory, request_id + 10, "sftp.write");
            assert!(following.record_intent().await.is_err(), "{mode}");
            assert!(quarantined.load(Ordering::Acquire), "{mode}");
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[tokio::test]
    async fn outcome_persistence_failure_returns_unknown_and_denies_future_mutation() {
        let directory = create_global_test_base();
        let (audit, ledger, quarantined) = test_grant_audit(&directory, 5, "sftp.write");
        audit.record_intent().await.unwrap();
        std::fs::write(ledger.checkpoint_path(), b"{").unwrap();

        let (mut client, mut server) = tokio::io::duplex(4096);
        super::ACTIVE_GRANT_AUDIT
            .scope(
                Arc::clone(&audit),
                super::write_frame_until(
                    &mut server,
                    &ipc::Frame::CreateDirAccepted {
                        operation_context_id: Some(
                            ipc::OperationContextId::parse(&"ab".repeat(32)).unwrap(),
                        ),
                        revision: 1,
                    },
                    Instant::now() + Duration::from_secs(2),
                ),
            )
            .await
            .unwrap();
        let replacement = ipc::read_frame_limited(&mut client, ipc::MAX_CONTROL_FRAME)
            .await
            .unwrap()
            .unwrap();
        let ipc::Frame::Error { msg } = replacement else {
            panic!("audit failure did not return an unknown error")
        };
        assert!(msg.contains("outcome is unknown"));
        assert!(quarantined.load(Ordering::Acquire));
        assert!(!super::operation_allowed_while_quarantined("sftp.write"));
        assert!(!super::operation_allowed_while_quarantined(
            "transfer.write"
        ));
        assert!(!super::operation_allowed_while_quarantined("job.submit"));
        assert!(super::operation_allowed_while_quarantined("daemon.status"));
        assert!(super::operation_allowed_while_quarantined(
            "ssh.connection-identity"
        ));
        assert!(super::operation_allowed_while_quarantined("sftp.list"));
        assert!(super::operation_allowed_while_quarantined("transfer.read"));
        assert!(super::operation_allowed_while_quarantined(
            "transfer.status"
        ));
        assert!(super::operation_allowed_while_quarantined("audit.diagnose"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn interrupted_outcome_finalization_quarantines_the_profile() {
        let directory = create_global_test_base();
        let (audit, _, quarantined) = test_grant_audit(&directory, 7, "sftp.write");
        audit.state.store(
            super::AUDIT_STATE_FINALIZING,
            std::sync::atomic::Ordering::Release,
        );
        assert!(audit.finalize_unknown_if_pending().await.is_err());
        assert!(quarantined.load(Ordering::Acquire));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn transfer_registry_is_profile_isolated_and_monotonic() {
        let registry = TransferRegistry::default();
        let transfer_id = ipc::TransferId::parse("00000000000000000000000000000001").unwrap();
        let initial = transfer_progress(
            transfer_id.clone(),
            ipc::TransferDirection::Push,
            ipc::TransferStage::Negotiating,
            100,
            0,
            0,
            ipc::TransferBackend::Sftp,
        );
        let cancellation = registry.begin("alpha", initial.clone()).unwrap();
        assert_eq!(
            registry
                .snapshots("alpha", None, None, false)
                .unwrap()
                .len(),
            1
        );
        assert!(registry
            .snapshots("beta", None, None, false)
            .unwrap()
            .is_empty());
        assert!(registry.cancel("beta", &transfer_id, None).is_err());
        registry.cancel("alpha", &transfer_id, None).unwrap();
        assert!(cancellation.is_cancelled());

        let mut advanced = initial.clone();
        advanced.stage = ipc::TransferStage::Transferring;
        advanced.confirmed_bytes = 50;
        registry.update("alpha", advanced).unwrap();
        let mut backwards = initial;
        backwards.confirmed_bytes = 49;
        assert!(registry.update("alpha", backwards).is_err());
    }

    #[test]
    fn operation_context_is_unforgeable_bound_and_registry_revisioned() {
        let key = OperationContextKey::random();
        let instance = InstanceId([1; 16]);
        let profile = serctl_core::vault::ProfileIdentity {
            profile_id: [2; 16],
            generation: 7,
        };
        let root = [3; 32];
        let binding = OperationContextBinding {
            instance_id: instance,
            grant_id: [4; 16],
            request_id: [5; 16],
            profile,
            root_request_hash: root,
        };
        let context = key
            .derive(
                binding,
                &"A".repeat(32),
                &"05".repeat(16),
                "transfer.write/accepted",
            )
            .unwrap();
        let same = key
            .derive(
                binding,
                &"A".repeat(32),
                &"05".repeat(16),
                "transfer.write/accepted",
            )
            .unwrap();
        assert_eq!(context, same);
        let changed_bindings = [
            OperationContextBinding {
                instance_id: InstanceId([9; 16]),
                ..binding
            },
            OperationContextBinding {
                grant_id: [8; 16],
                ..binding
            },
            OperationContextBinding {
                request_id: [9; 16],
                ..binding
            },
            OperationContextBinding {
                profile: serctl_core::vault::ProfileIdentity {
                    profile_id: [2; 16],
                    generation: 8,
                },
                ..binding
            },
            OperationContextBinding {
                root_request_hash: [6; 32],
                ..binding
            },
        ];
        for changed in changed_bindings
            .into_iter()
            .map(|changed| {
                key.derive(
                    changed,
                    &"A".repeat(32),
                    &"05".repeat(16),
                    "transfer.write/accepted",
                )
                .unwrap()
            })
            .chain([
                key.derive(
                    binding,
                    &"B".repeat(32),
                    &"05".repeat(16),
                    "transfer.write/accepted",
                )
                .unwrap(),
                key.derive(
                    binding,
                    &"A".repeat(32),
                    &"06".repeat(16),
                    "transfer.write/accepted",
                )
                .unwrap(),
                key.derive(
                    binding,
                    &"A".repeat(32),
                    &"05".repeat(16),
                    "transfer.read/accepted",
                )
                .unwrap(),
                key.derive(
                    binding,
                    &"A".repeat(32),
                    &"05".repeat(16),
                    "ssh.connection-identity/accepted",
                )
                .unwrap(),
                key.derive(
                    binding,
                    &"A".repeat(32),
                    &"05".repeat(16),
                    "ssh.exec/accepted",
                )
                .unwrap(),
                key.derive(
                    binding,
                    &"A".repeat(32),
                    &"05".repeat(16),
                    "sftp.list/accepted",
                )
                .unwrap(),
                key.derive(
                    binding,
                    &"A".repeat(32),
                    &"05".repeat(16),
                    "forward.local/open/accepted",
                )
                .unwrap(),
                key.derive(
                    binding,
                    "no-ssh-transport",
                    "daemon-lifetime-metadata",
                    "daemon.status/accepted",
                )
                .unwrap(),
                key.derive(
                    binding,
                    &"A".repeat(32),
                    "/tmp/created",
                    "sftp.write/create-dir/accepted",
                )
                .unwrap(),
            ])
        {
            assert_ne!(context, changed);
        }

        let registry = TransferRegistry::default();
        let transfer_id = ipc::TransferId::parse(&"05".repeat(16)).unwrap();
        let mut progress = transfer_progress(
            transfer_id.clone(),
            ipc::TransferDirection::Push,
            ipc::TransferStage::Negotiating,
            10,
            0,
            0,
            ipc::TransferBackend::Sftp,
        );
        progress.operation_context_id = Some(context.clone());
        progress.revision = 1;
        registry
            .begin("profile-a-generation-7", progress.clone())
            .unwrap();
        assert!(registry
            .begin("profile-a-generation-7", progress.clone())
            .is_err());
        let first = registry
            .snapshots("profile-a-generation-7", Some(&transfer_id), None, true)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(first.operation_context_id.as_ref(), Some(&context));
        assert!(registry
            .snapshots("profile-a-generation-7", Some(&transfer_id), None, true)
            .is_err());
        assert_eq!(
            registry
                .snapshots(
                    "profile-a-generation-7",
                    Some(&transfer_id),
                    Some(&context),
                    true
                )
                .unwrap()[0]
                .revision,
            1
        );
        let forged = ipc::OperationContextId::parse(&"ff".repeat(32)).unwrap();
        assert!(registry
            .snapshots(
                "profile-a-generation-7",
                Some(&transfer_id),
                Some(&forged),
                true
            )
            .is_err());
        assert!(registry
            .snapshots(
                "profile-b-generation-7",
                Some(&transfer_id),
                Some(&context),
                true
            )
            .is_err());
        let cancelled = registry
            .cancel("profile-a-generation-7", &transfer_id, Some(&context))
            .unwrap();
        assert_eq!(cancelled.revision, 2);
        assert_eq!(cancelled.event, "cancel_requested");
        assert!(registry
            .cancel("profile-a-generation-7", &transfer_id, Some(&forged))
            .is_err());
    }

    fn indexed_transfer_id(index: u128) -> ipc::TransferId {
        ipc::TransferId::parse(&format!("{index:032x}")).unwrap()
    }

    fn indexed_transfer_progress(index: u128, stage: ipc::TransferStage) -> ipc::TransferProgress {
        let completed_bytes = if stage == ipc::TransferStage::Completed {
            1
        } else {
            0
        };
        let mut progress = transfer_progress(
            indexed_transfer_id(index),
            ipc::TransferDirection::Push,
            stage,
            1,
            completed_bytes,
            completed_bytes,
            ipc::TransferBackend::Sftp,
        );
        progress.event = if stage == ipc::TransferStage::Completed {
            "completed"
        } else {
            "progress"
        }
        .to_owned();
        progress
    }

    fn worst_case_transfer_progress(
        index: u128,
        stage: ipc::TransferStage,
    ) -> ipc::TransferProgress {
        let mut progress = indexed_transfer_progress(index, stage);
        // A quote consumes two JSON bytes, covering the largest escaped form
        // permitted by TransferProgress::validate's 64-byte event cap.
        progress.event = "\"".repeat(64);
        progress.total_bytes = u64::MAX;
        progress.confirmed_bytes = u64::MAX;
        progress.durable_bytes = u64::MAX;
        progress.window_bps = f64::MAX;
        progress.average_bps = f64::MAX;
        progress.eta_ms = Some(u64::MAX);
        progress.backend = ipc::TransferBackend::SftpFallback;
        progress.chunk_bytes = u32::MAX;
        progress.window_bytes = u32::MAX;
        progress.updated_unix_ms = u64::MAX;
        progress.validate().unwrap();
        progress
    }

    #[test]
    fn transfer_registry_bounds_active_transfers_per_profile_and_globally() {
        let per_profile = TransferRegistry::default();
        for index in 0..MAX_ACTIVE_TRANSFERS_PER_PROFILE {
            per_profile
                .begin(
                    "alpha",
                    indexed_transfer_progress(index as u128, ipc::TransferStage::Transferring),
                )
                .unwrap();
        }
        let error = per_profile
            .begin(
                "alpha",
                indexed_transfer_progress(
                    MAX_ACTIVE_TRANSFERS_PER_PROFILE as u128,
                    ipc::TransferStage::Transferring,
                ),
            )
            .err()
            .unwrap();
        assert!(error
            .to_string()
            .contains("profile active transfer capacity is exhausted"));

        let global = TransferRegistry::default();
        for index in 0..MAX_ACTIVE_TRANSFERS_GLOBAL {
            global
                .begin(
                    &format!("profile-{index}"),
                    indexed_transfer_progress(index as u128, ipc::TransferStage::Transferring),
                )
                .unwrap();
        }
        let error = global
            .begin(
                "one-too-many",
                indexed_transfer_progress(
                    MAX_ACTIVE_TRANSFERS_GLOBAL as u128,
                    ipc::TransferStage::Transferring,
                ),
            )
            .err()
            .unwrap();
        assert!(error
            .to_string()
            .contains("global active transfer capacity is exhausted"));
    }

    #[test]
    fn transfer_registry_retains_latest_finished_records_with_profile_isolation() {
        let registry = TransferRegistry::default();
        let completed_per_profile = MAX_COMPLETED_TRANSFERS_PER_PROFILE * 4;
        for index in 0..completed_per_profile {
            let progress = indexed_transfer_progress(
                (completed_per_profile - index) as u128,
                ipc::TransferStage::Completed,
            );
            registry.begin("alpha", progress.clone()).unwrap();
            registry.finish("alpha", progress).unwrap();
        }
        for index in 0..completed_per_profile {
            let progress =
                indexed_transfer_progress(1_000 + index as u128, ipc::TransferStage::Completed);
            registry.begin("beta", progress.clone()).unwrap();
            registry.finish("beta", progress).unwrap();
        }

        let alpha = registry.snapshots("alpha", None, None, false).unwrap();
        let beta = registry.snapshots("beta", None, None, false).unwrap();
        assert_eq!(alpha.len(), MAX_COMPLETED_TRANSFERS_PER_PROFILE);
        assert_eq!(beta.len(), MAX_COMPLETED_TRANSFERS_PER_PROFILE);
        assert_eq!(alpha.first().unwrap().transfer_id, indexed_transfer_id(1));
        assert_eq!(
            alpha.last().unwrap().transfer_id,
            indexed_transfer_id(MAX_COMPLETED_TRANSFERS_PER_PROFILE as u128)
        );
        let beta_floor = indexed_transfer_id(1_000);
        assert!(beta
            .iter()
            .all(|progress| progress.transfer_id.as_str() >= beta_floor.as_str()));
    }

    #[test]
    fn transfer_registry_globally_bounds_many_rapid_finished_records() {
        let registry = TransferRegistry::default();
        let total = MAX_COMPLETED_TRANSFERS_GLOBAL + 64;
        for index in 0..total {
            let progress = indexed_transfer_progress(
                10_000 + (total - index) as u128,
                ipc::TransferStage::Completed,
            );
            let profile = format!("profile-{index}");
            registry.begin(&profile, progress.clone()).unwrap();
            registry.finish(&profile, progress).unwrap();
        }

        let records = registry.records.lock().unwrap();
        assert_eq!(records.len(), MAX_COMPLETED_TRANSFERS_GLOBAL);
        assert!(records.values().all(|record| record.finished_at.is_some()));
        assert!(!records.contains_key(indexed_transfer_id(10_000 + total as u128).as_str()));
        assert!(records.contains_key(indexed_transfer_id(10_001).as_str()));
    }

    #[test]
    fn transfer_registry_prunes_terminal_records_at_the_retention_boundary() {
        let registry = TransferRegistry::default();
        let expired = indexed_transfer_progress(19_001, ipc::TransferStage::Completed);
        let retained = indexed_transfer_progress(19_002, ipc::TransferStage::Completed);
        let active = indexed_transfer_progress(19_003, ipc::TransferStage::Transferring);
        registry.begin("alpha", expired.clone()).unwrap();
        registry.finish("alpha", expired.clone()).unwrap();
        registry.begin("alpha", retained.clone()).unwrap();
        registry.finish("alpha", retained.clone()).unwrap();
        registry.begin("alpha", active.clone()).unwrap();

        let base = Instant::now();
        let mut records = registry.records.lock().unwrap();
        records
            .get_mut(expired.transfer_id.as_str())
            .unwrap()
            .finished_at = Some(base);
        records
            .get_mut(retained.transfer_id.as_str())
            .unwrap()
            .finished_at = Some(base + Duration::from_nanos(1));
        TransferRegistry::prune_locked(&mut records, base + TRANSFER_RECORD_RETENTION);

        assert!(!records.contains_key(expired.transfer_id.as_str()));
        assert!(records.contains_key(retained.transfer_id.as_str()));
        assert!(records.contains_key(active.transfer_id.as_str()));
    }

    #[test]
    fn transfer_status_all_worst_case_is_strictly_below_control_frame_limit() {
        let registry = TransferRegistry::default();
        for index in 0..MAX_COMPLETED_TRANSFERS_PER_PROFILE {
            let progress = worst_case_transfer_progress(
                20_000 + index as u128,
                ipc::TransferStage::Transferring,
            );
            registry.begin("alpha", progress.clone()).unwrap();
            registry.finish("alpha", progress).unwrap();
        }
        for index in 0..MAX_ACTIVE_TRANSFERS_PER_PROFILE {
            let progress = worst_case_transfer_progress(
                30_000 + index as u128,
                ipc::TransferStage::Transferring,
            );
            registry.begin("alpha", progress).unwrap();
        }

        let snapshots = registry.snapshots("alpha", None, None, false).unwrap();
        assert_eq!(
            snapshots.len(),
            MAX_COMPLETED_TRANSFERS_PER_PROFILE + MAX_ACTIVE_TRANSFERS_PER_PROFILE
        );
        let frame = ipc::Frame::TransferStatusInfo {
            transfers: snapshots,
        };
        let encoded_len =
            ipc::encoded_frame_len_limited(&frame, ipc::MAX_CONTROL_FRAME - 1).unwrap();
        assert!(encoded_len < ipc::MAX_CONTROL_FRAME);
    }

    #[test]
    fn transfer_registry_owner_changes_when_a_profile_name_is_recreated() {
        let old = ConnInfo {
            profile: "same-name".into(),
            profile_id: Some([0x11; 16]),
            profile_generation: Some(1),
            host: "old.example".into(),
            user: "alice".into(),
            started: 1,
            token: Arc::new(zeroize::Zeroizing::new("old-token".into())),
        };
        let replacement = ConnInfo {
            profile: "same-name".into(),
            profile_id: Some([0x22; 16]),
            profile_generation: Some(1),
            host: "new.example".into(),
            user: "alice".into(),
            started: 2,
            token: Arc::new(zeroize::Zeroizing::new("new-token".into())),
        };
        let old_owner = old.transfer_owner_key();
        let replacement_owner = replacement.transfer_owner_key();
        assert_ne!(old_owner, replacement_owner);

        let registry = TransferRegistry::default();
        let progress = transfer_progress(
            ipc::TransferId::parse("00000000000000000000000000000002").unwrap(),
            ipc::TransferDirection::Pull,
            ipc::TransferStage::Completed,
            1,
            1,
            1,
            ipc::TransferBackend::Native,
        );
        registry.begin(&old_owner, progress.clone()).unwrap();
        registry.finish(&old_owner, progress).unwrap();
        assert!(registry
            .snapshots(&replacement_owner, None, None, false)
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn global_daemon_serves_catalog_rejects_bad_unlock_and_shuts_down() {
        use serctl_core::{daemon_runtime, vault};
        use serctl_protocol::v6::{
            v6_client_handshake, ActivationSecret, InstanceId, V6ClientIo, V6RequestPrelude,
            IPC_PROTOCOL_VERSION_V6,
        };

        let _test_home = GlobalTestHome::create().await;

        // Windows profile creation requires an initialized administrator
        // policy with a persisted 2-of-2 recovery share.
        #[cfg(windows)]
        vault::initialize_admin_password("test-administrator-password", |media| {
            std::fs::write(_test_home.path().join("recovery.bin"), media)
                .map_err(anyhow::Error::from)
        })
        .unwrap();

        vault::create_profile(
            "v6test",
            &Creds {
                host: "127.0.0.1".into(),
                port: 22,
                user: "tester".into(),
                password: "remote-password".into(),
                host_key: None,
            },
            "correct-passphrase",
            Some("test-administrator-password"),
        )
        .unwrap();

        let instance = InstanceId::random();
        let secret = ActivationSecret::random();
        let expected_endpoint = daemon_runtime::v6_endpoint(&instance).unwrap();
        assert_global_test_endpoint_fits(&expected_endpoint);
        let mut daemon_task = GlobalDaemonTask::new(tokio::spawn(super::run_global(
            instance,
            secret.clone(),
            "testbuild".into(),
        )));

        // Wait for the runtime descriptor: the daemon writes it only after the
        // listener is bound.
        let endpoint = wait_for_global_descriptor(&mut daemon_task, Duration::from_secs(5)).await;
        let deadline = Instant::now() + Duration::from_secs(10);

        // Catalog listing needs no unlock and no SSH.
        let stream =
            connect_global_until(&mut daemon_task, &endpoint, Duration::from_secs(2)).await;
        let list_frame = ipc::Frame::ListProfiles;
        let list_hash = serctl_protocol::v6::root_request_hash(&list_frame).unwrap();
        let list_prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [1_u8; 16],
            request_id: [2_u8; 16],
            operation_kind: "daemon.list-profiles".into(),
            profile_id: None,
            profile_name: None,
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: list_hash,
        };
        let session = v6_client_handshake(stream, &secret, instance, list_prelude, deadline)
            .await
            .unwrap();
        let mut io = V6ClientIo::new(session);
        ipc::write_frame_limited(&mut io, &list_frame, ipc::MAX_REQUEST_FRAME)
            .await
            .unwrap();
        let reply = ipc::read_frame_limited(&mut io, ipc::MAX_RESPONSE_FRAME)
            .await
            .unwrap()
            .unwrap();
        let ipc::Frame::ProfileList { profiles } = reply else {
            panic!("expected ProfileList, got {reply:?}");
        };
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "v6test");

        // A wrong passphrase fails the unlock before any SSH connection.
        let stream =
            connect_global_until(&mut daemon_task, &endpoint, Duration::from_secs(2)).await;
        let unlock_frame = ipc::Frame::Unlock {
            passphrase: "wrong-passphrase".into(),
        };
        let unlock_hash = serctl_protocol::v6::root_request_hash(&unlock_frame).unwrap();
        let unlock_prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [3_u8; 16],
            request_id: [4_u8; 16],
            operation_kind: "daemon.unlock".into(),
            profile_id: None,
            profile_name: Some("v6test".into()),
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: unlock_hash,
        };
        let session = v6_client_handshake(stream, &secret, instance, unlock_prelude, deadline)
            .await
            .unwrap();
        let mut io = V6ClientIo::new(session);
        ipc::write_frame_limited(&mut io, &unlock_frame, ipc::MAX_REQUEST_FRAME)
            .await
            .unwrap();
        let reply = ipc::read_frame_limited(&mut io, ipc::MAX_RESPONSE_FRAME)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(reply, ipc::Frame::Error { .. }));

        // Possession of the activation secret alone cannot stop the broker.
        let stream =
            connect_global_until(&mut daemon_task, &endpoint, Duration::from_secs(2)).await;
        let rejected_shutdown = ipc::Frame::Shutdown {
            passphrase: "wrong-passphrase".into(),
        };
        let rejected_hash = serctl_protocol::v6::root_request_hash(&rejected_shutdown).unwrap();
        let rejected_prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [5_u8; 16],
            request_id: [6_u8; 16],
            operation_kind: "daemon.shutdown".into(),
            profile_id: None,
            profile_name: Some("v6test".into()),
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: rejected_hash,
        };
        let session = v6_client_handshake(stream, &secret, instance, rejected_prelude, deadline)
            .await
            .unwrap();
        let mut io = V6ClientIo::new(session);
        ipc::write_frame_limited(&mut io, &rejected_shutdown, ipc::MAX_REQUEST_FRAME)
            .await
            .unwrap();
        let reply = ipc::read_frame_limited(&mut io, ipc::MAX_RESPONSE_FRAME)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(reply, ipc::Frame::Error { .. }));
        assert!(daemon_runtime::read_descriptor().unwrap().is_some());

        // A verified profile passphrase closes the daemon and clears runtime state.
        let stream =
            connect_global_until(&mut daemon_task, &endpoint, Duration::from_secs(2)).await;
        let shutdown_frame = ipc::Frame::Shutdown {
            passphrase: "correct-passphrase".into(),
        };
        let shutdown_hash = serctl_protocol::v6::root_request_hash(&shutdown_frame).unwrap();
        let shutdown_prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [7_u8; 16],
            request_id: [8_u8; 16],
            operation_kind: "daemon.shutdown".into(),
            profile_id: None,
            profile_name: Some("v6test".into()),
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: shutdown_hash,
        };
        let session = v6_client_handshake(stream, &secret, instance, shutdown_prelude, deadline)
            .await
            .unwrap();
        let mut io = V6ClientIo::new(session);
        ipc::write_frame_limited(&mut io, &shutdown_frame, ipc::MAX_REQUEST_FRAME)
            .await
            .unwrap();
        let reply = ipc::read_frame_limited(&mut io, ipc::MAX_RESPONSE_FRAME)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(reply, ipc::Frame::Ack));

        daemon_task
            .wait_for_exit(
                Duration::from_secs(5),
                "global daemon did not exit after shutdown",
            )
            .await;
        assert!(daemon_runtime::read_descriptor().unwrap().is_none());
        assert!(daemon_runtime::read_secret().unwrap().is_none());
    }

    async fn v6_io_for(
        daemon_task: &mut GlobalDaemonTask,
        endpoint: &str,
        secret: &serctl_protocol::v6::ActivationSecret,
        instance: serctl_protocol::v6::InstanceId,
        prelude: serctl_protocol::v6::V6RequestPrelude,
        deadline: Instant,
    ) -> serctl_protocol::v6::V6ClientIo<ipc::ClientStream> {
        use serctl_protocol::v6::{v6_client_handshake, V6ClientIo};
        let stream = connect_global_until(daemon_task, endpoint, Duration::from_secs(2)).await;
        let session = v6_client_handshake(stream, secret, instance, prelude, deadline)
            .await
            .unwrap();
        V6ClientIo::new(session)
    }

    #[test]
    fn policy_max_grant_holds_daemon_idle_guard_until_its_own_expiry() {
        use ed25519_dalek::SigningKey;
        use serctl_protocol::grant::{
            GrantProfileIdentity, OperationGrant, GRANT_DEFAULT_TTL, GRANT_MAX_TTL,
        };
        use serctl_protocol::v6::{V6RequestPrelude, IPC_PROTOCOL_VERSION_V6};

        let idle = Arc::new(IdleTracker::default());
        let grants = GrantRegistry::<TestGrantEntry>::new(Arc::clone(&idle));
        let holder = SigningKey::from_bytes(&[7_u8; 32]);
        let identity = serctl_core::vault::ProfileIdentity {
            profile_id: [9_u8; 16],
            generation: 7,
        };
        let entry = Arc::new(TestGrantEntry {
            profile_id: identity.profile_id,
            generation: AtomicUsize::new(identity.generation as usize),
            profile: "grant-idle-test".into(),
        });
        let grant = OperationGrant::new_with_ttl(
            "grant-idle-test".into(),
            GrantProfileIdentity::new(identity.profile_id, identity.generation),
            vec!["daemon.status".into()],
            1,
            &holder.verifying_key(),
            super::now_unix_ms(),
            GRANT_MAX_TTL,
        )
        .unwrap();

        assert!(idle.is_idle());
        let grant_id = grant.grant_id;
        grants.insert(grant, Arc::clone(&entry)).unwrap();
        assert_eq!(Arc::strong_count(&entry), 2);
        assert!(
            !idle.is_idle(),
            "an issued grant must prevent automatic daemon idle exit"
        );

        let record = match grants.lookup(&grant_id, Instant::now()) {
            GrantLookup::Live(record) => record,
            _ => panic!("new grant was not live"),
        };
        let mut grant_request = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [1_u8; 16],
            request_id: [2_u8; 16],
            operation_kind: "daemon.status".into(),
            profile_id: None,
            profile_name: Some("grant-idle-test".into()),
            grant_id: Some(grant_id),
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: record.grant.expires_unix_ms - 1,
            root_request_hash: [0_u8; 32],
        };
        grant_request.pop_signature =
            Some(serctl_protocol::grant::sign_prelude_pop(&holder, &grant_request).unwrap());
        record
            .validate_request(
                &grant_request,
                record.expires_at - (GRANT_MAX_TTL - GRANT_DEFAULT_TTL) + Duration::from_millis(1),
                super::now_unix_ms(),
            )
            .unwrap();
        let exhausted = record.spend_budget().unwrap();
        assert!(exhausted);
        let error = record
            .validate_request(
                &grant_request,
                record.expires_at + Duration::from_millis(1),
                super::now_unix_ms(),
            )
            .unwrap_err();
        assert_eq!(terminal_safe_error(&error), "grant has expired");
        assert!(!UNKNOWN_GRANT_ERROR.contains("expired"));
        let expired_at = record.expires_at;
        drop(record);

        grants.prune_expired(expired_at + Duration::from_millis(1));
        assert!(
            idle.is_idle(),
            "reaping the expired grant must release its idle guard"
        );
        assert_eq!(Arc::strong_count(&entry), 1);
        assert!(matches!(
            grants.lookup(&grant_id, expired_at + Duration::from_millis(1)),
            GrantLookup::Expired
        ));
        assert!(matches!(
            grants.lookup(
                &grant_id,
                expired_at + GRANT_TERMINAL_TOMBSTONE_TTL + Duration::from_millis(1)
            ),
            GrantLookup::Unknown
        ));
        let restarted = GrantRegistry::<TestGrantEntry>::new(Arc::new(IdleTracker::default()));
        assert!(matches!(
            restarted.lookup(&grant_id, Instant::now()),
            GrantLookup::Unknown
        ));
    }

    #[test]
    fn grant_generation_binding_rejects_old_or_changed_entry_before_budget_spend() {
        use ed25519_dalek::SigningKey;
        use serctl_protocol::grant::{GrantProfileIdentity, OperationGrant};

        let holder = SigningKey::from_bytes(&[11_u8; 32]);
        let idle = Arc::new(IdleTracker::default());
        let entry = Arc::new(TestGrantEntry {
            profile_id: [0x31; 16],
            generation: AtomicUsize::new(7),
            profile: "generation-test".into(),
        });
        let old_grant = OperationGrant::new(
            "generation-test".into(),
            GrantProfileIdentity::new(entry.profile_id, 6),
            vec!["daemon.status".into()],
            2,
            &holder.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let error = GrantRecord::new(
            old_grant,
            Arc::clone(&entry),
            Instant::now(),
            idle.acquire(),
        )
        .err()
        .expect("old generation must be rejected");
        assert!(
            terminal_safe_error(&error).contains("generation"),
            "unexpected error: {error:#}"
        );

        let grant = OperationGrant::new(
            "generation-test".into(),
            GrantProfileIdentity::new(entry.profile_id, 7),
            vec!["daemon.status".into()],
            2,
            &holder.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let record = GrantRecord::new(
            grant.clone(),
            Arc::clone(&entry),
            Instant::now(),
            idle.acquire(),
        )
        .unwrap();
        let request = signed_grant_prelude(&grant, &holder);
        entry.generation.store(8, Ordering::Release);
        let error = record
            .validate_request(&request, Instant::now(), super::now_unix_ms())
            .unwrap_err();
        assert!(terminal_safe_error(&error).contains("generation"));
        assert_eq!(
            record.remaining.load(Ordering::Acquire),
            2,
            "generation mismatch consumed grant budget"
        );
    }

    #[test]
    fn connection_identity_grant_scope_and_profile_generation_are_exact() {
        use ed25519_dalek::SigningKey;
        use serctl_protocol::grant::{GrantProfileIdentity, OperationGrant};

        let holder = SigningKey::from_bytes(&[0x37_u8; 32]);
        let idle = Arc::new(IdleTracker::default());
        let entry = Arc::new(TestGrantEntry {
            profile_id: [0x38; 16],
            generation: AtomicUsize::new(4),
            profile: "identity-scope".into(),
        });
        let grant = OperationGrant::new(
            entry.profile.clone(),
            GrantProfileIdentity::new(entry.profile_id, 4),
            vec!["ssh.connection-identity".into()],
            2,
            &holder.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let record = GrantRecord::new(
            grant.clone(),
            Arc::clone(&entry),
            Instant::now(),
            idle.acquire(),
        )
        .unwrap();

        let exact = signed_grant_prelude_for_operation(&grant, &holder, "ssh.connection-identity");
        record
            .validate_request(&exact, Instant::now(), super::now_unix_ms())
            .unwrap();
        assert!(!record.spend_budget().unwrap());
        assert_eq!(record.remaining.load(Ordering::Acquire), 1);

        let wrong_scope = signed_grant_prelude_for_operation(&grant, &holder, "ssh.exec");
        let error = record
            .validate_request(&wrong_scope, Instant::now(), super::now_unix_ms())
            .unwrap_err();
        assert!(error.to_string().contains("does not authorize"));
        assert_eq!(record.remaining.load(Ordering::Acquire), 1);

        entry.generation.store(5, Ordering::Release);
        let error = record
            .validate_request(&exact, Instant::now(), super::now_unix_ms())
            .unwrap_err();
        assert!(terminal_safe_error(&error).contains("generation"));
        assert_eq!(record.remaining.load(Ordering::Acquire), 1);
    }

    #[test]
    fn transfer_read_grant_is_exactly_profile_generation_and_scope_bound() {
        use ed25519_dalek::SigningKey;
        use serctl_protocol::grant::{GrantProfileIdentity, OperationGrant};

        let holder = SigningKey::from_bytes(&[0x47_u8; 32]);
        let idle = Arc::new(IdleTracker::default());
        let entry = Arc::new(TestGrantEntry {
            profile_id: [0x48; 16],
            generation: AtomicUsize::new(12),
            profile: "pull-scope".into(),
        });
        let grant = OperationGrant::new(
            entry.profile.clone(),
            GrantProfileIdentity::new(entry.profile_id, 12),
            vec!["transfer.read".into()],
            2,
            &holder.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let record = GrantRecord::new(
            grant.clone(),
            Arc::clone(&entry),
            Instant::now(),
            idle.acquire(),
        )
        .unwrap();
        let exact = signed_grant_prelude_for_operation(&grant, &holder, "transfer.read");
        record
            .validate_request(&exact, Instant::now(), super::now_unix_ms())
            .unwrap();

        let wrong_scope = signed_grant_prelude_for_operation(&grant, &holder, "transfer.write");
        assert!(record
            .validate_request(&wrong_scope, Instant::now(), super::now_unix_ms())
            .unwrap_err()
            .to_string()
            .contains("does not authorize"));
        assert_eq!(record.remaining.load(Ordering::Acquire), 2);

        entry.generation.store(13, Ordering::Release);
        assert!(terminal_safe_error(
            &record
                .validate_request(&exact, Instant::now(), super::now_unix_ms())
                .unwrap_err()
        )
        .contains("generation"));
        assert_eq!(record.remaining.load(Ordering::Acquire), 2);
    }

    #[test]
    fn connection_identity_request_binding_rejects_profile_or_generation_substitution() {
        let identity = serctl_core::vault::ProfileIdentity {
            profile_id: [0x41; 16],
            generation: 9,
        };
        let exact = serctl_protocol::Frame::ConnectionIdentity {
            profile_id: identity.profile_id,
            profile_generation: identity.generation,
        };
        validate_connection_identity_binding(&exact, identity).unwrap();

        for substituted in [
            serctl_protocol::Frame::ConnectionIdentity {
                profile_id: [0x42; 16],
                profile_generation: identity.generation,
            },
            serctl_protocol::Frame::ConnectionIdentity {
                profile_id: identity.profile_id,
                profile_generation: identity.generation + 1,
            },
        ] {
            let error = validate_connection_identity_binding(&substituted, identity).unwrap_err();
            assert!(error
                .to_string()
                .contains("does not match the authorized profile generation"));
        }
    }

    #[test]
    fn serialized_grant_metadata_cannot_expand_registered_authority() {
        use ed25519_dalek::SigningKey;
        use serctl_protocol::grant::{GrantProfileIdentity, OperationGrant};

        let holder = SigningKey::from_bytes(&[0x51_u8; 32]);
        let idle = Arc::new(IdleTracker::default());
        let grants = GrantRegistry::<TestGrantEntry>::new(Arc::clone(&idle));
        let entry = Arc::new(TestGrantEntry {
            profile_id: [0x52; 16],
            generation: AtomicUsize::new(11),
            profile: "registered-profile".into(),
        });
        let issued = OperationGrant::new(
            entry.profile.clone(),
            GrantProfileIdentity::new(entry.profile_id, 11),
            vec!["daemon.status".into()],
            1,
            &holder.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let registered_id = issued.grant_id;
        grants.insert(issued.clone(), Arc::clone(&entry)).unwrap();
        let record = match grants.lookup(&registered_id, Instant::now()) {
            GrantLookup::Live(record) => record,
            _ => panic!("issued grant was not registered"),
        };

        // Round-trip through JSON first: every mutation below represents an
        // edit to the advisory Agent-side grant-file metadata, while `record`
        // remains the daemon's authoritative in-memory registration.
        let serialized = serde_json::to_vec(&issued).unwrap();
        let from_file = || {
            serde_json::from_slice::<OperationGrant>(&serialized)
                .expect("deserialize simulated grant file")
        };
        let resign = |prelude: &mut serctl_protocol::v6::V6RequestPrelude| {
            prelude.pop_signature = None;
            prelude.pop_signature =
                Some(serctl_protocol::grant::sign_prelude_pop(&holder, prelude).unwrap());
        };

        let mut widened_scope = from_file();
        widened_scope.operations.push("sftp.write".into());
        let mut request = signed_grant_prelude(&widened_scope, &holder);
        request.operation_kind = "sftp.write".into();
        resign(&mut request);
        let error = record
            .validate_request(&request, Instant::now(), super::now_unix_ms())
            .unwrap_err();
        assert_eq!(
            terminal_safe_error(&error),
            "grant does not authorize this operation kind"
        );

        let mut changed_profile = from_file();
        changed_profile.profile_name = "other-profile".into();
        let request = signed_grant_prelude(&changed_profile, &holder);
        let error = record
            .validate_request(&request, Instant::now(), super::now_unix_ms())
            .unwrap_err();
        assert_eq!(terminal_safe_error(&error), "grant profile mismatch");

        let mut extended_expiry = from_file();
        extended_expiry.expires_unix_ms += 60_000;
        let mut request = signed_grant_prelude(&extended_expiry, &holder);
        request.requested_deadline_unix_ms = issued.expires_unix_ms + 1;
        resign(&mut request);
        let error = record
            .validate_request(&request, Instant::now(), super::now_unix_ms())
            .unwrap_err();
        assert_eq!(
            terminal_safe_error(&error),
            "requested deadline exceeds the grant expiry"
        );

        let mut changed_id = from_file();
        changed_id.grant_id[0] ^= 1;
        assert!(matches!(
            grants.lookup(&changed_id.grant_id, Instant::now()),
            GrantLookup::Unknown
        ));

        let mut advisory_identity_and_budget = from_file();
        advisory_identity_and_budget.profile_id[0] ^= 1;
        advisory_identity_and_budget.profile_generation += 1;
        advisory_identity_and_budget.budget = 1_000;
        assert_eq!(record.grant.profile_id, issued.profile_id);
        assert_eq!(record.grant.profile_generation, issued.profile_generation);
        assert_eq!(record.grant.budget, 1);
        let request = signed_grant_prelude(&advisory_identity_and_budget, &holder);
        record
            .validate_request(&request, Instant::now(), super::now_unix_ms())
            .unwrap();
        assert!(record.spend_budget().unwrap());
        assert_eq!(
            terminal_safe_error(&record.spend_budget().unwrap_err()),
            "grant budget exhausted"
        );
    }

    #[test]
    fn grant_budget_one_is_atomic_and_terminal_tombstone_releases_exact_entry() {
        use ed25519_dalek::SigningKey;
        use serctl_protocol::grant::{GrantProfileIdentity, OperationGrant};
        use std::sync::Barrier;

        let idle = Arc::new(IdleTracker::default());
        let grants = Arc::new(GrantRegistry::<TestGrantEntry>::new(Arc::clone(&idle)));
        let holder = SigningKey::from_bytes(&[12_u8; 32]);
        let entry = Arc::new(TestGrantEntry {
            profile_id: [0x41; 16],
            generation: AtomicUsize::new(9),
            profile: "budget-test".into(),
        });
        let replacement = Arc::new(TestGrantEntry {
            profile_id: entry.profile_id,
            generation: AtomicUsize::new(9),
            profile: "budget-test".into(),
        });
        let grant = OperationGrant::new(
            "budget-test".into(),
            GrantProfileIdentity::new(entry.profile_id, 9),
            vec!["daemon.status".into()],
            1,
            &holder.verifying_key(),
            super::now_unix_ms(),
        )
        .unwrap();
        let grant_id = grant.grant_id;
        let request = Arc::new(signed_grant_prelude(&grant, &holder));
        grants.insert(grant, Arc::clone(&entry)).unwrap();
        let record = match grants.lookup(&grant_id, Instant::now()) {
            GrantLookup::Live(record) => record,
            _ => panic!("new grant was not live"),
        };
        assert!(Arc::ptr_eq(&record.entry, &entry));
        assert!(!Arc::ptr_eq(&record.entry, &replacement));

        let workers = 8;
        let barrier = Arc::new(Barrier::new(workers));
        let mut threads = Vec::new();
        for _ in 0..workers {
            let record = Arc::clone(&record);
            let request = Arc::clone(&request);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                record.validate_request(&request, Instant::now(), super::now_unix_ms())?;
                record.spend_budget()
            }));
        }
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| terminal_safe_error(error) == "grant budget exhausted"));
        assert!(results.iter().any(|result| matches!(result, Ok(true))));

        grants.mark_terminal_if_same(
            &grant_id,
            &record,
            GrantTerminalKind::Exhausted,
            Instant::now(),
        );
        assert!(matches!(
            grants.lookup(&grant_id, Instant::now()),
            GrantLookup::Exhausted
        ));
        drop(record);
        assert_eq!(
            Arc::strong_count(&entry),
            1,
            "terminal tombstone retained the credential entry"
        );
        assert!(idle.is_idle());
    }

    #[tokio::test]
    async fn global_daemon_exits_after_its_idle_window_with_no_work() {
        use serctl_core::daemon_runtime;
        use serctl_protocol::v6::{ActivationSecret, InstanceId};

        let _test_home = GlobalTestHome::create().await;
        let instance = InstanceId::random();
        let secret = ActivationSecret::random();
        let expected_endpoint = daemon_runtime::v6_endpoint(&instance).unwrap();
        assert_global_test_endpoint_fits(&expected_endpoint);
        let mut daemon_task =
            GlobalDaemonTask::new(tokio::spawn(super::run_global_with_idle_timeout(
                instance,
                secret,
                "testbuild".into(),
                Duration::from_millis(300),
            )));

        // Wait for publication, then let the idle window expire.
        wait_for_global_descriptor(&mut daemon_task, Duration::from_secs(5)).await;
        daemon_task
            .wait_for_exit(Duration::from_secs(5), "global daemon did not idle-exit")
            .await;
        assert!(daemon_runtime::read_descriptor().unwrap().is_none());
        assert!(daemon_runtime::read_secret().unwrap().is_none());
    }

    #[tokio::test]
    async fn global_daemon_keeps_serving_while_live_work_holds_the_idle_counter() {
        use serctl_core::daemon_runtime;
        use serctl_protocol::v6::{
            frame_kind, ActivationSecret, InstanceId, V6RequestPrelude, IPC_PROTOCOL_VERSION_V6,
        };

        let _test_home = GlobalTestHome::create().await;
        let instance = InstanceId::random();
        let secret = ActivationSecret::random();
        let expected_endpoint = daemon_runtime::v6_endpoint(&instance).unwrap();
        assert_global_test_endpoint_fits(&expected_endpoint);
        let mut daemon_task =
            GlobalDaemonTask::new(tokio::spawn(super::run_global_with_idle_timeout(
                instance,
                secret.clone(),
                "testbuild".into(),
                Duration::from_secs(2),
            )));

        let endpoint = wait_for_global_descriptor(&mut daemon_task, Duration::from_secs(5)).await;

        // One open, authenticated connection is live work: it must postpone
        // idle exit well beyond the idle window.
        let list_frame = ipc::Frame::ListProfiles;
        let list_hash = serctl_protocol::v6::root_request_hash(&list_frame).unwrap();
        let prelude = V6RequestPrelude {
            protocol_version: IPC_PROTOCOL_VERSION_V6,
            client_session_id: [1_u8; 16],
            request_id: [2_u8; 16],
            operation_kind: frame_kind(&list_frame).into(),
            profile_id: None,
            profile_name: None,
            grant_id: None,
            pop_signature: None,
            profile_proof: None,
            requested_deadline_unix_ms: 0,
            root_request_hash: list_hash,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let held = v6_io_for(
            &mut daemon_task,
            &endpoint,
            &secret,
            instance,
            prelude,
            deadline,
        )
        .await;

        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            !daemon_task.is_finished(),
            "broker exited its idle window while a live connection held work"
        );

        drop(held);
        daemon_task
            .wait_for_exit(
                Duration::from_secs(5),
                "global daemon did not idle-exit after the last connection closed",
            )
            .await;
        assert!(daemon_runtime::read_descriptor().unwrap().is_none());
    }

    #[test]
    fn dropped_readiness_receiver_rejects_handoff_and_cleans_publication_owner() {
        struct FakePublication {
            live: Arc<AtomicBool>,
            lock_published: Arc<AtomicBool>,
            lease_held: Arc<AtomicBool>,
        }

        impl Drop for FakePublication {
            fn drop(&mut self) {
                self.live.store(false, Ordering::SeqCst);
                self.lock_published.store(false, Ordering::SeqCst);
                self.lease_held.store(false, Ordering::SeqCst);
            }
        }

        let live = Arc::new(AtomicBool::new(true));
        let lock_published = Arc::new(AtomicBool::new(true));
        let lease_held = Arc::new(AtomicBool::new(true));
        let publication = FakePublication {
            live: live.clone(),
            lock_published: lock_published.clone(),
            lease_held: lease_held.clone(),
        };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        drop(ready_rx);

        if handoff_readiness(Some(ready_tx)).is_err() {
            drop(publication);
        }

        assert!(!live.load(Ordering::SeqCst));
        assert!(!lock_published.load(Ordering::SeqCst));
        assert!(!lease_held.load(Ordering::SeqCst));
    }

    #[test]
    fn authorized_status_response_is_always_daemon_metadata() {
        // This response helper accepts no SessionManager or SshSession. The
        // Status branch therefore cannot inspect health, reconnect, or use the
        // retained password on behalf of its call-key-authorized caller.
        let info = ConnInfo {
            profile: "prod".into(),
            profile_id: Some([0x11; 16]),
            profile_generation: Some(1),
            host: "ssh.example".into(),
            user: "alice".into(),
            started: 123,
            token: Arc::new(zeroize::Zeroizing::new("unused-token".into())),
        };
        match status_info_frame(&info, None, 0) {
            serctl_protocol::Frame::StatusInfo {
                profile,
                host,
                user,
                started_unix,
                operation_context_id,
                revision,
            } => {
                assert_eq!(profile, "prod");
                assert_eq!(host, "ssh.example");
                assert_eq!(user, "alice");
                assert_eq!(started_unix, 123);
                assert!(operation_context_id.is_none());
                assert_eq!(revision, 0);
            }
            other => panic!("unexpected authorized status response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn daemon_shell_frame_reader_survives_remote_output_competition_mid_frame() {
        let (mut reader, mut writer) = tokio::io::duplex(1);
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel(1);
        let frame_pump = read_shell_frame_pump(&mut reader, frame_tx);
        tokio::pin!(frame_pump);
        let mut frame_pump_running = true;
        let expected = vec![0x41; 32 * 1024];
        let sent = expected.clone();
        let writer_task = tokio::spawn(async move {
            serctl_protocol::write_frame_limited(
                &mut writer,
                &serctl_protocol::Frame::ShellInput { data: sent },
                serctl_protocol::MAX_SHELL_FRAME,
            )
            .await
            .unwrap();
        });

        let mut competing_events = 0_usize;
        let mut received = loop {
            tokio::select! {
                biased;
                frame = frame_rx.recv() => break frame
                    .expect("frame pump closed early")
                    .into_inner()
                    .unwrap()
                    .unwrap(),
                () = &mut frame_pump, if frame_pump_running => {
                    frame_pump_running = false;
                },
                _ = tokio::task::yield_now() => competing_events += 1,
            }
        };
        writer_task.await.unwrap();
        match &mut received {
            serctl_protocol::Frame::ShellInput { data } => {
                assert_eq!(data, &expected);
                data.zeroize();
            }
            other => panic!("unexpected frame from persistent reader: {other:?}"),
        }
        assert!(
            competing_events > 0,
            "test did not exercise competing remote-output scheduling"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_owned_publication_is_cleaned_after_setup_deadline() {
        struct FakePublication {
            published: Arc<AtomicBool>,
            lease_held: Arc<AtomicBool>,
            cleaned: Arc<AtomicBool>,
        }

        impl Drop for FakePublication {
            fn drop(&mut self) {
                self.published.store(false, Ordering::SeqCst);
                self.lease_held.store(false, Ordering::SeqCst);
                self.cleaned.store(true, Ordering::SeqCst);
            }
        }

        // Start this test runtime's blocking pool before arming the deliberately
        // short deadline. Under a loaded workspace test run, aborting a queued
        // (not-yet-started) spawn_blocking job is valid but does not exercise the
        // late-owned-result cleanup path that this test is specifically about.
        tokio::task::spawn_blocking(|| {})
            .await
            .expect("prewarm blocking worker");

        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let published = Arc::new(AtomicBool::new(false));
        let lease_held = Arc::new(AtomicBool::new(false));
        let cleaned = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let worker_release = release.clone();
        let worker_published = published.clone();
        let worker_lease = lease_held.clone();
        let worker_cleaned = cleaned.clone();
        let operation = move || {
            worker_started.store(true, Ordering::SeqCst);
            while !worker_release.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            worker_published.store(true, Ordering::SeqCst);
            worker_lease.store(true, Ordering::SeqCst);
            Ok(FakePublication {
                published: worker_published,
                lease_held: worker_lease,
                cleaned: worker_cleaned,
            })
        };

        let wait = tokio::spawn(await_owned_blocking_until(
            Instant::now() + Duration::from_millis(250),
            operation,
            "test publication",
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let error = match wait.await.unwrap() {
            Ok(_) => panic!("late publication unexpectedly met its setup deadline"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("deadline"));

        release.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cleaned.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late publication did not clean its owned result");
        assert!(
            !published.load(Ordering::SeqCst),
            "late lock remained published"
        );
        assert!(
            !lease_held.load(Ordering::SeqCst),
            "late lease remained held"
        );
    }

    #[tokio::test]
    async fn cancelling_full_daemon_shell_pump_zeroizes_its_in_flight_frame() {
        let (reader, mut writer) = tokio::io::duplex(1);
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel(1);
        let dropped = Arc::new(AtomicBool::new(false));
        let constructed = Arc::new(AtomicUsize::new(0));
        let pump_dropped = Arc::clone(&dropped);
        let pump_constructed = Arc::clone(&constructed);
        let pump = tokio::spawn(async move {
            let mut reader = reader;
            read_shell_frame_pump_inner(
                &mut reader,
                frame_tx,
                Some(pump_dropped),
                Some(pump_constructed),
            )
            .await;
        });

        for byte in [0x41, 0x42] {
            serctl_protocol::write_frame_limited(
                &mut writer,
                &serctl_protocol::Frame::ShellInput {
                    data: vec![byte; 1024],
                },
                serctl_protocol::MAX_SHELL_FRAME,
            )
            .await
            .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while constructed.load(Ordering::Acquire) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("daemon pump did not construct its blocked second envelope");

        pump.abort();
        assert!(pump.await.unwrap_err().is_cancelled());
        assert!(
            dropped.load(Ordering::Acquire),
            "cancelling a full daemon pump bypassed in-flight frame cleanup"
        );
        let mut queued = frame_rx.try_recv().unwrap().into_inner().unwrap().unwrap();
        queued.zeroize_sensitive();
    }

    #[tokio::test]
    async fn daemon_protocol_helper_verifies_v5_client_proof() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = serctl_core::vault::new_ipc_token();
        let call_key = serctl_core::vault::ProfileCallKey::from_bytes_for_test([0x5a; 32]);
        let deadline = Instant::now() + Duration::from_secs(1);
        let (client_result, server_result) = tokio::join!(
            serctl_protocol::authenticate_client(&mut client, "prod", &token, deadline),
            authenticate_incoming_protocol(&mut server, "prod", &token, &call_key, deadline),
        );
        client_result.unwrap();
        server_result.unwrap();
    }

    #[tokio::test]
    async fn token_only_daemon_auth_rejects_all_business_requests() {
        for request in [
            serctl_protocol::Frame::Status,
            serctl_protocol::Frame::Shutdown {
                passphrase: "profile-passphrase".into(),
            },
            serctl_protocol::Frame::TunnelOpen {
                spec: serctl_core::ssh::TunnelSpec::local(0, 22),
            },
        ] {
            let (mut client, mut server) = tokio::io::duplex(8 * 1024);
            let token = serctl_core::vault::new_ipc_token();
            let call_key = serctl_core::vault::ProfileCallKey::from_bytes_for_test([0x3c; 32]);
            let deadline = Instant::now() + Duration::from_secs(1);
            let (client_result, server_result) = tokio::join!(
                serctl_protocol::authenticate_client(&mut client, "prod", &token, deadline),
                authenticate_incoming_protocol(&mut server, "prod", &token, &call_key, deadline),
            );
            client_result.unwrap();
            let mut context = server_result.unwrap();
            let error = context
                .verify_request(call_key.as_bytes(), &request)
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("requires master-passphrase authorization"));
        }
    }

    #[tokio::test]
    async fn tunnel_control_waiter_releases_cleanly_on_ipc_eof() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let (mut reader, peer) = tokio::io::duplex(16);
        drop(peer);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let acquired = acquire_tunnel_control_slot(
            Arc::clone(&slots),
            &mut reader,
            &mut shutdown_rx,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(acquired.is_none());
        assert_eq!(slots.available_permits(), 0);
        drop(held);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn fragmented_tunnel_stop_survives_poll_ticks_and_reports_closed() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let client_task = tokio::spawn(async move {
            let payload = serde_json::to_vec(&serctl_protocol::Frame::TunnelStop).unwrap();
            let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(&payload);

            // Split both the length prefix and payload across delays longer
            // than the production completion-poll interval.
            client.write_all(&wire[..2]).await.unwrap();
            client.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            client.write_all(&wire[2..5]).await.unwrap();
            client.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            client.write_all(&wire[5..]).await.unwrap();
            client.flush().await.unwrap();

            serctl_protocol::read_frame_limited(&mut client, serctl_protocol::MAX_CONTROL_FRAME)
                .await
                .unwrap()
        });
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let control = wait_for_tunnel_control_or_completion(
            &mut server,
            &mut shutdown_rx,
            Duration::from_millis(100),
            || false,
        )
        .await
        .unwrap();
        assert!(matches!(
            control,
            TunnelControlWait::Frame(Some(serctl_protocol::Frame::TunnelStop))
        ));

        let cleaned = Arc::new(AtomicBool::new(false));
        let cleanup_flag = Arc::clone(&cleaned);
        stop_tunnel_and_report(&mut server, &mut shutdown_rx, async move {
            cleanup_flag.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), client_task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            response,
            Some(serctl_protocol::Frame::TunnelClosed)
        ));
        assert!(cleaned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn invalid_client_proof_is_closed_without_a_structured_error() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let token = serctl_core::vault::new_ipc_token();
        let call_key = serctl_core::vault::ProfileCallKey::from_bytes_for_test([0x5a; 32]);
        let deadline = Instant::now() + Duration::from_secs(1);

        let server_task = async move {
            let error =
                authenticate_incoming_protocol(&mut server, "prod", &token, &call_key, deadline)
                    .await
                    .err()
                    .expect("invalid proof unexpectedly authenticated");
            assert!(error.to_string().contains("proof mismatch"));
            // Production handle_conn takes this same error branch and drops
            // the stream without serializing Frame::Error.
            drop(server);
        };
        let client_task = async move {
            serctl_protocol::write_frame_limited(
                &mut client,
                &serctl_protocol::Frame::AuthHello {
                    version: serctl_protocol::IPC_PROTOCOL_VERSION,
                    client_nonce: serctl_core::vault::new_ipc_token(),
                    intent_commitment: None,
                },
                serctl_protocol::MAX_AUTH_FRAME,
            )
            .await
            .unwrap();
            assert!(matches!(
                serctl_protocol::read_frame_limited(&mut client, serctl_protocol::MAX_AUTH_FRAME)
                    .await
                    .unwrap(),
                Some(serctl_protocol::Frame::AuthChallenge { .. })
            ));
            serctl_protocol::write_frame_limited(
                &mut client,
                &serctl_protocol::Frame::AuthResponse {
                    client_proof: serctl_core::vault::new_ipc_token(),
                    client_call_proof: None,
                },
                serctl_protocol::MAX_AUTH_FRAME,
            )
            .await
            .unwrap();

            match tokio::time::timeout(
                Duration::from_millis(250),
                serctl_protocol::read_frame_limited(&mut client, serctl_protocol::MAX_AUTH_FRAME),
            )
            .await
            {
                Ok(Ok(None)) | Ok(Err(_)) => {}
                Ok(Ok(Some(frame))) => {
                    panic!("authentication failure disclosed a response frame: {frame:?}")
                }
                Err(_) => panic!("server did not close a failed authentication promptly"),
            }
        };

        tokio::join!(server_task, client_task);
    }

    #[test]
    fn exec_timeout_is_bounded() {
        assert!(validated_exec_timeout(0).is_err());
        assert!(validated_exec_timeout(1).is_ok());
        assert!(validated_exec_timeout(serctl_protocol::MAX_EXEC_TIMEOUT_MS + 1).is_err());
    }

    #[test]
    fn sftp_timeout_is_bounded() {
        assert!(validated_sftp_timeout(0).is_err());
        assert!(validated_sftp_timeout(1).is_ok());
        assert!(validated_sftp_timeout(serctl_protocol::MAX_SFTP_TIMEOUT_MS + 1).is_err());
    }

    #[test]
    fn native_chunk_limit_is_independent_from_sftp_confirmed_write_cap() {
        let (chunk, window) = negotiated_native_limits(
            serctl_transfer_protocol::DEFAULT_CHUNK_BYTES,
            serctl_transfer_protocol::MAX_WINDOW_BYTES,
        )
        .unwrap();
        assert_eq!(chunk, serctl_protocol::NATIVE_IPC_CHUNK_BYTES as u32);
        assert!(chunk > serctl_protocol::SFTP_SAFE_CHUNK_BYTES as u32);
        assert_eq!(window, serctl_transfer_protocol::MAX_WINDOW_BYTES);

        let (smaller_chunk, smaller_window) = negotiated_native_limits(32 * 1024, 128 * 1024)
            .expect("valid helper limits should negotiate downward");
        assert_eq!(smaller_chunk, 32 * 1024);
        assert_eq!(smaller_window, 128 * 1024);
        assert!(negotiated_native_limits(0, 1).is_err());
        assert!(negotiated_native_limits(
            128 * 1024,
            serctl_protocol::NATIVE_IPC_CHUNK_BYTES as u32 - 1,
        )
        .is_err());
    }

    #[test]
    fn startup_rereads_after_removing_a_shadowing_hashed_lock() {
        let legacy = recover_invalid_startup_lock_read::<u8, _, _>(
            Err(anyhow::anyhow!("malformed hashed lock")),
            || Ok(true),
            || Ok(Some(9)),
        )
        .unwrap();
        assert_eq!(legacy, Some(9));

        let legacy_error = recover_invalid_startup_lock_read::<u8, _, _>(
            Err(anyhow::anyhow!("malformed hashed lock")),
            || Ok(true),
            || Err(anyhow::anyhow!("raw legacy lock is unsupported")),
        )
        .unwrap_err();
        assert!(legacy_error.to_string().contains("raw legacy lock"));
    }

    #[test]
    fn authenticated_request_semantic_limits_are_enforced() {
        assert!(
            validate_request_frame(&serctl_protocol::Frame::ConnectionIdentity {
                profile_id: [0x55; 16],
                profile_generation: 0,
            })
            .is_err()
        );
        assert!(
            validate_request_frame(&serctl_protocol::Frame::ConnectionIdentity {
                profile_id: [0x55; 16],
                profile_generation: 1,
            })
            .is_ok()
        );
        assert!(validate_request_frame(&serctl_protocol::Frame::Exec {
            cmd: "x".repeat(serctl_core::ssh::MAX_REMOTE_COMMAND_BYTES + 1),
            timeout_ms: 1,
        })
        .is_err());
        assert!(
            validate_request_frame(&serctl_protocol::Frame::UploadChunk {
                data: vec![0; MAX_UPLOAD_CHUNK_BYTES + 1],
            })
            .is_err()
        );
        assert!(
            validate_request_frame(&serctl_protocol::Frame::UploadBegin {
                transfer_id: serctl_protocol::TransferId::random(),
                path: "/tmp/x".into(),
                size: serctl_core::ssh::MAX_TRANSFER_BYTES + 1,
                sha256: "00".repeat(32),
                backend: serctl_protocol::TransferBackend::Sftp,
                resume: serctl_protocol::TransferResumeMode::Never,
                resume_token: None,
                expected_helper_identity: None,
                idle_timeout_ms: 1,
                deadline_ms: Some(1),
            })
            .is_err()
        );

        let download_with =
            |resume, resume_offset, expected_size, expected_sha256: Option<String>| {
                serctl_protocol::Frame::Download {
                    transfer_id: serctl_protocol::TransferId::random(),
                    path: "/tmp/x".into(),
                    local_target_sha256: Some("33".repeat(32)),
                    backend: serctl_protocol::TransferBackend::Native,
                    resume,
                    resume_offset,
                    expected_size,
                    expected_sha256,
                    expected_helper_identity: Some(Box::new(
                        serctl_protocol::ExpectedNativeHelperIdentity {
                            name: "serctl-xfer".into(),
                            binary_size: 123,
                            sha256: "44".repeat(32),
                            version:
                                "serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)"
                                    .into(),
                        },
                    )),
                    idle_timeout_ms: 1,
                    deadline_ms: Some(1),
                }
            };
        let valid_download = download_with(
            serctl_protocol::TransferResumeMode::Auto,
            5,
            Some(10),
            Some("ab".repeat(32)),
        );
        assert!(validate_request_frame(&valid_download).is_ok());
        assert!(validate_grant_frame_binding(&valid_download).is_ok());
        let mut missing_local_target = valid_download.clone();
        let serctl_protocol::Frame::Download {
            local_target_sha256,
            ..
        } = &mut missing_local_target
        else {
            unreachable!()
        };
        *local_target_sha256 = None;
        assert!(validate_request_frame(&missing_local_target).is_ok());
        assert!(validate_grant_frame_binding(&missing_local_target).is_err());
        let mut invalid_local_target = valid_download.clone();
        let serctl_protocol::Frame::Download {
            local_target_sha256,
            ..
        } = &mut invalid_local_target
        else {
            unreachable!()
        };
        *local_target_sha256 = Some("NOT-A-DIGEST".into());
        assert!(validate_request_frame(&invalid_local_target).is_err());
        for invalid in [
            download_with(serctl_protocol::TransferResumeMode::Auto, 5, Some(10), None),
            download_with(
                serctl_protocol::TransferResumeMode::Auto,
                11,
                Some(10),
                Some("ab".repeat(32)),
            ),
            download_with(
                serctl_protocol::TransferResumeMode::Auto,
                5,
                Some(10),
                Some("AB".repeat(32)),
            ),
            download_with(
                serctl_protocol::TransferResumeMode::Never,
                5,
                Some(10),
                Some("ab".repeat(32)),
            ),
        ] {
            assert!(validate_request_frame(&invalid).is_err());
        }
    }

    #[test]
    fn daemon_and_direct_routes_share_command_and_path_rejections() {
        let oversized_command = "x".repeat(serctl_core::ssh::MAX_REMOTE_COMMAND_BYTES + 1);
        assert!(serctl_core::ssh::validate_remote_command(&oversized_command).is_err());
        assert!(validate_request_frame(&serctl_protocol::Frame::Exec {
            cmd: oversized_command,
            timeout_ms: 1,
        })
        .is_err());
        assert!(serctl_core::ssh::validate_remote_command("echo\0hidden").is_err());
        assert!(validate_request_frame(&serctl_protocol::Frame::Exec {
            cmd: "echo\0hidden".to_owned(),
            timeout_ms: 1,
        })
        .is_err());

        for invalid_path in [String::new(), "nul\0path".to_owned()] {
            assert!(serctl_core::ssh::validate_remote_path(&invalid_path, false).is_err());
            assert!(validate_request_frame(&serctl_protocol::Frame::Download {
                transfer_id: serctl_protocol::TransferId::random(),
                path: invalid_path,
                local_target_sha256: None,
                backend: serctl_protocol::TransferBackend::Sftp,
                resume: serctl_protocol::TransferResumeMode::Never,
                resume_offset: 0,
                expected_size: None,
                expected_sha256: None,
                expected_helper_identity: None,
                idle_timeout_ms: 1,
                deadline_ms: Some(1),
            })
            .is_err());
        }

        for (cols, rows) in [(0, 24), (80, serctl_core::ssh::MAX_SHELL_DIMENSION + 1)] {
            assert!(serctl_core::ssh::validate_shell_dimensions(cols, rows).is_err());
            assert!(validate_request_frame(&serctl_protocol::Frame::Shell { cols, rows }).is_err());
        }
        assert!(serctl_core::ssh::validate_shell_dimensions(80, 24).is_ok());
        assert!(
            validate_request_frame(&serctl_protocol::Frame::Shell { cols: 80, rows: 24 }).is_ok()
        );
    }

    #[test]
    fn daemon_terminal_diagnostics_escape_controls_and_bidi_fields() {
        let hostile = "保留\n\u{1b}]52;c;payload\u{7}\u{202e}\u{2028}";
        let startup = daemon_up_line(hostile, hostile, 22, hostile, hostile, hostile);
        let diagnostic = terminal_safe_error(&anyhow::anyhow!("failure: {hostile}"));
        for line in [startup, diagnostic] {
            assert!(line.contains("保留"));
            assert!(line.contains("\\n"));
            assert!(line.contains("\\u{1b}"));
            assert!(line.contains("\\u{202e}"));
            assert!(line.contains("\\u{2028}"));
            assert!(!line.chars().any(char::is_control));
            assert!(!line.contains('\u{202e}'));
            assert!(!line.contains('\u{2028}'));
        }
    }

    #[tokio::test]
    async fn daemon_exec_wire_errors_keep_request_send_failures_plain() {
        let rejected = exec_request_rejected_wire_message(anyhow::anyhow!(
            "injected russh exec queue send failure"
        ));
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        serctl_protocol::write_frame(
            &mut writer,
            &serctl_protocol::Frame::Error {
                msg: rejected.clone(),
            },
        )
        .await
        .unwrap();
        let frame =
            serctl_protocol::read_frame_limited(&mut reader, serctl_protocol::MAX_RESPONSE_FRAME)
                .await
                .unwrap()
                .unwrap();
        let serctl_protocol::Frame::Error { msg } = frame else {
            panic!("daemon exec rejection was not encoded as an error frame");
        };
        assert_eq!(msg, rejected);
        assert!(serctl_core::ssh::ExecOutcomeUnknown::from_wire_message(&msg).is_none());

        let uncertain = exec_outcome_unknown_wire_message(anyhow::anyhow!(
            "remote command finish response was lost"
        ));
        assert!(serctl_core::ssh::ExecOutcomeUnknown::from_wire_message(&uncertain).is_some());
    }

    #[tokio::test]
    async fn buffered_operation_waiter_resumes_only_after_a_slot_is_released() {
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let (peer, mut reader) = tokio::io::duplex(1);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let waiter_slots = slots.clone();
        let waiter = tokio::spawn(async move {
            acquire_buffered_operation_slot(
                waiter_slots,
                &mut reader,
                &mut shutdown_rx,
                Instant::now() + Duration::from_secs(1),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        drop(held);
        assert!(tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .is_some());
        drop(peer);
        drop(shutdown_tx);
    }

    #[tokio::test]
    async fn authenticated_half_frame_is_closed_at_idle_deadline() {
        let (mut peer, mut reader) = tokio::io::duplex(16);
        peer.write_all(&[0, 0]).await.unwrap();
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let error =
            read_authenticated_request(&mut reader, &mut shutdown_rx, Duration::from_millis(20))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("idle deadline"));
    }

    #[tokio::test]
    async fn ipc_response_write_honors_absolute_deadline() {
        let (mut writer, _unread_peer) = tokio::io::duplex(1);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let error = write_frame_or_shutdown(
            &mut writer,
            &serctl_protocol::Frame::ExecOut {
                data: vec![0; 1024],
            },
            Instant::now() + Duration::from_millis(20),
            &mut shutdown_rx,
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("IPC response write exceeded its deadline"));
    }

    #[tokio::test]
    async fn daemon_shutdown_preempts_blocked_ipc_response_write() {
        let (mut writer, _unread_peer) = tokio::io::duplex(1);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let trigger = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            shutdown_tx.send(true).unwrap();
        });

        let error = write_frame_or_shutdown(
            &mut writer,
            &serctl_protocol::Frame::ExecOut {
                data: vec![0; 1024],
            },
            Instant::now() + Duration::from_secs(5),
            &mut shutdown_rx,
        )
        .await
        .unwrap_err();
        trigger.await.unwrap();

        assert!(error
            .to_string()
            .contains("daemon shutting down during IPC response write"));
    }

    #[tokio::test]
    async fn ssh_shell_input_write_honors_absolute_deadline() {
        let (mut writer, _unread_peer) = tokio::io::duplex(1);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let error = write_all_until_or_shutdown(
            &mut writer,
            &[0; 1024],
            Instant::now() + Duration::from_millis(20),
            &mut shutdown_rx,
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("SSH shell input write exceeded its deadline"));
    }

    #[tokio::test]
    async fn daemon_shutdown_preempts_blocked_ssh_shell_input_write() {
        let (mut writer, _unread_peer) = tokio::io::duplex(1);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let trigger = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            shutdown_tx.send(true).unwrap();
        });

        let error = write_all_until_or_shutdown(
            &mut writer,
            &[0; 1024],
            Instant::now() + Duration::from_secs(5),
            &mut shutdown_rx,
        )
        .await
        .unwrap_err();
        trigger.await.unwrap();

        assert!(error
            .to_string()
            .contains("daemon shutting down during SSH shell input write"));
    }
}
