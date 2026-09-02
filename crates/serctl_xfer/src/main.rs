use anyhow::{bail, ensure, Context, Result};
use serctl_transfer_protocol as protocol;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read as _, Seek as _};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[derive(Debug)]
struct TransferBusy;

impl std::fmt::Display for TransferBusy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native transfer is already active for this intent")
    }
}

impl std::error::Error for TransferBusy {}

#[derive(Debug)]
struct CommitOutcomeUnknown {
    source: anyhow::Error,
}

impl CommitOutcomeUnknown {
    fn new(source: anyhow::Error) -> Self {
        Self { source }
    }
}

impl std::fmt::Display for CommitOutcomeUnknown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native upload commit outcome unknown: {}",
            self.source
        )
    }
}

impl std::error::Error for CommitOutcomeUnknown {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// A no-replace commit syscall that returned failure before creating the
/// target directory entry. Unlike a failure after a successful link, this is
/// a deterministic non-commit and must never be promoted to outcome-unknown.
#[derive(Debug)]
struct CommitNotApplied {
    source: anyhow::Error,
}

impl std::fmt::Display for CommitNotApplied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native upload no-replace commit was not applied: {}",
            self.source
        )
    }
}

impl std::error::Error for CommitNotApplied {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug)]
struct CleanupIncomplete(String);

impl std::fmt::Display for CleanupIncomplete {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "native transfer cleanup incomplete: {}", self.0)
    }
}

impl std::error::Error for CleanupIncomplete {}

fn normalize_post_commit_result(result: Result<()>, commit_applied: bool) -> Result<()> {
    match result {
        // A verified cleanup failure means the target commit is known and only
        // the owned residue state is incomplete. Preserve that typed outcome;
        // wrapping it as commit-unknown would erase the distinction exposed by
        // the wire protocol.
        Err(error) if commit_applied && error.is::<CleanupIncomplete>() => Err(error),
        Err(error) if commit_applied => Err(anyhow::Error::new(CommitOutcomeUnknown::new(error))),
        other => other,
    }
}

/// Preserve the initial sidecar write failure only when its newly-created
/// partial was removed with an identity-verified cleanup. If cleanup itself
/// fails, the observable state includes owned residue and must be reported as
/// `cleanup_incomplete`, never as a plain pre-commit transfer failure.
fn reconcile_initial_sidecar_failure(
    sidecar_error: anyhow::Error,
    cleanup: Result<()>,
    cleanup_kind: &str,
) -> Result<()> {
    match cleanup {
        Ok(()) => Err(sidecar_error),
        Err(cleanup_error) => Err(anyhow::Error::new(CleanupIncomplete(format!(
            "initial resume sidecar persistence failed: {sidecar_error:#}; identity-verified {cleanup_kind} cleanup failed: {cleanup_error:#}"
        )))),
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("serctl-xfer: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let mut args = std::env::args_os();
    let _program = args.next();
    if args.len() == 1 && args.next().as_deref() == Some(std::ffi::OsStr::new("--version")) {
        println!("{}", xfer_version_line());
        return Ok(());
    }
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("serve"))
            && args.next().as_deref() == Some(std::ffi::OsStr::new("--stdio"))
            && args.next().is_none(),
        "usage: serctl-xfer serve --stdio"
    );
    serve(tokio::io::stdin(), tokio::io::stdout()).await
}

fn xfer_version_line() -> String {
    format!(
        "serctl-xfer {} (git {}; transfer protocol v{})",
        env!("CARGO_PKG_VERSION"),
        env!("SERCTL_BUILD_COMMIT"),
        protocol::VERSION
    )
}

#[cfg(any(target_os = "linux", test))]
fn helper_runtime_identity_from_reader<R: std::io::Read>(
    mut reader: R,
    binary_size: u64,
) -> Result<protocol::HelperRuntimeIdentity> {
    ensure!(
        (1..=protocol::MAX_HELPER_BINARY_BYTES).contains(&binary_size),
        "native helper self-image size is invalid"
    );
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("hash native helper self-image")?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .context("native helper self-image size overflow")?;
        ensure!(
            copied <= protocol::MAX_HELPER_BINARY_BYTES,
            "native helper self-image exceeds its size bound"
        );
        hasher.update(&buffer[..read]);
    }
    ensure!(
        copied == binary_size,
        "native helper self-image changed while it was hashed"
    );
    let identity = protocol::HelperRuntimeIdentity {
        name: protocol::HELPER_BINARY_NAME.to_owned(),
        binary_size,
        sha256: hex::encode(hasher.finalize()),
        version: xfer_version_line(),
    };
    identity.validate()?;
    Ok(identity)
}

#[cfg(any(target_os = "linux", test))]
fn helper_runtime_identity_from_file(
    file: std::fs::File,
) -> Result<protocol::HelperRuntimeIdentity> {
    let metadata = file
        .metadata()
        .context("read native helper self-image metadata")?;
    ensure!(
        metadata.file_type().is_file(),
        "native helper self-image is not a regular file"
    );
    helper_runtime_identity_from_reader(file, metadata.len())
}

#[cfg(test)]
fn helper_runtime_identity_from_test_path(
    path: &std::path::Path,
) -> Result<protocol::HelperRuntimeIdentity> {
    let file = std::fs::File::open(path).context("open native helper self-image")?;
    helper_runtime_identity_from_file(file)
}

fn helper_runtime_identity() -> Result<protocol::HelperRuntimeIdentity> {
    #[cfg(all(not(target_os = "linux"), not(test)))]
    bail!("native helper self-image identity requires Linux /proc/self/exe");

    #[cfg(any(target_os = "linux", test))]
    {
        #[cfg(target_os = "linux")]
        let self_image = PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let self_image = std::env::current_exe().context("locate test helper self-image")?;
        let file = std::fs::File::open(&self_image).context("open native helper self-image")?;
        helper_runtime_identity_from_file(file)
    }
}

async fn serve<R, W>(mut reader: R, mut writer: W) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Do not emit even a syntactically valid helper hello if the fixed
    // running-image handle cannot be opened and hashed first.
    let identity = helper_runtime_identity()?;
    let result = serve_inner(&mut reader, &mut writer, identity).await;
    if let Err(error) = result {
        let outcome_unknown = error.is::<CommitOutcomeUnknown>();
        let code = if outcome_unknown {
            "outcome_unknown"
        } else if error.is::<CleanupIncomplete>() {
            "cleanup_incomplete"
        } else if error.is::<TransferBusy>() {
            "transfer_busy"
        } else {
            "transfer_failed"
        };
        let _ = protocol::write_control(
            &mut writer,
            &protocol::Control::Error {
                code: code.to_owned(),
                message: error.to_string(),
                outcome_unknown,
            },
        )
        .await;
        return Err(error);
    }
    Ok(())
}

async fn serve_inner<R, W>(
    reader: &mut R,
    writer: &mut W,
    identity: protocol::HelperRuntimeIdentity,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    ensure!(
        cfg!(target_os = "linux") || cfg!(test),
        "native helper server requires Linux descriptor-bound commit semantics"
    );
    protocol::write_handshake_control(
        writer,
        &protocol::Control::HelperHello {
            version: protocol::VERSION,
            max_chunk: protocol::DEFAULT_CHUNK_BYTES,
            max_window: protocol::MAX_WINDOW_BYTES,
            resume: true,
            sha256: true,
            fsync: true,
            no_replace: true,
            identity,
        },
        protocol::HandshakePeer::Helper,
    )
    .await?;
    let client_hello = match protocol::read_frame(reader).await? {
        Some(protocol::Frame::Control(control)) => control,
        _ => bail!("client did not complete the native transfer handshake"),
    };
    client_hello.validate_handshake_sender(protocol::HandshakePeer::Client)?;
    let (chunk, window) = match client_hello {
        protocol::Control::Hello {
            version,
            max_chunk,
            max_window,
            sha256,
            fsync,
            no_replace,
            ..
        } if version == protocol::VERSION => {
            ensure!(
                sha256 && fsync && no_replace,
                "client omitted required native features"
            );
            let chunk = max_chunk.min(protocol::DEFAULT_CHUNK_BYTES);
            let window = max_window.min(protocol::MAX_WINDOW_BYTES);
            ensure!(
                chunk > 0 && window >= chunk,
                "client sent invalid native transfer limits"
            );
            (chunk, window)
        }
        _ => bail!("client did not complete the native transfer handshake"),
    };
    let root = match protocol::read_frame(reader).await? {
        Some(protocol::Frame::Control(control)) => protocol::Zeroizing::new(control),
        _ => bail!("client did not send a native transfer root request"),
    };
    match &*root {
        protocol::Control::BeginPush {
            transfer_id,
            target,
            size,
            sha256,
            resume_token,
            resume,
        } => {
            ensure!(
                resume_token.len() == 64
                    && resume_token
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
                "resume token must contain 64 lowercase hex characters"
            );
            serve_push(
                reader,
                writer,
                PushRequest {
                    transfer_id: transfer_id.as_str(),
                    target: target.as_str(),
                    size: *size,
                    expected_sha256: sha256.as_str(),
                    resume_token: resume_token.as_str(),
                    resume: *resume,
                    chunk,
                    window,
                },
            )
            .await
        }
        protocol::Control::BeginPull {
            transfer_id,
            source,
            offset,
        } => serve_pull(reader, writer, transfer_id, source, *offset, chunk, window).await,
        _ => bail!("client did not send a native transfer root request"),
    }
}

async fn serve_pull<R, W>(
    reader: &mut R,
    writer: &mut W,
    transfer_id: &str,
    source: &str,
    offset: u64,
    chunk: u32,
    window: u32,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    ensure!(
        !source.is_empty() && source.len() <= 4096 && !source.contains('\0'),
        "invalid source path"
    );
    let transfer_id_bytes = protocol::parse_transfer_id(transfer_id)?;
    let source = PathBuf::from(source);
    let source_file = open_native_source(&source)
        .with_context(|| format!("open native source {}", source.display()))?;
    let before = source_file
        .metadata()
        .with_context(|| format!("inspect native source {}", source.display()))?;
    ensure!(before.is_file(), "native source is not a regular file");
    let size = before.len();
    ensure!(offset <= size, "native pull offset exceeds source size");
    let mut source_file = tokio::fs::File::from_std(source_file);
    let mut hasher = Sha256::new();
    // Seed a second hasher with exactly the already-durable prefix. The
    // bytes read from `offset` onward are added as they are actually sent,
    // so a same-handle mutation after the identity announcement cannot make
    // the helper report the digest of bytes other than those delivered.
    let mut sent_hasher = Sha256::new();
    let mut buffer = vec![0_u8; chunk as usize];
    let mut hashed = 0_u64;
    loop {
        let read = source_file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if hashed < offset {
            let prefix = usize::try_from((offset - hashed).min(read as u64))?;
            sent_hasher.update(&buffer[..prefix]);
        }
        hashed = hashed
            .checked_add(read as u64)
            .context("native pull hash byte count overflow")?;
    }
    ensure!(hashed == size, "native source changed while hashing");
    let after = source_file.metadata().await?;
    ensure!(after.len() == size, "native source changed while hashing");
    if let (Ok(before_modified), Ok(after_modified)) = (before.modified(), after.modified()) {
        ensure!(
            before_modified == after_modified,
            "native source changed while hashing"
        );
    }
    let sha256 = hex::encode(hasher.finalize());
    source_file.seek(std::io::SeekFrom::Start(offset)).await?;
    protocol::write_control(
        writer,
        &protocol::Control::PullReady {
            chunk,
            window,
            size,
            sha256: sha256.clone(),
            start_offset: offset,
        },
    )
    .await?;
    let mut confirmed = offset;
    let mut durable = offset;
    loop {
        let read = source_file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let data = protocol::DataFrame::new(transfer_id_bytes, confirmed, buffer[..read].to_vec())?;
        protocol::write_data(writer, &data).await?;
        sent_hasher.update(&buffer[..read]);
        let next = confirmed
            .checked_add(read as u64)
            .context("native pull offset overflow")?;
        match protocol::read_frame(reader).await? {
            Some(protocol::Frame::Control(protocol::Control::Ack {
                confirmed_offset,
                durable_offset,
                receiver_window,
            })) if confirmed_offset == next
                && durable_offset >= durable
                && durable_offset <= confirmed_offset
                && receiver_window >= chunk
                && receiver_window <= window =>
            {
                confirmed = next;
                durable = durable_offset;
            }
            Some(protocol::Frame::Control(protocol::Control::Cancel)) => {
                bail!("transfer cancelled")
            }
            _ => bail!("native pull acknowledgement mismatch"),
        }
    }
    ensure!(confirmed == size, "native source changed while reading");
    ensure!(
        hex::encode(sent_hasher.finalize()) == sha256,
        "native source changed after its identity was announced"
    );
    let final_metadata = source_file.metadata().await?;
    ensure!(
        final_metadata.len() == size,
        "native source changed while reading"
    );
    if let (Ok(before_modified), Ok(final_modified)) =
        (before.modified(), final_metadata.modified())
    {
        ensure!(
            before_modified == final_modified,
            "native source changed while reading"
        );
    }
    protocol::write_control(writer, &protocol::Control::Completed { size, sha256 }).await
}

struct PushRequest<'a> {
    transfer_id: &'a str,
    target: &'a str,
    size: u64,
    expected_sha256: &'a str,
    resume_token: &'a str,
    resume: bool,
    chunk: u32,
    window: u32,
}

#[cfg(any(target_os = "linux", test))]
const NATIVE_TRANSFER_LOCK_SCHEMA: u8 = 1;
#[cfg(any(target_os = "linux", test))]
const MAX_NATIVE_TRANSFER_LOCK_BYTES: u64 = 4096;

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeTransferLockRecord {
    schema: u8,
    transfer_id: String,
    resume_token_hash: String,
    intent_sha256: String,
}

#[cfg(any(target_os = "linux", test))]
impl NativeTransferLockRecord {
    fn new(
        target: &Path,
        transfer_id: &str,
        size: u64,
        sha256: &str,
        resume_token_hash: &str,
    ) -> Result<Self> {
        let target_name = target
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .context("native target file name is not UTF-8")?;
        let mut intent = Sha256::new();
        intent.update(b"serctl-native-transfer-lock-v1\0");
        for field in [transfer_id, resume_token_hash, target_name, sha256] {
            intent.update((field.len() as u64).to_be_bytes());
            intent.update(field.as_bytes());
        }
        intent.update(size.to_be_bytes());
        Ok(Self {
            schema: NATIVE_TRANSFER_LOCK_SCHEMA,
            transfer_id: transfer_id.to_owned(),
            resume_token_hash: resume_token_hash.to_owned(),
            intent_sha256: hex::encode(intent.finalize()),
        })
    }
}

#[cfg(any(target_os = "linux", test))]
fn encode_native_transfer_lock_record(record: &NativeTransferLockRecord) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(record).context("serialize native transfer lock record")?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_NATIVE_TRANSFER_LOCK_BYTES,
        "native transfer lock record is empty or too large"
    );
    Ok(bytes)
}

#[cfg(any(target_os = "linux", test))]
fn decode_native_transfer_lock_record(
    bytes: &[u8],
    expected: &NativeTransferLockRecord,
) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_NATIVE_TRANSFER_LOCK_BYTES,
        "native transfer lock record is empty or too large"
    );
    let actual: NativeTransferLockRecord =
        serde_json::from_slice(bytes).context("parse native transfer lock record")?;
    ensure!(
        encode_native_transfer_lock_record(&actual)? == bytes,
        "native transfer lock record is not canonical"
    );
    ensure!(actual == *expected, "native transfer lock intent mismatch");
    Ok(())
}

#[cfg(target_os = "linux")]
struct NativeTransferGuard {
    parent: std::fs::File,
    lock: std::fs::File,
    pinned_target: PathBuf,
    lock_path: PathBuf,
    original_parent: PathBuf,
    parent_identity: FileIdentity,
    lock_identity: FileIdentity,
}

#[cfg(target_os = "linux")]
impl NativeTransferGuard {
    fn acquire(
        target: &Path,
        transfer_id: &str,
        size: u64,
        sha256: &str,
        resume_token_hash: &str,
    ) -> Result<Self> {
        use std::io::Write as _;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let original_parent = match target.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_owned(),
            _ => PathBuf::from("."),
        };
        let target_name = target
            .file_name()
            .context("native target must have a file name")?;
        let mut parent_options = std::fs::OpenOptions::new();
        parent_options.read(true).custom_flags(
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        );
        let parent = parent_options.open(&original_parent).with_context(|| {
            format!(
                "open pinned native target parent {}",
                original_parent.display()
            )
        })?;
        let parent_metadata = parent.metadata()?;
        ensure!(
            parent_metadata.is_dir(),
            "native target parent is not a directory"
        );
        let effective_uid = unsafe { libc::geteuid() };
        ensure!(
            parent_metadata.uid() == effective_uid || parent_metadata.uid() == 0,
            "native target parent belongs to an untrusted user"
        );
        let mode = parent_metadata.permissions().mode();
        let writable_by_others = mode & 0o022 != 0;
        let sticky = mode & libc::S_ISVTX != 0;
        ensure!(
            !writable_by_others || sticky,
            "native target parent permits untrusted directory-entry replacement"
        );
        let parent_identity = file_identity(&parent_metadata);
        let pinned_parent = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
        let pinned_probe = std::fs::File::open(&pinned_parent)
            .context("open pinned native target parent through procfs")?;
        ensure!(
            file_identity(&pinned_probe.metadata()?) == parent_identity,
            "pinned native target parent identity mismatch"
        );

        let pinned_target = pinned_parent.join(target_name);
        let lock_path = pinned_parent.join(format!(".serctl-native-lock-{transfer_id}"));
        let expected_record =
            NativeTransferLockRecord::new(target, transfer_id, size, sha256, resume_token_hash)?;
        let mut create_options = std::fs::OpenOptions::new();
        create_options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let (mut lock, created) = match create_options.open(&lock_path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut existing_options = std::fs::OpenOptions::new();
                existing_options
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
                (
                    existing_options.open(&lock_path).with_context(|| {
                        format!("open existing native transfer lock {}", lock_path.display())
                    })?,
                    false,
                )
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("create native transfer lock {}", lock_path.display())
                })
            }
        };
        if created {
            lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        validate_native_transfer_lock_metadata(&lock)?;
        let locked = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if locked != 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                return Err(anyhow::Error::new(TransferBusy));
            }
            return Err(error).context("acquire native transfer lock");
        }
        validate_native_transfer_lock_metadata(&lock)?;
        if created {
            let bytes = encode_native_transfer_lock_record(&expected_record)?;
            lock.write_all(&bytes)
                .context("write native transfer lock record")?;
            lock.sync_all()
                .context("sync native transfer lock record")?;
            parent
                .sync_all()
                .context("sync native transfer lock parent")?;
        } else {
            let length = lock.metadata()?.len();
            ensure!(
                (1..=MAX_NATIVE_TRANSFER_LOCK_BYTES).contains(&length),
                "native transfer lock record is empty or too large"
            );
            let mut bytes = Vec::with_capacity(length as usize);
            (&mut lock)
                .take(MAX_NATIVE_TRANSFER_LOCK_BYTES + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == length,
                "native transfer lock record changed while reading"
            );
            ensure!(
                lock.stream_position()? == length,
                "native transfer lock cursor did not consume the complete record"
            );
            decode_native_transfer_lock_record(&bytes, &expected_record)?;
        }
        let lock_identity = file_identity(&lock.metadata()?);
        let guard = Self {
            parent,
            lock,
            pinned_target,
            lock_path,
            original_parent,
            parent_identity,
            lock_identity,
        };
        guard.ensure_still_bound()?;
        Ok(guard)
    }

    fn target(&self) -> &Path {
        &self.pinned_target
    }

    fn ensure_still_bound(&self) -> Result<()> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let held_metadata = self.lock.metadata()?;
        ensure!(
            held_metadata.nlink() == 1 && file_identity(&held_metadata) == self.lock_identity,
            "native transfer lock inode was unlinked or rebound"
        );
        ensure!(
            file_identity(&self.parent.metadata()?) == self.parent_identity,
            "pinned native target parent identity changed"
        );
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let rebound = options
            .open(&self.lock_path)
            .context("reopen native transfer lock binding")?;
        validate_native_transfer_lock_metadata(&rebound)?;
        ensure!(
            file_identity(&rebound.metadata()?) == self.lock_identity,
            "native transfer lock basename was replaced"
        );
        Ok(())
    }

    fn ensure_original_parent_bound(&self) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        );
        let current = options
            .open(&self.original_parent)
            .context("reopen original native target parent")?;
        ensure!(
            file_identity(&current.metadata()?) == self.parent_identity,
            "original native target parent was rebound"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn validate_native_transfer_lock_metadata(file: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "native transfer lock is not a regular file"
    );
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "native transfer lock belongs to another user"
    );
    ensure!(
        metadata.permissions().mode() & 0o777 == 0o600,
        "native transfer lock permissions are not 0600"
    );
    ensure!(
        metadata.nlink() == 1,
        "native transfer lock has unexpected hard links"
    );
    Ok(())
}

// Non-Linux tests exercise state-machine exclusion only. They are not evidence
// for flock, inode, sticky-directory, procfs, or pinned-dirfd semantics.
#[cfg(all(test, not(target_os = "linux")))]
struct NativeTransferGuard {
    key: PathBuf,
    pinned_target: PathBuf,
}

#[cfg(all(test, not(target_os = "linux")))]
#[derive(Default)]
struct TestTransferLocks {
    active: std::collections::HashSet<PathBuf>,
    records: std::collections::HashMap<PathBuf, NativeTransferLockRecord>,
}

#[cfg(all(test, not(target_os = "linux")))]
fn test_transfer_locks() -> &'static std::sync::Mutex<TestTransferLocks> {
    static LOCKS: std::sync::OnceLock<std::sync::Mutex<TestTransferLocks>> =
        std::sync::OnceLock::new();
    LOCKS.get_or_init(|| std::sync::Mutex::new(TestTransferLocks::default()))
}

#[cfg(all(test, not(target_os = "linux")))]
impl NativeTransferGuard {
    fn acquire(
        target: &Path,
        transfer_id: &str,
        size: u64,
        sha256: &str,
        resume_token_hash: &str,
    ) -> Result<Self> {
        let parent = match target.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let parent = std::fs::canonicalize(parent)?;
        let pinned_target = parent.join(
            target
                .file_name()
                .context("native target must have a file name")?,
        );
        let key = parent.join(format!(".serctl-native-lock-{transfer_id}"));
        let record =
            NativeTransferLockRecord::new(target, transfer_id, size, sha256, resume_token_hash)?;
        let mut locks = test_transfer_locks()
            .lock()
            .map_err(|_| anyhow::anyhow!("test native transfer lock poisoned"))?;
        if locks.active.contains(&key) {
            return Err(anyhow::Error::new(TransferBusy));
        }
        if let Some(existing) = locks.records.get(&key) {
            ensure!(existing == &record, "native transfer lock intent mismatch");
        } else {
            locks.records.insert(key.clone(), record);
        }
        locks.active.insert(key.clone());
        Ok(Self { key, pinned_target })
    }

    fn target(&self) -> &Path {
        &self.pinned_target
    }

    fn ensure_still_bound(&self) -> Result<()> {
        let locks = test_transfer_locks()
            .lock()
            .map_err(|_| anyhow::anyhow!("test native transfer lock poisoned"))?;
        ensure!(
            locks.active.contains(&self.key),
            "test native transfer lock binding was lost"
        );
        Ok(())
    }

    fn ensure_original_parent_bound(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(all(test, not(target_os = "linux")))]
impl Drop for NativeTransferGuard {
    fn drop(&mut self) {
        if let Ok(mut locks) = test_transfer_locks().lock() {
            locks.active.remove(&self.key);
        }
    }
}

#[cfg(all(not(target_os = "linux"), not(test)))]
struct NativeTransferGuard;

#[cfg(all(not(target_os = "linux"), not(test)))]
impl NativeTransferGuard {
    fn acquire(
        _target: &Path,
        _transfer_id: &str,
        _size: u64,
        _sha256: &str,
        _resume_token_hash: &str,
    ) -> Result<Self> {
        bail!("native transfer locking requires Linux flock and dirfd semantics")
    }

    fn target(&self) -> &Path {
        unreachable!("unsupported native transfer guard has no target")
    }

    fn ensure_still_bound(&self) -> Result<()> {
        unreachable!("unsupported native transfer guard cannot be used")
    }

    fn ensure_original_parent_bound(&self) -> Result<()> {
        unreachable!("unsupported native transfer guard cannot be used")
    }
}

async fn serve_push<R, W>(reader: &mut R, writer: &mut W, request: PushRequest<'_>) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let PushRequest {
        transfer_id,
        target,
        size,
        expected_sha256,
        resume_token,
        resume,
        chunk,
        window,
    } = request;
    ensure!(
        !target.is_empty() && target.len() <= 4096 && !target.contains('\0'),
        "invalid target path"
    );
    ensure!(
        expected_sha256.len() == 64
            && expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "invalid expected SHA-256"
    );
    let transfer_id_bytes = protocol::parse_transfer_id(transfer_id)?;
    let resume_token_bytes =
        protocol::Zeroizing::new(hex::decode(resume_token).context("decode resume token")?);
    ensure!(
        resume_token_bytes.len() == 32,
        "resume token must decode to 32 bytes"
    );
    let resume_token_hash = hex::encode(Sha256::digest(&resume_token_bytes));
    let requested_target = PathBuf::from(target);
    let transfer_guard = NativeTransferGuard::acquire(
        &requested_target,
        transfer_id,
        size,
        expected_sha256,
        &resume_token_hash,
    )?;
    // All state observations below occur after exclusive acquisition. On
    // Linux, this path resolves through the pinned parent dirfd rather than
    // through the caller-provided ancestor path.
    let target = transfer_guard.target().to_owned();
    let partial = native_partial_path(&target, transfer_id)?;
    let sidecar = native_sidecar_path(&partial);
    let mut owned = false;
    let mut owned_identity = None;
    let mut commit_applied = false;
    let mut durable = 0_u64;
    let result = async {
        if path_entry_exists(&target)? {
            ensure!(
                resume,
                "destination already exists and this request has no resume proof"
            );
            let state = read_resume_sidecar(&sidecar)
                .context("destination exists without a readable commit receipt")?;
            let mut target_file = open_existing_private(&target, false)?;
            let target_identity = file_identity(&target_file.metadata()?);
            state.validate(
                transfer_id,
                size,
                expected_sha256,
                &resume_token_hash,
                target_identity,
            )?;
            ensure!(
                state.durable_offset == size,
                "destination exists without a fully durable commit receipt"
            );
            ensure!(
                hash_file_exact(&mut target_file, size)? == expected_sha256,
                "committed destination no longer matches its receipt"
            );
            drop(target_file);
            commit_applied = true;

            // A crash can occur after hard_link+parent fsync but before the
            // sidecar is promoted. Matching file identity and digest prove
            // that a fully durable Receiving record is the committed target.
            // Retry the parent-directory sync as well: the previous process
            // may have created the link but failed before proving its
            // directory entry durable.
            transfer_guard.ensure_still_bound()?;
            transfer_guard.ensure_original_parent_bound()?;
            sync_parent(&target).context("sync recovered native target parent")?;
            let committed = state.with_state(ResumeSidecarState::Committed);
            transfer_guard.ensure_still_bound()?;
            replace_verified_resume_sidecar(
                &sidecar,
                transfer_id,
                size,
                expected_sha256,
                &resume_token_hash,
                target_identity,
                state.durable_offset,
                state.state,
                &committed,
            )
            .map_err(|error| {
                anyhow::Error::new(CleanupIncomplete(format!(
                    "persist recovered native commit receipt: {error:#}"
                )))
            })?;
            // A post-link verification/fsync failure deliberately preserves the
            // already-durable partial name. Only remove that recovery anchor after
            // this retry has revalidated the target, re-synced its parent, and
            // durably promoted the receipt to Committed.
            if path_entry_exists(&partial)? {
                transfer_guard.ensure_still_bound()?;
                remove_owned_partial(&partial, target_identity).map_err(|error| {
                    anyhow::Error::new(CleanupIncomplete(format!(
                        "recovered committed partial {}: {error:#}",
                        partial.display()
                    )))
                })?;
            }
            protocol::write_control(
                writer,
                &protocol::Control::Ready {
                    chunk,
                    window,
                    durable_offset: size,
                },
            )
            .await?;
            match protocol::read_frame(reader).await? {
                Some(protocol::Frame::Control(protocol::Control::Commit)) => {}
                Some(protocol::Frame::Control(protocol::Control::Cancel)) => {
                    bail!("transfer cancelled")
                }
                Some(_) => bail!("unexpected frame while recovering native commit receipt"),
                None => bail!("native transfer client disconnected during receipt recovery"),
            }
            transfer_guard.ensure_still_bound()?;
            transfer_guard.ensure_original_parent_bound()?;
            protocol::write_control(
                writer,
                &protocol::Control::Completed {
                    size,
                    sha256: expected_sha256.to_owned(),
                },
            )
            .await?;
            return Ok(());
        }

        let continuing = resume && path_entry_exists(&sidecar)?;
        let (file, identity, mut hasher) = if continuing {
            let state = read_resume_sidecar(&sidecar)?;
            let mut file = open_owned_partial(&partial)?;
            let metadata = file.metadata()?;
            let identity = file_identity(&metadata);
            state.validate(
                transfer_id,
                size,
                expected_sha256,
                &resume_token_hash,
                identity,
            )?;
            ensure!(
                state.state == ResumeSidecarState::Receiving,
                "committed receipt exists but its destination is missing"
            );
            durable = state.durable_offset;
            let length = metadata.len();
            ensure!(
                length >= durable && length <= size,
                "native resume partial length is inconsistent"
            );
            if length != durable {
                transfer_guard.ensure_still_bound()?;
                file.set_len(durable)
                    .context("truncate owned partial to its durable prefix")?;
                file.sync_all().context("sync truncated owned partial")?;
            }
            let mut hasher = Sha256::new();
            file.seek(std::io::SeekFrom::Start(0))?;
            let mut buffer = vec![0_u8; protocol::DEFAULT_CHUNK_BYTES as usize];
            let mut hashed = 0_u64;
            while hashed < durable {
                let remaining = usize::try_from((durable - hashed).min(buffer.len() as u64))?;
                let read = file.read(&mut buffer[..remaining])?;
                ensure!(
                    read > 0,
                    "native resume partial ended before durable offset"
                );
                hasher.update(&buffer[..read]);
                hashed += read as u64;
            }
            file.seek(std::io::SeekFrom::Start(durable))?;
            (file, identity, hasher)
        } else {
            transfer_guard.ensure_still_bound()?;
            let file = create_new_private(&partial)?;
            owned = true;
            let identity = file_identity(&file.metadata()?);
            let state = ResumeSidecar::new(
                transfer_id,
                size,
                expected_sha256,
                &resume_token_hash,
                0,
                identity,
                ResumeSidecarState::Receiving,
            );
            transfer_guard.ensure_still_bound()?;
            if let Err(error) = create_resume_sidecar(&sidecar, &state) {
                // The sidecar never established recoverable ownership. Close
                // the creation handle, then remove only a path that still
                // resolves to the exact private partial we created. Never
                // suppress a replacement, permission, or storage failure.
                drop(file);
                let cleanup = transfer_guard
                    .ensure_still_bound()
                    .and_then(|()| remove_owned_partial(&partial, identity));
                return reconcile_initial_sidecar_failure(error, cleanup, "partial");
            }
            (file, identity, Sha256::new())
        };
        owned = true;
        owned_identity = Some(identity);
        let mut file = tokio::fs::File::from_std(file);
        protocol::write_control(
            writer,
            &protocol::Control::Ready {
                chunk,
                window,
                durable_offset: durable,
            },
        )
        .await?;
        let mut confirmed = durable;
        loop {
            match protocol::read_frame(reader).await? {
                Some(protocol::Frame::Data(data)) => {
                    ensure!(
                        data.transfer_id == transfer_id_bytes,
                        "transfer id mismatch"
                    );
                    ensure!(
                        data.offset == confirmed,
                        "native transfer offset gap, replay, or reordering"
                    );
                    ensure!(
                        data.payload.len() <= chunk as usize,
                        "native transfer chunk exceeds the negotiated size"
                    );
                    let next = confirmed
                        .checked_add(data.payload.len() as u64)
                        .context("native transfer size overflow")?;
                    ensure!(next <= size, "native transfer exceeded declared size");
                    transfer_guard.ensure_still_bound()?;
                    file.write_all(&data.payload).await?;
                    hasher.update(&data.payload);
                    confirmed = next;
                    if confirmed.saturating_sub(durable) >= window as u64 {
                        transfer_guard.ensure_still_bound()?;
                        file.sync_data().await?;
                        let previous_durable = durable;
                        durable = confirmed;
                        transfer_guard.ensure_still_bound()?;
                        replace_verified_resume_sidecar(
                            &sidecar,
                            transfer_id,
                            size,
                            expected_sha256,
                            &resume_token_hash,
                            identity,
                            previous_durable,
                            ResumeSidecarState::Receiving,
                            &ResumeSidecar::new(
                                transfer_id,
                                size,
                                expected_sha256,
                                &resume_token_hash,
                                durable,
                                identity,
                                ResumeSidecarState::Receiving,
                            ),
                        )?;
                    }
                    protocol::write_control(
                        writer,
                        &protocol::Control::Ack {
                            confirmed_offset: confirmed,
                            durable_offset: durable,
                            receiver_window: window,
                        },
                    )
                    .await?;
                }
                Some(protocol::Frame::Control(protocol::Control::Commit)) => break,
                Some(protocol::Frame::Control(protocol::Control::Cancel)) => {
                    bail!("transfer cancelled")
                }
                Some(_) => bail!("unexpected native transfer frame"),
                None => bail!("native transfer client disconnected"),
            }
        }
        ensure!(confirmed == size, "native transfer size mismatch");
        let streamed_sha256 = hex::encode(hasher.finalize());
        ensure!(
            streamed_sha256 == expected_sha256,
            "native transfer SHA-256 mismatch"
        );
        transfer_guard.ensure_still_bound()?;
        file.sync_all().await?;
        let previous_durable = durable;
        durable = size;
        transfer_guard.ensure_still_bound()?;
        replace_verified_resume_sidecar(
            &sidecar,
            transfer_id,
            size,
            expected_sha256,
            &resume_token_hash,
            identity,
            previous_durable,
            ResumeSidecarState::Receiving,
            &ResumeSidecar::new(
                transfer_id,
                size,
                expected_sha256,
                &resume_token_hash,
                durable,
                identity,
                ResumeSidecarState::Receiving,
            ),
        )?;
        let mut file = file.into_std().await;
        validate_owned_file_identity(&file, identity, size)?;
        let actual_sha256 = hash_file_exact(&mut file, size)?;
        ensure!(
            actual_sha256 == expected_sha256,
            "native transfer on-disk SHA-256 mismatch"
        );
        validate_owned_file_identity(&file, identity, size)?;
        transfer_guard.ensure_still_bound()?;
        transfer_guard.ensure_original_parent_bound()?;
        let prepared_commit =
            PreparedNoReplaceCommit::new(&file, &partial, &target, identity, size)?;
        #[cfg(all(windows, test))]
        drop(file);
        if let Err(error) = prepared_commit.commit() {
            if error.is::<CommitNotApplied>() {
                return Err(error);
            }
            return Err(anyhow::Error::new(CommitOutcomeUnknown::new(error)));
        }
        commit_applied = true;
        transfer_guard.ensure_still_bound()?;
        transfer_guard.ensure_original_parent_bound()?;
        if resume {
            transfer_guard.ensure_still_bound()?;
            replace_verified_resume_sidecar(
                &sidecar,
                transfer_id,
                size,
                expected_sha256,
                &resume_token_hash,
                identity,
                durable,
                ResumeSidecarState::Receiving,
                &ResumeSidecar::new(
                    transfer_id,
                    size,
                    expected_sha256,
                    &resume_token_hash,
                    durable,
                    identity,
                    ResumeSidecarState::Committed,
                ),
            )
            .map_err(|error| {
                anyhow::Error::new(CleanupIncomplete(format!(
                    "persist native commit receipt: {error:#}"
                )))
            })?;
        }
        transfer_guard.ensure_still_bound()?;
        remove_owned_partial(&partial, identity).map_err(|error| {
            anyhow::Error::new(CleanupIncomplete(format!(
                "committed partial {}: {error:#}",
                partial.display()
            )))
        })?;
        if !resume {
            transfer_guard.ensure_still_bound()?;
            remove_owned_sidecar(
                &sidecar,
                transfer_id,
                size,
                expected_sha256,
                &resume_token_hash,
                identity,
            )
            .map_err(|error| {
                anyhow::Error::new(CleanupIncomplete(format!(
                    "committed sidecar {}: {error:#}",
                    sidecar.display()
                )))
            })?;
        }
        owned = false;
        // Do not report Completed for a target whose caller-visible parent was
        // rebound after commit/cleanup. Since commit_applied is already true,
        // either check failing is normalized to outcome_unknown.
        transfer_guard.ensure_still_bound()?;
        transfer_guard.ensure_original_parent_bound()?;
        protocol::write_control(
            writer,
            &protocol::Control::Completed {
                size,
                sha256: actual_sha256,
            },
        )
        .await?;
        Ok(())
    }
    .await;
    // `PreparedNoReplaceCommit::commit` reports a typed unknown only after its
    // no-replace link succeeded. At that point the target entry may not yet be
    // durable, so retain the previously synced partial + Receiving receipt as
    // recovery evidence. A same-token retry reconciles and removes it above.
    let preserve_uncertain_commit_evidence =
        !commit_applied && matches!(&result, Err(error) if error.is::<CommitOutcomeUnknown>());
    let result = normalize_post_commit_result(result, commit_applied);
    if owned && result.is_err() && !preserve_uncertain_commit_evidence {
        let cleanup = if let Some(identity) = owned_identity {
            transfer_guard.ensure_still_bound().and_then(|()| {
                cleanup_failed_upload(
                    &partial,
                    &sidecar,
                    transfer_id,
                    size,
                    expected_sha256,
                    &resume_token_hash,
                    identity,
                    durable,
                    resume,
                    commit_applied,
                )
            })
        } else {
            Ok(())
        };
        if let Err(cleanup_error) = cleanup {
            return result.context(CleanupIncomplete(cleanup_error.to_string()));
        }
    }
    result
}

const RESUME_SIDECAR_SCHEMA: u8 = 2;
const MAX_RESUME_SIDECAR_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResumeSidecarState {
    Receiving,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResumeSidecar {
    schema: u8,
    transfer_id: String,
    size: u64,
    sha256: String,
    resume_token_hash: String,
    durable_offset: u64,
    file_device: u64,
    file_inode: u64,
    state: ResumeSidecarState,
}

impl ResumeSidecar {
    fn new(
        transfer_id: &str,
        size: u64,
        sha256: &str,
        resume_token_hash: &str,
        durable_offset: u64,
        identity: FileIdentity,
        state: ResumeSidecarState,
    ) -> Self {
        Self {
            schema: RESUME_SIDECAR_SCHEMA,
            transfer_id: transfer_id.to_owned(),
            size,
            sha256: sha256.to_owned(),
            resume_token_hash: resume_token_hash.to_owned(),
            durable_offset,
            file_device: identity.device,
            file_inode: identity.inode,
            state,
        }
    }

    fn validate(
        &self,
        transfer_id: &str,
        size: u64,
        sha256: &str,
        resume_token_hash: &str,
        identity: FileIdentity,
    ) -> Result<()> {
        ensure!(
            self.schema == RESUME_SIDECAR_SCHEMA,
            "unsupported resume sidecar schema"
        );
        ensure!(
            self.transfer_id == transfer_id,
            "resume transfer id mismatch"
        );
        ensure!(self.size == size, "resume source size mismatch");
        ensure!(self.sha256 == sha256, "resume source SHA-256 mismatch");
        ensure!(
            self.resume_token_hash == resume_token_hash,
            "resume ownership token mismatch"
        );
        ensure!(
            self.durable_offset <= size,
            "resume durable offset exceeds source size"
        );
        ensure!(
            self.file_device == identity.device && self.file_inode == identity.inode,
            "resume partial identity mismatch"
        );
        if self.state == ResumeSidecarState::Committed {
            ensure!(
                self.durable_offset == size,
                "committed resume receipt is not fully durable"
            );
        }
        Ok(())
    }

    fn with_state(&self, state: ResumeSidecarState) -> Self {
        Self {
            schema: self.schema,
            transfer_id: self.transfer_id.clone(),
            size: self.size,
            sha256: self.sha256.clone(),
            resume_token_hash: self.resume_token_hash.clone(),
            durable_offset: self.durable_offset,
            file_device: self.file_device,
            file_inode: self.file_inode,
            state,
        }
    }
}

fn native_sidecar_path(partial: &Path) -> PathBuf {
    let mut name = partial.as_os_str().to_os_string();
    name.push(".json");
    PathBuf::from(name)
}

fn read_resume_sidecar(path: &Path) -> Result<ResumeSidecar> {
    let file = open_existing_private(path, false)?;
    let length = file.metadata()?.len();
    ensure!(
        (1..=MAX_RESUME_SIDECAR_BYTES).contains(&length),
        "resume sidecar is empty or too large"
    );
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_RESUME_SIDECAR_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == length,
        "resume sidecar changed while reading"
    );
    serde_json::from_slice(&bytes).context("parse resume sidecar")
}

fn encode_resume_sidecar(state: &ResumeSidecar) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(state).context("serialize resume sidecar")?;
    ensure!(
        bytes.len() as u64 <= MAX_RESUME_SIDECAR_BYTES,
        "resume sidecar is too large"
    );
    Ok(bytes)
}

/// Create the ownership sidecar exactly once. Atomic replacement is
/// intentionally not used here: an existing path has not been authenticated
/// yet and must never be overwritten by a fresh transfer.
fn create_resume_sidecar(path: &Path, state: &ResumeSidecar) -> Result<()> {
    use std::io::Write as _;

    let bytes = encode_resume_sidecar(state)?;
    let mut file = create_new_private_file(path, "resume sidecar")?;
    let identity = file_identity(&file.metadata()?);
    let persistence = (|| -> Result<()> {
        file.write_all(&bytes)
            .context("write initial resume sidecar")?;
        file.sync_all().context("sync initial resume sidecar")?;
        sync_parent(path).context("sync initial resume sidecar parent")?;
        Ok(())
    })();
    drop(file);
    match persistence {
        Ok(()) => Ok(()),
        Err(error) => reconcile_initial_sidecar_failure(
            error,
            remove_owned_private_file(path, identity, "resume sidecar"),
            "resume sidecar",
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn replace_verified_resume_sidecar(
    path: &Path,
    transfer_id: &str,
    size: u64,
    sha256: &str,
    resume_token_hash: &str,
    expected_identity: FileIdentity,
    expected_durable: u64,
    expected_state: ResumeSidecarState,
    next: &ResumeSidecar,
) -> Result<()> {
    let current = read_resume_sidecar(path)?;
    current.validate(
        transfer_id,
        size,
        sha256,
        resume_token_hash,
        expected_identity,
    )?;
    ensure!(
        current.durable_offset == expected_durable && current.state == expected_state,
        "resume sidecar changed before its verified update"
    );
    replace_resume_sidecar_unchecked(path, next)
}

#[cfg(unix)]
fn replace_resume_sidecar_unchecked(path: &Path, state: &ResumeSidecar) -> Result<()> {
    use atomic_write_file::AtomicWriteFile;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    let bytes = encode_resume_sidecar(state)?;
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open resume sidecar temporary for {}", path.display()))?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(&bytes)?;
    file.commit()
        .with_context(|| format!("commit resume sidecar {}", path.display()))
}

#[cfg(all(windows, test))]
fn replace_resume_sidecar_unchecked(path: &Path, state: &ResumeSidecar) -> Result<()> {
    use atomic_write_file::AtomicWriteFile;
    use std::io::Write as _;

    let bytes = encode_resume_sidecar(state)?;
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open resume sidecar temporary for {}", path.display()))?;
    file.write_all(&bytes)?;
    file.commit()
        .with_context(|| format!("commit resume sidecar {}", path.display()))
}

#[cfg(all(not(unix), not(all(windows, test))))]
fn replace_resume_sidecar_unchecked(_path: &Path, _state: &ResumeSidecar) -> Result<()> {
    bail!("native resume sidecars require Unix durability semantics")
}

fn native_partial_path(target: &Path, transfer_id: &str) -> Result<PathBuf> {
    let name = target
        .file_name()
        .context("native transfer target must have a file name")?;
    let mut partial_name = name.to_os_string();
    partial_name.push(format!(".serctl-native-part-{transfer_id}"));
    Ok(target.with_file_name(partial_name))
}

fn create_new_private_file(path: &Path, kind: &str) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    // The same handle is used for the post-sync, on-disk verification pass;
    // opening it read/write avoids reopening a path that may have changed.
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("create native {kind} {}", path.display()))
}

fn create_new_private(path: &Path) -> Result<std::fs::File> {
    create_new_private_file(path, "partial")
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("inspect native transfer path {}", path.display()))
        }
    }
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

// Production native serving fails before Hello on non-Unix targets. Windows
// still exercises the state machine in unit tests; creation time is stable
// across writes and changes when the test replaces the partial.
#[cfg(all(windows, test))]
fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::windows::fs::MetadataExt;

    FileIdentity {
        device: 0,
        inode: metadata.creation_time(),
    }
}

#[cfg(all(not(unix), not(all(windows, test))))]
fn file_identity(_metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: 0,
        inode: 0,
    }
}

fn hash_file_exact(file: &mut std::fs::File, size: u64) -> Result<String> {
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; protocol::DEFAULT_CHUNK_BYTES as usize];
    let mut hashed = 0_u64;
    while hashed < size {
        let remaining = usize::try_from((size - hashed).min(buffer.len() as u64))?;
        let read = file.read(&mut buffer[..remaining])?;
        ensure!(read > 0, "owned native transfer file ended early");
        hasher.update(&buffer[..read]);
        hashed = hashed
            .checked_add(read as u64)
            .context("owned native transfer hash length overflow")?;
    }
    ensure!(
        file.read(&mut buffer[..1])? == 0,
        "owned native transfer file grew while hashing"
    );
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(unix)]
fn open_native_source(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        // A FIFO must not block the helper before fstat can reject it. Keep
        // symlink-following behavior for pull compatibility; the opened handle
        // remains the sole source for hashing and transfer.
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "native source is not a regular file"
    );
    Ok(file)
}

#[cfg(not(unix))]
fn open_native_source(path: &Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new().read(true).open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "native source is not a regular file"
    );
    Ok(file)
}

#[cfg(unix)]
fn validate_owned_file_identity(
    file: &std::fs::File,
    expected_identity: FileIdentity,
    expected_size: u64,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "owned native transfer file is not regular"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "owned native transfer file is accessible to another user"
    );
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "owned native transfer file belongs to another user"
    );
    ensure!(
        file_identity(&metadata) == expected_identity,
        "owned native transfer file identity changed"
    );
    ensure!(
        metadata.len() == expected_size,
        "owned native transfer file length changed"
    );
    Ok(())
}

#[cfg(all(windows, test))]
fn validate_owned_file_identity(
    file: &std::fs::File,
    expected_identity: FileIdentity,
    expected_size: u64,
) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "owned native transfer file is not regular"
    );
    ensure!(
        file_identity(&metadata) == expected_identity,
        "owned native transfer file identity changed"
    );
    ensure!(
        metadata.len() == expected_size,
        "owned native transfer file length changed"
    );
    Ok(())
}

#[cfg(all(not(unix), not(all(windows, test))))]
fn validate_owned_file_identity(
    _file: &std::fs::File,
    _expected_identity: FileIdentity,
    _expected_size: u64,
) -> Result<()> {
    bail!("native upload verification requires Unix file identity semantics")
}

fn remove_owned_private_file(
    path: &Path,
    expected_identity: FileIdentity,
    kind: &str,
) -> Result<()> {
    let file = open_owned_partial(path)?;
    let metadata = file.metadata()?;
    ensure!(
        file_identity(&metadata) == expected_identity,
        "refusing to remove a replaced native {kind}"
    );
    drop(file);
    std::fs::remove_file(path)
        .with_context(|| format!("remove owned native {kind} {}", path.display()))?;
    sync_parent(path).with_context(|| format!("sync removed native {kind} parent"))
}

fn remove_owned_partial(path: &Path, expected_identity: FileIdentity) -> Result<()> {
    remove_owned_private_file(path, expected_identity, "partial")
}

fn remove_owned_sidecar(
    path: &Path,
    transfer_id: &str,
    size: u64,
    sha256: &str,
    resume_token_hash: &str,
    expected_identity: FileIdentity,
) -> Result<()> {
    let state = read_resume_sidecar(path)?;
    state.validate(
        transfer_id,
        size,
        sha256,
        resume_token_hash,
        expected_identity,
    )?;
    std::fs::remove_file(path)
        .with_context(|| format!("remove owned native sidecar {}", path.display()))?;
    sync_parent(path).context("sync removed native sidecar parent")
}

#[cfg(test)]
fn post_link_fault_targets(
) -> &'static std::sync::Mutex<std::collections::HashSet<std::ffi::OsString>> {
    static TARGETS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashSet<std::ffi::OsString>>,
    > = std::sync::OnceLock::new();
    TARGETS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

#[cfg(test)]
fn inject_post_link_verification_failure(target: &Path) {
    let target_name = target
        .file_name()
        .expect("fault-injected target must have a file name")
        .to_owned();
    post_link_fault_targets()
        .lock()
        .expect("post-link fault registry poisoned")
        .insert(target_name);
}

#[cfg(test)]
fn fail_after_link_if_injected(target_name: &std::ffi::OsStr) -> Result<()> {
    if post_link_fault_targets()
        .lock()
        .map_err(|_| anyhow::anyhow!("post-link fault registry poisoned"))?
        .remove(target_name)
    {
        bail!("injected post-link target verification failure")
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cleanup_failed_upload(
    partial: &Path,
    sidecar: &Path,
    transfer_id: &str,
    size: u64,
    sha256: &str,
    resume_token_hash: &str,
    expected_identity: FileIdentity,
    durable: u64,
    resume: bool,
    committed: bool,
) -> Result<()> {
    let mut failures = Vec::new();
    if committed || !resume {
        if let Err(error) = remove_owned_partial(partial, expected_identity) {
            failures.push(error.to_string());
        }
        if !resume {
            if let Err(error) = remove_owned_sidecar(
                sidecar,
                transfer_id,
                size,
                sha256,
                resume_token_hash,
                expected_identity,
            ) {
                failures.push(error.to_string());
            }
        }
    } else {
        match open_owned_partial(partial) {
            Ok(file) => {
                let identity = file.metadata().map(|metadata| file_identity(&metadata));
                match identity {
                    Ok(identity) if identity == expected_identity => {
                        if let Err(error) = file.set_len(durable) {
                            failures.push(format!("truncate owned partial: {error}"));
                        } else if let Err(error) = file.sync_all() {
                            failures.push(format!("sync truncated owned partial: {error}"));
                        }
                    }
                    Ok(_) => failures.push("refusing to truncate a replaced native partial".into()),
                    Err(error) => failures.push(format!("inspect owned partial: {error}")),
                }
            }
            Err(error) => failures.push(error.to_string()),
        }
    }
    ensure!(failures.is_empty(), "{}", failures.join("; "));
    Ok(())
}

#[cfg(target_os = "linux")]
struct PreparedNoReplaceCommit {
    parent: std::fs::File,
    target_name: std::ffi::CString,
    source_fd_path: std::ffi::CString,
    expected_identity: FileIdentity,
    expected_size: u64,
    #[cfg(test)]
    fault_target_name: std::ffi::OsString,
}

#[cfg(target_os = "linux")]
impl PreparedNoReplaceCommit {
    fn new(
        file: &std::fs::File,
        _partial: &Path,
        target: &Path,
        expected_identity: FileIdentity,
        expected_size: u64,
    ) -> Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let parent_path = target
            .parent()
            .context("native target has no parent directory")?;
        let target_name = target
            .file_name()
            .context("native target must have a file name")?;
        #[cfg(test)]
        let fault_target_name = target_name.to_owned();
        let target_name = std::ffi::CString::new(target_name.as_bytes())
            .context("native target file name contains NUL")?;
        let parent_text = parent_path
            .to_str()
            .context("pinned native target parent is not UTF-8")?;
        let Some(parent_fd) = parent_text.strip_prefix("/proc/self/fd/") else {
            bail!("native upload commit target is not bound to a pinned parent descriptor")
        };
        ensure!(
            !parent_fd.is_empty() && parent_fd.bytes().all(|byte| byte.is_ascii_digit()),
            "native upload commit has an invalid pinned parent descriptor path"
        );
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(
            // Following this exact /proc/self/fd/N link is intentional: N is
            // the already-open parent descriptor held by NativeTransferGuard.
            libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        );
        let parent = options.open(parent_path).with_context(|| {
            format!("open pinned native target parent {}", parent_path.display())
        })?;
        let parent_metadata = parent.metadata()?;
        ensure!(
            parent_metadata.is_dir(),
            "native target parent is not a directory"
        );
        let mode = parent_metadata.permissions().mode();
        let writable_by_others = mode & 0o022 != 0;
        let sticky = mode & libc::S_ISVTX != 0;
        let effective_uid = unsafe { libc::geteuid() };
        ensure!(
            !writable_by_others
                || (sticky
                    && (parent_metadata.uid() == 0 || parent_metadata.uid() == effective_uid)),
            "native target parent permits untrusted directory-entry replacement"
        );

        validate_owned_file_identity(file, expected_identity, expected_size)?;
        let source_fd_path = std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        let source_probe = std::fs::File::open(
            std::str::from_utf8(source_fd_path.as_bytes()).expect("fd path is ASCII"),
        )
        .context("open descriptor-bound native commit source through procfs")?;
        ensure!(
            file_identity(&source_probe.metadata()?) == expected_identity,
            "descriptor-bound native commit source identity mismatch"
        );
        Ok(Self {
            parent,
            target_name,
            source_fd_path,
            expected_identity,
            expected_size,
            #[cfg(test)]
            fault_target_name,
        })
    }

    fn open_committed_target(&self) -> Result<std::fs::File> {
        use std::os::fd::{AsRawFd, FromRawFd};

        let descriptor = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.target_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error())
                .context("open descriptor-bound committed native target");
        }
        // SAFETY: openat returned a new owned descriptor on success.
        let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        validate_owned_file_identity(&file, self.expected_identity, self.expected_size)?;
        Ok(file)
    }

    fn commit(self) -> Result<()> {
        use std::os::fd::AsRawFd;

        let linked = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                self.source_fd_path.as_ptr(),
                self.parent.as_raw_fd(),
                self.target_name.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if linked != 0 {
            let error = anyhow::Error::new(std::io::Error::last_os_error())
                .context("descriptor-bound no-replace native commit");
            return Err(anyhow::Error::new(CommitNotApplied { source: error }));
        }
        #[cfg(test)]
        fail_after_link_if_injected(&self.fault_target_name)?;
        let first = self.open_committed_target()?;
        self.parent
            .sync_all()
            .context("sync pinned native target parent")?;
        let second = self.open_committed_target()?;
        ensure!(
            file_identity(&first.metadata()?) == file_identity(&second.metadata()?),
            "native target directory entry changed during commit"
        );
        Ok(())
    }
}

#[cfg(all(test, not(target_os = "linux")))]
struct PreparedNoReplaceCommit {
    partial: PathBuf,
    target: PathBuf,
    expected_identity: FileIdentity,
    expected_size: u64,
}

#[cfg(all(test, not(target_os = "linux")))]
impl PreparedNoReplaceCommit {
    fn new(
        file: &std::fs::File,
        partial: &Path,
        target: &Path,
        expected_identity: FileIdentity,
        expected_size: u64,
    ) -> Result<Self> {
        validate_owned_file_identity(file, expected_identity, expected_size)?;
        Ok(Self {
            partial: partial.to_owned(),
            target: target.to_owned(),
            expected_identity,
            expected_size,
        })
    }

    fn commit(self) -> Result<()> {
        if let Err(error) = std::fs::hard_link(&self.partial, &self.target) {
            let error = anyhow::Error::new(error)
                .context(format!("test no-replace commit {}", self.target.display()));
            return Err(anyhow::Error::new(CommitNotApplied { source: error }));
        }
        #[cfg(test)]
        fail_after_link_if_injected(
            self.target
                .file_name()
                .context("test native target must have a file name")?,
        )?;
        let target = open_existing_private(&self.target, false)?;
        validate_owned_file_identity(&target, self.expected_identity, self.expected_size)
    }
}

#[cfg(all(not(target_os = "linux"), not(test)))]
struct PreparedNoReplaceCommit;

#[cfg(all(not(target_os = "linux"), not(test)))]
impl PreparedNoReplaceCommit {
    fn new(
        _file: &std::fs::File,
        _partial: &Path,
        _target: &Path,
        _expected_identity: FileIdentity,
        _expected_size: u64,
    ) -> Result<Self> {
        bail!(
            "native upload commit requires Linux descriptor-bound no-replace semantics on this platform"
        )
    }

    fn commit(self) -> Result<()> {
        unreachable!("unsupported native commit cannot be prepared")
    }
}

#[cfg(unix)]
fn open_existing_private(path: &Path, writable: bool) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .with_context(|| format!("open owned native transfer file {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "owned native transfer path is not a regular file"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "owned native transfer file is accessible to another user"
    );
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "owned native transfer file belongs to another user"
    );
    Ok(file)
}

#[cfg(all(windows, test))]
fn open_existing_private(path: &Path, writable: bool) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(writable)
        .open(path)
        .with_context(|| format!("open owned native transfer file {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "owned native transfer path is not a regular file"
    );
    Ok(file)
}

#[cfg(all(not(unix), not(all(windows, test))))]
fn open_existing_private(_path: &Path, _writable: bool) -> Result<std::fs::File> {
    bail!("native resume requires Unix no-follow file semantics")
}

fn open_owned_partial(path: &Path) -> Result<std::fs::File> {
    open_existing_private(path, true)
}

fn sync_parent(target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .context("native target has no parent directory")?;
    #[cfg(unix)]
    {
        std::fs::File::open(parent)
            .with_context(|| format!("open native target parent {}", parent.display()))?
            .sync_all()
            .context("sync native target parent")?;
        Ok(())
    }
    #[cfg(all(windows, test))]
    {
        let _ = parent;
        Ok(())
    }
    #[cfg(all(not(unix), not(all(windows, test))))]
    {
        let _ = parent;
        bail!("native no-replace commit requires parent-directory fsync on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer_artifacts(root: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".serctl-native-lock-")
            })
            .map(|entry| entry.path())
            .collect()
    }
    use std::io::Write as _;
    use tokio::io::AsyncReadExt;

    #[test]
    fn helper_version_reports_its_transfer_protocol() {
        let version = xfer_version_line();
        assert_eq!(
            version,
            format!(
                "serctl-xfer {} (git {}; transfer protocol v{})",
                env!("CARGO_PKG_VERSION"),
                env!("SERCTL_BUILD_COMMIT"),
                protocol::VERSION
            )
        );
    }

    #[test]
    fn helper_self_image_identity_is_hash_bound_and_fail_closed() {
        let payload = b"helper image fixture";
        let identity = helper_runtime_identity_from_reader(
            std::io::Cursor::new(payload),
            payload.len() as u64,
        )
        .unwrap();
        assert_eq!(identity.name, protocol::HELPER_BINARY_NAME);
        assert_eq!(identity.binary_size, payload.len() as u64);
        assert_eq!(identity.sha256, hex::encode(Sha256::digest(payload)));
        assert_eq!(identity.version, xfer_version_line());
        identity.validate().unwrap();

        assert!(helper_runtime_identity_from_reader(std::io::Cursor::new(payload), 0).is_err());
        assert!(helper_runtime_identity_from_reader(
            std::io::Cursor::new(payload),
            payload.len() as u64 + 1,
        )
        .is_err());

        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected self-image read failure"))
            }
        }
        assert!(helper_runtime_identity_from_reader(FailingReader, 1).is_err());

        let missing = std::env::temp_dir().join(format!(
            "serctl-xfer-missing-self-image-{}",
            std::process::id()
        ));
        assert!(helper_runtime_identity_from_test_path(&missing).is_err());

        let directory = std::env::temp_dir().join(format!(
            "serctl-xfer-directory-self-image-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        assert!(helper_runtime_identity_from_test_path(&directory).is_err());
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn native_lock_record_requires_exact_canonical_intent() {
        let target = Path::new("target.bin");
        let expected = NativeTransferLockRecord::new(
            target,
            &"31".repeat(16),
            17,
            &"ab".repeat(32),
            &"cd".repeat(32),
        )
        .unwrap();
        let canonical = encode_native_transfer_lock_record(&expected).unwrap();
        decode_native_transfer_lock_record(&canonical, &expected).unwrap();

        let mut padded = canonical.clone();
        padded.push(b'\n');
        assert!(decode_native_transfer_lock_record(&padded, &expected).is_err());

        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        let with_unknown_field = serde_json::to_vec(&value).unwrap();
        assert!(decode_native_transfer_lock_record(&with_unknown_field, &expected).is_err());

        let different = NativeTransferLockRecord::new(
            target,
            &"31".repeat(16),
            18,
            &"ab".repeat(32),
            &"cd".repeat(32),
        )
        .unwrap();
        assert!(decode_native_transfer_lock_record(&canonical, &different).is_err());
    }

    #[cfg(target_os = "linux")]
    fn linux_guard(target: &Path, transfer_id: &str, size: u64) -> Result<NativeTransferGuard> {
        NativeTransferGuard::acquire(
            target,
            transfer_id,
            size,
            &"ab".repeat(32),
            &"cd".repeat(32),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_lock_rejects_unsafe_existing_entry_types_and_metadata() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::{symlink, OpenOptionsExt as _, PermissionsExt as _};

        for case in ["symlink", "directory", "fifo", "public", "hardlink"] {
            let root = std::env::temp_dir().join(format!(
                "serctl-xfer-lock-entry-{case}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir(&root).unwrap();
            let transfer_id = match case {
                "symlink" => "21".repeat(16),
                "directory" => "22".repeat(16),
                "fifo" => "23".repeat(16),
                "public" => "24".repeat(16),
                "hardlink" => "25".repeat(16),
                _ => unreachable!(),
            };
            let lock = root.join(format!(".serctl-native-lock-{transfer_id}"));
            match case {
                "symlink" => {
                    let source = root.join("source");
                    std::fs::write(&source, b"not-a-lock").unwrap();
                    symlink(source, &lock).unwrap();
                }
                "directory" => std::fs::create_dir(&lock).unwrap(),
                "fifo" => {
                    let path = std::ffi::CString::new(lock.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                "public" => {
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o644)
                        .open(&lock)
                        .unwrap();
                    file.set_permissions(std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                "hardlink" => {
                    let source = root.join("source");
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&source)
                        .unwrap();
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    std::fs::hard_link(source, &lock).unwrap();
                }
                _ => unreachable!(),
            }
            let target = root.join("target.bin");
            assert!(linux_guard(&target, &transfer_id, 1).is_err(), "{case}");
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pinned_parent_survives_path_rebind_but_terminal_binding_fails() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-parent-rebind-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let original = root.join("original");
        let moved = root.join("moved");
        std::fs::create_dir_all(&original).unwrap();
        let target = original.join("target.bin");
        let guard = linux_guard(&target, &"26".repeat(16), 1).unwrap();

        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        guard.ensure_still_bound().unwrap();
        let pinned = create_new_private(guard.target()).unwrap();
        drop(pinned);
        assert!(moved.join("target.bin").exists());
        assert!(!original.join("target.bin").exists());
        assert!(guard.ensure_original_parent_bound().is_err());
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_recreated_lock_invalidates_the_old_holder_and_drop_releases_flock() {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-lock-rebind-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let transfer_id = "27".repeat(16);
        let first = linux_guard(&target, &transfer_id, 1).unwrap();
        let busy = linux_guard(&target, &transfer_id, 1)
            .err()
            .expect("second Linux guard unexpectedly acquired the held lock");
        assert!(busy.is::<TransferBusy>());

        std::fs::remove_file(&first.lock_path).unwrap();
        let record = NativeTransferLockRecord::new(
            &target,
            &transfer_id,
            1,
            &"ab".repeat(32),
            &"cd".repeat(32),
        )
        .unwrap();
        let mut replacement = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&first.lock_path)
            .unwrap();
        replacement
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        replacement
            .write_all(&serde_json::to_vec(&record).unwrap())
            .unwrap();
        replacement.sync_all().unwrap();
        drop(replacement);

        let replacement_holder = linux_guard(&target, &transfer_id, 1).unwrap();
        assert!(first.ensure_still_bound().is_err());
        replacement_holder.ensure_still_bound().unwrap();
        drop(replacement_holder);
        let reused_after_drop = linux_guard(&target, &transfer_id, 1).unwrap();
        drop(reused_after_drop);
        drop(first);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn post_commit_cleanup_remains_distinct_from_unknown_outcome() {
        let cleanup = normalize_post_commit_result(
            Err(anyhow::Error::new(CleanupIncomplete("marker".into()))),
            true,
        )
        .unwrap_err();
        assert!(cleanup.is::<CleanupIncomplete>());
        assert!(!cleanup.is::<CommitOutcomeUnknown>());

        let unknown =
            normalize_post_commit_result(Err(anyhow::anyhow!("marker")), true).unwrap_err();
        assert!(unknown.is::<CommitOutcomeUnknown>());
        assert!(!unknown.is::<CleanupIncomplete>());
    }

    #[test]
    fn initial_sidecar_failure_requires_verified_partial_cleanup() {
        let original = reconcile_initial_sidecar_failure(
            anyhow::anyhow!("sidecar storage exhausted"),
            Ok(()),
            "partial",
        )
        .unwrap_err();
        assert!(!original.is::<CleanupIncomplete>());
        assert!(!original.is::<CommitOutcomeUnknown>());
        assert_eq!(original.to_string(), "sidecar storage exhausted");

        let incomplete = reconcile_initial_sidecar_failure(
            anyhow::anyhow!("sidecar permission denied"),
            Err(anyhow::anyhow!("partial identity changed")),
            "partial",
        )
        .unwrap_err();
        assert!(incomplete.is::<CleanupIncomplete>());
        assert!(!incomplete.is::<CommitOutcomeUnknown>());
        let message = incomplete.to_string();
        assert!(message.contains("sidecar permission denied"));
        assert!(message.contains("partial identity changed"));
    }

    #[tokio::test]
    async fn fresh_push_never_overwrites_an_unknown_sidecar() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-sidecar-create-new-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let transfer_id = "17".repeat(16);
        let partial = native_partial_path(&target, &transfer_id).unwrap();
        let sidecar = native_sidecar_path(&partial);
        let unknown = b"unknown-sidecar-must-survive";
        std::fs::write(&sidecar, unknown).unwrap();

        let (mut client_in, mut client_out, helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPush {
                transfer_id,
                target: target.display().to_string(),
                size: 1,
                sha256: hex::encode(Sha256::digest([1_u8])),
                resume_token: "18".repeat(32),
                resume: false,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            code,
            outcome_unknown,
            ..
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("fresh push overwrote or accepted an unknown sidecar")
        };
        assert_eq!(code, "transfer_failed");
        assert!(!outcome_unknown);
        assert!(helper.await.unwrap().is_err());
        assert_eq!(std::fs::read(&sidecar).unwrap(), unknown);
        assert!(!partial.exists());
        assert!(!target.exists());
        assert_eq!(transfer_artifacts(&root).len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn concurrent_helper_is_busy_then_observes_the_latest_durable_offset() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-exclusive-lock-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let transfer_id = "19".repeat(16);
        let transfer_id_bytes = protocol::parse_transfer_id(&transfer_id).unwrap();
        let resume_token = "1a".repeat(32);
        let payload = vec![7_u8; 512];
        let sha256 = hex::encode(Sha256::digest(&payload));

        let (mut first_in, mut first_out, first_helper) = helper_session(256, 256).await;
        protocol::write_control(
            &mut first_in,
            &protocol::Control::BeginPush {
                transfer_id: transfer_id.clone(),
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256: sha256.clone(),
                resume_token: resume_token.clone(),
                resume: true,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Ready {
            durable_offset: 0, ..
        })) = protocol::read_frame(&mut first_out).await.unwrap()
        else {
            panic!("first helper did not acquire the transfer lock")
        };
        protocol::write_data(
            &mut first_in,
            &protocol::DataFrame::new(transfer_id_bytes, 0, payload[..256].to_vec()).unwrap(),
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Ack {
            durable_offset: 256,
            ..
        })) = protocol::read_frame(&mut first_out).await.unwrap()
        else {
            panic!("first helper did not durably checkpoint its prefix")
        };

        let (mut second_in, mut second_out, second_helper) = helper_session(256, 256).await;
        protocol::write_control(
            &mut second_in,
            &protocol::Control::BeginPush {
                transfer_id: transfer_id.clone(),
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256: sha256.clone(),
                resume_token: resume_token.clone(),
                resume: true,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            code,
            outcome_unknown,
            ..
        })) = protocol::read_frame(&mut second_out).await.unwrap()
        else {
            panic!("concurrent helper was not rejected by the transfer lock")
        };
        assert_eq!(code, "transfer_busy");
        assert!(!outcome_unknown);
        assert!(second_helper.await.unwrap().is_err());

        protocol::write_control(&mut first_in, &protocol::Control::Cancel)
            .await
            .unwrap();
        let _ = protocol::read_frame(&mut first_out).await.unwrap();
        assert!(first_helper.await.unwrap().is_err());

        let (mut third_in, mut third_out, third_helper) = helper_session(256, 256).await;
        protocol::write_control(
            &mut third_in,
            &protocol::Control::BeginPush {
                transfer_id,
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256,
                resume_token,
                resume: true,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Ready {
            durable_offset: 256,
            ..
        })) = protocol::read_frame(&mut third_out).await.unwrap()
        else {
            panic!("replacement helper did not read the locked durable checkpoint")
        };
        protocol::write_control(&mut third_in, &protocol::Control::Cancel)
            .await
            .unwrap();
        let _ = protocol::read_frame(&mut third_out).await.unwrap();
        assert!(third_helper.await.unwrap().is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    async fn helper_session(
        chunk: u32,
        window: u32,
    ) -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (mut client_in, helper_in) = tokio::io::duplex(1024 * 1024);
        let (helper_out, mut client_out) = tokio::io::duplex(1024 * 1024);
        let helper = tokio::spawn(serve(helper_in, helper_out));
        let Some(protocol::Frame::Control(protocol::Control::HelperHello { identity, .. })) =
            protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper did not announce its server-only runtime identity")
        };
        identity.validate().unwrap();
        protocol::write_control(
            &mut client_in,
            &protocol::Control::Hello {
                version: protocol::VERSION,
                max_chunk: chunk,
                max_window: window,
                resume: true,
                sha256: true,
                fsync: true,
                no_replace: true,
            },
        )
        .await
        .unwrap();
        (client_in, client_out, helper)
    }

    #[tokio::test]
    async fn helper_rejects_offset_gap_and_removes_owned_partial() {
        let root = std::env::temp_dir().join(format!("serctl-xfer-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let (mut client_in, helper_in) = tokio::io::duplex(1024 * 1024);
        let (helper_out, mut client_out) = tokio::io::duplex(1024 * 1024);
        let helper = tokio::spawn(serve(helper_in, helper_out));
        let _hello = protocol::read_frame(&mut client_out)
            .await
            .unwrap()
            .unwrap();
        protocol::write_control(
            &mut client_in,
            &protocol::Control::Hello {
                version: protocol::VERSION,
                max_chunk: protocol::DEFAULT_CHUNK_BYTES,
                max_window: protocol::DEFAULT_WINDOW_BYTES,
                resume: false,
                sha256: true,
                fsync: true,
                no_replace: true,
            },
        )
        .await
        .unwrap();
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPush {
                transfer_id: "00000000000000000000000000000001".into(),
                target: target.display().to_string(),
                size: 1,
                sha256: hex::encode(Sha256::digest([1])),
                resume_token: "00".repeat(32),
                resume: false,
            },
        )
        .await
        .unwrap();
        let _ready = protocol::read_frame(&mut client_out)
            .await
            .unwrap()
            .unwrap();
        protocol::write_data(
            &mut client_in,
            &protocol::DataFrame::new([1; 16], 1, vec![1]).unwrap(),
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            code,
            outcome_unknown,
            ..
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper did not return a structured offset-gap error")
        };
        assert_eq!(code, "transfer_failed");
        assert!(!outcome_unknown);
        drop(client_in);
        assert!(helper.await.unwrap().is_err());
        assert!(!target.exists());
        assert!(transfer_artifacts(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
        let mut sink = Vec::new();
        client_out.read_to_end(&mut sink).await.unwrap();
    }

    #[tokio::test]
    async fn helper_reports_commit_phase_collision_as_known_non_commit() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-commit-unknown-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let payload = [7_u8];
        let transfer_id = "07".repeat(16);
        let (mut client_in, mut client_out, helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPush {
                transfer_id,
                target: target.display().to_string(),
                size: 1,
                sha256: hex::encode(Sha256::digest(payload)),
                resume_token: "08".repeat(32),
                resume: false,
            },
        )
        .await
        .unwrap();
        let _ready = protocol::read_frame(&mut client_out)
            .await
            .unwrap()
            .unwrap();
        protocol::write_data(
            &mut client_in,
            &protocol::DataFrame::new([7; 16], 0, payload.to_vec()).unwrap(),
        )
        .await
        .unwrap();
        let _ack = protocol::read_frame(&mut client_out)
            .await
            .unwrap()
            .unwrap();
        std::fs::write(&target, b"collision").unwrap();
        protocol::write_control(&mut client_in, &protocol::Control::Commit)
            .await
            .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            code,
            message,
            outcome_unknown,
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper did not return a structured commit error")
        };
        assert_eq!(code, "transfer_failed", "{message}");
        assert!(!outcome_unknown);
        assert!(message.contains("no-replace commit was not applied"));
        assert!(helper.await.unwrap().is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"collision");
        assert_eq!(transfer_artifacts(&root).len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn helper_rehashes_the_owned_partial_before_commit() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-on-disk-hash-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let transfer_id = "13".repeat(16);
        let partial = native_partial_path(&target, &transfer_id).unwrap();
        let payload = vec![0x41_u8; 256];
        let payload_len = payload.len() as u64;
        let expected_sha256 = hex::encode(Sha256::digest(&payload));
        // Make this one chunk fill the negotiated credit window. The helper
        // must therefore sync the write and report it durable before ACKing;
        // a merely confirmed ACK is not a disk-write completion barrier on
        // Windows because Tokio may still have a blocking file write in flight.
        let (mut client_in, mut client_out, helper) = helper_session(256, 256).await;
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPush {
                transfer_id: transfer_id.clone(),
                target: target.display().to_string(),
                size: payload_len,
                sha256: expected_sha256,
                resume_token: "14".repeat(32),
                resume: false,
            },
        )
        .await
        .unwrap();
        let _ready = protocol::read_frame(&mut client_out)
            .await
            .unwrap()
            .unwrap();
        protocol::write_data(
            &mut client_in,
            &protocol::DataFrame::new(
                protocol::parse_transfer_id(&transfer_id).unwrap(),
                0,
                payload,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Ack {
            confirmed_offset,
            durable_offset,
            ..
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper did not acknowledge the complete durable test payload")
        };
        assert_eq!(confirmed_offset, payload_len);
        assert_eq!(durable_offset, payload_len);

        let mut tamper = std::fs::OpenOptions::new()
            .write(true)
            .open(&partial)
            .unwrap();
        tamper.seek(std::io::SeekFrom::Start(0)).unwrap();
        tamper.write_all(&[0x42]).unwrap();
        tamper.sync_all().unwrap();
        drop(tamper);
        protocol::write_control(&mut client_in, &protocol::Control::Commit)
            .await
            .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            code,
            message,
            outcome_unknown,
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper committed a partial whose on-disk hash changed")
        };
        assert_eq!(code, "transfer_failed");
        assert!(!outcome_unknown);
        assert!(message.contains("on-disk SHA-256 mismatch"));
        assert!(helper.await.unwrap().is_err());
        assert!(!target.exists());
        assert!(transfer_artifacts(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn user_path_text_cannot_spoof_commit_outcome_classification() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-typed-outcome-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("commit outcome unknown").join("target.bin");
        let (mut client_in, mut client_out, helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPush {
                transfer_id: "15".repeat(16),
                target: target.display().to_string(),
                size: 1,
                sha256: hex::encode(Sha256::digest([1_u8])),
                resume_token: "16".repeat(32),
                resume: false,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            code,
            outcome_unknown,
            ..
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper did not return the pre-commit path error")
        };
        assert_eq!(code, "transfer_failed");
        assert!(!outcome_unknown);
        assert!(helper.await.unwrap().is_err());
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_file_validation_rejects_a_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt;

        let root =
            std::env::temp_dir().join(format!("serctl-xfer-fifo-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let fifo = root.join("partial.fifo");
        let fifo_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_path is a live, NUL-terminated path and mkfifo does not
        // retain the pointer after returning.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        let error = open_existing_private(&fifo, false).unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(error.to_string().contains("not a regular file"));
        std::fs::remove_file(fifo).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn helper_rejects_token_and_partial_length_mismatches_without_truncation() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-resume-mismatch-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let transfer_id = "0a".repeat(16);
        let partial = native_partial_path(&target, &transfer_id).unwrap();
        let sidecar = native_sidecar_path(&partial);
        let payload = vec![4_u8; 512];
        let sha256 = hex::encode(Sha256::digest(&payload));
        let token = "0b".repeat(32);
        let token_hash = hex::encode(Sha256::digest(hex::decode(&token).unwrap()));
        let file = create_new_private(&partial).unwrap();
        file.set_len(513).unwrap();
        file.sync_all().unwrap();
        let identity = file_identity(&file.metadata().unwrap());
        create_resume_sidecar(
            &sidecar,
            &ResumeSidecar::new(
                &transfer_id,
                512,
                &sha256,
                &token_hash,
                256,
                identity,
                ResumeSidecarState::Receiving,
            ),
        )
        .unwrap();

        for resume_token in [token.clone(), "0c".repeat(32)] {
            let (mut client_in, mut client_out, helper) = helper_session(256, 1024).await;
            protocol::write_control(
                &mut client_in,
                &protocol::Control::BeginPush {
                    transfer_id: transfer_id.clone(),
                    target: target.display().to_string(),
                    size: 512,
                    sha256: sha256.clone(),
                    resume_token,
                    resume: true,
                },
            )
            .await
            .unwrap();
            let Some(protocol::Frame::Control(protocol::Control::Error {
                outcome_unknown, ..
            })) = protocol::read_frame(&mut client_out).await.unwrap()
            else {
                panic!("helper accepted inconsistent resume evidence")
            };
            assert!(!outcome_unknown);
            assert!(helper.await.unwrap().is_err());
            assert_eq!(std::fs::metadata(&partial).unwrap().len(), 513);
        }
        assert!(!target.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn helper_rejects_data_larger_than_the_negotiated_chunk() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-negotiated-chunk-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let payload = vec![5_u8; 257];
        let (mut client_in, mut client_out, helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPush {
                transfer_id: "0d".repeat(16),
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256: hex::encode(Sha256::digest(&payload)),
                resume_token: "0e".repeat(32),
                resume: false,
            },
        )
        .await
        .unwrap();
        let _ready = protocol::read_frame(&mut client_out)
            .await
            .unwrap()
            .unwrap();
        protocol::write_data(
            &mut client_in,
            &protocol::DataFrame::new([0x0d; 16], 0, payload).unwrap(),
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            outcome_unknown, ..
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper accepted a chunk larger than its negotiated limit")
        };
        assert!(!outcome_unknown);
        assert!(helper.await.unwrap().is_err());
        assert!(!target.exists());
        assert!(transfer_artifacts(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn helper_rejects_replaced_partial_even_with_matching_length() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-partial-identity-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let transfer_id = "0f".repeat(16);
        let partial = native_partial_path(&target, &transfer_id).unwrap();
        let sidecar = native_sidecar_path(&partial);
        let payload = vec![6_u8; 512];
        let sha256 = hex::encode(Sha256::digest(&payload));
        let token = "10".repeat(32);
        let token_hash = hex::encode(Sha256::digest(hex::decode(&token).unwrap()));
        let file = create_new_private(&partial).unwrap();
        file.set_len(256).unwrap();
        file.sync_all().unwrap();
        let mut wrong_identity = file_identity(&file.metadata().unwrap());
        wrong_identity.inode ^= 1;
        drop(file);
        create_resume_sidecar(
            &sidecar,
            &ResumeSidecar::new(
                &transfer_id,
                payload.len() as u64,
                &sha256,
                &token_hash,
                256,
                wrong_identity,
                ResumeSidecarState::Receiving,
            ),
        )
        .unwrap();

        let (mut client_in, mut client_out, helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPush {
                transfer_id,
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256,
                resume_token: token,
                resume: true,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            outcome_unknown, ..
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper accepted a replaced resume partial")
        };
        assert!(!outcome_unknown);
        assert!(helper.await.unwrap().is_err());
        assert_eq!(std::fs::metadata(&partial).unwrap().len(), 256);
        assert!(!target.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn helper_recovers_a_committed_transfer_after_terminal_delivery_is_lost() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-commit-receipt-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let transfer_id = "11".repeat(16);
        let transfer_id_bytes = protocol::parse_transfer_id(&transfer_id).unwrap();
        let resume_token = "12".repeat(32);
        let payload: Vec<u8> = (0..512).map(|index| (index % 193) as u8).collect();
        let sha256 = hex::encode(Sha256::digest(&payload));
        let partial = native_partial_path(&target, &transfer_id).unwrap();
        let sidecar = native_sidecar_path(&partial);

        let (mut first_in, mut first_out, first_helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut first_in,
            &protocol::Control::BeginPush {
                transfer_id: transfer_id.clone(),
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256: sha256.clone(),
                resume_token: resume_token.clone(),
                resume: true,
            },
        )
        .await
        .unwrap();
        let _ready = protocol::read_frame(&mut first_out).await.unwrap().unwrap();
        for offset in (0..payload.len()).step_by(256) {
            protocol::write_data(
                &mut first_in,
                &protocol::DataFrame::new(
                    transfer_id_bytes,
                    offset as u64,
                    payload[offset..offset + 256].to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let _ack = protocol::read_frame(&mut first_out).await.unwrap().unwrap();
        }
        drop(first_out);
        protocol::write_control(&mut first_in, &protocol::Control::Commit)
            .await
            .unwrap();
        drop(first_in);
        assert!(first_helper.await.unwrap().is_err());
        assert_eq!(std::fs::read(&target).unwrap(), payload);
        assert!(!partial.exists());
        assert!(sidecar.exists());

        let (mut second_in, mut second_out, second_helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut second_in,
            &protocol::Control::BeginPush {
                transfer_id,
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256: sha256.clone(),
                resume_token,
                resume: true,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Ready { durable_offset, .. })) =
            protocol::read_frame(&mut second_out).await.unwrap()
        else {
            panic!("helper did not recover the committed receipt")
        };
        assert_eq!(durable_offset, payload.len() as u64);
        protocol::write_control(&mut second_in, &protocol::Control::Commit)
            .await
            .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Completed {
            size,
            sha256: completed_sha256,
        })) = protocol::read_frame(&mut second_out).await.unwrap()
        else {
            panic!("helper did not replay the committed terminal result")
        };
        assert_eq!(size, payload.len() as u64);
        assert_eq!(completed_sha256, sha256);
        assert!(second_helper.await.unwrap().is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), payload);
        assert!(sidecar.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn post_link_unknown_preserves_durable_evidence_until_receipt_recovery() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-post-link-unknown-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("post-link-unknown-target.bin");
        let transfer_id = "28".repeat(16);
        let transfer_id_bytes = protocol::parse_transfer_id(&transfer_id).unwrap();
        let resume_token = "29".repeat(32);
        let payload: Vec<u8> = (0..512).map(|index| (index % 181) as u8).collect();
        let sha256 = hex::encode(Sha256::digest(&payload));
        let partial = native_partial_path(&target, &transfer_id).unwrap();
        let sidecar = native_sidecar_path(&partial);

        let (mut first_in, mut first_out, first_helper) = helper_session(256, 256).await;
        protocol::write_control(
            &mut first_in,
            &protocol::Control::BeginPush {
                transfer_id: transfer_id.clone(),
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256: sha256.clone(),
                resume_token: resume_token.clone(),
                resume: true,
            },
        )
        .await
        .unwrap();
        let _ready = protocol::read_frame(&mut first_out).await.unwrap().unwrap();
        for offset in (0..payload.len()).step_by(256) {
            protocol::write_data(
                &mut first_in,
                &protocol::DataFrame::new(
                    transfer_id_bytes,
                    offset as u64,
                    payload[offset..offset + 256].to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let _ack = protocol::read_frame(&mut first_out).await.unwrap().unwrap();
        }
        inject_post_link_verification_failure(&target);
        protocol::write_control(&mut first_in, &protocol::Control::Commit)
            .await
            .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            code,
            outcome_unknown,
            ..
        })) = protocol::read_frame(&mut first_out).await.unwrap()
        else {
            panic!("helper did not classify the injected post-link failure")
        };
        assert_eq!(code, "outcome_unknown");
        assert!(outcome_unknown);
        assert!(first_helper.await.unwrap().is_err());
        assert_eq!(std::fs::read(&target).unwrap(), payload);
        assert_eq!(std::fs::read(&partial).unwrap(), payload);
        let receiving = read_resume_sidecar(&sidecar).unwrap();
        assert_eq!(receiving.state, ResumeSidecarState::Receiving);
        assert_eq!(receiving.durable_offset, payload.len() as u64);

        let (mut second_in, mut second_out, second_helper) = helper_session(256, 256).await;
        protocol::write_control(
            &mut second_in,
            &protocol::Control::BeginPush {
                transfer_id,
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256: sha256.clone(),
                resume_token,
                resume: true,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Ready { durable_offset, .. })) =
            protocol::read_frame(&mut second_out).await.unwrap()
        else {
            panic!("helper did not reconcile the preserved commit evidence")
        };
        assert_eq!(durable_offset, payload.len() as u64);
        assert!(!partial.exists());
        let committed = read_resume_sidecar(&sidecar).unwrap();
        assert_eq!(committed.state, ResumeSidecarState::Committed);
        protocol::write_control(&mut second_in, &protocol::Control::Commit)
            .await
            .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Completed {
            size,
            sha256: completed_sha256,
        })) = protocol::read_frame(&mut second_out).await.unwrap()
        else {
            panic!("helper did not complete the reconciled transfer")
        };
        assert_eq!(size, payload.len() as u64);
        assert_eq!(completed_sha256, sha256);
        assert!(second_helper.await.unwrap().is_ok());
        assert_eq!(transfer_artifacts(&root).len(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    async fn assert_helper_resume_at(durable_prefix: usize) {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-resume-test-{}-{durable_prefix}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target.bin");
        let transfer_id = "01".repeat(16);
        let resume_token = "02".repeat(32);
        let partial = native_partial_path(&target, &transfer_id).unwrap();
        let sidecar = native_sidecar_path(&partial);
        let payload: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let sha256 = hex::encode(Sha256::digest(&payload));

        let (mut first_in, mut first_out, first_helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut first_in,
            &protocol::Control::BeginPush {
                transfer_id: transfer_id.clone(),
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256: sha256.clone(),
                resume_token: resume_token.clone(),
                resume: true,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Ready {
            durable_offset: 0, ..
        })) = protocol::read_frame(&mut first_out).await.unwrap()
        else {
            panic!("fresh resumable transfer was not accepted")
        };
        for offset in (0..durable_prefix).step_by(256) {
            protocol::write_data(
                &mut first_in,
                &protocol::DataFrame::new(
                    [1; 16],
                    offset as u64,
                    payload[offset..offset + 256].to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let Some(protocol::Frame::Control(protocol::Control::Ack {
                confirmed_offset,
                durable_offset,
                ..
            })) = protocol::read_frame(&mut first_out).await.unwrap()
            else {
                panic!("native helper did not acknowledge the prefix")
            };
            assert_eq!(confirmed_offset, (offset + 256) as u64);
            assert!(durable_offset <= confirmed_offset);
        }
        drop(first_in);
        assert!(first_helper.await.unwrap().is_err());
        assert!(!target.exists());

        let (mut second_in, mut second_out, second_helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut second_in,
            &protocol::Control::BeginPush {
                transfer_id: transfer_id.clone(),
                target: target.display().to_string(),
                size: payload.len() as u64,
                sha256: sha256.clone(),
                resume_token,
                resume: true,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Ready { durable_offset, .. })) =
            protocol::read_frame(&mut second_out).await.unwrap()
        else {
            panic!("owned durable prefix was not resumed")
        };
        assert_eq!(durable_offset, durable_prefix as u64);
        for offset in (durable_offset as usize..payload.len()).step_by(256) {
            protocol::write_data(
                &mut second_in,
                &protocol::DataFrame::new(
                    [1; 16],
                    offset as u64,
                    payload[offset..offset + 256].to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let Some(protocol::Frame::Control(protocol::Control::Ack {
                confirmed_offset, ..
            })) = protocol::read_frame(&mut second_out).await.unwrap()
            else {
                panic!("native helper did not acknowledge resumed data")
            };
            assert_eq!(confirmed_offset, (offset + 256) as u64);
        }
        protocol::write_control(&mut second_in, &protocol::Control::Commit)
            .await
            .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Completed {
            size,
            sha256: completed_sha256,
        })) = protocol::read_frame(&mut second_out).await.unwrap()
        else {
            panic!("native helper did not confirm the commit")
        };
        assert_eq!(size, payload.len() as u64);
        assert_eq!(completed_sha256, sha256);
        assert!(second_helper.await.unwrap().is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), payload);
        assert!(!partial.exists());
        assert!(sidecar.exists());
        assert_eq!(transfer_artifacts(&root).len(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn helper_resumes_at_25_and_75_percent_only_from_owned_durable_prefixes() {
        assert_helper_resume_at(1024).await;
        assert_helper_resume_at(3072).await;
    }

    #[tokio::test]
    async fn helper_pull_resumes_from_an_exact_prefix_and_reports_full_identity() {
        let root =
            std::env::temp_dir().join(format!("serctl-xfer-pull-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let source = root.join("source.bin");
        let payload: Vec<u8> = (0..4096).map(|index| (index % 239) as u8).collect();
        std::fs::write(&source, &payload).unwrap();
        let expected_sha256 = hex::encode(Sha256::digest(&payload));
        let transfer_id = "05".repeat(16);
        let transfer_id_bytes = protocol::parse_transfer_id(&transfer_id).unwrap();
        let start_offset = 1024_u64;

        let (mut client_in, mut client_out, helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPull {
                transfer_id,
                source: source.display().to_string(),
                offset: start_offset,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::PullReady {
            size,
            sha256,
            start_offset: accepted_offset,
            ..
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("native helper did not accept the pull")
        };
        assert_eq!(size, payload.len() as u64);
        assert_eq!(sha256, expected_sha256);
        assert_eq!(accepted_offset, start_offset);

        let mut received = payload[..start_offset as usize].to_vec();
        loop {
            match protocol::read_frame(&mut client_out)
                .await
                .unwrap()
                .unwrap()
            {
                protocol::Frame::Data(data) => {
                    assert_eq!(data.transfer_id, transfer_id_bytes);
                    assert_eq!(data.offset, received.len() as u64);
                    received.extend_from_slice(&data.payload);
                    protocol::write_control(
                        &mut client_in,
                        &protocol::Control::Ack {
                            confirmed_offset: received.len() as u64,
                            durable_offset: start_offset,
                            receiver_window: 1024,
                        },
                    )
                    .await
                    .unwrap();
                }
                protocol::Frame::Control(protocol::Control::Completed { size, sha256 }) => {
                    assert_eq!(size, payload.len() as u64);
                    assert_eq!(sha256, expected_sha256);
                    break;
                }
                _ => panic!("native helper returned an unexpected pull frame"),
            }
        }
        assert_eq!(received, payload);
        assert!(helper.await.unwrap().is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn helper_pull_rejects_non_monotonic_durable_ack() {
        let root =
            std::env::temp_dir().join(format!("serctl-xfer-pull-ack-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let source = root.join("source.bin");
        std::fs::write(&source, vec![3_u8; 512]).unwrap();
        let (mut client_in, mut client_out, helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPull {
                transfer_id: "09".repeat(16),
                source: source.display().to_string(),
                offset: 0,
            },
        )
        .await
        .unwrap();
        let _ready = protocol::read_frame(&mut client_out)
            .await
            .unwrap()
            .unwrap();
        let Some(protocol::Frame::Data(data)) =
            protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper did not send pull data")
        };
        // Bypass the validating writer to exercise the helper's inbound wire
        // boundary against a malicious or incompatible peer.
        let invalid_ack = serde_json::to_vec(&protocol::Control::Ack {
            confirmed_offset: data.payload.len() as u64,
            durable_offset: data.payload.len() as u64 + 1,
            receiver_window: 1024,
        })
        .unwrap();
        client_in.write_all(&protocol::MAGIC).await.unwrap();
        client_in
            .write_all(&protocol::VERSION.to_be_bytes())
            .await
            .unwrap();
        client_in
            .write_all(&[protocol::FrameKind::Control as u8, 0])
            .await
            .unwrap();
        client_in
            .write_all(&(invalid_ack.len() as u32).to_be_bytes())
            .await
            .unwrap();
        client_in.write_all(&invalid_ack).await.unwrap();
        client_in.flush().await.unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            outcome_unknown, ..
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper did not return a structured acknowledgement error")
        };
        assert!(!outcome_unknown);
        assert!(helper.await.unwrap().is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn helper_pull_fails_if_bytes_change_after_identity_announcement() {
        let root = std::env::temp_dir().join(format!(
            "serctl-xfer-pull-mutation-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let source = root.join("source.bin");
        let original = vec![3_u8; 512];
        std::fs::write(&source, &original).unwrap();
        let (mut client_in, mut client_out, helper) = helper_session(256, 1024).await;
        protocol::write_control(
            &mut client_in,
            &protocol::Control::BeginPull {
                transfer_id: "13".repeat(16),
                source: source.display().to_string(),
                offset: 0,
            },
        )
        .await
        .unwrap();
        let _ready = protocol::read_frame(&mut client_out)
            .await
            .unwrap()
            .unwrap();

        let mut mutator = std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .unwrap();
        mutator.seek(std::io::SeekFrom::Start(256)).unwrap();
        mutator.write_all(&vec![9_u8; 256]).unwrap();
        mutator.sync_all().unwrap();
        drop(mutator);

        let Some(protocol::Frame::Data(first)) =
            protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper did not send the first pull chunk")
        };
        assert_eq!(first.offset, 0);
        protocol::write_control(
            &mut client_in,
            &protocol::Control::Ack {
                confirmed_offset: 256,
                durable_offset: 256,
                receiver_window: 1024,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Data(second)) =
            protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper did not send the second pull chunk")
        };
        assert_eq!(second.offset, 256);
        assert_eq!(second.payload, vec![9_u8; 256]);
        protocol::write_control(
            &mut client_in,
            &protocol::Control::Ack {
                confirmed_offset: 512,
                durable_offset: 512,
                receiver_window: 1024,
            },
        )
        .await
        .unwrap();
        let Some(protocol::Frame::Control(protocol::Control::Error {
            outcome_unknown, ..
        })) = protocol::read_frame(&mut client_out).await.unwrap()
        else {
            panic!("helper reported success for bytes that changed after PullReady")
        };
        assert!(!outcome_unknown);
        assert!(helper.await.unwrap().is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
