//! Fixed-command Linux remote execution helper.

#[cfg(any(target_os = "linux", test))]
use anyhow::ensure;
#[cfg(target_os = "linux")]
use anyhow::Context as _;
use anyhow::{bail, Result};
#[cfg(target_os = "linux")]
use serctl_jobs::JobStore;
#[cfg(any(target_os = "linux", test))]
use serctl_jobs::{
    AuthenticatedReceipt, JobDeadlines, JobIdentity, JobRecord, ReceiptBody, ReceiptOutcome,
};
#[cfg(target_os = "linux")]
use serctl_policy::{
    compile_policy_json, Capability, EnvVar, IntentBudget, IntentPath, PathFlavor, RunAs,
    TypedIntent, INTENT_SCHEMA_VERSION,
};
use serctl_remote_protocol as protocol;
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};
use std::ffi::OsStr;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(any(target_os = "linux", test))]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::sync::mpsc;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(target_os = "linux")]
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(250);
#[cfg(target_os = "linux")]
const CANCEL_WAIT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const OUTPUT_READ_BYTES: usize = protocol::MAX_OUTPUT_CHUNK;

fn main() {
    if let Err(error) = run() {
        eprintln!("serctl-remote: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.as_slice() == [OsStr::new("--version")] {
        println!("{}", version_line());
        return Ok(());
    }
    if args.as_slice() == [OsStr::new("serve"), OsStr::new("--stdio")] {
        return serve_stdio();
    }
    if args.as_slice() == [OsStr::new("receipt"), OsStr::new("--stdio")] {
        return receipt_stdio();
    }
    bail!("usage: serctl-remote <serve|receipt> --stdio")
}

fn version_line() -> String {
    format!(
        "serctl-remote {} (git {}; remote protocol v{})",
        env!("CARGO_PKG_VERSION"),
        env!("SERCTL_BUILD_COMMIT"),
        protocol::PROTOCOL_VERSION
    )
}

#[cfg(not(target_os = "linux"))]
fn serve_stdio() -> Result<()> {
    bail!("serctl-remote execution is supported only on Linux; refusing to run")
}

#[cfg(not(target_os = "linux"))]
fn receipt_stdio() -> Result<()> {
    bail!("serctl-remote receipt recovery is supported only on Linux; refusing to run")
}

#[cfg(target_os = "linux")]
fn serve_stdio() -> Result<()> {
    let (input_tx, input_rx) = mpsc::sync_channel(8);
    std::thread::Builder::new()
        .name("serctl-remote-input".to_owned())
        .spawn(move || read_input(input_tx))
        .context("spawn bounded protocol reader")?;

    let output = OutputSink::stdio()?;
    let hello = receive_input(&input_rx)?;
    let protocol::Frame::Hello(hello) = hello.frame else {
        bail!("first frame is not Hello");
    };
    ensure!(
        hello.effective_uid == 0,
        "controller Hello must not claim an EUID"
    );
    let helper_uid = effective_uid()?;
    ensure!(helper_uid != 0, "remote helper refuses UID 0");
    ensure!(
        output.try_frame(protocol::Frame::Hello(protocol::HelloFrame {
            max_frame_payload: protocol::MAX_FRAME_PAYLOAD as u32,
            feature_bits: protocol::SUPPORTED_FEATURE_BITS,
            effective_uid: helper_uid,
        })),
        "remote output relay is unavailable"
    );

    let envelope = receive_input(&input_rx)?;
    let protocol::Frame::Start(start) = envelope.frame else {
        bail!("second frame is not Start");
    };
    let start = *start;
    match prepare(&start) {
        Ok(prepared) => run_job(&output, &input_rx, start, prepared),
        Err(error) => {
            let _ = output.try_frame(protocol::Frame::Error(protocol::ErrorFrame {
                job_id: Some(start.job_id),
                code: "start_denied".to_owned(),
                message: bounded_message(&error),
                retryable: false,
            }));
            Err(error)
        }
    }
}

#[cfg(target_os = "linux")]
struct OutputSink {
    sender: mpsc::SyncSender<OutputCommand>,
}

#[cfg(target_os = "linux")]
struct OutputCommand {
    frame: protocol::Frame,
    acknowledged: Option<mpsc::SyncSender<bool>>,
}

#[cfg(target_os = "linux")]
impl OutputSink {
    fn stdio() -> Result<Self> {
        Self::with_writer(std::io::stdout())
    }

    fn with_writer<W: std::io::Write + Send + 'static>(mut writer: W) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<OutputCommand>(8);
        std::thread::Builder::new()
            .name("serctl-remote-output".to_owned())
            .spawn(move || {
                let mut sequence = 0_u64;
                while let Ok(command) = receiver.recv() {
                    let succeeded = protocol::write_frame_to(
                        &mut writer,
                        &protocol::Envelope {
                            sequence,
                            frame: command.frame,
                        },
                    )
                    .and_then(|()| writer.flush().map_err(protocol::ProtocolError::Io))
                    .is_ok();
                    if succeeded {
                        sequence = match sequence.checked_add(1) {
                            Some(next) => next,
                            None => break,
                        };
                    }
                    if let Some(acknowledged) = command.acknowledged {
                        let _ = acknowledged.send(succeeded);
                    }
                    if !succeeded {
                        break;
                    }
                }
            })
            .context("spawn bounded output relay")?;
        Ok(Self { sender })
    }

    /// Never waits for the relay. A full queue immediately marks delivery
    /// unavailable so the job owner can continue to its deadline and receipt.
    fn try_frame(&self, frame: protocol::Frame) -> bool {
        self.sender
            .try_send(OutputCommand {
                frame,
                acknowledged: None,
            })
            .is_ok()
    }

    fn try_final(&self, receipt: protocol::Frame, exit: protocol::Frame) -> bool {
        if !self.try_frame(receipt) {
            return false;
        }
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        if self
            .sender
            .try_send(OutputCommand {
                frame: exit,
                acknowledged: Some(ack_tx),
            })
            .is_err()
        {
            return false;
        }
        ack_rx
            .recv_timeout(Duration::from_millis(500))
            .unwrap_or(false)
    }
}

#[cfg(target_os = "linux")]
fn receipt_stdio() -> Result<()> {
    let (input_tx, input_rx) = mpsc::sync_channel(4);
    std::thread::Builder::new()
        .name("serctl-remote-receipt-input".to_owned())
        .spawn(move || read_input(input_tx))
        .context("spawn receipt protocol reader")?;
    let output = OutputSink::stdio()?;
    let hello = receive_input(&input_rx)?;
    let protocol::Frame::Hello(hello) = hello.frame else {
        bail!("first frame is not Hello");
    };
    ensure!(
        hello.effective_uid == 0,
        "controller Hello must not claim an EUID"
    );
    let helper_uid = effective_uid()?;
    ensure!(helper_uid != 0, "remote helper refuses UID 0");
    ensure!(
        output.try_frame(protocol::Frame::Hello(protocol::HelloFrame {
            max_frame_payload: protocol::MAX_FRAME_PAYLOAD as u32,
            feature_bits: protocol::FEATURE_RECEIPT_QUERY,
            effective_uid: helper_uid,
        })),
        "remote output relay is unavailable"
    );
    let envelope = receive_input(&input_rx)?;
    let protocol::Frame::QueryReceipt(query) = envelope.frame else {
        bail!("second frame is not QueryReceipt");
    };
    let store = fixed_job_store(helper_uid)?;
    let record = match store.load_journal(query.job_id) {
        Ok(record) => record,
        Err(error) if error_is_not_found(&error) => {
            let _ = output.try_frame(receipt_error(query.job_id, "job_unknown", false));
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let now = unix_ms()?;
    if now > record.deadlines.result_retention_unix_ms {
        let _ = output.try_frame(receipt_error(query.job_id, "receipt_expired", false));
        return Ok(());
    }
    let receipt_bytes = match store.load_receipt(query.job_id) {
        Ok(bytes) => bytes,
        Err(error) if error_is_not_found(&error) => {
            // A standalone helper has no live process handle. Remote journal
            // stages are hints only and cannot prove liveness after a crash.
            let _ = output.try_frame(receipt_error(
                query.job_id,
                missing_receipt_code(record.stage),
                true,
            ));
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let body = match verify_query_receipt(&record, &receipt_bytes, &query, now) {
        Ok(body) => body,
        Err(_) => {
            let _ = output.try_frame(receipt_error(query.job_id, "receipt_denied", false));
            return Ok(());
        }
    };
    let outcome = match body.outcome {
        ReceiptOutcome::Exited(code) => protocol::ExitOutcome::Exited(code),
        ReceiptOutcome::Cancelled => protocol::ExitOutcome::Cancelled,
        ReceiptOutcome::DeadlineExceeded => protocol::ExitOutcome::DeadlineExceeded,
    };
    ensure!(
        output.try_final(
            protocol::Frame::Receipt(protocol::ReceiptFrame {
                job_id: query.job_id,
                bytes: receipt_bytes,
            }),
            protocol::Frame::Exit(protocol::ExitFrame {
                job_id: query.job_id,
                outcome,
                completed_unix_ms: body.completed_unix_ms,
            }),
        ),
        "receipt relay is unavailable; authenticated receipt remains persisted"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn receipt_error(job_id: protocol::JobId, code: &str, retryable: bool) -> protocol::Frame {
    protocol::Frame::Error(protocol::ErrorFrame {
        job_id: Some(job_id),
        code: code.to_owned(),
        message: code.to_owned(),
        retryable,
    })
}

#[cfg(target_os = "linux")]
fn error_is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

#[cfg(any(target_os = "linux", test))]
fn verify_query_receipt(
    record: &JobRecord,
    receipt_bytes: &[u8],
    query: &protocol::QueryReceiptFrame,
    now_unix_ms: u64,
) -> Result<ReceiptBody> {
    let expected = JobIdentity {
        job_id: query.job_id,
        profile_id: query.profile_id,
        profile_generation: query.profile_generation,
        policy_digest: query.policy_digest,
        input_digest: query.input_digest,
    };
    ensure!(
        record.identity == expected,
        "receipt query identity mismatch"
    );
    let receipt = AuthenticatedReceipt::decode(receipt_bytes)?;
    receipt.verify(
        &expected,
        record.deadlines,
        record.run_as_uid,
        record.max_output_bytes,
        &query.receipt_token,
        now_unix_ms,
    )
}

#[cfg(any(target_os = "linux", test))]
const fn missing_receipt_code(_journal_stage: serctl_jobs::JobStage) -> &'static str {
    "job_unknown"
}

#[cfg(target_os = "linux")]
enum InputEvent {
    Frame(protocol::Envelope),
    Error(protocol::ProtocolError),
    Closed,
}

#[cfg(target_os = "linux")]
fn read_input(sender: mpsc::SyncSender<InputEvent>) {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut validator = protocol::ControllerSessionValidator::default();
    loop {
        let event = match protocol::read_frame_from(&mut reader) {
            Ok(Some(envelope)) => match validator.validate(&envelope) {
                Ok(()) => InputEvent::Frame(envelope),
                Err(error) => InputEvent::Error(error),
            },
            Ok(None) => InputEvent::Closed,
            Err(error) => InputEvent::Error(error),
        };
        let terminal = matches!(event, InputEvent::Error(_) | InputEvent::Closed);
        if sender.send(event).is_err() || terminal {
            break;
        }
    }
}

#[cfg(target_os = "linux")]
fn receive_input(receiver: &mpsc::Receiver<InputEvent>) -> Result<protocol::Envelope> {
    match receiver.recv().context("remote protocol input closed")? {
        InputEvent::Frame(envelope) => Ok(envelope),
        InputEvent::Error(error) => Err(error.into()),
        InputEvent::Closed => bail!("remote protocol input closed"),
    }
}

#[cfg(target_os = "linux")]
struct PreparedJob {
    executable: PathBuf,
    cwd: Option<PathBuf>,
    store: JobStore,
    identity: JobIdentity,
    deadlines: JobDeadlines,
}

#[cfg(target_os = "linux")]
fn prepare(start: &protocol::StartFrame) -> Result<PreparedJob> {
    ensure!(
        protocol::compute_start_input_digest(start) == start.input_digest,
        "input digest mismatch"
    );
    let policy = compile_policy_json(&start.policy_json).context("compile policy")?;
    let policy_digest = hex::decode(policy.digest().as_str()).context("decode policy digest")?;
    ensure!(
        policy_digest.as_slice() == start.policy_digest.as_bytes(),
        "policy digest mismatch"
    );

    let now = unix_ms()?;
    let deadlines = JobDeadlines {
        remote_unix_ms: start.remote_deadline_unix_ms,
        relay_unix_ms: start.relay_deadline_unix_ms,
        result_retention_unix_ms: start.result_retention_unix_ms,
    };
    deadlines.validate_at(now)?;
    let uid = effective_uid()?;
    ensure!(uid != 0, "remote helper refuses UID 0");
    ensure!(
        start.run_as_uid == uid,
        "requested run_as does not match helper identity"
    );

    let mut intent = TypedIntent {
        schema_version: INTENT_SCHEMA_VERSION,
        capability: Capability::ProcessRun,
        run_as: RunAs::Uid { value: uid },
        program: Some(start.program.clone()),
        argv: start.argv.clone(),
        env: start
            .env
            .iter()
            .map(|entry| EnvVar {
                name: entry.name.clone(),
                value: entry.value.clone(),
            })
            .collect(),
        paths: start
            .cwd
            .iter()
            .map(|cwd| IntentPath {
                flavor: PathFlavor::Posix,
                value: cwd.clone(),
            })
            .collect(),
        budget: IntentBudget {
            bytes: 0,
            output_bytes: start.max_output_bytes,
            parallel: 1,
            operations: 1,
        },
        deadline_ms: start.remote_deadline_unix_ms.saturating_sub(now),
    };
    let explanation = policy.dry_run(&intent);
    zeroize_intent(&mut intent);
    ensure!(
        explanation.allowed,
        "policy denied typed intent: {}",
        explanation.reason_code
    );

    let executable = resolve_executable(&start.program)?;
    validate_executable(&executable)?;
    let cwd = start.cwd.as_deref().map(validate_cwd).transpose()?;
    let store = fixed_job_store(uid)?;
    Ok(PreparedJob {
        executable,
        cwd,
        store,
        identity: JobIdentity {
            job_id: start.job_id,
            profile_id: start.profile_id,
            profile_generation: start.profile_generation,
            policy_digest: start.policy_digest,
            input_digest: start.input_digest,
        },
        deadlines,
    })
}

#[cfg(target_os = "linux")]
fn zeroize_intent(intent: &mut TypedIntent) {
    intent.program.zeroize();
    intent.argv.zeroize();
    for variable in &mut intent.env {
        variable.name.zeroize();
        variable.value.zeroize();
    }
    for path in &mut intent.paths {
        path.value.zeroize();
    }
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status").context("read process identity")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .context("process UID is unavailable")?;
    let mut values = line[4..].split_ascii_whitespace();
    let _real = values.next().context("real UID is unavailable")?;
    values
        .next()
        .context("effective UID is unavailable")?
        .parse()
        .context("parse effective UID")
}

#[cfg(target_os = "linux")]
fn resolve_executable(program: &str) -> Result<PathBuf> {
    let path = match program {
        "id" => "/usr/bin/id",
        "true" => "/usr/bin/true",
        "uname" => "/usr/bin/uname",
        "uptime" => "/usr/bin/uptime",
        "whoami" => "/usr/bin/whoami",
        _ => bail!("program has no fixed Linux executable mapping"),
    };
    Ok(PathBuf::from(path))
}

#[cfg(target_os = "linux")]
fn validate_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect fixed executable {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "fixed executable is not a regular file"
    );
    ensure!(
        !metadata.file_type().is_symlink(),
        "fixed executable is a symlink"
    );
    ensure!(metadata.uid() == 0, "fixed executable is not owned by root");
    let mode = metadata.permissions().mode();
    ensure!(
        mode & 0o022 == 0,
        "fixed executable is group/other writable"
    );
    ensure!(mode & 0o6000 == 0, "fixed executable carries set-id bits");
    ensure!(mode & 0o111 != 0, "fixed executable is not executable");
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_cwd(value: &str) -> Result<PathBuf> {
    let requested = PathBuf::from(value);
    ensure!(requested.is_absolute(), "working directory is not absolute");
    let canonical = requested
        .canonicalize()
        .context("canonicalize working directory")?;
    ensure!(
        canonical == requested,
        "working directory contains aliases or symlinks"
    );
    ensure!(
        canonical.metadata()?.is_dir(),
        "working directory is not a directory"
    );
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn fixed_job_store(uid: u32) -> Result<JobStore> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
    let passwd = std::fs::read_to_string("/etc/passwd").context("read local account database")?;
    ensure!(
        passwd.len() <= 1024 * 1024,
        "local account database is too large"
    );
    let home = passwd
        .lines()
        .filter_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            (fields.len() == 7 && fields[2].parse::<u32>().ok() == Some(uid))
                .then(|| PathBuf::from(fields[5]))
        })
        .next()
        .context("effective UID has no local home mapping")?;
    ensure!(home.is_absolute(), "account home is not absolute");
    let home_metadata = std::fs::symlink_metadata(&home).context("inspect account home")?;
    ensure!(
        home_metadata.file_type().is_dir() && !home_metadata.file_type().is_symlink(),
        "account home is not a stable directory"
    );
    ensure!(home_metadata.uid() == uid, "account home owner mismatch");
    ensure!(
        home_metadata.permissions().mode() & 0o022 == 0,
        "account home is group/other writable"
    );

    let serctl = home.join(".serctl");
    let jobs = serctl.join("jobs");
    for path in [&serctl, &jobs] {
        if !path.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder
                .mode(0o700)
                .create(path)
                .with_context(|| format!("create fixed job directory {}", path.display()))?;
        }
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("inspect fixed job directory {}", path.display()))?;
        ensure!(
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
            "fixed job path is not a stable directory"
        );
        ensure!(metadata.uid() == uid, "fixed job directory owner mismatch");
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "fixed job directory is not private"
        );
    }
    JobStore::new(jobs)
}

#[cfg(any(target_os = "linux", test))]
fn make_command(executable: &Path, start: &protocol::StartFrame, cwd: Option<&Path>) -> Command {
    let mut command = Command::new(executable);
    command.env_clear();
    command.args(&start.argv);
    for variable in &start.env {
        command.env(&variable.name, &variable.value);
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamKind {
    Stdout,
    Stderr,
}

#[cfg(target_os = "linux")]
enum ChildEvent {
    Chunk(StreamKind, Vec<u8>),
    Closed(StreamKind),
    ReadFailed(StreamKind),
}

#[cfg(target_os = "linux")]
fn read_child_stream<R: std::io::Read>(
    mut reader: R,
    kind: StreamKind,
    sender: mpsc::SyncSender<ChildEvent>,
) {
    let mut buffer = vec![0_u8; OUTPUT_READ_BYTES];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = sender.send(ChildEvent::Closed(kind));
                break;
            }
            Ok(length) => {
                if sender
                    .send(ChildEvent::Chunk(kind, buffer[..length].to_vec()))
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => {
                let _ = sender.send(ChildEvent::ReadFailed(kind));
                break;
            }
        }
    }
    buffer.zeroize();
}

#[cfg(target_os = "linux")]
fn run_job(
    output: &OutputSink,
    input: &mpsc::Receiver<InputEvent>,
    start: protocol::StartFrame,
    prepared: PreparedJob,
) -> Result<()> {
    let now = unix_ms()?;
    let mut journal = JobRecord::submitted(
        prepared.identity,
        prepared.deadlines,
        start.run_as_uid,
        start.max_output_bytes,
        now,
    )?;
    prepared.store.create_journal(&journal)?;
    journal.mark_running(unix_ms()?)?;
    prepared.store.update_journal(&journal)?;

    let mut command = make_command(&prepared.executable, &start, prepared.cwd.as_deref());
    let mut child = command.spawn().context("spawn fixed executable")?;
    let child_stdout = child.stdout.take().context("capture child stdout")?;
    let child_stderr = child.stderr.take().context("capture child stderr")?;
    let (child_tx, child_rx) = mpsc::sync_channel(16);
    let stdout_tx = child_tx.clone();
    std::thread::Builder::new()
        .name("serctl-remote-stdout".to_owned())
        .spawn(move || read_child_stream(child_stdout, StreamKind::Stdout, stdout_tx))?;
    std::thread::Builder::new()
        .name("serctl-remote-stderr".to_owned())
        .spawn(move || read_child_stream(child_stderr, StreamKind::Stderr, child_tx))?;

    let started = Instant::now();
    let mut next_heartbeat = started;
    let mut heartbeat_ordinal = 0_u64;
    let mut stdout_offset = 0_u64;
    let mut stderr_offset = 0_u64;
    let mut stdout_hash = Sha256::new();
    let mut stderr_hash = Sha256::new();
    let mut stdout_closed = false;
    let mut stderr_closed = false;
    let mut status = None;
    let mut termination = None;
    let mut kill_started = None;
    let mut relay_available = true;

    loop {
        let now_ms = unix_ms()?;
        if now_ms > start.relay_deadline_unix_ms {
            // Relay expiry stops new delivery attempts, but never kills a
            // committed remote job. Its independent remote deadline remains
            // authoritative and a receipt can be recovered later.
            relay_available = false;
        }
        if termination.is_none() && now_ms >= start.remote_deadline_unix_ms {
            termination = Some(Termination::Deadline);
        }
        loop {
            match input.try_recv() {
                Ok(InputEvent::Frame(envelope)) => match envelope.frame {
                    protocol::Frame::Cancel(cancel) if cancel.job_id == start.job_id => {
                        termination.get_or_insert(Termination::Cancelled);
                    }
                    _ => {
                        termination.get_or_insert(Termination::ProtocolViolation);
                    }
                },
                Ok(InputEvent::Error(_)) => {
                    // A malformed or closed relay is inconclusive. Continue
                    // the already committed remote job and persist its receipt.
                    relay_available = false;
                }
                Ok(InputEvent::Closed) | Err(mpsc::TryRecvError::Disconnected) => {
                    relay_available = false;
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
            }
        }

        if termination.is_some() && kill_started.is_none() && status.is_none() {
            match child.kill() {
                Ok(()) => kill_started = Some(Instant::now()),
                Err(_) => {
                    status = child
                        .try_wait()
                        .context("inspect child after kill failure")?
                }
            }
        }
        if let Some(killed_at) = kill_started {
            if killed_at.elapsed() > CANCEL_WAIT && status.is_none() {
                journal.mark_unknown(unix_ms()?)?;
                prepared.store.update_journal(&journal)?;
                bail!("child termination could not be confirmed within the bounded wait");
            }
        }

        while let Ok(event) = child_rx.try_recv() {
            match event {
                ChildEvent::Chunk(kind, data) => {
                    let projected = stdout_offset
                        .saturating_add(stderr_offset)
                        .saturating_add(data.len() as u64);
                    if projected > start.max_output_bytes {
                        termination.get_or_insert(Termination::OutputLimit);
                        continue;
                    }
                    match kind {
                        StreamKind::Stdout => {
                            stdout_hash.update(&data);
                            let length = data.len() as u64;
                            if relay_available
                                && !output.try_frame(protocol::Frame::Stdout(
                                    protocol::OutputFrame {
                                        job_id: start.job_id,
                                        offset: stdout_offset,
                                        data,
                                    },
                                ))
                            {
                                relay_available = false;
                            }
                            stdout_offset = stdout_offset.saturating_add(length);
                        }
                        StreamKind::Stderr => {
                            stderr_hash.update(&data);
                            let length = data.len() as u64;
                            if relay_available
                                && !output.try_frame(protocol::Frame::Stderr(
                                    protocol::OutputFrame {
                                        job_id: start.job_id,
                                        offset: stderr_offset,
                                        data,
                                    },
                                ))
                            {
                                relay_available = false;
                            }
                            stderr_offset = stderr_offset.saturating_add(length);
                        }
                    }
                }
                ChildEvent::Closed(StreamKind::Stdout) => stdout_closed = true,
                ChildEvent::Closed(StreamKind::Stderr) => stderr_closed = true,
                ChildEvent::ReadFailed(kind) => {
                    let _failed_stream = kind;
                    termination.get_or_insert(Termination::OutputRead);
                }
            }
        }

        if status.is_none() {
            status = child.try_wait().context("poll child status")?;
        }
        if Instant::now() >= next_heartbeat {
            heartbeat_ordinal = heartbeat_ordinal.saturating_add(1);
            let heartbeat = protocol::HeartbeatFrame {
                job_id: start.job_id,
                ordinal: heartbeat_ordinal,
                elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                stdout_bytes: stdout_offset,
                stderr_bytes: stderr_offset,
            };
            journal.observe_heartbeat(&heartbeat, unix_ms()?)?;
            prepared.store.update_journal(&journal)?;
            if relay_available && !output.try_frame(protocol::Frame::Heartbeat(heartbeat)) {
                relay_available = false;
            }
            next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
        }
        if status.is_some() && stdout_closed && stderr_closed {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let completed = unix_ms()?;
    let (receipt_outcome, wire_outcome) = match termination {
        Some(Termination::Cancelled) => {
            (ReceiptOutcome::Cancelled, protocol::ExitOutcome::Cancelled)
        }
        Some(Termination::Deadline) => (
            ReceiptOutcome::DeadlineExceeded,
            protocol::ExitOutcome::DeadlineExceeded,
        ),
        Some(
            Termination::OutputLimit | Termination::OutputRead | Termination::ProtocolViolation,
        ) => (
            ReceiptOutcome::Exited(125),
            protocol::ExitOutcome::Exited(125),
        ),
        None => {
            let code = status.and_then(|value| value.code()).unwrap_or(125);
            (
                ReceiptOutcome::Exited(code),
                protocol::ExitOutcome::Exited(code),
            )
        }
    };
    let receipt = AuthenticatedReceipt::issue(
        ReceiptBody {
            identity: prepared.identity,
            run_as_uid: start.run_as_uid,
            deadlines: prepared.deadlines,
            max_output_bytes: start.max_output_bytes,
            stdout_digest: protocol::Digest32::from_bytes(stdout_hash.finalize().into()),
            stderr_digest: protocol::Digest32::from_bytes(stderr_hash.finalize().into()),
            outcome: receipt_outcome,
            completed_unix_ms: completed,
        },
        &start.receipt_token,
    )?;
    prepared.store.persist_receipt(&receipt)?;
    journal.stage = match receipt_outcome {
        ReceiptOutcome::Exited(0) => serctl_jobs::JobStage::Completed,
        ReceiptOutcome::Cancelled => serctl_jobs::JobStage::Cancelled,
        ReceiptOutcome::Exited(_) | ReceiptOutcome::DeadlineExceeded => {
            serctl_jobs::JobStage::Failed
        }
    };
    journal.updated_unix_ms = completed;
    prepared.store.update_journal(&journal)?;

    if relay_available {
        let receipt_bytes = receipt.encode();
        let _ = output.try_final(
            protocol::Frame::Receipt(protocol::ReceiptFrame {
                job_id: start.job_id,
                bytes: receipt_bytes,
            }),
            protocol::Frame::Exit(protocol::ExitFrame {
                job_id: start.job_id,
                outcome: wire_outcome,
                completed_unix_ms: completed,
            }),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Termination {
    Cancelled,
    Deadline,
    OutputLimit,
    OutputRead,
    ProtocolViolation,
}

#[cfg(test)]
fn termination_at(
    now_unix_ms: u64,
    remote_deadline_unix_ms: u64,
    cancelled: bool,
) -> Option<&'static str> {
    if cancelled {
        Some("cancelled")
    } else if now_unix_ms >= remote_deadline_unix_ms {
        Some("deadline")
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn unix_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?;
    Ok(elapsed.as_millis().min(u64::MAX as u128) as u64)
}

#[cfg(target_os = "linux")]
fn bounded_message(error: &anyhow::Error) -> String {
    let mut message = error.to_string();
    if message.len() > protocol::MAX_ERROR_MESSAGE_BYTES {
        message.truncate(protocol::MAX_ERROR_MESSAGE_BYTES);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{Digest32, EnvEntry, JobId, ProfileId, Secret32, StartFrame};

    fn sample_start() -> StartFrame {
        StartFrame {
            job_id: JobId::from_bytes([1; 16]),
            profile_id: ProfileId::from_bytes([2; 16]),
            profile_generation: 1,
            policy_digest: Digest32::from_bytes([3; 32]),
            input_digest: Digest32::from_bytes([0; 32]),
            remote_deadline_unix_ms: 100,
            relay_deadline_unix_ms: 200,
            result_retention_unix_ms: 300,
            run_as_uid: 1000,
            max_output_bytes: 1024,
            program: "printf".to_owned(),
            argv: vec!["%s".to_owned(), "; touch /tmp/not-executed".to_owned()],
            env: vec![EnvEntry {
                name: "LANG".to_owned(),
                value: "C".to_owned(),
            }],
            cwd: Some("/srv/app".to_owned()),
            policy_json: b"{}".to_vec(),
            receipt_token: Secret32::new([4; 32]),
        }
    }

    #[test]
    fn version_reports_product_commit_and_remote_protocol() {
        let version = version_line();
        assert!(version.contains(env!("CARGO_PKG_VERSION")));
        assert!(version.contains(env!("SERCTL_BUILD_COMMIT")));
        assert!(version.contains(&format!("remote protocol v{}", protocol::PROTOCOL_VERSION)));
    }

    #[test]
    fn command_uses_direct_argv_and_clears_inherited_environment() {
        let start = sample_start();
        let command = make_command(
            Path::new("/usr/bin/printf"),
            &start,
            Some(Path::new("/srv/app")),
        );
        assert_eq!(command.get_program(), OsStr::new("/usr/bin/printf"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [OsStr::new("%s"), OsStr::new("; touch /tmp/not-executed")]
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/srv/app")));
        let env = command.get_envs().collect::<Vec<_>>();
        assert_eq!(env, [(OsStr::new("LANG"), Some(OsStr::new("C")))]);
        assert!(!command.get_args().any(|arg| arg == OsStr::new("-c")));
    }

    #[test]
    fn input_digest_changes_for_argument_environment_and_deadline() {
        let mut first = sample_start();
        let first_digest = protocol::compute_start_input_digest(&first);
        first.argv[1].push('!');
        assert_ne!(first_digest, protocol::compute_start_input_digest(&first));
        let mut second = sample_start();
        second.env[0].value.push('x');
        assert_ne!(first_digest, protocol::compute_start_input_digest(&second));
        let mut third = sample_start();
        third.remote_deadline_unix_ms += 1;
        assert_ne!(first_digest, protocol::compute_start_input_digest(&third));
    }

    #[test]
    fn deadline_and_cancel_are_independent_terminal_reasons() {
        assert_eq!(termination_at(99, 100, false), None);
        assert_eq!(termination_at(100, 100, false), Some("deadline"));
        assert_eq!(termination_at(99, 100, true), Some("cancelled"));
    }

    #[test]
    fn disconnected_job_is_recovered_only_by_an_independent_authenticated_query() {
        let identity = JobIdentity {
            job_id: JobId::from_bytes([1; 16]),
            profile_id: ProfileId::from_bytes([2; 16]),
            profile_generation: 3,
            policy_digest: Digest32::from_bytes([4; 32]),
            input_digest: Digest32::from_bytes([5; 32]),
        };
        let deadlines = JobDeadlines {
            remote_unix_ms: 2_000,
            relay_unix_ms: 3_000,
            result_retention_unix_ms: 4_000,
        };
        let mut record = JobRecord::submitted(identity, deadlines, 1000, 1024, 1_000).unwrap();
        record.mark_running(1_001).unwrap();
        record.mark_unknown(1_500).unwrap();
        let token = Secret32::new([6; 32]);
        let receipt = AuthenticatedReceipt::issue(
            ReceiptBody {
                identity,
                run_as_uid: 1000,
                deadlines,
                max_output_bytes: 1024,
                stdout_digest: Digest32::from_bytes([7; 32]),
                stderr_digest: Digest32::from_bytes([8; 32]),
                outcome: ReceiptOutcome::Exited(0),
                completed_unix_ms: 1_900,
            },
            &token,
        )
        .unwrap();
        let query = protocol::QueryReceiptFrame {
            job_id: identity.job_id,
            profile_id: identity.profile_id,
            profile_generation: identity.profile_generation,
            policy_digest: identity.policy_digest,
            input_digest: identity.input_digest,
            receipt_token: token,
        };
        let recovered = verify_query_receipt(&record, &receipt.encode(), &query, 2_000).unwrap();
        assert_eq!(recovered.outcome, ReceiptOutcome::Exited(0));

        let mut altered_journal = record.clone();
        altered_journal.run_as_uid += 1;
        assert!(verify_query_receipt(&altered_journal, &receipt.encode(), &query, 2_000).is_err());
        altered_journal = record.clone();
        altered_journal.deadlines.relay_unix_ms += 1;
        assert!(verify_query_receipt(&altered_journal, &receipt.encode(), &query, 2_000).is_err());
        altered_journal = record.clone();
        altered_journal.max_output_bytes += 1;
        assert!(verify_query_receipt(&altered_journal, &receipt.encode(), &query, 2_000).is_err());

        let wrong_query = protocol::QueryReceiptFrame {
            job_id: identity.job_id,
            profile_id: identity.profile_id,
            profile_generation: identity.profile_generation + 1,
            policy_digest: identity.policy_digest,
            input_digest: identity.input_digest,
            receipt_token: Secret32::new([6; 32]),
        };
        assert!(verify_query_receipt(&record, &receipt.encode(), &wrong_query, 2_000).is_err());
    }

    #[test]
    fn stale_running_journal_without_receipt_is_unknown() {
        for stage in [
            serctl_jobs::JobStage::Submitted,
            serctl_jobs::JobStage::Running,
            serctl_jobs::JobStage::Cancelling,
            serctl_jobs::JobStage::Unknown,
        ] {
            assert_eq!(missing_receipt_code(stage), "job_unknown");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn blocked_relay_cannot_block_job_receipt_persistence() {
        struct SlowWriter;
        impl std::io::Write for SlowWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                std::thread::sleep(Duration::from_secs(5));
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let now = unix_ms().unwrap();
        let job_id = JobId::random();
        let mut start = sample_start();
        start.job_id = job_id;
        start.profile_id = ProfileId::from_bytes([9; 16]);
        start.profile_generation = 7;
        start.program = "true".to_owned();
        start.argv.clear();
        start.env.clear();
        start.cwd = None;
        start.remote_deadline_unix_ms = now + 3_000;
        start.relay_deadline_unix_ms = now + 4_000;
        start.result_retention_unix_ms = now + 5_000;
        start.max_output_bytes = 1024;
        start.input_digest = protocol::compute_start_input_digest(&start);
        let identity = JobIdentity {
            job_id,
            profile_id: start.profile_id,
            profile_generation: start.profile_generation,
            policy_digest: start.policy_digest,
            input_digest: start.input_digest,
        };
        let root = std::env::temp_dir().join(format!("serctl-remote-blocked-{job_id}"));
        let store = JobStore::new(&root).unwrap();
        let prepared = PreparedJob {
            executable: PathBuf::from("/usr/bin/true"),
            cwd: None,
            store: store.clone(),
            identity,
            deadlines: JobDeadlines {
                remote_unix_ms: start.remote_deadline_unix_ms,
                relay_unix_ms: start.relay_deadline_unix_ms,
                result_retention_unix_ms: start.result_retention_unix_ms,
            },
        };
        let output = OutputSink::with_writer(SlowWriter).unwrap();
        let (_input_tx, input_rx) = mpsc::sync_channel(1);
        let began = Instant::now();
        run_job(&output, &input_rx, start, prepared).unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "job owner waited for the deliberately blocked relay"
        );
        let receipt = store.load_receipt(job_id).unwrap();
        assert_eq!(receipt.len(), serctl_jobs::RECEIPT_BYTES);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn beta_allowlist_excludes_process_spawning_build_tools() {
        assert!(resolve_executable("cargo").is_err());
        assert!(resolve_executable("bash").is_err());
        assert_eq!(
            resolve_executable("true").unwrap(),
            Path::new("/usr/bin/true")
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn execution_fails_closed_off_linux() {
        assert!(serve_stdio()
            .unwrap_err()
            .to_string()
            .contains("only on Linux"));
    }
}
