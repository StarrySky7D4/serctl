//! Desktop frontend. Eframe supplies the renderer and drives its native window
//! through Winit; all blocking vault/SSH work stays off the Winit event loop.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use anyhow::{anyhow, Result};
use eframe::egui::{self, Color32, FontFamily, FontId, RichText, TextEdit};
use tokio::runtime::Runtime;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use crate::{client, daemon, ssh::RemoteEntry, vault};

const MAX_CONCURRENT_STATUS_PROBES: usize = 8;
const TRANSFER_EXIT_GRACE: Duration = Duration::from_secs(6);
const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
const PROFILE_REFRESH_TIMEOUT: Duration = Duration::from_secs(32);
const ABORT_JOIN_GRACE: Duration = Duration::from_millis(250);

type VaultProfileRows = Vec<(String, String, u16)>;

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
                for (name, host, _) in rows.iter_mut() {
                    name.zeroize();
                    host.zeroize();
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
        SensitiveProfileListResult::new(vault::list().map_err(|error| error.to_string()))
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
    daemon: Option<client::DaemonStatus>,
}

fn spawn_status_probe<P, F>(probes: &mut JoinSet<ProfileRow>, row: (String, String, u16), probe: P)
where
    P: FnOnce((String, String, u16)) -> F + Send + 'static,
    F: std::future::Future<Output = ProfileRow> + Send + 'static,
{
    probes.spawn(probe(row));
}

async fn load_profile_rows_with_probe<P, F>(
    rows: Vec<(String, String, u16)>,
    deadline: tokio::time::Instant,
    probe: P,
) -> Result<Vec<ProfileRow>, String>
where
    P: Fn((String, String, u16)) -> F + Clone + Send + 'static,
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
    rows: Vec<(String, String, u16)>,
    deadline: tokio::time::Instant,
) -> Result<Vec<ProfileRow>, String> {
    load_profile_rows_with_probe(rows, deadline, |(name, host, port)| async move {
        let daemon = client::daemon_status(&name).await.unwrap_or(None);
        ProfileRow {
            name,
            host,
            port,
            daemon,
        }
    })
    .await
}

enum UiMessage {
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
    ShellOpened {
        operation: OperationContext,
        result: Result<(String, client::GuiShell), String>,
    },
    #[cfg(test)]
    ZeroizeProbe(Arc<std::sync::atomic::AtomicBool>),
}

impl UiMessage {
    fn zeroize_sensitive(&mut self) {
        match self {
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct OperationContext {
    id: u64,
    profile: Option<String>,
    profile_generation: u64,
}

#[derive(Default)]
struct UiOperations {
    next_id: u64,
    profile_generation: u64,
    refresh_epoch: u64,
    next_daemon_instance: u64,
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
        };
        self.active.insert(operation.id, Zeroizing::new(activity));
        operation
    }

    fn finish(&mut self, operation: &OperationContext) -> bool {
        self.active.remove(&operation.id).is_some()
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DirectoryRequest {
    profile: String,
    path: String,
    generation: u64,
    profile_generation: u64,
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
    ) -> DirectoryRequest {
        DirectoryRequest {
            profile,
            path,
            generation: self.advance(),
            profile_generation,
        }
    }

    fn context(&self, profile: String, path: String, profile_generation: u64) -> DirectoryRequest {
        DirectoryRequest {
            profile,
            path,
            generation: self.generation,
            profile_generation,
        }
    }

    fn invalidate(&mut self) {
        self.advance();
    }

    fn is_current(
        &self,
        selected: Option<&str>,
        profile_generation: u64,
        request: &DirectoryRequest,
    ) -> bool {
        selected == Some(request.profile.as_str())
            && self.generation == request.generation
            && profile_generation == request.profile_generation
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum WorkspaceTab {
    #[default]
    Command,
    Files,
    Bash,
}

#[derive(Default)]
struct ProfileEditor {
    visible: bool,
    original_name: Option<String>,
    name: String,
    host: String,
    port: String,
    user: String,
    password: String,
    master: String,
}

struct PendingTransfer {
    cancellation: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

enum DaemonReadiness<T> {
    Ready,
    Ended(std::result::Result<T, tokio::task::JoinError>),
    Closed(tokio::sync::oneshot::error::RecvError),
    TimedOut,
}

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
        self.name.zeroize();
        self.host.zeroize();
        self.port.zeroize();
        self.user.zeroize();
        self.password.zeroize();
        self.master.zeroize();
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
    delete_candidate: Option<String>,
    command: String,
    master: String,
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
    shell: Option<client::GuiShell>,
    shell_profile: Option<String>,
    shell_input: String,
    shell_bytes: Vec<u8>,
    shell_output: String,
    operations: UiOperations,
    pending_transfers: BTreeMap<u64, PendingTransfer>,
    notice: Option<(String, bool)>,
}

impl SerctlApp {
    fn new(cc: &eframe::CreationContext<'_>, runtime: Runtime) -> Self {
        configure_appearance(&cc.egui_ctx);
        let (tx, rx) = ui_message_channel();
        let mut app = Self::with_channels(runtime, tx, rx);
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
            delete_candidate: None,
            command: "uname -a && whoami".into(),
            master: String::new(),
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
            shell: None,
            shell_profile: None,
            shell_input: String::new(),
            shell_bytes: Vec::new(),
            shell_output: "尚未打开 Bash 会话。".into(),
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

    fn send_future<F>(&self, ctx: &egui::Context, future: F)
    where
        F: std::future::Future<Output = UiMessage> + Send + 'static,
    {
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.runtime().spawn(async move {
            let message = future.await;
            let _ = tx.send(message);
            ctx.request_repaint();
        });
    }

    fn refresh(&mut self, ctx: &egui::Context) {
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
                result: load_profile_rows(rows, deadline).await,
            }
        });
    }

    fn save_profile(&mut self, ctx: &egui::Context) {
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
            || self.editor.master.is_empty()
        {
            self.set_notice("请完整填写名称、地址、用户、密码和主口令".into(), true);
            return;
        }

        let name = self.editor.name.trim().to_owned();
        let original_name = self.editor.original_name.clone();
        let saved_original_name = original_name.clone();
        let creds = vault::Creds {
            host: self.editor.host.trim().to_owned(),
            port,
            user: self.editor.user.trim().to_owned(),
            password: std::mem::take(&mut self.editor.password),
            host_key: None,
        };
        let master = Zeroizing::new(std::mem::take(&mut self.editor.master));
        let operation = self
            .operations
            .begin(self.selected.clone(), format!("正在保存 {name}…"));
        self.send_future(ctx, async move {
            let saved_name = name.clone();
            let result = tokio::task::spawn_blocking(move || -> Result<String> {
                if let Some(old) = original_name.as_deref().filter(|old| *old != name) {
                    vault::rename_profile(old, &name, &creds, &master)?;
                } else {
                    vault::add_or_update(&name, &creds, &master)?;
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
        let operation = self
            .operations
            .begin(Some(name.clone()), format!("正在删除 {name}…"));
        self.send_future(ctx, async move {
            let display_name = name.clone();
            if let Err(e) = client::down_quiet(&name).await {
                return UiMessage::Removed {
                    operation,
                    result: Err(format!("停止连接失败：{e}")),
                };
            }
            let result = tokio::task::spawn_blocking(move || vault::remove(&name))
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

    fn execute(&mut self, ctx: &egui::Context, profile: String) {
        let command = Zeroizing::new(self.command.trim().to_owned());
        if command.is_empty() {
            self.set_notice("请输入要执行的命令".into(), true);
            return;
        }
        self.command.zeroize();
        let master = Zeroizing::new(std::mem::take(&mut self.master));
        self.output.zeroize();
        self.exit_code = None;
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在 {profile} 上执行…"));
        self.send_future(ctx, async move {
            UiMessage::Command {
                operation,
                result: client::exec_capture(&profile, command.as_str(), Some(&master))
                    .await
                    .map_err(|e| e.to_string()),
            }
        });
    }

    fn refresh_directory(&mut self, ctx: &egui::Context, profile: String, path: String) {
        let request =
            self.directory_requests
                .begin(profile, path, self.operations.profile_generation);
        let request_profile = request.profile.clone();
        let request_path = request.path.clone();
        let master = Zeroizing::new(std::mem::take(&mut self.master));
        let operation = self.operations.begin(
            Some(request_profile.clone()),
            format!("正在读取 {request_path}…"),
        );
        self.send_future(ctx, async move {
            let result = client::list_dir(&request_profile, &request_path, Some(&master))
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
        let name = self.new_directory.trim();
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            self.set_notice("目录名称不能为空，也不能包含路径分隔符".into(), true);
            return;
        }
        let path = join_remote_path(&self.remote_path, name);
        let current = self.remote_path.clone();
        let context = self.directory_requests.context(
            profile.clone(),
            current.clone(),
            self.operations.profile_generation,
        );
        let master = Zeroizing::new(std::mem::take(&mut self.master));
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在创建目录 {path}…"));
        self.send_future(ctx, async move {
            let result = client::create_dir(&profile, &path, Some(&master))
                .await
                .map(|_| current)
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
        let refresh = self.directory_requests.context(
            profile.clone(),
            self.remote_path.clone(),
            self.operations.profile_generation,
        );
        let master = Zeroizing::new(std::mem::take(&mut self.master));
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在上传到 {remote}…"));
        let operation_id = operation.id;
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let tx = self.tx.clone();
        let repaint = ctx.clone();
        let handle = self.runtime().spawn(async move {
            let result = client::upload_with_timeout_and_master_cancellable(
                &profile,
                &local,
                &remote,
                Duration::from_millis(crate::ipc::DEFAULT_SFTP_TIMEOUT_MS),
                Some(master),
                worker_cancellation,
            )
            .await
            .map(|bytes| format!("上传完成：{}", format_bytes(bytes)))
            .map_err(|e| e.to_string());
            let _ = tx.send(UiMessage::Transfer {
                operation,
                refresh: Some(refresh),
                result,
            });
            repaint.request_repaint();
        });
        self.pending_transfers.insert(
            operation_id,
            PendingTransfer {
                cancellation,
                handle,
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
        let local = std::path::PathBuf::from(self.local_download.trim());
        let master = Zeroizing::new(std::mem::take(&mut self.master));
        let remote = entry.path;
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在下载 {remote}…"));
        let operation_id = operation.id;
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let tx = self.tx.clone();
        let repaint = ctx.clone();
        let handle = self.runtime().spawn(async move {
            let result = client::download_with_timeout_and_master_cancellable(
                &profile,
                &remote,
                &local,
                Duration::from_millis(crate::ipc::DEFAULT_SFTP_TIMEOUT_MS),
                Some(master),
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
            },
        );
    }

    fn start_shell(&mut self, ctx: &egui::Context, profile: String) {
        let master = Zeroizing::new(std::mem::take(&mut self.master));
        let operation = self.operations.begin(
            Some(profile.clone()),
            format!("正在打开 {profile} 的 Bash…"),
        );
        self.send_future(ctx, async move {
            UiMessage::ShellOpened {
                operation,
                result: client::open_gui_shell(&profile, Some(&master))
                    .await
                    .map(|shell| (profile, shell))
                    .map_err(|e| e.to_string()),
            }
        });
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
        let startup_deadline = tokio::time::Instant::now() + daemon::CONTROL_SETUP_TIMEOUT;
        if self.master.is_empty() {
            self.set_notice("连接前请输入主口令".into(), true);
            return;
        }
        let master = Zeroizing::new(std::mem::take(&mut self.master));
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在连接 {profile}…"));
        let instance = self.operations.next_daemon_instance();
        let tx = self.tx.clone();
        let repaint = ctx.clone();
        self.runtime().spawn(async move {
            let status =
                match tokio::time::timeout_at(startup_deadline, client::daemon_status(&profile))
                    .await
                {
                    Ok(status) => status,
                    Err(_) => {
                        let _ = tx.send(UiMessage::DaemonStarted {
                            operation,
                            profile,
                            instance,
                            result: Err("连接未能在 30 秒内就绪".into()),
                        });
                        repaint.request_repaint();
                        return;
                    }
                };
            match status {
                Ok(Some(_)) => {
                    let _ = tx.send(UiMessage::DaemonStarted {
                        operation,
                        profile,
                        instance,
                        result: Ok(false),
                    });
                    repaint.request_repaint();
                    return;
                }
                Err(e) => {
                    let _ = tx.send(UiMessage::DaemonStarted {
                        operation,
                        profile,
                        instance,
                        result: Err(e.to_string()),
                    });
                    repaint.request_repaint();
                    return;
                }
                Ok(None) => {}
            }

            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let daemon_profile = profile.clone();
            let mut daemon_task = tokio::spawn(async move {
                daemon::run_with_ready_until(
                    &daemon_profile,
                    master,
                    Some(ready_tx),
                    startup_deadline,
                )
                .await
            });
            let ready =
                wait_for_daemon_readiness(ready_rx, &mut daemon_task, startup_deadline).await;
            match ready {
                DaemonReadiness::Ended(ended) => {
                    let error = match ended {
                        Ok(Ok(())) => "连接已结束".to_owned(),
                        Ok(Err(e)) => e.to_string(),
                        Err(e) => e.to_string(),
                    };
                    let _ = tx.send(UiMessage::DaemonStarted {
                        operation: operation.clone(),
                        profile: profile.clone(),
                        instance,
                        result: Err(format!("连接未能启动：{error}")),
                    });
                    repaint.request_repaint();
                }
                DaemonReadiness::Ready => {
                    // Queue readiness before observing termination so a short-lived
                    // daemon can never produce Ended before Started.
                    let queued = tx.send(UiMessage::DaemonStarted {
                        operation: operation.clone(),
                        profile: profile.clone(),
                        instance,
                        result: Ok(true),
                    });
                    repaint.request_repaint();
                    if queued.is_err() {
                        if !abort_and_wait(&mut daemon_task).await {
                            eprintln!(
                                "[serctl] abandoned daemon startup cleanup exceeded its join grace"
                            );
                        }
                        return;
                    }

                    let error = match daemon_task.await {
                        Ok(Ok(())) => "连接已结束".to_owned(),
                        Ok(Err(e)) => e.to_string(),
                        Err(e) => e.to_string(),
                    };
                    let _ = tx.send(UiMessage::DaemonEnded {
                        operation,
                        profile,
                        instance,
                        error,
                    });
                    repaint.request_repaint();
                }
                DaemonReadiness::Closed(error) => {
                    if !abort_and_wait(&mut daemon_task).await {
                        eprintln!("[serctl] daemon startup task cleanup exceeded its join grace");
                    }
                    let _ = tx.send(UiMessage::DaemonStarted {
                        operation,
                        profile,
                        instance,
                        result: Err(format!("连接就绪信号提前关闭：{error}")),
                    });
                    repaint.request_repaint();
                }
                DaemonReadiness::TimedOut => {
                    if !abort_and_wait(&mut daemon_task).await {
                        eprintln!("[serctl] daemon startup task cleanup exceeded its join grace");
                    }
                    let _ = tx.send(UiMessage::DaemonStarted {
                        operation,
                        profile,
                        instance,
                        result: Err("连接未能在 30 秒内就绪".into()),
                    });
                    repaint.request_repaint();
                }
            }
        });
    }

    fn stop_daemon(&mut self, ctx: &egui::Context, profile: String) {
        let operation = self
            .operations
            .begin(Some(profile.clone()), format!("正在断开 {profile}…"));
        let instance = self.owned_daemons.get(&profile).copied();
        self.send_future(ctx, async move {
            let result = client::down_quiet(&profile)
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
                                        }
                                        (Some(_), None) => true,
                                        _ => false,
                                    }
                            });
                            for profile in &mut self.profiles {
                                zeroize_profile_row(profile);
                            }
                            self.profiles.clear();
                            self.profiles.append(rows);
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
                UiMessage::Removed { operation, result } => {
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    match result {
                        Ok(name) => {
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
                    let current = self.operation_is_current(operation);
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
                    let current = self.operation_is_current(operation);
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
                    let current = self.operation_is_current(operation)
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
                    let current = self.operation_is_current(operation)
                        && self.directory_request_is_current(context);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if current {
                        match result {
                            Ok(path) => {
                                self.new_directory.zeroize();
                                self.set_notice("目录已创建".into(), false);
                                let profile = std::mem::take(&mut context.profile);
                                let path = std::mem::take(path);
                                self.refresh_directory(ctx, profile, path);
                            }
                            Err(error) => {
                                self.set_notice(std::mem::take(error), true);
                            }
                        }
                    }
                }
                UiMessage::Transfer {
                    operation,
                    refresh,
                    result,
                } => {
                    self.pending_transfers.remove(&operation.id);
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if current {
                        match result {
                            Ok(message) => {
                                self.set_notice(std::mem::take(message), false);
                                if let Some(mut context) = refresh.take() {
                                    if self.directory_request_is_current(&context) {
                                        let profile = std::mem::take(&mut context.profile);
                                        let path = std::mem::take(&mut context.path);
                                        self.refresh_directory(ctx, profile, path);
                                    }
                                    zeroize_directory_request(&mut context);
                                }
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
                    let current = self.operation_is_current(operation);
                    self.operations.finish(operation);
                    zeroize_operation_context(operation);
                    if current {
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
                }
                #[cfg(test)]
                UiMessage::ZeroizeProbe(_) => {
                    panic!("exercise reducer unwind with a sensitive message")
                }
            }
        }
    }

    fn open_editor(&mut self, profile: Option<ProfileRow>) {
        self.editor.clear();
        self.editor.visible = true;
        if let Some(mut profile) = profile {
            self.editor.original_name = Some(profile.name.clone());
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
        self.operations.advance_profile_generation();
        for transfer in self.pending_transfers.values() {
            transfer.cancellation.cancel();
        }
        self.invalidate_directory_context();

        self.remote_path.zeroize();
        self.remote_path = ".".into();
        self.command.zeroize();
        self.command = "uname -a && whoami".into();
        self.master.zeroize();
        self.output.zeroize();
        self.output = "选择一个主机，然后执行命令。".into();
        self.exit_code = None;
        self.new_directory.zeroize();
        self.local_upload.zeroize();
        self.remote_upload.zeroize();
        self.local_download.zeroize();
        self.close_shell();
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
        zeroize_option_string(&mut self.delete_candidate);
        self.command.zeroize();
        self.master.zeroize();
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
    }

    fn directory_request_is_current(&self, request: &DirectoryRequest) -> bool {
        self.directory_requests.is_current(
            self.selected.as_deref(),
            self.operations.profile_generation,
            request,
        )
    }

    fn sidebar(&mut self, root: &mut egui::Ui) {
        let ctx = root.ctx().clone();
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
                        .on_hover_text("刷新状态")
                        .clicked()
                    {
                        self.refresh(&ctx);
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
                    let status = if profile.daemon.is_some() {
                        "●"
                    } else {
                        "○"
                    };
                    let color = if profile.daemon.is_some() {
                        Color32::from_rgb(76, 205, 140)
                    } else {
                        Color32::from_gray(115)
                    };
                    let mut label = format!(
                        "{status}  {}\n     {}:{}",
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
        let busy = self.operations.is_busy();
        let mut profile = self.selected_profile();
        egui::CentralPanel::default().show(root, |ui| {
            ui.add_space(18.0);
            let Some(profile) = profile.as_ref() else {
                ui.vertical_centered(|ui| {
                    ui.add_space(170.0);
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

            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.heading(&profile.name);
                    let mut endpoint = format!("{}:{}", profile.host, profile.port);
                    ui.label(RichText::new(endpoint.as_str()).color(Color32::GRAY));
                    endpoint.zeroize();
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!busy, egui::Button::new("删除")).clicked() {
                        self.delete_candidate = Some(profile.name.clone());
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
                });
            });
            ui.add_space(18.0);
            ui.separator();
            ui.add_space(14.0);

            ui.label(RichText::new("主口令").strong());
            add_secret_password_edit(
                ui,
                !busy,
                "workspace-master",
                &mut self.master,
                if profile.daemon.is_some() {
                    "已有守护连接，执行命令无需口令"
                } else {
                    "用于解密本机凭据"
                },
            );
            ui.add_space(12.0);
            let previous_tab = self.workspace_tab;
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Command, "命令");
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Files, "文件");
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Bash, "Bash");
            });
            if !busy
                && previous_tab != self.workspace_tab
                && self.workspace_tab == WorkspaceTab::Files
            {
                self.refresh_directory(&ctx, profile.name.clone(), self.remote_path.clone());
            }
            ui.separator();
            ui.add_space(8.0);
            match self.workspace_tab {
                WorkspaceTab::Command => self.command_workspace(ui, &ctx, profile),
                WorkspaceTab::Files => self.files_workspace(ui, &ctx, profile),
                WorkspaceTab::Bash => self.bash_workspace(ui, &ctx, profile),
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
        let mut entries = self.remote_entries.clone();
        egui::ScrollArea::vertical()
            .max_height(245.0)
            .show(ui, |ui| {
                egui::Grid::new("remote_files")
                    .num_columns(3)
                    .striped(true)
                    .min_col_width(90.0)
                    .show(ui, |ui| {
                        ui.strong("名称");
                        ui.strong("类型");
                        ui.strong("大小");
                        ui.end_row();
                        for entry in &entries {
                            let selected = self
                                .selected_remote
                                .as_ref()
                                .is_some_and(|selected| selected.path == entry.path);
                            let icon = if entry.is_dir { "▣" } else { "▤" };
                            let mut label = format!("{icon}  {}", entry.name);
                            let response = ui.selectable_label(selected, label.as_str());
                            label.zeroize();
                            if response.clicked() {
                                if !entry.is_dir && self.local_download.is_empty() {
                                    self.local_download = entry.name.clone();
                                }
                                if let Some(mut previous) = self.selected_remote.take() {
                                    previous.name.zeroize();
                                    previous.path.zeroize();
                                }
                                self.selected_remote = Some(entry.clone());
                            }
                            if !busy && response.double_clicked() && entry.is_dir {
                                navigate = Some(entry.path.clone());
                            }
                            ui.label(if entry.is_dir {
                                "目录"
                            } else if entry.is_symlink {
                                "链接"
                            } else {
                                "文件"
                            });
                            ui.label(if entry.is_dir {
                                "—".into()
                            } else {
                                format_bytes(entry.size)
                            });
                            ui.end_row();
                        }
                    });
            });
        zeroize_remote_entries(&mut entries);
        if let Some(path) = navigate {
            self.refresh_directory(ctx, profile.name.clone(), path);
        }

        ui.separator();
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

    fn overlays(&mut self, ctx: &egui::Context) {
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
                        ui.label("主口令");
                        add_secret_password_edit(
                            ui,
                            true,
                            "profile-master",
                            &mut self.editor.master,
                            "",
                        );
                        ui.end_row();
                    });
                ui.add_space(8.0);
                ui.label(RichText::new("保存时会使用 Argon2id + ChaCha20-Poly1305 加密凭据。编辑配置时需重新输入用户和密码。").small().color(Color32::GRAY));
                ui.add_space(10.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.operations.is_busy(), egui::Button::new("保存"))
                        .clicked()
                    {
                        self.save_profile(ctx);
                    }
                    if ui.button("取消").clicked() {
                        self.editor.clear();
                    }
                });
            });
            if !visible {
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
        self.receive_messages(ctx);
        self.receive_shell_events(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
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
        let transfers = std::mem::take(&mut self.pending_transfers);
        let owned = std::mem::take(&mut self.owned_daemons);
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
            let mut shutdowns = JoinSet::new();
            for (mut profile, _) in owned {
                shutdowns.spawn(async move {
                    let _ = client::down_quiet(&profile).await;
                    profile.zeroize();
                });
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
    fn editor_clear_restores_default_port() {
        let mut editor = ProfileEditor {
            visible: true,
            port: "2200".into(),
            password: "secret".into(),
            master: "master".into(),
            ..ProfileEditor::default()
        };
        editor.clear();
        assert!(!editor.visible);
        assert_eq!(editor.port, "22");
        assert!(editor.password.is_empty());
        assert!(editor.master.is_empty());
    }

    #[test]
    fn sensitive_state_cleanup_covers_editor_output_shell_and_paths() {
        let (mut app, _) = test_app();
        app.profiles.push(ProfileRow {
            name: "secret-profile".into(),
            host: "secret-host".into(),
            port: 22,
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
        app.editor.master = "secret-master".into();
        app.delete_candidate = Some("secret-profile".into());
        app.command = "printf secret-command".into();
        app.master = "secret-master".into();
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
        assert!(app.editor.master.is_empty());
        assert!(app.delete_candidate.is_none());
        assert!(app.command.is_empty());
        assert!(app.master.is_empty());
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
            },
            request: DirectoryRequest {
                profile: "secret-profile".into(),
                path: "/secret/request".into(),
                generation: 3,
                profile_generation: 2,
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
            },
            refresh: Some(DirectoryRequest {
                profile: "secret-profile".into(),
                path: "/secret/refresh".into(),
                generation: 5,
                profile_generation: 2,
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
                },
            );
            app.master = "secret-master".into();
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
        let first = requests.begin("alpha".into(), "/one".into(), 4);
        let second = requests.begin("alpha".into(), "/two".into(), 4);

        assert!(second.generation > first.generation);
        assert!(!requests.is_current(Some("alpha"), 4, &first));
        assert!(requests.is_current(Some("alpha"), 4, &second));
        assert!(!requests.is_current(Some("beta"), 4, &second));
        assert!(!requests.is_current(Some("alpha"), 5, &second));

        requests.invalidate();
        assert!(!requests.is_current(Some("alpha"), 4, &second));
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
        app.master = "master-secret".into();
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
            },
        );

        app.select_profile(Some("beta".into()));

        assert_eq!(app.selected.as_deref(), Some("beta"));
        assert_eq!(app.command, "uname -a && whoami");
        assert!(app.master.is_empty());
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
