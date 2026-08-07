//! Desktop frontend. Eframe supplies the renderer and drives its native window
//! through Winit; all blocking vault/SSH work stays off the Winit event loop.

use std::collections::BTreeSet;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use anyhow::{anyhow, Result};
use eframe::egui::{self, Color32, FontFamily, FontId, RichText, TextEdit};
use tokio::runtime::Runtime;
use zeroize::{Zeroize, Zeroizing};

use crate::{client, daemon, ssh::RemoteEntry, vault};

#[derive(Clone)]
struct ProfileRow {
    name: String,
    host: String,
    port: u16,
    daemon: Option<client::DaemonStatus>,
}

enum UiMessage {
    Profiles(Result<Vec<ProfileRow>, String>),
    Saved(Result<String, String>),
    Removed(Result<String, String>),
    Command(Result<client::CommandOutput, String>),
    DaemonStarted(Result<(String, bool), String>),
    DaemonStopped(Result<String, String>),
    DaemonEnded { profile: String, error: String },
    Directory(Result<(String, Vec<RemoteEntry>), String>),
    DirectoryCreated(Result<String, String>),
    Transfer(Result<(String, bool), String>),
    ShellOpened(Result<(String, client::GuiShell), String>),
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
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

impl ProfileEditor {
    fn clear(&mut self) {
        self.password.zeroize();
        self.master.zeroize();
        *self = Self {
            port: "22".into(),
            ..Self::default()
        };
    }
}

pub fn run() -> Result<()> {
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("serctl-ui-worker")
            .build()?,
    );

    // Keeping the window dimensions as Winit logical units documents the DPI
    // contract at the platform boundary; eframe performs the Winit integration.
    let size = winit::dpi::LogicalSize::new(1120.0_f64, 720.0_f64);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("serctl · SSH 工作台")
            .with_inner_size([size.width as f32, size.height as f32])
            .with_min_inner_size([860.0, 560.0]),
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "serctl",
        options,
        Box::new(move |cc| Ok(Box::new(SerctlApp::new(cc, runtime.clone())))),
    )
    .map_err(|e| anyhow!(e.to_string()))
}

struct SerctlApp {
    runtime: Arc<Runtime>,
    tx: mpsc::Sender<UiMessage>,
    rx: mpsc::Receiver<UiMessage>,
    profiles: Vec<ProfileRow>,
    owned_daemons: BTreeSet<String>,
    selected: Option<String>,
    editor: ProfileEditor,
    delete_candidate: Option<String>,
    command: String,
    master: String,
    output: String,
    exit_code: Option<i32>,
    workspace_tab: WorkspaceTab,
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
    activity: Option<String>,
    notice: Option<(String, bool)>,
}

impl SerctlApp {
    fn new(cc: &eframe::CreationContext<'_>, runtime: Arc<Runtime>) -> Self {
        configure_appearance(&cc.egui_ctx);
        let (tx, rx) = mpsc::channel();
        let mut app = Self {
            runtime,
            tx,
            rx,
            profiles: Vec::new(),
            owned_daemons: BTreeSet::new(),
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
            activity: None,
            notice: None,
        };
        app.refresh(&cc.egui_ctx);
        app
    }

    fn send_future<F>(&self, ctx: &egui::Context, future: F)
    where
        F: std::future::Future<Output = UiMessage> + Send + 'static,
    {
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(async move {
            let message = future.await;
            let _ = tx.send(message);
            ctx.request_repaint();
        });
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        self.activity = Some("正在刷新主机状态…".into());
        self.send_future(ctx, async {
            let rows = match vault::list() {
                Ok(rows) => rows,
                Err(e) => return UiMessage::Profiles(Err(e.to_string())),
            };
            let mut result = Vec::with_capacity(rows.len());
            for (name, host, port) in rows {
                let daemon = client::daemon_status(&name).await.unwrap_or(None);
                result.push(ProfileRow {
                    name,
                    host,
                    port,
                    daemon,
                });
            }
            UiMessage::Profiles(Ok(result))
        });
    }

    fn save_profile(&mut self, ctx: &egui::Context) {
        let port = match self.editor.port.parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => {
                self.notice = Some(("端口必须是 1–65535 之间的数字".into(), true));
                return;
            }
        };
        if self.editor.name.trim().is_empty()
            || self.editor.host.trim().is_empty()
            || self.editor.user.trim().is_empty()
            || self.editor.password.is_empty()
            || self.editor.master.is_empty()
        {
            self.notice = Some(("请完整填写名称、地址、用户、密码和主口令".into(), true));
            return;
        }

        let name = self.editor.name.trim().to_owned();
        let original_name = self.editor.original_name.clone();
        let creds = vault::Creds {
            host: self.editor.host.trim().to_owned(),
            port,
            user: self.editor.user.trim().to_owned(),
            password: std::mem::take(&mut self.editor.password),
            host_key: None,
        };
        let master = Zeroizing::new(std::mem::take(&mut self.editor.master));
        self.activity = Some(format!("正在保存 {name}…"));
        self.send_future(ctx, async move {
            let saved_name = name.clone();
            let result = tokio::task::spawn_blocking(move || -> Result<String> {
                vault::add_or_update(&name, &creds, &master)?;
                if let Some(old) = original_name {
                    if old != name {
                        vault::remove(&old)?;
                    }
                }
                Ok(name)
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string()));
            UiMessage::Saved(result.map(|_| saved_name))
        });
    }

    fn remove_profile(&mut self, ctx: &egui::Context, name: String) {
        self.activity = Some(format!("正在删除 {name}…"));
        self.send_future(ctx, async move {
            let display_name = name.clone();
            if let Err(e) = client::down_quiet(&name).await {
                return UiMessage::Removed(Err(format!("停止连接失败：{e}")));
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
            UiMessage::Removed(result)
        });
    }

    fn execute(&mut self, ctx: &egui::Context, profile: String) {
        let command = self.command.trim().to_owned();
        if command.is_empty() {
            self.notice = Some(("请输入要执行的命令".into(), true));
            return;
        }
        let master = Zeroizing::new(std::mem::take(&mut self.master));
        self.output.clear();
        self.exit_code = None;
        self.activity = Some(format!("正在 {profile} 上执行…"));
        self.send_future(ctx, async move {
            UiMessage::Command(
                client::exec_capture(&profile, &command, Some(&master))
                    .await
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn refresh_directory(&mut self, ctx: &egui::Context, profile: String, path: String) {
        let master = Zeroizing::new(self.master.clone());
        self.activity = Some(format!("正在读取 {path}…"));
        self.send_future(ctx, async move {
            UiMessage::Directory(
                client::list_dir(&profile, &path, Some(&master))
                    .await
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn create_remote_directory(&mut self, ctx: &egui::Context, profile: String) {
        let name = self.new_directory.trim();
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            self.notice = Some(("目录名称不能为空，也不能包含路径分隔符".into(), true));
            return;
        }
        let path = join_remote_path(&self.remote_path, name);
        let current = self.remote_path.clone();
        let master = Zeroizing::new(self.master.clone());
        self.activity = Some(format!("正在创建目录 {path}…"));
        self.send_future(ctx, async move {
            UiMessage::DirectoryCreated(
                client::create_dir(&profile, &path, Some(&master))
                    .await
                    .map(|_| current)
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn upload(&mut self, ctx: &egui::Context, profile: String) {
        let local = std::path::PathBuf::from(self.local_upload.trim());
        if self.local_upload.trim().is_empty() {
            self.notice = Some(("请输入本地文件路径".into(), true));
            return;
        }
        let remote = if self.remote_upload.trim().is_empty() {
            let Some(name) = local.file_name().and_then(|name| name.to_str()) else {
                self.notice = Some(("无法从本地路径取得文件名".into(), true));
                return;
            };
            join_remote_path(&self.remote_path, name)
        } else if self.remote_upload.starts_with('/') {
            self.remote_upload.trim().to_owned()
        } else {
            join_remote_path(&self.remote_path, self.remote_upload.trim())
        };
        let master = Zeroizing::new(self.master.clone());
        self.activity = Some(format!("正在上传到 {remote}…"));
        self.send_future(ctx, async move {
            UiMessage::Transfer(
                client::upload_file(&profile, &local, &remote, Some(&master))
                    .await
                    .map(|bytes| (format!("上传完成：{}", format_bytes(bytes)), true))
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn download(&mut self, ctx: &egui::Context, profile: String) {
        let Some(entry) = self.selected_remote.clone() else {
            self.notice = Some(("请先选择一个远程文件".into(), true));
            return;
        };
        if entry.is_dir {
            self.notice = Some(("目录暂不支持整体下载，请选择文件".into(), true));
            return;
        }
        if self.local_download.trim().is_empty() {
            self.notice = Some(("请输入本地保存路径".into(), true));
            return;
        }
        let local = std::path::PathBuf::from(self.local_download.trim());
        let master = Zeroizing::new(self.master.clone());
        let remote = entry.path;
        self.activity = Some(format!("正在下载 {remote}…"));
        self.send_future(ctx, async move {
            UiMessage::Transfer(
                client::download_file(&profile, &remote, &local, Some(&master))
                    .await
                    .map(|bytes| (format!("下载完成：{}", format_bytes(bytes)), false))
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn start_shell(&mut self, ctx: &egui::Context, profile: String) {
        let master = Zeroizing::new(self.master.clone());
        self.activity = Some(format!("正在打开 {profile} 的 Bash…"));
        self.send_future(ctx, async move {
            UiMessage::ShellOpened(
                client::open_gui_shell(&profile, Some(&master))
                    .await
                    .map(|shell| (profile, shell))
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn send_shell_bytes(&mut self, bytes: Vec<u8>) {
        let Some(shell) = &self.shell else {
            self.notice = Some(("请先打开 Bash 会话".into(), true));
            return;
        };
        if shell.input.try_send(bytes).is_err() {
            self.notice = Some(("Bash 输入队列不可用".into(), true));
        }
    }

    fn receive_shell_events(&mut self, ctx: &egui::Context) {
        let mut closed = false;
        let mut close_error = None;
        if let Some(shell) = &mut self.shell {
            while let Ok(event) = shell.events.try_recv() {
                match event {
                    client::ShellEvent::Output(data) => self.shell_bytes.extend(data),
                    client::ShellEvent::Error(error) => {
                        close_error = Some(error);
                        closed = true;
                    }
                    client::ShellEvent::Closed => closed = true,
                }
            }
            if self.shell_bytes.len() > 2 * 1024 * 1024 {
                let keep_from = self.shell_bytes.len() - 1024 * 1024;
                self.shell_bytes.drain(..keep_from);
            }
            self.shell_output = terminal_text(&self.shell_bytes);
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        if closed {
            self.shell = None;
            self.shell_profile = None;
            self.notice = Some(match close_error {
                Some(error) => (format!("Bash: {error}"), true),
                None => ("Bash 会话已关闭".into(), false),
            });
        }
    }

    fn start_daemon(&mut self, ctx: &egui::Context, profile: String) {
        if self.master.is_empty() {
            self.notice = Some(("连接前请输入主口令".into(), true));
            return;
        }
        let master = Zeroizing::new(std::mem::take(&mut self.master));
        self.activity = Some(format!("正在连接 {profile}…"));
        let event_tx = self.tx.clone();
        let repaint = ctx.clone();
        self.send_future(ctx, async move {
            match client::daemon_status(&profile).await {
                Ok(Some(_)) => return UiMessage::DaemonStarted(Ok((profile, false))),
                Err(e) => return UiMessage::DaemonStarted(Err(e.to_string())),
                Ok(None) => {}
            }

            let decrypt_profile = profile.clone();
            let decrypt_master = master.clone();
            let creds = match tokio::task::spawn_blocking(move || {
                vault::decrypt(&decrypt_profile, &decrypt_master)
            })
            .await
            {
                Ok(Ok(creds)) => creds,
                Ok(Err(e)) => return UiMessage::DaemonStarted(Err(e.to_string())),
                Err(e) => return UiMessage::DaemonStarted(Err(e.to_string())),
            };

            let (ready_tx, ready_rx) = mpsc::channel();
            let daemon_profile = profile.clone();
            let mut daemon_task = tokio::spawn(async move {
                daemon::run_with_ready(
                    &daemon_profile,
                    creds,
                    master.to_string(),
                    Some(ready_tx),
                )
                .await
            });
            let ready_wait = tokio::task::spawn_blocking(move || {
                ready_rx.recv_timeout(Duration::from_secs(30))
            });
            tokio::select! {
                ready = ready_wait => match ready {
                    Ok(Ok(_)) => {
                        let watched_profile = profile.clone();
                        tokio::spawn(async move {
                            let error = match daemon_task.await {
                                Ok(Ok(())) => "连接已结束".to_owned(),
                                Ok(Err(e)) => e.to_string(),
                                Err(e) => e.to_string(),
                            };
                            let _ = event_tx.send(UiMessage::DaemonEnded {
                                profile: watched_profile,
                                error,
                            });
                            repaint.request_repaint();
                        });
                        UiMessage::DaemonStarted(Ok((profile, true)))
                    },
                    Ok(Err(_)) => UiMessage::DaemonStarted(Err("连接未能在 30 秒内就绪".into())),
                    Err(e) => UiMessage::DaemonStarted(Err(e.to_string())),
                },
                ended = &mut daemon_task => {
                    let error = match ended {
                        Ok(Ok(())) => "连接已结束".to_owned(),
                        Ok(Err(e)) => e.to_string(),
                        Err(e) => e.to_string(),
                    };
                    let _ = event_tx.send(UiMessage::DaemonEnded { profile: profile.clone(), error });
                    repaint.request_repaint();
                    UiMessage::DaemonStarted(Err("连接未能启动".into()))
                }
            }
        });
    }

    fn stop_daemon(&mut self, ctx: &egui::Context, profile: String) {
        self.activity = Some(format!("正在断开 {profile}…"));
        self.send_future(ctx, async move {
            UiMessage::DaemonStopped(
                client::down_quiet(&profile)
                    .await
                    .map(|_| profile)
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn receive_messages(&mut self, ctx: &egui::Context) {
        while let Ok(message) = self.rx.try_recv() {
            self.activity = None;
            match message {
                UiMessage::Profiles(Ok(rows)) => {
                    self.profiles = rows;
                    if self
                        .selected
                        .as_ref()
                        .is_none_or(|name| !self.profiles.iter().any(|p| &p.name == name))
                    {
                        self.selected = self.profiles.first().map(|p| p.name.clone());
                    }
                }
                UiMessage::Profiles(Err(e)) => self.notice = Some((e, true)),
                UiMessage::Saved(Ok(name)) => {
                    self.editor.visible = false;
                    self.editor.clear();
                    self.selected = Some(name.clone());
                    self.notice = Some((format!("已保存 {name}"), false));
                    self.refresh(ctx);
                }
                UiMessage::Saved(Err(e)) => self.notice = Some((e, true)),
                UiMessage::Removed(Ok(name)) => {
                    self.owned_daemons.remove(&name);
                    if self.shell_profile.as_deref() == Some(&name) {
                        self.shell = None;
                        self.shell_profile = None;
                    }
                    self.selected = None;
                    self.notice = Some((format!("已删除 {name}"), false));
                    self.refresh(ctx);
                }
                UiMessage::Removed(Err(e)) => self.notice = Some((e, true)),
                UiMessage::Command(Ok(result)) => {
                    let mut output = String::from_utf8_lossy(&result.stdout).into_owned();
                    if !result.stderr.is_empty() {
                        if !output.is_empty() && !output.ends_with('\n') {
                            output.push('\n');
                        }
                        output.push_str("[stderr]\n");
                        output.push_str(&String::from_utf8_lossy(&result.stderr));
                    }
                    self.output = if output.is_empty() {
                        "（命令没有输出）".into()
                    } else {
                        output
                    };
                    self.exit_code = result.code;
                }
                UiMessage::Command(Err(e)) => {
                    self.output = format!("执行失败：{e}");
                    self.notice = Some((e, true));
                }
                UiMessage::DaemonStarted(Ok((name, owned))) => {
                    if owned {
                        self.owned_daemons.insert(name.clone());
                    }
                    self.notice = Some((format!("{name} 已连接"), false));
                    self.refresh(ctx);
                }
                UiMessage::DaemonStarted(Err(e)) => self.notice = Some((e, true)),
                UiMessage::DaemonStopped(Ok(name)) => {
                    self.owned_daemons.remove(&name);
                    if self.shell_profile.as_deref() == Some(&name) {
                        self.shell = None;
                        self.shell_profile = None;
                    }
                    self.notice = Some((format!("{name} 已断开"), false));
                    self.refresh(ctx);
                }
                UiMessage::DaemonStopped(Err(e)) => self.notice = Some((e, true)),
                UiMessage::DaemonEnded { profile, error } => {
                    self.owned_daemons.remove(&profile);
                    if self.shell_profile.as_deref() == Some(&profile) {
                        self.shell = None;
                        self.shell_profile = None;
                    }
                    self.notice = Some((format!("{profile}: {error}"), true));
                    self.refresh(ctx);
                }
                UiMessage::Directory(Ok((path, entries))) => {
                    self.remote_path = path;
                    self.remote_entries = entries;
                    self.selected_remote = None;
                }
                UiMessage::Directory(Err(e)) => self.notice = Some((e, true)),
                UiMessage::DirectoryCreated(Ok(path)) => {
                    self.new_directory.clear();
                    self.notice = Some(("目录已创建".into(), false));
                    if let Some(profile) = self.selected.clone() {
                        self.refresh_directory(ctx, profile, path);
                    }
                }
                UiMessage::DirectoryCreated(Err(e)) => self.notice = Some((e, true)),
                UiMessage::Transfer(Ok((message, refresh))) => {
                    self.notice = Some((message, false));
                    if refresh {
                        if let Some(profile) = self.selected.clone() {
                            self.refresh_directory(ctx, profile, self.remote_path.clone());
                        }
                    }
                }
                UiMessage::Transfer(Err(e)) => self.notice = Some((e, true)),
                UiMessage::ShellOpened(Ok((profile, shell))) => {
                    self.shell = Some(shell);
                    self.shell_profile = Some(profile);
                    self.shell_bytes.clear();
                    self.shell_output = "Bash 会话已打开。".into();
                    self.notice = Some(("Bash 会话已打开".into(), false));
                }
                UiMessage::ShellOpened(Err(e)) => self.notice = Some((e, true)),
            }
        }
    }

    fn open_editor(&mut self, profile: Option<ProfileRow>) {
        self.editor.clear();
        self.editor.visible = true;
        if let Some(profile) = profile {
            self.editor.original_name = Some(profile.name.clone());
            self.editor.name = profile.name;
            self.editor.host = profile.host;
            self.editor.port = profile.port.to_string();
        }
    }

    fn selected_profile(&self) -> Option<ProfileRow> {
        let selected = self.selected.as_ref()?;
        self.profiles.iter().find(|p| &p.name == selected).cloned()
    }

    fn sidebar(&mut self, root: &mut egui::Ui) {
        let ctx = root.ctx().clone();
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
                    if ui.button("＋ 新建主机").clicked() {
                        self.open_editor(None);
                    }
                    if ui.button("⟳").on_hover_text("刷新状态").clicked() {
                        self.refresh(&ctx);
                    }
                });
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);

                if self.profiles.is_empty() {
                    ui.label(RichText::new("尚无主机配置").color(Color32::GRAY));
                }
                for profile in &self.profiles {
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
                    let label = format!(
                        "{status}  {}\n     {}:{}",
                        profile.name, profile.host, profile.port
                    );
                    if ui
                        .selectable_label(
                            selected,
                            RichText::new(label).color(if selected {
                                Color32::WHITE
                            } else {
                                color
                            }),
                        )
                        .clicked()
                    {
                        if self.selected.as_deref() != Some(&profile.name) {
                            self.shell = None;
                            self.shell_profile = None;
                            self.remote_path = ".".into();
                            self.remote_entries.clear();
                            self.selected_remote = None;
                        }
                        self.selected = Some(profile.name.clone());
                    }
                    ui.add_space(3.0);
                }
            });
    }

    fn central_panel(&mut self, root: &mut egui::Ui) {
        let ctx = root.ctx().clone();
        egui::CentralPanel::default().show(root, |ui| {
            ui.add_space(18.0);
            let Some(profile) = self.selected_profile() else {
                ui.vertical_centered(|ui| {
                    ui.add_space(170.0);
                    ui.label(RichText::new("选择或新建一台主机").size(24.0));
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("凭据会加密保存在本机，不会出现在命令行参数中。\n")
                            .color(Color32::GRAY),
                    );
                    if ui.button("新建主机").clicked() {
                        self.open_editor(None);
                    }
                });
                return;
            };

            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.heading(&profile.name);
                    ui.label(
                        RichText::new(format!("{}:{}", profile.host, profile.port))
                            .color(Color32::GRAY),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("删除").clicked() {
                        self.delete_candidate = Some(profile.name.clone());
                    }
                    if ui.button("编辑").clicked() {
                        self.open_editor(Some(profile.clone()));
                    }
                    if profile.daemon.is_some() {
                        if ui.button("断开").clicked() {
                            self.stop_daemon(&ctx, profile.name.clone());
                        }
                        ui.label(RichText::new("● 已连接").color(Color32::from_rgb(76, 205, 140)));
                    } else {
                        if ui.button("连接").clicked() {
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
            ui.add(
                TextEdit::singleline(&mut self.master)
                    .password(true)
                    .hint_text(if profile.daemon.is_some() {
                        "已有守护连接，执行命令无需口令"
                    } else {
                        "用于解密本机凭据"
                    })
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(12.0);
            let previous_tab = self.workspace_tab;
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Command, "命令");
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Files, "文件");
                ui.selectable_value(&mut self.workspace_tab, WorkspaceTab::Bash, "Bash");
            });
            if previous_tab != self.workspace_tab && self.workspace_tab == WorkspaceTab::Files {
                self.refresh_directory(&ctx, profile.name.clone(), self.remote_path.clone());
            }
            ui.separator();
            ui.add_space(8.0);
            match self.workspace_tab {
                WorkspaceTab::Command => self.command_workspace(ui, &ctx, &profile),
                WorkspaceTab::Files => self.files_workspace(ui, &ctx, &profile),
                WorkspaceTab::Bash => self.bash_workspace(ui, &ctx, &profile),
            }
        });
    }

    fn command_workspace(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, profile: &ProfileRow) {
        ui.label(RichText::new("命令").strong());
        ui.horizontal(|ui| {
            let response = ui.add_sized(
                [ui.available_width() - 92.0, 34.0],
                TextEdit::singleline(&mut self.command)
                    .font(FontId::monospace(14.0))
                    .hint_text("输入远程命令"),
            );
            let run = ui.add_enabled(
                self.activity.is_none(),
                egui::Button::new("▶ 执行").min_size([78.0, 34.0].into()),
            );
            if run.clicked()
                || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
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
                self.output.clear();
                self.exit_code = None;
            }
        });
        ui.add(
            TextEdit::multiline(&mut self.output)
                .font(FontId::monospace(13.0))
                .code_editor()
                .desired_rows(15)
                .desired_width(f32::INFINITY),
        );
    }

    fn files_workspace(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, profile: &ProfileRow) {
        ui.horizontal(|ui| {
            if ui.button("↑").on_hover_text("上级目录").clicked() {
                let parent = remote_parent(&self.remote_path);
                self.refresh_directory(ctx, profile.name.clone(), parent);
            }
            let path_response = ui.add_sized(
                [ui.available_width() - 84.0, 30.0],
                TextEdit::singleline(&mut self.remote_path)
                    .font(FontId::monospace(13.0))
                    .hint_text("远程目录"),
            );
            if ui.button("刷新").clicked()
                || (path_response.lost_focus()
                    && ui.input(|input| input.key_pressed(egui::Key::Enter)))
            {
                self.refresh_directory(ctx, profile.name.clone(), self.remote_path.clone());
            }
        });
        ui.horizontal(|ui| {
            ui.label("新建目录");
            ui.text_edit_singleline(&mut self.new_directory);
            if ui
                .add_enabled(self.activity.is_none(), egui::Button::new("添加目录"))
                .clicked()
            {
                self.create_remote_directory(ctx, profile.name.clone());
            }
        });
        ui.add_space(6.0);

        let mut navigate = None;
        let entries = self.remote_entries.clone();
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
                        for entry in entries {
                            let selected = self
                                .selected_remote
                                .as_ref()
                                .is_some_and(|selected| selected.path == entry.path);
                            let icon = if entry.is_dir { "▣" } else { "▤" };
                            let response =
                                ui.selectable_label(selected, format!("{icon}  {}", entry.name));
                            if response.clicked() {
                                if !entry.is_dir && self.local_download.is_empty() {
                                    self.local_download = entry.name.clone();
                                }
                                self.selected_remote = Some(entry.clone());
                            }
                            if response.double_clicked() && entry.is_dir {
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
        if let Some(path) = navigate {
            self.refresh_directory(ctx, profile.name.clone(), path);
        }

        ui.separator();
        egui::Grid::new("file_transfer")
            .num_columns(4)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("上传");
                ui.add(
                    TextEdit::singleline(&mut self.local_upload)
                        .hint_text("本地文件完整路径")
                        .desired_width(260.0),
                );
                ui.add(
                    TextEdit::singleline(&mut self.remote_upload)
                        .hint_text("远程文件名（可选）")
                        .desired_width(180.0),
                );
                if ui
                    .add_enabled(self.activity.is_none(), egui::Button::new("上传"))
                    .clicked()
                {
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
                ui.add(
                    TextEdit::singleline(&mut self.local_download)
                        .hint_text("本地保存完整路径")
                        .desired_width(180.0),
                );
                if ui
                    .add_enabled(self.activity.is_none(), egui::Button::new("下载"))
                    .clicked()
                {
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
        let active =
            self.shell.is_some() && self.shell_profile.as_deref() == Some(profile.name.as_str());
        ui.horizontal(|ui| {
            if !active {
                if ui
                    .add_enabled(self.activity.is_none(), egui::Button::new("打开 Bash"))
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
                    self.send_shell_bytes(vec![4]);
                    self.shell = None;
                    self.shell_profile = None;
                }
            }
            if ui.small_button("清屏").clicked() {
                self.shell_bytes.clear();
                self.shell_output.clear();
            }
        });
        ui.add(
            TextEdit::multiline(&mut self.shell_output)
                .font(FontId::monospace(13.0))
                .code_editor()
                .interactive(false)
                .desired_rows(16)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            let response = ui.add_sized(
                [ui.available_width() - 80.0, 32.0],
                TextEdit::singleline(&mut self.shell_input)
                    .font(FontId::monospace(13.0))
                    .hint_text("输入 Bash 命令并回车"),
            );
            let send = ui.add_enabled(active, egui::Button::new("发送"));
            if (send.clicked()
                || (response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter))))
                && active
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
                        ui.text_edit_singleline(&mut self.editor.name);
                        ui.end_row();
                        ui.label("地址");
                        ui.text_edit_singleline(&mut self.editor.host);
                        ui.end_row();
                        ui.label("端口");
                        ui.text_edit_singleline(&mut self.editor.port);
                        ui.end_row();
                        ui.label("用户");
                        ui.text_edit_singleline(&mut self.editor.user);
                        ui.end_row();
                        ui.label("SSH 密码");
                        ui.add(TextEdit::singleline(&mut self.editor.password).password(true));
                        ui.end_row();
                        ui.label("主口令");
                        ui.add(TextEdit::singleline(&mut self.editor.master).password(true));
                        ui.end_row();
                    });
                ui.add_space(8.0);
                ui.label(RichText::new("保存时会使用 Argon2id + ChaCha20-Poly1305 加密凭据。编辑配置时需重新输入用户和密码。").small().color(Color32::GRAY));
                ui.add_space(10.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(self.activity.is_none(), egui::Button::new("保存"))
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

        if let Some(name) = self.delete_candidate.clone() {
            egui::Window::new("确认删除")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!("确定删除主机“{name}”吗？此操作无法撤销。"));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("取消").clicked() {
                            self.delete_candidate = None;
                        }
                        if ui.button("删除").clicked() {
                            self.delete_candidate = None;
                            self.remove_profile(ctx, name.clone());
                        }
                    });
                });
        }
    }

    fn status_panel(&mut self, root: &mut egui::Ui) {
        if let Some(activity) = &self.activity {
            egui::Panel::bottom("activity").show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(activity);
                });
            });
        } else if let Some((message, error)) = self.notice.clone() {
            egui::Panel::bottom("notice").show(root, |ui| {
                ui.horizontal(|ui| {
                    let color = if error {
                        Color32::from_rgb(245, 104, 104)
                    } else {
                        Color32::from_rgb(76, 205, 140)
                    };
                    ui.label(RichText::new(message).color(color));
                    if ui.small_button("×").clicked() {
                        self.notice = None;
                    }
                });
            });
        }
    }
}

impl eframe::App for SerctlApp {
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
        self.master.zeroize();
        self.editor.password.zeroize();
        self.editor.master.zeroize();
        self.output.zeroize();
        self.shell_input.zeroize();
        self.shell_output.zeroize();
        self.shell_bytes.zeroize();
        let owned = std::mem::take(&mut self.owned_daemons);
        self.runtime.block_on(async move {
            for profile in owned {
                let _ = client::down_quiet(&profile).await;
            }
        });
    }
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
    let mut output = Vec::with_capacity(input.len());
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
    fn terminal_text_removes_common_ansi_sequences() {
        assert_eq!(terminal_text(b"\x1b[32mok\x1b[0m\r\n"), "ok\n");
        assert_eq!(terminal_text(b"ab\x08c"), "ac");
    }
}
