# serctl

`serctl` 是一个纯 Rust 的持久 SSH 控制工具，提供基于 Winit/Egui 的桌面 UI 和完整 CLI。它复用长连接完成远程命令、目录浏览、SFTP 文件传输与 Bash PTY 交互。

## 桌面 UI

开发时直接启动 debug 版本：

```powershell
cargo run
# 等价于 cargo run -- ui
```

桌面端支持：

- 新建、编辑和删除主机配置；
- 启动、查看或停止持久 SSH 连接；
- 执行远程命令并分别显示 stdout、stderr 与退出码；
- 浏览远程目录、返回上级目录和创建目录；
- 通过 SFTP 分块上传、下载文件；
- 使用持续的 Bash PTY 会话，支持连续输入、`Ctrl+C`、`Ctrl+D` 和清屏；
- 在后台进行口令派生和网络任务，避免阻塞 Winit 事件循环；
- 自动加载常见系统 CJK 字体。

上传和下载均先写入同目录随机临时文件，完整写入并校验字节数后再重命名；默认不覆盖已有文件，失败时清理临时文件。

## 架构

```text
Winit / Egui UI ─┐
                 ├─ client（命令、SFTP、PTY）─ authenticated local IPC ─ daemon ─ russh
CLI ─────────────┘        │ Windows Named Pipe / Unix Domain Socket       └─ russh-sftp
                         └─ vault（Argon2id + ChaCha20-Poly1305）
```

UI 与 CLI 复用同一组核心接口。守护进程关闭通过 Tokio 通知通道协调，不会调用 `process::exit`，因此可以安全嵌入桌面进程。

## CLI

```powershell
$exe = ".\target\debug\serctl.exe"

# SSH 密码与主口令交互输入，不进入 argv
& $exe add prod --host 192.168.5.15 --user deploy --port 22

# 前台启动持久连接
& $exe up prod

# 在另一个终端复用连接
& $exe exec prod -- "uname -a; whoami; df -h /"
& $exe shell prod

# 上传证据，再从服务器拉取 M7 evidence
& $exe upload prod .\request.json /tmp/request.json --timeout-secs 120
& $exe download prod /tmp/server-evidence.json .\server-evidence.json --timeout-secs 120

# 为可能挂起的命令设置更短的硬超时（默认 300 秒）
& $exe exec prod --timeout-secs 30 -- "collect-evidence"

# 查看状态并停止
& $exe status prod
& $exe down prod
```

| 命令 | 说明 |
| --- | --- |
| `ui` | 打开桌面工作台；省略子命令时默认执行 |
| `add [NAME] [--host H] [--user U] [--port P]` | 新增或更新配置 |
| `list` | 列出配置，不解密秘密字段 |
| `remove NAME` | 删除配置 |
| `up [NAME]` | 前台启动持久连接 |
| `exec NAME [--timeout-secs N] -- <CMD...>` | 执行远程命令，优先复用连接；默认硬超时 300 秒 |
| `upload NAME LOCAL REMOTE [--timeout-secs N]` | 原子上传文件，不覆盖已有远程文件；默认硬超时 300 秒 |
| `download NAME REMOTE LOCAL [--timeout-secs N]` | 拉取服务器 evidence，不覆盖已有本地文件；默认硬超时 300 秒 |
| `shell [NAME]` | 打开交互式 PTY shell |
| `status [NAME]` | 查看守护状态 |
| `down [NAME]` | 停止守护连接 |

`up`、`shell`、`status` 的 `NAME` 省略时为 `default`；`exec`、`upload`、`download` 要求显式配置名，避免自动化任务误用主机。自动化场景可用 `SERCTL_SSH_PASS` 和 `SERCTL_MASTER` 注入口令；程序读取后会立即从自身环境中移除变量。环境变量仍可能被父进程、调试器或同权限进程观察，因此交互输入更稳妥。

## 凭证与本机 IPC 安全

- 凭证库位于 `%USERPROFILE%\.serctl\vault.json`。
- 主口令通过 Argon2id 派生 32 字节密钥；当前参数为 64 MiB、3 轮、并行度 1，参数和格式版本随凭证库保存并设有安全上限。
- 用户名、SSH 密码和 TOFU 主机公钥指纹使用 ChaCha20-Poly1305 加密。配置名、主机和端口保留明文以支持列表，但作为 AEAD 附加数据参与认证，修改后解密会失败。
- 凭证库包含加密校验器，错误主口令或校验器篡改会在写入前被拒绝。随机盐和 nonce 长度均严格校验。
- 凭证更新使用进程间互斥锁和同目录原子替换，降低并发更新丢失与崩溃截断风险。
- Windows 上凭证目录和文件使用禁止继承的 DACL，仅保留文件所有者、SYSTEM 和 Administrators；Unix 上目录为 `0700`、文件为 `0600`。权限设置失败时保存操作失败关闭。
- 守护进程不再开放 TCP 端口：Windows 使用拒绝远程客户端的 Named Pipe，Unix 使用位于 `0700` 运行目录且权限为 `0600` 的 Unix Domain Socket。两端复用同一套长度前缀帧协议和异步读写接口。
- 每次启动生成 256 位随机能力令牌，平台端点名称由配置名和令牌散列得到。客户端必须先通过常量时间令牌校验，之后才能执行命令、传输文件或请求关闭。
- IPC 认证设有超时、帧大小和并发连接上限；单次命令输出限制为 8 MiB，避免本机或远端无限输出耗尽内存。
- 每个远程命令都有由 daemon 执行的硬 deadline；客户端在结果返回前断开时，daemon 会主动向对应 SSH channel 发送 EOF/Close。只有收到明确退出状态才会把命令视为完成，IPC 中断不会再被误判为退出码 0。
- SSH 会话每 30 秒发送 keepalive，并在连续无响应后标记连接失效；daemon 保持本地 IPC 在线，在下一次状态或业务请求时单飞重连并重新校验已固定的主机指纹，避免虚拟机重启后出现“daemon ACTIVE 但所有命令均 Channel send error”的假活状态。
- 目录浏览、建目录、上传和下载也具有 client/daemon 双层总硬 deadline，默认 300 秒、最大 24 小时；上传超时会尝试清理远端随机临时文件，无 daemon 直连上传即使 Future 被取消也会保留 SSH 会话并通过新的 SFTP channel 执行有界后台清理；下载超时会清理本地 `.serctl-part`。
- 运行锁文件使用配置名的 SHA-256 作为文件名，新格式不再明文写入远程主机和用户名；每个配置具有 OS 级生命周期租约，防止重复守护进程和陈旧锁竞态。
- 首次固定主机指纹时采用只写一次语义；并发连接不能用不同指纹覆盖已经固定的结果。
- 首次 SSH 连接采用 TOFU；第一次连接若遭中间人攻击，错误公钥仍可能被固定。高安全环境应通过独立渠道核对首次显示的指纹。

旧凭证库可继续读取，并在使用正确主口令修改记录时升级为新格式。旧版守护进程没有 IPC 令牌或仍使用 loopback TCP；新版客户端会拒绝连接并提示重启，而不会静默降级。升级程序后应在方便时重启旧守护进程。

本模型不防御已获得同一 Windows/Unix 用户身份、管理员权限、调试权限、内存转储或键盘记录能力的攻击者。主口令强度仍直接决定离线破解成本，建议使用长且唯一的口令。

## 构建与验证

开发构建：

```powershell
cargo build
```

发布构建会写入 `target\release\serctl.exe`；若该程序仍在运行，请勿执行发布构建或覆盖该文件。

```powershell
cargo build --release
```

构建脚本会把源代码 Git commit 写入程序；使用 `serctl --version` 可核对二进制来源。工作树不干净时版本后缀会显示 `-dirty`。`target` 构建产物不提交到 Git，发布时应结合 commit、二进制 SHA-256 和签名/制品仓库记录进行追踪。

本地验证：

```powershell
cargo fmt -- --check
cargo check --all-targets
cargo test
cargo clippy --all-targets -- -D warnings
```

测试套件除单元测试外，还会在随机本地端口启动临时 SSH/SFTP 服务和真实 daemon；daemon IPC 使用当前平台的 Named Pipe/Unix Socket，覆盖认证、错误令牌拒绝、exec 正常退出、deadline、客户端断连取消，以及上传/下载内容往返。所有状态写入 `target` 下的隔离临时目录，不读取或修改真实凭证库；外部服务器兼容性验证仍需要可访问的测试服务器。
