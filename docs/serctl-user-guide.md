# serctl 使用手册

适用版本：`v1.0.0-beta.3`（预发布测试版）
<!-- applicable-version: v1.0.0-beta.3 -->
最后更新：2026-08-31

> [!WARNING]
> 当前版本是测试版本，不应直接替代经过签名和独立验收的正式发行版。生产凭证必须先备份，再进行安装、升级或迁移。
>
> 当前源码的测试目录隔离仍在加固中。存有真实 `%USERPROFILE%\.serctl` 的 Windows 账户不得运行默认并行的 `cargo test`。开发测试必须使用专用操作系统账户，并严格使用 `-- --test-threads=1`。如果真实凭证库中出现 `v6test`、`e2e`、`prod`、`tester` 或 `127.0.0.1:22` 等测试数据，请立即停止 serctl 和测试，不要继续保存或初始化。

> [!NOTE]
> 当前预发布标记已同步为 v1.0.0-beta.3；该候选尚未验收或发布。候选本机 wire 已提升到 IPC v9，但仍使用现有 AEAD/JSON 帧；未来 Protobuf codec 不是当前能力。`serctl-remote`、jobs、remote protocol 与 policy 只有 source-only experimental / unshipped 基础，继续接受 workspace 质量检查但不进入 v1 beta 安装包、不发布、不支持；没有 `job.*` Agent 请求或 OperationGrant scope，也不能把普通 `ssh.exec` 解释成可恢复作业。远端透明日志、独立单调审计锚、完整策略 DSL 和 QUIC 高速通道也仍是目标设计。设计决策和验收路线见 [目标架构与演进路线](serctl-design-roadmap.md)；v1 候选的 Agent 契约见 [Agent JSONL 契约](v1-beta-agent-jsonl.md)。

## 1. serctl 是什么

serctl 是一个带桌面 UI 和命令行界面的 SSH 工作台，用于：

- 保存多个远程主机的加密 SSH 凭证；
- 复用后台 SSH 连接执行命令和打开 Bash 终端；
- 浏览远程目录，通过 SFTP 上传和下载文件；
- 建立本地转发、远程转发和动态 SOCKS5 隧道；
- 为每台主机设置互相独立的 profile 口令；
- 在 Windows 上使用“超管密码 + 离线介质”完成 2-of-2 凭证恢复。

serctl 中的“profile”就是一条主机配置。每个 profile 包含名称、地址、端口、SSH 用户、SSH 密码和可选的主机密钥指纹。

### 1.1 三类秘密不要混淆

| 秘密 | 用途 | 是否能打开其他 profile |
| --- | --- | --- |
| SSH 密码 | 登录一台远程 SSH 主机 | 否 |
| profile 独立口令 | 解锁该 profile 的加密凭证 | 否 |
| Windows 超管密码 | 保护本机恢复 share，授权初始化、恢复和管理操作 | 不能单独解密任何 profile |

Windows 保留原 SSH 凭据进行恢复时，必须同时具备超管密码和与当前 vault 匹配的离线恢复介质。serctl 不提供查看已有 profile 口令或 SSH 密码的功能。

## 2. 安装与启动

### 2.1 使用已构建的程序

Windows 交付目录至少应同时包含：

```text
serctl_cli.exe
serctl_daemon.exe
```

两个文件必须放在同一目录。客户端只查找同目录的 daemon，不会从 `PATH` 搜索替代程序。

检查版本：

```powershell
$Serctl = 'C:\Program Files\serctl\serctl_cli.exe'
& $Serctl --version
```

版本输出中的 Git 提交后缀若带 `-dirty`，表示它不是从干净源码状态构建的正式候选制品。

启动桌面 UI：

```powershell
& $Serctl
# 或
& $Serctl ui
```

### 2.2 从源码构建

仓库固定使用 Rust `1.97.1`。正式构建不得启用 `--all-features`，因为 `test-support` 只允许用于测试。v1 beta 的 Windows runtime 只构建匹配 CLI + daemon；Linux runtime 只构建通过实机门禁的 `serctl-xfer`，不是 Linux 桌面客户端包：

```powershell
rustup show
cargo build --locked --release -p serctl-cli --bin serctl_cli -p serctl-daemon --bin serctl_daemon
.\target\release\serctl_cli.exe --version
```

Linux helper 的正式构建命令为 `cargo build --locked --release -p serctl-xfer --bin serctl-xfer`。`serctl-remote`、jobs、remote protocol 与 policy 仅为 source-only experimental / unshipped；它们参加源码质量检查，但不进入 v1 beta runtime、symbols、SBOM 或支持面，`job.*` 也不能由 Agent/OperationGrant 签发。

开发测试必须使用没有真实 serctl vault 的专用系统账户：

```powershell
cargo test --locked --all-targets --all-features -- --test-threads=1
```

不要省略 `--test-threads=1`。

## 3. 凭证库位置与备份

正常用户的凭证目录为：

- Windows：`%USERPROFILE%\.serctl`
- Linux/macOS：`$HOME/.serctl`

其中：

- `vault.json` 是加密凭证库；
- `vault.lock` 是进程间写锁；
- `run` 保存 daemon 运行状态和租约，不属于长期备份内容。

profile 名称、主机地址、端口和 generation 是明文目录元数据；SSH 用户、SSH 密码和主机密钥 pin 保存在加密负载中。因此不要用敏感信息作为 profile 名称。

### 3.1 推荐备份方法

1. 关闭 UI，停止正在运行的 shell、传输和隧道。
2. 使用 `down PROFILE` 正常停止 daemon。
3. 备份完整的 `vault.json`，并保留文件 ACL/所有者信息。
4. 将当前离线恢复介质另存于不同的物理介质。
5. 用同一个版本号或日期标记 vault 与恢复介质，保持配对关系。
6. 不要把恢复介质、随机口令回执或其副本放入 `.serctl`。

不要通过删除 `run`、修改 JSON、放宽 ACL 或复制测试 vault 的方式“修复”凭证库。恢复前应先对当前文件做只读取证副本。

## 4. Windows 首次配置

Windows 必须先初始化超管密码和离线恢复介质，才能创建第一个 profile。

### 4.1 使用 UI 初始化

1. 启动 serctl UI。
2. 点击左侧“安全与恢复”。
3. 选择初始化超管与恢复策略。
4. 输入并确认新的超管密码。
5. 选择一个不存在的绝对文件路径，例如 U 盘上的 `E:\serctl-recovery-2026-01.srrec`。
6. 初始化成功后，将介质安全弹出并离线保存。

新介质路径必须满足：

- 使用绝对路径；
- 文件不得已经存在；
- 不得位于 `.serctl` 内；
- 应位于只有操作者可写的可信目录，推荐使用可移除介质。

### 4.2 使用 CLI 初始化

```powershell
$Media = 'E:\serctl-recovery-2026-01.srrec'
& $Serctl admin status
& $Serctl admin init --recovery-media $Media
```

命令会交互输入并确认超管密码。密码不会进入命令行参数。

初始化后检查状态：

```powershell
& $Serctl admin status
& $Serctl admin verify
```

## 5. 创建第一台主机

### 5.1 使用 UI

1. 点击“＋ 新建主机”。
2. 填写名称、地址、端口和 SSH 用户。
3. 输入 SSH 密码。
4. 如已从可信渠道取得主机指纹，填写 `SHA256:...` 指纹。
5. 输入并确认只属于这台主机的独立口令，至少 12 字节。
6. 点击“保存”。
7. Windows 如尚未取得超管授权，会自动打开“安全与恢复”。完成超管验证后，serctl 会继续原来的保存动作。

不同主机必须使用不同的 profile 口令。不要把超管密码、Windows 登录密码或 SSH 密码重复用作 profile 口令。

### 5.2 使用 CLI

```powershell
$Fingerprint = 'SHA256:请替换为真实指纹'
& $Serctl add prod `
  --host 192.168.5.15 `
  --user deploy `
  --port 22 `
  --host-key-sha256 $Fingerprint
```

命令会根据需要依次询问 SSH 密码、profile 独立口令和 Windows 超管密码。省略名称时使用 `default`：

```powershell
& $Serctl add --host server.example.internal --user operator
```

首次连接未预置指纹时使用 TOFU：serctl 会先观察并持久化主机密钥 pin，再发送 SSH 密码。TOFU 无法自行排除首次连接中的中间人攻击，建议预先通过独立可信渠道核对指纹。

## 6. UI 日常使用

### 6.1 选择和授权主机

左侧列表在锁定状态下只显示 profile 名称、地址和端口，不会连接远程主机。

1. 选择一个 profile。
2. 在顶部输入该 profile 的独立口令。
3. 点击“授权 5 分钟”。
4. 授权成功后才能查询连接状态和使用工作区。

授权有效期固定为五分钟，不会因为继续操作而延长。切换 profile 不会把授权转移给另一台主机。“撤销此主机”仅撤销当前 profile；“全部锁定”撤销所有 profile 授权。

授权到期或撤销后，serctl 会停止该 profile 的 shell、隧道和传输；后台 daemon 本身可以继续运行。

### 6.2 连接状态

- “连接”启动或复用全局 broker，并在 broker 中解锁当前 profile；实际 SSH 连接会在远程操作需要时建立。
- “断开”会请求停止全局 broker，因此其他 profile 的活动 SSH 会话也会断开；它不会自动撤销仍在有效期内的 UI profile 授权。
- “刷新”总是刷新本地 profile 列表，但只探测仍有有效授权的 profile。

编辑、安全轮转和删除前，应先断开正在使用该 profile 的连接。建立过 authenticated audit material 的 profile 当前不能删除；这不是连接占用错误，而是 v1 beta 为避免丢失审计可验证性而设置的失败关闭边界。

### 6.3 命令页

1. 输入远程命令。
2. 点击“执行”或按 Enter。
3. 分别检查输出和退出码。

非零远程退出码会作为失败返回。若出现“执行结果未知”，不要立即重复执行有副作用的命令；先在远端核对操作是否已经发生。

### 6.4 文件页

文件页支持：

- 输入远程路径并刷新；
- 双击目录进入，点击“↑”返回上级目录；
- 创建远程目录；
- 上传本地普通文件；
- 下载选中的远程文件。

上传和下载都不会覆盖已有目标。上传要求 SSH 服务端支持 OpenSSH `hardlink@openssh.com` 扩展；不支持时 serctl 会安全失败，不降级为可能覆盖目标的重命名操作。

文件页现在显示结构化传输卡：阶段、远端确认字节、进度条、3 秒窗口速度、平均速度、ETA、实际 backend、chunk/window 与 transfer id，并可取消。进度不按本地读取或 IPC 写入量虚报；只有完整性验证和 no-overwrite commit 都成功后才显示 100%。`auto` 会先探测固定命令 `serctl-xfer serve --stdio`：兼容 helper 存在时显示 `native`，否则明确显示 `sftp_fallback`。勾选“启用断点续传”后 helper 不可用会失败关闭，不会悄悄降级成不可恢复的 SFTP。

若上传或创建目录提示“提交结果未知”，应先检查远端最终路径和可能存在的 `.serctl-part-*` 临时文件，再决定是否重试。

### 6.5 Bash 页

点击启动 Bash 后可交互输入命令，并可发送 `Ctrl+C`、`Ctrl+D` 或清屏。关闭 UI、撤销授权或授权到期会终止对应 shell。

远端 PTY 输出被当作终端内容显示。不要把不可信程序生成的任意控制字符输出直接交给交互终端。

### 6.6 隧道页

支持三种模式：

| 模式 | 数据路径 |
| --- | --- |
| 本地转发 | 本机 `127.0.0.1:监听端口` → SSH 主机 `127.0.0.1:目标端口` |
| 远程转发 | SSH 主机 `127.0.0.1:监听端口` → 本机 `127.0.0.1:目标端口` |
| 动态转发 | 本机 `127.0.0.1:监听端口` 上的 SOCKS5 CONNECT 代理 |

监听端口填 `0` 时由操作系统选择。默认最大并发连接数为 32，硬上限为 128。

所有固定监听地址和固定目标地址都强制为 `127.0.0.1`，UI/CLI 不接受外部绑定地址。动态 SOCKS5 使用 `NO AUTH`，虽然只监听回环地址，但同一台计算机上的其他进程仍可能使用它。

## 7. CLI 日常操作

### 7.1 查看 profile

```powershell
& $Serctl list
```

`list` 不需要口令，只显示 profile 名称、地址、端口和 generation，不会解密 SSH 凭据。

### 7.2 启动 broker

通常无需手动启动；`exec`、`shell`、传输和隧道会按需启动后台 broker。

需要前台观察生命周期时：

```powershell
& $Serctl up
```

`up` 只启动全局 broker，不会预先解锁某个 profile。可选的旧式名称参数仅为兼容保留；每次业务命令仍会验证其目标 profile 的独立口令。按 `Ctrl+C` 正常结束前台 broker。

### 7.3 执行命令

```powershell
& $Serctl exec prod --timeout-secs 30 -- 'uname -a; whoami'
```

默认超时为 300 秒。远端返回非零状态时，serctl 也返回非零本地退出码。

`exec` 只提供一次性、absolute-deadline 约束的远程执行，不支持 daemon 重启后恢复、跨进程查询命令进度或可靠取回已越过 deadline 的最终退出状态。W2 vendor Linux 冷构建先在 900 秒边界没有 Cargo/测试终态；后续外层 1,200 秒请求也返回 timeout，但独立只读校验发现同一命令已经写入 `BUILD-READY-v1` receipt（SHA-256 `b1e8041912e6e1838ee2f9c2ec0405bf92a5fbfd52d54120a66d85fb5239564c`）。因此 timeout 首先必须归类为 `unknown`，只有预先约定、严格绑定输入和输出身份且经独立读取验证的 receipt 才能恢复成功状态。对于长时间编译，建议把 `fetch/vendor`、`cargo test --no-run`、测试执行和结果收集拆成独立阶段，将日志、退出码与 receipt 原子写入远端受控目录，再用新的短命令查询；内层远端命令应早于外层 relay deadline 结束，并至少预留三分钟用于 marker、终态读取和清理。当前产品尚未提供心跳进度或可恢复命令状态查询。

### 7.4 交互 shell

```powershell
& $Serctl shell prod
```

省略名称时使用 `default`。

### 7.5 上传与下载

```powershell
& $Serctl transfer push prod '.\request.json' '/tmp/request.json' `
  --backend auto --resume never --idle-timeout-secs 30 --deadline-secs 120
& $Serctl transfer pull prod '/tmp/result.json' '.\result.json' `
  --backend auto --resume never --idle-timeout-secs 30 --deadline-secs 120
```

本地和远端目标已存在时均不会覆盖。TTY 显示结构化进度；非 TTY 默认逐行输出无 ANSI 的 JSON。也可显式使用 `--progress tty|json|quiet`。`transfer status prod [TRANSFER_ID] --watch --json` 可从另一已授权客户端读取同 profile 的脱敏快照，`transfer cancel prod TRANSFER_ID` 可取消活动传输。registry 同时最多允许每 profile 8 个、全局 48 个 active transfer；终态最多保留 15 分钟，只保留每 profile 最新 16 个、全局 256 个，状态响应保持在 IPC 控制帧上限内。

SFTP fallback 固定使用保守的 2 KiB chunk 和单 WRITE/STATUS 窗口；每个 WRITE 都必须收到 request-id 匹配的远端 SFTP STATUS 后才推进 `confirmed_bytes`。native 候选使用 32 KiB，并保持严格的一块/一个 helper ACK lockstep；因此进度中的 `window_bytes` 报告实际 32 KiB，而不是 helper 可协商的 8 MiB durability/receiver 上限。mock E2E 已覆盖双向传输、首个 helper ACK 前 `confirmed_bytes=0`、no-overwrite、idle stall 与 cancel；Local-Linux2 的 1,298,223 B/64 MiB/1 GiB SHA-256 矩阵和同机 `scp` ≥80% 对比仍未完成，当前没有 native 实机或吞吐验收结论。

`--resume auto` 使用 profile id/generation 绑定的受保护 journal。上传恢复还要求 schema 2 远端 sidecar 的 token hash、transfer id、size、SHA-256、durable offset、partial device/inode 与 receiving/committed state 全部一致；初始 sidecar 必须 create-new，后续原子替换前也会重新验证上述所有权绑定及精确旧 offset/state，未知既有 sidecar 不会被覆盖。下载恢复要求远端重新报告的 size/SHA-256 与 journal 一致，并只保留已同步的本地连续前缀。任一项不符都会安全拒绝，且不会截断未知文件。committed receipt 当前没有消费 ACK/GC/保留期，只能由同一 id/token 的显式恢复请求对账。默认仍为 `--resume never`。旧 `upload` / `download` 命令暂作兼容别名，但不提供新的可观测参数。

恢复被接受时会出现 `resumed` 事件，速度与 ETA 从既有 durable prefix 之后重新计量。Linux descriptor-bound `linkat` 明确返回失败时，目标链接没有创建并返回确定性的 `transfer_failed`；`outcome_unknown` 只用于链接成功后无法完成目标身份复核或 parent fsync 的终态丢失。`cleanup_incomplete` 表示经过身份验证的 partial/sidecar 清理没有全部完成，既可能发生在目标已提交之后，也可能发生在首次 sidecar 持久化失败而新 partial 无法安全删除时。后两者都不得直接重试，应先独立核对目标的 size/SHA-256 与 partial/sidecar 状态；`resume=never` 没有 receipt 恢复保证。

native helper 必须是与远端操作系统/架构匹配的 `serctl-xfer`，由 SSH 用户拥有、不可被其他用户写入、具有执行权限，并位于该用户非交互 SSH exec 的 `PATH`。当前仓库尚未提供签名包驱动的 `transfer bootstrap`，因此首次安装需通过可信的软件包/运维通道完成；不要把本机 Windows `serctl-xfer.exe` 上传到 Linux，也不要用 `ssh.exec` + Base64 分块冒充 bootstrap。未满足这些条件时使用 `--backend auto --resume never` 可明确回退到 SFTP。

当前生产 native helper server 只支持 Linux 远端的 durability/no-follow/no-replace 语义。macOS、BSD 与 Windows helper 会在能力 Hello 前失败关闭，不会宣称可用；Windows 本地 CLI 到 Linux 远端仍可使用 native，其他远端则应选择 `auto` 并接受明确的 SFTP fallback。Linux 提交依赖 `/proc/self/fd`、`linkat` 与 parent-dirfd fsync；本轮 Windows 主机只完成 Linux target 交叉编译/Clippy，正式启用前仍须 Ubuntu 实机验证。

### 7.6 隧道

```powershell
# 本地 127.0.0.1:15432 → SSH 主机 127.0.0.1:5432
& $Serctl tunnel prod local --port 15432 --target-port 5432

# 本地 SOCKS5 127.0.0.1:1080
& $Serctl tunnel prod dynamic --port 1080

# SSH 主机随机回环端口 → 本机 127.0.0.1:8080
& $Serctl tunnel prod remote --port 0 --target-port 8080
```

隧道在前台运行，按 `Ctrl+C` 停止。

### 7.7 状态与停机

```powershell
& $Serctl status prod
& $Serctl down prod
```

两条命令都先验证目标 profile 口令。`status` 只显示 daemon 生命周期信息，不会测试 SSH 健康状态或触发重连。

### 7.8 编辑和删除

使用相同名称执行 `add` 会更新已有 profile，并要求该 profile 当前独立口令：

```powershell
& $Serctl add prod --host 192.168.5.16 --user deploy --port 22
```

更新时必须重新提供完整 SSH 凭据。删除：

```powershell
& $Serctl remove prod
```

`remove` 只对尚未建立任何 authenticated audit material 的 profile 可用；一旦该 profile 的审计 generation 已初始化或磁盘上存在审计材料，命令即失败关闭。该限制当前没有“删除日志后重试”的安全绕过方式；不要手工删除 ledger/checkpoint。若一个未审计 profile 确实删除成功，该操作不可撤销，随后用相同名称重建也会获得新的随机 profile identity，旧授权不能复用。

## 8. profile 口令管理

### 8.1 手动更改

```powershell
& $Serctl profile-password prod change
```

先验证当前 profile 口令，再输入并确认新口令。成功后 generation 增加，旧 UI 授权和旧调用密钥立即失效。

### 8.2 随机轮转

```powershell
$Receipt = 'C:\Users\Administrator\Documents\serctl-prod-passphrase.txt'
& $Serctl profile-password prod rotate-random --random-output $Receipt
```

回执必须是绝对路径且文件不得存在。serctl 会先安全创建、同步并回读随机口令文件，成功后才修改 vault。

命令失败时应区分：

- 回执写入失败：vault 未修改，旧口令仍有效；
- 回执已创建但 vault 提交失败：回执中的随机值尚未生效；
- 命令明确成功：立即将随机口令导入密码管理器，再安全销毁过渡回执。

UI 的随机轮转不会写回执文件，而是先一次性显示随机口令。只有勾选“已安全保存”并确认提交后才修改 vault；取消会清零暂存值。

## 9. Windows 超管与离线恢复

### 9.1 更改超管密码

```powershell
& $Serctl admin change-password
```

该操作只重新包裹本机恢复 share，不改变任何 profile 口令或 SSH 凭据。

### 9.2 忘记 profile 口令但保留 SSH 凭据

需要超管密码和匹配的离线介质：

```powershell
& $Serctl profile-password prod admin-reset --media 'E:\serctl-recovery-2026-01.srrec'
```

命令会为 profile 设置新的独立口令，但不会显示旧口令。也可生成随机新口令：

```powershell
& $Serctl profile-password prod admin-reset `
  --media 'E:\serctl-recovery-2026-01.srrec' `
  --random `
  --random-output 'C:\Secure\prod-new-passphrase.txt'
```

### 9.3 破坏性替换当前失败关闭

`profile-password NAME admin-reset --replace-credentials` 的参数仍存在，以便旧脚本获得明确、可诊断的拒绝；但 v1 beta 候选对**所有既有 profile** 都拒绝这条 destructive 路径，包括 Windows 超管入口与 Linux root `--target-user` 入口。原因是只持有管理员授权无法认证并衔接旧 profile 的 audit history，直接替换会破坏审计代际链。

不要删除 ledger/checkpoint、清空 `audit_initialized` 或编辑 vault 来绕过。已知旧 profile 口令时使用 `profile-password NAME change`/`rotate-random`；Windows 忘记口令时使用 9.2 节的“超管密码 + 匹配离线介质”2-of-2 保留式恢复，该流程仍能保留 SSH 凭据、生成新 DEK/AuthSeed 并建立认证的 successor audit generation，且不会显示旧口令。没有旧口令也没有匹配介质时，当前版本没有安全的就地替换方案；应保留证据并等待后续具备审计退役协议的版本。

### 9.4 轮转恢复介质

```powershell
& $Serctl recovery rotate `
  --old-media 'E:\serctl-recovery-2026-01.srrec' `
  --new-media 'F:\serctl-recovery-2026-02.srrec'
```

新介质路径必须不存在。命令成功后，当前 vault 不再接受旧介质。验证新介质已安全保存后，再按组织策略退役旧介质。

## 10. 从 v2 迁移到当前 storage v5

v2 使用共享主口令；当前独立 profile 架构要求每个 profile 有独立口令。候选的精确存储契约为 `vault-storage read=v4..=v5 write=v5`：顶层 `VaultFile` 和每个 profile 的外层加密 record 都读 v4/v5、只写 v5。v2 迁移只在 Windows 实现，并且是全量原子操作；成功时一次性写入顶层 vault v5 与全部 record v5。

迁移前：

1. 关闭所有旧版 UI、CLI 和 daemon。
2. 使用匹配旧 daemon 的旧程序正常停机，不要直接删除锁文件。
3. 备份旧 `vault.json`。
4. 准备一个不存在的新恢复介质路径。
5. 为每个 profile 准备不同的新独立口令。

执行：

```powershell
& $Serctl recovery migrate-v2 `
  --recovery-media 'E:\serctl-v5-recovery.srrec'
```

程序会依次要求旧共享主口令、每个 profile 的新独立口令和新 Windows 超管密码，并显示验证、独占访问、逐 profile 转换、介质持久化和原子提交进度。

任何一步失败时，旧 v2 vault 应保持不变。对未修改的 beta-2 storage v4 vault，候选可直接读取；首次成功 mutation 必须在同一受保护原子替换中推进顶层为 v5，并把受影响 record 重密封为 v5。此后 beta-2 旧 reader 必须在任何写入前失败关闭；不能只回退二进制，必须恢复精确的升级前 vault、匹配恢复介质及 ACL/owner。Linux 当前没有保留凭据的 v2 全量迁移路径。

## 11. 自动化与 Agent 网关

### 11.1 环境变量注入

自动化可使用：

| 变量 | 内容 |
| --- | --- |
| `SERCTL_SSH_PASS` | SSH 密码 |
| `SERCTL_PROFILE_PASS` | 目标 profile 独立口令 |
| `SERCTL_ADMIN_PASS` | Windows 超管密码 |
| `SERCTL_LEGACY_MASTER` | 仅 v2 迁移使用的旧共享主口令 |
| `SERCTL_MASTER` | 兼容旧脚本，不推荐新部署使用 |

环境变量可能被父进程、同权限进程、调试器或日志系统观察。高价值凭证优先使用交互输入，不要把秘密直接放入脚本、任务参数或 shell 历史。

### 11.2 有界 OperationGrant

签发带操作范围、次数预算和显式 TTL 的 grant。默认 TTL 为 30 分钟，允许范围为 1–40 分钟；CLI 和 daemon 都会独立拒绝越界值：

```powershell
& $Serctl grant-issue prod `
  --operations ssh.exec,daemon.status,sftp.list,sftp.write,transfer.read,transfer.write,transfer.status,transfer.cancel `
  --budget 20 `
  --ttl-minutes 40 `
  --output 'C:\Secure\prod-agent-grant.json'
```

启动 JSONL stdio 网关：

```powershell
& $Serctl agent --grant 'C:\Secure\prod-agent-grant.json'
```

自动化宿主也可以使用继承对象，避免把 profile 口令或 Grant 放入 argv、环境变量或可被重新解析的路径：

```text
serctl_cli grant-issue prod --operations ssh.exec --profile-passphrase-handle HANDLE_OR_FD --output-handle HANDLE_OR_FD
serctl_cli agent --grant-handle HANDLE_OR_FD
serctl_cli tunnel prod --profile-passphrase-handle HANDLE_OR_FD dynamic
```

`HANDLE_OR_FD` 必须是十进制 Windows `HANDLE` 或 Unix fd。调用者负责安全创建并继承对象，然后把所有权转交给 serctl；serctl 只操作该已打开对象，有界读取到 EOF 或在同一对象上写入、flush、durable sync，最后关闭，不会把它转换成路径重新打开。profile 口令输入最多 16 KiB 且必须为 UTF-8，可带一个结尾 LF/CRLF；Grant 输入最多 64 KiB。`--output-handle` 必须指向调用者以 create-new 语义打开的空保护常规文件，当前位置必须为 0。path、环境与 handle 来源互斥；不要在父进程保留该 handle 的重复副本。当前源码回归和真实子进程继承 E2E 只在 Windows 完成；Unix cfg、各 exact-tag 原生 runner 和跨账号 ACL 仍须独立验收，不能用 Windows 本地通过替代。

v1 候选的 stdin/stdout 都是严格 NDJSON：每行恰好一个 JSON 对象，不输出 ANSI；去除行终止符后的请求 payload 最多为 1 MiB，读取器总上限额外容纳一个 LF（CRLF 中的 CR 会占 payload 预算）。超限会失败关闭并终止网关而不是回显或解析无界输入。所有请求都必须携带整数 `schema_version: 1` 和调用方唯一的 `request_id`；未知字段、未知操作、类型错误或缺少必需字段失败关闭。无效 JSON/shape 只返回固定的 `invalid request (diagnostic detail withheld)`，不会回显原请求或 serde/parser 细节。

请求示例，每行一个 JSON 对象：

```json
{"op":"status","schema_version":1,"request_id":1}
{"op":"exec","schema_version":1,"request_id":2,"cmd":"uname -a","timeout_ms":30000}
{"op":"list-dir","schema_version":1,"request_id":3,"path":"/tmp","timeout_ms":30000}
{"op":"create-dir","schema_version":1,"request_id":4,"path":"/tmp/example","timeout_ms":30000}
{"op":"transfer-push","schema_version":1,"request_id":5,"transfer_id":"0123456789abcdef0123456789abcdef","local":"C:\\staging\\archive.tar.zst","remote":"/tmp/archive.tar.zst","backend":"auto","resume":"never","idle_timeout_ms":30000,"deadline_ms":300000}
{"op":"transfer-pull","schema_version":1,"request_id":9,"transfer_id":"fedcba9876543210fedcba9876543210","remote":"/srv/evidence.bin","local":"evidence.bin","backend":"sftp","resume":"never","idle_timeout_ms":30000,"deadline_ms":300000}
{"op":"transfer-status","schema_version":1,"request_id":6}
{"op":"transfer-status","schema_version":1,"request_id":7,"transfer_id":"0123456789abcdef0123456789abcdef"}
{"op":"transfer-status","schema_version":1,"request_id":10,"transfer_id":"0123456789abcdef0123456789abcdef","operation_context_id":"abababababababababababababababababababababababababababababababab"}
{"op":"transfer-cancel","schema_version":1,"request_id":8,"transfer_id":"0123456789abcdef0123456789abcdef","operation_context_id":"abababababababababababababababababababababababababababababababab"}
```

每个结果也占一行。成功结果包含 `schema_version`、原 `request_id`、`ok:true` 与 `data`；失败结果包含 `ok:false`、稳定的 `error_code` 和只供人阅读的 `error`，不含 `data`。调用方只能按 `error_code` 分支，不得解析或持久依赖可能脱敏、改写的错误文本。无效 JSON 无法可信恢复 request id，因此返回 `request_id:0`；能解析但 schema 不支持时保留请求中的 id。

```json
{"schema_version":1,"request_id":8,"ok":true,"data":{"transfer_id":"0123456789abcdef0123456789abcdef","operation_context_id":"abababababababababababababababababababababababababababababababab","revision":5,"cancel_requested":true}}
{"schema_version":1,"request_id":8,"ok":false,"error_code":"agent.scope_denied","error":"grant does not authorize transfer.cancel"}
```

稳定错误类别为：`agent.invalid_request`（JSON/字段/操作无效）、`agent.schema_unsupported`（schema 不是 1）、`agent.scope_denied`（14 类操作中的任一请求缺少其精确 scope）和 `agent.operation_failed`（其余执行失败）。scope 拒绝只会指出所需的公开 operation kind；所有非 scope 操作错误都压缩为固定的 operation-level `diagnostic detail withheld` 文本，不向 stdout 转发请求值或底层 anyhow/daemon/SSH/SFTP 错误链。错误文本不是兼容性承诺；v1 验收还必须证明其中不会泄露本地绝对路径、grant 私钥、profile/SSH 口令、被拒 JSON 或底层敏感错误链。

grant 文件同时包含 agent 私钥，应按密码文件保护。文件中序列化的 profile/scope/budget/expiry metadata 只用于 Agent 侧 fail-fast 和在缺少 scope 时阻止命令/路径校验、本地文件打开或 daemon 启动；它是 advisory preflight，不是最终授权根。同一 OS 用户即使改写这些字段，也不能扩大远端权限：daemon 只信任当前实例内 registry 中登记的签名 root intent，并重新核对 holder PoP、profile name/id/generation、精确 scope、预算与单调过期时间。40 分钟是当前策略硬上限，只应用于有明确 owner、操作范围和预算的单次长任务，并为业务运行与结果读取留出余量；它不会延长单个远端请求自身声明的 deadline。daemon 会在 Grant 有效期间保持运行，避免空闲退出丢失内存登记；Grant 过期后才恢复正常的空闲退出。若 daemon 因人工操作、升级或崩溃而重新启动，旧文件不会被新实例直接信任，必须重新签发。此时错误会明确报告“未在当前 daemon 实例登记”，而不会与“已过期”合并。过期、超预算或超出操作范围后同样必须重新签发。

`--operations` 只接受 Agent JSONL 已实现且 daemon 明确列入可签发集合的 14 个精确操作种类：`ssh.exec` 执行命令，`ssh.connection-identity` 查询已认证且 host-key pin 匹配的连接身份，`daemon.status` 查询状态，`sftp.list` 列目录，`sftp.write` **只允许 `create-dir`**，`transfer.read` 允许 `transfer-pull`，`transfer.write/status/cancel` 分别允许 `transfer-push/status/cancel`，`forward.local/open`、`forward.remote/open`、`forward.dynamic/open` 分别允许三种受管隧道启动，`forward.status` 与 `forward.cancel` 分别允许查询和取消。JSON envelope 与 schema 检查后，这 14 类请求都把精确 scope 作为首个 operation-specific gate：缺 scope 时在命令/路径/端口/deadline 语义校验、本地文件打开、哈希、目标解析/存在性检查、daemon 发现/启动、IPC、listener 或远端 I/O 前返回 `agent.scope_denied`；daemon 仍会对签名根 intent 复核授权。transfer/tunnel 的 read、write/open、status 和 cancel 权限彼此独立，并保持同一 profile id/generation 隔离；`forward-status` 不带 id 时只返回该 Grant profile 的有界活动/近期快照。`sftp.read` 和所有 `job.*` 仍不可签发。`sftp.write` 不包含 grant-backed upload，顶层兼容命令 `upload` 也不接受 `--grant`；`ssh.exec` 不能替代 transfer、forward 或 connection-identity scope。Agent push/pull 各自使用一个经过 PoP 认证的 `transfer.write`/`transfer.read` 根 intent，后续 chunk/ack 不单独消耗 grant budget，且不会读取 profile 口令。

`transfer-pull` 的 `transfer.read` 校验早于远端路径验证、本地目标解析/存在性检查、resume journal 和 daemon 发现，因此无权 Grant 不能把它当本地路径 oracle。客户端将绝对本地目标绑定成 SHA-256 commitment，根 IPC 不传本地路径；本地保持 protected `CREATE_NEW` 与 no-overwrite。其 stdout 保持 terminal-only，实时进度由独立 `transfer-status`/`transfer.status` 请求观察。Grant-backed transfer 的终态与 progress/status 包含 daemon 生成的 64 位 `operation_context_id` 和正数单调 `revision`；首次精确按 id 查询可发现 context，后续 status 和全部 cancel 必须回传它。成功的 `status`、`ssh-connection-identity`、`exec`、`list-dir` 与 `create-dir` 一次性终态也各自返回独立 context 与固定 `revision=1`，不能跨根操作替换。`status` 不建立 SSH 连接，使用明确的 no-SSH-transport 域标记而不伪造 transport attempt。形式化 runner 仍因 exact-tag 组件、真实 Grant/远端与跨平台实证未齐而 BLOCKED。

Agent 受管隧道请求名为 `forward-local-open`、`forward-remote-open`、`forward-dynamic-open`、`forward-status` 和 `forward-cancel`。open 不接受地址；listener 与固定目标强制为 `127.0.0.1`。ready 后由 daemon registry 持有。结果输出 `tunnel_id`、mode、stage、回环 bind host/port、deadline、64 位 `operation_context_id` 与正数 `revision`，不输出 profile identity 或远端地址。首次精确按 tunnel id 查询可不带 context 以发现它，后续 status 与全部 cancel 必须携带 context；状态变化只推进 revision。SSH/清理终态不确定返回 `unknown`，不能伪造 `closed`。

`ssh-connection-identity` 没有请求专用字段，但它会认证、复用或重连目标 SSH transport，并非离线 metadata 查询。成功结果固定为 profile id/generation、观察到的 `SHA256:` host-key fingerprint、恒真的 `pin_match`、最长 128 字节且仅含安全可打印 ASCII 的 SSH server identification、不透明的 32 位大写十六进制 transport attempt id、daemon 生成的 64 位小写十六进制 `operation_context_id`，以及固定 `revision=1`；不含 host/port、用户名、路径、pre-banner/raw banner 或凭据。`exec` 与 `list-dir` 的成功终态同样追加 context 与 `revision=1`。认证前失败、未观察到 host key、pin 不匹配、server identification 不安全或 profile/generation 失配时不返回部分身份。

以上新增 schema/error/transfer/tunnel/connection-identity 行为属于 v1.0.0-beta.3 候选，只有源码 handler、daemon 可签发列表、自动契约检查和 exact-tag 真实 OpenSSH/Dropbear E2E 同时通过后才成为已验收能力；当前预发布标记已同步为 v1.0.0-beta.3，但不因此视为已验收。

外部验收工具已加入有界进程监管原语，约束未来 runtime adapter 只能以绝对可执行文件和参数数组启动固定进程，并对 stdout/stderr、deadline 与进程树退出设限。当前仅有 Windows PowerShell 合成测试；仓库仍没有能产生真实 native/interop 子 receipt 的受控 adapter，因此该原语不能被解释为跨平台、真实 SSH、native、性能或发布验收通过。

### 11.3 Grant 根请求审计与 Unknown 恢复

v1 候选的 authenticated local audit ledger **只覆盖经 OperationGrant 授权的根请求（Grant-root only）**，不等于全部 CLI/UI/SSH 操作日志。每条记录同时包含哈希链连接和独立 `record_mac`，checkpoint 也以 HMAC 绑定 profile id、generation、序号与链头；攻击者不能只重算公开 hash 后伪造 Outcome/Administrative 记录。密钥来自 KeyPackage 中独立、非零的 `AuditSeed`，与 IPC `AuthSeed` 分域：generation 变化时 DEK 和 `AuthSeed` 重新随机化，`AuditSeed` 为认证 predecessor/successor transition 而保持稳定。这样旧 `AuthSeed` 不能授权新 generation 的 IPC，但旧完整 KeyPackage 泄露仍可能影响后续 generation 的审计密钥，这是当前残余风险。

beta-2 旧 KeyPackage 没有 `AuditSeed`。其第一次认证升级仅在 `audit_initialized=false` 且 seed 为零时，以 DEK 为 HMAC key、绑定版本化域/profile id/generation 确定性派生并持久化独立 seed；确定性用于 log-only/pair-only 崩溃重试，不会复用或回退到 `AuthSeed`。一旦 `audit_initialized=true`，缺 seed、缺 ledger/checkpoint、损坏记录 MAC 或未配对 Intent 都失败关闭。daemon 重启时会验证 ledger，发现未配对 Intent 时隔离该 profile，而不会猜测操作是否成功。

只读检查需要该 profile 的独立口令，并从口令验证到检查结束持有独占 profile lease：

```powershell
& $Serctl audit status prod --json
& $Serctl audit status prod `
  --anchor 'E:\Offline\prod-audit-anchor.json' `
  --anchor-output 'E:\Offline\prod-audit-anchor-next.json'
```

`--anchor FILE` 要求当前 ledger/checkpoint 与先前导出的 authenticated checkpoint 一致，可发现相对于该文件的本地回滚。`--anchor-output NEW_FILE` 只写 checkpoint，不含口令、SSH 凭据或审计密钥，并限制为最多 16 KiB 的 regular non-link file，强制 create-new、同句柄写后回读和路径/父目录身份复核：目标已存在时拒绝覆盖。为允许直接写入 FAT/exFAT 离线介质，Windows 不强制 NTFS protected DACL，文件继承父目录 ACL；Windows 也没有可移植的目录 fsync，父目录 flush 在特定 unsupported/permission 情况下只能 best-effort。文件内容由 MAC 防伪，但机密性、目录访问控制、断电后目录项持久性和离线保管仍由操作者负责。请把每一代 anchor 离线保存并记录保管流程，不要通过编辑或覆盖旧文件“更新”锚点。

若检查报告 pending Intent，唯一自动恢复动作是显式追加 `Unknown`：

```powershell
& $Serctl audit resolve-unknown prod `
  --acknowledge-unknown-outcome `
  --anchor 'E:\Offline\prod-audit-anchor.json' `
  --anchor-output 'E:\Offline\prod-audit-anchor-after-recovery.json' `
  --json
```

命令先验证完整 HMAC 链、checkpoint 与可选 anchor，再对每个已认证 pending Intent 追加 operation kind、policy digest 和 intent digest 均精确匹配的终态记录；decision 固定为 `Unknown`。必需的 `--acknowledge-unknown-outcome` 表示操作者接受“没有推断远端成功/失败”，它不是强制标成失败或成功的开关。操作期间持有同一个独占 profile lease；如果 ledger/anchor 验证或追加失败，保持失败关闭。恢复后的 anchor 导出失败不撤销已经追加的 Unknown，CLI 会明确报告这个顺序边界。

手工导出的 anchor 仍不构成独立、单调的 external trust domain：serctl 不能证明它确实位于离线介质、不能阻止本机管理员同步回滚 vault、所有 generation 的 ledger/checkpoint 和所提供的 anchor，也没有远端 transparency log。因此当前能力可以检测无密钥篡改、截断、重排和相对已保留 anchor 的回滚，但不能宣称完整审计闭环或跨快照 rollback protection；真正独立的外部锚/远端透明日志仍是 stable 1.0 阻断项。

## 12. Linux 与 macOS 差异

- Linux 不保存独立超管密码，管理授权使用有效 UID 0。
- `--target-user USER --replace-credentials` 入口仍会验证 root、NSS 非 root 目标、home/vault owner/type/mode，并在打开目标 vault 前不可逆降权；但 v1 beta 候选随后对每个既有 profile 的 destructive admin reset 失败关闭，因为它不能认证旧审计历史。该入口当前不是可用的凭据替换方案。
- Linux 的离线保留式恢复、恢复介质轮转和 v2 全量迁移到当前 storage v5 也失败关闭。不要通过 root 直接编辑 vault 或删除 ledger/checkpoint 绕过。
- macOS 只参加源码构建/测试矩阵；本 beta 不发布 macOS runtime，生产 native helper 也保持禁用。

## 13. 常见故障

### 13.1 找不到 serctl_daemon

错误通常表示 `serctl_daemon[.exe]` 不在 `serctl_cli[.exe]` 同一目录。将同一构建/发行版本的两个程序放回同一目录，不要从其他版本复制 daemon。

### 13.2 口令正确但 profile 无法使用

检查：

1. 是否选中了正确 profile；
2. 是否在编辑/轮转后仍使用旧 generation 的授权；
3. 当前运行 daemon 是否来自同一版本；
4. 是否恢复了旧 vault，但仍使用新介质或新口令；
5. 主机密钥是否已经变化。

不要通过删除锁文件或修改 vault JSON 绕过错误。

### 13.3 主机密钥不匹配

先通过独立可信渠道核对服务器的新指纹。确认服务器确实重装或更换密钥后，再在断开状态下更新 profile。无法确认时应按潜在中间人攻击处理。

### 13.4 上传失败并提示不支持 hardlink

远端 SFTP 服务没有声明 `hardlink@openssh.com`。serctl 不会退化为可能覆盖目标的上传方式。应升级/调整 SSH 服务端，或使用经过独立审查的其他传输流程。

### 13.5 执行、上传或创建目录“结果未知”

这表示请求可能已经越过远端提交边界，但确认响应丢失。先检查远端命令副作用、目标文件或目录，再决定是否重试。不要把未知结果当成失败后直接重复。

### 13.6 vault 中出现测试 profile

如果真实 vault 中出现 `v6test`、`e2e`、`tester` 或回环测试地址：

1. 立即关闭 serctl 和所有测试进程；
2. 不要初始化、保存、轮转或删除任何 profile；
3. 记录当前 `vault.json` 的大小、时间和 SHA-256，不输出文件内容；
4. 查找覆盖前的 vault 备份、文件历史、卷影副本或离线磁盘镜像；
5. 不要只凭恢复介质尝试重建，恢复介质必须与旧 vault 配对；
6. 在修复测试隔离前，只在没有真实 vault 的专用系统账户运行串行测试。

若旧 vault 已被原子替换且没有备份，应停止向原磁盘写入，并从另一块物理磁盘进行离线文件恢复或交给专业数据恢复人员。

## 14. 安全操作清单

- 为每个 profile 使用不同且足够长的独立口令。
- 超管密码不得与 Windows、SSH 或 profile 口令复用。
- 通过独立渠道核对首次 SSH 主机密钥指纹。
- 将 vault 与匹配的恢复介质分开备份。
- 介质轮转后更新配对备份并安全退役旧介质。
- 不在 `.serctl` 内保存恢复介质或随机口令回执。
- 不把密码写入命令行参数、脚本、日志或 shell 历史。
- 使用完动态 SOCKS5 后立即停止，避免同机其他进程借用。
- 升级前先用旧版本正常停止旧 daemon，再整体替换两个二进制。
- 不手工修改 `vault.json`、ACL、锁文件或运行描述符。
- 不在存有真实 vault 的账户运行并行测试。
- 对任何“提交结果未知”先核对远端副作用，再重试。

## 15. 命令速查

```text
serctl_cli [ui]
serctl_cli add [NAME] [--host H] [--user U] [--port P] [--host-key-sha256 SHA256:...]
serctl_cli list
serctl_cli remove NAME  # 已有 authenticated audit material 时失败关闭

serctl_cli admin status
serctl_cli admin init --recovery-media FILE
serctl_cli admin verify
serctl_cli admin change-password

serctl_cli profile-password NAME change
serctl_cli profile-password NAME rotate-random --random-output FILE
serctl_cli profile-password NAME admin-reset --media FILE [--random --random-output FILE]
serctl_cli profile-password NAME admin-reset --replace-credentials [OPTIONS]  # 既有 profile 当前失败关闭

serctl_cli recovery rotate --old-media FILE --new-media FILE
serctl_cli recovery migrate-v2 --recovery-media FILE
serctl_cli recovery init NEW_MEDIA  # Linux 接口当前失败关闭

serctl_cli up [NAME]
serctl_cli exec NAME [--timeout-secs N] -- COMMAND
serctl_cli upload NAME LOCAL REMOTE [--timeout-secs N]
serctl_cli download NAME REMOTE LOCAL [--timeout-secs N]
serctl_cli transfer push NAME LOCAL REMOTE [--backend auto|native|sftp] [--resume auto|never] [--idle-timeout-secs N] [--deadline-secs N] [--progress auto|tty|json|quiet]
serctl_cli transfer pull NAME REMOTE LOCAL [同上]
serctl_cli transfer status NAME [TRANSFER_ID] [--watch] [--json]
serctl_cli transfer cancel NAME TRANSFER_ID
serctl_cli shell [NAME]
serctl_cli tunnel NAME local --target-port P [--port P] [--max-connections N]
serctl_cli tunnel NAME remote --target-port P [--port P] [--max-connections N]
serctl_cli tunnel NAME dynamic [--port P] [--max-connections N]
serctl_cli status [NAME]
serctl_cli down [NAME]

serctl_cli grant-issue NAME --operations OPS --budget N [--ttl-minutes 1..=40] [--profile-passphrase-handle HANDLE_OR_FD] (--output FILE|--output-handle HANDLE_OR_FD)
serctl_cli agent (--grant FILE|--grant-handle HANDLE_OR_FD)
```

使用 `serctl_cli COMMAND --help` 查看当前二进制的最终参数定义；二进制帮助输出优先于旧版本手册。
