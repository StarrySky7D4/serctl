# serctl 使用手册

适用版本：`v0.2.0-test.1`（预发布测试版）
最后更新：2026-08-26

> [!WARNING]
> 当前版本是测试版本，不应直接替代经过签名和独立验收的正式发行版。生产凭证必须先备份，再进行安装、升级或迁移。
>
> 当前源码的测试目录隔离仍在加固中。存有真实 `%USERPROFILE%\.serctl` 的 Windows 账户不得运行默认并行的 `cargo test`。开发测试必须使用专用操作系统账户，并严格使用 `-- --test-threads=1`。如果真实凭证库中出现 `v6test`、`e2e`、`prod`、`tester` 或 `127.0.0.1:22` 等测试数据，请立即停止 serctl 和测试，不要继续保存或初始化。

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

仓库固定使用 Rust `1.97.1`。正式构建不得启用 `--all-features`，因为 `test-support` 只允许用于测试：

```powershell
rustup show
cargo build --locked --release --workspace --bins
.\target\release\serctl_cli.exe --version
```

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

编辑、安全轮转和删除前，应先断开正在使用该 profile 的连接。

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

### 7.4 交互 shell

```powershell
& $Serctl shell prod
```

省略名称时使用 `default`。

### 7.5 上传与下载

```powershell
& $Serctl upload prod '.\request.json' '/tmp/request.json' --timeout-secs 120
& $Serctl download prod '/tmp/result.json' '.\result.json' --timeout-secs 120
```

本地和远端目标已存在时均不会覆盖。

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

删除不可撤销。即使随后用相同名称重建，也会获得新的随机 profile identity，旧授权不能复用。

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

### 9.3 破坏性替换

没有匹配恢复介质时，只能明确丢弃旧 SSH 凭据、旧主机 pin 和旧密钥包：

```powershell
& $Serctl profile-password prod admin-reset `
  --replace-credentials `
  --host 192.168.5.15 `
  --user deploy `
  --port 22 `
  --host-key-sha256 'SHA256:请替换'
```

这是不可撤销操作。UI 还要求输入 profile 名称确认。

### 9.4 轮转恢复介质

```powershell
& $Serctl recovery rotate `
  --old-media 'E:\serctl-recovery-2026-01.srrec' `
  --new-media 'F:\serctl-recovery-2026-02.srrec'
```

新介质路径必须不存在。命令成功后，当前 vault 不再接受旧介质。验证新介质已安全保存后，再按组织策略退役旧介质。

## 10. 从 v2 迁移到 v4

v2 使用共享主口令；v4 要求每个 profile 独立口令。迁移只在 Windows 实现，并且是全量原子操作。

迁移前：

1. 关闭所有旧版 UI、CLI 和 daemon。
2. 使用匹配旧 daemon 的旧程序正常停机，不要直接删除锁文件。
3. 备份旧 `vault.json`。
4. 准备一个不存在的新恢复介质路径。
5. 为每个 profile 准备不同的新独立口令。

执行：

```powershell
& $Serctl recovery migrate-v2 `
  --recovery-media 'E:\serctl-v4-recovery.srrec'
```

程序会依次要求旧共享主口令、每个 profile 的新独立口令和新 Windows 超管密码，并显示验证、独占访问、逐 profile 转换、介质持久化和原子提交进度。

任何一步失败时，旧 v2 vault 应保持不变。Linux 当前没有保留凭据的 v2→v4 迁移路径。

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

签发最多 30 分钟、带操作范围和次数预算的 grant：

```powershell
& $Serctl grant-issue prod `
  --operations ssh.exec,daemon.status,sftp.list `
  --budget 20 `
  --output 'C:\Secure\prod-agent-grant.json'
```

启动 JSONL stdio 网关：

```powershell
& $Serctl agent --grant 'C:\Secure\prod-agent-grant.json'
```

请求示例，每行一个 JSON 对象：

```json
{"op":"status","request_id":1}
{"op":"exec","request_id":2,"cmd":"uname -a","timeout_ms":30000}
{"op":"list-dir","request_id":3,"path":"/tmp","timeout_ms":30000}
{"op":"create-dir","request_id":4,"path":"/tmp/example","timeout_ms":30000}
```

grant 文件同时包含 agent 私钥，应按密码文件保护。daemon 会在 Grant 有效期间保持运行，避免空闲退出丢失内存登记；Grant 过期后才恢复正常的空闲退出。若 daemon 因人工操作、升级或崩溃而重新启动，旧文件不会被新实例直接信任，必须重新签发。此时错误会明确报告“未在当前 daemon 实例登记”，而不会与“已过期”合并。过期、超预算或超出操作范围后同样必须重新签发。

`--operations` 使用协议中的精确操作种类：Agent 网关当前对应 `ssh.exec`、`daemon.status`、`sftp.list` 和 `sftp.write`。不要使用界面显示名称代替这些值。

## 12. Linux 与 macOS 差异

- Linux 不保存独立超管密码，管理授权使用有效 UID 0。
- Linux 当前只支持 root 通过 `--target-user USER --replace-credentials` 对指定 NSS 用户执行破坏性 profile 替换；进程会在打开目标 vault 前不可逆降权。
- Linux 的离线保留式恢复、恢复介质轮转和 v2→v4 迁移当前失败关闭。
- macOS 可构建普通客户端功能，但本手册所述 root 目标用户管理入口仅适用于 Linux。

Linux 破坏性替换示例：

```bash
sudo ./serctl_cli profile-password prod admin-reset \
  --target-user alice \
  --replace-credentials \
  --host 192.168.5.15 \
  --user deploy \
  --port 22
```

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
serctl_cli remove NAME

serctl_cli admin status
serctl_cli admin init --recovery-media FILE
serctl_cli admin verify
serctl_cli admin change-password

serctl_cli profile-password NAME change
serctl_cli profile-password NAME rotate-random --random-output FILE
serctl_cli profile-password NAME admin-reset --media FILE [--random --random-output FILE]
serctl_cli profile-password NAME admin-reset --replace-credentials [OPTIONS]

serctl_cli recovery rotate --old-media FILE --new-media FILE
serctl_cli recovery migrate-v2 --recovery-media FILE
serctl_cli recovery init NEW_MEDIA  # Linux 接口当前失败关闭

serctl_cli up [NAME]
serctl_cli exec NAME [--timeout-secs N] -- COMMAND
serctl_cli upload NAME LOCAL REMOTE [--timeout-secs N]
serctl_cli download NAME REMOTE LOCAL [--timeout-secs N]
serctl_cli shell [NAME]
serctl_cli tunnel NAME local --target-port P [--port P] [--max-connections N]
serctl_cli tunnel NAME remote --target-port P [--port P] [--max-connections N]
serctl_cli tunnel NAME dynamic [--port P] [--max-connections N]
serctl_cli status [NAME]
serctl_cli down [NAME]

serctl_cli grant-issue NAME --operations OPS --budget N --output FILE
serctl_cli agent --grant FILE
```

使用 `serctl_cli COMMAND --help` 查看当前二进制的最终参数定义；二进制帮助输出优先于旧版本手册。
