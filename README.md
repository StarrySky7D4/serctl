# serctl

`serctl` 是一个纯 Rust 的持久 SSH 控制工具，提供 Winit/Egui 桌面 UI 与完整 CLI。它复用 SSH 连接执行远端命令、浏览目录、执行可观察且可取消的文件传输、运行 Bash PTY，并支持本地（`-L`）、远程（`-R`）和动态 SOCKS5（`-D`）TCP 隧道。

当前重写版标记为预发布测试版本 **v0.3.0-beta.2**；原 main 基线保存在远端 `V1` 分支。测试版本不应替代正式签名发行物。

面向操作者的安装、首次配置、UI/CLI、备份恢复和故障处理流程见 [serctl 使用手册](docs/serctl-user-guide.md)；当前实现的安全边界见 [架构、安全与运维说明](docs/serctl-architecture-security.html)；尚未发布的策略、审计、作业、IPC codec 与高速数据面方案见 [目标架构与演进路线](docs/serctl-design-roadmap.md)；版本变化见 [更新日志](CHANGELOG.md)。

### 最近更新（2026-08-31）

- 新增 `transfer push/pull/status/cancel`：进度只按远端确认量推进，区分 idle timeout 与可选总 deadline，并显示阶段、3 秒窗口速度、平均速度、ETA、实际 backend、chunk/window 和 transfer id。
- 修复 SFTP 上传把本地 `write_all` 返回误当成远端确认的问题。fallback 现使用保守的 2 KiB chunk，并对每个 WRITE 等待匹配的远端 STATUS 后才推进 confirmed bytes。
- Agent JSONL 新增 grant-backed `transfer-push`，并在打开/读取本地文件前强制校验精确 `transfer.write` scope；`sftp.write` 仍只授权 `create-dir`，`ssh.exec` 也不能回退承载上传。Agent JSON 错误不回显本地绝对路径或凭据标记。
- 新增受保护 transfer journal、上传 ownership token proof、连续 durable-prefix push/pull 恢复，以及固定命令 `serctl-xfer serve --stdio` 的 Linux 原生后端；`auto` 仅在 helper 握手成功时报告 `native`，否则明确回退为 `sftp_fallback`。
- 修复远端文件刷新长时间停留在“正在读取”：目录刷新采用独立 20 秒上限，大目录只渲染可见行，避免每帧克隆和布局最多 10,000 条记录。
- 修复 Windows 新建主机在安全授权或恢复介质轮转后不能继续保存的问题，并补充迁移阶段的可见进度反馈。
- 修复首次 TOFU host-key pin 被 profile 使用租约错误拒绝的问题；该受限写入仍在 vault 排他锁内复核，不放宽普通 profile mutation。
- 修复 OperationGrant 尚未过期时 daemon 因空闲退出或 Windows 启动 CLI 的控制台结束而丢失内存登记的问题；Windows 后台 broker 使用 `DETACHED_PROCESS` 脱离签发 CLI 的控制台并建立独立进程组，未知当前实例与真正过期使用不同错误信息。人工重启、升级或崩溃后仍必须重新签发 Grant。
- `grant-issue` 新增 `--ttl-minutes`：默认 30 分钟，CLI、IPC 根 intent 与 daemon 共同强制 `1..=40` 分钟策略上限，满足单一受控长任务而不产生开放式授权。
- CI 测试改为单线程执行，降低进程级测试 home/daemon 状态互相干扰的风险。

当前工作树使用 vault/record v4：每个 profile 有彼此独立的口令、Argon2id KDF、随机 DEK、IPC `AuthSeed` 与随机 128 位 `profile_id`，不存在可解锁全部主机的共享主口令。Windows 另设超管密码并配合离线介质形成 2-of-2 恢复；超管密码本身不能查看现有 profile 口令，也不能单独恢复 SSH 凭据。CLI 的每次远程调用都重新验证目标 profile 口令，桌面 UI 则按 `(name, profile_id, generation)` 保存固定五分钟、非滑动授权。SSH 隧道的所有 listener，以及 L/R 的固定目标地址，都强制为 `127.0.0.1`。实现级说明、威胁边界和验证证据见 [架构、安全与运维说明](docs/serctl-architecture-security.html)。

### 目标架构（规划，不是当前能力）

长期方向是把 daemon 收敛为本机策略执行点：调用方只提交 typed intent，daemon 将 profile 身份、policy digest、Grant/审批、预算、deadline、审计 intent 与可验证 receipt 绑定后再执行。颜色等级只作为 UI 模板，不能覆盖不可关闭的安全不变量；高风险兼容入口使用短期、单次、精确绑定的 break-glass 证书，而不是“完全不检查”的黑牌。

原先设想中的“RFC1918 内网 UDP 裸流”“命令行传递 Session Key”“仅靠 SHA-256 链和 `chattr` 即不可篡改”“`shred` 即物理销毁”均不进入目标方案。高速数据面只有在现有 native SSH backend 完成实机验收后才评估始终认证加密的 QUIC；内部 Protobuf 也必须先通过 Named Pipe/UDS 端到端基准，不能把 Rust 实现误写成自动 Arena 零拷贝。完整决策、里程碑与验收矩阵见 [目标架构与演进路线](docs/serctl-design-roadmap.md)。

## 功能

桌面端支持：

- 新建、编辑、重命名和删除主机配置；
- 锁定状态只显示明文目录元数据（profile 名、host、port、随机 `profile_id`、generation），不会查询 daemon 或连接远端；
- 每个 profile 独立授权五分钟；切换主机不会混用口令，口令轮转、保存、重命名或恢复推进 generation 后旧授权立即失效；删除再以同名重建会得到新的 `profile_id`，也不能复用旧授权；
- Windows 超管授权独立为固定两分钟，可初始化/更改超管密码、轮转恢复介质、在介质参与时保留凭据重置 profile 口令，或明确丢弃旧凭据后执行破坏性重置；
- Windows 新建主机若尚无超管授权，UI 会保留未提交的编辑器内容并进入“安全与恢复”；初始化后提示授权，授权成功即自动续接原保存动作。恢复介质轮转会撤销旧授权，但重新授权后仍续接同一待保存主机；关闭安全窗口只取消自动续接，不清除编辑器；
- 随机 profile 口令采用两阶段交付：先在安全窗口一次性显示且不改 vault，只有勾选“已安全保存”并提交后才执行轮转/恢复/破坏性重置；取消或关闭会清零暂存值且无网络/vault 副作用；
- Windows 上的 v2 凭证库通过阻断式向导一次性全量迁移，迁移完成前所有网络功能保持禁用；Linux 按钮禁用且在读取迁移秘密前失败关闭；
- 启动、检查或停止持久 daemon；
- 执行命令并分别显示 stdout、stderr 与明确的退出码；
- 分批浏览远端目录、返回上级目录和创建目录；
- 上传与下载文件，目标已存在时安全失败；
- 持续 Bash PTY，会话内可输入命令、发送 `Ctrl+C` / `Ctrl+D` 和清屏；
- “隧道”页可启动/停止本地转发、远程转发和动态 SOCKS5 转发，并显示强制回环的实际监听端口；
- profile 授权到期或用户撤销时立即清零该授权并停止相应 shell、隧道与传输；其他 profile 的授权和已运行 daemon 保留；
- profile epoch、不可变 `(name, profile_id, generation)`、daemon instance id 与取消令牌共同约束异步任务；授权 TTL 到期或撤销后，Shell/Tunnel/Command/Directory/Transfer 的迟到结果会被取消或拒绝呈现；
- 正常退出时取消在途传输与隧道：传输最多等待 6 秒，隧道最多等待 8 秒；随后并发停止 UI 拥有的 daemon，最后以 1 秒上限关闭 runtime。

开发时启动 debug UI：

```powershell
cargo run -p serctl-cli --bin serctl_cli -- ui
# 省略最后的 ui 也会打开桌面工作台
```

## CLI

```powershell
$exe = ".\target\debug\serctl_cli.exe"

# Windows 首次使用：新介质路径必须不存在，超管密码交互输入
$media = 'E:\serctl-recovery-v1.json'
& $exe admin init --recovery-media $media

# SSH 密码与 profile 独立口令交互输入，不进入 argv；首次连接前可预置指纹
$expectedFp = 'SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU' # 仅示例，请替换
& $exe add prod --host 192.168.5.15 --user deploy --port 22 --host-key-sha256 $expectedFp

# 前台运行持久 daemon；另一个终端复用它
& $exe up prod
& $exe exec prod --timeout-secs 30 -- "uname -a; whoami"
& $exe shell prod

# 本地转发、动态 SOCKS5 和远程转发；所有 listener 仅限 127.0.0.1
& $exe tunnel prod local --port 15432 --target-port 5432
& $exe tunnel prod dynamic --port 1080
& $exe tunnel prod remote --port 0 --target-port 8080

# 上传请求，再拉取服务器 evidence；非 TTY 可改用 --progress json 输出 NDJSON
& $exe transfer push prod .\request.json /tmp/request.json --backend auto --resume never --idle-timeout-secs 30 --deadline-secs 120
& $exe transfer pull prod /tmp/server-evidence.json .\server-evidence.json --backend auto --resume never --idle-timeout-secs 30 --deadline-secs 120

& $exe status prod
& $exe down prod

# profile 自助轮换；随机值先持久写入受保护的新文件，再修改 vault
& $exe profile-password prod change
$randomReceipt = Join-Path $env:USERPROFILE 'Documents\serctl-prod-passphrase.txt'
& $exe profile-password prod rotate-random --random-output $randomReceipt

# 忘记 profile 口令后：超管密码 + 对应离线介质共同保留原 SSH 凭据
& $exe profile-password prod admin-reset --media $media
```

| 命令 | 说明 |
| --- | --- |
| `ui` | 打开桌面工作台；省略子命令时默认执行 |
| `add [NAME] [--host H] [--user U] [--port P] [--host-key-sha256 SHA256:…]` | 新建时设置独立 profile 口令；Windows 还要求超管授权。更新时只验证目标 profile 口令 |
| `list` | 无需口令，仅列出明文目录元数据与 generation；不解密 SSH 凭据 |
| `remove NAME` | 验证目标 profile 独立口令后删除 |
| `admin status` | 查看超管/恢复策略是否初始化；不验证口令 |
| `admin init --recovery-media FILE` | Windows：同时初始化超管密码与 2-of-2 恢复，介质路径必须不存在且 vault 必须为空 |
| `admin verify` | Windows 验证超管密码；Linux 验证有效 UID 0 |
| `admin change-password` | Windows 验证旧密码后只重包 vault-local 恢复 share，不改变 profile 口令 |
| `profile-password NAME change` | 验证当前独立口令后设置新口令 |
| `profile-password NAME rotate-random --random-output FILE` | 验证当前独立口令；先把随机口令同步并回读到受保护的 create-new 绝对路径，再提交新 package/generation |
| `profile-password NAME admin-reset --media FILE [--random --random-output FILE]` | **仅 Windows**：超管 + 离线介质恢复并重包当前 SSH 凭据；不显示旧 profile 口令。Linux 即使 root 也失败关闭 |
| `profile-password NAME admin-reset --replace-credentials [--host H] [--user U] [--port P] [--host-key-sha256 SHA256:…] [--random --random-output FILE]` | **Windows**：超管授权，不用介质，完整替换凭据/口令并永久丢弃旧凭据、pin 与密钥包；缺少的凭据交互输入 |
| `profile-password NAME admin-reset --target-user USER --replace-credentials [--host H] [--user U] [--port P] [--host-key-sha256 SHA256:…] [--random --random-output FILE]` | **Linux CLI**：必须以 root 启动；按 NSS 绑定非 root 目标并在打开 vault 前不可逆降权，然后只执行破坏性替换。Windows 拒绝 `--target-user` |
| `recovery rotate --old-media FILE --new-media FILE` | Windows：超管密码与旧介质共同认证后，全量原子轮转恢复 envelope；新路径不得存在 |
| `recovery migrate-v2 --recovery-media FILE` | **仅 Windows**：旧共享 master、逐 profile 新口令、新超管密码与新介质组成全量原子 v2→v4 迁移；Linux 当前无升级路径并失败关闭 |
| `recovery init NEW_MEDIA` | Linux root 接口；当前后端因缺少 root-owned share store 与目标用户边界而失败关闭 |
| `up [NAME]` | 前台启动全局 broker；不预解锁 profile，名称参数仅为旧脚本兼容保留 |
| `exec NAME [--timeout-secs N] -- <CMD...>` | 执行远端命令，默认硬 deadline 为 300 秒 |
| `upload NAME LOCAL REMOTE [--timeout-secs N]` | 上传普通文件，不覆盖已有远端路径 |
| `download NAME REMOTE LOCAL [--timeout-secs N]` | 下载文件，不覆盖已有本地路径 |
| `transfer push NAME LOCAL REMOTE [OPTIONS]` | 可观察上传；支持 backend、idle/total timeout、进度模式和安全失败的 resume 选择 |
| `transfer pull NAME REMOTE LOCAL [OPTIONS]` | 可观察下载；最终完整性校验和 no-overwrite commit 后才显示 100% |
| `transfer status NAME [TRANSFER_ID] [--watch] [--json]` | 查询该 profile 的脱敏传输快照；完成记录保留 15 分钟 |
| `transfer cancel NAME TRANSFER_ID` | 取消该 profile 的活动传输 |
| `grant-issue NAME --operations OPS --budget N [--ttl-minutes N] --output FILE` | 签发带 holder PoP、精确 scope、预算和 `1..=40` 分钟 TTL 的 Agent OperationGrant |
| `agent --grant FILE` | 启动 JSONL stdio 网关；操作能力严格受 Grant scope 限制，上传只接受 `transfer.write` |
| `shell [NAME]` | 打开交互式 PTY shell |
| `tunnel NAME local --target-port P [OPTIONS]` | 本机 `127.0.0.1` 监听，经 SSH 到已连接主机的 `127.0.0.1:P`（`-L`） |
| `tunnel NAME remote --target-port P [OPTIONS]` | SSH 主机 `127.0.0.1` 监听，转到本机 `127.0.0.1:P`（`-R`） |
| `tunnel NAME dynamic [OPTIONS]` | 本地 SOCKS5 `NO AUTH` / `CONNECT` 代理（`-D`） |
| `status [NAME]` | 先离线验证该 profile 的独立口令，再查看 daemon 状态 |
| `down [NAME]` | 先离线验证该 profile 的独立口令，再停止 daemon |

`shell`、`status`、`down` 的 `NAME` 省略时为 `default`；`up` 的可选名称参数仅为旧脚本兼容保留，当前全局 broker 不按名称预解锁 profile；`exec`、`upload`、`download`、`tunnel` 要求显式 profile。每个普通 profile 操作、每次 CLI 进程调用都必须重新提供并验证该 profile 的独立口令，不存在跨调用缓存；`list` 和 `admin status` 只读明文目录/策略元数据。`status` / `down` 也必须在 IPC connect 前从目标 profile 的 `AuthSeed` 派生 generation-scoped call key，并以精确 `Status` / `Shutdown` intent 完成协议授权；只有运行锁 token 的进程不能查询或停止 daemon。shell/隧道建立后，单个会话内不会按按键或每条 TCP 流重复询问。

`exec` 是有 absolute deadline 的一次性命令，不是可恢复的远程作业管理器。2026-08-30 的 W2 vendor Linux 冷构建先在 900 秒边界没有返回 Cargo/测试终态；后续外层 1,200,000 ms 请求同样超时，但独立只读校验发现同一命令已写入 `BUILD-READY-v1` receipt（SHA-256 `b1e8041912e6e1838ee2f9c2ec0405bf92a5fbfd52d54120a66d85fb5239564c`）。这证明远端工作可在 deadline 边界完成而 relay 丢失成功终态：没有经过预先约定的严格 receipt 校验时仍必须记为 `unknown`，不能把 timeout 直接当作构建失败。预计耗时接近上限的构建应拆成可查询的阶段，把输出、退出状态和绑定输入身份的 receipt 原子写入远端受控路径；当前操作建议为内层命令 deadline、较长的外层 relay deadline，以及至少三分钟终态读取/清理余量。产品仍缺少独立的远端/relay deadline、心跳进度和可恢复结果查询。

隧道公共选项只有 `--port`（默认 `0`，由系统选端口）和 `--max-connections`（默认 32，硬上限 128）。`--bind`、`--expose` 和 `--target-host` 已删除：L/D 的本地 listener、R 的 SSH 服务端 listener，以及 L/R 的固定目标地址都只能是 `127.0.0.1`；CLI/UI 只接受端口。动态 SOCKS5 使用 `NO AUTH`，每个 CONNECT 目标由本机 SOCKS 客户端请求，可访问已连接 SSH 主机能够到达的任意远端目标；强制回环只阻止代理 listener 直接向 LAN/公网暴露，并不限制代理目标，也不隔离同机进程。

自动化可用 `SERCTL_SSH_PASS`、`SERCTL_PROFILE_PASS`、`SERCTL_ADMIN_PASS` 和仅迁移使用的 `SERCTL_LEGACY_MASTER` 注入对应秘密；`SERCTL_MASTER` 仅作向后兼容，并按命令解释为 profile 口令或 v2 旧 master。程序在任何可失败的 Unicode 解码和异步 runtime 之前，先快照并从自身环境同时删除全部五个变量；一个值无效也不会把其他值留在环境中。父进程、调试器或同权限进程仍可能观察环境，交互输入更适合高价值凭证。

v4 已删除共享 `change-master` / `rekey` 模型。普通口令轮换只影响一个 profile，并推进其持久 generation；Windows 超管密码只保护 vault-local 恢复 share。恢复旧凭据必须同时取得超管授权和匹配的离线介质；单独持有任一项都不能打开 profile key package。CLI 与 UI 的介质读写都要求绝对路径，并用普通、非 reparse/link 文件与 4 MiB 上限；新介质通过同一稳定读写 handle create-new、同步并常量时间回读核对，Unix 还同步父目录。只有介质持久化回调成功后才提交 vault；失败最多留下无法单独恢复的孤立新介质，不会产生只写一半的有效策略。CLI 与 UI 都拒绝把介质输入/输出放进 `.serctl` vault 目录，CLI 的随机口令输出也遵守同一外部路径约束；路径检查不能证明目标卷确为 U 盘、已弹出或物理隔离，操作者仍须选择与 vault/备份分离的可移动介质并在使用后离线保管。

CLI 随机口令不会写到终端：`rotate-random` 以及带 `--random` 的 admin reset 都必须同时给出 `--random-output FILE`。程序先把严格的 UTF-8 `passphrase + newline` 写入受保护、不得预先存在的绝对路径，执行同步和同句柄回读，成功后才允许修改 vault，因此输出失败时旧口令/generation 不变，不会把 profile 锁在未交付的口令后。若后续 vault 提交失败，输出文件会保留但其中口令尚未生效；必须先检查命令成功，再导入密码管理器并按策略销毁过渡文件。该“先持久化再 commit”只保证非对抗 I/O 的交付顺序：同 UID 对手仍可在稳定句柄回读后删除/换名输出，或替换其可写父目录，因此应选择仅当前用户可写的受控父目录并及时接管 receipt。UI 不使用输出文件，而是在 modal 内先暂存/一次性显示，勾选已保存并点击提交前不会排队后台操作、访问网络或修改 vault；取消/关闭会清零暂存值。非 Windows 的 v2 migration 与 `admin-reset --media` 在捕获命令秘密前即拒绝。

CLI 将远端非零退出状态映射为本地非零退出码，缺失退出状态或 IPC 中断始终是失败，不再用 `0` 兜底。自身诊断、Clap 错误、日志、profile/路径/远端状态消息会转义控制字符，防止错误文本注入终端；`exec` 与 shell 的原始远端输出仍按受信任终端数据处理。

## 架构

```text
Winit / Egui UI ─┐
                 ├─ client ── IPC v8 AEAD ── 全局 broker ── russh 0.62.5 ── SSH
CLI ─────────────┘       │       │              ├─ russh-sftp / SFTP v3
                         │       │              └─ fixed exec: serctl-xfer serve --stdio
                         │       ├─ per-profile session pool + bounded handlers
                         │       └─ L/R/D tunnel control（TCP data 不经 IPC）
                         └─ 无 direct-connect 回退

vault/record v4: profile passphrase ─ Argon2id ─ KEK ─┐
                                                       ├─ wrap {DEK, AuthSeed, profile_id, generation}
Windows recovery: admin password ─ local share ─┤
                  USB offline share ────────────┘  (2-of-2 recovery envelope)
DEK ─ ChaCha20-Poly1305(username / SSH password / host-key pin)
AuthSeed ─ HMAC domain separation → name + profile_id + generation scoped call key
IPC: Windows Named Pipe / Unix Domain Socket，共用长度前缀 JSON 帧抽象
```

每个远程请求都只走 per-user/per-vault 全局 broker，不再存在 direct-connect 回退。客户端先通过激活密钥完成 IPC v8 双向认证并建立 ChaCha20-Poly1305 通道；首次使用某 profile 时，口令仅在该 AEAD 通道内发送。daemon 验证并解包该 profile 后返回域分离的短期 call key，后续每个普通请求以 HMAC 把完整 prelude（操作、profile 名/ID、请求 ID、deadline 与根请求哈希）绑定到该 profile。daemon 同时校验根帧哈希、profile 名/ID 和 call proof，未通过前不会触发 SSH、SFTP 或 listener 副作用。源码中的部分 `v6` 模块/类型名是兼容保留的内部标识，当前 wire version 固定为 8，旧版本握手失败关闭且没有 downgrade 或直连回退。

daemon 最多接受 64 个并发本机连接；会完整缓冲结果的 `Exec` 与 `ListDir` 共用额外 8 槽上限，长驻 tunnel control 另有 8 槽上限。每个已认证 IPC 连接只接受一个根请求；上传块、shell 输入和 tunnel stop 是该根请求生命周期内的后续帧。认证后 10 秒仍未发送根请求的连接被关闭。响应写通常受请求剩余 deadline 与 2 秒局部上限的较早者约束，并可被 shutdown 抢占；远端上传已明确提交而原预算刚过时的 `TransferDone` 例外使用新的最多 2 秒确认窗口。关闭时广播取消，使用 `JoinSet` 等待 handler 最多 4 秒，再中止并回收剩余任务。

UI 启动 daemon 的 status 探测、bind、lock publication 与 readiness 全部消耗同一个 30 秒 absolute deadline。listener 绑定/锁发布在 owned blocking worker 中，原子写锁前就 arm 了按 token 删除的 guard 并持有排他租约；迟到、取消或 readiness receiver 已消失时，Drop 会在 blocking 线程完成 listener/锁/租约清理，不会留下已发布但无主的 daemon。

## 凭证与运行锁

- 凭证库位于 `%USERPROFILE%\.serctl\vault.json`。vault/record v4 为每个 profile 保存独立的 Argon2id salt/KDF；当前参数为 64 MiB、3 轮、并行度 1，并对磁盘参数设置安全上下限。`argon2` 已启用 `zeroize` feature；派生用的 64 MiB 矩阵由 `Zeroizing<Vec<Argon2Block>>` 持有。
- profile 口令派生的 KEK 只包裹随机 `{DEK, AuthSeed, profile_id, generation}`；DEK 加密用户名、SSH 密码和 host-key pin，`AuthSeed` 用于派生 IPC call key，并认证当前完整 recovery configuration 的 profile-local HMAC 绑定。改口令或恢复会生成新的 key package，而不是让超管取得或显示旧口令。
- profile 名、host、port、随机 128 位 `profile_id` 与 generation 是有意明文保存的本地目录元数据，锁定 UI 和 `list` 均可读取。KeyPackage、key/payload AEAD AAD、call-key 派生与 recovery envelope 都绑定 `(name, profile_id, generation)`（凭据 AAD 另绑定 host/port）；孤立修改会认证失败，但明文元数据不具备机密性。
- `profile_id` 表示记录实例：创建和 v2→v4 迁移生成新随机 ID；更新、重命名、改口令、恢复和 admin reset 保留 ID 并推进 generation；删除后即使按同名重建也会得到新 ID。generation 是同一实例内的授权 epoch。两者共同使旧 UI grant、call key 和迟到异步结果失效；首次 TOFU pin 为避免使刚建立的 daemon 立即失效，会认证重包但保留同一 identity/package/generation。generation 不是可信硬件计数器；能回滚整个 `vault.json` 的管理员仍可恢复一份内部一致的旧快照。
- Windows 超管密码以独立 Argon2id KEK 只包裹 32 字节 vault-local recovery share，并在同一密文中认证完整 canonical recovery configuration 的 SHA-256 摘要；U 盘保存另一个 XOR share。每个 profile 还以自己的 `AuthSeed` 对完整 recovery configuration 计算 HMAC tag，所有口令认证/修改路径都会先验证该绑定。这阻止本地管理员只替换 recovery public key，再等待后续正常更新把新凭据密封给攻击者。两份 share 共同重建只用于打开 profile recovery envelope 的 X25519 私有输入，任一 share、超管密码或介质都不能单独恢复凭据。介质 checksum 只检测误选/损坏，不是身份认证。
- vault v2 不会被惰性或逐条升级：客户端先阻断网络，验证旧共享 master 并要求每个 profile 的新独立口令，再为每条记录生成随机 `profile_id`，一次性认证、转换全部 format-2 记录并原子提交 v4。UI 与 CLI 会报告输入校验、独占访问、旧库认证、逐 profile KDF、介质持久化和原子提交阶段；无效、已存在或位于 vault 内的介质路径会在取走输入秘密和执行高成本 KDF 前立即拒绝。任一记录、介质写入、租约或并发状态失败时，旧 v2 vault 保持不变。format 0 等未认证旧记录必须显式替换，不能进入全量迁移。开发过程中曾产生但未发布的中间 v3 与最终 v4 的 AAD/KeyPackage 布局不同；v4 对该 v3 的 load、catalog 和 migration 全部失败关闭，不会把它猜测为 v2 或自动转换。
- Linux 目前不保存超管密码；跨用户破坏性 reset 只在 CLI 接受 `--target-user USER`。进程仍为 root 时仅通过 NSS 解析账号并验证其非 symlink、非宽松权限的 home/现有 `.serctl`，随后清空附加组并把 real/effective/saved GID/UID 全部永久降为目标非 root 账号，之后才打开/修改该用户 vault；不能用 UID、`HOME`、`SUDO_USER` 或任意路径绕过绑定。该委托只允许丢弃并替换旧秘密，不提供保留式解密。
- 保存采用稳定文件句柄、进程间锁和同目录原子替换；锁等待上限为 30 秒，不会无限阻塞。
- vault 最多保存 10,000 个 profile；达到上限后仍可更新、重命名或删除既有记录，但不能新增。容量检查在写盘前再次执行，拒绝不会改写原文件。
- vault 与运行锁共用的受保护原子提交在 Unix 上执行同目录临时文件 `sync_all`、原子 `rename` 和父目录 `fsync`；Windows 从创建临时文件起即应用 protected DACL，`sync_all` 后以稳定的受保护父目录句柄配合 `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` 替换。注入提交失败时旧目标保持不变且临时文件被清理。这里验证的是 OS 提供的持久化/写穿原语与失败路径，不是断电模拟，也不承诺硬件或文件系统超出其语义的行为。
- 敏感 JSON 使用“计数遍 + 精确预分配写入遍”，直接落入 `Zeroizing<Vec<u8>>`；vault、运行锁与 IPC 帧不再先产生普通敏感序列化缓冲区。完成和错误分支均尽早清零可控副本。
- Windows 凭证目录/文件使用禁止继承的 owner、SYSTEM、Administrators DACL；Unix 目录为 `0700`、文件为 `0600`。路径通过稳定句柄检查 owner、类型、ACL/mode 与 reparse/symlink 边界，失败关闭。Windows owner 校验接受对象 owner 等于当前进程令牌的 `TokenUser` 或该令牌的 `TokenOwner`：这兼容提升令牌以 `BUILTIN\Administrators` 作为默认 owner 的正常创建结果，同时仍拒绝与本令牌无关的 SID，并且不扩大既有 DACL 已明确包含的管理员边界。
- v8 全局 broker 的 descriptor 与 activation secret 分离保存，并使用受保护权限和稳定句柄校验。profile pool 持有排他使用租约；profile mutation 只有在实际 contention 时才报告“正在被 daemon 使用”。credential lease 由独立 reaper 主动清理，handler/tunnel 还受同一 monotonic hard deadline 约束。旧 protocol-v5 profile 运行锁仅作为 legacy daemon 兼容代码保留；当前 client 不读取它、不清理它，也不回退直连。
- daemon 启动时用目标 profile 的 Argon2 KDF 解包 key package，解密 SSH 凭据并从 `AuthSeed + name + profile_id + generation` 派生 32 字节 `ProfileCallKey`；SSH 建连和首次 TOFU pin 完成后清除 profile 口令，只保留 SSH 会话与 call key。call key 不序列化、不写入 vault/运行锁，最后一个引用释放时清零。

UI 的 profile/admin/editor SSH secret 使用 `MaskedSecretTextBuffer`：egui 只能看到与 Unicode 字符数相同的 `*`，每次显示前后都把 undo 容量设为 0，Unicode 编辑替换的旧 app-side 字符串会清零。eframe persistence 已移除，window/egui memory persistence 都关闭。启动和锁定期间允许刷新本地明文目录元数据，但只有持有目标 `(name, profile_id, generation)` 固定五分钟授权的记录才会发 status probe 或执行网络操作；超管授权独立固定两分钟且不能用于普通 SSH 操作。到期或显式撤销会清零相应授权和受保护上下文，取消该 profile 的传输、关闭 shell 并停止 tunnel；daemon 故意保留。Shell/Tunnel/Command/Directory/Transfer 的任务都捕获不可变 identity，reducer 在呈现完成结果前再次核对 identity 与授权；TTL 撤销后的迟到结果会被取消或丢弃。随机轮转、Windows 保留式恢复和随机破坏性重置共用两阶段 modal：生成阶段只在 UI 内暂存并一次性显示，明确标注 vault 尚未修改；勾选已安全保存后提交按钮才启用，取消/关闭则清零且不产生后台消息。`SensitiveUiMessage` 的 RAII envelope 从排队、send 失败、receiver drop 一直存活到 reducer match 完成，unwind 也会清零 payload并取消 shell/tunnel。profile refresh 使用单一 32 秒 deadline；未授权 profile 的 refresh 只有本地 metadata，已授权 profile 的 Status 也不触发 SSH reconnect。Linux v2 迁移 UI 禁用；面向其他本机账号的 root 破坏性 reset 采用上述 CLI `--target-user` 降权入口，而不是任意 vault 路径选择器。

## IPC v8、CLI 逐调用验证与 UI 限时授权

daemon 不监听本机 TCP。Windows 使用拒绝远程客户端的 Named Pipe；每个 pipe instance 在创建时即带禁止继承、仅 owner/SYSTEM/Administrators 可访问的 DACL。Unix 使用 `0700` runtime 目录中的 `0600` Unix Socket。

受保护的 `daemon.secret` 只负责建立 IPC v8 的双向认证 AEAD 通道，不能单独授权 profile 操作或停机。`exec`、目录列出/创建、上传、下载、shell、tunnel、status 与 grant 签发均要求目标 profile 的短期 call key 证明；`down` 则在同一 AEAD 通道内重新验证所选 profile 口令，但不会为停机建立新的 SSH 连接。错误口令不会产生远端副作用。daemon 签发的未过期 OperationGrant 会持有活跃引用，阻止 daemon 在 Grant 有效期内空闲退出；Windows 后台启动还与签发 CLI 的控制台进程组隔离。人工重启、升级或崩溃仍会使旧 Grant 失去进程内登记，新实例不会仅凭磁盘 Grant 文件恢复授权。

客户端连接后先核对 OS 对端身份：Windows Named Pipe server PID 必须等于受保护 descriptor 中的 PID；Unix peer UID 必须等于当前 euid，且 peer PID 必须存在并匹配 descriptor。无法提供 peer PID 的 Unix 目标失败关闭，不降级为仅验证 UID。随后进行 transcript-bound HMAC 双向认证，以 HKDF-SHA256 派生双向独立密钥，并用严格递增计数器 nonce 的 ChaCha20-Poly1305 加密所有业务帧：

```text
client → V6Hello(instance, client_nonce, 完整 request prelude)  # 内部类型名兼容保留，wire=8
daemon → V6Challenge(server_nonce, transcript MAC)
client → V6Finish(transcript MAC)
daemon → AEAD response / stream
```

profile proof 与激活密钥使用不同 domain。proof 覆盖规范化完整 prelude，prelude 又提交根请求 SHA-256；地址不在 `TunnelSpec` 中，双方固定使用 `127.0.0.1`。任何字段替换、跨 profile/daemon instance 重放、AEAD 计数器乱序或第二个根请求都会在 SSH、本地 listener 或其他业务副作用之前关闭。上传块、shell 输入和 tunnel stop 只继承已经授权的单个根请求，不能单独作为授权根请求。

`Status` 使用 profile call proof；`Shutdown` 在 AEAD 内携带并验证本次 profile 口令。只有激活密钥的进程不能消费 profile 业务根帧或停机。CLI 每个调用进程都重新取得本次独立口令；UI 只使用仍匹配 `(name, profile_id, generation)` 的固定五分钟授权。其他记录只显示本地目录元数据且不产生网络副作用。`Status` 仍只是 daemon 生命周期元数据查询，绝不检查 SSH health 或触发 reconnect。

认证帧最多 4 KiB，控制帧最多 16 KiB，业务响应最多 16 MiB；二进制字段使用规范 Base64。长度前缀读取只有在第一个 header 字节之前读到 0 字节才是正常 EOF；1–3 字节的部分长度前缀必定报错。命令输出总计最多 8 MiB，上传 chunk 与 shell input 各最多 64 KiB。

认证有 2 秒上限；`status` / `down` 控制交换为 3 秒。Shutdown 的 4 字节长度头与完整 payload 被 writer 接收后、flush 前即置为 sent；从这个线性化点起，即使 flush、Ack 读取或连接随后失败，也会再以运行锁 token + 租约对账最多 10 秒。同 token 表示预期 generation 仍活跃，不同的有效 token 证明替换 generation 已在旧 daemon 释放排他租约后启动；锁消失本身不足以报成功，还必须探测到预期 daemon 的运行租约已释放。运行锁轮询均在同一 absolute deadline 下交给 blocking worker。

v8 全局 broker 不与旧 per-profile v7/v6/v5/v4 daemon dual-stack。当前 client 对旧 runtime 状态失败关闭且不回退直连。升级前必须先用与活动旧 daemon 匹配的旧 executable 正常 `down`，再整体切换 client/daemon；不要在 daemon 活动或租约仍持有时强删运行状态。

## SSH、命令、SFTP 与隧道

- SSH 使用 `russh 0.62.5` 的 `ring` 后端和默认现代 KEX/MAC；host-key 算法只保留 Ed25519、ECDSA 与 RSA-SHA2-256/512，明确拒绝 `ssh-rsa` SHA-1 签名。
- TCP 被放入可取消代理。即使 peer 发出 banner 后卡在 KEX，absolute deadline/cancel 也会关闭底层连接，避免 russh 预认证任务脱离并长期占用资源。
- 首次连接使用分阶段 TOFU：先 KEX/观测 host key，再在排他租约下原子持久化 SHA-256 pin，只有 pin 成功后才发送 SSH 密码。pin 失败会在认证前中止 transport；即使 blocking pin worker 在 async deadline 后迟到持久化，也绝不会认证已过期 transport。russh password-auth send 的 bounded Future 在每一次 poll 前检查 absolute deadline，Pending 不能越过预算后再把密码交给 transport。后续连接与重连必须匹配 pin；首次链路仍有固有 MITM 风险，应通过独立渠道核对指纹。
- `exec` 的 deadline 覆盖 daemon 路由、重连锁、DNS/TCP/SSH、channel open、exec request 和输出/ExitStatus。IPC writer 在每一次 `poll_write` 与 `poll_flush` 前都检查同一个 absolute deadline，不依赖外层 timeout 的 poll 顺序。只有 4 字节长度头与完整序列化 payload 都被 `AsyncWrite` 成功接收后、执行 flush 前才进入“可能已提交”：序列化失败、零字节或部分帧写失败，以及完整帧写完前的 deadline 都是确定的 pre-submit 错误；完整帧之后的 flush/响应 deadline、断开或无法分类的协议结果返回 typed `ExecOutcomeUnknown`。daemon 的普通拒绝仍可明确证明尚未交给 russh；直连 russh 的 bounded exec-send 同样在每次 poll 前检查 absolute deadline，并只以内部请求成功入队为提交边界，Pending 不能越过预算后再触发远端执行。异常后依次尝试 TERM、KILL、EOF/Close，并在不能确认清理时使 transport 失效；杀掉客户端不会让远端 channel 永久占用 daemon 槽。任何不确定结果都不会被兜底为成功，必须先检查远端副作用再决定是否重试。
- SFTP 所有远端操作共用调用者的 absolute deadline；每个可能产生副作用的 Future 在每次 poll 前重新检查该 deadline，覆盖 `mkdir`、上传 partial CREATE/WRITE/flush/shutdown、OpenSSH hardlink commit，以及 unlink cleanup，Pending 不能在预算后才发起远端变更。服务器未声明 `hardlink@openssh.com` 或该扩展报错时上传失败关闭，绝不降级到可能覆盖目标的 SFTP v3 RENAME。单帧长度前缀在分配 body 前限制为 1 MiB。目录读取直接流式执行 REALPATH/OPENDIR/READDIR/CLOSE，限制协议编码累计 8 MiB、保留字符串 2 MiB、10,000 entries，并在返回前精确验证 `DirList` JSON 不超过 16 MiB IPC wire 预算。
- `create-dir` 在 direct 与 daemon 路径都维护提交状态。只有显式 SFTP `STATUS` 拒绝或 daemon 的普通 pre-request/plain rejection 能证明未创建；完整请求之后的 deadline、EOF、unexpected response 或 transport/protocol 错误返回 typed `CreateDirOutcomeUnknown`，必须先检查远端路径再重试。
- 交互 shell 的列数和行数在 direct、IPC client 与 daemon 三处统一校验为 `1..=10000`。setup：直连共用 30 秒上限，IPC client 为 32 秒且 daemon 内部 setup 为 30 秒；每次 client/daemon 输入写为 2 秒并限制 64 KiB。client 和 daemon 在整个 IPC shell 内各自复用一个 pinned frame decoder，避免 cancel/drop 发生在 header/body 中间而破坏 framing；队列中及等待满队列的帧均有 RAII 清零包装。CLI stdin 每 100 ms poll 以响应取消，忽略 key release，接受 press/repeat；终端 raw mode 由 RAII guard 管理，正常退出、错误、abort 或 unwind 都会尝试恢复。建立成功的会话没有整体 deadline。

### SSH 隧道

- 本地转发（`-L`）在本机 `127.0.0.1` 监听，把每条连接通过 SSH `direct-tcpip` 接到已连接 SSH 主机的 `127.0.0.1:目标端口`；动态转发（`-D`）在本机回环实现 SOCKS5，仅接受 `NO AUTH` 的 `CONNECT`，支持 IPv4、IPv6 和受限 ASCII 域名，不实现 `BIND` 或 `UDP ASSOCIATE`；远程转发（`-R`）通过 SSH `tcpip-forward` 只在 SSH 主机的 `127.0.0.1` 监听，把 `forwarded-tcpip` channel 接到本机 `127.0.0.1:目标端口`。
- 隧道 TCP payload 由本地 socket 与 russh channel 直接 `copy_bidirectional`，不被 JSON/Base64 编码，也不穿过 daemon IPC。daemon IPC 只完成逐调用授权、ready/stop 通知和生命周期控制；控制连接 EOF、`TunnelStop`、daemon shutdown 或 CLI/UI 取消都会关闭隧道。
- L/D 的本地 listener、R 发给 SSH server 的 bind 请求，以及 L/R 固定目标地址均强制为 `127.0.0.1`；地址不进入 CLI、UI 或 IPC `TunnelSpec`，端口 `0` 支持系统分配。R 模式还只接收 `connected_address` 与 `originator_address` 都严格解析为 IPv4 `127.0.0.1` 的 forwarded channel。每条 tunnel 默认最多 32 个并发连接、硬上限 128；同一 SSH session 的所有 tunnel 合计最多 256 个 live flow，远程转发待接收队列最多 32，daemon 同时最多 8 个 tunnel control。
- setup 使用 direct 30 秒 / IPC client 32 秒 / daemon 30 秒上限；SOCKS5 握手和远程转发本地目标连接各有 10 秒上限。停止时先给 live flow 最多 2 秒 drain，再给 tunnel task/远程 forward cancel 最多 4 秒；daemon-routed GUI/CLI client 的清理上限为 7 秒，UI 退出总隧道宽限为 8 秒。不确定的 `-R` cancel、未知或失配的 server-opened channel 会使 transport 失效，避免遗留远程 listener/channel。
- CLI 每次启动 tunnel 都重新验证目标 profile 的独立口令；UI tunnel 必须在该 profile 固定五分钟授权有效时启动，授权到期或撤销会停止它。运行中的每条 TCP 连接不会再次进入口令流程。强制回环阻止 LAN/公网直接连接 listener，但不隔离同一主机上的其他应用；目标协议仍应具备自己的认证、授权和加密。

## 传输提交与清理

新的 `transfer` 命令与 UI 进度卡使用固定阶段 `preflight/hash/negotiating/transferring/verifying/committing/cleanup/completed/failed/cancelled/stalled`。CLI 的 `--progress json` 输出稳定 NDJSON；TTY 与 UI 最多每 250 ms 接收一次常规进度更新。`confirmed_bytes` 只在接收方确认后推进，最终 100% 只在完整性校验与 no-overwrite commit 成功后显示。`transfer status` 只能读取同一 profile 的脱敏快照，不包含本地或远端路径；终态保留 15 分钟。每个根请求使用 `transfer.read`、`transfer.write`、`transfer.status` 或 `transfer.cancel` 精确授权，chunk/ack 只是该根请求的后续帧。

registry 的“同一 profile”以随机 128-bit profile id 判断，不以可复用显示名称判断；即使终态仍在 15 分钟保留期内，删除后同名重建的新对象也看不到旧 transfer id 或统计。

`--backend auto` 会先通过固定 SSH exec 命令探测 `serctl-xfer serve --stdio`；版本和能力握手成功才报告 `native`，否则明确报告 `sftp_fallback`。`--backend native` 不允许回退。两种后端当前都保守把协商 chunk 限为 2 KiB。受控的完整 russh exec/SFTP 服务端矩阵中，4/8/16/32 KiB 帧都能到达 handler 并获 ACK，已经排除通用 ChannelStream、SSH window/flush 与服务端分帧本身是根因；尚未定位的是现实 OpenSSH + `serctl-xfer` 子进程 stdio 边界。外部实机和相对 `scp` 80% 门槛完成前不会提高 cap，也不能把 helper 接入误报为性能验收完成。

当前 `serctl-xfer serve --stdio` 的生产实现只在 **Linux** 远端启用 resume/fsync/no-follow/no-replace；macOS、BSD 与 Windows helper 都在 Hello 前失败关闭，避免先传完整文件再发现提交原语不受支持。Windows 本地 CLI/daemon 连接 Linux 远端是当前支持方向；其他远端应使用 `backend=auto` 的明确 SFTP fallback。

`--resume auto` 仅接受 `auto` 或 `native`，且 helper 不可用时失败关闭，不会降级成不可恢复的 SFTP。上传 journal 绑定 profile id/generation、目标、size、SHA-256、backend 与随机 ownership token；schema 2 远端 sidecar 保存 token hash、transfer id、size、SHA-256、durable offset、partial 的 device/inode 和 receiving/committed 状态，不保存 profile 口令。committed receipt 可在同一 id/token 的显式恢复请求中对账终态，但目前没有消费 ACK/GC/保留期。下载 journal 绑定同一 profile identity、远端源、最终本地路径、protected partial、远端 size/SHA-256 与 durable prefix。恢复时任一 identity、长度、token 或摘要不匹配均拒绝，绝不截断未知文件。UI 默认关闭恢复，并提供“启用断点续传”选项明确这一 helper 依赖。

恢复成功时 daemon 先发 `resumed` 进度事件，CLI 的窗口/平均速度基线从 durable prefix 之后重新开始，既有字节不会虚增吞吐或生成假 ETA。native pull 对 confirmed/durable/window 累计 ACK 全部做单调与协商边界检查；helper 的确定拒绝使用结构化 `Error`，commit 已发出后的失败则标记 `outcome_unknown`，必须先检查目标再重试。

清理语义按 backend 区分：SFTP 路径在 no-overwrite commit 已对账后，清理本方 partial 失败只记录告警；Linux native helper 在发送 `Completed` 前以 token/receipt/identity 校验清理，失败返回结构化 `cleanup_incomplete`，不会伪报已清理。`resume=auto` 可用同一 id/token 的 committed receipt 显式恢复终态；`resume=never` 没有 receipt 恢复保证，出现 `outcome_unknown` 或 `cleanup_incomplete` 时必须先独立核对目标与残片，不能盲目重试。

上传前对单次打开的稳定本地 handle 计算 SHA-256，传输结束后 daemon 重新读取远端 partial 并核对同一摘要；下载由 daemon 发送远端读取摘要，客户端在本地 protected partial 上核对后才执行 no-overwrite commit。idle timeout 只在 confirmed bytes 前进时刷新；可选 total deadline 覆盖整个调用。超时先产生 `stalled` 快照，随后进入 `failed`；普通权限、路径或协议拒绝不会被误报为停滞。

上传先在远端同目录以 `CREATE | EXCLUDE` 创建随机临时文件，并从创建时设置权限 `0600`。CREATE Future 第一次被 poll 后就保守记录 partial 可能存在；只有匹配请求的显式 SFTP `STATUS` 拒绝能证明这次请求没有创建 partial，deadline、断开或协议错误都保持不确定并进入 fresh-channel 有界清理。写完后必须使用服务器声明的 `hardlink@openssh.com` 扩展以 no-replace 方式安装目标，再删除本方临时名；扩展缺失或返回错误都失败关闭，绝不降级到无法跨服务端实现证明 no-overwrite 的 SFTP v3 `RENAME`。

若 daemon 上传在 `UploadEnd` 后发生 deadline/断开，client 给已在途 commit 响应 2.25 秒有界对账窗口；只有明确 `TransferDone` 才报告成功，无法确定时返回“提交结果未知，重试前检查目标”的专用错误。直连上传使用 owned worker；外层 timeout/drop 只发取消，worker 继续拥有 fresh-channel 清理。commit 已开始后的 `Finished(Err)` 也被分类为 typed `UploadCommitOutcomeUnknown`，不会把 transport/protocol 错误误报为确定未提交；若已由稳定状态确认目标提交，则后续 partial 清理错误不倒退成失败。网络/服务器彻底不可用、进程强杀或清理宽限耗尽时仍可能留下 `.serctl-part-*`。

上传源在路由和 SSH 认证之前只打开一次，并通过稳定普通文件 handle 读取；FIFO、设备和目录被拒绝。Unix 以非阻塞方式打开后 `fstat`，允许指向普通文件的 symlink；Windows 以 `OPEN_REPARSE_POINT` 拒绝 reparse source。

下载临时文件的 protected `CREATE_NEW` 一返回成功就立即 arm `CreatedFileRollback`，然后才做安全验证；验证错误或 panic 会删除确切的新对象。Unix 用 dev/inode 区分路径替换，Windows 通过稳定 handle 删除，因此碰撞或替换不会误删他人对象。本地 partial create 由 owned `spawn_blocking` 返回 `UnclaimedLocalPartial`，若异步 Future 被取消、超时、drop 或 unwind，其 Drop 仍会调度清理；claim 交接中间没有 await。

Unix 创建时即为 owner `0600`；Windows 将禁止继承的 owner/SYSTEM/Administrators DACL 作为 `SECURITY_ATTRIBUTES` 传给 `CREATE_NEW`。完整写入、`flush`、`sync_all` 后，以同目录 hard link 原子 no-replace 安装最终名，并校验 handle 身份；目标已存在时失败且不覆盖。Windows 在复制路径/启动不可逆 hardlink worker 前显式复查 deadline，并在有界 blocking worker 内对稳定 handle 调用 `GetFileInformationByHandle`；已进入内核的调用仍不可抢占。

daemon download 把下游断开/背压识别为 `IpcResponseWriteFailure`：一个不读取的大下载只关闭该 IPC/SFTP channel，不会使 daemon 共享 SSH transport 失效。

本地 `open` / `flush` / `sync_all` / `hard_link` 等文件系统调用进入内核后不能由 async timeout 抢占。实现保留 owned blocking task并进行有界结果/身份对账，不会把“退出等待”误报成普通成功；在病态文件系统中，调用仍可能越过对账窗口后完成，这是明确的平台边界。

## 构建与验证

体积优化已经提交并推送为 clean 基线 `94fb37118f4b31ab997f40cdba09d105081bde18`。当前 IPC v8 全局 broker、CLI/UI 授权语义与 loopback-only tunnel 工作树建立在后续重构上。下面严格区分 beta-2 冻结前源码门禁、较早 dirty 构建、历史体积测量和最终 clean tag/CI artifact：

```powershell
cargo fmt --all -- --check
git diff --check
cargo check --locked --offline --workspace --all-targets --all-features
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-targets --all-features -- --test-threads=1
cargo audit --no-fetch
cargo build --locked --offline --workspace --bins
# 正式 Release 禁止 --all-features，避免启用 serctl-core/test-support
cargo build --release --locked --offline --workspace --bins
target\debug\serctl_cli.exe --version
target\release\serctl_cli.exe --version
target\release\serctl_daemon.exe --version
target\release\serctl-xfer.exe --version
```

测试套件除单元测试外，还会在随机本地端口启动临时 SSH/SFTP 服务和真实 daemon；daemon IPC 使用当前平台的 Named Pipe/Unix Socket，覆盖认证、错误令牌拒绝、exec 正常退出、deadline、客户端断连取消，以及上传/下载内容往返。所有状态写入 `target` 下的隔离临时目录，不读取或修改真实凭证库；外部服务器兼容性验证仍需要可访问的测试服务器。

2026-08-31 的 beta-2 冻结前 dirty 工作树完成 `--workspace --all-targets --all-features` 离线串行测试：CLI 147 通过/1 忽略、Core 117、Daemon 31、Protocol 46、Transfer Protocol 5、helper 14，合计 **360 通过、0 失败、1 忽略**；同配置严格 Clippy `-D warnings`、Rustfmt 与 diff whitespace 检查也通过。受控 E2E 在真实 Named Pipe、daemon、SSH channel 与内存 SFTP/native 服务上完成固定 **1,298,223-byte** 快照并核对完整内容；首个 negotiating 事件在 500 ms 门槛内，Agent `transfer.write` 上传也覆盖在同一 E2E 中。另一个完整 russh exec/SFTP 服务端矩阵已验证 4/8/16/32 KiB 帧均能到达并获 ACK，因此排除了 core ChannelStream、SSH window/flush 与服务端分帧本身是 2 KiB 上限根因；真实 OpenSSH + `serctl-xfer` 子进程边界仍待插桩，当前 2 KiB 上限不提高。`cargo audit --no-fetch` 的既有离线缓存证据不是在线最新性证明。`Local-Linux2` profile 已确认存在，但本轮进程没有该 profile 的独立口令，未执行 21 B、固定快照、64 MiB 与 1 GiB 的外部实机验收，也不把受控服务端结果替代为实机结果。

匹配的 dirty Release 三件套曾在独立 `target/staging-v0.3/release` 中完成冻结前离线构建，未覆盖常用 `target/release`。CLI 与 daemon 的 build identity 均为 `5690281a2535-dirty`，daemon 自检报告 `IPC v8..=v8`，helper 报告 transfer protocol v1；这些产物只用于冻结前快照验证，不是 beta-2 clean 制品或签名发行版。

本轮预发布候选在 Cargo 与文档中冻结为 `v0.3.0-beta.2`。其可发布来源只能是最终由该标签指向、已推送至 `origin/main` 且通过远端门禁的 clean commit；冻结前 dirty staging、旧标签后的中间提交或本地测试结果都不能替代该来源与仓库外交付记录。

### Release 体积策略

正式 Release 使用以下可移植、体积优先配置：

```toml
[profile.release]
opt-level = "s"
lto = "fat"
codegen-units = 1
panic = "unwind"
strip = "symbols"
```

`opt-level = "s"`、fat LTO、单 codegen unit 与符号剥离共同压缩交付文件。`panic = "unwind"` 是有意保留的安全语义：终端 raw mode 恢复、敏感缓冲清零和已创建 partial 的回滚都依赖 unwind 时执行 `Drop`；不以 `panic = "abort"` 换取更小体积。构建也不使用 UPX，避免引入运行时解包、恶意软件误报、代码签名/扫描和故障定位方面的额外发布变量；不使用 `target-cpu=native`，确保同一 Windows 架构内的 Release 不绑定构建机 CPU 指令集。

依赖侧把 Tokio 的 `full` feature 收窄为实际使用的 `fs`、`io-std`、`io-util`、`macros`、`net`、`rt-multi-thread`、`signal`、`sync`、`time`，并移除已不再需要的 `async-trait` 直接依赖及锁定包，避免为未使用能力保留依赖和编译输入。

提交 `94fb371` 前的同一优化轮次 A/B 数据如下；它们用于选择并提交 release profile，不是当前 IPC v8/授权/隧道工作树的二进制测量：

| Release 候选 | 文件大小 | 相对原基线 |
| --- | ---: | ---: |
| 原标准 Release 基线 | 17,074,688 B | — |
| `opt-level=3` + fat LTO 候选 | 13,895,680 B | -18.6% |
| 选定的 `opt-level=s` profile | 10,734,080 B | **-37.1%** |

三次 `add` 的 Argon2 路径测量中，`opt-level=s` 平均约 215 ms，`opt-level=3` + fat LTO 平均约 200 ms，差约 7.5%。样本仅有三次，且 Argon2 本身刻意消耗时间和内存，因此这只是取舍信号，不是通用吞吐基准；当前选择以减少约 6.34 MB 分发体积为优先。

历史标准路径测量曾得到 `target\release\serctl.exe` **10,723,840 B**、SHA-256 `68F571F7FDAD09986C8E5E6E23F8AE229B8E0043654298F3C349A0B99490F601`，以及单独留存、不计入分发体积的 **2,748,416 B** PDB。该摘要产生于优化提交前，随后源码才以 clean commit `94fb371` 推送；这里只把它保留为 profile/体积选择证据。

上一轮 IPC v4 dirty 功能树的标准 Release 曾为 **11,273,216 B**，SHA-256 `A464F57EE7D60ACB583C0300D399E183F1BCB328C60B88CE6498D4C46592DE53`；单独 PDB 为 **2,797,568 B**。对应 debug EXE 为 **49,509,376 B**，SHA-256 `E2BEA438B1DFE10CF5996D69C829F009F383112424667332D4FC0DA67EE87FF8`；两者版本均为 `serctl 0.1.0 (git 94fb37118f4b-dirty)`。当前外部 IPC wire 已进入 v8（内部仍保留部分 `v6` 模块/类型名作为实现兼容别名），本地同名路径可能已被覆盖，因此这些只作为上一轮记录，不描述当前文件，也不是正式 clean artifact。

`v0.2.0-test.1` 标签的完整发布门禁与标签后的 `8bb9780` 修补复核是两个独立证据集，不与较早 v5 工作树的 **258/258** 相加。验证证据如下：

- **PASS：**Rust 1.97.1 下 `cargo fmt -- --check`、`git diff --check`、locked/offline all-target/all-feature `cargo check` 与严格 `clippy -D warnings`；
- **PASS（`v0.2.0-test.1` 标签）：**locked/offline all-target/all-feature 串行测试 **293/293**；测试报告执行 **116.68 s**；`build.rs` standalone tests **15/15**；
- **PASS（提交 `8bb9780` 后分包复核）：**CLI **134/134**、Core **115/115**、Daemon **27/27**、Protocol **43/43**，合计 **319/319**；Daemon `clippy --all-targets -- -D warnings`、`cargo fmt --check` 与 `git diff --check` 通过；
- **测试环境说明：**一次并行 workspace 运行中的既有 Windows KEX deadline 套接字测试遇到本机 `10053 ConnectionAborted`；该单项立即复跑通过，随后 Core 全套 **115/115** 通过。该现象未发生在 Grant、UI 或 vault 租约修补路径，不把首次失败的 workspace 命令记为全绿；
- **PASS（带新鲜度边界）：**`cargo-audit 0.22.2 --no-fetch` 扫描 **531 dependencies / 1198 advisories**，exit 0；同时报告 cache/index warning，因此只证明本机离线缓存快照，不证明 advisory 数据库在线最新；
- **PASS：**`cargo-deny 0.20.2` 的 bans、licenses、sources 检查均 exit 0；
- v4 定向覆盖包括独立 KDF/key package、随机 128 位 profile identity、identity/generation-bound call key、明文 catalog、Windows admin + USB 2-of-2、介质 create-new/同步/回读、CLI 随机口令“先交付文件、后提交”失败路径、UI 随机口令“先显示确认、后提交”取消路径、profile 手动/随机轮转、保留式恢复、破坏性重置、全量 v2→v4 迁移、未发布中间 v3 fail-closed、Linux `--target-user` NSS 绑定/不可逆降权与 offline recovery fail-closed，以及 UI 的 5 分钟 profile / 2 分钟 admin 授权；
- 已单独通过定向回归 `vault::tests::recovery_public_key_substitution_is_rejected_by_admin_and_profile_bindings`：只替换 recovery public key 会同时被 admin config digest 与 profile AuthSeed tag 拒绝，tag bit flip 和跨 profile tag replay 也被拒绝；该单项结果不替代待完成的全量门禁；
- 当前 IPC/SSH/SFTP/tunnel 回归应继续覆盖 v8 transcript/AEAD、per-profile call-key 互证、错误 call key 在业务帧前失败、exact root intent、旧锁 fail-closed、broker-only 路由和 loopback-only L/R/D；较早 v5 四帧 token 用例只属于历史协议证据；
- Shutdown 完整帧边界、SFTP mutation per-poll deadline、`CreateDirOutcomeUnknown`/明确 `STATUS`/plain rejection，以及 partial CREATE 状态均有定向回归；真实路径证据来自已认证 broker/SSH/SFTP E2E，不把这些定向用例表述为新增独立 E2E 函数；
- 较早一次 dirty v5 构建曾完成 debug/release all-target/all-feature 与二次 `Fresh`，但它早于本轮后续安全修补，不能描述当前源码或当前同名文件；
- 最终源码与文档冻结后的 dirty EXE/PDB 大小和 SHA-256 只写入仓库外部交付记录；正式制品必须从 clean commit/tag 重建并把摘要写入 release metadata；
- 较早的 RustSec/cargo-deny 与测试数字只属于其当时源码状态；本轮以以上最终数字为准，不与任何历史数字相加；
- 上一轮 IPC v4 **234/234**、提升态 Windows security **12/12**、硬化基线 **203/203 × 3**、所有者/租约树 **205/205 × 1** 以及较早 v5 **258/258** 均仅为历史证据；
- `argon2` 的 `zeroize` feature 已确认；`rsa` 与 `ttf-parser` 均不在锁定依赖图中；
- 较早的独立终审只属于当时源码状态，不是当前 vault v4 的形式化证明；
- `v0.3.0-beta.2` 仍是预发布测试版本；可靠回滚来源以最终推送的唯一 clean tag/commit 为准。为避免把摘要写回受监控源码造成自引用重建循环，冻结前 dirty artifact 的大小与 SHA-256 只记录在仓库外部交付记录中，不嵌入这些受监控文档；beta-2 摘要必须写入 clean tag/CI release metadata。

CLI、daemon 与 helper 的 `build.rs` 入口共享 [`build_support/git_provenance.rs`](build_support/git_provenance.rs)，将同一 12 位 Git commit 和 dirty 状态写入三件套版本字符串。共享实现先移除所有可重定向 repository/work-tree/index/object/config/replace refs 的继承 Git 环境，禁用 system/global config，只从 manifest 祖先的文件系统发现真实 `.git`；规范根必须包含 manifest，并以固定 `--work-tree`、`GIT_NO_REPLACE_OBJECTS=1`、关闭 fsmonitor/untracked cache 的 Git 查询证明来源。它解析 index 的 stage-0 mode/OID/path，并用 `git hash-object --no-filters` 计算工作树原始 blob OID，避免 clean/smudge filter 隐藏源码改动；mode `160000` gitlink 直接 fail-dirty。三处 wrapper 均在 CI 中执行共享 standalone fixtures；实现还监听 `.git/info/attributes` 以及 HEAD/index/ref/config/info/exclude 等元数据，`assume-unchanged` / `skip-worktree` 也强制 dirty。仓库通过 `.gitattributes` 的 `* text=auto eol=lf` 固定文本策略，并以 `core.autocrlf=true` clean checkout fixture 验证不会假 dirty。查询失败同样 fail-dirty。仓库根不作为 watcher，所以新根级 untracked 文件可能需其他受监听输入变化才触发重算；ignored/外部/动态构建输入仍是披露边界。正式 release 必须从 clean checkout 构建并记录 commit、lockfile、工具链、SHA-256 与签名。

发布链固定 Rust 1.97.1，并配置三平台 locked all-target/all-feature CI、严格 Clippy、build-script fixtures、在线 RustSec（warnings 即失败）、cargo-deny 的 license/source/bans 策略、CycloneDX 1.5 XML/JSON SBOM 与 Dependabot。Windows release 只允许在 `main` push 且 quality/test/RustSec 全绿后生成；构建与 SBOM 的 `SOURCE_DATE_EPOCH` 均绑定该 commit，证据记录完整 SHA、event/ref、工具链/runner，并哈希 EXE 与 PDB。beta-2 是否通过远端门禁必须以其最终 clean SHA 对应的 GitHub Actions 记录为准，不能把本地门禁冒充远端 CI 证据。

## 已知边界

- TOFU 首次连接无法自行排除 MITM；
- 远端上传要求服务器支持 `hardlink@openssh.com`；缺少该扩展的旧 SFTP 服务端会被安全拒绝；
- CLI 的逐调用验证与 IPC call-key 证明阻止“只窃取受保护运行锁 token”的同账户进程发起新操作；UI 则在验证后最多五分钟持有每个 profile 的口令副本，超管操作最多两分钟持有超管密码。这是明确的可用性/内存暴露权衡；
- v4、2-of-2 与 `Zeroizing` 防止静态 vault/单份介质直接恢复秘密，但不构成反调试边界。正常 SSH 或恢复必须在普通进程中短暂得到 profile 口令、key package、SSH 密码或会话材料；能读取/注入 daemon、UI、CLI 内存、记录键盘、抓取 crash dump 或拥有管理员级调试能力的攻击者仍可能取得或滥用它们。达到“调试器也不可见”需要非导出硬件密钥或不可调试 enclave，并把完整 SSH 认证/会话密码学移出普通进程；当前版本没有实现该边界；
- Windows 超管密码单独不能解密 profile，U 盘介质单独也不能；二者共同用于保留式恢复时，当前实现会在 serctl 进程内解密旧凭据后重新封装。普通文件型恢复介质可以被复制，所谓“必须配合 serctl”是格式、权限和操作流程约束，不是阻止管理员重实现算法的硬件绑定。绝对路径、create-new、文件类型和回读检查也不能证明某个卷真是可移动介质、已物理分离或使用后已弹出；这是部署/保管责任；
- profile 名、host、port、generation 和恢复策略标识是明文 catalog，不应放置敏感标签。AEAD 能发现字段与密文的局部篡改，但 generation 只防当前进程中的陈旧授权/竞态，不防具有文件写权限者回滚一份完整、内部一致的旧 vault；需要可信单调计数器或远端审计才能跨快照检测回滚；
- Linux 管理授权不保存第二个超管密码；offline recovery、recovery rotation 和 v2→v4 migration 在具备 root-owned 系统 share store 与恢复专用 target-vault 边界前均有意失败关闭。当前 `--target-user` 只实现 CLI 破坏性 reset：必须从有效 UID 0 启动并指定 NSS 账号，在打开目标 vault 与创建 Tokio worker 前不可逆降为该非 root 账号；它不恢复或保留任何旧秘密，也不让 root 指定任意 home/vault 路径，不能被当成已实现的离线恢复边界；
- tunnel 启动后每条 TCP 连接不重复验证 profile 口令。L/D 本地 listener 与 L/R target 强制回环；R 请求的远端 listener 也是 `127.0.0.1`，且 serctl 只路由 connected/originator 地址都严格为 IPv4 `127.0.0.1` 的 forwarded channel。若远端 sshd 启用 OpenSSH `GatewayPorts` 并把请求改成 wildcard，外部连接不能形成可用的 serctl 转发，但远端端口仍可能处于监听状态并可被探测；需要彻底消除该网络表面时还必须禁用 GatewayPorts 或配置远端防火墙。回环也不隔离同机应用；动态 SOCKS5 是 `NO AUTH`，本机客户端可借已连接 SSH 主机访问其可达的任意目标，回环只限制 listener 暴露而不限制目的地；
- 本地不可抢占的 kernel 文件系统 syscall、已经启动后只能异步 detach 的 blocking work、同用户可写目录中的路径竞争，以及进程强杀/崩溃均超出协作式 cleanup 的完整保证；blocking pool 饱和可延迟本地 partial 清理，线程创建耗尽时可能保留路径；UI panic/drop 只能 cancel + `shutdown_background`，不能保证有机会等待异步清理；
- 当前 IPC v8 不与旧 per-profile v7/v6/v5/v4 或更早协议 dual-stack。当前 client 对旧 descriptor/锁在连接前 fail closed，不发送业务帧、不删除证据，也不回退直连。活动旧 daemon 必须先用与它匹配的旧 executable 正常 `down`，再把 CLI、daemon 与 helper 作为匹配集合整体切换；stale 旧状态只能在离线确认 PID/进程不存在、租约未持有、owner/ACL/type 安全后人工处置，绝不能盲删；
- Windows 本机覆盖原生 IPC、DACL、原子写穿成功/失败/清理；这不是实际断电测试。Windows symlink/reparse 动态测试在无创建权限时会跳过，尚无多账户 ACL 攻击矩阵；GitHub Actions 已配置 Windows、Linux、macOS 的 locked all-target/all-feature 矩阵，beta-2 的远端结论只接受与最终 clean commit 绑定的 CI 证据；
- 较早 tunnel 基线曾覆盖 daemon `-L`/`-R` 与当时存在的 direct `-L`/`-D`；direct 已不是当前 v8 路由。当前 broker-only 路径仍需与 clean commit 绑定的 L/R/D 复验及 OpenSSH/Dropbear 等外部 server 兼容矩阵；
- 原始远端命令与 PTY 输出被视为受信任终端内容；不要把不可信字节直接显示在交互终端；
- `Zeroizing` 只能清理由本程序持有且可控的副本，不能清除 OS、allocator、第三方库、swap、崩溃转储或同权限调试器中的副本。非凭证 UI 的 command/shell/path/output 仍会在 egui、字体布局、IME、OS 与 allocator 中产生普通临时副本；稳定 widget ID 和每帧清 undo 不等于完整内存清零；
- 来源字符串只是 Git 来源信号，不是签名、制品证明或可复现构建证明；根级新 untracked、ignored、外部或动态构建输入还有上述 Cargo watcher 边界，可靠回滚仍需 clean commit 与已推送的唯一来源点。

## 许可证

本项目依据 [Apache License 2.0](LICENSE) 授权，Cargo 元数据使用 SPDX 标识 `Apache-2.0`。
