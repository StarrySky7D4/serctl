# serctl

`serctl` 是一个纯 Rust 的持久 SSH 控制工具，提供 Winit/Egui 桌面 UI 与完整 CLI。它复用 SSH 连接执行远端命令、浏览目录、通过 SFTP 上传/下载文件，并提供 Bash PTY 交互。

当前工作树完成了 IPC、凭证、deadline/cancel、原子传输与可回滚来源方面的系统性修补。实现级说明、威胁边界和验证证据见 [架构、安全与运维说明](docs/serctl-architecture-security.html)。

## 功能

桌面端支持：

- 新建、编辑、重命名和删除主机配置；
- 启动、检查或停止持久 daemon；
- 执行命令并分别显示 stdout、stderr 与明确的退出码；
- 分批浏览远端目录、返回上级目录和创建目录；
- 上传与下载文件，目标已存在时安全失败；
- 持续 Bash PTY，会话内可输入命令、发送 `Ctrl+C` / `Ctrl+D` 和清屏；
- profile epoch、目录 generation、daemon instance id 与取消令牌共同拒绝旧任务的迟到结果；
- 正常退出时先取消在途传输，最多等待 6 秒协作清理并中止超界任务，再并发停止 UI 拥有的 daemon，最后以 1 秒上限关闭 runtime。

开发时启动 debug UI：

```powershell
cargo run
# 等价于 cargo run -- ui
```

## CLI

```powershell
$exe = ".\target\debug\serctl.exe"

# SSH 密码与主口令交互输入，不进入 argv
& $exe add prod --host 192.168.5.15 --user deploy --port 22

# 前台运行持久 daemon；另一个终端复用它
& $exe up prod
& $exe exec prod --timeout-secs 30 -- "uname -a; whoami"
& $exe shell prod

# 上传请求，再拉取服务器 evidence
& $exe upload prod .\request.json /tmp/request.json --timeout-secs 120
& $exe download prod /tmp/server-evidence.json .\server-evidence.json --timeout-secs 120

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
| `exec NAME [--timeout-secs N] -- <CMD...>` | 执行远端命令，默认硬 deadline 为 300 秒 |
| `upload NAME LOCAL REMOTE [--timeout-secs N]` | 上传普通文件，不覆盖已有远端路径 |
| `download NAME REMOTE LOCAL [--timeout-secs N]` | 下载文件，不覆盖已有本地路径 |
| `shell [NAME]` | 打开交互式 PTY shell |
| `status [NAME]` | 查看 daemon 状态 |
| `down [NAME]` | 停止 daemon |

`up`、`shell`、`status` 的 `NAME` 省略时为 `default`；`exec`、`upload`、`download` 要求显式 profile。自动化可用 `SERCTL_SSH_PASS` 和 `SERCTL_MASTER` 注入口令；程序在任何可失败的 Unicode 解码和异步 runtime 之前，先快照并从自身环境同时删除这两个变量；一个值无效也不会把另一个留在环境中。父进程、调试器或同权限进程仍可能观察环境，交互输入更适合高价值凭证。

CLI 将远端非零退出状态映射为本地非零退出码，缺失退出状态或 IPC 中断始终是失败，不再用 `0` 兜底。自身诊断、Clap 错误、日志、profile/路径/远端状态消息会转义控制字符，防止错误文本注入终端；`exec` 与 shell 的原始远端输出仍按受信任终端数据处理。

## 架构

```text
Winit / Egui UI ─┐
                 ├─ client ── IPC v3 ── daemon ── russh 0.62.5 ── SSH
CLI ─────────────┘       │       │              └─ russh-sftp / SFTP v3
                         │       └─ persistent session + bounded handlers
                         └─ direct fallback + profile lease

vault v2: Argon2id → ChaCha20-Poly1305(AAD: domain/name/host/port)
IPC: Windows Named Pipe / Unix Domain Socket，共用长度前缀 JSON 帧抽象
```

每个 `exec` / `list` / `create-dir` / `upload` / `download` 请求只探测并认证 daemon 一次，然后固定走该 IPC stream 或直连路径，避免二次探测的路由竞态。无 daemon 的直连路径持有 profile 共享租约；首次 TOFU pin 需要只写一次时升级为排他租约，`exec`、SFTP 与 shell 使用同一规则。

daemon 最多接受 64 个并发本机连接；会完整缓冲结果的 `Exec` 与 `ListDir` 共用额外 8 槽上限。认证后 10 秒仍未发送业务帧的连接被关闭。响应写通常受请求剩余 deadline 与 2 秒局部上限的较早者约束，并可被 shutdown 抢占；远端上传已明确提交而原预算刚过时的 `TransferDone` 例外使用新的最多 2 秒确认窗口。关闭时广播取消，使用 `JoinSet` 等待 handler 最多 4 秒，再中止并回收剩余任务。

UI 启动 daemon 的 status 探测、bind、lock publication 与 readiness 全部消耗同一个 30 秒 absolute deadline。listener 绑定/锁发布在 owned blocking worker 中，原子写锁前就 arm 了按 token 删除的 guard 并持有排他租约；迟到、取消或 readiness receiver 已消失时，Drop 会在 blocking 线程完成 listener/锁/租约清理，不会留下已发布但无主的 daemon。

## 凭证与运行锁

- 凭证库位于 `%USERPROFILE%\.serctl\vault.json`。Argon2id 当前参数为 64 MiB、3 轮、并行度 1，并对磁盘中 KDF 参数设置安全上下限。`argon2` 已启用 `zeroize` feature；派生用的 64 MiB 矩阵由 `Zeroizing<Vec<Argon2Block>>` 持有，内部初始/块哈希由该 feature 覆盖清零。
- 用户名、SSH 密码和 host-key pin 以 ChaCha20-Poly1305 加密；v2 AAD 同时绑定格式域、profile 名、host 与 port。明文 host/port 被改写后认证失败。
- 磁盘中的 format 字节不在 AAD 内，所以更新时先按 legacy no-AAD 解密验证，才允许显式离线替换真正的旧 profile；旧 host-key pin 不会被继承。将现代记录的 format 从 2 翻为 0 会因 AEAD tag 失败，不能用来擦除 pin 或重开 TOFU。
- vault 校验器先验证主口令，再允许写入。保存采用稳定文件句柄、进程间锁和同目录原子替换；锁等待上限为 30 秒，不会无限阻塞。
- vault 与运行锁共用的受保护原子提交在 Unix 上执行同目录临时文件 `sync_all`、原子 `rename` 和父目录 `fsync`；Windows 从创建临时文件起即应用 protected DACL，`sync_all` 后以稳定的受保护父目录句柄配合 `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` 替换。注入提交失败时旧目标保持不变且临时文件被清理。这里验证的是 OS 提供的持久化/写穿原语与失败路径，不是断电模拟，也不承诺硬件或文件系统超出其语义的行为。
- 敏感 JSON 使用“计数遍 + 精确预分配写入遍”，直接落入 `Zeroizing<Vec<u8>>`；vault、运行锁与 IPC 帧不再先产生普通敏感序列化缓冲区。完成和错误分支均尽早清零可控副本。
- Windows 凭证目录/文件使用禁止继承的 owner、SYSTEM、Administrators DACL；Unix 目录为 `0700`、文件为 `0600`。路径通过稳定句柄检查 owner、类型、ACL/mode 与 reparse/symlink 边界，失败关闭。Windows owner 校验接受对象 owner 等于当前进程令牌的 `TokenUser` 或该令牌的 `TokenOwner`：这兼容提升令牌以 `BUILTIN\Administrators` 作为默认 owner 的正常创建结果，同时仍拒绝与本令牌无关的 SID，并且不扩大既有 DACL 已明确包含的管理员边界。
- 运行锁采用 profile SHA-256 文件名、受保护权限和 profile 生命周期租约。读取器在首次 I/O 前就建立 `Zeroizing` 64 KiB + 1 固定缓冲，避免增长重分配留下 token 前缀。profile mutation 只有在排他锁实际返回 contention 时才报告“正在被 direct operation 或 daemon 使用”；打开 lease、owner/ACL 与其他 I/O 错误保留原始原因，不再被误包装为占用。畸形的当前 protocol-v3 hashed 锁只能在同一排他租约下重验后清理；对账只有 `Removed` / `Absent` 允许直连 fallback，`Changed` / `Contended` 均 fail closed。Unix raw legacy 锁仍会被读出并拒绝。

UI 的 workspace master、editor SSH password 和 editor master 使用 `MaskedSecretTextBuffer`：egui 只能看到与 Unicode 字符数相同的 `*`，每次显示前后都把 undo 容量设为 0，Unicode 编辑替换的旧 app-side 字符串会清零。eframe persistence 已移除，window/egui memory persistence 都关闭。`SensitiveUiMessage` 的 RAII envelope 从排队、send 失败、receiver drop 一直存活到 reducer match 完成，unwind 也会清零 payload 并取消 shell；command/PTY 的 lossy 转换中间缓冲为 `Zeroizing`。profile 保存成功时，reducer 会先清零并移除原名和新名对应的缓存行，同时立即失效当前 profile context、目录、命令输出和 shell；即使随后 refresh 失败，同名覆盖也不能继续操作旧主机状态。profile refresh 从 UI 调用时就建立单一 32 秒 deadline，覆盖 blocking vault/KDF 和每波最多 8 个 daemon status 探测；超时后运行中的 blocking 任务可迟到，但结果由 RAII 清零且不阻塞 Tokio worker。

## IPC v3

daemon 不监听本机 TCP。Windows 使用拒绝远程客户端的 Named Pipe；每个 pipe instance 在创建时即带禁止继承、仅 owner/SYSTEM/Administrators 可访问的 DACL。Unix 使用 `0700` runtime 目录中的 `0600` Unix Socket。

客户端连接后先核对 OS 对端身份：Windows Named Pipe server PID 必须等于受保护运行锁中的 PID；Unix peer UID 必须等于当前 euid，平台能提供 PID 时还必须匹配。随后执行三帧 nonce-HMAC-SHA256 互认证：

```text
client → AuthHello(version, client_nonce)
daemon → AuthChallenge(version, server_nonce, server_proof)
client → AuthResponse(client_proof)
```

HMAC 证明以运行锁中的 256 位随机秘密为 key，并绑定不同的 client/server role 域、协议版本、profile、派生 endpoint id 和双方 nonce；秘密本身不在 IPC 上发送。Base64 必须是严格、规范的 32 字节编码，nonce 不得复用，证明按常量时间比较。旧 bearer-token 协议锁与未知协议版本均被拒绝。

认证帧最多 4 KiB，控制帧最多 16 KiB，业务响应最多 16 MiB；二进制字段使用规范 Base64。长度前缀读取只有在第一个 header 字节之前读到 0 字节才是正常 EOF；1–3 字节的部分长度前缀必定报错。命令输出总计最多 8 MiB，上传 chunk 与 shell input 各最多 64 KiB。

认证有 2 秒上限；`status` / `down` 控制交换为 3 秒。Shutdown 的 4 字节长度头与完整 payload 被 writer 接收后、flush 前即置为 sent；从这个线性化点起，即使 flush、Ack 读取或连接随后失败，也会再以运行锁 token + 租约对账最多 10 秒。同 token 表示预期 generation 仍活跃，不同的有效 token 证明替换 generation 已在旧 daemon 释放排他租约后启动；锁消失本身不足以报成功，还必须探测到预期 daemon 的运行租约已释放。运行锁轮询均在同一 absolute deadline 下交给 blocking worker。

v3 有意不与 v2 混用，因为 exec 的拒绝/不确定语义已经收紧：daemon 的普通 `Error` 只表示确认尚未把 exec request 交给 russh，远端可能已接收后的失败必须携带 typed `ExecOutcomeUnknown`。v3 client 在读取锁时就拒绝 protocol 2；即使直接收到 v2 `AuthChallenge` 也不会发送 `AuthResponse`。这样旧 daemon 不能把 v2 的无标记 post-submit `Error` 误导为“确定未执行”。

## SSH、命令与 SFTP

- SSH 使用 `russh 0.62.5` 的 `ring` 后端和默认现代 KEX/MAC；host-key 算法只保留 Ed25519、ECDSA 与 RSA-SHA2-256/512，明确拒绝 `ssh-rsa` SHA-1 签名。
- TCP 被放入可取消代理。即使 peer 发出 banner 后卡在 KEX，absolute deadline/cancel 也会关闭底层连接，避免 russh 预认证任务脱离并长期占用资源。
- 首次连接使用分阶段 TOFU：先 KEX/观测 host key，再在排他租约下原子持久化 SHA-256 pin，只有 pin 成功后才发送 SSH 密码。pin 失败会在认证前中止 transport；即使 blocking pin worker 在 async deadline 后迟到持久化，也绝不会认证已过期 transport。russh password-auth send 的 bounded Future 在每一次 poll 前检查 absolute deadline，Pending 不能越过预算后再把密码交给 transport。后续连接与重连必须匹配 pin；首次链路仍有固有 MITM 风险，应通过独立渠道核对指纹。
- `exec` 的 deadline 覆盖 daemon 路由、重连锁、DNS/TCP/SSH、channel open、exec request 和输出/ExitStatus。IPC writer 在每一次 `poll_write` 与 `poll_flush` 前都检查同一个 absolute deadline，不依赖外层 timeout 的 poll 顺序。只有 4 字节长度头与完整序列化 payload 都被 `AsyncWrite` 成功接收后、执行 flush 前才进入“可能已提交”：序列化失败、零字节或部分帧写失败，以及完整帧写完前的 deadline 都是确定的 pre-submit 错误；完整帧之后的 flush/响应 deadline、断开或无法分类的协议结果返回 typed `ExecOutcomeUnknown`。daemon 的普通拒绝仍可明确证明尚未交给 russh；直连 russh 的 bounded exec-send 同样在每次 poll 前检查 absolute deadline，并只以内部请求成功入队为提交边界，Pending 不能越过预算后再触发远端执行。异常后依次尝试 TERM、KILL、EOF/Close，并在不能确认清理时使 transport 失效；杀掉客户端不会让远端 channel 永久占用 daemon 槽。任何不确定结果都不会被兜底为成功，必须先检查远端副作用再决定是否重试。
- SFTP 所有远端操作共用调用者的 absolute deadline；每个可能产生副作用的 Future 在每次 poll 前重新检查该 deadline，覆盖 `mkdir`、上传 partial CREATE/WRITE/flush/shutdown、hardlink/rename commit，以及 unlink cleanup，Pending 不能在预算后才发起远端变更。单帧长度前缀在分配 body 前限制为 1 MiB。目录读取直接流式执行 REALPATH/OPENDIR/READDIR/CLOSE，限制协议编码累计 8 MiB、保留字符串 2 MiB、10,000 entries，并在返回前精确验证 `DirList` JSON 不超过 16 MiB IPC wire 预算。
- `create-dir` 在 direct 与 daemon 路径都维护提交状态。只有显式 SFTP `STATUS` 拒绝或 daemon 的普通 pre-request/plain rejection 能证明未创建；完整请求之后的 deadline、EOF、unexpected response 或 transport/protocol 错误返回 typed `CreateDirOutcomeUnknown`，必须先检查远端路径再重试。
- 交互 shell 的列数和行数在 direct、IPC client 与 daemon 三处统一校验为 `1..=10000`。setup：直连共用 30 秒上限，IPC client 为 32 秒且 daemon 内部 setup 为 30 秒；每次 client/daemon 输入写为 2 秒并限制 64 KiB。client 和 daemon 在整个 IPC shell 内各自复用一个 pinned frame decoder，避免 cancel/drop 发生在 header/body 中间而破坏 framing；队列中及等待满队列的帧均有 RAII 清零包装。CLI stdin 每 100 ms poll 以响应取消，忽略 key release，接受 press/repeat；终端 raw mode 由 RAII guard 管理，正常退出、错误、abort 或 unwind 都会尝试恢复。建立成功的会话没有整体 deadline。

## 传输提交与清理

上传先在远端同目录以 `CREATE | EXCLUDE` 创建随机临时文件，并从创建时设置权限 `0600`。CREATE Future 第一次被 poll 后就保守记录 partial 可能存在；只有匹配请求的显式 SFTP `STATUS` 拒绝能证明这次请求没有创建 partial，deadline、断开或协议错误都保持不确定并进入 fresh-channel 有界清理。写完后优先使用服务器声明的 `hardlink@openssh.com` 扩展以 no-replace 方式安装目标，再删除本方临时名；扩展已声明但返回错误时绝不降级。服务器未声明该扩展时才使用标准 SFTP v3 `RENAME`，此 fallback 的 no-replace 保证依赖服务器遵守 v3 规范。

若 daemon 上传在 `UploadEnd` 后发生 deadline/断开，client 给已在途 commit 响应 2.25 秒有界对账窗口；只有明确 `TransferDone` 才报告成功，无法确定时返回“提交结果未知，重试前检查目标”的专用错误。直连上传使用 owned worker；外层 timeout/drop 只发取消，worker 继续拥有 fresh-channel 清理。commit 已开始后的 `Finished(Err)` 也被分类为 typed `UploadCommitOutcomeUnknown`，不会把 transport/protocol 错误误报为确定未提交；若已由稳定状态确认目标提交，则后续 partial 清理错误不倒退成失败。网络/服务器彻底不可用、进程强杀或清理宽限耗尽时仍可能留下 `.serctl-part-*`。

上传源在路由和 SSH 认证之前只打开一次，并通过稳定普通文件 handle 读取；FIFO、设备和目录被拒绝。Unix 以非阻塞方式打开后 `fstat`，允许指向普通文件的 symlink；Windows 以 `OPEN_REPARSE_POINT` 拒绝 reparse source。

下载临时文件的 protected `CREATE_NEW` 一返回成功就立即 arm `CreatedFileRollback`，然后才做安全验证；验证错误或 panic 会删除确切的新对象。Unix 用 dev/inode 区分路径替换，Windows 通过稳定 handle 删除，因此碰撞或替换不会误删他人对象。本地 partial create 由 owned `spawn_blocking` 返回 `UnclaimedLocalPartial`，若异步 Future 被取消、超时、drop 或 unwind，其 Drop 仍会调度清理；claim 交接中间没有 await。

Unix 创建时即为 owner `0600`；Windows 将禁止继承的 owner/SYSTEM/Administrators DACL 作为 `SECURITY_ATTRIBUTES` 传给 `CREATE_NEW`。完整写入、`flush`、`sync_all` 后，以同目录 hard link 原子 no-replace 安装最终名，并校验 handle 身份；目标已存在时失败且不覆盖。Windows 在复制路径/启动不可逆 hardlink worker 前显式复查 deadline，并在有界 blocking worker 内对稳定 handle 调用 `GetFileInformationByHandle`；已进入内核的调用仍不可抢占。

daemon download 把下游断开/背压识别为 `IpcResponseWriteFailure`：一个不读取的大下载只关闭该 IPC/SFTP channel，不会使 daemon 共享 SSH transport 失效。

本地 `open` / `flush` / `sync_all` / `hard_link` 等文件系统调用进入内核后不能由 async timeout 抢占。实现保留 owned blocking task并进行有界结果/身份对账，不会把“退出等待”误报成普通成功；在病态文件系统中，调用仍可能越过对账窗口后完成，这是明确的平台边界。

## 构建与验证

当前修补树完成 debug 与 release 的 all-target/all-feature 编译验证。正在运行的旧 GUI 锁住标准 `target\release\serctl.exe`，所以本轮修补版 release 使用隔离的 target 输出完成验证，没有覆盖该运行中产物：

```powershell
cargo fmt -- --check
cargo check --locked --offline --all-targets --all-features
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
cargo test --locked --offline --all-targets --all-features -- --test-threads=1
cargo audit --no-fetch
cargo build --locked --offline --all-targets --all-features
cargo build --release --locked --offline --all-targets --all-features
target\debug\serctl.exe --version
```

本轮最终证据：

- `fmt`、所有 target/feature 的 `check` 与严格 `clippy -D warnings` 通过；
- 当前所有者/租约修补树的完整 locked/offline 测试为 **205/205**，本轮通过 1 次；提升态 Windows security 定向套件为 **12/12**。其中新增 `TokenUser`/`TokenOwner` owner 分支与 mutation lease 错误分类回归。此前硬化基线的 **203/203 连续 3 轮**仍作为历史稳定性证据；两组完整套件数字属于不同源码状态，不相加也不混作同一轮。完整套件包含真实 authenticated daemon/SSH/SFTP/direct E2E，不是仅单元测试。`build.rs` standalone 测试另有 **15/15** 的既有证据；
- E2E 覆盖三帧认证 IPC、旧 protocol 2 `LockInfo` 被 v3 client 在连接前拒绝且产生零连接、daemon 与无 daemon direct SSH 两条路径的真实 exec 成功、hang/deadline、disconnect、typed `ExecOutcomeUnknown` 和对应 channel cancel，另含无退出码、分阶段 TOFU 在 pin 失败时不发送密码、上传/下载往返、direct fallback、并发 no-overwrite、远端 partial `0600`、本地权限/回滚、下载背压隔离、UI 敏感消息 unwind 与 runtime 关闭；v2 challenge 无 client response 由协议回归测试覆盖；
- Shutdown 完整帧边界、SFTP mutation per-poll deadline、`CreateDirOutcomeUnknown`/明确 `STATUS`/plain rejection，以及 partial CREATE 状态均有定向回归；真实路径证据来自上述既有 authenticated daemon/direct E2E 的复跑，不把这些定向用例表述为新增独立 E2E 函数；
- `cargo audit --no-fetch` 使用本机已有 RustSec 数据库快照扫描 **529 crate dependencies / 1198 advisories** 并通过；`--no-fetch` 证据不声称该离线快照包含检查时刻之后的上游更新；
- `argon2` 的 `zeroize` feature 已确认；`rsa` 与 `ttf-parser` 均不在锁定依赖图中；
- 先前提交前审计 debug 版本为 `serctl 0.1.0 (git bcfa616f2a39-dirty)`，无变化的第二次构建显示 `Fresh serctl`；这是历史来源追踪证据，不代表当前所有者修补树的最终提交身份；
- 当前所有者修补树已完成 debug/release、all-target/all-feature 编译。标准 `target\release\serctl.exe` 因旧 GUI 正在运行而未被本轮覆盖；修补版 release 在隔离 target 输出中编译验证，因此标准路径中的运行中二进制不代表这些修补。正式交付仍应在停掉旧 GUI 后从 clean commit 重建并记录哈希。

`build.rs` 将 12 位 Git commit 和 dirty 状态写入版本字符串。它先移除所有可重定向 repository/work-tree/index/object/config/replace refs 的继承 Git 环境，禁用 system/global config，只从 manifest 祖先的文件系统发现真实 `.git`；规范根必须包含 manifest，并以固定 `--work-tree`、`GIT_NO_REPLACE_OBJECTS=1`、关闭 fsmonitor/untracked cache 的 Git 查询证明来源。脚本解析 index 的 stage-0 mode/OID/path，并用 `git hash-object --no-filters` 计算工作树原始 blob OID，避免 clean/smudge filter 隐藏源码改动；mode `160000` gitlink 直接 fail-dirty。它监听 `.git/info/attributes` 以及 HEAD/index/ref/config/info/exclude 等元数据，`assume-unchanged` / `skip-worktree` 也强制 dirty；Git fixture 不可用会明确失败测试而非静默跳过。仓库通过 `.gitattributes` 的 `* text=auto eol=lf` 固定文本策略，并以 `core.autocrlf=true` clean checkout fixture 验证不会假 dirty。查询失败同样 fail-dirty。仓库根不作为 watcher，所以新根级 untracked 文件可能需其他受监听输入变化才触发重算；ignored/外部/动态构建输入仍是披露边界。正式 release 必须从 clean checkout 构建并记录 commit、lockfile、工具链、SHA-256 与签名。

## 已知边界

- TOFU 首次连接无法自行排除 MITM；
- SFTP v3 rename fallback 的 no-replace 语义依赖服务器合规；
- 本地不可抢占的 kernel 文件系统 syscall、已经启动后只能异步 detach 的 blocking work、同用户可写目录中的路径竞争，以及进程强杀/崩溃均超出协作式 cleanup 的完整保证；blocking pool 饱和可延迟本地 partial 清理，线程创建耗尽时可能保留路径；UI panic/drop 只能 cancel + `shutdown_background`，不能保证有机会等待异步清理；
- v3 与旧实现使用同一 hashed `.lock` / `.lease` 文件命名，但不做 dual-stack。正在使用的旧 release 锁缺少 `protocol`，会被解析为 protocol 0/bearer IPC；开发期 protocol 2 锁也不兼容。v3 client 对两者都在连接前 fail closed，不发送认证字节、不删除证据，也不回退直连。活动旧 daemon 必须用匹配的旧 executable 正常 `down`；protocol 0/2 stale 锁只能在离线确认 PID/进程不存在、租约未持有、owner/ACL/type 安全后人工处置，绝不能盲删；
- Windows 本机覆盖原生 IPC、DACL、原子写穿成功/失败/清理；这不是实际断电测试。Windows symlink/reparse 动态测试在无创建权限时会跳过，尚无多账户 ACL 攻击矩阵；Unix 的临时文件同步、rename、父目录 fsync 分支当前只有条件编译/审查证据，仍需 Linux/macOS runtime CI；
- 原始远端命令与 PTY 输出被视为受信任终端内容；不要把不可信字节直接显示在交互终端；
- `Zeroizing` 只能清理由本程序持有且可控的副本，不能清除 OS、allocator、第三方库、swap、崩溃转储或同权限调试器中的副本。非凭证 UI 的 command/shell/path/output 仍会在 egui、字体布局、IME、OS 与 allocator 中产生普通临时副本；稳定 widget ID 和每帧清 undo 不等于完整内存清零；
- 来源字符串只是 Git 来源信号，不是签名、制品证明或可复现构建证明；根级新 untracked、ignored、外部或动态构建输入还有上述 Cargo watcher 边界，可靠回滚仍需 clean commit 与已推送的唯一来源点。

## 许可证

本项目依据 [Apache License 2.0](LICENSE) 授权，Cargo 元数据使用 SPDX 标识 `Apache-2.0`。
