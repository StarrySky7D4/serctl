# 更新日志

本文件记录面向使用者、运维人员和安全审计人员的重要变化。项目仍处于预发布阶段，正式发布前可能继续调整命令、存储格式和协议。

## v0.3.0-beta.2 - 2026-08-31

### 新增

- 新增 [目标架构与演进路线](docs/serctl-design-roadmap.md)，把策略执行、作业 receipt、审计锚定、IPC codec 与可选高速数据面拆成独立里程碑和验收门槛；明确它们是规划而非当前已发布能力，并拒绝 RFC1918 明文 UDP、argv 传密钥、仅靠无钥 hash 链宣称防篡改和 `shred` 物理销毁保证。
- 新增 `transfer push/pull/status/cancel` 与 UI 结构化进度卡。进度包含固定阶段、远端确认/持久字节、3 秒窗口速度、平均速度、ETA、实际 backend、chunk/window 和 transfer id；终态只有完整性验证与 no-overwrite commit 成功后才到 100%。
- 新增 profile 隔离的活动传输登记表，允许另一已授权本机客户端查询脱敏快照或取消，终态记录保留 15 分钟。
- Agent JSONL 新增 `transfer-push`，由精确 `transfer.write` OperationGrant 根 intent 授权；scope 在任何本地文件打开/读取前校验，不需要 profile 口令，也不能由 `sftp.write` 或 `ssh.exec` 回退触发。
- 新增有界 raw-data 原生传输协议 crate 与 Linux `serctl-xfer serve --stdio` helper，daemon 通过固定 SSH exec 命令完成版本/feature 协商并支持对称 push/pull；`auto` 仅在握手成功时报告 `native`，否则明确报告 `sftp_fallback`。
- 新增受保护的 push/pull transfer journal。上传以随机 ownership token 证明远端 partial/sidecar 所有权；schema 2 sidecar 还绑定 transfer id、size、SHA-256、durable offset、device/inode 与 receiving/committed state。下载绑定 profile identity、远端 size/SHA-256 与本地 protected partial；两端只从已同步的连续 durable prefix 恢复。

### 修复

- 修复 SFTP 上传在 `File::write_all` 仅把 WRITE 排入 in-flight 队列后就虚报远端确认的问题。fallback 改为原始 SFTP v3 的逐块 WRITE/STATUS 交换，只有 request-id 匹配的 STATUS 才推进 confirmed bytes；当前仍保守使用 2 KiB，但完整 russh exec/SFTP 服务端 4/8/16/32 KiB 矩阵已全数到达 handler 并获 ACK，因此根因继续收窄到现实 OpenSSH + helper 子进程 stdio 边界，不能再归因于通用 ChannelStream/window/分帧。
- 上传前后增加稳定本地 handle 与远端 partial 的 SHA-256 完整性核对；下载在本地 protected partial 提交前核对 daemon 提供的读取摘要。
- 修复 native helper 真实错误路径只关闭 stdio、未发送已定义的结构化 `Error` 帧的问题；offset/ACK 拒绝现在明确返回确定失败，只有进入 Linux `linkat` no-replace 调用或其后未取得可信终态才以 typed `outcome_unknown` 标记，路径/底层错误文本不能污染分类。
- native push 在 Commit 前对同一已验证 handle 执行 sync、完整落盘 SHA-256 复核及 owner/mode/dev/inode/size 二次校验；Linux 提交固定 parent dirfd，以 `/proc/self/fd/<fd>` + `linkat` 绑定已验证对象，并在 parent fsync 前后通过 `openat(O_NOFOLLOW)` 对账目标身份。FIFO 以 `O_NONBLOCK` 打开后 fstat 拒绝。
- 修复恢复传输把既有 durable prefix 计入本次窗口/平均速度的问题；`resumed` 事件重置单调速率基线，ETA 只按本次新确认字节计算。native pull 同时严格验证 confirmed/durable/window 累计 ACK。
- 修复 SFTP no-overwrite commit 已确认后，仅 journal/partial 清理失败却把整次传输误报为失败的问题。Linux native helper 则在 `Completed` 前按 token/receipt/identity 清理，失败返回 `cleanup_incomplete`；`resume=auto` 可用 committed receipt 对账，`resume=never` 不宣称可恢复成功终态。
- 将 active/terminal transfer registry 的隔离键从 profile 显示名称改为随机 128-bit profile id；同名删除重建后，新对象不能读取旧对象仍在 15 分钟保留期内的 transfer id/统计。
- 修复 `transfer status NAME --watch` 在保留表中存在任意旧终态时提前退出的问题；未指定 transfer id 时会持续到所有返回快照都进入终态。
- 将传输 idle timeout 与可选 total deadline 分离；只有 confirmed bytes 前进才刷新 idle 计时。超时产生 `stalled` 后失败，权限或路径拒绝不再误报停滞。
- 修正文档中的 Agent 能力误报：`sftp.write` 只对应 `create-dir`，grant-backed 文件上传必须使用 `transfer.write`。
- 修复 OperationGrant 文件尚在 30 分钟有效期内，但 daemon 自动空闲退出并由新实例接管后报告 `unknown or expired` 的问题。未过期 Grant 现在持有 daemon 活跃引用，到期清理后才释放；人工重启、升级和崩溃仍会使旧 Grant 失效。
- `grant-issue` 新增显式 `--ttl-minutes`。默认仍为 30 分钟，CLI 拒绝范围外输入，IPC 根帧提交 TTL，daemon 独立强制 `1..=40` 分钟并按 grant 自身 TTL 建立单调过期时间；40 分钟是策略硬上限而不是可任意延长的凭证租约。
- 修复 Windows 按需启动的后台 daemon 仍附着于签发 CLI 控制台、CLI/终端退出可终止 broker 并丢失 Grant 登记的问题。红绿探针证明 `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` 仍会继承控制台；后台启动现改为 `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`，前台 `up` 保持原有 Ctrl-C 协调语义。
- 修复 Agent 上传错误 JSON 泄露本地绝对路径或原始凭据标记的问题；grant 文件载入时还会先校验 TTL 策略、holder 私钥与公钥匹配及过期状态，失败时不进入请求循环。
- 修复 runtime descriptor 协议诊断仍显示 IPC v6 的陈旧信息；当前统一按 IPC v8 校验，旧 v7-only descriptor 即使 PID 已死也保留 descriptor/secret 证据并失败关闭。
- daemon 与 helper 新增不启动服务、不读取 vault 的 `--version` 自检；daemon 同时报告 build identity 与 `IPC v8..=v8`，helper 报告 transfer protocol version，便于成套 staging/升级时发现半升级。
- CLI 的 Clap 诊断统一为恰好一个结尾换行，避免 `--version` 在 PowerShell 中被拆成含空元素的数组，从而使三件套 clean-commit 发布校验可稳定执行。
- 将 `grant-issue` 可签发 scope 收紧为当前 Agent JSONL 实际可消费的 `ssh.exec`、`daemon.status`、`sftp.list`、`sftp.write` 和 `transfer.write`；协议预留但尚无 Agent handler 的 read/status/cancel/forward 不再生成不可用 Grant。
- 将 Grant 错误拆分为“当前 daemon 实例未登记”和“Grant 已过期”。新实例不会仅凭磁盘 Grant 文件恢复授权，避免削弱实例绑定和签发边界。
- 修复远端文件刷新可能长期卡在“正在读取”的问题：UI 目录请求使用独立 20 秒上限，并在状态文本中显示该上限。
- 大目录列表改为仅物化滚动视口内的行，不再每帧克隆和布局全部目录记录；新增 10,000 条记录的 UI 回归测试。
- 修复 profile 标题栏和授权输入框可能挤压工作区或把操作按钮推离可视区域的问题。
- 修复 Windows 新建主机在进入“安全与恢复”完成授权后没有继续原保存动作，以及恢复介质轮转撤销授权后不能续接保存的问题。
- 补齐 v2→v4 原子迁移的阶段进度消息，使校验、等待独占访问、旧库认证、逐 profile 派生、恢复介质持久化和 vault 提交均可见。
- 修复全局 daemon 首次 TOFU pin 被共享 profile 使用租约误判为无权 mutation 的问题。TOFU 仍只能填充空 pin、保留 identity/generation，并在 vault 排他锁内认证和拒绝并发冲突；普通 profile 修改仍需独占 mutation lease。

### 调整

- 将 `cargo-deny` 的重复版本策略从警告提升为发布阻断，只为 `russh 0.62.5`、`eframe 0.35.0` 与 `atomic-write-file 0.3.0` 三个已审计的上游分叉子树保留精确、带理由豁免；同时把已撤回的间接依赖 `chacha20 0.10.1` 更新到兼容的 `0.10.2`，不使用 advisory ignore 掩盖问题。
- 文件传输 resume metadata 与累计 durable ACK 将 wire 升级为 IPC v8，并对旧版本失败关闭；不提供 v7/v6 downgrade 或 direct-connect fallback。旧 `upload`/`download` 暂保留为兼容别名。
- `--resume auto` 仅支持 `auto|native`，helper 不可用或任何 journal/token/identity 校验不匹配时失败关闭；默认仍为 `never`。UI 提供显式断点续传开关。
- native 协议保留 256 KiB 默认 chunk/8 MiB 上限能力，但当前 daemon 在现实 OpenSSH + helper 子进程边界根因定位完成前仍把协商值限制为 2 KiB；功能 E2E 已覆盖，吞吐尚未达到 `scp` 80% 验收线。
- GitHub Actions 的全目标、全 feature 测试固定为单线程，避免进程级测试 home、daemon runtime 和凭证库隔离状态互相干扰。
- 修正 `up` 与 `grant-issue --operations` 的 CLI 帮助：全局 broker 不会在启动时预解锁指定 profile，Grant 操作范围必须使用精确协议种类。
- 新增完整中文使用手册，并同步 README 与架构安全文档中的 Grant 生命周期和故障处理说明。

### 已知限制

- W2 vendor Linux 冷构建首次在 900,000 ms absolute deadline 只得到 timeout；后续外层 1,200,000 ms 请求仍返回 timeout，但独立只读校验发现同一命令已写入 `BUILD-READY-v1` receipt（SHA-256 `b1e8041912e6e1838ee2f9c2ec0405bf92a5fbfd52d54120a66d85fb5239564c`）。因此 relay timeout 的提交状态必须先标为 `unknown`；只有预先定义且严格绑定输入/输出身份的 receipt 独立通过，才可恢复为成功。当前 `exec` 仍缺少独立远端/relay deadline、心跳进度和可恢复结果查询。
- `serctl-xfer` 的签名包驱动 `transfer bootstrap` 尚未实现；native helper 必须经可信软件包/运维通道预装。当前完整 russh channel 仍把 native/SFTP chunk 限为 2 KiB，尚无达到同机 `scp` 80% 的吞吐证据。
- native helper 的生产 server 当前仅支持 Linux；macOS、BSD 与 Windows 构建会在发送能力 Hello 前失败关闭，不再错误宣称已实现 resume/fsync/no-follow/no-replace。Windows 本地客户端到 Linux 远端仍受支持，其他远端使用 `backend=auto` 时会明确回退 SFTP。
- committed transfer receipt 尚无终端消费 ACK、GC 与保留策略；Linux `/proc/self/fd`、`linkat`、parent-dirfd fsync 和故障注入本轮仅交叉编译/Clippy，仍需 Ubuntu 实机运行证明。

### 本地验证

- 2026-08-31 beta-2 冻结前的 dirty 工作树完成 `cargo fmt --all -- --check`、`git diff --check`、严格 workspace Clippy `-D warnings` 与 `cargo test --locked --offline --workspace --all-targets --all-features -- --test-threads=1`：CLI 147 通过/1 忽略、Core 117、Daemon 31、Protocol 46、Transfer Protocol 5、helper 14，合计 360 通过、0 失败、1 忽略。
- 独立 `target/staging-v0.3/release` 完成冻结前锁定离线 Release 三件套构建，未覆盖 `target/release`；CLI/daemon 均报告 build `5690281a2535-dirty`，daemon 报告 `IPC v8..=v8`，helper 报告 transfer protocol v1。该 dirty staging 仅为冻结前证据，不是 beta-2 clean 制品或签名发布证据。
- 受控完整链路通过固定 1,298,223-byte 上传、内容一致性、首事件时延与 Agent `transfer.write` grant E2E；纯 SFTP 4/8/16/32 KiB × in-flight 1/2/8 及丢失 STATUS 矩阵通过。
- 新增完整 russh exec/SFTP 服务端的 4/8/16/32 KiB 首帧矩阵，所有尺寸均能到达 handler 并获 ACK；这排除了 core ChannelStream、SSH window/flush 与服务端分帧本身是 2 KiB 根因，但尚未覆盖真实 OpenSSH + `serctl-xfer` 子进程 stdio，当前 2 KiB cap 因而保持不变。
- `cargo audit --no-fetch --deny warnings` 以本机缓存扫描 543 个依赖和 1,226 条 advisory，0 漏洞、0 警告；这不是在线最新性证明，CI 仍会刷新 RustSec 数据库后重新检查。
- `Local-Linux2` profile 存在，但本轮没有获得它的独立口令，外部 21 B、固定快照、64 MiB 与 1 GiB 实机验收未执行。

### 验证记录

- 基线提交：`8bb97801fdca996296d89f79b43713f81ec0935f`，已推送至 `origin/main`。
- 2026-08-31 workspace 串行门禁：360 通过、0 失败、1 忽略；严格 Clippy、Rustfmt 与 Git diff whitespace 检查通过。
- 先前分包复核的 319/319 与一次并行 Windows `10053 ConnectionAborted` 仅保留为历史证据；本轮单线程全工作区测试已覆盖并通过对应链路。

## v0.2.0-test.1 - 2026-08-25

- 发布 vault/record v4 与 IPC v6 全局 broker 重写测试快照。
- 每个 profile 使用独立口令、KDF、DEK/AuthSeed、随机 identity 和 generation；移除共享主口令模型。
- Windows 引入超管密码与离线介质组成的 2-of-2 恢复；Linux 保留 root 降权后的破坏性替换入口并对未实现恢复路径失败关闭。
- UI 引入逐 profile 五分钟固定授权与两分钟超管授权；CLI 普通远程调用保持逐次口令验证。
- SSH 本地、远程和动态转发 listener 强制回环；L/R 固定目标地址同样仅允许 `127.0.0.1`。
- 标签提交：`ce634272ca1e98c3d18f76bcb78858ba07283f05`；原重写前 main 基线保存在 `V1` 分支。
