# serctl 目标架构与演进路线

> 状态：设计草案（2026-09-03）
>
> 适用范围：策略执行、作业生命周期、审计证据、IPC 编码与可选高速数据面
> 重要说明：本文描述目标架构和验收门槛，不代表这些能力已经发布。当前实现事实仍以 `README.md`、使用手册、架构安全说明和对应源码为准。

## 1. 结论先行

`serctl` 的长期定位调整为：

> 一个以本机 daemon 为策略执行点（PEP）、以 SSH 为信任传输根、以精确能力和可验证证据约束 AI/脚本的远程操作 broker。

“零信任”在这里不是“系统内没有可信组件”，而是：默认不信任调用方提交的名称、命令、路径、期限、状态和完成声明；daemon 必须把请求绑定到确定的 profile 身份、策略版本、操作 intent、资源预算和可验证终态。以下组件仍属于可信计算基：本机 OS principal、serctl daemon、密码学实现、SSH server 身份校验，以及被明确部署的远端 helper。拥有管理员/root 调试能力或完全控制远端主机的攻击者不在普通软件隔离能够消除的范围内。

用户提出的总体方向保留，但做以下关键调整：

| 原始设想 | 决策 | 调整后的方案 |
| --- | --- | --- |
| Client/daemon 分离 | 采纳 | 增加 attached/detached 作业所有权、持久 receipt 和可恢复状态查询；不能笼统承诺 UI/终端退出后所有操作都继续 |
| Protobuf + 全面压缩 + Arena 零拷贝 | 条件采纳 | 先做端到端基准；Protobuf 只作为候选控制面 codec，不宣称 Rust 下自动零拷贝；bulk data 保持 raw frame；压缩默认关闭 |
| `mlock` / `VirtualLock` | 纵深采纳 | 封装成受预算的 locked-secret allocator，并配合 no-dump/最短生命周期；明确不防管理员调试、休眠、DMA 或第三方库副本 |
| `sudo -u ... -- {args}` + 黑名单 | 拒绝作为主边界 | 改为 typed capability + 固定 helper + 绝对 executable/template + 参数级校验；黑名单只作最后一道拒绝规则 |
| 绿/黄/红/黑四级 | 改写 | 颜色只作 UI 风险模板；daemon 计算 capability 交集。黑牌改为 break-glass，永不关闭身份、期限、预算、审计和提交安全不变量 |
| SFTP append + SHA-256 链 + `chattr +a` | 改写 | 本地 write-ahead 审计为主，远端写入带认证 receipt，链定期锚定到独立/WORM 存储；`chattr` 仅是可选加固 |
| `shred -zu` 安全销毁 | 拒绝保证 | 使用 seal/export/retention/crypto-erasure 状态机；SSD、CoW、快照环境不宣称物理覆写成功 |
| RFC1918 内网 UDP 裸流 | 拒绝 | 私网地址不是信任证明；高速通道始终认证加密 |
| 手写 UDP + NACK | 拒绝作为默认方案 | 在现有 native SSH backend 达标后，再评估默认关闭的 QUIC fast lane |
| 命令行注入 Session Key | 禁止 | 临时密钥或证书 pin 只通过既有 SSH 加密 stdio/control frame 传递，不进入 argv、环境变量或临时文件 |
| 9.5 Gbps / CPU <5% | 改为实验指标 | 以 `iperf3`、`scp` 和 native SSH 为同机基线，报告吞吐分位数、core-seconds/GiB、RSS、RTT、丢包和 MTU |

## 2. 当前基线与状态标识

本文使用四种状态：

- **已实现**：当前源码存在对应机制；是否形成正式发布证据仍以 clean commit/tag/CI 为准。
- **部分实现**：当前 beta 源码候选已有功能路径，但尚缺完整实机或稳定版发布验收。
- **规划**：只有本设计，没有可依赖的产品能力。
- **拒绝**：不进入目标架构，避免后续文档或 UI 误报。

截至本文日期，当前基线是：

- **已实现**：候选存储契约 `vault-storage read=v4..=v5 write=v5`，顶层 `VaultFile` 与外层 profile record 双层均读 v4/v5、只写 v5；从 v2 迁移或对 beta-2 v4 首次成功 mutation 时原子推进 v5；逐 profile 独立 Argon2id KDF、DEK/AuthSeed/AuditSeed、随机 `profile_id` 与 generation；Windows 超管密码 + 离线介质 2-of-2 恢复边界。
- **已实现**：全局 broker、per-profile pool、IPC wire v9、握手 transcript、方向独立 AEAD、严格计数器、exact root intent、profile call-key 与 OperationGrant PoP/scope/budget；旧 v8 及 direct-connect downgrade 均失败关闭。
- **部分实现**：OperationGrant 显式 TTL 已进入 `v1.0.0-beta.2` 源码候选，默认 30 分钟、整分钟 `1..=40`，客户端与 daemon 双端校验；本地组合生命周期 E2E 覆盖“签发进程退出→等待→另进程首次/连续请求→到期拒绝并释放 idle reference”；仍需最终匹配 clean 制品与 exact-tag 证据。
- **部分实现**：可观察的 SFTP ACK、transfer registry、status/cancel、protected journal、连续 durable-prefix resume、no-overwrite commit，以及仅在 Linux 生产启用的 `serctl-xfer serve --stdio` helper。
- **部分实现**：原生传输协议采用有界 JSON 控制帧 + raw data frame；SFTP fallback 固定为 2 KiB、单 WRITE/STATUS 确认，native 则固定为 32 KiB、单 chunk/helper ACK lockstep。完整 russh exec/SFTP 服务端的 4/8/16/32 KiB 矩阵和 mock native E2E 已通过，但真实 OpenSSH + helper 子进程、实机哈希矩阵与同机 `scp` 吞吐门槛仍未验收。
- **部分实现且范围专用**：transfer helper 的 schema 2 sidecar/committed receipt 绑定 token hash、transfer id、size、SHA-256、durable offset、partial identity 与状态，可供同一 id/token 的显式恢复请求对账；它没有消费 ACK/GC/保留策略，不等同于规划中的通用 job/audit receipt 与外部锚定。
- **已实现但范围有限**：本机 `grant-audit.jsonl` 记录 Grant relay 接受/拒绝；它不是远端不可篡改审计系统。
- **规划**：策略 DSL、typed remote operation helper、approval/break-glass certificate、远端 receipt/外部锚定、锁页 allocator、使用新 wire 版本协商的内部 Protobuf codec、QUIC fast lane。

当前 IPC 的 JSON 位于受认证加密帧内；它是控制面性能候选，而不是已证明的系统瓶颈。外部 Agent JSONL 和 CLI `--json` 是稳定的人机/自动化边界，未来内部 codec 变化不得迫使调用方安装 Protobuf 工具链。

## 3. 目标分层

```text
Untrusted callers
  CLI / UI / Agent JSONL / optional MCP adapter
                    │ typed intent + caller proof
                    ▼
Local serctl daemon (trusted PEP)
  ├─ Identity & grant verifier
  ├─ Policy compiler/evaluator + policy_digest
  ├─ Job/transfer registry + cancellation + receipt store
  ├─ Local write-ahead audit + checkpoint anchor
  └─ Backend router
       ├─ SSH typed helper / native transfer
       ├─ conservative SFTP fallback
       └─ optional encrypted QUIC fast lane
                    │ existing SSH trust channel
                    ▼
Remote host
  fixed signed helper / constrained service account / optional audit sink
```

核心规则：UI 只能编辑和解释策略，真正的 enforcement 必须先在 headless daemon 中完成。任何 adapter（包括未来 MCP adapter）只转换外部调用，不持有 SSH 凭据，也不能绕过 daemon。

## 4. 不可关闭的安全不变量

无论风险等级、管理员策略或 break-glass 状态如何，以下规则均不可被用户 DSL 放宽：

1. IPC peer、daemon instance、profile name/id/generation 与 exact root intent 必须认证。
2. 每个请求必须有非零 deadline、资源上限、操作 scope 和可追踪 request id。
3. Grant/approval 必须有 holder PoP、预算、过期时间和防重放 nonce；策略变化后旧授权失效。
4. host key 校验不可被普通策略关闭；首次 TOFU 仍需独立核对。
5. 文件写入不得覆盖未知目标；partial、resume token、durable offset 与最终 SHA-256 必须绑定。
6. 路径授权不能只依赖字符串 `canonicalize` 或词法删除 `..`；安全关键 helper 必须采用 handle/dirfd-relative resolution，并拒绝 symlink/reparse escape。
7. 普通自定义策略不得产生 UID 0/root、任意 `sudo`、任意 shell、外部 listener 或不受限网络目标。
8. break-glass 也必须保留元数据审计、策略/证书 digest、deadline、budget、no-overwrite 与结果 receipt。
9. codec、压缩或 backend 协商不得静默降级到调用者未授权的安全级别。
10. 状态未知必须明确报告 `unknown`；不得把 timeout、断线或 ACK 丢失推断成成功、失败、删除或提交。

## 5. 策略模型：从颜色等级改为能力交集

颜色保留为 UI 模板，不作为 daemon 中的“数字越大权限越多”判断：

| UI 模板 | 默认能力 | 典型限制 |
| --- | --- | --- |
| 绿色 / ReadOnly | `fs.list`、`fs.read`、`process.inspect` 等 typed read capability | 无任意 exec；使用预配置非特权 identity，不假定所有系统都有可用的 `nobody` |
| 黄色 / Operator | 有界目录写、服务模板动作、受限 transfer | 目标/服务 allowlist、no-overwrite、并发/字节/deadline 上限 |
| 红色 / Privileged | 经审批的高风险 typed action | exact-intent 单次 approval，参数/路径/profile/policy digest 全绑定 |
| Break-glass | 紧急兼容能力 | 双重或明确管理员授权、极短 TTL、预算 1、原因码、强制元数据审计；不是“完全不检查” |

### 5.1 v1 DSL 采用 deny-only overlay

第一版自定义策略必须声明基础模板，且只能做交集收窄：

```toml
schema = 1
base = "operator"

[limits]
max_deadline_secs = 300
max_transfer_bytes = 1073741824
max_parallel = 2

[[allow]]
capability = "service.restart"
template = "systemd-unit"
units = ["web.service"]

[[deny]]
path_prefix = "/var/www/secrets"
```

编译结果是规范化 Policy IR，并生成 `policy_digest`。根请求、Grant/approval、审计记录和 receipt 都绑定该 digest。策略 reload 必须原子替换；旧 generation/digest 的新请求立即失败，已提交的长操作按其签发时的不可变快照运行并在结果中记录旧 digest。

后续若允许扩展基础能力，必须引入单独的管理员签名策略、静态 capability 检查与兼容门禁，不能把 deny-only 文件悄然升级为 allow-anything。

### 5.2 三种授权对象必须分离

- **OperationGrant**：当前 Agent 会话级能力，适合若干同 scope 操作；默认 30 分钟，策略上限 40 分钟。
- **ApprovalCertificate**：规划中的单次高风险批准，TTL 建议不超过 30 秒、预算 1，绑定完整参数/路径摘要和期望副作用。
- **BreakGlassCertificate**：规划中的紧急能力，仍绑定 exact intent、原因、操作者、policy digest 与预算；不能变成通用 bearer token。

三者不能复用同一个宽泛 scope，也不能用延长 OperationGrant 代替高风险逐操作批准。

## 6. 执行边界：typed operation 优先

当前兼容 `exec` 最终仍向 SSH exec channel 发送一个命令字符串，不能把它描述为“原子 argv”。`sudo --` 只结束 `sudo` 自身选项解析，不能阻止被执行程序启动 shell、再次调用 `sudo` 或解释危险参数。

目标方案：

1. 绿/黄策略只暴露 typed capabilities，例如 `fs.read`、`fs.write_new`、`service.restart`、`package.query`。
2. daemon 经 SSH 只启动固定命令，例如 `serctl-remote serve --stdio`；路径、argv、cwd、env 和 stdin 进入有界协议帧，不做 shell 插值。
3. helper 使用绝对 executable/template allowlist、固定/清空环境、受控 cwd、关闭继承 fd，并设置 OS 级 rlimit/job object/cgroup。
4. 需要特权动作时，由预配置 sudoers/doas/service manager 只授权固定 helper 子命令；不得授予通用 `sudo` 或 shell。
5. raw `exec` 保留为兼容/高风险能力，默认不进入绿色和黄色模板；命令 denylist 只能补充拒绝明显灾难输入，不能作为授权证明。

路径处理必须按平台使用对象句柄：Linux 优先 `openat2` 的 `RESOLVE_BENEATH`/`NO_SYMLINKS` 或等价 dirfd walk；Windows 使用 handle-relative open、reparse policy 与最终对象身份复核。不存在路径的词法规范化只能做语法预检，不能证明不会被 symlink/rename race 逃逸。

## 7. 内存与调试边界

规划新增统一 `LockedSecret<T>`/locked arena，仅用于短小、高价值、生命周期明确的秘密：

- Linux 尝试 `mlock`/`mlock2`，并设置 `MADV_DONTDUMP` 等可用 no-dump 属性。
- Windows 尝试 `VirtualLock`，并收紧应用自身 crash dump 与错误报告策略。
- 设置全局页数预算、分配失败指标和明确的部署策略：交互客户端可选择警告后继续，高保证 daemon/profile 可配置为失败关闭。
- 仍使用 `Zeroizing`、最短生命周期、避免日志/格式化和减少 `String` 副本；锁页不替代这些措施。

锁页只能减少 swap/core-dump 暴露，不阻止管理员调试器、进程注入、键盘记录、休眠镜像、DMA、allocator/第三方库副本或把 daemon 当作授权 oracle。不得在 UI 中宣传“调试也无法获取密钥”。真正的反调试边界需要不可导出硬件密钥或 enclave，并把 SSH 认证与会话密码学移出普通进程。

## 8. IPC codec 演进

### 8.1 迁移原则

Protobuf 是候选实现，不是既定性能结论。Rust 常用实现仍会为 `String`/`Vec` 分配；“Arena 自动零拷贝”不是本项目可以直接继承的保证。是否迁移必须由 Named Pipe/UDS 端到端基准决定，而不是只比较 codec microbenchmark。

安全关键认证不能依赖“对象重新序列化后字节一定相同”。目标 IPC envelope 应包含固定 magic、wire version、codec、flags、长度、方向计数器和认证 tag；根请求编码一次，对实际发送的同一不可变缓冲区取 hash。握手/PoP 使用字段顺序固定、长度前缀明确的独立 transcript。禁止 map；删除字段保留 tag；未知 enum、重复 singular 字段、缺失安全关键字段和超限递归均失败关闭。

### 8.2 数据与压缩

- 控制帧可评估 Protobuf；transfer/shell/file payload 使用 raw bytes sideband，不做 Base64。
- 压缩默认关闭。只有无秘密、超过阈值且基准证明有收益的目录/元数据响应可以逐帧启用。
- 压缩上下文不能跨帧或混合攻击者可控文本与秘密；解压前验证 AEAD，并限制压缩输入、解压输出、比例、CPU 时间和嵌套深度。
- 外部 `--json` 与 Agent JSONL 保留；未来 MCP 仅作为薄 adapter，不改变核心授权边界。MCP 支持多种传输方式，产品定位不再建立在“MCP 必然是 HTTP 重服务”的假设上。

### 8.3 发布方式

先在测试/基准中做 JSON 与候选 codec 的 shadow parity，不改变 wire。真正切换时必须发布区别于当前 JSON/AEAD IPC v9 的新 wire 版本（路线图暂记 v10），并将 CLI、daemon 和 helper 作为匹配集合 staging/原子替换；v9/v10 半升级必须 fail closed。最多保留一个明确配置的兼容窗口，禁止静默 downgrade 或 direct fallback。

## 9. 审计证据链

### 9.1 记录模型

本地 daemon 先写 write-ahead intent，再开始远端副作用。事件至少包含：

- 单调 sequence、前一记录 hash、event id、request id、时间与 daemon instance；
- profile id/generation、policy digest、Grant/approval digest、operation kind；
- 参数/路径/输入摘要、deadline、预算、backend；
- submission state、exit status、stdout/stderr 摘要、receipt、`confirmed/durable/committed/unknown` 终态。

默认不完整记录 stdout/stderr，因为输出可能包含凭据或个人数据。策略只能在 `none/hash/redacted/encrypted-content` 中选择，并受字段/字节上限、保留期和访问控制约束。

纯 SHA-256 链只能发现无钥修改，不能阻止攻击者截断后重算整条链。每个 checkpoint 必须由 daemon 的审计密钥做 MAC/签名，并定期锚定到控制机外的独立/WORM sink。远端日志是第二证据源，不是唯一真相。

### 9.2 远端写入

不采用“任意 SFTP append 即等于不可篡改”的模型。并发 append、STATUS ACK、远端 durability、父目录替换和 root 重写都必须单独处理。目标路径为固定 audit helper：

1. daemon 通过固定 SSH exec 启动已部署 helper，不使用 shell 拼接。
2. helper 接收有界记录帧，验证 sequence/checkpoint，采用 create/append + sync 语义，并返回带身份、offset、hash 和 durability 的 receipt。
3. `chattr +a`、WORM/object-lock 或专用日志服务只作为平台能力；缺失时明确降级证据等级，不能继续宣称“不可删除”。
4. 链不匹配时把 profile 置为 **quarantined**：默认禁止新的变更操作，但保留 status、audit export 和经管理员授权的诊断，避免单纯冻结造成不可恢复 DoS。

### 9.3 retire 状态机

`audit retire` 采用：`seal → export → verify external anchor → retention approval → revoke key/access → remove local/remote working copy → record receipt`。

Windows 可复用独立超管授权；Linux 使用 root/组织身份，不引入伪装成跨平台一致的第二密码。远端 `sudo` 是否可用是独立授权条件。人工处理无法验证时状态必须是 `external-action-required` 或 `unverified`，不能用 `acknowledge` 把未知删除伪装成成功。

`shred` 在 SSD、CoW、journal、快照和网络存储上不可靠。优先采用保留策略与加密密钥销毁；物理介质销毁属于组织流程，不由 serctl 成功消息担保。

## 10. 高速数据面

### 10.1 先收口现有 native backend

在增加新传输栈前，必须先定位现实 OpenSSH + `serctl-xfer` 子进程 stdio 在大于 2 KiB 时的停滞；受控完整 russh exec/SFTP 服务端已经证明 4/8/16/32 KiB 可以到达 handler 并获 ACK，因此不能再把问题笼统归因于 russh ChannelStream、window/flush 或分帧。随后还必须完成签名 helper bootstrap，并通过 Linux 上 `/proc/self/fd` + `linkat` + parent-dirfd fsync 的故障注入，以及 21 B、固定 1,298,223 B、64 MiB、至少 1 GiB 的外部测试和同机 `scp` 吞吐基线。不能用新 UDP 后端掩盖现有确认语义或 helper 部署问题。

### 10.2 可选 QUIC fast lane

只有 native SSH backend 无法满足已定义场景，才引入默认关闭的 QUIC 实验后端：

- 始终使用认证加密；RFC1918、VPN、VLAN 或低 RTT 都不是允许明文的依据。
- 临时证书 pin/PSK 经现有 SSH 加密 stdio 控制帧传递，禁止 argv、环境变量和磁盘临时 key。
- 变更型 push/commit 禁用 0-RTT；transfer id、offset、token、SHA-256、durable ACK 和 no-overwrite commit 继续复用 M2/M3 语义。
- 使用 QUIC 的可靠流、拥塞控制、丢包恢复、地址验证与 PMTU 机制，不自制固定 1400 字节 NACK 协议。
- helper 必须来自签名发布包并核对平台、版本和摘要；远端运行使用随机 0700 目录、受限服务账号和 systemd transient scope/job object 等可用沙箱，不假定 `/dev/shm` 可执行。
- SSH 控制通道持续作为生命周期 owner；超时、崩溃或断线进入可查询 cleanup journal，不能只依赖 300 秒后 `rm -f`。
- 网络预检、认证或端口可达性失败时，明确报告并按用户允许的策略回退 `native`/`sftp_fallback`，不得伪报 fast lane。

性能报告采用相对指标：相同机器、文件、网络条件下对比 `iperf3`、`scp`、native SSH；覆盖 RTT、丢包、乱序、MTU、NAT/防火墙，并同时报告吞吐 p50/p95、两端 core-seconds/GiB、RSS 和失败/恢复时间。9.5 Gbps 与 CPU <5% 只能成为特定硬件实验目标，不能写成产品保证。

## 11. 作业、deadline 与 receipt

现有 `exec` 是一次性请求，远端命令 deadline 与本机 relay deadline 尚未分离。W2 已证明远端工作可能在边界完成而 relay 丢失成功终态。目标作业协议必须提供：

- `job submit/status/cancel/result`，由独立 `JobId` 标识；
- remote execution deadline、relay deadline、result-retention deadline 三个不同字段；
- 有界 heartbeat/progress、阶段、最后确认时间和 submission state；
- 远端原子 receipt，绑定输入 digest、policy digest、exit status、输出 digest 和完成时间；
- daemon/client 重启后的 journal reconcile；receipt 未验证前始终保持 `unknown`。

OperationGrant TTL 只决定“调用授权能持续多久”，不能替代远端任务 deadline 或结果保留期。

## 12. 版本与里程碑

产品 SemVer、vault schema、IPC wire、transfer protocol 和 policy schema 必须分别编号。原先把产品 `v3.0/v3.1/v3.2` 与 IPC/数据面绑定，容易和 vault v4、IPC v9 混淆；以下采用可验收的产品路线：

仅在本路线表中，传输阶段缩写定义为：M1 = 可观察且按远端确认推进的可靠 fallback；M2 = 连续 durable-prefix journal/resume 与端到端完整性；M3 = 原生 helper 的功能、部署与性能验收。当前工作树完成的是 M1/M2 及 M3 功能预览，不代表签名部署或吞吐验收完成。

| 产品版本 | 范围 | 退出门槛 |
| --- | --- | --- |
| `v0.2.1` | 仅在仍维护无 wire-break 的 v0.2 来源分支且确有热修需求时，回移 SFTP ACK/进度/idle timeout | 不从 IPC v8 工作树直接挑入 wire change；固定快照真实服务端通过 |
| `v0.3.0-alpha → v0.3.0-beta.2` | IPC v8 + M1/M2 + Linux M3 功能预览、Grant 生命周期、resume/status/cancel 的前代预发布 | 只作 predecessor/回滚输入与历史证据；不把 v0.3 证据重标为 v1 通过 |
| `v1.0.0-beta.2` | 当前 IPC v9、storage `read=v4..=v5 write=v5`、M1/M2 与 Linux M3 候选、Grant 生命周期、Agent transfer status/cancel、匹配集合预发布 | 全量门禁、exact clean tag 与外部 SSH 证据、签名 helper bootstrap、Ubuntu descriptor/linkat 故障注入、Local-Linux2 21 B/1.3 MB/64 MiB/1 GiB 哈希一致、unknown/cleanup 证据、同机 `scp` 吞吐达到 80% |
| `v0.4.0` | 作业/receipt、远端/relay deadline 分离、锁页/no-dump 基础 | crash/restart/reconcile、receipt 恢复、锁页失败策略与平台测试 |
| `v0.5.0` | typed capability、Policy IR、deny-only evaluator、`explain`/dry-run | parser/fuzz、不可放宽不变量、policy digest/grant invalidation、无 UI 的 enforcement E2E |
| `v0.6.0` | 审计 v1、认证 checkpoint、外部锚定、quarantine/retire | 篡改/截断/重排/回滚、远端不可用、retention 与 unverified 状态矩阵 |
| `v0.7.0` | 策略管理 UI、审批与 break-glass 流程 | UI 不可绕过 daemon；双端权限、撤销、竞态与可访问性测试 |
| `v0.8.0` | 若基准成立则发布使用新 wire 版本（暂记 v10）的内部 Protobuf codec | v9/v10 成对升级、半升级、回滚与禁止 downgrade；p99、分配和 CPU 有显著收益 |
| `v0.9.0-experimental` | 可选、始终加密的 QUIC fast lane | 安全网络矩阵、外部基准、资源上限、resume/commit/cleanup 与回退证据 |
| `v1.0.0` | 冻结受支持的 CLI/Agent、policy、audit、upgrade 与 transfer 契约 | 至少一个稳定兼容窗口和可回滚签名发布链 |

若产品仍希望使用“v3.0–v3.2”作为市场路线，它们只能是能力主题：策略与审计基础、enforcement/UI、QUIC 实验；不能代替上述独立 wire/schema 编号，也不能在验收前标记为已完成。

## 13. 最低验收矩阵

### 策略与执行

- A profile/identity/generation/policy digest 的授权不能用于 B 或同名重建对象。
- deny-only overlay 的任意组合都不能产生基础模板之外的 capability。
- approval/break-glass 重放、超时、预算耗尽、参数/路径变化和 policy reload 全部失败关闭。
- shell metacharacter、嵌套 `sudo`、环境注入、cwd/path race、symlink/reparse 和目标竞态不会绕过 typed helper。
- parser 覆盖超长值、重复键、Unicode、regex/匹配复杂度、未知 schema，并进行 fuzz/property tests。

### IPC

- v8/v8、v9/v9、v8/v9 半升级、descriptor 污染、旧 Grant、回滚和禁止 downgrade。
- 超长 varint/frame、未知/重复字段、未知 enum、缺失关键字段、畸形 union、递归深度和解压炸弹。
- Named Pipe/UDS 端到端测试覆盖小控制帧、10,000 项目录、4 Hz progress、128 KiB shell 和 1 GiB transfer；报告 p50/p99、分配次数、CPU 与 RSS。

### 审计与作业

- intent 已提交但结果丢失、远端完成但 relay timeout、daemon/client crash、receipt 重放/替换、远端 helper crash。
- 日志 bit flip、截断、重排、删除中段、从旧 checkpoint 回滚、攻击者重算无钥 hash 链均可由独立锚定发现。
- sink 离线、磁盘满、权限拒绝、时钟回拨和审计密钥轮转不会生成虚假成功。

### 传输与高速通道

- 4/8/16/32/64/256 KiB chunk × window、延迟/丢失 ACK、断线、25%/75% resume、磁盘满、目标竞态和 daemon/helper crash。
- QUIC 覆盖认证失败、重放、nonce/transfer-id 冲突、NAT rebinding、MTU、丢包/乱序、端口阻断、cleanup journal 和显式 fallback。
- 所有 backend 最终 100% 只在完整性验证和 no-overwrite commit 后出现；`confirmed_bytes` 不得领先接收端 ACK，恢复只从 `durable_bytes` 开始。

## 14. ADR 与开放问题

后续实现前至少拆出以下 ADR：

1. Policy capability/IR 与 deny-only 组合语义。
2. typed remote helper 的部署身份、sudoers/service-manager 边界和路径解析 API。
3. Job receipt 的 canonical transcript、持久化和恢复状态机。
4. Audit MAC/signature、checkpoint、外部锚定和 retention/retire 模型。
5. 新 IPC wire 的 Protobuf codec 与 raw sideband；只有基准通过才选择具体实现，且不得复用当前 JSON/AEAD IPC v9 的版本标识。
6. QUIC fast lane 的身份绑定、密钥派生、helper 沙箱和显式 fallback。
7. `LockedSecret` 的平台预算、失败策略和可测量的 no-dump 边界。

每个 ADR 必须列出威胁模型、非目标、兼容性、回滚方案、测试矩阵和证据位置。未经 ADR 和验收门槛，不把规划项加入用户手册或标记为已支持。
