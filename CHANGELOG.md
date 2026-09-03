# 更新日志

本文件记录面向使用者、运维人员和安全审计人员的重要变化。项目仍处于预发布阶段，正式发布前可能继续调整命令、存储格式和协议。

## v1.0.0-beta.2 - Unreleased

> **候选状态（尚未验收/发布）**：当前 workspace 与正式发布标记仍保持 `v1.0.0-beta.1`，待 Rust 集成、exact-tag CI、受控实机和仓库治理门禁全部通过后再统一切换。候选 wire 为 IPC v9，并拒绝 v8 或 direct-connect downgrade；Agent JSONL 固定 `schema_version=1` 和稳定 `error_code`。普通 `main` CI 不产生正式发行物。

### 桌面工作区布局

- 文件页的目录与文件名称改为左对齐，列表宽度和高度随窗体动态铺满，同时按活动传输卡数量保留控制区空间。
- Bash 页改为终端式布局，使用深色输出区、`$` 提示符和底部输入栏；底层继续复用受保护的真实 PTY 会话，并让输出区随窗体宽高动态扩展。
- 命令页输出区不再固定为 15 行，改为同时跟随可用宽度和高度铺满；新增确定性布局回归并保留 10,000 项目录虚拟化门禁。

## v1.0.0-beta.1 - 2026-09-03

> **候选状态（尚未验收/发布）**：当前 workspace 与预发布标记已同步为 `v1.0.0-beta.1`；exact-tag CI、受控实机和仓库治理门禁仍须通过后方可发布。候选 wire 为 IPC v9，并拒绝 v8 或 direct-connect downgrade；Agent JSONL 固定 `schema_version=1` 和稳定 `error_code`。普通 `main` CI 不产生正式发行物。

### 发布门禁修正

- 将独立 fuzz workspace 的 `Cargo.lock` 纳入受控版本切换、回滚与一致性校验，避免主 workspace 已升级而 fuzz 路径依赖仍锁定旧版本。
- 普通 CI 与 exact-tag quality 作业固定获取完整 Git 历史，使版本身份重放能够验证真实 first-parent 发布转换；浅克隆现在以明确错误失败关闭。
- 本地 V1 beta gate 新增独立 fuzz lock 的 `cargo metadata --locked`，避免只验证根 workspace 而产生假绿。

## v1.0.0-beta - 2026-09-03

> **候选状态（尚未验收/发布）**：当前 workspace 与预发布标记已同步为 `v1.0.0-beta`；exact-tag CI、受控实机和仓库治理门禁仍须通过后方可发布。候选 wire 为 IPC v9，并拒绝 v8 或 direct-connect downgrade；Agent JSONL 固定 `schema_version=1` 和稳定 `error_code`。普通 `main` CI 不产生正式发行物。

### 安全与兼容性调整

- 修复 `audit resolve-unknown` 在存在 pending Intent 时先走普通 unlock 的 `verify_complete`、从而永远无法进入恢复逻辑的问题。离线恢复现在使用受同 profile 独占 `ProfileLease` 强制约束的专用认证入口；共享 lease 不能取得恢复 key，错误口令、租约竞争、anchor 不匹配、损坏链继续失败关闭。隔离临时 vault 回归覆盖 pending Intent→Unknown、二次幂等和 create-new anchor 不覆盖。
- 严格 JSON 解析器现在实现标准 JSON primitive/空白/Unicode surrogate grammar，不再依赖 PowerShell 对注释、`NaN`、`Infinity`、前导零、NBSP 或孤立代理项的宽松接受。Cargo metadata 同时要求 format version 1、package/node 双向闭包、精确 workspace runtime/source-only crate，以及仅允许 `null`/`dev`/`build` dependency kind；未知 kind 失败关闭。
- CycloneDX JSON/XML 的 source-only 检查扩展到 nested/primary/`metadata.tools.components`、Cargo purl/bom-ref 一致性和 dependency ref 闭包；XML 固定 1.5 namespace、8 MiB/reparse/DTD 边界。伪装 name、悬空 source-only ref、错误 namespace、实体或 oversized XML 均由双 PowerShell 合成回归拒绝。
- 固定 Linux x86_64 helper 的首个 beta ABI 门槛：正式 bundle job 使用 Ubuntu 22.04，并由 bundler 对最终 stripped ELF 的 `GLIBC_*` version needs 做 `readelf` 检查；高于 GLIBC 2.35、无法解析或未写入 platform provenance 都失败关闭，避免 `ubuntu-latest` 漂移静默抬高运行时要求。
- 每个平台 provenance 现在与 aggregate provenance 一样绑定完整 annotated tag object，不再只记录可被移动标签名与 peeled commit；发布 bundler 缺少该 40 字节身份时直接拒绝生成资产。
- 正式 publish job 在下载 attested artifact 后重新执行完整资产验证：精确 14-file allowlist、13 行且不自哈希的 `SHA256SUMS`、无路径/重复项、非空非 reparse、逐文件 SHA-256、aggregate/per-platform provenance 的 version/commit/tag/tag-object/repository 绑定，以及 Linux GLIBC 不高于 2.35 和 Windows MSVC x86_64 ABI 证据，任一漂移均在发布前失败关闭。
- publish job 现在还会对同一精确 14-file allowlist 中的每个文件分别执行 `gh attestation verify`，并同时绑定 repository、签发 workflow、peeled commit 与 exact tag ref；任何 subject 缺少匹配 OIDC provenance 都会在读取外部验收记录和创建 prerelease 前失败。
- 外部 acceptance、evidence manifest 与 release provenance JSON 现在使用无替换的严格 UTF-8 解码，并在任何 PowerShell 强转或宽松比较前验证整数、布尔、字符串、对象、数组及其元素的精确 JSON 类型；重复/大小写碰撞键、非法 UTF-8、`"1"`/`1.0` schema、`"true"`/`1` accepted 和复合值冒充字符串都会失败关闭。
- CLI 契约 golden 从顶层帮助扩展到完整递归 Clap command tree：当前 39 条真实命令路径的 long help、默认值、直接 required 参数及 subcommand-required 状态全部固定，`transfer`、`audit`、`grant-issue` 与 `agent` 的嵌套帮助漂移会在本地测试和文档治理中失败。
- 新增 SSH pre-auth 服务端证据的受限 JSON 模板与离线 verifier：只接受单探针、绑定 UTC 窗口、listener/admission/KEX 的归一化类别与计数，拒绝重复键、非数组事件、用户名/IP/banner/path/fingerprint/raw message/payload，并按事件一致性决定 attribution eligibility。模板与 synthetic self-test 明确不构成 OpenSSH/Dropbear、网络或 exact-tag 实证。
- 修复初始 profile unlock 在 SSH identification/KEX 完成前收到 transport-terminal 断线时直接向 CLI 泄出裸 `Disconnected`、且既有连接池重连完全未参与的问题。前两版候选分别因只 mock 认证后 channel-open、以及让重连争用剩余 setup deadline 而假绿；第三版实机又证明第二连接虽完成 TCP 并写入 22-byte russh identification，但客户端 10.2 秒内收到 0 字节。当前实现不再把 russh 的 `Error::Disconnect` 一律误称为 SSH DISCONNECT（它也可能是 pre-banner EOF），并将 OS shutdown 与 stream Drop、纯失败耗时与清理耗时分开。只有客户端未收到任何服务端字节、没有显式 SSH reason/host key、旧 stream 已释放时才在 1.5 秒退避后重连一次；预算必须另外保留退避、完整第二 KEX 及 post-KEX 工作。收到策略字节/reason 或 stream 未释放时保留首错。终态同时保留 attempt 1/2 的非秘密摘要及合法 SSH identification 是否已观察到，可区分 silent、pre-banner EOF、非 SSH/策略字节、identification 后未见 host key 与显式 SSH disconnect；这些均是客户端观测，零字节不能单独归因于 MaxStartups、PerSourcePenalties、封禁或网络黑洞。remote <code>message/lang</code>、banner、用户、口令和 fingerprint 永不进入诊断。raw peer 回归固定证明临时 pre-banner EOF 为 2 条连接/1 次认证/1 次 exec，持续故障为 2/0/0；静默 dummy peer 精确证明 client identification sent / server bytes zero 的分类；真实 russh stall 则证明仅 shutdown 而 stream 未释放时只连接一次。认证开始后任何拒绝或断线都不重放密码。
- 候选本地审计只覆盖 OperationGrant 根请求（Grant-root only）。每条记录除哈希链外还带独立 HMAC，checkpoint 同样认证；审计密钥由独立 `AuditSeed` 派生，不复用 IPC `AuthSeed`。generation 变化时 `AuthSeed` 与 DEK 重新随机化，`AuditSeed` 为衔接前后代审计链而保持稳定；因此旧完整 KeyPackage 泄露仍可能影响后续 generation 的审计密钥。beta-2 旧 package 首次升级时，用 DEK 作为 HMAC key、绑定 profile id/generation 的版本化域确定性派生并持久化 `AuditSeed`，不从 `AuthSeed` 回退。
- 明确 KeyPackage 升级的回滚边界：`audit_seed directionally incompatible`。新 reader 接受 beta-2 缺字段包并完整保留当前 AuditSeed/marker；它同时拒绝未来未知安全字段，以及 `initialized=true` 但 seed 为零的非法状态，不允许规范化后写回。一旦持久化 AuditSeed/marker，strict v8 reader 必须在 writer 前失败，`unknown fields must not be dropped`。此后 `binary-only rollback is forbidden`；只能恢复 `exact pre-upgrade vault backup`、匹配恢复介质和 ACL/owner metadata 的完整集合，不能靠替换旧二进制或删字段降级。
- `audit status` 与 `audit resolve-unknown` 要求 profile 口令和同一独占 lease；后者只为精确绑定的未配对 Intent 追加 `Unknown`，不猜测成功或失败。anchor 以 bounded regular-file、no-follow、create-new、同句柄回读和身份复核导出。为支持 FAT/exFAT 离线介质，Windows anchor 继承父目录 ACL，且目录 flush 只有 best-effort；anchor 不含秘密但必须依靠外部保管。同步回滚 vault、全部 ledger/checkpoint 和手工 anchor 仍不可检测，独立单调 external trust domain/远端透明日志仍是 stable 阻断项。
- 已有 authenticated audit material 的 profile 当前不能 `remove`。所有既有 profile 的 destructive `admin-reset --replace-credentials`（Windows 和 Linux `--target-user` 均包括在内）在 v1 beta 候选中失败关闭，因为该路径无法认证旧审计历史；使用旧 profile 口令执行正常轮转，或在 Windows 使用“超管密码 + 匹配离线介质”的 2-of-2 保留式恢复。保留式恢复不显示旧口令且仍受支持。
- Grant 文件中的 profile/scope/budget/expiry metadata 是 Agent 侧 fail-fast 与保密预检信息，不是最终授权根。文件也包含 holder 私钥，必须按密码文件保护；即使同用户篡改这些 metadata，daemon 仍只以当前实例内 registry 中登记的签名 root intent、holder PoP、profile identity、scope、预算和单调过期时间作为权威授权。
- Agent Grant 文件外层 envelope 现在与内层 `OperationGrant` 一样拒绝未知 JSON 字段，避免旧客户端静默忽略未来授权语义或把扩展字段降级丢弃；解析失败仍不回显 holder 私钥或未知字段值。
- SFTP fallback 继续固定 2 KiB、单 WRITE/STATUS 确认。native 候选使用 32 KiB，并保持严格的一块/一个 helper ACK lockstep；对外 `window_bytes` 因而报告实际 32 KiB，而不是 helper 可协商的 8 MiB durability/receiver 上限。当前只有 mock E2E 证据，没有 Local-Linux2 native 文件矩阵或同机 `scp` ≥80% 结论，不得宣称 native 吞吐验收通过。
- transfer registry 限制为每 profile 8 个、全局 48 个 active；终态最多保留 15 分钟，并只保留每 profile 最新 16 个、全局 256 个。状态仍按随机 profile id 隔离，响应保持在控制帧上限内。
- 正式 runtime 资产仅允许 Windows x86_64 的匹配 CLI + daemon，以及通过实机门禁后的 Linux x86_64 `serctl-xfer`；PDB/debug symbols 分离。`serctl-remote`、`serctl_jobs`、`serctl_remote_protocol` 和 `serctl_policy` 仅为 source-only experimental / unshipped，参加源码质量门禁但不进入 runtime、symbol、SBOM 或支持面，`job.*` 不能由 Agent/OperationGrant 签发。
- 新增 fail-closed runtime 依赖边界门禁：对 `serctl-cli`、`serctl-daemon`、`serctl-xfer` 的 Cargo normal/build 传递图拒绝全部 source-only crate，并在 attestation 前分别解析 CycloneDX JSON/XML 拒绝同名组件；dev-only 依赖不会被误算成 runtime 路径。
- 四个平台矩阵现在都通过同一 PowerShell 驱动执行 CLI/daemon/xfer/remote 的独立 build.rs fixtures；驱动在 Windows 为 `rustc -o` 显式添加 `.exe`，在 Unix 保持无扩展名，并拒绝 reparse-point 输入/输出。治理门禁同时把普通 CI action 收紧为完整 SHA 的精确 allowlist/count，并禁止 exact-tag release 引入跨运行可变 cache。
- policy parser 新增离线确定性 property-style corpus：覆盖逐字节截断/非法 UTF-8、畸形与递归上限、顶层及嵌套 unknown/duplicate fields、64 KiB 精确边界、5,040 种顶层字段排列，以及 deny-only 规则重排/重复幂等；重复 JSON 字段仍失败关闭，并作为 Quick/full 本地门禁的独立步骤运行。
- 新增独立锁定的 parser fuzz workspace 与每周/手动 Linux libFuzzer 工作流，覆盖 transfer、remote 与 policy 三个入口；nightly/cargo-fuzz、输入/RSS/时限和失败工件范围均固定并由 PowerShell 7/5.1 双版本自测门禁校验。policy target 同时驱动任意字节与 fuzz 派生的结构化有效策略；本地构建或工作流静态校验不替代 exact-tag Linux fuzz 运行证据。
- exact annotated tag 只是发布身份的一部分，本身并不天然不可移动。发布前必须由仓库 `v*` tag ruleset 阻止 force-update/deletion，并在平台支持时启用 immutable GitHub releases；二者是外部验收门禁。workflow 的远端 tag-object 复核与“拒绝覆盖已有 release”只能侦测/避免本次流水线改写，不能替代仓库治理设置。

### Agent 与发布契约

- 修复 Agent NDJSON 的 EOF 无换行边界曾错误复用 LF 的额外传输字节、从而允许 1 MiB + 1 byte payload 的上限偏差；精确 1 MiB 的 EOF/LF 行继续接受，超限 EOF/LF 均在解析和 daemon 访问前失败关闭。daemon 测试同时把 Grant 文件 profile/scope/budget/expiry 篡改显式绑定到当前实例 registry 权威性，防止仅靠 Agent 侧预检形成假安全证据。
- Agent JSONL 候选面扩展为 14 个精确操作。`transfer-pull` 要求独立 `transfer.read`，`forward-local-open`、`forward-remote-open`、`forward-dynamic-open`、`forward-status`、`forward-cancel` 分别要求 `forward.local/open`、`forward.remote/open`、`forward.dynamic/open`、`forward.status`、`forward.cancel`，`ssh-connection-identity` 要求 `ssh.connection-identity`。全部操作都在 operation-specific 校验、本地文件访问、daemon 启动或 listener/SSH 副作用前检查 scope；缺 scope 统一为 `agent.scope_denied`，无效 JSON 与其他执行错误不回显 parser/daemon/SSH/SFTP 下层细节。只有 handler、daemon 可签发列表和映射测试同时存在才视为源码实现。
- Agent `transfer-pull` 在任何远端路径验证、本地目标解析/存在性检查和 daemon 发现前先校验 `transfer.read`。根请求仅携带与 profile id/generation 绑定的本地目标 SHA-256 commitment，不向 daemon 暴露本地路径；本地仍以 protected `CREATE_NEW` partial 和 no-overwrite commit 失败关闭。Agent stdout 对单次 pull 保持 terminal-only，实时进度由独立 `transfer-status`/`transfer.status` Grant 进程观测；本地双进程 adapter 回归已覆盖同一 transfer id/context、revision 顺序与终态先后，但不构成真实远端验收。
- Agent 受管隧道由 daemon registry 在 ready 后接管生命周期，open/status/cancel 与三种模式使用互不替代的 scope；所有固定 listener/target 强制 `127.0.0.1`，结果不包含 profile identity 或远端地址，不确定取消/清理终态保持 `unknown`。连接身份只在认证和 host-key pin 匹配后返回有界脱敏投影，不暴露 endpoint、用户、路径、原始 pre-banner/banner 或凭据。这些能力仍缺 exact-tag OpenSSH/Dropbear 实机闭环。
- `tunnel`/`grant-issue` 新增继承 profile-passphrase handle/fd，`agent` 新增继承 Grant handle/fd，`grant-issue` 可向调用者预先 create-new 的保护对象写出 Grant。输入有界、来源互斥且不按路径重开；本地真实子进程继承 E2E 目前只覆盖 Windows，调用者保留的 duplicate handle 和 Unix/exact-tag 证据仍是明确边界。
- 外部验收新增有界进程监管原语及 fail-closed adapter：固定绝对可执行文件与参数数组、Windows `STARTUPINFOEX` 继承句柄 allowlist + Job kill-on-close、Unix `posix_spawn` process group、显式环境 allowlist、私有有界 stdin/captured stdout/stderr、单调 deadline，以及仓库固定 case recipe、全部 14 个 Agent operation 的 context/revision parser、双进程 transfer/status 观测和 exact native helper identity 绑定。独立 Windows PowerShell owner 进程只继承 20 只互异、按固定用途检查的 Grant handles，自行构造精确 10 案：两种 exec、OpenSSH directory、三种 OpenSSH tunnel，以及四种 OpenSSH/Dropbear SFTP/native transfer；tunnel 按 open → status → cancel，transfer 的独立 status 必须先于 primary terminal。四个传输案使用 owner 私有受保护 scratch 中 create-new、稳定只读 handle 锁定的实测 21-byte payload，调用方不能提供 path/size/hash。仅在全部完成后才以 protected `CREATE_NEW` 写 owner-v2 receipt；每案保留实际捕获的 canonical child receipt Base64 与 SHA-256 并重算验证。contract 导入时把 aggregate evidence context 与 10 个 operation context 分离，并在导入后仍保持 unsealable。contract 还固化 8 个尺寸/方向前置，并从闭合原始结构重算 11 个故障结论、registry/window 上限和 native/scp 各 5 个性能样本，仍拒绝用合成结构代替 isolated actual capture。official downloaded-set 锚定、Linux/macOS owner、真实 fault/performance owner、真实 Grant/远端与 HelperHello 均未验收，因此全部 real-host release receipt 继续保持 BLOCKED。
- formal owner 的 provisioning 输入进一步收紧为 25 个互异继承句柄：verified downloaded-set record、CLI、daemon、Linux helper、预开空 receipt output 与 20 个 Grant。组件版本/size/SHA/tag/commit/platform 均从稳定 handle 和闭合 record 重算，执行路径由 handle 的 Windows file identity 派生并重新钉住；调用方不再传 component path/provenance 或 receipt path。当前 synthetic downloaded-set record 必须产生 unsealable anchor，只有未来 exact-tag verifier 的受保护 official record 才可能进入 sealable 路径。
- 新增 native fault/registry/performance isolated actual-capture fixture owner：固定子进程输出原始事实，owner 重算 11 个故障终态、profile/global registry 与 ACK 约束，以及 native/scp 各 5 个本地 workload 样本。contract 仅把 canonical owner bytes 导入独立 `unsealable_fixture_only` projection，不写入 formal remote evidence 槽位，`completed=0 / blocked=20 / sealed=false`。interop owner-v2 也可确定性投影并由 external verifier round-trip，但 runner/remote/exact-tag 与真实 native fault/performance evidence 缺失时仍不可封印。
- 候选发布使用 exact tag `v1.0.0-beta` 的独立 workflow、clean staging、成套制品、独立符号、SHA-256、按受支持组件/目标生成的 SBOM、provenance 与 OIDC attestation；tag ruleset、immutable releases、三平台 CI、实机 native 及 clean-install/rollback 证据在完成前均保持未验收。
- whole-bundle 合成门禁补齐六种 CLI/daemon/helper 半升级组合与三种仅哈希替换，活动引用在替换前复核协作式并发写入，并在替换后注入失败时恢复并复核前驱引用；它还会在 600 秒绝对期限内离线执行生产 KeyPackage 的 storage-direction Rust fixture，不再用源码 marker 冒充 `audit_seed` 兼容证据。真实 descriptor owner/TOCTOU、旧 descriptor/Grant 失效及精确 vault/恢复介质回滚仍保持外部验收阻断，不以合成测试冒充。
- 修复本地总门禁 runner 将有正常 stdout 的原生命令结果误收集为对象数组，并在 StrictMode 下把成功步骤记为 `exit=-1` 的问题。runner 现在把 stdout/stderr 保留给操作者、以最后一个结构化对象传递退出码，并有 noisy-runner 回归；Quick/dirty 结果仍固定为不可验收。

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
- 修复 native helper 真实错误路径只关闭 stdio、未发送已定义的结构化 `Error` 帧的问题；offset/ACK 拒绝现在明确返回确定失败。Linux `linkat` 返回 `EEXIST`、权限或资源错误时已证明目标链接没有创建，保持确定性的 `transfer_failed`；只有 `linkat` 成功后无法完成目标身份复核或 parent fsync 才以 typed `outcome_unknown` 标记，路径/底层错误文本不能污染分类。
- 修复 native helper 首次写入 resume sidecar 时可能直接覆盖预存未知 sidecar、且失败后忽略 partial 删除错误的问题：初始 sidecar 现在严格 create-new；后续更新前重新验证 transfer/token/size/hash/partial identity、旧 durable offset 与状态。首次持久化失败时关闭创建句柄并按已记录的 device/inode/owner/mode/size 复核本方 partial；清理成功保留原始确定失败，清理失败返回 `cleanup_incomplete`。Linux helper 现以持久 intent-bound 0600 lock、非阻塞 `flock` 与 binding guard 关闭协作 helper 的并发竞态；advisory lock 不隔离恶意同 UID 进程，其在 last-instruction window 发起的 `same-UID path race` 仍是明确的文件协议边界，而非协作式排他锁的未实现候选阻断项。
- native push 在 Commit 前对同一已验证 handle 执行 sync、完整落盘 SHA-256 复核及 owner/mode/dev/inode/size 二次校验；Linux 提交固定 parent dirfd，以 `/proc/self/fd/<fd>` + `linkat` 绑定已验证对象，并在 parent fsync 前后通过 `openat(O_NOFOLLOW)` 对账目标身份。FIFO 以 `O_NONBLOCK` 打开后 fstat 拒绝。
- 修复恢复传输把既有 durable prefix 计入本次窗口/平均速度的问题；`resumed` 事件重置单调速率基线，ETA 只按本次新确认字节计算。native pull 同时严格验证 confirmed/durable/window 累计 ACK。
- 修复 SFTP no-overwrite commit 已确认后，仅 journal/partial 清理失败却把整次传输误报为失败的问题。Linux native helper 则在 `Completed` 前按 token/receipt/identity 清理，失败返回 `cleanup_incomplete`；`resume=auto` 可用 committed receipt 对账，`resume=never` 不宣称可恢复成功终态。
- 将 active/terminal transfer registry 的隔离键从 profile 显示名称改为随机 128-bit profile id；同名删除重建后，新对象不能读取旧对象仍在 15 分钟保留期内的 transfer id/统计。
- 修复 `transfer status NAME --watch` 在保留表中存在任意旧终态时提前退出的问题；未指定 transfer id 时会持续到所有返回快照都进入终态。
- 将传输 idle timeout 与可选 total deadline 分离；只有 confirmed bytes 前进才刷新 idle 计时。超时产生 `stalled` 后失败，权限或路径拒绝不再误报停滞。
- 修正文档中的 Agent 能力误报：`sftp.write` 只对应 `create-dir`，grant-backed 文件上传必须使用 `transfer.write`。
- 修复 OperationGrant 文件尚在 30 分钟有效期内，但 daemon 自动空闲退出并由新实例接管后报告 `unknown or expired` 的问题。未过期 Grant 现在持有 daemon 活跃引用，到期清理后才释放；人工重启、升级和崩溃仍会使旧 Grant 失效。
- `grant-issue` 新增显式 `--ttl-minutes`。默认仍为 30 分钟，CLI 拒绝范围外输入，IPC 根帧提交 TTL，daemon 独立强制 `1..=40` 分钟并按 grant 自身 TTL 建立单调过期时间；40 分钟是策略硬上限而不是可任意延长的凭证租约。
- `grant-issue` 在解析任何 daemon descriptor 或启动 broker 前，先用生产严格 schema 对目标 profile 做只读口令/KeyPackage 预检；`audit_seed`、未来未知安全字段或非法审计状态不兼容时，launcher callback 保持 0、不会生成 Grant 或写回 vault。预检后 daemon 仍独立解锁并复核 profile id/generation，避免把 CLI 解密态跨进程传递；代价是签发流程执行两次受独立 deadline 约束的 Argon2 KDF。
- 修复 Windows 按需启动的后台 daemon 仍附着于签发 CLI 控制台、CLI/终端退出可终止 broker 并丢失 Grant 登记的问题。红绿探针证明 `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` 仍会继承控制台；后台启动现改为 `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`，前台 `up` 保持原有 Ctrl-C 协调语义。
- 修复 Agent 上传错误 JSON 泄露本地绝对路径或原始凭据标记的问题；grant 文件载入时还会先校验 TTL 策略、holder 私钥与公钥匹配及过期状态，失败时不进入请求循环。
- 修复 runtime descriptor 协议诊断仍显示 IPC v6 的陈旧信息；当前统一按 IPC v8 校验，旧 v7-only descriptor 即使 PID 已死也保留 descriptor/secret 证据并失败关闭。
- 修复全局 daemon 把 runtime descriptor 先于 activation secret 发布、并由 launcher 过早释放启动锁造成的竞态。现在 daemon 自身在有界 startup singleton 内仲裁，先写 secret、最后写 descriptor 作为唯一 readiness 信号；并发候选接受已验证的赢家，退出或发布失败时只清理同时匹配自身 descriptor 与 secret 的状态，不会误删另一实例。
- daemon 与 helper 新增不启动服务、不读取 vault 的 `--version` 自检；daemon 同时报告 build identity 与 `IPC v8..=v8`，helper 报告 transfer protocol version，便于成套 staging/升级时发现半升级。
- CLI 的 Clap 诊断统一为恰好一个结尾换行，避免 `--version` 在 PowerShell 中被拆成含空元素的数组，从而使三件套 clean-commit 发布校验可稳定执行。
- 修复 Ubuntu/macOS E2E 把 Unix socket 放在过长 checkout 路径下、超过 `sun_path` 后只误报 descriptor 超时的问题；测试现在使用原子创建的 0700 短路径并直接报告 daemon 早退原因，同时用精确平台 `cfg` 消除非 Windows 构建中的 migration/recovery 死代码警告。
- beta-2 当时将 `grant-issue` 可签发 scope 收紧为该版本 Agent JSONL 实际可消费的 `ssh.exec`、`daemon.status`、`sftp.list`、`sftp.write` 和 `transfer.write`；当时协议预留但尚无 Agent handler 的 read/status/cancel/forward 不生成不可用 Grant。v1 候选后续增加的精确 scope 见上方 Unreleased 章节。
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
- native 协议保留 256 KiB 默认 chunk/8 MiB 上限能力；daemon 已将 SFTP 的 2 KiB confirmed-WRITE cap 与 native 数据面分离，native 有效 IPC chunk 固定为 32 KiB，并且每个 chunk 仍须等待 helper 的累计 ACK 后才推进 confirmed bytes。功能 E2E 已覆盖，但真实 OpenSSH + helper 子进程吞吐尚未达到 `scp` 80% 验收线。
- GitHub Actions 的全目标、全 feature 测试固定为单线程，避免进程级测试 home、daemon runtime 和凭证库隔离状态互相干扰。
- 修正 `up` 与 `grant-issue --operations` 的 CLI 帮助：全局 broker 不会在启动时预解锁指定 profile，Grant 操作范围必须使用精确协议种类。
- 新增完整中文使用手册，并同步 README 与架构安全文档中的 Grant 生命周期和故障处理说明。

### 已知限制

- W2 vendor Linux 冷构建首次在 900,000 ms absolute deadline 只得到 timeout；后续外层 1,200,000 ms 请求仍返回 timeout，但独立只读校验发现同一命令已写入 `BUILD-READY-v1` receipt（SHA-256 `b1e8041912e6e1838ee2f9c2ec0405bf92a5fbfd52d54120a66d85fb5239564c`）。因此 relay timeout 的提交状态必须先标为 `unknown`；只有预先定义且严格绑定输入/输出身份的 receipt 独立通过，才可恢复为成功。当前 `exec` 仍缺少独立远端/relay deadline、心跳进度和可恢复结果查询。
- `serctl-xfer` 的签名包驱动 `transfer bootstrap` 尚未实现；native helper 必须经可信软件包/运维通道预装。当前 SFTP 仍使用 2 KiB one-WRITE/STATUS，native 使用 32 KiB one-chunk/one-helper-ACK；两者都尚无 exact-tag、同机 `scp` 80% 的吞吐证据。
- native helper 的生产 server 当前仅支持 Linux；macOS、BSD 与 Windows 构建会在发送能力 Hello 前失败关闭，不再错误宣称已实现 resume/fsync/no-follow/no-replace。Windows 本地客户端到 Linux 远端仍受支持，其他远端使用 `backend=auto` 时会明确回退 SFTP。
- committed transfer receipt 尚无终端消费 ACK、GC 与保留策略；Linux `/proc/self/fd`、`linkat`、parent-dirfd fsync 和故障注入本轮仅交叉编译/Clippy，仍需 Ubuntu 实机运行证明。

### 本地验证

- 2026-09-01 在当前 dirty v1 工作树上用 `cargo-audit 0.22.2` 在线刷新到 1,233 条 RustSec advisory，并扫描 547 个锁定依赖，命令以 0 退出；这只是开发快照，正式门禁仍要求 exact-tag workflow 重新在线审计。
- 2026-08-31 beta-2 冻结前的 dirty 工作树完成 `cargo fmt --all -- --check`、`git diff --check`、严格 workspace Clippy `-D warnings` 与 `cargo test --locked --workspace --all-targets --all-features -- --test-threads=1`：CLI 148 通过/1 忽略、Core 121、Daemon 31、Protocol 46、Transfer Protocol 5、helper 14，合计 365 通过、0 失败、1 忽略。
- 独立 `target/staging-v0.3/release` 当前保存匹配的 clean beta-2 前驱三件套：CLI/daemon 报告 `0.3.0-beta.2 (git 8b555f7cf136)`，daemon 报告 `IPC v8..=v8`，helper 报告 transfer protocol v1。它只是前驱历史证据，不能作为 v1 构建输入或关闭 v1 exact-tag 门禁；旧 `target/release` 含混合 v0.2/v7-era 文件，禁止用于启动、升级、打包或发布。
- 受控完整链路通过固定 1,298,223-byte 上传、内容一致性、首事件时延与 Agent `transfer.write` grant E2E；纯 SFTP 4/8/16/32 KiB × in-flight 1/2/8 及丢失 STATUS 矩阵通过。
- commit `8b555f7` 的 Local-Linux2 前驱实机记录完成 100,000,000-byte SFTP fallback 双向 SHA-256、no-replace 与 ACL 校验（push 4.70 MB/s，pull 5.67 MB/s）；当时缺少 Linux native helper，因此该历史记录不构成 v1 exact-tag、native 或 typed-job 验收证据。
- 新增完整 russh exec/SFTP 服务端的 4/8/16/32 KiB 首帧矩阵，所有尺寸均能到达 handler 并获 ACK；这排除了 core ChannelStream、SSH window/flush 与服务端分帧本身是 2 KiB 根因。native cap 已据此独立提升并固定为 32 KiB，但尚未覆盖真实 OpenSSH + `serctl-xfer` 子进程 stdio，因此吞吐与更大窗口仍保持未验收。
- `cargo audit --no-fetch --deny warnings` 以本机缓存扫描 543 个依赖和 1,226 条 advisory，0 漏洞、0 警告；这不是在线最新性证明，CI 仍会刷新 RustSec 数据库后重新检查。
- v1 exact-tag 仍需重新执行 21 B、1,298,223 B、64 MiB 与 1 GiB 的双向实机矩阵；上述 100,000,000-byte 前驱结果不能替代它。

## v0.2.0-test.1 - 2026-08-25

- 发布 vault/record v4 与 IPC v6 全局 broker 重写测试快照。
- 每个 profile 使用独立口令、KDF、DEK/AuthSeed、随机 identity 和 generation；移除共享主口令模型。
- Windows 引入超管密码与离线介质组成的 2-of-2 恢复；Linux 保留 root 降权后的破坏性替换入口并对未实现恢复路径失败关闭。
- UI 引入逐 profile 五分钟固定授权与两分钟超管授权；CLI 普通远程调用保持逐次口令验证。
- SSH 本地、远程和动态转发 listener 强制回环；L/R 固定目标地址同样仅允许 `127.0.0.1`。
- 标签提交：`ce634272ca1e98c3d18f76bcb78858ba07283f05`；原重写前 main 基线保存在 `V1` 分支。
