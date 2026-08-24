# serctl 重构验收报告：Phase 2 / Phase 3（对照设计文档 §22 验收标准）

- 基线 commit：`b27803fb379ea5d2e6b5a5d565d32677086dcd6d`
- 版本标记：`v0.2.0-test.1`（预发布测试版；原 main 保留为 `V1`）
- 仓库：`StarrySky7D4/serctl`
- 验证环境：Windows，Rust 1.97.1，`cargo fmt --check` + `cargo clippy --all-targets --all-features -- -D warnings` 全绿
- 测试总量：**315 个**（serctl_cli 131、serctl_core 115、serctl_daemon 26、serctl_protocol 43），0 失败

---

## Phase 2：per-user / per-vault 全局 broker

### 2.1 单例启动协议（Singleton Startup）
- `serctl_core::daemon_runtime::acquire_startup_lock`：`daemon-startup.lock` 上的排他字节锁（fs2）；Windows `ERROR_LOCK_VIOLATION`(33) 映射为 `Contended`。
- 客户端 `client::ensure_daemon_until`：resolve → 抢锁 → 持锁二次检查（TOCTOU 双保险）→ `launcher::spawn_global_daemon` → 轮询 descriptor 直到出现目标 instance。
- 测试：`daemon_runtime` 7 个单测（`crates/serctl_core/src/daemon_runtime.rs`）覆盖锁获取/竞争/陈旧清理。

### 2.2 运行时 descriptor + 激活密钥（Runtime Descriptor & Activation Secret）
- `DaemonRuntimeDescriptor` v1：instance_id、pid、endpoint、protocol 范围、started_unix、build_commit —— **不含任何密钥**。
- `daemon.secret`：仅当前用户可读的独立受保护文件，daemon 退出时与 descriptor 一并清除（`clear_runtime_state`）。
- CLI `up`/后台模式均通过 `--global-instance <hex>`（argv，非密）+ stdin `SD02` 帧（Base64 密钥）引导，密钥从不进入 argv/环境/日志。
- 测试：`global_daemon_serves_catalog_rejects_bad_unlock_and_shuts_down`、`global_daemon_exits_after_its_idle_window_with_no_work`（descriptor/secret 清理断言）。

### 2.3 IPC v6 双向认证 + AEAD
- `serctl_protocol::v6`：per-boot `ActivationSecret`(256-bit) + `InstanceId`(128-bit)；握手双向 transcript-bound HMAC（`v6_client_handshake`/`v6_server_handshake`）；HKDF-SHA256 派生 c2d/d2c 方向密钥；ChaCha20-Poly1305，方向字节 + 严格递增 64-bit 计数器 nonce，AAD 绑定 version/instance/direction/length；重放/乱序/篡改一律断连。
- `V6RequestPrelude` 在明文握手段提交 `root_request_hash`（根帧 `serde_json` 序列化的 SHA-256）；服务端校验 hash 与 `frame_kind` 一致，adapter 对 4 字节长度前缀做一致性校验。
- 复用层：`V6ClientIo`/`V6ServerIo` 使 v6 会话呈现 v5 字节流，所有既有 daemon/client 操作处理器**零改动**运行于其上。
- 测试：`serctl_protocol` 43 个测试（含握手、root-hash、profile proof 全字段绑定、nonce 严格性、截断/篡改失败闭合）。

### 2.4 删除 direct-connect 回退
- `crates/serctl_cli/src/client.rs` 中 `direct_connect_until`、`acquire_direct_profile_snapshot_with/until`、`connect_direct_profile_until`、`upload_file_direct_until/worker`、`download_direct_until`、`open_direct_shell_until`、`shell_direct`、`gui_tunnel_from_direct` 及全部 `else { direct }` 分支已删除；`connect_daemon_for_request_until` 返回非空 `DaemonConnection`。
- 客户端操作（exec/shell/tunnel/upload/download/list/create-dir/status/down）现在**只**经由全局 broker；TOFU pin 持久化移至 daemon 的 `connect_unlocked_session`（独占 lease 下原子 pin，失败则中止 KEX，先 pin 后密码认证的顺序不变量保留）。
- 测试：e2e `authenticated_daemon_exec_timeout_and_transfer_e2e` 全流程经 broker 通过（含 TOFU 失败时密码认证为 0 的断言）。

### 2.5 per-Profile 资源池与 credential lease
- `ProfilePool`（`StdMutex<HashMap<profile_id, Arc<ProfilePoolEntry>>>`）：`CREDENTIAL_LEASE_TTL = 30 min` 由独立 1 秒 reaper 主动清理；每个 handler/tunnel 还受同一 monotonic hard deadline 包裹，到期即取消并释放 `vault::ProfileLease`。活跃 profile 的 vault 变更（update/remove/rekey）被 lease 阻止。
- 客户端进程内 `UNLOCKED_PROFILES` 镜像按 `(instance_hex, profile_id)` 缓存短期 call key（不是口令、DEK 或 SSH 凭据），每次访问主动清理全部过期项；daemon 重启换 instance → 镜像自动失效。普通请求必须携带 call-key HMAC，绑定完整 prelude，激活密钥本身不能操作任何已解锁 profile。
- 错误口令在 unlock 步被 daemon 拒绝（Error 帧，含 "wrong profile passphrase"），永不触及 SSH（e2e 以 SSH 端无 exec 事件证明）。

### 2.6 空闲退出（Idle Exit）——引用计数实现
- `IdleTracker`：`AtomicUsize` 工作量计数 + `Notify`；每条连接 handler 持有 `IdleGuard`（tunnel/shell/传输贯穿 handler 生命周期）；计数归零并保持 `IDLE_EXIT_TIMEOUT = 10 min` 后 broker 自行退出并清除运行时状态；窗口到期与新增工作竞态时二次检查，绝不在工作进行中断退。
- 测试：`global_daemon_exits_after_its_idle_window_with_no_work`、`global_daemon_keeps_serving_while_live_work_holds_the_idle_counter`。

### 2.7 CLI / UI 迁移
- `main.rs`：`up`（前台全局 broker、已运行时拒绝）、`exec/upload/download/shell/tunnel/status`（on-demand 启动 broker）、`down`（每次重新读取目标 profile 口令，在 v6 AEAD 内本地验证但不新建 SSH 连接，再等 descriptor 消失完成协调式停机）。
- `ui.rs`：`start_daemon` 变为"确保 broker 发布 + 解锁该 profile"（授权 Status 探测兼作就绪信号）；刷新使用**不启动 broker** 的 `daemon_status_probe_at_generation`；`stop_daemon` 走全局 `down_quiet`。

---

## Phase 3：Agent 网关与 OperationGrant

### 3.1 OperationGrant：PoP Ed25519 + scope/budget/audit
- `serctl_protocol::grant::OperationGrant`：单 profile + 明确 operation-kind 白名单（`ssh.exec/daemon.status/sftp.list/sftp.read/sftp.write/forward` 的子集）+ `budget ≤ 1000` + `GRANT_TTL = 30 min` + holder Ed25519 公钥。
- PoP：agent 对**完整 prelude**（domain 分隔符 + 规范化 JSON，含 grant_id、requested_deadline、root_request_hash）签名；`sign_prelude_pop`/`verify_prelude_pop`；prelude 新增 `pop_signature` 字段，`validate()` 强制 grant_id 与 PoP 同现、且与 profile_id 互斥。
- 测试：`signed_prelude_verifies_and_tampering_fails_closed`、`grant_scope_and_expiry_are_checked`、`grant_issuance_rejects_invalid_scope`、`pop_signature_and_grant_id_are_bound_in_the_prelude`。

### 3.2 daemon 端发放与强制
- `GrantRegistry`：grants 随 daemon 实例生死（重启即全部失效，与新 activation secret 绑定），硬上限 1024 并由 1 秒 reaper 主动清理过期项；`issue_grant` 同时核对 profile name/id、已解锁 lease 与完整 prelude 的 profile call proof。
- 每次中继：`check_and_spend` 依次校验 monotonic 未过期 → requested deadline 必须非零、尚未到期且不晚于 grant 到期 → scope → profile name/id → PoP → CAS 原子扣减预算；handler 的实际 hard deadline 取 requested deadline、grant expiry 与 credential lease expiry 三者最早值。
- 测试（e2e）：预算 3 次中继全部成功、第 4 次 "grant budget exhausted" 且 SSH 端零 exec；scope 外操作被拒；异钥 PoP 被拒。

### 3.3 审计（Audit）
- 每条中继与每次拒绝在进程内互斥序列化后，通过创建时即受保护或已验证的稳定句柄追加 JSONL 到 `<run_dir>/grant-audit.jsonl`，并执行 `sync_data`；daemon 重启后持久保留。持久化失败仅告警，因此这是 best-effort 本机诊断记录，不是完整性日志或不可否认证据。
- e2e 断言审计文件同时包含 `accepted`、`rejected: grant budget exhausted`、scope 拒绝与 PoP 拒绝记录。

### 3.4 Agent stdio 网关
- `serctl_cli grant-issue --operations ... --budget ... --output FILE`：生成 agent 密钥对，仅公钥绑定进 grant；`AgentGrantFile`（grant + 32 字节种子）使用创建时即受保护的 create-new handle 写入并同步，绝不覆盖既有文件。
- `serctl_cli agent --grant FILE`：通过受保护稳定句柄读取，文件上限 64 KiB，种子/解析缓冲按生命周期清零；stdin JSONL 单行上限 1 MiB，超限在继续扩容前拒绝。
- 单元测试：`agent_stdio_gateway_reports_invalid_request_lines_without_a_daemon`（注入式读写流）。

### 3.5 Visible Relay
- daemon 侧：每次成功中继向 stderr 输出 `[serctl] grant relay: <kind> <profile> (grant <id>, budget left N)`；每次签发输出 `grant issued ...`。
- agent 侧：每条结果行即对用户的可见中继回执（含错误原因）。
- 审计文件仅提供本机可见、best-effort 的排障轨迹；对本机管理员不宣称防篡改或不可否认。

---

## 遗留说明（不阻塞验收）
- daemon 二进制仍保留 legacy `--profile` 单 profile 模式与 v5 服务路径（`daemon::run`）：与 v6 并行、互斥运行，仅供回退兼容；CLI 已完全不再引用。设计若要求彻底移除，可作为独立收尾项。
- 普通 profile 操作的 hard deadline 由 daemon 的 monotonic credential lease 强制；grant 操作还必须提供非零绝对 deadline，并转换为 monotonic deadline，与 grant/profile 到期时间共同取最早值。
- 30 分钟 credential lease 与 grant TTL 对齐；grant 中继仍要求 profile 处于已解锁状态（口令永不进入 grant）。

## 结论
Phase 2 全部验收项（单例启动、descriptor、v6 双向认证 + AEAD、per-profile proof、direct-connect 删除、per-profile 池 + hard lease、空闲退出、CLI/UI 迁移）与 Phase 3 全部验收项（Agent stdio 网关、30 分钟 OperationGrant、PoP Ed25519、scope/budget/best-effort audit、Visible Relay）均已实现并通过 315 项测试、`cargo fmt --check` 与 `cargo clippy -D warnings`。
