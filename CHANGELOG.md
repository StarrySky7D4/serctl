# 更新日志

本文件记录面向使用者、运维人员和安全审计人员的重要变化。项目仍处于预发布阶段，正式发布前可能继续调整命令、存储格式和协议。

## 未发布

### 修复

- 修复 OperationGrant 文件尚在 30 分钟有效期内，但 daemon 自动空闲退出并由新实例接管后报告 `unknown or expired` 的问题。未过期 Grant 现在持有 daemon 活跃引用，到期清理后才释放；人工重启、升级和崩溃仍会使旧 Grant 失效。
- 将 Grant 错误拆分为“当前 daemon 实例未登记”和“Grant 已过期”。新实例不会仅凭磁盘 Grant 文件恢复授权，避免削弱实例绑定和签发边界。
- 修复远端文件刷新可能长期卡在“正在读取”的问题：UI 目录请求使用独立 20 秒上限，并在状态文本中显示该上限。
- 大目录列表改为仅物化滚动视口内的行，不再每帧克隆和布局全部目录记录；新增 10,000 条记录的 UI 回归测试。
- 修复 profile 标题栏和授权输入框可能挤压工作区或把操作按钮推离可视区域的问题。
- 修复 Windows 新建主机在进入“安全与恢复”完成授权后没有继续原保存动作，以及恢复介质轮转撤销授权后不能续接保存的问题。
- 补齐 v2→v4 原子迁移的阶段进度消息，使校验、等待独占访问、旧库认证、逐 profile 派生、恢复介质持久化和 vault 提交均可见。
- 修复全局 daemon 首次 TOFU pin 被共享 profile 使用租约误判为无权 mutation 的问题。TOFU 仍只能填充空 pin、保留 identity/generation，并在 vault 排他锁内认证和拒绝并发冲突；普通 profile 修改仍需独占 mutation lease。

### 调整

- GitHub Actions 的全目标、全 feature 测试固定为单线程，避免进程级测试 home、daemon runtime 和凭证库隔离状态互相干扰。
- 修正 `up` 与 `grant-issue --operations` 的 CLI 帮助：全局 broker 不会在启动时预解锁指定 profile，Grant 操作范围必须使用精确协议种类。
- 新增完整中文使用手册，并同步 README 与架构安全文档中的 Grant 生命周期和故障处理说明。

### 验证记录

- 基线提交：`8bb97801fdca996296d89f79b43713f81ec0935f`，已推送至 `origin/main`。
- 分包复核：CLI 134/134、Core 115/115、Daemon 27/27、Protocol 43/43，合计 319/319。
- Daemon 严格 Clippy（`--all-targets -- -D warnings`）、Rustfmt 和 Git diff whitespace 检查通过。
- 一次并行 workspace 运行中的 Windows KEX deadline 测试出现本机 `10053 ConnectionAborted`；该单项与 Core 115 项全套随后均通过，因此未把首次 workspace 命令记录为全绿。

## v0.2.0-test.1 - 2026-08-25

- 发布 vault/record v4 与 IPC v6 全局 broker 重写测试快照。
- 每个 profile 使用独立口令、KDF、DEK/AuthSeed、随机 identity 和 generation；移除共享主口令模型。
- Windows 引入超管密码与离线介质组成的 2-of-2 恢复；Linux 保留 root 降权后的破坏性替换入口并对未实现恢复路径失败关闭。
- UI 引入逐 profile 五分钟固定授权与两分钟超管授权；CLI 普通远程调用保持逐次口令验证。
- SSH 本地、远程和动态转发 listener 强制回环；L/R 固定目标地址同样仅允许 `127.0.0.1`。
- 标签提交：`ce634272ca1e98c3d18f76bcb78858ba07283f05`；原重写前 main 基线保存在 `V1` 分支。
