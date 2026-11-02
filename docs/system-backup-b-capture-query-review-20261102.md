# B 共享 SQL 采集查询审查

基线：`951f4c517e0584d6ef1ee5424c1edd41f97c9f28`。本切片已获审核者批准，在指定 domain 文件实现查询组织优化及差分测试；未运行编译或数据库，不占用审核者的缓存、SQL、容器和端口。

结论：业务专用导出已接入原只读 RR 内的有界单行多列精确 `COUNT(*)`，零行表省去第二次数据 SELECT，仍输出原完整 schema；非空表仍逐行读取并比较精确行数。COUNT 后增加一次完整 catalog 重读，shape变化整次拒绝。审核者已确认 domain 整包与新增真实 MySQL 五项检查通过；原 30 秒组合链仍在验证，不能据此声称已解决窗口失败。

## 当前生产消费与成本

生产调用为 `production_capture_modules.go` → `NewUsersInstancesModule` → 唯一 `users_instances_database` 请求 → `worker/formal_capture.go` → `domain.CaptureBusinessSourceGuarded` → 业务专用 `captureWithCatalogMode(..., true, ...)`。通用 `captureWithCatalog` 始终选择 false。Teams/Skills inventory 放在同一个数据库请求中，捕获后对同一 snapshot 执行 `VerifyTeamCapture` 和 `VerifySkillCapture`。不得另起 SQL Job。

| 文件 | 当前行为 | 本提案保留的边界 |
| --- | --- | --- |
| `backend/internal/systembackup/domain/source_table_grants.go` | 有限表 SELECT、原会话身份/角色/权限、前后完整 schema census | 不增加授权，不读取控制表，不放宽未知表拒绝 |
| `backend/internal/systembackup/domain/source_catalog.go` | 四条聚合查询返回完整表/列/主外键/所需唯一键元数据 | 沿用已有实现，不重复优化 |
| `backend/internal/systembackup/domain/mysql.go` | 一个只读 RR；每表 SELECT 全列并按原 PK 排序；每个 Next/EOF 前后授权 | 非空表逐行路径、容量、原值编码、事务结束与会话复核不变 |
| `backend/internal/systembackup/worker/formal_capture.go` | 原 source 与 key 当前检查、加密输出、完整 schema/Teams/Skills比较 | 默认原 30 秒及所有加密输出检查不变 |

静态成功路径计数：令 T 为实际被采集的业务表数，R 为总业务数据行数。仅 `captureWithCatalog` 与四行 catalog 主路径约有 `G = 29 + 4T + 2R` 次 source guard：四条 catalog 每条 6 次，加 catalog 尾部 1 次、事务路径 4 次；每张数据表 query 前后 2 次、每行和 EOF 前后各 2 次。这里没有计入外围 worker/seal 和会话/census 内部 SQL，也不是 native 日志总数的反推。

当前 `formal_capture.go` 的 `checkSource` 先调用一次 `env.SourceAuthorize`，随后 `inUseCheck` 内做 key recheck 并再次 source authorize。因此每个上述 guard 对应两次 source authorize、一次 key recheck。它们横跨 key recheck 的前后顺序，不能未经 A 审核就合并或删除。本提案完全保留该 callback。

协调者提供的现场诊断为：174 迁移原任务在 DB 的原 30 秒 key/context/source 截止失败，128 次 key checks 累计 28.306 秒；约 801 次 local authorizations 和历史边缘成功约 455 次 key checks 是不同观测口径，不能直接代入 G 或拼成一次成功证据。

后续协调补充：历史 v13 的 801 次 local source auth 仅累计 0.717 秒，而 409 次控制 key checks 累计 28.76 秒。主要成本在控制侧 key check，不能为小额本地收益改变撤权顺序。两次 source authorize 之间包含耗时控制 RPC；删除后一次可能失去 RPC 后的独立源撤权复核，删除前一次也需另证 key check 的副作用与 operation context 语义。本切片不提议修改此顺序。

## 建议的精确空表 census

只对 `BusinessTableSourceScope` 启用；legacy 通用 `Capture`/`CaptureSource` 路径保持原行为。先完成原 catalog、完整 schema census 和所有实际选中表的结构校验，再在同一 `*sql.Tx` 上构造分块查询，例如：

```sql
SELECT
  (SELECT COUNT(*) FROM `users`) AS c0,
  (SELECT COUNT(*) FROM `user_quotas`) AS c1,
  (SELECT COUNT(*) FROM `instances`) AS c2;
```

表名只取经 `rules()`/原有限授权选中且通过 identifier/quoted 校验的实际 catalog，按原确定顺序绑定列位置。建议每块最多 64 表，并设语句字节上限；这两个界限应成为固定实现约束并有边界用例。不能拼接用户输入、配置中的任意表名或额外 schema。

每块通过现有 `sourceGuardedQuery{tx, authorize}` 执行，读取唯一一行及 EOF 均使用现有 `sourceRowsNext`。SQL 执行前后、结果 Next 前后、EOF 前后继续完整当前授权。COUNT 是同一敏感 SQL statement 的多个子查询，不在查询中途新增未授权读取，也不把之前的授权缓存到之后的 statement。若 A/D 要求子查询逐个授权而非 statement 边界，则此方案不适用，不能通过削弱该要求推进。

结果必须恰好一行、列数等于本块表数、列顺序与本地计划一致，逐值用整数无损解码；NULL、负值、溢出、丢列、额外行、SQL/Scan/EOF错误一律整次捕获失败。不得以错误或缺结果推断空表。COUNT 本身不进入公开日志或改变结果协议。

COUNT 持有所有选中表的事务期 MDL 后，使用原四条聚合查询重读完整 catalog，以结构值精确比较原/新表名、engine、Columns/Type/Nullable/Default/Extra、PK/FK/UniqueKeys；不同则拒绝，不采纳新 shape。这样避免 catalog 与 COUNT 之间的 DDL 被零行分支掩盖。审核者已确认真实 MDL 与 DDL 反例检查通过。

精确 count=0 时，把原 catalog 的完整 `Table` 以原零行表示追加到结果，不执行该表的第二次数据 SELECT；不是省略表。count>0 时原数据 SELECT、逐行 rawCell、排序和行/字节预算全部执行，并要求读到的精确行数等于该表 census。任何 mismatch 拒绝，不修正 count、不重采集。

不能使用 `information_schema.TABLES.TABLE_ROWS`、统计信息、旧任务行数、业务 inventory 的非空推断或独立连接上的 count。不能启用 `READ COMMITTED`、locking read、第二事务或扩大业务角色权限。

## 正确性与收益条件

同一个 RR 事务中，catalog 后的 COUNT 和后续数据 SELECT 必须使用相同 InnoDB 一致性视图；这是跳过零行 SELECT 的核心条件，需要真实 MySQL 并发用例证明，不由内存 driver 冒充。原 writer freeze 与 schema census 保持：并发 DDL、未知表、失效授权均不能被空表结果掩盖。未知/不合法表应在 census 前拒绝，原最终身份/权限/schema census复核仍执行。

设 E 为精确空表数，K 为 census 分块数。每块单行结果加 EOF 约 6 个 guard，空表各省 4 个 guard，锁后 catalog 复读增加 25 个 guard；所以主路径变为 `G' = 54 + 6K + 4(T-E) + 2R`，静态减少 `4E - 6K - 25`。实际数据 SELECT 从 T 次减少到 T-E 次，另增加 K 次 census 和四条 catalog 查询。若采用每表一行的 UNION 结果，结果 Next 会继续按表触发检查，收益小于这里的单行多列方案。

例如仅作算例，T=100、E=80、K=2 时减少 283 个 guard；这不是现场表数或计时结论。COUNT 也会扫描非空表索引，密集大表可能增加耗时；不能承诺一定赶上 30 秒，也不能在 census 失败后 fallback 另采一次。应先用同规模数据测量 count 扫描成本与控制往返节省，再决定部署采用。

## 已批准的实现文件范围

本切片只修改以下已获批文件：

- `backend/internal/systembackup/domain/mysql.go`：抽出业务专用的内部选择入口；原 `captureWithCatalog` 调用保持兼容。对明确证实空表的分支追加完整 Table，其余原逻辑继续执行。
- `backend/internal/systembackup/domain/source_table_grants.go`：仅让正式有限表入口选择上述 census 路径，保留前后原会话检查。
- 新 `backend/internal/systembackup/domain/source_row_counts.go`：有界单行多列 COUNT builder、严格解码及原 guard 调用；不导出新公共 ABI。
- 新 `source_row_counts_test.go`：查询覆盖/损坏/撤权差分；必要时对已有 `mysql_test.go` 的专用内存 driver 作最小扩展，不把 driver 结果当 RR 证明。
- 新 `source_row_counts_mysql_test.go`：由审核者安排真实 MySQL 的事务/权限/并发差分，复用现有原 TLS fixture 边界，不创建第二套环境。

不改 `worker/formal_capture.go`、A permit/KEK、D production 构造、公共 C publication、两位 C 模块。`mysql_test.go` 仅新增专用查询 hook/观测列表，未启用 hook 的原测试行为不变。

## 必要差分验证与执行交接

| 验证 | 必须观察 |
| --- | --- |
| 混合空/非空与全空支持表 | 新旧 snapshot 的完整表/列/值/digest一致；空表仍在，非空原始大整数、二进制、NULL和时间值不变 |
| 跨块与容量 | 1/64/65 表；完整全表映射；原行/字节限制仍拒绝；COUNT不得因溢出当零 |
| 撤权/截止/取消 | 每个 COUNT query/Next/EOF边界及之后数据/最终边界注入失败；返回零 snapshot、rollback、无部分成功 |
| 错误回执 | 缺列/NULL/负数/溢出/第二行/提前EOF/Scan/SQL错误全部拒绝；不能标为空 |
| 同快照真实反例 | 事务A count空后B提交插入，A后续一致性读取仍为零；A count非空后B提交更新/删除，A导出仍为原同批次值；新事务能看到B提交 |
| 有限权限 | 原 SELECT-only业务身份可执行精确COUNT，撤销某表SELECT立即失败；控制表/未知表不得进入生成SQL |
| 正式消费 | 同一原task/attempt六部分中Teams/Skills验证不变；记录整体key/source/capture剩余窗口和phase耗时，不能只报COUNT耗时 |

2026-11-02 主审核对话 `01a199ad-14eb-7003-8f6b-1b4c9ad793bc` 回报的本轮实际结果：

- 整个 `domain` 包实际 PASS，包耗时 8.565 秒。
- `TestSourceRowCountsMySQL` 五项全部实际 PASS，耗时 2.25 秒，均非 SKIP：完整 snapshot 差分、真实 RR 并发、COUNT 持有 MDL 阻 DDL 且 rollback 释放、COUNT 前 DDL 改变空表 shape 被拒绝、有限 SELECT 及撤权拒绝。
- 审核者独立读回确认，本轮随机 `b_counts` schema/account 均已不存在。
- 本轮测试日志 SHA256：`55dd273db952b367e62642331512be46382d3a4c89af947f648dd0481e4b18d2`。
- 其他 opt-in 恢复/worker native 因未设置其专属环境而 SKIP，不列作通过。

以上是主审核实际运行并回传的结果，B 对话没有自行执行编译、SQL或远程操作，没有自建测试产物。六个 Go 文件保持冻结。A+B+C 的原 30 秒完整 capture → SQL local cleanup 组合测试已由审核者启动，结果仍待返回；本次 domain/RR 通过不能替代该链或真实页面备份验收。

代码冻结后，由审核者在其独占缓存中统一执行（PowerShell，cwd 为仓库 `backend`；不设置 TLS 环境变量时 native 子项会 skip）：

```powershell
go test ./internal/systembackup/domain -run 'TestBusinessAggregate|TestBusinessCaptureSchema|TestFiniteBusinessSourceGrantMatrix|TestSourceRowCounts' -count=1
```

新 native 入口 `TestSourceRowCountsMySQL` 复用审核者持有的 `TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS` 私有凭据文件，读取最多16385字节、拒绝超过16384字节的JSON。格式与当前 same-task 测试一致：Host=127.0.0.1、Port=1024至65535且非3306、非空User/Password/TLSServerName、绝对CAFile、ServerUUID；另须独立设置 `A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID`。TLS最低1.3，在任何建库/建账号前核对真实UUID=凭据UUID=独立pin；创建随机 `b_counts_<nonce>` schema/account，始终清理自身资源，失败也不保留数据。该测试只证明查询/RR/MDL/权限，不冒充正式 task 授权。

在审核者已正确设置该凭据变量和其独占 Go 缓存后，PowerShell/cwd=`backend` 执行：

```powershell
go test ./internal/systembackup/domain -run '^TestSourceRowCountsMySQL$' -count=1 -v
```

预期五项真实检查通过：新旧完整snapshot差分、同RR的空→插入和非空→更新/删除、COUNT持有MDL令并发ALTER得到1205且rollback后可ALTER、COUNT之前DDL改变空表shape被拒绝、SELECT撤销后COUNT拒绝。输出只含测试结果/错误类型，不输出凭据/业务值。测试在主fixture进程存活期间清理自有用户/库；审核者按本轮独占快照流程删除自己生成的Go构建产物，不触碰其他缓存或日志。远测统一由协调者安排，本对话不连接现场。

## 供 A D C 引用的生产消费差集

`deployment_service.go:277` 构造 `NewPublicCapture` 并提供 `ModuleFactory`；`public_runtime.go` 从原冻结输入调用该工厂。`production_capture_modules.go` 已注册 Users/Instances、Teams、Skills、控制证据、部署及秘密资源、源 Redis 六个构造，并可加入 capture description。早期“没有正式模块生产 caller”的交接已过时。

`deployment_runtime_sources.go` 的 `attachRuntimeSources` 使用 D 的 `NewSQLRuntimeControl` 与 `BuildWriters`，将 platform/runtime 的冻结 writer 分开绑定后合并。不是因为 B 的低层 `NewRuntimeLinuxProfileConfig` 没有生产 caller 就代表 Runtime 未接入，也不应重新申请 reservation。`RuntimeWriterSpec` 已保留原 Source、RuntimeLocator v2、operation、restart摘要/材料引用和原 resume generation；回调包含 GatewayControl、ClaimRestart、CompleteRestart、ConfirmStopped、ConfirmResumed。原 stopped 实例保留 stopped 身份，不作为运行实例重启。

Teams 共享 writer 检查覆盖六项 `TeamsWorkUnits`：pending deletions、event projection、maintenance sweep、northbound operation、lifecycle action、workspace HTTP。配置全集检查不能证明实际每个副本和子进程已经退出；现场仍由 D 交原 operation/PodUID/generation、真实停止/恢复与迟到回调隔离证据。

两位 C 的直接输入是原 `SourceInventory.Teams`、`TeamFacts`、`Skills`，对象的精确版本/hash和实例 workspace依赖。`users_instances_module.go` 克隆两个 inventory 到唯一 SQL 请求，不能另建独立 SQL snapshot。`productionModuleContext` 绑定原 task/request/config/profile/attempt/hold、完整 Source hash 和 FrozenWriters；part index 按 module/part 全局确定顺序生成。结果继续使用原 worker receipt、seal 与登记链，不新增 C 自造成功 DTO。

完整 SQL profile 已有有限表授权、独立 schema census、聚合完整 metadata、`northbound_operations` 依赖及 26 列显式 077 恢复适配。`normalize.go` 已区分普通 `DEFAULT_GENERATED` 和真正 `VIRTUAL/STORED GENERATED`；现场 schema/权限匹配仍须独立验证，不能从这些源码推定通过。

## 正式恢复输入差集

`public_restore.go` 已把原 task loop 接到 `NewRestoreRunner`，但该 runner 无认证源参数，`RestorePorts` 目前只暴露 `CheckRestore`。拒绝 `ErrRestoreSourceUnavailable` 是真实能力边界，不能改成成功。

A 已有 `systembackupkms.NewRecoveryJob`、`systembackupwire.InspectWrappedStream` / `VerifyWrappedStream` 和独立 `Unwrapper` 原语；这些不是完整 public v12 认证源句柄。后续恢复装配需要：

- A/公共 C：同一正式成品的固定 manifest/marker/acceptance/catalog、签名信任与完整成员覆盖认证；每成员精确对象 version、cipher/envelope、KeyContext、历史 mapping 与 live 恢复授权；完整帧认证通过后才可消费的读取句柄。
- D：原 drill task/plan、独立 namespace UID、数据库 serverUUID/name、源挂载到目标 PVC/PVUID 的映射，以及当前真实物理隔离能力与原权限。
- 两位 C：沿上述认证成品派生的 Teams/Skills 数据输入和独立目标只读核验，不能以 workspace 成功替代全部业务恢复。

legacy `recovery.StagingAuthenticator`、版本 map、proof callback、receipt/hash 或签名 JSON 本身不能代替完整认证源与隔离句柄。本轮只记录输入，未修改恢复 runner，也未另建状态机。
