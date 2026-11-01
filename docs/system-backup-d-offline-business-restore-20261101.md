# D 离线业务恢复交付（2026-11-01）

本次从本地已提交 `backup` 基线 `0e797e4e0db1305cb4b4ea55456764b207e4d548` 创建独立 clone，分支 `d/offline-business-restore`。未修改 ClawManager、ClawManager-A、ClawManager-D；未 fetch/pull/push，未连接远侧、真实 provider、集群、对象存储或 KMS。没有创建子代理或向其他聊天发消息。

**结论：完成了可审查的非空 SQL 恢复修复与本机组件验证，尚未完成正式发布产物的六部分生产恢复/验收。** 下列成功结果不授予 readiness、catalog 资格、验收签名或启动权限。

## 代码改动

1. `domain.Policy.Skills` / `worker.DatabaseSpec.SkillsRestore` 复用 `systembackupskillhub.RestoreMapping`。公共 worker、profile 目标预检使用相同请求字段；验证任务清除映射，仅消费恢复前提交边界封存的加密预期数据。当前公共 SQL 路径保留各域 ID，所以拒绝任何改变 ID 的 Skills 映射。
2. 八表非空时要求完整源表集合和显式映射。原 SQL raw-cell 格式不变；只将明确列清单投影给 B 的现有 `PrepareRestoreRows` 做关系、扫描结果、版本归属、对象映射和路径校验。投影不是新的备份格式，raw cells 仍用于 SQL 写入，包含 `manifest_json`、`findings_json` 等 `json:"-"` 字段。
3. 保留 Skills 扫描关系与八表历史。`skill_package_materialize_jobs` 从丢弃改为保留，pending/running 归一为 cancelled；实例安装状态与用户修改的 observed hash 保留，安装/workspace 路径显式重映射到目标相对路径。对象 key 必须使用同一映射。缺少映射不回退到源路径或 removed 状态。
4. 添加 `skill_scan_results.updated_at` 和 materialize 表的显式列清单。未知列/缺少列继续拒绝。独立验证检查关系闭包、终态作业、安全相对路径以及实例 stopped；它**不证明**映射指向的物理挂载或对象已经恢复。
5. 修正真实 MySQL 暴露的两个通用断点：普通 timestamp 的 `DEFAULT_GENERATED` 不等于 `STORED/VIRTUAL GENERATED`；`Cell{Null:false, Bytes:nil}` 必须以非 nil 空 byte slice 绑定，防止驱动把合法空值写成 SQL NULL。真正生成列仍拒绝。
6. SQL worker 在调用任何授权回调前冻结完整请求，每次回调获得独立副本。源调用者或回调修改映射不能改变待写对象 key/安装路径。新增路径的投影、B 关系校验和独立验证继承任务 context。

未变更授权、认证、签名、发布 continuation、目录 append/read、最终 CAS 或 SecretPolicy。没有自动生成放行十一张未知 owner 表的 identity adapter。

## 本地测试证据和范围

最新可审查日志位于 `docs/evidence/d-offline-restore-20261101/`；`scope.json` 明确未验证项。测试使用本地 Go 1.26.1、现有模块缓存，`GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`。本窗口 MySQL 为从缓存复制的 8.4.13、独占 datadir、随机 loopback 端口 50809；不使用 63507、65298、59355 或其他窗口账号/库。

| 验证 | 实际覆盖 | 不能据此宣称 |
| --- | --- | --- |
| `TestOfflineBusinessRestoreMySQL` | 实际 Skills migrations 008/023/039，八表均非空；实例/Teams 非空夹具 schema；现有 Capture → staging AEAD → Decode → RestoreDrillWithEvidence → SELECT-only VerifyDrill；源句柄在恢复前关闭；写账户关闭、ACCOUNT LOCK、再次认证失败；空值/NULL/timestamp、关联内容、篡改拒绝；证据失败、取消、隔离撤销均到达证据边界后回滚 | 全量生产 schema、集群 Job 结束、真实 TLS/挂载、生产账户撤销 |
| `TestPublicWorkerNonemptyBusinessRestoreWithFrozenMapping` | 公共 SQL worker 加密文件协议；非空实例/Teams/八表；授权回调/调用者映射变异不影响目标；独立 SQL verifier；同一 SQL object/workspace 映射被 B 版本对象验证器与原 workspace worker 消费；本地加密对象捕获；用户编辑的 SKILL.md 未被包内对象替换 | 正式 v12 已发布 manifest/container 的完整生产 Runner 装配；真实对象 PUT/version receipt |
| domain / worker / profile / systembackupskillhub 四包 | 全包 PASS；B 的独立 MySQL writer 测试也只使用本窗口同一隔离服务器的独立库/账号；现有 Team shared-workspace、版本对象、正式 Redis collector/readback 的本地测试包含在包内 | 所有 opt-in 外部服务测试均已运行；未配置的真实 Redis/MinIO/生产凭据测试仍 skip |
| `TestOfflineNonemptyRedisCaptureToIsolatedHistoryTarget` | 现有有限源捕获 → `AdaptSourceRedisHistory` → `RestoreRedisHistory` → 独立 reader `VerifyRedisHistory`；独占随机 loopback RESP 夹具、AUTH；非空 stream/binary；writer 结束/撤销后不能再认证，reader 写拒绝；只写历史前缀，不激活源队列；取消零写，注入失败保留所属部分目标并拒绝直接重试；源无写命令 | 真实 Redis RDB/Lua/ACL/PEL 引擎执行；该 fixture 只保存 opaque DUMP 字节 |
| 离线预检 7 项 | 无参数输出缺失材料；拒绝 live 参数；UNC/device/URL/ADS/越界在 FS 调用前拒绝；祖先 symlink/junction 拒绝；真实本地 >16 字节 JSON 正向；16 MiB 边界；输出 wx 不覆盖 | 文件系统被并发恶意替换时的 OS 级隔离；现场状态真实性 |

早期红日志保留，不能与最新成功日志混淆：

- 首批 `e75a0ba55de3cac1b7e8cdf7532906ff727de2b9` 的 Redis 重试断言不足：使用只读账号且故障仍开启，不能排除因权限/注入错误而假通过。补强后使用原有效 writer，解除故障后重试，断言准确的 nonempty 错误、RESTORE 尝试次数未增加、原单条内容未变；随后关闭/撤销 writer，用独立 reader 拒绝不完整目标。`redis-retry-guard-pass.txt` 三场景通过；测试 overlay 将唯一 `n != 0` 守卫改为 `n < 0` 后，`redis-retry-guard-mutation-expected-fail.txt` 在重试边界按预期失败。没有改动生产守卫；原 `scope.json` 对应首批测试源码，补强的源码绑定见 `redis-retry-guard-scope.json`。

- 沙箱内原 staging worker 文件身份/硬链接操作失败；同一原测试在获准 host 本机环境通过。没有关闭保护，不能归因为 Windows 不支持。
- 初次真实 MySQL fixture 缺少有效 visibility、过长测试账号；修正 fixture 后真实恢复继续暴露上述 timestamp 和空值生产代码问题。最终日志逐项通过，失败用例额外断言确实到达证据边界，避免“前置失败冒充回滚成功”。
- 原 `system-backup-d-capacity-deployment.test.mjs` 扩展回归仍有 **2 个基线失败**：当前 registry 不包含其测试要求的 `system_backups`；仓库缺少 `deployments/k8s/system-backup-capacity.template.json`。另 9 项原测试通过，新预检测试独立 7/7 通过。本次没有改写原 D 文件掩盖这两项。

## 离线预检使用

```text
node scripts/system-backup-d-offline-restore-preflight.mjs
node scripts/system-backup-d-offline-restore-preflight.mjs --input docs/local-restore-materials.json --output docs/local-restore-review.json
node --test scripts/system-backup-d-offline-restore-preflight.test.mjs
```

无参数合法，退出 2 并列出五类缺失材料。输入必须先复制到本 checkout 的本地普通文件，大小最多 16 MiB；输入/输出路径不能越出 checkout，不接受 UNC、URL、设备、ADS、`..` 或链接祖先。输出只创建新文件。脚本不支持现场执行开关，也不读取 DSN/密码环境变量。

输入顶层只允许 `capacity_plan`、`fresh_reference`、`public_inventory`、`observer_observation`、`restore_target`，允许缺省以生成缺失清单：

- capacity_plan：复用 `capacityTemplate` / `renderCapacityDeployment` 的公开字段和本地校验；不执行渲染的 Deployment。
- fresh_reference：复用 `checkFreshReference`，包含 `catalog_sha256 / records_sha256 / records`；只检查提供字节与当前迁移目录，来源仍须现场确认。
- public_inventory：保存的 Kubernetes List，仅 Namespace、Pod、Node、PVC、PV；核对公开 UID、节点、MySQL mount 与不同 report PVC。不是 live 查询。
- observer_observation：现有 `system-backup-sql-observation.v1` 的保存输出；检查 readOnly / snapshotRolledBack / tupleBound。不能证明当前权限或凭据有效。
- restore_target：公开 `namespace / database / server_uuid / writer_user / verifier_user / workspace / object_bucket / object_prefix / redis_history_prefix`。只做隔离命名和身份冲突检查，不能替代权限与物理资源观测。

即使材料齐全，也只输出 `LOCAL_MATERIALS_REVIEWED`，`readiness_proven=false`、`acceptance_eligible=false`。脚本列出必须现场执行的 Runtime/节点权限/授权挂载/observer/恢复隔离检查。新增 A 的安全工具负责 SecretPolicy、signer/capability/provider、KEK coverage；这里只消费其将来认证的输入，不重复实现。

## B/C 仍需补齐的精确适配项

基线中十一张非空 owner 表仍由 `TestCurrentBusinessSecretsAndConfigRequireExactOwnerRestoreAdapters` 拒绝。不是十一张业务表被删除或永久排除：

| 表 | 还需要的明确输入/装配 |
| --- | --- |
| gateway_keys | 精确 schema/全列动作，key/secret 的隔离 stub 与停用，用户及模型关系映射；不能保留可用源 key |
| gateway_key_budget_reservations / gateway_key_budget_ledger | 与 key 同一目标映射、余额/预留/账本语义和终态规则；不能以猜测的固定值破坏账务历史 |
| gateway_image_artifacts / gateway_image_jobs | 版本对象 target receipt、key 对照、作业终态/外部回调去活；与对象独立读回对齐 |
| llm_model_user_grants | 用户、模型、授权关系完整映射；目标 outbound 模型禁用与授权定义保留分别验证 |
| routing_classifier_settings | 版本配置 SecretPolicy、模型/用户关联和目标执行禁用策略 |
| northbound_admin_settings | 对接 resources 已有私有 `normalizeRestoreNorthbound`：目标 observed version/absence、端口、允许类型、较严格限额与 CAS；不能用静态 TableAdapter 猜测现场值 |
| northbound_caller_policies / northbound_owner_records | caller/owner 身份映射、目标认证策略、去活与权限边界，精确字段适配 |
| northbound_settings_audit | 对接 resources 私有五表组合与 common transaction 的历史映射/独立 readback；原历史值保留，不当作目标控制版本 |

此外，`northbound_operations` 是 C owner provisioning 历史的 B 依赖；现有 Team 单测仅提供命名 fixture 的极小精确 TableAdapter，**不是**生产 schema 适配。需要当前实际列、lease/operation 状态、关联字段的 owner 批准归一化。`owner_team_provision_steps` 仍保存终态历史并停用源 operation 引用，outbox/admission locks 不重放。

资源包 `restore_five.go`、`restore_write.go`、`restore_readback.go` 的组合/证明回调仍是私有候选。生产 B 适配必须将完整 dump、目标声明和最终 fence 绑定到公共恢复事务；不可将测试 `return nil` proof 当作真实 authority。

Skills 侧还需要 B 将经过认证的对象上传/version receipt、安装路径和 workspace 物理恢复结果绑定为 `Target.SkillsRestore`；映射不能仅由浏览器 DTO 或日志填充。当前公共 SQL 路径只接受 ID 保持不变。需要换 ID 时，应先完成全部依赖域的统一重映射协议，不能单独启用 B 的 ID 变换。

C 侧需要将真实 Teams 对象、共享文件和 Redis 历史恢复结果，与最终源 SQL ciphertext / inventory digest、同一目标/任务/attempt 绑定。已有 Team shared-workspace worker 和 Redis history 消费者可复用；本次本地成功不是这些结果已被生产协调器组合成同一证明。

## 下一批可以离线继续的工作

已补齐两个已核对的原 normalizer 合同缺口（仍未据此放行十一表公共恢复）：

- `NormalizeDataRow` 接受图像服务已存在的 `unknown` 终态并保留它；只将 preparing/running 转成 failed。目标 settled/analytics_recorded 按原去重放规则设 1，原 false 标记、charge/estimate、reservation、结果与 SQL NULL 仍保留在独立 `Change.Before`；不能用目标标记宣称原结算成功。五状态正向及未知状态拒绝见 `image-unknown-history-pass.txt`。
- resources 私有 northbound 候选及读写闭合集合补齐 migration 077 的 `owner_teams_enabled/owner_team_creation_user_id`：目标开关关闭，零哨兵保留，正用户 ID 必须显式映射，非法/缺失映射拒绝。旧 33 列不再冒充当前 35 列；未来需要旧版迁移时必须增加具名版本适配。资源包默认离线全包测试通过，见 `resources-owner-team-schema-pass.txt`；需要外部 MySQL 的 opt-in 测试未运行，本项不证明生产事务或目标事实认证。

十一表适配前置修复：普通 SQL catalog 与四批聚合源 catalog 原先只读取 WorkBuddy 的唯一索引。现在对十一表及 `northbound_operations` 显式读取唯一索引名称、列及顺序，纳入原 `SchemaDigest`；缺失/改名/换列/换序都会改变适配指纹。此前 WIP 中不带这些索引的指纹不能继续当作当前完整指纹。该变化不等于覆盖完整 schema：collation、CHECK、trigger 和非唯一索引仍由独立 schema census/目标观测认证。四包离线回归通过（`owner-unique-four-packages-pass.txt`），外部 MySQL opt-in 未运行；尚未为这十一表添加 preserve 放行。

Caller policy migration 066：A 的 source DTO 增加 `APIKeysJSON` 与指针 `APIKeysVersion`；version=nil 明确是旧 057 schema，current 066 读取器必须设置 version 指针（包括零），JSON=nil 此时才表示 SQL NULL。当前版本输出 disabled policy、`api_keys_json=[]`，保留版本作为历史值（不代表完成目标 CAS）；原文档及 NULL 留原输入/加密证据。缺版本、负版本、超限/畸形文档拒绝，公共 business normalizer 的冻结副本也复制新增指针，callback/调用者不能改变已冻结值。`caller-066-businessa-pass.txt` 是 A business 包默认离线全包通过；具名 proof fixture 只验证既有回调与冻结边界，不是生产 authority，实际 066 SQL 映射与公共 domain writer 尚需接线。

以下是本地代码工作，不应全部推给现场：

- 为上述 owner 表整理实际 schema、全列策略与既有 owner 私有 normalizer 的公共事务桥接，增加真实 migrations 非空测试。需要相应 owner 合同和目标语义的明确输入；不能用泛化 preserve 或假 proof 代替。
- 对共同 snapshot / receipt 关联编写公共恢复协调器的前置全覆盖检查：SQL、对象、workspace、Teams 共享文件、Redis 必须属于同次冻结捕获、同一源证书和同一目标任务；增补交叉混用/缺失/旧版本拒绝测试。本次组合测试的对象和 workspace 仍分别捕获，没有证明共同冻结时点。
- 将已有 C Team shared-workspace / Redis history 与 B 对象版本 readback 接入生产 restore/verify worker dispatch、恢复 Job、证据持久化和账户撤销协调；拒绝旧消费者不能理解的 part，而非按未知域为空处理。
- 正式 v12 reader、目录资格、完整 manifest/index 和原认证材料的最终入口，要在原 A/D 发布合同稳定后接线。接口/协议与错误路径可先离线测试；最终原产物联调依赖原主线正式产物，不能伪造材料取得成功。

本批提交提供上述工作的稳定 SQL/映射基础与隔离验证，不宣称这些剩余本地接线已完成。

## 远侧可连接后的剩余验收

### Caller 066 已接入公共事务（本地目标侧组件验证）

`TableAdapter.Normalizer="northbound-caller-policy.066"` 已由公共 `Normalize` 消费，沿现有 `RunDatabase`/profile 的 Dependencies 进入同一 SQL 事务；没有修改 `worker/database.go` 的连接/传输函数。适配要求源和目标各自匹配同一精确 schema 指纹、八个完整列和 user_id 主键，并且列动作全部 preserve，先校验原数据再调用 A 的 owner normalizer。未知名称、不同表、schema 漂移、先 fixed/null 掩盖坏原数据均拒绝。默认空 Normalizer 的 JSON 序列化不增加字段。

从实际捕获 users 的 ID、用户名、邮箱、角色和时间构造闭合的恒等 ID 映射；不编造缺失用户信息、不改公共 SQL 原用户策略。目标 enabled=0、api_keys_json=[]；原 key 文档/SQL NULL 留在源加密归档，version（含最大 int64）、actor NULL、微秒时间和 scopes 原 SQL 字节保留。066 不接受旧 057 缺列冒充当前列。`VerifyDrill` 在独立读库前调用 `VerifyCallerQuarantine`，预期文件自身若含启用状态、keys、非法 actor 或未知 schema 即拒绝；随后仍逐字段读回并检查额外行。

证据分两层：

- `caller_restore_test.go` / `caller_worker_integration_test.go` 使用具名合成 SQL driver，验证非空原 keys、最大版本、原 scopes 空格、源未改、关闭源后恢复、关闭 target writer 后独立读回、目标 key 篡改拒绝，以及写入后 final fence 丢失整事务回滚。这里的 allowWorker 仍只是夹具，不是正式源/目标认证。
- `offline_business_mysql_test.go` 在本窗口专用 MySQL 8.4.13 loopback **61674** 上加载实际 057/066（及原 Skills 008/023/039）migrations；验证真实 JSON/时间/整数类型、两条 caller 历史（非空 key + 最大版本；SQL NULL key/actor + 版本 0）、三个失败回滚场景、锁定 writer 后认证失败、独立 SELECT-only 读回及源快照未改。users/instance/Teams 和空 operations 仍是明确夹具，不代表全量当前生产 schema。夹具只清理本次随机创建的库/用户。

初始 native MySQL 失败日志保留。**最终诊断显示失败停在权限检查，不能把早期失败日志说成已经证明 JSON 比对错误**：新服务器默认 partial_revokes=OFF，旧夹具直接 GRANT 含下划线库名会产生通配权限。现改为复用 `QuotedGrantDatabase` 生成精确授权，不放松 verifier。诊断读回各字段一致。另保留 scopes 原字节以避免 owner 的压缩格式与 MySQL JSON 表示不同，并以含空格 fixture 和实际 MySQL 精确读回固化。

最终完整回归见 `caller-final-four-packages-native-mysql.txt`：domain 25.933s（含 native MySQL 22.02s）、worker 36.702s、profile 3.307s、businessa 2.193s 全 PASS。其他外部服务 opt-in 环境变量已清空。专用进程按可执行文件身份确认后正常 shutdown，临时根路径校验后删除，见 `caller-mysql-cleanup.json`。精确代码 SHA256 / Git blob 见 `caller-common-scope.json`。

这完成了一个 owner 的实际公共消费者接线。剩余十张 owner 表、northbound_operations 的完整当前列、跨域共同 snapshot/receipt、正式源认证后的公开 restore/verify dispatch 仍需继续。没有新增静态生产 schema pin、源认证结果、最终资格或 CAS；正式历史 source 的完整 Invocation/inventory 承载由原发布 owner 补齐后才可接入。

### Operation 077 公共消费者与下一批 dispatcher 接线位置

`northbound-operation.077` 沿 caller 的具名 TableAdapter 入口接入公共 Normalize/RunDatabase；精确源/目标指纹之外，明确要求 045/066/077 的全部 26 列、id 主键、全 preserve 输入列策略。`InterruptedAt` 是冻结计划的 UTC 微秒时间字符串；缺失、非 UTC Z、超微秒精度或早于该历史行创建/更新均拒绝，不能用当前进程时间补齐。实际调用已有 `team.Normalize`，不复制另一套运行态判断；三种 active → failed，三种终态保留，双 lease=NULL，仅 active 且原 finished_at=NULL 时填冻结时间。原始错误、历史 session/key/owner/team/template 引用保留；这些引用不授予重新创建/运行源业务的能力，历史 team/template 无 FK 的旧删除关系不被擅自改成强制存在。

请求 JSON 仍经过原显式 Config/Secret registry；未配置策略或未知字段拒绝。测试 fixture 只批准 message 保留、api_token 替换，原 Secret 只在源加密快照保留。真实 JSON 列经 Secret 策略改写后，公共事务在**首次写入前**用同一隔离目标的参数化 `SELECT CAST(? AS JSON)` 得到 MySQL 实际渲染字节，再用于插入和加密预期证据；独立 verifier 保持逐字节比较，未降级为模糊 JSON 比较。VARCHAR/TEXT 和 SQL NULL 不受这一步影响。

`operation-077-worker.txt` 为命名 SQL driver 的公开 worker 流程（非 production proof），验证源关闭、6 条历史、原输入和 callback 企图改冻结时间无效、final fence 写后回滚、writer 关闭后独立 reader。真实 MySQL 使用另一个独占 loopback **50830**，加载实际 045/066/077；6 状态、旧 finished_at 不改、9007199254740993 bigint、UTC 微秒、原 JSON Secret 归档/目标脱敏与含空格渲染均有断言，同库保留先前 caller/Skills/Teams 非空组合，三种失败仍验证整事务回滚且源不变。`operation-final-four-packages-native-mysql.txt` 全 PASS：domain 37.197s（native 33.45s）、worker 36.574s、profile 3.223s、team 0.302s；`operation-mysql-cleanup.json` 确认专用 server/datadir 已关闭删除。源文件精确指纹见 `operation-common-scope.json`。

追加审查反例（仅测试/证据，生产代码保持 d3a180cc）：JSON canonicalization 适用于**所有**实际 JSON 列，故 `TestJSONCastFailureAndCancellationPrecedeAllBusinessWrites` 用有真实 json 列型的命名 driver 注入 CAST 失败/取消，确认 CAST 恰好执行一次，全部业务 writes/commits/evidence=0，等待回滚完成后源/目标 digest 均未变。`native-json-boundaries` 在真实 MySQL **54774** 调用同一生产函数，区分 SQL NULL、JSON null、空对象/数组，逐项核对 9007199254740993、9223372036854775807、18446744073709551615，TEXT 不规范化，源 clone 不被修改；另执行原生非法 JSON CAST 和已取消上下文拒绝。完整 domain 包包含先前 native 恢复四场景全 PASS 13.012s（native 9.55s），见 `json-boundaries-domain-native-mysql.txt`。新专用 server/datadir 同样关闭删除，见 `json-mysql-cleanup.json`；测试文件指纹见 `json-boundaries-scope.json`。

正式公共调用链的下一批边界（以下是待实现接线，**不是**已有入口）：

1. 当前 `systembackupdispatch.Runner` 只有 Prepare/Capture/Recover，`BindTaskRunner` 只接受 sbk/spf；Recover 是捕获中断的源 writer 恢复，不是灾备恢复。不得把 sdr 伪装为 capture、复用恢复源 writer 的补偿流程，或将本地 profile.Driver 当公开恢复入口。
2. A 的 WIP 位于 execution 层，并已依赖 publicadapter；B 不能从 publicadapter 反向 import execution 造成循环。完整源具体类型可构造/释放后，应由更高层的 restore composition（可在独立 `systembackuprestore` 包，由服务组合根装配）消费该具体类型，并调用 B 目标侧组件。此入口先核对完整成员、原 Invocation/inventory、SQL descriptor、同次捕获证书和内容生命周期；单 `RestoreSourceContainer`、DTO、hash 或结构 helper 不接目标写端。
3. 目标计划使用独立版本，冻结目标 SQL/namespace UID、对象 bucket/root/version 归属、workspace/Team claim+PV、Redis server/database 分配、逐表 owner/Secret 策略和 interruption time。D 需将它绑定真实 sdr task/attempt/阶段/current claim/fence，并提供独立目标观测与账户证明。现有 `CheckRestoreTarget` 只覆盖 SQL/storage 描述，不能当作对象或 Redis 身份证明。A 原 source attempt/AAD 与新 restore attempt 分开保留。
4. Restore 的实际 dispatch 次序：完整源和所有目标身份/必需成员预检 → 建立持久目标写意图 → 受控对象/version 和 workspace/Team 文件恢复及读回 → 按独立 DB 分配恢复 Redis 历史 → 将真实物理结果映射交给同一公共 SQL 事务 → 保存受保护预期证据。多个 Redis member 不逐个写同一空 DB。每步必须在外部调用前后复核当前 authority，未知执行结果留 journal，不能当失败重放或删除不确定目标。
5. Verify 独立入口只在恢复 Job 结束、写凭据撤销/认证失败证据齐备后运行，使用独立只读 SQL/确切对象版本/文件挂载/Redis读者，核对同一任务/源/目标/成员集合。失败只记录本任务隔离目标与已知结果；不激活 agent/队列，不自行签名或生成 D 最终 CAS。

其余十张 owner 表的接线顺序：先 A 的当前 llm_models/062 扩展、`llm_model_user_grants` 与 `routing_classifier_settings` 的闭合模型/用户与 Secret 策略；再 `gateway_keys`、budget reservations/ledger 的同组映射与原账务状态；然后绑定真实对象版本的 image artifacts/jobs；最后 resources 的 northbound_admin_settings（35 列）、owner_records、settings_audit，保持目标观测 version/absence 与 CAS 的区别。不会用十张表统一 preserve 或静态固定值代替 owner 合同。

### Routing 061 公共 SQL 适配已完成

新增 `routing-classifier.061`：明确匹配 060/061 六列、全 NOT NULL、id 主键及源/目标精确 SchemaDigest，源列只能 preserve 后再执行 owner 规则。singleton 必须 id=1、timeout 遵循现有服务 100–30000 范围，源 mode 只接受空默认/rules/hybrid/laya；未知模式、缺字段、nullable/schema 漂移、固定值掩盖原 credential 均拒绝。

旧 `NormalizeDataRow` 和新公共 Normalize 都调用新提取的 `gatewaypolicy.DisableRoutingClassifier`，避免两套去活逻辑：目标 mode=rules，base_url/encrypted_api_key 清空，id/timeout/updated_at 精确保留。新路径不解密旧 ciphertext、不调用原 endpoint，也不把旧 credential 作为目标凭据。公共 VerifyDrill 先检查预期隔离语义，再独立读回。旧路径仍尊重原列 nullability：YES→SQL NULL、NO→非 NULL empty；Reason=restore_disabled、Quarantined、Before 与 After/source 的独立字节副本全部已有专门回归。

`routing-final-four-packages-native-mysql.txt`：domain 13.671s（native 10.04s）、worker 35.977s、profile 3.206s、gatewaypolicy 0.349s，全 PASS；具名 driver 的 worker 测试关闭源后恢复、关闭 writer 后独立读回，authority callback 仍明确仅 fixture。真实 MySQL 8.4.13 专用端口 **53611** 加载实际 060/061，非空 endpoint/ciphertext/mode 与 caller/operations/Skills/Teams 共用原事务，验证目标 non-NULL empty、规则模式、原 timeout/更新时间、三种失败全回滚、撤权后认证失败和源快照未变。`routing-legacy-owner-pass.txt` 是根 systembackup 包相关 owner 回归 3.181s（非该包全部测试）；未修改其他旧 switch 分支。专用 server/datadir 已关闭删除，见 `routing-mysql-cleanup.json`，精确源指纹见 `routing-common-scope.json`。

剩余 owner 表现为九张。模型授权的下一个具体缺口是：当前 llm_models 相比已接旧列还包含组/优先级/并发/上下文、能力与 override、reasoning mode、visibility/access version、图像能力/价格等 migration 049–071 扩展；A 的完整 batch 还要求非空 credential 的不可变 Secret 版本与真实 source proof。不能为了让 grants 成功而给模型临时 generic preserve 或编造版本。先补 owner 当前投影/版本合同和闭合模型/用户映射，再接 `llm_model_user_grants`；正式 dispatcher 的完整源句柄依赖和后续顺序仍如上一节。

### Model 071 与 grants 062 公共 SQL 适配

新增 `llm-model.071` 与 `llm-model-user-grant.062`，匹配实际 35 列模型、3 列授权、主键及源/目标相同 SchemaDigest；模型 display_name 唯一索引现在同时进入普通与聚合 catalog 指纹。要求逐列 preserve 后执行具名转换，不允许先 stub/null 覆盖原值。非空 grants 必须同时有这两个适配，模型与用户引用闭合；不推导新授权、不调用 SaveModel/repository.Save，不推进 access_policy_version 或时间。

模型原行先投影到 A 的纯行 normalizer，再隔离：is_active=0、两类 credential 均 SQL NULL、base_url=https://disabled.invalid。api_key 与 api_key_secret_ref 按原始 SQL 字节分别区分 NULL/空/非空，不 trim；每个非空状态分别要求 immutable version 字符串，缺失、多余、latest/current/default 或给空状态附加版本均拒绝。`TableAdapter.LLMSecrets` 随公开 worker 请求冻结，callback 修改原映射及其参数副本无效。**版本 map 只是转换输入，未证明 SQL credential 与 Secret 绑定**；本地 staging 测试和 allowWorker 不是 A 完整历史源认证。正式入口必须核对 inline 的原行/列/材料、ref 的原 namespace/name/key/UID/version/content 和同一完整归档，材料不足必须拒绝，不能查询 live Secret 或采用目标默认 namespace。本次没有调用 A proof-gated batch 并伪造通过回调，也没有开放正式 restore dispatch。

17 个当前扩展显式解码：decimal 仍保留 SQL 字符串，image_price 的 NULL/零/高精度不同；采用历史非负 DECIMAL(18,8) 存储范围，不套用当前保存接口的 1,000,000 价格上限。group 可重复，priority/concurrency/context 的零值不重算；能力来源与 tools/vision override 的 NULL/false/true 原值保留，不按自动能力重推；reasoning 空值与 none 区分，显式启用的推理/图像操作要求原协议符合已有 OpenAI 兼容合同，图像操作还要求 kind=image。不按 078 回填协议；缺少原显式协议且无法满足操作合同则拒绝。模型图像定义保留不代表可调用，目标整体 inactive、endpoint 和 credentials 已隔离。group/capability 按合法 UTF-8 字符数验证 VARCHAR(100)/(64)，不是字节数。来源缺失必要时间、未知扩展或旧 schema 仍失败关闭，未新增旧版升级适配。

`VerifyModelGrantQuarantine` 同时用于 Normalize 和 VerifyDrill，先拒绝预期文件中的可用 provider、坏扩展与孤立授权，再沿原独立逐字段读回。provider_models_json 继续走显式 Config registry，批准结构保留，JSON 对象键顺序可规范化；其他定义、版本、价格与 NULL 精确保留，源快照不改。

验证：`model071-regression.txt` 五包全 PASS（domain 3.572s、worker 35.676s、profile 3.130s、gatewaypolicy 0.327s、businessa 2.136s）；随后 UTF-8 修复的完整 domain/native 最终回归见 `model071-domain-native-final.txt`，18.238s（native 14.73s）。公开 worker 用非空模型/授权、关闭源/写库后独立 reader，并检查冻结映射。实际 MySQL 8.4.13 独占端口 **63467** 执行模型 045、049、053、054、两个 056、057、058、059、062、069、070、071 的完整迁移，和原 Skills/caller/operations/routing/Teams 组合走同一事务。100 个汉字的 group、64 个四字节字符的 capability、最大 decimal/access version、NULL/false、两条 grants 均精确读回；成功、证据失败、取消、final fence 撤销四模式，以及 writer 撤权认证失败和源不变均通过。初次建库因现有 synthetic model_invocations 同名冲突失败，随后明确将该旧夹具暂存，完整 056 在另一个空 prerequisite 表执行后移除并还原旧夹具；不据此宣称覆盖当前 invocation schema。仅清理本次随机库/账号，独占 server/datadir 正常关闭删除，见 `model071-mysql-cleanup.json`。

剩余八张 owner 表：gateway_keys、gateway_key_budget_reservations、gateway_key_budget_ledger、gateway_image_artifacts、gateway_image_jobs、northbound_admin_settings、northbound_owner_records、northbound_settings_audit。模型 SQL 接线和 grants 已完成本地目标侧验证，完整源认证/共同 snapshot 与真实物理 receipt/公开 restore-verify dispatch/最终资格仍未完成。

### Public Restore/Verify dispatch 依赖核对与共享范围（a50c07be 后）

本节来自当前提交代码的只读核对，不把旧 functional profile 当正式 v12 恢复链。完整源句柄缺失是一项阻塞，但不是唯一阻塞：

| 实际消费层 | 已有行为 | 真正接线前缺口 |
| --- | --- | --- |
| `systembackupdispatch/contract.go`、`task_binding.go` | Runner 只有 Prepare/Capture/Recover；任务绑定只接受 sbk/capture 与 spf/preflight | 独立 Restore/Verify 操作和 sdr 计划绑定；不能把 Recover 改义或扩大旧 capture 计划正则后直接放行 |
| `systembackupcontroller/task_execution_loop.go` | Step 只有 prepare/capture/recover，Record 交给 WorkStore | 实际 restore/verify 分支必须先装配就绪检查，再选择任务；结果须有独立类型，不套用捕获 Parts/RecoveryResult |
| `execution_queue.go`、`sql_execution_work_store.go` | TakeBackup 从 backups 读取，冻结 admitted config/profile，原计划及副作用决定接管 | drill 原任务/source/target 配置投影、claim/attempt、目标配置冻结及接管分支；不能新建 control.Task 影子账本 |
| `execution_ports.go`、`execution_heartbeat.go` | SQLExecutionAuthority 仅接受 backup/capture、preflight/preflight；读当前 DB 时钟、claim/lease/权限 | drill 三阶段独立权限、原 target 配置摘要、目标资源写意图与续租；源 maintenance gate 不是灾备目标写权限 |
| `sql_execution_records.go` | write 明确 task_type=backup；加密原 plan/capture_result、按任务/attempt/phase 绑定 | drill plan/result 的加密持久化、容量、幂等原字节、unknown commit 读回；不能把 source attempt/AAD 改成 restore attempt |
| `systembackupexecution/plan_store.go` | lock 只接 TargetBackup，读 backups/execution_inputs | 不直接将这个旧 PlanStore 当 drill store；当前正式记录链应由 D 选择统一扩展方案，避免再建一套竞争计划存储 |
| `public_jobs.go`、`job_plan.go`、`public_runtime.go` | 实际 profile/config JOIN backups，relay 身份与取 authority 默认 backup/capture | 恢复 Job 及独立 verifier Job 的 target-only grants、invocation 绑定、发送意图、退出、撤权/认证失败，之后才装配服务运行循环 |
| `result_evidence.go` | registerResult 只接 backup，inline 成功报告含固定五个统计字段；证据 owner=backup | drill 结果与失败观察的受保护证据合同；正文不得含源 credential、SQL row、原始 provider error；不能将临时 staging receipt 冒充正式 evidence |
| `execution_capture_outcome.go`、`execution_cancel.go` | FinishCapture 用 collectors_stopped/source_resumed 事实结束 backup；取消操作也限定 backup | drill 必须用目标写入已知/未知状态、全部 Job 退出和写权限撤销事实决定 failed/canceled；不能复用 source-resume 成功条件，不直接写 D 最终资格/CAS |
| `systembackupapi/tasks.go`、`task_requests.go`、`sql_writer.go` | 当前 Create route/decoder/writer 仅 backup/preflight | 若要从公开 HTTP 创建新 sdr，还需 D 交付 drill 请求/幂等/admission 合同；不能在 B 自造浏览器 DTO 来补这个入口 |

数据库结构也需 D/A 协调，不能只改 Go switch：122 execution_records 的 phase 仅 capture、record_kind 仅 plan/capture_result；123 runtime_resources 的 target_type/phase 仅 backup/capture，而且 task 外键指向 backups；121 job_send_intents 的 target_type 仅 backup、phase 只 capture/secret_capture/publish，并依赖旧 execution_plans；104 staging_resources phase 同样不含恢复。098 attempts、107 job_observations 已列 restore/normalize/verify，但这不代表上述持久链都支持。若需要扩展，应新增 owner 审核迁移，不能重写已应用的历史 migration，也不能改 publication 外键来规避原 plan 认证。

建议协调的最小第一段是：dispatch `contract.go/task_binding.go`，controller `task_execution_loop.go/execution_queue.go/execution_ports.go/sql_execution_work_store.go/sql_execution_records.go/execution_heartbeat.go`，以及 execution `public_runtime.go` 的装配点。只接目标计划冻结、权限与“全源材料不可用”的真实拒绝/持久观察，尚无完整源 concrete handle 时不发任何目标 Job 或写凭据。第二段才接 `public_jobs.go/job_plan.go/result_evidence.go` 和独立 drill outcome/cancel 文件；producer/MF/bootstrap、publication_*、artifact_read_* 与最终资格仍归原 A/D。本分支尚未修改这些共享文件，需原监督协调范围后才能改；这是共享编辑约束，不是这些本地实现必须等现场。

剩余八表与调度的关系如下：

- `gateway_keys` / `gateway_key_budget_reservations` / `gateway_key_budget_ledger` 必须统一核对 key 引用、原 decimal、settlement 状态及账务去重。特别是 `repository/gateway_key_repository.go` 的 `GetBudgetUsage` 会调用 `loadGatewayKeyBudgetForUpdate`，进而 reconcile pending、插 ledger、删 reservation、更新 spent；**仅把 key 标成 revoked 并不能证明账务读取无副作用**。正式目标隔离及禁止启动消费者、image_pending 与图像 Job 关系必须纳入合同，不能编造 settled/ledger 或抹掉 pending 历史。可独立实现原状态/关联校验，非空正式 SQL 全量恢复仍被该合同阻塞。
- `gateway_image_artifacts` / `gateway_image_jobs` 除 SQL 原终态/unknown/金额/去重标记外，必须有同源 inventory 的确切对象版本、目标 version 与 readback receipt。对象映射 DTO 或目标 SQL object_key 不能作为上传完成证明；这两表阻塞对象→SQL 的最终映射放行，不阻塞失败拒绝链。
- `northbound_admin_settings` 的当前 35 列私有候选包含目标 port、严格 limits、类型列表与 observed target version/absence 输入。公共写事务需独立证明这些目标事实；source version 是历史，不是目标 CAS。`northbound_settings_audit` 还需原 JSON/actor/时间的脱敏及保护历史关联，不能传一个空 audit_logs 假称完成所有 resources proof。`northbound_owner_records` 的 067 schema 有 unsigned bigint、nullable metrics、DECIMAL(24,6) 及无 FK 的删除后历史；应保留未知量 NULL，不用浮点或强制现存实例伪造闭合。

上述八表不阻塞编写目标计划/权限/失败记录接线，但任何一个必需非空表未适配，都必须在首次对象、workspace、Redis 或 SQL 写入之前的全域预检拒绝。不能先写其他域，再把 SQL ErrNormalization 当已安全回滚了全部目标。

本批独立修复只触及 B 的 `publicadapter/restore_target.go`：原检查按 source hash 与 ClaimUID 去重，却允许同 namespace 的相同 ClaimName 配不同 UID，或不同 claims 指向同一 PVUID。现均在调用 proof owner 前拒绝；唯一描述仍必须调用原独立当前 proof，不能由结构合法代替授权。新增真实公共 B runner 与 D→B wrapper 的 18 个 sdr restore/normalize/verify × Prepare/Capture/Recover 反例，确认源发现、writer bind/pause/resume、Job ensure、结果读取均未增加，且不返回恢复事实。这证明旧 capture 接口保持拒绝，不宣称有新的正式恢复入口。另验证三阶段 target proof 的完整 authority、callback 副本隔离、typed nil、取消及四类存储冲突。`restore-dispatch-boundary-packages.txt`：publicadapter 3.662s、dispatch 0.308s 全 PASS；无新数据库/服务，无远侧连接。

不同 PVUID 仍可能对应相同 NFS server/export 或 CSI volume handle；本次只防描述层别名，不证明物理隔离。这些存储后端事实必须由当前独立 observer/proof 闭合。controller 的 drill/sdr task claim 与 provider 的 restore_resource/srr ownership 是不同身份，也不能互换。共享路径已交由主监督协调，目前尚无边界确认，继续保持未修改。

### A 只读目标授权审查落实清单（仅合同与路径，尚未启用）

主监督转交了基于 1626bb25 的 A 只读审查。本分支再次只读核对相关已有实现，新增共享协调路径 **`backend/internal/systembackupcontroller/execution_identity.go`**：`PinnedExecutionIdentity.decode` 只接受 prepare/capture/preflight/recover/issue_worker；`checkSQLAction` 只读取 backups/preflights；`allowSQLAction` 默认 capture。仅扩展 `execution_ports.go` 不足以授权 drill。后续应建立明确 restore/normalize/verify actions 与事务内复查，不能靠替换 TaskType、默认 capture action 或一个 claim 成功结果放行。该文件尚未修改。

冻结计划与授权中必须分别保存下列身份，不允许字符串别名转换：controller/attempt 为 drill + sdr；phase 为 restore/normalize/verify，对应任务状态 restoring/normalizing/verifying；provider proof target 为 restore_resource + srr；108 资源行通过 installation + drill_public_id 关联原 sdr。`restore_drill` 不是该任务 kind。108 restore_drill_resources 的 creating/created/ownership_unknown 等生命周期与123 runtime_resources 的 creating/ready 等不同，不能直接换表名复用 MappedResourceRows。既有 `kube.NewAttemptMappedResourceRows` 的 task/type/attempt/phase 冲突拒绝必须保留，旧 attempt 同物理键不能当资源不存在。

provider 认证应复用 `systembackupsecurity/providerproof_registration.go` 的 `PrepareProviderProofEvidence`，并通过 `providerproof_transaction.go` 的 `ProviderRegistrationService.Register` 或 `providerproof_sql.go` 的 `StageProviderProofEvidence` 原事务边界登记。可信 issuer、DB 时钟、已锁定资源及 row_version、location/owner token、UID/immutable version 均需逐项核对。restore_resource 仅接受 ownership，不能接受 present_sealed。签名通过或证据登记完成既不自动更新资源生命周期，也不产生 restore 写权限；此链不改成本分支自行签名或布尔 proof。

实际 `RestoreTargetProof.VerifyRestoreTarget` 的生产实现仍缺失。CheckRestoreTarget 中的 UID、server UUID、evidence SHA、策略字符串只构成待核对描述。后续实现必须独立观察当前目标、网络隔离、空白库（写前）、写者退出、存储身份与 grants，并在前向操作边界持续复核；verify 阶段应读取已恢复目标，不能继续要求空白库，也不能从冻结 plan 推导当前事实。

独立 verifier 必须核对 SELECT-only/无角色、同 server/database、与 restore writer 不同账户，并等待实际撤权。旧 `control/credentials.go` 的 `DatabaseCredentials.Revoke` 展示了必要动作：锁账户、清除现存连接、删除账户并确认零连接；该实现依赖 legacy vault/fence，不能原样装配 v2。Job Complete、资源 revoked 标志、取消请求或旧 profile 检查成功均不足以证明这一事实。正式失败/取消终态必须保留不确定写入与残留资源，直到有同任务/attempt 的退出与撤权观察，不能以 capture 的 source-resumed 条件结案。

### 独立 Restore/Verify 调用已接入实际任务循环（SQL custody 仍在下一批）

共享范围确认后新增 `systembackupdispatch/restore.go/restore_plan.go`、`publicadapter/restore_runner.go`、`systembackupexecution/public_restore.go`，并在现有 `TaskExecutionLoop` 增加专属 restore/verify 分支。`NewPublicRestore` 固定装配真实 B 拒绝执行器，不接 caller 的 source-proof callback，不接 capture Runner/恢复源 writer 的 Ports。目前完整源句柄尚缺，B 恒返回明确的 `ErrRestoreSourceUnavailable`，没有目标 IO 能力；这不是一次恢复成功，也不证明 SQL custody 或生产启动已接通。

新 `DrillExecutionWorkStore` 的 ReadyDrill/NextDrill/RecordDrill/RecordDrillInterruption 分离选择边界，旧 capture SQL store 不满足此类型；手工混装 loop 也在首次队列选择前拒绝。循环冻结原 Input、DrillSpec 和 plan，权限回调与 Runner 修改副本不能改变 Record 的原观察。结果伴随错误仍交 D 记录。取消或普通 Record 失权/commit unknown 时，原 outcome 和中断原因转交专属 interruption 方法，必须由 D 获得新的有界记录上下文、在 SQL 内重新授权；既不据此续租原 claim，也不推断目标退出/撤权/清理。记录成功的 drill 任务失败返回调度成功，避免整组 leader 因普通 source-unavailable 重启；旧 backup 的返回与取消语义保留。

`system-backup-restore-task-plan.v1` 只绑定元数据和保留原 inner-plan 字节，不代替实际目标计划闭合解析。绑定 original sdr、request/config/profile、attempt/phase/deadline、source identity/checksums、目标配置摘要、purpose/cleanup。renewable claim 不写入不可变 binding，执行时仍由 D 查询当前权限。inner version 由独立调用方参数核对；实际公共 composition 固定 `publicadapter.RestorePlanVersion`，不接受 envelope 自报未知版本。verify 必须另建 phase-bound plan，并绑定先前 restore plan/result 及撤权 evidence 摘要；这些只是待核对引用，不是证明。normalize 目前仅元数据可识别，尚无可执行 step。

反例覆盖真实 NewPublicRestore → TaskExecutionLoop → RestoreDispatcher → B 拒绝执行器 → 命名 D 记录夹具；不使用 fixture 让 B 目标写成功。另覆盖未知 inner version、跨任务/phase/config/源/目标/策略变更、callback 后取消和超时、原 plan 字节副本、结果+错误、Record unknown 原观察保留、普通任务失败继续调度、旧 capture store 无法选任务。最初一次完整四包日志 `restore-loop-four-packages.txt` 保留 RED（当时 verify 缺前序引用的反例断言仍期待走到 Record）；修正断言后最终证据另存 `restore-loop-four-packages-final.txt`。SQL drill store、新迁移、精确 grants、控制表排除新 pin 与实际174→新版/失败重入测试尚属下一批；没有将未完成的 SQL WIP 混入本提交。

### 正式源认证模块应交给恢复侧的最小合同（待 A/D 确认，未制造授权类型）

恢复侧需要 A 的**不可序列化、字段私有、只能由完整认证入口构造的具体结果类型**；接口名字可由 A 定义。不能把以下 DTO 列表当作已认证 receipt，也不能用 caller 的布尔值、raw JSON、hash 字符串或恒真回调创建该结果。

1. 原源身份沿用 `systembackuppartcontainer.Scope`：installation、backup、原 capture attempt、config version/hash、capture-context hash；附已读取并认证的 catalog/MF/index/capture certificate/commit/acceptance 对象身份与摘要。恢复 attempt 保存在另一绑定，不覆盖原 AAD。
2. 精确成员集合沿用 container Header/Member：part、member index/path、原 StreamSpec、固定 key/version/size/hash、envelope、checkpoint 摘要。应提供认证后 checkpoint 中的 `worker.Invocation`、invocation hash、Job UID/generation、source inventory hash，且已与源证书及完整集合交叉核对；单个 `pc.Facts` 或 `StreamVerification` 不足够。
3. SQL 消费需要原 `domain.BusinessCaptureSchema`、原 schema census pin、原 SQL 密文摘要，以及认证后完整 raw-cell snapshot（或受控只读输入）。Teams 构造 `NewTeamWorkspaceSpec` 必须使用这份最终 snapshot、原 `team.Inventory` 和同一 SQL 密文摘要。Skills 使用原对象 inventory/fixed versions 与 SQL blob/version/binding 关系；workspace 使用原 runtime policy/原实例或 Team 归属；Redis 使用原 `RedisCapturePolicy`/成员归属，不能从目标或 live 源查询补造。
4. 输入读取需要可验证的 custody 和生命周期：完整 fullC、原 C 终帧/EOF、使用后授权均完成后，才向 B 释放可消费的只读内容或由 A 管理的已认证句柄；暴露只读身份、原始格式、容量及当前授权复核方法。大文件不能强制塞进无界内存，也不能在 `InspectWrappedStream` 回调内写业务 SQL/对象/文件。若需要落地，A/D 须定义私有暂存、完整认证后发布句柄的具体方式；B 不会自行把 fullC 当作旧 `staging.Receipt`。
5. 当前恢复权限由 D 独立提供：`systembackupdispatch.Authority` 的 sdr task/attempt/phase/claim/fence/deadline、冻结计划与策略映射；以及 `CheckRestoreTarget` 的独立目标 proof。目标 SQL server/database/schema、namespace UID、workspace claim/PV、object bucket/root/version、Redis server/database 和独立只读凭据必须绑定到这个执行。源认证结果本身不发写权限。

恢复侧将先核对整个必需成员集合，再写入；恢复结果保持隔离，写账户结束/撤销及独立读回完成后仍交由原 D 资格链判断，不生成最终 CAS。多个 Redis 成员须先得到独立目标数据库分配，或形成一次完整去重的预期集合后只调用一次 Restore/Verify；现有逐成员 DBSIZE 校验不能拼到同一个 DB。

### 已追踪的历史 capture policy 兼容边界

基线 `0e797e4e` 的 capture policy pin 为 `62ec7bc2c2a6f443e6c26adc8dfbc6b43c3123622c45a09cdb92589a0c95055d`，Skills history 改动后为 `dfc25ae4d1a6744d853b447a36f401b018281c0b53dacc0ac12668dbc39d8bc8`。已用只读 `git show` 的基线 dependencies + Go overlay 独立复算；变化来自 rules 中 materialize 的 RestoreAction，原捕获表集合相同。

当前 `VerifyBusinessCapturedSnapshot` 会与当前 policy 比较，调用方包括 worker/formal_capture、execution/formal_observer、owned_payload_reader；production metadata/source exclusion 和 publication SQL counts 也显式比较当前 policy。它们属于当前捕获/发布链，未在本分支改成接受历史 pin。旧 functional `RunDatabase` 消费其自己的 staging 格式，并非正式历史 fullC 接口。

新增 `MatchHistoricalBusinessCaptureSchema` **只做原描述与原 metadata 字节结构对照**：明确识别上述两个历史 pin、固定表集合，比较原 schema hash，不生成/补齐缺失 UniqueKeys；它不认证原描述、不发 receipt、不接通写入。只有 A/D 完整认证结果给出原描述后才可消费此结果，不能直接以 raw JSON 调用成功作为恢复授权。新当前 metadata 丢唯一索引、旧 metadata 后填看似合理的索引都会与原 schema 摘要不符；旧归档到新目标的精确 owner 适配仍需具名版本策略。

1. 复核现场 Runtime 镜像 digest、节点 UID/GID/DAC、volume/PVC/PV/NFS 身份、只读源 mount、授权投影和 observer 的独立 TLS/SELECT-only 账号；重采当前事实，不能把本地保存材料当 live observation。
2. 完成正式发布 v12 manifest/index/container → 认证解封 → 所有恢复消费者的公共 Runner 装配。当前 `profile.discoverTarget` 仍走其原 bundle/part 逻辑，`SixDomainOwner` 是 backup 侧合同；没有因为本次 SQL 映射修复而自动获得正式六部分恢复能力。
3. 同一正式源/任务下，用非空实例、Teams、Skills 八表、历史对象版本、用户改写安装文件、共享产物和 Redis stream/PEL 运行完整恢复。不可用空域、伪造 manifest/签名、身份 adapter 或手拼资格绕过。
4. 目标必须 schema-only/可证明的空白业务库。真实 migrations 会插入 Skill Hub 默认 tags；本机 fixture 仅清空自身新建库的 seed，生产恢复仍会拒绝这种非空目标，不能运行应用 initializer 或在现库上自动清表/升级。
5. 恢复 Job 正常退出后先撤销 SQL/Redis/对象写凭据并证明认证/写失败，再用独立只读 SQL、确切对象版本和只读文件挂载验证关系/内容/多余行。原 stopped 实例保持 stopped，禁止自动启动 agent、队列或 outbound。
6. 测试任务取消、节点/挂载变化、写失败、证据失败、未知提交、凭据撤销失败，按现有 journal 接管；保留所属不确定目标，不重放、不清理他人资源，并确认源 writer 恢复行为。
7. 上述 owner 适配、共同证据和独立 verifier 都完成后，由现有 D 发布/验收链路完成最终资格判断。本分支不写最终 CAS。

### Gateway key 与预算三表候选（独立第三批，待原 A 只读交叉审查）

本批仅为 `gateway_keys`、`gateway_key_budget_reservations`、`gateway_key_budget_ledger` 增加具名 `gateway-key-budget.055` 适配，基于既有 common SQL transaction writer 和独立 SELECT-only verifier；不是八表完成，也不是正式源认证或生产恢复资格通过。原 `7a415209` 与独立业务启动保护 `30ac4f1c` 均不改写。正式 B 仍因缺少完整认证源句柄而拒绝，不以本批测试 callback 或 staging receipt 代替 fullC/manifest/目标物理隔离证明。安全字段最终规则仍须原 A 审查，此处列出可复核的具体候选行为。

三表必须一起选择、使用同一个冻结时点、源/目标各自精确 schema SHA 与完整具名列策略。形状核对 28/7/4 列、类型/NULL、PK/FK 和三项有序唯一约束；不以宽泛 preserve 放行。所有关系与值在第一次 SQL 写入前检查，缺表、缺策略、未来字段/类型、重复 HMAC、金额精度/ID 溢出、非法状态或跨 key 账目冲突都拒绝。保留被选中空表 metadata，防止恢复/读回闭包丢失。19 项负例同时经过纯 Normalize 和实际内存 SQL writer，并断言无 DML/commit；缺 ledger adapter 也经真实 MySQL common preflight，目标无写入。

`key_id`、prefix、pepper HMAC 原字节保留，不替换成统一空值或伪 token。active/disabled 仅转为 revoked：改 status、revoked_at、updated_at、revoked_by_user_id=NULL、固定 revocation_reason；原已 revoked 行的全部历史撤销字段保留。owner/instance 的真实 FK 必须闭合；owner 历史 NULL 保留，created/revoked actor 无 FK，允许其用户已删除，不强行归 bootstrap。过期 key、旧 reset/period/review 标记、limit=0、DECIMAL(18,8) 原字节与 SQL NULL 全保留，不用 float，不按 ledger 总额重算 spent，不重置预算窗口。allowed_model_groups 当前仅接 SQL NULL 或有界字符串数组，JSON literal null 拒绝，属于待原 A 确认的封闭输入规则。

reserved 与 pending 各自保留 actual_cost 的 NULL/非 NULL；过期 reservation 不清除，ledger-only 历史合法且不补造 reservation；同 reservation 的 pending+ledger 只在 key 和精确金额一致时保留。`image_pending` 虽为已知状态，缺少同源 image job/object owner 证据时明确在写入前拒绝，不能通过改状态、删行或结算来绕过。migration 052 在 model_invocations/audit_events/cost_records 的 nullable gateway_key_id 归因原值保留，允许 key 已删除，不增加原本不存在的 FK；非 NULL 仍核对 BIGINT 范围。

实际 MySQL 8.4.13 native fixture 使用未经修改的 038/050/051/052/055 gateway migration SQL、私有 CA 与 DNS 校验 TLS，服务器明文连接实际返回 3159。核心 users/instances 等为明确的小型私有夹具，trace 表为空占位，**不代表完整生产 core/fullC**。public worker 实际 capture -> 加密 staging -> 关闭源 reader 并锁账号 -> restore；四场景 success、写后 evidence 失败、commit 前取消、真实 writer 账号撤销，均抵达对应边界。后三者完整回滚：原 bootstrap=1，keys/reservations/ledger=0；每个 writer 的物理 session 归零，fresh login 实际 3118。成功路径另用独立 TLS SELECT-only 账号解封预期证据、读回 raw cell 和多余行。

真实 repository/service 正负认证控制：源端 old key、instance token、alias 均能认证；恢复后 HMAC lookup 仍匹配原 key，但真实 GatewayKeyService.Resolve 拒绝 revoked key，InstanceRepository 拒绝原 instance token 与 alias，目标 alias 行为空。独立 reader 对合法零行 UPDATE keys、DELETE reservations、INSERT ledger 均实际收到 MySQL 1142；真实 GetBudgetUsage 在 reader 下也失败，前后独立 snapshot digest 不变。

**保留的真实反例：** revoked 本身不能阻止 write-capable `GetBudgetUsage` 执行结算。只在成功独立读回之后，由私有 fixture operator 调用真实 getter，reservation 实际 3->0、ledger 2->3；随后同一个公共 verifier 必须拒绝。该反例用于证明恢复库必须保持消费者隔离，不能以 GetBudgetUsage/Release/UpdatePolicy/ImageSettlement 作读回；没有修改原 repository 来隐藏结果。三表在隔离库中保存数据，不能因此启动业务或声称所有预算流程已安全恢复。

冻结测试：`gateway-budget-twelve-packages-frozen.txt` 的 12 个适当包全部 PASS（含原九包、worker/profile/businessa）；`gateway-budget-unit-frozen.txt` 为具名 19 个负例及精度/NULL/删除历史/取消/空表/归因正例；`gateway-budget-native-frozen.txt` 原生四场景全部 PASS，domain 11.555s，其中实际测试 7.91s。后者逐项列出上述认证、1142、3118、bootstrap rollback 和 getter 反例；完整原始文件 SHA256 与 Git blob 见独立 `gateway-budget-scope.json`，不是运行期授权。

早期失败同样保留：memory observer 误复用 max-open=1 池导致等待（仅核对本任务父进程/命令后终止自有测试子进程）；空 bytes 与 nil clone 的 reflect 比较误判（改为 bytes.Equal 且分别核对 SQL NULL）；测试接口未暴露已有 alias writer（改为实际 concrete method 的接口断言）；过早关闭 evidence root 只触发 startup 拒绝、未进入写后窗口（移到真实 before-evidence，并强制断言 evidence/commit 到达）。后续日志分别证明修复，没有把提前失败当 rollback 成功。

自有 MySQL 56251 / UUID `81275efe-d604-11f1-b2ac-745d22085e06` 已正常关闭清理。退出前核对 local nonce、CA SHA、实际 PID 14420/exe/command line、SQL UUID，且仅四个系统库、root 与三个 locked 内置账号、cleanup CLI 一条 session；所有 fixture DB/user/owner marker 已由 native cleanup 删除。mysqladmin 在 VERIFY_IDENTITY TLS 下正常 shutdown，进程自然退出后再次核对精确 Temp 根及 marker，再删除私有 bin/share/data/cert 根。`gateway-budget-mysql-cleanup.json` 与保留的 server shutdown log 给出清单；没有访问共享 63507/65298/59355 或监督者实例。
