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

以下是本地代码工作，不应全部推给现场：

- 为上述 owner 表整理实际 schema、全列策略与既有 owner 私有 normalizer 的公共事务桥接，增加真实 migrations 非空测试。需要相应 owner 合同和目标语义的明确输入；不能用泛化 preserve 或假 proof 代替。
- 对共同 snapshot / receipt 关联编写公共恢复协调器的前置全覆盖检查：SQL、对象、workspace、Teams 共享文件、Redis 必须属于同次冻结捕获、同一源证书和同一目标任务；增补交叉混用/缺失/旧版本拒绝测试。本次组合测试的对象和 workspace 仍分别捕获，没有证明共同冻结时点。
- 将已有 C Team shared-workspace / Redis history 与 B 对象版本 readback 接入生产 restore/verify worker dispatch、恢复 Job、证据持久化和账户撤销协调；拒绝旧消费者不能理解的 part，而非按未知域为空处理。
- 正式 v12 reader、目录资格、完整 manifest/index 和原认证材料的最终入口，要在原 A/D 发布合同稳定后接线。接口/协议与错误路径可先离线测试；最终原产物联调依赖原主线正式产物，不能伪造材料取得成功。

本批提交提供上述工作的稳定 SQL/映射基础与隔离验证，不宣称这些剩余本地接线已完成。

## 远侧可连接后的剩余验收

1. 复核现场 Runtime 镜像 digest、节点 UID/GID/DAC、volume/PVC/PV/NFS 身份、只读源 mount、授权投影和 observer 的独立 TLS/SELECT-only 账号；重采当前事实，不能把本地保存材料当 live observation。
2. 完成正式发布 v12 manifest/index/container → 认证解封 → 所有恢复消费者的公共 Runner 装配。当前 `profile.discoverTarget` 仍走其原 bundle/part 逻辑，`SixDomainOwner` 是 backup 侧合同；没有因为本次 SQL 映射修复而自动获得正式六部分恢复能力。
3. 同一正式源/任务下，用非空实例、Teams、Skills 八表、历史对象版本、用户改写安装文件、共享产物和 Redis stream/PEL 运行完整恢复。不可用空域、伪造 manifest/签名、身份 adapter 或手拼资格绕过。
4. 目标必须 schema-only/可证明的空白业务库。真实 migrations 会插入 Skill Hub 默认 tags；本机 fixture 仅清空自身新建库的 seed，生产恢复仍会拒绝这种非空目标，不能运行应用 initializer 或在现库上自动清表/升级。
5. 恢复 Job 正常退出后先撤销 SQL/Redis/对象写凭据并证明认证/写失败，再用独立只读 SQL、确切对象版本和只读文件挂载验证关系/内容/多余行。原 stopped 实例保持 stopped，禁止自动启动 agent、队列或 outbound。
6. 测试任务取消、节点/挂载变化、写失败、证据失败、未知提交、凭据撤销失败，按现有 journal 接管；保留所属不确定目标，不重放、不清理他人资源，并确认源 writer 恢复行为。
7. 上述 owner 适配、共同证据和独立 verifier 都完成后，由现有 D 发布/验收链路完成最终资格判断。本分支不写最终 CAS。
