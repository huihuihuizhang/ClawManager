# 用户和实例备份恢复领域组件

依据 `system-backup-plan.v12`，本目录实现 users/instances 的领域数据平面。此前按当时尚无公共 Controller 的信息补齐了 `control`。2026-10-26 合并前检查发现本地 `origin/backup` 已有另一套公共控制器；用户已指定合入 `backup`，两套任务协议、停写锁和资源账本仍需整合，不能直接同时启用。当前协议为内部 `v1alpha1`，不代表六域 `system-backup.v1` 合同冻结，也没有生产恢复 execute API。默认不连接控制数据库或真实 Kubernetes。

最新进度见[开发清单](../../../docs/users-instances-backup-development-plan.zh-CN.md)、[合并前审查报告](../../../docs/users-instances-backup-premerge-review.zh-CN.md)、[backup 分支本地冲突处理](../../../docs/users-instances-backup-branch-integration.zh-CN.md)和[控制器接入说明](../../../examples/backup-controller/README.md)。WorkBuddy Lite 固定身份版本、历史 UID 占用、分配器、实例根及 Wine 文件适配已通过隔离 Linux/MySQL 演练；恢复预检已补充源数据与目标 schema、冻结恢复策略的只读验证。WorkBuddy Pro 身份适配按用户要求不纳入，仍拒绝未知身份合同。

**以下是按开发批次保留的历史记录。** 其中“Docker 未运行”“身份表缺少资料”“尚无公共控制器”等是当时状态，当前结论以第 24、25 节和合并前审查报告为准。隔离测试通过不等于 `backup` 分支整合通过或真实 Kubernetes 验收通过。

## 已实现入口

| 包 | 入口 | 行为 |
| --- | --- | --- |
| `scope` | `BuildInventory` / `TableRegistry` | 领域表、跨域依赖、Linux 类型/存储规划；包含 WorkBuddy Lite、生命周期、身份记录及浏览器组件配置分类 |
| `domain` | `Catalog` / `Capture` | SELECT 元数据；在单个 MySQL REPEATABLE READ + READ ONLY 事务内枚举全部领域数据；不运行迁移；限额超出整次失败 |
| `domain` | `CaptureSource` / `RestoreDrillWithEvidence` | 在采集事务的同一连接上核对源数据库/UUID 与 SELECT-only 权限；隔离恢复提交前保存精确归一化结果的加密依据，失败回滚 |
| `domain` | `Encode` / `Decode` | 内部行数据 codec；保留 NULL、二进制、精确十进制和密码哈希；只允许接加密 staging |
| `domain` | `Normalize` | 纯数据计划；检查所有权、类型、表/字段兼容；目标停止、调度关闭、令牌/绑定失效；保留原备份 |
| `domain` | `JSONRegistry` | 每个 JSON 叶节点必须恰好命中一条显式规则；保留定义、随机 stub、禁用布尔开关；未知配置拒绝 |
| `domain` | `RestoreDrill` | 仅 `cm_drill_*` 数据库；两次隔离身份回调、server UUID/数据库名核对、空白目标检查；在事务内替换 bootstrap admin、按 FK 顺序导入；失败回滚 |
| `domain` | `VerifyDrill` | 独立 SELECT-only 连接；拒绝写权限/角色/wildcard grant；逐字段、行数和不应恢复的活动表校验 |
| `workspace` | `Archive` / `Restore` | 整个登记根的 tar 数据流，含隐藏目录、会话/WAL、Skill、任务文件；限额、路径/链接验证、UID/GID/权限/时间恢复；目标必须为空且独占 |
| `staging` | `Seal` / `Open` | AES-256-GCM，1 MiB 内存分片、随机 nonce、任务/attempt/路径/context AAD、认证终止帧；拒绝换序、截断、篡改、追加数据和错误密钥 |
| `staging` | `SealFile` / `OpenFile` / `Compress` / `ConsumeCompressed` | 只写密文文件，fsync 后 create-if-absent 封存；整份密文校验；有上限的流式 gzip 解压；失败只清理本次创建的 partial |
| `flow` | `Capture` | 全部 collector prepare → 持久化 pause intent → 全部 writer ACK → 采集并 seal → 撤权并确认 collector 退出 → 按原状态 resume；取消不取消补偿；失败留下可接管 intent |
| `kube` | `ResolvePVC` / `VolumeRelativePath` | 只读解析 PVC → PV → HostPath/NFS/CSI，核对 Claim UID；解析共享卷实例目录；不把存储类名称当作 snapshot 能力 |
| `kube` | `Job` / `Snapshot` / `SnapshotReady` / `RestorePVC` / `DrillNetworkPolicy` | 生成 Job、快照、恢复 PVC、默认拒绝网络的对象；固定 digest、无 SA token、明确 node affinity、源只读/恢复 staging 只读；不自动提交 API |
| `kube` | `Runner.Ensure` / `JobComplete` / `Cleanup` | 实际 client-go 创建/接管/观察/删除逻辑；强制先记 intent，核对请求 hash、UID 和 spec，删除用 UID/RV 前置条件并观察不存在 |
| `kube` | `SQLJournal` / `NewMappedResourceRows` | 公共权威账本的 SQL 事务适配器，事务内 fencing、行锁、版本 CAS、不可变请求/UID 校验；列名由公共 schema owner 映射，不自动建表 |
| `kube` | `DatabaseJob` / `WorkerEgressPolicy` | 数据库采集/恢复/校验 Job；恢复输入只读、加密校验依据独立卷；按单个 worker 限制精确控制端/数据库 IP 和端口、可选 DNS |
| `worker` | `Run` / `ControlClient` / `ControlHandler` | 工作空间采集和隔离恢复执行器；mTLS 任务授权、短期 DEK、边界复核、配置归一化；恢复始终留在 quarantine |
| `worker` | `RunDatabase` / `OpenDatabase` | 数据库加密采集、隔离事务恢复和独立只读验证；显式 TLS，口令仅通过 mTLS 短期 grant 进入内存；完整验证输入后才访问恢复数据库 |
| `cmd/backup-worker` | `/backup-worker` | 可构建的 Linux 独立 worker，支持工作空间及数据库操作；读取无凭据 invocation，等待 controller 放行；不支持生产 restore 或自行加载源配置 |

## 与公共控制面接入顺序

1. D 的 coordinator 提供冻结合同、任务身份、完整 writer registry、持久化 `flow.Journal`、fencing/watchdog、绝对 deadline。Lite gateway、Pro Deployment 和独立 Pod 的 `Writer` 适配代码已提供，具体授权、进程停止证明与应用接线见下文；API 与后台 writer 仍需登记并停写。仅副本数为零不构成 ACK。
2. 准备普通采集和独立 Secret 采集 Job。`kube.Runner` 提供实际资源操作，但必须注入公共持久化 ResourceJournal 和 fencing。`WorkerConfigMap` 保存不可变无凭据 invocation，`Job.WorkerControl` 挂载它及独立任务 mTLS 身份，启动 `/backup-worker`。源码和离线打包 Dockerfile 已提供，镜像尚未构建/发布，不能使用虚构 digest。
3. A 的 key provider 提供本任务的 DEK 与 envelope identity。`staging` 接收内存 key，不保存 key、不实现 KEK/KMS 权限或撤销；**此格式仅用于内部 staging，不能冒充原计划的最终 envelope_v1/manifest**。内存不可换页、禁用 swap/core dump 仍由 Job capability probe 证明。
4. gate 内调用 MySQL `Capture` 和各持久化根 `Archive`，内容交给 `Seal` 的 writer。collector 只有确认 immutable staging seal 后才返回 Part。当前 `flow` 保守地在全部 seal 后 resume；cluster 提前释放需接共享 checkpoint 证明。
5. 内部 staging 已实现流式 gzip；由 C 的最终 artifact、签名、catalog 流程接收领域内容。AI Gateway 的模型/渠道与平台 chat、Skill Hub 的绑定/对象、Teams 的任务仍由各 owner 按依赖 registry 交付。本目录没有把这些依赖伪造为已完成。
6. drill 必须先校验 committed artifact，再由共享 provisioner 核对 planned/observed namespace、数据库、卷身份和网络隔离。调用 `RestoreDrill` 前目标除 bootstrap admin/quota/schema_migrations 外必须为空；它是隔离领域测试入口，不能直接替代六域 MySQL restore coordinator。
7. 解密工作空间只能写入 inert quarantine；完整认证、runtime 规则归一化和校验成功前不能发布。`Open` 出错时可能已向 sink 交付认证过的前缀；不能把前缀当成功恢复。各 runtime 的真实配置/文件规则必须由 owner 提供，当前测试规则是虚构 fixture，不是生产覆盖声明。
8. 停止 restore Job、撤销写凭据，再创建独立 verifier Job/连接调用 `VerifyDrill`。仅调用一个函数或开启只读事务不能替代真实权限撤销。

## 兼容性与当前限制

- `Capture` 必须使用 `parseTime=false` 的 MySQL 连接，源 DDL 也必须在公共 gate 中受控。SQL 错误不会带原始查询参数或驱动凭据向外传播。
- 当前数据库实现为**有界内存领域批次**，适用于隔离测试和受限规模。大库接共享流式 MySQL collector，不能无上限提高内存额度。它不会自动导入/执行来源 DDL；目标 schema 不兼容即拒绝。
- WorkBuddy Lite 进入类型矩阵和完整根采集。服务器分支新增身份表的字段级恢复适配仍缺失；有数据时会拒绝未知字段。不会据此宣称那台服务器已经可以完整恢复。
- Linux 工作空间恢复应使用 `preserveOwner=true`。Windows 本地测试使用 false，只验证内容/路径行为。ACL/xattr、特殊权限、设备/socket、跨文件系统根和硬链接恢复暂不支持，检测到相应证据时拒绝；完整挂载/bind mount 清单仍由 discovery/gate 负责。
- Job/VolumeSnapshot/PVC/ConfigMap 已有构建器与实际资源 Runner 逻辑；工作空间/数据库 worker、SQLJournal、mTLS 授权处理器及镜像打包文件已实现。尚未把公共资源账本的 schema 映射/lease 查询、任务授权 Authorizer、业务写 gate、KMS、完整 status relay 和应用路由接线；默认缺任一授权/账本依赖即失败，当前应用不会自动停实例或创建 Job。
- 未提供生产 restore execute；NFS writer fencing、真实 CSI checkpoint、灾备资格和四矩阵验收仍是独立集成门禁。

## 隔离验证

从 `backend` 执行：

```powershell
$env:GOTOOLCHAIN='local'
$env:GOPROXY='off'
$env:GOSUMDB='off'
go test ./internal/systembackup/... ./cmd/backup-inventory ./cmd/backup-worker -count=1
```

测试使用临时目录、内存密钥、虚构数据、数据库/sql 驱动替身及 Kubernetes fake client。包含 22 个 Lite 实例矩阵、七类 Agent 工作空间、admin 替换、失败回滚、非空/错误身份目标、只读权限检查、未知字段、密文故障、路径攻击和停写取消补偿。

`domain.TestIsolatedDomainBackupRestoreRoundTrip` 演示领域闭环：采集数据库与工作空间 → 加密 → 关闭源连接/文件句柄 → 恢复到独立目标 → stub 凭据/禁用任务 → 只读校验。没有网络连接或真实迁移。

本轮本机 Docker daemon 未运行；没有完成真实 MySQL 8 / Linux K8s 集成测试，不把测试替身结果当作生产验收。

## Worker 与资源 Runner 接入说明

`cmd/backup-worker` 当前支持 `capture-workspace`、`restore-workspace`、`capture-database`、`restore-database`、`verify-database`。命令参数只接受 invocation 路径和 mTLS endpoint/证书路径，不接受 DEK、数据库口令或 kubeconfig。

运行入口：

```text
/backup-worker --request /run/backup/request/invocation.json \
  --control-url https://<controller>/internal/backup/worker \
  --control-ca /run/backup/identity/ca.crt \
  --client-cert /run/backup/identity/tls.crt \
  --client-key /run/backup/identity/tls.key
```

这是待接共享 Controller 的内部接口，并未向应用注册该路由，也不是冻结的公共 OpenAPI。`ControlHandler` 必须运行在要求验证客户端证书的 TLS server 上；它提取唯一 SPIFFE URI，再调用必填 `Authorizer`。Authorizer 负责从公共任务库确认 Job UID、完整 invocation hash、路径/挂载身份、policy version、writer barrier/fence、取消状态和目标隔离，并使用 A 的 key provider 返回绑定 envelope 的短期 DEK。源停写绝对时限必须约束 grant 的 expires_at；没有默认放行实现，也没有自行生成密钥的生产兜底。

调用顺序为 ready → acquire → prepare → before-capture → before-seal → sealed，恢复则为 prepare → 完整密文/压缩校验 → before-restore → before-normalize → restored-quarantine。每个边界重新授权；stdout 仅输出密文 receipt/统计/quarantine 标记，不含文件内容、密钥或账号数据。短期 DEK 不会因后续检查而延长到期时间。资源就绪/结果证据持久化、日志脱敏、身份撤销、内存不可换页 probe 和正式 status relay 仍需公共 Controller 集成。

`Runner` 不加载 kubeconfig；调用者注入 client-go client。`ResourceJournal` 必须接原计划中的 staging/drill resource 权威账本；现在可用 `SQLJournal` 提供事务和 CAS 适配，测试仍用替身验证，不代表已建立公共表。资源创建响应丢失、观察结果落库失败均可通过记录的请求和 GET 接管。若 UID 更换、spec 漂移、owner 不符或 DELETE intent 失败，拒绝修改/清理。PVC 删除成功也不等于底层 PV 已擦除，须由独立 cleanup verifier 确认。

创建前必须持久化 `CreateDispatched`，每次更新使用账本 `Revision` 做 CAS。若创建结果不确定且 GET 返回 404，保持 pending，既不再次 CREATE，也不宣告清理完成；公共 reconciler 必须解决仍在途的请求。未记录创建来源的既有对象，即使标签和请求完全匹配，也不接管或删除。

新增测试还覆盖真实 localhost mTLS 握手及工作空间 worker 文件往返、短期授权绑定、重定向拒绝、失去停写确认不发布成功、密文校验失败不写目标，以及 Kubernetes fake 下的不确定创建接管/UID 条件删除。Windows 仅运行库级隔离测试；CLI 只允许 Linux 执行。镜像通过 `deployments/docker/Dockerfile.backup-worker` 打包预编译 Linux binary，无运行时下载。

## 数据库 worker 接入

数据库 invocation 的 `workspace_path` 必须为空，`staging_path` 指向输入/输出密文目录；`restore-database` 另需独立 `evidence_path`，在 Job 中固定为 `/evidence`。公开 `database` 配置只含 endpoint、数据库名、server UUID、TLS server name/公开 CA、容量限制、目标 placement 和显式归一化规则。当前单次数据库批次最多 100,000 行，采集内存估算和编码输入各最多 32 MiB，超限失败，不是大库流式备份器。

数据库口令由 Authorizer 在 `acquire` grant 中下发，必须是该操作的独立短期账号；`ready/check` 不得返回口令或 DEK。连接使用显式 CA 验证的 TLS，禁用明文降级、多语句和 LOCAL INFILE，不从应用配置读取 DSN、不运行 migration。采集账号和 verifier 账号必须为 schema 级 SELECT-only；恢复账号只能访问已证明隔离的目标。Go 驱动使用不可变口令字符串，不能承诺内存完全清零；worker 应为任务结束即退出的短进程。

恢复先完整认证/解压/解析输入，再连接目标执行事务。归一化后的精确行内容在 COMMIT 前写入独立加密 evidence，最后复核目标隔离和授权；evidence 写入失败、同名冲突或授权失效均回滚。成功仍返回 quarantine。若 COMMIT 或结果上报不确定，共享 Controller 必须保留该 attempt 的 evidence 和目标，安排只读核对，不能重复导入或直接清理；仅有 evidence 文件不能证明事务已提交。

独立 `verify-database` 使用上述 evidence 的 receipt/binding，以及新的 SELECT-only 凭据，核对精确行内容及不应恢复的活动表。Authorizer 必须先确认 restore Job 已结束、原写凭据已撤销，且 evidence 属于该次 attempt；worker 不会把重新生成的随机 stub 当作预期值。引用的 evidence 仍使用内部 staging 格式，正式注册/签名由公共 evidence/artifact 流程负责。

`DatabaseJob` 不挂载业务工作空间或数据库 Secret。`WorkerEgressPolicy` 与 Job 使用同一个 worker 专属标签，只允许精确控制端/数据库 IP、端口和可选 DNS IP；不能用 hostname 或整个网段代替。Kubernetes 网络策略是叠加的，Controller 仍需证明没有额外放行策略并验证 CNI/Service NAT 行为，构建对象不等于已隔离。

## SQL 资源账本接入

`SQLJournal` 每次操作开启 SERIALIZABLE 事务：锁定并检查公共 lease/generation → `ResourceRows.Load` 行锁 → 校验原请求/UID/版本 → INSERT 或 CAS → 同事务再次检查执行权 → COMMIT。提交响应丢失后由重新读取同一权威行解决，不依赖内存状态。调用者必须提供基于传入 `*sql.Tx` 的 `Fence`，不能以进程布尔值、单独数据库连接或仅看过期时间代替完整 gate。

`NewMappedResourceRows` 为已冻结的公共表提供参数化 MySQL 映射：显式 table/column 名、task scope、不可变 request bytes/hash、dispatch intent、UID/RV、lifecycle 和 row version。数据库必须使用 InnoDB，并具有 `(scope,kind,namespace,name)` 唯一约束；所有写入方都须遵守 CAS。UID/RV 等映射字段必须非 NULL（尚未知时为空串），数据库负责 shared public ID、时间、HMAC owner marker 等其余必填字段。`created`/`ready` 映射对应 drill/staging，未解析的 `ownership_unknown`/`delete_failed` 会拒绝更新，由公共 resolver 处理。Job observation 表等无法直接映射的仓库可实现 `ResourceRows`，使用同一事务，不应新建第二份 cleanup inventory。

当前仓库没有公共 Controller 的权威表定义，因此这里没有默认物理表名、自动建表脚本或应用注册。这是可持久化适配器实现完成，**不是公共 schema、lease/fencing、HMAC ownership 和完整控制面已完成**。SQL 测试使用具备事务回滚和提交响应丢失模拟的 database/sql 驱动替身；真实 MySQL 并发/崩溃验收仍待隔离环境。

## 源实例暂停、恢复与中断接管

新增的适配器仅恢复**源平台备份前的运行状态**。目标恢复仍保持停止，由用户手动启动。它们没有注册业务 API，也不会通过现有 `InstanceService.Stop` 修改状态并将其视为停写证明。

| 入口 | 行为与边界 |
| --- | --- |
| `services.BackupGatewayWriter` | 使用现有 Runtime Agent HTTP 客户端，按 gateway ID/generation 停止 Linux Lite；保留 DB binding 和 slot。恢复使用预留的新 generation，避免晚到的旧 DELETE 停掉恢复后的实例。 |
| `quiesce.DeploymentWriter` | Linux Pro Deployment 按 UID/resourceVersion 条件缩容；等副本/Pod 清空并验证原 CRI 进程已停止。恢复原副本数，写入本 attempt 的恢复标记，令旧 RV 的停止 PATCH 失效。 |
| `quiesce.PodWriter` | Linux Pro 独立 Pod 使用 UID/resourceVersion 条件 DELETE，不强制删除、不接管 controller/mirror Pod。停止后使用不可变加密引用中的原配置重建，核对 spec 摘要、恢复标记和新 UID；原先不存在的 Pod 不创建。 |
| `flow.RecoverSource` | 公共 watchdog/controller 从持久化 pause intent 读取原状态，包含 ACK 尚未落库的操作；先校验完整清单，再按逆序补偿。失败保持待接管，不采集数据、不重新推断原状态。 |

`flow.Writer.CheckPaused` 会在每个 collector 开始前和全部封存后重新检查停写。`Journal.CheckRecoveryFence` 是独立于采集时限的恢复执行权；取消/超时不会取消补偿 context，但补偿仍必须持有有效权限。缺少 writer、身份、持久化意图或执行权时拒绝修改；调用方必须给恢复过程设置 deadline。

所有适配器的 `Guard` 都是必填接入点。它必须核对公共任务/attempt/phase、完整 writer 清单、数据库与工作空间后台写入隔离、HPA/reconciler/scheduler 禁止重新拉起、源 UID/版本/挂载和当前执行权；不能只返回进程内布尔值。恢复观察与提交边界还须验证该资源来自同一 attempt 的持久化 dispatch，不能仅凭匹配的名字或 annotation 接管。`FenceID` 必须是每个 attempt 唯一、持久化的非敏感标识。

`ConfirmStopped` 必须提供原节点上精确 CRI container IDs 已终止或已被可靠隔离、无法再写入的证据。仅 API GET 404、副本数为零或节点 NotReady 不够；网络分区时也不能据此创建第二个写入进程。节点/运行时证据采集器尚未实现接线。Lite 的 `Guard` 还须先证明 Runtime Agent 版本支持按 generation 删除、状态查询和真正的停止确认；不支持路由返回的 404 不能冒充不存在的 gateway。

Lite 与独立 Pod 的 `LoadRestart` 从任务绑定的不可变加密引用加载源端重启参数，暂停日志只保存引用和身份摘要，不能存环境凭据或原始 Pod manifest。适配器在停止前先验证该引用。`ClaimRestart` 必须在公共事务中持久化发出创建请求的意图，且只允许一次；如果创建超时且 GET 404，只等待核对，不重发 CREATE。若进程在持久化 dispatch 后、实际发送前退出，也会保留 pending，须由公共 resolver 证明结果后处理。`CompleteRestart` 在同一恢复执行权下幂等更新源 binding/generation/Pod UID 和 slot 状态；它们不是普通的无条件回调。

独立 Pod 重建要求原 spec 与提供的干净 restart spec 摘要一致；admission/defaulting 的兼容性、原节点存储可达性及服务/绑定更新由 discovery 与 Guard 验证，无法证明时失败。适配器不覆盖任意 StatefulSet/DaemonSet 或未登记的 workload。

隔离测试覆盖现有 HTTP 客户端到 localhost 模拟 Runtime Agent、Kubernetes fake 中显式模拟 UID/RV 前置条件、原停止状态、身份/配置漂移、缺少节点证明、响应丢失、晚到停止请求、单次创建及进程重建后接管。它们证明适配器的代码行为，不代替真实 Runtime Agent/Linux/K8s 验收。

## 本项目控制面接入（2026-10-23）

以下内容更新上文需要其他 owner 提供公共实现的历史描述。当前在本项目实现，不等待其他分支；后续通过接口适配公共合同。

| 入口 | 当前实现 |
| --- | --- |
| `control.SQLStore` / `schema.sql` | 独立控制库的任务、幂等请求、事件、配置版本、租约、停写门禁、暂停意图、资源、Worker 和发布账本；同一事务内行锁和执行权检查 |
| `control.Controller` / `Service` | 任务阶段推进、请求取消、超时补偿、失权中断、配置健康过期、发布结果不确定时的独立只读核对循环 |
| `control.PauseJournal` / `ResourceJournal` | 对接现有 flow 和 Kubernetes Runner；捕获身份与控制进程接管 generation 分离；暂停清单不可缩短或替换 |
| `control.JobCollector` / `AwaitWorker` | Job 创建及身份登记、等待认证 Ready、关联结果回传与精确 Job UID 的 Complete 条件；撤销授权/数据库凭据、清理 Job，并要求节点进程停止证明 |
| `control.WorkerAuthorizer` / `worker.ServeControl` | TLS 1.3 双向认证；SPIFFE、完整 invocation、Job UID、任务阶段、租约、配置版本和采集门禁联合授权；固定有效期 grant；幂等结果回传 |
| `control.Publisher` | 发布意图先落库、再关闭取消窗口；逐步检查执行权；只有精确内容、签名和密文验证成功才写 committed；接管时不重发不确定的发布请求 |
| `artifact.Directory` / `SecretKeys` | 功能测试用 users/instances 密文包、DEK 绑定封装、Ed25519 签名、提交标记、完整读取验证；可在源目录关闭后读取 |
| `mutation` / `SystemBackupGate` | API 请求生命周期和已接入后台任务的持久化写入许可；停写期间返回 503，取消/查询备份任务仍可用 |
| `quiesce.CRIProver` / `CRICommand` | Linux 节点侧只读 `crictl inspect`，按 node/Pod UID/container ID 验证 EXITED；不存在、GC 或分区不冒充已停止 |
| `domain.NormalizeDocument` | JSON/YAML/TOML/dotenv 的显式字段归一化；拒绝歧义、未知字段、YAML alias/merge 和 dotenv 插值 |

应用管理路由：

```text
GET  /api/v1/admin/system-backup/profiles
GET  /api/v1/admin/system-backup/tasks
POST /api/v1/admin/system-backup/tasks                 Idempotency-Key: <稳定请求标识>
GET  /api/v1/admin/system-backup/tasks/:id
POST /api/v1/admin/system-backup/tasks/:id/cancel      If-Match: <row_version>
```

全部使用现有登录和管理员校验。任务接受 `backup`、`drill`、`preflight`、`catalog_scan`、`catalog_import`，默认 `purpose=functional_test`；backup 在明确配置 acceptance 策略并具备完整证据时可使用专用验收准入。不接受生产 restore。目录导入只做认证并持久化结果；要求 `artifact=sbr_...` 和 `record_sha256`。前端入口为 `/admin/system-backup`；支持配置健康原因、任务列表、阶段轮询、取消和响应丢失后的同一请求重试。

`CLAWMANAGER_BACKUP_CONTROL_CONFIG` 指定独立控制库配置 JSON 的绝对路径；结构为 `DatabaseConfig`，数据库名必须以 `cm_backup_control_` 开头。凭据从另一个绝对路径文件读取，MySQL 使用校验服务身份的 TLS。`schema.sql` **不由业务数据库初始化流程自动运行**；这里只提供安装源码，本次没有在任何真实数据库执行。没有设置配置时，原业务流程不建立控制库连接，备份入口报告依赖未配置。设置后，启动迁移/后台任务也必须取得门禁许可。

需要区分以下责任，不能以默认返回成功代替：

- `Executor` 仍需实现具体 profile 的 discovery → 不可变计划 → Jobs/PVC/快照 → 采集/隔离恢复/校验阶段组装，并提供可部署的 controller 主程序。`Service` 是宿主生命周期实现，不是已经部署的 controller。
- `WorkerAuthorizer.ValidateLive` 必须核对真实 Job/Pod UID、挂载和运行时停止或目标隔离证据；`JobCollector.StopProof` 必须证明原节点上的进程终止。节点证明远程通道、工作身份签发、数据库临时账号实际撤销及 Runtime Agent 能力发现尚需接入。
- 所有应用副本及外部 writer 必须纳入发现与门禁。当前已接入 HTTP、RuntimeScheduler、Sync、Skill materialize、实例/Team 删除、配置级联、安全扫描、PVC monitor、WorkBuddy prewarm、Team 消费/扫描、northbound operation 等路径；这不等于已证明不存在外部 NFS writer、HPA 或脱离请求生命周期的其他写入。
- 完整 runtime/version 文件策略、独立业务 Secret、WorkBuddy 源分支身份表字段适配、加密重启引用与源 binding/slot 更新仍需完成。格式解析器和类型矩阵不等于这些策略已齐全。
- `users-instances-functional.v1alpha1` 仅是领域功能包，不能单独代表六域验收；完整 catalog、retention、acceptance 合同由独立 recovery 层及显式 owner 证据提供。

源恢复顺序是：停止/撤权所有 collector → 节点证明确认 → 标记 Worker terminated → 逆序恢复原暂停状态 → 打开门禁。控制账本阻止未清理 Job、未终止 Worker 或未恢复 pause 进入成功终态。遗留 mutation permit 不因 TTL 自动删除；进程崩溃的许可还需要有终止证据的 resolver。任一不确定操作保留待核对，不通过扩大权限或重建同名资源绕过。

本轮验证使用本机临时目录、localhost mTLS、Kubernetes fake 与 SQL 驱动替身。前端依赖从本机 npm 缓存离线安装并通过构建；没有连接参考服务器、修改真实数据库/集群或执行迁移。真实 Linux/MySQL/K8s 和存储矩阵验收仍未执行。

## 执行编排与运行时基础组件（2026-10-25）

以下更新上一节相关组件的实现状态，不表示完成可部署的整个备份系统。

`control.Pipeline` 已实现 `Executor` 的备份、隔离恢复、preflight 阶段和补偿顺序。`ProfileDriver.Discover` 必须只读，返回冻结计划；`Bind` 从同一计划重建具体适配器，不能重做 discovery 或生成新的身份。计划、阶段开始标记、结果和敏感资料保存在 `Vault` 中，以 AES-256-GCM 加密并绑定任务/profile revision/记录名/类型/密钥版本。接管保留原身份，已有记录不允许覆盖；缺失密钥、认证失败或阶段结果不确定时拒绝推进。轮换密钥后须保留仍有任务引用的旧版本。

每个 profile 必须提供完整 source 检查、目标隔离检查、资源准备、采集结果核验、发布和清理实现。`Pipeline` 不使用默认返回成功的回调。`ActiveRevisions` 显式选择接受新任务的 driver，历史 revision 只用于恢复原任务。**具体环境 driver、`backup-controller` 命令及其完整部署配置尚未实现**；API 不会因这些新文件存在就自动开启执行。

`IdentityIssuer` 为每个 task/invocation 生成 ECDSA P-256 客户端证书，证书用途限定 clientAuth，有效期不超过任务截止时间和两小时。`WorkerIdentities` 将私钥放入加密记录及任务专用 immutable TLS Secret，普通资源账本不保存私钥。Secret 先记录 dispatch，再创建并核对精确内容、UID/RV；不确定创建保持待核对。删除时不生成缺失凭据，不接管同名外部 Secret。签发 CA 与 Worker 验证服务端的 CA 均须显式提供。

`DatabaseCredentials` 使用单独的管理连接创建、读取及回收临时 MySQL 账号。管理连接必须通过 TLS，并匹配冻结的数据库名/服务器 UUID；账号有归属 ATTRIBUTE，远端 named lock 串行化 DDL 与撤权，连接不归还到池中以免遗留锁。源采集/目标 verifier 只有 SELECT；隔离恢复仅有 SELECT/INSERT/UPDATE/DELETE。每次检查精确授权范围，拒绝角色、全局权限、额外写权限和 grant option。依赖支持 USER_ATTRIBUTES/CREATE USER ATTRIBUTE 的 MySQL 8 版本和相应管理权限，不自动升级或修改服务器设置。

回收先持久化 revoked，再锁定账号，终止该任务账号已有的全部连接，最后删除账号并核对零连接。不能把 DROP USER 当作既有会话已终止；其行为见 [MySQL DROP USER 文档](https://dev.mysql.com/doc/refman/8.0/en/drop-user.html)。生成和验证 schema grant 时读取 `partial_revokes`，避免下划线扩大数据库范围，依据 [MySQL GRANT 文档](https://dev.mysql.com/doc/refman/8.0/en/grant.html)。创建账号语句包含临时口令，部署时的 SQL 审计/代理不得把原始账号 DDL 写入普通日志；应用接口及错误输出仅返回固定错误码。

`WorkerAuthorizer` 在授权事务提交后调用 Vault/密钥/数据库账号提供器，随后再次检查 live proof、任务执行权、阶段、撤销和固定时限。这样既避免嵌套事务死锁，也不允许慢速提供器在任务撤销后返回可用 lease。失败擦除已取出的密钥和口令。

`kube.WorkerObserver` 读取真实 Job/Pod/节点/PVC/PV/Secret/ConfigMap 并核对冻结身份，接受明确列出的 Kubernetes 默认值，拒绝递归配置注入。当前支持单容器、单 Pod、RestartPolicy Never 的本组件 Worker；额外 Pod、sidecar、container restart 和不匹配的 admission 修改均拒绝。`WorkerSecurity` 必须由 discovery 冻结，包含精确 node UID、PVC/PV UID 和 spec hash、不可变 Secret/ConfigMap UID/content hash。仅核对 claim 名称、hash annotation 或 Job succeeded 计数都不够。

`control.LiveWorkers.Validate` 可接入 `WorkerAuthorizer.ValidateLive`；它在返回 Ready/密钥之前持久化进程身份，替换 Pod 或容器不能继承旧 grant。`Stopped` 可接入 `JobCollector.StopProof`，从持久化记录向原节点请求 CRI 停止证明。`CheckEvidence` 仍须由具体 profile 实现源暂停/目标隔离验证；Pod 核验本身不构成隔离证明。未产生进程记录的失败任务仍待专用 resolver，不能用空清单代替终止证明。已持久化 terminated 的 Worker 重复补偿可复用证明，避免受节点后续 GC 影响。

节点证明服务入口为 `cmd/backup-node-proof`，客户端为 `quiesce.ProofClient`。服务仅接受精确授权 controller SPIFFE；客户端同时检查服务端 CA、DNS/IP 和节点专用 SPIFFE。证明绑定随机 nonce、请求摘要、原 Pod UID/CRI container ID 和短期时间窗。缺失容器、运行中、节点失联、重放和身份错误均失败。各节点与控制器需要同步时钟。

逐节点部署模板为 [node-proof.pod.yaml](../../../examples/backup-controller/node-proof.pod.yaml)，Dockerfile 为 [Dockerfile.backup-node-proof](../../deployments/docker/Dockerfile.backup-node-proof)。模板不能直接部署：需替换 node、镜像 digest，并提供该节点专属服务端证书和 controller CA；服务端证书的 SAN 必须匹配配置中的 HTTPS 地址，URI 必须匹配 `ProofEndpoint.ServerURI`。URL 使用 `/proof/v1` 路径。静态 `crictl` 由发布流程提供，镜像内不下载。节点 runtime socket 的只读挂载不限制 CRI RPC 权限，该服务仍是具有节点 runtime 访问权的受信组件；代码只调用固定 inspect，不提供 exec/停止/任意路径接口。

新增控制表为 `system_backup_private_records`、`system_backup_identities`、`system_backup_credentials`、`system_backup_worker_processes`。账号的 revoked 与 removed 分别表示停止发放和已确认远端回收；任务终态还检查所有账号 removed、身份 Secret deleted，不能只凭撤销标记结束。`schema.sql` 只提供源码，不自动运行。

## 具体驱动与控制器入口（2026-10-25）

`profile.Driver` 现已完成 discovery → 加密冻结计划 → writer/collector → CSI 快照或直接归档 → 隔离恢复/校验 → 发布/清理的实际组装。`host` 和 `cmd/backup-controller` 连接 Service、Pipeline、mTLS relay、版本密钥、身份签发、SQL 账号、节点证明与真实挂载检查。`control.SourceRestarter` 在同一 MySQL 事务中预留 generation、记录恢复 dispatch，并将源 binding 回写与恢复回执一起提交；控制库和源库必须同 server UUID。新增 `system_backup_pauses.restart_result`，已有安装需显式执行对应升级 SQL。

使用方式、配置文件、RBAC、共享卷要求、Runtime Agent/NFS 外部能力契约、目标保留规则见[控制器接入说明](../../../examples/backup-controller/README.md)。`target` profile 不打开源数据库；没有证明或完整策略时拒绝执行。恢复目标保持停止。节点镜像实际发布、MySQL/CRI/K8s 存储矩阵仍待隔离验收，模板未部署。

## 版本策略、业务资产与写入者覆盖（2026-10-25）

本节更新前文相应“未完成”描述。`worker.RuntimePolicy` 绑定精确镜像 digest 和文件规则；`domain.WorkBuddySchema`/`TableAdapter` 提供严格版本适配，未覆盖字段或缺失身份 schema 拒绝恢复。用户确认暂时没有 WorkBuddy 源分支结构，本轮仅交付接口和合成 schema 测试。

`assets` 采集显式登记的业务 Secret、ConfigMap 和 Skill 对象，核验 UID/RV、引用、版本与内容 hash，直接加密归档。`restore-assets` Job 将对象和逻辑 key 索引写入隔离 PVC，凭据生成不可用演练值，配置按版本规则处理；`verify-assets` 以只读挂载独立核对实际目标文件。不向真实业务 Secret/MinIO 写入，不启动 Agent。模型、聊天记录、Skill 依赖已纳入数据库一致性采集；Team 非空表仍需要 owner 的精确 schema/JSON 策略。

`control.ProcessGate` 在应用初始化前登记进程，把 mutation permit 关联到原 Pod/Node/CRI container 身份。`profile.applicationCoverage` 校验全部已配置 Deployment 副本并冻结清单；当前不支持应用 sidecar/init/ephemeral container。`WriterCoverage` 校验外部 writer 的受认证证明。`ResolveApplication`/`ResolveLegacyMutation` 只有在原 CRI 进程与远端副作用均已停止、租约仍有效时才删除精确许可；未知记录不会因 TTL 或 Pod 消失被清除。旧控制库手工使用 `upgrade-app-processes.sql`，没有自动升级。

领域包新增签名 `DomainContract`，目标匹配策略摘要；`Directory.Scan` 按提交标记分页并重新验签/认证密文。仍不等于全六域 system-backup.v1 的独立 catalog 签名、注册/删除、保留策略和灾备资格。实际 runtime 发布策略、外部 writer 证明服务和跨域 owner 接入仍有工作。当前状态及验收边界以[开发清单第 14 节](../../../docs/users-instances-backup-development-plan.zh-CN.md#14-第-34-项适配与覆盖证明2026-10-25)和[控制器接入说明](../../../examples/backup-controller/README.md)为准。

## 六域公共合同与跨域适配更新（2026-10-25）

本节更新上一节相关状态。仓库中的 Team 任务/事件/工作流及 AI Gateway、resources 表已有显式列清单和归一化；共享卷、私有 JSON/WorkBuddy 版本仍需真实规则。用户/实例贡献合同升级为 v2，新增 resources 依赖。运行中的任务关闭，源数据仍完整保留在加密包中。

新增 `recovery` 包实现六域/六 part 合同、分用途签名、顺序发布、独立 catalog 注册/删除、不可变快照扫描、源无关导入认证及 retention 规划；`control.CatalogActions/CatalogScans` 提供事务日志。JSON Schema 可通过 `cmd/backup-contract-schema` 离线生成。详细调用约束、存储/Redis/共享卷适配接口和测试边界见 [recovery/README.md](recovery/README.md)。

目录扫描/导入已通过 `control.CatalogExecutor` 挂到 functional_test API；六域发布通过 profile owner 生命周期、冻结 `SixDomainPlan`、`CatalogAdmission` 和 `SixDomainPublisher` 接入控制器。`host.RunWithAdapters` 提供六域 owner、共享卷、私有 codec 工厂注册，未注册的真实实现不降级为空数据。默认命令可使用内置 Gateway 客户端和显式 CMSTG01 codec；Gateway 服务端通用层已提供，其原生存储适配仍需 owner 提供。

新增独立 Catalogs 配置无需源 DB/K8s；有固定信任文件、KEK、格式描述和 locator/bootstrap 白名单。共享 Team 卷身份经实际 PVC/PV 与 owner 证明复核后传入 Worker。Redis 提供完整认证后逐项写入的编排接口，不包含猜测的现场 Redis 客户端。SQL 增加 `system_backup_recovery_publications` 本地提交结果，初装/升级脚本均已更新，程序不自动安装。

现场 acceptance 仍需真实 provider/owner 适配；专用准入及服务端通用层的后续实现见本文件末节。不能把核心库测试通过描述为全系统六域迁移已部署。

## 目录管理、恢复账本与离线诊断（2026-10-25）

目录新增管理员分页/详情/脱敏报告接口和页面“结果”入口；完整扫描后才能浏览，游标绑定快照，报告不返回 provider 地址、对象路径、bootstrap 或密钥，历史校验不授权恢复。

`control.RedisJournal` 提供整份清单冻结、逐项发送/完成状态、进度和只读 Reconcile。`control.RecoveryGuards` 提供同控制库互斥、按消费者划分的恢复租约、保留标记、清理候选冻结和重新核验。`ProtectedCollector` 接入 Pipeline 生命周期；`ExecutePrune` 在持久化发送意图后才调用显式提供的 PruneProvider，未知结果只读核对；`PruneJournalProof` 把已确认删除证据交给 Tombstone。没有默认原生 Redis/删除实现或自动清理入口；owner 组装时必须显式接入，不能用本地锁替代外部资源停止证明。

任务终态检查增加未决 Redis 写、清单完成度、未释放消费者及已认领清理操作。初装 schema 已包含新表；已有控制库手工使用 `control/upgrade-recovery-operations.sql`，本轮没有执行 SQL。

`backup-controller --diagnose --config <绝对路径>` 输出脱敏结构/策略覆盖/资料缺项报告；`--materials-template` 输出不含凭据的资料清单。两者均不连接网络或读取引用的密钥文件，runtime_verified 永远为 false。接口、限制和隔离测试说明见 [recovery/README.md](recovery/README.md)及[控制器接入说明](../../../examples/backup-controller/README.md)。最新进度见开发清单第 17 节。

## 六域验收准入与 provider 服务端（2026-10-25）

专用 acceptance 准入已接到 profile、管理员任务 API、控制器及页面。固定 AcceptancePolicy 和六域独立验证证据，授权记录绑定完整发布计划并加密持久化；每个发布动作核对授权和前序确认，签名验收结论重新计算，只有合格点注册。终态和脱敏报告区分任务完成与灾备资格；原功能包不会自动获得验收资格。

GatewayServer 提供既有协议的 mTLS 服务端及固定身份/根目录/操作授权。GatewayDispatch 在发送前持久化完整请求，重复及未知写只读核对。新增 backup-provider-gateway 命令、离线配置检查、显式工厂接入和独立账本安装脚本；默认二进制缺少原生 factory 时拒绝启动。底层 native expiry/strong absence/immutable inventory、实际 owner 证据和厂商格式仍需资料，不能用普通 S3 操作伪装实现。

本轮只运行本机合成数据、SQL 替身及 localhost TLS 测试，没有真实迁移/删除、SQL 安装或部署。详细契约见 [recovery/README.md](recovery/README.md)，最新清单见开发计划第 18 节。
