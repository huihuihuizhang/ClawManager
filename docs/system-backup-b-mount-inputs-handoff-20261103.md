# B：第 1～3 项增量交付

基线：`backup@71e2f3186a28ff150bc183b86ffdfe491678a5e9`。本轮已 fetch 并再次核对主仓库 backup；远端没有更晚提交，现有未提交改动完整保留。没有提交、推送、合并、安装依赖或真实迁移。

## 提交前整合记录

上述基线与“未提交”状态记录的是开发及测试完成时的现场。用户随后授权直接提交并推送主仓库 `backup`，不创建 PR。提交前重新 fetch，远端已更新至 `21de0cf77c96801a84e89dc8aa7267233d7a90db`，本地已无冲突快进至该提交。

新增上游提交只涉及前端备份页面提交入口、相关脚本和验证记录，与本轮 B 文件无交集。整合前后逐一复核本轮 21 个源码文件，SHA256 均与 `evidence/b-mount-inputs-20261103/summary.json` 相同；go.mod/go.sum 也未变。因此沿用下述已完成的针对性隔离测试，不将它们改写为新一轮现场整链验证。准确检查见同目录 `submission-precheck.json`；本次实际交付 SHA 以 Git 提交记录为准。

## 1. 实例级盘点与 SQL / Runtime 关联

新增实际只读入口 `DeploymentService.ObserveInstanceMountInputs(ctx)`，位于 `backend/internal/systembackupexecution/production_mount_observation.go`。它使用原 `newSourceSQLObservation` / `observeInventory`：同一已签发源授权、独立最小权限 SQL、用户归属检查、原 source scope、控制器身份、数据库时钟及有效期检查。运行实例经原 `ResolveGatewaySource` 核对 SQL 绑定、实际 Pod 和 Runtime capability，再取节点身份。两轮实例投影和前后完整 SQL inventory 不一致则拒绝，不返回部分成功。

返回 `InstanceMountInputObservation`：安装/namespace UID、inventory/source scope 摘要、SQL 检查时间、原有效期，以及逐实例的 user_id、instance_id、generation、原状态、workspace、Runtime Pod UID/spec hash、绑定摘要、节点和普通/init 容器的持久化挂载。输出不含 env、args、端点凭据或业务文件。`DiagnosticOnly=true`，任何执行/首次纳管构造均不接受该结果作为授权或物理停写证明。

原本停止的实例只输出缺项；不会根据空 Pod 名或 SQL stopped 推导旧目录，也不会启动实例。发现源授权撤回、材料变化、超时或 SQL/Runtime 漂移时沿用原拒绝路径。

**调用边界：这个诊断入口沿用已启用的正式 source delegation；不能用于绕过首次纳管。** 首次纳管继续使用既有 Installer 的不透明原维护身份和 source registry reader，B 没有新增 controller、权限签发器或 SQL 控制表。

现场通过用户授权的 SSH 仅再次执行固定 `kubectl get` 投影：`10.130.14.23`，context `kubernetes-admin@kubernetes`，namespace `clawmanager-zhanghui08-system`，UID `337cfe30-2c17-4b8e-b32a-760778b8098e`。仍观察到 10 Deployment、10 Pod、38 ReplicaSet、6 PVC，两个采样之间未见投影变化。原始安全投影见本轮 evidence；没有读取 Secret 正文、SQL 凭据或业务数据，没有执行停写或纳管。

**尚未完成现场实例级 SQL/Runtime 核对。** 未收到可用的原 source 只读授权/生产构造，不能使用 SSH root 身份提取平台数据库口令来替代它。Pod 数量不是实例数量。

## 2. 停止实例输入与失败诊断

新增 `InstanceMountInputError`，通过 `errors.As` 取得固定 Code、InstanceID、MountID；保留 `errors.Is(err, dispatch.ErrNotReady)`，停止实例也匹配原 `controller.ErrSourceRecoveryStoppedWitnessRequired`。

| 诊断 Code | 含义 / 接收者 |
| --- | --- |
| `original_mount_scope_required` | 缺少原 owner 已选定的完整挂载范围；D 装配 |
| `stopped_original_snapshot_and_witness_required` | stopped 原挂载快照与真实停写/无在途 writer 证明缺失；D/A |
| `sql_runtime_binding_mismatch` | SQL 原身份与实际 Runtime 绑定不一致；D |
| `sql_mount_owner_generation_mismatch` | 挂载材料的实例归属或代数过期；D |
| `incomplete_persistent_mount_layout` | 普通/init 容器有未登记的持久化挂载、overlay 或不支持存储；D/存储 owner |
| `original_mount_pin_changed` | Pod / Node / 卷 UID 或原 spec pin 已变化；D，重新盘点并走原材料流程 |
| `original_mount_inventory_drift` | 两轮读取间的原身份/挂载发生变化；不得继续使用该结果 |
| `overlapping_instance_mount_roots` | 两个声明指向相同或重叠物理目录；不得以不同实例名重复授权 |

当前 D 的 `SQLRuntimeControl.Prepare` 对 stopped 仍保存 `{}`，没有历史 Pod 挂载全集。B 已补停写前拒绝、错误分类及隔离测试，但**没有虚构新的历史快照/物理 witness 协议，也没有放行停止实例采集**。运行与停止混合的非空 six-part 源仍可能在此拒绝。

D/A 需要交付的 stopped 输入，必须从真实原记录产生：

- D：原安装/namespace、完整 `InstanceIdentity`（用户、实例、原 generation、状态、workspace），对应原挂载快照的不可变引用及摘要、生产者和格式版本；完整普通/init 容器、卷与子目录范围；PVC/PV/Node UID 和所有权依据。不能用当前新建同名 Pod 或 Deployment 模板替代已删除的原 Pod。
- D：真实 stopped / drain 与迟到请求隔离证明接点，绑定同一原实例代数、参与者及无在途 writer 范围；恢复路径仍维持原本停止，不发 start。需要明确能传给 B 的实际构造/回调。
- A：上述历史输入与物理 fence 的原认证用途、原 epoch / 有效期 / 撤销及重放规则。需要真实验证入口；签名 JSON、数据库状态或调用方 Passed 不能独立证明物理停止。

在这些输入未到齐前，接口字段需求是交接清单，不是 B 自行定义并签发的新授权合同。

## 3. 原挂载材料生成及公共清单接线

新增 `BuildOriginalInstanceMountScope(ctx, client, cfg, instances, specs, layouts)`，位于 `production_mount_inputs.go`。D 输入原 SQL / Native 比对数据和 owner 已批准目录布局；B 通过实际 Kubernetes GET 自动填 Pod UID、完整 Go PodSpec hash、Node UID、VolumeSource hash，并核对原部署 PVC/PV pin、原 staging 放置、目录范围与物理重叠。两轮读取和最终 namespace UID 复核失败时不返回候选材料。

返回的是**未签名的原材料候选 JSON**，不是 source authority、首次纳管身份或数据一致性证明。必须在原 definition 被选定并 SHA 固定之前，放入其 `Materials.Discovery.PersistentMounts`；已 Begin 的 sequence 不能临时替换 scope。

`productionPersistentMountBinding` 新增必填 `UserID`、`Generation`，与原 SQL 实例和运行绑定逐项比对。它们随既有 `sourceMetadataScope` 进入 A 原元数据签名；不能只改实例号而复用共享 Runtime Pod 的 pin。此前本地尚未提交的 v1 声明需要重新生成，不存在已发布合同的静默升级。

实际生产接点已经补入：

1. `OriginalCaptureSequence.MaterializeMappings`：在创建 mapping 资源前核对选定的挂载 pin；新增读取后再做原 authority Recheck。旧 nil scope 不增加这次重查。
2. `OriginalCaptureSequence.observeMappings`：正式 Finalize 既有签名前、发布前、输出后复查点均核对原挂载 pin。原 owner、原绝对时间窗、失败 latch 和 create-only 输出保持原语义。
3. `bootstrapSourceRegistryReader.checkRuntimeWorkspace` / `checkNFSRuntimeWorkspace`：两轮事实采集都核对普通/init 容器的额外挂载、真实卷 pin 和原 Pod 读回；前后保留 `checkPhysical`。
4. `bootstrapSourceRegistryReader.deriveParts`：为每个额外挂载登记 `users_instances / instance_<id>_<mount> / capture-workspace`，和正式 production inventory/Job 使用同一原 operation。主 workspace 和共享 SQL 各保留一份，不收缩六类 requested parts。

最小接入顺序（由 D 放进现有装配，不是新增管理 API）：

```go
// originalInstances / runtimeSpecs 必须来自 D 的真实原 SQL/native 读取；
// layouts 是原 owner 批准的各实例目录，不能由备份 HTTP 请求传入。
scopeJSON, err := execution.BuildOriginalInstanceMountScope(
    ctx, sourceAPI, coreConfig, originalInstances, runtimeSpecs, layouts,
)
if err != nil { return err }
// 将 scopeJSON 放入尚未选定/签发的原 definition 的
// Materials.Discovery.PersistentMounts，再固定 definition 的文件和 SHA。
// 随后走现有 BeginOriginalCaptureSequence -> MaterializeMappings -> Finalize。
// 原构造提供 Installer、enrollment pin、独立 issuer、原时间窗与权限。
```

上述 builder 的输入是比较数据，B 的执行器不会据 builder 返回值取得任何权限。实际任务仍重读原 SQL/Runtime、核对已签原 scope、停写/源状态恢复和逐操作授权。

## D/A 接收清单

| 接收者 | 需要提供 / 完成的实际输入 | B 已交付 / 调用位置 |
| --- | --- | --- |
| D | 合法 source SQL projection：实例 user_id、id、runtime_generation、原 status、原 workspace；Runtime locator v2 的实际 Pod UID、注册绑定及代数。正式诊断要有已启用原 source delegation；首次纳管使用原 Installer 维护授权，二者不可循环借用 | `ObserveInstanceMountInputs`；原 `ResolveGatewaySource` 未改为控制 SQL 写入 |
| D | 原目录布局 `InstancePersistentMountLayout`；部署 `NamespaceUID`、`Security.NodeUIDs`、额外 PVC 的 `Security.Volumes` 及 staging 放置。目录全量归属仍需原 owner 证据 | `BuildOriginalInstanceMountScope` 自动生成 UID/hash；不要求操作者手填 PodSpec hash |
| D | 将未签候选 scope 在原 definition 选定前装入；交出真实 production 构造调用及 receipt pin | 原 MaterializeMappings / Finalize 和首次纳管 parts/卷核对已接 |
| D/A | stopped 原快照 + 真实 witness 生产者/验证入口，精确字段见第 2 节 | 专用拒绝及诊断已补；实际历史恢复适配仍阻塞 |
| A | 原 source-owner 签名覆盖新增用户/代数字段、原 issuer/用途、原文件/epoch/时间窗与撤销；原生产用途和 provider/key 能力照旧，不接受本地测试身份替代 | 复用既有 metadata scope 和原认证 sequence；没有新增 issuer 或签名域 |
| D / 操作者 | 同版本隔离安装及只读 SQL/Runtime 材料；真实 MySQL、Agent、存储和 Job 条件 | 本轮只做本地隔离模型和服务器只读盘点；真实备份和迁移均未执行 |

PVC/hostPath 仍要求原 staging 节点；NFS 只接受当前获准安装 export/子树。整卷根目录所有权不明、nested overlay、inline CSI、block、未解析 subPathExpr、Pro/Windows 不在本轮支持范围。额外挂载目录含 Skills/Teams 内容时，领域对象清单和一致性仍由原 owner 接收，不据文件归档单独宣称领域完整。

## 验证记录

准确源码 hash、命令、退出码、根测试 PASS/SKIP、现场执行和清理记录统一放在 `docs/evidence/b-mount-inputs-20261103/`。测试使用已缓存依赖，GOPROXY/GOSUMDB=off、GOTOOLCHAIN=local、mod=readonly。完整物理停写、正式备份/还原整链和真实迁移均未验证。

- Windows 两组相关回归分别 49 根 PASS / 5 根 SKIP、11 根 PASS / 6 根 SKIP，不将重复执行或 SKIP 合计为通过。
- 后续在本地已有 Linux 镜像 `sha256:349727db7d6cce07ed6e0e0c273941fbc22f296a7d4079a52bb5127ac8dbd315` 内运行补充回归：55 根 PASS、1 根 SKIP，退出 0。`--pull never`、禁网、只读 rootfs/源码挂载、tmpfs 测试目录、无 host 端口。没有下载镜像、模块或安装工具。
- 新的完整挂载材料 component 用实际 A Installer 认证、bcrypt、Ed25519 和 B Begin/Finalize/原 consumer，覆盖合法输入、原 Pod 替换、scope 改写、数据库原窗口过期、原定义文件撤回、materialize 前漂移及失败 latch。SQL/API 仍是严格隔离模型，不能据此宣称真实 MySQL、现场认证或物理 writer 已通过。
- Linux 唯一 SKIP 是 `TestProductionFactoryDistinctIdentitySecretsOriginalSQLJournalAndCertificateScope`，要求 disposable local MySQL。本轮没有提供该测试的数据库，因此不计通过。其他名称带 MySQL/Native 的测试未选择。
- `gofmt -l` 干净，`git diff --check` 退出 0；go.mod/go.sum 未改动。

组合 `go vet` 仍只有上游既存 `deployment_publication_startup_test.go:213` 的锁复制错误：测试对含 `sync/atomic.Bool` 的 DeploymentService 做值复制。本轮未修改该 D 测试，也未关闭 copylocks 检查。该项不能记为通过。

隔离容器已经 `--rm` 自动删除。Go 自动清除了本轮构建临时子目录；日志保留。本轮新建 `.codex-temp/b-mount-inputs-20261103/systembackupexecution.test`（Linux 测试二进制）和 owner.txt 的精确删除命令，被自动审批以 `blocked by policy` 拒绝且未执行，文件仍在。没有换工具重试，也没有重试上轮已被拒绝的缓存递归清理；未删除其他 owner 的文件。准确残留见本轮 cleanup.json。
