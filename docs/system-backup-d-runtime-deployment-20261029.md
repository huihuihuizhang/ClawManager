# D：Runtime 生产构造、原配置留存和 relay 注册

本补丁承接 `f2f78aef`（C current facts v1）和 `af7c3ad5`（D Runtime/relay SQL）。范围仍为 `functional_test` 的 workspace；`acceptance_ready=false`，没有扩大成完整六域或正式成品。现场执行由用户在远侧 zhanghui08 测试环境完成；已获得部署、存储及只读 SQL 元数据，尚未获得实际停止、备份和恢复的运行证明。

## 实际构造与 caller

| caller | 实际实现及输入 |
|---|---|
| `cmd/system-backup-v2-controller.runConfiguredPublic` | 先读取 SHA256 固定的 `SYSTEM_BACKUP_PUBLIC_CONFIG_FILE`；只有显式 runtime 配置才选择 `SQLRuntimeControlGrantProbe`。继续调用原 `NewDeploymentService`。 |
| `NewDeploymentService → attachRuntimeSources` | 在原 Gate/DB/client/独立恢复身份上构造 `NewSQLRuntimeControl`，组合平台 Deployment writers 与 Runtime writers；不覆盖、遗漏平台物理 writer。 |
| `LinuxProfile.BuildWriters` | 先验证 source inventory 的 namespace、支持类型和实际 PVC/子路径；D `Prepare/BuildWriters` 提供真实 `RuntimeWriterSpec`、`RuntimeWriterDependencies`、`WriterCallbacks`。恢复只读原 custody/frozen plan。 |
| `RuntimeControl.Dependencies` | 读取完整 `system_backup_participants`，扣除已由物理 writer 表示的 ID。剩余 ID 必须逐项存在显式 probe，未知/漏项拒绝。注册仍走原 Gate；管理员必须先通过现有 Gate 安装接点登记 lease participants，不由 B 编写 SQL。 |
| participant probe | `runtimeLeaseProbe` 查询当前 application gate 和未释放 mutation leases。仅适用于所有写入均受该 lease 约束的已审查 participant；外部写入者不能冒充这一类型。 |
| Deployment probe | 固定 namespace/name/UID，检查 HPA、实际 Pod 节点 UID/Linux；恢复仍使用原 resume fence 与实际新 Pod 的绑定 CAS。 |
| Pro stop proof | `StopProofForTask(a, namespace)` 构造原 `PublicJobOwner.StopWitnessIn`；停止前建立 kubelet watch，原 Pod UID、Node UID、container IDs 的 terminated ACK 写入 `SQLStopProofs`。缺失、断流、强删均不生成证明。 |
| Lite stop/restart | D 现由 `GatewayControl` 调用 native Agent 正向停止/恢复接口，核对绑定请求和原字节回执并写入 gateway proofs；`ClaimRestart/CompleteRestart` 处理原绑定 PID/generation CAS。Agent token 只从固定私有文件读取。现场旧共享 Agent 没有该路由，真实停止/恢复和 SQL 回执尚未通过。 |
| TLS server → `/relay` | `DeploymentService.controlHandler` 实际注册 B `NewAuthenticatedRelayHandler`。先通过原 `WorkloadIdentity` 的 TLS + TokenReview，再匹配已登记原 Job process、原 immutable IdentitySecret、原证书 pin；每请求关闭 authenticator。 |
| relay SQL | `SQLAuthenticatedRelayAcceptor` 锁原 authority/Job，事务内 A Bind → receipt INSERT → A Recheck → 最终 authority/SQL clock → COMMIT。没有新增控制授权。 |

`/relay` 接收者要求 worker 已通过原 `/worker/v1` Authorize 登记 process；生产 worker 当前没有自动发送新 relay 协议，B 的 sender 需在这个时序后调用该 endpoint，并附原 client certificate 和 bound Pod bearer token。入口返回成功仅表示该 worker 消息持久化，不等于备份成功、成品发布或 acceptance。

relay 游标改为在原 Job 行锁下读取 `system_backup_v2_relay_receipts` 最新原字节。它不再占用 `job_observations` 的 `running/sealed` 序列；两个协议的状态不能混用。最新原字节/hash/Job身份一致才允许 replay；未知提交结果不冒充成功。此修改不需要覆盖 migration 124 或恢复未版本化 SQL。

## 固定部署参数

保留原 `system-backup-public-deployment.v1` 参数，显式选 `capture_scope=runtime-workspace`，增加 `runtime_sources`：

- `supported`：B `AgentKind` 的完整 `Type/Mode/Variant/OS` 组合，仅受支持 Linux 类型。
- `namespaces`：必须只有一个条目，且等于 deployment 的 `namespace`；平台 writer、Runtime Deployment 也必须在同一 namespace，不生成跨 namespace 的控制 Role。
- `workspace_root`：来源容器内的原 workspace 根路径；本 profile 只接受与目标采集 PVC 同一 PV、对应子路径的实际挂载。HostPath/其他存储需独立 profile，不会以路径字符串替代存储身份。
- `lease_participants`：全部经审查的 application mutation lease participant ID；不是“所有未知 participant 都返回成功”。
- `deployments`：Runtime 所属 Deployment 的 namespace/name/UID，用于真实 HPA/节点及恢复探针。
- `agent_token_file`：Lite 必需，私有文件，内容不进入计划/日志。
- `agent_ca_file`、`agent_ca_sha256`：Lite 必需，固定 pool Agent 证书的 CA PEM 原字节及 SHA256。D 只接受与运行 Pod IP 相符的 `https` 端点，TLS 1.3 校验 `lite-agent.clawmanager.internal`；证书或端点不匹配时拒绝发现和停止。
- `gateway_originals`：逐来源 `Source` 完整身份、`file` 加密收据路径、`cipher_sha256`、`plain_sha256`、`key_ref`。旧 generation 与当前 SQL/原 binding 必须相等。

同一 CA 也必须挂载到主应用，并设置 `RUNTIME_AGENT_CA_FILE` 与 `RUNTIME_AGENT_CA_SHA256`。主应用保留旧 Pod 的 HTTP 生命周期调用；新 pool 的 HTTPS 调用使用固定 CA、TLS 1.3 和内部证书名。只配置路径或只配置摘要会使主应用启动失败，防止新实例在证书未配齐时被调度。

source 只读连接和控制连接必须指向同一 database/server UUID；账号仍分离。SQL 授权由 `system-backup-controller-grants -runtime-control` 输出；Kubernetes 授权仍用 `-kubernetes-config` 和固定 SHA 输出，新增权限仅在显式 runtime namespaces。生成工具只输出待审查授权，不自行应用。

## 原 generation 配置的真实来源

原 `RuntimeScheduler.createGatewayOnPod` 最终通过 `services.NewRuntimeAgentClient().CreateGateway` 发出请求。该真实客户端新增显式启用的加密留存，在 POST **之前** fsync 保存实际请求，包括原 Environment/port/UID/GID/limits/generation；不会调用 scheduler 重新计算原配置。

运行实际创建请求的 backend（以及需要留存后续恢复 generation 的控制器）配置：

```text
RUNTIME_CREATE_RECEIPT_DIR=/private/runtime-originals
RUNTIME_CREATE_RECEIPT_KEY_FILE=/private/keys/runtime-original-v1
RUNTIME_CREATE_RECEIPT_INSTALLATION_ID=<真实 installation_id>
```

目录由部署者预建并独占写；key 为 32 字节私有文件。controller 的 forward/recovery 独立签名 grant 的 `RecordKeys` 均须明确包含相同 `key_ref` 和 key SHA256，挂载该版本 key。它仅是原配置 custody key，不是正式备份 DEK/KEK 或 provider 凭据。

文件名为 `gateway-<instance>-<generation>-<原请求SHA256>.enc`。将实际文件及其 ciphertext SHA256 固定到 `gateway_originals`，来源完整身份取现库只读 projection。重试先验证已有完整密文；不覆盖同名文件；端口重试保存不同 hash。部分参数/密钥/目录失效会拒绝 POST，防止产生无法恢复的新 generation。

启用留存前的历史 generation 若没有原始创建收据，本交付仍拒绝 Runtime capture。不能把当前配置、当前 ENV、source SHA 或一个手工同形 JSON 叫做原配置；需先获得现有真实收据，或在明确的测试实例生命周期操作中产生新 generation 后再采集。

## 现场验证和数据库路径

先在用户指定远侧主机、已有仓库目录执行只读检查：

```bash
bash scripts/system-backup-d-runtime-discover.sh clawmanager-zhanghui08-system
```

输出仅 context、namespace/Pod/Deployment/节点/SA/PVC/image 元数据；不读取 Secret、日志、环境值或凭据。拿到实际服务、数据库名和测试实例后，再绑定具体联调命令；当前不能声称真实 MySQL/Agent/Kubernetes 联调通过。

新的隔离测试数据库走仓库已审查 migration runner 初始化并校验 journal；现库先核对 migration journal/实际 schema，再按 reviewed migration 路径升级至包含 124 的状态，不能用 `CREATE IF NOT EXISTS` 掩盖旧表差异。Runtime Ready 会检查新增 custody/receipt 列，不等到停止实例后才发现缺表。

`4fe83bcd` 现库导入 profile 继续作为 D 的独立后续交付：需以现库 schema/语义及历史迁移事实构造输入 fixture、对照映射、升级验证和实际导入测试；本补丁没有以替换 source SHA 冒充完成，也没有运行现库升级。

## A 的正式 DEK 接点边界

现有 `PublicJobOwner.Authorize` 在 SQL commit 后返回 functional `Lease.DEK`，不能连接正式在线 provider。原 SQL 顺序为 engine/application gate → runtime capture（如有）→ maintenance lock → installation/config/task/attempt → 原 `runtime_resources` Job 行；relay 按此顺序使用 `FOR UPDATE` 锁 Job，`Revoke` 经独立 Recovery.CheckTx 后更新同一 Job 行，提交后才是已确认撤销。Revoke 之前先 Arm，物理删除后另由 `Stopped` 保存真实终止证明；revoked 位本身不是进程停止。

正式 `OriginalJobAuthority.WithUse` 需要在原 Job 本地同步使用 DEK，并与上述撤销锁/停止屏障共享线性化边界。若 Job 不持有原 SQL guard，仍需要受控 use-session 和终止证明；单次 HTTP recheck 后返 key 不够。此补丁仅交付锁序/实际接点事实，未把测试 mutex、空回调、functional Lease 或新 relay receipt 宣称为正式 provider 集成。

## 验证口径

新增本地边界测试覆盖：创建请求先留存后 POST、失败不派发、原 generation/installation/key/密文完整性、Runtime 固定配置和精确 RBAC、实际 PVC/子路径拒绝、生产 relay 路由拒绝匿名、Pod 等待异步停止证明，以及 relay SQL 的失败回滚/未知提交/replay/序列/旧 attempt evidence 边界。这些测试使用 SQL driver 和 Kubernetes fake；真实现场验证状态仍为待执行。

本轮本地结果：`runtimecustody`、`systembackupexecution`、`systembackupcontroller`、`quiesce`、`publicadapter`、`cmd/system-backup-v2-controller` 完整包测试通过，grants 命令编译通过；`services -run '^TestRuntimeAgent'` 通过。只读脚本 `bash -n` 通过。测试使用独立临时 Go cache/tmp，测试结束清理，不提交二进制或构建缓存。

## 现场 NFS 路径与后续验收

用户确认这是测试环境，最终目标是多用户环境成功备份、恢复。保留实际 NFS 路径作为验证对象；PVC-only 通过不能替代此目标。以下是只读现场证据和待实现工作，不代表新增 profile 已可运行。

用户进一步明确产品边界：在指定 namespace 部署的页面操作，仅备份和恢复该 namespace 对应的数据。服务端需固定 namespace 身份与 installation、数据库范围和 NFS 数据子树的归属；不能因为页面位于该 namespace，就推定共享数据库或 NFS 根目录全属于它。其他 namespace 不自动加入备份、停止或恢复范围；如果来源实例确实位于范围之外，应明确报出范围不匹配，不能静默漏掉实例，也不能自动扩大权限。跨 namespace 读取只是此次管理员现场排查共享存储关系的手段，不是普通备份页面应具备的集群权限。现在已强制 deployment/writer/Runtime namespace 一致；NFS 数据子树归属的完整强制校验仍待实现。

现场 app、OpenClaw、Hermes 挂载的是同一个直接 NFS export `/`，其 Service 位于另一 installation 的 namespace。本 namespace 的 workspace PVC 则绑定另一条 hostPath，不能拿该 PVC 的内容代表正在使用的数据。不能仅凭 namespace 名切换 NFS server，也不能将另一个 installation 的写入者自动纳入停止授权。

2026-10-30 现场 App 容器的 `/proc/mounts` 再次直接确认：`/workspaces` 来源为
`10.107.165.245:/`、类型为 `nfs4`。同一条命令中的 `du -sk /workspaces`
结果未随回传出现，因此容量仍未知；只将挂载身份列为已验证。该 IP 对应
前述另一 installation 的 `workspace-store` Service，不能把本 namespace
的 hostPath PVC 或整条共享 NFS export 当成本 installation 的独占备份源。

同日对现库三个运行实例的已登记 workspace 子目录只做 `stat`：

| instance | device | inode | UID | GID | mode |
| --- | ---: | ---: | ---: | ---: | ---: |
| 7 | 86 | 105775331 | 200007 | 1000 | 750 |
| 8 | 86 | 105775467 | 200008 | 1000 | 750 |
| 11 | 86 | 105775316 | 200011 | 200011 | 750 |

三目录均存在且位于同一 NFS 挂载，属主和组并不完全相同。恢复验收须保留
各目录实际 UID/GID/mode，并逐实例核对目标路径；这些元数据尚不能证明
目录由本 installation 独占，也不能将整条 export 视为备份范围。

现库只有 user 1 的三个运行 Lite 实例，原 `instances.pod_name/pod_namespace` 为 NULL；实际位置来自 `instance_runtime_bindings → runtime_pods`，后者 `pod_uid` 也为 NULL。另有 generation 0 的未启动 Pro 实例。因此当前运行证据既不能证明多用户隔离，也不能通过 D 现有要求非空原 Pod 身份的控制链。后续需保持原 source projection/hash 不变，另行冻结实际 Runtime locator，交叉验证 Kubernetes UID、Agent 身份及原绑定，并在执行/恢复时复查；不得靠回填 Pod 名或虚构 generation 修复。

数据库为 MySQL 8.4.8，迁移 ledger 到 080，仅发现旧 `system_maintenance_participants`。它不是新版完整 participant registry。`4fe83bcd` 导入 profile 仍由 D 独立负责：需覆盖现场 080 的真实 schema 差异，并与仓库已审查导入基线区分。在独立数据库副本上验证保留用户/实例主键和关系、迁移 journal、导入结果及重跑边界，再形成现库升级步骤；新环境继续使用当前 reviewed migration runner。不能只修改 source SHA，也不能直接向旧库执行全部新增 SQL。

只读盘点命令（现有远侧仓库目录；本脚本仅需 Python 3 和 kubectl）：

```bash
python3 -B scripts/system-backup-d-nfs-inventory.py \
  --context kubernetes-admin@kubernetes \
  --namespace clawmanager-zhanghui08-system \
  --server 10.107.165.245 --export /
```

该脚本跨 namespace 枚举直接 NFS、绑定身份匹配的 NFS PV、容器/init/ephemeral 挂载及工作负载模板；列出 Service/EndpointSlice/实际 exporter Pod 的存储链。输出只有白名单元数据，不打印 env、启动命令、Secret、日志或文件内容。不执行 exec、数据库查询或任何集群变更。无法读取任何一类资源时返回 `incomplete` 和非零退出码，不用空清单冒充成功。

默认输出已缩为有数量上限的摘要：本 namespace 的匹配 Pod、未解析挂载数量，以及同 NFS 的外部挂载冲突候选数量。外部候选明确排除在备份范围外。其他 namespace 未知 PVC/CSI 仅计数，不再倾倒其历史 ReplicaSet 明细；需要核查详细证据时显式传 `--full`。摘要不会将模板数量视为实际运行 writer 数量，也不会因输出缩短而宣称 writer 清单完整。该修改的本地测试共 11 项通过，使用 `-B` 未生成构建或字节码产物。

该输出是候选写入者清单，始终标记 `writer_coverage_proven=false` 和 `ready_for_backup=false`。Kubernetes 外部 NFS 客户端、未知 DNS 别名、CSI、文件系统别名/符号链接、export 实际目录及访问权限仍需核实；多次 API 读取不是一致性快照。特别需要确认两个 installation 是否共用同一目录树，不能假定同名 `user-1/instance-7` 属于同一用户。发现跨 installation 目录重叠时先明确数据所有权和迁移方案，不能继续把整 export 作为本 installation 的恢复目标。

实施顺序及出口：

1. **数据范围**：将 installation、NFS endpoint/export、实际目录与用户/实例关系绑定；明确独立采集子树。盘点所有实际和可重新创建的写入者。未知 writer 或跨 installation 范围不明时不进入停止阶段。
2. **Runtime 控制**：补空 source locator 的真实映射、UID/Agent 交叉验证、未启动 generation 0 的明确合同；保留原 source 字节语义和恢复 CAS。启用真实创建请求的加密留存后，使用受控测试实例生命周期产生新 generation 收据；当前 ENV 或手写 JSON 不能替代历史原配置。以原配置加密读取、实际停止证明、完整 probes 和 relay 持久化完成 B 接入。
3. **一致性采集**：在同一授权和维护周期内关闭入口、暂停后台和 Runtime writer，核实停止证据，再捕获对应 SQL 状态与 NFS 子树。固定 export/目录身份及完整 writer 清单到计划，最终复查后提交。`runtime-workspace` 已增加显式 NFS 采集构造和来源 Pod 挂载核对，但仅限安装专属子树的功能测试配置；现场共享根目录仍不符合准入条件。
4. **首次恢复**：在同一 NFS 上预留独立、可核实归属的测试恢复目录，配合隔离数据库及测试实例恢复，避免覆盖原目录。保留用户和实例主键关系；仅按明确的目标位置映射调整 workspace locator。不能将另一个 installation 的相同数字 ID 当作同一主体。原配置解密、ClaimRestart/CompleteRestart 及恢复 CAS 必须沿真实 caller 执行。
5. **多用户验收**：至少两个用户，各自独立样本、同名但不同内容文件、目录、权限和运行实例；验证文件 hash、UID/GID/mode、用户/实例归属、用户间访问隔离、真实 Agent 重启及恢复后的读写。并发写入必须被 fence；停止失败、绑定漂移、部分失败及重复恢复不得冒充成功。首次恢复验证后，再单独设计原实例切换和回退。

NFS 盘点工具本地 8 项测试通过，覆盖跨 namespace/DNS/endpoint、PVC UID 漂移、hostPath 与 NFS 区分、CSI 未解析状态、子路径边界、只读标志和失败不泄露输出。使用 `python -B`，不产生字节码或构建产物；此结果不代表现场 NFS、MySQL 或 Agent 联调通过。

## 安装专属 NFS 功能测试范围

`runtime-workspace` 的部署配置现在允许 `workspace.nfs={"server":"<固定 IP>","export":"<绝对导出路径>"}`，此时 `workspace.claim` 必须为空，`workspace.sub_path` 必须精确为 `installations/<SHA256(installation_id)>`。采集 Job 以只读 NFS 卷和该 subPath 构造；部署权限不再请求空名称的来源 PVC。运行中实例必须映射到本 namespace 的真实 Pod，Pod 在对应实例路径上的挂载必须是相同 NFS server/export，并位于该子树；已停止实例的登记路径也必须在该子树内。此配置仅用于 `runtime-workspace`，不能绕过 Runtime source 核对。

此规则不会准入现场现有 `/workspaces/openclaw/user-1/instance-*` 路径，也不会将 `10.107.165.245:/` 根目录视为本 installation 的独占数据。还需在隔离测试安装下准备新子树、使 Runtime 和 App 确实写入该树，并验证 NFS exporter 身份、符号链接与其他客户端写入者。当前 `BuildParts` 仍标记 `acceptance_ready=false`；本节只描述功能测试的采集入口，不宣称多用户备份或恢复已闭环。

## 原 source 与实际 Runtime locator 的版本化交接

`RuntimeWriterSpec` 新增可比较的 `Runtime RuntimeLocator`（JSON `omitzero`，原有无 locator 的 custody 字节不因零值增加字段）。D 生成 `Version=runtime-locator.v1`，字段为 `Namespace/Pod/RegisteredPodUID/Deployment/AgentEpoch/RuntimePodID/GatewayPID`；实际 Kubernetes Pod UID 仍在 `spec.UID`，endpoint/port 仍使用原 spec 字段。B 通过 `RuntimeNamespace()`、`RuntimePod()` 获得有效定位；旧 custody 回退到原非空 source 定位，不重新发现或回填。

`Source` 仍是原 `instances` 投影，包括空 Pod/namespace；source inventory/hash 不变，B 继续逐字段匹配 source。新 `ResolveGatewaySource` 是只读查询，通过原控制连接读取实际 binding，而不扩大 source 只读账号的 SQL 权限。它先拒绝 namespace 越界，再核验 generation/workspace/gateway/port/PID、注册 UID（若有）、Kubernetes Pod UID/Ready/IP、真实 ReplicaSet→Deployment UID 和固定部署探针，最后核验 Agent UID/epoch/协议能力。NULL 注册 UID 只表示未登记，不生成或修改该列；实际 UID 取控制面并与 Agent 相互验证。

`Prepare` 使用该投影，原授权事务下 `save` 再锁原 source 和 binding；`Guard/ClaimRestart/CompleteRestart` 复查同一 Runtime row ID、注册 UID、endpoint、PID、Agent epoch 和原身份。读取原配置仍用未改写的 raw source，重启预留和原恢复 CAS 沿用原链。部署预检的实际卷检查也先解析 Lite locator，不能拿空的 `instances` Pod 字段拼 API 地址。单 namespace 的配置、资源访问授权和运行时定位检查均拒绝越界，而非过滤后继续备份。

这些是定位及范围校验的实现，不是完整 quiesce 实现。2026-10-29 用户执行 `system-backup-d-agent-capabilities.py`，远侧 `openclaw-runtime`、`hermes-runtime` 均返回 HTTP 404；公开读回存于 `docs/evidence/d-runtime-agent-capabilities-20261029.json`。脚本只在目标 namespace 内读取元数据，通过 Deployment/ReplicaSet UID 选择 Pod；仅在远侧内存中使用 app 现有控制 token 发起能力 GET，不打印 token/任意响应体、不发送停止请求。返回 404 不作为成功或空进程证明。

此现场证据要求继续补 Agent 协议与构建/部署接点：现有文档的 `process_group` 能力本身也不覆盖脱离进程组的工作进程，且没有完成原代次受控恢复协议。不能只部署一个返回能力 JSON 的 handler、复用升级中的不可释放隔离，或把 DELETE/404 当作备份停止证明。generation 0、直接 NFS admission、完整 writer fencing、旧库副本导入及多用户恢复仍是未完成项。

本次映射更新验证：`systembackupcontroller`、`systembackup/publicadapter`、`systembackupexecution`、`cmd/system-backup-v2-controller` 测试通过，`cmd/system-backup-controller-grants` 编译通过；Agent 只读探测脚本 7 项测试通过。边界覆盖 raw source 不改写、旧 custody 零 locator 字节兼容、注册 UID 缺失/漂移、Pod IP/owner/Ready、Agent epoch 漂移、PID 缺失、跨 namespace 在 API 调用前拒绝、越界 Role 不生成，以及探测凭据不进入输出或命令参数。SQL-driver/Kubernetes fake 的通过不替代真实 MySQL/Agent/NFS 联调。测试缓存和临时构建目录在测试结束后删除。
