# ClawManager P0 分阶段备份与恢复计划

第一阶段在现有管理员「系统备份」页面交付「备份（试行版）」，并验证管理员可在没有 C1 接管记录 `head1` 的环境中发起备份和完成隔离恢复。恢复后，原有用户和实例仍存在，实例归属正确，静态配置可读，代表性实例可按配置启动。

## 分阶段计划

| 阶段 | 交付范围 | 验收标准 |
| --- | --- | --- |
| 1. 用户、实例和静态配置 | 管理员从现有页面发起「备份（试行版）」。备份用户身份、账号状态、角色和配额，实例归属与规格、启动所需静态配置及必需引用。管理员使用试行产物执行隔离恢复。 | 正式备份未启用且没有 `head1` 时，管理员可发起试行备份并看到任务状态和独立读回结果。用户与实例 ID 对账通过，归属及静态配置一致。用目标环境测试凭据验证用户视角，抽样启动覆盖现场使用的实例类型。 |
| 2. 用户内容 | 接入对话记录、用户上传及生成文件、实例工作区。按原 P0 范围逐类纳入其他数据。 | 抽样用户能读取原对话及文件，逐类核对数量、摘要、归属及权限。 |
| 3. 正式入口与整单验收 | 完成正式备份的首次接入和启用，从现有页面发起真实整单备份，再做隔离恢复。 | 用同一 `TaskID` 核对采集、业务恢复、上传、独立读回、目录登记和任务成功，并按业务数据类别记录隔离恢复结果。 |

## 跨集群验收

集群 1 从管理员页面生成试行备份并独立读回。将这份密文产物及其回执导入集群 2 的独立存储，通过部署密钥渠道单独下发对应的试行密钥。在集群 2 的管理员页面用原备份 ID 恢复，恢复应用只读取目标集群内的导入目录，使用集群 2 自己的数据库凭据和资源配置。

现场验收记录两个 Kubernetes 集群的独立身份、源和目标 MySQL UUID、同一备份 ID、密文摘要、目标读回与业务核对。集群 2 恢复期间应能阻断对集群 1 的访问。单集群内隔离测试用于预验证，跨集群现场回执用于验收交付。

2026-11-23 单集群搬运预验证通过。恢复任务 `8c45078a5100b1eb8d98779916636983` 使用原备份 `ed8aea21cdd9e341cd0d02b649bacbae`。现场实测目标导入卷不可写，目标无法访问源 Service 和 Pod。恢复用户只看到自己的两条实例，访问另一条返回 HTTP 403。实际跨集群验收仍需要第二套独立 Kubernetes 环境。

## 第二阶段首轮对话恢复

先用第一阶段已启动验收的 Hermes Lite 跑通一条原生对话。现有实例历史读取代码从对应用户和实例的工作区打开 `home/.hermes/state.db`。网关 SQL 表 `chat_sessions` 和 `chat_messages` 用于网关记录与审计，单独完成这两张表的对账无法证明用户能在实例聊天页读回原对话。

- 以源端已确认归属的测试实例为样本，核对原生会话和消息的实际字段、排序及引用。使用能读到已提交 WAL 内容的一致性快照，确认对话数据范围后接入试行加密与独立读回。
- 在空隔离目标把会话绑定到恢复后的用户和实例，核对会话、消息数量及摘要。用普通测试账号打开实例聊天页查看原对话，用另一账号验证越权被拒。随后用同一份产物向第二个空目标复跑。
- `scripts/system-backup-trial-hermes-history.py` 已实现离线采集和恢复组件。它使用 Hermes 的原生会话导出和导入方法，保留会话与消息顺序。恢复前检查实例归属参数与父会话关系，恢复后通过独立连接核对对话内容，再发布目标 SQLite 文件。本机 SQLite 夹具已验证 WAL、二次复跑、目标非空拒绝及读回不一致拒绝。
- Hermes 对话已接入试行密文，归属与 SQL 快照在写入和读回时都要一致。已用两个本机目录验证密文搬运、旧产物兼容和归属篡改拒绝。仓库固定的真实 Hermes Lite 镜像已在本机验证原生导入、socket 读回和错误实例拒绝。现场仍需验证恢复用户能打开聊天页里的原对话，并用另一普通账号验收越权拒绝。

## 第二阶段首轮工作区文件恢复

选定的实例用户文件目录已接入试行密文。服务按同一份 SQL 快照核对用户、实例及运行时类型，再归档选定目录的普通文件与子目录。本机 Linux 原生文件系统已验证上传样本与生成样本的二次复跑、内容和 POSIX 权限对账，以及已有内容不一致时拒绝覆盖。现场待以恢复的普通账号下载原文件并核对摘要，另以不同账号验证越权拒绝。完整工作区及其他文件存储仍按运行时类型继续覆盖。

## 试行版入口与执行

- **管理员入口**。「备份（试行版）」在系统备份页可见，正式备份尚未接入或启用时也可用。按钮由试行版的就绪结果控制，未就绪时显示缺项。服务端校验管理员权限和试行就绪条件。
- **独立就绪检查**。试行后端使用独立入口，检查源库只读权限、加密密钥和存储的写入及读回权限。所需授权、密钥和存储身份独立配置，无需 C1 接管记录 `head1`。
- **采集范围**。从 `users`、`user_quotas`、`instances` 和启动实际引用的配置记录确定表及字段清单。复用现有一致性快照、加密和隔离恢复逻辑，在采集时限定清单。对话、用户上传或生成的文件及实例工作区内容纳入第二阶段。
- **任务与产物**。页面显示试行任务状态、备份范围和独立读回校验结果。加密产物用于隔离恢复，正式恢复点目录仅登记通过正式验收的任务产物。

## C1 依赖判断

| 路径 | 当前结论 | 依据 |
| --- | --- | --- |
| 现有正式备份入口 | 当前现场的首次接入依赖 C1。需要完成接管、取得 `head1`、初始化配置并启用，正式入口才可接单。 | 备份任务创建走 `AdmitReady`。现有首次接入流程先导入 `head1`，再初始化 `disabled v1`。验收任务要求六类备份部件齐全。 |
| 第一阶段试行备份与恢复 | 按无 C1 路径交付管理员入口。现有 SQL 采集、加密和隔离恢复已有离线测试记录。页面发起到现场代表性实例启动的端到端流程待验证。 | 正式生产的 `users_instances` 模块同时组装数据库与实例工作区。试行版需要独立入口及明确的采集清单。 |

现有 API 接受 `functional_test` 请求选择 `mysql` 部件，创建任务仍经过 `AdmitReady`。`mysql` 表示部件范围，试行版的表和字段清单由独立采集入口执行。

## 查询方法

### 1. 查代码入口和配置来源

在 `backup` 工作树运行以下只读搜索。沿调用链分别记录任务准入、采集授权、产物写入与加密、独立读回、恢复五处依赖。

```powershell
rg -n 'AdmitReady|CanCreate' backend/internal/handlers/system_backup_handler.go backend/internal/systembackup/readiness.go
rg -n 'requested_parts|acceptance|functional_test' backend/internal/systembackupapi/task_requests.go
rg -n 'ImportOriginalPreColdHead1|InitializeOriginalDisabledUnverified' backend/internal/systembackupinstallationowner/install/original_first_adoption_production.go
rg -n 'users_instances|capture-database|capture-workspace' backend/internal/systembackupexecution/production_capture_modules.go
rg -n 'func (Capture|CaptureSource|Normalize|RestoreDrill|VerifyDrill)\b' backend/internal/systembackup/domain
rg -n 'OpenClawConfigSnapshotID|openclaw_config_snapshot_id|instance_config_revisions|openclaw\.json' backend/internal
```

以现场实际使用的实例类型为样本，追踪启动时读取的配置版本、注入快照、配置包以及资源引用。核对最终配置是从数据库生成、来自目标环境，还是存在必须保留的卷内文件。卷内若仅有个别启动必需配置，第一阶段按文件最小范围纳入。配置引用涉及目标环境的镜像、模型或凭据时，逐项记录重建或映射方式。恢复后的实例默认停止，首次启动由目标环境重新建立 Pod 和 Gateway 绑定。

### 2. 查现场数据库结构和引用完整性

用只读账号连接现场业务库。先运行结构查询，再按实有表和字段运行汇总检查。只记录数量和缺失项，避免在报告中输出用户信息、配置正文、口令哈希和令牌。

```sql
SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME IN (
    'users', 'user_quotas', 'instances', 'instance_config_revisions',
    'openclaw_injection_snapshots', 'openclaw_config_bundles',
    'openclaw_config_bundle_items', 'openclaw_config_resources'
  )
ORDER BY TABLE_NAME, ORDINAL_POSITION;

SELECT TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
FROM information_schema.KEY_COLUMN_USAGE
WHERE TABLE_SCHEMA = DATABASE()
  AND REFERENCED_TABLE_NAME IS NOT NULL
  AND TABLE_NAME IN (
    'user_quotas', 'instances', 'instance_config_revisions',
    'openclaw_config_bundle_items'
  )
ORDER BY TABLE_NAME, COLUMN_NAME;
```

有些引用由应用维护。确认字段存在后，用下面的查询补查实例归属与快照引用，并统计各实例类型的样本规模。若缺记录，先查清现场语义再决定纳入范围。

```sql
SELECT type, runtime_type, COUNT(*) AS instance_count
FROM instances
GROUP BY type, runtime_type;

SELECT COUNT(*) AS instances_without_owner
FROM instances i LEFT JOIN users u ON u.id = i.user_id
WHERE u.id IS NULL;

SELECT COUNT(*) AS instances_with_missing_snapshot
FROM instances i
LEFT JOIN openclaw_injection_snapshots s ON s.id = i.openclaw_config_snapshot_id
WHERE i.openclaw_config_snapshot_id IS NOT NULL AND s.id IS NULL;
```

### 3. 做一次无 C1 隔离演练

| 步骤 | 怎么做 | 留下的证据 |
| --- | --- | --- |
| 确认前置状态 | 在隔离环境确认没有 `head1`，也没有使用 C1 生成的授权、密钥材料或存储身份。测试源可以使用已获授权的快照或样本。 | 环境标识、C1 状态、只读源及存储和加密身份的来源。 |
| 从页面发起 | 保持正式备份未启用。验证管理员可以发起「备份（试行版）」，服务端拒绝非管理员请求和试行条件未就绪的请求。 | 试行就绪结果、页面任务标识及权限验证结果。 |
| 采集与独立读回 | 用一致性快照按清单采集必需数据，生成范围、计数和摘要清单，加密写入隔离存储。独立读回并验摘要，核对页面结果及正式恢复点目录。 | 试行任务状态、产物位置、加密与读回结果、源端和产物的对账结果，以及试行产物未登记为正式恢复点的验证结果。 |
| 恢复与核对 | 使用现有隔离恢复逻辑或经验证的最小适配，将产物恢复到隔离目标。核对用户与实例 ID、归属和静态配置，验证用户只能看到授权实例，并抽样启动。 | 恢复对账、用户视角和启动结果。用同一产物在新的隔离目标复跑，核对两次恢复的 ID 和记录数。 |
| 判定 C1 依赖 | 如果失败，记录第一个失败步骤、实际报错及所需材料的签发来源。 | 无 `head1` 仍通过采集、写入、读回和恢复，即可确认第一阶段具备独立交付路径。若某一步强制使用 C1 下发材料，则记录具体依赖，再决定复用独立权限入口或继续等待 C1。 |

## 本机跨集群演练

演练使用两套独立的 Kind 控制面和 MySQL 实例。源 `kube-system` UID 为 `f60a0ab2-a0fd-4dbb-8a25-d1f5aaa6191b`，目标为 `c8f90db4-54e9-4e8d-963c-088925b8fe5a`。源端生成试行备份 `0ae241210355b6e3d168e77de44a7140`，从只读挂载读回校验，随后保留加密产物与回执并删除源集群。目标只挂载导入产物，使用自己的数据库读写凭据，恢复任务 `71ae2854a3364d1f8951b4bbf0c09347` 通过。源和目标的密文 SHA-256 为 `14b44f100fc3aadf00126468671c1e65d8490a8d005f45c506f88b0d62219723`。

目标恢复了 2 个用户、2 个配额、2 个实例和 4 个工作区条目。用应用仓库层验证了普通用户的密码与实例可见范围，并从目标卷另行读回上传和生成文件。加入工作区卷预检后，使用同一备份对新的隔离数据库和工作区再次恢复，任务 `2ecae622c27d46f97eda75a99984afbe` 通过。该样本的配置修订和注入快照为空，聊天记录走单独的 Hermes 验收。现场浏览器操作与应用启动的证据由隔离验收流程记录。

测试构建临时产物使用 D 盘，测试结束后清理。
