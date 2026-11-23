# 试行备份部署与演练

试行入口位于管理员「系统备份」页面。服务端使用现有管理员会话校验，并校验账号处于启用状态。首次部署可以保持正式备份关闭。试行任务及产物使用自己的配置和存储，不需要 C1 的材料或 `head1`。

## 试行配置

下面的变量统一使用 `SYSTEM_BACKUP_TRIAL_` 前缀。路径指向 API 进程可访问的绝对路径。凭据和密钥文件应通过部署的 Secret 挂载，避免放入工作目录、日志或环境变量值。

| 后缀 | 内容 |
| --- | --- |
| `SOURCE_DSN_FILE` | 源库的独立 MySQL DSN。通过 TCP 连接远端数据库时使用 `tls=true`，并由部署安装受信任的 CA。 |
| `SOURCE_UUID` | 已核对的源 MySQL `@@server_uuid`。 |
| `KEY_FILE` | 64 位十六进制字符表示的 32 字节独立主密钥。保留与已有试行产物对应的密钥。 |
| `WRITE_DIR` / `READ_DIR` | 同一专用卷的两个挂载路径，分别可写和只读。存储应支持硬链接、原子创建和同步写入。就绪检查会加密写入临时探针，从只读挂载重开并校验。 |
| `RESTORE_DSN_FILE` / `RESTORE_READ_DSN_FILE` | 隔离 MySQL 的写入和单独的只读 DSN，指向同一个 `cm_drill_*` 库。只读身份只授予目标库的 SELECT。写入身份应限制在该库的读取和恢复所需数据修改。 |
| `RESTORE_UUID` | 隔离 MySQL 的 `@@server_uuid`。它必须与加密产物所记载的源服务器身份不同。 |
| `RESTORE_NAMESPACE` / `RESTORE_STORAGE_CLASS` | 演练环境专用的 `cm-drill-*` 命名空间和目标 StorageClass。 |
| `RESTORE_ISOLATED` | 操作员完成网络和身份隔离后设为 `true`。应用验证 MySQL 身份与库名，网络隔离由部署维护。 |
| `ENVIRONMENT_PROFILE_FILE` | 可选。只读挂载由平台登记的试行环境 JSON，记录部署位置、镜像摘要、PVC、服务账号和 Secret 名称。 |

源 MySQL 用户单独授予下列六张表的表级 SELECT。就绪检查拒绝角色、库级通配授权和写权限。部署时请将试行流量固定在一个启用了试行配置的 API 副本。任务运行状态属于该进程，已校验的备份产物和收据存在专用卷上，进程重启后仍可凭备份 ID 恢复。

## 从页面准备已登记的试行环境

源与目标各自挂载平台登记的配置，`side` 分别设为 `source` 和 `target`。在同一集群登记两个不同 namespace。下面示例为目标端，镜像填入该端实际可拉取的摘要。目标端的 namespace 和实例存储类需与 `RESTORE_NAMESPACE` 和 `RESTORE_STORAGE_CLASS` 一致。管理员可以从试行页下载该 JSON，并查看当前端使用的引用。

```json
{
  "revision": "trial-v1",
  "side": "target",
  "source": {
    "cluster": "site-a",
    "namespace": "cm-drill-source",
    "image": "registry.example/clawmanager@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "service_account": "trial-source-api",
    "artifact_claim": "trial-export",
    "key_secret": "trial-key",
    "source_read_secret": "trial-source-reader"
  },
  "target": {
    "cluster": "site-a",
    "namespace": "cm-drill-target",
    "image": "registry.example/clawmanager@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "service_account": "trial-target-api",
    "artifact_claim": "trial-import",
    "workspace_claim": "trial-target-workspace",
    "instance_storage_class": "isolated",
    "key_secret": "trial-key",
    "restore_write_secret": "trial-target-writer",
    "restore_read_secret": "trial-target-reader",
    "runtime_secret": "trial-target-runtime"
  },
  "prepare_job": {
    "name": "prepare-trial-v1",
    "uid": "11111111-2222-4333-8444-555555555555"
  }
}
```

平台先在当前端 namespace 建立 `spec.suspend: true` 的准备 Job，注解 `clawmanager.io/trial-environment-revision` 使用同一个 `revision`。登记其实际名称和 UID。Job 使用独立服务账号及受限的准备权限，在完成所需的 SQL 授权、Secret 或存储配置并验证后退出。保留该 Job 供应用检查结果。为应用服务账号绑定当前 namespace 的 `batch` `jobs` 权限，`resourceNames` 指定该名称，`verbs` 使用 `get` 和 `patch`。

管理员点击「准备试行环境」后，应用仅解除该 Job 的暂停，页面轮询任务状态。Job 完成后，备份或恢复继续使用原有的实时就绪检查。重复点击会读取同一任务状态。Job 失败且需要替换时，平台更新配置版本及新任务 UID。只需展示配置或沿用已人工配置的流程时，可以省略 `prepare_job`。Secret 内容保留在部署授权的文件挂载中。

## 数据范围

- `users` 和 `user_quotas` 保留身份、角色、账号状态、登录凭据哈希和配额。
- `instances` 保留 ID、归属和启动规格。恢复后清空旧 Pod、PVC、工作区路径、访问令牌及运行错误，设为停止。恢复时将存储类映射为目标环境配置。
- `openclaw_injection_snapshots` 采集被实例直接引用的渲染清单和启动环境。启动使用渲染结果生成目标 Secret。配置中心的包编辑历史和资源正文留在后续阶段。
- `instance_desired_state` 和 `instance_config_revisions` 仅采集当前请求的配置版本及其关联。恢复后的期望电源状态为停止。
- 对话、上传文件、生成文件及工作区内容留在后续阶段。产物与收据由试行存储管理，正式恢复点目录只由正式流程维护。

## 隔离恢复

在隔离 MySQL 上用当前版本的离线固定目标迁移入口预建结构。试行恢复允许迁移记录、可替换的默认管理员及其配额，以及目标库预置的镜像设置、技能标签、初始调度行和初始北向设置。预置行来自目标，试行恢复会记录其摘要并在写入后通过独立只读连接复核。已有的实例、任务、用户内容和正式控制记录会使恢复拒绝目标。

备份成功后记录页面上的备份 ID。从页面提交该 ID 进行恢复，检查任务完成及行数。恢复任务重新读回密文并验证摘要，写入后以目标 SELECT 身份核对 ID、归属、配置与行数。复跑时配置另一个新空库，使用同一备份 ID。

跨集群恢复时，从集群 1 的已读回试行产物中取同一备份 ID 的 `<id>.trial` 和 `<id>.receipt`，保留文件名，通过现场批准的渠道导入集群 2 的专用卷。文件全部导入后再挂载为集群 2 的 `READ_DIR`。试行密钥通过目标部署的 Secret 单独下发，目标恢复和独立读回 DSN 使用集群 2 自己的凭据。目标 API 仅需产物只读挂载及恢复配置，即可用原备份 ID 提交恢复。目标会以回执中的密文长度与摘要校验文件，再核对加密绑定、快照摘要和源 MySQL UUID。

## Hermes Lite 对话试行样本

在获准的 Hermes Lite 工作区运行 `scripts/system-backup-trial-hermes-history.py capture`，使用该工作区所属实例的用户和实例 ID。采集通过只读 SQLite 连接生成一致性快照，再用该 Hermes 版本自带的会话导出方法取得选定对话及父会话。将进程输出直接交给隔离部署的私有临时挂载，并把文件路径设为 `SYSTEM_BACKUP_TRIAL_HERMES_HISTORY_FILE`。回执和日志只记录聚合数据。试行服务确认归属与 SQL 快照一致后，将对话随原备份 ID 一起加密并独立读回。

目标部署在试行 API Pod 内增加一个使用同版 Hermes 镜像的容器，以该镜像中的 Python 启动 `system-backup-trial-hermes-history.py serve --socket /run/trial-hermes/history.sock --workspace-root /workspaces`。两个容器通过专用 `emptyDir` 共享 `/run/trial-hermes`，并使用具有该目录访问权的组。Sidecar 挂载目标演练工作区 PVC 和只读脚本配置，按目标 Hermes 实例的工作区身份写入。Unix socket 仅在同一 Pod 内使用，无需暴露 Service 或端口。

仓库固定的 Hermes Lite 镜像 `ghcr.io/yuan-lab-llm/agentsruntime/hermes-lite@sha256:4fd519962d0afe796b36dade6f8e66379e7030a2c6f3c62b4a6574352b2eac44` 已通过本机原生测试。该镜像使用 `/opt/hermes-agent/.venv/bin/python`，并将 `/opt/hermes-agent` 加入 `PYTHONPATH`。在断网容器中用原生 `SessionDB` 创建一条合成会话和两条消息，经 socket 导入、读回相同摘要，并拒绝错误实例请求。

API 容器设置 `SYSTEM_BACKUP_TRIAL_HERMES_HISTORY_SOCKET=/run/trial-hermes/history.sock` 和 `SYSTEM_BACKUP_TRIAL_HERMES_HISTORY_TARGET_ROOT=/workspaces`。先在目标 PVC 创建该实例的 `home/.hermes` 空状态目录。启动验收部署保持同一工作区根及实际 PVC。应用在写 SQL 前检查 sidecar 与目标工作区根，之后经本机 socket 发送已认证的对话。Sidecar 独立读回一致后发布 SQLite 文件。若 SQL 已恢复，可用原备份 ID 重试。重试先核对目标 SQL 与产物，再恢复缺失的对话或核对已发布的对话。

浏览器取证脚本可在集群 1 用 `BACKUP_TRIAL_CAPTURE_ONLY=1` 仅发起备份，在集群 2 用 `BACKUP_TRIAL_REPLAY_ID` 恢复导入产物。两端设置 `BACKUP_TRIAL_HERMES_HISTORY=required` 可分别验证对话计数和摘要。普通用户在 Hermes 聊天页读回原对话的验收单独取证。

## 工作区用户文件试行样本

将获准实例的工作区快照只读挂载到 `SYSTEM_BACKUP_TRIAL_WORKSPACE_FILES_SOURCE_ROOT`，目录布局沿用 `<runtime>/user-<id>/instance-<id>`。`SYSTEM_BACKUP_TRIAL_WORKSPACE_FILES_SELECTION_FILE` 指向包含 `user_id`、`instance_id` 和 `relative_dir` 的 JSON 文件。本轮每个产物选择一个用户文件目录，支持现有 Gateway Lite 的 Hermes、OpenClaw、OpenCode 和 DeepSeek Harness。服务以同份 SQL 快照核对实例归属，归档选定目录的普通文件和子目录。选定目录的最大归档大小为 32 MiB。实例运行配置和状态目录按各自的恢复流程处理。

恢复端挂载独立的目标工作区卷，将它配置为 `SYSTEM_BACKUP_TRIAL_WORKSPACE_FILES_TARGET_ROOT`。预先创建对应实例及选定目录的父目录。申请恢复时选定目录应尚未创建。成功后可以用同一备份 ID 复跑，服务会独立读回已存在的同内容目录。目标卷需支持 Linux 无覆盖原子重命名。恢复开始写数据库前，服务会在目标目录旁验证发布能力并清理探针。现场试行的 Longhorn RWX（NFSv4）卷对此操作返回 `EINVAL`，普通重命名替换临时空目录也返回 `EEXIST`。现场优先用独立 RWO 卷验证工作区恢复，归档存储仍按自身的挂载和读写条件检查。服务先在独立暂存目录写入并校验内容及 POSIX 权限，再发布到原相对路径。保持同一实例的目标运行 UID/GID 配置，启动验收 API 与运行池使用该工作区卷。

设置 `BACKUP_TRIAL_WORKSPACE_FILES=required` 核对备份和恢复的工作区条目数、字节数和归档摘要。向运行时取证脚本的普通账号清单加入 `workspace_files`，用应用已有下载接口核对文件大小和 SHA-256。另一个账号的清单可加入 `forbidden_workspace_file`，从同一接口验证 HTTP 403。用于下载核对的 `path` 相对于应用的工作区文件根。

## 隔离实例启动样本

用单独的隔离应用部署打开已经对账的 `cm_drill_trial_*` 目标。部署负责人提供独立的 MySQL、Kubernetes 身份、工作区、存储类、镜像和模型访问。网络策略须阻断生产依赖访问。普通应用入口依旧拒绝 `cm_drill_*` 及现有受保护格式的 `cm_restore_`、`cm_import_` 演练库。

在样本部署中设置 `SYSTEM_BACKUP_TRIAL_RUNTIME_BACKUP_ID` 为已恢复的备份 ID，并配置 `SYSTEM_BACKUP_TRIAL_RUNTIME_DSN_FILE`。该专用身份只授予目标库 `SELECT, INSERT, UPDATE, DELETE`。同时提供试行只读产物挂载、试行密钥、目标独立只读 DSN、目标 UUID 及原隔离和存储配置。应用数据库名必须等于目标库，常规 Kubernetes 命名空间、运行时命名空间和存储类必须与试行恢复配置一致。样本部署使用隔离的本地账号，并关闭企业身份、IEI、北向及正式备份入口。

准备试行运行库时，用现有固定目标迁移任务的 `-apply` 和 `-prepare-trial-runtime` 选项。保留目标库名、MySQL UUID 和迁移目录摘要的固定参数。任务仅对指定的 `cm_drill_trial_*` 库创建空的 `trial_runtime_admission` 表。使用持久化目标工作区卷，把应用工作区根设为卷的挂载目录。

首次启动从只读挂载重开密文，以独立 SELECT 身份核对停止状态、归属、静态配置和产物包含的用户内容。对账通过后，应用把对应的启动核验记录写入目标库及工作区卷。以后重启继续检查密文、账号、已应用迁移和记录绑定的 MySQL、命名空间、存储类与工作区。应用保留启动后用户产生的变更。首次对账仍要求目标与产物一致，因此旧版本中已发生业务写入且没有核验记录的目标，无法直接补录。

使用演练用户登录并检查自己的实例列表，随后按现场类型抽样启动。目标应用重建 Pod 和 Gateway 绑定。

现场可用 `node e2e/backup-trial-runtime-click.mjs --help` 查看取证参数。每个普通用户使用一份预先从获准样本记录提取的清单，填入该用户的全部恢复实例 ID、类型和模式，另填已知属于其他用户的实例 ID，以及本次选择启动的样本 ID。脚本使用恢复后的测试凭据实际登录，并读取样本 App 提供的备份 ID 和命名空间。身份或归属不一致时，脚本会在点击启动之前退出。启动清单为空时只验证登录和可见范围。

根据源端的类型与模式清单选择覆盖样本。脚本记录从页面点击一次启动后的应用可用状态。现场取证同时记录目标集群、目标命名空间、实例 ID、对应 Pod 的 Ready 状态，以及 Lite 样本的当前 Gateway 绑定。Pro 实例的用户命名空间由应用基于试行前缀和用户 ID 派生，Lite 运行池使用试行运行时命名空间。

Pro 样本按 `instance-id` 标签在目标用户命名空间内定位 Pod。若演练与生产共用集群，在创建样本 Pod 前预先建立参与演练的派生用户命名空间，并验证其中的出站隔离实际生效。Lite 样本可用以下只读查询核对当前代次的 Gateway 绑定，再在已确认的目标集群按返回的命名空间、Pod 名和 UID 对应 Kubernetes 的 Ready 状态。将查询参数绑定到获准启动的实例 ID。

```sql
SELECT i.id, i.runtime_generation, b.state, b.gateway_port,
       p.namespace, p.pod_name, p.pod_uid
FROM instances AS i
JOIN instance_runtime_bindings AS b
  ON b.instance_id = i.id AND b.generation = i.runtime_generation
JOIN runtime_pods AS p ON p.id = b.runtime_pod_id
WHERE i.id = ? AND b.state = 'running' AND b.gateway_port > 0;
```

## 2026-11-23 本机验收

使用两个仅监听回环地址的 MySQL 8.4.13 进程，分别承担源和恢复。源库仅建样本业务表，环境无正式备份配置及 C1 `head1`。

`TestTrialMySQLRoundTrip` 使用备份 `f9df0b5ac1196af29d7839bbea5b1a78`，从独立路径重开密文并校验，然后恢复到同一隔离服务器上的两个新空库。两个目标均通过各自的 SELECT 身份完成对账。

| 检查 | 两次恢复结果 |
| --- | --- |
| 用户及配额 | 各 2 条，普通测试用户的口令哈希可验证 |
| 实例 | `101 → 10`，OpenClaw Lite，停止。`202 → 20`，Hermes Pro，停止 |
| 用户视角 | 应用仓储以用户 20 查询时仅返回实例 202 |
| 静态表 | 引用的启动快照、配置版本及期望状态各 1 条 |
| 范围排除 | 两个目标的会话样本表均为空，源的无引用快照和历史版本均未入包 |

本机通过了 TypeScript 与 Vite 构建、管理员鉴权、读回路径可写时的拒绝、错误密钥和密文篡改测试。该轮从后端测试入口执行 MySQL 演练，使用 Windows junction 提供第二条文件读取路径。同日的浏览器与只读挂载复验见下节。

## 2026-11-23 本机页面复验

使用 Edge 打开正式备份关闭模式下构建的管理员「系统备份」前端。临时服务装配了试行路由、管理员中间件和真实 MySQL 仓储。认证使用夹具账号。两个 MySQL 实例与产物卷均为本机临时资源，环境没有正式控制面或 C1 `head1`。同一 Docker 专用卷以可写和只读两个挂载交给试行服务。正向采集通过了实际只读挂载的就绪检查。

| 操作 | 页面及服务端结果 | 任务 ID |
| --- | --- | --- |
| 点击创建试行备份 | HTTP 202，成功，独立读回通过 | `0d516c3e3681352ae0d489c397a1dc4e` |
| 点击恢复到第一个空库 | HTTP 202，成功，读回及恢复对账通过 | `daf475a281d41a31055060b7be40b129` |
| 用同一备份 ID 从页面恢复到第二个空库 | HTTP 202，成功，读回及恢复对账通过 | `ee2914af52afa6434be6763ae444196b` |

两个目标的数据对账一致。用户、配额、实例各 2 条。启动快照、期望状态和配置版本各 1 条。实例 101 属于用户 10，类型为 OpenClaw Lite。实例 202 属于用户 20，类型为 Hermes Pro。两条实例均为停止，两库的会话样本表均为空。

复验使用仓库脚本 `e2e/backup-trial-live-click.mjs`。运行 `node e2e/backup-trial-live-click.mjs --help` 查看隔离目标、登录和复跑参数。脚本从页面提交，跟踪同一任务 ID，并核对页面成功和读回标记。完整 ClawManager 服务本轮仍在正式备份包的 `Binding.Retention`、`SameGuardedTransaction` 等未定义符号处构建失败。主对话负责完整服务的远程隔离部署和现场实例启动验收。

## 2026-11-23 完整迁移与启动准入复验

本机使用两台独立的 MySQL 8.4.13，按工作树固定的迁移目录构建目标。当前完整迁移目标有 178 条迁移记录、9 条镜像设置、10 条技能标签、1 条初始调度和 1 条初始北向设置。恢复保留这些目标预置行，并通过独立 SELECT 连接核验。已使用的调度状态会拒绝恢复，恢复之后预置行发生变化会被独立对账发现。

实际备份 `bf153ae57a653ee2514f0e9420b11d00` 写入后，恢复到完整迁移目标并通过独立对账。恢复目标的样本启动入口在约 4.5 秒内验证并建立应用 SQL 会话。通过应用仓储验证了普通测试用户的测试口令和其自有的停止实例。尚未恢复、命名空间不匹配和已恢复实例状态被改动时，样本入口均拒绝启动。原有普通应用拒绝正式和试行演练库的回归测试通过。

该轮验证覆盖恢复后的完整迁移结构与应用 SQL 准入。完整服务构建仍被正式备份包的未定义符号阻塞，现场实例的 Pod 和 Gateway 启动待主对话部署测试。

## 2026-11-23 现场取证脚本复验

启动样本 App 提供认证后的试行备份 ID 和命名空间。试行模块测试确认匿名请求和停用账号无法取得该身份，启用的普通用户可取得且响应禁止缓存。本机 Edge 使用合成 HTTP 夹具验证脚本的拒绝和成功路径。备份 ID 不一致或列表出现跨用户记录时均未提交启动，匹配时仅提交一次并记录应用可用状态。现场的真实用户登录、集群 Pod Ready 和当前 Gateway 绑定仍由主对话确认。

## 2026-11-23 独立现场构建

独立验收对话在 D 盘以 `c1182ed2` 为基线加入试行改动，完整前端的 TypeScript 和 Vite 构建已通过。读回了 Linux amd64 的完整服务和迁移程序，并确认完整服务二进制包含试行启动身份入口。现场独立 SSH 已认证，部署前正在检查目标集群的网络策略是否实际生效。

| 构建产物 | SHA-256 |
| --- | --- |
| `clawreef-server` | `8ffb3fe8a6de8f6a21c34f277dfe7381fc96f3d87bdc6c9e45a895bac1e1ed2f` |
| `system-backup-migrate` | `a23fa96a296562c704f44a391413a70da5e00d67ba0d900e434f2eefcc11abae` |

现场试行部署已建立独立命名空间和默认拒绝网络策略，浏览器 SSH 隧道仅监听本机回环。master 的 110 个 Pod 槽位占满后，试行 Pod 改在 node1 调度。产物卷的写挂载和只读挂载均已核对，专用 RWX 工作区已绑定，目标 MySQL 已通过独立 Pod 启动。源 MySQL 的首启日志出现 `io_setup()` 返回 `EAGAIN`，重启的 `MY-010457` 显示初始化中断后数据目录仍有残留文件。现场对话正在用独立源库 Pod 和关闭原生 AIO 的试行配置重试。此时现场页面任务尚未发出。

## 2026-11-23 现场管理员页面回执

独立现场验收对话已通过管理员页面提交备份及恢复，两次请求均返回 HTTP 202，随后页面和任务接口均报告成功及独立读回通过。备份与恢复均对账为 3 个用户、3 条配额、3 个实例。该批现场样本的启动快照、期望状态及配置版本记录均为 0。

| 操作 | 任务 ID | 备份 ID |
| --- | --- | --- |
| 试行备份 | `30e9019b4866e237d1427d0c9179c389` | `30e9019b4866e237d1427d0c9179c389` |
| 隔离恢复 | `e0e810c56e28621e0261e4475f397de8` | `30e9019b4866e237d1427d0c9179c389` |

已从现场浏览器回执和本机回环隧道复核以上结果。恢复用户视角、样本实例启动以及同份现场产物的第二目标复跑分别跟踪。

普通用户视角已通过现场浏览器回执。恢复账号的用户 ID 为 `1201`，通过恢复后的应用实际登录，实例列表只返回 `1201`、`1202`，读取另一用户的实例 `1203` 返回 HTTP 403。此回执使用空启动清单，实例启动与集群绑定由独立回执记录。

OpenClaw 的首次现场启动请求返回 HTTP 200，随后控制面尝试从默认 `clawmanager-system` 获取 Leader Lease，被演练身份拒绝，实例因此尚未通过启动验收。现场复验会把候选构建的 `POD_NAMESPACE` 对齐到演练命名空间。共享工作树的试行模式现已自动用核准的演练命名空间绑定 Leader Lease，本机三个试行启动相关回归全部通过。普通应用的 Leader Lease 配置仍走原入口。

现场第二目标复跑任务 `6dd954e234e3d454d279fac1b425c681` 使用原备份 `30e9019b4866e237d1427d0c9179c389`，独立读回和恢复均通过，仍为 3 个用户、3 条配额、3 个实例。候选应用对齐演练命名空间后，浏览器记录实例 `1201` 的 OpenClaw Lite 启动返回 HTTP 200，应用报告 `running/available`。同一回执中 Hermes Pro 实例 `1202` 的启动也返回 200，随后在等待阶段尚未达到可用状态。

扩展现场矩阵采用另一份试行备份 `d870a76ad036201658e823941730c86a`，恢复任务为 `4185a01351c8f5ba1c28b60e35802f15`。两次提交返回 202，随后均通过独立读回。两端各有 3 个用户、3 条配额和 21 条实例，覆盖 12 个类型，其中 OpenCode 和 DSH 均有 Lite、Pro 样本。配置计数为 21 条当前版本、21 条期望状态及 6 条引用快照。

带可启动配置的现场样本使用备份 `e31073257e6258a6b8349890df9021f5` 和恢复任务 `a223ec20ab23b436c627cac8a9d1ecda`。现场确认正式备份关闭且没有 C1 `head1`。两次任务均成功并通过独立读回，记录数与扩展矩阵一致，并对账了归属和启动规格。普通用户实际登录后可见自己的 20 个实例，访问另一用户的实例返回 HTTP 403。

现场确认 OpenClaw Lite 实例 `1201` 和 Hermes Lite 实例 `1302` 均达到 `running/available`，对应 Pod Ready，Gateway 健康探针返回 HTTP 200。Hermes Lite 在补齐演练前端 Service 后获得 Gateway 绑定。恢复用户的模型目录及补全请求均获 HTTP 200，补全返回预期的合成测试回复。历史 Hermes Pro/Gateway 组合的备份及恢复通过，启动停在 `creating`，现有 Gateway 调度查询仅接收 Lite 模式。

现场执行方确认专用命名空间、存储卷、存储类和暂存目录均已删除。本机复核 D 盘现场构建目录已删除。
