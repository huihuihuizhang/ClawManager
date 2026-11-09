# Longhorn keeper 接线和页面备份最小闭环

目标是在验证环境从现有页面提交一次 `functional_test` 完整备份。同一个 task/attempt 必须完成源卷保护、快照和六域采集、源业务恢复、keeper 回收、正式产物发布、独立读回及目录登记。已通过的专用卷 R3 结果作为存储基线。正式任务需要自己的证据。

## 1. 收口控制器接线

1. 在原停写意图落库后、物理停写前，复核当前 task/attempt、维护代次、writer 身份和签名源。创建固定镜像摘要、固定节点、只读挂载原卷且不挂载 SA token 的 keeper Job。
2. 用现有资源日志保存 keeper 计划、实际 Job/Pod/容器身份和 Node 注册请求。先持久化请求，再发 mTLS 调用。拿到经验证的 `prepared/rw` 回执并持久化后才放行停写。重试只复用原请求。
3. 所有 writer 已停后才执行采集。快照阶段从原日志读取请求，使用同一 keeper、claim 和设备身份执行 `state/acquire/check-held`。记录实际后端快照完成和冻结窗口的证据。单有 Kubernetes `ReadyToUse` 或 `held` 回执不能证明切点受保护。
4. 正常路径在快照完成后用原请求释放 Node hold，克隆采集可以在解冻后继续。失败路径在源恢复前用同一份请求核对和释放，包括已注册但还没生成快照授权的中断。普通采集 Job 全部停止且确认 release 后才恢复原 writer。writer 恢复验证通过后，按已记录的 Job UID 回收对应 keeper，随后确认该 writer 的恢复义务完成。keeper 在资源日志使用专用类型，仍由 Kubernetes Job 承载。
5. 在隔离的提交基线上编译并运行相关 Go 回归。优先覆盖回执丢失、同任务重试、换 keeper 被拒、注册后未生成快照授权的恢复、以及回收失败保留义务。Linux 原生用例和需要真实 MySQL 的测试应分别在适用环境执行。验证结束清理构建和测试目录。

通过条件是同一请求贯穿三个阶段，且代码从实际页面任务的控制器入口可达。把可审核的最小接线提交到 `backup` 后再准备部署。

## 2. 准备并更新验证环境

1. 在已有可用凭据的验证主机上只读核查 context `kubernetes-admin@kubernetes`、验证环境 `clawmanager-sbk-validation-system`、实际租户 namespace、签名源的 PVC/PV/Node UID、Snapshot API 和 `sbk-validation-longhorn-local`。检查 Pod 配额、Longhorn 双副本调度余量，以及 RWO writer 恢复时能否与 keeper 在同一节点挂载原卷。任何一项缺失时停在预检并记录缺项。
2. 从同一提交构建控制器、worker 和 Node owner，记录镜像及二进制摘要。用同一份签名 SourceRegistry 生成 LonghornVolumes，核对每个 Node 和控制器消费的材料摘要、mTLS 身份及授权范围。控制器在签名 RWO 租户中需要 Job 的 get/create/delete 与 Pod 的 get/list，以及对 `default` ServiceAccount 的具名读取。keeper 计划与回执 ConfigMap 在控制器 namespace。
3. 暂停备份接单，确认没有冻结和未完成的恢复义务。按节点停用并停止原 Node owner，使用审核过的旧二进制和 unit 摘要执行安装包的 `install.sh --apply --update-shared`。更新后校验 unit 参数、节点服务、卷授权摘要及控制器 mTLS 连接，再更新控制器和 worker。以实际镜像 digest 和配置回读为准。
4. 核对页面已有的 `创建完整备份` 入口、六域提交体及实时数据来源。现有页面用 `functional_test`。若旧 e2e 脚本仍断言 `acceptance`，这次用现有页面和同任务证据验收，脚本对齐另行处理。

### 部署交接与验收

| 顺序 | 输入与动作 | 达成目标与通过条件 |
| --- | --- | --- |
| 1. 固定镜像 | 从 `fb8e70c0718c1f6118c6ef7b7423e1e537a3ae17` 的独立源码构建 `app`、`backup-worker`。验证标签为 `sbk-validation-fb8e70c0-20261109`，仓库为 `10.130.14.23:5000`，镜像仓库名为 `clawmanager` 和 `clawmanager-backup-worker` | 推送后回读两份 `repository@sha256:…`。确认 Linux amd64、同一提交和仓库回读的配置摘要与本地镜像 ID 一致。部署清单固定两个摘要 |
| 2. 签名源与 Node 材料 | 复用验证环境的 `fresh-backup-enrollment-r2/enrollment.json` 和 `original-runtime-issuers/original-runtime-issuers.json`。按现有 owner 流程观测实际源并生成签名 SourceRegistry，依据签名源生成 `LonghornVolumes`，在 Node host definition 绑定 `LonghornVolumes` 与 `LonghornSourceRegistry` | enrollment 的安装身份及 namespace UID 必须对应 `clawmanager-sbk-validation-system`。校验真实 PVC/PV/handle、writer 与 Node UID、SnapshotClass、原卷健康、RWO 同节点恢复条件。生成可审核的签名源、卷授权和每节点安装包摘要 |
| 3. 安装 Node owner | 按 Node UID 下发同源卷授权。首次安装用已审核包的 `install.sh --apply`。已有 owner 时先排空恢复义务，按计划停用服务，再用原二进制和 unit 摘要执行 `--update-shared` | Node owner 服务 active。unit 指向正确的授权文件和 SHA256。Node 与控制器卷授权、mTLS 证书身份和端点一致。任一节点失败时保持接单暂停 |
| 4. 安装并启用控制器 | 使用验证 namespace 的安装身份生成 controller SA、限定源 namespace 的 RBAC、输入和 staging PVC、控制器 Deployment/Service。按安装流程生成并下发绑定该 Deployment 的 controller config、授权和 worker 镜像摘要，校验前置条件后启用接单 | 实际控制器 Pod 使用步骤 1 的 app digest，worker 配置使用配对 digest，控制器 Ready 并持有验证环境的领导租约。用实际身份通过 Kubernetes 权限、SQL 连接、mTLS 和运行时 readiness 检查。应用登录和页面读取仍正常 |

2026-11-09 的现场回执显示两个 Linux keeper 用例已通过。验证 namespace 的 Deployment、StatefulSet、DaemonSet 和 Pod 查询没有匹配到现有备份控制器。验证 enrollment 和 runtime issuer 回执存在，现场盘点未发现签名源注册表。使用验证 namespace 的安装输入，旧的 `zhanghui08` operator 入口不能直接用于该环境。

## 3. 执行一次页面验收

1. 在页面提交一单，保存 HTTP 202、实时数据来源、任务 ID、幂等键及最终使用的 attempt。提交响应不明时使用原幂等键查询或重试。
2. 依次核对停写前的 keeper 注册回执、原 writer 停写、实际后端快照完成、冻结解除、原 writer Ready 和原卷读写、同 UID keeper 回收、六域产物正式发布、独立读回、目录登记。记录每步的任务标识和对象 UID。
3. 同一 task/attempt 的上述证据齐全且任务为 `succeeded`、产物可用，才记为最小闭环通过。记录测试资源清理结果。若有步骤未确认，写明停点和恢复状态。

## 失败时的处理

| 停点 | 应看到的结果 |
| --- | --- |
| keeper 请求未持久化，或 Node 回执无效 | 原 writer 不停。使用原资源日志核对 Job 和 Pod |
| 注册回执丢失 | 按原身份查询或幂等重试。换 Pod、容器、claim 或请求摘要时拒绝 |
| 快照失败，或 freeze/release 结果不明 | 保留原任务日志和 keeper。用原 Node 授权确认 release。结果不明时保持恢复义务 |
| 原 writer 已恢复，keeper 删除失败 | 按原 Job UID 对账和重试。闭环保持未完成 |
| 发布、独立读回或目录登记失败 | 保留同任务证据，记录实际失败阶段 |

本轮验收止于这一单完整页面备份。DR `acceptance`、额外取证工具、通用存储改造和页面改版另行排期。
