# 租户 Pro / Longhorn 页面任务恢复交接（2026-11-11）

基线：origin/backup `4ec7a14a830d99ea816c4a598249faf76c2bc8fa`。
独立分支：`codex/pro-longhorn-recovery-20261111`；工作树：`D:/codex-worktrees/pro-longhorn-20261111`。

## 本次实际补齐

正式页面链已有租户 Pro Deployment 停写和 Longhorn keeper/native hold，本次复用它们。修复原任务恢复在两个外层入口仍依赖 forward 材料的缺口：

- `DeploymentService.inventory` 在 recovery-only 启动时，经 `PublicJobOwner.input(..., true)` → `SQLRecoveryAuthority` → `LoadRecoveryPlan` 解封原计划，比较完整 Discovery（含来源、所有 writer、所有 part），再进入已有恢复流程。避免当前 capture materials 不存在时拒绝或空指针。
- `attachRuntimeSources` 的 `BuildWriters` 与 `runtimeInventory` 在当前签源不可用时，要求同 task/attempt/authority/profile 的独立恢复授权，完整原 Source 和完整 frozen Writers 精确匹配，再交 `SQLRuntimeControl.BuildWriters` 从原控制行绑定。实例、generation、namespace、原 Pod、卷材料、writer/state 或来源摘要变化仍拒绝。新发现没有 frozen 列表，仍走原签源准入。

keeper 回收新增原任务卷身份复核：读取原 Namespace/PVC/PV UID、Bound/access mode、PV spec 摘要、claimRef 与实际 Longhorn CSI handle；任何替换保留 keeper 和恢复义务，避免业务 Ready 后对错误卷结清。该读取不持有 SQL 事务，随后再次校验独立恢复授权。

当前安装材料、完整额外 writer census、SQL 身份、PVC/PV/CSI handle 和 Node UID 检查继续由已有正式路径消费。

## 实际调用链及恢复顺序

页面任务 → controller/dispatch → publicadapter runner → LinuxProfile → attachRuntimeSources.BuildWriters → SQLRuntimeControl → DeploymentWriter。

停写前：`ExecutionJobPorts.PauseIntent` 先持久化恢复义务 → `PublicJobOwner.BeforeSourceStop` → 原 keeper plan/Job/实际进程登记 → `BindKeeper` 原 Node 注册 → 原 Deployment UID/RV 停写和真实停止证明。

采集：`prepareHeldLonghornMount` → `prepareLonghornCutSet` → 原 native grant → `Hold` → 实际 Longhorn VolumeSnapshot → 保存 cut pins → `Release`（中断也保留原 task/attempt 请求及恢复错误）→ clone/采集。

正常和失败恢复：原计划 inventory/BindWriters → 原 Pending 日志 → 停止所有 collector 并确认 → `BeforeSourceResume` 按原 native/keeper 登记 release → DeploymentWriter.Resume/ConfirmResumed（原 UID/spec、恢复 fencing、Ready、SQL 原 source CAS）→ `AfterSourceResume` 按原 keeper Job UID 回收 → `Ports.Resumed` 写 ACK。keeper 删除失败不 ACK；同 task 重试完成回收后才 ACK。

## 必需的既有安装配置

使用同一安装的 source/profile/capture/mount 签名和摘要；`PersistentMounts.RunningTenantPro` 绑定 SQL 实例、租户 Namespace UID、Deployment/ReplicaSet/Pod UID、实际 claim/PV spec 摘要和 workspace subpath。`Discovery.LonghornSources` 绑定实际 CSI handle、provider namespace UID、snapshot/clone classes 及 UID/摘要。

`runtime_sources.longhorn_hold` 必须配置原 `FormalLonghornHoldConfig`：Materials 文件及 SHA256、Observer 的 endpoints、CA/certificate/key 文件与摘要。恢复客户端证书 URI 必须匹配材料的 RecoveryURI；保留原 Node journal 与独立 SQL recovery/key 权限。源资料过期不取消恢复义务，原 transport/安装身份仍须有效。

共享 NFS/其他来源从安装配置及实际挂载绑定，本补丁没有硬编码现场卷或 NFS 名称。

## 最短现场验证（由原窗口统一执行）

1. 补齐当前全新安装必需的正式 source/profile/capture/mount/core 材料与连接，部署原窗口统一审核镜像；不默认执行旧 offline 历史冷接管。
2. 页面创建一单，保留 task/attempt；SQL 清单全部 8 行，本轮运行时 1、2、3、7、8，deferred 为 4、5、6。
3. 记录实例 2 的原控制器/卷身份、同 task keeper 注册、Deployment 停写、后端 snapshot 完成、release、业务 Ready/原卷读写、同 UID keeper 回收。
4. 使用独立测试任务，在 keeper 注册/停写后中断控制器；保留原 task/attempt/journal。撤销 forward source 后以有效独立恢复配置重启，确认原业务恢复、keeper 回收和义务结清；不要新建 task 替代恢复。任何身份漂移保留拒绝并交 owner 对账。
5. 继续核对同 task 的完整产物上传、独立读回、目录登记和最终成功。仅本地测试不能作为整单验收。

## 范围与阻塞

未连接或修改远测环境，未推送、合并或部署。首次安装的配置和源材料尚由原窗口补齐；Redis/现场连接及整单验收由原窗口负责。

`install.PrepareOriginalWriterSet` 的 taskless offline 冷接管仍拒绝 TenantPro；该操作不具有正式页面 task/claim，不能借用本次 Longhorn owner。原窗口已确认本轮不扩 taskless 协议，须结合全新安装状态选择必要初始化路径。

## 本地验证

定向测试覆盖：原计划恢复库存和身份变化拒绝；原 tenant mount/额外 writer 校验；现有 Deployment 正常恢复/延迟停写隔离；Longhorn acquire 中断后仍用原 task 和独立 context release；release 未确认保留错误；keeper 回收失败不 ACK 与同 task 重试。测试缓存、模块副本、临时目录全部在 D 盘，结束清理。最终固定源码复测：Go 1.26.1，windows/amd64，CGO_ENABLED=0，`-p=2 -mod=readonly -count=1`，四包全部 PASS，退出码 0；测试前后八个变更 Go 文件摘要一致。首轮三包定向回归也 PASS。

最终四包：`./internal/systembackupexecution`、`./internal/systembackupcontroller`、`./internal/systembackup/quiesce`、`./internal/systembackup/publicadapter`。完整 `-run` 正则和输出保留在 D 盘工作树 `pro-longhorn-final-tests.log`（本地结果文件）；版本化结果摘要见 `docs/evidence/tenant-longhorn-recovery-20261111.json`。

本地 API/协议夹具不是现场 Kubernetes、真实 Node freeze/release、Longhorn snapshot 或恢复后卷读写证据；真实 SQL recovery/key 权限与 Node/CSI 组合、Linux 原生运行及整单上传/读回/目录登记尚未现场验证。
