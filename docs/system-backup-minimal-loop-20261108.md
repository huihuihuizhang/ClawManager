# 备份最小闭环：2026-11-08 接续记录

当前阶段已按用户最新要求收口为“本地候选冻结与远测准备”，范围、证据和停止条件以 [阶段交付](system-backup-local-candidate-frozen-20261108.md) 为准。以下保留此前推进记录。

目标仍是从真实页面产生同一 task/attempt 的非空完整备份，完成源恢复、正式发布、独立读回和目录登记。当前没有这条现场成功证据。用户本次要求先做本地验证，并在每个独立项目完成后提交到远程 `backup`。

已推送：

- `53216e9e`：自建 loopback ext4 的冻结诊断脚本及执行说明。watchdog 介入、冻结期间同步未返回均不能给出正常通过结果；子进程不会落入父进程的设备清理栈。
- `0cbe907b`：日志管道关闭时继续执行解冻和自有设备清理，并拒绝正常成功结果。
- `37a1d56a`：部署步骤先校验 App 和 Worker 两个镜像，再创建输入 PVC。保留原凭据、配置和漂移检查。原顺序的两个失败用例已复现；基于提交版本的完整 16 项脚本回归通过。另有输入 PVC 的 4 项模型回归通过。

- `b5b98501`：原 Recovery 事务内按原 task/attempt 的 runtime journal 恢复具名 Deployment 检查的底层支持；独立基线回归通过，生产租户适配仍在下述本地候选中。

本地候选仍位于 `.b-longhorn-rwx-csi-20261106/source`，不是已发布版本。已合入 Longhorn 资源 namespace 与实际 provider/keeper Pod namespace 的独立坐标、安装脚本材料复制及控制器消费接线。针对 kube、controller、execution 的定向回归通过；当时的 installer 选择器没有匹配用例，不能算安装行为验证。三个 Linux 入口 `backup-shared-runtime-node-owner`、`system-backup-observer-deployment-materials`、`system-backup-v2-controller` 交叉编译通过。该轮独占构建目录、源码归档及缓存已清理。

后续新增的候选包括：采集材料缺失时，在独立 Recovery 事务和原 task/attempt 的锁定 runtime journal 下，恢复租户 Deployment 的具名检查；原检查失败不会降级，Forward 不能借用恢复入口。另增加调用实际安装 validator 的 HTTP 回归，覆盖不同 namespace、错误 UID 及禁止写入。新增恢复组合回归已通过，包含修正为生产规范 JSON 的实际安装 HTTP 校验。可独立提交的控制器底层补丁另在未叠加候选的源码上验证，定向回归通过。

剩余实际阻断：

1. 普通 ext4 只读重配置会被保留的可写 FD/共享映射阻断。冻结替代路线尚未实测，也尚未替换生产停写实现。本机 Docker daemon 当前不可连接，现场暂不能连接；Linux 交叉编译不能代替内核和 Longhorn 验证。
2. observer 的卷校验仍默认只授权安装的系统 namespace。租户源需要已有 V2 Registry 签名材料与原 maintenance 实例/owner chain 的精确关联；不能用裸 JSON、SHA 或 namespace 名称放行。该关联适配已进入本地候选，复用既有 V2 consumer 和 maintenance；签名窗口在原实例/API 观察前后均复核，定向安装回归已通过，Linux 材料命令编译结果另行记录；尚未接入 operator 的实际定义生成。
3. operator 首次安装 Node observer 早于最终 source registry，且目前没有把 LonghornVolumes 写进该阶段的定义。最终 grant 的准备和消费顺序仍需接通。
4. RWO attachment keeper 目前只有 helper 定义，没有生产调用。原 Pod 停止后，Node owner 仍会检查其 PID/CRI 身份，仅持有 FD 不能继续。需要在原停写意图之后、Writer.Pause 之前创建并读回 keeper；还须处理已安装 provider UID 的认证关联、tenant Job 权限，以及 keeper 与普通 collector 的恢复顺序。现有 runner 要求全部 writer 已停，不能直接用于预停阶段；tenant 角色目前只有 Job list，且 CollectorsStopped 会把 keeper Job 也计入，须在原日志的精确资源用途下处理。
5. 既有 host 安装脚本的 `copy_exact` 会拒绝修改已安装的 systemd unit（退出码 28）。不能把“能生成第二份 bundle”说成“能安全更新同一个 Node”。需要原安装流程提供可验证的更新步骤或消除首次安装顺序循环。
6. 上述条件满足后，仍需验证双卷共同停写、原日志快照、解除后克隆采集，以及同一正式任务的发布和独立读回。

共享工作区保留其他未提交修改。本轮仅精确暂存已审核文件或基于 HEAD 的独立补丁，没有全量 add、reset、stash 或切换分支。冻结探针执行与结果判读见 [执行说明](system-backup-ext4-freeze-canary.md)。
