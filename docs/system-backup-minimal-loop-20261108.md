# 备份最小闭环：2026-11-08 接续记录

当前阶段已按用户最新要求收口为“本地候选冻结与远测准备”，范围、证据和停止条件以 [阶段交付](system-backup-local-candidate-frozen-20261108.md) 为准。

2026-11-09，操作者在 `kubernetes-admin@kubernetes` 回传只读结果。Snapshot v1 API 已提供三个所需资源，对应 CRD 均存在。`sbk-validation-longhorn-local` 的驱动为 `driver.longhorn.io`，类型为 `snap`，删除策略为 `Delete`。回执中的 snapshot-controller 2/2、CSI snapshotter 3/3、Longhorn manager 2/2 均为 Ready。

节点清单确认 `k8s-master` 为 `6.8.0-71-generic`、`node1` 为 `6.8.0-124-generic`，两者均为 amd64。操作者在两台宿主机上只读检查 tracefs，均返回 `tracing_on=1`，匹配冻结、解冻及 ioctl 的已启用事件均无输出。`node1` 对已挂接的冻结或解冻函数的额外查询也无输出。盘点结果仅覆盖这些查询，其他取证来源仍待确认。

R2 在只读预检结束。此后 R3 加入了一次性取证探针。操作者在 `k8s-master`（`6.8.0-71-generic`）以 `acffa127` 复跑，原生校准退出 `0`。同一设备 `7:8` 的记录依次显示父进程冻结成功、独立子进程提前解冻成功、父进程计划解冻收到 `EINVAL`。冻结期间直接写和共享映射写均阻塞，两个同步调用成功，解除后写读恢复，临时卷清理完成。校准证明本节点本次启动能捕获受控提前解冻。

专用 RWX 测试源已创建，写入 Pod 达到 Ready，实际 share-manager 在 `node1`。操作者校验三个脚本摘要后，在 `node1`（`6.8.0-124-generic`）完成原生校准，退出 `0`。同一 loop 设备 `7:0` 记录到独立进程提前解冻成功和父进程随后返回 `EINVAL`。临时卷清理完成。

随后创建 RWO 源、writer 和 keeper。两个 Pod 均 Ready，但 RWO 等待 `healthy` 超时。现场只读结果显示 `longhorn` 和 `longhorn-rwx` 都请求两个副本，两卷均附着在 `node1` 且 `degraded`，`Scheduled=False`、`ReplicaSchedulingFailure`、`disks are unavailable`。RWO 一个副本在 `k8s-master` 运行，另一个副本未获分配。原 writer 尚未进入删除测试，本轮 Longhorn 冻结快照 `NOT_RUN`，keeper、冻结连续性、克隆和恢复仍为 `UNVERIFIED`。操作者回传 namespace 已删除、`CLUSTER_CLEANUP_OK` 和 `NODE1_CLEANUP_OK`，本轮资源清理完成。新一轮须先确认两节点仍可调度，并为两源卷和两个克隆卷留出双副本额度。见 [R3 一次性验证](system-backup-storage-probe-r3-20261109.md)。

清理后的只读复核确认 `node1` 的 `default-disk-d21bf823c181132b` 因调度额度不足处于 `DiskPressure`。100% 超配下，已调度 `2341042388992` 字节比额度 `2326010003456` 字节多 14 GiB。其物理可用空间仍高于 25% 下限约 1064 GiB，`k8s-master` 调度余量约 384 GiB。按两源卷和两克隆各 1 GiB、每节点留 4 GiB 额外余量计算，操作者将此盘 `storageReserved` 由 `819989307392` 降至 `796366987264` 字节。回执 `NODE1_DISK_SCHEDULABLE` 确认 `schedulable=true`、实际调度余量 `8589934592` 字节。下轮须重新创建测试卷并检查双副本健康，磁盘结果只证明调度前提恢复。

复跑时，RWO 与 RWX 两卷都通过 `healthy` 检查，writer 和 keeper 均已 Ready。删除本轮 RWO writer 的 30 秒等待超时，超时后 Pod 仍显示 `Terminating`。准备脚本随后删除了本轮 namespace，PV 和 Longhorn Volume 回收待复核。旧测试 writer 使用 Kubernetes 默认 30 秒退出宽限，和删除等待同长。本地修订仅给该一次性 writer 显式配置 5 秒宽限，保留 30 秒删除等待和原卷读回标准，并在再次超时后记录 Pod 终止状态。等待现场复跑，keeper 和冻结快照仍未验收。

操作者以 `33ef53e4` 再跑，确认上一轮 namespace、PV 和 Longhorn 卷已回收。新一轮两源卷均通过双副本健康及调度检查，RWO writer 删除完成，同一 keeper 和原卷身份保持，seed 读回一致。实际节点为 `node1`。Pod 清单在建卷前记录 `node1` 104/110、`k8s-master` 110/110。实际冻结快照和克隆读回待测。

操作者以 `fa23dd46` 在同一轮执行一次双卷冻结快照。内核回执为 `WINDOW_OBSERVED`，共同保护窗口约 8.020 秒，请求前到双快照 Ready 后约 7.750 秒，整个区间在共同保护窗口内。两份租约退出 `0` 并确认解冻，挂载身份前后相同，原卷恢复实际写读，tracefs 探点和实例已清理。回执显示每卷均保存两条匹配的引擎日志。完整验收仍须核对开始与成功完成记录及后端身份，并完成两个独立克隆的内容读回和资源回收。

操作者随后以 `60f30fdf` 完成同轮取证和读回。两份 `BACKEND_COMPLETION_OK` 各有同一 engine、原卷和后端快照对应的开始、成功完成日志，且绑定和引擎快照元数据校验通过。RWO 和 RWX 都从各自快照创建了独立健康双副本克隆，两份 `CLONE_READBACK_OK` 确认 seed 一致且原卷解冻后写入的标记未进入克隆。回执 `CLUSTER_CLEANUP_OK` 确认本轮 namespace、PV、SnapshotContent、Longhorn Volume 和后端 Snapshot 已回收。存储行为验证通过，最后的 `node1` SSH 登录超时，节点私有目录清理待补，尚未记录 `STORAGE_PROBE_PASS`。

以下为此前推进记录。

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
