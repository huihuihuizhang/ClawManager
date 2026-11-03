# B：真实写入者观察与额外挂载采集接线

> 本文件保留前一轮记录和对应源码 hash。后续第 1～3 项增量、必填 UserID/Generation、正式材料/首次纳管接线和 Linux 隔离验证，以 [最新交接](system-backup-b-mount-inputs-handoff-20261103.md) 及 `evidence/b-mount-inputs-20261103/summary.json` 为准。

基线：`backup@71e2f3186a28ff150bc183b86ffdfe491678a5e9`。本轮按用户确认的范围处理 Linux Lite 实例**已挂载的持久化数据**；容器可写层、临时目录、内存现场不纳入实例文件备份。未扩展 Pro、Windows 或目标还原。

当前状态分别为：源码已有本轮增量；局部隔离组合已运行，准确结果见本轮证据；真实环境仅做只读盘点，没有停写、首次纳管或备份整链成功结论。源码未提交或推送。

## B-1：现场实际观察

用户本轮明确提供 SSH 密钥位置及 `root@10.130.14.23`，允许查看 `clawmanager-zhanghui08-system`。已用严格 SSH 主机密钥检查、非交互连接核对：

- context：`kubernetes-admin@kubernetes`。
- namespace UID：`337cfe30-2c17-4b8e-b32a-760778b8098e`。
- 观察到 10 Deployments、10 Pods、38 ReplicaSets、6 PVC、6 对应 PV、2 个运行节点；本轮该 namespace 没有观察到 StatefulSet/DaemonSet/Job/CronJob。
- 两轮 namespace 资源投影未发现变化。这不构成不可变快照、全源 writer 完整性或停写证明。

准确 Pod/Deployment/卷 UID、resourceVersion、代数、容器/imageID、挂载与 PV 绑定保存在 `evidence/b-mounted-data-20261103/field-writer-observation.json`。未输出 env/args、Secret 正文、令牌或业务文件内容。

| 实际组件 | 观察到的数据写入面 | 源码/物理能力差集及接收者 |
| --- | --- | --- |
| clawmanager-app | `/workspaces` → NFS `10.107.165.245:/`；平台 API 与嵌入后台任务可能写 SQL/Redis/对象 | B/D 核对每个 App 副本 gate；两位 C 核对实际任务。Pod Running/Ready 不能证明后台退出 |
| openclaw-runtime、hermes-runtime | 同一 NFS export 挂载 `/workspaces`，跨 k8s-master/node1 | D 提供合法 SQL 实例投影、Runtime 注册和原 operation/UID/generation；B 不能从一个 Pod 推出实例数量、归属或 stopped 状态 |
| skill-scanner | 未观察到实例持久化卷；可能写扫描结果/对象/SQL | 对应 owner 明确服务写入与排空；不能因为没挂盘就从 writer 清单删除 |
| Skills materialize/backfill | 当前不是独立同名 Pod，源码在 App 内使用 `skill-backfill` / `skill-materialize` gate | C—Skills/D 交运行配置、子任务/子进程与许可释放后实际退出证明；不能把“没有同名 Pod”当作未运行 |
| Teams 后台任务、Redis | App 嵌入 worker；team-redis `/data` 实际是 EmptyDir | C—Teams 对齐 SQL/Redis 一致性、TTL 和 writer；Redis 内容仍需独立采集，不因实例临时卷排除而丢弃 |
| workspace-store | PVC `clawmanager-workspaces` 挂到 `/exports/workspaces`，为上述 NFS 提供后端 | D/存储 owner 证明 export 与 PVC/PV/目录归属、外部客户端及共享卷 fence；B 仅观察到了拓扑 |
| mysql、minio | 各自 data PVC | SQL/S3 的旧账号、外部直接客户端及结果不明操作需要原 owner 列清并物理阻断/排空，不由 runtime gate 自动覆盖 |
| secret-broker、Vault | 身份/密钥及 Vault data PVC | A/D 保持采集、恢复和正式发布所需的最小服务能力；不能为停写直接停止所有服务导致安全收尾不可用 |

App 本次观察仍为 `backup-test-zh-fix18`；不能把已导入的工程镜像或本地新源码当作现场已运行版本。现场进程树、具体 SQL 实例状态、在途外部操作没有在本轮读取或改变。

## 源码入口及真实调用

1. `productionSourceDiscovery.PersistentMounts` 增加原 source-owner scope 中的额外挂载声明，随既有 `sourceMetadataScope` 签名输入和独立材料 hash 绑定。没有新控制表、issuer、claim 或任务。
2. `checkRuntimeWorkspace` 在新 six-part 非空源准备阶段要求有效挂载 scope，并核对全部普通/init 容器；未登记的持久化旁路、未知存储、临时卷覆盖 workspace、block device、ephemeral container 等拒绝。原 primary PVC/NFS 身份与 subPath 检查继续运行。
3. `instanceMountMetadata` → `additionalInstanceMounts` → `resolvePersistentMount` 在原 source authority 的前后重查内使用实际 Kubernetes GET，核对原 Runtime Pod UID、完整 PodSpec hash、namespace、Node UID/OS、卷源 hash、PVC→PV 绑定及既有 `Security.Volumes` pin。读取后重新 GET 原 Pod，spec/UID 变化拒绝。
4. 每个额外挂载变成 `productionInstanceMount{DataOnly:true}`，携带确定的实例子目录、源卷与节点；和 primary 合并做重叠检查，按确定顺序进入原 metadata。冻结后重查整份 mount 集合，不接受漏/增/改项。
5. `production_capture_modules.go` → `NewUsersInstancesModule` 为每个额外挂载生成原 `capture-workspace` Job。额外挂载不冒充 primary runtime-policy 根，不套用主 workspace 中的配置文件路径；主根及 WorkBuddy 身份/Skills 校验仍必需。共享 SQL 仍只有一份。
6. 原 `productionInventory` 按每个实例/挂载生成预期 part，必须仍包含唯一 primary。`productionPartMounts` 消费各 part 的原 PVC pin；HostPath 只接受与原 metadata 精确匹配的原挂载。加密、原 key 使用、候选 ACK、原任务和 source-resume 流程复用。

未新增 Worker wire 字段、任意 shell 命令或弱化真实授权；`DataOnly` 只区分额外挂载的采集布局，不是覆盖完整、已停写或可恢复的布尔证明。

## D/A 必须接收的材料输入

新增字段位于原 capture materials 的 `Discovery.PersistentMounts`：

| 字段 | 必须的来源 |
| --- | --- |
| `Version` | 固定 `original-instance-persistent-mounts.v1` |
| `Mounts` | 原 source-owner 确认的额外实例目录映射；只有实际核对后才能给空列表，不是“没有历史”或“已停写”声明 |
| 每项 `InstanceID/MountID` | 合法 SQL 实例归属及唯一 part；MountID 不能是 workspace，不能超出 part 长度限制 |
| `Container/Volume/MountPath/DataPath` | 原 Runtime Pod 的具体挂载与被授权实例子目录；DataPath 必须位于对应 MountPath，subPathExpr 不推导 |
| `Namespace/Pod/PodUID/PodSpecSHA256` | 同一原 Runtime 绑定；hash 使用现有 Go `kube.ContentHash`。Python 盘点 JSON 不是可直接签发的 PodSpec hash |
| `Node/NodeUID/VolumeSourceSHA256` | 实际节点与原 VolumeSource 的同一 Go hash；Node UID 必须也在部署安全配置中 |
| 额外 PVC 的 `Security.Volumes` | 真实 PVC UID、PV name/UID、PVSpec hash，不能凭 claim 名或新建同名 PVC 代替 |

D 应在既有材料 author/装配中生成并经 A 原 source-owner 认证，不能要求操作者手写授权 JSON。新非空 six-part 源缺少该字段时拒绝前进；没有自动兜底到“仅 workspace 也算完整”。旧零实例路径不要求凭空产生实例 scope；既有冻结任务的恢复仍使用原 frozen writers，不重新申请发现/停写身份。

## 本轮仍有明确边界

- 支持当前可核对的运行中 Linux Lite Gateway 原 Pod。**原本 stopped 的记录目前没有完整原 Pod 挂载快照（D 现存 material 为 `{}`），非空 six-part 准备阶段提前拒绝，不启动实例来猜原目录。**D 需提供独立认证的原 mount inventory 和真实 stopped/退出证明后再接通；Pro 仍不扩展。
- 额外 PVC 支持已绑定文件系统卷和精确安全 pin；HostPath 要求已存在目录、固定节点及原源声明。PVC/HostPath 的源节点必须与既有 staging 节点相同，避免无证明跨节点挂载；直接 NFS 仅接受当前已批准安装 export 与其 installation 子树，并沿用原 staging 节点，不篡改源 Pod 实际节点。
- 不接收整卷根目录归属不明、nested overlay、未知存储/inline CSI、block volume、未解析 subPathExpr。缺少原所有权/布局资料时整次拒绝，不静默跳过。
- 当前额外挂载为原加密采集能力；没有认证目标恢复源，不声称 data-only 内容已完成配置规范化或目标还原。
- 本轮没有产生任何物理停写证明。首次纳管 `Opaque native prepared physical writer fence` 仍要由 D 的维护授权、A 的 witness 协议及实际 Runtime/存储能力共同闭合；正式 backup source grant 不能循环替代首次纳管的授权。

## 验证、接收及剩余工作

本轮使用本机**已存在**的既定依赖，设置 GOPROXY/GOSUMDB=off、GOTOOLCHAIN=local、mod=readonly，使用独占构建缓存。相关 Go 测试已进入真实包级编译/执行，不再沿用昨天的“缺 JCS 无法编译”状态。测试仅使用 fake Kubernetes、本地模型/临时文件，不访问现场 SQL 或运行真实 Job。准确根数、SKIP、失败修正和日志摘要见本轮 `summary.json`；SKIP 不计通过。

最终节点放置修正后的相关回归为 43 个根 PASS、2 个 Windows 条件根 SKIP；盘点工具 7 个根 PASS。publicadapter vet 退出 0；两个包组合 vet 退出 1，唯一输出来自本轮未修改的 `deployment_publication_startup_test.go:213`：复制 `DeploymentService` 时携带 `sync/atomic.Bool` 的 noCopy。HEAD 原文件同一位置已有该写法，已交 D/原测试 owner，不关闭 copylocks 检查或把组合 vet 写成通过。

现场脚本是 `scripts/system-backup-b-writer-inventory.py`：仅固定 `kubectl get`，验证 namespace UID，分页结束/数量/对象身份检查，白名单投影，两次观察。它始终输出 `physical_fence_proven=false`、`complete_writer_inventory_proven=false`、`first_adoption_authorized=false`。对应隔离测试验证不导出 env/args/Secret 投影、namespace 变化拒绝及旁路清单。

下一接收人：

- D：接本轮 source discovery/material 字段与 worker 原 part 输出；提供实例 SQL/Runtime 原绑定、stopped 原挂载快照和首次纳管原维护接口。共享部署与控制 SQL 仍由 D 管。
- A：审核新 discovery 字段进入原签名范围；提供原 physical writer fence witness 所需用途/有效期/撤销和验证协议，不接受 JSON bool/hash 冒充物理事实。
- Skills/Teams C：按现场 App 嵌入 worker 和 NFS/SQL/Redis/对象拓扑给实际后台 writer 差集；额外目录若含 Skill 内容，仍由原内容 inventory 绑定，不据额外文件归档宣称领域完整。
- 公共 C/存储 owner：提供旧 S3/NFS/SQL 外部 writer 与在途操作、固定历史范围和物理阻断机制。B 盘点及原 source snapshot 不构成首次纳管 history/fence 证明。

没有执行真实迁移、安装依赖、停止现场 Pod/Agent、修改 replicas/Secret/SQL 或发送外部消息；没有提交、推送。缓存清理结果以本轮独立 cleanup 记录为准，不删除其他 owner 的产物。

本轮自建 `.codex-temp/b-mounted-data-20261103/cache` 与 `tmp` 的清理命令被自动审批以 `blocked by policy` 拒绝，未执行，目录仍在；没有通过其他删除方式重试。日志与验证记录保留。
