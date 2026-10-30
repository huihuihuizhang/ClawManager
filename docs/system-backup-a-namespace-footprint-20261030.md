# A：当前 namespace 全量数据范围观察

2026-10-30 用户在本地仓库将 `scripts/system-backup-a-namespace-footprint.py` 经 SSH 标准输入发送至远侧，固定 namespace UID `337cfe30-2c17-4b8e-b32a-760778b8098e` 和 MySQL Pod UID `6d314752-86e1-41ce-9831-af03179dcf3b`，只读查询实例/持久卷关系与 Pod/PVC 元数据。远侧无仓库，不写文件、不读取业务数据值或密码。原始回传 `SSH_EXIT=0`；此处仅记录操作者回传摘要，不是数据一致性或备份成功证明。

| 当前实例 | 模式 / 状态 | 数据位置 |
| --- | --- | --- |
| 7、8 | Lite gateway / running / generation 1 | NFS `/workspaces/openclaw/user-1/instance-7`、`instance-8`；无实例 PVC |
| 11 | Lite gateway / running / generation 5 | NFS `/workspaces/openclaw/user-1/instance-11`；无实例 PVC |
| 12 | Pro desktop / stopped / generation 0 | `instances.pvc_name=clawreef-12-pvc`，workspace 路径为空；该 PVC 不在根 namespace，后续确认它在子 namespace `clawmanager-zhanghui08-system-user-1`，已绑定且不能因实例停止而排除。 |

当前 namespace PVC：`mysql-data`、`minio-data`、`redis-data`、`clawmanager-workspaces`、`system-backup-capacity-report` 均为 Bound。当前运行 MySQL Pod 挂 `mysql-data`，MinIO Pod 挂 `minio-data`，`workspace-store` Pod 挂 `clawmanager-workspaces`。运行中的 `clawmanager-team-redis` 没有 PVC 挂载；`redis-data` 虽 Bound，初次观察没有任何当前 Pod 挂载。app、Hermes、OpenClaw Pod 也没有 PVC 挂载；其直接 NFS `/workspaces` 挂载见 [NFS 归属观察](system-backup-a-nfs-ownership-20261030.md)。

第二次只读观察补齐了卷类型与挂载路径：运行中的 `clawmanager-team-redis` 将 **`emptyDir` 挂在 `/data` 且可写**；已绑定的 `redis-data` PVC 没有运行 Pod 使用。MySQL `mysql-data` 挂 `/var/lib/mysql`，MinIO `minio-data` 挂 `/data`。当前 `workspace-store` 把 `clawmanager-workspaces` PVC 挂 `/exports/workspaces`，但 app、Hermes、OpenClaw 的实际 `/workspaces` 都直接挂 `10.107.165.245:/` 且可写；不能以本 namespace 的 workspace PVC 代替实际运行目录。MySQL 另有仅供测试 TLS 运行时的 `emptyDir`，不属于数据库持久卷。

随后通过只读 Deployment 模板查询确认，现场 `clawmanager-team-redis` 模板同样没有 PVC claim，卷是 `emptyDir`；操作者回传 `SSH_EXIT=0`。仓库 `deployments/k8s/cluster/clawmanager.yaml` 的 Redis Deployment 模板写的是 `persistentVolumeClaim: redis-data`，与现场运行 Pod 和现场 Deployment 模板均不一致。备份准入应以现场实际绑定为准；不能因为仓库模板期望 PVC 就从未挂载的 PVC 取数。现场模板即使重建新 Pod 仍采用 `emptyDir`，旧 Pod 中的数据不会随之保留。

第三次只读观察用 `scripts/system-backup-a-redis-live-observe.py` 固定 namespace UID 和 Redis Pod UID，查询 Redis `INFO keyspace` / `INFO persistence` 的筛选数字与状态。操作者回传 `SSH_EXIT=0`：`db0` 有 **6 个键**、其中 0 个设到期；`loading=0`、`aof_enabled=1`、`aof_last_write_status=ok`、`rdb_last_bgsave_status=ok`。工具不读取键名、键值或密码，结果不证明 6 个键在备份时刻仍不变。AOF 当前写在 `emptyDir`，因此启用 AOF 也不使 Pod 更换后保留现有数据。首次探针因旧解析器不接受 Redis 返回的额外 keyspace 数字字段而退出 1；修复并通过本地解析检查后重跑取得以上回执。

第四次只读 PV/子 namespace 查询均退出 0。`clawmanager-zhanghui08-system-user-1` UID 为 `b49d2b4a-9a9a-43be-a0fb-e486649b9681`；其中 `clawreef-12-pvc` UID `35c3e1db-fdd2-43e4-8a4d-5af2a6c39e37`，Bound 到 `pvc-35c3e1db-fdd2-43e4-8a4d-5af2a6c39e37`，PV reclaim policy 为 Delete，100Gi Longhorn CSI `driver.longhorn.io`。该子 namespace 还有 `clawreef-team-3-shared` UID `a263c53c-c284-4a8d-bada-889413799310`，Bound 到 `clawreef-pv-clawmanager-zhanghui08-system-user-1-team-3-shared`，PV reclaim policy 为 Retain，10Gi NFS `10.107.165.245:/teams/user-1/team-3-shared`。后端类型查询也退出 0。当前查询没有返回该子 namespace 的运行 Pod 行，不能因此断定卷内容为空。两块卷均属于当前 installation 的全量数据范围候选；其业务归属需按原实例/团队关系确定，不能遗漏或跨租户采集。团队 NFS 路径与直接挂载的 export 根和三个实例目录可能共用后端，不能重复计入或因为路径不在三个实例目录中而漏掉。

同轮只读 MinIO 查询先核对 Pod UID `2b674b10-0360-4164-8055-022c46991d17`，再 `ls -1 /data` 与 `ls -la /data`，均退出 0。普通列表没有顶层项；包含隐藏项的列表只见 `.minio.sys`，没有可见桶目录。这是当前挂载点的目录观察，不是对象 API 的全量桶/版本证明；`minio-data` PVC 和服务配置仍在备份范围判断内。

这些是不同数据域：完整备份必须在一致性窗口覆盖现库、真实 Redis 状态、MinIO 对象及三个运行实例的 NFS 子树，并包含已确认的实例 12 子 namespace PVC 与团队共享 PVC 的业务数据边界。团队目录 `/workspaces/teams/user-1/team-3-shared` 已在实际根 export 挂载中只读确认存在，见 [NFS 归属观察](system-backup-a-nfs-ownership-20261030.md)。原任务还请求 `deployment_resources` 和 `secret_bundle`；本次元数据盘点没有读取 Secret.data，也没有证明这两部分已经完整采集。Redis 的当前 `/data` 是 `emptyDir`：删除或替换 Pod 会丢失该卷，不能在捕获 Redis 前把它缩容/删除，也不能从未使用的 `redis-data` PVC 读取旧快照冒充现状。运行 Runtime 的 NFS 和本 namespace `workspace-store` 使用的 PVC 不是同一已证明的数据源。`system-backup-capacity-report` 的用途及保留边界也需按原业务事实判断。直接采整个共享 NFS export 或只采这四个目录都不能自动证明“当前 namespace 所有数据”。

共享分支 `a3b34b85` 新增的 `runtime-workspace` NFS 入口只接受安装专属的 `installations/<SHA256(installation_id)>` 子树，并要求所有来源的 workspace 路径非空且在该子树内。现场三个运行实例位于共享根 export 的 `/openclaw/user-1/instance-*`，团队目录在 `/teams/user-1/team-3-shared`，已停止实例 12 的 workspace 路径为空且数据位于子 namespace 的 Longhorn PVC。因此该新增入口**不会准入本次现库全量范围**；不能通过把配置的 NFS server 指向同一 IP、修改 `sub_path` 或忽略实例 12 来取得虚假的成功。D/B 需按原实例与团队数据来源分别交付可冻结的范围、真实 writer/停止证明及采集与恢复目标；A 的 KEK/签名接线仍须随正式成品使用。这是当前源码与现场观察的对照，不是对新功能测试入口的失败回执。

工具本地四项离线测试 `py -3 -B scripts/system-backup-a-namespace-footprint.test.py` 退出 0，覆盖已停止实例与 PVC、重复/异常 SQL 行拒绝、Pod/PVC 输出不含环境值和非法身份拒绝。没有构建产物。该工具只观察，`ready_for_backup=false`；正式采集仍依赖 B/C 冻结 context、D 现库升级及全域 writer/停止证明、A KEK 准入与凭据接线。
