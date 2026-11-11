# 本次安装的 P2 必要连接接续

2026-11-11，用户远侧回执已确认：

- MinIO 原 plan 已完成 TLS 切换、App 两副本加载及真实认证 S3 List（HTTP 200）。材料 `/root/sbk/p2-minio-prepare.9vnemhVi/connection-continuation/minio-source-fragment.json`，SHA256 `c3b4eae48b3d78c12872742be55e6bc95f11bc9e594c83b8697728edc020ede8`。
- Redis 原 RWO 卷八项身份校验全部通过。临时 Recreate 收敛后已恢复原 RollingUpdate 策略；未重发 native apply。原 owner query 返回 `desired_specs_ready_requires_native_finalize`，finalize 返回 `native_tls_and_accounts_read_back_not_a_hold`。
- Redis 材料 `/root/sbk/p2-redis-connection.b5dQ12Lt/redis-source-fragment.json`，SHA256 `8451e409dbc331e249b2824ec34be3a0d62c9ceb1de4151f813b9e26f7ffa43d`；native successor selection `/root/sbk/p2-redis-connection.b5dQ12Lt/native/redis-native-writer-selection.json`，SHA256 `00f897c181ccfe88b4904ff77f06a549a9c7a9831f966e5d5c3d8fd0fc60a8a9`；TLS 端口 6380。
- 租户 Pro / Longhorn 正式任务恢复修复已合入 `222fdc0c`；八个 Go 文件原始 Git 摘要及原测试日志摘要均与交付回执相符。原有离线无 task 接管拒绝条件保留。

这些回执尚不证明整单停写、恢复、正式上传、独立读回、目录登记或最终 task 成功。

下一批 `scripts/system-backup-field-tools/prepare-p2-api-runtime-inputs.py` 仅面向上述安装，复用现有 `sources` ServiceAccount，给本次 system/tenant/实际 Longhorn provider 命名空间接入只读权限。集群对象读取限已发现的 namespace/node/PV，另读取 storage/snapshot class 元数据。TokenRequest、TokenReview 和实际 sources 身份 SelfSubjectReview 均保留私有回执；不会新建 token anchor Pod。生产 source API consumer 以实际 ServiceAccount 名称、UID、CA 和 token 文件摘要验证身份，并不要求 Pod-bound token。

脚本从固定现有 App 镜像的真实 Deployment→ReplicaSet→Pod 链提取已安装的原生 enroll 工具，前后核对 executable SHA256、Pod UID、容器运行身份，然后由原工具独立验证 SQL、管理员及已登记签发身份，生成或查询用途分离的运行签名材料。prepare 发送后若未知，禁止重发；保留原目录。该操作不创建任务、hold、forward grant 或配置行。配置仍需消费原生材料并通过各自 owner。

首次使用一个新私有 records 目录；接续始终使用同一目录。原私有 journal、credential、intent、selection 均保留。新增四项本地测试覆盖 API TLS/身份漂移拒绝、只读权限以及带相同 label 的外来 Pod 不能提供可执行文件。无本地构建产物。
