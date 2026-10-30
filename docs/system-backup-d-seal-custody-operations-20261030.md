# D：封存容量、孤儿清理与实际 PVC 验收

2026-10-30 后续现场进展：独立临时 Longhorn PVC 跨节点能力验收已通过，运行 `sbk_8c80058b-2d2a-4c24-b083-2a5a73ca8015` 的内外层 passed/cleaned 均为 true、退出 0。回执见 `docs/evidence/d-seal-capability-passed-20261030.json`。这是独立工具镜像和临时卷的验证；正式 staging 部署、真实工作区挂载及 MySQL 清理验收仍未完成。

## 生产准入现状（2026-10-30）

现有现场只读库存 `docs/evidence/d-existing-db-live-inventory-direct-20261030.json` 记录 99 张表、没有 `system_backup_v2_*` 表，且 `migration_authorized=false`、`schema_equivalence_verified=false`。D 的清理查询明确依赖 `system_backup_v2_backups`、`system_backup_v2_runtime_resources`、`system_backup_v2_evidence`。因此此库存对应的数据库尚不能执行 seal prune 的 dry-run 或 apply，更不能把缺表错误解释为无引用。旧表与新 `079` 迁移的同名结构冲突由统一执行链 D 窗口处理；本工具不能代替迁移或绕过准入。

现场 `clawmanager-app` 仍没有 `SYSTEM_BACKUP_PUBLIC_CONFIG_FILE`、固定配置 SHA、正式 staging 挂载和封存工具。仓库的 `examples/backup-controller/public-deployment.security.example.json` 是占位模板，含 `REPLACE_WITH_*`，不得当成已审定的现场部署材料。临时 Longhorn 探针的 namespace、PVC、PV、Pod、镜像身份只证明该次存储能力，不是正式安装的固定身份。

维护 CLI 新增 `-mode preflight`：在 pinned 部署配置和私有 SELECT-only DSN 下，仅查询 `@@server_uuid`、`DATABASE()` 和三张清理表所需列的 `SELECT ... LIMIT 0`。输出 `ready=true` 才表示这几项准入检查通过；它不读取或创建 staging 目录，也不判定任何文件可删。`prune` 现在先执行相同数据库预检，缺表、错库或权限不足时在触碰 staging 前拒绝。现场仍需真实固定配置、独立账号和已批准的迁移，才能运行：

```sh
system-backup-seal-custody -mode preflight \
  -config /run/backup/public-deployment.json -config-sha256 "$CONFIG_SHA256" \
  -dsn-file /run/backup/seal-maintenance.dsn
```

继续生产接线时，按以下依赖顺序核对：

1. 先由数据库迁移 owner 提供同一目标库的新版表结构等价与迁移准入记录，并在迁移后的实时库存中核对三张清理表及其列、索引。
2. 由部署 owner 固定真实 `installation_id`、namespace/SA/PVC/PV UID、原工作区和 staging 根卷、`seal_custody_max_bytes`、controller 与 worker 镜像 digest，以及公开配置文件的 SHA。容量按实际保留量和卷剩余空间决定；不能仅复制 1 GiB 示例。
3. 排空旧 controller 后安装相同版本的新 controller/worker，核对实际挂载和原配置 pin，再在**正式 staging PVC** 上运行 `scripts/system-backup-seal-custody-probe.py`。接收同轮 `passed=true`、`cleaned=true` 和精确 UID/image/PV 记录。
4. 使用独立 SELECT-only 控制库账号，在 controller 挂载环境先运行 inventory 和 prune **dry-run**。保存候选、未知文件、数据库身份和引用判定回执；只有符合下述清理规则的版本才进入单独的 apply 操作。现场目前没有这份 DSN/准入记录，不能运行这一阶段。

以上各项未有实时回执前，保留本轮独立存储能力通过的结论，不宣布正式 staging 或真实 SQL 清理完成。

本增量承接 `a113760a` 的 controller 私有 staging seal。它不发布 C 最终 artifact，不删除正式 evidence，也不把本机测试计作真实 PVC/MySQL 验收。

## 部署要求

固定摘要的 public deployment 配置增加必填 `seal_custody_max_bytes`，范围 1 MiB 至 1 TiB。A 已在公开 `public-deployment.security.example.json` 提供 1 GiB 示例；应按实际 PVC 和原 staging 数据的总需求配置，不机械沿用示例。

升级时先排空旧 controller 的在途复制，再统一部署新 controller/worker 镜像。旧版不使用新文件锁，不能与新维护工具并行运行。Dockerfile 已将 `system-backup-seal-custody` 打入 app 与 backup-worker 两个目标。

首次使用 `.controller-seals` 时固化 installation 和预算到 `.custody-policy.json`。后续不同安装或不同预算拒绝；本工具不自动覆盖策略。修改预算必须由部署 owner 在排空并核对旧目录、引用与新配置 pin 后处理，不能在线删除策略/锁文件让另一个进程重新初始化。

## 容量行为

- 所有生产复制经 `ObserveManaged`，在同一稳定 `.custody.lock` inode 上取得跨进程独占锁；扫描、预算判断、intent 写入和复制期间不释放。
- 计入正式 seal、intent、历史未跟踪文件和中断 partial；最多扫描 10000 个普通文件。未知子目录、符号链接、读取错误和超出上限均拒绝继续复制。
- 新写入须同时满足固定字节预算和真实文件系统剩余空间。额外保留预算的 5%，且不低于 64 MiB。其他卷使用者仍可能并发占用空间，后续写入/同步失败不会返回成功封存。
- 已存在的精确版本重放不再次写入 seal/intent；不通过更换名字逃避计费。intents 仅记录原 Job/配置/receipt 绑定，不含密钥或正文。
- Linux 使用 `flock`，Windows 本地测试使用 `LockFileEx`。锁在进程退出后由内核释放，不按文件时间猜测锁已过期；生产锁文件永不删除。共享文件系统必须通过下述跨 Pod 验收。

## 清理规则和命令

默认只读出候选，不删除。apply 只处理超过最小年龄（默认 24 小时、最小 1 小时）的本目录已知对象：

1. `.seal-<随机 ID>.partial` 从不成为结果引用；独占锁证明没有本版本 writer 正在复制，才可按准确文件身份删除。
2. seal/intent 必须与不可变 intent 中的安装、原 Job、attempt、配置和 receipt 重新计算匹配。缺失、畸形或旧版没有 intent 的文件保留。
3. D 在同一真实 SQL 事务核对 database/server UUID，锁原 backup、Job，并查询 evidence 引用。任务必须为终态且完成至少 1 小时、配置精确匹配、Job 已撤权、attempt/UID/generation/unit 一致、没有 result SHA。只要该任务存在任何 evidence（包括过期或失败记录）就保留，避免猜测外部/加密引用。
4. 缺失的任务/Job 不作为“无引用”证明。数据库错误不批准删除 seal。SQL 锁一直持有到准确文件删除完成，然后释放；不更新 SQL 历史或任务状态。
5. 先删除 seal 再删除其 intent；中间失败可重跑。只有 intent 的中断记录也须通过相同 SQL 判定。不递归清扫、不删除未知文件、不自动删有引用版本。

在 controller 的挂载环境执行，配置 SHA 来自独立部署记录。DSN 文件为私有文件，仅需要相关控制表的 SELECT；不要使用 source 业务读取账号，也不要把凭据放在命令行：

```sh
system-backup-seal-custody -mode inventory \
  -config /run/backup/public-deployment.json -config-sha256 "$CONFIG_SHA256"

system-backup-seal-custody -mode prune \
  -config /run/backup/public-deployment.json -config-sha256 "$CONFIG_SHA256" \
  -dsn-file /run/backup/seal-maintenance.dsn -minimum-age 24h

# 核对候选后执行；仍在锁内重新核对实时原状态。
system-backup-seal-custody -mode prune -apply \
  -config /run/backup/public-deployment.json -config-sha256 "$CONFIG_SHA256" \
  -dsn-file /run/backup/seal-maintenance.dsn -minimum-age 24h
```

维护账号读取 `system_backup_v2_backups`、`system_backup_v2_runtime_resources`、`system_backup_v2_evidence`，不得借此授予 UPDATE/DELETE 或新的任务执行权限。每个 seal 独立判定；如果本轮中途失败，JSON 的 `complete=false` 与已输出 items 保留此前已完成的删除事实。应在失败任务回收后或容量告警时执行；达到容量上限不会触发无条件淘汰。

## 实际 PVC 与 worker 隔离验收

`scripts/system-backup-seal-custody-probe.py` 需要配置原文件及其 SHA、原 Kubernetes context、正在运行的 controller Pod UID/实际 imageID。默认只输出方案；加 `--execute` 才创建一个随机 run-owned Pod。

```sh
python3 scripts/system-backup-seal-custody-probe.py \
  --config public-deployment.json --config-sha256 "$CONFIG_SHA256" \
  --context "$KUBE_CONTEXT" --controller-pod "$CONTROLLER_POD" \
  --controller-uid "$CONTROLLER_UID" --controller-image-id "$CONTROLLER_IMAGE_ID" \
  --container controller --worker-node "$PINNED_WORKER_NODE" --execute
```

使用更新后、按 digest 固定的镜像。探针核对 namespace UID、ServiceAccount UID、源及 staging PVC/PV UID、worker Node UID，以及 controller 的准确根卷挂载；worker 使用原捕获安全上下文、准确 task subPath、只读原 workspace 挂载和无 token 的内存 scratch。注入额外容器、卷、环境凭据或更改安全上下文会拒绝。

controller 在独立随机任务形状目录测试 hard link 的 same-inode/create-only、chmod、原字节回读、文件及目录 fsync；在 sibling custody 放入本轮标记。worker 必须能够读取自己挂载中的标记，不能直接或通过越界 symlink 读取 sibling 标记，也不能通过 workspace 的同级入口读到标记。原 marker 在 worker 测试后再次由 controller 核实仍存在。

controller 持有该探针目录的锁期间，worker 必须无法取得同一锁；释放后 worker 必须能够取得。两端使用同一新版工具：controller 保持锁直到 worker 写入竞争检查结束标记，随后释放并写入 release；不再按固定 10 秒猜测另一节点已看到 ready。检查结束标记不代表检查成功，worker 意外取得锁仍失败。输出 `cross_node=false` 只证明本次同节点跨 Pod 情况；需按实际可调度节点组合复跑，不能外推为跨节点 NFS 锁通过。此工具也不证明存储管理员无法修改文件，或任意未纳入部署清单的额外挂载不存在。

清理使用 API UID precondition 删除准确探针 Pod，等待消失、锁 holder 结束，再删除核对 run ID 的已知探针文件。创建提交结果不明时按原名称、run label 和 spec 恢复 UID；不明确时保留现场并输出 `cleaned=false`，不冒险清理仍被 Pod 使用的文件。永久 custody 控制目录/锁不属于探针垃圾。

接收必须是同一次输出 `passed=true` 且 `cleaned=true`，并保存全部 run/PVC/PV/Pod/image/node 身份。失败或清理未完成不拼接其他轮次结果。工具未读取或修改真实备份正文，也不迁移数据库。

## 本地验证边界

包含字节预算、历史文件计费、策略漂移、并发不超额、跨进程互斥/释放、精确重试、孤儿/引用/未知文件/数据库失败、终态与撤权、配置/Job 绑定、候选模式不删除、intent-only 收敛等回归。Python 回归验证探针挂载、身份和安全漂移拒绝。本地 Windows 测试和 Linux 编译不能代替上面的真实 PVC 或 MySQL 运行回执。

2026-10-30 最终本地验证：staging 全包 8.833s、execution 全包 5.606s 通过，维护 CLI 包编译通过；Linux/amd64 staging 测试二进制及维护 CLI 编译退出 0。Python 3 项测试（含安全漂移子例）通过。各轮本次独占构建目录和 Linux 二进制均已删除；未运行镜像构建、真实 PVC 探针或真实 MySQL 清理。
