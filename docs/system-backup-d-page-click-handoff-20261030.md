# 页面点击完整备份：D 接线交接（2026-10-30）

## 验收口径

管理员在 `/admin/backups/records` 点击“创建备份”后，同一个 v2 任务必须取得 `mysql`、`redis`、`object_storage`、`workspace`、`deployment_resources`、`secret_bundle` 六项真实结果，经原任务停写/恢复、封存、发布及读回校验，最终可见可用成品。`202 Accepted` 只表示任务已建立；`functional_test`、合成 Gateway 回执和只含 `workspace` 的任务都不满足此口径。

## 当前已接的调用链

| 接点 | 实际调用与边界 |
| --- | --- |
| 页面 | `BackupLiveWorkspace.createBackup` 通过 `systemBackupTaskService.createSystemBackupTask` 向 `POST /api/v1/admin/system-backups` 提交固定六项 `task_purpose=acceptance` 请求。请求结果不明时保留原 JSON 字节和 `Idempotency-Key`；只接受 202、`X-System-Backup-Data-Source: live` 和同键任务回执。旧 `/admin/backups/system` 的创建入口已改为跳转此页，不再调用被 503 封闭的 `/admin/system-backup/tasks`。 |
| API 与任务事务 | `systembackupapi` 解析六项请求，原事务准入要求 `system_backup_v2_execution_readiness` 的 `supported_parts` 与 `acceptance_ready`。当前生产发布器只写 `supported_parts=workspace, acceptance_ready=FALSE`，因此六项请求应拒绝 `not_ready`，不能手改数据库或前端布尔值。 |
| B 调 D Runtime | `NewPublicCapture` 的 `PublicCaptureConfig.RuntimeControl` 传给 `SQLRuntimeControl.BuildWriters`；D 校验原 task/attempt、namespace、Pod UID、Agent epoch、generation、恢复 PID，只有正向停止证明才可恢复。未知派发仍隔离，不凭 DELETE/404 宣称停止。 |
| KEK | D 的 `systembackupkekregistry` SQL Store 与原 bootstrap/config/Job 事务组合已单独提交；完整历史扫描和 writer/最终发布接线未验收时仍拒绝完整结论。 |

## 今日现场证据与剩余工作

- 独立 pool/slot OpenClaw 测试 Pod 在固定测试镜像上取得 TLS 能力回执和合成 Gateway 正向停止、恢复回执，PID `78 → 87`。测试 Pod、Secret、临时 AppArmor profile、归档、测试镜像 manifest 已清理；现场 OpenClaw Deployment 已恢复原 digest。该测试没有通过页面、控制数据库或六项数据源。
- 现场仍为 OpenClaw/Hermes 单容器共享 Agent Deployment。运行中的工作区在共享 NFS，另有子 namespace 的已停止实例 PVC、团队目录、MySQL、Redis 和 MinIO。现有 `runtime-workspace` profile 要求单 namespace、单工作区根；原配置不能覆盖这套现场来源。不要只滚动镜像：旧模板不会启动 slot/pool 路由。
- B/A/C 仍需把六项生产数据面、完整 participant 与来源扫描、实际非空 Runtime 停写/恢复、KEK 使用、正式成品发布及独立读回接到同一 v2 任务；随后才能让 readiness 宣告六项。D 的 Agent 重启自动接管仍不具备证明，未知状态须保留隔离。
- 现库处于 migration 080/97 行 ledger。真实数据隔离副本已试跑缺失的 92 项迁移并清理，原库未升级；该探针不授权原库升级。正式导入 profile 与逐行保全/失败重试仍单独交付。

## 下一次现场执行顺序

先固定并核对六项数据源与部署镜像，再在隔离副本完成升级/数据保全；在有审查过的 native Runtime cutover 和六项生产 readiness 后，才给用户完整 PowerShell SSH 命令分阶段部署和点击单次备份。最后核对原任务/attempt、六项 result、停止与恢复原回执、PID/generation CAS、不可变成品及读回结果。未得到这些证据时页面必须显示受阻，而不是备份成功。
