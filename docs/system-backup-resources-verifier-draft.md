# D resources 备份校验草案（v12）

状态：**draft / 离线 fixture**。本实现不接入备份资格、controller 或真实 artifact。

## D 已定义的输入与检查

`backend/internal/systembackupresources.VerifyBackupSnapshot`接收源视图与 dump 视图各一份脱敏元数据、冻结的同版本 registry，以及 B 提供的 `CaptureProofVerifier`。两份元数据各含 checkpoint SHA-256、capture-context SHA-256、已登记 evidence ID、九张固定表的行数和 `audit_logs` 最大已纳入 ID。空审计表的最大 ID 为 `null`。

调用顺序固定为：registry 冻结门禁 → 两份元数据完整性校验 → B 的证明校验 → D 的逐项比较。没有证明校验器、证明校验失败、表集合不完整、审计 cutoff 与行数矛盾时，函数返回错误和空检查集，不产生通过结论。

机器合同 `verifier-contract.schema.json` 中 `resources/backup_validate` 的 D 草案登记了 12 个 check：checkpoint、capture context、九张表的 `resources.table_count.<table>`、`resources.audit_cutoff`。`expected/actual` 只包含 hash、非负行数或最大审计 ID，不包含业务行或凭据。已认证输入出现差异时，对应 check 为 `failed / integrity / validation_failed`。校验结果的封装、持久化和资格判定仍需公共合同冻结及集成。

## B 交接要求

B 的 `CaptureProofVerifier` 必须独立验证 capture certificate 的真实性、有效性和未被 forced resume/失效 gate 撤销；验证 dump 内容确实产生了所报告的表集、行数和审计最大 ID；证明源端统计和 dump 统计都绑定到同一 MySQL checkpoint 与 capture context。仅比较两份自报 JSON 或检查 `sev_` 引用格式不能实现此接口。若 B 无法在源端只读事务与 dump 之间给出共同 checkpoint，当前 `SQLCountCollector.CollectSnapshot` 的数值不能作为已证明的 expected 侧，需由 B/D 共同调整采集流程。

固定样例在 `backend/internal/systembackupresources/testdata/resources-backup-verify-draft.json`，其中 proof 明确标为 `synthetic-test-only`。Go fake verifier 只供离线逻辑测试，不代表 B 的证明已交付。A 仍需统一 redaction/evidence 接口；A/B 仍需评审北向平台管理配置字段的备份与恢复语义。

## D 控制表排除检查（restore_validate 草案）

`ControlExclusionAllowlist`从同一冻结 registry 核对 31 张系统备份控制表及其 `metadata_only/reference_only` 策略；任何新增、缺失或误归类的控制表都会使门禁失败。`schema_migrations` 属于目标本地迁移元数据，不作为源控制记录的空表检查对象。

`SQLControlExclusionVerifier.VerifyRestoreTarget`要求 B 提供的隔离目标证明、已登记 evidence ID 和独立只读数据库连接。它在一个只读 repeatable-read 事务内检查 31 张 InnoDB 基表并逐表计数：零行为 `passed`，非零行为 `failed / integrity / normalization_failed`。证明、表结构、查询或事务提交失败时不返回部分检查。机器合同中 `control_plane/restore_validate` 登记了这些封闭 check ID 和行数字段。

B 的目标证明需要在执行检查的同一个只读事务上覆盖 planned/observed 目标身份、normalization 已完成、restore 写凭据已销毁，以及 verifier 的新连接只有 SELECT/必要的 `information_schema` 权限。目前只有 fake proof 与 fake DB 定向测试；没有真实隔离目标或凭据证明，因此这项检查还不能用作 drill 验收。九张业务表的恢复归一化策略仍须 A/B/C 交叉评审和 normalization registry 冻结。
