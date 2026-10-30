# A：KEK 正式准入代码交接

2026-10-29。本文记录 A 的代码边界和当前实际装配状态；候选或测试通过均不表示已完成现场准入。

## 已落地的 A 边界

- `systembackupkekadmission.CheckUnadmittedInput` 只检验候选内部结构、两用途 typed ref、精确 provider 版本、四分区形状，以及每个历史引用的完整 KeyBinding 和 JCS 摘要。它不产生许可。
- `systembackupkekadmission.Prepare` 要求独立的 `PreparedMappingSource`、generate 与 unwrap 各自的 `PreparedCapability`、完整 `PreparedCoverage`。首笔登记允许 D 快照中的 binding 列表为空，但仍须有四分区独立完整扫描，且不能有悬空历史引用；已有同一 identity/version 须复用 D 的 `SameSecurityBinding` 安全语义比较并保持两用途未撤销。只有 `description_redacted` 及其原字节摘要允许在后续准入改变，其他来源、版本、期限或集合不一致均拒绝。
- `PreparedAdmission.Recheck` 只接收 D 在原事务及共享 fence 内取得的 `LockedSnapshot` 和 SQL 时钟；使用 D 的 `SameSnapshotFacts` 核对冻结的 SQL 事实，允许准备与加锁两次采样时间不同，再调用原映射、两用途及 coverage 的复查。epoch、引用或覆盖来源变化仍拒绝。它不调用 provider、不提交事务，也不签发 Job grant。
- `systembackupkekadapter.KEKAdmissionValidator` 分别将 bootstrap 原 grant/config pin、config mutation 的 `reference:kek` 当前/拟议 pin 与上述准入检查绑定。轮换时旧 binding 必须仍出现在完整历史快照。导入放在独立 adapter 包，避免 security → admission → typed-ref → security 的循环依赖。

## 原来源 reader 和生产 caller

2026-10-30 更新：D 的 `6efb79c1` 已交付 `InstallationPreparation`、签名原映射记录的 `SQLOriginalReader`、事务内 `RecheckOriginal`、`WireServices` 装配函数以及提交后 `ReadCommitted` 核对。随后 `6b15c64a` 交付版本化权威表/历史表迁移、同一 KEK fence 下的签名记录 importer 与操作员命令；导入者不持有原安装签名私钥，也不从候选/配置生成映射。A 已核对源码：`WireServices` 在生产构造中仍没有调用；`CapabilityPreparation` 仍为接口，C/B 的四分区 `PreparedCoverage` 与 writer fence 尚未实现，`Bound.CompleteScan` 仍固定返回 `ErrKEKCoverage`。因此签名记录的独立读写边界已有代码，但现场原安装 owner 的真实签名记录、公钥 pin、两用途当前 capability、生产服务装配与完整扫描仍待交付。以下早期“尚无 reader 实现”的描述以本段为准。

A 对 D reader 的复审增量：原签名 JSON 在验证签名后还需拒绝重复成员、未知成员和尾随值；`WireServices` 对值或指针形式的 SQL reader 都要固定同一 DB，且拒绝非 SQL reader 混入此部署组合。定向回归覆盖签名歧义和跨库 reader；这些安全校验不构成现场签名记录或准入回执。
`go test -mod=readonly -p=1 -count=1 -timeout=180s ./internal/systembackupkekadapter -run '^Test(OriginalSignatureAndRevocation|WireServicesPinsSQLOriginalReaderDatabase)$'`（默认 vet）最终 `TEST_EXIT=0`，包运行 2.945s；本轮隔离 Go 缓存和临时目录返回 `ARTIFACT_CLEANED=True`。前一次只测原签名记录时也为 `TEST_EXIT=0`，隔离产物已清理。

`OriginalKEKPreparation.PrepareKEK(ctx, AdmissionInput)` 是 A 的注入入口。D 的 `InstallationPreparation` 已实现独立原 mapping reader，读取并认证与候选独立的原安装签名记录，返回 `PreparedMappingSource`；两用途当前权限对象仍由尚未实现的 `CapabilityPreparation` 提供。reader 固定原安装、identity_hash、opaque registry_version、完整 provider locator/key/version、两份 typed ref 原字节与 SHA、来源 revision、有效窗口和撤销位置；不能把 candidate 与其 expected hash 当作两个独立来源。生产构造尚未注入该接点，也没有正式准入回执；A 不提供恒成功默认实现。

具体 caller 为 D 的原 bootstrap/config mutation owner：`ConfigBootstrapService.KEK` 与 `ConfigMutationService.KEK` 在 SQL 锁外通过 `systembackupkekadapter.BootstrapComposition` / `MutationComposition` 取得 A 准备对象；在原授权及既有引用锁之后 `Bind` 同一 KEK fence，在原 config/operation 事务内 `StageAdmission` 并最终 `Recheck`。这些原事务接点已由 D 提交于 `abd6565c`，但现有生产构造尚未调用 `WireServices`。`BootstrapOwnerAdapters.References["kek"]` 与 `ConfigMutationResolverSources.References["kek"]` 仍须固定同一原 registry 引用及配置关系。提交成功并读回准确 config/operation 关系后，运行组合才能创建 `systembackupkms.Config`。`Bound.CompleteScan` 仍返回 `ErrKEKCoverage`；生产装配、现场原权威签名记录、C 四分区 scanner/adoption 和 B/原 writer 覆盖尚未接通，故当前生产 caller 应 fail closed，不能从 A 准备对象直接构造 Config。

四分区完整扫描需要 C/B/原 producer、hold、catalog、restore/prune owners 接入同一个 D fence。缺 adoption/backfill、分页 EOF 或 writer 参与时，`PreparedCoverage` 不得由空列表替代。D 的 [持久化与锁协议交接](system-backup-d-kek-persistence-locks-20261029.md) 给出了需落盘的事实和锁序；该文档目前明确实现未完成。

## 验收边界

本地 vet/test 仅验证结构和独立来源接口的拒绝逻辑。正式准入仍需 D 已提交的 SQL reader/Bind/Stage 在生产构造中启用、独立原来源认证、四分区完整扫描和成功提交读回；真实 generate/unwrap 还需要 B 的冻结 `systembackupkms.Access`、原 Job/Pod/SA 身份与 permit、精确 provider policy/role 及现场操作回执。已通过的 JWT trust 和 KEK profile 回执不替代这些证据。

2026-10-29 本批 `go vet -p 1` 与 `go test -p 1` 对 `systembackupkekadmission`、`systembackupkekadapter`、`systembackupsecurity` 三包均退出 0；专用测试构建缓存已清除。此结果不包含后来 D 的事务接线或生产扫描验收。
