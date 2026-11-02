# Skills 生产采集与恢复接线核对

核对基线为 `951f4c517e0584d6ef1ee5424c1edd41f97c9f28`，日期为 2026-11-02。Skills 的发现、正式 worker、固定版本对象、共享 SQL 与未打包 workspace 校验已有生产消费点；当前无需重建模块。此结论来自本地调用链静态检查，不表示真实页面备份、完整 writer 物理覆盖或正式成品恢复已经验收。本轮仅新增本文件，不改共享生产构造，不启动编译、MySQL、容器或远测。

## 已消费的生产接口

| 数据或能力 | 实际生产接点 | 必须保留的绑定 |
| --- | --- | --- |
| 八张 Skills 表发现 | `systembackupexecution/production_source_profile.go:attachProductionSources` → `publicadapter.WithSkillCaptureInventory` → `domain.ReadSkillCaptureInventory` | 原 discovery RR transaction、源 database/server UUID、users/instances 所有权及完整八表 keyset/schema hash |
| 共享 SQL 成品 | `publicadapter.NewUsersInstancesModule` 把 `Source.Skills` 写入 `Database.SkillsInventory`；`worker/database.go` 及 `formal_observer.go` 调用 `domain.VerifySkillCapture` | 使用同一份完整业务 SQL snapshot，包含 raw columns，不以有限发现投影替代 SQL；Skills 与 users/instances/Teams 不另开拼接快照 |
| 正式模块注册 | `production_source_profile.go` 工厂 → `productionCaptureModules` → `NewSkillObjectsModule` | `skill_hub`、`skills_objects`、`capture-skill-objects`；原 task/attempt、capture context、hold deadline、part index 和 provider context 一致 |
| 对象版本冻结 | `production_source_freeze.go` → `originalSourceMetadataAuthority.skillObjectMetadata` | 独立材料限定的 bucket/prefix、启用 versioning；遍历版本后选择各 key 的原 current immutable version，保留未被 SQL 引用的对象，最新 delete marker 不作为内容 |
| 实际对象字节 | `worker.captureSkillObjects` → `CopyFrozenObject` → `VersionReader.OpenVersion` | 精确 VersionID 与 size；从该次 GET 计算 SHA256 和 metadata；不得以 latest GET 或另一个任务的摘要替代 |
| 独立内容检查 | `systembackupexecution/owned_payload_reader.go:inspectOwnedSkillObjects` | 重算归档内每个对象 SHA256，逐项比较 key/version/size，重建完整 canonical index，拒绝多余成员、损坏内容及遗漏 metadata |
| 未打包内容 | `CaptureInventory.WorkspaceRequirements` → `production_source_runtime.go:instanceMountMetadata` → `NewSkillObjectsModule` 的原 workspace 依赖 | 每个无 ObjectKey 的 blob 必须由原绑定或 materialize job 的路径及预期 MD5 定位；实际 whole workspace 归档通过 `VerifyWorkspaceCapture`，不能靠一个 covered 布尔值销项 |

八表为 `skills`、`skill_blobs`、`skill_versions`、`instance_skills`、`skill_package_materialize_jobs`、`skill_scan_results`、`skill_hub_tags`、`skill_hub_tag_assignments`。全部 `skill_versions` 的 BlobID 关系来自 SQL；对象存储 VersionID 是另一种身份，不与 SkillVersionID 混用。冻结阶段 SHA256 可为空，实际 worker 必须计算，独立 reader 随后重算并核对最终 index。

`production_source_profile.go:CheckFrozenSources` 重新取得源元数据并比较原 bytes；源或版本漂移应拒绝，不能悄悄换成较新版本。未打包 Skills 所需的 OpenCode Pro project 映射尚未从原 SQL 独立冻结，`production_source_runtime.go` 和 `publicadapter/skill_workspace.go` 因而主动拒绝该组合。B/D 应补原映射及受信路径后再支持，不能移除拒绝或仅指定调用者路径。

## 给 B 和 D 的 writer 差集

`services/skill_package_materialize_worker.go` 中的 `skill-backfill` permit 覆盖一次回填，`skill-materialize` permit 覆盖一次完整 claim/batch、子 goroutine、未开始 job 的 ReleaseToPending、取消清理与 wait。`StopAndWait` 超时保留仍在运行的 run；没有实际退出便不能重启或认为已停写。

当前 `worker.BackupGate=nil` 并不直接绕过门禁：`enterBackupMutationContext` → `mutation.EnterContext` → `backupgate.HoldWorkUnit`。`cmd/server/main.go` 在 worker StartContext 前，按非空 `db.SQLGateScope()` 调用 `ConfigureWorkBoundary`，通过独立控制池 `HoldRequest` 接到同源 SQL gate；同文件给 Gin 路由注册 `middleware.BackupRequestBoundary`，覆盖含副作用的 GET。scope 未启用时此 optional 边界允许原 disabled 行为，这不能授予正式 capture 资格。

需要 B/D 对安装现场核对以下原参与者，而不是新增另一套 Skills 控制器或给 coverage JSON 添两个字符串：

1. 承载 `startBackground` 的真实 App Deployment 和全部副本、leader 切换时旧 run 的退出；冻结 UID/generation/original replicas，停止后保留原 stop witness，恢复后核对原状态。
2. 普通 Skills/Skill Hub 导入、更新、删除、安装、同步、重扫、包收集等 HTTP 写入，以及 agent `/skills/inventory`、`/skills/upload`、runtime-agent `/skills/report` 的实际请求边界；正在进行的 SQL、对象上传及 workspace 写入都须结束。
3. materialize 实际消费路径为 `ProcessJob` → `materializeSkillPackageFromWorkspace` → `loadLiteSkillDirectoryFromWorkspace` → `persistDiscoveredSkillPackage`，覆盖本地 workspace 读、对象 PutObject、scanner 和 SQL 更新；这一方法不启动 Runtime 命令。其他 Skills 同步/安装调用的 Runtime 命令及源实例/Runtime/工具实际写 workspace 的进程，仍须由 B/D 证明退出；HTTP 返回、permit 释放或 SQL lease 为零不能证明远端子进程退出。
4. `TeamPlatformUnits` 目前只允许 `TeamsWorkUnits()` 的六个 Teams 单元，是 Teams delta。勿把 `skill-backfill` 或 `skill-materialize` 填进去绕过闭集；全平台 writer inventory 和物理覆盖由 B/D 原构造承担。

上述代码已有本域生命周期组件；本轮没有证明现场四项均满足。没有发现可独立于 B/D 构造修复的 Skills 最小代码差集，故不抢写 main、controller、production_source 或 Teams 文件。

## 给公共 C 的正式成员接口

从同一 task/attempt 的 `skills_objects` 正式成品认证、解密后读取内部 tar，按 `PrepareObjectCapture` 的 key 排序读取：

```text
skill-hub/header.json
skill-hub/objects/0.bin ... skill-hub/objects/N-1.bin
skill-hub/index.json
```

header 是当前 Go JSON 字段 `Version`、`InvocationSHA256`、`Spec`，不是另造的小写 DTO；Version=`skill-hub-versioned-capture.v1`。index 条目保留 `key/version_id/size/sha256/metadata/etag/last_modified/omitted_user_metadata_count`。沿用现有独立 reader 对 bytes、顺序和成员闭集的核对。metadata omission 不得被忽略成成功。

最终成员集合还必须有同一成品中的 `users_instances_database` SQL（模块 ID 为 `users_instances`）和每个所需 `instance_<id>_workspace`；`skills_objects` 中列出 WorkspaceRequiredBlobIDs 并不表示这些 blob 已经备份。非空验收应报告 SQL 八表行数、技能版本与 blob 关系、实际对象数/字节、未打包 blob 的原路径/MD5 覆盖。源确实为空时保留真实零值，不生成非空证据。

## 正式成品恢复所需输入

公共 `publicadapter.NewRestoreRunner` 当前仍返回 `ErrRestoreSourceUnavailable`。恢复 owner 应先取得 A/D 的完整认证源句柄、原 manifest/精确对象版本、同成品解密能力、独立目标身份和 startup fence，再沿原 public task/RestorePorts 接线，保留失败与 unknown 原操作身份。

已有本域接口可直接消费，无需新增平行恢复格式：

- 完整 raw SQL 共事务路径：`domain.RestoreDrillWithEvidence` 的 `Policy.Skills` 及 `worker.Database.SkillsRestore`；`domain.VerifyDrill` 使用独立只读 SQL 连接验证，`VerifySkillQuarantineContext` 核对危险状态不重放。此路径保留共享 SQL ID，不混入另一套会改 ID 的独立八表写入事务。
- 数据模块准备：`systembackupskillhub.Normalizer.Normalize` / `RestoreRequest`，其 Binding 需要 registry/schema/checkpoint/capture-context/artifact/target hashes 及原 EvidenceRef；所有权证明由具体 authority 提供，哈希语法不是认证。
- 对象：`PrepareObjectRestore` 消费认证的源 Blobs、完整 FrozenObject/CapturedObject index、SQL ObjectKeys 映射和独立目标上传回执的 key/VersionID；包括未被 SQL 引用的对象。用目标只读 VersionReader 调用 `VerifyObjectRestorePlan`，精确比对摘要和 metadata。
- 完整独立核验：`RestoreVerifier.Verify` 同时要求 SQLRestoreVerifier、目标 Objects、WorkspaceRestoreVerifier 和 RestoreVerificationAuthority；缺一即拒绝。workspace authority 必须核对同成品、目标代数、binding/job 路径与全部未打包 blob 预期内容，不能用 sev_ 字符串或 workspace 成功替代完整 Skills。

## 协调者可合并安排的验证

以下为待安排的本地定向回归，不是现场完整备份命令；本轮未执行，因此没有测试退出码。协调者在已有构建环境的仓库 `backend` 目录执行，依赖保持本机现有版本，SQL 两项仅在其独占 disposable MySQL 夹具启用 `TEST_D_LOCAL_MYSQL_CREDENTIALS` 后运行，SKIP 不算通过。禁止自行指向生产 DSN。

```powershell
# shell: PowerShell; cwd: C:/Users/zhanghui08/Desktop/clawmanager/ClawManager/backend
# 前提：协调者已设置其本轮独占 GOCACHE/GOTMPDIR；不得复用其他运行中的可写缓存。
$env:GOTOOLCHAIN = 'local'
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
$env:GOTELEMETRY = 'off'
go test -count=1 -p=2 ./internal/systembackupskillhub -run '^(TestCaptureInventoryRetainsEightKeysetsAndOriginalWorkspaceRequirements|TestObjectCapturePlanIncludesUnreferencedAndSharedObjects|TestCopyFrozenObjectUsesExactVersionAndContentSHA256|TestObjectCapturePlanRejectsIncompleteOrOversizedInventory|TestObjectRestorePlanRejectsIncompleteOrInconsistentMappings|TestRestoreVerifierRejectsMissingCapabilitiesAndBadPreflightBeforeIO|TestRestoreVerifierStopsOnFailureWithoutPartialSuccess)$'
go test -count=1 -p=2 ./internal/systembackup/publicadapter -run '^(TestSkillsModuleBuildsActualJobWithOneSharedSQLDependency|TestSkillsModuleFailsClosedWithoutWorkspaceProofOrExactInventory|TestUnpackagedSkillsRequireActualOriginalFormalWorkspaceDependency|TestSkillsDiscoveryAndSharedSQLWorkerNonemptyMySQL)$'
go test -count=1 -p=2 ./internal/services -run '^(TestMaterializeGateContextLossJoinsChildrenAndCleanup|TestMaterializeBackupGatePermitSpansCanceledJobCleanup|TestMaterializeWorkerStopTimeoutDoesNotAllowOverlappingRestart|TestMaterializeBackupGateReopensDeferredBackfillExactlyOnceBeforeClaims)$'
go test -count=1 -p=2 ./internal/systembackupexecution -run '^(TestProductionSourceObjectVersionSelectionOriginalAuthorityTLSMySQL|TestFormalObserverVerifiesSkillMD5InActualWholeWorkspaceArchive|TestFormalSkillObserverRejectsValidAEADWithUnsafeArchiveHeaders)$'
```

每条命令分别检查 `$LASTEXITCODE`，预期为 0，必要 MySQL 根不得 SKIP。将 stdout/stderr 和前后源码集合留到协调者原有本轮证据目录；本交接不另分配端口、数据库、容器或缓存。日志按原证据交付，测试构建产物在结束后仅由其 owner 清理：先解析其自建 scratch 的绝对路径并确认在仓库/backend 内且归属本轮，再 `Remove-Item -LiteralPath <已核对的该轮绝对路径> -Recurse -Force`。不得清理全局 Go cache、他人缓存、日志或 `.worktrees/`。

最终现场验收仍需协调者安排真实页面点击产生的同一正式成品；上面的组件回归与既有证据均不能替代该结果。当前优先依赖 A 原 30 秒授权窗口内采集通过、B/D 完整 writer 实际覆盖、公共 C 正式发布完成，然后沿该成品接入隔离恢复。

## local cleanup 后远端最终校验的具体谓词

本节供公共 C 的 `publication_final_verification` 接线使用，区分当前确实执行的谓词与建议补入的纯冻结数据复核。核查时该新文件尚未出现在工作区，不对其未来实现作通过判断。

远端已有实际路径是 `verifyOriginalRemoteContainerCapture` → `inspectOriginalRemoteContainerMember` → 当前 `PublisherVerifierForPart` → `CapturedRecord` → `ArtifactReadOnlyS3.InspectContainerCipher` → `inspectOwnedBusinessPayload`。每个成员在自己的 bounded deadline 下验证原 candidate、envelope、AEAD 完整流及当前 verifier.Recheck；container header scope、SourceInventorySHA256、完整成员数量和 seen 闭集在外层核对。不是只验证外层 S3 checksum。

| 分支 | 远端读取中已执行 | 此分支不执行 |
| --- | --- | --- |
| 共享 SQL | `domain.Decode`；candidate Rows/Tables 和内存限额；BusinessTableSourceScope；`VerifyBusinessCapturedSnapshot`；SkillsInventory 非 nil 时 `domain.VerifySkillCapture(snapshot, *spec.SkillsInventory)`；gzip EOF/限额 | 不强制 SkillsInventory 非 nil，不自行取另一个成员的 inventory，不与 skills_objects spec 对比 |
| skills_objects | `inspectOwnedSkillObjects` 用 Spec.Blobs/Spec.Objects 调 `PrepareObjectCapture`；全部未打包 ID 列表一致；header 完整 bytes 与当前 invocation hash 一致；每个实际归档对象 size/SHA；index key、VersionID、size、SHA、metadata omission 和 canonical bytes 一致；成员/尾部闭集 | 不解码共享 SQL，不拿 `Spec.InventorySHA256` 与 SQL.SkillsInventory/Sources.Skills 再比，不验证实际 workspace 成员已完成 |
| SkillWorkspace | `VerifyWorkspaceCaptureWithCounts` 及 spec.Validate；whole archive 安全头、唯一成员、大小/文件数/内存限制、SKILL.md、按规范文件集合算出的 ContentMD5、零 padding 与源 EOF；实际 Entries/Bytes 等于 candidate.Files/Bytes | 不从 SQL inventory 重建 requirement，不自行证明该 BlobID/BindingID/JobID 是 SQL 中的原关系，不聚合所有 workspace 的未打包覆盖 |

`domain.VerifySkillCapture` 内部先验证 raw Snapshot，再从 users/instances 和八表重建 `skillCaptureProjection`，对用户所有权、skill→version→blob、binding/job 引用、八表完整 IDs/schema hash 验证并比较整个 CaptureInventory.SHA256。它不是只比较表总行数，也不验证对象字节或 workspace。`frozenSkillsInventory` 若用于最终 helper，应是从认证 `capture.Input.SourceSnapshot` 解出的 `SourceInventory.Skills` 的私有副本；现有实际 SQL 请求字段叫 `Invocation.Request.Database.SkillsInventory`。

### 已在生产装配执行的跨成员约束

`NewUsersInstancesModule` 将源 Skills clone 到共享 SQL spec；`modules.go` 的 Build 再检查该 SQL inventory hash 等于源 Skills hash。`NewSkillObjectsModule` 要求对象 InventorySHA256 等于源 Skills hash，Blobs 数量与每个 ID/ObjectKey/SizeBytes 精确一致，并以原 B workspace dependencies 覆盖未打包 blob。最后 `validateSkillWorkspaceParts(source, assembled JobParts)` 调用 `validateOriginalSkillWorkspace`，要求每条 requirement 属于源 inventory 的 `WorkspaceRequirements()`，检查原 instance/runtime/part/mount，并聚合每个无 ObjectKey blob 的覆盖。`productionInventory` 再检查共享 SQL inventory 与 source.Skills 相等。

这些已执行约束连同原 sealed plan、invocation hash、capture context 和远端 description 的成员绑定构成既有链条；没有证据支持“可以随意拼接不同任务成员通过”。但 `inspectOwnedBusinessPayload`、`validateDescriptionContents` 和 `verifyOriginalRemoteContainerCapture` 没有集中重新执行上段 Skills 语义关联。`validateDescriptionContents` 检查 invocation/candidate/scope/hash 及 control seed 闭集；它不调用 `NewSkillObjectsModule` 或 `validateSkillWorkspaceParts`。

### 给公共 C 的最小复核输入与顺序

在 local cleanup 之后，从当前 claim 的原历史读取及远端认证材料开始，不重开 source DB、不重新 freeze、不重采集，也不依赖已删除本地文件。复用既有远端函数与解析器，只补一个有界的纯数据交叉检查：

1. 要求 `capture.checked()`；严格解码原 `capture.Input.SourceSnapshot` 为 `b.SourceInventory`，核对其 bytes hash 等于 `capture.Input.SourceSHA256`。源 Skills 非 nil；从源 Users/Instances 构造 users/owners，调用 `Skills.Validate(users, owners)`。远端 description.SourceInventoryJSON 已与此原 bytes 比较，不另造 inventory。
2. 原完整 part 集合中恰有 `b.UsersInstancesDatabasePart`（值为 `users_instances_database`）/capture-database 和 `b.SkillObjectsPart`（值为 `skills_objects`）/capture-skill-objects。使用本轮当前 verifier 的 `CapturedRecord().Invocation`；每个 record 按 `publicationContainerMember`、`sameOriginalContainerMember` 及原 part invocation/candidate/result hash 校验。不能只接收一个调用者 map 或沿用前次 claim 的 live verifier。
3. SQL spec 必须有 SkillsInventory，且 SHA256 等于 frozenSkillsInventory.SHA256。对象 spec 的 InventorySHA256 也必须等于该 hash；Blob IDs 无重复，完整数量及各 ID/ObjectKey/SizeBytes 与 frozen inventory 相等。使用 `PrepareObjectCapture(ctx, convertedBlobs, objectSpec.Objects, limits)` 得到精确固定版本 object plan，并逐项比较其 UnpackagedBlobIDs 与对象 spec.WorkspaceRequiredBlobIDs。
4. 从 frozen inventory 调 `WorkspaceRequirements()`；对所有原 SkillWorkspace specs 调 Validate，核对其 InventorySHA256、InstanceID、MountID=workspace、part=`instance_<id>_workspace`、Runtime 与同一源 instance/runtime policy。每个 requirement 必须属于原 allowed requirement 集合。保留现有 OpenCode Pro project 缺认证映射时的拒绝。聚合完整远端成员集；所有无 ObjectKey 的 blob 至少有一个已完成远端认证与 MD5 内容检查的 workspace 覆盖。不得要求 blob 只对应一个路径，因为原绑定/job 可能提供多个合法来源。
5. 接着或在上述登记后，对每个选定远端 immutable version 实际执行既有 `inspectOwnedBusinessPayload` 与完整流验证。只有其外层 AEAD/EOF/当前 authority 最终检查均成功，才把该成员标记 verified；失败时丢弃整轮聚合，不能在 parser callback 返回时提前授予 receipt。最终再检查 required 与 verified 成员/未打包覆盖闭集并绑定最终当前 claim。

非空应由原 inventory 推导：SQL 已对完整 keyset/关系严格匹配；对象 plan 非空便必须实际读取每个归档对象；原有未打包 blob 便必须有通过实际 MD5 的 workspace。不要硬编码对象数>0，合法非空 Skills 可以全部未打包；也不要以 Files>0 代替具体 blob 覆盖。`SkillVersionID`、对象存储 VersionID、SQL ContentHash/ObservedHash（内容 MD5）与归档对象 SHA256 是不同语义，不能直接互相比字符串。

`validateOriginalSkillWorkspace`、`validateSkillWorkspaceParts` 当前是 publicadapter 包私有函数；公共 C 所在 systembackupexecution 包不能直接调用。最小复用选择是由协调者划分归属后增加窄的纯验证导出包装（不授予 authority），或在公共 C 自有 final helper 按上述谓词消费 frozen inputs。无需重新实例化 BuildCapturePart/完整模块工厂，也不引入新 gate、provider 或恢复目标。

本节仅静态核对和独占文档追加，未执行编译、SQL、远程或生成构建产物。建议必要回归只覆盖：缺 SQL SkillsInventory、错 object inventory hash、遗漏 blob ref、错 workspace requirement、缺未打包成员，以及合法全未打包非空 Skills；由协调者合并到公共 C 原 final verification 定向测试，不并发运行本域测试。
