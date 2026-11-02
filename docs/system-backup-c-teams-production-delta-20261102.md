# Teams 生产备份差集与正式成品验收交接

核对基线：2026-11-02，HEAD `951f4c517e0584d6ef1ee5424c1edd41f97c9f28`。本轮由 C—Teams 核对实际调用；只新增本页，不改共享构造、安全、发布或其他 owner 文件。当前已接入生产构造的能力不再沿 10/30 交接重复实现。真实页面同一 task/attempt 备份成功仍是第一优先级。

## 生产已消费

| 内容 | 实际调用点与约束 |
| --- | --- |
| 自动 Teams 发现 | `systembackupexecution/production_source_profile.go:attachProductionSources` 在 six-part、ForwardEnabled 及材料验证通过时安装 `WithTeamsSourceFacts`、`FreezeSourcesWithWriters`、`CheckFrozenSources` 和模块工厂。`production_source_freeze.go:freezeProductionSource` 从原 SQL facts 绑定真实 PVC/PV UID；`BindAutomaticStorage` 不接受另外维护的 Team 清单。 |
| 唯一 SQL snapshot | `production_capture_modules.go:productionCaptureModules` → `NewUsersInstancesModule` 把 TeamsInventory 放入唯一 `users_instances_database` 请求；`worker/database.go` 同一次 `CaptureSource` 后运行 `domain.VerifyTeamCapture`，封存前核对当前 schema、owner/member、共享目录和 northbound operation 关系。Teams 模块只有 SQL dependency，不另采 SQL。 |
| 11 表 | `custom_team_templates`、`owner_team_admission_locks`、`owner_team_provision_steps`、`team_event_outbox`、`team_events`、`team_members`、`team_tasks`、`team_work_items`、`team_workflow_phases`、`team_workspace_file_audits`、`teams`；另依赖 B 的完整 `northbound_operations`。 |
| Redis | 当前生产走唯一 `source_redis` / `capture-source-redis`，Teams 依赖该 part。`validateSharedTeamRedis` 验证 server、DB、每个 Team 前缀及 exclusion；不再要求生产每 Team 单独 `capture-team-redis`。 |
| 共享目录 | 每个原 Mount 生成 `team_<id>_workspace`，原 PVC 只读挂载 `/workspace`；工厂和 `NewTeamsModule` 固定 part、capture context、deadline、全局 part index。成员私有完整根仍由 B 的 instance workspace 覆盖。 |
| 空 Team / 删除历史 | 无活跃 Team 仍注册 SQL dependency；删除历史保留 SQL，不要求已删除的共享卷。不能用空清单替代现场实际非空数据。 |
| writer 映射 | `production_source_authority.go` 校验 TeamPlatformUnits；freeze 将其与 FrozenWriter 原 UID/generation/running/checkpoint 绑定，再绑定实际成员 Runtime，调用 `ValidateTeamsWriters`。public runner 在准入和捕获 fence 再验。 |

以上是当前源码消费关系，不等于现场已经部署或获得正式成功成品。

## 实际缺接和 owner 输入

1. **D 的生产 Teams 对象发现仍为空。** `freezeProductionSource` 初始化 `AutomaticStorageMapping.Objects=[]team.ObjectRef{}` 后未填充；因此该生产路径的 `source.Teams.Objects` 为空，工厂不会生成 `teams_objects`。`CaptureTeamObjectRefs` 已能按 Bucket/Key/Version 读取并核对 size/SHA256，但不能据此声称生产对象发现完整。当前业务 artifactRefs 主要指向 `/team/` 文件。需要 D/B 确认现场是否还有独立 Team 对象、其权威 TeamID 关系及冻结版本来源；若有，D 在原 source grant 下提供 `[]team.ObjectRef{TeamID,Bucket,Key,Version,SHA256,Size}` 给原 `BindAutomaticStorage`，并保证后续 frozen check 使用同一规则。禁止推断对象归属、LIST 全 bucket 或用今日版本替换原版本。本轮未改 D 文件，也未把“可能没有业务对象”冒充认证的空集合证明。
2. **正式恢复源未接。** `publicadapter/restore_runner.go:NewRestoreRunner` 当前仍返回 `ErrRestoreSourceUnavailable`。C 的 staging 恢复组件不提供正式 CMBKGC01 unwrap、源认证、目标授权或公共调度；A 提供完整认证源句柄，D/B 沿原 RestorePorts 装配。保持该拒绝边界。
3. **artifactRefs 验收组件已齐，生产恢复入口尚不能调用。** 原 SQL 的 `artifact_refs_json` 原字节保留；`domain.TeamArtifactReferences` 从同一 snapshot 的 work item/task/event 提取显式路径。`NewTeamWorkspaceSpec` 核对 Teams capture 并绑定原 SQL 密文 digest。它是恢复输入，不是 grant，也不是当前捕获阶段已经验证了每个引用文件的证明。

## 交给 B 和 D 的完整 writer 差集

`publicadapter.TeamsWorkUnits()` 返回独立列表：`team.pending_deletions`、`team.event_projection`、`team.maintenance_sweep`、`northbound.operation`、`northbound.lifecycle_action`、`team.workspace_http`。

前三项实际边界在 `services/team_service.go`，operation/lifecycle 在 `northbound/core_service.go`。lifecycle 的子动作在实际退出前持有共享 work permit，父取消/租约过期不释放它。`team.workspace_http` 是共享 HTTP admission / SQL work boundary 的覆盖类别；不是一个单独名为该字符串的 HoldWorkUnit 实现。App 的实际入口是 `middleware.BackupRequestBoundary`，包括会创建目录/审计的 GET；独立 Core API 在 `cmd/server/main.go` 使用 `HTTPBoundary(...,"northbound.core_http")`。

D 必须提供每个实际平台 writer（全部副本/其他服务进程）的 ID、UID、generation、原运行状态、checkpoint 和确切执行的 Units；B/D 为每个非零成员 instance 提供原 gateway/pod/deployment/stopped writer，不能把 SQL stopped 映射成 running。C 的 finite-unit 列表不是平台发现全集，也不覆盖 B 的其他 scheduler/sync/Runtime/工具子进程。coverage JSON 的 union 满足校验不能替代真实 HTTP 排空、子进程退出、Redis/文件外部 writer 停止及原状态恢复回执；这些仍由 B/D 独立提供。

## 同一正式成品的恢复和独立验收顺序

前提是公共 C 已交付同一 task/attempt 的成功正式 manifest、marker、catalog、固定版本 index/parts；A 认证签名、unwrap/解密，D 认证隔离 namespace、SQL/Redis/object/PVC 身份与卷映射。失败或 unknown 沿原操作身份收敛，不能另采或拼接别的 task。

1. 从该正式成品的 `users_instances_database` 认证解密出 `domain.Snapshot` 和原 inventory。运行 `VerifyTeamCapture`，确认 11 表非空业务样本、owner/member、northbound operation/创建历史、任务/结果/模板/icon/audit 关系；不从 live SQL 重新发现。对现场原本为空的表记录真实行数，不伪造样本。
2. 对每个共享 Mount 调用 `worker.NewTeamWorkspaceSpec(snapshot, inventory, teamID, originalSQLCiphertextSHA256)`，绑定原 SQL 密文 digest、inventory digest、原 `team_<id>_workspace` part 和同一 capture context。A/D 将正式原对象认证解密后转入受控 staging，D 将独立目标 PVC UID 与该源绑定，不复用源卷或仅凭名称前缀授予写权。
3. 原 worker 的 `restore-workspace` 携带 TeamWorkspace、`PolicyVersion=teams-shared-workspace.v1`，完整认证 staged 对象后才向空目标写 inert data；`kube.TeamWorkspaceJob` 要求隔离 namespace、绑定 Pod 身份与受控命令。恢复只返回 Quarantined=true、Verified=false。
4. 独立 `verify-team-workspace` Job 对 target/staging 都只读。核对完整 archive 的文件内容、类型、权限、时间/适用时 owner、链接文本、无额外文件，并确认每个 artifactRef 是普通文件且父目录无链接替代。缺引用、坏版本、损坏、非空目标、跨 part、撤权均保留失败/不确定副本。仅独立 verifier 成功才 Verified=true。
5. SQL 恢复沿公共 Normalize/Restore/VerifyDrill；独立 `VerifyTeamQuarantine` 确认成员 offline、活动任务终结、凭据/cursor 清除、outbox/锁不重建、owner/template operation 不重放。结果/历史/产物关系保留。禁止启动消费者证明“可用”。
6. 从同一 `source_redis` 认证导出走 `RestoreRedisHistory` / `VerifyRedisHistory` 到独立 Redis，保留历史而不重建活跃执行键。若实际有 Teams 对象，原 `teams_objects` 走 `RestoreObjects` / `VerifyObjects` 到独立 bucket，并核对源固定版本/hash；无生产 objects part 时不能声称这一步已验证。

## 统一测试请求与本轮结果

本轮没有运行编译、SQL、容器或远测，没有测试构建产物需要删除。未变更业务代码，无需重复整包构建；以下仅供审核者在既有独占缓存/夹具中合并安排，不是已通过证明。

PowerShell，cwd 为仓库 `backend`，保留审核者原 GOCACHE/GOTMPDIR/fixture 配置：

```powershell
go test -p 1 ./internal/systembackup/domain ./internal/systembackup/worker ./internal/systembackup/publicadapter ./internal/systembackup/kube -run 'Test(Team|Teams|PublicSQLWorkerKeepsNonemptyOwnerTeam|SharedTeam|EmptyTeams|PublicTeam|IndependentTeam|OwnerTeamProvision)' -count=1
go test -p 1 ./internal/systembackupexecution -run 'TestProduction(SixPartFactory|FactoryReconstruction|SourceBindingCannotBeAttached)' -count=1
```

预期退出 0；这些是组件/构造回归，不能替代现场证明。需要真实 TLS MySQL 的 `TestProductionSourceOriginalMetadataAuthorityMySQL` / `TestDeploymentProductionCompositionUsesOriginalRuntimeAndSourceHooksMySQL` 由审核者原夹具统一安排，缺夹具不可把 skip 写成通过。日志路径和独占缓存由审核者分配；结束后仅清理本次创建且已确认绝对路径/归属的构建产物，不碰他人缓存/日志。本轮不提供或执行 SSH/部署命令；正式恢复还缺上述认证源和隔离目标，不能编造可执行远测入口。

## localcleanup 后远端 typed opener 的 Teams 接点

本节针对公共 C 的最终验证装配：只读核对 `publication_remote_container.go`、`publication_container.go`、`owned_payload_reader.go` 的现行实现，不宣称尚在实施的新 opener 已消费以下建议。这里所称 Teams 捕获验证，源码实际方法是 `domain.VerifyTeamCapture`，没有另一个名为 `Teams.VerifyCapture` 的方法。

### 已执行的真实谓词

`verifyOriginalRemoteContainerCapture` 对六个远端容器逐个 `InspectPartContainer`，检查 `pc.Scope{Installation,Backup,Attempt,ConfigVersion,ConfigSHA256,CaptureContextSHA256,Part}`、`Header.SourceInventorySHA256==capture.Input.SourceSHA256`、成员数及原 checkpoint；逐 member 的 `publicationContainerMember` 再检查完整原 `record.Input`、plan hash、capture result hash、invocation/candidate/result/hash/checkpoint、part/index/operation 和原密文/信封 bytes/hash。`inspectOriginalRemoteContainerMember` 在当前 claim 下取得原 publisher verifier、`ForEnvelope`，通过 `InspectContainerCipher` 调用 inert parser，并在完整读流后 `Recheck`。跨容器同批次身份与原成员绑定已有实际校验。

| 远端业务内容 | `inspectOwnedBusinessPayloadCounts` 已做 | 没有由该分支证明的内容 |
| --- | --- | --- |
| 唯一 SQL | `domain.Decode`；candidate Rows/Tables、memory/schema/scope；`VerifyBusinessCapturedSnapshot`；若 TeamsInventory 非 nil 则 `VerifyTeamCapture(snapshot,*spec.TeamsInventory)`。后者校验 11 表 schema、原活跃 Team 数与 inventory 一致、owner/member、SQL 共享卷字段、provision operation 和依赖关系。 | 不调用 `TeamArtifactReferences`，不留共享文件依赖给后续 workspace；总 SQL rows>0 不等于 Teams 非空。TeamsInventory 的非 nil 和与原 source 一致由生产 inventory 装配检查，通用 parser 本身允许 nil。 |
| `source_redis` | `ReadSourceRedisSnapshot(ctx,reader,*Request.SourceRedis)` 核 header Source/server/DB/prefix/exclusion、捕获时刻、每项合法性/顺序/TTL/stream groups、end count/hash/EOF。 | 当前只有全 part Items/ContentBytes；不按 TeamID 计数，不解码 Redis DUMP 与 SQL event/task ID 做语义 join。合法非空 Redis 可以全来自其他业务。 |
| `team_<id>_workspace` | `inspectOwnedWorkspace` 的 `CapturedArchiveValidator`、安全类型/路径/PAX、candidate Files/Bytes、limits、tar EOF/zero tail。 | 不用原 SQL artifactRefs 检查该 Team 的引用文件存在；也不以 TeamID 对每个目录/文件另做业务归属断言。共享卷的 Team 归属来自冻结 source/plan。 |
| `teams_objects`（若原计划存在） | `inspectOwnedTeamObjects` 构建 invocation ref 的 Bucket+Key 完全集合；读回 metadata Version/Size、每个对象正文 size/SHA、拒绝遗漏/多余/重复。 | TeamID 来自原 inventory/ObjectRef，归属不在对象正文中被独立认证；当前生产 source freeze 仍为空集合。不能用其他 skill 对象的非空计数代替 Team 对象。 |

`productionInventory` 已检查 SQL 请求的 TeamsInventory digest 等于 source.Teams digest、所有 Team 共享目录必有 part，且对象清单非空时必有 teams_objects；新 opener 若独立重建输入，应从认证的 `capture.Input.SourceSnapshot` 取得该 inventory 并复核关系，不能依赖任意 caller DTO。原 `publicationPayloadCountsComplete` 允许零值且只要求六域计数形状完整；它不是非空 Team 证明。

### 最小装配建议和输入

1. 保留已有逐容器完整读取、当前 claim renew、独立 Unwrap 和最终 Recheck；在同一轮远端验证内增加一个私有的 Teams 内容关联累积器。其身份键固定原 task/attempt/context/source digest、SQL ciphertext digest 和最终选定对象的固定 version/hash，不允许将前一轮 receipt 或本地封存目录的计数充当这轮结果。
2. 在唯一 SQL parser 的 `VerifyTeamCapture` 成功后、现有 defer 清理 cell 之前，对原 `inventory.Teams` 调用 `domain.TeamArtifactReferences(snapshot,teamID)`；输出只保留本轮私有的 `teamID → []canonicalRelativePath` 和各 Team/关系计数，不保留整个 Snapshot。需要有共享卷才能满足非空 artifactRefs；没有 Mount 却有引用应拒绝或明确作为缺能力处理。原表/历史数据保持不变。若使用 `NewTeamWorkspaceSpec`，输入必须是这份 snapshot、认证的同一 inventory、TeamID、原 SQL **密文** SHA256；它不授予恢复或写入权限。
3. 当前容器顺序先 mysql 后 workspace，正好允许流式完成关联。对每个认证 `team_<id>_workspace` 的 tar header，在现有 validator 之外匹配该 Team 的 expected refs；要求每条引用命中 TypeReg/TypeRegA，并拒绝引用父路径为链接/非目录。为了与 `RunTeamWorkspace` 独立恢复验收一致，要求引用父目录有实际目录项；现有 tar validator 本身允许隐式父目录，因此仅复用它不能声称这一额外谓词成立。完成 tar/body/gzip/AEAD/EOF 和 verifier.Recheck 后，才提交该 member 的事实；缺引用应让 typed opener 失败，不提取、不写目标、不从 live source 补文件。
4. Redis 分支可在 `ClearSourceRedisSnapshot` 前按认证 inventory 的 `claw:team:<id>:` 精确前缀统计 Items/Bytes，将本轮每 Team 计数关联 SQL TeamID，并复核 scope 的 server/DB/前缀未漂移。共享 Redis policy 可合法包含其他业务或删除历史，因此不能把所有未知 Team 前缀一概拒绝，也不能凭全域非零宣布每 Team 非空。没有源侧认证的每 Team key census 时，零 key 不足以推断丢数据；报告真实零值，对要求非空的验收场景明确失败，不能制造 key。SQL event 与 Redis stream 内容的语义对应目前没有现成 inert DUMP decoder，需单独定义依据，不能把 prefix 校验描述成已验证该语义。
5. 对象保持现成的 fixed-version bytes verifier。在同一认证 source inventory 上复核每个 ObjectRef.TeamID 属于该 Team 集合、请求 Objects 与原清单精确一致、InventorySHA256 与原 inventory 一致；再按 Team 记录 verified 对象数/bytes。清单非空必须有且仅有一个 teams_objects member；清单为空记录零，不挪用其他对象域的数据。不得为获得非空在此阶段重新发现对象或版本。
6. 最终只输出经完整认证后的有限计数/满足谓词状态；artifactRefs、SQL 明文、Redis keys/DUMP 留在私有短生命周期内存，失败时丢弃，不能写进公开 manifest/counts。新 typed receipt 必须在全部必需 member、SQL→workspace refs 及最终当前 claim 检查结束后生成。恢复 `verify-team-workspace` 是将来隔离目标的独立验证，不应在备份 final verification 中创建恢复 Job 来补这项缺口。

以上建议只涉及公共 C 的 parser/opener 接线；本轮未改 Go，也未运行 SQL、编译或远端命令。若最终 acceptance 声称“共享 SQL 中的全部产物引用均在同批次共享目录存在”，第 2/3 项是尚须补齐的真实谓词；若只接现有 parser，应明确其证明范围停在逐 part 内容合法、原 scope 一致，不能把它扩大为该产物引用完整性结论。

### 后续获准实施的最小关系补丁

协调者随后释放 `publication_final_team_refs.go` / `_test.go` 与 `owned_payload_reader.go`。已新增 `newPublicationFinalTeamRelations(source)`、`inspectOwnedBusinessPayloadRelations(...,relations,out)`、`relations.confirmPart(invocation)`、`relations.complete()`；原 Counts reader 以 nil 委托保持原行为。SQL 通过既有检查后提取 canonical refs；原 tar 循环核对引用为普通文件及真实父目录，全部预算、identity、tar/gzip/EOF 检查保留。对象请求额外与原 inventory 的固定 ref 集合逐字匹配；没有新增 Redis 语义。

公共 C 须在当前远端验证轮次创建一个 relations，将其传入每个 business member 的 inert parser；每 member 外层 `InspectContainerCipher` 完整 AEAD/EOF 与 verifier.Recheck 成功后调用 `confirmPart(record.Invocation)`；全部读完再 `complete()`。同轮显式 Renew 允许聚合纯关系数据，不保存或复用 live claim/guard/verifier；任何外层失败或跨轮重启都丢弃。重复 confirm、未实际解析或 Invocation 不匹配会拒绝并使本轮失效。该方法只核关系，不产生授权或 final receipt。

新增回归覆盖正常引用、缺文件、目录/链接替代、隐式父目录、未确认读取、重复确认、对象未读、跨 task/attempt/context/config、错 inventory/对象版本/归属、分支规格替代、完整及截断 gzip、空 Team 仍要求 SQL。已运行 gofmt 和静态 diff 检查；没有编译、SQL 或远测。协调者统一运行：`go test -p 1 ./internal/systembackupexecution -run 'Test(PublicationFinalTeamRefs|OwnedPayloadCountsRequireCompleteOriginalArchive)' -count=1`。测试结果与公共 C 实际消费状态须由协调者后续记录，不把待测代码描述为生产全链路通过。
