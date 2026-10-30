# Skill Hub 备份实施与交接

## 2026-10-30：PR #2 接入当前统一基线

PR `82552a96` 接入 `backup` 的 `27d1de2e`。下文 `4fe83bc`、旧表名和
migration 082 是原交接历史；当前控制表与文件名以
`docs/backup-team-integration/sql-map.json`、当前 reviewed catalog 为准。
合并保留现有 v2 registry、35 表显式合成测试夹具、待评审执行记录策略和
已删除部署模板的状态，不恢复旧的 137 文件摘要或旧版生成清单。

本次保留 permit 失效传递至 `StopAndWait` 的修复，以及正常 release 取消
自身 context 不算授权失效的边界。当前统一基线已移除原 context helper，
因此补回生产 `mutation.EnterContext` 与注入 `ContextGate` 的适配；空
context/release 必须拒绝，已取得的无效 permit 必须释放。保留父取消、子
任务与清理全部退出后才释放的顺序，并增加无效能力不能进入 backfill/claim
的回归。该合并不代表分布式停写、现场恢复或跨 owner 签收通过。

本批基于 `huihuihuizhang/ClawManager` 的 `backup` 分支，来源提交为
`ec831611bcaf1dea3763cd9457149d1b4b6a382f`。主规范是
[总计划](system-backup-restore-division-plan.md)，阶段导航见
[易读版](system-backup-restore-execution-readable-plan.md)。

已完成 P0-0a 的 Skill Hub 策略登记、模型字段覆盖、写入路径盘点和可执行校验，
并实现 P0-0b 的本地 materialize worker 取消、排空和任务归还。
第三批已实现八表恢复候选转换、独立行比对、对象清单核对、指定版本 S3 读取及流式 SHA-256。
第四批进一步实现带强制凭据检查的 Normalizer 入口，以及有容量限制的只读 SQL verifier。
第五批实现八表 SQLRestorer 事务写入器及独立 verifier 回读测试，并提供可选实库测试入口。
第六批补齐必要对象 metadata 的提取、白名单、16 KiB 上限、属性验证与有容量限制的对象索引。
第七批补齐 SQL 对象映射与完整对象恢复计划的关联、整组目标校验，并明确只负责 Skill Hub。
第八批将 SQL、对象、workspace 证明和权限复查接入统一 Skill Hub 恢复校验入口。
这些模块尚未绑定公共 Runner wire DTO、生产证据适配器或分布式停写 participant；
未部署生产；隔离 MySQL/MinIO 专项通过记录见第 14 节。registry 中的 normalizer/verifier
ID 尚未绑定正式 Runner 适配器。
`owner_recorded` 表示策略已登记，所有跨 owner 批准仍为空，公共合同保持 draft。核心实现已由 52117de 提交；各批次的未提交描述为历史记录。当前接入基线为 4fe83bc，最新进度见第 15 节。

## 1. 数据策略

八表决议写入现有 `contracts/system-backup/v12/schema-registry-decisions.json`，由原有
`scripts/system-backup-contract-check.mjs` 生成 `schema-registry.json`。同步更新 A 的嵌入
测试快照，避免独立测试二进制携带不同 registry。未修改其他 owner 的决议或历史验收材料。

补充的 `c-skill-hub-object-policies.json` 是评审输入，不是新的运行时授权协议。
它登记八个 Go 模型当前的 88 个数据库字段、引用关系、对象与路径字段、证据脱敏字段和
materialize 状态映射。模型字段校验不能代替真实 information_schema 或全量字段语义评审。
未列入特殊处理的字段按源值保留；ID 使用公共恢复映射，同一映射必须跨表一致并保留 null。
所有原始数据进入加密备份；证据脱敏清单不表示可以删减备份正文。

| 表 | 恢复约束 | 必需交叉评审 |
| --- | --- | --- |
| skills | 映射用户、当前版本和扫描结果；保留可见性、发布属性，不触发发布 | A/B/D |
| skill_blobs | 映射隔离对象位置；验证内容，保留原摘要算法语义 | A/D |
| skill_versions | 保留全部版本、manifest 和 skill/blob 关联 | A/D |
| instance_skills | 使用 B 的实例与目录映射，保留删除状态和原工作区差异 | A/B/D |
| skill_scan_results | 保留历史扫描事实，不变成新的安全批准，不触发扫描 | A/D |
| skill_package_materialize_jobs | pending/running 转为现有 cancelled；终态及历史时间不改写 | A/B/D |
| skill_hub_tags | 保留 key、排序、管理员专用属性，处理 seed 唯一性 | A/D |
| skill_hub_tag_assignments | 精确恢复标签关联，不产生重复或扩大权限 | A/D |

映射依赖允许相互引用，不能把 depends_on 简单当作 SQL 导入顺序。B 的恢复写入器需要先建立
完整身份映射，再处理 current_version/last_scan 等回指关系并验证引用闭合。

## 2. 对象和工作区边界

- Skill Hub 是业务 category；数据分别进入既有 mysql、object_storage 和 workspace part。
- 对象采集使用登记 prefix 的完整当前可见集合，并核对数据库引用；保留共享 blob 和历史版本。
- 非空 object_key 的对象缺失是完整性失败。空 object_key 可能是未打包状态，必须交接给 B
  证明冻结 workspace 包含可恢复的对应内容；相关合同未评审前不把该情况判为正式验收成功。
- content_hash/observed_hash 沿用源业务含义，不能假设它们都是 SHA-256。
  对备份对象字节独立流式计算 SHA-256；不把 ETag 当成内容校验。
- strong 采集遵循总计划 11.3：暂停全部 prefix writer，在 gate 内冻结 key/version/size 清单，
  随后只读指定版本。无版本能力或 keyset 漂移不能成为 strong。
- 库中包和实例中的技能可能合法不同，校验恢复前后差异是否保留，不能强制覆盖用户修改。
- object_key 的逻辑键与 provider prefix 分开映射，不能双重拼接或回退读取生产对象。
- normalizer 不调用现有 Import/Install/Sync/Scan 等带副作用的业务方法。

## 3. 写入路径交接

`writer_groups` 当前是源码盘点，`protection=pending`；它不能充当已准入的 source-writer registry。
新增间接写路径仍需要人工及实际调用链核对，方法存在性检查不证明已经覆盖所有写入者。

负责人是改造责任角色，不是审核签收。C 仅指 Skill Hub 开发者；机器清单新增 owner，十组均保持 protection=pending。

| 源文件 | 负责人 | 事务、回调和任务阶段 |
| --- | --- | --- |
| skill_service.go | C | 导入/修改/删除、安装移除、SyncAgentSkills/上传回调、对象补写和扫描结果回写；同一次业务变更使用同一受保护事务；ListInstanceSkills 的卸载回写也纳入 |
| skill_hub_service.go | C | 发布/撤销、标签替换、回存/复制、导入/重试；skill/version/tag/binding 的关联更新共享提交边界 |
| skill_package_materialize_service.go | C | 入队/回填、claim、执行、归还/重试及最终终态提交分别绑定 lease，不能只保护领取 |
| skill_package_materialize_worker.go | C | 停止新接单，permit 覆盖子任务和归还；超时、释放失败或授权失效不得报告停写成功 |
| skill_runtime_sync.go | B | runtime 报告、workspace 同步、延迟报告和命令完成由 B 改造；调用 C 写接口时传递有效代次/授权 |
| skill_import.go | C | 决策导入、新建/覆盖、blob/version/skill 发布、recordImportScan；扫描完成/失败回调另做当前授权检查 |
| skill_lite_package_collect.go | C | C 负责包持久化的对象/SQL 写入及 syncSkillRecordFromBlob；B 提供 workspace 冻结和一致读取，C 不代改 runtime |
| instance_command_service.go | B | MarkFinished/markUninstalledSkillRemoved 的迟到命令回调和绑定更新由 B 改造 |
| security_scan_service.go | D | StartScan/RescanSkill/runJob/scanBlob 的异步扫描及三表写入由 D 改造；C 仅保护自己收到结果后的落库 |
| workspace_file_handler.go | B | Delete/syncSkillDeletionFromWorkspacePath 的文件删除和绑定更新由 B 协调 |

### 3.1 C 的公共停写接入位置

1. **同步业务事务**：公共层授予 mutation lease 后，C 将 repository 写入迁移至
   ExecuteProtectedMutation 的同一 Executor。需要读取/生成 ID 的事务能力须与 D 对齐；
   不能在其回调外使用另一连接提交，也不能只在 HTTP/service 入口检查 gate。
2. **对象和扫描回调**：permit 覆盖外部 I/O、子任务和回调；上传/扫描返回后核对当前
   generation/授权，再提交对象引用、版本回指和扫描事实。网络 I/O 不是 SQL 原子事务；
   已上传未提交的候选交公共 C provider 对账/清理，不自行删除共享对象。
3. **materialize 阶段**：入队/回填、领取、执行、归还/重试、终态提交逐阶段保护。
   关闸后停止新接单，等待在途任务和归还结束再释放 permit。D 需明确关闸后的清理权限；
   归还被拒绝时保留失败，不绕过 gate，也不报告成功。
4. **迟到回调**：Agent 包上传/库存报告、扫描完成/失败及卸载回写绑定原任务和当前代次。
   B/D 改各自的调用端，C 改自身 SQL 落库入口，不替其他负责人修改运行时或扫描器。
5. **全局判定**：本地 join 不等于全局停写。还须 B/D 汇总跨副本 writer、对象/workspace
   保护和当前 lease/fence 证明；超时、归还失败、释放失败、权限失效均阻止成功结论。

### 3.2 最新接口与本轮修正

基线 4fe83bc 已提供 systembackup/mutation.ContextGate，以及 worker 的 skill-backfill、
skill-materialize permit 接入，不能再记作“公共 gate 不存在”。但 service 的同事务提交
保护尚未闭合；未配置 gate 时的旧行为兼容也不是备份准入证据。

本轮补齐：父运行 context 有效而 permit context 已取消时，即使 release 返回 nil，
回填/批次仍返回失败并保留到 StopAndWait。检查在 release 前进行，避免将正常释放自身
取消 context 误判为失效。父运行取消和 lease 失效同时发生时，仍需要公共 release/fence
给出真实授权结论；context 检查不能代替该证明。

## 4. 分批实施和验收

| 批次 | 交付 | 当前状态 |
| --- | --- | --- |
| P0-0a | 八表决议、字段策略、写路径、公共依赖、负向测试 | 本地已实现，待交叉评审和真实 schema 对照 |
| P0-0b | service 提交前 lease 检查、worker 排空、多副本及异常恢复 | 本地 worker 排空已实现；公共 gate/participant 及提交隔离尚未接入 |
| P0a | 统一 DB 快照/对象版本/workspace checkpoint 关联，流式采集和校验 | 对象清单核对、版本读取和流式校验已实现；冻结清单及 checkpoint 证明待集成 |
| P0b | 隔离恢复归一化、独立只读 verifier | 八表 Normalizer、空目标事务写入、只读事务验证已实现；生产凭据适配器和公共 Runner 接线待集成 |
| P0c | 故障/规模/矩阵验收，检查结果接入 D | 未实现 |

验收向量至少包含：多用户私有/公开技能、多版本共享 blob、管理员标签、删除绑定、合法工作区
修改、未打包对象、缺包、摘要篡改、跨技能版本错绑、待执行/运行中任务，以及迟到扫描回写。
后续规模验收至少 10,000 个 Skill 对象，记录内存、吞吐和停写耗时。部分 Skill Hub 测试成功
不代表六类业务、六个 part 或系统 P0 完整验收成功。

## 5. 本地验证

从仓库根目录执行，不需要连接数据库或集群：

```powershell
node scripts/system-backup-contract-check.mjs --check
node scripts/system-backup-skill-hub-policy.mjs --check
node --test scripts/system-backup-skill-hub-policy.test.mjs
```

生成策略后如需同步 registry，使用原工具，不能手工修补统计：

```powershell
node scripts/system-backup-contract-check.mjs --write
Copy-Item contracts/system-backup/v12/schema-registry.json backend/internal/systembackupbusinessa/testdata/schema-registry.json
```

在 backend 目录验证嵌入快照：

```powershell
go test ./internal/systembackupbusinessa -run '^TestEmbeddedBusinessRegistryFixtureMatchesCanonical$' -count=1
```

`--strict` 仍会因公共合同、真实 schema 和交叉评审缺口拒绝。本批不修改或绕过这些门禁。
新 Node 校验已加入现有 Build workflow；未增加依赖，也未更改运行时启用开关。

## 6. 第二批：materialize worker 本地排空

实现位置是 service/worker、包收集、扫描、任务仓储及 server 的后台生命周期接线：

- `StartContext(ctx)` 继承 leader 的 context；重复启动不创建第二个运行实例。
- `StopAndWait(ctx)` 取消本轮回填和任务，等待批次、执行 goroutine 和任务归还全部退出。
  旧 `Start/Stop` 保留兼容；无截止时间的 `Stop` 会等待，server 使用 30 秒等待上限并记录失败。
- 等待超时返回 context 错误，旧运行实例仍保留；重新启动必须先等它真正退出，
  不会因超时立即启动第二轮。此约束仅覆盖同一 worker 对象。
- 已领取但尚未执行、以及因 context 取消而中断的任务，条件更新 running -> pending。
  条件更新不改动 succeeded/failed/cancelled。归还继续使用现有 SQL 语义，不回退 attempt_count。
- 部分领取失败返回已确认领取的任务供归还；成功 UPDATE 后读取详情失败，也保留任务 ID。
  UPDATE 或 RowsAffected 返回错误时，不能证明该任务属于本 worker，不擅自归还它。
  领取或归还失败会使本轮 `StopAndWait` 返回错误；每轮保留首个错误，避免长期故障累积内存。
- ProcessJob 拒绝执行终态任务，取消不再写为业务失败；回填和入队在写前检查取消。
  worker 将取消传到对象上传及扫描请求，上传后、扫描后检查取消，阻止后续状态回写。
- 保持现有全局与单实例并发限制。单实例测试使用同步屏障，确保测量的是在途任务数量。

这不是公共 gate 的替代品。尚未支持 context 的 DB/文件调用必须实际返回才能排空；
等待超时不能授权备份。远端扫描服务可能仍继续执行自己的任务。对象上传成功但 DB 未写入
时可能留下对象，需要后续 inventory/reconciliation 处理，不能随意删除可能共享的对象。
SQL 确认不明、跨副本接管及异常崩溃仍需公共 lease、事务提交检查和恢复协调。

接下来接入公共组件时，应先把现有 upper/db 独立写入重构为可绑定同一受保护事务的写入，
再使用 D 的 `ExecuteProtectedMutation` 做提交检查；不能仅在 service 入口检查一次 gate。
B 的 participant 代次、workspace writer 证明，以及 D 的独立安全扫描 writer 仍待接线。
`writer_groups.protection` 继续为 pending，未生成任何 pause ACK 或运行时启用标记。

新增本地故障测试覆盖：重复启停、父 context 取消、等待超时与禁止重叠重启、在途任务等待、
待执行任务归还、归还失败、部分领取失败、终态拒绝，以及上传/扫描/回写取消。
仓储测试通过真实 database/sql 与 upper/db 适配器注入离线驱动故障，无需真实 MySQL。

```powershell
# 在 backend 目录执行
go test ./internal/services ./internal/repository ./cmd/server -count=1
go test ./internal/services -run '^Test(MaterializeWorker|SkillPackageMaterializeWorker)' -count=20
```

这些测试不覆盖真实多副本停写、MinIO 版本读取或恢复演练。当前 Windows 环境未配置
CGO/C 编译器，未运行 Go race detector；上述重复并发测试不能替代 race 检测。

## 7. 第三批：恢复数据核心与对象流

新增包：`backend/internal/systembackupskillhub`。不依赖线上 Skill Service，
不调用导入、安装、扫描或发布接口，也不生成公共 acceptance/check 结果。
本节的纯数据转换与对象流不执行 SQL；只读 SQL 入口见第 8 节。

### 7.1 八表恢复与独立比对

- `ValidateRows`：检查八表 ID、引用闭合、版本所属技能、扫描所属 blob、标签关联，
  以及字节级唯一键。技能可以引用自身历史版本的扫描，实例技能允许保留旧版本和用户修改。
- `PrepareRestoreRows`：使用公共恢复协调器提供的十类 ID 映射（八表及 users/instances），
  按逻辑 object_key、绑定及 job 的路径映射产生完整候选行。映射缺失、重复目标、路径逃逸
  时整体失败，不返回部分结果；空表也必须在映射中显式出现。
- 所有原始业务字段保留，只变更登记的 ID/对象/路径映射和 job 状态：
  pending/running -> cancelled，三个终态不变，不重写历史时间、尝试次数或错误记录。
- 不通过 JSON 序列化复制模型，避免漏掉带 `json:"-"` 的 manifest 和扫描详情；
  返回值与输入的可变指针分离。NULL 与空串保持区别，SHA-256 不覆盖原业务摘要。
- `CompareRestoredRows`：从 source + 映射与另行读取的 target 逐字段比对，
  不调用 normalizer，也不把 normalizer 的返回值当作期望数据；检测权限、标签、
  历史版本、绑定、扫描详情及任务状态漂移。比较不依赖行顺序，时间按同一时刻比较。
- 错误只含静态表/字段名，不含业务值、主键、路径、对象键或扫描内容。

当前函数处理完整内存快照。调用期间输入必须保持不变。B 仍须认证 dump 和映射，
证明目标隔离、停用 worker/event、处理 seed 标签及目标占用，并在实际 SQL 提交时重新检查
写权限。字节级唯一键检查不能代替 MySQL collation 检查。行比对不能证明对象内容或
workspace 可恢复，也不能充当完整的 Skill Hub 验收结果。

### 7.2 对象清单、读取和校验

- `PrepareObjectCapture`：核对 blob 引用与输入的完整冻结清单；保留清单里未被当前数据库
  引用的对象，按 key 排序；共享 key 只出现一次。缺包、重复 key、size 不符、缺少版本
  或对象数量/单对象/总字节超限，整体失败。非空 object_key 不回退到 workspace。
- 空 object_key 的 blob 返回在 `UnpackagedBlobIDs` 中，必须交给 B 取得冻结 workspace
  内容证明。它们不是成功条目，也不能被跳过后宣称 eligible。
- `CopyFrozenObject`：只读请求的 immutable version，核对同一响应的版本/size，
  使用 64 KiB 缓冲区计算真实内容 SHA-256；截断、增长、读写/关闭错误、摘要不符或取消
  均不返回成功摘要。错误时已写入的候选数据必须由调用方丢弃，不发布或自动删除源对象。
- `VerifyFrozenObject`：使用独立目标读取器和来自认证 artifact 的期望 SHA-256，
  流式消费目标字节，不具备目标写能力；不接受 ETag/MD5 代替 SHA-256。
- `NewS3VersionReader`：复用现有 MinIO SDK 的 `Core.GetObject`，GET 明确带 versionId，
  版本和长度取自同一 GET 响应，不通过分离的 HEAD 观察推断，也不回退读取当前对象。
  provider prefix 与逻辑 key 只拼接一次，拒绝绝对路径和路径逃逸。

本地清单核对不能证明 provider 分页完整、gate held、root hash、checkpoint 绑定或强一致性。
源/目标只读凭据、TLS/provider 证明、必要 metadata、index 字节上限、候选加密/staging、
最终发布及清理仍须接入公共组件。没有新增顶层 part，也没有把上述 helper 接入生产开关。

### 7.3 测试与接线顺序

模块测试覆盖全部 88 个模型字段和登记引用；黄金数据覆盖共享 blob、历史版本、权限、
管理员标签、removed 绑定、合法 workspace 差异、未打包状态及五种 job 状态。
另含缺引用/错绑/路径逃逸/映射冲突/目标漂移/字段丢失负测，一万条 Skill 的转换与比对，
以及 32 MiB 对象的有界读取测试。S3 用真实 SDK 配合离线 HTTP transport 验证请求和响应，
不连接生产；这些不是实机性能指标或多副本演练证据。

```powershell
# backend 目录
go test ./internal/systembackupskillhub -count=1
```

下一步先接 B 的认证 source/mapping 与目标只读快照接口，再接 C 的冻结清单与候选存储；
D 完成 check registry/schema 评审后才将本地比对输出映射到正式 verifier checks。
真实 SQL restore、真实 MinIO/CSI 及六类业务验收仍未完成，公共合同继续保持 draft。

## 8. 第四批：带凭据检查的恢复入口与 SQL verifier

### 8.1 Normalizer 接线

`Normalizer.Normalize(ctx, RestoreRequest)` 对完整请求先做容量和数据检查，再冻结 source、
映射及绑定；调用 `NormalizationAuthority.VerifyNormalization` 后产生候选行，并在返回前
调用 `RecheckNormalization`。缺少适配器（包括 typed nil）、凭据错误、取消或最终复查失败
均不返回候选行。每次回调得到独立副本，不能通过修改参数改变后续转换或比对依据。

`RestoreBinding` 绑定 registry/schema、checkpoint、capture context、artifact、target identity
的 SHA-256 以及 evidence ID。格式检查本身不构成凭据，B 的生产适配器必须对照可信部署、
已认证备份和隔离目标证明核验完整请求，不能返回一个固定 true/nil。适配器也必须验证
ReadLimits 来自任务的冻结配置。此处仍只返回候选行，实际 SQL writer 必须在自己的提交事务中
重新校验写权限及 fence。

### 8.2 只读目标验证

`SQLRestoreVerifier.Verify(ctx, RestoreRequest)` 接收独立的 `*sql.DB` 和
`TargetReadAuthority`，实际运行顺序为：

1. 检查请求、容量和凭据适配器，冻结输入。
2. 开启 `ReadOnly=true / RepeatableRead` 事务；在该事务上调用首次目标凭据校验。
3. 对八张表检查 InnoDB；在同一快照内用 COUNT 和 OCTET_LENGTH 聚合检查总行数、字符串
   payload 字节数。所有表的容量检查结束后才读取 manifest/findings 等正文。
4. 用明确的全部数据库列读取每张表，保留 NULL 和 `json:"-"` 字段，按预期行数加一的
   LIMIT 检测多余数据；读取异常、少行、多行、列漂移或类型错误直接失败。
5. 调用独立行比对；分批检查实际引用的 users/instances 是否存在（每批最多 256 个 ID），
   关联表也要求 InnoDB。未使用的公共映射条目不要求在本模块中验证。
6. 在同一事务上复查目标凭据，然后提交只读事务；任何中途错误均回滚，提交失败也不成功。

`ReadOnlyQueries` 只提供 Query 方法，回调拿不到原始事务或 Exec 方法。
但 SQL 事务选项和 Go 接口本身不能证明数据库角色只读：B 的生产适配器仍必须验证
该连接的真实 SELECT-only 凭据、目标身份、启动隔离和已完成的归一化。
代码不会自动连接生产库，也不会从业务 DB 单例获取连接。

`ReadLimits` 分别限制行数、八表字符串字节数、映射条目和映射字符串字节数，
复制输入前先检查，转换后的候选行也再检查一次。verifier 当前仍读取有界内存快照，
不是超大表无限流式处理器。数据库和凭据适配器的错误统一脱敏，不暴露 DSN、SQL 参数、
对象路径或业务内容。

### 8.3 验证情况和剩余接线

新增测试使用真实 database/sql 事务路径和离线驱动，覆盖：

- 八表完整查询、88 个字段、同一只读隔离级别、用户/实例引用和空表。
- 初始/最终凭据错误、参数副本被修改、读取中取消和提交前取消。
- COUNT/正文/Scan/Rows.Err/Close/Commit 故障、列漂移、行数漂移、目标内容漂移。
- 非事务表、正文读取前容量拒绝、映射容量拒绝以及 300 个关联用户的分批检查。

```powershell
# backend 目录，运行所有 Skill Hub 备份模块测试
go test ./internal/systembackupskillhub -count=1
```

本批未连接真实 MySQL 或恢复环境。SQL writer 后续实现见第 9 节；B 的生产 authority、
独立数据库凭据、公共 Runner DTO、D 的正式 check registry 输出，以及对象/workspace 的最终
联合验收仍待集成。仅 SQLRestoreVerifier.Verify 返回 nil 不能宣称整个 Skill Hub 恢复已验收；
collector、normalizer 和 verifier 的公共协议冻结状态仍保持原样。

## 9. 第五批：空目标事务写入与独立回读

### 9.1 SQLRestorer

新增 `SQLRestorer.Restore(ctx, RestoreRequest)`，必须提供独立恢复库连接及
`RestoreWriteAuthority`；不会复用业务数据库单例或 Normalizer 的候选数据授权。

- 在 Serializable 事务中完成首次权限/绑定校验，按固定顺序检查八表 InnoDB，并锁定空表
  主键范围。任何已有记录（包括迁移 seed 标签）都返回 `ErrTargetOccupied`，不清空、
  不覆盖、不 upsert，也不关闭外键。
- 检查映射后的 users/instances 存在；依次插入 blob、skill、scan、version、tag、
  instance binding、materialize job 和 tag assignment，显式写入全部字段。
- 先将 skill 的 current_version/last_scan 及 blob 的 last_scan 回指留空，待对应记录存在后
  用条件 UPDATE 补齐；UPDATE 显式写回源 updated_at，避免 MySQL 自动改写历史时间。
- 每条 INSERT/UPDATE 要求 RowsAffected=1；任何写入、计数、取消或回指错误都终止事务。
- 提交前在同一事务内回读八表并独立逐字段比对，最后调用
  `RecheckTargetWrite`。B 的该适配器必须在此事务内锁定并复查目标写入 fence，使授权
  保持到 commit；不能仅做一次事务外布尔检查。
- commit 报错返回 `ErrRestoreCommitUnknown`，不自动重试或清理目标。响应丢失时可能已经
  持久化，必须由恢复协调器核对。commit 已确认成功后才到达的取消不会被误报为已回滚。
- 提交后的正式验证仍由独立 SELECT-only 连接的 SQLRestoreVerifier 执行，writer 的回读
  不是权限分离后的正式验收，也不涵盖对象/workspace。

本模块只负责八张业务表；B 仍负责隔离资源、依赖数据恢复、seed 标签处理、target fence
及恢复 attempt 的持久化幂等记录。目标已有数据时，要由协调器判断是否属于已提交 attempt，
或者重新分配干净目标；不能靠本模块强制覆盖继续。

### 9.2 离线与实库测试

离线测试从空目标执行 24 条 INSERT 和 5 条回指 UPDATE，再交给独立 verifier 读取，
验证共享 blob、循环引用、全部字段和历史时间。负测覆盖部分 INSERT/回指失败、
RowsAffected 异常、回读漂移、缺少依赖、已有 seed、凭据复查失败、取消回滚、提交响应丢失、
成功提交后的迟到取消以及重复执行不修改既有数据。

新增 `TestSQLRestorerMySQLRoundTrip`，默认跳过。显式设置
`CLAWMANAGER_SKILLHUB_TEST_MYSQL_ADMIN_DSN` 后，可针对**一次性本地 MySQL 服务**执行：

```powershell
# DSN 通过本地环境变量提供，不写入仓库；只接受 loopback TCP。
# backend 目录：
go test ./internal/systembackupskillhub -run '^TestSQLRestorerMySQLRoundTrip$' -count=1 -v
```

此测试需要创建 database/user 和 grant 权限。它生成随机测试库与读写分离用户，运行仓库的
008/023/039 迁移，补充循环外键以检查插入顺序，验证 seed 拒绝、事务回滚、完整恢复、
只读用户不能 UPDATE、重复恢复拒绝和权限字段漂移检测。结束只清理成功创建的随机资源；
不打开或修改现有应用 schema。测试凭据及原始驱动错误不写日志。

当前机器 Docker engine 管道不存在，测试 DSN 也未配置，因此**本批未执行实库用例**；
该用例编译通过并按预期跳过。不能将离线驱动测试记为真实 MySQL、权限矩阵或恢复演练通过。

本批最终回归结果（2026-10-26）：

- `go test ./internal/systembackupskillhub ./internal/services ./internal/repository ./internal/systembackupbusinessa ./cmd/server -count=1` 五个包全部通过。
- writer 的回滚、提交响应丢失和成功提交后取消三组测试连续运行 20 次通过。
- `node --test scripts/system-backup-contract-check.test.mjs scripts/system-backup-contract-artifacts.test.mjs scripts/system-backup-skill-hub-policy.test.mjs` 共 101 项通过。
- 策略检查覆盖 8 表、88 字段和 10 组 writer；`runtime_ready` 和 `cross_review_complete` 仍为 false。
- Go 格式及 diff 空白检查通过；完整累计补丁覆盖 36 个文件，独立临时仓库 apply 检查、实际应用和逐文件字节比对通过。

代码位于 `D:\ClawManager\.codex-temp\skillhub-backup-work`，仍基于 backup 的
`ec831611bcaf1dea3763cd9457149d1b4b6a382f` 固定版本。最新交付包位于相邻的
`skillhub-backup-delivery-current`，替代旧的首批 delivery 包，包含完整补丁、变更文件 ZIP、
逐文件 SHA-256 和应用说明。工作副本不是独立 Git clone；不要在其中直接 `git add .`。
本批未提交、推送或修改父项目的 dev 分支代码。

### 9.3 尚未完成

- 源端十组 writer 的公共 gate/lease/participant 接线，尤其跨模块的 workspace 与异步扫描写入。
- B 的生产恢复 authority/fence、独立凭据及公共 Runner 请求适配。
- C 的冻结对象清单与 checkpoint 证明、metadata/index 上限、加密候选存储及发布接线。
- D 的 Skill Hub 正式 check registry 与证据输出；对象、workspace、SQL 的联合验收。
- 真实 MySQL/MinIO、故障接管和多副本演练。

以上均未用自动放行的 adapter、虚构 ACK 或 runtime_ready=true 替代。

## 10. 追加代码审查（2026-10-26）

### 10.1 已复现并修复：对象入口校验不一致

`CopyFrozenObject` 原来只检查 key 非空，直接调用它或 `VerifyFrozenObject` 时，
`../escape`、绝对路径、反斜杠、控制字符及非法 UTF-8 能进入自定义 VersionReader。
虽然 S3 adapter 会拒绝多数非法路径，但公共复制函数不能依赖特定 adapter 才保护逻辑 key
边界。另有纯空白 key 被清单规划和恢复映射接受、随后在复制阶段才失败的问题。

统一使用 `validObjectKey`，在清单规划、复制/校验、S3 GET 和目标 object_key 映射中
提前拒绝上述输入；不自动 clean 路径或改写对象 key，防止读取非冻结清单指定的对象。
新增回归先在修复前复现失败，再验证 12 类非法 key 在 I/O 前被拒绝，并覆盖 S3 和映射入口。
同时修正 package 注释，明确模块已包含需要授权的 SQL writer。

修复后 `go test -vet=all ./internal/systembackupskillhub -count=1` 通过（包含 Go 静态检查）；
Go 格式和 diff 空白检查通过。MySQL opt-in 测试仍按未配置 DSN 跳过，没有新增实库验收结论。

### 10.2 仍待完成的验收缺口

- **高优先级：源端分布式停写。** `StopAndWait` 只等待当前本地 worker run；十组源 writer
  的 gate/lease/participant 仍为 pending。其他 API、扫描器、workspace/runtime 与副本仍可能
  写入，不能据此签发 strong capture 的全局停写 ACK。后续应接公共协议并验证多副本及
  跨 SQL/S3/workspace 写入均被阻断，而不是把 `runtime_ready` 手动改为 true。
- **高优先级：生产恢复入口。** SQLRestorer/SQLRestoreVerifier 尚未接入应用 Runner；
  当前不存在可代替 B 生产权限、隔离目标与事务 fence 的适配器。测试适配器仅用于测试。
  需要按冻结协议接线，并对 stale fence、错误目标和未隔离目标进行失败测试。
- **高优先级：对象完整恢复链路。** 当前 S3 reader 输出 body/version/size，未保存必要
  metadata；冻结清单完整性证明、metadata/index 容量约束、加密 candidate 存储、目标对象
  恢复写入及正式证据输出仍待接入。字节 SHA-256 验证成功不等于对象属性和整个域恢复完成。
- **验证缺口：实环境。** MySQL 测试仍需一次性本地服务和显式 DSN；当前是跳过。
  MinIO、权限隔离、故障接管和多副本演练未执行，不得把离线 SQL/HTTP 驱动测试当成实库证据。

审查没有将这些未完成接线包装成生产实现，也未改动 backup 以外分支或提交、推送代码。

## 11. 第六批：对象 metadata 与有界索引

### 11.1 同一次 GET 的必要属性

`NewS3VersionReaderWithMetadata` 接收冻结配置中的用户 metadata 白名单，构造时复制并检查
小写 HTTP token、重复项和总长度。原 `NewS3VersionReader` 使用空白名单，仍提取所有必要
标准属性。白名单不能从对象自身或未经认证的浏览器请求推导。

精确版本 GET 同时提供 body、version、size、ETag、last modified，以及 Content-Type、
Content-Encoding、Cache-Control、Content-Disposition、Content-Language、Expires 和白名单
用户 metadata。不会额外 HEAD 或回退读取当前版本；歧义的重复 header、非法文本或属性
超限均在流式复制正文前失败，并关闭 reader。ETag 是历史属性，不替代内容 SHA-256。

`CanonicalObjectMetadata` 使用闭集字段及 JCS 字符串规则，检查完整 canonical JSON 的
UTF-8 字节数不超过 16 KiB；HTML 字符和 U+2028/U+2029 不被多余转义，转义膨胀计入上限。
未知用户 metadata 不保存名称或值，仅在 `OmittedUserMetadata` 中计数。公共 adapter 必须
据此产生 disqualifying warning；这不是已经注册的公共 warning code，也不能据此宣称 eligible。

`CopyFrozenObject` 返回实际读取的属性快照；`FrozenObject.Metadata` 可携带独立认证的
预期属性并在写 staging 前逐字段比较。正式对象恢复校验使用 `VerifyRestoredObject`，
缺少预期 metadata、内容摘要不匹配、属性漂移或存在被省略的用户 metadata 都会失败。
兼容的 `VerifyFrozenObject` 仍允许仅校验字节；它不能单独替代完整对象恢复验收。
恢复后的目标版本可能拥有新的 ETag/last modified，因此它们进入源索引，但不作目标相等条件。

### 11.2 冻结清单和复制后索引

`ObjectCaptureLimits.MaxIndexBytes` 现在是必填正向容量限制，空清单也需要至少 2 字节。
`PrepareObjectCapture` 在复制输入前计算冻结清单 canonical JSON 大小；所有对象和未引用对象
都计入预算，不因数据库没有引用就跳过。存在预期 metadata 时也计入，并深复制其 map。

`WriteCapturedObjectIndex` 接收冻结计划与逐对象复制结果，按 key 排序，写出本地 candidate
JSON 索引。每行包含 key、version、size、实际 SHA-256、ETag、last modified、闭集 metadata
及省略用户 metadata 数量。遗漏、重复、错误版本/大小/摘要、缺失必要属性、超容量全部在
第一次外部写入前拒绝；空 prefix 显式写 `[]`。

索引按实际 JCS/UTF-8 字节数二次核算 `max_index_bytes`，先通过总容量检查再复制属性 map，
在调用 writer 前冻结输入。输出块不超过 64 KiB，不构造整份索引字节缓冲；输入清单、排序
和属性快照仍占用与条目数相关的内存，生产 Runner 必须将其纳入冻结容量配置及实测资源预算。
发生写入错误或取消时返回空摘要，调用方须丢弃候选 staging；错误不包含对象 key 或属性内容。

结果包含索引 size/SHA-256 和 `ObjectsWithOmittedMetadata`，供公共适配器做证据和警告映射。
这是本地 staging 格式，尚不是冻结的公共 artifact wire schema；未实现任务发布或 eligible 判定。

### 11.3 验证与剩余事项

测试覆盖同一次 S3 GET 到内容复制再到索引的属性传递，16 KiB 精确边界/转义膨胀、白名单
修改隔离、未知 metadata 不泄漏、目标属性漂移、缺少预期属性、reader 关闭、索引漏项/重复项、
索引容量精确边界、失败前无外部写入、取消/写入故障、writer 修改输入及 10,000 对象有界输出。

本批验证通过：`go test -vet=all ./internal/systembackupskillhub -count=1`；合同、artifact 和
Skill Hub policy 三组 Node 测试合计 101 项；策略、Go 格式及 diff 空白检查通过。
累计变更现为 40 个文件，交付补丁重新执行 apply 检查、实际应用与逐文件字节比对。
上述 S3 测试使用真实 MinIO SDK 加离线 HTTP transport，未连接真实 MinIO；MySQL opt-in
用例仍因没有 DSN 而跳过。本批未部署、提交或推送。

本批补齐第 9、10 节中的**本地 metadata 和 index 上限**缺口。仍未完成源端分布式停写与
完整冻结清单证明、公共 Runner/生产 authority/fence、加密 candidate store、目标对象写入、
正式 warning/check/evidence 映射及真实 MySQL/MinIO/多副本联调；没有将这些工作改标为完成。

## 12. 范围确认与 Skill Hub 接入准备

本次用户明确只负责 Skill Hub。此前列出的全链路依赖不是全部分配给本模块的开发任务。
后续代码范围以 Skill Hub 自身的数据、写入路径、对象处理和验收为准。

| 事项 | Skill Hub 本模块负责 | 公共组件负责人提供 |
| --- | --- | --- |
| 数据恢复 | 八表策略、字段/引用/路径映射、任务状态归一化、目标 SQL 写入和只读校验 | 公共快照、users/instances 映射和已恢复依赖、隔离目标 |
| 停写 | Skill Hub service/worker 接公共 gate，等待已接收任务收敛，验证本模块写入覆盖 | D 的 gate/lease/fence 协议、B 的 runtime/workspace 停写机制 |
| 对象 | Skill 对象清单、复制、metadata、索引、SQL object_key 一致性和目标内容校验 | 公共 C provider 的加密 candidate writer、恢复上传及目标不可变版本回执 |
| Runner/权限 | 按冻结请求调用本模块，返回 Skill Hub 统计、警告及检查结果 | B 的 Runner/目标隔离，A/B 的权限证明，D 的正式 check/warning 协议 |
| 联调 | 本模块数据集、失败场景和目标 Skill Hub 数据/对象/绑定验收 | 公共环境、凭据、全局调度及跨业务矩阵验收 |

本模块不另建 Teams、全局 controller/任务状态机、KMS/密钥托管、公共加密存储后端、
Kubernetes 恢复环境或其他业务域 verifier。公共接口到位后的 **Skill Hub 侧接线** 仍属于本模块。

### 12.1 本批补齐的对象恢复关联

新增 `PrepareObjectRestore`：接收 source blobs、`RestoreMapping.ObjectKeys`、完整冻结清单、
已完成的对象复制结果，以及公共恢复上传器提供的 `source key -> target key/version` 回执。
它检查复制结果完整性，要求所有数据库引用的目标 key 与 SQL 映射一致，也要求每个未引用
对象都有独立目标；漏项、多项、目标 key 冲突、空/null 版本、错误摘要、缺失 metadata 或
目标清单超限都不返回部分计划。不同 blob 共享同一 source key 时只验证一个目标对象。

返回值保留 `UnpackagedBlobIDs` 和 `ObjectsWithOmittedMetadata`。前者必须交由 B 的 workspace
恢复证明覆盖，后者必须转成正式 disqualifying warning，不能因为对象字节校验成功而丢弃。

新增 `VerifyObjectRestorePlan`：在任何目标 I/O 前校验整组 key/version/SHA-256/metadata，
冻结输入后只读取恢复目标精确版本。正文、属性、版本漂移立即失败，不回退生产对象或当前版本。
这是对象检查入口，不是整个 Skill Hub 的 acceptance；SQL 校验、workspace 证明及源端 warning
必须由公共适配器一并汇总。该函数本身不提供上传、权限认证、加密存储或发布能力。

### 12.2 接入时所需输入及交接验收

以下按最新基线 4fe83bc 核对，接口存在不代表本域生产接线完成。沿用既有协议，不另建框架。

| 输入/接口 | 提供方 | 接入位置 | 当前阻塞点与下一步 |
| --- | --- | --- | --- |
| 认证 Runner 请求、完整 source/Binding/limits | B Runner、D 调度授权 | Normalizer.Normalize、SQLRestorer.Restore、RestoreVerifier.Verify | 共享 systembackupdispatch 和 publicadapter.NewPublicRunner 已有；缺 Skill Hub wire DTO 到本地请求的完整注册/映射，不能直接 marshal 带 json:"-" 的模型 |
| users/instances、域内 ID 映射及依赖就绪证明 | A 用户、B 实例/恢复协调器、C 本域 | RestoreMapping、PrepareRestoreRows、SQL 外部引用检查 | 需同一 artifact/target 的认证映射，不能靠目标查询猜测 ID |
| 独立写入/只读连接、隔离与权限证明 | A 权限、B 目标、D 当前授权 | NormalizationAuthority、RestoreWriteAuthority、TargetReadAuthority、RestoreVerificationAuthority | B 已有 RestoreTarget/CheckRestoreTarget 提案；仍缺真实 observer/grant/fence 到本域 authority 的适配 |
| gate/lease、同事务 Executor、participant、清理权限 | D 协调提交；B participant | 第 3.1 节 service 提交及 worker ContextGate | worker permit 已有；C service 事务改造、授权传递和关闸清理规则待闭合 |
| 完整 key/version/size、白名单、checkpoint | 公共 C provider、B/D 停写冻结 | PrepareObjectCapture、NewS3VersionReaderWithMetadata | reader 已有；仍需认证完整库存，不能仅取 SQL 引用集合 |
| 加密 candidate writer、seal/发布/失败清理 | 公共 C provider | CopyFrozenObject、WriteCapturedObjectIndex | 需任务专属 writer/生命周期回执，不在本域重建加密存储或默认明文落盘 |
| 恢复上传回执、目标只读 reader | 公共 C provider | PrepareObjectRestore.Targets、RestoreMapping.ObjectKeys、VerifyObjectRestorePlan | 认证 key/version/target，覆盖引用及未引用对象，不回退生产/当前版本 |
| workspace 映射与真实恢复证明 | B workspace/runtime | WorkspaceRestoreVerifier.VerifySkillHubWorkspace | 覆盖实例绑定、job 路径和全部 UnpackagedBlobIDs；evidence ID 格式不是证明 |
| 正式 check/warning/evidence 与资格判定 | D；A 证据权限 | RestoreVerificationSummary 的公共输出适配 | 已有公共结果框架；仍需本域 check ID/错误分类及 metadata 省略的 disqualifying warning，nil error 不能直接升级 eligible |

本模块接入验收应至少包括：八表 SQL 校验通过、所有引用和未引用对象校验通过、SQL key 与
目标上传回执一致、未打包 blob 的 workspace 证明闭合、metadata 警告未丢失，以及过期权限、
错误目标、取消和 I/O 故障均拒绝成功。公共能力尚未提供时记录具体依赖，不将其误标为本模块
已经完成或要求 Skill Hub 开发者重写公共基础设施。

本批 `go test -vet=all ./internal/systembackupskillhub -count=1` 通过；测试新增共享 blob、未引用
对象、SQL 映射不一致、目标 key 冲突、漏项/多项、目标容量上限、输入修改隔离、整组预检和
目标正文/属性/版本漂移场景。Go 格式和 diff 空白检查通过；累计交付为 42 个变更文件。
公共协议没有新增或变更，本批没有创建公共服务、部署资源、提交或推送。

## 13. 第八批：统一 Skill Hub 恢复校验调用链

### 13.1 可执行入口

新增 `RestoreVerifier.Verify(ctx, RestoreVerificationRequest)`，直接调用已有 SQL verifier 和
对象 verifier，并强制调用 workspace 证明适配器及首尾权限校验。它不是只声明接口，也不是
公共 Runner 的替代品；后续 Runner 只需组装可信能力并调用本模块入口。

执行顺序固定为：

1. 完整预检并冻结 source、mapping、binding、对象清单/摘要、目标上传回执、容量和 workspace
   evidence refs；引用格式、重复项、缺失引用及容量检查都在外部 I/O 之前完成。
2. `RestoreVerificationAuthority` 验证完整请求及**实际配置的**对象 reader：绑定同一 sealed
   artifact、隔离目标 generation、只读凭据和冻结配置。不能仅验证 hash 字符串格式。
3. `SQLRestoreVerifier` 通过独立只读数据库连接执行八表快照和全部字段/外部引用校验；
   SQL 的真实 SELECT-only 身份继续由其独立 `TargetReadAuthority` 核验。
4. 依据 SQL object_key 映射读取全部目标对象精确版本，核对内容 SHA-256 和必要 metadata，
   包括没有数据库引用的对象。
5. `WorkspaceRestoreVerifier` 核验 B 的实际证明，输入包含同一 RestoreRequest、全部待覆盖
   的 unpackaged blob ID 和 evidence refs。必须覆盖实例绑定、job workspace 路径及未打包
   内容，不能把合法 `sev_` 字符串本身当成已验证证明。
6. 再次复查整体目标隔离与权限，确认整个跨 SQL/对象/workspace 阶段期间都有效，最后才
   返回脱敏计数。任何阶段失败、取消或最终权限失效，都返回空摘要与脱敏错误。

所有能力都是必需依赖（含 typed nil 检查），没有自动放行的生产默认实现。空域也查询八张
空表并执行首尾权限及空 workspace 证明检查，不把缺少适配器当成“无数据所以成功”。
每次外部证明回调都收到独立副本，不能修改后续比较依据或读取目标。

### 13.2 返回值与正式协议边界

`RestoreVerificationSummary` 只包含 SQL 行数、对象数、workspace binding 数、unpackaged
blob 数和 `ObjectsWithOmittedMetadata`，不暴露业务正文、对象 key、路径或原始错误。
metadata 省略数量在所有步骤通过后仍被保留，公共适配器必须据此输出正式 disqualifying
warning；不能因为函数返回 nil error 就把 public eligibility 标成 true。

`RestoreVerificationRequest` 和该摘要仍是本模块 Go 调用格式；业务模型带 `json:"-"` 字段，
不得直接 JSON marshal 后当作公共备份载荷。公共 Runner DTO、D 的 check/warning schema 和
证据登记由对应接口适配，未在本批擅自冻结或新增全局协议。

### 13.3 本批测试与尚未接入的能力

集成测试实际执行 `SQLRestorer` 的 24 条 INSERT、5 条回指 UPDATE，然后用另一只读连接
运行统一校验：八表读取、3 个指定目标版本的 MinIO SDK GET、workspace 证明和最终权限
复查。SQL 使用 database/sql 离线驱动，S3 使用离线 HTTP transport；workspace/authority
适配器仅为测试实现，不能将其计为真实 MySQL/MinIO 或生产权限联调。

失败测试覆盖缺失/typed nil 能力、缺少或重复 workspace evidence、非法 selector metadata、
目标映射错误、SQL 字段漂移、对象 I/O 故障、workspace/权限失败、各阶段取消及回调修改
参数。空域测试确认没有跳过 SQL 表和权限检查；成功摘要确认 metadata 警告数量没有丢失。

本批未改源端 writer registry 的 protection 状态。D 已有 `ExecuteProtectedMutation`，但它
要求业务写入都使用提供的**同一事务 Executor**；Skill Hub 现有 upper/db repository 和
跨 S3/workspace 写入不能只在调用前加一次 gate 查询就宣称已保护。源端事务/participant
接入仍是明确待办。公共 Runner 具体调用实现、生产权限/workspace 证明适配器、加密
candidate writer、目标上传以及正式 check/evidence 输出仍需相应公共能力到位后接线。

本批验证：`go test -vet=all ./internal/systembackupskillhub -count=1` 全模块通过；补充空域和
SQL 漂移场景后，`go test -vet=all ./internal/systembackupskillhub -run '^TestRestoreVerifier' -count=1`
通过。Go 格式及 diff 空白检查通过。累计交付为 44 个变更文件，补丁重新做 apply 检查、
实际应用和逐文件字节校验；没有 commit、push 或生产部署。

## 14. 2026-10-26 测试审查

本轮针对 Skill Hub 现有实现做回归、真实依赖验证及测试补充，没有调整生产业务逻辑。
前文各批次关于实库未执行或 Docker 不可用的描述是当时记录；本轮已能访问本机
Docker Engine，并使用缓存镜像完成下述独立测试。这不等于生产环境联调通过。

### 14.1 已完成的验证

- 合同、工件及 Skill Hub 策略 Node 测试：101 项通过。
- Skill Hub 全模块 `go test -vet=all` 通过，离线测试语句覆盖率为 91.1%；
  此覆盖率统计中 opt-in MySQL/MinIO 用例未启用，实库结果由下面的独立运行提供。
- services/repository 的 `Materialize|Claim` 测试随机顺序重复 25 轮通过，覆盖 worker
  取消、退出等待、任务领取及释放。重复测试不能代替 Go race detector。
- MySQL 8.0（缓存镜像实际版本 8.0.46）和 8.4.8 的 `TestSQLRestorerMySQLRoundTrip`
  均实际运行并通过：真实迁移、额外循环外键、种子数据拒绝、最终 fence 失败整事务回滚、
  八表恢复、独立 SELECT-only 账号校验及写入拒绝、重复恢复拒绝和提交后数据漂移检测。
  authority 仍是测试适配器，不能替代生产隔离、权限及租约证明。
- 新增 `TestS3MinIORoundTrip`，在真实 MinIO 上启用版本控制并通过：共享 blob 和未引用
  空对象、源端/目标端覆盖后仍读取指定旧版本、缺失版本不回退、正文/metadata 漂移拒绝、
  metadata 白名单及未知字段省略计数、索引中不泄漏省略字段、未打包 blob 证明需求保留。
  独立匿名身份仅获该随机测试 bucket 的 target 前缀 GET/GetObjectVersion 权限；实际上传
  返回 AccessDenied。该策略仅用于一次性回环地址测试，不是生产权限配置建议。
- 新增 `FuzzCanonicalObjectMetadata`：使用独立 JSON 解码器核对字符串往返、合法 JSON、
  16 KiB 上限、失败不返回部分结果及 map 顺序稳定性；种子包含 Unicode、HTML 字符、
  U+2028/U+2029、引号、反斜线、TAB、控制字符及无效 UTF-8。
  以 `-fuzztime=15s -parallel=2` 实际执行 6,091 次，未发现失败。

### 14.2 可重复运行的实库测试

在仓库根目录运行（Go、Docker Engine 和相应缓存镜像须已可用）：

```powershell
.\scripts\test-skill-hub-backup-mysql.ps1 -Image mysql:8.0
.\scripts\test-skill-hub-backup-mysql.ps1 -Image mysql:8.4.8
.\scripts\test-skill-hub-backup-minio.ps1
```

脚本使用唯一名称/标签、随机测试凭据、回环地址随机端口和 tmpfs；设置 `--pull=never`，
不下载镜像、不连接现有应用数据库、不挂载主机业务目录。退出时检查名称、容器 ID 和
本轮标签后才删除本轮容器，并还原进程环境变量。三次实库测试均已清理容器，最终标签查询为空。
初次 MySQL 就绪探测遇到 Docker CLI 本机异常，未进入 Go 测试；已修正 PowerShell 原生
stderr 的探测重试处理并重新运行成功，失败探测没有记为实库通过。

手动连接一次性测试服务时，MySQL 使用
`CLAWMANAGER_SKILLHUB_TEST_MYSQL_ADMIN_DSN`；MinIO 使用
`CLAWMANAGER_SKILLHUB_TEST_MINIO_ENDPOINT`、`CLAWMANAGER_SKILLHUB_TEST_MINIO_ACCESS_KEY`
和 `CLAWMANAGER_SKILLHUB_TEST_MINIO_SECRET_KEY`。未设置环境变量会明确跳过用例。

### 14.3 验证边界

完整后端执行 `go test -p 2 -vet=all -timeout 10m ./... -count=1`：首次 31 个包通过、
7 个包没有测试，另 4 个包因开发副本缺少固定版本的 docs/evidence、OpenAPI/SQL
资料失败。按原基准 commit 补齐到 base/work 两份副本（未改这些文件内容），再单独复跑
这 4 个包后，northbound、systembackupconfig 和 systembackupsecurity 通过；
systembackupevidence 触发整个包 10 分钟超时。因此累计 34 个有测试包通过，
**不能声称整个后端全部通过**。该公共模块没有被本轮修改。

超时时正在运行 `TestDownloadRetentionGCBatchChecksWorkerOnEmptyRange/expired_lease`，
父用例当时仅运行约 3 秒；这条栈信息本身不能证明该用例死锁，也不能证明是 Skill Hub
回归。需将整体超时与专项测试的通过结果分开判定。
随后用 `-run '^TestDownloadRetentionGCBatchChecksWorkerOnEmptyRange$' -timeout 2m`
单独复跑：replaced_claim、stopped_worker、expired_lease 三个子场景均通过，父用例
耗时 2.28 秒，没有复现阻塞。此结果不替代公共证据模块整包验证，也不确定整包超时根因。

当前 Windows Go 环境 `CGO_ENABLED=0`，未检测到所需 gcc 工具链，未运行 `-race`。
生产多副本停写、真实 authority/workspace 证明、公共 Runner/provider 加密存储和生产
部署联调仍按第 12、13 节列为待接入；本轮未改变 `runtime_ready=false`。

本轮新增两个 Go 测试文件、两个 PowerShell 实库复跑脚本并更新本文，累计交付为
48 个变更文件。补丁已在独立临时仓库检查、应用并逐文件比对；没有 commit、push
或生产部署。

## 15. 两阶段推进与策略评审（2026-10-29）

交付口径：**Skill Hub 模块已实现，待公共能力接入**。保持 runtime_ready=false。
本轮仅改责任登记、交接与已存在 ContextGate 的错误传播，不改 B/D 负责的 writer。
八表依据第 1 节及策略 JSON，任务状态 pending/running 转 cancelled 且不重放；
对象依据第 2、12.1 节，metadata 依据第 11 节，不重复另建策略。
第 14 节 MySQL/MinIO 通过记录继续有效，但不冒充新基线全链路生产验收。

| 评审方 | 本次请确认 | 签收 |
| --- | --- | --- |
| A | 用户/发布者映射；私有/公开与 admin_only 权限不扩大；正文与脱敏证据分离；独立只读权限 | 待本人评审，GitHub 账号待确认 |
| B | 实例/路径映射；workspace 合法差异；未打包 blob 证明；任务不重放；B writer 归属和隔离目标 | 待本人评审，GitHub 账号待确认 |
| D | 历史扫描不视为新批准；fence/迟到回调；metadata 白名单及省略告警；正式检查/证据 | 待本人评审，GitHub 账号待确认 |

cross-owner-review-requests.json 已登记角色和对象，不重复创建签收数据。
在 PR 中解释并处理反馈，按“意见链接、涉及规则、修复提交、验证结果、负责人复核”追踪。
未收到意见不虚构反馈，未由负责人确认不填写 approved_cross_reviewers。

第二阶段按接口就绪逐项接入：本域事务保护、Runner 适配、candidate/上传回执、
workspace 证明、正式检查输出。任何单项稳定可先接；本轮已对现有 worker gate 补充验证。
联合验收需覆盖取消、迟到回调、权限过期、fence 失效、多副本停写；公共层问题交对应负责人。
不安装依赖，不在仓库留下测试二进制或构建输出。

本轮验证：策略检查仍返回 8 表、88 字段、10 组 writer，runtime_ready 和
cross_review_complete 均为 false；三组 Node 合同/策略测试共 105 项通过。
设置 GOPROXY=off 后，services 的 Test(Materialize|SkillPackageMaterializeWorker)
专项及 vet 通过，包含新增权限 context 失效、归还等待与正常释放取消的回归。
初次合同测试缺少稀疏检出的 DTO/YAML/SQL/Dockerfile，补齐同版本原文件后全部通过；
没有通过修改公共测试或安装依赖来消除失败。未重跑已有效的旧基线实库专项，未进行生产联调。
