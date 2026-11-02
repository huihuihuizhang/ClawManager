# A → C：acceptance/catalog 生产签名调用交接

基线：`backup@d91eada6`。本轮为现有生产接口静态核对，只新增本交接；未改变授权、签名或 C 业务代码，未冷编译、SSH、部署或连接现场。现场 App fix18、同 namespace 未见备份 controller、host 缺少 Go/node/npm 的信息来自审核交接，本轮未独立验证。接口存在不代表现场装配或备份通过。

## 1. 直接消费现有 concrete types

无需新建 signer 框架、HTTP endpoint、task 或数据库表。生产入口及类型如下（`execution`=`internal/systembackupexecution`，`security`=`internal/systembackupsecurity`，`controller`=`internal/systembackupcontroller`）：

```go
// 由已启动的原 DeploymentService 提供，claim 必须是原 publisher 当前持有的 token。
(*execution.DeploymentService).PublicationSignersForTask(
    ctx context.Context, claim controller.ClaimToken,
) (*security.SQLPublicationTaskSigners, error)

(*security.SQLPublicationTaskSigners).PublicationSigningKey(
    ctx context.Context, purpose string,
) (security.PublicationSigningKey, error)

(*security.SQLPublicationTaskSigners).PreparePublicationRecord(
    ctx context.Context, purpose string, payload []byte,
) (*security.SQLPreparedPublicationRecord, error)

(*security.SQLPreparedPublicationRecord).Stage(ctx context.Context, tx *sql.Tx) error
(*security.SQLPreparedPublicationRecord).SignCommitted(ctx context.Context) ([]byte, string, error)
(*security.SQLPublicationTaskSigners).Close()
```

这是方法签名清单，非新增 Go interface。`PublicationSigningKey` 已有字段和 JSON tags：`Purpose/purpose`、`KeyID/key_id`、`KeyVersion/key_version`（均 string）。purpose 只能选本次需要的 `acceptance_record` 或 `catalog_record`，不能从 payload/request 选择另一把 key。

调用顺序：

1. `q, err := service.PublicationSignersForTask(ctx, claim)`；成功后 `defer q.Close()`。
2. `key, err := q.PublicationSigningKey(ctx, purpose)`；将 key 原样填入 C 自己验证完整语义的 unsigned payload。
3. C 序列化完整 payload 为 `[]byte`；`p, err := q.PreparePublicationRecord(ctx, purpose, payload)`。不传签名 envelope、不传 payload digest、不传 legacy `recovery.Seal` 文档。
4. 在 C 原业务事务中先验证该原任务的完整证据/准入条件，冻结自己的原签名发送意图，再调用 `p.Stage(ctx, tx)`。Stage 不提交、不做 provider RPC，不授予业务 acceptance。
5. 原事务已明确 commit 成功且没有存活 SQL 事务后，原发送日记允许唯一首次发送时调用 `raw, objectSHA256, err := p.SignCommitted(ctx)`。
6. C 记录这次原发送结果，按自己现有原对象写入/查回协议发布 `raw`。`objectSHA256` 是 **JCS 完整 `{payload,signature}` bytes 的 SHA-256**，不是 payload 或 JWS input 的 hash。

所有返回 error 必须原样失败处理；`Commit` 结果不明不能接着签名。`SignCommitted` 失败/回复丢失不能当作“provider 未收到”，也不能自行重签；这个通用 API 冻结输入及复核当前授权，**不替 C 实现唯一发送/unknown 日记**。同一 purpose 的原输入已冻结后，不能改变 decision_at/recorded_at、key 或业务内容来覆盖；明确读回原日记/已知签名结果，继续原操作。claim heartbeat/takeover 后必须由原 owner 明确重新绑定已取得的新 token，不能查询最新 row_version 后偷偷替换旧 token，也不能借此扩长原冻结 evidence 到期时间。

## 2. C 需要提供的精确 payload

以已有 schema 为准，以下列出本次首次注册所需字段；C 保留 DTO/业务验证所有权，A 不新增另一套 payload DTO。

| purpose | schema_version | 时间字段 | signature domain / protected typ |
| --- | --- | --- | --- |
| acceptance_record | system-backup-acceptance.v1 | decision_at，RFC3339Nano | clawmanager.system-backup.acceptance.v1 |
| catalog_record | system-backup-catalog-record.v1 | recorded_at，RFC3339Nano | clawmanager.system-backup.catalog_record.v1 |

`acceptance_record` unsigned payload 完整字段：

```text
schema_version: string = "system-backup-acceptance.v1"
backup_public_id: string (原任务)
attempt_no: integer (原 latest sealed capture attempt)
manifest_checksum, marker_checksum: string (原精确成品 bytes 的 SHA-256)
staging_cleanup_evidence_id, staging_cleanup_evidence_hash: string (原实际清理证据)
local_acceptance: boolean (C 完整验证计算结果)
local_reason_codes: []string (非空、唯一、Unicode code point 升序)
local_reason_codes_hash: string (按公共合同计算)
decision_at: string (RFC3339Nano)
config_version: integer (原配置版本)
signing_key: security.PublicationSigningKey (由 q 返回)
```

`local_acceptance=true` 时 reasons 恰为 `["eligible"]`；false 时不得含 eligible。可用 reason 枚举、禁止作为 local reason 的失败原因及结构约束见 [acceptance-marker.schema.json](../contracts/system-backup/v12/acceptance-marker.schema.json)。该 schema 不包含 `origin_installation_id`；不要为“绑定 installation”擅自添加额外字段。A 的 task/installation 绑定由独立 owner record 与原 SQL 完成。

`catalog_record` 的 `artifact_registered` unsigned payload 完整字段：

```text
schema_version: string = "system-backup-catalog-record.v1"
origin_installation_id: string (原 installation)
backup_public_id: string (原任务)
attempt_no: integer (原 latest sealed capture attempt)
record_id: string (原稳定 append 意图标识)
recorded_at: string (RFC3339Nano)
signing_key: security.PublicationSigningKey (由 q 返回)
event_type: string = "artifact_registered"
manifest: {provider: string, identity_hash: string, key: string, version: string}
manifest_checksum, marker_checksum, acceptance_checksum: string
capture_certificate_hash, artifact_index_checksum: string
```

字段限制、tombstone 分支见 [catalog-payload.schema.json](../contracts/system-backup/v12/public-c-crypto-v1/catalog-payload.schema.json)；本次注册不要混入 tombstone 字段。manifest 必须来自原已验证 locator/object version，不能用 latest/无版本别名来代替原不可变对象。catalog 签名输入中的 `acceptance_checksum` 应取上一步完整签名 acceptance 成品 SHA-256。

关键兼容结论：`internal/systembackup/recovery.Acceptance` 使用嵌套 identity、decision_time_ms、config_snapshot 和 staging_cleanup_evidence，与上述公共 v12 payload 不同。不能直接 Marshal 此 legacy DTO 后送入本生产签名接口；也不要用 legacy Catalog `recovery.Record` 替代 public-c-crypto payload。公共签名向量在 [signature-vectors.json](../contracts/system-backup/v12/public-c-crypto-v1/signature-vectors.json)。

A 内部已有 JCS、protected header、无填充 base64url 和 JWS framing；C 不需要重新实现。输入长度同时受 payload/JWS input 的 16384-byte 上限约束；大 payload 会拒绝，不允许只签一个 digest 代替完整 input。`PreparePublicationRecord` 检查 framing、任务/key/schema/time/history；**不验证 C 完整 payload 业务语义**，例如真实 cleanup、config_version 与原配置是否相符、reasons 和其 hash、全部 checksum 关联仍必须由 C 验证。

## 3. 当前 publisher 授权和安装材料

生产实现位置：

- `systembackupexecution/deployment_publication_startup.go`：`PublicationSignersForTask` 先核对当前 Forward/deployment 绑定、启动时 publisher DB/runtime 和精确 `PublisherOwner`。
- `systembackupsecurity/publication_factory.go`：`ForTask` 从原 SQL 取得 request_id 和 latest capture attempt；只接受原 token owner/row_version、live lease/deadline、validating/publishing 和 latest sealed attempt。每个 task signer 保留精确 token。
- `systembackupsecurity/sql_signing_authority.go`：`current` 复核独立 SQLOwner 的真实 CURRENT_USER/server UUID/database、installation、原 request/config/task purpose、完整六模块列表、cancel、capture_result hash、原 gate generation，以及 collectors_stopped_at/source_resumed_at 的真实顺序。不能只凭 status 允许签名。
- `StageSigningInput` 在调用者同一 tx 中冻结完整 JWS input/原 task/attempt/workload/capture hash/epoch；签名前后与 JWT/provider 使用边界复核当前事实，未提交/已回滚输入不能授权签名。

安装材料不是 C 生成的 payload 附件。启动 `SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_FILE` 与 `SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_SHA256` 独立注入，路径与父配置 `PublicationSigners` 的 protocol/path 一致；不能把该派生材料 hash 回填父配置/Forward 形成自签循环。materials schema=`system-backup-publication-signers.v1`，含原 owner 签名 installation record、独立 revision/bytes/issuer pin，以及 capture/acceptance/catalog 三个 purpose 的 JWT/CA/provider mount。`POD_NAME` 对应的真实 Pod、namespace UID、publisher SA UID 必须匹配独立 grant；publisher owner 为 `public:<真实PodUID>`，publisher SA 不得复用 capture SA。

签名 key 三用途独立，JWT/CA/provider policy、原 SQL account/config/workload 精确匹配；不能用 capture grant、数据库登录、payload signing_key 或 provider 登录成功替代 SQLOwner 授权。catalog append/read identity 的独立材料在 `publication_catalog_target.go`，与 `catalog_record` 签名授权是两道不同门禁；有签名不代表有 append 权限或 catalog 已发布。

## 4. 审核与剩余工作

本轮只做静态审查与本文档 diff 检查；不新增 Go 框架、不改变任何 A/C/D Go 文件、不创建构建产物。没有新增必须远测的代码。现场 host 缺少 Go，不提供在现场 host 临时安装编译器或绕过 controller 装配的命令。

审核者若需要回归已有签名接口，在**原有构建环境**的 repo/backend 执行下面定向命令；与统一单缓存复测合并，本轮未执行。GOCACHE/GOTMPDIR 由审核者指向独占、有足够空间的 scratch，完成后只清理该轮自有目录。

```bash
GOMAXPROCS=2 GOTELEMETRY=off GOTOOLCHAIN=local GOPROXY=off \
go test -count=1 -p=2 ./internal/systembackupsecurity \
  -run '^(TestPublicationRecordPublicCContractVectors|TestPreparedPublicationRecordCurrentClaimSQLToTLS|TestPublicationFactoryOriginalTaskAndLiveWorkload|TestPublicationFactoryMaterialAndPostSignRevocation|TestSQLSigningAuthorityRefusesUncommittedAndReboundInput)$'
```

需要 C：按已有完整证据构造/验证上述两个 public payload，在原 publisher 事务和原发送日记下调用现有 A API，串起 acceptance 成品 checksum → catalog 签名输入。需要 D：将同 task 生产 C 调用点与已安装 `DeploymentService`/当前 claim 接通，保留实际清理、独立验证、catalog append 和终态准入。未因本交接认定上述链条已接通或现场通过。

## 5. C local cleanup 的 publisher 权限静态复核

现有 `systembackupcontroller.PublicationGrantSQL` 已覆盖此次 C local cleanup，无需新增 GRANT、列级扩大或源角色权限。继承链为 `publicationTableGrants → formalCaptureTableGrants → publicCaptureTableGrants`；runtime/provider-permit 分支同样保留这些控制表权限。这里确认的是现有 table/verb 矩阵足够，不是声称已改成仅五列 UPDATE，也不是现场账号已应用。

| C 实际访问 | 当前矩阵 | 结论 |
| --- | --- | --- |
| staging_resources SELECT / FOR UPDATE；UPDATE lifecycle、cleanup_result、claim_owner、claim_expires_at、row_version | system_backup_v2_staging_resources: SELECT, INSERT, UPDATE | 已涵盖；不新增 DELETE/源数据写入 |
| cleanup_result evidence INSERT、同原ID/归属 SELECT / FOR SHARE；既有 diagnostic 日记 | system_backup_v2_evidence: SELECT, INSERT | 已涵盖；evidence_type/原task限制由 C 原SQL和当前授权执行，不由 GRANT 按值筛选 |
| 原配置 retention、capacity SELECT / FOR SHARE | system_backup_v2_configs: SELECT | 已涵盖 |
| RegistrationCapacity.Reserve 的 INSERT IGNORE、SELECT FOR UPDATE、reserved_bytes UPDATE | system_backup_v2_metadata_reservations: SELECT, INSERT, UPDATE | 已涵盖 |
| 原 publisher task 行锁、claim/row_version 复核 | system_backup_v2_backups: SELECT, UPDATE | 已涵盖 |

调用点：`publication_local_cleanup.go` 的 `transaction/checkTx/begin/finish/recheckCompleteTx` 始终使用 `service.publisherVerifierDB`；`reserve` 调用 `security.RegistrationCapacity.Reserve`，读取该 service 的原 CapacityFile。`publication_payload.go` 的 `registerPublicationMetadata/loadPublicationMetadata` 使用同一 evidence 表。容量文件仍需真实新鲜 DB/server 绑定和 headroom；有 SQL 权限不代表容量准入自动通过。

生产准入：`deployment_service.go:446` 在 control-evidence 装配下使用 `SQLControlEvidenceGrantProbe(... Publication: Config.PublicationTarget != nil)`；该矩阵在 publication=true 时继承 `publicationTableGrants`。普通 publication 分支在 `:449` 使用 `SQLPublicationGrantProbe`。CLI `cmd/system-backup-controller-grants/main.go` 的 publication 选项渲染同一 `PublicationGrantSQL`；不用另手写更宽的 GRANT。当前同任务 fixture 在 `production_same_task_mysql_test.go` 通过 `ControlEvidenceGrantSQL(..., options.PublicationForward)` 给原随机 controller caller 授予有限控制表权限，随后切换到该 caller；不是把 admin 连接交给业务。

本轮未改变 grants/probe/源账号。实际 caller 的 SHOW GRANTS、列写入和正负边界由审核者正在进行的隔离真实 SQL 回归确认，不将上述静态结论当作线上验证。

## 6. C final_verification 后的唯一签名发送：直接复用现有 capture 协议

本节只补签名交接，不改 Go/工具，不新增 signer/查询框架，不执行构建、SQL 或远测。C 已获准实现 final_verification；其完整业务证明、原 cleanup/final-verification receipt 及 publication 阶段由 C 自己校验，A 的成功签名不能代替它们。

### 6.1 已有正常路径及准确消费点

原生产调用图为 `ensureOriginalForwardCertificate → prepareOriginalCaptureCertificate → prepared.Stage → 明确commit → prepared.SignCommitted`。最后这个 **execution 业务 wrapper** 内部先查已存结果，再执行 `beginOriginalCertificateSign → 明确commit → security.SQLPreparedPublicationRecord.SignCommitted → storeOriginalPublicationCaptureCertificate → 明确commit`。正常首次执行只调用一次 provider Sign，不先调用 provider 原操作查询 API。

| 现有方法 / 文件 | 已有行为 | C 可复用的边界 |
| --- | --- | --- |
| `ensureOriginalForwardCertificate`，`publication_forward_request.go:15` | 先读 known bytes；缺失才准备，Stage 原tx提交后调用业务 Sign wrapper，最后读回原bytes/hash | 生产消费者入口的顺序与读回，不能用 generic signer 返回替代持久化完成 |
| `preparedPublicationCaptureCertificate.Stage`，`publication_capture_certificate.go:118` | 锁原task；access.Bind/current facts；写 business prepared payload；同一tx调用 `record.Stage`；再复核business facts/current guard | C 将已完成full-read stamp的 **current final proof**、其内部cleanup history核验和完整payload冻结，与 `SQLPreparedPublicationRecord.Stage(ctx,tx)` 放在同一原业务事务；用 `publicationFinalVerification.recheckVerifiedTx`，不调用旧cleanup live recheck |
| `beginOriginalCertificateSign`，`publication_capture_certificate_intent.go:64` | 原task行锁下复核原prepared bytes；检测 `_sent` 根及残留chunk；首次写原send-intent并明确commit，既存/未知不授予第二次Sign | 只允许本次新插入且明确提交成功的原send-intent授予一次外部调用 |
| `SQLPreparedPublicationRecord.SignCommitted`，`systembackupsecurity/publication_factory.go:322` | 当前task/workload/material检查；内部签名；再次current检查 | 这是**通用签名调用**，本身不负责C的唯一发送/结果日记；必须被C的private业务wrapper包住 |
| `storeOriginalPublicationCaptureCertificate`，`publication_capture_certificate_store.go:135` | 精确prepared payload比较、当前原guard/business facts、history验签、原metadata写入及读回，明确commit后返回 | C 对签名结果做同样的原输入/当前业务复核，存完整原signed bytes及hash，不只存一个success/hash |
| `loadOriginalPublicationCaptureCertificate`，`publication_capture_certificate_store.go:88` | 只读原metadata/current facts/history，返回已存原bytes，不生成新时间/key/signature | C 的本地known-result查询与重入路径，不要求provider查询能力 |

其中 `record` 的准确类型为 `*security.SQLPreparedPublicationRecord`，由 `q.PreparePublicationRecord(ctx,purpose,payload)` 返回；`q` 来自 `service.PublicationSignersForTask(ctx,claim)`。不直接取得私钥，不另建授权session或新task，不把capture执行grant当publication signer grant。

### 6.2 acceptance/catalog 最小冻结与发送规则

1. **稳定业务坐标。** C 在原task/attempt下为 acceptance 和 catalog 分开定义原业务journal标识；catalog 注册分支绑定原 `artifact_registered` 操作。标识不能加入当前Pod/claim/row_version、decision_at/recorded_at、key版本或payload hash，使这些变化产生“全新签名操作”。这些字段及原manifest/marker/index/capture/cleanup/final_verification摘要应放在冻结正文里做精确比较；它们变化时拒绝原操作，不另起ID。
2. **只准备一次完整 input。** 首次从当前 `q.PublicationSigningKey(ctx,purpose)` 取得key，C用已有 `ce.Canonical` 产生完整public payload JCS bytes，冻结原decision_at/recorded_at、signing_key及全部业务字段。然后 `q.PreparePublicationRecord(ctx,purpose,payload)`。不要只冻结digest；不要在重试时重算时间、切换key或重做业务判断覆盖原input。A内部已有protected header/JWS input，不需要新增input-getter或另一套编码器。
3. **原业务T1。** 按原publication锁序锁task并核对精确当前claim/owner/row_version/当前phase和deadline；消费实际完成full-read stamp的 `*publicationFinalVerification`，调用 `final.recheckVerifiedTx(ctx,tx)`，由其内部在当前new token下认证旧cleanup不可变history及原固定成品。登记C的不可变prepared正文/原业务摘要，再调用 `record.Stage(ctx,tx)`；在同一tx尾部再次复核 current final proof 与guard，然后明确commit。任一步失败rollback；commit ACK丢失、context到期或不明，不能落入Sign调用。不能把旧cleanup claim替换成new token来通过其旧live recheck。
4. **唯一发送T2。** 按capture现有协议另在原业务事务中重新锁原task、核对原prepared正文与当前精确claim，消费同一current final proof的 `recheckVerifiedTx(ctx,tx)`（包括其内部history核验）。已存在send-intent（含不健康、过期或孤儿chunk）不表示可再发；只有原稳定ID完全没有历史发送记录且本次新intent实际写入、尾复核、commit明确成功，才给这次调用栈一次发送许可。不能把 `Stage` 幂等返回nil、查到既存intent或重启后的布尔变量当该许可。整个provider调用期间不得持有SQL事务。
5. **一次Sign。** 仅上述明确新发送边界之后，执行一次 `raw,sum,err := record.SignCommitted(ctx)`。通用API在JWT/provider前后仍复核当前签名授权；该调用任意error、取消、回复丢失或后置授权失效都可能发生在provider已处理之后。C统一保留原send-intent并返回 `ErrExecutionCommitUnknown` 语义，不盲目再Sign，也不据错误文本推断“未发送”。
6. **结果T3。** 对实际收到的原signed bytes：确认payload与冻结JCS bytes完全相同、`hash(raw)==sum`，通过独立历史公钥的 `VerifyPublicationRecord(raw, security.ArtifactSigningTask{BackupPublicID:原任务, AttemptNo:原attempt},purpose)` 验证，并在原业务事务以 current final proof 的 `recheckVerifiedTx(ctx,tx)` 重新检查当前claim、内部原history和冻结输入。以同一稳定ID将完整 `raw`、hash、长度及其原关联持久化，尾复核后明确commit；再读回精确bytes/hash。只有这一步已知结果才能用于后续acceptance写入或catalog输入，不能直接据内存Sign返回就宣布成品发布/终态成功。

以上保留了现有capture两道发送前commit屏障，不要求设计新全局状态框架。A `StageSigningInput` 冻结的完整JWS input包含原task/workload、capture_result hash和epoch；C business prepared/send/result必须另有原操作稳定标识，因为A底层 `signingInputEvidenceID` 还绑定原workload。换Pod/claim不能借新的底层ID制造第二次业务Sign。prepared/send/result可以沿用现有 `system_backup_v2_evidence` 的原不可变diagnostic metadata和容量协议，不需要新表或写源角色。

`registerPublicationMetadata/loadPublicationMetadata` 在 `publication_payload.go:101/114`，分别执行原归属SELECT/FOR SHARE及不可变INSERT；`registerPublicationMetadata` 不自动做capacity reserve。capture的 `stageOriginalCertificateEvidenceBytes` 在 `publication_capture_certificate_store.go:192` 示范每个新metadata正文先 `RegistrationCapacity.Reserve`、按原配置retention登记、相同ID只接受相同bytes、最后读回。C本次正文若在既有8192-byte inline界限内可直接沿用这些通用metadata接点；超限拒绝，不能截断/改签digest。capture专用chunk描述符绑定capture业务类型，不直接拿它假装acceptance/catalog记录。

### 6.3 unknown 与已知结果的最小处理表

| 原本地日记观察 | 允许动作 | 不允许动作 |
| --- | --- | --- |
| 全新业务input，本次T1/T2都明确提交 | 执行本次唯一Sign，然后验证和持久化原结果 | 因provider没有查询API而拒绝正常首次发送 |
| 已存有效signed result | 当前业务准入和history验证后返回/重用完全相同的原bytes/hash | 重新生成时间、key、payload或再次Sign；强制provider再查一次才准继续 |
| 既存send-intent，结果缺失或结果不可验证 | 只查询原已存结果；保持unknown保护，停止后续发布/acceptance/catalog/终态推进 | 把SQL缺行、TTL、健康状态变化、Pod重建或相同digest当成provider未处理证明后重签 |
| T2 commit ACK丢失 | 该调用不发Sign；后续只查原结果/日记，未有明确原操作完成证明则保持unknown | 读到已提交send-intent后把它当本次新许可；因“可能没commit”重试Sign |
| provider返回丢失，原bytes未取得 | 保持unknown，保留原日记/对象保护 | 即使算法确定性、相同payload或新claim也再Sign |
| 结果T3 commit ACK丢失 | 先查原稳定result ID，验证已存原bytes；若仍持有已验证的精确原bytes，可按原不可变写入协议处理同一结果持久化，不调用Sign | 用一次新的Sign“恢复”结果；已存不同bytes时覆盖 |
| 只有既存prepared或不能解释的同purpose冻结记录，未确认原发送状态 | 查询已存原结果并按原owner恢复规则处理；默认保留unknown | 新建时间/业务ID绕过；把其他purpose的正常capture输入一并当成可删除的旧记录 |

**provider没有原操作查询能力时，unknown可以保持受保护的失败/待恢复状态。** 这是一条允许的错误路径，不是要求为正常首次发布新增查询API、resolver、callback或provider capability。只有provider本来就提供受支持、能绑定该原操作且有独立结果证明的查询协议时，后续恢复owner才可另行消费；本切片不把它作为happy path前置，也不把普通404/缺行当外部未发送证明。现有 `SQLPreparedPublicationRecord.SignCommitted` 没有承诺provider幂等键或once语义，C不能因为签名bytes可能确定性相同而取消send-intent屏障。

### 6.4 不可盲目复制的 capture 专用条件

- `lockOriginalCertificateTask` 在 `publication_capture_certificate_intent.go:22` 精确限制 `status='validating'`。C acceptance/catalog应使用其原publisher当前实际phase及准入条件；通常已在publishing，不能直接调用该capture helper，也不能只把它改成宽泛状态集合来制造成功。A通用signer允许validating/publishing，C仍需自己的更精确业务phase检查。
- `readPublicationCertificateFactsTx` 要求原capture hostpath仍为ready，是签capture certificate的历史边界。完成local cleanup后原104应为deleted/succeeded。旧 `publicationCompleteCleanup.recheckCompleteTx` 仍绑定旧精确cleanup claim，**不能直接作为新publisher token下的签名准入**。C应消费真正完成full-read及跨成员关系验证stamp的 `*publicationFinalVerification`，使用 `recheckVerifiedTx(ctx,tx)`（`publication_final_verification.go:131`）；它检查 `verifiedSHA256==contentSHA()` 后内部调用当前 `recheckTx`，将旧cleanup作为immutable history在当前new token下重新认证。不能把旧cleanup claim/token替换掉、把104改回ready或伪造原目录。
- 当前 final producer 在完整跨成员关系尚未消费时仍返回 `ErrPublicationFinalRelationsRequired`，没有complete stamp；仅构造history handle、`contentSHA()`、单独调用history reader或逐成员解密成功都不能给签名/终态发放准入。该现存guard由C获准的full-read切片实现后消费，不在A文档中虚构为已完成。
- `originalCertificatePreparationAbsentTx` 在 `publication_capture_certificate_intent.go:42` 会拒绝该任务任意 `sev_asign_` 记录。acceptance/catalog之前正常已有capture签名输入，所以不能照抄这条全purpose COUNT判断。C的prepared/send/result检查需按原业务purpose分开，保留过期/不健康/孤儿记录的未知保护，而不把另一个purpose的合法记录当成本次新发送许可或可清理对象。
- `originalCaptureCertificateID` 在 `publication_capture_certificate_store.go:36` 绑定固定domain+installation+backup+attempt，prepared后缀`_prepared`、dispatch后缀`_sent`、known result为原根ID，chunk为`_pN`。C复用该稳定坐标/不可变写入/唯一发送模式，勿直接复用capture ID或描述符schema覆盖原certificate。

参考已有原链回归接点（本轮不执行）：`TestAOriginalSixPartCertificatePublicationMySQL` 的 known-byte replay、`dispatch-commit-ack-unknown`、`store-commit-ack-unknown` 等子场景，以及 `publication_capture_certificate_resume_mysql_test.go` 的 `checkAOriginalCertificateKnownResume` / `checkAOriginalCertificateCommitACK`。其中dispatch提交ACK丢失断言Sign次数为0，known result和store ACK丢失重入断言仍只Sign1次；这是C可照用的行为验收规则，不是C新实现已经通过的证据。

## 7. App / bootstrap / config-mutation 真实生产接线审核（2026-11-02）

本节单独基于 `875e3960` 与审核时共享 WIP 做只读源码核对；只补本文，不改 Go、不构建、不连接 SQL/远端、不读取秘密文件。前面各节的实现状态是各自当时的审核记录，不用来否定后续 C acceptance 切片。本节没有验证现场是否具备下列既存配置和材料。

**结论：`WireServices` 仍没有生产调用，确实存在首次安装和配置更新的接线缺口；但不能据此认定每次页面备份前必须执行 bootstrap 或调用这个 helper。** 当前新任务生产链从既存启用配置入场，不经过 bootstrap/config-mutation。只有现场已经合法具备全部相符的配置、KEK 原事实和当前部署授权时，才可直接沿现有任务入口推进。新安装、仅有 disabled v1、配置必须变更或缺少 KEK 原事实的现场，不能靠这一前提继续，更不能人工补行、跳过认证或关闭检查。

### 7.1 实际 caller 与确定缺口

以下路径均相对仓库根目录，行号是本节审核时位置。

| 真实生产边界 | 已有调用链 / 确定事实 | 对本次备份的意义 |
| --- | --- | --- |
| App 新任务 | `backend/cmd/server/main.go:999-1007` → `linkedSystemBackupTaskApplication`（`system_backup_tasks_live.go:18`）→ `composeSystemBackupTaskApplication:42` → `NewSQLApplication`；`:64` 的 `registerBackupTaskMutations` 挂载 `POST /api/v1/admin/system-backups` | 此链不创建/启用配置，也不调用 `WireServices`。已存配置满足原准入时可提交原任务 |
| App 配置读取 | `backend/cmd/server/system_backup_read_live.go:61-63` 只挂载 versioned config 的 GET | `GET /system-backup-config` 可用不证明有配置写入能力 |
| 旧配置入口 | `backend/cmd/server/main.go:989-997` 对整个旧 `/admin/system-backup` 组拒绝所有非 GET/HEAD；旧 handler 虽在 `backend/internal/handlers/system_backup_handler.go:30` 声明 PUT，但被此前置 middleware 拒绝 | 不可解开旧写入口去代替新配置事务；旧 `Store.SaveConfigAuthorized` 也不是 `ConfigMutationService` |
| 新配置写入 | `backend/internal/systembackupsecurity/config_mutation_http.go:23-33` 有 `ConfigMutationHTTP`/constructor，但仓库非测试代码没有 constructor 调用或该 handler 路由挂载；`ConfigMutationService` 没有真正配置写入的非测试装配 caller | `PUT /api/v1/admin/system-backup-config` 和 rollback 尚没有生产消费边界；仅补 KEK helper 仍不能让页面保存配置 |
| 离线 bootstrap | `backend/cmd/system-backup-bootstrap/main.go:40` 调用 `run(...linkedOwnerAdapters())`，`:86` → `LoadBootstrapDeployment` → `Apply`；`linkedOwnerAdapters:25` 只链接 `rbac_bindings`、`provider_proof_issuers`、`strong_auth_issuers` 三个 registry validator | 其余六个 registry、全部二十个 reference 和 cross-resource owner 在此实际入口仍缺；`--check`/结构校验不能代替完整 admission |
| 既有 material wrapper | `backend/cmd/system-backup-bootstrap/materials.go:55` 的 `runWithBootstrapMaterials` 只有测试调用；它依赖外部已认证 `Original`/nonce/两种 CA bindings/selections | 不是当前 `main` 的装配。即使真正接入，也只补三个 reference（nonce/artifact_ca/evidence_ca），其余 owner 不会自动出现 |
| A KEK 接点 | `backend/internal/systembackupkekadapter/deployment.go:39` 的 `WireServices` 只有测试调用；`BootstrapAdmissionInput`、`MutationAdmissionInput` 在非测试代码仅有接口和消费点，没有具体 source 实现 | 缺口既包括 caller，也包括原业务材料 source；不能用新增一个未调用 wrapper 宣称完成 |
| registration listener | `backend/cmd/system-backup-registration/main.go` → `LoadRegistrationApplication`；`backend/internal/systembackupsecurity/registration_runtime.go:235` 装配 provider registration、TOTP 和 attestation | 此应用不是配置更新/bootstrap 的既成 caller；它的运行或 activation PASS 不证明配置写入已接线 |

`WireServices` 本身只给两个传入 service 赋 `.KEK`（`deployment.go:61-62`），不挂路由、不补 Admission/Authority/Resolver/Responses、不提供 owner source，也不启用配置。其同一 DB 指针校验意味着不能把离线 bootstrap 与 App 两个进程的连接池硬拼为“一次 WireServices”。每个实际进程仍须使用自己原事务所用的 DB 与同一独立材料绑定；可在外层组合现有 `BootstrapComposition` / `MutationComposition`，helper 名称本身不是授权条件。

### 7.2 最小实际接线位置、可复用材料和阻塞项

1. **App 真实配置 writer：修改实际启动/路由装配边界。** 接点是 `backend/cmd/server/main.go:999` 附近的 versioned admin 装配，沿用 `backupSessionSQL`、`backupSessions` 与实际登录认证；以既有 `NewConfigMutationHTTP` 挂载其精确 PUT/rollback 路径，消费装配后的 `ConfigMutationService`。现有 `JWTRegistrationAuthenticator` 能解析应用 access token，`SQLLoginSessions.CheckConfigMutationSession` 负责原事务里的 live session/revocation 检查；只解析 JWT 或已有 read/action authorizer都不能代替配置写权限。
2. **App 可复用的具体组件：** `NewPinnedConfigMutationAuthority`、`NewConfigMutationSecurityFiles(...).StrongAuth`、`NewConfigMutationCapacity(...).Reserve`、`NewSQLOperationResponses(db,database,installation,sessions,registryDirectory)` 已存在。最后一个才是完整 public Operation 响应适配器，不需要另接 ConfigResource diagnostic 外部发布链。仍须提供真实 registry 文件 source、A 的 reason redaction、`NewPinnedConfigMutationResolver` 的全部 registry/reference/cross-resource owner 和独立 deployment switch。当前无生产装配不能省略这些项；`ConfigMutationService.valid`（`config_mutation_transaction.go:180`）明确拒绝缺 Authority/Resolver/Responses。
3. **KEK 的独立 public pins 可以复用，但业务 source 不能凭空补出。** `backend/internal/systembackupkekadapter/capability_records.go:88` 的 `NewSQLInstallationPreparation` 已将 SQLOriginalReader、installation issuer 公钥和 Generate/Unwrap capability pins 绑定同一 DB。现有 `FormalVerifierDeploymentConfig`（`backend/internal/systembackupexecution/deployment_formal_verifier.go:20`）与 publisher materials 已描述 database/binding/installation issuer/capability pins，实际运行 consumer 使用这些 pins；可在部署 owner 认证其来源、安装/配置相等后复用这些字段。不能从页面 JSON/数据库候选自身推导可信 issuer，也不能把 `attachFormalVerifier` 的 worker execution grant 当 config mutation authority。`system_backup_installation_kek_authority` 是另一个 owner 管理的原 signed mapping 表（`deployment.go:17`）；admission 不创建/签发它。
4. **缺少的 C/source owner 是硬阻塞。** 两种 admission source 必须从精确 bootstrap grant/config 或 resolver 的 current/proposed KEK pair 出发，保持 D 提供的完整 Snapshot 与 ObservedAt，解析原 signed mapping、source revision、Generate/Unwrap source 和真正 `PreparedCoverage`。在非测试源码中未找到 `PreparedCoverage` 的具体实现。`SQLCoverageCensus`（`sql_coverage_census.go:25`）和 `UnadmittedS3CoverageCensus`（`s3_coverage_census.go:70`）明确只是未准入库存，不能直接冒充完整 writer/adoption/history/unknown/catalog/restore/prune 覆盖证明。没有这些材料时，不能给 source 返回空 coverage 或仅新索引 census。
5. **离线 bootstrap 必须接进自己的 transaction owner。** 真正需修改的是 `backend/cmd/system-backup-bootstrap/main.go` 的 linked owner/材料入口，以及 `backend/internal/systembackupsecurity/bootstrap_deployment.go` 的可信 owner 依赖传递和 `:238` 的实际 `ConfigBootstrapService` 构造，使准备后的 `.KEK` 确实到达原事务。不要把 adapter import 放进 security：`systembackupkekadapter` 已 import `systembackupsecurity`，反向 import 会形成 Go 循环。security 只接收其既有 `BootstrapKEKPreparation` 等接口；具体 adapter 在 cmd 或更外层 deployment composition 组装。
6. **candidate 分支有单独漏接点，不能只修 legacy service 构造。** `bootstrap_deployment.go:199` 直接转 `applyCandidates`；`bootstrap_deployment_candidates.go:112` 调用 `PrepareConfigBootstrapCandidateAttempt`，`:123` 消费 `attempt.Apply(d.openDatabase)`。后者（`config_bootstrap_candidate_attempt.go:111`）直接构造 producer consumer，不经过 `ConfigBootstrapService.Bootstrap`，且 attempt state/environment 未携带 KEK。既有 service candidate 路径则在 `config_bootstrap_candidates.go:145/208` 将 `.KEK` 传给 environment 并准备。要在部署 candidate 路径补同一效果，必须由 D 明确解决 **原 one-shot authority 先准备、再开 DB** 与 `PrepareBootstrapKEK(ctx,db,...)` 需要 DB 的时序，贯穿同一原 session/context/事务；仅给某个旁路 service 赋 `.KEK` 不会生效，也不能重复 Prepare、重建 deadline 或绕过 prepare-before-DSN 边界。
7. **bootstrap 完成也不等于可提交新任务。** `DecodeBootstrapConfig`（`config_bootstrap.go:63-74`）只接受 disabled；`writeBootstrapConfigData:362-364` 写 `last_effective_enabled=FALSE`。实际部署 legacy 构造没传 `CanonicalSnapshot`，candidate deployment attempt也传 false；而 versioned writer 必须读到 `canonical_config_json`。现有 `writeBootstrapConfigData:355-356` 已有 canonical 写入分支，且正式 migration 112 已声明该列，但不能因列或 helper 存在就认定生产 caller已采用。首次安装还需要在真实迁移/schema条件下正确持久化 canonical bytes，并通过完整 authenticated config mutation启用；不能把 bootstrap 改成直接 enabled 或手动翻 SQL 开关。

因此当前不能给出“只改一个 caller、材料全已存在”的修复承诺。最小工作落点已有上述真实入口，但原部署材料认证、全部 owner source、KEK coverage 和 candidate 一次性时序尚须补齐；新增空 source 或未被 main 调用的 factory 不能交付这个缺口。

### 7.3 可以直接用既存配置的严格前提

此处“直接用”仅表示不重复执行首次 bootstrap，不减少任一当前认证。必须已有合法原流程提交的配置和 KEK 原事实；本轮没有现场只读证据证明这些前提成立。

- **既存 active canonical config：** `public_sql_writer.go:180/215/308` 要求同 installation 的 active version/state 有效、`last_effective_enabled=true`、配置 `enabled=true`、完整 canonical bytes/长度/hash一致、可通过 `DecodeConfigValues`，deadline与物化列一致；profile/matrix须相符。仅有旧 redacted config JSON、disabled v1 或手工 inserted fixture 不够。
- **真实 App task admission：** `system_backup_tasks_live.go:18-35` 要求已加载 execution profile、`SYSTEM_BACKUP_EXECUTION_PROTOCOL=public-v1`、独立 execution deployment switch；现有登录 session/read/action pins继续生效。`deployment_admission.go:123` 还要求原 config/profile 的真实、未过期 readiness、协议、请求 parts覆盖；acceptance purpose须有 acceptance_ready及合格目标。不能合成 readiness 或删除六模块要求。
- **真实 controller / 原 KEK 与 current materials：** 必须已有运行中且正确装配的 controller/执行 owner，匹配既存任务配置的 KEK binding/fence、原 signed mapping、Generate/Unwrap capability evidence、issuer/Pod/SA/material pins及其他当前授权。`provider_permit_issuer.go:449` 的 `RequireUnrevoked` 会拒绝缺失 binding 或被撤销的 Generate；publisher另行检查 Unwrap。`WireServices` 不在每次任务调用链里，不代表缺失 KEK事实可以被运行期自动初始化或忽略。
- **不需要本次改配置：** 若目标、引用、授权材料或配置版本必须更新，不能把读取既存配置当成授权迁移；应先补齐并消费真正 config mutation路径。若现场无 active config，应走已补全 owner/KEK 接线的真实离线 bootstrap及随后authenticated enable，不重复初始化已有安装，也不向 source DB临时建表/填行。

满足上述条件只说明 **WireServices/bootstrap 接线缺口不必挡住“沿既存配置发起一次原任务”的调用路径**；不证明原 30 秒 key window、C full-read/acceptance/catalog/terminal、六模块页面备份已经成功。当前端到端状态仍以主审核的原 Linux/现场证据为准。

## 8. 冻结 acceptance 与 A 生产 signer 的语义审核（2026-11-02）

本节为独立追加，不修改前七节。本轮只读实际函数、SQL条件和调用顺序；不改 Go、工具或 catalog，不编译、执行 SQL/远程、提交，也不运行 AST/源码计数测试。以下“Stage 数量增长”指 C 生产代码自身的数据库检查，并非本轮新增测试。

冻结核对值：`publication_acceptance.go` SHA256 `90bd7d117f7531200b6c6b9b5710dd60bc0542a733463f6457cdf3d5642e0a17`；`publication_signing_journal.go` SHA256 `ddffbcc20addcb79009adf13a6166451845ed372084697f484366f0519f81d80`，审核结束复核相同。typed acceptance gate 读取时 `publication_journal.go` 为 `6008948e638b61523ada0cc1cd3488dcf9905333b83d12a740b96905d748e74d`；共享 catalog 工作随后已改变该文件。本节对 typed gate 的结论限定于该已读冻结版本，不扩展为新 catalog 分支审核。

**结论：正常由这套 C 协议创建且保留 prepared/sent/result 的路径，没有发现 claim/RV 变化或 ACK/RPC 不明导致二签的入口；但不能据现有 Stage 前后增长检查声称所有既存/孤儿 A 输入都被阻断。另有当前 KEK Unwrap 撤销未被 acceptance 恢复检查消费的具体缺陷。**

### 8.1 [P1] 新增 A evidence 不等于原业务没有历史签名输入

位置：`backend/internal/systembackupexecution/publication_signing_journal.go:263-281`。C 在自己的稳定 `_prepared` 不存在时，比较该 backup 下所有 `sev_asign_` evidence 的前后数量，只要求 `after>before`，然后允许后续首次 `_sent`。这一检查确实阻断 **当前 A ID 下完整输入的幂等 Stage**：A 在 `backend/internal/systembackupsecurity/sql_signing_authority.go:266-271` 对完全相同既存 input 返回 nil、不新增 evidence，C 随即 rollback 并返回 unknown；不同原 input 则 A 自身拒绝。它也不会因正常 capture purpose 已有 evidence 就无条件拒绝 acceptance。

但是，A ID 的范围是 `installation + ArtifactSigningTask + purpose`（`sql_signing_authority.go:122-125`），`ArtifactSigningTask` 包含 workload。实际 factory 在 `publication_factory.go:234-236` 使用当前 namespace/PodUID/SAUID 填充 workload。因此已有 **另一 workload 的同 backup/attempt/acceptance_record A 输入**、但没有该稳定 C business journal时，新 workload 的 Stage 会新建另一个 A ID，数量增长成立。C 的 absence 查询只检查 `sev_pub_accept_<stable hash>`，不会认证旧 `sev_asign_` 的 purpose/input/发送历史。A `SignCommitted` 也没有跨 workload once 日记，不能补上这一判定。

这一反例的明确前提是 replacement workload 已能取得合法 current final proof、当前 claim 和全部 signer授权；本节没有声称现有冷启动恢复已能重建该私有 proof。它说明这道 gate 本身只证明“本次新增 A 输入”，不能证明“同原业务从未存在可疑签名输入”。正常旧 C journal 仍在时，稳定 C ID 会先挡住该分支；风险范围是旧 generic/迁移/孤儿 A history 没有相应 C journal的入口，不能外推成正常 wrapper 任意换 Pod 都会二签。

同一语义还影响孤儿 chunk：A `readFrozen`（`:383-387`）先找当前根 ID，根缺失即返回 NoRows；`insertFrozen`（`:333-360`）只写本次需要的根/chunks。若旧 `_pN` 孤儿仍在、此次写入不与其 ID 冲突（例如此次 inline 输入），Stage 可以新增根；C 总数依然增长。旧孤儿不会被当成 unknown 全面拒绝。原子 Stage 正常提交本身不会产生这种半记录；此处讨论的是已存在孤儿历史，不能将其缺根解释为 provider 未处理证明。

修复/验收边界应是：在原业务首次准备前，明确处理 **同一原 task/attempt/purpose、跨 workload 的 A 原输入与残留**，无法解释时保留 unknown；不能仅以增长替代。也不能照抄 capture 对全 purpose `sev_asign_` 一律拒绝的逻辑，因为正常 capture 输入合法存在。本文不新增 A 私有 ID 推导器、宽泛清理或空权限回退。

### 8.2 [P1] acceptance 当前恢复检查遗漏持久化 Unwrap 撤销

位置：`backend/internal/systembackupexecution/publication_acceptance.go:91-109`。`acceptanceRecoveryFactsTx` 读取并持有 KEK fence 的共享锁，随后认证原 owner signed record、attestation 和 capability evidence，但读出的 epoch 未用于绑定或比较当前 registry facts；没有读取 `system_backup_v2_kek_bindings.unwrap_revocation_json`，也未消费等价的 current unrevoked 证明。

这与原 owner signed record 的 `UnwrapRevoked` 不同：`backend/internal/systembackupkekregistry/revoke.go:47-61` 的原 `Bound.Revoke` 独立持久化 `unwrap_revocation_json` 并推进 epoch，不要求同时重写 `system_backup_installation_kek_authority` 或 capability evidence。`InspectOriginalKEKMaterial` 是纯字节认证；它看不到这条独立 SQL 撤销。fence 共享锁会阻止检查期间的并发撤销，但不会使 **锁取得前已经提交的撤销** 自动成为拒绝条件。

具体时序：真实 final full-read 完成 → 原合法 KEK owner 提交 Unwrap 撤销、原 mapping/evidence/签名 grant 仍有效 → acceptance 准备或发送事务执行。`proof.recheckVerifiedTx` 复核当前 publisher 和原清理/成品 history，不重新执行 `PublisherVerifierForPart` 的 KEK fence/unrevoked 链；A publication signer 的 `current`（`sql_signing_authority.go:131-184`）检查签名授权、task/claim、sealed attempt、stop/resume/capture hash，也不读取 KEK binding撤销。因此当前代码仍可能沿用 `KEK.SourceIndependent=true` 和原 `RecoveryProof` 的恢复判断，签名并创建 acceptance。

原 publisher verifier 明确在 `backend/internal/systembackupkekadapter/publisher_verifier.go:300-302/449-450` 消费 `RequireUnrevoked(..., UnwrapRevocation)`，不能用之前 full-read 已检查过来代替 acceptance 当前事务检查。所需修复是沿原锁序读取该精确 KEK binding 的当前 persisted Unwrap 撤销/绑定一致性，在 acceptance 准备、发送、结果/typed消费的共同 current gate中拒绝撤销；不能撤销后重发恢复 RPC、替换原 evidence，或把旧 signed record 未撤销当成 registry 未撤销。

### 8.3 正常 C 日记路径已确认的 once / unknown 边界

| 触发状态 | 实际路径及结论 |
| --- | --- |
| T1 首次准备 | `publication_signing_journal.go:248-284` 在当前 publishing task 的精确 owner/RV行锁下，写完整 C prepared并执行 A Stage；`:119-123` 尾部重新检查 current final/recovery/payload，commit 明确成功才返回。T1 ACK 不明不进入本次 Sign；若数据库已有原 prepared，后续只加载原 bytes，不重算 decision_at/key/payload |
| T2 首次发送 | `:357-374` 再取得同原 task行锁，要求 intent 原 claim 等于当前 proof claim、原 SignUntil 与 current recovery窗口有效；拒绝既存 `_sent`/`_result`及其同前缀残留。只有本次事务明确提交新 `_sent` 后才到 `:378` 的唯一 A SignCommitted |
| 竞争调用 | 即使两调用先前都读到无 sent，T2 task行锁仍串行化；后者在锁内重读 sent prefix，拒绝第二次发送。没有以外部 provider 幂等性或确定性签名代替该屏障 |
| T2 commit ACK 丢失/context 到期 | `transaction:122-123` 返回 unknown，调用不执行 RPC。若 sent 已提交，后续 `:330-351` 只报告 unknown。若提交确未发生且无 sent，后续新调用仍需重新获得真实首次 sent明确提交许可；前一次未曾调用 RPC |
| RPC 已发生但回包丢失/后置 A 授权失效 | `:378-384` 任一 error 保留 sent并返回 unknown；没有再次 Sign 或改原时间/key的分支。A `publication_factory.go:322-329` 后置检查失败可丢弃已收到签名字节，C同样按 unknown处理 |
| T3 结果提交 ACK 不明 | `:386-404` 在 current事务校验原 sent、写完整 signed record/hash并读回；不明返回 unknown。重入如能读到健康完整 result，直接验证原 bytes返回；如 result缺失/失效而sent仍在，维持 unknown，不重签。没有实现“丢结果后重新 Sign”恢复 |
| 当前 claim/RV 改变 | 使用旧 proof的 SQL guard拒绝；合法新 proof下可以检查原 prepared/known result，因为历史 intent的 claim不被覆盖。无 known result时 `ensureSigner:292` 和 T2 `:358` 要求 intent claim精确等于新 proof claim，因此旧 prepared不会换token继续签。known result则只做当前业务与历史验签，不要求构造新 signer |
| 过期/不健康/缺根残留 C 日记 | `loadPublicationMetadata` 只读健康未过期原 bytes；NoRows之后的 `acceptanceJournalAbsentTx:60-67` 不按 TTL/health过滤，仍检查稳定前缀下所有原行。它们阻断新准备/新发送；未知状态不授予第二次Sign。此项是 C journal保护，不等于 8.1 的 A孤儿保护 |

上述结论以日记未被另一个未审查写入口删除/绕过为前提；A 通用 API 本身仍可重复调用 `signer.Sign`（`backend/internal/systembackupsecurity/publication_record.go:127`），业务 once 来自本 C wrapper，不是 A API的承诺。

### 8.4 purpose / task / payload / header 与 typed消费的贯通范围

- **业务正文与恢复事实：** `acceptanceRecoveryFactsTx` 每次先调用实际 `proof.recheckVerifiedTx`，验证原 policy/trust/目标与独立恢复 evidence；`validateAcceptanceBusinessPayload:129-140` 比较 six-part strong acceptance manifest、无 disqualifier、外部无风险 target、恢复证明、原 manifest/marker/cleanup/config/task/attempt、decision_at和唯一 eligible reason。这些检查不是 caller布尔量；但当前 registry撤销缺陷按 8.2保留。
- **完整输入冻结：** C持久化完整 public payload及其hash、原 claim、原 SignUntil和artifact原history摘要。A `PreparePublicationRecord` 构建规范 EdDSA protected header和完整 JWS input；`StageSigningInput` 冻结完整 authorization/task/workload/purpose/binding/input/capture hash/epoch。A `authorize:439-453` 在实际 provider前后重新读取 committed冻结输入并验证精确授权/摘要，不以 Stage返回nil当外部授权结果。
- **签名验收：** C `verifyPublicationAcceptanceRecord:175-182` 要求 envelope payload与冻结 payload字节一致，并调用 A history `VerifyPublicationRecord(...,"acceptance_record")`。A `publication_record.go:184` 后的验证重建规范 header，核对 purpose/domain/key、backup/attempt、payload key、artifact-time key有效性/当前revocation和 Ed25519签名。C只传 backup/attempt的 history任务用于成品验签；live workload/operation/claim授权另由原 A current/frozen input链完成，不混称为 history验签涵盖所有live字段。
- **新的 acceptance_put：** 审核的 typed journal版本 `publication_journal.go:153-178/205-228` 在原事务前后消费 `publicationSignedAcceptance.recheckTx`，没有typed proof则拒绝新 action。该 proof在 `publication_acceptance.go:195-212` 绑定当前 service/claim/attempt/target、精确 `_ACCEPTANCE` key、完整 signed bytes、原 known result与current final gate。既存 generic action只返回 `send=false` 的查询/原对象 receipt，不能自行制造 `publicationAcceptedObject`；typed producer还独立读取固定对象至 EOF、复验并重新检查原事务。此次 acceptance切片不自行推进 terminal usable/succeeded。

本节没有执行故障注入或真实 provider/SQL验证。8.1/8.2是实际 gate语义的静态缺陷/边界；8.3/8.4是扣除这些缺陷后的有条件确认，不构成原 Linux窗口或现场页面备份 PASS。

### 8.5 A 的 StageFirst 实现交接（修复候选，未执行测试）

根审核接受上述两项发现后，授权 A 实现首次 Stage 接点。8.1/8.2 的冻结源码证据和限制保持原样；本段记录后续候选，不将候选实现称为已验收修复。8.2 由根另交 C，A 本轮没有新增 registry 读写或将 `reg.Bind` 引入 readonly transaction。

准确 API：`(*security.SQLPreparedPublicationRecord).StageFirst(ctx context.Context, tx *sql.Tx) error`，在 `backend/internal/systembackupsecurity/publication_first_stage.go`。C 在自己的原 business prepared事务首次创建分支调用 `record.StageFirst(ctx,tx)`，取代 `Stage + COUNT增长`；已知结果/unknown恢复不重新 StageFirst。`ErrPublicationFirstStage` 表示已有输入或历史不完整，不授予再次 Sign。原 `Stage`、`SignCommitted` 及业务 prepared/sent/result协议保持原语义，C仍拥有事务和唯一发送决定。

实际实现先锁该精确 current task/owner/RV 的原行 `FOR UPDATE`（保持到 caller提交/回滚），执行 A `current`，在同一tx读取该 backup所有 `sev_asign_` 行，不按健康/TTL或当前 workload过滤。A内部读取和认证每个完整根/分块、checksum/size、protected input、authorization task/purpose/workload及私有ID。相同 attempt/purpose任何输入均拒绝；完整可归属的其他 purpose/attempt可保留，旧expiry不被当作重新授权。无根、额外/缺失chunk、坏metadata/输入、无法归属的任何残留均拒绝；不声称能从缺根孤儿推断其purpose。超过4096行或累计4MiB完整输入也拒绝，绝不将截断库存当成空历史。

随后复用原 `StageSigningInput`，并再次比较 A current facts/有效期。方法不执行 Kube/provider I/O、不提交、不签名。任意error须由原 owner rollback；只有 business事务明确commit和原唯一 sent协议明确commit，才可执行原 SignCommitted。原 `sql_signing_authority.go` 只将私有 `readFrozen` 的根/分块读取提取为 `readFrozenID`，复用同一原校验体；未改变 legacy Stage幂等分支，未让 C推导/选择 A私有ID，未新建表。

待根统一运行的测试：

- 普通 SQL协议模型：`TestPublicationStageFirstHistory`、`TestPublicationStageFirstTransactionAndLegacyStage`、`TestPublicationStageFirstCurrentAuthority`、`TestPublicationStageFirstHistoryBound`，位于 `publication_first_stage_test.go`。覆盖跨workload同purpose、过期/不健康/根缺失/缺chunk/多余chunk/坏根、正常其他purpose及完整分块、rollback后首次、commit后拒绝、旧Stage幂等、stale/canceled/completed tx、库存界限。模型不是 InnoDB锁证明。
- 实际 SQL入口：`TestPublicationStageFirstTLSMySQL`，位于 `publication_first_stage_mysql_test.go`，需 `systembackup_mysql` build tag。仅消费根已有 `TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS`（Host/Port/User/Password/CAFile/TLSServerName/ServerUUID JSON）和独立 `A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID`。要求127.0.0.1非3306高端口、UUID三方相同、SAN验证且TLS最低1.3，并在 CREATE前核验实际会话 `TLSv1.3`；不兼容plain SQL回退，不关闭 `require_secure_transport`。它在独立随机 `ad_a_pub_first_<nonce>` schema内测试真实历史拒绝、正常分块capture→acceptance、rollback、原task锁竞争、acceptance→catalog purpose分离、stale claim和readonly拒绝。schema只按直接持有的本次随机name、UUID和owner marker清理，不做prefix/差集删除，也不创建用户或修改server政策。

本轮仅对这三个新Go文件及 `sql_signing_authority.go` 执行 gofmt和静态diff检查，未调用 Go build/test、SQL或远端。测试是否编译/运行通过、C两处是否消费新API，仍由根统一验证；普通模型、native SQL、原30秒窗口和现场页面成功是不同证据边界。

### 8.6 根独立快照 StageFirst 实际验证结果（2026-11-02）

以下结果来自根审核的本轮交接，A未自行重跑或连接测试数据库。根按 A四文件精确冻结pins、基线 `74ea` 建立独立快照，实际执行 `-tags systembackup_mysql -run ^TestPublicationStageFirst`：security包 PASS，耗时5.445s。`TestPublicationStageFirstTLSMySQL` 确实运行，耗时1.14s，十个子例全部PASS；普通 History十四个、TransactionAndLegacyStage两个、CurrentAuthority两个具名子例及其他 current/bound断言均通过。根明确报告无SKIP、无provider Sign。

根使用新的独占 MySQL 8.4.13 实例，SAN `VERIFY_IDENTITY`、实际TLS1.3、`require_secure_transport=1`、独立datadir与独立UUID。测试结束后根另行执行SQL读回，确认业务schema剩余0，测试自身随机schema已清理。此清理结果不是A对共享数据库执行的扫描/删除。日志SHA尚待根提供，本节不填写猜值。

本次 A四个Go文件复核仍为交付pins：`publication_first_stage.go`=`678a8a422f7ac5b320951d716e40dcdc4b1227374d2ed2aad3f35c81a599bb8f`；`publication_first_stage_test.go`=`fb0aeae66e741211dcd1f83b807beb8b71b7ebb1c0e1cfe81cff3b22842d760a`；`publication_first_stage_mysql_test.go`=`6888a10328a8f7b97bc12d40939644d8de70a372a0d749031dfb4c6c7c72630b`；`sql_signing_authority.go`=`e596e3a49f9233e26db9a019bcc3d1cc4a93797af59183c72323cdf9e4aa1696`。继续冻结，不重复编译或测试。

该证据确认的是 A StageFirst测试切片。根的 A4+D4+C24 共32pins caller组件验证在此次通知时仍进行中；同任务 C producer及页面备份尚未通过，原30秒窗口与现场端到端结果仍未取得。本节不宣称catalog已经可用，也不把测试fixture成功当作现场配置/备份成功。8.1/8.2原审查证据及其限制继续保留。

### 8.7 根补充日志pins与清理完成记录（2026-11-02）

根后续提供的实际日志SHA256如下，补足8.6当时待提供的日志字段；A未自行重跑测试：

| 实际验证范围 | 根报告结果 | 日志SHA256 |
| --- | --- | --- |
| A StageFirst 普通测试及真实SAN/TLS1.3 MySQL切片 | PASS，具体包/子例耗时与条件见8.6 | `c561fa59a605dea451c4ff950695fb6223fc5d1458c0802f770a8bd17dc83e4e` |
| 根所列C32文件统一caller/组件验证 | PASS，4.405s | `66ae7e2fc5ec648ce61755741008d7fb7fe14e5419fd35af75e0b97e8815ed98` |

根确认本批MySQL已正常shutdown，完整自有D测试根已删除，包括该批凭据、证书、源码快照、cache、tmp、发行zip及定位脚本marker，仅保留非秘密日志/pins。这是根的自有测试资源清理结果；A本轮只追加本文，没有执行删除、编译或SQL。

caller/组件PASS不等于C实际同任务producer正向、原30秒窗口或现场页面备份PASS；这些正向结果仍未取得，不据此宣称catalog已可用。A四个Go文件继续保持8.6所列原冻结pins；本段之后文档也冻结，原审查发现及证据边界不覆盖、不改写。
