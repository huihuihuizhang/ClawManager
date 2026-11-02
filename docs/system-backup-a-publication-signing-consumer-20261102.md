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
