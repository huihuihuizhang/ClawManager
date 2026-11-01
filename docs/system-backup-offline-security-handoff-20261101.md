# 新增 A：B/C 安全材料离线交付

基线：本地 `backup` 的 `0e797e4e0db1305cb4b4ea55456764b207e4d548`。
独立 checkout：`ClawManager-A-offline-security`；分支 `offline/a-security-materials`。
本项只增加独立检查器、模板、测试和两个无 I/O 的公开材料检查函数。
没有修改现有 A 的 manifest/index、容器、upload-only Job、first-forward、发布预算，
也没有修改 D 的 continuation/catalog/最终验收链。

## 已有实现与本次补充

以该基线源码为准，不能把较早文档的“尚无实现”当作当前结论：

| 需求 | 已有实际消费者 | 本次离线入口及限制 |
| --- | --- | --- |
| 原安装签名与三用途权限 | `systembackupsecurity/installation_signing.go`；`publication_factory.go` 已调用 `NewSQLInstallationArtifactSigners` | `InspectInstallationSigningMaterial` 复用原签名/pin/history 解码，额外检查三用途当前 key 窗口、撤销、独立 role/policy/provider key；不构造 signer，不检查当前 SQL owner/task 许可 |
| KEK 原始权威记录 | `systembackupkekadapter/authority_writer.go`、`original.go` | `InspectOriginalKEKMaterial` 复用 importer 与 active record 检查；独立 issuer、完整原文件 SHA、安装、reference、revision 均须匹配；不导入 SQL、不创建 PreparedMappingSource |
| SecretPolicy | `systembackup/secret_capture_policy.go`、`systembackupexecution/production_secret_policy.go` | 原 `DecodeSecretCapturePolicy` 与 `ValidateSelections`；不根据本次 UID 选择集制造策略，不宣称实际 Secret type/content/AEAD/EOF 已验证 |
| provider capability | `systembackupsecurity/capability.go`，v12 `a-capability-role-mapping.json` | 原证据校验，并要求各 role 的全部明确 code 均为 supported/none；测试锁定与 v12 code 集合一致。证据仍未认证为现场当前事实 |
| source owner grant | `worker/source_credentials.go` 的 `readGrant` | 原 Ed25519 domain 与 `FormalSourceGrant` 类型，精确 Expected/pin、用途、身份、有效窗口和最长 24h；不读取凭据、不重建实际 Invocation scope |
| 源权限 | `worker.ResourceSourceRules`、`domain.ValidateBusinessSourceGrants` | 复用纯校验器检查导出的有效规则/SQL grants；现场 CURRENT_USER、TLS、原会话、跨 namespace 权限仍待验证 |
| KEK 完整性/恢复权限 | `systembackupkekregistry` 四分区、`systembackupkekadmission`、SQL/S3 census | 独立 pin 的 expected snapshot 与 observed snapshot 逐项比较；不制造 PreparedCoverage，不以四行/数量相等作为扫描完整性 |

`cmd/system-backup-kek-authority` 名称及其旧注释虽包含 offline，但会连接数据库并写入。
它不是本项离线入口。本轮没有运行它，也没有运行任何 provider apply/revoke。

## 安全运行方式

仅在已确认的本机普通磁盘目录执行；不使用 UNC、映射网络盘、符号链接或 junction。
工具读取两个显式指定的 JSON 文件，不跟随其中的路径，也不读取 JWT、DSN、密码、
Secret 内容、私钥或环境凭据。不要将这些秘密放入 bundle。外层 JSON 拒绝重复/未知成员、
大小写别名、尾随值；每份最多 16 MiB，超限拒绝而不是截断。

使用已有 Go 1.26.1 与已有 module cache；不得为了本项自动联网安装依赖：

```powershell
# 在独立 checkout/backend，按本机已有位置设置 go 可执行文件与 module cache。
$env:GOTOOLCHAIN='local'
$env:GOPROXY='off'
$env:GOSUMDB='off'
$env:GOCACHE="$PWD/.cache/offline-build"
$env:GOTMPDIR="$PWD/.cache/offline-tmp"
New-Item -ItemType Directory -Force $env:GOCACHE,$env:GOTMPDIR | Out-Null
go build -mod=readonly -o .cache/offline-security.exe ./cmd/system-backup-offline-security
.cache/offline-security.exe --template trust
.cache/offline-security.exe --template bundle
.cache/offline-security.exe --trust <独立审核的本机trust.json> --bundle <本机公开材料bundle.json>
```

退出码：0 = 所有列出的本地材料检查完成；1 = 拒绝/输入无法读取；2 = 有真实输入未提供。
所有报告始终 `production_ready:false`；即使退出 0，`unverified` 仍列出必须现场完成的项目。
输出只含封闭 slot/status/reason 和固定未验证项，不回显文件路径、原始内容或错误。
`checked_offline` 只指本工具说明的局部检查；不是 readiness、admission、permit、验收或生产批准。
`MaterialKind` 只接受 `template`、`local_test_only`、`operator_supplied`；该标签是声明，不能认证来源。

生成器还支持 `secret-policy`、`signing-record`、`source-grant`、`original-kek-record`、
`coverage-inventory`、`source-rules`、`source-sql`、`capability-policy`。
`examples/offline-security/*.template.json` 是同一生成器输出的待填写 DTO：
安装、UID、key、版本、SHA、签名和时间均未伪填。零时间/null 是缺失，不能原样交给生产消费者。
`secret-policy` 模板为了便于填写是缩进 JSON；填完后须用现有 JCS 实现规范化，再取得独立 config pin。

## B/C 字段与路径合同

外层字段名按生成的模板大小写精确传递；内部现有 DTO 保持原 JSON tags。
所有 `[]byte` 字段在 JSON 中都是标准 base64，承载原始文件字节，不能 parse/serialize 后再签名。
公钥为原始 Ed25519 32 字节，signature 为原始 64 字节，不是 PEM、hex 或 Vault `vault:vN:` 文本。
外层本地 bundle 不能直接替换任意生产材料文件。

| 离线字段 | 输入来源/必须保持的内容 | 生产消费位置 |
| --- | --- | --- |
| `Trust.InstallationID/Namespace/WorkerNamespace` | 原安装 ID、源安装 namespace、独立 worker namespace；两 namespace 不要求相同 | 源 discovery、worker control 与原 task 身份；namespace/SA/Job/Pod/node UID 在现场采集并由 owner 认证 |
| `Trust.Signing` | `InstallationSigningPin{InstallationID,Revision,RecordSHA256,Issuer}`，来自独立部署信任输入，不从 bundle 自推 | 原 signing record reader / publication signer factory |
| `Bundle.Signing.Record/Signature` | 原 owner 签名的 `InstallationSigningRecord` 原字节/签名；三用途为 `capture_certificate`、`acceptance_record`、`catalog_record` | `FileSigningRecordReader.RecordFile/SignatureFile` 均为绝对本机挂载路径；domain `system-backup-original-signing.v1` 后接 NUL |
| signing `Permissions[].Binding` | InstallationID/Purpose/KeyID/KeyVersion/Endpoint/KeyName/ProviderVersion；opaque KeyVersion 和 provider 数字版本不可互推 | `SigningJWTMount.Binding` 必须精确一致，AuthMount/Role/Policy/CASHA256 也必须与签名记录一致；CAPEM 是公开 CA 字节，JWTFile 为单用途绝对投影路径 |
| `Trust.KEK` + `Bundle.KEK` | 原 issuer、完整原记录 SHA、Revision、Reference{IdentityHash,Version}；原 `OriginalRecord` 字节/签名 | `InstallationAuthorityWriter`/`InstallationPreparation`；domain `system-backup-original-kek.v1` 后接 NUL；现场仍需 D 同 fence 的 import/admit/commit/readback |
| `Trust.SecretPolicy` + `Bundle.SecretPolicy.Policy` | 原 097 config 的 `secret_allowlist` version/sha；完整规范 JCS 文件字节 | `Discovery.SecretPolicy={protocol,path,sha256}`；protocol=`system-backup-secret-capture-policy.v1`，path 为干净绝对路径；与原 config 的 version/SHA 和真实 SQL 列双重核对 |
| `Bundle.SecretPolicy.Selections` | 冻结的 group/version/resource/name/uid，每个 required 必须出现，每个选择必须在策略中 | 原 SourceSnapshot/capture context/Invocation；实际 GET 后及完整 archive reader 仍检查 namespace/name/UID/type |
| `Trust.Capabilities[role]` | 原配置 role/IdentityHash/RefVersion/ScopeHash、MaxValidity（Go Duration 纳秒）、ValidUntil；`Now` 被本次实际时钟覆盖 | role 为 artifact/catalog/evidence/kms/secret/signing；`Bundle.Capabilities` 使用现有 v1 evidence DTO，不包含真实凭据 |
| `Trust.SourceGrants[operation]` | 独立原 source-owner Issuer、RecordSHA256、Expected 的全部 `FormalSourceGrant` 字段 | `Bundle.SourceGrants` 的 Record/Signature 原字节；domain `system-backup-original-capture-source.v1` 后接 NUL；生产 `FormalSourceMount.GrantSHA256` pin **外层 SignedFormalSourceGrant 文件**，不同于这里 RecordSHA256 |
| source operations | capture-database / capture-source-redis / capture-skill-objects / capture-team-redis / capture-team-objects | 每用途原 source owner 认证；本检查器将未提供项列为未验证，不自行推断“不适用” |
| `Bundle.SourceRules` | Selections 与 `SubjectRulesReviewStatus` 的完整实际导出；不接受 incomplete、源写/list/watch/* | `ResourceSourceRules` 是 worker 精确对象 GET 合同；controller discovery 与其他 namespace 的有效权限要由各 owner 单独审核 |
| `Trust.SourceDatabase` / `Bundle.SourceSQL` | 独立 ServerUUID/Database；导出的 Database、CurrentRole、完整 Grants | 当前有限业务表模式 `ValidateBusinessSourceGrants`；导出文件不能替代真实同会话 CURRENT_USER/ROLE、数据库 UUID、schema census 及 TLS 核验 |
| `Trust.CoverageInventorySHA256` | 独立原源 inventory 文件的完整 SHA | 不能只由候选方给出 expected 与 hash 来“认证”自身；本工具始终将 pin provenance 标为现场未验证 |
| `Bundle.Coverage.Expected/Observed` | Expected 为 `reg.Snapshot` 原字节；Observed 为 D 快照 DTO | 逐项比较 database/installation/epoch、四分区 source/adoption/revisions、每份 binding 与每份 reference 的完整 provenance/KeyBinding/hash/state |

从已有公开材料打包字节的 PowerShell 片段（只用于已审核的公开文件）：

```powershell
$recordBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes('<原owner记录本机路径>'))
$signatureBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes('<原owner签名本机路径>'))
# 把这两个字符串分别放到 Bundle.Signing.Record / Signature。
# SHA/pin 必须由独立审核渠道提供；此步骤不生成原安装签名或信任。
```

## provider ACL/role 离线编译

`scripts/system-backup-offline-provider-materials.py` 只调用已有
`reviewed_plan` / `policies` / `workload_roles` 纯函数，没有 apply/revoke/token 参数。
使用现有 Python 3.12；它不会创建 Provider。公开生成结果仍是待独立审核数据。

```powershell
python -B scripts/system-backup-offline-provider-materials.py --kind signing --plan <本机已审plan> --plan-sha256 <独立SHA> --endpoint <已审精确HTTPS端点>
python -B scripts/system-backup-offline-provider-materials.py --kind kek --plan <本机C原plan> --plan-sha256 <独立SHA> --workload <本机原Job身份JSON> --workload-sha256 <独立身份SHA>
```

signing plan 遵循现有 `system-backup-a-signing-acl.v1`：status 必须
`review_only_not_authorized`，三个 binding/三个 workload，各自独立 key、role、policy、JWT audience。
不能为未观察到的 Pod/SA UID 填随机值。KEK plan 由已有 `backupTransitPlan(mapping, request)`
生成（`scripts/system-backup-a-backup-transit-plan.mjs`），其 key/context 必须来自真实原 `Access`。
workload 使用已有 `namespace/service_account/service_account_uid/pod_uid/job_uid/invocation_sha256/execution_grant_sha256/operation`。
operation 仅 `backup_dek_generate` 或 `backup_dek_unwrap`；两份 policy 独立，单次输出 role 只绑定一种用途。
离线编译不验证在线 key profile、公钥读回、JWT mount trust、ACL 参数语义或实际授权。

## 权限与恢复映射

| 对象/阶段 | 所需权限与材料 | 必须保留的拒绝/证据 |
| --- | --- | --- |
| 源 MySQL | 原签名 source grant；独立凭据 Secret；每份已审业务表 SELECT；准确 census routine EXECUTE 与 SHOW_ROUTINE；CURRENT_ROLE=NONE | 禁止 SELECT database.*、控制表、DML/DDL/角色/GRANT OPTION；现场同会话核验 UUID、用户、全部 grants、routine body 和有限表 census |
| 源 Redis / Teams Redis | 原 source grant；独立只读账号；精确 DB、server ID、prefix/exclusion 与 TLS scope | 必须现场读回有效 ACL 并证明写/跨 prefix/其他 DB 拒绝；本工具没有把未提供 ACL 标为通过 |
| Skill/Teams 对象源 | 原 source grant；独立只读源凭据；精确 bucket/prefix/key/version，允许需要的版本列表/HEAD/GET | 源凭据不能上传/删除；catalog/artifact/目标上传账号不可复用；现场 EOF/分页/版本与 checksum 证据 |
| 源 Kubernetes | deployment_resources 与 secret_bundle 各自身份；SourceAPI CA/token 与其 SA UID 独立于 control/KMS JWT | worker 具名对象 GET + 合同允许的 self-review/discovery；controller 的必要 list/metadata discovery 是另一份授权，不放宽 worker 规则；跨 namespace 权限另核 |
| 材料挂载 | `FormalInputMount` 的 Volume 必须 `formal-` 前缀，Directory 为 `/run/backup/materials/<单层名>`；Secret/ConfigMap item path 为单文件名 | `attachFormalMaterials` 固定 0400、ReadOnly；`FormalJobMaterials.ConfigMap` 挂到 `/run/backup/formal/materials.json`；D 必须真实观察每份 UID/hash、PVC→PV、SA UID、node UID，不准模板伪填 |
| capture KEK | 原 B Access + D current permit + generate 专属 JWT/ACL；精确 C context、binding hash、provider 数字版本 | 只能原 Job 内 Generate；不能向 controller/其他 Pod 传明文 DEK；停止/撤销须原 worker 证明 |
| 独立恢复/验证 KEK | 保留每个历史 KeyBinding、精确版本、原 context/ciphertext；独立恢复身份及 unwrap 专属当前 permit/JWT/ACL | Generate 权限不替代 Unwrap；generate 撤销不意味着可删除历史 key；非 released 引用遇到 unwrap 撤销本报告拒绝，后续人工恢复流程由 owner 决定 |
| 还原目标/只读验证 | 隔离目标写入/创建能力与独立 read-only verifier 身份分开，恢复引用加入同一 fence | 由新增 D 完成 Runtime/挂载/非空业务恢复预检；本项不宣称目标可写、数据已还原或业务可用 |

coverage 分区固定为 retained_artifacts、inflight_and_unknown_writes、holds_and_catalog、restore_and_prune。
每个 expected 引用产生 `coverage_reference:<partition>:<expected数组下标>` 检查，包含 released/unknown，
不按 TTL、状态或数量删除未决引用。相同数量但不同成员、遗漏、多余、重复、错完整 key/hash、
错生命周期来源、错 epoch/数据库或 source revision 均拒绝。null 不是空扫描；空数组即使局部比对一致，
也不证明已完成原源 EOF、旧数据 adoption/backfill、全部 writer 纳入同一 fence 或事务内 Recheck。
该工具不验证每份历史 binding 的全部准入语义，仍须原 KEK admission；它负责完整引用成员与恢复映射比对。

## 恢复远侧连接后的执行顺序（本轮未执行）

1. 原安装 owner 提供独立安装/DB identity、签名公钥 pin、最新原签名记录/签名/revision/SHA、
   当前撤销位置；原 config owner 提供 097 config pins、SecretPolicy 与 registry 的真实批准来源。
   记录采集时间、源版本与证据摘要；不要将新随机安装/节点 UID 当原安装身份。
2. B 冻结真实 task/attempt/fence、SourceSnapshot、Invocation/Access；D 核验原 Job/Pod/SA/node UID、
   Secret/ConfigMap/PVC/PV 的 UID/hash、只读挂载和控制身份。原 source owner 独立签发有限期 grant。
3. 运行本离线入口比较现有公开材料；缺失保持 unverified。由独立审核者核验 trust 文件来源，
   当前时间/撤销及原业务授权，重新核验有效规则、凭据文件保护和跨 namespace 权限。
4. 原 provider operator 按已审 plan/SHA 使用已有 apply 工具，在准确 CA/JWT mount pin 下安装并读回
   三用途 signing 与两用途 KEK policy/role；获取真实 capability、版本与撤销回执。不得直接把本工具输出作为批准。
5. C/B/D 原 owner 完成四分区 SQL/S3/catalog/hold/restore/prune 的全部分页 EOF、adoption/backfill 与 writer fence；
   D 原事务锁定并 recheck 后正式 admission/commit/readback，保留每个引用对应的 key/context/source。
6. 在隔离范围由原 worker 执行实际 generate/sign/独立 unwrap；分别执行错安装/用途/版本/context、过期、
   撤销拒绝，保留当前 provider 回执、原 task/claim、停止和单用途撤销读回。禁止把 synthetic fixture 充作现场证据。
7. 新增 D 用真实非空业务数据做独立恢复/Runtime/挂载验收；现有 A/D 完成发布主链、清理及终态。
   全部原证据由对应 owner 复核后才能讨论 readiness；本离线报告不升级状态。

本次没有提供真实安装签名、生产批准、节点 UID、现场 capability、原 source 凭据、
完整 KEK coverage 或实际恢复结果。这些都列入 unverified，不能因本地测试成功而省略。
