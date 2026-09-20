# System backup machine contracts v12

This directory is the machine-readable P0-0a workspace for
`system-backup-plan.v12`. It is intentionally marked `draft`; the presence of
these files does not mean the contract is frozen.

As of 2026-09-17, `contract-manifest.json` contains 29 draft artifacts and 7
missing artifacts. The generated registry records D policy for 41 of 95
inventoried objects; 54 A/B/C policies and all 41 D-object cross reviews remain
pending. These are inventory counts, not completed acceptance gates.

## Current contents

- `contract-manifest.json` accounts for every artifact required by plan section
  3 and records missing artifacts explicitly.
- `registry-enums.json` defines the closed values used by the schema registry.
- `schema-registry-decisions.json` contains owner decisions. D-owned entries are
  recorded here; A/B/C entries must be supplied and reviewed by their owners.
- `schema-registry.json` is generated from the ownership inventory, decisions
  and embedded migration catalog. Do not edit it directly. Its current 95-object
  coverage is not the full plan: section 6.2 names three additional control or
  resource tables still absent from the inventory; the strict gate lists them.
- `schema-registry.schema.json` describes the generated registry wire shape.
- `hash-algorithms.json` fixes the migration catalog hash framing and records the
  pending live-schema hash algorithm.
- `status-failure-enums.schema.json`, `task-operation.schema.json` and
  `admin.openapi.json` are the first draft of the public status, DTO and Admin
  route contracts. Resource-specific request/response schemas are not frozen.
- `runner-data-interfaces.schema.json` fixes the module names and authority
  boundaries; `source-writer-check-state.schema.json` records the v12
  fail-closed writer-inventory state.
- `dto-parity.json` points at the Go and TypeScript wire snapshots. The artifact
  test prevents their enum values and JSON field names from drifting.
- `redacted-examples.json` contains synthetic, non-replayable examples only.
- `cross-owner-review-requests.json` is the machine-readable A/B/C handoff. It
  lists pending submissions and reviews, but deliberately contains no approval
  evidence until reviewers provide it.
- The publication draft is split across
  `manifest-system-backup-v1.schema.json`, `artifact-index.schema.json`,
  `committed-marker.schema.json`, `acceptance-marker.schema.json`,
  `provider-finalizer-request.schema.json` and
  `external-action-payload.schema.json`. `artifact-common.schema.json` holds
  shared hashes, timestamps and signing-envelope definitions, while
  `publication-redacted-examples.json` proves exact-byte and checksum binding
  with synthetic values.
- D-owned control-plane drafts now include `installation-state.schema.json`,
  `compact-tombstone.schema.json`, `staging-resource-lifecycle.schema.json`,
  `verifier-contract.schema.json` and
  `metrics-alert-registry.schema.json`. The verifier shell deliberately leaves
  A/B/C check registries pending. `metrics-alert-registry.json` now materializes
  every section-15 metric and D-owned default alert; production evaluator
  parsing/execution and A/B cross-review remain explicit freeze blockers.

## Commands

From the repository root:

```bash
node scripts/system-backup-schema-inventory.mjs --check
node scripts/system-backup-contract-check.mjs --check
node scripts/system-backup-metrics-registry.mjs --check
node --test scripts/system-backup-contract-check.test.mjs scripts/system-backup-contract-artifacts.test.mjs scripts/system-backup-schema-hash.test.mjs
```

`schema_hash` 的 D-owned canonicalizer 接受
`schema-hash-observation.schema.json` 的只读结构化观测：

```text
node scripts/system-backup-schema-hash.mjs --input <observation.json>
```

该命令只输出 deterministic hash result，不把它冒充 live evidence，也不把 synthetic fixture 或缺少完整字段、索引、外键、
non-table definition 的对象名清单当作 live evidence。数据库/schema 名、采集时间、凭据和业务行
均不进入 hash。

MySQL 8.0/8.4 测试安装使用只读账号运行
`schema-hash-capture.mysql.sql`，以 batch/raw/no-column-names 模式把两列结果保存为临时 TSV，
然后执行：

```text
node scripts/system-backup-schema-hash.mjs --records <capture.tsv>
```

已有测试安装可从带 `kubectl` 和 Node.js 的 Linux 部署机器直接生成清理过原始 TSV 的候选证据。
从**包含当前脚本改动的仓库根目录**执行以下完整命令；它只运行仓库固定的
`information_schema` 查询，使用 MySQL Pod 已注入的应用数据库账号，不读取业务行，
不把密码传给本机 `kubectl` 参数，也不保存原始记录到部署机器的工作目录：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
KUBE_CONTEXT='kubernetes-admin@kubernetes'
NAMESPACE='clawmanager-zhanghui08-system'
DATABASE='clawmanager'
test -f scripts/system-backup-schema-hash-capture.mjs
kubectl --context="$KUBE_CONTEXT" --namespace="$NAMESPACE" rollout status deployment/mysql --timeout=60s
NAMESPACE_UID="$(kubectl --context="$KUBE_CONTEXT" get namespace "$NAMESPACE" -o jsonpath='{.metadata.uid}')"
test -n "$NAMESPACE_UID"
INSTALLATION_IDENTITY_HASH="$(node -e 'const {createHash}=require("node:crypto");process.stdout.write(createHash("sha256").update("k8s-namespace-uid-v1\0"+process.argv[1]).digest("hex"))' "$NAMESPACE_UID")"
node scripts/system-backup-schema-hash-capture.mjs \
  --kubectl-context "$KUBE_CONTEXT" \
  --namespace "$NAMESPACE" \
  --database "$DATABASE" \
  --installation-identity-hash "$INSTALLATION_IDENTITY_HASH" \
  --installation-identity-version 'k8s-namespace-uid-v1'
```

上面的身份哈希只绑定该测试 namespace 的 UID；正式登记前还须核对平台 installation ID 的
绑定方式。stdout 是 `status=candidate` 的脱敏 JSON，可回传作对象差异核查；若
`inventory_comparison.matched=false`，不得把它标成 reviewed。命令失败时脚本只报告退出码，
不会输出 MySQL stderr 中可能包含的连接信息。原始 TSV 由脚本在私有临时目录创建并在
成功或失败时删除；`records_cleanup.verified_absent=true` 是脚本核验结果。

现场取证使用单独的redacted context JSON，只允许
`installation_identity_hash|installation_identity_version|capture_started_at|capture_finished_at`四个字段；不得写数据库名、
连接串或credential。生成candidate：

```text
node scripts/system-backup-schema-hash-evidence.mjs --records <capture.tsv> --context <context.json>
```

删除临时TSV后，用原路径和删除时间验证缺失状态：

```text
node scripts/system-backup-schema-hash-evidence.mjs --verify-cleanup <candidate.json> --records <deleted-capture.tsv> --deleted-at <RFC3339>
```

该步骤只把`records_cleanup`改为verified，仍不会把candidate提升为reviewed。只有对象全集与inventory精确一致、
`capture SQL`/inventory/migration catalog hash均匹配当前仓库、evidence已登记，并由A/B/C分别提交批准后，
`system-backup-contract-check.mjs --schema-hash-evidence <reviewed-evidence.json>`才接受该输入。即使输入有效，
manifest的`schema_hash_evidence_present`未显式置true时strict gate仍保持失败，D不能自行替其他owner批准。

采集 SQL 只查询当前 database 的 `information_schema` 及 server metadata。若 definition 因权限
不可见、record 缺失/重复、字段不闭合或 ordinal 不连续，canonicalizer 会 fail closed；临时 TSV
按测试证据清理规则处理，不提交包含环境细节的现场采集文件。

`schema-hash-result.schema.json` 只描述确定性计算结果。P0-0a 的 live evidence 还必须在验收记录中
另行绑定安装身份、采集时间、只读命令、result、执行结果和临时文件清理证明；在此之前
`schema_hash_evidence_present` 必须保持 `false`。

`admin-api-common.schema.json` 是 D 管理编排 API 的公共 wire 草案。OpenAPI 当前已锁定所有
mutation 的 `Idempotency-Key`、资源类型 path ID、cursor/limit、list consistency、错误 envelope
和同步/异步成功状态。`admin-operation-policy.json` 与其 schema 进一步逐项锁定65个 operation 的
middleware、内置角色、权限、strong-auth 条件、kill-switch 行为、幂等和成功状态；proof/nonce
字段仍由 A 提交，D 只记录何时必须校验。所有 operation 已挂 closed default error，并为201/202
声明 `Location`。`admin-operation-errors.json` 用20个closed profile为65个operation逐项分配允许的
API error子集，特殊约束包括strong-auth错误不外溢、`commit_started`仅属于备份取消、
`logs_expired`仅属于日志路由、`range_not_satisfiable`仅属于evidence range读取；A/B/C仍各自负责
判定其domain failure何时发生。`Resource`仍是显式placeholder，资源级closed body、owner payload
refs和交叉评审仍未补齐，不能移除freeze blocker。

`admin-mutation-requests.schema.json` 已为16个不需要复制 owner 内部载荷的 D 编排接口提供11种
closed business body，并接入 OpenAPI、Go/TypeScript snapshot 和 synthetic redacted fixtures。
`request_id|idempotency_key|strong_auth_proof` 是 request-hash 排除的传输/认证字段；前两者由公共
header/middleware处理，后者等待 A 的 proof/nonce 合同。Finalization/ownership只接受已登记
public ID和expected row version，明确拒绝URI、credential、force和客户端自报结论。

`admin-control-resources.schema.json` 已关闭 D-owned overview、config、prune-run、prune-confirmation
资源及config/prune typed list，并把既有manifest schema直接绑定到下载响应。Config update现在有closed
business body；P0时间、容量、并发和preflight限制的min/default/max进入机器schema，registry和外部
provider/security配置仅以固定purpose、redacted identity hash和immutable version出现。Go/TypeScript
snapshot和synthetic fixture锁定全部字段、20个reference purpose、9个registry kind及关键跨字段安全关系。
Prune planning阶段candidate摘要允许为null，离开planning后必须完整，避免异步202响应伪造尚未计算的
candidate。剩余直接`Resource` placeholder只有A的evidence、C的三类catalog和B的preflight diff；D没有
代填这些owner payload。

`admin-activity-resources.schema.json` 已关闭Task/Operation分页、公共event/log、prune item和promotion
控制视图。19个核心event type及`diagnostic.<owner>.<name>`扩展格式、64 KiB details、8 KiB日志行、
prune item状态/失败码/identity条件和promotion七组read-time health均由测试锁定；event不得成为第二套
状态权威，日志只返回已持久化脱敏行，provider location只返回canonical hash。原21个generic list目前只剩
C的catalog三类列表与B的staging/restore-resource两类列表；连同上述5个直接placeholder都明确等待owner
schema和评审，OpenAPI继续保持draft。

`admin-task-detail-resources.schema.json` 已关闭backup、drill、preflight和artifact-verification四类
详情响应，并接入OpenAPI及Go/TypeScript DTO parity。详情只投影D编排权威字段、执行进度、聚合校验结果、
checksum、typed public ID和immutable config hash；A的check/audit/redaction正文、B的restore target内容、
C的artifact/catalog locator与credential均不进入响应。`admin-task-detail-redacted-examples.json` 用synthetic
片段装配四种完整响应，测试锁定task type、eligibility、manual hold、registration成对关系、cleanup和
artifact lifecycle条件。剩余五个直接`Resource`和五个generic list仍全部属于A/B/C，D不代填。

`metrics-alert-registry.json` 由`scripts/system-backup-metrics-registry.mjs`从主计划第15节具名指标清单
确定性生成，当前完整登记210个指标和99个profile-specific告警实例。每个指标都有type、HELP、精确低基数
label、aggregation、no-data和histogram buckets；每条告警都有expression language、threshold source、
severity、for、dedupe、recovery、missing-series、counter-reset、runbook、profile及固定时钟状态机用例。
CI用`--check`阻止主计划与registry漂移。A/B/C collector只提交观测，不拥有新增label/name/alert semantics的
权限；在选定的生产PromQL/controller-state evaluator中完成解析执行并取得A/B评审前，registry仍为draft。

`prometheus-alert-rules.yaml`是由registry确定性生成的95条PromQL规则**候选**，
`node scripts/system-backup-prometheus-rules.mjs --check`检查来源hash和逐条内容；4条`controller_state`
规则不在其中。仓库尚无Prometheus规则加载器、missing-series策略执行或PromQL fixture验证，
因此文件带有`DO NOT LOAD`标记，不可把它当作已部署告警。生产接线前还须选定并验证执行器、
补齐no-data/counter-reset语义，并以真实采集样本验证恢复与去重。

`dependency-provider-capability.schema.json` 关闭D控制面保存的dependency-health与provider-capability
记录及read-time投影。Dependency owner使用backup/catalog-import/promotion/system类型化引用，`stale`只按数据库
时间与`expires_at`派生；provider capability严格绑定role、identity hash、ref version和P0 capability code，
缺行/过期固定为unknown。Artifact、catalog、evidence三组capability闭集及absence/full-discovery any-of规则
由测试锁定。C仍负责真实adapter/probe，A/B/C只提交已登记evidence或bounded observation，D未伪造supported。

`control-evidence-sidecar.schema.json` 关闭`control/evidence.json.enc`解密后JSON的D-owned外层结构，并在
manifest的sidecar引用中显式绑定schema version。Sidecar只包含控制对象排除证明、redaction证明、九类历史
记录的count/time/rolling hash、registered evidence refs和A/B/C/D owner completion摘要；不包含原始控制行、
审计正文、owner check payload、provider locator或self-checksum。P0 restore只读验证且不把历史控制行导入目标
control database。Synthetic示例将A/B/C明确保持incomplete/evidence_missing，不能被误当作owner批准。

`evidence-chunk-log.schema.json` 关闭D控制面的evidence、1 MiB plaintext chunk索引与redacted job-log索引持久化
外壳。Evidence只保存typed owner、内容/对象/checksum、server-derived relative key、immutable version、加密envelope
引用、claim和生命周期；inline与external状态、失败码、删除转换、连续chunk offset及ready log引用由机器测试锁定。
Admin调用方仍只能提交evidence public ID，不得提交provider endpoint、credential或storage key。A继续负责脱敏分类和
envelope framing/AAD，B继续负责JobObserver与序列产生，C继续负责provider写入和immutable-version证明；synthetic
fixture不代表三方实现或批准。合同当前总数与冻结状态以本文件顶部及`contract-manifest.json`为准。

After an approved decision changes, regenerate and verify the derived registry:

```bash
node scripts/system-backup-contract-check.mjs --write --check
```

The strict command is expected to fail until every required artifact is frozen,
all owner policies and cross reviews are recorded, and live `schema_hash`
evidence exists:

```bash
node scripts/system-backup-contract-check.mjs --check --strict
```

Never change a missing or draft gate to frozen merely to make strict mode pass.
Capability evidence, review identity and observed hashes must be supplied by the
corresponding owner or test environment.
