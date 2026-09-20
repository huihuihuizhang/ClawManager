# D / P0-0a 仓库静态盘点记录

> 2026-09-14；对应尚未冻结的主计划 `system-backup-plan.v12`。这是开工时仓库事实及后续进展记录，不是机器合同或 schema object registry。八表归属已补入主计划；分类、策略、verifier 等正式决议仍须进入同版本合同并通过交叉评审。

## 范围和复核方法

盘点了主计划第 5.1 节的业务对象表、`backend/internal/db/migrations/*.sql`、`backend/internal/repository/*.go` 中的建表入口、四套官方 k8s/k3s YAML、站点模板、现有 Admin 路由与数据源配置。静态命令：

```powershell
rg -n -i 'CREATE\s+(TABLE|VIEW|TRIGGER|PROCEDURE|FUNCTION|EVENT)' backend/internal/db/migrations --glob '*.sql'
rg -n 'ensureTable|ensureTables|CREATE TABLE' backend/internal/repository --glob '*.go'
rg -n 'clawmanager-app-cluster-admin|clawmanager-runtime-manager' deployments/k8s/cluster/clawmanager.yaml deployments/k8s/single-node/clawmanager.yaml deployments/k3s/cluster/clawmanager.yaml deployments/k3s/single-node/clawmanager.yaml
rg -n 'system-backup|system_backup|SystemBackup|BackupController' backend/internal backend/cmd frontend/src --glob '*.go' --glob '*.tsx' --glob '*.ts'
kubectl config current-context
```

统计方法：从主计划第 5.1 节表格提取反引号对象名，与 migration 的 `CREATE TABLE/VIEW/TRIGGER/PROCEDURE/FUNCTION/EVENT` 名称集合比较；再独立扫描 repository 中的 `CREATE TABLE`。当前 migration 扫描只找到 table 创建语句；未来引入非 table 对象时须扩展 registry 与验证。该扫描不是 SQL parser，也不能代替运行中数据库的 `information_schema` 核验。

## 开工时确认的静态结果（补录八表前）

| 检查项 | 结果 | 后续动作 |
| --- | --- | --- |
| 主计划第 5.1 节业务表 | 开工时 55 个：A 12、B 20、C 16、D 7；`system_backup` 控制表尚未在该表逐名列出 | 已补录八表；P0-0a 仍须冻结控制表 registry，并由各 owner 核对业务对象 |
| D 的 `resources` 七表 | `system_image_settings`、`egress_private_exceptions`、`audit_logs` 已见 embedded migration；四个 security-scan 表只见 repository 建表 | 本轮已新增 migration 并移除该构造时 DDL，见下节 |
| A 的未迁移业务表 | `chat_sessions`、`chat_messages`、`risk_rules` 只见 repository 建表 | A 负责 migration/移除运行时 DDL；D 验证全局 coverage |
| migration 中未列入开工时主计划第 5.1 节的表 | `northbound_admin_settings`、`northbound_auth_challenges`、`northbound_caller_policies`、`northbound_operations`、`northbound_sessions`、`northbound_settings_audit`、`runtime_upgrade_items`、`runtime_upgrade_audits` | 唯一 owner/category 已补入主计划；分类、策略、verifier 和评审仍待 P0-0a 完成 |
| repository 建表入口 | 开工时为 14 个表名；包含上列 7 个未迁移表，也包含已迁移表的重复 ensure 路径 | P0-0b 逐 owner 移除剩余运行时 DDL，并用静态门禁防回归 |
| `schema_migrations` | 由 migration runner 创建 bookkeeping 表，不在 embedded SQL 内 | 按主计划第 5 节以 metadata/reference-only 处理并纳入 registry |
| 系统备份控制面 | 仍无独立 `system-backup-controller`；已新增明确标记为 `draft` 的 `contracts/system-backup/v12` 合同骨架，现有 `backups`/`backup_schedules` 仍属实例备份 | 不复用实例级模型；补齐 manifest 中的 missing/draft 项并通过评审后才能冻结，controller 留在后续阶段 |
| 官方权限模板 | `deployments/{k8s,k3s}/{cluster,single-node}/clawmanager.yaml` 四处均有 app `cluster-admin` binding；九节点站点模板亦有同类 binding | P0-0b 在保留现有 runtime/sync 能力的前提下改为最小权限并做正负测 |
| 当前路由位置 | Admin API 在 `backend/cmd/server/main.go`；Console 路由/导航在 `frontend/src/router/index.tsx`、`frontend/src/components/AdminLayout.tsx` | P0a/P0b 仅按冻结 OpenAPI/DTO 接入 |
| 当前环境真实能力证据 | `kubectl config current-context` 返回 `current-context is not set` | 无法在此环境验证 CSI、对象存储、Redis、KMS 或 provider 权限；不宣称 capability spike 通过 |

## 本轮代码改动后的静态复核

- 【D-only 新增第五张】`077_add_system_restore_drill_resources.sql`把drill资源intent、owner HMAC、lifecycle/cleanup失败码、evidence关联和幂等位置约束纳入D控制面；B的资源类型、provider identity规则和创建/删除实现保持待交接。`restore_target`仍在manifest标missing，未作真实MySQL与cleanup负测。
- 【D-only 新增第四张】`076_add_system_backup_job_observations.sql`为当前Job identity/generation、relay anti-replay游标、progress年龄和controller单次command slot提供D持久化权威；与attempt的FK、唯一unit/UID及组合CHECK已登记。B的status-relay合同和消息处理继续missing；本机未作真实MySQL或Job重建并发验证。
- 【D-only 新增第三张】`075_add_system_backup_strong_auth_nonces.sql`把消费后的nonce HMAC/key version、请求绑定、audit/operation或response关联和retention纳入D控制面migration；A-owned proof/nonce wire及跨历史key验证仍保持manifest missing。该表不是strong-auth端到端实现，也未经过live MySQL验证。
- 【D-only 新增第二张】`074_add_system_maintenance_participants.sql`把participant的scope/generation、pause ACK、checkpoint/offset、heartbeat和resume/forced/failed事实纳入D控制面migration；对应closed合同和A/B/C待评审请求已登记。实际writer pause/resume/watchdog仍属对应owner；本机无live MySQL验证，不能将静态DDL测试视为运行验收。
- 【新增门禁缺口】主计划第6.2节逐名要求32张控制/资源表；当前5.1归属盘点与embedded migration的并集只覆盖其中29张，另3张未进入inventory：`system_backup_catalog_imports`、`system_backup_catalog_records`、`system_backup_catalog_scan_states`。`system-backup-schema-inventory.mjs`现显式报告并在strict模式阻断，合同strict blockers也保留该清单。此处仅发现缺口，不擅自分配A/B/C业务owner、补造payload或宣布P0-0a覆盖完成。
- 【D-only 已补一张】`073_add_system_backup_staging_resources.sql`把`system_backup_staging_resources`纳入D控制面migration和`metadata_only/reference_only` registry，新增`staging-resource-lifecycle.schema.json`及A/B/C待评审请求。DDL持久化intent、位置/owner marker哈希、生命周期和cleanup组合、防重复位置、CAS版本与证据FK；实际资源创建/清理及provider证明仍由对应owner实现，本机无MySQL CLI且Docker daemon不可用，未声称live DDL通过。
- 【已完成】主计划第 5.1 节补录八表归属：A/`users` 为 `northbound_auth_challenges`、`northbound_sessions`、`northbound_caller_policies`；B/`instances` 为 `northbound_operations`、`runtime_upgrade_items`、`runtime_upgrade_audits`；D/`resources` 为 `northbound_admin_settings`、`northbound_settings_audit`。当前具名业务表为 63 个：A 15、B 23、C 16、D 9；C 不因升级表的 `team_id` 关联取得 owner。归属是主计划设计决议，尚未获得 A/B/C 交叉评审，不代表 registry 或 schema coverage 门禁通过。
- 【已完成】`backend/internal/db/migrations/063_add_security_scan_tables.sql` 追加四张 security-scan 表；`backend/internal/repository/security_scan_repository.go` 已移除构造时 DDL。逐条规范化空白后，四个 migration 建表语句与原 repository SQL 完全一致，且外键依赖按原顺序创建。
- 重新扫描后，当前主计划94个具名业务表中只剩A的`chat_sessions`、`chat_messages`、`risk_rules`未见embedded migration；D已显式登记的具名业务表现在都已见migration。`064_reconcile_system_image_settings_schema.sql`已接管D最后一条repository runtime CREATE/ALTER路径；当前剩余9个runtime CREATE和3个runtime ALTER均来自A-owned repository，全局“无运行时DDL”仍须由A收敛。
- 新增 P0-0a 机器合同草案门禁：`contracts/system-backup/v12/contract-manifest.json` 对主计划第 3 节必需产物逐项标记 `missing|draft|frozen`；`schema-registry-decisions.json` 记录 D 的九张资源业务表、`schema_migrations`及三十一张系统备份控制表共 41 个 owner 决议，生成的 `schema-registry.json` 覆盖全部 95 个对象并将其他 owner 的 54 个决议、D 的 41 项交叉评审和 live `schema_hash` 保持为 blocker。当前`migration_catalog_hash`已对91个embedded SQL（含`078`）的filename和LF规范化content bytes使用固定length-prefix framing计算为`b3fe27c26b2917b2b17a8c20b0af24b5c375188a5478fbe43c4fd15cd1375991`，避免Windows `core.autocrlf`与Linux CI checkout产生伪漂移。`scripts/system-backup-contract-check.mjs --check`与无依赖Node测试（含LF/CRLF等价）通过并接入CI；`--strict`在上述缺口存在时必须失败。
- 机器合同草案第一批已覆盖主计划第 14.1 节全部 65 个 Admin method/path、公共 task/operation 状态与 failure enum、closed DTO、五个 runner/data interface 边界、source-writer-check state、Go/TypeScript wire snapshot、synthetic redacted examples 和 A/B/C 机器可读交接清单。新增六项无依赖检查逐项锁定路由、operation ID、schema 引用、字段/枚举 parity、fixture 脱敏、接口边界及 owner/reviewer 覆盖；交接清单不预填任何批准证据。这些文件仍标 `draft`，OpenAPI 中资源级 body 仍是显式 placeholder。Manifest 当前为 11 项 draft、21 项 missing，不能宣称完整合同或 DTO parity 门禁通过。
- 机器合同草案第二批已补 `system-backup.v1` manifest、artifact index、`_COMMITTED`、签名 `_ACCEPTANCE`、provider-native finalizer request 和 external-action payload。三项新增无依赖检查证明 manifest 不含自身checksum/staging cleanup/最终eligibility、index不索引自身/final对象、落盘action与出站request绑定相同canonical bytes/checksum/content-length/key，credential envelope不进入action持久化，acceptance签名输入只含payload且本地reason不混入技术失败码。Manifest 当前为17项draft、15项missing；签名算法和config recovery闭集仍为显式freeze blocker，A/C没有任何预填批准。
- D-only 草案第三批已补 installation-state、compact tombstone、verifier 公共 envelope 与 metrics/alert registry；first-enable/matrix authority、destructive/standard tombstone retention、verifier聚合/owner边界和高基数label禁止由无依赖检查覆盖。第15节210个具名指标和99个profile-specific默认告警现已逐项物化，包含type/HELP/label/bucket、aggregation/no-data、表达式域、阈值/恢复/missing-series/counter-reset/runbook及固定时钟状态机用例，并由生成器与CI防漂移。A/B/C verifier registry保持`pending_owner_submission`；生产evaluator解析执行和A/B评审仍阻断freeze。
- D-only Admin error profile 草案已用20个closed profile覆盖全部65个operation且无重复；profile code只能取公共39项API code→HTTP status映射。新增测试把strong-auth、`commit_started`、`logs_expired`和`range_not_satisfiable`限制在对应operation集合，并保持A/B/C的domain failure判定和membership评审为显式外部责任。OpenAPI的逐operation精确error子集已不再是D侧缺口，但资源payload placeholder及非D批准仍阻断freeze。
- D-only Admin control resource 第一批已关闭overview/config/prune-run/prune-confirmation、config/prune typed list和config PUT body，并把现有manifest合同绑定到API。机器schema记录P0 config min/default/max、20个redacted external reference purpose、9个registry kind、关键跨字段关系和完整prune状态；Go/TypeScript DTO与synthetic fixture由新增测试锁定。剩余直接Resource placeholder为A evidence、C catalog scan/record/import和B preflight diff，未由D代填；generic list及D其余控制视图仍待后续拆分，故OpenAPI继续draft。
- D-only Admin activity/list 第一批已把Task/Operation、四类task、五类event、四类log、prune item及promotion列表改为closed typed response。新增schema/DTO/fixture测试锁定核心与namespaced diagnostic event、details/log上限、非权威事件语义、`spi_` ID、prune item转换及provider-location hash边界、promotion七组派生health。原21个generic list仅剩C catalog三类和B staging/restore-resource两类；D没有提交owner字段或伪造批准。
- D-only Admin task detail 第一批已把backup、drill、preflight、artifact-verification四个详情GET切换为closed typed response，并纳入OpenAPI、Go/TypeScript parity和synthetic redacted fixture。D仅提供任务/执行状态、eligibility与hold、cleanup、artifact lifecycle、checksum、typed public ID、聚合校验和immutable config hash；A的check/audit/redaction正文、B的restore target内容、C的artifact/catalog locator及credential未被复制。剩余五个direct Resource和五个generic list均是明确的A/B/C owner缺口。
- D-only dependency/provider persistence 草案已关闭dependency-health与provider-capability record/read-time projection，固定typed owner、identity hash/ref version、row-version CAS、唯一键、过期fail-closed、role-specific capability code及absence/full-discovery any-of组。Synthetic fixture证明dependency stale仅由数据库时间派生，provider missing固定unknown且supported必须来自完整正向probe。Manifest对应artifact已从missing改为draft并请求A/B/C评审；C的真实adapter/probe与A/B的业务检查没有由D实现或假定通过。
- D-only control-evidence sidecar 外层草案已关闭`control/evidence.json.enc`的控制对象排除/redaction证明、九类历史count/time/rolling hash与owner evidence引用，并在manifest引用中绑定schema version。Sidecar不保存原始控制行、audit/check正文、provider locator或self-checksum，P0 restore只读验证且不导入历史控制状态。Synthetic示例中的A/B/C均保持`incomplete/evidence_missing`；对应manifest artifact从missing改为draft并新增三方评审请求，没有预填批准。
- D-only evidence/chunk/log 持久化外壳草案已关闭三张计划表的typed owner、inline/external存储状态、fail-closed失败码、claim/expiry/delete转换、1 MiB连续chunk元数据和ready log→redacted evidence绑定。持久化只记录server-derived relative key、typed provider identity/ref version、immutable version及envelope hash引用，Admin不得提交storage key/provider endpoint/credential，raw stdout/stderr不落控制表。Synthetic示例验证inline bytes checksum、双chunk连续offset及日志关联；A的脱敏/envelope、B的JobObserver、C的provider adapter均未实现或假定完成。对应artifact从missing改为draft并请求A/B/C评审，Manifest当前为24项draft、8项missing。
- D-only live schema-hash 接入门禁草案已补closed candidate/reviewed evidence envelope、candidate builder、临时records缺失验证和contract-check reviewed输入。证据同时绑定安装identity hash/version、capture SQL、records/server context、inventory snapshot、migration catalog、完整object-key集合及result；candidate无法带registered evidence或批准，reviewed必须对象全集匹配、清理verified、evidence已登记且A/B/C批准齐全，manifest gate为false时strict继续失败。2026-09-15本机复核显示`kubectl config current-context`未设置且`%USERPROFILE%/.kube/config`不存在，因而未生成或伪造live结果；取得指定测试安装的只读kubeconfig/TSV后再执行现场采集。
- D-owned `system_image_settings` runtime DDL已移入追加`064` migration：migration以现有行保留为前提收敛当前表、gateway enum、runtime variant、enabled列、历史单列唯一索引和普通查询索引；repository构造器不再执行CREATE/ALTER或读取`information_schema`。Inventory和无依赖测试锁定该边界，repository runtime CREATE/ALTER分别由10/4降为9/3。离线Go定向测试因所需modules不在本机cache而在setup失败，遵守约束未下载依赖，临时build/module cache已清理；尚不能以静态测试替代真实MySQL升级验证。
- Go 包测试尝试使用独立工作区缓存、`GOPROXY=off` 和 `-mod=readonly`；本机没有所需模块缓存，测试在 setup 阶段失败，未安装依赖。测试缓存已清理。本机 Docker daemon 未运行，也没有可用 `mysql`/`mariadb` CLI；当时四表的真实数据库升级验证尚待完成，后续集群结果见下节。

## 已提供集群的升级验证进展（2026-09-14～2026-09-15）

- 【已完成】现有数据库的 `063` migration 执行与升级后结构验证：切换镜像前，`schema_migrations` 中 `063_add_security_scan_tables.sql` 为 0 条；在 master 上对现有 Pod `clawmanager-app-799bfcc64f-sgvxr` 原地切换到 `10.130.14.23:5000/clawmanager:backup-test-zh-fix1` 后，容器报告实际镜像 digest `sha256:fcd389c47e2f63e8b4c2d593f317ed90c99af5e109218db84a64965ea876c70f` 且 `ready=true`，同一查询返回 1。升级前后四张 security-scan 表的列数均为 10、14、16、5；`security_scan_job_items.job_id` 与 `security_scan_reports.job_id` 升级后仍引用 `security_scan_jobs`。
- 【已完成】独立全新数据库建表验证：run `20260915022655-16943` 使用当前部署的 MySQL image/init ConfigMap、临时 Service/Secret、`emptyDir` 数据目录和固定 fix2 digest 启动隔离 MySQL 与 app；全部 embedded migration 从 `001` 执行到 `063`，`063_add_security_scan_tables.sql` 仅一条，四表/总列断言为 `PASS (1:4:45)`，列数、CASCADE 外键、主键、唯一键及二级索引与已有库结果一致。脚本退出后已报告清理该 run 的 Pod、Service、Secret 和临时数据。仓库已补 `TestMigration063CreatesSecurityScanSchema` 静态回归测试；下载依赖后，定向测试与 `go test ./internal/db -count=1` 整包测试均通过，格式化和 diff 检查通过，两次运行的一次性缓存均已清理。启动日志同时证明其他 repository 仍尝试对已迁移的 `llm_models` 列和 `model_invocations` 索引执行重复 ALTER，并产生非致命 `Duplicate column/key`；这是全局运行时 DDL 门禁的独立缺口，不回退 security-scan 子项结论。
- 【已完成】定位并绕过本次启动阻断：新旧镜像均曾因 `/app/start.sh` 卡在从 `/workspaces/.clawmanager/tls/tls.crt` 复制证书而无法就绪；`clawmanager-tls` Secret 当时不存在，用户随后确认旧 Pod 恢复，并在同一 Pod 上实测新镜像就绪。Pod 的 NFS server `10.107.165.245` 属于 `clawmanager-ltt-system/workspace-store`，其 endpoint 为 `10.244.235.250:2049`；本命名空间 `workspace-store` 的 Service IP 为 `10.111.9.69`，endpoint 为 `10.244.235.213:2049`。跨命名空间共享是否有意配置、证书的长期来源及 NFS 文件读卡顿原因仍待核对。
- 【已完成】node1 与 Deployment 完整滚动更新验证：node1 当前 Ready、无 taint，`MemoryPressure/DiskPressure/PIDPressure=false`，kubelet/containerd 为 active，节点根盘、kubelet 和 containerd 路径所在文件系统共 2.9 TiB、使用 27%。恢复阶段曾重复出现 kubelet Starting 和 `InvalidDiskCapacity`，随后 Longhorn 事件收敛为 `Node node1 is ready`，最近 15 分钟 kubelet/containerd 无 warning。最终镜像 rollout 后 `clawmanager-app` Deployment 为 desired/updated/ready/available 2/2，目标 ReplicaSet `clawmanager-app-586c468f84` 为 2/2；两个 Pod 分别在 node1 和 k8s-master Running、零重启，旧 ReplicaSet 均为 0。
- 【已完成最终测试镜像 rollout 与已有库结构复核】两个 app Pod 的 spec 均为 `10.130.14.23:5000/clawmanager:backup-test-zh-fix2`，实际 imageID 均为 `sha256:e755ee87f9523ed16b59212d4f0c1859af8e70c453dba87de58069c7670cbadc`，Deployment rollout 成功。containerd 的 `status.image` 显示同 digest 的 fix1 RepoTag 别名，不覆盖 Pod spec 和 imageID 证据。此前 `clawmanager-frontend` EndpointSlice 已包含两个 Ready 地址，无认证 `/api/v1/auth/me` 通过 Service 返回 401。fix2 下只读查询确认 `063_add_security_scan_tables.sql` 仅有一条 applied 记录（2026-09-14 07:16:42），`security_scan_configs/jobs/job_items/reports` 列数为 10/14/16/5，两条外键均指向 `security_scan_jobs` 并级联删除，主键、唯一键和二级索引与 migration 一致。八张新归属的 northbound/runtime-upgrade 表在此前查询中均未返回；P0-0a schema coverage、Go 包测试及 P0-0b 总阶段门禁继续保持未完成。
- 【交接 B】fix2 运行期间，leader app 仍每 5 秒打印数据库中实例 1 的既有 `Status=error`；集群中不存在带 `instance-id=1` 的 Deployment、Pod 或 Service。来源 IP `10.244.235.224` 持续调用 `POST /api/v1/agent/register`，约每 10 秒形成一组 `invalid agent bootstrap token`/HTTP 400；同时其他 runtime-agent IP 的 heartbeat/report 返回 200。该问题已证明不是仍运行早期 app 镜像导致，属于 B 的 `instances` 域。D 只保留无 token 的状态和来源证据，不执行 token 重置、实例删除或工作负载重建。

### 本轮 `064`–`077` 迁移修复与已有库复测（用户提供，2026-09-17）

- 【已完成】失败原因与代码修复：fix3 启动时 `066` 第2条建表因`VARBINARY(65535)`触发 MySQL 1118；把`system_backup_operations.external_action_public_ids_canonical_json`改为`BLOB`，同时把`072`的`system_backup_check_results.expected_canonical_json`与`actual_canonical_json`改为`BLOB`，保留原有字节数、JSON和hash约束。fix4 已越过1118，但相同建表语句的CHECK引用自增`id`触发 MySQL 3818；随后把重试关联改为`retry_of_operation_public_id CHAR(40)`，增加同installation的自引用外键、显式子索引及不引用自增列的非自引用CHECK。MySQL DDL非事务性，失败时不手工删表；由`CREATE TABLE IF NOT EXISTS`在后续镜像启动时续跑未登记的`066`。
- 【已完成】本地回归与合同同步：DDL静态断言、合同产物和`migration_catalog_hash=bd2cb7414daa6740b9c452f6041a3ad59294c95cd24051bb9e41214fec44759f`已同步；`node scripts/system-backup-contract-check.mjs --check`、80项Node测试及离线可运行的`internal/migrationcatalog`、`internal/systembackupcontroller` Go包测试通过。没有为此安装依赖；`internal/db`整包Go测试因本机离线module cache缺失未运行，不能拿静态回归代替真实MySQL。
- 【已完成】已有库迁移与字段验收：测试命名空间`clawmanager-zhanghui08-system`的`schema_migrations`查询列出`064`至`077`十四条；`information_schema.COLUMNS`确认`system_backup_operations.external_action_public_ids_canonical_json`、`system_backup_check_results.expected_canonical_json`、`actual_canonical_json`均为`blob`，`retry_of_operation_public_id`为`char`。这验证了已有库的本轮升级，不覆盖全新库从`001`至`077`的独立重放、历史额外migration内容比对或全部控制表字段/索引审计。
- 【已完成】隔离全新库重放：远程脚本运行于临时namespace`sbk-mig-260917093255-6c0a`（UID `e4da3878-99be-4eaa-a8a0-9f39cdd0a8f9`），使用固定app/MySQL digest和MySQL 8.4.8，从空库启动embedded migration runner；现场输出`PASS fresh-migration-replay=001..077 applied=90 exact_filenames=yes d_columns=blob/blob/blob/char`，随后输出同UID的`CLEANED`。这补足全新库`001`–`077`迁移冒烟，但不等于历史SQL内容比对、全部表结构审计或真实备份验收。
- 【已完成】D结构差异核对：2026-09-18再次隔离重放并只读采集全新库与现有测试库，两份TSV的本地SHA-256均与远程输出一致。95个实测对象中，registry归属D的41张表在列、索引、外键上差异数为0；两份原始TSV的规范化全库指纹不同，仅定位到A-owned`users`表在现有库缺少新库中的`local_username_key`生成列和`uk_users_local_username`索引，这是修复前快照；后续A已定位并补齐，见下条。见[脱敏比较报告](system-backup-d-schema-compare-2026-09-18.json)。远程原始TSV尚待清理；本次不覆盖CHECK约束、表选项或历史migration SQL内容。
- 【已完成】A-owned `users`约束补齐：历史对话确认旧版同名`049`已于2026-08-28在现有库登记，而`local_username_key`和`uk_users_local_username`是2026-08-31才加入仓库`049`。新增`078_reconcile_local_username_key.sql`后，用户在现有测试库只读确认其于2026-09-18 01:54:33登记；生成列表达式对应`auth_provider=local`时的`username`，索引`NON_UNIQUE=0`、`SEQ_IN_INDEX=1`且只含该列，本地用户名重复组数0。原`049`登记未修改；修复后全库指纹仍待重采，历史脱敏报告保持修复前取证。
- 【已完成】D CHECK与基础表选项核对：随后远程独立重放并采集，两份DDL TSV的360条记录与SHA-256完全相同；D的41张表包含265条CHECK，新旧库在CHECK名称/表达式/ENFORCED以及engine、默认collation、实际row format、`CREATE_OPTIONS`和comment上差异数为0。见[脱敏DDL比较报告](system-backup-d-ddl-compare-2026-09-18.json)。临时namespace已报告清理，远程原始TSV仍须删除；动态计数和未选取的物理属性不在覆盖范围内。
- 【已完成】D资源表只读冒烟：`information_schema.TABLES`确认D的九张`resources`业务表均为InnoDB基表；一次只读repeatable-read事务中的九表`COUNT(*)`全部成功：`audit_logs=0`、`egress_private_exceptions=0`、`northbound_admin_settings=1`、`northbound_settings_audit=0`、`security_scan_configs=0`、`security_scan_job_items=0`、`security_scan_jobs=0`、`security_scan_reports=0`、`system_image_settings=10`。这是人工源库查询，不代表需冻结registry后才能调用的`SQLCountCollector`已在生产编排中执行，也不验证B的dump或任何备份包。
- 【已完成】最终镜像稳定性复查：Deployment报告successfully rolled out；两个新app Pod分布于node1和k8s-master，分别运行约17、18分钟，均`1/1 Running`、零重启且imageID同为`10.130.14.23:5000/clawmanager@sha256:91d34660b191ec05aad783e148644c2167b32049729bc023e83de9a9ffa2a611`。本轮启动/迁移问题通过更新app镜像验证，无须为`066`/`072`修复额外修改现网Deployment YAML；未启动真实备份Job。运行时migration已嵌入后端二进制，`schema-hash-capture.mysql.sql`只用于后续P0-0a现场结构取证，不是运行镜像的启动依赖，也未在本次远程测试执行；live schema-hash、controller/权限正负测和A/B/C跨域验收继续待完成。

## 未完成的 P0-0a 决议与验证

### 可重复运行的对象覆盖率盘点

已新增 `scripts/system-backup-schema-inventory.mjs`，从主计划第 5.1 节读取单一 owner，扫描 embedded migration 的 `CREATE` 对象、repository 的建表/改表入口、四套官方 YAML 的手写建表，并把 migration runner 的 `schema_migrations` 例外一并列入 `system-backup-restore-schema-inventory.json`。运行 `node scripts/system-backup-schema-inventory.mjs --check` 可检查快照是否随代码和主计划更新；CI 在安装前也执行该检查。`--write` 仅刷新该静态快照，`--strict` 会在覆盖缺口、运行时 DDL 或部署手写建表未消除时返回失败。此脚本只做对象发现、不解析完整 SQL；新增的 `system-backup-contract-check.mjs` 在其输出之上合并 owner 决议并计算 `migration_catalog_hash`。D 已补 `schema-hash-observation.schema.json`、`schema-hash-result.schema.json`、MySQL 8.0/8.4 只读 capture SQL 和 `scripts/system-backup-schema-hash.mjs` canonicalizer；固定测试向量、乱序/换行等价、结构漂移及 malformed record fail-closed 测试已接入 CI。确定性 result 不含安装身份、采集时间或签名上下文，不能冒充 live evidence，因此 `schema_hash_evidence_present` 仍保持 false。

本次可重复结果：主计划业务表 94、连同 `schema_migrations` 共 95 个对象；migration 创建对象 91；未迁入 migration 的仍是 A 的 `chat_messages`、`chat_sessions`、`risk_rules`。未发现无 owner 的静态对象；repository 仍有 9 个表的 `CREATE TABLE` 路径和 3 个表的 `ALTER TABLE` 路径，均属 A（部分重叠）；四套官方 YAML 各手写创建相同的 22 张业务表，均须收敛为最小 bootstrap 或同源生成物（详见 JSON）。D-owned `audit_logs`及`system_image_settings`均已从四套MySQL init脚本移除，继续由embedded migration负责。移除system-image七块前已逐块验证四清单SQL与同名embedded migration一致、其他init块不引用该表；真实首次安装仍待验证。此处仅为 ownership inventory；D 的41项策略已记录但交叉评审仍未完成，其他 owner 的54项策略仍待提交，因此**不能作为已冻结 registry**。

真实库对照时，在目标业务数据库连接上以只读账号分别导出下面两个查询的 TSV 结果（无表头），再运行 `node scripts/system-backup-schema-inventory.mjs --db-objects <objects.tsv> --applied <applied.txt>`。比较结果会分别列出当前已应用 migration 应有而缺失的对象、数据库额外对象和未知 migration；不要把查询结果中的业务数据或凭据写入仓库。

```sql
SELECT 'table', TABLE_NAME FROM information_schema.TABLES
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
UNION ALL SELECT 'view', TABLE_NAME FROM information_schema.TABLES
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'VIEW'
UNION ALL SELECT 'trigger', TRIGGER_NAME FROM information_schema.TRIGGERS
 WHERE TRIGGER_SCHEMA = DATABASE()
UNION ALL SELECT 'routine', ROUTINE_NAME FROM information_schema.ROUTINES
 WHERE ROUTINE_SCHEMA = DATABASE()
UNION ALL SELECT 'mysql_event', EVENT_NAME FROM information_schema.EVENTS
 WHERE EVENT_SCHEMA = DATABASE()
ORDER BY 1, 2;
```

```sql
SELECT filename FROM schema_migrations ORDER BY filename;
```

本机 `kubectl config current-context` 仍返回 `current-context is not set`，且没有可用的 MySQL/MariaDB CLI 或数据库连接；因此本次未生成真实库 TSV，也未把真实 schema 或 provider capability 判为通过。

### 测试安装只读输出核对（用户提供，2026-09-14～2026-09-15）

- 目标命名空间为 `clawmanager-zhanghui08-system`，集群 context 为 `kubernetes-admin@kubernetes`。用户在 MySQL Pod 内以只读 SQL 查询 `information_schema` 与 `schema_migrations`，没有修改数据库。
- 实际 64 个对象均为 table，名称与当时 64 个对象的 ownership inventory 双向一致，未见额外 view、trigger、routine 或 event。当前 inventory 因新增二十七张 D 控制面表已扩为91个对象，不能拿旧查询冒充新快照覆盖证明。`063_add_security_scan_tables.sql` 已应用，四张 security-scan 表均存在；对象名覆盖通过不等于字段、索引、外键、schema hash 或 owner 策略验证通过。
- 线上`schema_migrations`早期观测有79个文件名；当时仓库76个embedded migration均已应用，`064`至`077`彼时尚未在目标安装验证。2026-09-17的新查询已确认这十四条全部登记；线上仍额外存在`045_update_workbuddy_windows_runtime.sql`、`046_add_instance_pvc_name.sql`、`047_add_instance_runtime_variant.sql`三个当前仓库不存在的文件。仅凭applied filename无法证明旧文件与后续同主题migration内容等价，须找回历史文件或构建来源并核对；暂不能宣称整个migration catalog兼容。
- 扫描器按“只从已应用且在当前仓库的 migration 创建”比对时，将 `chat_messages`、`chat_sessions`、`risk_rules` 单列为 `runtime_only_in_database`；三者均有 A owner，且在 repository 有建表路径，并非无归属对象。A 仍需用追加 migration 收敛新装路径。
- 安装中 MySQL 与 team Redis Deployment 均为 1/1；app Deployment 已于 2026-09-15 收敛为 2/2，两个新镜像 Pod 均在 node1 Ready/Running 且零重启。Redis 历史状态记录不能证明 checkpoint 能力。
- 集群存在 `driver.longhorn.io` CSIDriver，以及 `longhorn`、`longhorn-rwx`、`longhorn-static` StorageClass，但 API discovery 和 CRD 清单都没有 VolumeSnapshot 资源，`kubectl get volumesnapshotclass` 明确返回服务端不支持该资源。本命名空间四个 PVC 全部为 `manual` StorageClass；结合下节 PV source 证据，当前源卷不是 CSI/Longhorn 卷，不能宣称 cluster profile 的不可变 CSI checkpoint 可用。

### 测试安装 PV 与 migration 时间补证（用户提供，2026-09-14）

- `clawmanager-workspaces`、`minio-data`、`mysql-data`、`redis-data` 绑定的四个 PV 均为 `spec.hostPath`，没有 CSI、NFS 或 local volume source。这与主计划第 2.2 节的 HostPath/`single-node` 路径相符，但还不能仅凭 PV 类型确定当前部署声明的 `CLAWMANAGER_STORAGE_PROFILE`、PV node affinity、实际 Pod 节点绑定和最大停写窗口是否满足；若部署仍声明 `cluster`，属于需纠正的 profile/capability 不一致，不得宣称 cluster CSI checkpoint 可用。
- 三个当前仓库缺失的历史 migration 均在 2026-08-12 02:32:22 留下 applied 记录；名称相近的 `050_update_workbuddy_windows_runtime.sql`、`052_add_instance_pvc_name.sql`、`053_add_instance_runtime_variant.sql` 均在 2026-09-14 07:16:42 应用。时间证明先后和两套文件名都运行过，不能证明 SQL 内容相同或副作用等价；旧文件仍须从历史源码/镜像构建输入找回并评审。不要删除历史 `schema_migrations` 行来掩盖 catalog 差异。
- 远程 GitHub `Yuan-lab-LLM/ClawManager` 的 `main` 文件历史页面对上述三个旧文件名均显示 `No commits history`；本地为非浅克隆，`HEAD`/`origin/main` 均为 `576e4bb`，`git log --all --name-only` 在当前追踪的分支与 tag 历史中也未找到这三个文件名。现有同主题的 `050`/`052`/`053` 在提交 `00d4d2a` 中加入，且当前代码仍使用 `pvc_name`、`runtime_variant` 和 Workbuddy Windows 运行时，因此不能据旧文件名缺席断言功能已舍弃。旧 SQL 可能来自未公开/未合并源码或历史镜像构建输入；尚无原文，仍不能断言与新 SQL 等价。当前 migration runner 只遍历 embedded SQL 并跳过已记录的同名文件，不会因数据库中额外存在这三个旧 filename 本身报错；P0 清单一致性和 schema 兼容性仍需单独验证。
- app 先前的 1/2、Pending 和 Terminating 状态已在 node1 恢复后收敛；当前 Deployment 为 2/2，两个 Pod 均在 node1 Running。调度阻塞已关闭，但与 schema/capability 门禁继续分开判断。

### 测试安装 profile 与节点约束补证（用户提供，2026-09-14）

- 当前 `clawmanager-app` Deployment 明确配置 `CLAWMANAGER_STORAGE_PROFILE=cluster`、`K8S_STORAGE_CLASS=longhorn`；后者不能改变已经绑定到 `manual` HostPath PV 的四个核心 PVC。工作空间、MinIO、MySQL、Redis 的实际数据卷仍为 HostPath，且当前没有 VolumeSnapshotClass API。按主计划第 2.2、7.3 节，不能把这套安装作为 P0 `cluster` 的不可变 CSI checkpoint/strong acceptance 能力证明；正式 admission 应 fail closed，而不是从 `cluster` 静默降为 HostPath `single-node`。
- 四个 HostPath PV 的 node affinity 均只要求节点标签 `clawmanager.io/storage-node=true`；后续节点清单证明仅 master 带该标签。MySQL、MinIO、Redis 等 HostPath 数据负载继续受该约束；两个无显式 nodeSelector/affinity 的 fix2 app Pod 当前分别在 node1 和 master Ready。app 可跨节点调度不代表 HostPath 源卷已经迁移、共享或变为 CSI 卷。
- 该环境若要用作 P0 `cluster` 矩阵，需要独立证明工作空间等源卷的 CSI 快照/只读 checkpoint、Redis/Object checkpoint 及相应 provider 能力。若选择 HostPath `single-node` 矩阵，应在独立测试安装中按主计划绑定唯一 storage node、在 gate 内完成完整加密 staging 并验证停写预算；不能直接修改运行中 Deployment 的 profile 来代替迁移和回滚评估。当前能力状态为不满足 `cluster` 验收前提，`single-node` 尚未验证。
- 测试安装已完整运行最终工作树测试镜像 `backup-test-zh-fix2` 及上述固定 digest，证明 node1 恢复后的完整 rollout 路径；`063` migration 由早期 fix1 在已有库执行，fix2 下已复核结构无漂移，且同一固定 digest 已完成临时隔离全新 MySQL 建表验证。P0-0a 的基础设施/capability 发现不依赖继续重打镜像；当前仓库尚无系统备份 controller/API，现有镜像不能完成系统备份端到端验收。
- 节点标签补证：`k8s-master` 为 Ready 且唯一带 `clawmanager.io/storage-node=true`；`node1` 已从 NotReady 恢复为 Ready、无 taint，仍无该 storage-node 标签。四个 HostPath PV 的 node affinity 继续只匹配 master。单 storage node 是 HostPath `single-node` 的必要条件之一，但不修复当前 Deployment 声明的 `cluster` profile，也不证明 gate/staging、停写预算或 provider 能力；node1 与 app rollout 恢复只关闭此前的调度阻塞。

1. 请 A/B 对八表归属及 D 所有的北向配置跨域字段交叉评审；各 owner 补齐八表的数据分类、备份/恢复策略、normalization 和 verifier，D 补齐控制面表与 `schema_migrations` 的 registry 项。当前不能宣称 schema coverage 完成。
2. 在已提供的测试安装查询 `information_schema`，与 embedded migration、registry 双向比对；确认 view/trigger/routine/event、安装程序和 MySQL init 中的实际对象及差异。
3. 与 A/B/C 对真实 provider/CSI/KMS/Redis 做第 17.1 节能力和权限 spike；固定 fixture 只能证明接口行为，不能替代真实 provider 能力证明。
4. 冻结机器合同、DTO parity、redacted fixture、文档版本门禁和非实现 owner 交叉评审；在这些提交前，P0-0a 总门禁仍为未通过。

此记录只保存对象名、代码位置和无密钥命令，不复制 YAML 中的 Secret 值、外部连接信息或运行时凭据。
