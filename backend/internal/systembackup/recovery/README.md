# 六域 artifact / recovery catalog

本目录提供原计划中的六域合同、发布状态机、独立目录扫描、导入认证、删除记录和保留策略核心实现。`profile.Driver` 默认执行 `functional_test`；六域 acceptance 必须显式配置策略并接入独立证据校验，详见下文。没有新增真实迁移入口。

本次范围遵循“缺少真实资料先完善接口”：仓库已有字段直接实现归一化；外部存储能力、Redis 原子采样、共享卷恢复和 owner 私有格式由明确的适配接口提供。缺实现、缺证明或结果不完整均返回错误，没有默认成功实现。

## 六个业务域与六个物理 part

业务域固定为 `users`、`instances`、`ai_gateway`、`teams`、`resources`、`skill_hub`。物理 part 固定为 `mysql`、`redis`、`object_storage`、`workspace`、`deployment_resources`、`secret_bundle`，两者分别校验，不能互相替代。另有独立 `control_plane` verifier。

`Registry.Capture` 要求六个 collector 全部注册，逐项调用并验证 checkpoint、不可变对象版本、大小/hash、状态、全局重复 key 和一致性等级。任何 bounded part 都使总体降为 bounded。`Registry.Verify` 接收独立只读身份与隔离证明，要求六域及控制面的 verifier 全部通过。

已有 SQL 路径的新增归一化位于 `../domain/teams.go`、`crossdomain.go`、`dependencies.go`：

| 范围 | 恢复处理 |
| --- | --- |
| Teams / members | 关闭活动状态和运行时引用；保留删除历史；共享 PVC 必须有明确的隔离卷映射 |
| tasks / work items / phases | 保留定义和历史；活动任务置失败，活动阶段取消；核对 Team 内引用及成员归属 |
| events / outbox | 事件历史归档，清除 Redis stream 绑定；outbox 仅留源密文，不导入目标重放 |
| AI Gateway | 模型、聊天、调用、成本、风险和审计表纳入依赖；活动调用关闭，清除实际运行引用 |
| resources | 镜像设置、出站例外、扫描配置/任务/报告、管理审计纳入依赖；可执行规则禁用、活动扫描关闭 |
| 配置 JSON | 已登记的配置字段仍需逐叶规则；未知字段、未知源 schema 不自动放行 |

用户/实例贡献合同更新为 `users-instances-contribution.v2`，明确包含 resources。旧 v1 仍可被领域包读取器校验，但不能用旧合同假冒当前 profile 的完整依赖。`TeamPlacements` 已进入数据库 Worker 参数；当前 profile 不会自行猜测共享卷映射，需要共享空间 owner 先恢复并验证实际目标卷。WorkBuddy 精确源 schema 接口保持不变。

## 发布与信任

`contracts.schema.json` 是 JSON Schema 的 `$defs` 合同库。调用方选择对应定义（如 `#/$defs/SignedManifest`）进行结构验证，再调用 Go 校验器完成引用、签名、大小/hash、provider 和资格判断。执行 `go run ./cmd/backup-contract-schema` 可离线生成，测试检查生成物与代码一致。

`Canonical` 实现本合同使用的 RFC 8785 子集：Unicode 标量字符串、UTF-16 属性排序、布尔、null、数组、对象及安全整数。拒绝重复 key、未配对代理项、浮点/指数数字、超界整数和尾随数据。该函数不用于规范化业务浮点数据；业务数据仍在加密 part 中。

签名外壳为 `{payload, signature}`，保护头和 payload 一起签名。`manifest`、`acceptance_record`、`catalog_record` 三种用途使用独立的 key ID 和实际公私钥；用途复用、未知 key、被标记泄露的 key 或其别名均失败。公开文件仅保存密钥/凭据的不可变引用，不保存可重放凭据。

`Publisher.Publish` 消费已加密、已固定版本的数据对象，先验证六 part/六域、控制面证明和全部密文认证，再顺序发布：

1. `artifact-index.json`；包含加密 payload、envelope、控制面证据，不包含自身或后续文件。
2. 签名 `manifest.json`；不包含自身 checksum 或 acceptance 状态。
3. `_COMMITTED`；绑定 manifest/index 完整字节摘要。
4. 源 staging 清理证明。
5. 仅 acceptance 任务发布签名 `_ACCEPTANCE`。
6. 只有 `local_acceptance=true` 才发布签名 `artifact_registered`。

functional_test 不生成 `_ACCEPTANCE` 或注册记录，也不需要后两种 signer。bounded、同集群副本、不可恢复 KEK、目标风险或非 operational warning 均不能注册。记录 ID 根据原计划的 canonical 数组、SHA-256 前 20 字节和无 padding 小写 base32 计算。记录绑定源身份、矩阵、精确 locator/core 版本及灾备 bootstrap 引用。

## 外部写入与 SQL 日志

`Finalizer.Execute` 在发送前绑定 `AppendProvider.Identity/Location`，由 Journal 持久化规范字节、provider 身份、key、hash、size、固定 deadline 和 generation。`Sent` 事务关闭取消并记录发送意图，提交响应不确定时不能发送。接管发现 `request_sent/provider_unreachable` 只调用 Observe/Open，不重新 Create。

`AppendProvider.Create` 的生产实现必须使用存储端原生条件创建，并把 key/hash/length/到期时间绑定到请求授权；普通长效 S3 写凭据加客户端时间检查不满足接口。普通 404 只能返回 unknown。只有带当前能力证明的强一致/版本化 absent，且原授权已过期，才能最终判 absent。不同字节或 provider 身份变化为冲突。

`control.CatalogActions` 实现事务 fence、精确字节冻结、单一未决动作、关闭取消和观察结果持久化。`control.CatalogAdmission` 从 Vault 解密冻结的 `SixDomainPlan`，核对任务用途、provider、签名 key ID/version/实际公钥 hash、前序确认对象及源补偿/Worker 状态。index、manifest、marker 必须与原计划精确匹配。acceptance 还必须读取绑定完整计划的授权记录，重算验收结论及注册内容；functional_test 不能通过 owner 回调扩大用途。原生存储能力仍在 provider 边界独立核验。

相关 SQL 表为 `system_backup_catalog_actions/scans/records/pages` 和 `system_backup_recovery_publications`。后者保存逐步外部确认后的本地结果；acceptance 提交必须核验完整发布链及条件性注册，单独存在功能包记录不能充当验收。初装见 `control/schema.sql`，已有控制库见 `control/upgrade-catalog.sql`；程序不自动执行这些 SQL。

## 扫描、导入与删除

`Scanner.Step` 每次处理一页（最多 1000 条），仅接受固定 provider snapshot 或 inventory manifest。扫描冻结 root、快照 ID、总数、摘要和到期时间；Journal 将签名原始字节、解析记录、分页回执、游标、数量和 checksum 链同事务保存。最终在一致性事务中重新验签、重算数量/对象摘要和分页链，并检查跨页 tombstone 对原注册的精确引用。EOF 已提交而 Finish 响应丢失时只重试 Finish。

`known_record_only` 只支持已知记录读取，不代表全量目录发现。provider 的普通 LIST 不能实现冻结快照接口。`RequireCapabilities` 拒绝缺失、过期、unknown 或身份不符的能力证据。

`Importer.Import` 只需要外部 catalog、disaster bootstrap 和不可变 artifact reader。它验证 manifest/index/marker/acceptance/registration 的全部关系，流式认证每个加密对象至最终记录，并在前后两次核对 tombstone。认证器只消费前缀、对象被替换、弱 absent 或导入中出现 tombstone 都失败。返回值是已验证元数据；调用方仍须在实际恢复前持有资源 lease 并重新检查删除状态，不能把一次 Import 当成永久恢复授权。

`PlanRetention` 根据固定 origin/matrix/failure-domain 分组保留最新 N 个历史合格点，当前健康状态损坏不使受保护点被删。hold、lease、未结束任务及活动 finalizer 均保护；缺少历史点的组返回 shortage。候选 hash 绑定 cutoff、配置、core、guard version、首次终态和对象身份；执行删除前必须在同一事务锁下重算。

`Tombstone` 必须得到 `PruneProof.VerifyDeleted` 的全版本及 delete marker 删除证明，再冻结首次执行人、首次 deleted 时间和原候选摘要。这里只提供策略、证明接口及签名删除事件；真实 provider 的版本删除与 lease/CAS 适配没有假实现，也不会因签发 tombstone 而主动删除数据。

## 待提供资料的适配接口

| 接口 | 必须提供的真实依据 |
| --- | --- |
| `AppendProvider` / `Discovery` | 存储角色与根目录不可变身份、原生条件请求与到期授权、精确版本读取、强 absent 和固定快照/清单 |
| `PublicationProofs` / `Authenticator` | 全部 collector/verifier/清理证据账本，以及 owner 的真实加密 framing/envelope 格式 |
| `RedisReader` / `RedisSnapshotProvider` / `RedisRestore` | topology、精确 prefix/DB、原子 DUMP/type/PTTL/server time、stream/group 格式及目标隔离证明 |
| `RedisSealer` | 直接写入任务密文 staging，produce 失败必须丢弃未完成结果，禁止明文临时文件 |
| `ObjectSnapshot` / `SharedWorkspace` | 固定对象版本清单、全部 writer 暂停证明、共享卷内容及 UID/GID/挂载身份校验 |
| `PruneProof` | 冻结候选与 guard/lease 事务、全版本/删除标记清除后的强一致证据 |
| 六域 `Collector/Verifier/Normalizer` | 各 owner 实际版本字段、策略和独立只读 verifier 身份；不能用空报告替代 |

Redis scan_dump 只能声称 bounded；共享 keyspace 禁止整实例 RDB/AOF。TTL 使用毫秒绝对到期时间，过期 key 跳过，时钟漂移超限报错；只有 functional_test 可选 restart_remaining。重复 SCAN 项内容变化、循环游标、prefix 越界、无 stream groups 或容量超限均失败。

## 验证边界

测试使用内存 provider、合成数据的 AES-GCM 包、SQL driver 替身、本机临时目录及既有 Kubernetes fake/localhost TLS。覆盖完整六 part 发布→注册→源无关导入→分页扫描→tombstone、未知写结果/丢失提交响应、缺 part/证明、密文破坏、签名用途/泄露、扫描重启和页链、保留策略及 Redis TTL/重复项。

HTTP/UI 默认用途为 `functional_test`，只有具备固定 acceptance 策略及就绪 owner 的 backup profile 可显式提交验收备份。专用准入通用实现已接通；现场六域 acceptance 仍需要真实 adapter、证据及隔离联调。本轮没有访问参考服务器、执行真实备份迁移或发布部署。

## 控制器与 owner 生命周期接线

`profile.Config.SixDomainModule` 是版本及 SHA 固定的 owner 模块引用，只能用于 backup profile。通过 `host.RunWithAdapters` 的 `Adapters.SixDomain` 注册对应工厂。工厂收到已装配基础依赖的 Driver；工厂及 `Bind` 仅构造对象，不能执行迁移或重做 discovery。默认命令没有注册任何猜测的生产 owner，实现缺失时 profile 未就绪。

`SixDomainOwner.Discover` 只读返回 owner 计划，与基础计划一起加密冻结；`Bind` 从该计划返回 `SixDomainExecution`：

- owner Writers 合入完整 PauseJournal，暂停/恢复及接管使用同一清单，重复 ID 拒绝。
- owner Collectors 合入 Pipeline 的 prepare/capture/stop，采集发生在共同暂停窗口内，ID 不得与原 collector 重复。
- Prepare、CheckSource、ResolveMutations、Cleanup、Validate 必须齐全。owner 自行实现的远端变更也必须使用持久化意图和 fencing；仅注册接口不构成副作用安全证明。
- Contribute 接收已认证的用户/实例 Bundle 和全部封存 Part，产生真正完整的 `SixDomainPlan`；不得在源恢复后重采实时数据。计划在 validating 阶段冻结，发布时禁止重新生成。
- `SixDomainPublisher` 使用真实 CatalogActions、Admission、provider 与独立清理证明，逐项发布并写本地提交结果。Service 将该 profile 的未知发布交给只读 resolver；未确认写不重发，缺失的后续步骤不在接管时新增。部分完成保留待核对，不冒充成功。

共享 Team 工作区通过 target profile 的 `SharedWorkspaceModule` 和 `Adapters.SharedWorkspace` 注册。owner 提供已经恢复并校验的隔离卷回执；discovery 冻结后，每次核验实际 PVC/PV UID、绑定关系、StorageClass 和删除状态，并要求 owner 内容/UID/GID/独占隔离证明。通过后才把 TeamPlacements 传入数据库 Worker。该接口不等于已经实现任意存储系统的共享卷复制。

## Provider owner 网关协议

`Gateway` 实现 AppendProvider 和 Discovery 客户端，`GatewayServer` 实现对应服务端通用层。**这是 owner 网关协议，不是 S3 API；代码尚未部署。** 服务端必须接入 `NativeGatewayBackend`，不会把 HTTPS 200 或布尔声明当作底层原生机制的实现。

请求为 TLS 1.3 双向认证的 `POST /recovery/v1`。使用 `GatewayRequest` 的 canonical JSON 字节；字段大小写与生成 schema 一致，Schema 固定为 `clawmanager-recovery-provider.v1`。绑定随机 Nonce、不可变 Identity、精确 Location、Operation 和 Arguments。响应为 `GatewayResponse`，回显 Nonce、请求**完整字节**的 RequestSHA256、Identity，附不超过当前时间后 60 秒的 ValidUntil 和类型化 Payload。拒绝重定向、未知字段、非 canonical 字节、错误身份、过期或重放回执；调用必须带 context deadline，不自动重试 HTTP 写。

| Operation | Arguments | Payload |
| --- | --- | --- |
| capabilities | `{}` | `[]Capability`，Role 固定 `catalog`，Code 表示读取/写入/发现能力 |
| observe | `{ "Key": "..." }` | `Observation`；普通 404 返回不可用，不能证明 absent |
| open | `Object` | 响应正文为精确版本字节；`X-Recovery-Receipt` 头为响应外壳，其 Payload 是同一 Object；Content-Length 必须匹配 |
| conditional_create | `Request` | `Observation`；必须原生绑定 key/hash/length/deadline，客户端 AllowAppend 默认 false |
| begin_snapshot | `{ "Deadline": 123, "Mode": "inventory_manifest" }` | 固定 root/count/hash/expiry 的 `Snapshot` |
| snapshot_page | `{ "Snapshot": {}, "Cursor": "...", "Number": 0 }` | `Page`；每页重新检查发现能力 |

`open` 调用者仍须核对完整对象 hash/length，并认证密文最终记录。当前 Gateway 接收受信 owner 服务的证明回执，不独立验证厂商原始证明格式；该服务必须审核底层存储授权、版本化读取/absence、原生到期和固定快照语义。普通长效 S3 凭据、代理端时间检查、实时 LIST 均不能替代这些要求。

写入额外要求 `conditional_create`、`checksum_bound_request`、`content_length_bound_request`、`native_deadline_enforced` 和 `scoped_append_credential` 全部为当前身份的 supported 证明；缺少原生到期能力时在发送前拒绝。

## 独立目录配置与 codec

`host.Config.Catalogs` 可与旧 Profiles 共存，也可作为独立控制器仅运行目录功能：只装载控制库和 Vault 密钥、目录信任配置及 provider mTLS；不需要源 DB/K8s、节点证明或 Worker relay。参见 [catalog.example.json](../../../../examples/backup-controller/catalog.example.json)。本地配置文件固定绝对路径，Trust、Codec、WrappingKeys 固定版本/hash；record 里的 locator/bootstrap 只能命中预配置白名单，不能触发任意 URL 或凭据加载。

内置 codec `cmstg01-adapter.v1` 只适配本仓库 CMSTG01 framing。CodecDescriptor 明确绑定每个不可变对象、完整备份身份、capture hash、staging.Binding 和 wrapped DEK；读取时认证至最终帧。这是明确选择的兼容接口，不声称等于原计划所有 owner 的正式发布格式。私有格式可通过 `Adapters.CatalogCodecs[Format]` 注册工厂，接收已经验 hash 的 descriptor 字节、固定配置和 reader。构造过程不能进行网络 discovery；需要长期保存 descriptor 的实现应复制字节，宿主返回后会擦除原 buffer。未知格式没有 checksum-only 或内置格式回退。

API/界面增加两种 functional_test 任务：`catalog_scan` 续扫固定快照，`catalog_import` 接收 `artifact=sbr_...` 和规范签名注册记录的 `record_sha256`。控制器冻结 revision/provider/请求摘要，用任务 fence 持久化分页/结果；导入重新认证全部内容及 tombstone，仅保存加密校验元数据，**不写业务目标库、不创建恢复资源、不启动 Agent**。扫描记录在控制库持久化，目录分页、详情与脱敏报告见下文管理接口。实际恢复必须再次核对删除状态并持有资源 lease。

RedisCollector 已把 scan_dump 与专用实例快照接口统一；RedisRestorer 在任何目标写前验证完整归档、prefix、重复项、容量和隔离证据，按绝对 TTL 恢复。恢复日志已有下述控制库实现；真实原子采样客户端、stream/group codec、快照服务仍由 Redis owner 提供，不添加默认生产 Redis 连接。

## 目录管理与脱敏报告

管理员路由新增：

```text
GET /api/v1/admin/system-backup/tasks/:id/catalog?limit=50&cursor=...
GET /api/v1/admin/system-backup/tasks/:id/catalog/:record?type=artifact_registered
GET /api/v1/admin/system-backup/tasks/:id/report
GET /api/v1/admin/system-backup/tasks/:id/report?download=1
```

目录只展示完整扫描的持久化快照，limit 为 1–100，游标绑定 scan ID、snapshot 摘要和排序位置。注册记录 ID 为 sbr_，删除事件 ID 为 sbd_，详情的 type 必须匹配。页面支持前后分页、记录详情、填入导入校验表单以及下载 JSON 报告。

响应是白名单投影：记录 ID/hash、源安装/备份标识、部署矩阵、尝试次数、事件时间和任务状态。不会返回 provider 地址、对象路径、bootstrap、签名原文、密钥、私有计划或业务内容。接口继承现有管理员认证，设置 no-store；报告里的 restore_authorized 永远为 false。完整扫描是当时的历史证据，不代表当前签名仍可信或备份仍未被删除；实际导入仍独立验签、认证全部内容并核对 tombstone。

## Redis SQL 恢复账本

`control.RedisJournal{Store, Task}` 实现 `RedisRestoreJournal`。`Begin` 先冻结目标隔离身份、archive 引用、策略 hash 和**完整有序 item hash 清单**，拒绝重排、缺项、换目标或策略替换。普通日志不保存 Redis key、DUMP 或 stream 内容。随后逐项 Freeze→Sent→Done；Sent 的 SQL 提交不确定时不发送，已为 request_sent 的项不能改回 prepared。

恢复写只允许 functional_test 的 drill 任务、restoring 阶段、cm-drill- 目标命名空间和未过截止时间；真实 Redis 隔离仍由 RedisRestore.CheckIsolated 证明。取数据库时间和提交前均检查任务执行权。`Progress` 返回计划总数、prepared/request_sent/completed/skipped 计数。

`Reconcile` 只调用只读 `RedisReconciler.Observe`；必须返回精确目标/archive/item hash 绑定、原 writer 已停止以及目标结果匹配的证明。仅 key 不存在、超时、TTL 到期均不足以确认。取消清理阶段可在数据截止时间之后核对，但必须持有当前控制器执行权；重新接管不会自动重发 Redis 写。源 owner 在其清理回调中调用此方法，缺少真实比较证明时保留未决状态。

任务终态增加检查：不允许留下 Redis request_sent；成功还要求冻结清单中的每项完成，避免把空结果或部分恢复当成功。

## 恢复租约、保留标记与清理协调

`control.RecoveryGuards` 使用独立控制库 singleton 行锁，使 artifact 登记、保留标记、消费者租约和候选选择遵循同一锁顺序；所有修改还检查任务执行权。只有已认证的发布/导入 owner 可以调用 Register，不能用外部 API 提交任意“历史合格”标记。登记固定 locator/core/注册记录摘要；相同 ID 不允许替换。

- Acquire/AcquireFor 按 artifact/task/consumer 发放或续期恢复租约；Check 核验当前执行权和有效期。已进入 deleting/deleted 的备份不能再获得租约。
- `ProtectedCollector` 将租约接到 Pipeline 的 Prepare/Capture/Stop 生命周期，采集期间续期，失去执行权立即取消上下文，返回前重新检查。消费者 ID 由 collector ID 固定派生；同任务多个消费者独立持有租约，不能互相释放。
- Stop 先停止真正的 collector，再由独立 LeaseStopVerifier 提供绑定原消费者的正面停止证明，最后 Release。接管只采用同任务已有租约，不生成缺失的恢复操作。**未释放的租约即使过期仍保护 artifact**；这避免控制器崩溃但远端恢复仍在运行时被清理。
- Hold 使用 guard version 比较更新 manual/promotion 保留标记。FreezePrune 持久化 retention/minimum/groups/config、cutoff、候选 hash 和固定到期时间；相同 run ID 重试不重选候选。
- ClaimPrune 在同一互斥事务中重新读取全部分组、保留标记和未释放租约，重新计算候选；历史点、guard version 或分组变化会拒绝原计划。所有候选先原子标记 deleting，才允许调用 provider。
- ExecutePrune 在发送前提交精确 dispatch 和 request_sent。响应丢失或进程接管只调用 provider.Observe，不再次 Delete。只有精确 dispatch、全部版本/删除标记不存在、原删除 writer 停止、证据引用和首次删除时间均通过，才能置 deleted/completed。
- AbortPrune 只允许尚无任何外部发送的计划，恢复原候选状态并增加版本；存在 request_sent 时不能取消后清空记录。PruneJournalProof 可把已确认 SQL 证据交给现有 Tombstone 签名流程，绑定首次执行人、时间、原注册和候选摘要。

此层提供通用 SQL 协调器、采集器包装器和清理执行器，**没有默认厂商删除实现或公网删除入口**。对接的所有恢复消费者与删除者必须使用同一控制库/registry，并由 owner 提供真正的资源停止和原生删除证明。它无法约束绕过协议的存储管理员操作；仅凭本地锁不声称拥有厂商端到期或全版本删除能力。旧的本地域包读取路径不会自动变成远端六域恢复，owner 组装时须显式使用 ProtectedCollector。

新增七张表及 singleton 初始行见 `control/upgrade-recovery-operations.sql`，初装 `schema.sql` 同步包含。程序不自动安装，本轮没有执行 SQL。使用新任务终态检查前，已有隔离控制库需要显式升级。测试使用 SQL driver 替身核对锁顺序、绑定参数、冲突、响应丢失与接管；尚不等同于真实 MySQL 并发验收。

## 六域 acceptance 专用准入

`profile.Config.AcceptancePolicy` 是独立策略的 ID/version/SHA-256 引用，必须同时配置 backup 模式和 SixDomainModule。owner 还需实现 `SixDomainAcceptanceOwner` 的 `ProbeAcceptance` 和 `VerifyAcceptance`。未配置策略、owner 未实现或证据未就绪时，没有可用的 acceptance 能力；不会从功能备份推断已通过验收。

管理员创建任务仍使用原任务 API：`kind=backup`、`purpose=acceptance`，并传 `acceptance_policy`（与 profiles 响应中的引用完全一致）。SQL 创建事务读取未过期的 profile、匹配策略并固定 profile revision；控制器执行及接管继续匹配原 revision。其他任务种类不能使用 acceptance；functional_test 不能附带 acceptance_policy。页面仅在选中的配置提供策略时展示验收选项，默认不勾选。

`SixDomainPlan.Acceptance` 固定 Policy、Proof、Target、KEK、ControlPlane 和六个域的独立 verifier 引用。Target/KEK/ControlPlane 必须与 manifest/bootstrap 精确对应，三个签名用途的 key ID 和实际公钥 hash 必须互不复用，artifact prefix 必须绑定 origin/backup/attempt。owner 的 VerifyAcceptance 必须**读取并验证真实证据内容**：固定版本/策略、六域范围、只读 verifier 与采集写身份隔离、目标故障域、KEK 可恢复性和控制面结果；引用合法并不代表这些事实成立。此接口不应执行恢复、重采或新建远端操作。

validating 阶段先冻结完整发布计划，再验证证据并将 `six-domain-acceptance` 授权记录加密保存到既有 Vault 表；绑定 task/request hash/profile revision/完整 plan hash/Proof。丢失提交响应后只能读取并比较同一记录。每次发布前重新验证 owner 证据、校验实际三个 signer；每个 Prepare/Sent 的 SQL 准入事务再次读取冻结授权，核对源补偿及存活 Worker。

`_ACCEPTANCE` 由已确认 index/manifest/marker 和冻结 cleanup/decision time 重算；签名合法但结论或 key 不匹配仍拒绝。注册必须已有完全匹配的 `_ACCEPTANCE` 且 local_acceptance=true；locator/bootstrap/core/matrix/acceptance key 均从冻结计划和已确认对象重建。提交本地结果时再次核对整条确认链。acceptance 成功终态只接受六域结果，不能使用旧用户/实例功能包提交记录代替。

不符合强一致、独立故障域、KEK 恢复或风险条件的备份可以产生 local_acceptance=false 的签名验收记录，但不会注册。任务“完成”表示流程完成；脱敏报告单独返回 `acceptance.local_acceptance`、`registered` 及注册 ID/hash，历史结论仍不授予恢复权限。该能力不新增生产恢复入口，也不自动执行真实迁移。

## Provider 网关服务端通用层

`recovery.NewGatewayServer` 接入固定 Identity/Location、`NativeGatewayBackend` 和 `GatewayDispatchJournal`。`host.RunProviderGateway` 装配 TLS 1.3 `RequireAndVerifyClientCert`、证书指纹到操作的白名单、配置 hash 固定的 backend 工厂、独立 SQL 发送账本和有界 HTTP 服务；只有注册真实 factory 后才能启动。`cmd/backup-provider-gateway` 提供配置检查入口，默认没有厂商 factory，正式运行会在读取凭据、连接数据库或监听端口之前拒绝。自有发布入口用 `RunProviderGateway(ctx, config, factories)` 显式注册 owner 实现。

- 接口只接受 canonical JSON POST /recovery/v1，限制正文 4 MiB、header 16 KiB、处理时限 1–60 秒；请求须匹配固定身份和根目录。未知操作、路径穿越、无 mTLS/未授权证书/无操作权限、未知或重复字段、过期请求均拒绝。错误响应为固定文本，不回显请求或原生错误。
- capabilities、observe、open、conditional_create、begin_snapshot、snapshot_page 都经过能力检查。快照请求另外核对所配置的准确 discovery mode；返回对象版本、快照身份、页号、游标、数量和排序不匹配拒绝。backend 的 Page 必须独立验证传入的 Snapshot 全部字段及 cursor/number 确属原固定快照，不能信任调用者重写的 count/hash/expiry。
- 响应绑定随机 Nonce、完整请求字节 hash、身份和短期 ValidUntil。open 返回同对象的头部回执及精确 Content-Length，流式核对长度/hash；消费者仍须认证完整密文至最终帧。
- 每次原生 Create 前，`control.GatewayDispatch` 在 SQL 事务中按 provider/root/key 锁定完整请求，并约束同一 scope/action 不可换 key。只有首次确定提交者可以发送一次。提交响应丢失、并发重复、进程崩溃后的再次调用只允许 Observe；不同请求字节冲突拒绝。未知写不会因本地超时或重启清空，过期 Create 请求须改走独立 observe 操作核对。
- 账本单独安装 `control/upgrade-provider-gateway.sql`，数据库名仍要求 cm_backup_control_ 前缀。它没有自动安装、重置或清理命令；记录至少保留到对应不可变 provider 根目录生命周期结束，丢弃账本可能重新授权未决写。开启写入时，全部网关副本必须共享同一账本。客户端控制器的 CatalogActions 与服务端账本分别保护两个发送边界。

示例为 [provider-gateway.example.json](../../../../examples/backup-controller/provider-gateway.example.json)，其中 hash 和证书指纹均为占位值，仅供结构检查。服务端不实现普通 S3 PUT/LIST 的“兼容假证明”：NativeGatewayBackend 必须验证真实的限定根目录凭据、key/hash/length/expiry 原生授权、精确版本读取、强 absent、固定清单和自身不可变身份；普通 404、客户端计时或即时 LIST 不满足合同。尚无这些资料时只交付接口；没有 delete/迁移/任意 URL 转发入口。

本批隔离测试覆盖 acceptance 策略准入、完整签名链、冻结授权/计划替换、终态与报告、真实 localhost mTLS 客户端→服务端调用、缺原生到期能力、弱/错误请求、丢失提交/原生响应、并发重复单次发送及离线命令。SQL 使用 driver 替身；尚未声称通过真实 MySQL 锁竞争或厂商原生授权验收。没有安装表、部署网关或访问参考服务器。
