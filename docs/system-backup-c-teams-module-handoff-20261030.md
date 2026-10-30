# C—Teams：迁移与公共模块交接（2026-10-30）

## 当前范围与结论

本轮按用户要求完成**第一阶段，以及第二阶段 A、B**。第二阶段 C 的完整 writer 屏障、恢复独立验证和最终生产全链路不属于本轮完成项。实现只在 `D:/test/backup/ClawManager`；不操作服务器，不触碰个人正式项目。阶段 commit 先留本地，全部完成后才推送 `backup`。

代码从 `origin/backup@304a15d9bc0de092975f3249c2190e56c9d6a393` 建立 `codex/backup-teams-adaptation`，保留 KEK authority、B 正式流、Runtime、数据库兼容及 Skill Hub 新实现。结束前再次 fetch，远端仍为该基线。没有整分支覆盖，没有恢复旧 Team 独立控制器、任务表写入入口或第二套门禁。

| 本地阶段提交 | 实现 |
| --- | --- |
| d3cf98bb | 第一阶段：旧历史、公共 UTC 等待、原操作核实、历史成品/密钥接口、旧 SQL/清理清单迁入 |
| 1350f63c | 第二阶段 A：原 SQL 快照的 Teams 范围、字段与关联、C 领域策略 |
| c5a6319b | 第二阶段 B：公共 Teams 模块、源读取、正式候选流与读回 |
| e6922f6a | 故障回归：授权回调不再能修改冻结采集范围 |

**已完成 C 侧代码适配，不等于生产备份产品已经完整接通。** 生产准入仍是 `workspace / functional_test`、`acceptance_ready=false`；未删除限制、伪造审批或用 functional DEK 代替正式 Generate。正式 worker 命令缺少原 source grant 时仍明确拒绝。

## 1. 第一阶段：迁入已有成果

复用较早 C50 已接收的 Team/owner、模板、状态与产物 normalizer、恢复库存和原暂停意图代码。仅迁入 `f09eb731`、`77c820bc`、`5bda334c`、`8f4ed883`、`0b20713f`、`762c03d9` 中缺失的实际能力。

- 旧 TeamData job 列表/详情只读，包含分页、首页外未完成统计和不确定结果提示；不启用旧 POST/retry/restore。
- 公共源 gate 使用持久 UTC 起点和任务冻结预算；超时不能解除其他任务保护，有副作用继续要求原恢复证据。
- `/api/v1/admin/system-backups/:id/recovery-actions` 与 `/reconcile` 使用公共权限、任务及 operations 账本；仅请求核实原 capture，不新建任务或 attempt。取消保持取消；活 owner、租约和 row_version 不变。
- 原请求幂等键支持 `lookup_only`：响应丢失/刷新后找回原 operation，未找到返回 404，不分配任务。202/succeeded 仅指调度受理，不能当作备份成功。
- 历史成品按 commit 原版本/长度/摘要读取，使用 `HistoricalTeamAuthority`；不以当前密钥代替历史版本。支持授权消费和已有 staging 格式的加密交接。
- 旧 SQL 通过显式 `legacy-team-sql.v1` 接公共数据库 restore worker；失败副本只读列候选，缺原 UID/退出证明不提供删除授权。

保留对方 `128_backup_installation_kek_authority.sql`，追加 `129_backup_v2_source_gate_wait.sql`、`130_backup_v2_capture_reconcile.sql`。001～128 未改写；当前 catalog 为 **171 文件**，生成器冲突仅重建 metadata，未覆盖新控制表分类或审批状态。

## 2. 第二阶段 A：Teams 范围及策略

### 2.1 原快照读取与字段保护

`team.ReadInventory(ctx, tx, mapping, users, instanceOwners)` 在调用方已经认证的同一个只读事务中读取 Team/owner、成员与实例关系。`publicadapter.WithTeamsInventory` 只接 C reader，保留原 VerifySource、writer 和恢复回调。

`SourceInventory.Teams` 为可选字段，旧计划省略该字段，原 JSON/hash 不因空字段改变。C reader 的输出、module 配置和授权回调均深复制；回调不能修改原冻结内容。

`team/schema.json` 明确记录当前 11 表的列与主键，`CheckSQLSchema` 在 discovery 检查本领域表和字段差集；新增未知字段、缺表、未知 Team 表拒绝。`SchemaSHA256` 对规范化结构计算，避免 Windows/容器换行造成不同摘要。摘要只标识 schema，不是审批或物理停写证明。

范围包括普通及 owner Team、模板、成员、共享卷、Redis 分组和明确对象引用。缺 user/instance、跨 owner 成员、缺 mount、Redis 分组不全、重复或无版本对象均拒绝。删除 Team 不进入必备文件范围；不据此删除源历史。

### 2.2 11 表及关联

核心 9 表：`teams`、`team_members`、`team_tasks`、`team_events`、`team_work_items`、`team_workflow_phases`、`team_event_outbox`、`team_workspace_file_audits`、`custom_team_templates`。

新增公共差集：`owner_team_provision_steps`、`owner_team_admission_locks`。前者加密保留创建步骤，恢复时活动步骤失败并替换原 operation 引用；后者原始归档保留，公共隔离恢复不恢复活动 admission。原不可变归档保留中断前状态和结果，不增加“恢复后继续原任务”功能。

owner 创建步骤还引用 **B-owned `northbound_operations`**：原始操作行进入同一公共 SQL 采集；C 在封存前核对引用。没有给 B 表伪造 owner 决策。其非空恢复需要 B 的精确 schema/规范化适配，未提供时继续拒绝，不能直接重放原操作。

C 的 11 项策略记为 `owner_recorded`，A/B/D 交叉评审均未冒填。全 registry 当前 139 对象；仍 draft，不能据本轮单域策略称全系统已批准。五张执行控制表的 35→40 排除边界仍按原 owner 复审保留。

## 3. 第二阶段 B：公共模块及真实采集

### 3.1 给 B/D 的可注册接口

- `publicadapter.NewTeamsModule(TeamsModuleConfig)`：纯构造，无 SQL/provider IO、无任务创建或调度。
- 与已有 `NewUsersInstancesModule` 一起交给 `NewCaptureModules`，再接原 `PublicCaptureConfig.Modules` / `WithCaptureModules`。
- Teams descriptor 为 required，要求 B-owned `users_instances_database / mysql / capture-database`；缺 SQL、Redis、共享卷或必要对象 part 时拒绝整个组合。
- **只存在一份公共 SQL 导出**。成员实例 workspace 复用 B 的实例 part；C 只贡献 Team 共享 PVC、Redis 与实际对象引用。
- `NewUsersInstancesModule` 将 C inventory 绑定到 `DatabaseSpec.teams_inventory`。两个实际数据库采集路径在封存前调用 `domain.VerifyTeamCapture`，检查 11 表、字段、Team/owner/member 范围及 owner 操作历史引用。遗漏不能成为成功 SQL part。
- 各 part 共用原 task/attempt/context 与全局索引。原 ProviderKey context 的索引不匹配时拒绝，不重新绑定 permit。

这些注册器和已有 B 注册器一样是**原任务作用域**：D 要在原映射固定后构造，不能把一次任务的模板全局缓存给其他任务；接手读取原计划，不重新发现或创建替代任务。

典型接入顺序：

```go
// observed is from the authenticated original discovery snapshot.
base = publicadapter.WithTeamsInventory(base, originalTeamProviderMapping)
bConfig.Source = observed
bRegistration, err := publicadapter.NewUsersInstancesModule(bConfig)
// handle err
cConfig.Source = observed
cRegistration, err := publicadapter.NewTeamsModule(cConfig)
// handle err
modules, err := publicadapter.NewCaptureModules(
    []publicadapter.CaptureModuleRegistration{bRegistration, cRegistration},
    originalCaptureContextResolver,
)
// handle err; retain D's original admission, inventory proof and writers.
```

冻结映射包括真实 PVC UID/namespace/claim、原 Redis 身份和数据库、对象版本及摘要。C 构造器检查对应关系；这些字符串本身不代替 D 的实际存储/身份认证。

### 3.2 Redis 与对象采集

新增 typed worker 操作 `capture-team-redis`、`capture-team-objects`，接已有 worker 解析、Kubernetes Job/ConfigMap builder、公共模块和正式 `RunFormalCapture`。不伪装成 workspace，不接 functional acquire/complete，不交付任意命令或源 Secret mount。

`CaptureTeamRedisScope` 只扫描所选 `claw:team:<id>:*`，固定 Redis run_id 和 database。一个有界 `EVAL_RO` 原子读取该 scope 的 DUMP/type/PTTL 和服务器 TIME，保留二进制值、stream 数据与绝对到期时间，不续 TTL。结果使用既有 Redis archive 读取格式，并携带实际捕获时间。

这证明**单个 Redis scope 的原子读**，不是多个 Redis 服务器同一物理瞬间。跨域捕获区间仍必须由 D/C 原 writer 屏障及固定 context 证明，本轮不伪造这个证据。

`CaptureTeamObjectRefs` 仅 GET/STAT 明确的原对象版本，核对长度与 SHA-256，不 LIST 整桶，不读 latest 替代丢失版本。无不可变版本的组合不准入正式 C 对象采集。

### 3.3 正式加密与源授权边界

`worker.TeamCaptureSources` 只接受 A/D 提供的原 source client 和必需的 `Authorize(ctx, originalInvocation)`。所有检查用独立 invocation 副本，防止授权 callback 改动 scope。授权缺失/撤销、错 server/db、超容量或错对象摘要不能返回有效候选。

采集复用 A `CaptureKeyJob` 和 B/C 已有 `CMBKGC01` framing/envelope；只有原 Generate，没有 functional key 兜底。候选文件 create-only；未知 key/provider 结果不自动重新 Generate。候选不是正式发布、catalog、capture certificate 或 acceptance。

**生产命令仍明确拒绝 SQL/Teams source credential 路径**：A/D 尚需交付原 Job 的 source credential lease、独立最小读取权限、formal material mounts/`--formal-config`、生产 composition 与 candidate observer/finalizer。没有用公共配置里的 DSN/token 或 KEK 权限代替这些能力。

## 4. writer 差集与后续责任

机器交接见 `contracts/system-backup/teams-domain-adapter.v1.json`。已有 work boundary：`team.pending_deletions`、`team.event_projection`、`team.maintenance_sweep`、`northbound.operation`；共享 HTTP admission 及 Runtime 的 Redis/workspace 写入还需完整差集和物理证明。**本轮只是清单，不把已注册或 lease 过期当作暂停/退出成功。**

| 接手方 | 未完成内容 |
| --- | --- |
| C 第二阶段 C | 对完整 Team writer 集合补停止/退出/原状态恢复证据；共享文件与产物引用的独立恢复校验；不重放 outbox、租约、旧凭据和中断任务的完整公共验收 |
| A | 历史映射/签名 key、原 source 读取身份和业务权限、source grant 的实际授权来源；源读取权限独立于 KEK |
| B | 真实目标 schema/生成列和 northbound operation 恢复适配；不能只改 import profile SHA |
| D | 原任务作用域模块装配、完整 writer/Runtime 控制、实际卷身份、formal material mounts/command、原 candidate 接收、正式发布/读回、隔离恢复及阶段安全续做 |
| A/B/D | C 策略的独立交叉评审；整个 registry/schema evidence 和新增执行控制表策略 |

这些依赖未实现的组合继续 not_ready。不能以“C 单域代码合入”宣布非空 Runtime 或全系统正式备份可用。

## 5. 本轮验收及证据界限

日志仅存本机 Git 忽略目录 `.local-dev/teams-backup-20261030/`，临时配置/容器不提交。合成数据运行在独占本机 MySQL 8.4、Redis 7 和 MinIO，不是现场数据或线上验收。

| 日志 | 实际执行与结论 |
| --- | --- |
| stage1-go.log / stage1-node.log | 第一阶段 9 个后端相关包、12 项前端/契约检查通过 |
| stage1-sql.log / stage1-wait-sql.log | 真实 MySQL 的原 operation 幂等、权限/取消/owner 保护，公共 UTC 等待及不解除外部 gate 通过 |
| stage2a-red.log / stage2a-owner.log | 先复现公共 SQL 规则遗漏 owner Team 步骤，再补规则与不重放恢复回归通过 |
| stage2b-public-sql-final.log | 真实当前 171 迁移 schema、非空普通/owner Team、模板/成员/状态/结果/产物；一次公共 SQL 捕获及 C 覆盖核对、缺表拒绝、原有隔离恢复通过。使用测试账号，不冒称生产 SELECT-only grant 验收 |
| stage2b-modules.log | 原公共模块/实际 Job builder 组合；一份 SQL、成员目录不重复、全部必要 C parts、跨 owner/缺域/上下文或 provider 索引变更拒绝；此项是计划构造，不是运行真实 Job |
| stage2b-data-final.log | 真实 Redis 固定 scope/TTL、真实 MinIO 原版本/摘要、历史成品固定版本适配通过 |
| stage2b-formal-readback-final.log | 真实非空 Redis/MinIO → 正式 worker 数据路径 → 原 C framing → 独立 AES-GCM 解密/解压读回原数据通过；key authority 使用 test fixture，不是正式 KMS/Job 授权验收 |
| source-scope-alias-red.log / worker-source-grant-final.log | 先复现授权 callback 改动 TeamIDs 导致原数据消失；独立副本最小修复后，真实数据与 worker 整包复测通过 |
| backend-all.log | 代码冻结点 c5a6319b 的 `go test -p 4 -timeout 8m ./... -count=1` 退出 0：75 包通过、16 包无测试。随后 e6922f6a 只修 worker callback 副本，整个 worker 包带实际源重新通过；其他包不重复跑 |
| node-final.log / frontend-build.log | 24 项相关前端/契约检查通过；Node 24、LIVE_READ=1/EVIDENCE_DOWNLOAD=0 的 TypeScript 与生产构建通过 |

catalog `--check`、Git whitespace 检查通过。未运行无关旧大契约脚本，也未将前轮其 23 项失败写成已修复。

复盘：复用已合入 C50，不搬回旧控制器；生成器冲突保留新基线后重建。两个夹具问题按根因修正：应用 SQL 的 parseTime=true 不能用于公共原始采集，改为与真实 worker 相同的 false；原 runtime 测试把第一次已结束的 tx 绑定到后续所有发现，已先用未改的 baseline 复现，再修为逐次同事务校验，未放宽生产检查。最终全量一次，发现 scope callback 别名后只复测受影响 worker。

## 6. 应用、回退与收尾

正常受保护迁移流程追加 129/130，核对实际账本、列、末尾枚举及 CHECK；不手改账本或跳过 gate。没有业务 schema DDL；C schema JSON 是受审源码形状，不是迁移脚本。

回退应保留追加 schema、旧备份与审计。若已有 `capture_reconcile` 操作，不能直接回退到不识别此类型的读模型；先核实原任务安全结果。受保护原操作仍按原身份和回执恢复，禁止强清 gate。

已核对本机 Docker Desktop 及任务标签，清理本轮独占 `teams-adapt-mysql`、`teams-adapt-redis`、`teams-adapt-minio` 容器及其卷；确认无挂载后删除 `teams-adapt-node` 缓存。其他对话容器、源数据、历史备份和未知副本未触碰。没有发行镜像、服务器部署或历史运维操作。

推送在本轮开发、验收和交接 commit 全部完成后执行，目标固定 `origin HEAD:refs/heads/backup`，不强推；最终远端 SHA 以最终交付回复为准。
