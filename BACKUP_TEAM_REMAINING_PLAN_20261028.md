# 新 backup 增量与 Team 整合：对比结论及剩余开发计划

> 用户最新决定：剩余 M2 实现和原 M3/M4 已重新收敛到最后两个开发阶段，执行以 [M3/M4 最终计划](BACKUP_M3_M4_FINAL_PLAN.md) 为准。本文保留来源差异和历史计划，不代表旧阶段全部完成。

> 2026-10-28 本轮执行更新：M0/M1 已提交，M2 真实工作区 functional 链路已通过但完整阶段未完成。当前实现、验收边界、未完成项和效率反思见 [M0～M2 执行记录](BACKUP_M0_M2_EXECUTION.md)。下文保留原完整范围；不能把 M2 未接的生产 owner、多数据域/所有 writer 和未知结果恢复挪成已完成或仅部署问题。

日期：2026-10-28。本文以实际源码和本轮定向检查为依据，替代此前交接文档中关于“来源没有 runner/执行循环”的旧判断。本文是开发计划，不是完整功能验收报告。

## 1. 本轮实际完成与准确基线

| 项目 | 当前状态 |
| --- | --- |
| 备份专用目录 | `D:/test/backup/ClawManager` |
| 备份目录同步结果 | 从干净的旧 `main@576e4bb5` 切换到新建的本地跟踪分支 `backup`，与 `origin/backup` 相同 |
| 新来源 | `4fe83bcde5a8a693dddb2635e9a3e397d6e3472e` |
| 上次评审来源 | `8ef5fa7fd4df45f6306e910705db01f589266ba7` |
| 新来源增量 | 13 个可达提交、759 个变化路径；backend 356、docs 333、scripts 33、examples 20、contracts 8、frontend 4、CI 2、deployments 2、属性文件 1 |
| 我们的整合目录 | `D:/test/ClawManager-2` |
| 我们的整合分支 | `codex/backup-team-integration@6dcdbb75` |
| 我们新增阶段提交 | `64bdfcc1`、`6dcdbb75`，仍在本地；远端整合分支为 `288d74a9` |
| 本轮改动范围 | 同步备份 checkout、源码比较、定向验证和文档；未合入业务代码、未 push、未发布镜像、未操作服务器 |

同步没有覆盖未提交文件；两份 checkout 开始时均干净。旧本地 main 和我们的三个阶段提交均保留。Runtime 和个人项目未改动。

## 2. 新代码真正补齐了什么，还缺什么

| 能力 | 新 backup 的真实实现 | 我们的实现 | 整合决定 |
| --- | --- | --- | --- |
| 用户/实例数据面 | 新增 `systembackup/domain`、workspace、staging、flow、kube、worker、quiesce、publicadapter 等，包含 SQL/文件采集、加密、隔离恢复、WorkBuddy Lite 身份适配 | 主要是原 Team 底座和之前的通用备份模块，未接实际新 worker | 优先复用新实现；不能再次手写一套 collector |
| 公共 runner | `publicadapter.NewPublicRunner/NewLinuxDispatcher`，Prepare/Capture/Recover、DescribePlan、writer 构造、relay 认证入口 | 有 dispatcher ABI，没有完整生产 runner | 采用新公共 runner，保留它的原 bytes、停写/撤权顺序和认证边界 |
| 执行循环 | `TaskExecutionLoop`、`DurableExecutionStore`、`ExecutionJobPorts` 已可调用 | SQLExecutionQueue 只完成任务领取和接管识别 | 将我们的真实 SQL 领取改造成新 `ExecutionWorkStore` 的生产实现，复用循环，不另写循环 |
| 执行授权/领取 | 新 `SQLExecutionAuthority`、`SQLTaskClaimStore.AcquireWithReceipt`，领取 CAS 与历史回执同事务 | 当前 claim/队列检查存在，但没有新公共回执协议 | 用新回执协议补强我们的领取；不能用 row_version 推算领取历史 |
| 不可变执行记录 | `SQLExecutionRecords`，公共 task-plan 原 bytes、staging AEAD、plan/capture_result、未知提交读回，最大约 8 MiB | 自有 AES-GCM PlanStore、64 KiB 计划上限，外加专用 Job plan schema | 以公共记录为新执行路径唯一持久格式；原实现冻结兼容，不双写两份权威计划 |
| Job 执行 | 真实 kube.Runner、ConfigMap/Job intent、Ensure/Observe/Stop，具体 owner 尚缺 | 单次发送意图、UID 检查、丢响应不重发；尚无 Observe/Stop/Recover | 复用新完整 Job 层，把我们的丢响应/同名换 UID 测试迁入公共层；不能启用两套 sender |
| HTTP writer | 新 SQLTaskWriter 已有同事务保存、请求规范化、TaskAdmission/guard 插槽 | 有真实授权事务、部署 profile/readiness/容量、immutable inputs、真实 SQL 测试 | 以公共 writer 为核心，将我们已验证的准入条件接成 TaskAdmission；保留事务和回滚测试 |
| 详情/manifest | 新 SQLTaskDetails 要求 CurrentTaskFacts 和 ManifestReader，支持正式 manifest | 已有真实 SQL 详情、未就绪时独立读/取消 | 合并为实际事实 reader；manifest 未发布时明确缺失，不因 manifest provider 缺失把历史/取消一起关掉 |
| 取消 | 新 API/实验控制面各有逻辑，不能据名称判断协议一致 | 未启动任务安全取消、过期 claim 不冒认停止、审计失败回滚 | 保留我们的已验证行为；运行中取消交同一公共恢复流程 |
| Team 门禁 | 来源补了多个 API/后台 writer 的准入点；生产 main 中 `backupGate` 仍为 nil，部分入口使用全局 mutation hook | 旧业务 `system_backup_gate` + v2 engine binding/共享适配，真实 SQL 验证 | 保留我们的单一业务门禁，接入来源新增 writer 点；公共 fence 必须与该门禁受控映射 |
| 安装冒烟 | 新手动 kind workflow、Broker TLS、先检查 MinIO 镜像，再部署 | 有现有镜像构建/部署逻辑 | 合并独立安装冒烟；它不代替功能验收，也不成为每次开发必跑的大工程 |

### 生产空接点仍存在

源码搜索确认，非测试代码没有为 `systemBackupExecutionOwnerLink` 和 `systemBackupTaskOwnerLink` 赋值。新 `DurableExecutionStore` 仍要求实际 Scheduler；循环本身不提供 SQL 阶段推进。新 `ExecutionJobOwner` 仍要求实际 Admit/Bind/Read/Evidence/Revoke/Stopped。A 的真实执行用途授权、密钥、worker grant、认证结果，C 的最终发布/catalog 以及完整恢复接线尚未齐备。

因此，“没有执行循环”已经过时；准确缺口是“循环和执行组件已存在，但生产依赖、持久调度和恢复闭环尚未装配”。后续应补接点，不能重新实现这些组件。

### 三套控制概念必须收敛

1. 我们当前稳定的旧备份 Store/控制器及业务 gate。
2. 新公共控制面（来源未加前缀，我们映射为 `system_backup_v2_*`）。
3. 来源 `systembackup/control` 私有控制面，拥有 `system_backup_maintenance` 等独立表。

来源已把私有 controller 限为 `--experimental-isolated-lab`，生产 server 拒绝其配置。保留领域能力不等于启用私有控制器。私有表、任务和路由不得进入生产调度；保留为隔离实验代码或明确实验入口。生产只保留一个任务状态权威、一个业务停写事实和一个 Job sender。

## 3. 冲突复核与具体合并方法

通过旧来源→新来源的增量与 source-map 关联，找到 43 个重叠候选。以旧来源为祖先的逐文件 `merge-file` 预演得到：13 个文本冲突、8 个双方新增、14 个文本可合并、8 个目标没有该原路径（有些已移入 reference 或改为整合脚本）。这不是完整分支 Git merge 的冲突数；路径映射和语义冲突更多，必须单独处理。

### 3.1 不直接执行整分支覆盖或 ours merge

继续在 `codex/backup-team-integration` 做基于来源映射的增量适配。旧来源固定 `8ef5fa7f`，新来源固定 `4fe83bcd`，Team 底座固定 `be7da27d`。对每个源码模块保留原来源 SHA 与我们的适配说明。不要用 `checkout --theirs` 覆盖服务文件，也不要用“merge 成功”替代执行链安全。

### 3.2 按文件群处理

| 冲突群 | 处理方式 | 最小证明 |
| --- | --- | --- |
| `server/main.go`、服务调度/Sync/Team/北向/WorkBuddy | 以我们的最新业务实现为底，只移入来源新增的 writer 准入、取消传播和释放错误处理；全局 mutation hook 与注入 BackupGate 必须绑定同一实例，初始化先于后台 Start | 普通/批量北向、续期、Team outbox/event/monitor、物化任务在 gate 打开时正常，关闭时无写入；旧执行未退出不能放行 |
| `handlers/system_backup_handler.go` | 双方同名但完全不同：我们是旧 Store，来源是私有 control；保留我们的旧 handler，来源私有 handler 如确有实验调用则改名并隔离，不覆盖原构造函数 | 原 `/admin/backups/system` 和旧任务可读；实验 API 不能因导入而自动注册 |
| `system_backup_tasks_live.go`、api sql_writer/details/submission | 按上表统一公共 writer/真实准入和详情；吸收来源 ExpiredTaskError 权限复核、manifest，保留我们的安全取消、不可用 profile 时仍可读可取消 | 同事务授权/容量/审计，重复请求、响应丢失、撤权、未就绪无残留 |
| controller/bootstrap/claims/execution_* | 将来源 SQL/锁序/回执/新增记录统一映射至 v2；保留我们的旧 engine 排他和 gate | 两控制器竞争只有一个执行；失 claim 的旧执行不能更新状态或创建资源 |
| frontend service/router/admin pages | 保留最新 Team、北向 UI、旧备份页面；来源公共 manifest/结果能力定向移入，私有实验页不替换正式页 | 原页面和真实新 DTO 都可用；查询失败不触发变更请求重试 |
| `.gitattributes`、CI/build | 保留现有构建和语言/Team 资源；合入来源 LF 固定规则、公共 worker 打包和独立手动安装冒烟 | 无强制 MinIO 全仓库变量；缺镜像/私钥不生成假成功；安装不等于恢复成功 |
| contracts/registry/测试 fixture | 对生成物和合同版本整体更新；不逐块手拼旧 hash | 生成两次无差异，普通 freshness 通过；严格未评审项仍如实阻断 |

13 个文本冲突路径：`.gitattributes`、`.github/workflows/build.yml`、`server/system_backup_tasks_live.go`、`migrationcatalog/catalog_test.go`、`northbound/core_service.go`、`services/k8s/workbuddy_prewarm.go`、`runtime_proxy_policy.go`、`runtime_scheduler.go`、`skill_package_materialize_worker.go`、`sync_service.go`、`team_service.go`、controller/bootstrap、`contracts/system-backup/v12/admin.openapi.json`。双方新增的 writer/details/handler/前端 service 必须按语义整合，不能因没有共同祖先就任取一份。

### 3.3 SQL 和计划兼容

- 新来源只增加一个 migration：`082_add_system_backup_execution_records.sql`。来源实际目录 137 个文件，但 bootstrap/registry 仍 pin 136。本轮只读复跑 inventory/contract `--check` 均 exit 1，未用 `--write` 修改来源。
- 我们目录已有 162 个迁移。新 SQL 追加未占用序号并映射新表及 FK；不能覆盖我们的 082/119/120/121，也不能把来源 137 当成我们的最终目录数量。预计新增一个为 163，最终以脚本和真实迁移结果为准。
- 来源 `system_backup_execution_records` 尚不在我们的 sql-map 内。补为独立 v2 记录表，并更新 runtime grants、registry、catalog、bootstrap pin、import/schema profile；旧来源 136/137 的已知导入 profile 和目标 catalog 必须分开。
- 我们的 120/121 属于已提交迁移，保留字节。新公共执行记录替代新任务的自有计划/发送路径，旧表如存在数据只读保留。迁移前查引用和既有记录：没有证据不能假定全空，也不能把两种计划转换后继续沿用原签名/hash。
- 原 PlanStore 64 KiB/AES-GCM 与来源公共 plan 约 8 MiB/staging framing 不兼容。不要强塞转换。新任务用公共格式；已有旧格式任务按 schema 显式分流并先收敛/停止，无法安全续做则保留数据并显示原因。两个读取兼容器不代表允许两个执行器并行。
- 数据表前缀替换必须覆盖生产 SQL、grant probe、FK、registry、bootstrap、记录解密绑定和实际调用；不能全仓库替换字符串污染历史证据和原合同。

## 4. 业务数据覆盖不能沿用旧清单结论

新 schema-registry 已从 100 个对象变为 122 个，记录策略 68、待定策略 54、待交叉评审 68；新 082 的登记还未同步。此前“32 个待定”属于旧基线，不能继续使用。

来源新增了用户/实例与 WorkBuddy Lite 的恢复规则，也补了 `runtime_rollout_checkpoints` 仅留证据、`instance_workspace_write_intents` 不重放、北向新 scope 恢复后不激活等策略。这些应保留，但仍须对我们最新 schema 逐项差集，特别是 owner Team、模板、成员、任务/事件/outbox/控制通知、运行池升级协调、文件编辑意图、费用和 Skill 引用。

恢复要同时证明数据保留与危险状态失效：身份/owner/FK/历史/文件内容保持；活动任务、lease、旧 token、待发送控制消息不自动重放；实例保持停止/隔离，由用户受控启动。源备份原文不因目标归一化被修改。未知字段/策略不得静默丢弃，也不能填写虚假审批人。

## 5. 可执行剩余开发顺序

每阶段产出代码、针对性证据和一个可回退 commit；保留所有原功能。下面的时间是工作块预算，不是未经验证的总工期承诺。每个工作块结束必须报告实际出口和阻塞，不再用一批新增文件替代可用能力。

### M0：增量收敛（先做，约 30～45 分钟工作块）

1. 固定本报告的两端 SHA 和旧 source-map；移入独立领域库、公共 ABI、runner/loop/records/Job Ports，实验 control 保持隔离。
2. 完成上述映射和冲突群适配，保留最新业务文件；不全量搬运 333 个 evidence/docs 路径。只保存本次依赖的合同、来源说明和必要测试 fixture。
3. 新增 execution records 映射迁移、目录 pin 和最小 registry 差集；更新来源映射，普通 freshness 必须消除；pending 审批单独列出。
4. 出口：受影响包可编译，schema/SQL映射一致；已有 Team、旧 handler、安全取消回归通过。此时仍不启用新执行。

### M1：唯一持久调度和授权（一个纵向工作块）

1. 将我们的事务准入实现为公共 TaskAdmission，保存同一 canonical config/input；readiness 由实际完整执行组合产生，不能由 HTTP 或测试表写入代替。
2. 用新 AcquireWithReceipt 接通 SQLExecutionQueue→ExecutionWorkStore：领取、续约、attempt、阶段 CAS、Record、错误/未知结果收敛；锁序统一，禁止嵌套独立事务。
3. 接真实 ExecutionAuthorization、task-scoped record keys 和原记录读回；历史创建权限不能延长为后台执行权限。逐项列出所需部署身份、用途、refs 和到期/撤销来源，先核查现有配置可复用材料。
4. 出口：真实 MySQL 中“提交→领取→Prepare→保存原计划→重启读回”成功，响应不明/并发/失权失败无重复；尚未调用源采集时明确显示准备完成，不标备份成功。

### M2：实际采集并恢复源业务（优先做出的完整可用链）

1. 同一实例装配业务 gate、来源 writer registry、公共 PauseIntent/ACK/Resumed 和受控 fence 映射；覆盖 SQL、Redis、Runtime、文件/对象和后台 writer。
2. 从持久原计划 DescribePlan 建 ConfigMap/Job journal，接真实 Worker grant/认证 relay/结果 reader 和停止证明。复用新 kube.Runner，不再扩写我们的单次 Ensure。
3. 全部 writer 停写确认后才能创建会读源的活跃 Job；完成封存后撤权、停止并确认实际 Pod/worker 退出，才按原状态恢复业务。租约过期、Job 404、Deployment 缩零都不能单独证明停止。
4. 恢复使用独立当前 recovery authority；forward deadline/cancel 不能取消补偿。失去授权时保留原数据和 ledger，显示可执行的恢复动作，不永久假 running，也不提前释放停写。
5. 出口：一组小规模真实隔离环境“提交→采集→源业务恢复”，同一 task/attempt/实际 UID/文件与 SQL 证据闭合；注入创建响应丢失、控制器重启、未知停止、迟到结果各一例。失败不得造成第二份执行或错误放行。

### M3：发布、独立恢复和当前数据覆盖

1. 封存副本交现有 C provider/finalizer/catalog，上传不重新读活动源；处理 PUT/append 结果不明，先查原事实。
2. 联核 A/C 的签名、授权和精确原 bytes；manifest/acceptance 来自正式验证，不能拿 staging checkpoint 充当最终成品。
3. 完成第 4 节当前 schema/数据策略差集，用合成多用户+owner Team+实例/文件完成隔离恢复，独立只读 verifier 对内容、引用和危险状态逐项检查。
4. 出口：同一真实备份可恢复到隔离目标，源业务可继续；损坏密文/缺对象拒绝；目标不会自动发任务、调用模型、结算或启用旧凭据。通过后才显示“验证可恢复”。

### M4：剩余用户操作、部署及交付

1. 接真实进度/health、运行中取消、核实并继续、原操作安全重试、恢复业务和隔离恢复。按钮以实际服务端能力和状态启用，失败说明保留了什么及下一步。
2. 校验实际最小 grants、Broker TLS、worker镜像/挂载/网络和下载；构建 app/worker 所需镜像。现有旧镜像回退必须认识新表和隔离类型，不能直接降到混查两类控制面的版本。
3. 最终才跑安装冒烟及功能验收；分开报告。发布仅在用户确认的目标环境执行，不能把本计划当作新服务器操作授权。
4. 必要验收通过，commit→显式 push `backup-origin HEAD:refs/heads/codex/backup-team-integration`→核对远端 SHA。是否合入 `backup`/Team 稳定分支属于后续交付决定，不直接覆盖同事分支。

## 6. 验收与效率约束

| 门槛 | 必须检查 | 不重复做什么 |
| --- | --- | --- |
| 合并兼容 | 原 Team/北向/WorkBuddy/旧备份关键测试、新 ABI 与迁移映射 | 未改的页面不反复构建；不跑数百实例压力测试 |
| 真实 SQL | 非空 Team 基线升级、双启动、领取/回执/计划事务、权限与取消、未知 commit | 不用 driver mock 代替真实 SQL；不多轮重跑所有来源历史实验 |
| 真实执行 | 一次小规模隔离采集/恢复源/发布/独立恢复，加关键故障点 | 不以安装健康检查、fixture UI 或模拟 Job 代替 |
| 最终提交 | 改动相关定向测试；后端改动节点一次 `go test ./...`；前端变动才 build；diff/catalog/秘密检查 | 同一源码已通过且证据可复用时不再反复验收 |

开发前先核查隔离环境、实际授权材料、worker镜像和存储是否可用。缺少材料先给出精确缺项及可继续开发部分，不加空 owner 接口、不虚构证据、不扩大权限。下一阶段必须优先缩短未接通的真实链路，不重复做来源归档、框架或健康页。

本轮仅做两个新的必要验证：新来源 controller/执行记录/Job桥接定向测试通过；inventory/contract freshness 均失败。没有为了分析运行全量后端、前端、镜像构建或服务器演练。

## 7. 完成标准与接手要求

完整完成必须同时具备：两份代码的既有功能保留、一个生产任务与门禁权威、真实任务可执行且有边界的故障恢复、源业务安全恢复、正式成品发布、独立恢复通过、用户操作可用，以及目标环境实际验收。阶段 commit 和测试通过分别记账，不能再次被称为整项完成。

当前源码差异、冲突预演和测试原始记录放在本机忽略目录 `team-optimization-docs/backup-20261028-*`、`backup-new-source-*-20261028.log`；不要提交本地凭据、运行缓存或所有来源 evidence。旧交接文档继续保留历史适配细节，以本文更新的来源状态和执行顺序为准。
