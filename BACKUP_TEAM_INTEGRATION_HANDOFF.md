# 备份专用版与 Team 版整合：当前交接说明

更新日期：2026-10-29。本文件是**当前状态和后续工作的唯一交接入口**，已替换旧交接正文；旧阶段计划和执行说明已删除，历史可通过 Git 查询。原始设计、合同、来源映射和验收证据保留用于溯源，不作为当前完成状态。

## 1. 先读结论

- **整合尚未完成。A、B、C、D 均为部分完成，E 尚未完整开展。不是“只剩 B”，也不是“只差验收”。** 之前把普通 Team 数据备份子链的完成，表述成原计划 C、D 全部完成，不准确，以本文件为准。
- 已处理的文件没有遗留 Git 冲突，代码能够编译，必要回归通过；**旧/新执行器、Runtime 停写/恢复、正式发布及独立还原的生产衔接仍有代码缺口**。
- 当前普通 Team 数据备份具备实际采集、加密发布、隔离恢复、读回和重试能力，一致性为 `best_effort / team_data`。不能用它替代正式 v2 全系统强一致能力。
- 正式 v2 已有一条实际生产入口的工作区功能链，但目前要求**源 instances 为零、仅 workspace、用途 functional_test**；结束于 `validating`，不代表正式成品已发布或可独立恢复。
- 不要启用全系统 v2、不删除非空源限制、不伪造 Runtime 能力或任务成功。没有确认旧执行退出时，继续保留数据保护。
- 用户最新要求是：**把 A～E 全部剩余工作写清楚，将当前已提交的进度推送到 backup-origin 供接手**。这次推送不表示功能全部完成，不包含服务器部署授权。

## 2. 仓库、分支和合并方式

| 项目 | 当前事实 |
| --- | --- |
| 集成工作目录 | `D:/test/ClawManager-2` |
| 集成分支 | `codex/backup-team-integration` |
| 最近业务代码提交 | `56b2fa957f4aca86dbf0159f1e34c7f0eb41f520`；本次只更新交接/索引/来源映射，不改业务代码 |
| 推送目标 | `backup-origin` → `https://github.com/huihuihuizhang/ClawManager.git`，同名分支 |
| Team 底座 | `be7da27dff85c2daf3321b8245ffdab024e67853` |
| 最新已核对的备份来源 | `backup@4fe83bcde5a8a693dddb2635e9a3e397d6e3472e`；“已核对”不代表远端以后没有新提交 |
| 备份来源 checkout | `D:/test/backup/ClawManager`，保留 `backup` 分支，没有用集成代码覆盖它 |
| 核查过的 Runtime checkout | `D:/test/AgentsRuntime`，本轮未修改；不能据本地源码推断所有线上镜像能力 |

合并采用**逐模块移植、共同文件按调用点适配**，没有整文件覆盖 `main.go`、工作区服务、Runtime 客户端或调度器，也没有用 `ours` 假合并。备份来源没有整分支 merge 认祖；后续同步应按 `docs/backup-team-integration/source-map.json` 比较，不仅看 Git 的 merged 标记。

保留了 Team/owner/北向、WorkBuddy、登录、实例、Gateway、旧备份及历史数据。来源控制表适配为 `system_backup_v2_*`，历史 SQL 不重写，迁移总数目前为 **164**。SQL 映射见 `sql-map.json`，原文件在 `reference/`；参考 SQL 不能直接作为自动迁移重复执行。

**冲突状态：**文本/编译冲突已解决；语义衔接尚未全部完成。例如旧 `SourceRestarter` 使用私有任务/日记，新 v2 使用公共任务授权，不能直接混用；升级停止会保留实例 fence，不能直接用于备份后原处恢复。这些是待开发项，不是 Git 冲突标记。

## 3. 三条入口必须分清

| 入口 | 代码/记录 | 可用范围 |
| --- | --- | --- |
| 既有 legacy 备份 | `systembackup.Store` 等既有入口 | 保留原行为，不因移植自动切换引擎 |
| 普通 Team 数据备份 | `TeamDataService`；`/api/v1/admin/system-backup/team-data`；`system_team_data_backup_jobs` | 实际 best-effort 数据备份/隔离恢复及管理；不是全系统强一致 |
| 正式公共 v2 | `system-backup-v2-controller`；`systembackupapi/systembackupcontroller/systembackupexecution`；`system_backup_v2_*` | 当前仅明确的零实例工作区功能 profile，完整全系统能力未完成 |

以上控制记录不能通过“另建一个旧任务再同步状态”接通。必须维持原任务身份、唯一状态权威和共享物理门禁。关闭新入口不应删除历史、撤销合法独立恢复权限或让旧接口失效。

## 4. 已完成且有证据的内容

| 已完成内容 | 真实范围和限制 |
| --- | --- |
| 数据库与来源适配 | 保留 Team 迁移/历史账本；新增控制元数据隔离、迁移/采集排他；来源 schema 导入只能进入符合要求的隔离副本，不覆盖活动数据库 |
| 普通 Team 数据兼容 | 保留 northbound owner/resource_scope/display_name、成员图标、模板与文件审计；恢复归一化旧运行投影，不重放旧创建操作/活动任务 |
| 普通数据链 | 真实 SQL/Redis/对象/文件采集、加密发布、隔离恢复与只读内容核验通过；该组 Kubernetes 配置边界是受控 client，不能算全系统真实停写验收 |
| 普通用户重试 | 真实 API/页面已接：同键找回原请求；发布不明先查原成品；恢复失败先归属清理，再用稳定子请求续做；取消不自动继续；续做等待有界 |
| 普通后台准入 | 领取前参加服务器共用物理门禁；关闭时保留 pending；首次等待写明确 UTC 时间，轮询不续期；超时只结束本次未采集任务，不解除其他 owner 保护 |
| 结果写回异常 | 同步执行与取消监控退出后再处理丢失结果；普通 worker 不永久占位、不重跑原外部操作；离线恢复读回权威终态，仍不确定则保留副本并明确报错 |
| v2 任务基础 | 实际授权事务提交/幂等、详情查询、持久领取、加密原计划、Job 单次发送与原对象查回、真实进度投影、受阻诊断 |
| v2 工作区生产链 | 实际生产 controller、选主、签名配置、TLS HTTP 创建、实际 Worker/Job、封存核验、实际退出、源 Deployment 恢复、进入 validating、授权取消与原数据保留；仍是零实例功能 profile |
| 原恢复证明 | 暂停前同事务保存原意图与独立 checkpoint；缺行只恢复意图，不编造 ACK；释放前核对完整冻结集合、原 UID/代数、collector 撤权/退出与逐 writer 恢复回执 |
| 迟到和权限失效 | 已实现路径保留终态保护和当前 owner/代数校验；特定工作区故障可在 forward 权限撤销后使用独立恢复身份处理同一原操作 |
| Gateway 备份准入 | 不把注册记录缺失当作原本停止；不把普通 DELETE/404 当作完整停写能力。要求实际备份隔离及原处恢复能力；当前核查的 Runtime 不提供，必须暂停前拒绝。**这是安全拒绝，不是 Runtime 备份已实现** |
| 恢复控制权隔离 | 新增5张 v2 执行控制表已进入精确恢复排除清单；不将旧租约、授权和执行日记恢复为活动控制权；这不代表整个业务 registry 已完成评审 |

最近增量提交：

| 提交 | 内容 |
| --- | --- |
| `f53772cc` | 当前 owner Team 数据恢复兼容 |
| `c38083a2` | 普通重试、归属清理、持久恢复续做及界面 |
| `f6a8e382` | 原意图丢失后的真实恢复证明、结果写回异常 |
| `4ce54ccc` | Gateway 缺注册记录/确认停止边界；随后由 f75788f3 补严恢复能力要求 |
| `ca39bcfb` | 普通后台执行纳入共享准入 |
| `64f47bd2` | 源准入等待超时与明确展示 |
| `5629c249` | 离线恢复结果不明确时不重跑 |
| `f75788f3` | 拒绝只有升级停止、没有备份原处恢复能力的源 |
| `56b2fa95` | 等待预算使用明确 UTC 起点，兼容旧创建时间时区 |

## 5. 剩余任务：A～E 都不能销项

### A. 完整生产采集、正式发布及唯一状态权威：部分完成

**还缺：**

1. 将 mysql、redis、object_storage、deployment_resources、secret_bundle 接到同一公共 v2 任务；目前生产 `BuildParts` 只有 workspace，数据库凭据请求仍拒绝。
2. 为每域接最小数据面身份、冻结范围、真实容量和封存结果；不能把 controller 写库连接交给 Worker，不能缺域却报全量成功。
3. 将 `validating` 之后接正式校验/发布：原 sealed bytes、独立 KEK/signer/provider、精确对象版本/摘要及不确定远端写入日记。
4. 发布回复丢失先核实同一原操作，源恢复后仅继续封存副本上传，不能重复采集或覆盖唯一备份。
5. 对未观察到原对象的已发送请求，补受支持的封禁/停止证明；不能凭404、TTL或租约到期认定原执行不存在。

**主要位置：**`systembackupexecution/deployment_platform.go`、`public_jobs.go`、`public_runtime.go`；`systembackupcontroller/execution_capture_gate.go:FinishCapture`；`systembackupproducer/finish.go` 和现有 recovery/provider/envelope 原语。

**完成标准：**非空源从真实公共入口得到包含全部请求域、可读回验证的正式不可变成品；失败/响应丢失不重复，不遗留活动源停机或假成功。

### B. 全部实际写入者停写、退出和原状态恢复：部分完成

**还缺：**

1. `deployment_platform.go:platformProfile` 接上 `publicadapter.NewRuntimeWriterBuilder` 的非空 Gateway/Pod/Deployment 和平台参与者；覆盖实际 Lite/Pro、OpenClaw/Hermes、在线/原本停止者及相关后台/工具写入。现有 builder 和测试不等于生产回调已接。
2. 暂停前冻结原身份及可恢复材料。Lite 原 `RuntimeAgentCreateGatewayRequest.Environment`、Pro 原 Pod 可能含秘密，需按原 authority/密钥加密留存；不能放到明文 `runtime_writers.original_json`，不能停止后用当前配置拼回。
3. 增加公共任务的原重建发送/结果日记和唯一恢复代数。迁移123的 writer 表只有 paused/resumed，缺这部分；必要 schema 只能追加并同步 catalog/最小 grants。
4. 公共 `ClaimRestart/CompleteRestart` 同事务核对实例/原 generation、Lite runtime_pod_id/gateway_id/port/workspace、Pod UID/slot与当前恢复授权，再记录唯一发送与结果。写回 `instances`/`instance_runtime_bindings` 需明确的独立最小恢复授权，现有 source 只读连接不能承担。
5. 真正实现 Runtime 备份停止与原处恢复协议。核查的 `D:/test/AgentsRuntime/.../gateway/safe_stop.go` 只支持 OpenCode/process_group；`manager.go` 的 stopOperation 还会拒绝同实例后续 Create。完整工具树可能逃出进程组，不能据它宣称完整停写。`/v1/backup/capabilities` 未在所核查源码中实现。
6. `backup_safe`/`backup_resume` 当前是后端的暂停前准入要求，旧 Runtime 默认不满足。**不能只把两个布尔值置 true、清 stopOperation 或放开 fence**；必须实际支持原 operation/实例/Pod/代数绑定下的退出及原处恢复。
7. 以上真实可用后才能扩 `deployment_service.go:PublishReadiness` 和支持范围，不得先删零实例限制。无法证明原执行退出时，显示明确受阻并保留保护。

`control/source_restart.go:Claim/Complete` 可参考原语义，但绑定旧私有任务/日记，禁止直接混用或创建影子任务。加密材料可参考 `systembackupcontroller/sql_execution_records.go`，需同步正式 record-kind 合同。

**完成标准：**一个小规模非空源覆盖必要 Lite/Pro 与在线/停止状态，实际退出可证、原身份恢复/绑定读回正确，无重复执行、不启动原本停止者，异常能安全收敛。

### C. 当前业务数据策略及正式成品独立恢复：部分完成

**还缺：**

1. 完成真实 schema 与 registry 差集及逐项策略。当前 `contracts/system-backup/v12/schema-registry.json` 共127对象、59项待 owner review、68项待交叉评审；这些不能用生成摘要或伪造批准消除。
2. 对 Team/owner/模板/成员/群聊/产物/FK、北向会话、WorkBuddy、费用/配额等明确保存、恢复、重建、撤销、仅留证或丢弃规则。普通 Team 表适配完成不代表全部公共策略完成。
3. 从 **A 的正式成品** 在独立 DB/Redis/对象前缀/卷/命名空间恢复，使用独立目标身份，不继承源执行权；分步日记支持半恢复和重启。
4. 独立 verifier 核对实际内容与关系；证明旧活动任务、outbox、租约、凭据没有重放/激活，且不能写源。损坏/缺片/错密钥/越界/目标误指必须拒绝并保留数据。

**主要位置：**registry、`systembackup/domain`、`team`、`systembackupresources`、`systembackupbusinessa`、既有普通恢复和正式 producer/recovery 适配。

**完成标准：**正式 v2 非空成品独立还原可读回、业务关系正确、危险状态不重放；源不受写入影响。现有 best-effort 普通恢复证据不能代替此出口。

### D. 完整用户操作、状态展示与故障处理：部分完成

**还缺：**

1. 将正式 v2 的 manifest/授权下载、独立验证、隔离恢复、重试、核实继续、恢复业务等剩余动作接到实际能力。现有工作区创建/详情/取消和普通 Team-data 重试已做，不需要重写。
2. 不确定结果、恢复受阻、等待依赖、已退出未结算等要显示真实原因及允许的下一步；不能无限表现为正常 running，也不能靠解除保护把页面变绿。
3. 断线/重复点击/服务重启找回原操作；需要清理时只处理归属副本，不覆盖原备份，不新建重复根任务。
4. 两条入口及历史、权限、文件传输分别适配；按钮依服务端真实能力，不通过前端解除禁用冒充实现。

**主要位置：**`backend/cmd/server/system_backup_read_live.go`、`system_backup_tasks_live.go`、相关 handlers/API，`frontend/src/pages/admin/backups` 与 services。

**完成标准：**用户能从真实页面完成全链，看到失败原因并安全继续；UI、任务、实际 Job/对象/源状态一致。

### E. 权限、安全、最终镜像、部署与回退：未完整完成，纳入剩余计划

上一轮 E 被暂缓；用户最新要求将其完整写入交接，**因此这里保留为待办，不能删掉或标成完成**。本次仅文档与推送，不执行 E 或共享部署。

1. 核对实际生产组合的 SQL grants、Kubernetes RBAC、Job/卷/网络、TLS、私有密钥材料及下载链路。补 B 的源恢复权限和 A 的数据读取权限时，不扩大普通管理员、北向 owner 或业务实例权限。
2. Broker 仍为显式切换；未完成切换不假装已用 Broker，切换后故障不能自动回退宽权限。隔离恢复身份/网络不得写源或使用生产秘密，秘密正文不进入日志、manifest 或 Git。
3. 从最终同一源码构建 App/Worker/必要 Runtime，确认镜像中的实际二进制与配置相符。现有历史 App/Worker 镜像来自旧 SHA，**不是当前代码发行物，不能直接当作本轮发布镜像**。
4. 在一套可复用隔离环境完成真实入口→非空停写采集→实际退出→源恢复→正式发布→独立还原→查询/必要页面操作；不能用模拟 Job/模型/fixture API冒充真实外部能力。
5. 在同一小规模链中只覆盖关键故障：创建/发布回复丢失、控制器接手、迟到回调、取消竞争、损坏成品及恢复失败；未改且已有证据的路径复用，不做数百实例压测或反复全矩阵。
6. 准备能识别新 Team/v2 类型的兼容回退、关闭新入口及原数据保留方案，核对未决任务/授权/写入的处置；不能回退到会串权限/重放旧任务的版本。
7. 真正发布前另行确认目标、镜像 digest、配置与回退材料；代码 push、镜像构建、服务器部署、业务验收分别记录，不相互替代。

**完成标准：**最终发行物、最小权限、隔离与回退有实际证据；所有未执行项仍明确保留，不能以一次空环境启动销项。

## 6. 综合判断与建议实施顺序

剩余不是清理几个冲突，也不是加几次测试：**关键缺口是正式 v2 的非空源控制、完整数据出口、正式成品还原与用户恢复接线。** 已有普通数据链、加密/对象原语和恢复证明应复用，继续堆平行框架没有帮助。

1. **一次核对真实依赖后开工：**Runtime 备份协议、原材料/密钥、源恢复最小授权、全部数据域 provider、隔离目标及真实策略责任人；把实际缺项前置暴露，不临近交付才发现。
2. **先贯通 A+B 的一个最小非空生产闭环：**原任务→冻结→停写→实际退出→封存→按原状态恢复；只认真实运行事实，不新增第二状态机。
3. **完成 A+C 的正式成品闭环：**各请求域均接齐，独立发布/核实/还原/内容与关系验证，不用普通 Team-data 路径替代正式 v2。
4. **D 随已完成能力逐项接入：**先复用现有入口/会话/幂等；先做能用的纵向行为，不再增加后端尚不存在的按钮或占位结果。
5. **E 的必要依赖前置，最终验收与发行后置：**权限、密钥和隔离在设计/接线时就要落实；最终镜像与完整闭环待 A～D 实现后验一次。

每块先做一条失败复现和对应正常/必要故障回归，再提交。只在业务代码最终冻结后跑要求的后端全量；前端改动才跑前端构建。实际 schema/协议/外部调用有变再复验相关链。**按可用功能和出口报告进度，不按提交数、文件数或模拟测试数报告“完成”。**

## 7. 已有验收证据、限制和可复用入口

证据摘要/hash 在 `docs/backup-team-integration/validation.json`；原始日志在本机忽略的 `team-optimization-docs/`，未上传仓库。接手不能假定这些本机文件在其电脑存在。

| 证据 | 能证明什么 | 不能证明什么 |
| --- | --- | --- |
| 最后业务代码的 `go test ./...`、前端构建 | 编译及已有回归通过 | 外部 opt-in 测试没有环境时可能 skip，不能证明完整系统可用 |
| 真实 MySQL 当前 owner Team 导出/独立恢复 | 普通恢复 schema/内容及归属适配 | 正式 v2 全部业务策略已批准 |
| 真实 SQL/Redis/MinIO/文件普通采集发布恢复 | 普通 best-effort 数据链实际运行 | 全系统真实停写、真实 Kubernetes 边界或正式强一致还原 |
| 9个普通重试/续做用例及3个前端传输用例 | 已实现重试、取消、期限和幂等边界 | 未接入的正式 v2 用户动作 |
| 原意图库存/同库共享门禁/UTC等待/结果写失败的真实 SQL | 原身份、全集、原保护保留、有限等待及不重跑 | detached Runtime/模型工具真正停写 |
| 独立 kind 的实际 controller/TLS/Worker/source Deployment | 工作区正常入口45.20秒、未知停止/丢回执行/撤 forward 后原恢复57.07秒通过，一个原 Job/attempt、源恢复、gate idle | 这是 counter Deployment 与零实例功能 profile，不能冒充 OpenClaw/Hermes 非空验收 |
| Gateway 真实 HTTP 适配 fixture | 升级专用能力/缺记录/未确认回执被拒绝，原操作重试约束 | fixture 的正向能力不是当前实际 Runtime 已支持 |

定位用例：`team_data_retry_test.go`、`team_data_admission_test.go`、`team_data_settlement_test.go`、`recovery_inventory_test.go`、`user_instance_backup_gateway_test.go`；真实 native 入口是 `systembackupapi/public_capture_native_test.go` 的 `production-entry` 与 `unknown-stop-recovery`。不要未经核对就运行全部历史 native 场景；fixture YAML 只能用于独立本机集群，禁止应用到共享环境。

本轮自有 kind、4个数据容器及最后时钟回归 MySQL 已核对 ID/标签后清理，临时对象凭据文件已删除；未执行全局 Docker prune/reset。保留的 native 测试镜像不是当前 App 发行镜像。没有更新32543/32443，没有改变共享实例或生产引擎。

## 8. 接手保护规则及本次交付

- 原则仍是先查完整链、定位违反的合同、最小修改、必要失败复现与邻近回归；不能通过删校验、改成功状态、清数据/插件或扩大权限“修好”。
- 不重写已调稳的 Leader/Worker 协作，不加 Worker 必填编号/哈希；保留 Team/owner/WorkBuddy、原账号/计费/历史、会话和文件关联。
- 不用404、Pod缩零、租约过期、文件存在或进程还在单独宣布停止/完成；暂停前保存原状态，恢复按原身份及确切事实收敛。
- SQL只追加；registry 策略/签名审批必须有真实来源；旧执行权、秘密和日志不进入可重放业务状态或 Git。
- 本次只重写交接、删除四份过期阶段说明、刷新索引/来源映射并提交推送。旧内容可在 Git 历史找回，不作为当前待办入口。
- 推送命令目标固定为 `git push backup-origin HEAD:refs/heads/codex/backup-team-integration`；不强推、不改源 `backup` 分支、不推 Team 的 `origin`。本次用户已明确授权带未完成项的进度交接推送；最终远端 SHA 以交付回复核对为准。
