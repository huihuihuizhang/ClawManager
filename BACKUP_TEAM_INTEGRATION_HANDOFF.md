# 备份专用版与 Team 版整合交接

## 2026-10-29 M3 / M4 本轮交付与未完成结论

**本节是最新状态，优先于下面所有历史记录。M3、M4 总出口均未完成，v2 全系统备份不能启用。** 这不是只差服务器部署或一份授权文件；完整数据面、正式发布与独立还原仍有实际实现缺口。完整原范围保留在 [最终计划](BACKUP_M3_M4_FINAL_PLAN.md)，每块成果、失败复现和提交复盘见 [本轮执行记录](BACKUP_M3_M4_EXECUTION.md)。

### 仓库与合并方法

- 开发目录：`D:/test/ClawManager-2`，分支 `codex/backup-team-integration`；仍在 Team 底座上增量适配，不是在备份 checkout 里直接覆盖开发。
- 备份来源：`backup@4fe83bcde5a8a693dddb2635e9a3e397d6e3472e`；`D:/test/backup/ClawManager` 保持干净、不改动。
- Team 基线：`be7da27dff85c2daf3321b8245ffdab024e67853`；保留 Team/owner/北向、WorkBuddy、登录、实例、旧备份和既有历史。
- 推送目标明确为 `backup-origin` → `https://github.com/huihuihuizhang/ClawManager.git` 的 `codex/backup-team-integration`；不推 Team origin，不覆盖同事的 `backup` 分支，不强推。
- 不使用整文件替换或 `ours` 假合并；来源/目标 blob 映射在 `docs/backup-team-integration/source-map.json`。来源未被整分支 merge 认祖，未来仍需按这份来源映射核对新增量。
- 当前164个迁移；本轮没有追加/重写迁移，119/120/121继续保留。127个 registry 对象中59项仍待 owner review、68项待交叉评审，没有把摘要更新当作策略批准。

### 已经真正接通的能力

实际生产 `system-backup-v2-controller` 通过选主、原公共任务和独立控制连接执行显式 `public-v1 / platform-workspace / functional_test`。**源 instances 必须为零，数据域仅 workspace**；这不是当前正式环境非空 Team/实例的全系统备份能力。

已通过的纵向路径：真实 HTTP/RBAC 创建 → 生产进程领取 → 原加密计划 → 实际 scratch Worker → 工作区密文内容核验 → 实际退出证明 → 原源 writer 恢复 → validating → 查询 → 授权取消 → 原密文/历史保留。validated/sealed 不等于已发布/可独立恢复。

本轮修复包括：物理释放与公共记录同事务；历史释放缺口按原 epoch 和回执补记；acquiring 日记原子性；原 Job binding/process 缺失时找回原对象；运行中取消；forward/source/私钥丢失后的独立恢复；最小 SQL/Kubernetes 角色；实际 MySQL 卷容量；超过10秒的退出监听；受阻诊断；认证 Job 的真实进展投影；摘要中的恢复保护提示；暂停回执整行缺失拒绝补记。

已完成13个开发提交，从 `525fe528` 至 `806d1458`。每个工作块后的真实成果与效率复盘均在执行记录中；最终文档/验收提交另见本分支 `git log`，避免在文档中自引用最终 HEAD。

### 完整验收矩阵的真实状态

| 原计划 | 状态及尚未覆盖的边界 |
| --- | --- |
| A1 真实生产执行/单份原计划 | 工作区受控 writer 通过；未验非空 Runtime/完整多域 |
| A2 准入/容量/权限与旧路径 | 实际容量、最小角色、缺授权拒绝及原列表通过；不是完整生产配置验收 |
| A3 gate 事务及历史缺口 | acquiring/释放 SQL 故障和原代数恢复通过；发布后的未知外部写入尚未接入 |
| A4 原 Job 不重复 | 响应/绑定缺口、真实原 Job 重启恢复通过；已记发送但始终没有观察到原对象时仍受保护，不能自动解锁 |
| A5 超时/停止/取消/独立恢复 | 真实受控 Deployment/Worker、13秒退出、未知停止及独立恢复通过；非全部实际 Runtime/后台 writer |
| A6 六域一致性采集 | **未通过：当前仅 workspace，其他五域未生产接齐** |
| A7 当前业务恢复策略 | 摘要一致性已修；59项 owner 和68项交叉评审仍未完成 |
| A8 正式发布/不确定写入 | **未完成生产公共 v2 适配** |
| A9 正式成品独立还原 | **未完成**；密文 tar 内容比较不是正式成品独立还原 |
| A10 用户动作/断线恢复 | 真实创建/详情/取消/幂等及前端传输通过；manifest/正式下载/恢复/全部重试未接齐，无真实浏览器验收 |
| A11 安装/镜像/回退 | 最小角色、TLS 原链及真实 App/Worker 已验；完整 Broker/CNI 安装和安全切换回退未验 |
| A12 原业务/最终交付 | 后端全量、前端构建、实际整包登录/原列表通过；非空 owner Team/WorkBuddy 的正式备份还原与共享环境发布未做 |

每次验收的原始日志仅在本机忽略目录，可信范围和 SHA256 记录于 `docs/backup-team-integration/validation.json`；最终镜像证据在本轮执行记录收尾节。没有通过浏览器/模型/生产 NFS 的项目不能据此声称通过。

### 仍需完成的代码位置与闭环要求（属于原 M3/M4，不另设 M5）

1. **真实停写者与非空源**：`systembackupexecution/deployment_platform.go` 当前只装配显式 Deployment，`deployment_service.go` 仍拒绝非空 instances。接现有 `systembackup/publicadapter/writers.go` 的 Runtime writer builder 与当前 Team/background gate；用非空 Lite/Pro、OpenClaw/Hermes 和原本停止者证明逐个恢复，不能只删除零实例校验。
2. **六域数据面和凭据**：`deployment_platform.go:BuildParts` 当前只有 workspace；`public_jobs.go:Authorize` 仍拒绝 Database 凭据请求。按原范围接 mysql/redis/object/deployment/secret 的真实采集与只读权限发放，每域形成实际内容及隔离恢复证据；不能把 controller SQL 写连接传给 Worker。
3. **当前业务策略**：`contracts/system-backup/v12/schema-registry.json` 仍有未决项。逐对象落实 owner/Team/WorkBuddy、引用/FK、运行状态重建及凭据失效；交叉审批必须来自实际审阅，不批量写 owner_recorded/approved。
4. **正式发布**：`SQLCaptureGate.FinishCapture` 当前终止于 validating。围绕同一公共 v2 task 适配 `systembackupproducer/finish.go` 与既有 recovery/provider/envelope 原语；接独立 KEK/signer/provider 身份、精确原 bytes 与外部效果日记。`systembackup.CorePublisher` 依赖旧任务，禁止通过另建旧任务接通它。
5. **独立还原**：由正式发布成品恢复独立 DB/Redis/对象前缀/卷，真实目标隔离、逐步日记和独立 verifier，核对非空业务关系及危险队列/凭据不重放。没有正式发布就不能先用工作区包伪造独立恢复成功。
6. **用户恢复及安装**：接真实重试/核实/恢复/manifest/下载/隔离演练；按钮取决于已实现能力。完成 Broker/网络/卷/私有材料安装、v2-aware 回退和最终浏览器操作，再考虑启用和共享环境发布。
7. **未知发送边界**：目前不会用404或租约过期证明原执行停止。需要补经过审阅的原发送封禁/停止证明路径，不能删日记、重建 Job、清 gate 或手改失败状态解锁。

本轮独占的本地 kind 与两个 MySQL 容器已经核对身份后清理；临时整包 App/Redis/测试库及测试用户也已清理。最终本机镜像与忽略日志保留，复验需重建独占 fixture，不能把 native fixture 应用到共享集群。未发布共享服务器。

### 本轮为何没有完成，以及后续怎样提高效率

这次仍未兑现“全部 M3/M4 完成”。主要问题是执行组织：先把工作区可靠性展开成了多个相邻工作块，虽然修复真实，但没有及时推进六域和正式成品出口；不能把未完成说成只差验收。对来源库“已有原语”的可组合程度仍估计不足，实际生产装配缺口远大于函数数量。

可避免的浪费包括：新角色未先逐个核对实际 PATCH 调用、用发送标记代替实际 Job 作为测试前提，造成两次约八分钟等待；若干次猜文件名和重复镜像构建；工作块中间编译参数不同导致缓存未复用。必要的真实故障验证本身不是浪费。

接手应直接复用当前生产纵向链和一次性 native 驱动：先把一份非空六域快照、正式发布、独立恢复的实际调用点和最小提供方材料核实清楚，再动代码；一次运行保留原始故障现场、阶段和集合完整性，不等统一长超时；每块先做失败复现/定向验证，冻结后做要求的全量和最终镜像验证。不要再横向增加一套状态机、演示页面或来源归档代替数据出口。进度按 A1～A12 和真实用户能力报告，不能按提交数或文件量报完成比例。

---


> 最新接手入口：[M3/M4 最终开发计划与复盘](BACKUP_M3_M4_FINAL_PLAN.md)。按用户要求，原 M2 未完成项作为 M3 必做前置，后续只保留 M3/M4 两个最终阶段；不改变下文已经记录的验收边界。

## 2026-10-28 M0～M2 四小时开发交接（当前结论）

本节优先于后文历史记录。当前仍在 `D:/test/ClawManager-2` 的 `codex/backup-team-integration`，不是备份目录直接开发；来源固定 `backup@4fe83bcde5a8a693dddb2635e9a3e397d6e3472e`。备份专用 checkout 保持不变。合并方法仍是 Team 稳定底座上的逐模块增量适配，不整文件覆盖、不以 ours 合并掩盖差异，保留原 Team/owner/北向/WorkBuddy/旧备份路径。

- M0 `9c53b6ad`：来源公共执行组件、执行记录、SQL/catalog 兼容；实验私有 control 不注册到生产。
- M1 `5bf61815`：公共 SQL 准入、唯一持久 Prepare 调度、签名执行身份及原加密计划；真实 COMMIT 确认丢失后复用原计划。
- M2 本轮后续提交：真实 functional 工作区采集和源业务恢复、Job/Pod 身份与停止证明、独立恢复授权、实际资源日记。**完整 M2 尚未完成，生产全系统备份仍不能启用。**

当前 catalog **164 个迁移**，122/123 为新追加；119/120/121 未改写。新增控制记录不能恢复为可执行工作。registry 新条目仍待策略/owner 审查，不批量批准。

本轮真实隔离环境四例通过：正常采集、创建响应丢失找回原 Job、停止证明不可用保持保护并在接手后恢复、Prepare 撤权无源副作用。另通过真实 MySQL/M1 回归、Linux setgid 和后端全量测试。源是受控文件 writer，容量是合成测试信号；不能据此声称 OpenClaw/全数据域、最小生产授权、发布或独立恢复验收通过。

**接手先读 [本轮开发验收及明确缺口](BACKUP_M0_M2_EXECUTION.md)。** 未完成的 M2：生产 `NewPublicCapture` 调用/实际 readiness、完整数据域采集与所有 writer 停写、若干提交不明窗口的恢复、受阻恢复操作。M3 发布/独立恢复和 M4 部署仍保留原范围。下一步先闭合一个生产 profile，不再重复移植库、整理来源或补虚假 readiness。

本轮仅本地分阶段 commit；没有 push、没有服务器变更。后续若用户授权推送，显式使用 `backup-origin`，不可误推 Team origin。

---

## 2026-10-28 新来源同步后的补充

备份专用目录 `D:/test/backup/ClawManager` 已切换到跟踪 `origin/backup` 的 `backup@4fe83bcde5a8a693dddb2635e9a3e397d6e3472e`，工作区干净。我们的整合分支仍为 `codex/backup-team-integration@6dcdbb75`，本轮尚未合入新业务代码。

最新深度对比、双边保留方法及剩余开发顺序见 [新 backup 增量与剩余开发计划](BACKUP_TEAM_REMAINING_PLAN_20261028.md)。下文是此前阶段的历史记录；关于来源尚无 runner/loop、100 对象/32 项策略待定、备份目录未修改等判断已被新计划更新。新来源已有公共 runner、执行循环、执行记录和 Job Ports，但 production owner 接线及真实整链仍未完成。新 registry 为 122 对象/54 策略待定/68 交叉评审待定，且 137 个迁移与 136 pin 未同步。

本轮新来源执行定向测试通过，inventory/contract freshness 检查均失败；未发布镜像、未 push、未操作服务器。接手时先读新计划，避免按旧缺口重复开发。

---

更新日期：2026-10-28。按用户最新要求，在当前小阶段验收和 commit 后暂停，待用户查看成果后继续。本文记录实现、合并方法及剩余工作；不是生产启用许可。

## 1. 当前结论

**整合尚未全部完成，v2 全系统备份仍不能启用。** 已完成模块移植、数据库隔离适配、授权任务提交、真实详情查询、未启动任务取消、共享门禁身份适配，以及当前阶段的持久任务领取、加密计划保存和 Job 防重复发送。生产 v2 调度循环、实际采集/恢复组合、远端写入者恢复和最终部署闭环尚未完成。

不能将“代码已移植”“单元测试通过”“任务提交返回 202”“本地存储测试通过”写成“新版备份已可用”。当前生产组合没有发布 executor readiness；因此新任务提交会明确拒绝，不创建永久排队任务。不要手动写入 readiness、修改数据库状态或移除启用保护。

原计划包含 G0～G7 完整执行与恢复要求，当前没有完成全部范围，剩余要求继续有效。暂停来自用户本次明确指示；不能把阶段提交当作原计划交付完成。本轮只提交当前阶段，未推送这些新阶段提交、未发布镜像、未操作服务器。

## 2. 仓库、分支与来源

| 项目 | 准确信息 |
| --- | --- |
| 本次工作目录 | `D:/test/ClawManager-2` |
| 本次整合分支 | `codex/backup-team-integration` |
| Team 稳定基线 | `be7da27dff85c2daf3321b8245ffdab024e67853`，`codex/team-personal-integration` |
| 备份来源仓库 | `https://github.com/huihuihuizhang/ClawManager.git` |
| 最后复核的备份来源 | `backup@8ef5fa7fd4df45f6306e910705db01f589266ba7` |
| 初始移植来源 | `63a13b2771091e4ba47b691ce066a670cbc88d54`；后续吸收 `d3c5715a`、`8ef5fa7f` |
| 共同 Git 基线 | `b5582554f330e0e92a115bf9f4afe6a669a9e3d6` |
| 推送 remote | **`backup-origin`**，上面的 huihuihuizhang 仓库 |
| 推送目标分支 | `codex/backup-team-integration` |
| 备份专用工作目录 | `D:/test/backup/ClawManager`，本次没有修改；其检出的旧 `main` 不是本次移植来源 |
| Runtime 工作目录 | `D:/test/AgentsRuntime`，本次没有修改 |
| 个人项目 | `D:/test/gitlab/*`，不在本次范围 |

这里是在 **Team 底座的独立整合分支**开发，然后推送到备份仓库。并不是在备份目录的旧 `main` 上开发。Team 仓库的 `origin` 也不是本次推送目标。不能直接 `git push origin` 猜测目标。

阶段提交：

- `288d74a9`：来源模块移植、SQL 隔离、Team 兼容及工具/页面适配。
- `64bdfcc1`：事务内授权提交、真实详情查询、未启动任务安全取消。
- 后续共享门禁/恢复入口和本交接文档的提交，以本分支 `git log` 为准；不要在文档中维护会自引用变化的最终 HEAD。

## 3. 合并方法与冲突处理

采用 **可追溯的模块移植和适配**，没有把整个备份分支做 `ours` 合并，也没有整文件覆盖 Team 实现。Git 不会因此将备份分支全部标为已合并；后续更新仍应按来源映射审核增量。

保留最新 Team、owner 权限、北向门户、WorkBuddy、实例管理、登录、文件编辑与预览、Runtime 调度和旧备份路径。Worker 工具参数及业务交付协议没有因备份整合而增加必填字段。

具体处理：

1. **启动入口和 Dockerfile**：保留原服务与原控制器；新控制器单独命名 `system-backup-v2-controller`，新增导入、迁移、安全等工具分别打包，避免同名二进制覆盖。
2. **数据库连接**：保留 Team 业务连接的门禁与隔离恢复库拒绝规则。新控制连接逐物理连接设置 UTC；读权限和操作权限分离，不把控制连接作为业务写入旁路。
3. **Repository 和业务写入**：保留现有 `backupgate` 边界，新模块适配现有工作单元，而不是安装第二套独立业务暂停状态。
4. **Skill Worker**：接入停止等待、未执行 claim 归还、迟到执行保护；保留 `HoldWorkUnit`。首次门禁拒绝后可以等待重开，不允许已经开始的工作重复 claim。
5. **安全组件**：Broker 保持显式切换；切换后故障不能自动退回宽权限直连。未启用时保留原行为。
6. **前端**：原 Team 备份页保留；旧系统任务页与新控制历史页分开，原任务 ID 和链接仍有效。所有五种语言同步适配。

逐路径来源和处置见：

- `docs/backup-team-integration/source-map.json`：来源 Git blob 与当前文件内容摘要。
- `docs/backup-team-integration/sql-map.json`：SQL 文件、表和约束映射。
- `docs/backup-team-integration/conflict-resolution.md`：冲突处置说明。
- `docs/backup-team-integration/reference/`：只供核对的来源 SQL，不能当成应用迁移执行。

## 4. 数据库与旧数据适配

两边有同名但结构不同的控制表，不能把来源 SQL 原样放进自动迁移目录。

- 原 Team 控制表和已发布迁移不改写；新控制资源使用 `system_backup_v2_*`。
- 映射覆盖建表、查询、外键和 CHECK 约束，避免只改表名而引用仍指向旧表。
- 新迁移按增量方式加入；当前完整 catalog 为 **162 个迁移**，由脚本生成摘要，不手工改计数冒充覆盖。
- 新表建立不启动 v2，引擎选择默认保留 `legacy`。
- 旧备份记录和包继续走旧 reader；不批量改任务 ID，不改旧格式。
- `119_backup_v2_execution_admission.sql` 增加不可变执行输入及执行准备记录；这些是安装本地控制权，恢复业务数据时不能重放为可执行任务。
- `120_backup_v2_execution_plans.sql` 保存加密不可变执行计划；`121_backup_v2_job_send_intents.sql` 保存发送前意图及实际 Job UID。两者同样归类为安装本地控制记录，不恢复为运行中工作。
- 迁移与采集共用排他约定。持锁连接失效或释放不确定时销毁连接，不能继续执行 DDL。

备份来源库导入只支持结构完全匹配的**隔离复制库** `cm_import_<32hex>`：核对来源 122 张表及 136 文件历史 ledger，保留原始行、ID 和 ledger，记录表重命名日记，支持中断后续做并比较原始列行摘要。未知结构、活动工作或正常业务库名会在操作前拒绝。禁止用这个工具直接改原备份项目的在线库。

## 5. 本轮新增的可用链路

### 5.1 授权任务提交

入口在 `backend/cmd/server/system_backup_tasks_live.go`，实现主要在 `backend/internal/systembackupapi/sql_writer.go`。

在同一授权事务中检查当前权限、引擎、配置、执行准备和容量，再保存任务、配置快照、执行输入及审计事件。`next_reconcile_at` 是持久调度意图，不是内存队列。

- 相同操作者、接口、幂等键和规范化请求返回原任务；相同键不同请求返回冲突。
- 响应丢失后复用原键，不新建第二份任务；准备状态后来失效也可以找回已经提交的原任务。
- 执行输入固定安装身份、部署版本、源环境和恢复目标；后续改配置不能悄悄改旧任务。
- 执行准备必须与任务类型、配置版本和 profile 摘要匹配，并使用数据库时间验证新鲜度。
- 容量使用与注册相同的单调预留账本；事务回滚同时回滚预留，新容量采样不擅自清零账本。
- 当前没有生产执行器发布准备证明，正常情况下缺依赖会拒绝提交，不留下不可执行任务。

接口：`POST /api/v1/admin/system-backups`、`POST /api/v1/admin/system-backup-preflights`。创建请求契约位于 `contracts/system-backup/v12/admin-task-create-requests.schema.json`。

### 5.2 真实详情和安全取消

`SQLTaskDetails` 通过授权的重复读快照查询真实记录，并进行最终权限复核。未开始任务的执行、校验和一致性证据保持未产生；不填成功默认值。`acceptance_ready` 不因 SQL 中有成功状态而自动为真。

取消入口为上述任务的 `/{id}/cancel`，正文 `{}`，保留幂等键。仅允许 pending、无 controller owner、无尝试、无外部动作、无产物租约的任务。过期 owner 也不能当成“已经退出”。任务状态、取消操作和事件一起提交；审计失败全部回滚。

采集 profile 缺失或无效时，只关闭创建，授权历史查询和安全取消仍保留。取消使用独立的控制容量报告，但仍需要有效授权与容量证据，不是绕过校验的紧急数据库改状态。

前端 `BackupCancelUnstarted.tsx` 保留原请求键，检查返回安装/任务/操作身份，支持不确定结果后按原键查询；不自动反复发送变更请求。运行中取消尚未接通远端停止与恢复协议，因此不能用这个按钮处理运行中执行。

### 5.3 共享门禁的 v2 任务身份适配

代码位于 `backend/internal/systembackup/versioned_gate_admission.go`：

- `BeginVersionedCapture`：先验证任务，再在取得旧 Team 门禁的事务内重新验证安装、任务输入、controller owner、row version、lease 和绝对期限。
- `HoldVersionedCapture`：必须确认实际写入者排空，并在状态转换事务内复核当前任务身份；旧控制器在接管后不能继续持有门禁。
- `ResolveVersionedCapture`：创建响应丢失后找回同一代门禁，不增加代数、不延长期限、不重新采集。
- 仍使用 `system_backup_gate`；这些方法不向来源 `system_backup_v2_maintenance_locks` 创建第二套业务控制权。
- 旧 watchdog 对 v2 任务超时先封住采集；只要存在尝试、Job 观察或外部动作，就不能凭“没有旧版 capture plan”释放业务写入。

**这些适配方法已经真实 MySQL 验证，但生产 v2 scheduler 尚未调用它们。** 远端暂停、实际退出证明和恢复释放必须一起接入后才可启用。当前保留封锁是防止不明执行与业务并发写入，不能冒称故障恢复已经闭环。

### 5.4 本次暂停前完成的小阶段：领取、计划与 Job 发送

- `systembackupcontroller/execution_queue.go` 从真实 public task 领取工作，读取原始配置、profile 和请求并校验摘要。新领取与 preparing 转换、审计事件在同一事务中完成；六个并发调用（包括相同 owner）只有一次启动。过期 owner 或已有执行事实转为恢复处理，不把 pending 标签当成从未执行。kill switch 阻止新启动，但保留旧任务的恢复入口。
- `systembackupexecution/plan_store.go` 使用 AES-256-GCM 保存固定计划，认证数据绑定安装、任务、配置、profile、schema 和 key version。相同计划重放返回原密文对应的内容；不同计划不能覆盖。密钥不写入数据库，不在对象打印或 JSON 中输出；只在当前有效 claim 下解密。
- `systembackupexecution/job_plan.go` 校验固定 Job 模板、镜像 digest、命名空间身份、服务账号、运行边界和禁止自动重试/自动删除；恢复不能悄悄用更新后的模板。
- `systembackupexecution/jobs.go` 先提交发送意图再调用 Kubernetes。创建响应丢失后只查询原 Job；查不到也不重复创建。找到后保存实际 UID，同名新 UID 不能冒充原执行。
- 这些是生产代码实现，但**尚未接入持续运行的 scheduler、worker 与恢复组合**。SQL 和加密测试是真实的；Job 故障测试的 Kubernetes 客户端是受控模拟边界，并非实际集群验收。

本小阶段不包含完整 `Observe/Stop/Recover`、采集 worker、发布和独立恢复。后续要继续接完整纵向路径，不能只给这些模块安装一个循环就启用 readiness。

## 6. 配置与启用边界

| 配置 | 当前作用 |
| --- | --- |
| `SYSTEM_BACKUP_READ_SESSIONS_ENABLED` | 显式启用真实登录/刷新/注销会话记录，默认不替换普通登录行为 |
| `SYSTEM_BACKUP_READ_LIVE_ENABLED` | 显式启用真实控制记录读取；没有 fixture HTTP 回退 |
| `SYSTEM_BACKUP_READ_PINS_PATH` / `SYSTEM_BACKUP_READ_PINS_SHA256` | 读取/操作授权绑定；读权限不自动获得操作权限 |
| `SYSTEM_BACKUP_EXECUTION_PROFILE_FILE` | 部署拥有的封闭执行配置；缺失或无效不影响授权历史/未启动取消 |
| `SYSTEM_BACKUP_CAPACITY_REPORT_FILE` | 绑定实际数据库身份的容量报告，提交及取消需要新鲜报告 |
| `SYSTEM_BACKUP_V2_CONTROL_PLANE_ENABLED` | 独立控制面入口；不等于允许采集，生产采集组合仍拒绝启用 |
| `CLAWMANAGER_SECRET_BROKER_MIGRATION_COMPLETE` | 明确完成 Broker 切换后才使用，故障不降级绕过 |

不能直接退到不认识 v2 类型/表的版本并启用旧控制器采集。回退应先确认所有执行退出和门禁恢复，保留新控制历史，采用认识新结构的兼容构建。关闭入口也不能删除任务或数据。

## 7. 验收证据及含义

摘要记录在 `docs/backup-team-integration/validation.json`。本机原始日志在忽略目录，不含在提交中。

| 已执行验证 | 证明的范围 |
| --- | --- |
| 前阶段真实一次性 MySQL、当时完整 160 迁移 | 授权事务、六个并发同键请求仅一份任务、请求冲突、回滚和准备状态丢失 |
| 真实 HTTP handler + SQL 会话/RBAC | 操作人可提交、只读用户不可提交/取消、撤销权限后不能重放成功结果 |
| 真实详情及取消 | 已持久化查询、过期 claim 仍拒绝取消、审计失败无残留、profile 不可用仍可安全取消 |
| 真实 MySQL 共享门禁 | 当前 claim 约束、同代找回、双引擎排他、写入者超时不视为停止、未确认 v2 执行不自动释放 |
| 旧门禁真实回归 | 原采集、暂停、恢复、超时与错误 token 路径保持约束 |
| 本阶段真实 MySQL、完整 162 迁移、任务领取和计划 | 输入篡改拒绝、kill switch、审计回滚、六个并发只启动一次、接管保护、加密重放/篡改拒绝 |
| 真实 SQL + 受控 Kubernetes 故障边界 | 丢失创建响应不重复发送、最终找回原 UID、同名替代 Job 拒绝；不等于真实 Job/Pod 运行验收 |
| 后端全量测试 | 常规包回归；需要独立平台的 opt-in 测试可能跳过，不能算真实平台验收 |
| 前端生产构建、操作服务测试 | 类型/打包及响应身份检查；不是当前服务真实浏览器变更验收 |
| 前阶段隔离导入、SQL/Redis/对象/文件验证 | 原模块数据路径证据；Kubernetes 边界受控，不能提升为生产 v2 执行闭环 |

任务提交测试中的 readiness 和控制器状态由测试构造，真实 SQL 事务经过验证，但**没有因此执行真实采集 Job**。前阶段浏览器测试使用 fixture HTTP，也不能代替实际服务与恢复验证。

必要复跑命令（Windows PowerShell，临时数据库必须是测试自有环境）：

```powershell
go -C backend test ./... -count=1
$env:TEST_SYSTEM_BACKUP_MYSQL_PORT = '<自有本机临时 MySQL 端口>'
go -C backend test ./internal/systembackupapi -run 'Test(SQL|Versioned|Execution)' -count=1
go -C backend test ./internal/systembackup -run 'Test(Gate|ExpiredGate|EngineSwitch|ConcurrentEngines)' -count=1
npm --prefix frontend run build
python scripts/backup-team-catalog.py --check
git diff --check
```

不要使用服务器 DSN 替代临时数据库，也不要把缺平台的 skip 记为通过。数据库测试应串行执行，迁移与采集本来就互斥。

## 8. 接手开发的具体顺序与缺口

### A. 生产执行器与唯一状态权威（未完成，优先级最高）

接入点是 `backend/cmd/system-backup-v2-controller/main.go`、`backend/internal/systembackupcontroller` 和 `backend/internal/systembackupdispatch/contract.go`。

`Dispatcher` 只是 ABI 调用边界，生产 `Runner`/`Ports` 及实际调度循环尚未装配。不能看到接口或健康检查可启动就认为会执行备份。持久领取、加密计划和 Job 意图已经实现，下一步直接接原执行的观察、停止、实际采集、发布和恢复，避免再重复开发相同基础层；只有组合完整才发布短期 readiness。

保留一个任务状态权威。旧 `systembackup.Store` 和 runner 与旧任务表/ID 紧耦合；旧 ID 为无连字符的 36 字符形式，新 ID 是带 UUID 连字符的 40 字符形式。不能创建一个影子旧任务来“同步”两套状态，也不能全局放宽 ID 正则。应提取与控制表无关的实际采集能力，通过版本化计划和受控 Ports 调用。

### B. 真正暂停、退出和恢复（未完成）

接入已实现的共享门禁方法，替代来源 controller 对独立维护表的业务控制。枚举 SQL、Redis 消费、Runtime 工具、workspace、对象上传和后台任务等实际写入者。以实际 UID/代数与明确停止、恢复回执为准。

创建 Job 的响应丢失时查找原 Job；lease 过期不能证明旧执行已停。已有执行不明确退出时，禁止启动第二份；恢复接口应显示具体阻塞、已保留数据和可执行下一步。当前 watchdog 只封锁不明执行，**自动安全释放 v2 的恢复组合仍缺失**。

### C. 当前数据 registry 与独立恢复（未完成）

来源 `contracts/system-backup/v12/schema-registry.json` 仍是 draft。来源清单有 100 个对象，32 个策略待定，其余也不能仅因字段存在就认定完成评审。增加迁移 catalog 摘要不等于当前 Team 数据已覆盖。

以当前真实 schema 逐表逐列核对 owner、resource_scope、Team 模板/成员/任务/事件/工作项/阶段/outbox、Gateway、Skill Hub 和文件引用。明确原文保留、恢复归一化、凭据撤销及禁止重放策略；保留费用与历史事实。不要填写虚假评审人/冻结证明绕过源 collector 校验。

独立恢复后检查行内容、对象摘要与跨表引用，并证明没有模型调用、任务派发、结算或生产凭据重新生效。使用真实 SQL/Redis/对象/文件、隔离目标和实际执行器；源业务恢复与异步上传分开，上传只能读取封存副本。

### D. 剩余用户操作与界面（部分未完成）

`backend/cmd/server/system_backup_read_live.go` 中 overview/log/catalog 等尚有拒绝未就绪的生产入口。已有真实历史及详情不能代表所有页面动作可用。继续接实际执行进度、运行中取消、核实并继续、重试、隔离恢复与恢复业务；操作是否可用由服务端能力和当前事实决定。

未完成的按钮继续明确不可用，不通过解除前端禁用隐藏后端缺口。当前取消仅覆盖未启动任务。

### E. 安全、镜像和环境验收（未完成）

实际授权、数据库 grants、Jobs 配置、卷、TLS、Broker 和下载通路需要独立环境验证。完成一次真实“提交→采集→源业务恢复→发布→独立恢复→查询”闭环，再在同一小规模环境覆盖响应丢失、控制器重启、迟到执行、损坏对象和取消竞争。

最终镜像必须包含实际 runner 和对应配置；本轮没有发布镜像、操作服务器或切换生产引擎。部署、真实回退与业务影响不能以代码 push 代替。

## 9. 后续来源同步与提交方式

1. 核对工作区、当前分支及备份 `backup` 最新 SHA；保留 Team 和备份双方原历史。
2. 对照 `source-map.json` 审核新增路径及共同修改处，不从备份旧 `main` 整体覆盖。
3. 新 SQL 只追加，运行 catalog 检查；适配结束后再生成来源映射。
4. 只对本次受影响路径做必要真实回归；不重复用大规模测试替代执行器缺失。
5. 检查敏感信息和本地开发文件，阶段 commit 后显式推送并核对远端 SHA。

```powershell
python scripts/backup-team-catalog.py --check
python scripts/backup-team-source-map.py
git diff --check
git remote get-url backup-origin
git push backup-origin HEAD:refs/heads/codex/backup-team-integration
git ls-remote backup-origin refs/heads/codex/backup-team-integration
```

不强推、不直接覆盖备份分支、不提前合回稳定 Team 分支。所有完整执行、独立恢复和故障恢复门槛通过后，才可以将状态改为“备份整合完成”。

## 10. 未完成原因与改进要求

这次的主要问题是工作组织和估时，而不是缺用户确认。最初把“来源模块较完整”误当作“可组合为生产执行链”，没有先验证 writer、scheduler、runner、远端暂停和独立恢复是否真正贯通。实际来源存在空生产组合、两套不同任务/门禁以及待定 registry；每一处都需要适配，不能直接拼接。两小时内完成全部能力的估计没有建立在这条链路上。

执行中又花了较多时间整理模块来源、扩展基础设施和重复读文件，阶段结果没有优先形成用户能使用的纵向功能。虽然必要的安全校验不能省略，但它们不应替代真实执行开发。把局部测试通过或阶段推送作为收尾，也偏离了用户要求；用户已明确指出，本次暂停仅为先检查阶段成果。

后续改进：

1. 先列出实际可调用的完整路径和缺失实现，按“提交→领取→准备→暂停→采集→恢复业务→发布→独立恢复→查询”推进，一个纵向闭环优先，不再横向堆接口和文档。
2. 复用已完成的 SQL 领取、计划和 Job 意图模块。下一阶段的交付必须包含实际运行进度，不能再次只交接口类型、健康检查或拒绝未就绪保护。
3. 每阶段只跑受影响的失败复现、邻近回归及必要真实存储用例；到一个可提交节点再做要求的全量测试。未变化的前端构建和导入/存储证据复用，明确其边界。
4. 在开始阶段就核实实际运行环境和权限、所需镜像与挂载。缺少真实环境时立即区分“代码已实现”和“环境未验收”，不在最后靠模拟结果补成功结论。
5. 以实际可用能力报告进度，不能按移植文件数估算完成率。时间不够时提前报告，不擅自削减原计划，也不再把阶段提交称为整合完成。
