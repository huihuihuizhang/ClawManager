# C—Teams 剩余阶段交付与集成接缝（2026-10-30）

## 1. 范围与结论

工作目录 `D:/test/backup/ClawManager`，本地分支 `codex/backup-teams-adaptation`；起点和实施中再次 fetch 核对的 `origin/backup` 都是 `cf52722cca43ef2c863bb90fd7406025e6ec1bdb`，已包含前轮 A/B 成果。没有回搬旧 Team 控制器、独立循环、第二套状态或门禁，没有修改历史 SQL、个人项目或团队 checkout，没有操作服务器。

**本轮完成我们负责的 Team 领域适配及本地验收，不等于统一产品正式全链路上线。** A/B 历史见 [前轮交接](system-backup-c-teams-module-handoff-20261030.md)，当前接缝以本页和 [机器清单](../contracts/system-backup/teams-domain-adapter.v1.json) 为准。

任务、结果、产物引用、事件、模板、owner、图标和创建历史保留。恢复后的活动工作变为失败/未完成，成员离线，不自动继续中断任务。原状态和原操作引用保存在不可变加密源成品中；规范化数据提交前另行加密封存，作为独立读回依据。

## 2. 完成点与实际调用链

### C1：实际 writer 生命周期和冻结覆盖

- `OperationWorker.runLifecycleActionWithLease` 原先在父取消后返回，但 provider/owner goroutine 仍可能运行。现在通过**同一共享 work boundary** 持有 `northbound.lifecycle_action` 许可，直到实际动作退出才释放；关闭 gate 后不能启动该动作。取消、租约过期、父返回都不作为退出证明。
- 可选 `team.Inventory.Writers` 固定原映射，旧 nil 字段编码不变。`publicadapter.ValidateTeamsWriters` 已接入 `runner.guardInventory`，在 Prepare 和每个捕获 fence 检查。
- 原 SQL 状态为 stopped 的成员不能由 running writer 覆盖，避免把已停止实例当作需要启动的原状态。

- C finite-unit 差集为 `team.pending_deletions`、`team.event_projection`、`team.maintenance_sweep`、`northbound.operation`、`northbound.lifecycle_action`、`team.workspace_http`。每个有实例的成员还须有原 gateway/pod/deployment/stopped writer。ID、UID、代数、原运行状态和 checkpoint 必须匹配；缺项、替代实例、冲突、假 gate participant 都拒绝。`TeamsWorkUnits()` 返回独立列表。
- **coverage JSON 是映射，不是物理回执。D 仍须独立核对全部真实平台副本、外部写入者、Runtime/工具子进程。** PauseIntent、CheckPaused、原状态 Resume、独立恢复权限及先停 collector 后恢复 writer 全部复用原 flow/B/D 实现；没有制造 ACK 或另一套控制流程。

### C2：公共 SQL 与独立恢复规则

- B 的唯一 `capture-database` 同事务采集 C 11 表及 northbound operation 关联；没有第二份 Team SQL。`domain.VerifyTeamCapture` 补强源 snapshot 格式/行结构、当前 C schema、owner/member、Team 状态及原共享卷映射核对。
- 公共 `domain.Normalize` 拒绝未知成员状态和未知 task workflow state；已知工作项终态及 blocked/awaiting_review 等活动态继续使用既有规则，不猜测未知状态。
- `domain.VerifyTeamQuarantine` 同时接入 **Normalize 返回边界和实际 VerifyDrill**，独立检查 Team/成员/任务/工作项/阶段、凭据、cursor、owner/template operation、outbox 和锁。加密 expected receipt 若错带可执行状态，也不能通过公共 verifier。
- `team_work_items.artifact_refs_json` 是业务关系：校验支持的路径列表后保留原字节，通用 Secret stub 不能改写产物位置。其余 task/result/template JSON 继续走明确 registry，未加入 preserve-all 或默认测试密钥。
- 无活跃 Team 时仍注册 `DependencyOnly` C 模块并要求 B SQL，保留模板和历史。不生成空假 Job、不重复 SQL；缺依赖仍拒绝。已删除 Team 不加入共享卷采集，恢复仅保留其 SQL 历史并清除已移除卷的绑定；原位置仍留在加密源历史。

### C3：共享目录、产物恢复与只读验证

成员实例私有完整根仍由 B 负责，C 只处理共享目录。

1. 从**最终原 SQL part** 认证解密得到 snapshot，调用 `domain.NewTeamWorkspaceSpec`（worker 提供同名包装），核对 C 捕获范围并固定 Team ID、inventory digest 及原 SQL 密文成品 digest（不公开明文 SQL 指纹），提取 work item/task/event 的显式 artifactRefs。不得 live SQL 重新发现。
2. D 把 spec 原样绑定到原成品、同一 capture context、原 part `team_<id>_workspace`、实际隔离 PVC UID 和独立身份/授权。构造 spec 或名称前缀本身不是 grant。
3. 同一个 worker 使用 `restore-workspace + TeamWorkspace + PolicyVersion=teams-shared-workspace.v1`；共享目录是 inert data，不需编造 Runtime config 规则，不能混入其他 Runtime/database/network spec。
4. 完整认证 staged 对象之后才写空隔离目标，复用安全 tar extractor。保留全部文件，不执行脚本、不启动消费者，不删除失败/不确定副本。
5. 逐文件读回 archive，核对内容、类型、权限、适用时 UID/GID、普通文件/目录 mtime、链接文本、额外文件及产物引用。恢复仅返回 `Quarantined=true, Verified=false`。
6. 独立 `verify-team-workspace` Job 再验收。`kube.TeamWorkspaceJob` 强制隔离 namespace、原受控 worker/绑定 Pod 身份，不接受任意命令；target/staging 都只读。WorkerConfigMap、实际 CLI、worker.Run、共享 Control checkpoint/result 已识别。验证代码不修复或写入目标。
7. 只有独立验证通过才 `Verified=true`；不代替 D 对实际 Job/身份/evidence 的认证、正式成品终态或业务可用性判断。

此入口接收现有 authenticated staging 格式。**正式 CMBKGC01 成品的授权 unwrap/解密/重新封存、目标 grant 和公共 restore 调度仍须 A/D 装配。** 没有 ProviderKey 缺失时回退 functional key；普通 staging 本地通过不能称正式成品全链路恢复通过。

### C4：复用 Redis / 对象恢复

现有 `RestoreRedisHistory/VerifyRedisHistory`、`RestoreObjects/VerifyObjects` 可读取 C scope 输出，无需另一套 Team 状态。新增本机真实回归证明：Redis 只恢复到独立服务器的 `cm:restore-history:<run>:`，不重建活跃 `claw:team:*`；独立 ACL 账号只读，损坏值拒绝。原版本对象恢复到本次新建隔离 bucket，损坏拒绝、原对象不变。

**正式公共目标计划中的 adapter 装配、目标身份/映射和最小权限仍由 D/A 接通。** 没有宣称生产恢复路由、S3 最小权限或正式成品已通过。

## 3. 明确范围和安全失败

- artifactRefs 支持当前 `/team/...` 及历史相对路径。穿越、外部 URL、其他实例绝对路径、错误列表、重复 JSON 属性、不受支持引用不能猜归属。
- 原 archive 完整保存。引用文件原本就缺失、指向目录/链接时，独立验证安全失败并保留副本，不能伪造成“所有产物存在”。没有实现历史已删除文件找回。
- 共享普通布局沿用原 extractor 对 device/socket、挂载跨越、未知 ACL/capability/xattr 的拒绝。B Runtime/Wine 特殊布局不套 C data-only 规则。
- 本轮无业务 schema DDL、无迁移文件/账本改写。旧可选字段、旧备份读取及原安全/Runtime/WorkBuddy 行为保留。

## 4. 其他负责人依赖

| 负责人 | 仍须接通或确认 |
| --- | --- |
| D | 原任务作用域 ReadTeams/NewTeamsModule；真实完整平台/Runtime writer 集合及停止、退出、原状态恢复证明；原 PVC UID，不能只填 coverage JSON |
| A/D | SQL/Redis/对象源最小读取身份及真实 source grant；ProviderKey/签名/密钥、formal material mount；源读取权限与 KEK 分离 |
| B | 现场真实 schema 导入 profile、生成列、northbound_operations 完整版本适配；test 中 toy B adapter 不能当现场配置 |
| D/A | candidate observer/finalizer、正式发布及原版本读回；正式成品认证解密/重新封存；隔离 SQL/Redis/对象/PVC 装配，verify-team-workspace 纳入原能力/路由和原任务映射、原任务安全续做 |
| A/B/D | C 11 项 owner 决策独立交叉复核、全 registry/schema evidence，未把 draft 改 approved |
| D/页面集成 | 根据真实能力/阶段显示原因和动作；没有 grant/目标装配就不开放恢复；validating/candidate 不当正式成功 |

生产保护保持原状：workspace functional_test、acceptance_ready=false。没有镜像发行、推送、部署或现场 Runtime 验收，不推断线上已具备新代码。

## 5. 阶段提交与证据

| 提交 | 完成点 |
| --- | --- |
| 21c72512 | 实际子动作工作许可 |
| 68ec7587 | 公共冻结 writer 覆盖 |
| baaaa3b1 | 未知状态拒绝和独立 quarantine |
| 8cccce6c | 同一 SQL/文件依赖、共享恢复/验证 |
| 26268d11 | 空 Team 的 SQL 覆盖 |
| 2315ab8f | 非空公共 SQL 与真实 Redis/对象恢复 |
| be7cbc38 | 隔离 namespace 和绑定验证身份 |
| 7b5d93b7 | 原 SQL 密文引用绑定，避免公开明文指纹；保护原 stopped 状态 |
| bff7e4c9 | 已删除 Team 不要求恢复已移除的卷 |

日志仅存本机忽略目录 `.local-dev/teams-c-final-20261030/`，不提交访问材料、临时配置或容器数据。

| 日志 | 实际覆盖 |
| --- | --- |
| writer-lifetime-red/green | 先复现父取消后 active work 错变 0，修后动作退出前持有许可；northbound/backupgate 整包 |
| writer-coverage-red/green | public Prepare 先复现漏 writer 仍准入；缺项、错身份/代数/状态/checkpoint、假 participant 和 stopped 回归 |
| team-states-red / team-normalization-green | 未知 member/workflow 先复现后修复；独立 verifier 拒绝执行态 |
| artifact-reference-red / team-artifact-empty-scope | stub 擦除引用先复现；修后原字节保留；空 Team SQL 注册 |
| source-snapshot-red / final-adapters-windows | 未知原 SQL codec 先复现后拒绝；当前 schema/关系/共享卷核对 |
| shared-workspace-red / regression / metadata | data-only 被 Runtime 规则阻断先复现；二进制/中文、错 key、坏终帧、非空目标、缺产物、额外文件、撤权、取消、跨 part、callback 副本 |
| team-verifier-manifest-red/green | source namespace、无控制身份、无 Pod 绑定、任意命令先复现后拒绝；kube 整包 |
| team-public-sql-roundtrip | 实际公共数据库 worker 的内存 SQL 协议夹具：owner/template/icon/历史/不同状态、提交前加密证据、源断开后恢复及独立只读验证；不是现场 profile |
| real-domain-roundtrip | 独占本机 MySQL 8.4、两个 Redis 7 服务器及 MinIO：真实恢复/读回、独立 Redis ACL、损坏拒绝、源不变 |
| plain-fingerprint-red / ciphertext-reference-green | 先复现公开配置泄露明文 SQL digest，改为显式绑定原密文成品 digest；不根据原数据猜来源 |
| stopped-source-red / final-capture-policy-green | 先复现 stopped 源被 running writer 覆盖，修后拒绝，相关包通过 |
| deleted-team-volume-red/green | 先复现已删 Team 仍要求已删卷，修后只留 SQL 历史并清理活动绑定 |
| final-nonempty-sql / final-sql-ciphertext-binding | 当前真实 171 迁移 schema，四个普通/owner Team、七种非空工作项、创建步骤、模板及文件审计进入同一次公共 SQL，最终共享 spec/错卷拒绝；原 SQL 隔离兼容回归 |
| final-linux-adapters / final-linux-worker-kube | Linux 实际 workspace/worker/domain/publicadapter/northbound；最后 worker/kube 改动定向复测。首次只挂 backend 缺合同/文档，改为整仓挂载后通过，未改测试绕过 |

权限和兼容界限：真实 SQL 采样使用本机 root fixture，不是正式源 SELECT-only grant 验收；实际独立 SQL verifier 使用 SELECT-only。现场整库 profile 尚未接通；公共 SQL worker 完整往返使用协议夹具，真实当前 schema 的 SQL 隔离回归复用既有兼容 adapter。Redis 独立只读 ACL 的真实证明仅适用于该本机 Redis 用例。

后端全量及最终结果以本页冻结补记为准。没有前端改动，不重复前轮已通过的构建。任何测试夹具、测试密钥、模拟 Job 都不作为现场 Runtime/正式成品证明。

## 6. 回退与复盘

回退先禁用新能力并核实原 pause/resume journal，保留源、原成品、旧历史及不确定副本；不强清 gate 或删除其他任务保护。本轮无需回退业务 DDL。旧程序不识别 verify-team-workspace 时先禁用对应调度，保留原任务，不重新采集或执行。存在未完成 pause/resume 时不可直接退回不识别新 inventory.Writers 的旧严格解码程序；必须先用本版本恢复能力核实源已原处恢复，再安排回退。

本轮只追 C 实际调用链，复用 SQL worker、flow、work boundary、tar、Redis/S3；没有开发任务自动续跑或新状态机。先用小复现定位，真实非空数据只跑针对性验证。收尾发现 verifier manifest 隔离问题后只补对应复现和 kube 回归。可避免的浪费是 Linux 首次挂载遗漏；后续直接整仓只读挂载，复用独占缓存。首轮全量出现未修改的 20 ms AI 网关用例超时，其整包单独通过。随后 C 的密文绑定/已删卷修复完成，代码冻结后降低并发做一次最终全量；没有为测试改动 AI 网关，也不再扩展开发范围。


## 7. 最终冻结验收及清理补记

- 冻结业务代码 `bff7e4c9`。`go test -p 2 -timeout 8m ./... -count=1`（GOMAXPROCS=2）退出 0：**75 包通过，16 包无测试，0 失败**。日志 `backend-frozen-low-parallel.log`。此前一次 p=4 全量有 1 个未改动的 AI 网关 20 ms fallback 用例超时；该包单独通过，最终低并发全量也通过，没有修改该包。
- 最后真实当前-schema SQL / 密文引用验收退出 0，见 `final-sql-ciphertext-binding.log`；最后 domain/worker/publicadapter Windows 及 Linux 整包均通过，见 `deleted-team-volume-green.log`、`final-linux-capture-policy.log`。其余最后 worker/kube Linux 验收通过，见 `final-linux-worker-kube.log`。
- catalog `scripts/backup-team-catalog.py --check` 与 Git whitespace 检查通过；没有改任何 SQL 文件、迁移账本或 AI 网关源码。未改前端，未发行镜像，未部署服务器。
- 复核本次标签及创建时间后，清理四个本轮独占容器 `teams-c-final-mysql/minio/redis/redis-target` 及其卷。确认无容器引用且创建晚于本轮开始后，删除本轮 `teams-c-final-gocache` 编译缓存；其他对话容器、镜像、既有备份和未知副本未触碰。
- C1～C4 实施及 C5 冻结回归/交接均完成；本页第 4 节是其他 owner 的生产装配依赖，不作为本轮已实现能力。本页第 3 节是明确的支持边界，不以假回执或空数据绕过。
- 推送前再次 fetch，远端 backup 仍为本轮基线 cf52722；全部代码和本交接提交后再正常快进推送，不强推。最终推送 SHA 以根入口及最终交付回复/Git 远端为准。
