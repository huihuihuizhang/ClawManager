# M0～M2 开发与验收记录

> 后续计划已按用户最新要求重排为最后两个阶段，见 [M3/M4 最终计划](BACKUP_M3_M4_FINAL_PLAN.md)。M2 欠账移入 M3 前半段实施，原未完成结论继续有效。

本轮开始于 2026-10-28 19:05:35 CST，最长四小时，收尾截止 23:05:35 CST。开发目录 `D:/test/ClawManager-2`，分支 `codex/backup-team-integration`；来源固定 `backup@4fe83bcd`。范围为 M0～M2；M3 发布/独立恢复和 M4 最终部署另一个开发批次。本轮不推送、不操作测试服务器。

## M0：公共执行组件增量整合

已移入用户/实例领域数据面、公共 runner、Job/worker/暂停组件、公共 task-plan ABI、执行循环、领取回执、执行记录、Job Ports 和必要授权增强。私有 control 仅保留库代码，生产没有注册它的 API 或独立控制器。旧 Team、北向业务、旧备份 handler 和安全取消保留。

新来源 082 追加映射为 122，表为 `system_backup_v2_execution_records`；当前 catalog 为 163 个迁移。registry 升为来源当前清单加新增执行记录的 draft；待评审项保持待评审，目录 freshness 不代表恢复覆盖或采集授权。原 119/120/121 字节保持不变。

必要验证：新领域库和执行组件编译通过；真实一次性 MySQL 下 163 个迁移、原授权任务提交/并发去重/回滚和已有执行计划保护通过。阶段后端全量结果及摘要见 `docs/backup-team-integration/validation.json`，原始日志留在本机忽略目录。

阶段复核：M0 的成果是可组合执行组件与 schema 兼容，还没有生产调度/采集闭环。来源已有实现不再重写；后续直接在同一公共循环上装配。发现 CI 安装渲染依赖来源尚未合入的 Broker manifest，尝试后撤回，按原 M4 处理；应在移入工具前先核对其实际输入，避免花时间修与当前执行链无关的部署样例。全量中下载测试误用新 pending registry，按来源历史 15 表正例修正，不扩大生产策略。

## M1：持久 Prepare 链路与执行身份

目标：公共事务准入、唯一 SQL 调度/领取回执、原计划加密保存与读回、真实执行授权及 key 组合。阶段出口必须有真实 MySQL 的提交→领取→Prepare→原计划保存→重启读回，含失权、响应不明和并发验证。

已接公共 SQL writer 与部署 TaskAdmission：原 readiness、物理容量、不可变 profile/input 和新请求合同在同一授权事务内。旧 writer 保留兼容；通过明确 `SYSTEM_BACKUP_EXECUTION_PROTOCOL=public-v1` 选择新协议，不能由旧 enable flag 激活。缺 profile/容量时，历史查询和未启动取消仍可用。

`SQLExecutionWorkStore` 复用公共循环和记录层，领取与回执同事务，Prepare 后保存原 plan 才推进 ready_for_capture；旧格式计划拒绝交给新 sender。公开记录按密文大小另行预留容量，保留原小元数据上限。

`PinnedExecutionIdentity` 提供具体的后台执行身份与 record key 适配：独立 pin 的 Ed25519 信任锚认证部署签名，绑定专用 MySQL 账号/服务器/库、controller owner、配置及 profile 摘要、用途和有效期；原文件移除或替换立即拒绝。只读取签名允许的记录加密 key 版本，不授予 capture DEK、provider、Job、发布或恢复权限。现场部署仍需独立授权方交付这些真实材料，测试签名不能用于现场。

真实一次性 MySQL + HTTP/RBAC 验证创建→领取→Prepare→原计划加密保存。测试在服务端真实提交后丢弃 COMMIT 确认，观察结果不明；重新领取找回原计划，仅调用一次 Prepare。篡改 issuer 签名、修改密文、撤销授权均拒绝。SQL/加密/网络提交故障是真实的，Prepare 业务发现使用明确小型测试 runner，尚不代表 B 实际采集；其真实调用在 M2 验证。测试账号在一次性 schema 使用宽测试权限，不代替生产最小 grants 验收。

阶段复核：本阶段的成果是原子准入、实际持久调度 Prepare 路径和具体执行身份；生产 Capture/Job/恢复组合属于 M2，仍未启用。本轮直接采用来源 writer/plan/loop，把原真实 SQL 准入接成适配器，避免重写。测试中公共 plan 的内部 bytes 使用版本封装，初次错误地直接搜索外层 JSON，已改为正式 Unwrap 后比较；应按协议层验证，减少把正确封装误当实现故障。后续只补实际执行和恢复，不再增加同类基础组件。

## M2：工作区真实采集与源恢复通过，完整阶段尚未完成

**结论：M0、M1 已提交；M2 的 functional_test 工作区纵向链路已通过，但完整 M2 未完成，不能启用生产全系统备份。** 不是只剩部署文件；生产调用方和其他采集/停写域尚有业务实现缺口。

已实现：

- `NewPublicCapture` 将现有 SQL 调度/领取、原计划记录、公共 runner、实际 ConfigMap/Job owner、Worker 结果 reader 接在同一个循环内，复用 Team 已有业务 gate。生产启动入口尚未调用该组合。
- 迁移 123 增加实际资源发送日记、暂停前原状态、采集会话和退出回执；共 164 个迁移，119/120/121 保持原字节。readiness 明确协议、支持的数据域和 acceptance 能力，旧 readiness 不能默认激活新执行。
- Job/Secret 创建前固化原请求，响应不明查询原名称和实际 UID，不盲目重建。领取续约不改变当前执行身份，丢失领取停止后续动作。恢复独立签名授权，不因 forward 到期而失去补偿资格。
- Worker 同时校验任务 mTLS、Kubernetes TokenReview 的 Pod 绑定 JWT、ServiceAccount UID、Job/Pod/Node/卷身份；结果按原任务和 part 校验、验证封存密文并加密持久化。执行私钥仅加密保存在任务域，原始凭据不进入一般日记。
- 实际停止前订阅 kubelet 的明确容器 Terminated 回执，保存原 Pod UID/容器/Node 身份。404、缩零、租约过期不能当停止证明；退出证据不可用时保持门禁，证明恢复后由 recovery 续做。
- 修复共享目录 Linux setgid 的合法保存/恢复：仅目录允许，保留原属组和模式；普通文件特权位继续拒绝。修复恢复 Deployment 的未调度 Pending Pod 被误判异常；仍不能把 Pending 当停止证明。
- 修复前向与恢复锁序差异，控制检查只在原有界限内重试临时错误，失败日志使用封闭错误类别，不泄露文件或凭据正文。

实际验收：

1. 后端 `go test ./...` 全量通过；外部 opt-in 用例的默认 skip 不作真实验收依据。
2. 真实一次性 MySQL 验证 164 个迁移及 M1 提交/加密原计划/COMMIT 确认丢失回归。
3. 一次性 kind（Kubernetes 1.31.2、containerd）+ MySQL + 编译 Linux Worker：正常采集、真实 Job 创建响应丢失、停止证明不可用后重新接手恢复、Prepare 撤权四例通过。实际核对源文件写入暂停和恢复、封存 AEAD/gzip/tar 内容、唯一 task/attempt/Job UID、最终门禁与任务事实。
4. 实际 Linux 文件系统 setgid 捕获/恢复与特权文件拒绝两例通过；认证反例及 Pending Pod 回归通过。

验收边界：源业务是持续写文件的受控 Deployment，不是实际 OpenClaw/Hermes 对话；容量观察是显式合成 fixture，不证明真实存储容量及生产最小授权。授权、TLS 和密钥由隔离测试生成，不作为生产材料。当前 owner 仅允许 `functional_test`，数据库 part 明确拒绝。成功采集只到 `validating`，不宣布发布、备份成功或可恢复。native 验收使用本轮构建的 Worker，最终源码另通过编译和单测，本轮不交付生产镜像。

### 完整 M2 仍欠缺的实现（不得转列成已完成或仅 M3/M4）

- **生产 owner 装配和 readiness 发布**：当前 `NewPublicCapture` 由真实集群验收调用，生产 daemon 尚未接入；只有真实能力齐备才能发布对应 profile 的 readiness。
- **所有数据域和 writer**：SQL/Redis/对象/部署/secret 采集与真实提供方凭据，Lite/Pro Runtime 和后台 writer 的暂停/恢复回调、当前完整 registry 覆盖尚未完成。工作区 fixture 不能替代这些能力。
- **剩余不确定结果恢复**：已覆盖创建响应丢失后查回原 Job；发送后 GET 仍不确定且没有 binding/process 时只保留保护，自动核实续做未完整。物理 gate 已释放但公共投影提交丢失、获取 gate 中途提交不明等窗口仍需专门恢复设计和故障用例。
- **完整恢复入口与观测**：运行中取消、人工核实并继续/恢复业务、受阻原因和实际能力展示尚未完整接通；不得自动解除未知执行的保护。
- **生产权限/真实性验收**：真实容量来源、独立授权/key provider、最小 grants/TLS/卷和节点证明仍需生产组合验证；M3 发布和独立恢复、M4 UI/部署另批进行。

### 阶段复核与效率改进

本次直接贯通了真实工作区采集和源恢复，没有以模块数量或模拟 Job 称完成。实际集群暴露了 CRI 记录先于 Pod 回收、正常 Pending 恢复和共享目录 setgid 三个单元测试未暴露的问题，并修复了其合同源头。

**未能完成全部 M2 的原因**：仍低估了“来源有库”到“生产域全部接通”的工作量；M2 同时包含授权、物理门禁、身份、停止证明和多个数据域，四小时内实际只闭合工作区域。前期诊断错误过于笼统，花时间逐层定位；后改为封闭阶段错误和一条真实链路，定位效率才提高。不能将这些实际缺口改名为部署工作来凑完成。

后续按可用 profile 逐个纵向交付：先把工作区 functional profile 的生产装配与未知结果恢复补齐，再按 SQL→Redis→对象/配置/secret 接真实采集和原 writer；每个域固定一条真实成功链和关键故障点，复用已通过证据。先列出真实依赖和未实现回调，不再先铺框架、反复归档或跑无关大规模测试。

## 运行环境

Docker Linux 引擎可用；本轮独占 MySQL 容器 `cm-backup-m0m2-20261028`，仅绑定 `127.0.0.1:54007`，使用合成测试库和任务标签，收尾只清理本轮自有资源。已使用本轮独占 kind 集群验证真实 Worker 链路；收尾删除本轮集群和 MySQL，不操作其他资源。所有未知 Job 结果保留账本，不按 lease 过期或 Job 不存在假定停止。

收尾：本轮专用 kind 集群与一次性 MySQL 已按真实容器 ID/任务标签核对后删除，未清理其他资源；本轮不 push、不部署。阶段提交后的复核以本文的实际能力清单为准，完整 M2 仍未销项。
