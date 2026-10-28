# M0～M2 开发与验收记录

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

## M2：待开发

目标：实际停写、采集 Job、认证结果、撤权/确认退出及源业务恢复；补偿采用独立恢复授权。实际集群链路未通过前不声明 M2 完成，不启用 v2。

## 运行环境

Docker Linux 引擎可用；本轮独占 MySQL 容器 `cm-backup-m0m2-20261028`，仅绑定 `127.0.0.1:54007`，使用合成测试库和任务标签，收尾只清理本轮自有资源。kind/kubectl 可用，但实际集群和 worker 镜像尚未验收。所有未知 Job 结果保留账本，不按 lease 过期或 Job 不存在假定停止。
