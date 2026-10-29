# Backup / Team integration

当前状态、已完成能力、A～E 全部剩余任务、接手顺序及验收边界，统一见：

**[备份与 Team 整合当前交接说明](../../BACKUP_TEAM_INTEGRATION_HANDOFF.md)**

集成尚未全部完成。普通 Team-data best-effort 数据链可用；公共 v2 目前只完成明确的零实例 workspace functional profile，不能启用或宣称完整全系统备份。文件/编译冲突已处理，不代表生产语义衔接完成。用户已授权本次带明确未完成项的进度推送，不代表部署或业务验收。

## 技术资料索引

- [来源映射](source-map.json)：来源 Git blob 与目标工作树的映射、适配归属；不是整分支 merge 认祖。
- [SQL 映射](sql-map.json)、[迁移清单](catalog.json)：目前164个迁移；历史 SQL 不重写。
- [冲突处理规则](conflict-resolution.md)：保留 Team/owner/WorkBuddy 等现有功能的适配方式。
- [任务准入与取消合同](task-admission.md)：已接入口的技术约束；完成状态以根目录交接为准。
- [当前工作区功能 profile 部署合同](public-capture-deployment.md)：不是完整非空 Runtime 或正式发布/还原能力。
- [验收证据摘要](validation.json)：每条证据的实际范围与限制；普通全量测试不能证明 opt-in 外部用例已运行。
- `reference/` 与 `docs/system-backup/reference/v12/`：原始合同/SQL/设计输入，供溯源，不是当前实施进度。

四份旧阶段计划/执行说明及旧交接正文已从当前目录移除，可通过 Git 历史找回。请勿继续引用旧文件中的“最新状态”“只剩某阶段”或旧镜像作为本轮完成结论。
