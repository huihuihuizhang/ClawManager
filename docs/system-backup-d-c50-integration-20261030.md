# C 最新交付与 D 基线对齐（2026-10-30）

## 来源与边界

- C 的最新交付点是 `50b27d7763d545a7905862fa1a1e544a5e14235e`；`5874d7d7fba480fcefbd8ae6e9a3ef22d61442d3` 仅是此前 D 基线的首次接收点。
- 本轮以 `5874d7d7..50b27d77` 的 11 个提交净变更对齐 D 基线，不把分叉的 C 历史直接并入。C 的新交接说明是 `BACKUP_TEAM_INTEGRATION_HANDOFF.md`。
- 公共控制表仍为 `system_backup_v2_*`，共享源 gate 仍为 `system_backup_gate`，生产入口仍为 `cmd/system-backup-v2-controller`。这批 C 增量没有 SQL 迁移；迁移目录及控制表分类由 `scripts/backup-team-catalog.py --check` 校验。
- C 的 TeamData `system_team_data_backup_jobs` 是独立业务能力；不能据此宣称公共 v2 全域采集、正式发布或历史恢复已接通。

## 接手接口与文件归属

| 归属 | 新增或调整的入口 | 接手约束 |
| --- | --- | --- |
| C：TeamData 业务 | `internal/systembackup/team_data.go`、`team_data_worker.go`、`team_data_retry.go`、`team_data_recovery.go`、`internal/handlers/team_data_backup_handler.go`；前端 `teamDataBackupService.ts` | 在线工作进入共享源 gate；重试必须沿用原请求身份；离线还原不确定结果不得重跑。此链仍使用独立任务表。 |
| C→D：公共恢复控制 | `internal/systembackupcontroller/recovery_inventory.go`、`execution_capture_gate.go`、`internal/systembackupexecution/public_recovery.go` | 恢复库存读写继续受 `SQLRecoveryAuthority.CheckTx` 约束；D 负责与唯一公共 controller、原 Job 身份及授权状态核对。 |
| D：源停止与恢复证明 | `internal/services/user_instance_backup_gateway.go` 及对应测试 | 冲突处保留 D 的原生操作回执；不能把 registry 404 或升级停机当作停写证明。C 的旧 `waitStopped` 片段尚需按 D 的原回执接口重新审查。 |
| D：资源审批与排除 | `internal/systembackupresources`、`contracts/system-backup/v12/verifier-contract.schema.json` | C 将执行记录及四张 Runtime 表纳入 40 表控制排除闭包，但 D 的显式测试 capsule 只审批了历史 35 表；C 的测试动态冻结当前待审 registry。为保持 fail-closed，本轮暂缓整组资源排除/测试/contract 变更，须由 owner 明确 5 张表的策略与独立评审后重做静态测试材料。 |
| A：安全与历史读取 | 原 Job 的 KEK、三用途 signer、ProviderKey、task key | A 复审指出 C 的独立 TeamData retry/restore 仍用当前 `cfg.KeyVersion` 和单一公钥读历史成品；不能关闭公共 v2 历史 mapping、签名版本与 Provider 接线任务。 |
| B：writer/relay | 现有 Runtime writer、认证 relay 与公共任务装配 | 本轮没有用 C 的旧 gateway 停止路径替换 B/D 的 writer/relay 接口；非空 Runtime 与现场退出证明仍按现有接手清单验收。 |

A 对 35→40 控制表范围的复审见 [C50 控制排除准入记录](system-backup-a-c50-control-exclusion-review-20261030.md)：五张新表仍待 owner 和交叉评审，当前恢复路径须继续拒绝未审 registry。

A 对本轮源码的只读复审确认：新增公共 recovery 仍通过独立 `Recovery.CheckTx`，未见放宽原 Job 用途/撤销；丢失 writer intent 时仅重建未恢复的元数据，final 仍要求冻结集合和逐条完成。该结论不包含真实 SQL 或 Agent 现场证明。初始候选基底中的 `backupHTTP` 明文令牌风险已在合入前由 `7c1951de` 修复，客户端会在发送 control token 前拒绝非 HTTPS；现场 TLS、停止与恢复证明仍须单独验收。

## 验证与未完成项

- C 净变更在隔离工作树对齐后，相关 Go 包编译检查通过；迁移目录检查通过；新增前端 TeamData 服务测试 3 项通过；前端 `npm run build` 通过。
- Go 定向行为测试在初始候选通过：`internal/handlers`、`services`、`systembackup`、`systembackup/domain`、`systembackup/team`、`systembackupapi`、`systembackupcontroller`、`systembackupexecution`、`systembackupresources`。`systembackupexecution` 首轮在 Windows 高负载下有 1 秒循环用例超时，单用例及全包复跑均通过。重放到 D 新基底后，9 包中 8 包通过；`services` 的并发调度用例首轮 3/4 断言失败，单用例重复 3 次通过。不能把该轮记作完整 9 包通过。
- C 净变更已通过集成提交 `05c2f897` 纳入并推送至 `codex/unified-backup-baseline`；HTTPS gateway 测试桩修正 `f7d5a5bc` 也已推送。C 原始 `50b27d77` 不是该分支的祖先，五张待审批控制表未随净变更放行。
- 完整 `go test ./...` 已在隔离工作树运行两轮，不能记作全绿。首轮在 `05c2f897` 上发现本机 Python 路径缺失、HTTP 测试桩与 HTTPS 生产约束冲突，及 `systembackupevidence` 的时间敏感失败/20 分钟包超时；前两项在补齐 Python 路径与 `f7d5a5bc` 后按包通过。第二轮在 `96c2fa3f` 上以 Python 路径、`-p 4`、每包 20 分钟运行，`ownerrecords`、`publicadapter`、共享 dispatch、controller、迁移、核心执行包均通过；`quiesce/valid`、证据原始 deadline、KMS JWT 过期边界三个时间敏感用例在整轮失败，各自低负载单独连跑 3 次通过。全量 CI/生产验收仍待独立环境给出绿色回执。
- 正式全系统成品、非空 Runtime、历史密钥读取、发布和独立还原的剩余任务，仍以 C 新交接说明和各 owner 的现场回执为准。
- 2026-10-30 远测窗口优先：原生 Agent TLS 和停止/恢复、非空 Runtime participant、真实 SQL/原 Job 授权、现库 inventory 能测则留原始回执；未具备 role/policy/凭据、正式 KEK mapping、完整 writer/permit 的项目不得以临时 grant 代测。明日远测机不可用，今天未完成项必须明确标阻断。
