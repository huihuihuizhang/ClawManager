# D controller 数据库账号准备（草案）

独立 controller 默认关闭。当前部署样板的数据库用户名是 `sbk_controller`，密码只从
`clawmanager-system-backup-controller-db` Secret 的 `password` key 读取；仓库不创建账号、
不保存密码，也不会自动执行 GRANT。账号和 Secret 缺失时不得启用 controller。

当前二进制的授权唯一来源是
`backend/internal/systembackupcontroller/database_grants.go` 中的 `controllerTableGrants`。

隔离测试可用 `CONTROLLER_ENABLED_SMOKE=1 bash scripts/system-backup-fresh-migration-smoke.sh`：它只在临时 namespace 的全新 MySQL 中创建 `sbk_controller` 和 Secret，复用当前 14 条逐表授权，并在 `SYSTEM_BACKUP_ENABLED=false`、active config `enabled=false` 下验证两副本选主及权限正反例。脚本用 namespace UID 清理所有资源；测试用 `sbk_controller@'%'` 只存在于临时库，不能复制到现有安装。2026-09-18隔离现场测试已通过专用账号正反例、两副本选主与Lease；它不代表现有安装的账号/Secret、首次开启CAS、故障接管或备份Job验收。
只读生成工具可供部署方审查 SQL：

```text
go run ./cmd/system-backup-controller-grants --schema clawmanager --user sbk_controller --host <经批准的精确主机>
```

从 `backend` 目录运行。工具仅输出 14 条逐表 `GRANT`（新增 D 终态告警状态表的 `SELECT, INSERT, UPDATE`），不连接数据库，不创建用户或 Secret，
不输出密码。若确需 MySQL 通配主机 `%`，须显式加 `--host % --allow-any-host`，并先完成网络出口
与账号来源评审；工具不会自行选择通配主机。账号创建、密码注入、SQL执行及 Secret 创建均由
测试安装的授权运维流程完成，不在此仓库自动进行。

启用前必须在真实 MySQL 8.0/8.4 和测试部署中分别证明：`CURRENT_USER()`与显式DB_USER一致、
无活动/授予角色、`SHOW GRANTS`只有当前闭集；正常bootstrap/claim/gate恢复可执行，而跨库、
任一A/B/C业务表写入、DDL、DELETE、GRANT OPTION和Secret/KMS访问被拒绝。改变controller功能后
必须重新评审闭集与正负测。通过这些现场证据前，此文档和工具均不代表P0-0b权限验收。
