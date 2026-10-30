# B 与统一基线合并，直接交付主仓库 backup

日期 2026-10-30。原 B 交付 `2326adaa642375a5a4a768699be41d1de05985ed`，接收统一分支 `d75b1c529af9ec4c8655ede5654072c23d447393` 的 13 项后续提交。用户已明确：不创建 PR，直接推送 `https://github.com/huihuihuizhang/ClawManager.git` 的 `backup`；不是 Fork。

推送前重新 fetch 的主仓库 backup 为 `4fe83bcde5a8a693dddb2635e9a3e397d6e3472e`，是本地祖先，允许普通快进推送，不需要强推或另造历史。合并没有文本冲突；deployment_platform.go 自动合并同时保留 B PlatformWriterGroup 和 D 原 VerifySource/NFS 采集入口，没有删除准入或授权校验。

本次接收 native pool/slot 的旧 Ensure 隔离和健康识别、安装范围 NFS 来源校验、KEK endpoint 精确主机检查、签名 key 当前有效期，以及跨节点临时 seal 能力通过回执与生产维护前置限制。该临时卷通过回执仍标记 production_accepted=false，不等于正式备份整链通过。

## 实际验证

- `python -B scripts/system-backup-seal-isolated-probe.test.py`：10 项通过，exit 0；probe-tests.log / .exit.txt。仅本地 mock，无集群操作。
- `python -B scripts/backup-team-catalog.py --check`：exit 0；catalog-check.log / .exit.txt。
- `go -C backend test -json -p=2 -count=1 -timeout=3m ./internal/services/k8s -run 'TestRuntimeDeploymentService'`：19 个通过事件（包含子测试），exit 0；runtime-tests.jsonl / .stderr.log / .exit.txt。包括新增 native pool slot/旧 Ensure 保护用例。
- `go -C backend test -json -p=2 -count=1 -timeout=3m ./internal/systembackupexecution ./internal/systembackup/publicadapter -run 'TestFormal|TestRuntimeProfile|TestRuntimeModuleSourceAuthentication|TestPublicCapture'`：精确 json-canonicalization 缓存缺失，setup 失败，exit 1，执行用例 0；composition-tests.jsonl / .stderr.log / .exit.txt。没有下载依赖或用替身库。
- Go 使用现有缓存，GOTOOLCHAIN=local、GOPROXY/GOSUMDB=off、GOFLAGS=-mod=readonly。未对无变化的 C 流式核心/staging 重复测试，原 2326adaa 的有效证据继续保留。

尚缺的原冻结业务输入、正式 worker/observer/finalizer/签名与数据库凭据接线，继续以 B 流式交接为准；本次 merge 不把它们标成完成。没有真实迁移、部署、密钥发放或服务器写入。没有删除其他 owner 的产物。
