# D Runtime / 页面主链交接（2026-10-31）

开发目录：`C:/Users/13542/Desktop/新建文件夹/ClawManager-D`，分支 `codex/d-runtime-round23`。基线 `8578b0bf0bf7de4461b1899e95f2fd0cbef178b0`。未连接 SSH、生产 Kubernetes、在线 KMS 或进行部署；没有改 readiness。

## 当前实施状态

1. **切片 D1（本地已通过）**：旧 Scale / rollout / 升级池 / lab 入口拒绝 native 布局；Scale 保持原 patch 权限并携带原 UID/resourceVersion，冲突重读后拒绝 native cutover 或同名替换；两个 DELETE 携带原 UID/resourceVersion 前提。测试覆盖九类入口、三种布局、权限不足、并发 cutover/替换和删除冲突保留对象。
2. **切片 D2（开发中，尚不可集成）**：显式 native `Ensure` 新建路径、单槽、持久且独占的 ledger、固定节点/PVC/PV/Secret 身份与最小 node profiles。创建保持禁止调度，不生成停止/恢复证明；不对旧池执行热迁移。
3. **生产完整链仍未完成**：实际 `NewDeploymentService` 只构造 workspace；`supportedPublicCapture` 仅允许 functional_test/workspace；`FinishCapture` 将成功结果停在 validating。需继续接 B/C 完整模块、D/A 正式采集/候选认证、最终 publisher 和独立读回。不能把 D1/D2 当成页面六项备份完成。

## A ABI 接缝

保持现有 `PinnedExecutionIdentity`、`ExecutionRecordKeys.Resolve(ctx, Authority, ref)` 与 worker `CaptureKeyJob`，必须验证 installation/task/attempt/phase/config 绑定，不能以进程级 key 替代任务授权。监督正在审查 A `NewInstallationArtifactSigners` 后交接。D 保留共享构造、controller、server 文件修改权。

## 工具及测试

使用监督提供的 Go 1.26.1 与父目录 `.tools/gocache`、`.tools/gomodcache`、`.tools/gopath`，`GOTOOLCHAIN=local`。早期模块下载因沙箱 DNS 失败，已停止 D 的重复下载，改用监督的完整共享缓存。D1 定向测试正在首次编译；以随后补记的实际退出码为准。

## 同步及 SHA

开始时已尝试 `git -c http.version=HTTP/1.1 fetch origin backup`，含 require_escalated；网络分别返回连接重置/无法连接。现有 origin/backup 仍为基线。提交前继续同步；GitHub 登录/统一推送由监督协调，不对 backup 写入，不 force push。

## 必须保留的真实界限

原本 stopped 的实例不得启动；Agent 未声明/证明重启接管时不得推断跨进程恢复；404/DELETE/202 均非正向退出证明。现场原安装签名、原创建请求、最小凭据、节点策略和镜像尚未验证，本地材料不冒充生产证明。所有现场剩余事项在本地功能完成后统一列出。

## D1 验证补记

- 当前代码定向测试：go test -p 2 ./internal/services/k8s -run 'TestLegacyRuntime|TestRuntimeScaleRefuses|TestRuntimeDeploymentService' -count=1，退出 0，包耗时 3.002s。首轮旧命令也通过，但最终以这轮包含 DELETE 冲突的测试为准。
- 提交前 fetch 成功，origin/backup 仍为 8578b0bf，无他人新增提交。

