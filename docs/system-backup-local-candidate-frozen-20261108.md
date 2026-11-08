# 本阶段交付：最小闭环本地候选冻结与远测准备

本阶段按用户 2026-11-08 的最新范围收口：整理现有代码、完成可独立验证的修复和必要验证、保存不可变源码候选，准备唯一存储远测方案。**本阶段结束后等待远测条件恢复，不继续实现依赖未验证存储能力的配套功能。** 完整页面备份尚未完成。

## 已完成、已验证的部分

- `ca3cc7f5`：修复 quiesce 的历史测试循环导入。原有 Deployment 暂停、原 checkpoint 随实际暂停内容归档、读回和恢复断言均保留；测试改为外部集成测试，复用 test-only 原夹具，不修改生产权限或成功条件。独立 `1a689892` 基线加此补丁的回归通过。
- `82c72cb7`：增加只读 attachment keeper 命令入口，并在 worker 镜像构建定义中复制同源码的可执行文件。入口只允许 `/source`、只读目录 FD 和只读挂载检查，不需要提供 Node 服务的 TLS/身份参数。独立基线的 Linux CLI/worker 编译通过。**没有构建或运行容器镜像，真实挂载行为仍待验证。**
- 本地候选修复：租户源挂载记录使用原 Pod 的真实节点，并在停止后的检查中使用冻结记录；错误 Pod/节点身份、原记录的错误实例和错误 claim 均拒绝。对应只读 API 回归通过。此部分依赖尚未整体发布的候选，保留在冻结包中。
- 已落盘的停写前准备切片：原 pause intent 提交后才准备 keeper；读取原 task/attempt/冻结 writer，走原 SQL resource journal、真实 Job/Pod 读回和 process CAS。Node 交接未实现时拒绝放行原实例停止。对应顺序回归通过；**不等于真实 keeper 或交接已可用**。
- 冻结候选的公共状态转换逻辑已执行本地故障模型回归：正常 ACK、freeze/thaw 结果未知、日志保存失败、写计数变化和 owner 重启。Linux syscall/设备检查保持 Linux-only，当前原型限定 x86_64。**模型通过不证明内核、Longhorn 或真实恢复能力。**

## 验证范围、命令与清理

验证源码为 Git `1a689892` 的 `backend`、`contracts` 加冻结包 `source/` 覆盖；不以共享工作区其他未提交内容作为基线。最终文件摘要保存在包内 `MANIFEST.json`。恢复源码应在新建的独占目录：先 `git archive --format=tar --output=<独占目录>/base.tar 1a689892 backend contracts`，解包，再复制 `source/backend/` 的文件；不要覆盖共享工作区。

Windows 本地实际执行并通过：

```powershell
go test -p 4 ./internal/systembackup/quiesce ./internal/systembackup/kube ./internal/systembackupcontroller ./internal/systembackupexecution ./internal/systembackupinstallationowner/install -run 'Test(DeploymentCapture|Longhorn|TenantSourceMount|RuntimeSourceStop|OriginalLonghorn|RuntimeTenantPro|RunningTenantPro|OriginalMountAuthor|ProductionPlanUsesHeldCloneClaim|OriginalObserverTenantSource|ExecutionStorage)' -count=1
```

上述命令的 cwd 是独占副本的 `backend`。独立基线另执行并通过：

```powershell
go test -p 4 ./internal/systembackup/quiesce -run '^TestDeploymentCapturePreservesOriginalCheckpointAlongsidePausedObject$' -count=1
```

Linux **交叉编译**通过，测试二进制没有在 Linux 执行；`$verifyDir` 指前述新建独占源码目录：

```powershell
$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -p 4 ./cmd/backup-shared-runtime-node-owner ./cmd/system-backup-observer-deployment-materials ./cmd/system-backup-v2-controller
go test -p 4 -c -o (Join-Path $verifyDir quiesce-linux.test) ./internal/systembackup/quiesce
# 以下在独立基线加 keeper 命令补丁的副本执行：
go build -p 4 ./cmd/backup-shared-runtime-node-owner ./cmd/backup-worker
```

使用独占 `GOCACHE`、`GOTMPDIR`、`GOPROXY=off`、`GOTOOLCHAIN=local`。原始命令、源码 pin 和结果位于本机 `artifacts/sbk-keeper-closeout-20261108/`；最终结果以 `linux-final-result.json` 为准。两次已修复的失败分别为历史测试循环导入、当前 x/sys 缺少冻结 ioctl 常量；旧失败记录保留，不冒充成功结果。未跑完整后端、前端构建或完整任务验收；此前 Windows 全 execution 包的两个 TLS 用例曾在未改基线上复现失败，本轮没有将其标为修复。

所有本轮独占 D 盘测试目录、源码测试副本、归档、编译缓存和测试可执行文件已核对归属并删除。静态远测校验的临时文件也已删除。保留的冻结 ZIP 是**用户要求交付的源码包**，不含测试构建二进制、镜像、缓存或秘密。

## 未验证假设与硬阻塞

| 能力 | 当前标记 | 进入下一阶段需要的证据 |
|---|---|---|
| FIFREEZE/FITHAW、保留可写 FD、sync 行为 | 待真实验证 | 实际 Linux 6.8 节点执行专用 canary、正常解除及写读恢复，无 watchdog/unknown |
| Longhorn 两卷快照及独立 clone | 待真实验证 | 同一轮真实 Snapshot/Content/clone UID、lineage、共同 held 窗口和内容读回 |
| RWO keeper 保持挂载 | 待真实验证 | 原 writer 删除后，keeper 保持同 Node、同 PVC/PV/handle，原卷和 clone 可读回 |
| freeze-stable 设备计数证明 | 待真实验证 | 真实 whole-device、iostats=1、diskseq、write/discard/inflight 数据及实际 provider IO 路径；不依据模型放行 |
| Node 认证 keeper 交接、完整恢复顺序 | 未接通，停止扩展 | 先通过存储远测，再沿原 task 日志接通；目前没有 BindKeeper 实现，不允许完整任务试跑 |
| 安装材料顺序和已有 unit 更新 | 未接通，停止扩展 | SourceRegistry/LonghornVolumes 消费及原 unit 的明确更新流程；当前 copy_exact 仍拒绝不同内容 |
| 页面完整任务、正式发布及独立读回 | 未验收 | 后续同一 task/attempt 的全链证据，不能拼接本轮组件结果 |

旧只读重配置对可写 FD 的限制仍是已知问题。新的冻结/计数算法仅作为源码候选保存；没有将其标成现场资格。Node owner 重启、未知 syscall 或无法证明 thaw 的情况仍保留恢复义务，不能靠清表、过期、404 或强置成功结束。

## 唯一远测入口与停止条件

仅使用 [存储远测步骤](system-backup-storage-remote-acceptance-20261108.md)：专用 loopback 前置检查 → 新建专用 RWX/RWO 测试卷 → 保持挂载 → 两卷冻结与真实 CSI 快照 → 原 FD 解除 → 实际写读与独立 clone 读回 → 核对并清理本轮资源。

步骤中的 Bash/Python 已做本地语法检查，四种 fixture JSON 已构造并校验；退出保护的远程变量转义也已验证。未执行 SSH、kubectl、挂载、冻结、镜像构建或现场操作。现场仍须提供实际连接、工具镜像 digest、StorageClass、SnapshotClass 和对应工具；缺项即停止，不临时放宽配置。

任意失败先尝试本轮原 FD 的明确解除并确认实际写读；未确认时保留测试卷、keeper、原 UID/handle 和日志，不先删除资源或重启节点。watchdog 恢复也判该轮失败。完整命令、输入、通过标准、失败恢复和仅清理本轮资源的步骤均在上述唯一远测文档中。

**只有这套存储验证通过后，才恢复完整任务开发。本阶段不发布镜像、不部署候选、不执行真实备份、不新增配套框架。**
