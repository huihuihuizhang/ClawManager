# D：旧共享 Runtime 到 native pool/slot 的切换入口

2026-10-30，操作员在 `kubernetes-admin@kubernetes` 只读运行[白名单盘点脚本](../scripts/system-backup-d-native-deployment-inventory.py)，退出码 0，远端 `/tmp` 脚本随后删除。此记录固定部署事实和切换条件；没有修改现有 Deployment。

| 项目 | OpenClaw | Hermes |
| --- | --- | --- |
| Deployment UID | `0fd3bcb3-3388-4bba-a48c-13518af1ee9d` | `1cb9ad8c-f269-4443-8310-90c649c4b299` |
| 当前 Pod UID | `bd3a718c-0313-41bd-9a68-da650bfa5e7a` | `39b187c9-dbb4-49c9-a305-e14503b82a2d` |
| 节点 | `k8s-master` | `node1` |
| 实际 imageID | `openclaw-lite@sha256:37c43ba05ff7fd4f0949f274fc67c3e9825f6d3d0f9124b5fc45dc8366c39cee` | `hermes-lite@sha256:6688834a944161d8dada995cdffd90781533b24ab1e75bb2182c46eaee3fb52c` |
| 容器 | 单个 `runtime`，镜像默认入口；无 pool/slot | 单个 `runtime`，镜像默认入口；无 pool/slot |
| 工作区 | 直接 NFS `10.107.165.245:/` → `/workspaces` | 同一直接 NFS `10.107.165.245:/` → `/workspaces` |

namespace UID 为 `337cfe30-2c17-4b8e-b32a-760778b8098e`。两个 Deployment 均为单副本、无关联 Runtime Service、无 PVC、无显式 `securityContext`，Pod 自动挂载默认 ServiceAccount token。当前只有共享 Agent 环境变量，没有 `RUNTIME_AGENT_ROLE`、slot socket/计数、TLS 文件或持久 Agent 数据卷。控制器通过实际 Pod endpoint 而非 Runtime Service 联系 Agent。

## 改造顺序和每阶段出口

1. **原状态固定**：逐实例冻结原 SQL binding、Pod UID、PID、generation、端口、工作区路径和挂载身份；从真实原创建请求的加密 custody 读取恢复配置。现场三个运行 Lite 实例的原 `pod_uid` 为 NULL、原创建请求收据尚未证明存在，不能手工回填或以当前环境变量重建。先用受控新测试实例产生真实收据；旧实例在没有原收据时保持隔离。
2. **并行 native pool**：从固定 Agent 源码 `AgentsRuntime` commit `52f47fc` 构建各 Runtime 的新镜像，并固定镜像 digest。创建新的、不接管旧 Pod 身份的 pool/slot 工作负载：pool 在 19090 提供 TLS 1.3，slot 通过共享 Unix socket 提供单槽生命周期；两者共享准确 `/workspaces`，slot 的 Agent ledger 需要跨容器/Pod 重启持久化且每槽独占。显式提供 Pod UID/namespace/node/IP、控制与报告 token、服务器证书/密钥、端口块、slot 计数。空 `emptyDir` 账本只适合一次性探针，不能作为生产恢复依据。先禁用调度或限制到受控实例，验证 pool 注册、能力 JSON、实际 imageID 和 TLS pin，再放入候选池。
3. **节点沙箱**：现场两个节点的 Ubuntu AppArmor 4.0 均曾拒绝 bwrap 写 `uid_map`。临时 `/usr/bin/bwrap` profile 加仅测试 slot 提权才跑通合成停止/恢复；该 profile 已卸载。生产节点须有受审、持久且限定到 bwrap 的策略和最小容器权限，并分别完成真实 Gateway 启动/停止/恢复验证。不能将临时 profile、全局 sysctl 放宽或测试用 privileged slot 直接视为生产配置。
4. **受控迁移**：主应用部署须固定 pool CA/TLS 配置及真实创建请求加密留存；在一个新测试实例上走原调度器，获得新 Pod/Agent epoch/generation/PID，确认原工作区 UID/GID/mode 和 NFS 目录不变。先有正向停止证明，再通过原恢复请求启动新 PID，最后执行 SQL binding/generation CAS；未知派发保持隔离。迁移一个实例后再考虑其余实例和 Hermes。旧共享 Deployment 不在准备阶段滚动或删除。
5. **完整备份准入**：D 现有 `checkRuntimeWorkspace` 只接受采集 PVC 与 Runtime PVC 的同一 PV/子路径；现场两端是直接 NFS、当前目标 workspace PVC 还是另一条 hostPath。必须交付受审的 NFS 子树归属和完整 writer/participant 检查，以及与该子树同源的采集/恢复目标，不能把共享 export `/` 整体备份或将另一 installation 的写入者静默纳入。现场库仍按独立 080 导入/升级方案处理，不能直接应用 126/127。之后才用原 task/attempt 事务验证 `system_backup_v2_gateway_proofs` 原回执字节、恢复 PID/generation CAS 和 B relay。

现有 [`BuildRuntimeDeployment`](../backend/internal/services/k8s/runtime_deployment_service.go) 生成单个 `runtime` 容器。旧 `Ensure` 对带 `clawmanager.io/runtime-layout=pool-slot-v1`、pool/slot 容器或明确 role 的模板会拒绝回写；它尚不能创建 native 布局。`RolloutImage` 仍按 `runtime` 容器和 HTTP `/readyz` 处理，`Scale` 也未接入 native 的实例转移协议。切换时须由专门的 native 控制器管理新工作负载，并隔离这些旧管理入口。只执行 `kubectl set image` 或新增 `RUNTIME_AGENT_ROLE=pool` 均无法得到上述出口。

已通过的独立 Agent 停止/恢复原回执见[现场证据](evidence/system-backup-d-native-agent-lifecycle-20261030.json)。那次测试镜像已按产物规则删除；其 digest 是证据中的版本 pin，继续部署前必须重建并重新核对。当前 `backup_ready=false`。
