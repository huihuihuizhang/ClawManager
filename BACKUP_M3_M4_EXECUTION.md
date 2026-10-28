# M3 / M4 实施记录

开始：2026-10-28 23:19:50 CST（15:19:50 UTC）；硬截止：2026-10-29 05:19:50 CST（21:19:50 UTC）。分支 `codex/backup-team-integration`，起点 `b74c2d24`，来源 `4fe83bcd`。执行完整 `BACKUP_M3_M4_FINAL_PLAN.md`，每个功能块验收后提交并复核。原计划文档改动并入首个实现块，不单独用规划提交充当进度。

## M3.0 已核实

- Docker Linux 正常；C 盘约13.5GB、D盘约26.5GB可用，复用现有本地镜像，避免无关构建和压测。
- 生产 controller 当前只有 ControlLoop，尚无公共 Capture 实际调用。Task API 已具备事务提交、读取及未启动取消。
- `NewPublicCapture` 的 callback、签名/CA/keys、源读取连接及能力回报需要具体生产装配；不得用测试 handler 或合成容量交付。
- 现有 CorePublisher 依赖旧任务表；复用原语但不能创建旧 shadow task。
- 优先修复已确认的 gate/日记恢复窗口，再接生产装配；不重写既有组件。
- 真实源环境授权/审批材料不预设存在；本地生成的隔离测试身份只用于本地验收。缺少材料不启用对应能力，继续可独立开发项。

## 执行与证据

### 第一工作块：实际释放和日记的原子性、历史断点恢复

实现 `Gate.FinishReleaseTx`，公共 owner 在同一事务校验独立 recovery 权限、完成实际 gate release 和公共投影；SQL 故障回滚两者，不留下新跨事务断点。旧版本已经物理释放的任务，必须核对同一 generation、原 frozen registry、全部 participant/intent 恢复及所有 collector 撤权/停止证据才补记；随后以真实恢复事实结束原受阻任务，不重新执行采集。

真实一次性 MySQL + kind 验证原四例及新增“投影 SQL 不可用时保持 releasing，修复后续做”“旧版本缺投影补记、错误 generation/缺恢复回执拒绝”两例；旧断点追加终态验收通过。后端全量通过。源码和日志摘要见 validation.json。原始日志仅本机忽略目录。

同步修复 registry 摘要从 objects 推导，当前127对象/59待 owner review；新增计数、未知决策/重复对象测试，未批准任何 pending 策略。

验收驱动固定为 scripts/backup-public-native.py，实际镜像 digest 和独立 context/container 标签验证，测试资源继续复用。控制器源仍由测试构造，容量还是合成；这一工作块不代表生产装配/全系统采集完成。

提交复核：先修真实已知断点，约25分钟形成完整测试出口；避免复制执行器和重新建集群。发现手工 MySQL Connector 缺 UTC Location 导致测试 panic，已修正；固定验收入口减少 Windows 路径参数返工。下一块接实际生产入口和能力回报，不再横向整理来源。

### 第二工作块：实际生产入口及原 Job 日记缺口恢复

公共 controller 新增显式 public-v1 模式，与旧控制循环互斥；实际 Kubernetes 选主、Pod UID publisher、独立签名 forward/recovery 材料、SHA 固定部署配置、源 SELECT 账号、mTLS 控制服务、受界限 Job 和实际 workspace Worker 已接通。生产能力当前严格为 platform-workspace、functional_test、源实例为零；明确不接受完整备份，不把工作区采集冒充所有 Runtime 已停写。

新增 unknown binding/process 恢复：先独立撤权，再核实原发送 Job/Secret/Pod 与实际进程，不重发 Job、不签发新凭据。允许对原 terminated 容器建立恢复身份，forward 仍拒绝已终止容器。停止 ACK 遇到短暂日记写入失败时，在原观察界限内保存原 ACK，避免 Pod 清理后证据丢失。生产调度错误采用有界退避并继续查询原持久状态；错误期间暂停新任务能力回报，不退出从而遗弃恢复。

真实验收：实际生产二进制选主→实时能力回报→实际 TLS HTTP/RBAC 创建→实际 Job→读取认证解密后的 tar 内容→实际源 counter 恢复写入→validating；原绑定 SQL 写入故障下独立 recovery 找回并停止原 Job，最终 failed/idle，单 task/attempt/Job。最终两例69.87秒通过，定向单元和后端全量通过。容量还是显式合成输入，测试控制账号尚非正式最小权限；不据此启用生产。

提交复核：首次生产运行暴露 issuer 根集合遗漏、readiness owner/generation 装配遗漏、测试 HTTP 路径错误和实际 Kubernetes 默认 QPS 饱和。已逐项修复；这块用时约80分钟，超过预期。效率改进：生产启动的一次日志应覆盖每个封闭阶段，先验证配置/签发/选主再进入长流程；不等八分钟统一超时才检查子进程是否退出。后续复用这一实际入口，优先接用户恢复动作、权限和成品出口，不再重建 native 环境。
