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

### 第三工作块：实际运行中取消与 acquiring 事务断点

沿用原操作表持久化取消请求，不新增第二任务状态机。取消 API 不修改原 claim、不撤销恢复权限、不把请求受理当作退出证明；forward guard 拒绝继续读取，原 runner 或独立 recovery 核对停止、恢复事实后同事务关闭根任务/attempt/取消操作。准备阶段证明没有源动作后可直接取消；不认识的旧执行和 publishing/finalization_unknown 仍禁止强制覆盖。UI 支持已有公共运行中任务的取消，区分“请求已受理”和“取消已完成”，同 key 核实结果；五种语言同步。

物理 acquiring 与 runtime_captures/attempt/root epoch 现在通过同事务 journal 提交；插入 journal 故障时实际 gate 和 participant 状态一并回滚。只关闭请求准入但尚无源动作的原任务，可在真实 lease 到期和 recovery 权限下取消并清除其自己的 admission；不释放别人的 gate。旧 acquisition 兼容路径只复用原 generation，不延长时限。

真实 native 验收：正常采集＋准备取消＋已创建 Job 运行中取消三例69.76秒通过；生产二进制入口＋注入真实 acquisition journal SQL 故障两例63.70秒通过。取消例等待真实领取过期，没有手工改根任务或 gate 状态。后端全量、前端构建、取消服务四个传输测试通过。未做真实浏览器验收，也未启用全系统能力。

提交复核：约30分钟完成新的用户操作出口及相邻原子性修复。早期取消用例发现测试组合未带容量路径、SQL capability 禁止语句文本内分号，均修正在原链路而未放宽检查；补封闭阶段诊断后定位一次完成。另修测试随机将加密字节写成同值造成1/256漏注入的问题，改为对原字节异或，未改生产校验。下一工作块集中正式成品/隔离恢复所需的真实权限和提供方，不继续扩充零散 UI。

### 第四工作块：公共控制器精确 SQL 权限与业务门禁分离

新增26张控制表的逐表逐 verb 矩阵、只读授权探测与可审阅 SQL 输出。源 inventory/容量账号独立；不授予控制器 users、instances、配置修改、不可变记录修改、删除或 DDL。现有旧控制角色不扩权。不可变 inputs/records/stop-proof 读取改用共享锁，继续在已锁根任务下防并发，避免为锁定读取误给 UPDATE 权限。

修复生产 metadata pool 沿用业务 SQL gate 的设计问题：公共控制器显式独立 UTC pool，返回前强制精确授权检查，不执行迁移/初始化，不影响普通 business/read/operate 的门禁。原连接不再在自身停写阶段阻塞恢复记录。补恢复中的 readiness 保持：一次空轮询不能把 unresolved task 的错误清除并重新报告可执行。

真实最终二进制用最小角色完成创建→采集→源恢复→validating，并在 business SQL gate 环境启用下通过；真实 MySQL 否认 users/config 写、不可变记录删除及 DDL。原准备 fixture 的 broad control grants 已从这条生产验收撤除；容量仍合成，未扩大成完整 M4。全量后端及授权负例通过，具体部署材料见 public-capture-deployment.md。

提交复核：约半小时，第一次最小权限实跑揭示旧 joined FOR UPDATE 隐式要求修改 immutable input 的权限，改为根任务锁＋EXISTS，而非扩大 grants。一个本地证明 Pod 的两小时 sleep 到期造成90秒等待，已改为六小时并只重建已确认终止的本地专用 Pod。后续先看实际现场状态再跑等待命令；容量接线、发布和独立恢复仍不能由这次最小权限通过代替。

### 第五工作块：实际 MySQL 数据卷容量接入正式入口验收

验收驱动增加 --physical-capacity，运行同源正式 system-backup-registration capacity collector；它在实际 MySQL 数据卷旁以 mysql UID、独立逐表 SELECT 账号检查真实 server UUID/auto.cnf、完整控制表 inventory、实际分配和 Statfs。驱动只转运原报告，不改 observed_at/allocated/available，也不合成 ready；密码内存生成后仅写本地容器私有文件，不输出、不提交。

一次性两 GiB tmpfs 使用合法的一 GiB显式测试元数据预算。最初沿用样例十 GiB预算时，正式 HTTP 创建被正确以422拒绝；只调整隔离测试 config、重新固化签名配置，没有降低生产最小值或预留量。最终实际容量、精确 SQL 角色、正式二进制/mTLS HTTP、真实 Job/内容/源恢复一条链46.36秒通过。后端全量通过；不认作真实生产磁盘持久性、全域容量或正式成品恢复验收。

提交复核：约12分钟完成，复用已有容量生产命令而非新建测量协议。第一次尝试扩大原本地 tmpfs 被环境拒绝，未绕过隔离限制；另建唯一标识的专用2GiB容器并等待原测试退出后更换测试入口，不删除旧容器或其他项目数据。下一步复用这条真实链，不再以准备环境替代恢复/发布开发。

### 第六工作块：失去 forward 材料后的独立恢复重启

生产装配先检查独立 recovery 身份，明确只允许 recover 动作；forward 缺失、过期或动作不正确时，只按原签名配置恢复，不开放新任务。恢复模式不读取源数据库 DSN、不加载 issuer/server 私钥、不启动签发监听、不发布 forward readiness；原 CA 的公开指纹固定在签名部署配置里。原冻结 writer 用恢复绑定接管，不重新发现源数据。

原 Job 绑定补记同时核对原 immutable Secret UID、原加密日记哈希、调用哈希和实际证书数据，拒绝同名替换。真实生产二进制、真实容量及最小 SQL 角色下，forward 正常链32.27秒、移走 forward/source/私钥并重启的恢复链49.81秒通过。后者等待实际 lease 过期，停止原 Job、恢复源 counter、原任务 failed/idle，始终只有一个 Job/attempt；未产生新读取授权。

提交复核：约半小时完成实际重启缺口，复用原测试环境，没有重新建立协议。首次识别公开 CA pin 仍隐含依赖 forward 身份，改为独立签名配置绑定；避免将 recovery 身份当 forward 授权。完整发布、六域采集和独立还原仍未通过，不能以本块恢复成功代替。下一块直接修复用户当前可见的验证中任务退出，不再扩充无实际出口的接口。
