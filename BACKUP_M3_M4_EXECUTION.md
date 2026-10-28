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

### 第七工作块：已恢复源业务的验证中任务可安全取消

修复真正的用户出口：公共采集已封存、尚未发布时，原取消 API 在同一授权事务核对原 epoch、全部 writer 原身份及恢复回执、collector 撤权/停止、sealed attempt、无在途发布/引用/远端效果后，关闭原根任务和取消操作。保留加密 staging、原 sealed attempt 和实际历史，不释放任何当前业务 gate，不改成成功。发布中/结果未知/缺退出或恢复记录仍拒绝。原幂等键查询与权限最终复核保留。详情页面展示验证中取消入口。

真实生产二进制、实际容量/最小角色链验证了正常采集→源恢复→详情查询→取消→再次查询，同 key 返回原操作；删失原恢复回执的两个故障样本均拒绝，取消后原密文逐 byte 保留。最终 native28.35秒通过；前端构建通过，后端全量另记 validation。没有真实浏览器验收，不将 cancel 当成发布/恢复成功。

提交复核：约十分钟完成，首次真实测试发现 capability 只接受 SELECT 后空格而非换行，修正 SQL 排版，未放宽权限检查。额外增加了真实详情查询，避免只验证数据库落点而页面读不出。下一块补持久恢复受阻诊断和实际镜像交付检查，仍保持完整六域/正式还原缺项可见。

### 第八工作块：恢复受阻持久诊断和过期报告保护

原 runner 返回而公共结果无法安全落定时，在独立短预算内记录固定、脱敏的 diagnostic.d.recovery_blocked 事件；必须匹配原 installation/task/request/owner/row-version 和未过期领取，不能报告其他任务或覆盖终态。该记录只解释实际恢复受阻，不授予 source action、不改 gate、不制造退出证明、不改成失败已恢复。根任务锁下按同任务去重。控制角色新增 events SELECT 只用于查询原诊断，仍无业务表权限。

真实停止证明不明用例51.29秒通过：原源 Deployment 保持暂停、诊断恰好一条、重复报告不新增、错误版本拒绝；等待实际 lease 过期后，独立恢复原 Job、源业务恢复，任务 failed/idle。没有手改原领取或业务状态来通过这一用例。定向和全量后端另记。

提交复核：十分钟左右形成持久可见故障事实，复用已有 events/DTO，未新增任务状态机或迁移。原表约束禁止将 capturing 硬改为 finalization_unknown 的 attention，保留原语义而用正式诊断记录，避免为了展示突破控制协议。完整六域/正式发布/独立还原仍未完成；进入镜像接线前继续保持能力关闭。

### 第九工作块：退出监听独立预算与实际 Worker 镜像

Dockerfile 增加正式 backup-worker target：同源静态二进制、scratch、无 server/shell/内置凭据，默认65532；已审阅 Job 为保留文件身份显式使用原 root+最小能力，仍只读源、只写 staging。验收驱动按加载后的真实 digest 运行最终 Worker，支持提取实际 App 镜像内 controller 二进制并记录其 hash，避免测试壳镜像冒充最终 Worker。

最终 Worker 实跑在同时构建 App 的负载下发现退出监听的相邻缺陷：生产 Kubernetes client 的10秒 HTTP Timeout 也限制 Watch。原数据保护没有被绕过，但 ACK 可能在退出较慢时丢失。生产入口现分离普通短请求与 Watch client；Watch 仅由两分钟跟踪 context 限时。原命名空间也按实际 writer 绑定，不混用 Job namespace。

真实延迟退出回归使用13秒 preStop，超过原10秒限制，实际生产二进制＋scratch Worker＋真实容量＋精确 SQL 角色49.93秒通过：退出 ACK、源恢复、内容/详情/安全取消均通过。缺退出 ACK 的故障仍保护资源，未将超时或404改成证明。全量后端及 watcher 选用独立 client 的定向验证另记；App 初版镜像在修复前构建，不视为最终验收，后续需重建并从该镜像提取 controller 再验。

提交复核：镜像阶段发现了测试负载差异，而非只列构建成功。一次本地 fixture 更新使用旧 resourceVersion 发生冲突，改为创建前固化 preStop，避免为测试引入重试状态。初次镜像故障提前读取封闭日志并停止已确认的本地测试子进程让清理完成，没有耗尽八分钟统一超时。下一块复用最终镜像和真实入口接最小 Kubernetes 权限，不重新搭建环境。

### 第十工作块：实际最小 Kubernetes 角色与独立恢复准入

从签名配置导出同一份真实调用权限清单，用于管理员 RBAC 输出和新任务实际 SelfSubjectAccessReview：控制命名空间的动态 Job/identity、源 Deployment 精确名称 GET/PATCH、只读 Pod/RS/HPA、指定 node/PVC/PV/worker SA 与独立选主 lease。没有 exec/log、source Secret list、Deployment创建/删除、无关对象 mutation 或 RBAC 管理。默认不自行申请权限，安装命令只输出可审阅对象。

公共 runner 增加显式 RecoveryAdmission，默认沿用原 Admission 而非放行；生产恢复仅检查原 profile/scope，再由原独立 SQLRecoveryAuthority 执行逐步授权，不依赖新建 Job 的权限。新任务仍必须通过完整权限预检。

真实验收由宿主安装器临时清空本轮原 broad fixture roles，运行正式控制器和 scratch Worker，验证 API server 否认 exec、Secret list、无关源/节点操作；正常实际容量/最小 SQL/Kubernetes角色链40.30秒通过。恢复例确认原 Job 实际存在后撤掉所有 namespaced create 权限和 forward/source/私钥，重启后65.23秒通过，原任务 failed/idle、实际源 counter 恢复，只有一份原 Job/attempt；后端全量通过。新旧 test fixture 权限恢复后才执行自有资源清理。

提交复核：首次实际最小角色暴露 UPDATE/PATCH 写法不符和 shared Admission 错接 forward 检查，均修正真实调用与权限边界，没有补 ALL。一次 ack 路径误限定001导致安装确认超时，改为受限的实际 Go TempDir编号。一次正常用例未及时读取诊断而等了八分钟，这仍是可避免的浪费；已改为正常链出现持久恢复受阻时立即结束测试并保留封闭诊断。下一步只做最终镜像与已实现用户链验收，不重复已通过的大矩阵。

本块恢复测试早期错误地在 create_dispatched 位落盘就中断，这可能发生在真实 API 请求之前；等待到了保护状态而非预期的原 Job 恢复。已让该例先核实真实原 Job UID/owner，再测试恢复。无实际对象的未知发送仍明确受阻，这一自动收敛缺口没有被改等待条件掩盖为完成。

### 第十一工作块：真实 Job 观察与业务进展投影

认证后的原 Pod/进程/Job 通过现有事务写入 job_observations；只保存原身份引用与内容摘要，不保存证书、请求正文或密钥。心跳刷新观察时间，不生成业务进展；原密文实际打开验证后，封存结果和业务进展在同一事务落盘。重复结果复用、不同结果拒绝，迟到心跳不能将 sealed 改回 running。原 HTTP 详情现在能读出实际 Job generation 和 last_business_progress_at，未发布的 artifact_usable/acceptance_ready 仍为 false。

最小 SQL 角色仅为原 job_observations 增加 INSERT/UPDATE，没有业务表扩权。实际正式入口、真实容量、最小 SQL/Kubernetes 角色、scratch Worker45.18秒通过；核对 projection 的 digest 与实际加密结果日记一致，详情/取消后历史仍可读，后端全量通过。没有改变旧备份、Worker 参数或 Team 业务协议。

提交复核：复用现有表和 reader/DTO，不新增一套进度协议。先实际链验证，再补“同心跳只刷新观察时间”边界并以最终源码重新运行；避免只通过纯状态转换测试就认定用户详情可见。当前完整六域、正式成品及独立还原仍未完成，不能以进度展示补足这一缺口。

### 第十二工作块：恢复保护提示与实际整包验证入口

真实详情摘要读取同安装/任务/版本校验过的最近事件，存在原任务 recovery_blocked 记录时直接解释数据仍受保护，并提供事件入口；不把历史诊断当作当前成功或失败。任务已到 validating/publishing/终态时不覆盖后续权威结果；事件读取失败明确未知，不能当健康。请求切换/卸载使用 AbortController，不自动发任务、重试或解除保护。五种语言同步，2个诊断边界＋4个原取消传输测试通过，前端构建通过；未宣称浏览器视觉验收。

增加可复用整包 smoke 驱动，仅识别本轮本地 App/MySQL，独立 schema、随机凭据、独立 Redis、127.0.0.1 HTTPS；结束核对实际容器ID/标签后清理本次资源。真实镜像启动、全部迁移、SPA no-store/JS、登录、原 Team/实例列表、匿名拒绝、缺正式备份授权时拒绝新读写及旧接口独立权限、无残留备份任务已经通过。该 smoke 的业务数据为空，不计作六域/真实 Team 成品还原验收。

提交复核：复用已有事件授权与DTO，未另设状态或恢复协议。首次前端构建发现 Windows 上仅大小写不同的helper/component命名冲突，改为明确不同文件名；没有放宽类型检查。整包测试首次即通过；后续从最终同源镜像复验，不重复铺独立环境。

### 第十三工作块：暂停回执整行缺失不能通过历史恢复补记

最终复核发现 releasedCaptureProofTx 只校验现存 runtime_writers 行，没有证明已暂停者的回执都存在。先以真实已暂停/恢复的 Deployment、原 gate generation/exit proof 复现：删除一条本地 fixture writer 行后原实现错误接受恢复补记，失败用例23.77秒。没有以文档或新增检查替代失败复现。

修复将 physical participant 的原暂停 checkpoint 与冻结原始身份摘要核对，并要求每个实际暂停过的成员都有对应恢复回执。整行丢失、缺恢复标记、错原 epoch 均拒绝；没有收到暂停意图、没有暂停 checkpoint 的原 untouched writer 仍不被强制当作已暂停成员。未放宽任何停机或数据保护条件。

真实缺行用例恢复原始行后22.88秒通过：原补记继续、再次调用幂等、没有重读源数据或重复恢复，最终 failed/idle；后端全量通过。修改只涉及原恢复证明，接口/迁移/Worker/前端不变，镜像必须由这次修复后的源码重建。一次本机 kubectl 客户端产生异常栈，虽然远端测试完成，为得到清晰验收日志又做了一次小规模复跑，没有扩大到全矩阵。

提交复核：这是冻结后的实质安全缺陷，因此允许打破一次镜像冻结；应在阶段实现时同时审查“缺字段”和“缺整行/集合不完整”，避免只覆盖布尔标记错误。后续只验证最终镜像对应二进制和这一改动，不重跑无关前端。

## 本轮最终镜像与交付边界

- 源业务代码：`806d14588bf6caf8ec12e75c0efb71e23c3bf59f`；后续收尾仅文档/证据更新，不改变已测 backend/frontend/Worker。
- 本机 App：`cm-backup-app:m3m4-20261029-reviewed`；Image ID `sha256:27f63eec6d14eaf47e812569e4265ec8d49a9117050a86eac013127127053e83`。
- 本机 Worker：`cm-backup-worker:m3m4-20261029-reviewed`；Image ID `sha256:9a13299fbed6a5f6f729db8339085ac758d0e65b6ac3f0cd154fca5f5953f2bc`；实际加载 manifest `sha256:ca7dbe1bbec0878d8b26e78acbaaaca93a68862ba17dc3c72fc34b7a64c452fb`。
- 从最终 App 提取的实际 controller SHA256：`bd1a941a8ffd787e55755370f9bd48c5ce0a97ae0d0044f29f2fd3ff950ef67e`。实际长退出/内容/进度/取消链58.76秒通过；撤 forward/source/私钥/create 权限后的独立重启恢复56.98秒通过；真实整包启动/HTTPS/迁移/登录/列表/缺能力拒绝通过。
- 上述是本机已实现子链的验收，不是正式 registry 发布、真实浏览器、非空全域正式备份或独立还原验收。没有更新32543，没有修改32443、真实实例或共享服务器。
- 推送目标为 `backup-origin HEAD:refs/heads/codex/backup-team-integration`，禁止 force；最终远端 SHA 在交付消息核对。源 `backup` 分支仍为 `4fe83bcd`，不覆盖同事代码。

全范围 **M3/M4 未完成**。六域/全部 Runtime writer、真实策略评审、正式发布/独立还原、全部用户恢复操作和完整安装回退仍有实现缺口。根目录交接已经逐项列出代码位置、真实验收矩阵、失败原因与效率改进，不把它们写成“只差测试”。

最后复盘：这一轮已有13个能独立验收的开发提交，但仍主要推进工作区可靠性，没有按原最终计划进入完整数据出口；不能用提交数证明整合完成。接手不应重做已通过模块，而应先固定全域生产组合、正式 key/provider 和独立恢复的真实接入位置，再直接贯通。镜像构建应统一完整 Git SHA 与 build args，避免仅短/长 SHA 差异失去缓存。新增缺行故障的“先失败、后修复、实际通过”过程应成为集合类恢复校验的固定检查点。

本轮本地验收资源已收尾：确认原 native.test/public-controller 均退出，删除本轮唯一 kind 集群及两个已核对完整 ID/标签的 MySQL 容器；临时 App/Redis/schema/user 已由 smoke 驱动清理。最终 App/Worker 镜像和本机忽略验收日志保留，没有执行全局 Docker prune/reset、没有删除其他项目资源。
