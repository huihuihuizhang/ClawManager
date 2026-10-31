# D Runtime / 页面主链交接（2026-10-31）

开发目录：`C:/Users/13542/Desktop/新建文件夹/ClawManager-D`，分支 `codex/d-runtime-round23`。基线 `8578b0bf0bf7de4461b1899e95f2fd0cbef178b0`。未连接 SSH、生产 Kubernetes、在线 KMS 或进行部署；没有改 readiness。

## 当前实施状态

1. **切片 D1（本地已通过）**：旧 Scale / rollout / 升级池 / lab 入口拒绝 native 布局；Scale 保持原 patch 权限并携带原 UID/resourceVersion，冲突重读后拒绝 native cutover 或同名替换；两个 DELETE 携带原 UID/resourceVersion 前提。测试覆盖九类入口、三种布局、权限不足、并发 cutover/替换和删除冲突保留对象。
2. **切片 D2（本地已通过）**：显式 native `Ensure` 新建路径、单槽、持久且独占的 ledger、固定节点/PVC/PV/Secret 身份与最小 node profiles。创建保持禁止调度，不生成停止/恢复证明；不对旧池执行热迁移。
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


## 切片及验证补记

- D1 SHA: 5b8b4bfb8947d52138b7c3526444ca903bf3a426，已推送 D 分支；监督独立复测后已合入 backup。
- D2 通过同一个 RuntimeDeploymentService.Ensure 的显式 Native 配置分支调用，拒绝旧池就地改造；单槽 ledger 用独立 Retain CSI PVC，要求 ReadWriteOncePod，pool/slot 分目录持久化；普通旧 Scale、rollout、升级/实验池入口不能接管。固定 Node/PVC/PV/immutable Secret UID；缺权限先拒绝，无凭据明文配置。
- D2 slot 清空所有网络探针；pool TCP 仅为 TLS listener 存活检查，绝不代表 backup_ready。构造显式写入已知 API 默认字段，并对副本规范化后严格比对；未知 admission/sidecar/权限/卷变更均拒绝。
- D2 本地 go test -mod=readonly -p 2 ./internal/services/k8s -count=1 -timeout=180s 退出0，9.867s。覆盖丢 Create 回执后 GET 原对象、不重复创建、默认化模板重试、持久卷/节点/Secret 替换、权限不足、卷别名、旧池和未知修改拒绝。没有使用真实 Kubernetes API，因此这是 client-go fake 下的 API 默认字段回归，不冒充现场 Pod 重启/CSI 排他或 AppArmor/bwrap 成功。
- D2 不自动激活调度、不迁移现有 Gateway，不生成 capability/停止回执。未声明 Runtime 外仓 Agent 的跨进程接管成功。最小容器策略未放宽 privileged/SYS_ADMIN/Unconfined，实际节点 profile 与 Runtime 内部所需权限必须真实执行验证；失败保持受阻。
- D2 提交前 fetch 成功，origin/backup 仍为 D1，无额外 owner 新提交。


## D3 正式候选原 Job 回传（本地已通过）

- 实际 CLI RunFormalCapture 后调用 CaptureKeyJob.ReportCandidate，通过原 mTLS/TokenReview 控制回传；原 nonce、key-use finished、相同 claim/Pod/Job/grant/时间窗核对。未知 ACK 只重传原候选 JSON，不再次 Generate 或采集；不进入 legacy Complete。
- 控制器 Authorize 在同一原 Job/authority 锁事务中写 candidate_cipher/key_ref/sha256；容量只保留一次，重放摘要不同、撤权或 CAS 丢失拒绝。候选不写 sealed/completed/evidence/终态。
- ReadFormalCandidate 只解原加密 journal，支持明确 recovery read 边界，按原 frozen plan 找 Job/Invocation重算并验证候选形状；不读 stdout，不回退当前 worker 文件。下一切片必须将该读入口接独立内容 observer；目前读到候选不等于流已认证/可发布。
- 新迁移 131_backup_v2_formal_job_candidates.sql 已与监督协调占用；不改旧 SQL。catalog 五处自动产物已更新，--check通过。
- 五包完整测试（GOPROXY=off，Go1.26.1）：worker 7.401s、execution 3.358s、cmd/backup-worker 2.999s、migrationcatalog 2.444s、db 1.598s，退出0。Windows sandbox下原有回环mTLS/文件测试失败，按工具规则使用沙箱外本机测试后通过；未连接在线KMS或远端。
- SQL journal 测试通过真实 database/sql transaction API + 严格协议驱动，证明同候选随机重加密只写/占容量一次、错scope/撤权/CAS/容量拒绝；不是实际 MySQL 引擎事务验收。加密读回覆盖 task/attempt/phase/config/job/unit/key/截断。mTLS候选ACK故障测试发现并修复替换Pod身份误接收，回归已通过。
- 本项fetch后发现A1新增7文件1050行，已审查其接口并快进合并backup@3f2fd114；没有覆盖A改动，三用途signer稍后由真实候选/验收/目录owner调用。
- 签名消费点：manifest必须在同任务全部正式part认证后按实际清单摘要授权；acceptance/catalog必须重新取validating后publisher当前claim，不能沿用FinishCapture已释放的capture claim；不预先要求未知artifact digest。


## D3.1 真实本机 MySQL 事务补证

- D3 SHA 7895f8a78227f9a4b4242521645be3bbf262ac50，已推送，监督已独立五包复测。
- 新增 TestFormalCandidateMySQLMigrationAndTransactionalReplay，opt-in环境变量 TEST_D_LOCAL_MYSQL_CREDENTIALS 指向监督提供的本机JSON凭据文件（不打印/不提交），强制127.0.0.1，只创建并删除唯一 ad_d_candidate_ 临时schema。不触碰A库/系统库/生产。
- 使用真实MySQL8.4.13、精确123 runtime_resources DDL、125与131迁移，候选行保留原任务/attempt外键和原资源CHECK。两事务并发同一摘要不同密文只写一次；已commit后丢ACK重放保持原cipher/ref且不重复容量。错误报告/attempt/撤权拒绝；partial-null、空ref、bad-hash、32769bytes、non-Job五类实际CHECK拒绝。
- 真实9000bytes候选回归同时验证容量走ReserveExecutionPayload；原Reserve仅容纳8192bytes，现修复为既有执行payload预算，不放宽旧小型inline注册规则。
- 本机命令：go test -mod=readonly -p 2 ./internal/systembackupexecution -run TestFormalCandidateMySQL -count=1 -timeout=180s，require_escalated仅为loopback连接，GOPROXY=off，退出0，4.451s。测试最终销毁自己的schema。该回归只证明DDL/原方法InnoDB存储事务与CHECK；没有冒充完整SQLRuntimeControl/页面生产验收。


## D4 正式候选消费者 / 完整 CMBKGC01 认证（本地已通过）

- 实际消费者接点：ExecutionJobPorts.ObserveJob确认原Job完成 -> PublicJobOwner.Evidence在无result时 -> ReadFormalCandidate解原journal并核原plan -> 每次调用FormalCandidateKeyFactory -> 独立unwrap逐帧AEAD+认证EOF -> 独占custody保存ciphertext与envelope -> BuildFormalPartResult -> 原saveResult/evidence/sealed observation。后续ReadResult按同一原候选重读两个精确私有版本，不回退worker文件。不是仅新增无消费helper。
- C正式帧解码器支持既有完整public-C向量，严格匹配原KeyRequest、C envelope canonical字节、KEK/version/context/path/index、nonce唯一性、tag/frame hash、连续序列、frame大小、最终EOF及无尾随字节；unwrap后撤权返回零验证结果。Envelope在typed slice分配前检查数组数量/深度/重复属性。无明文/DEK输出。
- 复用staging原锁/意图/容量/原子create-only复制；每次新私有副本只unwrap一次，不重复消费单次权限；重试只读原私有cipher+envelope。失去worker源仍可重试，私有副本损坏拒绝。原CMSTG01观察仍保留相同校验，未增加格式或key回退。
- 按任务工厂ABI：FormalCandidateKeyFactory(ctx, FormalCandidateReadScope) -> FormalCandidateKeyUse。scope含Authority、Job、原Invocation/Candidate、CapturePod与CaptureGrantSHA256，来自原SQL和plan；每次返回的use必须提供Identity、Recheck、Unwrap、Close。D逐次deep-copy、前后复查、精确request限制并Close，不能复用worker的Generate grant。ExpectedUnwrapAccess明确返回backup_dek_unwrap。
- 真实执行者是controller；FormalVerifierIdentity允许Deployment/StatefulSet/Job的实际owner-kind/owner-UID及Pod/SA名称UID，factory必须实际mTLS/TokenReview/owner-chain认证。拒绝capture Pod、SA、Job owner或原capture grant；没有把Deployment UID冒充JobUID，也没有把另一个Pod的JWT借进controller。A须据此装配独立controller当前unwrap权限，而非仅provider capability准入观察。
- FormalKeys缺失时原BuildParts提前拒绝formal plan，不到停写/派发；不能把process-global裸Unwrapper传给所有任务。真实生产NewDeploymentService尚未提供该factory或完整六项模块，因此本项未打开acceptance/readiness；后续D5继续实际生产构造。
- 清理遇到candidate_sha256即保留原副本；正式候选不因失败/取消被旧unreferenced清理误删。
- 五包完整回归：systembackupwire0.748s、staging13.869s、execution3.957s、publicadapter3.498s、worker6.558s，退出0；使用GOPROXY=off，沙箱外仅本地临时文件/回环TLS。后补typed数组预检的wire整包0.747s通过。针对消费者/工厂/转换最终复测结果见下一补记。测试Unwrapper为严格本地夹具，不冒充在线KMS/真实安装权限；实际原任务工厂调用点已经存在，但缺生产材料继续拒绝。
- 同步时发现A真实SQL最小角色回归新增6文件263行，已合并backup@5fdf7637；未覆盖A文件，无其他owner改动。D3.1已推送，合并提交7d0d668c。


- D4最后消费者/工厂/正式转换定向复测退出0：execution3.478s、publicadapter3.153s；提交前fetch/merge成功，无新增远端变化。

## D4.1 原 SQL Evidence 消费者与最小权限（2026-10-31）

- 新增 TestFormalCandidateMySQLActualEvidenceConsumer：独占 ad_d_consumer_ 本机临时库和表级账号，使用实际 PinnedExecutionIdentity、DeploymentService.captureGate 的 deploymentAuthorization 包装器、原 execution plan/Job/candidate SQL。原 attempt=3 的 Evidence 经独立完整流认证、私有封存、saveResult/evidence 到 ReadResult；删除 worker 文件后仍只读原私有版本，未知 ACK 不重复 unwrap。
- 负例覆盖错 attempt、插入更新 attempt 后旧消费者、Job 撤权、部署包装器关闭、unwrap 后 claim 改变、ciphertext/envelope 篡改，均不登记 ModuleResult/evidence。独立 KMS unwrap 与 Kubernetes metadata 是本地夹具，未称为在线权限或物理停止证明。
- 新增独立并发持久化场景：先完整认证实际候选并经冻结计划 ValidatePartResult，再同时启动两个原 saveResult 事务。单份 evidence、一次 len(raw)+65536 容量增量；丢 commit ACK 后保持原随机密文和容量。另有 Evidence 已提交后的两个并发读重试，二者覆盖范围不同。
- 真实 MySQL 发现 evidence FOR UPDATE 与正式 SELECT+INSERT 权限冲突。改为 FOR SHARE 当前读并保留原 Job FOR UPDATE 串行化、唯一内容 ID、全部原字节/owner/expiry 比对和最终 authority 复查；未增加 evidence UPDATE/DELETE 权限，真实账号两类写入均拒绝。正式 publicCaptureTableGrants 和 without-mutation 测试保持原约束。
- ExecutionInputForAttempt 只接受调用方原已认证 Authority 的 attempt，并在事务中要求当前 journal 仍同轮次；不选择更大轮次。首次 ExecutionInput 和 Queue 创建 attempt=1 的顺序及规则未修改，无新增自动重试状态机。worker Authorize/functional workspace/identity 的部署派发仍有首轮限制，不能因此宣称生产多轮派发完成。
- 新结果 AAD 使用真实 attempt。旧版本 attempt>1 若曾经绕过既有输入校验存有 Attempt=1 的密文，新读法明确拒绝；本轮没有原部署数据不存在的证据，也没有重封存、重新采集或旧 AAD 回退。该类历史数据只能在取得原版本与 checkpoint/Job/attempt 的独立认证后另行设计受限迁移。
- 本测试 surrounding control DDL 是 focused 当前列夹具，123 runtime_resources/runtime_captures、125、131 为仓库实际 DDL；不是完整172迁移消费者验收。监督的完整catalog迁移证据见 docs/evidence/ad-supervisor-local-migrations-20261031.json，二者不混称。
- 最终 Go1.26.1 / GOPROXY=off 整包：systembackupexecution 10.428s，systembackupcontroller 4.355s，退出0；本地 MySQL 8.4.13，精确服务UUID固定为 b9c4d686-d4d3-11f1-9eb5-745d22085e06。所有临时用户/库均由测试清理，凭据不输出不提交。原签名/正式发布/六项Runtime生产构造仍继续开发。
