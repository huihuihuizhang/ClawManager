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
## D4.2 独立 verifier 有效期接口

- FormalCandidateKeyUse 增加 ValidUntil() time.Time，必须来自实际独立 grant/capability/task/authority 最早有效期；零值或已到期拒绝并Close。D封存该值与identity，后续改变（包括延长）拒绝，额外以原task/invocation/Job窗取最早限制。
- 原消费者open后立即context.WithDeadline，覆盖custody复制、完整AEAD读取、Gate复查与saveResult。initial Recheck、每次Recheck和Unwrap也使用有界context；没有修改全局WithDEK签名。
- 流验证新增逐次底层Read前后检查context，帧header/payload/EOF间到期不发起后续读取；实际阻塞中的普通文件Read本身由OS返回，但返回后不得继续认证/读取。测试以第一段header读取期间到期证明底层read总数恰好1、零认证结果。
- 真实MySQL新增expired-during-unwrap，原task/claim仍有效但独立verifier窗到期时不登记任何结果/evidence。工厂零窗/过期/延期负例、原窗有效正例通过。
- 三包完整回归退出0：execution11.282s、wire0.414s、staging13.404s；后续最后小型nil-context/期限不可延期检查以最终复测为准。曾有局部变量context遮蔽包名导致构建失败，修正为keyContext后上述三包通过，不抹除该失败。
- 最后nil-context/期限不可延期定向回归：execution3.101s、wire0.809s，退出0。Windows沙箱内文件权限测试拒绝，按既有真实本机文件权限方式复测通过。
## D5.1 部署资源 / Secret 的实际数据面

- 新增 capture-deployment-resources 和 capture-secret-bundle 两个真实worker操作；它们读取原Namespace/固定GVR+name+UID清单，分别调用既有Kubernetes历史序列化器，压缩后经原CMBKGC01流/KMS单次使用，复用原ReportCandidate。实际CLI已调用OpenResourceCaptureSources/RunFormalCapture；无源文件系统、无ServiceAccount token automount、无源写权限或恢复Apply。此项没有宣称NewDeploymentService六项生产构造已经完成。
- ResourceSourceMount属于原FormalCaptureSpec SHA固定材料，指向独立API endpoint/CA SHA/只读source token文件；不读kubeconfig、control JWT或KEK令牌。实际TLS客户端无重定向、无ambient root/凭据。每个GET及记录/EOF前后检查原Job控制权限和独立源SelfSubjectReview（精确SA名称/UID）及当前namespace SelfSubjectRulesReview；额外get对象名、list/watch/mutation、未知nonresource权限、incomplete均拒绝。该API只说明请求namespace里的权限，不证明其他namespace或集群bindings没有额外权限，完整安装owner仍需独立审查其bindings。
- NonResourceRules仅允许列明的标准discovery/health/version路径。/api/*、/apis/*、/openapi/*仅为RBAC非资源discovery规则的精确已知模式，不授予resource请求；独立测试拒绝全局*、/logs/*、/debug/*、/metrics、/healthz/*等其他模式/路径。
- 实际Job模板新增FormalJobMaterials，传--formal-config /run/backup/formal/materials.json并只读挂载原ConfigMap和显式Secret/ConfigMap refs。拒绝挂载目录越界/重名/权限override/任意shell，无workspace或DAC_READ_SEARCH。原worker mount observer必须按部署提供的每个UID/hash核对这些refs；builder本身不伪造现场UID证明。
- 新NewResourceCaptureModule真正物化两个上述Job，经B原CaptureModules/BuildCapturePart。两项均required，缺secret不降级，源SA UID和材料mapping必须独立，错误原namespace/task/attempt/context/index/formal shape拒绝。它是D对六项目录的实际贡献，仍需接入动态完整模块生产工厂。
- 暂停中的Deployment archive同时保留精确原writer checkpoint和当前维护态对象。ResourceCaptureSpec.OriginalWriters由原冻结计划提供，原控制Authorize逐字节对比desc.Writers；API NamespaceUID由controller独立GET核对，源SA UID由实际源API认证。归档header把原checkpoint与对象清单一起加密；独立ReadResourceCaptureArchive核namespace UID/原header/完整精确selection+UID/EOF，并可从DeploymentOriginalReplicas读取原replicas。未从当前0反猜原态，也不改源对象。
- 现有writer adapter尚无CronJob原suspend checkpoint，因此新资源操作遇CronJob明确拒绝，不能保存临时suspend而冒充原始desired。完整profile实现须补对应原writer adapter后才可覆盖此类对象。
- 本地测试：独立TLS源API真实HTTP身份/权限/源GET，两类candidate成功；源SA替换、额外权限、对象UID替换、GET后撤权、scope变化、错namespace读回和截断拒绝。实际DeploymentWriter Observe/Pause/CheckPaused/Resume的client-go fake case记录非零1→0捕获视图→原态1，并序列化保存原checkpoint和历史后独立读回；停止proof是既有fixture，不冒充真实CRI。KMS仍为严格本地fixture，未连接在线KMS。
- 六包整包退出0：worker34.950s、kube3.142s、publicadapter3.401s、quiesce3.137s、execution3.621s、cmd/backup-worker2.862s；本轮未设置SQL opt-in，不能将该execution整包称为新的真实MySQL验收。新增D模块两真实Job物化/缺域/错误独立SA专项另通过3.160s。
- 生产后续仍需：实际6parts完整来源/模块工厂、A5 FormalKeys闭包、source credential生命周期/全部binding准入、publisher新claim/正式三用途签名/immutable finalizer+独立成品读回/终态。另原worker ProviderPermit包含实际Job/Pod身份而FormalCaptureMaterials整体SHA预先冻结，需用原Job自动发行/挂载流程闭合顺序，不能要求用户逐任务人工提供permit，也不能删验签放过。
- 最后原Kubernetes历史兼容/实际pause-archive-resume/双Job物化定向回归退出0：root3.141s、quiesce2.946s、publicadapter3.182s。
## D5.2 同一次 Discover 的原 writer 快照与模块工厂

- LinuxProfileConfig 新增可选 BuildPartsWithWriters；使用时同一Discover先构造writers、逐个Observe一次并验证非空/唯一ID与原UID/generation，再把完整冻结[]FrozenWriter显式传给parts工厂。out.Writers保存同一快照；callback只收独立slice，不能改计划。旧BuildParts路径顺序保留，无新任务/二次发现或恢复时重采集。
- 实际NewPublicCapture的configuredPublicSource增加ModuleFactory(in,inventory,hold,writers)，每个原任务据同一次原快照生成CaptureModules。factory收到deep-copy的input/inventory/writers；目录BuildParts仍使用未被callback修改的原输入。静态Modules与动态factory不能同时指定，原formal key工厂缺失仍拒绝。
- 动态目录输出的资源OriginalWriters逐项精确比对同次冻结快照；错UID/generation/running/checkpoint或缺原writer拒绝。原Authorize继续独立核原plan，archive header和plan因此有同一原来源。实际NewDeploymentService完整六项目录配置仍需下一步装配，未称本callback配置就是完整生产上线。
- 两包完整回归退出0：publicadapter3.469s、execution3.621s。新增真实LinuxProfile.Discover路径验证Observe一次→parts调用一次、原计划不受callback改动、重复/坏状态/Observe失败不到parts；并覆盖资源原writer精确字段负例。SQL source为原已有严格driver fixture，不冒充新的MySQL验收。
- 同步发现A6四文件718行，已保留并merge origin/backup@66440e80（e53753dd），无覆盖他人文件。
## D5.2.1 preflight 分支修复

- 监督复审发现新ModuleFactory闭包在preflight也调用实际backup-only目录；已在闭包入口恢复原source_inventory/preflight短路，RecoveryOnly继续拒绝。不是在factory执行后才绕过结果验证。
- 新TestModuleFactoryPreflightDiscoverUsesOnlySourceInventoryMySQL通过真实configuredPublicSource→NewLinuxProfile→Discover读取独占本地SQL users/instances，返回唯一source_inventory、空writer、无Job spec，并断言动态factory/writer/provider/旧parts回调均0次；执行3.815s退出0。它验证预检只读路由，未将该测试账号称为生产源最小权限或完整schema验收。
## D5.3 实际 NewDeploymentService 的独立 verifier 构造（无环文件引导）

- NewDeploymentService 在实际captureGate构造后调用attachFormalVerifier，原Owner.FormalKeys闭包从同一原SQL恢复input/candidate，复核完整候选/原Pod/capture grant后调用A.NewControllerVerifierFactory.ForCandidate。Authority/Records均保留deploymentAuthorization，Records.Keys仍原Forward，不用裸Forward替换包装器，也不借用capture SA/grant作为unwrap。每次use提供实际controller身份、ValidUntil/Recheck/Close，scope逐字节固定。
- 核心DeploymentConfig.formal_verifier现在只含静态protocol=controller-verifier-materials.v1和path。依赖Forward的独立verifier grant SHA/Workload grant SHA放在独立启动材料包；CLI以SYSTEM_BACKUP_VERIFIER_MATERIALS_FILE和SYSTEM_BACKUP_VERIFIER_MATERIALS_SHA256注入。配置→原完整config digest→Forward→独立verifier grant→材料包hash→外部启动pin单向生成；未排除config任何字段或放松原digest校验。材料包按原路径、独立hash、closed/duplicate-free JSON加载。
- 新bindDeploymentFileInputs是实际constructor调用的共享纯文件阶段：重读原core文件及profile，核Forward/Recovery的安装/controller/config完整digest/profile hash，再加载独立材料包。只有原DB授权选择Forward后才要求verifier文件；独立Recovery路径不被forward材料过期/缺失阻断。Linux门禁未移动/放松。
- Windows本地文件测试实际生成core文件、独立真实签名Forward+Recovery、verifier签名记录和外部材料包，通过同一bindDeploymentFileInputs。core变化仍用原pin、有效签名但DeploymentConfigSHA/ProfileSHA错误的Forward、缺/错材料pin/路径、重复/未知JSON均在verifier加载/provider前拒绝。该阶段不是完整Linux启动；本机wsl --list确认未安装Linux环境，不安装系统，不宣称source/staging启动已运行。
- 正式SQL role新增显式FormalCaptureGrantSQL/SQLFormalCaptureGrantProbe，可选择原public或runtime base。只增加原installation authority/bindings/coverage/references SELECT；KEK fence为既有SQLStore.Bind的INSERT IGNORE+FOR UPDATE增加SELECT/INSERT/UPDATE。evidence继续SELECT+INSERT，不给UPDATE/DELETE；registry/authority不能改写。部署grant CLI新增--formal-verifier，必须显式选择--public-capture或--runtime-control，旧role不默许新权限。实际相同schema账号使用这些新增最小表权限完成了consumer；完整role inventory probe另以严格driver校验，非完整catalog现场权限证明。
- 新真实本机SQL+TLS consumer测试使用实际D的attachFormalVerifier/原Evidence/ReadResult到A自动original owner+capability+独立business grant→controller JWT login→exact-context/opaque ciphertext/version unwrap→完整CMBKGC01认证→私有custody→同一原SQL结果。ACK重复保持1次login/unwrap；篡改候选和原安装owner同fence Unwrap撤销不触及provider。实际签发记录仅本地临时keys，Kubernetes owner metadata为明确fake，非现场权限。
- 测试暴露A5把typed SpecSHA当真实kube.Intent requestSHA比较，已保留真实journal并合入A修复98ccb4d3（backup f4631961），未修改A helper或把fixture SQL改为错误SpecSHA。之后原D fixture的opaque占位wrapped key不满足A真实Transit 60-byte密文格式；改为正确vault:v1/60-byte格式的本地opaque fixture，没有弱化生产验证。
- 最终A/D MySQL opt-in均启用、UUID独立固定，五包完整退出0：execution20.403s、controller4.321s、kekadapter2.990s、v2-controller CLI2.901s、grant CLI编译通过。前述文件/consumer定向5.301s通过。SQL仍使用D focused surrounding schema及实际123/125/127/128/131 DDL，不冒充完整172消费者验收；所有自有临时库/用户清理。
- 本项没有开启acceptance_ready、修改supportedPublicCapture或把workspace-only inventory称为六项完成。动态Generate permit producer/lease/worker消费、真正完整模块生产工厂/Runtime参与者、publisher新claim/三用途签名/immutable发布独立读回及终态仍继续开发。实际controller Pod/SA/owner读权限由独立部署提供并须现场核对，当前五包不能代替Kubernetes RBAC/CSI/CRI实证。

## D5.4 动态 Generate 许可消费端（2026-10-31）

- FormalCaptureSpec/materials 只冻结 A PermitDeliveryPin（独立 delegation SHA、公钥、协议）；不依赖未来 Invocation/Pod/Job 或许可摘要，动态材料禁止混入静态 PermitMount。实际 backup-worker CLI 使用 NewDeliveredCaptureKeyJob，签名字节只能取自原 mTLS key-reserve ACK，旧静态构造显式拒绝动态 invocation。
- Lease 新增公开签名许可，只允许动态 key-reserve ACK 携带，其余 action 禁止；不传 DEK/provider token。未知 reserve ACK 最多以相同原请求/nonce重读两次，原 reserved key-use 只能原字节ACK，不重签、不续期、不接受 using/finished 或替换claim/Pod/key/nonce。旧静态 reserve 不可重放规则保留。
- 原 keyUseTx 保留 A ce375f28 的 UTC 微秒向下截断四行，待合并时不覆盖 A 的独有 SQL 纳秒期限回归。
- 实际本机 mTLS ControlHandler/ControlClient + 独立 TLS JWT/Generate + CMBKGC01 文件封存 + 原 ReportCandidate 测试通过。未知ACK仅一次签名、同nonce两次reserve；正常login/Generate各一次。缺许可、错签名/nonce、登录后撤销均零Generate；动态materials错独立公钥/delegation/缺pin/静态混用拒绝。此测试authorizer明确为状态夹具，不冒充原SQL issuer提交证据。
- Go1.26.1四包完整退出0，原D/A MySQL opt-in均启用：worker35.212s、publicadapter3.434s、execution20.325s、backup-worker2.897s。当前仍未接入PublicJobOwner实际Prepare/Stage/ReadCommitted，紧接着合入A7.1与精度修复后完成；不能称实际生产Generate链路完成。

## D5.5 实际 PublicJobOwner 动态签发接线（2026-10-31）

- NewDeploymentService 的同一 attachFormalVerifier 阶段现在构造 A 具体 ProviderPermitIssuer；外部独立 SHA 材料包可含 provider_permits（独立 Generate 原业务 delegation、专用私钥路径、实际 controller workload、预冻结 DeliveryPin）。core 仍只引用静态材料协议/路径，不增加依赖 Forward 的 hash 环。额外认证 delegation 原签名中的 SigningPublicKey 与 worker DeliveryPin 完全相同；拒绝 pin 替换、delegation SHA 不符、借用 worker identity/server key 路径。
- 实际 PublicJobOwner.Authorize 在已认证原 Pod/Job/mount/process/plan 后事务外 Prepare；原 keyUseTx 取 relay/task/guard/Prepared.ValidUntil 的最早窗并保留 A 的 UTC 向下截微秒入口；在同一原事务末尾 Stage，Commit 后仅 reserve ACK ReadCommitted 原签名字节。每个 key-check/begin/end/candidate 均执行 Stage；Generate 可能在 begin 之前发送，因此第一个 key-check 已提交 unknown，任何后续结束/候选/期限都不释放引用。没有网络调用置于原 SQL 锁内。
- 实际 Authorize 不再固定 AttemptNo=1：经当前 TokenReview 认证的 Pod owner Job 名称/UID，定位原 runtime_resource 的 attempt，再由原 input/plan/guard 认证其仍是当前轮次；不把请求 Context.AttemptNo 或 MAX 当作权限，不创建自动重试。首次 SQL locator JOIN 因 focused surrounding schema 的两种 utf8mb4 collation 失败，改为只定位原资源行，保留原 input/guard 中对 attempts 的独立同轮次认证，未修改生产 DDL/collation。
- 保留真实启动观察窗口：原行已 create_dispatched、UID 空、creating 且未撤销/停止时，先验证原 attempt/plan/完整 invocation/peer，才返回 PendingControl 503；不发许可、不写 key-use、不调用 provider。缺原行、DB 错误、非 dispatched、已撤销/停止、已知 UID 不符或其他 lifecycle 均拒绝。原 controller SQLJournal.Observe 后可正常继续；原 binding 未落库仍由已有 pending 路径处理。
- CheckDeploymentDatabase 增兼容 variadic FormalVerifierInput；Forward 有效时在 early role probe 前严格加载同一独立材料 pin。CLI 在 ConnectPublicBackupMetadata 前解析一次，早期 DB 回调与后续构造复用。Recovery 保持独立，不要求坏/缺 Forward 材料。新增显式 --formal-provider-permits（需 --formal-verifier 与 public/runtime base）：仅给原 references SELECT/INSERT/UPDATE，来源/registry/签名 evidence 不可变，无 DELETE。
- 新实际 mTLS WorkloadIdentity→ControlHandler→PublicJobOwner.Authorize→原 SQL keyUseTx/Stage/Commit/ReadCommitted→worker 动态许可→TLS JWT/Generate→CMBKGC01→ReportCandidate→ReadFormalCandidate 用例，原 attempt3；unknown reserve ACK 丢回复后仅一份原 permit；独立 SQL provider handler 在收到 Generate 时核实 unknown 已提交；login 后原 Generate owner 撤销使 Generate=0。非零纳秒独立最短窗在实际 handler/lease/签名/DATETIME(6)完全一致且向下缩短。
- 同实际 handler 负例：worker 改 attempt、Pod owner Job UID 替换、SQL出现更新 attempt、原 participant 未暂停、pending 中撤销/错 UID/旧attempt，均无许可/key-use/provider。原创建尚待观察先503，实际 SQLJournal.Observe 后恢复原 binding 夹具，同 worker成功。固定部署公钥/delegation/key 路径负例也拒绝。early CheckDeploymentDatabase 正例新精确role、旧role缺 refs 写、额外DELETE、缺材料/错pin均校验；Recovery不要求材料。该early SQL transport为严格只读driver，producer handler为真实本机MySQL临时表级账号。
- 测试修复明确：旧 consumer focused gate 不能覆盖实际 ValidateCollectors，新增用例对 gate/participants 直接使用仓库原079 CREATE片段，并填真实独立 hold_deadline 与非空 paused participant 事实；不绕过检查。其余 surrounding control 表仍为 focused schema，123/125/127/128/131使用实际DDL；不是完整172 migration或真实CSI/CRI/RBAC证据。Kubernetes/TokenReview/挂载内容为明确 local fake API，provider与签发材料为独立临时本机夹具；实际 Linux service 启动与在线部署尚未执行。
- 七包完整（A/D MySQL opt-in启用）退出0：execution36.271s、controller4.464s、kekadapter3.277s、worker35.090s、v2-controller2.823s、grant CLI编译、backup-worker2.825s；此后新增 pending 修复的 actual handler三场景定向14.385s通过，最终受影响三包复测另补。backend/.local-dev 原临时go-build/go-mod缓存经绝对路径/无reparsepoint检查后清理，未动共享 .tools cache。
- acceptance/readiness仍保持原门禁；六模块生产装配、独立 SQL/Teams 源身份消费、validating 后新publisher claim/原业务三用途签名/immutable发布独立读回与终态继续实现，不以本切片的组件回归宣称全部完成。
- pending 修复最终完整三包退出0：execution37.504s、controller4.516s、v2-controller2.835s，A/D MySQL opt-in 均启用；git diff --check 无错误。

## D5.6 SQL / Teams 独立源权限与实际 CLI（2026-10-31）

- backup-worker 的实际 formal 分支不再无条件拒绝 Database/Teams：通过已认证原 control CaptureKeyJob 打开 OpenFormalCaptureSources，再调用原 RunFormalCapture/ReportCandidate。FormalCaptureMaterials 新 Sources 只接受独立源 owner 的签名 grant/credential/TLS mount；SourceConfigSHA256 被原 Invocation 冻结，并由实际 PublicJobOwner.Authorize 比对原 task ConfigSHA256。不能把 KMS JWT/token/DEK 或静态 KEK PermitMount 当源凭据。
- 源 grant 独立签名域 system-backup-original-capture-source.v1，原安装/业务配置、worker namespace/SA UID、具体操作、凭据摘要与有界源权限范围均需匹配，且 issuer 不得等于动态 KEK permit signer。没有未来 Invocation/Pod/Job/hash环。真实原 Job/Pod/Invocation 权限仍来自 concrete 原 mTLS control-backed CaptureKeyJob；本 grant 不能单独构造它。每次读取授权复查原签名文件、credential原字节hash/当前有效期及同一冻结invocation，关闭后拒绝；源最短期限进入 RunFormalCapture context，不能续长。
- 草稿原先把对象版本/TeamIDs写入静态scope，会要求每任务重签，已在交付前修正：静态 DB endpoint/TLS/DB/UUID；Redis固定 endpoint/TLS/server/scope/database/claw:team: key族；S3固定 endpoint/TLS和最多32个精确bucket+非空目录prefix。实际任务的 TeamIDs/对象key/version/SHA/size 仍由原冻结plan和C逐项collector固定，越界在源连接/读取前拒绝。源grant不含逐任务版本或未来Job身份，不需为每次点击人工签source授权。
- SQL实际 OpenDatabase 保持明确 TLS CA/server name、无DSN回退或LOCAL INFILE/multi statement；开连后当前账户、NONE role、DB/UUID须匹配。密码/源S3 key只从独立0600文件读取，不经公共lease。Redis使用明确TLS和专用AUTH后核原server ID/database；S3只用独立静态读源身份及精确TLS根，无ambient proxy，transport拒绝重定向到其他host/scheme。原源owner仍须独立部署真实只读provider权限；本地签名fixture不冒充现场ACL观察。
- domain.CaptureSourceGuarded 在同一实际SELECT-only会话和原RR快照中，在catalog每次query、metadata rows.Next/EOF、逐表SELECT、数据rows.Next/EOF、最终只读Commit前后调用原源授权/Job检查。进行中的驱动读取受原最短context取消。既有 CaptureSource/Catalog 调用仍可保留原签名，未拆SQL事务、未重新连接或分表拼快照。
- 实际本机MySQL测试：独占 ad_d_source_ 库/SELECT-only账号，真实mysql driver包装器不制造SQL结果，仅记录实际逐表SELECT并在首表EOF改原签名材料；实际 RunFormalCapture 使用本机DB后源授权拒绝，后续表读取数零、无cipher/envelope/partial candidate。KMS与key callback为明确fixture，此例注入TCP DB，未声称验证TLS源连接。
- 独立实际生产 opener 测试：OpenFormalCaptureSources→OpenDatabase→database/sql/mysql driver，真实本机MySQL协议STARTTLS+native auth及SQL identity query。正例完成TLS/认证/查询；错CA、UUID、账户、活动role、密码均拒绝，错CA/密码零SQL。协议fixture只返回身份信息，不冒充完整MySQL业务SQL/RR数据，后者由前一真实MySQL例覆盖。共享MySQL实例和全局TLS配置未改动。六场景0.22s/pkg3.099s；监督独立3.037s通过。
- 源S3实际TLS协议fixture+原C collector+文件CMBKGC01：同一原签名grant/credential/prefix，两次连续capture使用不同taskID、TeamID、v1/v2内容与摘要，grant原字节不变，无重签；只读两个指定版本。跨bucket/prefix、原config变更、credential/grant替换均在data GET前拒绝。原control身份为实际mTLS夹具，KMS帧key为明确fixture；不是完整SQL issuer/真实K8s六项验收。Redis scope纯契约用例另验证新TeamIDs/InventorySHA保持同一静态scope，换server/db/scope/全局prefix拒绝。
- 合入 A9/backup@92ec4e7a，未修改A源码。A/D本机MySQL opt-in完整五包退出0：worker35.816s、domain3.232s、execution42.332s、publicadapter3.474s、backup-worker2.883s。此后仅把连续S3测试第二次改为明确不同taskID，定向复测3.044s通过；git diff --check无错误。
- 下一项直接推进 NewDeploymentService 六模块生产factory/原Teams实际inventory与Runtime/参与者，以及新publisher claim/三用途签名/immutable发布独立读回终态。当前默认workspace-only门禁未放开，不以source材料/协议测试宣布完整页面备份成功；完整KEK coverage/adoption/backfill与现场CSI/CRI/RBAC仍未伪造。


## D5.7 Skills 固定版本对象实际 worker / CLI / Job（2026-10-31）

- 新增独立 capture-skill-objects，不借用 TeamID。原冻结请求包含明确 blob ID/key/size、整个原 prefix 的固定版本清单（含未被引用对象）、SQL投影摘要和未打包 blob 的 workspace 需求ID。复用原 Skill PrepareObjectCapture/CopyFrozenObject/WriteCapturedObjectIndex，逐版本核实 response version/size、SHA、真正 EOF 和同一次 GET 的原 metadata；当前 omitted metadata 非零直接失败，不静默丢弃。
- 在原 RunFormalCapture/动态 CaptureKeyJob 路径内生成有界 tar（绑定原 Invocation 的 header、完整对象字节、规范 index），压缩后由 CMBKGC01 原帧实现加密、封存、原 ReportCandidate ACK。每次打开/读取/EOF 前后复查原 Job 和独立 source grant，错误不保留 cipher/envelope/partial。source grant 静态范围只固定独立 TLS endpoint/CA 与精确 bucket/prefix，仍不纳入未来任务/版本，不借用KEK授权。
- 实际 Linux CLI formal 分支抽取为 runFormalInvocation 共用生产阶段；Linux guard 保留。Windows测试经 ReadInvocation→实际 mTLS Ready→该共用生产阶段→独立源签名与 TLS S3→原动态许可消费→TLS JWT/Generate→C帧→原 candidate ACK。authorizer/unknown提交明确为状态夹具，未冒充 D5.5 原SQL issuer；不是完整 Linux 二进制启动或现场S3权限证明。
- CLI八场景通过：正例解密并核实原 blob + 未引用对象和每条 index 的固定版本/size/SHA；错 request.Version、版本缺失/响应版本改变、错SHA、截断EOF、源grant中途失效、跨prefix均零候选，错误版本/越界零源GET/Generate，错误版本零reserve。另补资源操作空workspace的实际 ReadInvocation 回归，修正旧解析器与资源网络捕获契约的矛盾；旧functional workspace不能混带Skills source。
- NewSkillObjectsModule 进入原 module catalog/BuildCapturePart/SkillObjectCaptureJob/immutable WorkerConfigMap。required skill_hub 精确依赖唯一 B users_instances_database，整个原 Source.Skills DTO验证所有8表keyset、owner/version/blob关系。实际4parts装配通过，源投影漂移/错误请求版本/外来blob/重复user/混Team/缺材料拒绝；任何未打包blob仍因缺实际workspace证明而关闭，空对象归档不等于证明。
- 初次 module→Job正例失败原因是测试 materials 仅有 ConfigMap、遗漏正式 attachFormalMaterials 所需至少一个只读 Inputs；补齐明确源 credential Secret mount后，通过实际 BuildCapturePart/4parts断言，没有放宽生产guard。Job测试保证原 backup-worker CLI、显式只读材料、无source filesystem/DAC能力/ambient SA token/arbitrary shell。
- CaptureInventory是显式计划DTO，避免业务models的json:"-"漏字段；完整manifest/findings等仍应由单一原rawSQL快照保存。当前尚未给生产 discovery ReadSkills 赋值、尚未将该投影接入原SQL collector、尚未在默认service注册六模块。未提交的 domain/skill_capture.go 留给紧接着的同一discovery RR/原rawSQL对照切片，不把 helper存在算生产闭环。readiness及默认workspace-only门禁保持。
- 已保留本地改动快进合入 backup@6b360148（A11真实 signer startup）；未修改 A 当前publisher claim生命周期工作。新publisher编排仍须真实 public:PodUID owner、FinishCapture后新Acquire的当时claim，不复用capture token或绕过原guard。
- 合入A11后受影响7包完整回归（A/D真实本机MySQL opt-in启用）退出0：backup-worker3.223s、worker35.604s、kube3.121s、publicadapter3.468s、skillhub1.622s、domain3.209s、execution36.382s；git diff --check无错误。


## D5.8 同一 discovery RR 与原 raw SQL 的 Skills 投影（2026-10-31）

- LinuxProfileConfig.ReadSkills 在原 inventory 的同一个已认证只读RR事务中实际执行；WithSkillCaptureInventory 安装具体 domain.ReadSkillCaptureInventory，不接收伪造现成DTO。前后 VerifySource、user/instance owner验证、source冻结和恢复只读frozen plan语义保留。完整8表schema/keyset与blob/version/binding/materialize投影均有界读取，缺表/必需列/错误engine或PK拒绝，保留rows.Err/Close/ctx失败。
- 原 B NewUsersInstancesModule 将 Source.Skills 深复制进入唯一 DatabaseSpec.SkillsInventory；真实 Module.BuildParts 在该字段与当前 source 摘要不符时整体拒绝。原 functional RunDatabase 与正式 runFormalCapture 都在同一次 raw CaptureSource/CaptureSourceGuarded 返回后、任何有效封存前调用 domain.VerifySkillCapture，比较原8表schema/keyset和owner/version/blob/workspace需求投影。没有第二次SQL快照来拼接或用DTO冒充原始dump。原业务raw列如manifest_json/findings_json/idempotency_key保留。
- 真实本机MySQL测试建立D独占source schema/SELECT-only账号：Skills CREATE直接用008/023/039原DDL，instance_skills workspace_dir使用039原ALTER；users/instances/quotas为明确focused surrounding schema，不是完整172迁移或现场TLS/权限证明。8表全部非空、2blob/2version、原materialize任务、未打包blob两个原workspace_dir候选demo/previous。实际LinuxProfile.Discover的认证/ReadSkills使用同一*sql.Tx；users读取后独立admin提交currentVersion变化，Skills仍读原13证明保持RR快照，然后恢复自有fixture。该并发测试不冒充实际停写证据。
- 同一用例经原 RunDatabase 加密快照、全GCM/gzip读回解码，8表/manifest/findings/物化原字段均核实。漏投影行/错version-blob/缺表/错schema/实际source currentVersion变化均拒绝且无候选。正式SQL另走实际 runFormalCapture→原C帧→完整解密解码与同投影核实，正例11表；漏行/错version/缺表/实际source变化均丢弃cipher/envelope/partial。其keycallback/source-admission callback为明确fixture，真实mTLS/issuer/TLS源身份由D5.5-D5.7独立测试，不把此例算整任务授权证明。
- 原 WorkspaceCaptureRequirement 字段更正为 WorkspaceDirectory：保留原DB workspace_dir，相对于各runtime的Skill install root，明确不是/workspace相对路径。后续必须由原Runtime/实例映射确定root并固定原挂载，不能固定加skills/；需求DTO仍不是证明，未打包blob的对象module仍关闭。
- 已保留dirty同步backup@4cba3582（D5.7监督集成）。完整6包A/D真实SQL opt-in退出0：publicadapter3.997s、worker36.291s、domain3.153s、skillhub1.680s、execution38.101s、backup-worker3.171s；监督另独立跑2个新增真实MySQL suite通过。git diff --check无错误。当前default DeploymentService仍旧functional workspace profile；本切片不声称六部分生产factory已开启。
- 最终publisher需要A合法独立unwrap新入口（不能改旧ForCandidate guard）：输入应为当时真实Publisher ClaimToken（owner=service.PublisherOwner/public:实际PodUID、精确row_version）+原capture AttemptNo/Part定位，具体factory自行从原encrypted plan/candidate/finished key-use/原Job journal读取并认证，不把请求里的Invocation/CandidateSHA当权限。用途只允许原已封存分片的exact provider KeyRequest/capture context；actor用独立publisher-verifier业务grant/workload/Unwrap capability、当前claim/SQL时钟最短窗逐boundary复核。验证阶段可validating/publishing，worker原capture deadline/claim不可复用或伪造。最终不可变对象version/locator与原cipher/envelope receipts由D冻结，A输出原范围WithDEK/Recheck供D读取/全帧认证，无任意request/Generate/重封装回退。需要监督尽快协调A此scope，以免最终编排卡在capture-only授权。


## D5.9 同一完整 workspace 归档中的 Skills 原MD5独立证明（2026-10-31）

- 新 WorkspaceCaptureSpec 冻结原SQL投影SHA、instance/mount、原runtime及layout、原SkillRoot与原workspace_dir/MD5/Binding或Job引用。不是固定把workspace_dir加skills/；WorkspaceSkillRoot与services.runtimeSkillInstallRoot的8组原业务root实测一致（OpenClaw/Hermes/DeepSeek/OpenCode lite/pro，含OpenCode Pro所选嵌套project），服务原hashDirectory golden=7c876ed8f2fc9206f8cc0914cb0a24f0实测一致。生产B模块尚未有OpenCode Pro原project投影，故该类型在模块准入保持拒绝，纯reader golden不能冒充该部署scope已合法接线。
- Request.SkillWorkspace 仅允许正式capture-workspace，必须与原RuntimePolicy.runtime/layout、原请求file/byte预算一致。旧functional workspace/assets/DB及Skills对象路径拒绝混入，不能忽略证明降级。原worker继续完整workspace tar格式与原字节采集，无第二次source读取、额外bookkeeping文件或伪造worker成功flag。
- 原独立 observeOriginalFormalCandidate→staging.ObserveFormalManaged 在同一次独立unwrap/原C帧认证中实际解压并读取捕获tar，按原服务算法匹配SKILL.md、普通非hidden文件和全部父目录entry排序MD5，symlink不入旧MD5但完整归档仍保存/校验。包外和hidden文件不被丢弃；正例另外独立读取同一实际C候选核实.private原字节仍保留。错误root、缺manifest、错MD5、proof容量不足拒绝original custody seal。
- CMBKGC01新增兼容InspectWrappedStream：<=1MiB原帧逐帧认证后经无额外plaintext文件的pipe交给惯性parser，等待parser和全部frame/终端/密文EOF/provider post-use。提前返回、未消费suffix、parser失败、坏末帧/尾字节、使用后撤销均没有验证结果；原VerifyWrappedStream仍同编码/原golden与独立密钥策略，无新DEK返回/unwrap fallback。所有协程在原Unwrap callback返回前等待退出。staging新增可选严格inspector，不改旧调用；只有解析成功与全流/授权成功才可生成private observation。
- 初稿确有漏洞：非regular header仅检查size0，可能让有正确MD5的额外绝对symlink/device/hardlink通过。监督只读overlay复现后已修正：workspace.CapturedArchiveValidator复用同一Layout.entry/pax、精确类型/UID/GID/mode/metadata、原链接范围、禁止hardlink/devices/unknownPAX、跨链接payload和反向父路径替换；逐header验证整个tar，Finish检查完整Wine映射/registry和DeepSeek父目录类型。Linux setgid共享目录、Wine DOSATTRIB和精确C/Z/DeepSeek image-link例外保留；此API只读解析Linux metadata，不放开Windows capture/restore执行guard。
- 监督overlay safe/absolute-symlink/device/hardlink复测全PASS1.263s。新正式observer用有效AEAD/正确原MD5但伪造额外header六场景：safe confined link可封存；绝对link/device/hardlink/setuid/unknownPAX无seal且OpenFormalObserved不能打开完整私有版本。原create-only readonly文件没有被改写，恶意worker夹具在独立新source目录生成其候选。
- 新真实本机SQL Evidence六场景经原encrypted plan/candidate、实际deploymentAuthorization/capture gate、独立observer、private custody、原saveResult：安全link正例成功；其余五种即使AEAD+SkillMD5有效，result_sha256行数0、system_backup_v2_evidence行数0。该fixture的Kubernetes/source admission/Unwrap是明确本机替身，原SQL journal和consumer真实，未冒充完整六模块或在线权限。
- NewSkillObjectsModule不再把未打包blob默认为对象成功：必须声明同一catalog中实际B primary workspace part依赖；B原构造校验每条workspace证明需求来自同一Source.Skills原Binding/Job，runtime/mount/part/SHA固定；最终Module.BuildParts对实际组装Invocation再核全体未打包blob覆盖。仅声明map、缺Scope/伪造目录/root/foreign instance/functional fallback/缺依赖全拒绝。真实4parts封装正例含唯一sharedSQL、Skills对象与原实例workspace；只有后者的独立observer匹配原归档MD5才能有completed ModuleResult。
- parser另对选中file body+map开销、目录hash索引（各<=32MiB）、匹配路径4096字节/128段、零padding<=1MiB设限，MD5索引构建逐步查ctx且按root缓存，防止大量零文件/重复需求/超深目录或无限zero suffix耗尽内存/CPU。容量超限不产生证明。MD5用于兼容原内容身份，整个artifact安全仍由原SHA256/AEAD/EOF/许可复查承担。
- 已保留dirty快进backup@7ffa962c（A12真实publisher lifecycle）。9包完整A/D真实SQL opt-in退出0：wire0.855s、workspace1.088s、staging13.836s、skillhub1.661s、worker36.266s、publicadapter4.060s、execution60.684s、domain3.187s、backup-worker3.199s；原服务root/MD5 golden定向3.076s。最后增加parser容量边界后完整受影响3包再次退出0：skillhub1.702s、execution59.862s、publicadapter4.052s；git diff --check无错误。
- 当前尚未在默认DeploymentService完成六部分正式生产factory/自动源inventory/Runtime与完整participants；以上实际module/observer接线不等于页面六项完成。A下一交付新SQLPublisherCaptureAuthority后，D紧接独立文件实现受控SQLExecutionRecords.LoadPublisherCapture；历史事实不能伪造旧capture ClaimOwner/row_version/phase authority，旧LoadPlan/ForCandidate/capture gate保护不改。最终v12成品仍必须用A9 JCS/JWS及artifact-index.json/system-backup-committed.v1 schema，不复用旧同名签名/commit格式。

## D5.10 新 publisher 权限读取原始加密采集历史（2026-10-31）

- 新 SQLExecutionRecords.LoadPublisherCapture(ctx, *security.SQLPublisherCaptureAuthority) 只接受 A13.1 concrete 独立只读权限，返回同一指定 attempt/part 的 HistoricalCaptureInput、Plan、Job、Invocation、认证后原字节 CandidateJSON、原 request SHA、finished KeyUse、SealScope 和 ModuleResult。HistoricalCaptureInput 没有 Authority/claim/fence；接口没有任意 record-kind/key/ciphertext 或调用者 decrypt callback。旧 LoadPlan/ReadFormalCandidate/ForCandidate/capture gate 均未放宽。
- 先比对 concrete PinnedExecutionIdentity 与 A 的完整原安装/config/profile/deployment/capture-grant/account/server/database/window；要求实际 deploymentAuthorization 保留原部署文件绑定。原 key-custody 的 CheckDeployment 与新 publisher grant/workload/claim 分别复核，不把 public:PodUID 或新 row_version 换入旧 capture 权限。私有 key reader 只读取此次精确原 SQL 行选择的 ref，并核同一原签名 grant 的文件/hash。
- 三次有界短 RR 事务只读取原 task/config/profile/plan/capture_result 与最终选中的原 Job/resource/candidate/result/key-use，全部在相同 concrete Bind/RecheckTx 中。所有 Kube、原 key 文件和 AEAD 操作均在事务外。最终一次 workload GET 后再次检查原材料，再以短 SQL 事务复核精确 claim/facts、所有原密文及期限，返回前另检查 context/deadline；续租要求重建新权限，不能延长旧对象。
- 原 candidate 内本来就加密保存 genuine capture Authority；它只在私有解析中用于原 D.UnwrapTaskPlan/B.DescribePlan 的纯历史形状/绑定校验。必须与原 capture owner、epoch、attempt、config、request、deadline、execution-grant 精确一致，不能合成旧 row_version=1 或当前 publisher token。输出 CandidateJSON 仍是相同原认证字节，公开历史 Input 不携带该 Authority。
- 同时验证原 Job request JSON/hash、Pod/SA/Job/Invocation/Generate identity、finished key-use 与原 AuthoritySHA/nonce、原 capture_result 成功全部 parts、选中结果的 B 校验、原两件 custody seal reference 和统计；原 per-Job result_cipher 也必须解密为 capture_result 中同一个 ModuleResult。所有读取固定 record kind/原 AAD，失败零返回；事务后重复读取防止未认证替换。
- 本机真实 MySQL 14 场景：实际原 Evidence/ReadResult/RecordCapture 后，释放旧 capture claim，真正 SQLTaskClaimStore.AcquireWithReceipt 取得新的 public:PodUID claim，并以 A 独立 Ed25519 grant 构建 concrete authority。validating/publishing/finalization_unknown 正例读取原 attempt3；grant替换/真实续租/候选密文篡改/foreign key ref/缺finished use/裸wrapper/foreign part 均拒绝。末次SA GET期间真实Renew、撤销publisher grant、撤销原业务grant、改candidate密文四例全部拒绝；每次Kube调用断言原SQL连接无事务占用。旧 capture ReadFormalCandidate 仍拒绝，evidence DELETE仍无权限。
- 该测试的停止/恢复时间与 finished-key-use 是明确命名的本机事实夹具；Kubernetes 是假客户端。原 SQL journal/密文/认领回执/权限检查为实际代码和真实 MySQL，不声称完成物理 source 恢复或在线授权。原 Generate+finished use 的真实签发链另由 D5.5 覆盖。初次临时事件表缺 details_present 导致真实回执失败，已按原协议修复夹具，未绕过 AcquireWithReceipt。
- 已保留 dirty 同步 backup@a77a643a 与 A末次I/O修复159717d0。完整controller4.338s/security19.785s/execution91.780s/publicadapter5.181s/v2-controller2.927s/backup-worker4.664s通过，A/D真实SQL opt-in均启用；首次命令误写不存在的grant CLI路径使总命令退出1，已用实际cmd/system-backup-controller-grants单独编译通过。最终返回期限补强后14场景定向复测24.526s通过。git diff --check无错误。
- 后续继续实际六模块生产factory/自动源inventory/Runtime与完整participants，以及 A13.2 独立publisher unwrap 和最终 v12 JCS/JWS immutable 发布/独立读回/终态；不以本只读历史接口宣布页面六项闭环。

## D5.11 Teams 自动 SQL 库存（2026-10-31）

- 新 team.ReadAutomaticInventory 与 B.WithAutomaticTeamsInventory 从原 LinuxProfile 的同一已认证只读 RR 中自动枚举所有未删除 Team，再复用原 ReadInventory 的11表精确schema/owner/member/storage校验。没有预填Team/member ID清单、第二事务、Kube/provider I/O或新gate。原共享PVC名称/namespace/root来自真实SQL；UID来自独立原源映射，按 namespace/PVC 精确匹配；不制造空Team替代品。
- 原受信存储映射只含Redis ID/server/database、原PVC UID、固定对象版本和writer关系。逐项有界、深拷贝，未知/重复/多余PVC、foreign对象/成员和未知schema失败；原provider LIST顺序先按bucket/key排序再入冻结库存。新Team ID在同一Redis源scope内自动纳入下一次SQL发现，无逐任务授权清单。该DTO本身不能授予source权限；其外部Kube/provider实际发现与worker源grant仍须生产service接线。
- 真实本机MySQL+实际 LinuxProfile.Discover：在users已读后的同一RR中，另一个真实连接提交新Team/member，第一次发现仍只有旧Team，下一次同配置发现自动得到两个Team及真实成员；同一source的ONE domain.CaptureSource SQL导出同时通过Teams与非空Skills投影校验。原共享PVC `/team`、独立UID及固定对象版本正例另测；missing/extra/duplicate claim、foreign object/member、unknown schema六例全拒绝。
- 该用例11表使用原 reviewed schema.json 在真实MySQL构造精确column/type/nullability/extra的具名fixture，不冒充原业务迁移/外键验收。BuildWriters/BuildParts是明确fixture，所以本项不等于生产六项factory、物理quiesce或完整source权限已完成。原B gate/writers/recovery包装未变，默认functional/workspace门禁未改。
- 已保留WIP安全快进 backup@4ae5d729（含监督集成D5.10/A精确Kube reads）。完整team0.651s/publicadapter4.841s通过，D真实SQL opt-in开启；监督另独立定向8场景3.903s通过。git diff --check无错误。下一项继续实际service构造/同一acceptance六项spec/自动metadata/全部参与者与原冻结barrier；readiness必须来自真实探测后才放行。

## D5.12 原 SQL 事实 / 事务后源身份绑定（2026-10-31）

- team.ReadSourceFacts 在原认证RR内只读原schema、Team/PVC名称/namespace/root和实际成员/owner/instance关系，不虚构PVC UID或provider身份。新SourceFacts有明确版本、有界行数及关系验证；独立BindAutomaticStorage在事务外绑定原受信存储映射。ReadAutomaticInventory现在复用这两个阶段，保留原schema及完整关系/存储校验，D5.11旧接口行为不变。
- LinuxProfile新增明确ReadTeamFacts/FreezeSources边界；SQL事实、users/instances和Skills仍在同一原RR。RR结束后只可加入具体Teams存储身份和有界CaptureMetadata；基础SQL DTO逐层深拷贝，MatchesInventory拒绝回调替换Team/member/PVC关系。原事实与实际存储身份一起进入同一SourceSHA，再由原模块工厂与writer snapshot消费。
- CheckSource再次读取相同SQL事实并独立重做存储发现，要求同样SourceSHA；metadata不携带每次读取时间或临时令牌。preflight仅SQL，不调用FreezeSources/providers，不生成Job。配置ReadTeamFacts却缺FreezeSources或混用旧ReadTeams会在构造时拒绝。
- 实际本机MySQL+LinuxProfile.Discover/CheckSource测试：FreezeSources入口断言原源DB Stats.InUse为0；尝试改users/instances/Skills及Team事实不能改变原库存；伪造已绑定Team状态被拒绝。相同固定metadata重读通过，原PVC UID/对象版本改变后拒绝。preflight调用次数证明不触发远端resolver。既有同RR外部提交/新Team下次纳入和8个原映射场景保留通过。
- 最终完整team0.632s/publicadapter5.056s通过，D真实SQL opt-in开启；监督此前独立postRR及旧8场景4.181s通过。安全保留WIP快进backup81e418e4（A当前publisher verifier）；git diff --check无错误。
- 本切片的FreezeSources测试明确使用具名provider metadata fixture；实际DeploymentService的capture材料加载、六模块工厂、远端发现及新完整Redis操作仍为未交付WIP，未包含进本提交。页面acceptance/六项guard/readiness未放开，不把本边界当生产装配或完整备份成功。

## D5.13 实际 MySQL Job 保留 formal 材料（2026-10-31）

- 修复真实 BuildCapturePart→kube.DatabaseJobRequest→DatabaseJob→job 的字段丢失：原 w.FormalMaterials 现在逐级传给原只读 attachFormalMaterials；生成的 MySQL Job 实际带 --formal-config /run/backup/formal/materials.json、原材料ConfigMap和独立SQL源credential/provider JWT/public CA的readonly挂载。数据库仍无源filesystem/evidence挂载，捕获staging仍在原task子目录。
- 原DatabaseJobRequest新字段仅用于capture-database；restore/verify携带formal capture材料失败。缺材料、非法挂载目录或附加source filesystem均在实际builder拒绝；没有凭据fallback或任意shell。
- 原 usersInstancesModuleFixture 的真实DB请求，显式先通过worker.ValidateRecordedInvocation，再实际 BuildCapturePart并解码batch/v1 Job：static/delivered permit两正例直接核CLI flag、全部readonly挂载、ConfigMap/Secret原引用、staging task子目录及无源volume；missing/invalid/source volume三负例无Job，纯构造不dispatch。完整kube3.213s/publicadapter5.360s通过，D本机MySQL opt-in开启。
- 监督原字节overlay已在修复前独立复现该问题（3.308s FAIL），交付后可复跑原overlay。此独立提交只包含数据库材料传递与真实manifest回归，不依赖仍未提交的SourceRedisCaptureJob/完整Redis/六项factory WIP。六项页面闭环仍继续实现，readiness未放开。
- 补强static permit缺材料边界：原顶部检查仅覆盖delivered pin；现capture-database分支对任意FormalCapture非nil但FormalMaterials缺失都拒绝。六场景分别含missing-static/missing-delivered，两者均无Job；旧纯functional DB捕获完整回归保留。受影响publicadapter完整5.398s通过，D本机SQL opt-in开启。此补强仍独立于SourceRedis WIP。

## D5.14 原有限 Redis 源、正式 worker 和独立历史回读（2026-10-31）

- 新 capture-source-redis 不借用虚构 Team。固定原 source/version/SHA、run ID、DB、有限正向前缀和排除范围；只读 SCAN 后以单次 EVAL_RO/TIME/DUMP/PTTL/XINFO GROUPS 观察全部选中键，保存二进制 DUMP、绝对 TTL 和完整受限 groups 元数据。保留 cm:restore-history: 排除，重复 cursor、容量、身份变化和时钟偏差失败。空源及全部被排除的源也在写 header 前检查原时钟。
- 新 original-scoped-redis-snapshot.v1 惯性格式有完整 header、排序唯一项、count/hash/EOF；独立 ReadSourceRedisSnapshot 不调用 Redis，拒绝额外字段、错误源、范围、TTL、group、DUMP、终端和 suffix。AdaptSourceRedisHistory 只有完整验证后才生成旧 redis_dump_v1 惯性输入，不执行目标恢复。敏感 payload 由原 CMBKGC01/gzip 加密，无 plaintext staging。
- 实际 CLI、worker、kube SourceRedisCaptureJob、B BuildCapturePart 与正式 source credential/grant 接线已完成；独立签名范围包含全部前缀/排除及原 source reference，原 TLS CA/credential 文件和 SA/namespace/job 逐边界复查。没有 functional Acquire/LeaseDEK 或任意文件源回退。正式模块贡献唯一 D/source_redis；Teams 改用对该实际 part 的依赖并校验同一 run ID/DB/全部 Team key family 覆盖。非空 Instances + 空 Teams 不生成虚构 Team，原每 Team 模式兼容保留。
- 实际独立 observer 在原 unwrap/frame 认证内解析同一 Redis 明文；有效 AEAD 但坏内容不能生成可用 custody/result/evidence。8 场景真实本机 MySQL 经原 encrypted plan/candidate、PublicJobOwner.Evidence、实际 deployment wrapper、独立 observer 与原结果存储；负例 result/evidence 仍为零。另 9 场景实际 CLI 覆盖 mTLS control、signed reserve/delivery、JWT Generate、独立源 grant/TLS 与撤销/替换/错误源身份。
- ValidateFormalCaptureResult 的持久纯形状使用原 ValidateRecordedInvocation，避免已完成候选因原 collector deadline 过去失效；LIVE ValidateControl/runFormalCapture/captureSourceRedis 仍拒绝过期。新真实 SQL 回归在原 plan/candidate 加密前固定 8 秒 invocation deadline、保留原四分钟 task deadline，实际新 public claim 在过期前后读取完全相同的 candidate/plan/invocation 原字节及 SHA，未重写任何期限；旧 capture claim 和 live control 仍拒绝。历史 finished-key-use.Until 同时不得超过原 invocation/task deadline。
- 覆盖边界必须区分：Redis 使用具名本机 TCP/TLS/RESP 协议 fixture，未安装真实 Redis，未实际执行 Lua/DUMP 或目标恢复；CLI control/provider 和 SQL 用例的 Kubernetes/source/unwrap 是具名替身。SQL journal、原消费路径和独立解析是真实代码/真实 MySQL。不能据此宣称在线原源许可、完整物理一致性或六项服务已就绪。
- 完整 8 包、A/D 真实 SQL opt-in 已通过：root4.662s/recovery0.496s/worker36.505s/kube3.246s/publicadapter5.489s/execution129.502s/backup-worker4.375s/v2-controller3.425s。最后空 clock 与历史期限修复后，root4.069s/worker3.561s/CLI3.442s、真实新 SQL 历史11.804s通过；最终完整 controller4.671s/worker36.392s 和实际 SQL 历史、14 原历史、8 内容证据及 observer 定向组合 execution35.636s通过。监督独立 clock3.107s、历史 shape3.151s、CLI3.198s、实际 SQL8场景9.482s、原 deadline SQL11.722s 亦通过。
- 已安全保留所有 WIP 快进 backup@8e6d02f7（A 精确 inventory 最后 I/O 复核）。本提交排除 deployment_capture_materials/production_capture_modules 及四个服务构造文件的未完成六项 WIP；默认 functional workspace guards/readiness 不变。下一项继续实际 service metadata 权限、同一 RR 的业务事实、事务后原源发现、全部 Runtime/participants/挂载与六模块正式工厂。最终不可变 v12、三用途 JCS/JWS、artifact-index.json、system-backup-committed.v1、独立版本读回及真实终态仍由 A 原 publisher pass 接线推进。

## D5.15 六项构造材料的两个实际启动入口（2026-10-31）

- D5.14 最终 SHA e172f24fec153bb530b377e8203acf530a56bf26 已由监督正常推 D 分支；D 不重试此前被自动审批拒绝的外部 push。后续继续小切片而不等待完整工厂。
- 新 ProductionCaptureReference 仅在原 core config 放独立 path/protocol；后生成的 original-six-part-capture-materials.v1 通过实际 CLI 的 SYSTEM_BACKUP_CAPTURE_MATERIALS_FILE/SHA256 注入。core→原 Forward grant→capture bundle SHA 无循环；不把未来 task/Job/hash 或凭据放进公开创建请求。六项 scope 要求 RuntimeSources 和独立材料引用，原 functional guards/readiness 尚未开放。
- 原 CheckDeploymentDatabaseWithInputs 的提前 SQL 准入与 bindDeploymentStartupInputs 的服务文件绑定现在调用同一个 loadProductionCapture；前者仍在任何 source/staging/provider I/O 前。解析限定 8MiB、closed/canonical JSON、原 config/install/controller/capture-grant 精确绑定；固定 6 个必要操作、仅 1 个可选 Teams objects，均要求 Generate、原 permit-delivery pin、正式只读材料及同一 pinned image/namespace/worker SA/control/staging，拒绝任意命令。
- checkProductionCaptureMaterials 重读原 core 与独立文件，要求同一原字节摘要和对象；失败加载不保留可用 capture bundle。恢复路径跳过全部 forward material I/O；删除 capture 和 formal verifier 材料后，原恢复身份仍可启动。此检查是构造模板准入，不代替后续业务源权限、原 Job 工厂校验或运行能力探测。
- 两个真实启动函数以原 Ed25519 grant/record-key 文件测试 11 模式：valid/missing/wrong-pin/wrong-file/extra/replaced/unknown-field/wrong-grant/missing-operation/optional-worker-command/recovery；SQL 身份和 SHOW GRANTS 是具名严格只读 driver，未声称本项实际访问源或执行六部分任务。另实际 CLI 测试保留不完整的 file/SHA 输入供统一 loader 明确拒绝，不静默丢弃。
- 初稿夹具 installation ID 不满足原 profile 协议、Runtime SQL role 未包含原 relay 表；已修正为合法原 ID/原 FormalCaptureGrantSQL(runtime=true)，未放宽验证。定向旧正式 bootstrap/恢复/CLI 和新两入口 execution3.735s、CLI2.889s通过；扩大相关 deployment/Runtime/正式 bootstrap 回归 execution4.301s、CLI2.920s通过。剩余 production_capture_modules.go 仍不包含本提交；下一项实际元数据权限、源发现与 service ModuleFactory 接线继续实现。

## D5.16 原 Runtime writer 快照之后冻结源身份（2026-10-31）

- D5.15 最终 SHA 3e9d53cd9294ff6a72b58de7d406992d6d25b94d。新 FreezeSourcesWithWriters 是旧 FreezeSources 的互斥替代，只允许搭配 BuildPartsWithWriters；原已认证业务 RR 结束、原 BuildWriters/Observe 完成后才解析物理源身份，完整 metadata 和同一原 writer 切片在 module factory 之前进入最终 SourceSHA。旧回调与旧 BuildParts 顺序兼容；preflight 不读远端 metadata。
- CheckSource 使用原 Discovery.Writers 再次发现 metadata，不调用 BuildWriters/Observe 或新建 reservation；传给 resolver 与工厂的 writer/source DTO 都深复制/分离，回调修改不能换掉原 plan。原 Team facts/关系验证与有界 metadata 规则全部保留。
- 既有真实本机 MySQL 同 RR/新 Team 下次纳入测试新增 original-writers 模式：真实源连接 InUse=0、原 writer 只 Observe 一次，resolver 与工厂逐值比对同一原 State；连续 CheckSource 使用原快照，PVC/object version 变化拒绝，preflight 不调用 provider。另四个具名 driver 场景覆盖 Observe 失败、metadata 失败、双 hook 和 legacy-only 工厂误配：无可用 Source/parts、模块工厂调用零次。完整 publicadapter（真实 SQL opt-in）5.407s通过。
- 安全保留 WIP 合并 backup@1469c77e（A 最后 Kube I/O 后原 inventory custody 短复核）；本提交不包含 production_capture_modules.go 草稿，不声称已开放六项服务或完成物理 source 停写。下一步在服务构造中使用本顺序及独立 controller 元数据授权，原 worker source grant 不能被伪造为 discovery Job。

## D5.17 服务和正式 SQL worker 的同一有限业务源权限（2026-10-31）

- D5.16 最终 SHA 1b9b74ebc6df9bdb7f2378d73130ec5feffd371b。继续接线时发现真实不相容：服务 SHOW GRANTS 只允许 users/instances 表级 SELECT，而原共享 domain.CaptureSource 只接受 database.* SELECT。新 reviewed-business-tables.v1 使用与实际 capture 完全相同的 reviewed rules() 生成 BusinessCaptureTables，精确覆盖 Users/Instances、Teams11、Skills8 和所有既有业务依赖；不额外授予 global/schema wildcard、控制表、未知表、role、写入或 GRANT OPTION。未知新业务表仍需原注册表与合法 source-owner role 同步。
- 新 CaptureBusinessSourceGuarded 沿用原单一源 session/RR、原 row/schema/capacity 检查，校验同一数据库/server/无 role/完整有限表 grant。原 capture 在 RR 完成后、交出任何 snapshot 前再次校验该原 session 的身份/权限和当前源授权；中途撤销返回零 snapshot。旧 schema-scope 功能测试接口保留原协议。
- DatabaseSpec.SourceScope 只允许 capture-database 使用该精确版本；正式 worker 的原 encrypted collector 在有独立 SourceAuthorize 时选择新 API，缺独立源授权拒绝。FormalSourceScopeSHA256 将 scope protocol 和同一 reviewed table set 纳入新源 grant hash；旧空 scope 编码不变，不能用旧 database-scope source grant 冒充新有限角色。模块工厂草稿已设置该 scope，但仍未作为可用工厂提交。
- 实际本机 MySQL 新建随机 ad_d_src schema/只读账户、每个 reviewed table 的最小具名空 schema（users 有一行），用真实 SHOW GRANTS 验证服务连接及同一 RR，然后实际共享 SQL capture 成功且全表数一致；真实 UPDATE 被服务器拒绝。缺 skill_blobs SELECT、额外控制表 SELECT、UPDATE、schema wildcard 四例服务和 worker 均拒绝，RR 中原 users SELECT 被撤销后无 snapshot。此用例不冒充原完整业务 DDL/跨表约束、TLS 部署或完整六项任务；只清理自建 schema/account。
- 11 模式纯 grant 矩阵、源 scope/hash/restore 拒绝另测。实际源回归 execution5.023s，完整 domain3.197s/worker36.410s（D 真实 SQL opt-in）通过；原两表服务 parser 回归保留。安全保留 WIP 同步 backup@0ce6fc7f；默认 guards/readiness 不变。

### v12 control evidence producer ABI 协调（未交付）

- 监督已认可原 capture 计划 part=control_evidence、operation=capture-control-evidence；D 负责原正式 Job/Generate permit/CMBKGC01/custody/observer/历史读取接线，A 负责原 SQL 脱敏构造及规范独立验证。绝不把 publisher Unwrap 提升为 Generate、复活旧 capture claim、删除 control/evidence.json.enc 必需项或复制 SQL sealed_payload 冒充正式密文。
- D 建议 A collector 输入原只读 SQL连接、原 task/attempt、固定 coverage cutoff、行/字节容量及原权限复查；输出规范 canonical JSON，直接写 C stream（不 gzip）。独立 observer 调用 A 验证器并核真实 registered evidence；不伪造 owner complete、proof/ref 或 rolling hash。cutoff 可合法早于当前任务终态，不将当前 sidecar 自己的结果纳入自引用。
- 实际私有候选仍使用原 flat artifact name/envelope/KeyRequest/全局 PartIndex；A 发布映射到 control/evidence.json.enc，并保留原 capture path/AAD 与原 envelope 身份供独立读回，不能按目标路径重新加密。此小节是待 A 确认函数签名的协调说明，当前尚无 sidecar producer，不声称闭合。

## D5.18 完整源元数据 census，修复表级 ACL 隐身漏采（2026-10-31）

- 监督在 D5.17/91dc8d69 实际 MySQL 上复现：未给 reader SELECT 的新 instance_unreviewed_payload 会从 information_schema 隐身，旧 75 表导出静默成功。因此 D5.17 不能单独作为完整源启用。本修复要求同一原数据库的独立完整 census，缺材料直接拒绝，不开放六项 guards/readiness。
- 先实际验证 SQL SECURITY DEFINER VIEW：owner 能看到新对象，reader 仍看不到，失败5.148s，故没有交付这种假完整性。改为固定 READS SQL DATA / SQL SECURITY DEFINER 例程，原 source owner 安装，固定名 system_backup_source_schema_census。collector 只有原有限业务表 SELECT、精确该 PROCEDURE 的 EXECUTE 和只读 SHOW_ROUTINE（MySQL 8.4 的 EXECUTE 不能读取定义，SHOW_ROUTINE 用于独立核全文）；没有 schema/global SELECT、EVENT/TRIGGER、DDL、控制行读取或写入。安装/原 owner 材料是后续现场事项，本地用锁定 ad_d_cen 账户代替，未连接生产。
- CALL 前从原 source session 读取实际 DATABASE/partial_revokes、原 ROUTINE_DEFINITION/DEFINER/SECURITY_TYPE/SQL_DATA_ACCESS：既核独立 spec hash，也要求完整正文逐字等于本地 reviewed SchemaCensusProjection(实际database,原definer,原grant模式) 的 BEGIN/END 规范。固定 SQL 只投影对象名称/类型/engine 和 capability canary，无参数、动态 SQL、DML/DDL或任意外部 hash 授权。更新外部 spec hash 也不能放行 foreign DB、漏对象过滤、额外语句或副作用正文；真实 driver CALL 计数不变、原控制行未变化。
- 例程在自己的原 definer context 枚举 base tables/views/triggers/procedures/functions/events；只接受 reviewed 业务表、98 个原 metadata_only 控制表及精确本 census routine。共享叶包 schemaobjects 的名单由原 registry.go/v2_control_registry.go 生成，并与原 Registry() metadata_only 做完整 parity 回归。instance_workspace_write_intents 原被标 metadata_only，现从业务 SELECT 表集移除，不能因旧 domain drop 规则读取控制行。未知表/任何其他 view、trigger、routine、event、非InnoDB、重复或额外结果集、容量超限均拒绝。
- 原 definer 的 SELECT/SHOW VIEW/TRIGGER/EVENT 直接 schema grant、SHOW_ROUTINE 动态 grant 和无入站 role 必须生成实时 CENSUS_READY；能力不足时即使不存在任何未知对象也返回 CENSUS_INCOMPLETE 或 SQL拒绝。definer 是锁定的专用 source-owner 账户，读取 mysql.global_grants/role_edges 只用于其固定 canary，collector不能读取这些表。撤销 EVENT/TRIGGER/SHOW_ROUTINE/SELECT/SHOW VIEW 或授予 definer role，服务和 worker 均无可用 snapshot。CALL 后再次比原定义；原 capture RR 后再次用同一 source session 检查 scope/原源授权和 census，采集中撤销或替换也失败。
- 下划线 schema scope 复用原 QuotedGrantDatabase；实际本机 partial_revokes=false，schema 级 owner 权限明确转义，canary用同一转义模式的精确二进制值，actual mode 也绑定到 SchemaCensusSpec 与独立 source grant hash。近似 ad_d_srcx... 库中的原行，无论锁定 definer（通过 root 调用其只读 probe）或 collector 都不能读取。纯生成器分别覆盖 partial_revokes true/false，未修改共享服务器全局设置。
- DatabaseSpec.SchemaCensus 与 reviewed scope 是同一原独立 source grant 的一部分；hash另包含完整 schema policy 和精确业务表集，服务从同一 capture materials 的 Database模板读取，worker选择同一 guarded API。原无 census 的 D5.17输入不能回退为部分目录；旧 functional SQL 接口维持原协议。
- 实际 MySQL 原 fixture 现在覆盖 27 个具名负例（ACL/隐藏对象/definer权限与role/采集中变化/更新pin伪SQL）及非空业务正例、最终行权限撤销、近似库隔离和模式漂移。新增私有 driver 只计 CALL，转发实际 MySQL BeginTx/Query；不是 SQL结果替身。所有 schema/account/role/routine/event 都在随机 ad_d_* 自建范围内清理。
- 完整 root4.085s/domain3.601s/worker36.952s/publicadapter5.354s、定向 execution6.322s/v2CLI3.352s通过；backup-worker本轮仅编译无匹配 test，不能记CLI行为覆盖。最后规范正文及underscore补强后实际 SQL6.486s、纯domain2.936s通过。已保留 WIP 同步 backup@6ff766ae（A真实服务发布恢复 pass）；仅暂存/恢复本服务文件原stash da21ef22966fa835bd2baa9c5721f0d6a29f9681，保留可恢复副本。未完成的 production_capture_modules/production_source_authority/Discovery材料仍不包含本修复。

## D5.19 原172迁移/177表完整源与独立SQL内容观察（2026-10-31）

- D5.18 SHA a32d45641ac7a93e22c51f8b7761de5a5adf1131。监督随后只读真实172 ledger/177表发现14个已reviewed业务表未被domain覆盖、6个外部历史runtime变体被错误当作必需。已将原 registry 中 gateway key/budget/image/model-grant/classifier、northbound配置/owner及认证历史归入原业务规则；没有把业务/密钥/配置表加入控制排除。Root Registry 也明确6个原 teamDataHistoricalOperationTable 变体为加密业务归档，parity验证原分类。
- 可选集合固定为原六个名称，当前迁移没有创建它们，本仓 services 也没有相应建表入口；不编造运行时建表来源或新建空表使源通过。完整census决定真实存在集合，存在即必须有精确SELECT，缺权限不能隐身；缺失只允许这六项。原实例事实若存在Linux Lite/gateway WorkBuddy，两个已observed UID/allocator表必须存在，不能将该功能称未启用。必需核心/当前迁移业务表仍全部要求存在与权限。
- 新测试用原 ApplyPinnedMigrations、原 server UUID/database/catalog hash 在自建 ad_d_full 库实际应用全部172迁移，验证177原base tables，实际只读角色导出82个当前业务表、逐表对照原非空rows/counts。既有库只读监督probe另PASS；没有修改监督保留库。原控制行始终无法SELECT，95个实际控制表不会进入业务snapshot。
- 测试最初误将管理连接 parseTime=true 复用于捕获，真实 northbound_admin_settings datetime 被原 rawCell guard 正确拒绝。现管理/metadata连接保持true、捕获池按真实worker保持false；没有转换time.Time掩盖零日期损失。worker原 databaseConfig 保持raw并明确UTC；TLS命名协议fixture只新增精确一次 SET time_zone = '+00:00' 的OK，其余SQL仍拒绝。
- 原DDL实际插入非空challenge/key行：微秒datetime、全零datetime、NULL/空值区分、DECIMAL(18,8)精度和原token hash均逐字保留；已存在可选历史表另验证unsigned BIGINT最大值与NUL/0xff二进制。启用原WorkBuddy事实但缺UID、可选表已存在却未授SELECT，服务和worker都无snapshot；合法授予该已存在原表后才纳入导出。
- 新 ObserveBusinessCaptureSchema 在同一原source/census边界冻结精确存在表清单、完整schema摘要及reviewed分类/恢复策略policy SHA；不包含数据行。CaptureSchema进入原Invocation/加密plan/hash，live worker同时核原schema/policy，独立observer对同一C帧内gzip/SQL JSON逐项验证：schema、精确表集、policy、原rows/tables、内存容量及原Teams/Skills投影。没有信任worker的完成标志或只验AEAD。监督已复现不同合法policy hash被初稿忽略，已在统一VerifyBusinessCapturedSnapshot比较actual/expected policy，补纯验证及真实SQL原consumer负例。
- 实际完整源snapshot→原CMBKGC01候选→真实原encrypted plan/candidate/Job→实际Evidence/deployment wrapper→独立observer/private custody→SQL ModuleResult/Evidence：valid成功；缺gateway_keys、schema变更、错误policy、夹带控制表、suffix、错误count即使AEAD有效也零result/evidence。Kubernetes/producer key+unwrap/finished-use仍为明确本机fixture，source SQL/RR/原consumer/独立解析真实；本测试不声称实际TLS原源许可或完整六项任务已运行。初稿沿用8frames却设32MiB，原wire正确拒绝，已在Invocation加密前设64frames，未删budget guard。
- 三类原认证历史在target normalize明确drop；其余11个新业务/secret/config域的非空未知owner schema没有identity fallback，仍需完整exact owner restore adapter，失败回归保留。这里交付原源采集与独立观察，不能借此宣称这些域DR验证、完整六项服务或最终v12发布已完成。实际factory草稿已消费SQLSchema，但仍排除提交。
- 完整root4.314s/domain3.784s/scope0.375s/publicadapter5.488s通过；UTC fixture修复后worker36.414s、实际SQL/custody/observer组合execution34.368s通过。安全保留两worker文件stash44084051f27b41d6685f2bd97288488d6115784f合并backup45ae224b（A control-evidence新operation/CLI/两份C流），无冲突，保留双方CE隔离guard与CaptureSchema/UTC。合并后完整worker36.498s/domain3.789s/backup-worker CLI5.024s、实际SQL/完整schema/旧原consumer/启动组合execution36.722s通过。监督独立原schema+frame overlay29.925s、原分类/不同policy3.202s通过。
- 控制sidecar分工已更新：A交付原worker operation/pull/CLI；D接 ce.CaptureLocator 两份原control_evidence/control_evidence_proofs part、实际 source PrepareLocator/registered exclusion proof、observer、历史与全局排序。公开Invocation/ConfigMap只带locator/checksum，不包含SidecarJSON/ProofsJSON/body。默认六项guard/readiness保持关闭，源发现authority/完整模块factory/全体Runtime参与者和最终原v12成品链继续推进。

## D5.20 两份原控制证据模块及正式Job接线（2026-10-31）

- B原模块目录只接纳固定ID=control_evidence、Owner=D、Required=true、mysql存储selector下的control_evidence/control_evidence_proofs两份精确part，统一operation=capture-control-evidence/category=control_evidence。缺proof、重复/额外part、错owner、单独引入第七前端selector或借用保留名均拒绝；原六项请求协议不变。
- NewControlEvidenceModule只接实际原FormalCapture/Generate/PermitDelivery/locator映射，禁止source卷与subPath，两份必须同一完整locator。Build绑定真实安装/config/task/attempt/context/hold和原provider全局PartIndex；BuildCapturePart使用A原kube.ControlEvidenceCaptureJob，保存原Invocation/Job字节与hash，不自行构造命令或上传证据body。目录末端也对raw registration的实际两份locator进行独立配对复查。
- 监督指出初稿json.Unmarshal回同一含非nil指针cfg会复用入参，已改独立零值frozen深拷贝。反例在构造后修改caller locator refs/hash、permit公钥、provider地址、Workload挂载与InvocationConfigMap，要求原三份Job/Invocation/hash逐字不变；不是仅检查返回成功。
- 自有pure assembly用明确synthetic locator（不声称真实注册proof），将两份原CE Job放在较早workspace Job后验证连续全局索引1/2、正式CLI参数及无源PVC。负例涵盖不同locator/源卷/错全局索引/不完整目录。定向B3.321s/execution纯内容3.244s通过，完整publicadapter3.529s通过。内容observer/真实SQL consumer已另在工作区测试，不包含本小片；生产factory/source发现与默认guards/readiness均不随本片开放。

## D5.21 原控制证据C流独立内容观察（2026-10-31）

- D5.20提交5f4ed3b1。当前observer在原ObserveFormalManaged独立unwrap/AEAD/private custody流程内直接检查两份未gzip的canonical JSON。每份均受独立locator精确hash与字节上限约束；sidecar核closed JCS/scope/固定registry/原cutoff，proofs核完整原bundle并用ce.Rebuild离线重建/ce.Verify全部组/排除/脱敏/owner证明，不能从SQL补丢失body。最终publisher仍必须对两份实际读回的原C流一起ce.Verify，本观察不替代最终v12成品验收。
- 纯内容反例将修改后的payload重新计算合法locator hash，仍拒绝missing/forged body、错误scope、suffix、unknown field、不同cutoff/registry；正例含非空event。实际原SQL encrypted plan/candidate/Job→Evidence/deployment wrapper→独立内容observer/custody→原ModuleResult/evidence，两份合法part分别成功，suffix/缺proof/错payloadhash即使AEAD有效也零result/evidence。producer key/unwrap、source proof注册及Kubernetes/finished-use明确为命名本机fixture，不能声称原SQL source producer/mTLS拉取或完整六项已验收。
- 真实SQL CE consumer8例9.152s通过；合并后CE+既有正式observer组合10.060s通过。一次未提权的旧filesystem observer fixture在staging原文件identity创建阶段失败；按既有约定用本机原filesystem权限重跑全部相关observer通过，没有修改seal/owner guard。保留WIP同步监督原backup源完整链及A7f19da41 source endpoint兼容；本片未含production factory/discovery材料。

## D5.22 六原构造器的纯生产模块factory（2026-10-31）

- D5.21提交5c09e9e3。productionCaptureModules只消费原冻结SourceInventory中的typed metadata（完整SQLSchema、原instance mounts/runtime policy/UID、Skills versioned objects、完整Redis policy、两类资源selection及CE locator），无SQL/provider/Kubernetes调用或任务/密钥授权。仍未在NewDeploymentService接为可用生产factory；真实metadata discovery/registered exclusion producer接线继续，不开放sixpart guards/readiness。
- 使用B UsersInstances、C Teams、D Skills/Resource/SourceRedis/ControlEvidence六个原constructor，SQL只有一份。所有draft按原module/part规范排序后统一分配global PartIndex；原task/attempt/context/envelope/Generate context及Job绑定一致。CE保持A原固定logical cipher names。每份InvocationConfigMap由真实part生成独立名称，修复重复workspace使用同一模板时ConfigMap冲突。
- resource OriginalWriters仅包含其真实所选Deployment的原checkpoint，精确UID/缺writer拒绝；全体writer仍绑定统一捕获上下文，不能将其他runtime/lease writer偷偷丢出原barrier。Skills workspace mapping仅选择实际未打包blob的原WorkspaceRequirements涉及的primary mount，不误加无关instance。
- 自有pure fixture明确模拟两原实例（running/stopped）、非空Teams SQL事实/共享PVC/object、非空Skills blob/versioned object及原六项acceptance spec，通过全部原constructor与真实Job工厂生成11份Job：1SQL+2实例workspace+1Teamworkspace+1Teamobject+1Redis+1Skillsobject+2resource+2CE。检查精确part全集、唯一ConfigMap、连续全局索引/Generate上下文；构造后caller改DB/template/permit/writer不改变原计划字节。
- 缺operation/primary、重复mount、替换Team事实、错业务policy、缺CE/异scope、选Deployment缺writer/错UID等九类反例均拒绝。工厂定向组合3.418s通过。SQLschema在此pure测试是完整已知表的明确synthetic形状，不声称原177表现场metadata；原完整迁移SQL真实性属于D5.19。未完成Discovery/源metadata authority仍排除本提交，下一步继续原服务接线及真实非空目标恢复。

## D5.23 修复各part原身份及attempt日志绑定（2026-10-31）

- 监督用独立probe实测D5.22/266e0c39的11份Job复用模板job-identity，第二Job会被原Invocation绑定拒绝，故266e不能单独启用。现按同一原task/attempt/part确定性Job名生成独立IdentitySecret名，全部11份实际Job的worker-identity Secret挂载逐一唯一；原TLS/不可变Secret/生成许可证校验不放宽。
- 自有真实两identity SQL测试进一步触发原ensureIdentity的attempt FK：旧INSERT省略target_type/attempt_no/phase而默认1，AAD也硬写1。现原当前TaskType/AttemptNo/Phase显式入行；identity AAD用实际attempt；身份读取、dispatch与observed更新、workerSecurity及原Job绑定查询/CAS均约束同一原坐标。合法attempt1原AAD不变；历史错误坐标不会静默迁移/重封/借给新attempt，缺原记录仍按原unknown/recovery规则关闭。
- 同样核对Invocation ConfigMap/Job原共用kube.MappedResourceRows，发现其INSERT也依赖同一默认1。新增原attempt映射入口，将target/attempt/phase同时用于Load/INSERT/CAS；旧legacy表映射保持原SQL。所有public runner/security/recovery调用传同一Authority，不修改FK、CAS、dispatch-before-create、原owner或不可变request hash规则。
- 实际原claim attempt3+独立签名worker issuer+原encrypted identity SQL journal：两份CE Job分别创建/重放成功；本机Kube fixture每次首create先落原对象却返回timeout，原生产代码只GET确认，重复ensure不再create。原同一个certificate校验函数用于public_jobs实际绑定及测试，跨part SPIFFE/原Invocation拒绝；强行恢复旧共享Secret模板由原ensureIdentity journal拒绝且零额外create；跨attempt也拒绝。该测试未冒充完整sixpart原plan/TokenReview，Kube create为明确fixture。
- 同一原SQL实测Invocation ConfigMap行在attempt3/phase capture的原FK插入、dispatch CAS、observe CAS、重放成功，另一个attempt的映射Load返回sql.ErrNoRows。自建角色仅新增本fixture所需原runtime_resources INSERT，未改共享server/生产权限；创建/元数据始终在自建ad_d_consumer范围清理。
- 定向identity/factory/原secret反例4.041s；加入原mapped SQL journal后kube3.451s/execution4.350s；最新原SQL consumer/concurrent结果/原provider permit mTLS handler/identity/factory组合kube3.240s、execution24.225s通过。source Discovery/原SourceProfile接线和恢复适配WIP继续留工作区，不含本小片；主任务仍优先实际NewDeploymentService装配。

## D5.24 原资源scope冲突不能变成“未派发”（2026-10-31）

- D5.23提交56892485。监督在新scope mapper上实测同一原PK的已派发Job被放入prior attempt1后，当前attempt3过滤查询返回sql.ErrNoRows，可能让Pending误作Undispatched，初始反例FAIL3.797s。现scoped Load未命中时，在同一原SQL事务用原PK FOR UPDATE再查：同PK存在任何其他target/attempt/phase或读取失败都返回ErrJournal；只有物理PK真正无行才返回sql.ErrNoRows。精确scope INSERT/CAS继续保留，未派发证明不因过滤而放宽。
- Pending的实际缺席分支提为loadPendingOriginalJob，仍消费同一原锁内MappedResourceRows；错scope错误直接传播。实际SQL五模式覆盖真正缺席、错attempt、错phase、错target、显式prior-attempt错日志；对应原Pending分支不把任何冲突标Undispatched。完整owner.Pending在shadowed fixture同样返回错误且没有Undispatched条目；该fixture其他恢复inventory材料有限，不据此宣称完成全体writer恢复。
- 原两identity测试的跨attempt期望改为ErrJournal；对真正不存在的名称仍要求sql.ErrNoRows。监督在干净候选树组合原身份/唯一mount/五模式/独立两反例全部PASS7.481s；本机定向回归另见本轮tool输出。仅本mapper、Pending helper与两份真实SQL回归交付，source Discovery/restore WIP不包含本片，生产接线继续推进。

## D5.25 WorkBuddy Pro/Lite 原身份适用范围修复（2026-10-31）

- 监督原Pro探针确认factory和UsersInstances构造器均把全部WorkBuddy强制套入Lite UID合同。现共同使用RequiresWorkBuddyUIDIdentity：先原scope.PlanRuntime验证Linux已知runtime，再仅原workbuddy/lite/gateway/linux variant要求身份；Pro无Lite身份且禁止借用Lite身份。纯WithWorkBuddyIdentities与诊断沿同一适用规则，未放宽worker原UID检查或Windows/未知runtime规则。
- Factory逐一绑定实际Source instance与全部Runtime tuple，Lite身份必须原instance/user、schema1、UID10000..65533且GID一致；所有非Lite来源带Lite身份直接拒绝。Source WIP中的SQL与mount选择也已用同一predicate，但未包含本独立提交。
- 新增8模式完整原factory/Job构造回归：Pro正例、Pro借Lite身份拒绝、Lite正例、缺身份/错owner/错instance/错GID/越界均拒绝；B模块/纯binder/诊断Pro正例与Windows/unknown/backend边界覆盖。原UsersInstances、WorkBuddy binder、factory组合publicadapter3.315s/execution4.046s PASS。六部分Discovery/Runtime源接线和restore仍继续施工，未据本修复声明页面完整通过。

### D5.25a 归一化Lite不能绕过UID（2026-10-31）

- 监督补充原scope.PlanRuntime允许ModeLite/backend空、mode空/backend gateway两种归一化边界。RequiresWorkBuddyUIDIdentity现以原已验证RuntimePlan的Type+Mode判断，所有已知Linux WorkBuddy Lite必须保留身份，不能因raw backend缺失转入普通workspace；Pro仍不借Lite身份，Windows/未知runtime仍拒绝。
- 新增factory缺UID的blank-backend、inferred-mode反例，以及共同predicate两边界正分类；与原Pro/Lite/UsersInstances/binder/诊断组合publicadapter3.274s、execution见本轮日志通过。TLS原客户端（明确RESP协议fixture）及Kubernetes元数据实际客户端组合8.246s PASS，属于source WIP未含本补片。

## D5.26 原服务六部分source接线与组件验证（2026-10-31，尚非完整任务验收）

- Linux NewDeploymentService保留原OS/身份/签名/正式verifier入口，通过同一composeCaptureRuntime实际安装platformProfile→原SQLRuntimeControl→production source hooks→原NewPublicCapture ModuleFactory。明确sourceMetadata controller delegation由独立owner签名，绑定原core/Forward/config、源范围、controller Pod→RS→Deployment/SA链和有界期限；不是未来Job/Invocation/Generate authority。每次原HTTP边界前后、最后Kube GET后重查原SQL claim与原文件。RecoveryOnly不重新发现或加载forward source材料。
- 原SELECT-only源RR输出完整census业务/控制表名和SQLschema，原所有Teams事实与Skills八表、全部当前versioned Skills prefix（含未引用对象）、finite PartialObjectMetadata GVR+UID、实际原Runtime custody spec、共享workspace/PVC/PV身份一起冻结；结束SQL RR后才进行远程IO。业务writer仅观察一次，CheckSource重用原locator/cutoff并重查当前SQL与远程选择，不重做Prepare/注册新的CE cutoff。
- 镜像源key保留原type/mode/backend/variant/OS、os_version和nullable registry/tag。仅原full-registry分支直接匹配；默认/managed image由独立source-owner明确签名的typed输入→immutable policy映射，不猜Docker名、不把tag当完整镜像、不使用任意Pod sidecar证明。Pro不借Lite UID，所有canonical Linux Lite WorkBuddy仍按最终D5.25a合同严格检查。
- 实际Job卷名是workspace（kube builder重命名），每part源PVC/PV pin使用此原名；正式ConfigMap/Secret期望按原operation保存在同一sealed Source内，原workerSecurity先验证同一原part/spec/invocation，再用对应pin。缺operation/formal input/source UID/PV UID、不同CM/claim和重复volume均拒绝，避免全局formal/source同名误绑定。
- 实际原SQL preparing AcquireWithReceipt/签名deployment和本机TLS组件测试：签名grant配置/范围/撤销/过期/未来/workload替换及原claim丢失均拒绝；原AUTH/SELECT/INFO客户端使用明确TLS RESP协议fixture（非真实Redis Lua/DUMP），原S3版本列表及Kubernetes SSR/SSRR/PartialObjectMetadata客户端使用明确TLS protocol fixtures。未引用对象保留，版本/新key/UID漂移反映在原frozen selection；null版本、foreign prefix/namespace、duplicate latest/delete marker、deleting对象、写权限、错SA和最终响应期间token替换均关闭。
- 原172迁移完整非空SQL+原捕获/独立observer+census新返回值及失败零partial输出组合47.399s/publicadapter3.869s PASS。最终source authority/client/compose/metadata/image/各part pins/factory/WorkBuddy/原frozen重检组合execution22.774s、publicadapter3.229s PASS。另实际文件归属/回环可用下非SQL全三包execution7.295s/publicadapter3.990s/domain3.288s PASS；sandbox内首次全包失败为回环/文件identity权限，未修改安全检查。Windows未装WSL，Linux启动守卫未删。
- 本提交不包括restore adapters WIP。readiness仍原supported_parts=workspace/acceptance_ready=false；尚未证明一个原API/queue任务完成全六项、真实quiesce/Resume、CE晚报告时序及A最终发布。CE当前仍复用A现有locator，A v2part-basis/CE-last施工后需一起接入。独立可信容量collector原CLI已每秒采样，controller消费只读报告；本机夹具的刷新不代表已部署该collector。继续同一实际任务验收，不据组件通过标D owner complete。

### D整链专用TLS MySQL（2026-10-31）

- 仅D整链fixture使用：127.0.0.1:63507，MySQL8.4.13，serverUUID=f3756194-d52b-11f1-b8cc-745d22085e06；VERIFY_IDENTITY实际连接成功，session cipher TLS_AES_128_GCM_SHA256。使用已有发行版，独立SAN含localhost/127.0.0.1，未改共享59355实例/UUID/credentials或其他现有172迁移schema。
- 凭据文件（只引用，禁止打印内容）：C:/Users/13542/Desktop/新建文件夹/.tools/mysql-d-sixpart-tls/credentials.json；公有CA：同目录ca.pem；专用datadir：同目录data；my.ini/client.ini/process.json与服务器stdout/stderr日志均在同目录。测试env仅TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS指向该credentials.json，不替换现A/共享fixture env。
- Windows原生MySQL绝对Unicode配置路径有兼容问题；当前通过临时ASCII junction入口启动，process.json记录进程PID和ascii_access_root（C:/Users/13542/AppData/Local/Temp/codex-d-sixpart-mysql-0aeba8b33d5f45b883dcf0f512b380e7），两个入口fixture/distribution分别指向专用根和现有只读发行版。启动隐藏窗口；清理前必须核对process.json/PID/原commandline/datadir，仅停此新实例，junction删除不能递归遍历目标。保留当前实例供独立SQLworker/restore验收复用。
- 新production_same_task_mysql_test.go正施工：实际原172迁移、原签名session/RBAC/HTTP acceptance六项、有限controller role和原queue准备同一task；readiness/capacity暂为明确local输入夹具，不代表主服务PublishReadiness。初次运行发现fixture refresh token expiry必须晚于access、instances原必填CPU/memory/disk/os_version，正补原字段而不改SQL约束或源guard；尚未声明整链通过。

## D5.27 原runner先业务Evidence后CE调度（2026-10-31）

- 原publicadapter runner Capture保持sealed Discovery、全局indices/AAD、原Job specs和结果顺序不变，只给flow.Collectors传入业务优先、两个CE最后的稳定依赖顺序。CE依赖所有业务Job原独立Evidence读取，不能在它们尚未派发时等待而死锁或耗尽Generate期限；collector停止与原writer恢复仍由同一flow执行。
- 新真实runner/flow单元夹具（明确port/evidence模型，非SQL或物理证明）故意令canonical计划CE排在第一；CE Ensure若业务Evidence未全部Read即返回错误。旧顺序正例会失败；现四个原Job依次业务→CE、结果仍canonical、计划bytes不变且全collector Stop后原writer Resume。业务Ensure失败反例不派发CE、不返回完成parts。定向3.267s、完整publicadapter3.591s PASS。
- 专用63507 SAN/TLS库上的production_same_task_mysql_test.go施工检查点：完整原迁移/非空Teams和Skills八表/运行与停机实例/原签名session+RBAC+HTTP acceptance六项/有限controller direct grants+原queue拿同一task与capture+secret_capture两attempt单元已PASS18.259s。这不是完整捕获：source hooks、SavePlan/reTake/held gate、实际worker/Evidence/Stop/Resume仍须在同一个fixture继续。该整链WIP未含本调度小片，readiness仍关闭。
- 与A采用无环方案：完整Source只保留完整V1 base locator，原context仍哈希完整Source；最终TaskPlan冻结前仅CE两个Invocation绑定V2 policy。factory须先用原构造器得到准确business Invocation（注意SQL构造器会附加Teams/Skills inventory，不能提前哈希draft），再绑定CE seed并重建；productionInventory精确验证V2.BaseSnapshot==冻结base、policy context与全体准确business inv集合。没有排除Source字段的哈希投影。

## D5.28 原签名Job duration保持重建确定性（2026-10-31）

- 监督原factory跨1.1秒重建同输入在backup FAIL4.510（CE Job SpecSHA变动）；原因是factory按time.Until重算ActiveDeadlineSeconds。现只消费原独立签名operation.Workload.DeadlineSeconds（1..3600），不从更晚时钟重新生成值；原BuildCapturePart仍拒绝超过原hold剩余窗口的duration，未放宽deadline或延长旧key-use。
- 新原factory完整Job/Invocation跨秒bytes比较、缺duration0/超3600/越原hold三反例全部通过；实际source Discovery材料加载也要求该原字段。生产source材料正例和startup模板示例已显式填写30；仓库无正式六部分capture bundle生成器，operator每个Operations.<operation>.Workload必须提供独立批准的固定DeadlineSeconds（30仅本机fixture示例），不存在省略为0或运行时改填的自动授权。
- 原factory/WorkBuddy/挂载pin/startup模板定向4.801s PASS；加原SQL source授权与compose后10.909s PASS；监督独立candidate跨秒PASS4.471。V2seed桥接、同任务原Runtime/六worker和restore WIP不含此独立确定性小片。

## D5.29 完整Source下的V2 CE seed桥接（2026-10-31）

- 基于A b415ac72实际ABI，完整Source永远保留原V1 locator；factory先执行全部原构造器及BuildParts（SQL已附加原Teams/Skills inventory），从实际非CE InvocationSHA生成精确有序policy，再仅重建两个CE invocation为V2 seed。全局indices、业务invocation、完整Source字节及其InventorySHA不做字段排除，context包含同一完整Source和原writer集合。
- 原productionInventory保留精确parts/operation/globalindices与SQLschema检查，另外要求两个seed均为V2、BaseSnapshot完全等于冻结V1、policy精确等于完整Source context与全部实际业务inv集合。Source含V2/缺CE/改base、context、checks version、part hash/op、增删policy或业务part、业务inv、原writer、hold、其他Source字段漂移均拒绝。
- 定向原factory跨秒/六部分/seed与CE回归无需overlay通过：execution5.525s、publicadapter3.441s、controlevidence0.814s。先前只读A ABI overlay通过4.817s，不作为当前最终编译凭证。额外writer使排序不变性检查覆盖实际两个writer。此片不证明同任务六worker、物理来源、D owner complete或页面readiness；同publicID/attempt整链仍继续。

## D5.30 同一原HTTP任务的SQL/TLS、Runtime custody及source元数据检查点

- 新same-task fixture在独立63507实例使用原172迁移、实际非空Teams/Skills八表、原签名session/RBAC/HTTP六部分acceptance入口、原有限controller/source角色、原SQL queue TakeBackup与同publicID/attempt1。一个运行Pro实例和一个原停机Pro实例，经原SQLRuntimeControl Prepare生成两个加密custody胶囊；平台、原participant、运行和停机四个writer各Observe一次，停机状态未提升。readiness/capacity为明确本地输入fixture，不代表PublishReadiness/实际磁盘认证。
- 同一source-owner签名绑定该core/Forward/config与完整有限metadata bundle及原controller Pod→RS→Deployment/SA链；实际原SQL RR同时读Teams/Skills与用户实例。随后同一authority消费原只读TLS源角色，完整census返回82业务/95控制表、实际schema与两原镜像；原TLS RESP metadata fixture、S3 versioning/全部当前版本（含未引用对象）、Kubernetes SSR/SSRR/PartialObjectMetadata均通过原客户端。原custody spec、immutable policy、PVC/PV与unpackaged Skill workspace绑定验证通过。
- Forward的WorkerIssuerSHA256已指向独立生成的实际本地CA；原worker IdentityIssuer与TLS1.3 control server使用其真实证书/独立server key，core签名前写入全部pin。此检查点尚未调用worker/Generate/Job admission。缺CE材料时原attachProductionSources拒绝，原任务Job/evidence计数均为0。
- 最新同任务定向PASS20.976s（此前metadata组合25.126s）。当前仓库schema registry仍draft，只有36个system_backup对象，不能直接覆盖实际95控制表；生产拒绝保留。监督明确允许后续完整本地测试使用按原逐表分类/实际DDL观测装配的明确本地owner材料fixture，仅证明代码调用；现场原始审批及KMS等材料仍列最终清单。此检查点不声称freeze/SavePlan/held gate/六worker/Stop/Resume或终态已完成。

## D5.31 有限控制表离线draft与批准材料精确范围检查

- 新system-backup-control-proposal命令只从独立observer的SQLTable元数据JSON生成新draft文件：`-observed <原控制表观察JSON> -server-uuid <原UUID> -database <原schema> -out <新文件>`。绑定当前原172迁移catalog及原RegistryHash；每表分类/backup/restore仅查既有有限Policy，未知表、业务表、重复表、缺column/PK及坏key拒绝。输出始终draft_requires_independent_owner_review，各表owner_and_cross_review_required，不自动标批准，不写repo registry，不产生grant/readiness，也不查询SQL或KMS。
- 原ObserveControlScopeSchemas仅对原已分类控制表读取column/PK/生成表达式等惰性元数据；ReadTableSchema默认业务捕获的生成列拒绝保持。离线proposal记录这份明确形状的hash，并不把纯DTO当现场来源证明。实际源census、原独立owner批准的frozen v12 bytes及pin仍由现有source grant与ReadPolicies入口验证。
- 原registerSourceExclusion在ReadPolicies之后新增精确校验：批准控制表集合必须等于同次完整原census；逐表category/classification/backup/restore必须等于原已审查Policy，不能用metadata_only统配新表。新增缺项/未知/错分类/业务冒名/捕获control/重复反例；离线draft排序/数据独立性/形状漂移与五类非法观察组合root3.151s、execution3.259s PASS，CLI编译通过。
- 同任务扩展WIP已用明确LOCAL owner/cross-review fixture、真实95表惰性schema观察、原8KiB evidence边界内的实际观察摘要注册，经过原NewPinnedCaptureScope/ReadPolicies与原freezeProductionSource→CE base注册PASS21.587s；未把draft就地改frozen，未放宽原8KiB限制。该整链测试扩展尚未含本独立小片：最新继续到all-constructor阶段出现原BuildCapturePart拒绝，正在定位原模板，不改变task/parts/构造器检查。没有声称原runner SavePlan或六worker完成。

## D5.32 同一task的实际source冻结及10个原part/V2校验

- 在D5.30的同一HTTP/queue publicID/attempt1继续，未创建替代任务。实际95控制表column/PK/生成表达式观察形成离线draft与有界摘要；本地审批fixture仅沿原逐表Policy分类，独立材料经原NewPinnedCaptureScope/ReadPolicies及D5.31精确census/分类入口。原guard事务注册观察摘要，原8KiB上界保持；真实schema数据保留在离线proposal文件，未把超界全schema塞进evidence。
- 原SQLExecutionWorkStore.RunWithExecutionHeartbeat维持同一原epoch；原freezeProductionSource重查SQL/TLS、版本化Skills对象、finite资源元数据、runtime custody/mount/PVC/PV和非空Team映射，实际注册source exclusion与原CE base。完整Source保留V1 locator；原全部六构造器BuildParts生成准确10个业务/CE part并经productionInventory/V2精确完整context及原invocation集合校验，未派发Job。
- 新阶段首次失败经只读overlay定位到原ControlEvidenceCaptureJob→attachFormalMaterials的最少一个Input要求：元数据stage夹具原先清空了Inputs。现使用实际不可变公有CA ConfigMap及其原UID/内容hash，签入对应operation材料；没有修改原Job builder/expectedparts或跳过材料检查。临时诊断overlay仅在.tools，正式代码无调试包装。
- 无overlay最终同任务定向PASS21.549s；此前仅source冻结/摘要注册PASS21.587s。测试仍明确LOCAL approval/协议环境，只证明原代码调用；formal mapping/独立permit issuer/verifier/实际worker、原runner Prepare/SavePlan/reTake/held gate及Stop/Resume仍继续，不能由该成功断言D owner complete、生产readiness或最终发布。

## D5.33 同任务admission前准备实际Skill/对象/workspace源字节

- 新本地payload构造在原HTTP admission之前创建实际确定性ZIP、未引用对象、运行/停机instance完整目录与Team结果文件。unpackaged Skill的demo/previous两原绑定都有SKILL.md、src/main.py与隐藏文件；沿原service目录/文件framing计算MD5，并对独立既有golden 7c876ed8f2fc9206f8cc0914cb0a24f0断言。SQL blob/content/archive hash、size、binding observed_hash与materialize job content_hash均在最初源种子中使用实际值，取消此前重复字母占位。
- 原S3协议fixture固定version返回实际同一源body及Content-Length/ETag/Last-Modified/version头；原生产S3VersionReader通过同一签名源authority/TLS客户端逐个读取精确version，检验原Size/VersionID及body SHA。其余目录/隐藏文件保留原整体archive输入，不把legacy Skill MD5过滤当删除源数据。
- 本地workspace上界在core签名之前明确为100files/4MiB file bytes/16MiB archive+compressed；workspace operation材料沿同一原上界，尚无现场物理PVC或真实Kube进程声明。完整同一task源freeze/原10part/V2检查+真实version body读取PASS24.315s；上一版实际文件/SQL绑定组合PASS21.598s。实际C worker、独立permit/verifier、原runner Prepare/SavePlan/reTake/held gate/Stop/Resume尚继续。
