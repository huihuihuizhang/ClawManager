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
