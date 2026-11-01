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

## D5.34 同任务原NewPublicCapture/Prepare/SavePlan/reTake链路

- 同一原任务内安装实际a.NewInstallationAuthorityWriter、签名Generate/Unwrap capability、独立verifier grant与Generate permit owner grant，经原loadFormalVerifier/attachFormalVerifier得到原真实FormalKeys与providerPermits构造器。每operation的formal mapping为实际immutable ConfigMap及内容pin；SQL source另有实际独立签名finite worker grant。当前TLS provider协议端明确拒绝全部业务调用，尚未假造Generate/Unwrap成功或使用替代key callback。
- 原named Kubernetes reads材料与finite SelfSubjectAccessReview协议fixture支撑实际composeCaptureRuntime→NewPublicCapture。删除constructor中的手动Runtime.Prepare/writer.Observe与预先source freeze：现在原leased public runner Prepare经原LinuxProfile原路生成两custody、观察4writers、冻结完整source和CE cutoff一次，返回原TaskPlan。之后所有运行/停机/Skills/PVC/V2断言从该frozen plan读取；原saved CheckFrozenSources重检不增evidence、不改原cutoff。
- 实际原DurableExecutionStore.Record执行SavePlan与public outcome CAS，密文record的SHA等于原Plan，public状态ready_for_capture并释放旧claim；随后原Loop.Store.Next/SQL queue重拿同publicID/attempt1，读取完全相同原plan字节，建立新current rowversion与原maintenance fence，原gate进入acquiring。该点Jobs仍0，未把acquiring称held；源writer真正Pause、held、六worker与Stop/Resume仍继续。
- 原controller fixture role已收窄为实际capture/runtime/provider/CE权限，不预给未配置publication权限。容量仍明确独立LOCAL输入采样fixture（原SQL UTC、原WriteCapacityReport原子文件每秒更新），没有用controller伪造现场disk证明；生产freshness/reservation/collector接口未改。Linux NewDeploymentService启动守卫、生产readiness和签名规则未改。
- 无overlay实际同任务Prepare/加密SavePlan PASS23.655s；加入原reTake/acquiring与窄role后PASS27.402s，已经同步监督4aed原heartbeat窄修。以上只证明当前明确本地SQL/TLS/元数据API协议环境中的原调用链，尚非真实节点/PVC/KMS生产验收或A最终发布。

## D5.35 原Generate owner签名的独立Pod JWT路径投影

- 现有ProviderPermitIssuerGrant.WorkerJWTIdentityFile兼容静态容器绝对路径，并允许独立owner预签一个完整的`{pod_uid}`路径段。只由原已admit的lease.Identity.PodUID解析；产生的具体路径进入原delivered permit原签名，ReadCommitted重验相同派生值。没有客户端路径覆盖、替代resolver、改写冻结plan或延长key window。
- 拒绝非法UID、相对/不规范路径、路径穿越、非完整模板段、重复模板及残留brace。两不同Job/Pod使用独立实际文件，两个原NewDeliveredCaptureJob的TLS login必须交错到达才释放；实际Generate返回各自不同DEK。错误namespace/Pod UID/SA UID在原jwtToken校验处拒绝，错误Job无Generate调用。
- adapter全包PASS5.450s、KMS全包PASS3.295s。这是明确LOCAL协议及原客户端边界验证；同任务10worker整体Capture仍WIP，暂未通过Stop/Resume或A最终publication，生产readiness保持原值。

## D5.36 同一原任务真实provider拒绝→collector stop→原状态恢复→失败Record

- 新独立负向测试`TestProductionSameTaskOriginalProviderDeniedStopsBeforeResumeMySQL`每次只创建一个原HTTP任务，实际原Prepare/SavePlan/reTake/acquiring，四原writer Pause/ACK之后的首个Job只能在原held gate派发。原issued mTLS Secret、TokenReview与live Pod/SA核验、原Ready/relay、SQL issuer Stage签名permit及每Pod独立JWT路径均走原代码；只在明确LOCAL TLS provider端主动拒绝实际Generate一次。没有将失败的正向任务复位/改成预期失败。
- 实际worker退出后，本地API/kubelet模型才记录同原container ID的Terminated状态。原StopWitness/SQL stop proof、Job revoke/删除/stopped_at与collectors_stopped_at进入原链路；实际原Pro Create和platform恢复前另只读断言全部collector已停且无native worker活跃。验证四writer paused/resumed、3份原终止witness、gate idle；原Pro新PodUID/原fence/running且SQL generation仍3，原stopped实例保持4和stopped，platform原replicas1/ready，只有原Pro被重建。
- 明确断言provider拒绝1次、成功Generate/Unwrap均0、一个实际admitted/held Job与一个SQL原签名projection、没有candidate/result或成功密文/envelope。随后实际原Loop.Store.Record写失败密文结果、FinishCapture落failed并释放claim/lease。无overlay定向PASS34.24s（package37.466s）。
- 该提交保留原AdmissionAndQueue测试的Prepare/SavePlan/reTake边界；独立完整正向测试仍在D工作区继续，当前已实际完成前六worker/C候选/独立Evidence，后续因原120秒固定hold余量不足拒绝。新任务在core签名与plan之前声明300秒，原gate600秒上界、原DEK窗口、所有校验不变。完整10parts/validating/A发布尚未完成，不能把本负向证明称完整正向成功。
- 所有API/kubelet/Redis/Transit仍是明确LOCAL协议模型，实际TLS/SQL/原客户端及同步C代码调用不等于真实Linux节点/PVC/线上KMS验收。同步主分支2107a4a4，生产readiness未变。

## D5.37 完整SQL目录有界聚合，保留默认固定窗口与逐次当前授权

- 实际同任务正向已到第8个users_instances_database worker；原key window约29秒，logging-only诊断测得SQL目录阶段25.966秒后context deadline exceeded，随后原Stop/Resume恢复。默认30秒claim、5秒heartbeat与旧DEK固定Until未改，没有以抬高ClaimTTL替代修复。
- 仅reviewed-business source分支改为四个有界JSON metadata结果（tables/columns/PK+FK/原WorkBuddy unique），在同一原RR中重建完整原Table形状。每个真实SQL Query及Next前后仍调用原source guard，业务DATA每行与最后原session/schema/census检查保持；没有授权缓存、schema字段删减、额外SQL权限、源数据重编码或旧hash重写。legacy Catalog/Capture路径保持。
- 约束名只作metadata排序，不新增SQL标识符限制；PK/FK和unique的排序由原MySQL ORDER BY生成ROW_NUMBER ordinal，避免Go字节排序改变原外键数组/hash。监督独立真实MySQL ordinary、合法fk$owner和a_owner/B_creator三类probe全部PASS；domain全包（含metadata全部边界撤权、data/final读取撤权）PASS3.464s。
- 实际D独立SAN/TLS MySQL原172迁移、原SELECT-only source角色完整capture与旧Catalog逐字段等价，含schema/PK/FK/unique/defaults，原frozen schema验证PASS19.08s（package22.469s）；完整RR/data path当前授权437次、SQL耗时123.7841ms（该低层对照无HTTP key-check延迟，不冒充完整native任务成功）。完整同任务默认30秒key window、10parts/C/Evidence/原Record(validating)仍继续。

## D5.38 同一控制请求复用已认证原计划，提交前完整输入/密文重查

- 01:23 SQL-first logging-only失败保留在`.tools/d-same-task-sql-cost-diagnostic.log`及CPU profile；原窗口26.486秒的另一轮只完成129次SourceAuthorize，未称正向成功。profile中Authorize累计14.18秒、input11.69秒（约82%，包含重叠），同次请求原Read、挂载与issuer重复原计划解密/Describe是实测成本。
- 新SQLExecutionRecords.OpenOriginalCapturePlan只从实际原SQL/原密钥解析与完整plan绑定签发私有OriginalCapturePlan历史凭据，绑定当前context及原Records配置；调用者不能由DTO构造。每个Authorize独立读取一次，不跨请求缓存，不延长claim/hold/DEK，不删减逐行/EOF guard。Read的原gate/资源journal、security的原CM/Secret/Pod挂载、issuer的原controller/worker/SA/grant/capability/mapping与Stage均继续。
- 原始profile bytes/hash、config bytes、全部BackupSpec字段、原plan payload hash/key_ref、实际sealed_payload的SHA256与长度在签发前取样；原LoadPlan认证全部sealed bytes。原key-use事务提交前以FOR SHARE重读全部字段，与原样本逐字段等同；issuer Stage也重查该凭据，最终原guard Recheck及commit后的ValidateCollectors保留。原解密8MiB读取上限不变，预分配改为实际有界密文大小。
- 实际mTLS Ready在原CM GET期间变更profile_json、profile_sha256、runner、config_snapshot_json、payload_sha256、key_ref、sealed_payload七反例均拒绝；异context与调用者零值凭据拒绝。实际TLS/SQL valid、unknown-reserve-ack与revoked-after-login三模式PASS10.47s/package13.709s；controller9.341s、adapter5.346s、execution8.245s全包PASS。完整原任务、173迁移/新staging producer、10 C/Evidence与Record(validating)待无overlay正向实跑，当前不能声称已解决默认窗口或A发布。

## D5.39 请求内合并重复当前读取，公共历史读取边界保持

- D5.38无overlay原173迁移完整任务`sbk_5b31eeca-4b3e-4c09-b793-adb6a370ff72`仍FAIL140.59s/package143.830s：前七实际native worker完成，SQL原窗口26.235秒内进行263次SourceAuthorize/25.862秒后拒绝；原失败Record=ok。未进入validating，不计正向成功。新的SQL-first logging-only profile保留`.tools/d-request-reuse-cost.log`/`d-request-reuse-cpu.pprof`，该轮FAIL57.98s；profile增加额外成本，不能与无profile延迟直接比较。
- profile定位当前Authoritiy.Check重复开销：原readExecutionInput/Gate一次、LoadPlan两次、Read一次。Authorize现在先只重建原输入，再由OpenOriginalCapturePlan在任何解密/part使用之前进行一次完整当前Authority.Check。私有readPlain仍执行实际记录读取、原Keys.Resolve/AEAD/完整hash/8MiB边界；同次原Unwrap/Describe完整执行一次。公共SQLExecutionRecords.read/LoadPlan仍保留原前后两次Check，公共Read仍保留原额外Gate.Check，恢复入口不改。
- 同次请求的当前事务Bind、原process/Job锁和原guard Recheck、issuer Stage（含独立Bind/current grants与原registry事务）、完整原input/sealed digest/key_ref末尾重查、最终guard Recheck及commit后ValidateCollectors全部保留。无跨请求history或授权缓存；每次原data row/EOF仍发起原完整控制请求。
- 增加在原CM GET期间实际撤回controller_owner反例，八种mutation均确认affected=1且独立SELECT字节等于注入值并不同原值，再断言拒绝；这是窄fixture主动篡改验证，不证明完整原DDL允许这些UPDATE。实际D专用MySQL/TLS三场景PASS7.86s/package11.092s；完整controller9.390s/adapter5.803s/execution7.682s PASS。新完整原任务无overlay/default30秒窗口验证继续；尚未称全部437检查、10part或A发布成功。

## D5.40 当前claim中途撤销必须先于key-reserve，计数口径校正

- 窄真实mTLS/SQL fixture新增独立admin actor：在首轮当前授权/完整原plan认证之后的原CM GET实际撤回controller_owner，affected=1并独立SELECT确认。原NewOriginalKeyAuthority发送真实key-reserve必须拒绝；SQL key_use、签名sev_apermit、candidate/result均0，provider Generate计数未变。原三场景与八种输入/密文变更组合PASS8.34s/package11.597s。该测试不证明完整原DDL可篡改，也不是同任务Stop/Resume验收。
- D5.39无overlay完整任务`sbk_d189b9eb-d17c-4157-b08d-7bf26a73bac7`仍FAIL118.41s/package121.647s：SQL窗口24.835秒，279次env.SourceAuthorize后24.560秒拒绝；原失败Record=ok。未进入validating。
- 监督纠正：domain完整RR/data的437是checkSource回调数；原checkSource调用一次本地env.SourceAuthorize，随后inUseCheck执行一次实际Control key-check并再次env.SourceAuthorize，因此263/279等本地计数不能除以437作为完成比例。原437回调通常会产生约874次本地grant/file授权及额外流前后检查。后续分别记录本地Authorize次数/累计耗时、实际Control key-check请求次数与domain guard回调数，保持所有原row/EOF范围；不以调整预期或删除边界宣称完成。

## D5.41 原held事务完整当前字段批量重读

- 无CPU profile的SQL-first日志`.tools/d-request-authority-once-cost.log`实际FAIL63.91s/package67.226s，domain guard222次、本地Authorize445次/384.6221ms，实际key-check231次（包括流前后）。平均每次控制请求约125ms：plan30.947、Stage41.239、collectors19.932ms；本地grant/file并非主要成本。该轮不是验收，原固定窗口未解决。
- 首次SQLExecutionAuthority.snapshot仍按原gate→business顺序、原全部SQL锁/owner授权取得完整状态；只在同一guard、context/tx且原application及metadata gate都held时，后续RecheckAfter把原当前SQL字段重读合为一条FOR SHARE查询。现有owner/grant回调仍每次执行；SQL时间下界/原固定until、全部原字段、config完整字节、原config历史、latest attempt、当前cancel、原app/public gate/fence/lease保持核验。其他阶段/恢复/无application-scope仍走原完整snapshot。没有跨请求/跨事务缓存或首次JOIN取锁顺序变化。
- 明确BINARY比较原Go精确比较的字符串与完整config，防止默认SQL collation掩盖大小写/尾空格变化。真实原SQL事务17种已独立读回实际变更（含rowversion/claim lease延长/owner尾空格/schema与task/status大小写/request尾空格/config/maintenance fence+lease+hold+owner/installation/attempt）均由末尾guard拒绝并锁定失败；每例rollback保留原fixture。原mTLS/TLS provider三场景、8种中途input/sealed变更与key-reserve当前claim撤回组合PASS8.71s/package11.927s；完整controller9.312s/adapter6.361s/execution8.244s PASS。
- 这是当前检查SQL往返优化，不代表完整新任务通过。完整原173/default30秒任务仍需无overlay完成原row/EOF、10 C/Evidence/Stop/Resume和实际Record(validating)，A发布/生产readiness均未声称完成。

## D5.42 批量事实读取之后重新采SQL时钟，修复监督过期反例

- 监督真实透传driver只延迟原SQL事实行交付2.5秒：旧末尾采时钟路径PASS6.507s，6ce批量查询在语句开头采UTC时间、返回时原2秒claim已过期却返回nil，candidate FAIL6.472s。因此6ce单独不安全且未被监督集成，D5.41的17种字段漂移/全包通过不能替代该时序证明。
- 在整条当前事实Query/Scan完成后增加独立SELECT UTC_TIMESTAMP(6)，严格检查时间不早于事实sample/原snapshot时间，且严格早于原claimUntil/taskDeadline/gateUntil/holdUntil；外层仍检查原owner until与beforeOwner/floor，并保留原当前grant回调。无原expiry延长、无caller时钟或权限伪造。
- 监督同一真实SQL probe复制为repo独立回归（原透传连接/真实SQL、仅事实行延迟），扩展claim、task deadline、gate lease、hold四种原2秒上界，每次实际更新一行、原Bind健康、delay真实触发且跨过原界限，四例全部拒绝且guard锁失败。定向PASS10.84s/package14.056s；最初同监督单claim例PASS3.31s/package6.531s。完整任务尚待，不能把修复和6ce字段测试称完整备份通过。

## D5.43 只转移已解码数据所有权，当前part按需规范化

- DescribePlan仍完整loadPlan（canonical/unique JSON、原任务绑定、完整Discovery/全部worker part验证）；loadPlan解码产生的Source/parts/writers已是新内存，直接转移所有权，取消随后同份数据的Marshal/decodeStrict副本。其他跨owner回调的copyDiscovery保持。新增实际plan多次Describe与Source/Writer/SpecJSON/InvocationJSON/CM name调用者变更反例，其他观察和原plan bytes不变。
- OriginalCapturePlan仍完整解密、Unwrap/Describe、验证全部part hash并在私有map克隆原SpecJSON；只在MatchPart中为当前原part执行kube.Intent规范化，与原job namespace/name/owner精确匹配。没有跨请求缓存或接受调用者Job字节。实际SQL/mTLS反例另将返回的plan/discovery字节原地破坏，原私有part MatchPart仍保持原值，异context与伪造对象拒绝。
- 原SQL/mTLS三场景、8中途输入/密文变化、当前claim撤回、17 held当前字段反例与私有所有权验证PASS/package11.616s。合并监督87082fae及906时钟修正后，publicadapter3.636s/controller9.310s/kekadapter5.491s/execution7.871s全包PASS。下次完整新任务必须包含906修正，默认window/行和EOF guard不变；仍未声称完整positive或A发布。

## D5.44 dedicated metadata使用驱动原生参数传输，真实二进制/协议验证

- 当前go-sql-driver/mysql v1.9.0默认参数查询返回driver.ErrSkip，database/sql每次Prepare/Execute/Close；仅metadata连接启用原生Config.InterpolateParams的SQL-first诊断`.tools/d-metadata-interpolation-diagnostic.log`，完整默认window仍FAIL62.21s/package65.589s：domain guard344、本地Authorize689/594.1792ms、实际key-check353，stream29.532秒。平均plan21.616/Stage25.604/collectors11.885ms，较prepared诊断226次有明显收益，尚未完成原437 callbacks/10parts。
- 只在实际ConnectPublicBackupMetadata连接选项增加interpolateParams=true，由驱动转义/参数类型编码，不拼接调用者值；现有utf8mb4/utf8mb4_unicode_ci、UTC、单语句、原pool admission/role及事务策略保持。business/source/observer连接选项未改，原SQL/guard/Keys/issuer/nonce/window无任何跳过。D完整TLS fixture后续只镜像该metadata driver flag，保留原TLS/账号/UTC，不将diagnostic overlay当生产入口已接入。
- 新独立实际构造器test使用一次性schema/有限SELECT,INSERT,UPDATE role（仅LOCAL SQL参数协议证明）。两种SQL mode（STRICT_ALL_TABLES与NO_BACKSLASH_ESCAPES）下，引号/双引号/反斜线/NUL/0x1a/中文emoji/看似SQL的完整字串、全部256种字节与真实staging.Seal密文均byte-exact，实际staging.Open核验原明文。time.Time UTC微秒、decimal、bool一致，提交后密文一致。服务器Com_stmt_prepare在正常参数操作不增加、含字面问号时原prepared fallback确实增加，证明确实走实际constructor flag而非只测fixture布尔值。
- 实际验证charset/collation/UTC、RepeatableRead与多语句拒绝；定向PASS0.07s/package1.375s，db全包1.710s/execution7.598s PASS。此项不证明TLS生产部署或完整capture，default30窗口/所有row EOF范围保持，仍需后续完整无overlay正向。

## D5.45 有界已认证原计划数据缓存，每请求重建私有对象/当前授权

- 监督明确允许缓存已认证不可变历史数据以消除重复解密/Describe，禁止缓存旧授权/claim/nonce/window/DEK。仅对实际PinnedExecutionIdentity开放；全局最多8项/32MiB（保守4倍外plan字节计费）、数据可用期最多5分钟且不超过原task deadline，LRU淘汰/过期不可用，所有返回byte slice独立复制，空非nil数组形状保留。缓存值只有plan/discovery，不含context、OriginalCapturePlan、guard、许可、nonce、key或DEK。
- 每次请求仍先原完整Authority.Check，再读取完整当前profile/config/spec与实际sealed SHA256/size/key_ref；当前Keys.Resolve读取原grant/实际key bytes并校验后只以digest参与data key。数据索引还包含原DB pool身份和完整Input/当前stamp；任一变更必须miss或拒绝。命中后重新构造本context私有OriginalCapturePlan/part副本，原Kube/claim/grants/取消/issuer Stage/固定期限/row EOF/末尾Recheck保持；原事务末尾还用闭合PinnedExecutionIdentity重新Resolve并检查当前记录密钥digest，临时key bytes立即clear，不接入provider IO。
- readPlainRecord返回实际已AEAD认证的cipher SHA/size/ref/payload hash/key hash；冷读必须与前置sample全等才可缓存，避免“sample是坏C、读取瞬间换成好C”把好明文错误归到坏C身份。真实SQL probe主动形成该竞态，首次拒绝、随后恢复坏C仍拒绝，未污染cache。冷读实际raw record SELECT计数1，另context命中保持1且对象不同；破坏返回plan/Source/Spec/Invocation不会污染后续命中；异context复用旧对象拒绝。
- 真实key bytes改变/本请求末尾key改变、cipher tag改变、claim/config/profile/spec/key_ref实际独立UPDATE并SELECT确认均拒绝；恢复原scope后缓存数据与独立LoadPlan/Unwrap/Describe逐字节等价。首次测试暴露空Writers由[]变null，修复后unit内存/数量/过期/alias/oversize组合PASS3.130s；实际cache SQL定向PASS1.60s/package5.010s。当前mTLS三模式/8输入变化/17当前事实/claim reserve撤回/4真实延迟期限及cache组合package24.157s PASS；controller9.441s/kekadapter5.403s/execution8.887s全包PASS。
- 仍未声称完整原六项任务成功，默认30秒窗口保持。下一轮以正式metadata原生参数传输及本数据优化，真实BuildCommit创建全新测试运行的原HTTP task；不改任何已失败旧任务/nonce/DEK，也不将diagnostic SQL-first顺序当完整正向验收。

## D5.46 当前部署forward授权完整字段合并读取，保持每个检查时点

- D5.45原顺序/无overlay原任务`sbk_045b1ce8-9678-47fb-b63d-0abed30aa27b`在原173基线FAIL101.98s/package105.316s，SQL localAuthorize715次/636.3345ms，stream28.914秒后拒绝；原failed Record=ok，未到validating。后续原顺序logging-only诊断确认plan持续cache hit（125847 bytes），每key-check约172成功SELECT+3DML/事务，Stage约72 SELECT；root独立透传profile约189/191含事务，均无PREPARE，不能称完整成功。
- 仅deploymentAuthorization改用PinnedExecutionIdentity.AuthorizeEffectiveExecution：仍每次读取pinned部署文件、当前signed grant及原purpose/status/profile/effective/账户UUID数据库。在原gate/business锁之后，一条FOR SHARE读取完整当前task status/profile bytes+SHA/last_effective_enabled，随后独立SELECT CURRENT_USER/UUID/DATABASE/UTC_TIMESTAMP，在事实交付/可能锁等待之后严格检查原grant及task deadline/clock floor。每处Authorize/Recheck/Stage/最终检查次数保持；generic AuthorizeExecution、issue_worker、recover、preflight的原入口保持旧SQL路径，动作选择复用相同纯函数，没有当前authority缓存或期限延长。
- 原分条effective+generic identity作为实际SQL对照，capture-only与prepare+capture两种原签名grant的capture/disabled/preparing/ready/acquiring十例决策及窗口/current guard一致。增加actual last_effective_enabled=0同事务反例（现18 facts）；另真实signed grant原5秒到期，真实owner facts Rows交付延迟5.5秒后原Bind必须拒绝（此前四个held事实延迟clock反例保持原触发点）。三mTLS模式、8input/cipher变更、claim-reserve撤回、18 facts与原baseline/新grant期限组合package20.830s PASS；此前baseline定向1.83s/package5.219s，grant期限6.45s/package9.765s。controller9.351s/kekadapter4.800s/execution8.248s全包PASS。
- root独立同driver/native参数传输对照每RPC189/191→165/167（少24），多数46–54ms；独立实际18facts/3mTLS/owner grant期限PASS16.212s。当前已同步审定5350e218的174迁移/catalog d4fe00a440acf094e1def2d99586e333bed7803ba82b504ab25829b133680a21，旧173日志不改名。下一步优先原顺序/无overlay新174完整任务，默认30秒/原DEK until/原行EOF保持，A最终发布未验收。

## D5.47 原held初始snapshot剩余共享事实合并

- D5.46新174原顺序无overlay任务`sbk_af10aeac-3f6e-44a5-b81b-849c18304767`仍FAIL96.37s/package99.615s：SQL开流原剩27.424秒，localAuthorize697次/609.5463ms，stream27.297秒后拒绝，failed Record=ok。原30秒窗口未解决，未到validating。
- 初始snapshot仍依原顺序取得engine/application/runtime、maintenance、installation、active config与task原锁，原task/config字节检查保持。仅在原application及metadata gate都held、status capturing的backup分支，把其后的原config历史、latest/current attempt、cancel与同一task维护owner/fence五份共享事实读取合为一条FOR SHARE；值/版本/完整config/取消/lease/hold全部验证，事实交付后独立SQL UTC时钟再查。其他状态、preflight/recovery路径不改；每处current调用/owner/Stage/EOF及固定期限不减少。
- 真实signed owner grant、原分条forward对照、原三mTLS/18facts/input变化、旧held四期限与cache反例组合package29.697s PASS。新增仅延迟该新共享事实行交付2.5秒、原claim/task/gate/hold各2秒真实SQL界限的四反例，原Bind均拒绝，PASS10.82s/package14.035s。完整controller9.380s/execution8.566s PASS。同步监督7079d230后下一轮原174/default30完整任务继续；本项不代表D owner complete或A发布成功。

### D5.47 后续：取消和最新attempt的真实SQL隔离

- 在D专用63507真实MySQL窄fixture中，独立admin插入并确认affected=1及SELECT读回：同任务pending/running cancel拒绝，已完成cancel和其他任务pending cancel允许；同任务较新capture attempt拒绝，其他任务较新attempt允许。每例均实际Bind与Recheck，事务rollback后才清理插入行。六例PASS0.88s/package4.127s；不把窄fixture当完整原DDL/备份任务验收。
- D5.47新174原顺序无overlay任务`sbk_96ccfed1-f311-42b3-81b1-030d31792cf8`仍FAIL96.73s/package99.984s：SQL开流剩27.23256秒，799次本地SourceAuthorize累计680.5178ms，stream27.1131秒后拒绝，原failed Record=ok。799是本地调用数，不能除以完整domain回调437当完成比例；尚未进入validating或完成A发布。监督已审查8c01075f并推送backup 975d2cec，独立当前事实/期限回归及初始Bind字段等价通过，每RPC少16查询。

## D5.48 相同已认证能力字节复用，当前证据仍逐次锁定读取

- `faadd9b8`只改三个能力文件。Prepare继续认证完整原签名文档；私有prepared对象在每次Recheck仍实际FOR SHARE读取原证据，核验system owner/installation、capability_snapshot、inline/healthy/none、完整SHA256/size与8192上限，要求当前raw及原expires_at逐字节/时间相同，并检查原database/installation/NotBefore/最短until。仅移除相同字节的再次JSON解析/签名/DeepEqual，无跨请求授权缓存、无权限读取跳过。
- 监督指出候选入口遗漏原authenticate的显式now.IsZero拒绝：合法签名NotBefore可为非零year0000，零时钟不一定Before它。原基线PASS3.472s/旧候选FAIL3.086s；现已补回显式拒绝，repo包含原签名year0000健康正向与零时钟拒绝。监督独立修复探针PASS3.060s/签名变更组合3.069s。
- 增加签名revoked/revision/破坏envelope、原时间上下边界反例；实际D63507 MySQL逐一变更owner type/id、evidence type、storage、health、encryption、expiry延长/缩短，affected=1且独立SELECT确认后旧prepared均拒绝；签名撤销同样确认实际raw/hash/size变更且旧prepared拒绝。最终真实SQL/签名定向package3.406s、原mTLS/consumer两组12.532s PASS；此前适配器全包在支持本地TLS/文件身份的执行环境5.103s PASS。普通沙箱的原Generate文件委派与S3 census失败不混作生产回归，监督同条件旧基线也复现。
- `.tools/d-prepared-capability-benchmark_test.go`仅诊断：同一元数据driver完整当前证据读，旧重复认证219071ns/op、168198B/op、848alloc；当前7821ns/op、6736B/op、27alloc，package5.566s。不能将微基准当完整备份通过。
- 原顺序、全量数据、默认期限的日志/CPU透明诊断任务`sbk_adad8c33-e660-43f9-88f1-f53937114a40`仍FAIL98.50s/package102.330s，source-open剩26.8636168s，domain437范围内实际完成386次回调、本地773次Authorize/691.8219ms，stream26.7400574s后拒绝，原failed Record=ok；尚无validating。日志/CPU profile位于`.tools/d-current-capability-cost.*`，持续plan cache hit，单请求132成功SELECT+3DML、事务计数另算。Stage通常58增量SELECT，collectors19；CPU样本Stage5.86s、PinnedExecutionIdentity.current5.09s（包含文件read3.93s），这些累计值重叠、且profiling增加成本，不能与无overlay延迟直接对比。后续优先Stage三次current/rebind路径实际测量，不延长原窗口或删减row/EOF。

## D5.49 原provider拒绝负任务增加实际背景写入与恢复证明

- 原公开HTTP/原Prepare、SavePlan、reTake任务`sbk_e0e24ecb-5295-44f1-ae92-ad9900e17a8d`，无overlay、当时HEAD真实build commit及174迁移，显式Generate拒绝的独立负测试PASS29.09s/package32.373s（`.tools/d-provider-denied-strong-background.log`）。该失败任务没有被转为成功：断言实际denied=1、Generate/Unwrap=0，candidate/result和C/envelope不存在，原Store.Record(Err)到failed并释放claim。
- 背景SQL使用原AcquireMutation/WriteWithLease/ReleaseMutation gate，另两协程实际写Pro7 sessions及Team20 artifacts文件；三个writer先各有至少两次成功写入。原模型进程终止ACK前停止并join物理文件writer；每次原Job dispatch要求2文件哈希、SQL progress和三个计数的非空held观察保持。原Resume后要求三个进程都运行、计数均超过held前值，且确实观察过application gate拒绝写入。原停止屏障/7运行且9仍停止/仅一次Pro重建等既有负例断言保留。
- 控制调用使用原service完整controlHandler（保留CE/relay等原路由），不再用trace handler替代。完整TLS fixture只镜像实际metadata constructor的InterpolateParams flag；原TTL/heartbeat、所有源数据和权限边界保持。流日志明确是localAuthorize次数与耗时，不拿它除以437估计domain完成比例。此有限提交不包含未成功的正向wrapper、validating延续hook或正向成功声明；仍为本地代码调用证据，不是生产kubelet/PVC认证。

## D5.50 Stage复用同一原事务已持锁guard，仍完整当前重查

- PublicJobOwner的StageOriginal仅接受同一原context/tx、完整Authority、DB指针、installation/application scope/enabled及同一个可比较Authorization对象；不同但字段相同的可变owner也拒绝。Stage入口以原guard执行完整RecheckOriginal（当前owner/grant/profile/effective、完整held事实、独立SQL UTC和原first期限），替代再次初始Bind/重新取得同样锁；随后所有原registry Bind、三次current/capability/mapping/grant回调、原DEK/nonce、末尾UTC和最终public guard/collectors均保留。独立Stage入口保持原Bind路径。StageOriginal任何失败都Invalidate原共享latch，不能由早期校验失败继续提交。
- ctx/tx/input/DB/installation/scope/enabled/相同字段不同owner身份八反例与健康当前回调/SQL读取，以及八事实漂移unit均通过；监督发现首版owneridentity测试的回调赋值使两边内容不等，已修为该case不加回调，监督独立PASS3.089s。此为模型driver，不替代真实SQL。
- 原mTLS fixture在原Bind后由同一实际事务变更20项字段，affected=1且独立SELECT确认，旧Stage与新StageOriginal健康都通过；四种SQL到期均拒绝。部分version/lease延长旧Stage内部新Bind可通过、新原guard拒绝；旧public最终guard本来也会拒绝，不能称Stage内部决定全部相同。另在明确核验私有schema/账号身份后仅授该窄fixture两表INSERT，用同一事务新增latest attempt/pending与running cancel，两路径均拒绝，permit/reference/binding/coverage数量及epoch不变，原失败latch保持。不是生产角色/完整DDL准入验收。
- 首版比较错误地在原NewDeliveredCaptureKeyJob已经真实key-check、引用进入unknown后重放key-reserve，旧健康也拒绝，FAIL6.756s；拒绝site定位RetainPlanned。改为先独立SELECT确认原unknown，再用当前合法key-check，不改引用/门控/nonce/许可，PASS6.696s。后续三mTLS/consumer/当前事实/四SQL期限/最新attempt及cancel/真实owner grant与事实行交付延迟期限组合PASS41.524s。
- 新独立issuer-expiry模式在新fixture签名冻结前将issuer设为8秒（其他原窗口不变），实际构造器/SQL保留原lease+签名until，健康business guard更长，等待原until自然到期并以SQL UTC确认；旧Stage和StageOriginal均拒绝，无新增permit/reference/epoch、provider Generate/login均0且原guard不能复活。PASS8.94s/package12.163s。三包全量（本地TLS/文件身份可用、未启实际MySQL环境变量）controller9.812s/kekadapter5.182s/execution8.764s PASS。
- 同源透明native参数RPC对照17次key-check：原Stage 151/149次SQL调用→145/143（少6，含事务），中位43.2154→40.9483ms，均值43.6718→40.7010ms；package6.937/6.133s均PASS。日志`.tools/d-stage-original-native-{baseline,current}.log`，仅诊断，不称完整六项通过。原174/default30/原顺序无overlay正向仍待新任务验证；A发布未验收。

## D5.51 背景held观察补充单调计数与首次恢复前采样

- D5.49的单Job拒绝任务只有一次Job-dispatch held基线，不能单凭32.373s负例宣称整个held期间SQL始终稳定。现在每个后续held观察除实际SQL progress与两文件哈希外，还要求三个成功写单调counter精确等于首个baseline；原所有worker实际停止及SQL stop barrier之后、首个Source Resume之前再次检查。第二个writer恢复时已有第一个writer运行，按原resumeChecks只在首次恢复前取全静止样本。checkResumed要求至少两次held观察。
- 新独立观察反例先在尚未取得capture gate的私有fixture实际运行原三个writer，各自成功至少两次，再停止并取得健康观察；随后真实启动Pro文件writer完成一次写入、停止，确认实际文件内容和成功counter均改变，再恢复原文件字节模拟ABA。下一次checkHeld必须因真实成功counter变化拒绝，没有手改counter、backup状态、门控、许可、nonce或receipt。该测试不声明自己进入原held capture，也不是同任务正向验收。
- 原实际writer ABA反例PASS15.42s；加强后的原provider拒绝新174任务`sbk_1ebd5531-29b0-4a37-86e9-c3d56735808f`PASS29.21s，两测试合包47.899s（`.tools/d-background-monotonic-and-denial.log`）。该原负任务仍由failed Record收敛，非成功任务。背景进度/文件内容因实际写入变化，后续恢复验收应比较实际held快照，不对照启动前写死值，也不缩减数据范围。

## D5.52 每次重开并核对完整当前grant文件，只复用原验签解释

- D5.50/51同步backup975d2cec后，以8deabc9d真实build commit、原174迁移/默认30秒/原顺序/无overlay新任务`sbk_0e2fb80e-a202-4d69-867d-fde180dd5364`仍FAIL96.47s/package99.695s：SQL source-open原剩27.939337s，857次localAuthorize/740.8679ms，stream27.8258414s后provider_permission_denied；原failed Record=ok，没有validating。日志`.tools/d-same-task-174-stage-original.log`，857不除以437估计domain进度。
- 原profile中PinnedExecutionIdentity.current累计5.09s，实际readExecutionFile3.93s，其余包括重复签名/解析。构造器仍完整decode/Ed25519/字段验证，并私有拥有有界65536字节原文副本；current每次仍同一路径os.Open/Stat规则/有界ReadAll/SHA256，再要求完整raw逐字节等于构造器认证的原文。删除/替换（包括同issuer合法重签续期/改purpose）仍拒绝；只消除相同字节的再次decode/verify。原grant本来已私有存储，所有SQL、current purpose/profile/effective、原time、每次key-file读取与digest及最终guard不变，无当前授权决定或DEK缓存。
- 新签名文件回归覆盖删除、目录、空、超限、额外字节、破坏签名、合法新签renewal/purpose、原NotBefore/Until与当前installation/owner/config版本/hash；构造器public输入、调用方raw与DeploymentBinding返回Actions/RecordKeys/CaptureKeys破坏均不影响私有数据。原TaskCaptureKey实际文件撤销/密钥变化反例保留。真实文件微基准重复认证210756ns/op、11657B/58alloc；当前完整读/hash/byte-equal131630ns/op、3665B/12alloc，unit+bench package5.751s PASS；不替代原任务验收。
- 实际D63507当前SQL/mTLS/四模式含原issuer自然到期、consumer/完整20字段及latest attempt/cancel、当前key/cipher/缓存污染反例、原claim/task/gate/hold/owner signed-grant真实延迟期限组合PASS50.804s。三包全量controller9.366s/kekadapter4.972s/execution8.216s PASS。后续必须重新以真实build创建原任务，无诊断overlay全六部分验证；当前未声称完整正向或A发布。

## D5.53 原六部分单任务捕获首次完整到validating

- 同步backup975d2cec、build commit=c076ceeb4d51247b86103494108b45c3fd8fe76d，新原174任务`sbk_6381882a-acee-428f-a737-00722c43b785`通过原HTTP admission→Prepare/原加密SavePlan→原reTake/acquiring→实际writer Pause/held→10原Jobs/native workers/独立原Evidence→全部停止→原态Resume→原Store.Record(Results)，独立SQL确认status=validating。无overlay、原顺序、默认claim TTL30/heartbeat5及所有原行/EOF检查，不重试失败旧任务/nonce/DEK。PASS127.52s/package130.819s，原runner=ok/record=ok，日志`.tools/d-same-task-174-current-grant-data.log`。
- SQL source-open原剩29.6047918s，流28.9898405s，本地SourceAuthorize880次/772.4078ms，RunFormalCapture及ReportCandidate返回nil；880是本地调用数，不除以437作domain比例。后续control_evidence与control_evidence_proofs两个原native worker也成功，原worker completed/heldDispatches/独立JWT projections均10，active0，原恢复前检查2，10原stop journal及source witnesses等既有物理模型断言通过。真实背景3counter/SQL+2文件held观察与首次恢复前样本不变，恢复后三writer均重新实际写入；原7运行、9仍停止且gen不增、platform原UID/replicas恢复与单次Pro重建保持。
- 本提交公开单独正向test wrapper与严格结果/worker计数/物理恢复/原Record(validating)断言。helper新afterValidated回调只允许完整非deny分支、原Record已成功且SQL确为validating后调用，可让A在同一个task、SQL/C文件/本地服务仍存活时接firstForward；本轮回调nil，A尚未执行。失败分支仍原Record(Err)且测试FAIL，不将失败转成功。
- 运行时工作区另有未提交的restore-only适配WIP（domain/dependencies.go、normalize.go、current_business_restore*.go），未纳入此提交或恢复验收；其生产Normalize入口在restore/drill/preflight，不在本轮原capture路径。监督独立冻结或后续完整A发布复验应排除该WIP并同步已审定A材料。本次任务随fixture结束已清理，不能在结束后复用C/DEK/claim做A发布；A必须在下一次原测试的afterValidated生命期内继续同一task。
- 监督指出current grant注释“any replacement revokes”超出实际语义：原字节相同的文件替换在新旧实现都允许，没有inode pin。改为“removal or any byte change”，不新增inode限制。D63507当前无活测试handle，已给监督独立背景复测预留窗口。整体A firstForward/v12不可变发布/独立native readback与11表完整恢复仍未完成，不称production readiness。

## D5.54 同一次held重查合并完整owner与held事实，保留回调后SQL时钟

- 监督不含restore WIP的独立新174任务`sbk_ddf14508-51e9-49b2-b226-3060010dc23c`仍FAIL97.20s/package100.445s：SQL source-open剩28.834051s，localAuthorize867次/752.3392ms，stream28.720169s拒绝，原failed Record=ok。相比D5.53原source-open29.6047918s/完整880次，本次原claim/heartbeat签发相位余量更小；一次自测通过不能计默认窗口稳定解决。原until/nonce/DEK/数据及row/EOF均保持。
- 每次同一原guard的held Recheck，当前部署owner回调仍实际查forward flag/原pinned config文件/当前grant文件及原scope/期限；只登记闭合PinnedExecutionIdentity，登记本身不授权。owner回调返回、原ValidUntil相等后，控制器finish才把原完整held事实与原profile bytes/hash、last_effective_enabled合并FOR SHARE读取，随后独立SQL UTC+CURRENT_USER/UUID/DATABASE采时与核验。保留原回调→末尾事实读取顺序，当前字段全部比较、原最短until/clock floor/latch不变；非held、preflight、未采用该闭合入口的owner走原接口。每次held重查原5条读取变3条，未减少重查次数或跨请求缓存当前权限。
- 初版opaque公开值的used/valid与Mutex可整体复制，首版copy测试不足；改成private共享生命周期state+origin实例锚点，公开值仅含私有state指针，不复制Mutex。复制本体、复制回写不能重置登记，旧合法read副本赋给新read、closed/foreign ctx/tx/Authority/零值/unused均不能通过。真正SQL仅finish执行；新增原生wrapper先真实child Prepare成功，再同tx UPDATE backup row_version，affected=1且独立SELECT确实+1后返回nil，finish拒绝并锁失败。没有伪造SQL时钟/权限/receipt；原evidence/job-observation/key-use数量不增。
- 真实separate/combined对照包括原20字段及四SQL期限/latest attempt/cancel、profile_json/hash与effective false、实际forward flag撤回和config文件移走，失败后恢复文件/flag也不能复活原guard；私有fixture profile UPDATE显式核验schema/账号后授权，不是生产role或完整DDL接受UPDATE证明。原账号/server/db身份变化由透明native driver仅在真实结果行交付后替换命名单元，真实服务器/账号/UUID未改，不称实际identity迁移。原signed grant5秒、合并facts行真实延迟5.5秒确认触发并跨期后拒绝；原四个held及四个initial期限反例保留。
- D最终模型3.074s、原生四provider模式/consumer/全部字段和策略/身份/真实延迟/copy与尾部变更/原缓存key+cipher反例组合66.004s PASS。监督独立65298原生矩阵60.302s、copy+尾部变更补8.740s/模型3.116s、缺口consumer与原plan/key/currentSQL补8.491s、controller9.330s/execution7.792s/publicadapter3.636s PASS；最终private registerOwner命名和注释已与监督冻结核对。日志`.tools/d-held-owner-final-combined-regression.log`，本项10个Go文件单独交付，不混全174新钩子或restore WIP。下轮仍须新原任务无诊断全六项验证，A最终发布尚未完成。

## D5.55 A原core签名前配置与同任务材料准备接口

- 新`dOriginalSixPartFixtureOptions`提供`BeforeCoreSeal(ctx,t,f,*DeploymentConfig) error`、`AfterOwnerReady(ctx,t,f) error`、`BeforePrepare(ctx,t,f) error`。`runDOriginalSixPartCaptureWithOptions(t,deny,complete,options,afterValidated)`保留同一个原HTTP task、原queue/reTake/nonce及全部10workers；旧三个helper入口均用空options，原行为不变。
- BeforeCoreSeal在原coreRaw/DeploymentConfigSHA256及Forward/Recovery签名之前调用，此时原HTTP task publicID/完整源数据/SQL和控制TLS地址已存在，service/owner尚未构造。只允许PublicationSigners、PublisherVerifier、PublicationTarget、PublicationWorker四组声明不同；所有capture字段包括hold、scope、workspace、runtime/security/source/grant均须逐字节等同。传入proposal和返回结果各深复制，保留callback指针不能修改后续sealed core。
- AfterOwnerReady位于原owner/queue claim/源库存和RuntimeControl.Ready完成后、constructor返回前，可准备此前已声明的当前材料和Kubernetes对象；该点Runtime仍是component owner，完整capture runtime尚未compose。BeforePrepare位于原RunWithExecutionHeartbeat内、真实metadata/formal/runtime composition完成之后，原Prepare/SavePlan之前。材料准备不得改旧core，每个非nil准备callback后检查内存core、原digest与磁盘sealed bytes全等；afterValidated前后同样检查。afterValidated仍只在原Record真正到validating后调用，不能借它补改core refs。
- 不启实际SQL的两个签名前/后置防改测试PASS/package3.312s：四publication refs允许、七capture修改拒绝、nested/retained alias不影响原文或返回sealed配置、late publication memory ref/磁盘字节/digest改动均拒绝。未称已运行A材料配置/发布或全174新接口正向；A可直接使用该窄接口在未来一次原任务生命期内接线。
- 新SQL优化监督原174任务`sbk_4c8b86ad-12f2-47b3-88ca-fccdc98465d9`仍FAIL92.08s/package95.362s，SQL开流24.9963365s、localAuthorize833/726.1642ms、stream24.8808215s后拒绝，原failed Record=ok。源码证据：execution_heartbeat.go按5秒ticker以SQL UTC续同epoch 30秒；public_jobs.go最短until取当前guard/relay/request/prepared；public_key_use.go首次floorUTC写入原nonce，后续即使当前claim更长也保留original.Until；issuer签名NotBefore为reserve SQL时间、ExpiresAt为该原Until。尚未新增任何首次签发协调；如需此项必须由活跃合法controller在首nonce/intent前完成，不能由worker请求直接驱动续命，旧intent/DEK直到期均不得延长或替换。优先进一步有测量依据的当前读取/解析优化，不盲重跑。

## D5.56 同一prepared请求保留issuer已认证文档，逐次读取完整当前文件

- 旧完整任务CPU诊断中`readPermitIssuerGrant`累计1.60s（样本总CPU52.04s，包含profiling成本、不能当无诊断延迟）。当前Prepare仍完整打开/Stat/有界读取/SHA256、严格JSON与Ed25519验签及全部原grant配置/身份/期限验证；仅把已认证raw、独立issuer pin和私有解码数据保存在这一个prepared请求。每次Stage/ReadCommitted原recheck仍重新读取完整当前文件并检查hash/逐字节相同、issuer pin、完整当前配置语义、真实wall clock以及传入SQL now的原NotBefore/Until，显式拒绝零SQL now。所有原guard、capability、mapping、SQL及最终clock回调不变；没有跨请求授权决定缓存或原nonce/permit/DEK期限变化。
- 新文件/配置矩阵同时运行完整当前认证和prepared recheck：删除、目录、空/超限/破坏/额外字节、信任issuer替换、capture与workload digest、controller、binding、capability database身份改变均拒绝。合法新签续期在完整新认证可通过，旧prepared即使同时换新pin也拒绝；合法签名revoked两者均拒绝。原字节相同的文件恢复仍通过，没有声称inode变化就是撤销。独立公共读取DTO和caller输入的RawJSON/public-key切片变动不能修改私有grant/raw/issuer。NotBefore含边界、Until边界、零now及真实2秒原签名授权先成功后自然到期（即使用旧SQL now也不能复活）均覆盖。
- 不启实际SQL的三包全量PASS：kekadapter7.071s、execution8.429s、controller9.462s（`.tools/d-issuer-data-packages.log`）。实际D63507原mTLS/MySQL四模式valid/unknown-reserve-ack/revoked-after-login/issuer-expiry及原20字段/期限/latest attempt/cancel矩阵PASS28.363s（`.tools/d-issuer-data-native-regression.log`）；原issuer自然到期分支保留provider Generate/login为0及无新增journal/reference/epoch的断言。普通沙箱原Windows签名路径测试仍拒绝，在支持原文件身份/TLS的执行环境通过，不改授权规则绕过。
- 精确HEAD旧issuer两生产文件与当前生产文件、相同native参数/透明SQL计数overlay对照，各17次key-check，SQL数均125/127；中位总耗时40.5482→36.1896ms、均值41.6640→38.5147ms；中位SQL24.5340→21.3995ms也波动，不能把总差值全部归于解析；逐请求total减SQL的中位16.0495→14.6631ms。两次package6.361/6.783s均PASS，日志`.tools/d-issuer-data-native-{baseline,current}.log`。此诊断不替代完整六项任务/A发布验收；尚未重跑同候选全量，也未实现首次签发协调。

## D5.57 issuer候选一次完整时间线诊断与窗口移交

- 在新候选578c3095、merge build6bd73090上，以原174/六部分/默认30和5/原顺序及全部row/EOF检查创建新任务`sbk_e7732a6d-d1d5-46ad-bc10-642fa7293883`。六个当前源码文件的overlay只加日志，不增加SQL、不改权限/顺序/数据/nonce/期限；不是无overlay接受证据。原10个native worker、真实背景held/停止/恢复、原Store.Record及独立SQL validating断言通过；test125.70s/package129.219s，runner=ok/record=ok。afterValidated仍nil，没有A发布。session49753已terminal/exit0，63507窗口已明确释放给A/监督，D不再起SQL测试。
- 日志`.tools/d-issuer-full-timeline.log`的SHA256为`75a693983e5629ed4b0bb9678f875d33d4c3f0cbec0c596f3db09ae418b7ea7d`；结构化事件和六个实际overlay副本SHA在`docs/evidence/d-issuer-timeline-20261101.json`，生成器`.tools/d-issuer-timeline.py`。SQL worker的UTC链：heartbeat实际UPDATE开始03:13:03.030640/成功返回03:13:03.0362572；worker原nonce生成03:13:03.5967192；首Bind03:13:03.6177017已经读得until03:13:33.030791；初始minimum03:13:03.6203543明确guard最短（relay03:17:13、request03:17:13.8920211、prepared09:12:11.739626均更晚）；原意图UPDATE成功的SQL now03:13:03.621146，commit完成03:13:03.6458365。原until减30秒落在此次heartbeat SQL调用的实际wall bracket内，没有由worker驱动renew。
- 源打开之前的现有fixture观测为03:13:03.7337293/剩29.2970617s，实际外部Generate HTTP调用03:13:04.0813737仍用原until；该“source-open”日志在源构造器之前，不能称已量得首个SQL行/精确stream入口。实际RunFormalCapture26.6475761s、本地SourceAuthorize880次/765.0161ms，原SQL worker和ReportCandidate均成功。后续03:13:08、13、18等heartbeat继续成功，也不延长此DEK/permit原until。本轮相位较好，26.65秒流仍不能证明D5.55约25秒余量的相位稳定通过；任务已cleanup，不能复用它做A发布。
- 若后续确需首次签发协调，最小可审边界应是活跃`RunWithExecutionHeartbeat`的私有闭合controller上下文，在原Job第一次create-dispatch journal事务内、真实Job create/worker nonce/原key-use intent之前，仅对同Authority/owner/epoch做完整当前检查和默认TTL30的同epoch续租，并要求重新观察续后当前界限。必须同时证明确为首次dispatch、原key_use_json为空；已dispatch/已有nonce/旧DEK不能触发该协调。HTTP ready/key-reserve不得取得或调用它，关闭/复制/外国context、取消/latest attempt、实际到期及回滚必须拒绝。此处是依据时间线提出的边界方案，尚未设计完原journal锁序/闭合接口，也未实现；优先交监督/A复核后决定，不能直接让worker请求续命。

## D5.58 同一prepared请求复用owner mapping文档，变化仍完整认证

- 对照来源明确区分：本项原生九case的Stage/StageOriginal是两个现行入口，均运行新recheckMapping；纯单测legacy oracle不是原生旧源。另行原生旧源对照使用`mapping-data-native-baseline-overlay.json`，只将生产`provider_permit_issuer.go`替换为精确`2a4f08caf594607a694b321db5b85c3caed4c3e7`的完整文件（其已包含D578 issuer grant优化），副本`mapping_data_baseline_issuer.go`；其余生产源码与当前相同。两边均使用同一包含新九case的fixture、透明计数handler/probe与native参数consumer；`mapping-data-native-current-overlay.json`不替换生产文件。以上overlay均位于父workspace的`.tools/d-original-worker-overlay/`，只用于旧/新对照诊断。

- 旧完整CPU样本中issuer的recheck调用decodeOwnerRecord累计0.41s。Prepare仍实际读原owner表并完整decode/严格JSON/验签/Binding校验，另私有复制原raw、signature、issuer。每次recheck仍先执行原实际FOR SHARE当前行读取；仅当三个认证输入都相同才复用原私有解码数据。任一变化均回到原完整decodeOwnerRecord，随后始终比较原Binding、GenerateRevoked、SQL now上下界及当前Until不小于原p.until。保留合法新revision/Source版本/续期/仅Unwrap撤销的原Generate语义，不把byte变化当成owner表的撤销，不更新缓存原文/原minimum，不改任何SQL、回调数或许可期限。
- 非SQL原完整认证对照PASS3.060s，覆盖合法revision/续期/原minimum边界、缩短/Generate撤销/Unwrap-only/未来/到期/合法签名不同Binding、空/超限/坏JSON/重复/未知字段/坏或缺signature、合法签名仅JSON空白变化、issuer变化下旧签名拒绝和新有效签名完整认证。各case后原mapping、raw/signature/issuer及p.until保持，变化不会推进原prepared缓存。
- 监督授权后仅使用独立65298（真实UUID9679c9da-d595-11f1-b25e-745d22085e06）的一次性窄schema/用户，不改D63507 pin、不占A窗口，也不跑完整catalog迁移。原mTLS/MySQL四provider模式、原20字段/期限/attempt/cancel加实际owner签名表九case PASS35.795s（`.tools/d-mapping-data-native-regression.log`）。九case为revision、renewal、等于原minimum、短1微秒、Generate撤销、仅Unwrap撤销、未来、过期、坏signature；每次admin实际UPDATE affected1并独立SELECT raw/signature确认，Stage与StageOriginal都保留原决定/Until，permit/reference/binding/coverage/epoch无新增，失败原guard不复活，Stage比较不触发login/Generate。明确这是原表已签名字节故障注入，不是fenced installation writer/历史协议验收；没有新增生产角色权限。旧精确HEAD issuer生产文件overlay同样通过全部九case，package6.845s；当前package10.378s亦通过。两受影响包无MySQL opt-in全量PASS6.974/9.044s（`.tools/d-mapping-data-packages.log`）。所有SQL session92631/6128/48389已terminal0，65298窗口释放。
- 相同native参数/透明计数对照各17次key-check，SQL数均125/127。旧→新总中位38.7571→43.6092ms、均值39.1617→45.4322ms；SQL中位24.4807→30.0592ms，逐请求扣SQL后中位14.8552→13.6144ms。本次总时间变慢，不能声称完整请求提速，也不凭此排除回归；记录实际SQL波动，留待监督独立复核。文档认证单独微基准`.tools/d_mapping_cost_test.go`/`d-mapping-cost-overlay.json`只比较同一健康raw/sig/issuer完整认证与复用数据：211671ns/183665B/2477alloc→595.0ns/704B/2alloc，PASS6.018s；它不包含或代替任何SQL/current/provider授权检查。此提交不混首次签发协调、A fixture接线或完整六项通过声明。

## D5.59 首次dispatch只读边界审查，尚未实现协调

- 后续源码核实更正：初始SQLExecutionAuthority.snapshot已按原顺序对maintenance、installation和task执行FOR UPDATE；FOR SHARE主要用于后续held重查。下述锁升级担忧来自把后续held查询误作初始Bind，不适用于实际初始事务，不能据此认定原路径有该死锁。最终按监督最新指示选择D5.60首次Bind同事务边界，未实现本节RecordCreate替代方案。

- 原`kube.SQLJournal.transact`顺序是Serializable Begin→完整Fence→ResourceRows.Load FOR UPDATE→change/原CAS→完整Fence→Commit；`Runner.Ensure`只在原RecordCreate已成功后发真实Job Create。PublicJobOwner.runner的两次Fence各自Bind并Recheck，没有把第一次guard保存到第二次使用。`SQLExecutionWorkStore`本来已有Queue、完整Authority和Records；实际public scheduler三者齐全，fixture单纯源准备heartbeat仅有Queue，不能据此默认为可做新dispatch协调。
- 因而不能直接在已锁Job行的CAS回调里调用现成DB续租：原Fence可能已持backup共享锁，再升级该行写锁；若多个首次Job事务同时停在此点，会有锁升级死锁风险。D5.57的“同journal事务”只是拟议边界，并非已验证实现要求。任何此类方案需先解决原锁序与并行创建；本轮没有改CAS/SQLJournal/heartbeat。
- 更窄的待审替代是只装饰controller持有的ResourceJournal.RecordCreate(Job)：在调用原RecordCreate、打开其原事务之前，通过活跃RunWithExecutionHeartbeat私有闭合上下文发起controller自有协调事务。它必须使用原Store.Authority/DB/owner/完整Authority，并在任何SQL锁之前串行同task的协调；按原业务锁序检查当前授权，再锁/核验原Job exact intent/revision、create_dispatched=false、UID空、非删除/撤销/停止及key_use_json为空，才做默认TTL30同epoch续租。必须在旧claim仍未过期时成功affected1，并以新的完整Bind与SQL clock确认原task/hold/grant等期限仍有效后提交。随后原RecordCreate原CAS/双Fence及真实Kube Create照常执行，不给worker任何续租入口。这里是候选设计，不是已验证的锁正确性结论。
- 此分离事务窗口即使发生同Job并发，原RecordCreate CAS仍可拒绝；协调事务提交之前原create-dispatch尚为false且Job行被锁，合法Job API Create与worker首nonce不能先发生。提交之后若其他合法controller调用先完成原create，当前调用只能通过原CAS正常处理或失败，不能对已dispatch/已有key-use再做协调。已存在其他Job的原nonce/permit/DEK.until始终不改。活跃上下文关闭、WithoutCancel派生、同值不同owner/store、过期/取消/latest attempt、rollback/unknown SQL结果、与heartbeat及并行collector交错仍须真实测试，不能仅凭上述顺序宣称解决。尚未新增接口、context handle、SQL或测试；先供监督判断是否需要继续，A接线与已冻b583不受影响。

## D5.60 原controller Bind和实际Ready屏障的更窄候选点

- 继续只读审查发现另一个现存controller事件：ExecutionJobPorts.EnsureJob先让原Runner.Ensure真实创建并观察Job，再调用Jobs.Bind；PublicJobOwner.Bind→bindOriginal在独立原事务中首次写binding_json，之后worker才具备已提交Job/relay绑定。Authorize在public_jobs.go当前binding_json读取点明确把空binding拒为ErrNotReady，尚未走后面的key-use transaction。
- 两个本任务实际执行入口均在生成nonce前等待Ready：`backend/cmd/backup-worker/main.go`先awaitControl Ready，才进runFormalInvocation/NewDeliveredCaptureKeyJob；`production_same_task_workers_test.go`同样先Ready成功，再加载materials并调用NewDeliveredCaptureKeyJob；原rand.Read在NewOriginalKeyAuthority内。故可审查“活跃controller首次Bind、原binding_json/key_use_json仍空、原actual UID已观察”的协调点，比新建generic journal hook更窄，并可能少受Job创建耗时影响。Ready HTTP本身不做续租，也不得取得controller上下文。
- 不能把这个顺序推广到全部库调用者：NewDeliveredCaptureKeyJob/NewOriginalKeyAuthority库构造器本身没有强制先Ready，单独调用可先生成随机nonce再尝试reserve；本段只证明原命令入口和本任务native fixture的次序。若选择此点，必须把受支持调用路径/原pinned worker入口作为明确前提并审查所有实际调用者，不得靠空key_use_json就声称进程从未生成nonce。首次Binding已存在、recovery绑定、实际key-use存在或闭合controller上下文失效均不得触发；原同epoch续租/实际锁序/并行首次绑定仍需独立SQL验证。本轮没有改Bind/Ready/构造器、任何期限或测试。

## D5.61 首次controller Bind协调候选与最小SQL矩阵

- 根据监督授权改为原PublicJobOwner.Bind→bindOriginal的首次空binding分支，recovery和已有binding仅读路径不续租。原RunWithExecutionHeartbeat私有上下文绑定完整Store.Authority/Records/Queue、owner/epoch/attempt；WithOriginalControllerBinding只在该活跃上下文创建私有闭合frame，跨关闭/外国Authority/store拒绝，WithoutCancel派生也由原controller取消并join。未携带该私有上下文的旧库调用只保留旧行为，得不到新续租；生产LeasedExecutionRunner使用原完整scheduler，前置只有Queue的source准备fixture不被放宽。Ready/key-reserve等HTTP路由未改。
- 原Bind事务已有完整FOR UPDATE锁序，再核原Job exact request/owner/revision、真实观察UID、ready/未撤销/未停止、binding/key-use/process空，才用原Policy.TTL（默认30/heartbeat5均不变）更新同epoch heartbeat/claim。原guard显式Invalidate；新Bind产生独立guard，要求所有原snapshot事实及ownerUntil不变（仅SQL now和claimUntil可变）。写原binding后在原commit前重查完整owner、Job、held事实、实际metadata身份和独立SQL UTC；始终严格在原first guard cutoff内提交，不能靠新claim复活已到期原scope。旧nonce/key-use/permit不写，原row_version/epoch不变。私有frame used/prepared/closed为atomic，spent另有mutex；同run一次协调尝试后明确rollback或domain unknown返回都使该Job后续首写尝试只读拒绝，已有binding原读取分支仍保留。
- 私有上下文/原heartbeat协作测试PASS8.085s：健康与caller raw alias、外国Authority/不同owner对象/DB、关闭/取消、unknown标记后的readOnly、WithoutCancel异步取消并等待操作退出，模型明确不执行授权SQL。监督冻结前版两受影响包无MySQL opt-in全量PASS9.308/7.937s，当前新增SQL夹具不以此替代原生验证。
- 实际D63507窄当前列fixture十三case最终PASS1.22s/package4.483s，`.tools/d-first-binding-native-v5.log`，session41067已terminal0：健康实际读回新lease且原guard失效/新guard独立，随后真实rollback后committed lease不变；实际key-use/binding/revoked/stopped/合法空UID+空resource_version的unknown shape、偷owner、SQL claim/task/hold过期均affected1+独立读回后拒绝；另取消context、rollback后readOnly、模拟domain ErrCommitUnknown后readOnly。原evidence/runtime-resource/job-observation/execution-record计数不变，原另一个Job的key_use_json完整字节不变。新增Job为明确命名SQL DATA，非新Kube观察/正式采集准入；该fixture没有KEK registry表，不声称测到其epoch/引用。unknown-readOnly是rollback后返回domain错误的wrapper标记测试，尚非真实Commit ACK丢失或实际PublicJobOwner.Bind恢复。取消case是cooperative context，尚非committed cancel行。
- 前面失败均不算通过：首版复制Job保留旧request-hash annotation导致Intent拒绝；admin/db返回顺序及最后refresh误作cleanup已纠正（refresh只写容量采样，不续许可）；本scope不存在providerStageRows要求的KEK表，改为实际存在表的census；窄backups缺heartbeat_at，按真实098列定义仅在私有fixture加DATETIME(6) NULL；unknown造数使用NULL触发原NOT NULL/CHECK，已改合法双空字段，未改DDL约束或扩大角色权限。生产协调尚待完整原174/六项任务及真实ACK未知/重复Bind恢复、原cutoff交付延迟、committed cancel、多Job并发heartbeat等验证；本候选不称已解决完整任务或A发布。

## D5.62 首次Bind候选原完整捕获到validating，A当前C/domain验证失败

- 生产源码精确eff7b750，唯一overlay是监督冻结A d9100d1c的五个测试文件（原core前声明/材料安装/同任务回调）；没有生产日志探针、SQL/数据/row/EOF/顺序替换。原174、默认30/5、新原HTTP task `sbk_ccad2719-cfd6-4fda-8dad-ef93fdac55d5`完成10个原native workers、实际C/独立Evidence、背景held/物理stop/原态resume及原Record，runner=ok/record=ok、原独立validating断言通过。
- 十个源打开前原观测窗口依次29.6410837、29.673631、29.665803、29.6756631、29.6582491、29.6722328、29.6651952、29.6640764、29.4478253、29.4238142秒。SQL完整880次本地SourceAuthorize/756.921ms，RunFormalCapture25.1295495s，SQL ReportCandidate成功；这些是本轮实际观测，不把880除437作完成比例，也不据一次任务断言任意数据量都适用静态30秒许可。
- afterValidated确已进入A原回调。A在原validating/释放capture claim之后，以原默认policy取得同任务publisher claim receipt；随后`verifyOriginalPublicationCapture`返回0 parts/`execution record unavailable or conflicting`，在d910测试publication_same_task_mysql_test.go255失败。尚未进入prepareOriginalCaptureCertificate，也未签出证书；完整test FAIL130.97s/package134.209s、exit1。失败不可改记为A healthy通过；后续firstForward/v12不可变最终发布/目录/独立native readback仍未完成。
- `.tools/d-first-binding-a-d910-full.log` SHA256=`e1f51d81db81d5cb35af12ac9d4f7bef7d8e23a9d6f1436692f50148a68e610b`，结构化终态在`docs/evidence/d-first-binding-full-task-20261101.json`。session57967已terminal1，63507已释放给监督/A定位；fixture清理后不能复用旧task/C/DEK补做发布。真实ACK未知/重复实际Bind只读、原cutoff行交付延迟、committed cancel与定向并发尚待后续独立测试；当前不再为同候选盲重跑完整任务。

## D5.63 实际commit后丢ACK及同run只读查询的窄SQL补充

- 只增加测试，生产eff7不变。原consumer fixture的受限连接使用既有透明aPublicationACKConnector；仅在新case的实际first-binding UPDATE、完整tail检查之后把lose flag置true。底层原生Commit成功后返回专用ACK错误，包装为原ErrExecutionCommitUnknown；独立admin SELECT确认binding_json确已提交且与原字节相同、续后claim确已提交。随后同run创建只读frame，按当前完整authority锁和实际原binding读取/解码/commit，所得JobBinding相同，committed lease不再改变。原其他Job的key_use_json完整字节仍不变。
- 65298当时已明确释放后运行，原13case加此实际ACK case PASS1.19s/package4.469s（`.tools/d-first-binding-native-actual-ack.log`），session45102已terminal0并释放；此后按监督最新安排等待65298新窗口，不再起SQL。明确这是原生helper事务/同run SQL读回，**没有**把命名SQL DATA当真实Kube观察、原PublicJobOwner.Bind证书/冻结plan准入或跨进程恢复验收；先前rollback后模拟domain unknown的case仍独立保留，不与真实Commit ACK丢失混为一谈。原cutoff交付延迟、committed cancel、实际Bind重复/unknown恢复与定向并发仍待覆盖。

## D5.64 原cutoff在真实续租后行交付延迟中到期仍拒绝

- 仅测试扩展现有透明dHeldClockConnector：当且仅当实际first-binding UPDATE执行成功/affected1时arm，随后原fresh Bind的实际initial facts行交付延迟2.5秒。保持真实defaultPolicy30/5，把本case进入协调前的原SQL claim设为实际UTC+2秒；不是改TTL/heartbeat，也没有伪造SQL UTC。确认delay.fired和arm已消费，独立实际SQL时钟已越过原cutoff；尽管事务内已写入新30秒claim，Prepare仍拒绝且旧guard保持失效，实际rollback后committed lease仍精确等于原cutoff。
- 监督重新明确分配65298后，原13case+真实ACK丢失+上述实际延迟组合PASS3.69s/package6.912s，延迟case2.52s（`.tools/d-first-binding-native-cutoff.log`）；session70224已terminal0，无活跃D SQL handle。生产源码仍eff7，旧case默认不arm，不改语义；已有binding实际PublicJobOwner.Bind查询、committed cancel和定向并发仍未以本项替代。后续正式publication测试还必须在捕获前以ldflags链接真实Git HEAD，D5.62未带该链接的失败只保留其真实采集阶段证据，A正独立核验unknown build的消费门原因，尚不称唯一根因。

## D5.65 真实committed pending/running cancel在首次绑定前拒绝

- 仅测试：管理员连接实际INSERT原operations的cancel/pending和cancel/running，各affected1，独立SELECT精确installation/task/type/status确认已提交。随后新的活跃controller scope仍使用原受限角色，完整Authority.Bind两者均拒绝，不能取得后续首次协调权；独立committed lease前后精确不变。清理仅删除该私有fixture精确operation，affected1；没有扩大角色权限。它和原cooperative canceled-context case分开，不以取消context替代SQL取消。
- 65298原17case组合PASS3.89s/package7.191s（`.tools/d-first-binding-native-cancel.log`），session81527已terminal0。原cutoff延迟和真实commit后ACK丢失均继续通过，原key-use完整字节保持。生产eff7未改；实际PublicJobOwner.Bind重复/unknown恢复、定向heartbeat/多Job并发仍须另证。当前继续使用监督分配的65298窄窗口，不占A63507。

## D5.66 heartbeat拿锁后独立SQL钟拒绝过期复活，保留新鲜claim

- 新实际并发反例在默认heartbeat5/TTL30下持原backup行锁，独立performance_schema.data_lock_waits只过滤本私有schema/table，确认原heartbeat已在MySQL等待；随后完成首次绑定，旧statement-start UPDATE把刚续出的claim从04:47:42.467043写短到04:47:42.436513（30.530ms），FAIL9.361s，日志`.tools/d-first-binding-heartbeat-overlap.log`。一行GREATEST候选虽通过未过期写短反例，监督要求追加过期等待：旧claim实际设为SQL UTC+2秒（不改policy），实际wait已存在且独立SQL钟确认越期后才rollback释放锁；GREATEST候选仍返回成功并改写lease/heartbeat，FAIL6.618s，`.tools/d-heartbeat-expired-wait-baseline.log`。两项失败均保留，不计通过。
- 生产renewExecutionLease改为短事务：按原installation/task/owner/RV/允许status拿FOR UPDATE行锁，不用等待前UTC作准入；行交付后独立采SQL UTC并确认原lease仍有效、时钟不倒退。随后仍用原Policy.TTL更新同epoch，不降已有更新鲜lease；独立读取真实更新heartbeat/lease及其SQL钟，再次独立采交付后SQL钟，要求严格早于原expiry、新lease有效、heartbeat不倒退且新lease精确等于max(旧lease,真实heartbeat+原TTL)，才commit。任一失败rollback；不依赖SYSDATE/sysdate_is_now，默认30/5、owner/RV和旧key-use Until不改。Queue-only源准备不需要完整Authority；ctx取消导致SQL中断与真实零行/DB错误/过期拒绝仍按原分类处理。
- 最终65298二十case组合PASS10.80s/package14.026s（`.tools/d-heartbeat-locked-clock-multijob.log`，session9589已terminal0）：真实过期wait拒绝且lease/owner/RV/heartbeat原值完全不变，Queue-only Renew同样拒绝，之后当前authority不能再新绑定；真实未过期wait完成后claim和heartbeat均不倒退；两个同时启动的命名SQL DATA Job以同一活跃run分别完成完整guard/first binding/commit，独立读回各自UID和name，不串身份。旧另一个Job key-use完整字节不变，原ACK丢失/rollback/取消/旧nonce/截止交付均继续通过。这仍是窄SQL/闭合上下文证据，不替代实际PublicJobOwner.Bind恢复、跨进程或新的全量发布验收。
- 两受影响包全量无MySQL opt-in PASS controller9.321s/execution8.573s（`.tools/d-heartbeat-locked-clock-packages.log`，session44104已terminal0），原shutdown具名driver仅扩展事务和拿锁/时钟读协议，所有原zero-row/database-error/callback/parent-stop分类断言保留。此前单独GREATEST版两包9.363/8.469和native12.461均只是被后续真实到期反例否定的中间候选，不作为最终修复。当前原first binding主体eff7不变，本项单独三个Go文件和文档交付；65298所有D handle终态，窗口可交监督独立复测。

## D5.67 通用publisher续租拿锁后重新判定旧claim，保持RV递增

- 监督独立实际MySQL红基线`.tools/supervisor-publisher-claim-expired-wait-baseline.log`：真实data_lock_waits与独立SQL钟确认原claim过期后才释放行锁，原单条UPDATE仍成功，RV19→20、lease05:31:09.567646→05:31:37.571419，FAIL6.364s。此问题不在D5.66同epoch heartbeat API内；三个实际生产调用点`publication_pass.go`、`publication_remote_capture.go`、`publication_verified_capture.go`的ClaimCoordinator.Renew均传`*sql.DB`。
- RenewClaimInInstallation保留原目标五种descriptor、安装/owner/RV/active status CAS及成功RV+1。`*sql.DB`/`*sql.Conn`自行开始短事务：先FOR UPDATE取得原claim和旧heartbeat，行实际交付后独立SQL UTC确认尚未到期且钟/heartbeat不倒退；原Policy TTL经既有intervalMicros验证用于SQL，用GREATEST保留更鲜原lease。原UPDATE继续原CAS并固定读得旧Until；读取实际更新值和独立交付后SQL UTC，仍须严格早于旧Until、新lease有效/不缩短、heartbeat不倒退且新lease=max(旧Until,真实heartbeat+SQL TTL)，才commit返回RV+1。Operation无heartbeat，保留NULL并在实际前后SQL钟范围内检查lease。任何失败rollback，不把旧token/Job/key-use/DEK迁到新epoch。
- Exec-only与外部拥有的`*sql.Tx`无本函数可控制的commit边界，在写入前返回明确`ErrClaimTransactionRequired`（同时errors.Is ErrClaimLost），不回退旧UPDATE。已有Acquire/Release接口不变。旧coordinator/CAS单测使用明确标识的driver协议模型，保留正常RV/旧owner/接管/取消断言；operation无heartbeat分支实际走模型。TTL+1us仍通过，TTL+1ns保持原intervalMicros在SQL前拒绝的行为，未改共同Validate或截断接受新输入；尾检统一用实际SQL微秒参数。
- 原监督反例测试文件原样overlay在新实现PASS6.711s（`.tools/d-publisher-claim-expired-wait-fixed.log`，session12395 terminal0）；提交版三组原生测试PASS8.381s（`.tools/d-generic-claim-native.log`，session3063 terminal0）：过期真实wait拒绝、DB/Conn健康及长期限不写短、错误owner/RV/安装/终态/已过期拒绝、旧RV重试拒绝；额外两个真实wait中由locker实际提交owner/RV变化后均拒绝，独立读回只能保留已提交的接管值，续租不再写行。原Job binding/key-use完整字节不变。
- A实际发布者SQL/TLS Acquire/Renew/Release/接管与真实Commit后丢ACK两项PASS19.521s（`.tools/d-generic-claim-publisher-native.log`，session48633 terminal0）；ACK用已有透明Commit connector代替不再受支持的Exec-only adapter，仍先实际commit、再丢ACK并返回空token，旧冻结输入/旧授权的原断言保留。31秒长流项明确SKIP，不计通过。最终不启SQL的两相关包全量PASS controller9.359s/execution8.307s（`.tools/d-generic-claim-packages.log`，session83936 terminal0）。结构化证据`docs/evidence/d-generic-claim-renew-20261101.json`。实际PublicJobOwner.Bind读回候选仍独立、未SQL验证/未提交，不混入本项。

## D5.68 实际PublicJobOwner.Bind已有身份及真实只读Commit未知后恢复

- 新测试调用实际PublicJobOwner.Bind→bindOriginal，经过完整原input/加密plan读取、原实际authority/记录校验、真实本地CA签出的worker TLS证书、实际staging.Seal身份封套与原IdentitySecret SQL行。Kube Secret明确是本地fake client中的immutable模型对象，UID明确命名；既有consumer fixture原Job绑定seed在调用前作为本项命名SQL DATA绑定到这张证书，期限取证书/task/原invocation的最早界限并按DATETIME(6)截断。既有fixture key-use仅作为旧完整字节不变的pin，不声称它取得了新证书的key-reserve准入。
- 在活跃完整RunWithExecutionHeartbeat中依次实际Bind正常读、底层真实Commit成功后回执丢失而返回ErrExecutionCommitUnknown、同run再读；再关闭并新建进程内controller run做实际Bind读取，均返回同一原JobBinding。管理员独立读取确认原binding/key-use字节、committed lease及epoch完全相同，没有新nonce、首次协调续租、旧key-use更换或后补期限。明确只覆盖**已有binding仅读Commit未知/恢复**，不是新first-binding写入未知、跨进程重启、实际Kube观察或完整正式发布。
- 首轮测试FAIL4.416s：MySQL QueryContext可返回driver.ErrSkip，database/sql随后实际走Prepare；测试注入器只在QueryContext直接成功时标记事务，故实际没有丢ACK、Bind返回nil。保留`.tools/d-public-bind-readback-fault-dispatch-baseline.log`。最终仅在dispatch原binding精确SQL时标记所属事务，兼容透明Prepare回退；任何实际读失败均不能到commit，周期heartbeat/前置plan事务不消费该flag。最终原生PASS case1.10s/package4.414s（`.tools/d-public-bind-readback-native.log`，session46102已terminal0）。结构化证据`docs/evidence/d-public-bind-readback-20261101.json`。65298已正式释放给监督generic独立复核，D当前无活跃SQL句柄。

## D5.69 同一publishing任务的confirmed continuation与真实下一阶段接口

- 新`publication_continuation.go`接入实际RunPublicationPass：未知action仍优先原query-only路径；没有未知候选时，从同一安装的publishing/最新sealed capture attempt、原deadline/next_reconcile/无活跃claim及全部action已confirmed条件选择原任务，经原SQLTaskClaimStore.AcquireWithReceipt取得真实新claim。加载并固定原canonical payload、logical/action key、dispatch deadline/generation、row version及原observed version/checksum，要求manifest→marker→acceptance→catalog为完整无缺口前缀。依原version做独立HEAD/完整GET/EOF/hash/字节读回并取得原publication receipts；没有重签、重发旧PUT或新建attempt。
- A可调用的同包小接口：`preparePublicationContinuation(ctx,store)`返回私有句柄（原claim/attempt/policy、next/action/object）；`recheckTx(ctx,tx)`在调用者同一原事务中重新检查当前authority、目标pin、完整原actions和各独立readback receipt；`publishNext(ctx,store,immutableIntent)`在实际beginPublicationAction原事务中先完成上述recheck，再创建下一marker原journal并走原native发送/观察协议，句柄一次消费且commit未知不盲重试；`close()`先关闭并join已进入发送/读回，再释放精确原claim。外部请求/HTTP没有该句柄入口。acceptance/catalog明确返回ErrPublicationFinalizationRequired，不能仅凭confirmed存在就签发验收/目录；最终CAS尚未连入。
- 首轮WIP在事务内构造publicationAccess，原fixture捕获“Kubernetes I/O while original metadata SQL transaction held”，47740由Ctrl-C停止exit1，保留`.tools/d-publication-continuation-access-in-tx-baseline.log`，不计通过，也不声称该中断轮清理已验证。已修为任何TX前构造/Check原access并私有保存；recheckTx只用该原access.Bind及本地SQL/文件检查，不重开跨连接authority、不延长原Until或采纳新epoch。最终native包含实际外层持同task FOR UPDATE时的recheck，界限内返回且fixture无SQL中Kube I/O。
- 早期7case PASS23.539s只限当时源码；后续8case实际PASS27.682s保存在`.tools/d-publication-continuation-native-eight.log`。最终9case实际PASS case27.29s/package30.614s（`.tools/d-publication-continuation-native-nine.log`，session73251 terminal0）：真实marker下一阶段、同任务新claim重入/原PUT不重发、并发CAS仅一个claim、下一marker实际PUT后读回失败保留原manifest confirmed和marker unknown、真正RunPublicationPass仅读恢复后下一轮再次选择原publishing并要求独立验收、unknown不入send、原version变化/阶段缺口拒绝、四个确认对象仍不准succeeded、生产pass显式next-intent拒绝、close join真实在途GET及闭合后不能重发。fixture JSON为明确协议DATA，不是正式签名manifest/marker/验收。
- 最终execution包无SQL opt-in全量PASS8.446s（`.tools/d-publication-continuation-package.log`，session64424 terminal0）；结构化证据`docs/evidence/d-publication-continuation-20261101.json`。主线backup0e9ed46a已安全merge到D28d74bee后实现本项。当前runPublicationContinuation的NextIntentRequired/FinalizationRequired是尚未接A typed生产者的明确保护，**不能作为整链完成**；A继续manifest/container/upload和签名适配，D继续独立读回/验收/catalog及最终CAS。所有D SQL句柄终态，65298释放给监督独立复测，63507不占用。

## D5.70 并发close共享同一次join和唯一Release结果

- 监督精确0ccc纯协议红例（无SQL/生产改动）确认：首close等待entered operation时，第二close因closed.Swap(true)直接nil返回，并隐藏首close实际Release错误；`.tools/supervisor-continuation-concurrent-close-baseline.log` FAIL3.229s。原D5.69的单close GET测试不证明此并发性质，不能用原9case通过掩盖新反例。
- close现在先closed.Store(true)停止新操作，再用同一sync.Once.Do执行join及唯一原claim Release。并发Do等待首次调用完成；所有close返回同一保存的closeErr，后续调用也不重复Release或隐藏第一次失败。单独模型使用真实database/sql driver边界、0-row Release→ErrClaimLost：两个close均不能越过持有的operation，释放后相同错误、唯一SQL call，第三close仍同错/call不增加，PASS3.341s（`.tools/d-continuation-multiple-close-model.log`，39211 terminal0）；不冒称原生SQL权限证据。
- 原生在途GET改为两个并发close，两者都须等GET完成、原发送返回后共享一次成功Release，闭合后不能再PUT。仅此定向native PASS case2.93s/package6.168s（`.tools/d-continuation-multiple-close-native.log`，84060 terminal0），不记成修后9case重跑。监督原红文件原样test-only overlay加execution全量PASS8.027s（`.tools/d-continuation-multiple-close-package-and-root-probe.log`，65117 terminal0）；没有production overlay。结构化证据`docs/evidence/d-continuation-close-join-20261101.json`。65298所有D句柄自然终态并已释放监督，不抢63507。

## D5.71 Reader/native S3按原配置预算兼容v12大产物

- 原097实际CHECK/公开资源schema：max_artifact_bytes默认16GiB、最小1MiB、上限900GiB；max_index_bytes默认512MiB、最小1MiB、上限8GiB。新增共享MaxPublicationArtifactBytes/MaxPublicationIndexBytes仅表示契约ceiling，不代表当前任务授权。native S3 PUT/HEAD/open不再把所有payload硬截为8GiB，仍检查int64 size、固定version、delete-marker、encoding、原凭据/期限及后续完整EOF/hash。
- NewArtifactReadOnlyS3现在必须显式传ArtifactReadLimits，不使用未知SQL/环境/默认值补预算；repo全部既有调用点已更新（原调用仅四处测试）。成员读受实际MaxArtifactBytes、index定位/有界内存读取受实际MaxIndexBytes、版本搜索仍受独立总读取/页/版本预算约束。catalog/index读取检查index+全部唯一成员累计预算（与现有A assembly预算口径一致），按剩余量减法避免溢出；加载后的content同时固定原limits，不能换更宽reader继续ResolveEntry。合法index的8GiB上限保留，未扩大为900GiB。
- readPublicationLimitsTx在原guard/同一TX按安装/version/configSHA读取实际materialized两项预算并recheck，无跨连接SQL/Kube I/O。D continuation取得并私有冻结该limits，读回/下一marker transport用withObjectLimit只收紧当前任务clone，不改变共享client/target identity；原recheck又读当前limits，变化拒绝，不把旧scope采纳新预算。A payload/upload/verified_capture负责对应actual配置传递及其上限修复，可复用该同TX helper和共享ceiling；D这一项不冒称已经修完A路径。
- TLS/Reader容量矩阵PASS3.754s（`.tools/d-artifact-capacity-native-tls.log`，57438 terminal0）：真实签名TLS HEAD的9GiB和900GiB边界接受、900GiB+1拒绝、较低16GiB transport拒绝17GiB且clone不能放大；PUT仅是明确HTTP metadata boundary模型，不发送大body。9GiB版本元数据进入真实List/HEAD/GET后，5字节短流仍因完整EOF/length检查失败；较低实际配置在I/O前拒绝、index实际budget拒绝、缺失/超契约limits拒绝。真实签名catalog/index的9GiB成员元数据在16GiB预算内可定位，8GiB预算与累计18GiB超16GiB拒绝，改变reader预算拒绝。此为大size边界/元数据和短流证据，**不是9GiB/900GiB全文或业务验证**；原小body实际EOF/hash/篡改/固定旧版本回归保留。
- 实际65298当前原config预算读取/transport收紧/Reader接收及committed budget变化拒绝PASS case7.74s/package11.307s（`.tools/d-artifact-capacity-config-native.log`，19768 terminal0）；最终execution全量无SQL opt-in PASS10.319s（`.tools/d-artifact-capacity-package.log`，80846 terminal0）。结构化证据`docs/evidence/d-artifact-capacity-20261101.json`。基线backup8f82e387已安全merge至D5eb3bbf3且容量WIP完整保留；当前D所有SQL句柄终态，65298释放监督，63507不占用。

## D5.72 预算首次绑定也核对原snapshot bytes/size/SHA/JCS

- 监督独立发现D5.71只读materialized预算的缺口：在任何capture/authority前冻结完整原ConfigValues JSON，健康读16GiB；仅把097列合法改为17GiB（原20GiB staging关系/CHECK均保留），原098 task JSON/SHA完整字节不变，全新access/guard仍采纳17GiB。v2 FAIL case2.71s/package6.037s（`.tools/supervisor-d-capacity-initial-snapshot-v2.log`，40558 terminal1）。v1的32GiB注入被原CHECK拒绝6.013s，未到读取点，不算漏洞复现或修复证明，原log保留。
- readPublicationLimitsTx现在同一原guard/TX把097配置和同一098 task按原安装/configVersion/configSHA关联；完整读取snapshot JSON和两端size，要求实际bytes长度精确一致、2..262144范围、SHA等于原guard ConfigSHA、原bytes确为JCS且无重复/尾随JSON；以UseNumber解析原capacity中的两个必需整数，类型/范围严格校验后与两materialized列逐一相等，才做原guard tail recheck并返回。初次或后续不一致均拒绝ErrPublicationConfigBudgetMismatch，不以新claim/newaccess合法化同hash的列漂移，不查询真实097不存在的canonical_config_json列，不加DDL或改任何CHECK。
- 原9场景使用的窄consumer快照曾只有`source` DATA，缺容量应失败而不是猜默认；newAOriginalPublicationService现从原v12完整ConfigValues示例在任何capture/authority/key-use创建前冻结完整canonical快照，enabled/control容量预先固定，其余保护不变。没有事后修改已签/封存task JSON/SHA/nonce。单测覆盖缺capacity/字段、字符串数字、非整数、重复键、非JCS、超范围和SHA替换，均无预算输出；仅是预算提取模型，不冒称完整ConfigValues准入验证。
- 监督v2源原样test-only overlay和提交版同反例均运行，production无overlay。组合原生PASS43.852s（`.tools/d-capacity-initial-fixed-native.log`，49631自然terminal0）：提交版初次漂移case3.56s、当前配置/变更拒绝3.07s、完整9 continuation实际30.85s、监督原样反例2.57s。最终execution全量无SQL opt-in PASS8.877s（`.tools/d-capacity-initial-fixed-package.log`，26414自然terminal0）。结构化证据`docs/evidence/d-capacity-snapshot-binding-20261101.json`；65298已明确释放监督，D无活跃SQL。
- catalog独立WIP七个文件先按SHA完整保存至workspace `.tools/d-catalog-wip-d48e5bf9f34c4b448dc99a7289a83382/manifest.json`并移出编译，本项没有catalog源码/材料。预算复核通过后再恢复并继续typed artifact/acceptance/catalog/final CAS，D5.69临时拒绝不是完成终点。

## D5.73 原始purpose引用三方绑定与独立catalog仅读恢复

- 监督原生反例在原098 JSON/SHA不变、仅097 artifact_write ref_version变化时，新current guard与匹配漂移DTO仍被旧helper接受，FAIL case9.50s/package12.841s，原日志和test-only探针SHA保留。现在artifact与catalog共用同TX原始检查：按安装/task/configVersion/configSHA关联097/098，读取原snapshot bytes与两端size，核对长度/SHA/JCS/唯一JSON，严格提取唯一purpose/identity_hash/version；原快照、当前列和传入映射三者必须一致。容量解析复用相同canonical body检查，原预算限制保留。仓库内原生覆盖artifact write/read/CA与catalog read/append/共享artifact_ca列漂移，原task bytes/SHA保持不变，新access和匹配DTO均不能采纳漂移。
- 可选catalog child文件在原deployment target内按绝对路径/SHA预先固定；独立catalog read/append身份和凭据路径不能复用artifact任一角色，互相也保留原native transport区分。catalog未另造CA配置列，明确沿用原artifact_ca身份/ref并独立pin其本地CA文件。实际unknown pass、observation、receipt与confirmed continuation按action选择正确store；current检查仍在原TX，构造器仅本地文件/TLS检查，无嵌套SQL或Kube I/O。catalog request_sent协议DATA实际仅原一次PUT+一次GET恢复为confirmed_present，artifact请求为零，task仍publishing/不可用。新catalog action在已有journal读取之后仍明确ErrPublicationFinalizationRequired，映射不能当作签名或独立验收。
- fixture现在在任何capture/authority前冻结完整原ConfigValues与实际purpose refs，未补写已封存snapshot。旧四JSON finalization用例收紧为三个artifact确认对象，artifact writer尝试catalog被拒绝；不再把第四个artifact对象称为目录确认。独立证书固定对象后续沿用A的control/capture-certificate.json，通过manifest capture_certificate_hash绑定，不改index角色或framing。
- 首轮最终组合native FAIL117.936s，四个continuation case返回generic unavailable，完整失败保留；只增加样本年龄/固定安全phase标签后的单例PASS10.780s、九场景PASS77.205s，未复现原失败，故不声称唯一根因已证实。五秒容量报告freshness是明确边界：之前开始操作时样本已有3.35–4.54秒。fixture在新的容量预留边界重新采集明确命名的容量报告DATA，不改生产freshness/TTL/授权；额外原生用SQL时钟制作六秒旧sample，必须零journal/零PUT、原status/RV不变，随后仅新sample即可用同原task/claim完成一次PUT。不是生产物理容量测量证明。
- 最终native组合PASS128.708s（26980自然terminal0）：独立原反例、catalog两项、原九continuation、真实原journal ACK/冲突/receipt，以及stale capacity拒绝。既有六项readback/current变化复查+原过期dispatch query-only PASS72.993s（34800 terminal0）；仓库内artifact三purpose反例PASS11.372s（68681首段）。最终execution整包无SQL opt-in PASS10.050s（68681末段），diff check通过。最初受限host整包FAIL8.973s为本地socket/private-file权限失败，日志保留，不计通过。所有D测试进程终态，65298可供监督复核，63507未占用。
- 结构化证据docs/evidence/d-publication-original-reference-catalog-20261101.json。此项不声称完成正式manifest全部业务验证、原C逐成员独立解密验证、staging cleanup、signed acceptance/catalog producer或最终CAS。临时拒绝不是整链完成；继续与A的固定证书/manifest/upload接线组合。

## D5.74 独立artifact_read固定版本整流容器内容检查

- D5.73交付b3630f8b1b35152129dd22555722461ea4da69ab；随后安全merge共享backup a9fb7ce9为2d121933dfb1412f6db86fb901063781d28b1162，保留原registry/SecretPolicy及新增离线材料，没有覆盖A的MF/Job工作。合并后execution整包无SQL opt-in PASS14.871s，51237自然terminal0。
- 新ArtifactReadOnlyS3.InspectPartContainer仅复用既有独立artifact_read构造器及显式原ArtifactReadLimits。输入固定对象版本/大小/hash、完整scope/checkpoints，先核对原installation/root及固定backup/attempt/parts/<part>/container.enc路径，然后实际HEAD+一次固定version完整GET。私有sequential ReaderAt仅适配现有Inspect的顺序读，任何回跳失败；读取的同一prefix/header/member字节由既有part-container Inspect解析与整包hash，最后再对实际HTTP body做EOF探测，不能由known size合成EOF。调用后检查关闭、精确消费长度、实际EOF、当前context/绝对Until和原pin读凭据，任一失败返回零facts。
- 未调用SQL/current claim/KMS/写凭据，没有临时完整对象文件或大body ReadAll。返回pc.Facts明确为惰性内容事实，不是typed finalization receipt；仍须从独立认证原记录获得输入hash/scope、逐成员完整C解密及六域业务验证。此处不把仅cipher hash/envelope结构当作C plaintext验证，也不声称manifest/certificate链、staging cleanup或signed acceptance/catalog/最终CAS已完成。
- 13场景使用实际本地AES-GCM C和真实container codec字节，但明确是命名LOCAL DATA而非原任务capture。构造reader前真实删除artifact write凭据，健康仅1 HEAD+1 GET/0 PUT；整包hash、成员cipher变化且同步更新整包hash、checkpoint/config scope、固定version/size、越界key/budget、HTTP短流、GET中撤回读凭据、已进入GET正文后的实际deadline、预先cancel全部拒绝且无可用facts。额外纯adapter模型确认读满size仍未EOF、回跳失败、独立EOF探测后才可完成。未做多GiB全文或业务验证。
- 初始11场景TLS PASS3.463s（10767）；加入deadline/cancel并跑两包全量PASS execution10.543s/part-container5.166s（38285）；最后加强deadline case必须原HEAD/GET各1，13场景最终PASS case0.35s/package3.659s（26625）。上述均无SQL opt-in且自然terminal0，65298没有D活跃句柄。结构化证据docs/evidence/d-artifact-container-read-20261101.json；A的公开证书固定路径与MF/index角色保持原约定，继续完整typed验收接线。
