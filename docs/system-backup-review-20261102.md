# 页面完整备份优先：审核记录（2026-11-02）

本轮基线 `backup@171ad17c`。用户要求新建 A、D、公共 C 三个对话，由本对话统一审核并提交远程 `backup`；第一优先级是页面点击完成同一任务的正确备份。

## 本轮通过的切片

- D：真实页面单次点击采证入口，保留原幂等键，核对原 task/installation、详情头和递增版本；公开成品就绪仍返回待独立证据，不宣称完整验收。首提交 `0e082158` 已推送并核对远程 SHA。
- A：Permit Stage/Recheck 固定标签分段计时，默认关闭，不缓存授权或延长原窗口。native context 接线作为可检查的独立 patch 随附；未应用时不得声称 native 日志已有分段。PowerShell 验证器对 native SKIP 或缺计时输出拒绝通过。
- 公共 C：实际上传入口复用原封存名推导，额外核对 task/attempt/config、Job UID/代数、invocation/binding 和候选内容。不含未消费的清理 helper，不宣称本地删除、acceptance/catalog 或成功终态已完成。

## 审核者独立验证

仓库根目录运行 `node e2e/backup-live-contract.test.mjs`：4/4 通过、0 skipped、退出 0。`node --check` 两个模块通过；点击入口 `--help` 退出 0，缺配置反例退出 1、receipt=null，未连接现场。默认 `node --test` 在沙箱因 spawn EPERM 未执行用例，已改用同进程执行。

`backend` 目录，Go 1.26.1、GOTOOLCHAIN=local、GOPROXY=off、GOSUMDB=off、GOMAXPROCS=2：

```text
go test -mod=readonly -p 2 ./internal/systembackupkekadapter ./internal/systembackupexecution -run 'TestProviderPermitTiming|TestPublicationLocal|TestPublicationNativeCleanup' -count=1 -timeout=180s
```

退出 0：kekadapter 2.292s，execution 6.025s。覆盖新增计时拒绝/并发快照及封存绑定篡改负例、原文件清理和 native cleanup 邻近回归；这是本机组件验证，不是真实 SQL、Runtime 或完整页面验收。owner 初次并行冷编译遇 C 盘不足；审核者统一使用 D 盘独占临时目录，测试后 finally 校验绝对目标并删除全部本轮缓存和临时产物，退出 0。A/C 各自先前的构建目录也已清理。

## 尚未关闭的关键路径

1. 原 30 秒授权窗口内完整数据库采集未有新 native 成功证据；诊断接口不是性能修复。
2. 生产 PublishReadiness/PublicCapability 仍 workspace/false，页面六域 acceptance 会受阻；不能先置 true。
3. 原本地封存清理 SQL 日记及完整 evidence、acceptance/catalog 正式签名和读回、唯一成功结算仍需接线。
4. 同任务非空 Teams/Skills 最终产物和全部源 writer 物理恢复尚无本轮实证。

用户确认最终前端 origin 为 `https://10.130.14.23:32643`，目标是 zhanghui08 环境、远测 shell 为 Bash。默认密钥认证被拒绝后，用户明确改为自己连接、自己测试，审核者提供命令；停止继续尝试 SSH。未建立远程会话、未上传或部署。已提供只读 namespace/deployment/pod 版本和工具/磁盘盘点命令，待用户回传。Bash 页面命令见 D 交接；隔离 SQL 组件命令见 C 交接，均须满足前提，不能将 SKIP 或公开投影误作完整备份成功。

用户随后回传：context 为 `kubernetes-admin@kubernetes`；namespace 为 `clawmanager-zhanghui08-system`，UID `337cfe30-2c17-4b8e-b32a-760778b8098e`；App 为 `backup-test-zh-fix18`，实际 digest `c16f07c25c6dc8362aa09b7a1e81f5d1204f2812ae542bbcb21a3946975c6c9d`。未找到备份 controller；用户明确新增内容从未部署，其他 namespace 也没有。主机找到 Bash/git/Python3/kubectl，未找到 Node/npm/Go，可用磁盘约 1.8TB。这是用户执行回传，非审核者独立现场测量。下一步先完成生产收尾和同版本 App/controller/Worker 部署材料，不能在旧镜像上验收当前源码。

D 的 Bash 交接已改为独占工具目录，仅要求真实 repo 和登录态两个路径，不触碰已有 node_modules；现场证书沿浏览器实际信任链。审核者对三个 Bash 代码块执行 `bash --noprofile --norc -n` 通过，未执行安装、登录或点击，语法检查临时目录已删除。

用户已有 `docs/deployment_cn.md` 修改及 `.worktrees/` 保留，不纳入本轮提交。

## 第二轮审核中的接点

A 已核对现有 `PublicationSignersForTask → PublicationSigningKey → PreparePublicationRecord → Stage → SignCommitted`，无需新建签名框架。精确 payload/当前授权/唯一发送边界见 `system-backup-a-publication-signing-consumer-20261102.md`；legacy recovery DTO 与公共 v12 不兼容，不能替代。该文档仅静态核对，不代表正式接受/目录已经发布。

D 已核对根 Dockerfile 的 `app` target 同时包含 App 和 v2 controller、`backup-worker` 独立输出；App 默认启动不会自动运行 v2 controller。`system-backup-d-release-package-20261102.md` 目前只准备同源 OCI 候选构建与真实安装材料接点，不是完整可启用清单。审核者对两段 Bash 执行 `bash -n` 通过，并原样提取其清理函数，用失败的假 Docker 命令验证：builder 删除失败仍删除本轮 context；原构建退出 7 保持 7；构建成功但清理失败返回 1。测试未连接 Docker 或远端，临时目录已清理。

C 新增的实际 SQL 本地清理 producer 正在审核和准备独占 SAN/TLS MySQL 回归，尚未批准提交。原 native context 分段计时接线也已在工作区应用，待本轮统一编译验证；不能复用首轮的回归结果证明新代码。

第二轮实际回归已执行：现有公共签名向量通过（security 2.209s）；C 原文件清理/native 清理组件及新代码编译通过。首次 SQL 用例缺少 buildinfo commit，在建库前拒绝；补入真实基线 commit 与 dirty 文件 SHA 后，独占 MySQL 8.4.13/TLS1.3 下完整174迁移和原任务实际执行，226.86s 用例失败于数据库原30秒key/context/source截止时间，128次key-check累计28.306s，没有进入发布/本地SQL清理。SQL读回4位writer均有恢复回执、两道门禁idle、任务failed且无claim、external_actions=0；不认定现场全部物理恢复。精确边界和源码pins见 `evidence/supervisor-original-window-review-20261102-r1.json`。A据此继续当前读优化；C正向SQL闭环仍未验收，不批准推送删除实现。

D 的 `system-backup-d-controller-candidate.py` 已独立检查并运行8项测试通过，包含显式/缺省Downward API v1兼容、错误挂载和私有字节变更拒绝、输出不覆盖及不回显材料内容；对应文档两段Bash语法通过。它只消费私有已审核模板和材料pins，输出零副本/forward关闭的离线候选，report明确授权/在线资源/完整验收均未验证，不执行apply或创建权限。该工具不替代仍缺的正式安装材料和现场激活验收。

## 当前授权读与原窗口复核

审核者从 `951f4c51` 导出独立源码快照，仅叠加 A 冻结四文件，复用本轮 D 盘缓存。`go test -mod=readonly -p 2 ./internal/systembackupkekadapter -count=1 -v -timeout=180s` 退出0，包耗时9.027s。新增 `TestHeldProviderPermitRowsCurrentMySQL` 在本轮独占、独立UUID pin的MySQL 8.4.13/TLS1.3上实际运行，14子例全部通过（0.58s）：原序读取与后续同事务批量当前读取对证据篡改、缺失、mapping撤销/合法续期行为一致；事务结束后不能复用。独立SQL读回确认该测试自建随机schema已删除。原始日志SHA256为 `a4348a943fe61c8e31e82ba99d7c86117ee1ceedc44d3139518c1aa69fe469ba`。此结果不证明原30秒采集链已成功；A/B/C组合仍须实际复测。

C 新增 late-seal/absence 检查已在另一个冻结快照独立回归，`TestPublicationCompleteCleanupRejectsIncompleteHandles|TestPublicationLocal.*|TestPublicationNativeCleanup.*` 全部通过，包耗时6.490s。Windows用例在持有外来cipher的真实独占字节锁时，执行本轮自有文件删除和最终absence检查并保留外来文件，证明absence扫描不读取外来cipher；不把Windows上无效的chmod当作读访问拒绝证明。此处仍是组件证据，不能代替尚未通过的C实际SQL清理正向链。

D 的独占Kubernetes MySQL诊断入口已独立静态审查，默认使用现场真实私库固定digest；长连接PF/Ready不继承普通25秒HTTP请求超时，仍保留自身有界等待。审核者运行10项本地mock全部通过，Bash入口及A三个关联Bash脚本语法检查通过。mock覆盖原测试失败码保留、精确owner/UID变化拒绝删除、原子UID删除前置条件、清理错误继续擦除本轮本地秘密及长短请求超时分离。该工具仅为新随机namespace中的独占fixture，未连接集群，未证明镜像内OpenSSL可用或真实SAN/TLS/页面成功。

B 冻结六文件在A/B/C组合快照中通过整个domain包回归（8.565s）；新增MySQL五项真实专项全部通过（2.25s），包括全snapshot差分、同RR并发插入/更新/删除、COUNT保留MDL及rollback释放、COUNT前DDL拒绝和有限SELECT撤销拒绝。随机schema和账号已独立确认不存在。其他未设置其专属fixture环境的native恢复/worker用例仍为SKIP，未认定通过。原始日志SHA256为 `55dd273db952b367e62642331512be46382d3a4c89af947f648dd0481e4b18d2`。

同一冻结A/B/C快照的原窗口复测仍失败：`TestPublicationOriginalLocalCleanupSameTaskMySQL` 193.42s，包198.455s；数据库160次key-check累计28.1627152s，最后原key/context/source deadline逾期2.129ms。前序七个worker通过，未进入发布或SQL本地清理，不能将更多key-check解释为完整采集成功。A/B优化按保持当前读/权限/快照语义的窄范围回归审核，不宣称已解决原30秒。完整源码pins与失败记录见 `evidence/supervisor-original-window-review-20261102-r2.json`。公共C的SQL删除实现继续保留未验收状态，不随此性能切片提交；后续正常最终验证、acceptance/catalog和真实部署也仍未完成。

A 原context timing hook已实际接入测试源码，新增独占实例入口在任何fixture创建前检查TLS/独立UUID/全库可见性和空业务库，不删除按census推断的库。Linux打包工具绑定构建前source receipt与构建后精确文件集合/hash；运行入口只选择原candidate-cleanup测试，不宣称覆盖C的新SQL本地清理。审核者对实际runner进行7项本地假程序故障测试：成功、测试失败、测试与tee同时失败、仅tee失败、测试与退出码日志写入同时失败、测试与清理同时失败、仅清理失败均符合预期；原测试退出7始终保留，只有清理失败时返回1。假程序替代ELF，uname/stat/tee/rm按案例替换，不涉及Go/native SQL/Docker/网络；各轮临时树已删除。Bash语法和PowerShell AST解析通过，不能据此声称实际Linux诊断通过。

首次Linux构建准备在source receipt阶段暴露逐文件启动sha256sum的性能问题，尚未开始Go编译。审核者核对准确shell路径、启动时间和命令后主动取消该准备阶段，改为同一NUL清单的`xargs -0 -r sha256sum --`批量执行；保留逐路径regular/non-symlink预检和打包时文件集合/全部字节重核。实际空格/Unicode文件的摘要与旧循环一致，虚拟换行/tab/字面shell字符参数的NUL边界一致；完整3681文件来源快照也完成。旧半成品receipt不用于后续构建证明，新构建必须从新冻结提交重新取得receipt。

两位C新增的最终关系检查已完成独立窄回归：Skills在冻结511源码上2根用例及20种损坏/遗漏反例通过，publicadapter4.424s；Teams三文件加Skills两文件的独立冻结快照中，4组Team SQL/文件关系、确认边界及原OwnedPayload邻近回归通过，execution4.629s。日志SHA分别为 `896cd545d9c2e29329fffd2ef5e5f5840213b87e378dfe2b0b280457a85c7222`、`37cb3e2eb00b5ea8fc1fb146a6d022ed8205cf1809ffda8531ec4251de9b0fae`。它们是由现有reader/原Skills校验复用的纯内容关系检查，不授权、不生成完整final proof；公共C真实caller、同原任务SQL正向和最终签名链仍待统一验证，不能据此开放readiness。

Linux诊断ELF已从51181049干净worktree实际构建并验ELF架构、构建前后3681文件来源及全部内部校验，交付归档46,870,961字节。用户Bash入口经真实归档提取与假诊断程序3种退出/清理路径验证，未执行ELF/SQL/Kubernetes。完整执行命令、两个交付摘要和清理规则见 `system-backup-supervisor-native-delivery-20261102.md`；现场镜像未更新，实际远测和页面验收仍未完成。

用户随后实际运行该包：归档校验OK，在`pod-ready-openssl-tls`阶段失败，native/SQL尚未启动；报告原退出1、资源清理0、residuals空、交付清理0。审核者未独立连接核查。原工具清理前没有保存Pod启动状态/事件，当前不能据此定位调度、拉取、init或MySQL进程原因。用户追加的只读现有MySQL镜像检查确认OpenSSL3.5.1及MySQL8.4.8/Linux x86_64存在，排除CLI缺失，但不能证明本次新Pod已启动。完整用户回传边界见`evidence/supervisor-kube-startup-user-report-20261102.json`。D正在补不需要bundle的独占startup-only探针，先解决启动可观测性，不降低TLS/镜像/权限/网络策略，也不在相同未知条件下重传大包盲跑。

新一轮公共C冻结快照（基线7f617ce7，叠加精确10文件）已统一编译并通过最终验证结构/拒绝边界、Teams关系、OwnedPayload以及local/native清理组件，execution2.203s；三个`TestPublicationFinalVerification*`根确实执行，未选择真实MySQL根。日志SHA256为`c341e5cd22439282a51a2f8b2c8a75c144b531a6f9a5768ab682c7b92b9d0275`。这仍不证明原SQL清理/最终远端验证正向链；其实现继续待真实同任务验收。A静态确认当前claim路径不复用旧DEK/旧30秒live lease，但原capture grant/RecordKeys/CaptureKeys及保留的staging HMAC key仍须有效，安装材料不能提前删除或轮换。

D补充的startup-only小探针已完成独立源码审核和冻结快照16项mock（0.395s），包括原失败码保留、清理前准确Pod UID状态/事件、显式双容器脱敏尾日志、诊断失败仍清理，以及不需要bundle/ELF。原始日志SHA256为`f700c044e36081accd79c5181ec59d4ddf1a316633df27436f39a7e80e34b17b`；Python交付SHA256为`2180d7ea96523df6c88c4a7731f94e6dc60835a1390c1ae5d457a6944d33a18c`，30621字节。测试临时树已删除；已给用户PowerShell上传和Bash启动专用命令，尚待现场结果。没有启动ELF、连接集群或更新镜像，不将mock结果认作TLS fixture/原窗口/页面验收成功。

用户随后回传startup-only实际失败：Pod调度及两个容器启动均成功，tls init退出0；MySQL8.4.8初始化InnoDB时`io_setup()`连续五次EAGAIN，报`Cannot initialize AIO sub-system`并退出1。报告诊断0、清理0、residuals空，仍未执行native。该证据限定了失败位置，但未采集主机AIO计数，不能断言具体哪个进程占满额度。准确UID、imageID及时间见`evidence/supervisor-kube-startup-aio-user-report-20261102.json`。D按MySQL官方启动替代方案，仅对隔离fixture设置`innodb_use_native_aio=OFF`并核对实际变量；不改主机或生产数据库，不将替代I/O配置下的结果作为生产等价性能验收。

AIO OFF修复在独立冻结快照17项mock全部通过（0.407s），日志SHA256为`a1597e7d4d058915b8942407b2c5ab5e0975519a443b5b9754640e1ff89293fd`。冻结Python摘要`fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873`，交付副本一致；mock临时树已删除。新现场运行尚待用户执行，不能提前声称已解决启动或原窗口失败。

公共C七个acceptance/signing日记文件和D两个实际forward调用点，连同之前十个local/final文件，按7f617ce7基线及18个精确dirty pins导出独立快照。五个新增acceptance/signing组件根、final/Teams/OwnedPayload/local/native邻近回归实际通过，execution6.197s，日志SHA256为`425babd3c03a68bc2e5b6c0b5849bd53d1021c9cf0c32f43505b01ac1fcc895d`。完整包测试源码均参与编译，未选任何MySQL根，无SQL正向/唯一provider RPC实证；不批准以此结果启用readiness或成功终态。该批测试结束后已确认无go/compile/link进程，删除本轮D盘源码快照、Go缓存/临时产物及workspace定位标记，只保留pins和非秘密日志。

原生下一阶段入口已单独准备：二进制/原归档保持51181049，外部AIO OFF fixture固定875e3960。新入口按独立摘要复制探针到自有work再运行，记录两个来源，输出清理前启动诊断；仍保留原失败码和准确路径/摘要的产物删除。Bash语法及5项本地真实归档提取/校验、fake runner控制流通过：0成功、7优先于summary9、仅summary9、仅归档清理失败1、错误fixture预检拒绝。未执行ELF/SQL/Kube，临时副本及解压树已删除；原native仍未执行，原归档仅供尚未完成的该阶段使用，完成后删除。新入口SHA256为`d88d94bc18cb92d3a7bc8e54bf63ca3e7cea937052c3baed4b86d26d0f635c8b`，日志`0aa3a03477c327eafe3da5b3a03fd94375d7afa0f3fd294c51dc99c127ebd208`。用户完整上传/执行命令与来源边界见更新后的`system-backup-supervisor-native-delivery-20261102.md`；需先取得修复startup-only成功结果。

静态审核发现D终态合同曾将final的history-only `recheckTx`作为Ready前置接点，已要求并收到D文档修正为`recheckVerifiedTx`，后者才核对完成stamp和完整成员关系；未新增空Ready或修改生产门禁。主审核冻结catalog独立producer范围和稳定注册ID/key，允许C实现五文件及原journal最小typed gate；完整同任务SQL、Ready及终态仍未验收。最终eligibility决定使用原任务独立immutable JCS evidence和一次SQL微秒UTC时间，绑定完整acceptance/catalog/成品/cleanup，而非其他checksum别名；artifact_bytes口径为原artifact transport本轮唯一固定版本外层持久对象物理bytes和，排除内层明文/重复入口/已删candidate及独立catalog对象。均须由后续真实producer实现，不用文档决定替代实际证据。

A进一步只读审查发现两个具体门禁缺口：C首次Stage前后A evidence计数增长只能拒绝当前AID的幂等Stage，不能分类跨workload同purpose或孤儿chunks；acceptance当前恢复检查仅锁fence并认证owner/evidence，遗漏独立持久化的Unwrap撤销。正常保留原C日记的ACK/RPC unknown路径未发现二签，但不能据此掩盖这两个缺陷。已协调A提供同原业务StageFirst、D提供registry只读ReadBindingTx，C负责共同current门禁与两签名调用；都仍须实际编译/SQL验证后再提交，不沿用旧组件结果声称修复完成。

D新增v2只读配置盘点工具已由根审核独立快照15项mock通过（0.030s），日志SHA256 `c32c66994a16cd5eb39959eb391b5b87af06132404dd8d88978e88ef13837e3e`，临时树已删除。固定用户给出的namespace UID，按真实Deployment/RS/Pod/container身份复核；只返回v2配置/KEK候选元数据，缺表缺列正常报告，不导出正文/凭据或写入任何资源。源码/测试摘要及界限见`evidence/supervisor-v2-config-observe-review-20261102.json`，完整上传和Bash命令见`system-backup-d-v2-config-observe-20261102.md`。旧legacy盘点不能替代这组v2观察；当前尚无用户现场报告证明active canonical config存在，更不能由计数推定PreparedCoverage或配置已认证。

两项安全API已完成本轮独立实测。A冻结4文件的StageFirst五根测试全部通过，security5.445s；其中真实SAN/TLS1.3、独立UUID的MySQL根执行1.14s、10子例，覆盖跨workload/不健康/过期/根缺失chunk拒绝、合法其他purpose、并发原task锁、rollback和旧Stage幂等性。D冻结4文件全registry包3.086s通过，含真实ReadOnlyTx与原Revoke的1.36s根、缺/坏当前binding的0.37s根；共享fence争用返回1205、精确行NOWAIT返回3572，释放后原Revoke提交及新的只读事务观察到Unwrap撤销。根分别独立读回server UUID及业务schema剩余0。这里使用本轮root fixture账号，不是现场SELECT-only账号、全部授权或physical恢复证明。

A4/D4/C24共32个精确dirty pins在74ea1c94基线独立快照统一编译，C五个新catalog组件、两个current KEK组件及相邻回归共33根全部通过（execution4.405s），无SKIP；tag为systembackup_mysql的同任务测试源码参与编译但未执行。不能据此认定C SQL删除/final/acceptance/catalog同任务正向或全部ACK故障已过。A/D/C日志摘要、全32pins和准确范围见`evidence/supervisor-signing-safety-review-20261102.json`。整个批次结束后，原SQL确认无业务schema，精确核对本轮PID/路径/启动时间/UUID后正常shutdown并删除D盘MySQL/秘密/证书/数据/下载包/源码快照/Go缓存/tmp，workspace定位和setup/cleanup脚本亦删除，仅留非秘密证据。C继续只实现内部decision三文件，未授予空Ready/成功CAS或readiness开放。
