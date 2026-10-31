# A 安全调用链交接（2026-10-31）

本轮基线 `backup@8578b0bf`；唯一目录 `ClawManager-A`，分支 `codex/a-security-round23`。
不连接 SSH、生产 Kubernetes、在线 KMS，不部署。进度估计不作为验收。

## 首个纵向切片：原安装签名材料到三用途 provider 调用

新增独立文件 `backend/internal/systembackupsecurity/installation_signing.go`，未修改共享 main/controller 构造或迁移。

D 构造 ABI：

```go
NewInstallationArtifactSigners(ctx, reader, pin, mounts, task, owners)
// reader: OriginalSigningRecordReader；已有 FileSigningRecordReader 实现
// pin: InstallationSigningPin（独立固定 installation/revision/raw SHA256/issuer 公钥）
// mounts: []SigningJWTMount（三项独立 JWT 文件、CA 和精确绑定）
// task: ArtifactSigningTask（原 BackupPublicID/AttemptNo/OperationID/Workload）
// owners: ArtifactSigningAuthorities{Capture, Acceptance, Catalog}
// 返回对象：Signer(purpose) (ProofSigner,error)、History(ctx)、Close()
```

`ArtifactSigningAuthority.AuthorizeArtifactSigning` 收到包含原任务身份和精确 TransitSigningRequest 的请求，返回 `AuthorizedArtifactSigningUse{Task,Use}`；Use 沿用 `OriginalSigningUse` 的当前 owner Recheck。错 task/attempt/operation/workload/digest 立即拒绝。D 必须用实际冻结采集/验收/目录 owner 实现，不能放行回调或从 HTTP/config 自证。

原安装 owner 在独立环境签 `InstallationSigningDomain + raw JSON`（Ed25519）；record 文件是 `InstallationSigningRecord` 的原始 JSON，signature 文件为原始 64 字节。包含完整三用途历史公钥、当前 provider binding、AuthMount/Role/Policy/CA hash、独立 revision 和期限。构造和每次调用/返回/历史公钥导出均重新读回验签并核对独立 pin。材料变化或撤销令已有 signer 拒绝，必须用新受信任 pin 重建；旧材料不能以另一签名版本替换。没有任何签发默认值、原私钥或 token 常驻。

另有 `NewPinnedInstallationArtifactSigners` 和 `PinnedArtifactSigningAuthority`，消费原 owner 签过的精确 task/attempt/operation/workload/digest 记录，完整本地文件→原授权验签→JWT→三个 Transit sign 路由已通过。该接口是**受控原记录导入适配**；后两用途输入在执行后才产生，不应要求每个页面任务预挂三份人工文件，不能据此声称自动业务 caller 完成。下一切片须从原公共任务/producer 冻结记录自动授权。未调用 D 生产入口。

真实 TLS 串联发现并修复既有 `OriginalSigningResolver` bug：它将登录后 token.NotBefore 和登录前时间比较，导致实际 JWT 新 token 永远被拒绝。现在登录后重新取时并拒绝时钟回退；新增无网络定向回归和完整 TLS 往返。`SigningToken` 格式化/JSON 防泄密补齐。

`LoadInstallationSigningHistory` 独立验签/核对当前部署 pin，不要求当前签名权限有效或 provider 在线；旧过期 key、撤销标记完整保留。owner use 撤权不删除公钥，材料被替换则旧 pin 拒绝；新受信任 pin 可读取明确撤销历史。

## 同步、测试与待办

- 已 fetch 并检查 D 的 `5b8b4bfb`（3个文件，Runtime legacy mutation fence），快进 merge；保留双方代码。
- Go 1.26.1 共享缓存就绪，未禁用 go.sum/sumdb。沙箱内既有 JWT/Transit 与新 TLS 测试均不能访问 loopback；沙箱外仅连接本地测试服务通过。
- `go test -mod=readonly -p=1 -count=1 -timeout=180s ./internal/systembackupsecurity -run 'Test(Installation|PinnedInstallationArtifact|PinnedArtifactSigning|SigningTokenCannot|OriginalSigningResolver|SigningJWT|CredentialTransit)'` 退出0，2.188s。
- `go test -mod=readonly -p=1 -count=1 -timeout=180s ./internal/systembackupsecurity` 退出0，19.273s（默认 vet）。覆盖三用途真实 TLS、缺材料/错用途/两种错版本/错安装/错 issuer/未来/过期/撤销/跨任务/attempt/operation/workload/digest/材料更换和历史保留。
- 首切片即将提交；SHA 由提交后的追加交接记录。
- 下一项核对四分区 KEK coverage 原来源/历史扫描，以及用途 capability 的真实 reader/caller；不靠空 registry 自证完整。

## 第二切片：自动原公共任务 SQL owner

A1 已提交并推自己的分支：`5b57f1f56ec9d7b3cf19343026d03d50332db710`。其后检查并 merge D2 `209fbd1c`。没有改 D 主文件、没有新迁移。

新增 `NewSQLInstallationArtifactSigners(ctx, db, installationReader, installationPin, mounts, originalTask, SQLSigningClaim)`，返回对象沿用 `Signer/History/Close`，增加 `StageSigningInput(ctx, originalTx, purpose, exactJWSInput)`。

- 自动 owner 是真实 `database/sql` reader/caller，读取 `system_backup_v2_backups` 原 request_id/claim/row_version/config/六项请求/期限，原最新 `attempts`，取消操作，`runtime_captures` 的 collectors stopped/source resumed 原 epoch，`execution_records.capture_result`，以及现有 `evidence` 中原冻结签名输入。
- 业务调用点：C/D 的原采集/验收/目录 owner 通过完整业务校验后，在**其原事务**中调用 StageSigningInput，再提交；随后用对应 Signer 对同一字节签名。该方法只冻结当前用途精确 JWS，不提交、不建任务、不从 provider ACL 或当前 config 自证。已有 evidence 是写入一次、冲突拒绝，后续校验不改 bytes 或期限。真实值必须来自 owner 已验证结果，不能直接使用 HTTP digest。
- 独立原安装签名 record 的 `Permissions[].SQLOwner` 是明确的 workload/数据库/控制器/config 签名 capability（不是普通 capture ExecutionGrant）。缺此原授权拒绝。它是部署/workload 级材料，不包含每个 task 的未来输入，页面新任务无需逐任务离线签发。
- 当前仅处理正式 acceptance 的同一六项公共任务；签名前后重新读取原事实和冻结 evidence。缺 capture_result、源未恢复、claim更换、跨任务/attempt/安装、取消、过期、材料撤销均拒绝。JWS framing、任务和用途/两种版本精确核对。
- 使用现有 evidence inline/internal/diagnostic 存储公开签名字节；精确 JWS 上限4096字节，编码后须<=8192字节。未支持更大签名输入，不能静默截断或改签名内容。没有秘密写入此记录。
- SQL 协议模型测试已验证生产 SQL/原事务、三用途 TLS/独立验签和拒绝路径；不作为真实 MySQL 锁/grants 或现场运行证明。security 整包回归20.585s退出0；后续补严冻结epoch/证据严格解码/插入行数/原事务最终事实复查后，非网络定向负例1.876s退出0，最终 `go test -mod=readonly -p=1 -count=1 -timeout=180s ./internal/systembackupsecurity`（默认vet）19.023s退出0。D 真正调用点尚需接入。

原 frozen payload 的业务完整性由 C owner 的实际采集/验收/目录校验承担；A 的 Stage 验证的是原授权/精确任务/用途/字节和原 source provenance，不代替业务校验报告或全系统验收。

原 request_id 作为 `ArtifactSigningTask.OperationID`；`SQLSigningClaim` 必须是对应阶段**仍持有的当前正式owner claim**，不能沿用 FinishCapture 释放的 capture claim。主入口安排正式 publisher 领取同一 root task 后构造后两用途。

A2 提交 `4490fc162706194ed246836dad2510f87ca7313d`，重试后已成功push自己的分支。未push backup。

真实 MySQL 定向入口准备：计划使用 tag `systembackup_mysql`、测试 `TestSQLSigningOwnerMySQL`；仅允许本机TCP隔离服务，DSN从私有文件读，不进入stdout/Git。需原服务器UUID独立pin。最小表为 `system_backup_v2_backups/attempts/operations/runtime_captures/execution_records/evidence`，用生产字段和真实事务/唯一证据ID验证；fixture建库用独立本地root，签名reader用独立SELECT+INSERT-evidence用户，证明不能UPDATE源task。此定向fixture不声称全171迁移、全部FK或现场SQL profile验证。

该 MySQL gate 代码已落地，tag编译通过（`-run '^$'`，2.308s）。发现既有三个 tagged fixture 测试经 controller 导回 security 导致编译环，已改为直接引用同一 `migrationcatalog.ReviewedHash/ReviewedFileCount`，没有修改catalog值或迁移。输入环境变量 `A_SIGNING_MYSQL_CREDENTIALS_FILE`（监督者本机JSON私有文件，替代DSN文件）与 `A_SIGNING_MYSQL_SERVER_UUID`（监督者独立取得的本机服务UUID）。测试自建随机 `ad_a_signing_*` 数据库和SELECT/INSERT用户，结束按UUID/marker严格核对后清理本次库/用户。

## 第三切片：真实隔离 MySQL 验证

提交并推自己的分支：`25fd3cb15e8e73fb4a14688f40b1835cd98f980d`；监督已独立复测并集成。

- 监督者本机 MySQL 8.4.13，loopback端口59355，固定server_uuid `b9c4d686-d4d3-11f1-9eb5-745d22085e06`，未访问远侧。
- `go test -mod=readonly -p=1 -count=1 -tags=systembackup_mysql -timeout=180s ./internal/systembackupsecurity -run '^TestSQLSigningOwnerMySQL$' -v` 退出0；测试3.60s，进程包6.117s。
- 增补真实CHECK损坏拒绝并带三个历史seed回归后，最终 `-run '^Test(SQLSigningOwnerMySQL|(AConfigProof|DConfigWriter|DConfigMaintenanceReceipt)MySQLSeed)$'` 退出0，MySQL测试1.38s，包3.866s。旧tagged seed的候选SQL摘要仍指表名适配前内容，现按仓库中原fixture的**完整LF字节**重新固定两个测试pin，并显式LF归一化；不改fixture SQL、迁移或生产信任pin。错摘要/错字节/重复字段/未知字段负例继续拒绝。
- 三用途自动SQL→JWT→TLS Transit→历史公钥独立验签实际成功。源记录来自原backup/attempt/source journal/capture_result；Stage原事务回滚后不可签，提交后可签，原字节重复freeze幂等。
- 独立SQL签名用户只有六表SELECT及evidence INSERT，实际UPDATE源task和DELETE evidence均被MySQL拒绝；原owner推进claim版本后旧signer在登录前拒绝。
- 按本轮随机数据库/用户名、原服务器UUID与fixture marker核对后清理本次资源；未修改其他schema、系统库或停止共享服务器。该测试的最小DDL验证真实事务/CHECK/grants，不声称整套应用迁移/FK或正式六域业务采集通过。

## 第四切片：真实 SQL 原 KEK provider capability reader

提交并推分支：`3ce1bc04c12434f6e5b921ae7786371885d985d3`，监督已独立复测/集成。

新增 `systembackupkekadapter.NewSQLProviderCapabilityPreparation` 和 `NewSQLInstallationPreparation`。后者直接组合既有 `SQLOriginalReader`、独立安装issuer与两用途签名capability evidence，再供 D `WireServices` 消费；两服务与具体capability reader必须同一DB指针。没有新增表、迁移或默认能力。

capability来源复用 `system_backup_v2_evidence` 的 `owner_target_type=system`、当前installation、`capability_snapshot/inline/healthy/none`。每用途固定独立 SourceRecord/issuer，原permission owner签 `ProviderCapabilityDomain + raw record`；完整绑定、typed ref、generate/decrypt精确路径、provider数字version、原AuthMount/Role/Policy及其hash/JWT trust hash必须一致。配置、review脚本或provider写成功不能生成这个原授权证据；本实现没有签发/回填接口。

prepare在SQL锁外短事务读取；原config/bootstrap事务内使用同一read view与当前FOR SHARE重读，核对原证据字节/期限/原数据库、用途及撤销。签名capability只是准入事实，不能授予Job Generate或controller verifier Unwrap，也不是恢复授权。

验证：

- `go test -mod=readonly -p=1 -count=1 -timeout=180s ./internal/systembackupkekadapter ./internal/systembackupkekadmission ./internal/systembackupkekregistry` 退出0，1.138s/0.979s/0.795s；包含错用途/typed ref/两种版本/错issuer/未来/过期/撤销/换原证据/期限续期/数据库越界/绑定材料副本。
- 真实本机 MySQL：`-tags=systembackup_mysql -run '^TestSQLOriginalKEKCapabilityMySQL$' -v ./internal/systembackupkekadapter` 退出0，case0.38s/pkg1.620s。精确执行仓库127/128迁移；既有原authority writer导入、SQL reader验签、两用途准备及原KEK fence事务内复查、只读user禁止UPDATE/DELETE、原generate撤销与不可复活、历史2版本保留均真实执行。capability metadata evidence表为本轮最小SQLfixture，不冒充完整现库。
- 同一真实事务的 `Bound.CompleteScan` 仍拒绝：全新空registry不能自证历史覆盖。没有为测试放开此门禁。

剩余代码/来源边界：四分区 `retained_artifacts / inflight_and_unknown_writes / holds_and_catalog / restore_and_prune` 的 C 原scanner/adoption/backfill和旧writer/GC mutation hooks在当前仓库仍未提供生产实现，只有DTO/parser/持久化协议；A没有将4行coverage或空References变成完整来源。需原C/业务owner交付其真实来源/分页EOF/旧历史回填及共享fence参与，再接 `PreparedCoverage`。这不是可由现场填一个布尔值解决的事项，也不能据本切片宣布KEK全覆盖。

下一实际消费者为controller独立候选验证Unwrap，必须绑定真实controller workload、原task/attempt/part/config/candidate；A继续补专用resolver/构造，不复用capture Generate或隔离恢复权限。

## 第五切片：controller真实执行身份独立Unwrap（本地验证完成，待D生产装配）

实际代码在独立 `systembackupkekadapter/controller_verifier.go`，只依赖 controller/dispatch/publicadapter/worker/SQL/K8s DTO，**不反导入systembackupexecution**。

D消费ABI：

```go
factory, err := systembackupkekadapter.NewControllerVerifierFactory(ControllerVerifierConfig{
    Capabilities: originalSQLCapabilityPreparation, Binding: admittedBinding,
    CAPEM: originalCA, JWTFile: controllerProjectedJWTFile,
    Workload: ControllerVerifierWorkload{
        Namespace: ..., PodName: ..., PodUID: ..., ServiceAccountName: ...,
        ServiceAccountUID: ..., OwnerKind: ..., OwnerUID: ..., GrantSHA256: ...,
        ControllerOwner: ..., ConfigVersion: ..., ConfigSHA256: ...,
    },
    Kubernetes: actualClient, Authority: owner.Gate.Authority, Records: owner.Gate.Records,
    CaptureGrantSHA256: owner.Identity.GrantSHA256(),
    InstallationIssuer: independentOriginalInstallationPublicKey,
    GrantMount: ControllerVerifierGrantMount{File: independentVerifierGrantFile,
        SHA256: independentVerifierGrantEnvelopeHash, Issuer: originalVerifierOwnerPublicKey},
})
// 在原scope恢复原in（D owner.input 已认证），把D3原candidate record完整JSON的SHA256传入。
unwrapper, err := factory.ForCandidate(ctx, ControllerVerifierCandidate{
    Input: originalInput, Job: originalCaptureJob, Invocation: originalInvocation,
    CandidateSHA256: originalSQLCandidateHash, CaptureGrantSHA256: originalCaptureGrantHash,
})
// unwrapper实现wire.Unwrapper，另有Recheck(ctx)/Close()/ValidUntil()。
// D适配FormalCandidateKeyUse.ValidUntil，并在open成功后以该deadline
// context.WithDeadline包住源读取、AEAD校验、私有custody复制和saveResult/Gate。
```

Workload前8个身份字段对齐D的FormalVerifierIdentity。**GrantSHA256是独立verifier业务grant完整签名envelope的独立部署pin，必须不同于capture/record-key grant**。原 `Authority.Authorization` 保持实际 `deploymentAuthorization{Service:s}` wrapper；Records.Keys继续使用原s.Forward。工厂明确拒绝把裸PinnedExecutionIdentity当task authorization、错误recordKeys或复用capture grant。独立 `ControllerVerifierGrant` 是原verification业务owner按真实workload/installation/数据库账号/config/capture-grant引用签发的部署级授权，不含每任务未来input；文件+hash+issuer独立固定、期限/撤销每次复查，不能由provider ACL snapshot自证。

支持真实Deployment（Pod→RS→Deployment）、StatefulSet或Job owner链，原captureJob UID仅定位candidate，绝不冒充controller身份。signed Unwrap capability中的 `Permission.ControllerVerifier` 只是该provider role授权给真实workload的观察绑定；它与独立业务grant及当前原task授权三者缺一不可。专用集成测试为 A 唯一文件 `backend/internal/systembackupexecution/a_controller_verifier_integration_test.go`，直接复用实际 `DeploymentService.captureGate(db)` 的deploymentAuthorization/Forward recordKeys，未修改D主文件。

ForCandidate将重读原加密plan及完整invocation/Job spec身份，对照runtime_resources原candidate_sha256，当前SQLExecutionAuthority绑定原task/attempt/config/fence/claim；随后取得原KEK fence并检查保留mapping与Unwrap用途未撤销。只读取Unwrap capability，不要求Generate。原provider登录使用controller自己的JWT，校验batch/nonrenewable/1..20s/单一原policy与真实Pod/SA metadata。

Provider RPC在原SQL锁之外；实际DEK消费在同一原task/KEK-fence事务保护内执行只读流校验/私有本地custody写入，前后重查原authority和provider evidence，完成后rollback释放只读事实锁，再检查实际K8s身份。callback失败不提交custody。回调中的Recheck复用当前原事务，避免新连接递归自锁；对象按Unwrap串行。此路径不提供Generate、独立恢复或裸DEK返回。

`v.until`精确取独立原grant.Until、capability/evidence期限、task deadline和原authority guard的最小值；Config、返回Grant.ExpiresAt、login credentialUntil、解封RPC和WithUse均受它约束。login不接受超出该时间窗的provider TTL。`ValidUntil()`把同一期限暴露给D，wire回调没有context参数，D必须用此deadline派生完整流的context，不能只靠回调后的报错。

验证（Go1.26.1，GOPROXY=off）：

- 五包真实回归 `go test -mod=readonly -p=1 -count=1 -timeout=240s ./internal/systembackupkekadapter ./internal/systembackupexecution ./internal/systembackupkms ./internal/systembackupkekregistry ./internal/systembackupkekadmission` 退出0，3.033s/8.099s/3.755s/0.762s/1.073s。环境启用本机MySQL，execution确实运行A专用集成，没有skip该用例。
- 专用SQL+TLS测试：原forward/independent grant分离、实际原SQL加密plan重读、真实SQL authority/KEK锁、独立controller JWT→TLS Transit解封→callback原DEK一次、派生context在原事务内Recheck均通过；没有Generate evidence也可Unwrap。裸Forward绕过原wrapper、复用capture grant、关闭原部署、替换原candidate、跨attempt、cancel均在provider登录前拒绝。
- 独立grant有效期比task/capability早，正常用例断言ValidUntil相等；另以3.5s独立grant和1sprovider credential实际解封，候选流context在DEK回调**内部**到期取消，Recheck当场拒绝、Unwrap失败；之后重试不再login。没有将credential期限错误充当整个流期限。
- 原grant单测覆盖独立issuer/已撤销/过期/未来/过长/安装/数据库server/账号/Pod/SA/owner/controller/config/capture来源/hash循环、重复/未知JSON成员、挂载字节替换等拒绝。

本机数据库是随机 `ad_a_controller_*`，独立UUID+fixture marker校验后清理；最小原业务DDL和精确127/128迁移，不冒充完整现库。K8s身份链使用client-go fake，TLS provider和签发材料为本地fixture，未运行实际集群/现场KMS/正式六域任务。D仍需在实际observer的FormalKeys闭包及部署配置中作上述适配，且保留独立identity/hash拒绝守卫；不应再要求controller提供不存在的JobUID。

已同步监督D4.1 `b399efc7`，其原 `captureGate` 可直接供本工厂使用。后续A代码责任继续四分区scanner/adoption/backfill及旧writer/GC fence参与；不能将缺失实现改记为现场事实。

### A5.1 原installation owner用途撤销补丁

监督复审指出 `InstallationAuthorityWriter.Put` 只写原authority/history并推进共享fence，不改registry purpose revocation列；A5若只查registry，重试读取新epoch后可能遗漏原Unwrap撤销。修复不依赖registry同步：`ControllerVerifierConfig.InstallationIssuer`新增独立原安装owner公钥pin，ForCandidate预读原SQL记录并验签，原SQL/KEK-fence事务内每次`session.check`重读当前signed_record/signature、严格解码并验证完整原binding、原NotBefore/Until及**仅UnwrapRevoked**。原record.Until也纳入整个ValidUntil，缩短窗口将拒绝旧对象，绝不续期。

只撤销Generate不阻断历史Unwrap，因此没有复用“必须两用途都有效”的admission authenticate函数。原安装writer的fence/authority锁顺序保持一致，DEK使用中该原事实受同一事务锁保护；失效后旧verifier、新ForCandidate都在登录前拒绝。新增独立原issuer替换反例。

真实MySQL测试直接调用现有 `NewInstallationAuthorityWriter.Put` 导入原签名record，再保持registry的unwrap_revocation_json为空；覆盖初始正常解封→仅UnwrapRevoked后旧/新对象均拒绝，以及另一随机schema内仅GenerateRevoked仍可解封→再UnwrapRevoked拒绝。不是手工改registry列或fake epoch。A5 commit `40ba9d81`配合本补丁交付，不改写已推送历史。

### A5.2 实际kube.Intent摘要对照修复

独立提交/推送 `98ccb4d3`。监督真实D consumer证明原plan typed Job SpecSHA与Runner规范化后的runtime RequestSHA不等。公共 `loadOriginalCandidatePlan` 继续校验原SpecJSON完整SHA，并解typed batchv1.Job调用**同一** `kube.Intent("Job",...)`（补apiVersion/kind、删status、unstructured重编码），只以所得RequestSHA对照runtime_resources.request_sha256。没有放松比较，也没有只改D fixture。A SQL正例改存真实RequestSHA/RequestJSON，断言两SHA不同，旧/新verifier均拒绝把SpecSHA替换进runtime；两场实际原SQL+TLS测试PASS，pkg8.844秒。公共workload/plan认证仅抽取复用，保留原签名/当前授权/身份守卫，供后续issuer共享。

## 第六切片：原SQL四分区来源census与原事务冻结（首个实际scanner切片）

新增 `systembackupkekadapter.NewSQLCoverageCensus(db, databasePin, installation)`，不是对candidate/registry的DTO转换。直接遍历当前172迁移中49张原业务/历史来源表，包括079旧任务/manifest/attempt/send/staging/restore和v2原backup/计划/加密record/evidence/unknown actions/runtime/hold/promotion/lease/import/drill/prune/tombstone，整个数据库保守扫描而非按terminal/deleted/TTL排除。扫描之前枚举所有backup命名空间表，未审查新表或缺失必需表直接失败；派生KEK索引、认证与无引用协调表的排除列表固定在代码，不接收请求提供的表名/布尔值。

每表按真实PRIMARY KEY排序，完整读到cursor EOF并检查Rows.Err/多结果/Close；记录schema摘要、区分NULL/空值及列边界的逐行SHA、真实行数/字节数。每表百万行/单行16MiB/总512MiB是拒绝阈值，超限从不当作分页完成。只返回摘要和计数，不返回原config、manifest、加密payload字节。

消费流程：`observed := scanner.Observe(ctx)` → 原owner在事务起点改用 `original := scanner.BeginOriginalTransaction(ctx)`，以 `original.Tx()` 持续取得原业务授权/maintenance/domain锁 → `locked := scanner.LockOriginalSources(ctx, original, observed)` → 再取得原KEK fence并做原adoption/backfill → `locked.Recheck(ctx, original.Tx())` → 原owner自行Commit/Rollback。冻结对全部原表全范围FOR SHARE，包含空区间，阻止未升级旧SQL writer趁adoption插入。原对象只接受构造器创建的同一RR事务能力；不能传外来 `*sql.Tx` 伪装，且没有另开事务/二次提交。原事务内自己的后续来源改动也会被重查拒绝。

监督及A识别 `@@transaction_isolation` 仅是session默认，不能证明外来tx当前隔离级别；已删除该判定，改为上述私有构造能力。真实SQL反例展示外来RC tx的@@仍报告RR但被拒绝。另一测试先确认原config_versions表确实0行，以test-root的 `performance_schema.data_lock_waits/data_locks/threads` 检查**精确schema/table/old-writer connection/blocker connection、WAITING INSERT_INTENTION、GRANTED supremum pseudo-record**；观察到真实等待后才释放census事务，要求**同一条**旧writer INSERT成功，随后rollback该writer。观察系统表只用于测试root，不增加生产账号权限。不以任意超时/SQL/driver错误冒充gap-lock证明。

验证：真实MySQL `-tags=systembackup_mysql -run '^TestSQLCoverageCensusOriginalSourcesMySQL$'` 最新增强版退出0，pkg17.850s；此前同生产代码完整tagged adapter suite退出0，21.115s。在随机 `ad_a_census_*` 空库运行**全部172个** `db.ApplyPinnedMigrations`（catalog `718e4509d2c83c73636dd9745ac7c2b350a57c01d75b5ac50e482ffcb4f537d8`），再实际运行原表枚举/EOF/重复稳定性/防别名、旧config表新增使旧准备失效、同原事务冻结/复查/跨事务拒绝、空来源旧writer精确等待/释放后成功、owner自身改动拒绝、rollback释锁、未知表拒绝、跨库拒绝和RC伪装反例。独立server UUID+fixture marker检查后删除本次随机schema，不修改监督/D测试库。

明确尚未完成：这个对象**刻意不实现PreparedCoverage**，不会把SQL census直接升级为四分区完整性，更没有放开Bound.CompleteScan。外部immutable artifact/catalog全分页EOF、真实expected-request/envelope历史回填、未知provider调用处置、原source adoption签名与持续writer/GC共享fence hook仍待实际代码接入；不能用本地census、四行receipt或手填完成布尔值替代。此切片提供原SQL完整读取/锁定/重查的真实基础，后续将连接上述原owner记录和producer入口，保持完整KEK覆盖门禁关闭直到都满足。

## A7进行中：解除未来permit摘要循环（优先实际producer接线）

监督确认原FormalCaptureMaterials.Permit.PermitSHA256→materials hash→Invocation.Hash→permit.Identity.InvocationSHA256→PermitSHA256有摘要循环，且真实Job/Pod UID创建后才知。静态future permit文件不能作为自动页面路径。

A/D消费ABI草稿（代码正在实现，尚未宣称接线完成）：

```go
// 冻结materials只含这个原Generate-owner部署pin，没有未来permit digest/JobUID/PodUID。
pin := systembackupkms.PermitDeliveryPin{
    Version: systembackupkms.PermitDeliveryVersion,
    Issuer: independentGeneratePermitSigningPublicKey,
    IssuerGrantSHA256: independentGenerateOwnerDelegationEnvelopeSHA256,
}
// 原mTLS/TokenReview/SQL key-reserve完成后，D lease返回同一原事务已持久化的原字节。
delivery := systembackupkms.DeliveredProviderPermit{Payload: originalPayload, Signature: originalSignature}
// OriginalPermitJobAuthority额外PermitNonce()来自原KeyUseLease.Nonce。
// worker.OriginalKeyAuthority已实现该方法，绝不由delivery字段反向选择nonce。
job, err := systembackupkms.NewDeliveredCaptureJob(ctx, admittedKMSConfig, pin, delivery, original, frozenRequest)
```

`DeliveredPermitPayload`签名域为 `system-backup-original-generate-permit-delivery.v1\x00`，内含schema_version、issuer_grant_sha256、原nonce、完整KeyRequest和原ProviderPermit。原ProviderPermit.Identity继续严格绑定真实namespace/JobUID/PodUID/SAUID/完整InvocationSHA/capture grant；只允许Generate+JWT，不接受静态凭证/Unwrap/其他source、旧v1裸payload签名。kms consumer每次Resolve及DEK使用前后均复验独立signature/grant pin/完整request/nonce，随后复用全部既有issuer/identity/context/provider/期限检查，无动态失败fallback。

**A7.0 consumer ABI已实现并验证，先独立提交供D消费**：`systembackupkms/delivered_permit.go`、原Job resolver共用校验及NewDeliveredCaptureJob、worker.OriginalKeyAuthority.PermitNonce。KMS整包PASS3.786秒，worker整包PASS34.727秒。真实loopback TLS正例验证exact完整context/version/bits、原JWT→batch单policy生成、原DEK回调及原单次调用守卫；20类拒绝覆盖wrong grant/nonce/request/invocation/Job/Pod/SA/capture grant、Unwrap、静态凭证、未来/过期/越原权限、旧签名域、重复/未知JSON、issuer替换、构造后nonce变化/原授权撤销。DTO byte修改不改变已构造resolver。此阶段original authority为明确unit double，原producer SQL/K8s/签发授权测试仍在开发，未声称生产闭环。

生产producer由 `ProviderPermitIssuer` 持独立原Generate-owner部署级签名delegation（签发专用公钥+真实controller workload/SQL账号/备份业务config/完整binding/精确Generate role-policy-JWT trust/worker namespace-SA/期限撤销），准备时核对原加密plan/真实Job和Pod；`Prepare`在SQL锁外完成，`Stage(ctx, originalTx, originalKeyUseLease, req.Action)`在原owner所有业务锁之后、Commit之前写原public signed permit evidence、planned/unknown引用并取得原KEK fence。签发使用专用被授权Ed25519签发key；不调用artifact三用途signer、worker身份CA或ACL观察签发业务grant。`ReadCommitted(ctx)`只回读已提交原字节，不为ACK不明重签/续期。D负责原ControlClient/lease/CLI/部署消费；A提供具体原owner签发权限和current Generate来源，不要求每任务手工材料。

无环构造修正：**ProviderPermitIssuerGrant不包含Forward/CaptureGrantSHA，也不包含父DeploymentConfig/ProfileSHA**。其Workload.ConfigSHA只绑定既有备份业务配置（该schema不包含issuer delegation/未来permit）。可以先生成独立delegation→materials只pin独立公钥/delegationSHA→Invocation/Profile/DeploymentConfig→Forward grant→真实Job/Pod绑定→动态permit。`ProviderPermitIssuerConfig.CaptureGrantSHA256`仅在运行期绑定实际原recordKeys/SQL执行grant，不写回独立delegation。每份动态payload仍严格包含经原授权验证的Identity.ExecutionGrantSHA256，拒绝跨grant替换。D的外部启动材料包也不能把依赖Forward的派生摘要嵌回父config/profile/materials。

**A7.1 producer实际消费ABI**（待本轮提交；D接入同一原控制事务）：

```go
issuer, err := systembackupkekadapter.NewProviderPermitIssuer(ProviderPermitIssuerConfig{
    Capabilities: actualSQLPurposePreparation, Binding: admittedBinding,
    InstallationIssuer: independentInstallationOwnerPublicKey,
    Authority: owner.Gate.Authority, Records: owner.Gate.Records,
    Kubernetes: owner.Client, Workload: actualControllerWorkload,
    CaptureGrantSHA256: owner.Identity.GrantSHA256(),
    GrantMount: ProviderPermitIssuerGrantMount{File: independentDelegationFile,
        SHA256: independentDelegationEnvelopeSHA, Issuer: originalGenerateBusinessOwnerPublicKey},
    SigningKeyFile: dedicatedDelegatedRawEd25519PrivateKeyFile,
})
// 原mTLS/TokenReview/frozen plan/process检查后、开原tx之前；身份全部来自原链。
prepared, err := issuer.Prepare(ctx, ProviderPermitIssueScope{
    Input: originalInput, Job: originalJob, Invocation: originalInvocation,
    WorkerIdentity: actualOriginalWorkerIdentity, WorkerPodName: actualBoundPodName,
})
// D应把prepared.ValidUntil()再min到原until；精确DATETIME(6)微秒窗，不续期。
// 原tx内keyUseTx/候选/容量/观察等业务锁完成后、原Commit之前：
err = prepared.Stage(ctx, originalTx, originalKeyUseLease, req.Action)
// 原owner自行Commit；结果不明只执行原记录readback，不重签。
delivery, err := prepared.ReadCommitted(ctx)
```

需接 `key-reserve/key-check/key-begin/key-end/candidate` 所有原动作。只有reserve首次创建permit；using/finished没有原record则拒绝，不追补。deterministic `sev_apermit_*` evidence保存独立domain签名payload的原始字节；重复读取比较signature/context/full identity/nonce/期限，签名key不在时仍可回读同一现有permit，不能重签/续期。当前SQL原guard、signed installation Generate撤销、独立issuer delegation文件与provider Generate capability在同一原fence事务反复检查；实际profile的容量报告存在时沿用原RegistrationCapacity事务额度。原purpose证据只作观察，不能颁业务授权。

planned/unknown保持保守：reserve原事务持久化planned。**kms Transit的Generate RPC发生在WithUse/key-begin之前**，所以从constructor/Resolve/preRPC第一次原 `key-check` 开始即同事务标unknown，早于JWT/provider I/O；不能只挂key-begin。key-begin/end/candidate均保留unknown；status/TTL/撤销/ACK不明不释放。每次状态写入推进同一fence，之后在同一原tx刷新其派生snapshot继续复查，未创建第二提交边界。没有实现release/retire/CompleteScan成功分支。

本地A7.1集成验证已跑通：四包整回归adapter3.155s/execution13.273s/registry0.612s/kms3.819s，全部退出0。同步D5.3 `3c4e8c1d` 后execution再PASS12.338s。真实原DeploymentService.captureGate/deploymentAuthorization、原加密plan、**实际keyUseTx**、独立Generate owner授权/专用签发key、原事务Stage/Commit/ReadCommitted、worker NewDeliveredCaptureJob、原JWT→TLS Transit Generate→原回调，原guard全程复查。实际写入表使用仓库123 runtime_resources CREATE段＋125 key_use＋131 candidate DDL及真实FK/CHECK；evidence也使用096原CREATE段。周边控制表保留明确focused fixture，不冒充完整现库。real runtime父表保留匹配的PK/ASCII/enums用于真实FK。

真实provider handler在收到**首个**Generate请求时另连接查SQL，断言unknown已提交；另一用例在JWT login响应前由原InstallationAuthorityWriter导入GenerateRevoked，后续Generate调用数严格0、无DEK、unknown仍保留。actualStage成功后rollback不会返回permit/索引，提交后planned；ACK重放在专用privatekey被换成无效字节时仍返回原signature/payload一字不变；原envelope最多一次Generate，key-end后unknown不释放；当前原Generate撤销禁止新的Prepare和旧记录ReadCommitted。K8s使用fake API，测试桥接原keyUseTx而非真实mTLS/TokenReview；D生产handler/启动材料/lease/CLI调用仍须落地。独立授权单测覆盖过期/未来/过长/其他安装映射/DB/账号/workload/controller/SA/JWT路径/issuer替换、错误签名用途与私钥规范性，delegation不包含Forward/Profile/DeploymentConfig摘要。

CompleteScan持续关闭直到外部EOF/adoption/backfill/持续writer-GC hooks齐备。

### A7.2 原key-use持久化前统一微秒窗口

原 `PublicJobOwner.keyUseTx` 现在在读取/构造原lease之前统一 `until.UTC().Truncate(time.Microsecond)`，覆盖全部原claim/relay/task/issuer/capability最短窗口；不在签名后修改lease，也不向上取整。A7.1 `PreparedProviderPermitIssue.ValidUntil` 也先向下截微秒，Stage拒绝不规范的纳秒lease；D仍须在原keyUseTx之前min准备期限与原guard/relay/task。

真实SQL新用例 `TestAProviderPermitIssuerNanosecondAuthorizationDeadline`：独立issuer grant的最短期限显式含123456789纳秒，小于task/relay/Generate capability；从真实Prepare.ValidUntil→原keyUseTx首次写入→签名payload→真实evidence DATETIME(6)→ReadCommitted→JWT/TLS Generate完整跑通，断言各处期限完全一致且严格早于未截断授权期限。普通正例也不再在fixture手工截断原until，原生产入口自身负责规范化。三条issuer实际SQL+TLS测试PASS，pkg7.432秒。

## 第八切片：原生S3全版本/删除标记/保护与未知multipart EOF观察

新增 `NewS3CoverageCensus`，从独立部署固定的endpoint/region/bucket/prefix、CA SHA、只读发现凭证文件SHA和原SourceRecord读取真实原生S3 API；Source.ContentSHA为Scope完整JSON摘要，不从HTTP任务选择scope。SDK固定path-style/region/HTTPS/CA、一次尝试；专用transport只允许原bucket版本配置/Object Lock配置、原prefix的全版本/multipart列表和精确version retention/legal-hold GET，拒绝写方法、HTTP/crosshost跳转、邻接prefix及内容GET。私密凭证结构String/JSON均不输出内容，SDK内部Go string无法承诺完全清零，没有日志打印秘密。

实际枚举 `WithVersions=true` 全部Version和DeleteMarker；保留旧版本及`null`历史为legacy_unversioned，绝不把删除标记当作旧版本解密材料释放。逐版本读取retention/legal-hold；原生multipart列表持续分页至EOF，每个上传标为multipart_unknown，不由TTL或任务状态去掉。所有返回成员保留原key/version/upload ID/metadata及保护事实，返回防别名副本和摘要；不输出对象payload。

在SDK宽松XML解码**之前**捕获实际HTTP响应：核对root/bucket/prefix/回显cursor、必需IsTruncated和终止页、精确下一游标及全局已访问游标集（拒绝非相邻循环）、必需且无重复的Key/VersionId/IsLatest/LastModified/Size/ETag、0字节版本与缺失Size严格区分；拒绝多根尾随XML、错entry kind、重复版本身份及未知截断空页。原页SHA/数量与SDK实际输出数量一致，EOF才返回观察。单HTTP响应4MiB、10k页、100k成员、成员metadata64MiB及页证据32MiB均为拒绝阈值，从不当作分页完成。

保护元数据也先严格解析：**只有HTTP404 + 唯一ObjectLockConfigurationNotFoundError代码**才视为原bucket未配置Object Lock。HTTP200须明确唯一Enabled；缺字段、重复字段、尾随多根、歧义retention Mode/date、歧义legal-hold Status均拒绝。成功Enabled时逐版本保护API不可省；原404未配置正例不虚构每对象持有保护。versioning也要求唯一Enabled。读取末尾复核原凭证文件SHA，途中材料替换使观察失败。

本地验证：实际MinIO SDK→loopback TLS/SigV4 GET，23场景（完整双页旧版本/删除marker/legacy null、明确Size=0、原404 no-lock、持有COMPLIANCE+legal-hold、未知multipart双页及各类拒绝）+只读/前缀边界transport与歧义XML测试全部PASS；最终完整adapter suite PASS4.599秒。每个负例均确认真实HTTP已到达，未把前置连接错误算成特定源拒绝。TLS fixture没有实际生产S3/IAM，返回native响应作为本地协议验证，不冒充现场provider能力。

边界保持：返回 `UnadmittedS3CoverageCensus`，不实现PreparedCoverage，没有StageAdmission/CompleteScan/删除权限。live LIST遍历完整EOF不是immutable snapshot；还需原owner的固定inventory/snapshot及expected-request历史投影、与原SQL冻结/adoption同一维护协议结合，所有writer/GC参与共享fence后才可完整准入。没有用0行/四行receipt/观察标签放开门禁。

直接阻塞同一正式v2六项封存/签名/发布的最小本地剩余项：

1. D5.5已将A7生产issuer的Prepare/Stage/ReadCommitted接进实际mTLS/TokenReview控制入口，合入8d25bcf5；实际attempt3原handler→同SQL事务→JWT Generate→candidate由D及监督独立验证。保留启动pending guard，不能把该单模块链路等同六模块完整封存。
2. 六类正式ModuleFactory与原Runtime/参与者停采和恢复在同一原任务执行；FinishCapture成功释放capture claim并进入validating后，D必须取得**当前publisher新claim**。A下一切片提供三用途签名对正式v2发布的最小适配，在该原业务tx StageSigningInput，不沿用capture authority。
3. 当前recovery.Publisher仍用Signer.Private/旧签名Seal，旧control publisher写system_backup_catalog_actions等旧表；不能作为正式v2终结器。需保持C既定JWS字节/域/三用途历史独立验签，冻结真实原输入→原owner commit/readback→独立JWT/TLS签名→不可变finalizer原字节/ACK未知读回→所有终态前提真实成立。A负责安全签名适配，D负责当前claim/原事务/六模块/终态路径。
4. KEK四源adoption/backfill及持续hold/catalog/restore/prune/GC fence仍是代码待办。A6原SQL和本切片原生S3是可消费来源，不是完整准入；此项继续保留，不改记成现场材料。

## 第九切片：正式v2原publisher claim的三用途JCS/JWS签名适配

新增 `systembackupsecurity/publication_record.go`，只适配已存在的 `public-c-crypto.v1` 三用途profile，不调用legacy recovery.Seal、不接收/导出私钥。部署适配仍从 `NewSQLInstallationArtifactSigners` 的原安装授权/三份JWT mount开始；当前publisher自行取得新claim后构造该实例，不复用FinishCapture释放的capture claim。

接入顺序：

```go
keyRef, err := signers.PublicationSigningKey(ctx, purpose)
// 原C/D publisher将keyRef放入完整业务payload，校验全部六模块/Job/结果/前置条件。
prepared, err := signers.PreparePublicationRecord(ctx, purpose, payloadJSON)
// 在同一个原业务事务、业务锁及当前publisher claim下，完成真实业务校验后：
err = prepared.Stage(ctx, originalTx)
// 原owner commit/readback；provider RPC必须在事务提交后。
recordJCS, objectSHA256, err := prepared.SignCommitted(ctx)
// 原不可变finalizer用recordJCS原字节；固定原immutable version并readback。
history, err := signers.History(ctx)
observedSHA256, err := history.VerifyPublicationRecord(readbackBytes, originalTask, purpose)
// 原owner必须比较expected objectSHA256/immutable locator及完整业务字段，
// 并在终态原事务再次校验当前claim/全部发布前提。
```

`capture_certificate` / `acceptance_record` / `catalog_record`各自固定安装的当前key，payload/header/task/attempt/origin/purpose必须一致。JCS header恰为alg/key_version/kid/purpose/typ；签名输入保留完整canonical payload。最终对象为JCS `{payload,signature}`，对象SHA覆盖完整签名envelope。对独立历史按issued_at/decision_at/recorded_at检验artifact-time窗口及当前撤销；完整closed schema、业务接受性、六模块清单与原输出正确性仍归C/D原owner，签名成功不证明不可变写入/本地acceptance/终态成功。四个公开C向量（capture/acceptance/registration/tombstone）输入、JCS record及对象SHA逐字节匹配；篡改签名、payload、purpose/domain/version/header、重复字段、未知signature字段、非canonical/尾随JSON、其他attempt及已撤销历史key均拒绝。

完整多Job容量：原输入上限从4096对齐Transit接口16384字节，按base64后的完整JWS input检查，超限拒绝且不截取Job、不把payload换成hash。冻结JSON总量最多32768字节。**现有096 evidence列仍VARBINARY(8192)，迁移与公共inline契约均不改**：冻结JSON超过8192时，在同一原事务/同一registry写4096-byte原始片段的严格JSON包装（最多8块）及deterministic root index。每行<=8192，固定parent/ordinal/count/总字节/总SHA/同expires；完整读回组装原输入，缺块/错序/错parent/hash/窗口不一致拒绝。旧小记录布局继续可读；没有独立task表、第二提交或provider网络锁。

实际MySQL测试使用独立UUID与随机自有DB/SELECT+INSERT受限用户，保留真实8192列宽及CHECK：六模块、2实例、每实例capture+verify共24 Job、6 checkpoint、12 staging的完整本地capture payload6128字节，input8396，frozen11922，3块，最大单行5637。原事务rollback后0行/禁止签名；重复Stage不改变输入；错ordinal/删块在JWT/provider前拒绝；独立历史验证最终record。原claim11释放/接管后拒绝；新publisher claim13复用原完整冻结输入签出完全相同原字节，旧claim仍不能恢复。该focused SQL fixture验证签名所有权/事务/列宽，不冒充actual controller Acquire API或完整现库部署；D负责该调用和原终态。K8s/provider仍本地TLS模拟，未接生产秘密。

验证：重点公开向量/容量/实际SQL链路PASS2.332秒；最终四包完整回归security19.879s、execution3.870s、adapter5.690s、kms3.152s均退出0。未改动任何migration/catalog hash。正式六模块factory、Runtime参与者停采恢复、当前publisher业务事务、不可变finalizer/ACK未知读回/终态仍须D原链路连接；KEK完整coverage adoption/backfill/持续writer-GC fence仍未完成，保持fail closed。

生命周期接线约束：原 `RenewClaimInInstallation` 自增row_version，A signer的精确claim版本及签名前后原SQL事实检查保持不变。D须协调有界签名动作与原renew/takeover；续租不能悄悄修改expectedRowVersion继续旧signer。原冻结evidence expires_at不会随新claim延长，已过期必须拒绝；未知外部ACK/已有签名结果必须由原journal精确读回。A实际SQL用例只模拟原表claim变化，不声称跑过实际publisher Acquire/Renew API；D实际调用测试仍需覆盖renew/takeover发生在sign前/期间及按原字节恢复。

## 第十切片：部署外部材料→当前publisher claim的生产三用途工厂

独立文件 `systembackupsecurity/publication_factory.go` 提供具体 `NewSQLPublicationSignerFactory`；D的独立桥 `systembackupexecution/deployment_publication_signers.go` 提供 `NewDeploymentPublicationSignerFactory` 和 `ForTask(ctx, original ClaimToken)`。不修改D的deployment config/service/启动文件，避免并行覆盖。工厂没有任意授权callback、私钥、capture authority、task/claim缓存，也不获取/续租/替换claim。

外部接口已固定，D可直接使用：

```go
factory, err := execution.NewDeploymentPublicationSignerFactory(ctx, controlDB, actualKubeClient,
  execution.PublicationSignerRuntime{
    InstallationID: installationID, ServerUUID: originalControlServerUUID, Database: originalControlDatabase,
    PublisherOwner: actualPublisherOwner, // 原AcquireClaim使用的owner，例如实际public:<PodUID>
    Namespace: namespace, NamespaceUID: actualNamespaceUID,
    PodName: actualControllerPodName, PodUID: actualControllerPodUID,
    ServiceAccountName: actualControllerSAName, ServiceAccountUID: actualControllerSAUID,
  }, execution.PublicationSignerInput{File: independentlyDeployedFile, SHA256: independentlyDeployedSHA})
taskSigners, err := factory.ForTask(ctx, originalPublisherClaimToken)
defer taskSigners.Close()
keyRef, err := taskSigners.PublicationSigningKey(ctx, purpose)
// 原owner构造并验证完整payload，将keyRef纳入既定payload。
prepared, err := taskSigners.PreparePublicationRecord(ctx, purpose, originalPayloadJSON)
err = prepared.Stage(ctx, originalBusinessTx) // 此处只有本地文件/原SQL，不做Kube/provider网络
// 原owner自行commit/readback；之后调用：
recordJCS, objectSHA, err := prepared.SignCommitted(ctx)
history, err := factory.History(ctx) // 也可taskSigners.History；没有活跃claim依赖
```

`PublicationSignerInput` 必须由独立部署/启动信任通道给定，不从导入文件现算SHA、不来自HTTP任务。建议D启动使用独立 `SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_FILE/SHA256`；本切片未擅自修改实际启动解析。父Config/Grant只需固定路径/协议（如D接线需要），不包含该材料SHA；材料不含capture grant/profile/parent deployment hash，保持无哈希环。外部JSON请用导出类型 `PublicationSignerMaterials` marshal：`schema_version=system-backup-publication-signers.v1`，`record`是原`FileSigningRecordReader`（RecordFile/SignatureFile），`pin`是原`InstallationSigningPin`（InstallationID/Revision/RecordSHA256/Issuer），`mounts`恰好三项（binding、auth_mount、role、policy、jwt_file、ca_file、ca_sha256）。原Binding/Pin/Record内部字段保留既有Go JSON字段名；严格解码/roundtrip拒绝重复/缺失/大小写别名/未知字段。不合成原安装授权、不自签、不回填。

构造时实际验证DB CURRENT_USER/server_uuid/database、原record独立签名/精确pin和三用途SQLOwner、精确当前controller workload、三用途key/role/policy/CA、各JWT绝对路径。三份原SQL授权必须属于同一个原业务config版本/SHA，不能把`cfg.ControllerOwner`或已释放capture claim硬当原publisher owner。当前Pod/Namespace/SA的UID、Running/deletion状态来自实际Kube客户端；独立原安装授权仍须允许该精确workload/SQL账号/owner/config。重启Pod/owner变更不能在代码里自动重签授权。

每次ForTask只接受调用方原ClaimToken；从原SQL取request_id及**最新**sealed capture attempt，随后在原SQL authority中复核当前owner/row_version、安装/账号/配置/状态/期限/取消/采集恢复和capture_result。Prepare/Sign不能悄悄采用更新版本。Stage继续在原业务事务冻结完整输入；SignCommitted前后核验workload和原SQL，并将工厂私有workload检查接入原authority的use recheck：**每次原只读SQL事务开始前及结束后**检查，尤其JWT login之后/Transit Sign之前；没有将Kube网络塞入current(tx)或reader/materialCheck。材料/CA原SHA每次原material检查重读，provider JWT按既有安全源读取/轮换。权限、当前claim、完整原输入及三用途签名检查均保留。

`LoadPublicationSignerHistory`/factory.History只读独立材料pin+原签名公钥历史，不要求当前claim、原controller存活、CA/JWT存在或签名permission未过期；不恢复任何签名授权。原record当前撤销/材料替换仍严格拒绝旧pin。这样原不可变finalizer在任务完成后仍可按原checksum/version独立回读验签。

验证：最终实际MySQL签名测试已改走此生产工厂，保留原8192列/受限用户/24Job完整证书/原事务分块rollback/损坏拒绝与新claim13原字节恢复；新增真实TLS JWT login hook替换Pod，严格login+1而Transit Sign不增加。单测也覆盖login期间Pod替换/SA删除、claim版本变化均Sign0，provider签名期间删除SA则丢弃输出，材料替换/错误runtime DB/安装/owner/Pod/Namespace/SA及独立bundle尝试换purpose/key/role/root-policy/CA/issuer/revision均拒绝。fake Kube reactor实际断言每次Kube调用时原SQL pool无占用连接；不是只读代码断言。历史用例删除Pod/CA/JWT、状态succeeded/claim变化以及独立发布当前expired permission后仍可读取公钥历史，JWT调用0。Kube仍是fake API，SQL+TLS是真本地协议，不冒充现场原授权或实际controller Acquire/Renew API。

最终重点factory+实际MySQL链路PASS4.515s；四包完整回归security25.004s/execution4.144s/adapter4.942s/kms3.151s均退出0。D实际启动/当前publisher acquire-renew调度/业务closed schema/原journal/不可变finalizer/终态还未由本工厂替代或验证，需接线继续完成；KEK完整adoption/backfill/持续writer-GC fence待办保持。

## 第十一切片：实际service/CLI启动与当前ClaimToken consumer

A10现已接进真正的生产共享构造流程：`NewDeploymentServiceWithInputs` 保留原Linux守卫和全部旧构造阶段，旧 `NewDeploymentService` 委托到同一实现。`CheckDeploymentDatabaseWithInputs` 与实际constructor使用相同独立输入；旧DB准入函数也保留兼容委托。`DeploymentStartupInputs{FormalVerifier,PublicationSigners,ControllerPodName}` 不嵌入任何任务/claim。真正 `runConfiguredPublic` 已改为向早期DB准入和service构造传同一inputs，构造成功后才进入health/election；不存在另一个跳过平台守卫的生产constructor。

实际CLI现读 `SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_FILE` 与 `SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_SHA256`，现有verifier输入继续独立传入；Pod名由原 `POD_NAME`/hostname入口给定。父core新增可选静态字段：

```json
"publication_signers": {
  "protocol": "system-backup-publication-signers.v1",
  "path": "/run/backup/publication-signers/materials.json"
}
```

该core只有固定path/protocol，外部材料SHA仍仅由独立启动信任通道给定，不写回父core/Forward；原record签名和pin也不在启动现算/自签。Forward且配置此ref时，缺失/额外/错路径/错SHA材料一律拒绝；无此ref仍兼容原workspace非acceptance能力，但`PublicationSignersForTask`不可用，不能借此宣称六项发布就绪。已签原安装record的三用途SQLOwner须与原Forward的installation、DB/server/account、business config版本/SHA和core namespace一致。完整core路径/原SHA、原Forward controller owner/profile/core SHA在共享file-binding阶段核对，实际ForTask入口再次读原core并验证原Forward文件/真实DB身份，不用bare记录key identity替代原授权。

service在source/staging连接前调用真正 `attachPublicationSigners`：从实际client查controller Pod，再查Namespace/SA并核对原UID、Running/deletion状态，拒绝使用capture worker的SA UID；PublisherOwner由查询结果导出`public:<真实controller PodUID>`。**它与 `Config.ControllerOwner`（原capture deployment owner）是两种身份**，后者仍用于Forward绑定；原签名SQLOwner.ControllerOwner必须允许实际publisher owner，D不得把二者覆盖为同一字符串。检查三份私有projected JWT文件实际可读/容量/私密模式，不做provider login或生成秘密，然后构造A10具体factory。Recovery/fallback模式不加载或认证signer文件/CA/JWT/issuer材料，只沿原Pod查询建立election owner；坏/缺签名材料不阻断原恢复。损坏的原core/Recovery授权仍不能绕过。

D实际publisher应使用这两个service方法，不能再单独New一个裸signer：

```go
// 原Acquire/Renew及业务状态变更返回的精确当前token，由D串行协调：
taskSigners, err := service.PublicationSignersForTask(ctx, originalClaimToken)
defer taskSigners.Close()
keyRef, err := taskSigners.PublicationSigningKey(ctx, purpose)
prepared, err := taskSigners.PreparePublicationRecord(ctx, purpose, completeOriginalPayload)
err = prepared.Stage(ctx, originalBusinessTx)
// D原owner commit/readback；不得在SQL锁内进行sign/network：
recordJCS, objectSHA, err := prepared.SignCommitted(ctx)
// 原immutable locator/checksum固定后，从provider读回相同原字节：
history, err := service.PublicationSigningHistory(ctx)
observedSHA, err := history.VerifyPublicationRecord(readbackBytes, originalTask, purpose)
```

每次consumer入口核对实际publisher owner、当前Forward/core/DB和A10完整原SQL claim；不获得、模拟或刷新token。A10 login后、provider前的私有workload检查及原SQL/原安装授权复查继续有效。公钥History仍独立于当前claim/生命周期，不能由签名权限过期推断丢弃旧key。D须在原事务完成完整closed payload/六项/所有Job/slot/验收条件校验、协调真实renew/takeover，以及在终态前验证原journal与不可变provider ACK/readback；A没有代写业务成功。

验证走同一生产共享stage，Windows未绕过Linux守卫：完整真实core→签名Forward/Recovery→外部原record/pin/三JWT/CA文件，无父哈希环。有效原issuer签名但wrong ConfigVersion/SHA、DB/account/server/installation、Pod/SA UID，worker SA混用，缺JWT、替换core静态reference/pin及startup参数错路径/摘要/数量均拒绝且provider0；每条错scope先用独立原公钥History证明原issuer签名有效，避免把坏签名当作scope检查。Recovery删除材料/record/signature/CA/JWT仍通过同一file+attach恢复阶段、不保留Forward signer。

新增 `TestAPublicationSignerActualServiceStartupToSQLAndTLS` 使用独立UUID、随机自有DB/用户、marker检查后清理，受限SELECT六表+INSERT evidence、8192列/CHECK的focused原表结构；没有迁移/改监督DB。完整文件bind→实际attach→`service.PublicationSignersForTask`当前原表ClaimToken→原SQL tx Stage/commit→三个purpose独立JWT/TLS Sign→`service.PublicationSigningHistory`独立读回验签全通，login/sign均3。后续原表row_version变更使service旧token及已取task signer拒绝，不自动采用12；Forward关闭禁止新consumer。该claim为明确种子SQL fixture，**没有声称调用了原Acquire/Renew API**；C payload取公开向量替换本地身份/时间，不冒充真实六模块完整验收/终态。Kube为fake API、签名为本地TLS，现场事实边界未改变。

实际最小RBAC也已补齐：启用PublicationSigners时，官方grant CLI使用的 `CaptureKubernetesGrants(cfg, controllerSA)` 经同一 `RequiredCaptureAccess` 增加**cfg.Namespace中传入controller SA的精确get**，与worker SA get分开；无wildcard/新增写权限，不把SA名或派生pin写回父core。`RequiredCaptureAccess`/`CheckCaptureKubernetesAccess`增加可选controllerSA参数，配置signer时必须提供唯一且非worker的实际controller名。service两处真实capture probe均从startup冻结的actual controller身份传此值，缺自身SA读权限会阻止forward readiness。生成角色启用/未启用正反例、空/worker/wildcard身份拒绝、准确SelfSubjectAccessReview允许/拒绝均通过；startup原SA GET返回真实Forbidden语义时同样拒绝且provider0。Recovery不依赖该forward probe，原捕获/恢复权限继续独立。

重点stage/拒绝/实际MySQL/CLI PASS execution4.307s +CLI2.870s；六包完整回归security21.285s/execution15.435s/adapter5.861s/kms3.120s/v2-controller3.179s/grantsCLI编译通过。最后RBAC补充后三个受影响包再次完整PASS execution14.878s/v2-controller2.854s/grantsCLI编译。实际CLI全启动仍需Linux部署/现场权限/材料，本机只验证同生产共享阶段。D后续直接消费上述service入口，继续真实新claim/renew/原事务/finalizer/终态；完整KEK历史adoption/backfill/持续fence仍待办，未改为现场事实或放开CompleteScan。

## 第十二切片：实际AcquireWithReceipt/Renew/Release/接管与丢ACK

新增A专用 `a_publication_claim_lifecycle_mysql_test.go`。正例初始只seed原业务任务的**未持有**validating行、sealed capture attempt/恢复结果；每个可用ClaimToken均来自真正 `SQLTaskClaimStore.AcquireWithReceipt` 或 `RenewClaimInInstallation`，没有手写owner/row_version代替获取。原Capture Config.ControllerOwner与service由实际Pod查询导出的`public:<PodUID>`不同。测试经完整A11文件bind/attach→service.PublicationSignersForTask→原SQL tx Stage/commit→三用途TLS signer→独立History，使用独立UUID/随机自有DB/marker/受限账号；本地schema加原task schema_version/task_type、heartbeat/next_reconcile，直接执行099原events CREATE段，额外权限仅backup五个claim列UPDATE与events SELECT/INSERT，未更改生产权限/迁移。

AcquireWithReceipt的真实CAS/原task锁定snapshot/099 durable event在同一事务；逐次核验固定event协议、task/安装/request/status/无detail与条数，接管也走同入口。真实Renew递增row_version后旧service token和已构造signer均在JWT/Sign前拒绝；JWT login hook内调用真实Renew也使Transit Sign=0，新原始token必须重新经service取signer。真实Release清NULL owner/lease并设置DB retry时间；未到next_reconcile不能抢占，时间到后其他owner取得带receipt的新token；原service拒绝其他workload的token，旧owner续租返回ClaimLost。竞争owner再经真实Release后，原owner才能AcquireWithReceipt重新获取，不伪造接管事实。

新原始token允许复用原**完全相同**冻结输入，三个签名record原字节相同，证据全行payload/SHA/size/expires snapshot一字未变。测试实际等到最初15秒冻结期限，保持后来45秒当前lease仍有效：Stage/Sign仍拒绝、JWT/Sign调用不增加，不能把续租/接管当作扩大原冻结授权；已签record仍由独立History验签。provider token也必须完整落在原剩余窗口内：回归曾用10秒fixture token在剩8秒时触发正确拒绝，本切片保持这条生产保护，生命周期fixture使用合法1秒batch token，不缩减/重签原记录或自动clip授权来凑正例。

四类ACK/重试均按原事实核验：

1. 透明包装真实MySQL connector，原Stage事务真实Commit成功后只丢调用方ACK，返回实际error；原证据已提交。按原输入readback/重复Stage后行数/字节/期限不变，再签名。
2. 同一connector用于真正AcquireWithReceipt的Commit后丢ACK：API返回ErrTaskClaimCommitUnknown与**零token**；独立SQL读回确认owner/原request/schema/type/status/heartbeat/lease/row_version及唯一原receipt。用旧expected version重试不会新增receipt/token，不凭该error或readback制造token执行签名，provider0。
3. 真正Renew primitive执行成功后丢ACK，返回零token；独立完整SQL读回确认版本已变，原Acquire receipt保留。旧token、零token均不能签名，原冻结输入/期限不变；本测试不自创D的未知续租恢复调度或fresh-version盲重试。
4. TLS handler先实际执行Ed25519签名，再主动关闭连接丢响应；调用方拿不到record。保留的公共observed Input/Signature与原capture记录完全一致，后续只按同原输入、原key/version和当前真实token重试，输出仍为原JCS bytes；原freeze期限不延长。没有重封装/换payload/把provider ACK当不可变finalizer ACK。

最终4个实际API/SQL/TLS重点用例PASS20.219s；增强“真实Sign后丢ACK并比较原Input/Signature”、合法1秒provider窗口后，在最新4cba3582基线上完整execution32.118s/controller4.822s PASS。没有发现需放松的生产保护，本切片修改仅A测试/fixture及交接；未改D capture/worker运行文件。Kube仍fake API，完整core/签名授权/原API/SQL/TLS为本地真实调用；不冒充现场、实际六模块输出、原immutable finalizer/journal/业务终态。D可直接沿已验证的AcquireWithReceipt→service当前token入口继续封存发布；KEK完整历史adoption/backfill/持续fence仍待办。

## 第十三切片之一：具体publisher历史读取authority（供D受控Records API）

新增security独立 `publisher_capture_authority.go`，不导入controller。独立原publisher-verifier business owner签发 `PublisherCaptureGrant`，域 `system-backup-original-publisher-verifier-grant.v1\x00` / version `system-backup-publisher-verifier-grant.v1`；包含原deployment/record-custody绑定、真实publisher workload、有界NotBefore/Until与Revoked。没有任务/未来claim hash，不从provider ACL/signing grant/capture grant推出此项业务授权。部署另给grant envelope SHA+issuer公钥；Workload.GrantSHA256在signed payload为空，runtime为完整envelope独立摘要，且不能等于capture grant SHA。

准确公开类型/字段在该文件，可直接供D编译：

- `PublisherCaptureAuthorityConfig{DB *sql.DB, Kubernetes kubernetes.Interface, Deployment PublisherCaptureDeployment, Workload PublisherCaptureWorkload, GrantMount PublisherCaptureGrantMount}`。
- Deployment是原Forwards已认证的InstallationID/ServerUUID/Database/DatabaseAccount、**原capture ControllerOwner**、ConfigVersion/ConfigSHA256/ProfileSHA256/DeploymentConfigSHA256/CaptureGrantSHA256及其NotBefore/Until；这是record-custody绑定，不是旧live capture claim。读取层仍须校验其**实际**原deploymentAuthorization/record-key identity与此值一致。
- Workload固定Namespace/NamespaceUID/PodName/PodUID/ServiceAccountName/ServiceAccountUID、PublisherOwner、GrantSHA256。PublisherOwner强制`public:<真实PodUID>`，且不能混成capture ControllerOwner。
- Scope是`PublisherCaptureScope{BackupPublicID, Claim SQLSigningClaim{ControllerOwner:真实c.ClaimToken.Owner, RowVersion:真实token.RowVersion}, CaptureAttemptNo, Part}`。Part仅locator，不是存在/封存/解密权限证明。

```go
a, err := security.NewSQLPublisherCaptureAuthority(ctx, cfg, scope)
lookup := a.Scope()                 // value copy，当前publisher scope
deployment := a.Deployment()        // value copy，原record custody pins
until := a.ValidUntil()             // 不可延长的最短当前授权窗口
err = a.CheckWorkload(ctx)          // 本地grant + 真实Kube，SQL tx外
err = a.Check(ctx)                  // workload→短SQL guard→rollback→workload
guard, err := a.Bind(ctx, originalTx)
facts := guard.Facts()              // 值拷贝，只读事实，绝非capture执行权
err = guard.RecheckTx(ctx, originalTx)
until = guard.ValidUntil()
```

Bind/RecheckTx仅SQL+有界本地原签名检查，不Kube/provider、不commit、不返回record key/DEK；guard绑定同一tx和相同comparable context，先拒绝不可比较/typed-nil ctx再比较，避免interface panic。构造和Check前后真实Kube校验namespace/Pod/SA UID、Running/deletion状态在短SQL事务外，fake reactor实际断言SQL pool无占用连接。grant closed/duplicate/case-alias严格JSON、独立域签名/固定hash/当前撤销和有效期每次检查，最长24h。cfg内issuer防别名复制，无授权callback或default-allow。

当前原SQL要求真实当前publisher owner/精确row_version/活跃lease与任务deadline、原安装/SQL账户/server/db/config，允许validating/publishing/**finalization_unknown只读**；拒绝当前cancel、非最新或未sealed capture attempt、未真实记录source resumed、无capture_result SHA/不规范schema/task identity。初次完整facts、epoch/result hash和最短窗口被固定，后续不能换状态/结果/配置或悄悄更新claim来续长；新实际token必须重新构造。Facts含InstallationID/BackupPublicID/RequestID/Status、ConfigVersion/SHA/TaskPurpose/RequestedParts、CaptureAttemptNo/Epoch/ResultSHA、ClaimLeaseUntil/TaskDeadline/CollectorsStoppedAt/SourceResumedAt，SQL时钟单调复核。该阶段**未认证某一Part实际存在**，只限定后续读取者允许查看的原任务/attempt/part locator。

D协调的新 `SQLExecutionRecords.LoadPublisherCapture(ctx, access *security.SQLPublisherCaptureAuthority)` 必须继续独立认证原sealed plan/result/candidate/finished key-use/Job journal唯一匹配，保留原记录密钥custody；不得借原LoadPlan/capture Gate绕授权。建议返回明确的历史不可变事实而不是伪造“原Input.Authority”：taskPlanBinding/runner.binding未绑定旧可续租claim，不能将当前pubclaim填为capture、或补造旧rowversion=1。认证candidate中真实保留的旧Authority可只作历史数据；缺失字段用受控纯历史解析，不改旧capture校验；原AuthoritySHA只能作原journal标识，不用新token重算替代。unknown状态只能读原candidate/part和D已冻结immutable locator/version/cipher/envelope receipts，不能Generate/重封装/换版本。

真实本地SQL测试：独立UUID/自有schema与最小列权限，真实AcquireWithReceipt取得token，再独立签发本地business grant；3阶段、Renew后旧token拒绝/新token重建、撤销/材料替换/SA替换、错capture owner/version/task/attempt/peer、未sealed、capturing、cancel、过期task、未resume、result漂移、原tx内rowversion变化、最短独立grant到期、未来/过期/过长/错误版本/部署/workload/issuer/pin/domain/空Part/typed-nil client，以及不可比较/typed-nil context均通过；provider调用0，Part存在性未冒充。重点首次PASS10.168s，最终完整security20.722s/controller4.400s/execution39.434s；此前kekadapter5.221s完整PASS。Kube明确fake，独立业务授权临时keys仅本地测试，不冒充现场事实。

后续A13.2将用此authority+ D受控历史读结果构造独立publisher exact-request unwrap，保留旧ForCandidate所有capture-only保护。当前没有提供任意解密/Generate/新封装或完整页面终态。实际A5 ownerchain需GET自身RS/Deployment/StatefulSet和可能独立namespace，官方RBAC旧清单仅list RS且只列source writers；该权限缺口已记录，A13.2必须按实际独立材料scope补同源精确只读generator/probe，不把controller加入source writers蹭权限，拒绝/provider0测试不可省。KEK完整历史adoption/backfill/持续fence仍未完成。

A13.1最终安全同步D5.9 backup f9e2742f后，execution整包再次PASS39.687s，保留所有D代码与新增authority；未引入生产schema迁移。

A13.1补充修复 `159717d0`：监督独立 overlay 复现最后 SA GET 内真实 Renew 或替换为已撤销 business grant 后 Check 仍 nil。现 CheckWorkload 在最后 Kube I/O 后重验原 grant/pin/时间与原固定窗；constructor/Check 在末次 workload/material I/O 之后另开短 SQL 事务，重新 Bind/Recheck 同一原 claim/事实/最短窗口再 rollback，Kube 不进 SQL。正式新测试同时覆盖 constructor/Check 中真实 Renew、末次撤销和慢 GET 跨原窗口，旧 token 拒绝，实际 fresh token 重新全构造正例；provider0。相关 authority 完整重点 PASS14.179s；监督原 overlay 两个 FAIL 转 PASS3.781s。

## 第十三切片之二a：独立验证器实际 GET、角色生成与 readiness 同源

新增 adapter `VerifierKubernetesReads`，版本 `system-backup-verifier-kubernetes-reads.v1`，经独立 SHA 固定的 formal verifier materials 可选 `kubernetes_reads` 字段提供 namespace 名/UID、Pod 名/UID、SA 名/UID、OwnerKind/Name/UID；Deployment 额外要求 ReplicaSetName/UID，StatefulSet/Job 不接受 RS 字段。映射是读取坐标，业务授权仍来自独立 business grant 与 provider capability 中完全相同的 ControllerVerifierWorkload；不能以 DTO/hash 代替授权。构造器复制映射，防止外部指针别名修改。

实际检查精确读取 namespace→Pod→SA→RS→Deployment（或 StatefulSet/Job），核验 UID/Running/deletion 和完整 controller owner chain。Pod 或 RS 所指父名称/UID 与固定映射不符，在父 GET 前拒绝；无 list/猜名/宽泛 GET 回退。旧 ForCandidate 的原 capture-only 权限、旧 deadline/claim、原计划及 journal 检查完全保留；没有映射的既有底层 factory 仍保留原保护路径，未开放 publisher 解密。

`RequiredDeploymentCaptureAccess` 将原 capture 清单与映射的精确命名 GET 合成；official `CaptureKubernetesGrants` 与 service 两处实际 forward/readiness probe 均走同一清单。配置 FormalVerifier 后官方角色生成和实际探测必须提供完整映射，且 verifier 的 namespace/SA 必须与真实 controller namespace/SA 相同；旧无 FormalVerifier 配置保持原行为。CLI 新增 `--verifier-materials-sha256`，材料路径只取原 core 静态 reference，摘要必须由独立部署参数提供；缺 pin/错 pin/缺映射 fail closed，不自动读取文件计算摘要。没有把 controller 加进 source writers，没有新增 verifier 写权限；Recovery 继续不依赖此 forward probe。

测试覆盖三种 owner 的实际 client-go GET 与 RequiredReads 精确一致；Pod/namespace/SA/RS/owner UID 替换、父名称变化、API Forbidden、缺映射拒绝；生成角色和实际 SelfSubjectAccessReview 都包含所有指定坐标，RS GET denied 阻止 readiness。真实本地原 MySQL authority/独立 grant/TLS provider 加真实 client-go HTTP API fixture：正例完成 exact DEK unwrap；RS 或 Deployment GET 返回实际 HTTP 403 后，已构造 verifier.Recheck/Unwrap 和新 ForCandidate 均拒绝，provider login+decrypt 总计数不增加，DEK callback 不调用。Kubernetes API 是隔离 HTTP fixture，不是现场集群。

本切片只封闭实际读取权限缺口。A13.2b 的当前 publisher claim→受控历史 reader→原 exact-request unwrap 仍在继续；不把旧 capture ForCandidate 用于停止/恢复后的 publisher。D 新受控 reader 尚未进入此切片基线，未复制或绕开它。

验证：精确清单/三种 owner/角色/probe 重点 PASS adapter3.074s/execution3.296s；真实 SQL/TLS/HTTP403/provider0 PASS11.269s。受影响完整回归 adapter5.043s/execution47.171s/v2-controller3.319s/grantsCLI编译通过；随后独立竞态修复另经上述正式用例与监督 overlay 验证。

独立 verifier-only 组合补充：真实 startup Pod GET 观测的 PodName/PodUID/SAName 保存到独立 controllerActor，service 两处实际探测使用该观测值，即使 PublicationSigners 未启用也不从材料 DTO 猜 SA；mapped verifier attach 将 namespace UID、Pod/SA 坐标与真实 startup 观测匹配。缺 controller Pod 参数时 Forward verifier-only startup 拒绝。此组合重点 PASS3.397s；最终完整 security21.569s/adapter5.149s/execution52.011s/v2-controller3.383s/grantsCLI编译通过，HTTP403 实际用例同步修正后再次 PASS10.252s。

材料部署顺序必须明确：core 仅静态路径/协议；原 owner 签 core/Forward；实际 controller Pod/RS/owner UID 出现后，由可信独立 owner/provisioner 生成业务授权、capability 和独立材料 SHA，再向同一 Pod 交付并由独立启动机制提供 pin。不能把含该 Pod UID 的派生材料 SHA 再写回 Pod template 环境造成新 Pod UID/摘要循环。本地测试只实现并验证这些原始文件及独立 startup pin 的消费；尚未实现现场自动 provisioner、Pod 重建后的自动独立签发/交付机制，不能宣称每次重启或新部署已无人值守。相同真实 Pod 在其授权有效期内的后续任务不需要逐任务人工签名。

## 第十三切片之二b：publisher 原始历史凭证与 exact unwrap

新增 adapter `PublisherVerifierConfig` / `NewPublisherVerifierFactory`；输入是独立 publisher business grant/issuer/pin、原 KEK/安装 issuer、独立 Unwrap capability、真实 Pod/SA/owner 精确读取映射、原 SQL/Records/deployment wrapper。`ForPart(ctx, security.PublisherCaptureScope)` 只接收真实当前 publisher claim+backup/attempt/part locator，内部调用 D6c3ea956 的 `LoadPublisherCapture` 认证全部原记录。KeyRequest/AAD、原 Endpoint/KeyName/Generate、plan/result/candidate/finished key-use/Job 均从原记录取；没有接受调用方 Invocation/KeyRequest/hash 作为权限，也没有 Generate/重封装/换版本接口。旧 ControllerVerifierFactory.ForCandidate 所有 capture-only 保护保留；仅把其原始安装映射验证和严格 JWT login transport parser提为私有共享函数，独立业务授权没有混用。

受控 reader 返回的 `PublisherCaptureRecord` 现在含只能由 reader 构造的私有 opaque receipt。reader 原 SQL snapshot 的有界读取拆出同事务内部 helper，仍由原 concrete publisher guard Bind/Recheck；无 Kube、密钥文件解析、AEAD、provider 或 commit。`record.RecheckTx(ctx,tx,access)` 必须同一 concrete access 指针、原 shortest window、完全相同 DTO 和原 SQL snapshot（含cipher/key ref/plan/result/candidate/Job request/binding/finished key-use/stop facts）。手造 DTO 没有 receipt；值拷贝后改任一字段也不能借原 receipt。JSON Marshal 会压紧 RawMessage，故 receipt 与 adapter history fingerprint 除有界整体字段外，另以长度前缀分别固定 Input.ConfigSnapshot、Plan.CanonicalJSON、CandidateJSON、PartResult.Checkpoint 的原始字节，空格变化同样拒绝；hash只是比较事实，不是权限。

`PublisherVerifier.ValidUntil/Recheck/ExpectedRequest/Close`；`ForEnvelope(ctx, originalEnvelopeBytes)` 必须匹配原 sealed candidate 的 envelope name所属receipt、长度/SHA、单 entry closed canonical envelope 和原完整 StreamSpec，再返回只接受该确切 wrapped ciphertext 的 `PublisherEnvelopeVerifier`（Unwrap/Recheck/ValidUntil，可直接供 C InspectWrappedStream）。`WithDEK(ctx, originalEnvelopeBytes, callback)` 提供同样约束下的便捷入口。即使同 KeyRequest 的另一份合法 vault ciphertext，也在 provider 前拒绝；原 request/AAD 不重算。明文/密钥与原源对象/全帧认证/immutable版本及发布接受仍由后续 D 受控消费者完成，WithDEK本身不冒充已发布成功。

每次 login前、login后、decrypt前和DEK callback前后，复查当前 concrete publisher claim/SQL时间/原业务grant/pin/真实UID与owner chain、原静态deployment/custody和当前ForwardEnabled、原安装Unwrap撤销、独立capability及同KEK fence。provider网络在SQL事务外；DEK callback处同一短原事务持有原claim/records/KEK fence，并用opaque receipt固定所有原记录；callback内Recheck复用该session，避免新事务自锁。rollback后再完整复查；不采用旧capture claim、续租不修改已构造对象窗口。新增实际 deploymentAuthorization.CheckPublisherVerifierDeployment 只查当前本地部署/材料绑定，无网络/新SQL；保留真正生产 wrapper，不换 bare record identity。

A专用实际集成基于 D 原加密 history fixture，增加可选 A owned credentials/独立server UUID，创建随机 `ad_a_publisher_*` DB/`ad_a_pub_*` user，清理前核验UUID与本次run marker；不会触及任何已有D/监督库。额外权限直接采用官方 FormalCaptureGrantSQL 中所需原安装/registry五表项（fence SELECT/INSERT/UPDATE，其余 SELECT），未跳过Bind。原 Job deadline 用合法短测试窗口，实际等原 invocation deadline过期后，当前真实 AcquireWithReceipt 的publisher仍能读原历史并以TLS独立JWT/Unwrap获得确切DEK；task/business/capability/currentclaim窗口仍有效。Kube是fake API，原加密plan/result/candidate/finished-use/实际SQL+新claim与TLS真实本地执行。

正例原单entry Envelope WithDEK；DTO修改Invocation/Request/CandidateJSON/Config/Plan/Checkpoint原字节/ValidUntil、手造无receipt、wrong part、合法JSON nonce/Job请求变更和candidate cipher变更均拒绝，明确读回实际变更后验证provider0/DEK callback0；同request换wrapped ciphertext或换原Envelope同样provider0。login期间真实Renew使decrypt0/旧对象拒绝、仅新真实token重建成功；login期间原安装Unwrap revoke使decrypt0；decrypt完成前原candidate被换使DEK callback0；当前actual deployment Forward关闭也provider0。旧对象ValidUntil不变。首次完整两suite PASS13.443s，监督独立复跑13.486s及独立精确RawMessage overlay4.346s均通过；最后扩充原字节/正式角色/部署关闭检查后完整相关回归见后续结果。

最终相关五包完整回归 PASS security22.852s/controller4.934s/adapter5.317s/execution62.652s/kms3.139s，包含新增部署关闭、所有原字节负例和直接采用官方角色权限的实际SQL/TLS路径；已同步监督backup a51309f8，保留D自动Teams发现提交。没有生产迁移或修改任何远侧部署。

此切片提供组件与同事务保证。真实 service 的独立材料输入、同一实际Pod可完成bootstrap及D实际publisher消费者仍在下一切片继续，不把 helper 当完整生产装配。时间预算另须在后续跨窗口流式对象用例明确：现有kms.Grant.CredentialExpiresAt只约束provider RPC，ExpiresAt是独立原DEK使用权限；原JWT batchTTL<=20s、当前claim/业务/原cap窗口各自保留，不能静默延长对象或把过期RPC credential用于新调用。长归档必须在其真正原DEK/claim窗口内完成全帧认证，否则不接受输出；合法分片/预算/显式新claim重建及D超时终态尚须整链验证。

## 第十三切片之二c：真实service、当前就绪检查与同Pod独立pin装配

配置增加独立 `publisher_verifier:{protocol:"system-backup-publisher-verifier-materials.v1",path:"固定绝对路径"}`，仍仅静态协议/路径进入原core完整SHA；派生bundle SHA不写回core或Pod template。`DeploymentStartupInputs.PublisherVerifier []PublisherVerifierInput{File,SHA256}` 经实际CLI `SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_FILE/SHA256` 进入早期 `CheckDeploymentDatabaseWithInputs` 与真实 `NewDeploymentServiceWithInputs` 共用file-binding阶段。`PublisherVerifierInputsFromEnvironment()` 是CLI实际调用的同一解析入口，既不读取bundle推算可信hash，也不发起任务/签名/授权。

独立 `PublisherVerifierMaterials` 包含原database/binding/安装issuer、provider capability pins、CA/JWT固定路径、实际publisher workload、具体 `kubernetes_reads` 与独立 business grant mount/issuer/pin。file loader严格独立摘要、版本、closed JSON、部署/原Forward config绑定；worker SA不能混用。生产构造器的 `publisher-verifier` stage 经 `attachPublisherVerifier(ctx,db,client,gate.Records)` 保留原actual deploymentAuthorization/record-key custody，验证真实startup PodName/UID/SAName、namespace UID、business grant、owner chain、原安装/registry/cap/current peer、私有JWT/固定CA，不联系provider；原Linux完整构造守卫没有绕过。主体在独立新文件，共享文件仅publisher字段/输入/调用点；没有复制D未提交六项factory。

公开实际service入口：

```go
use, err := service.PublisherVerifierForPart(ctx, realClaimToken, captureAttempt, part)
err = service.CheckPublisherVerifierReadiness(ctx)
```

前者必须真实 `c.ClaimToken.TargetBackup`、当前实际 `public:<PodUID>` owner与原rowversion，随后仍经A13.2b具体ForPart/原history/SQL权限；不会接受DTO代替claim。后者是当前no-task/no-provider部署检查，缺feature/factory/原材料时明确拒绝，供D的六项readiness消费；旧legacy无此feature的真实admit/PublishReadiness保留原路径。启用时，两处实际service admit/PublishReadiness均在SQL事务外调用此probe并经相同精确Kube SSAR清单，不能只信startup一次检查。实际wrapper在每次provider/DEK边界内还做本地有界core/材料pin/CA复核，payload来源修改会使既有对象拒绝。

`PublisherVerifierFactory.CheckDeployment` 在Kube与JWT/原record-key部署观察之后，用短原SQL事务读取真实peer/SQL clock、同KEK fence、exact registry security binding/Unwrap撤销、原安装Unwrap撤销、原capability与本地pinned publisher grant窗口。没有CompleteScan/全coverage推断。监督先独立复现registry-only Unwrap revoke后ForPart拒绝但readiness仍nil，本切片已补同源registry检查；监督原只读overlay转PASS5.228s。正式测试现同时覆盖owner/registry各自Generate-only撤销仍可unwrap、Unwrap撤销readiness/ForPart都拒绝/provider0，保持用途隔离。

权限生成增加 `CaptureKubernetesGrantsWithInputs(cfg,actualControllerSA,DeploymentStartupInputs)`，旧函数仍兼容原FormalVerifier参数；publisher映射同源进入RequiredDeploymentCaptureAccess、official role与两处真实SSAR。CLI新 `--publisher-verifier-materials-sha256` 只配固定core reference路径，不由本地bundle自算信任摘要。SQL模式沿用官方formal-verifier扩展role；启用publisher verifier的早期DB检查确切选择此role，普通base role不能冒充足够权限。没有给controller新增source writer角色。

可实现的同Pod bootstrap契约（本机验证，未apply任何部署）：部署模板固定材料Secret名称、环境变量SecretKeyRef、volume/path及POD_NAME downward field；模板中**不放派生SHA字面值或该Secret内容checksum annotation**。独立原owner先创建并持有空的固定Secret对象，记录其UID；再创建Pod/RS，必需pin key尚不存在时容器可Pending。独立原owner观察其实际Pod/RS UID后签业务授权/能力材料，只UPDATE这个原有Secret的data一次交付文件及独立pin，并核对Secret UID未变。controller官方role只有Secret get/create，没有update/patch/delete，因对象已存在，不能抢先create自选材料作为独立信任源；原owner的签发/更新principal须独立于controller能创建Pod/Job所可选的SA与其运行namespace。不能把controller自己创建或可改写的Secret当独立pin。Kubelet随后启动同一Pod内的容器，从SecretKeyRef注入SHA；实际controller仍要求Running并复核全部UID。Secret名称/路径可固定在部署协议内，文件中的grant/CA/JWT指向各独立只读挂载。一个最小模板片段如下（仅契约示例）：

```yaml
env:
  - name: POD_NAME
    valueFrom:
      fieldRef: {fieldPath: metadata.name}
  - name: SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_FILE
    value: /run/backup-publisher/materials.json
  - name: SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_SHA256
    valueFrom:
      secretKeyRef:
        name: publisher-materials
        key: materials_sha256
volumeMounts:
  - {name: publisher-materials, mountPath: /run/backup-publisher, readOnly: true}
# Pod spec volumes:
volumes:
  - name: publisher-materials
    secret:
      secretName: publisher-materials
      items:
        - {key: materials.json, path: materials.json}
```

固定单Secret的契约要求单active publisher按受控Recreate/租约交接顺序更新材料，不能让两个不同UID的Pod同时共享同一份UID绑定bundle并宣称都就绪。材料或Secret版本传播不一致会因独立pin失败而拒绝；应等待一致后重启同Pod容器读取环境值，不修改template来注入派生pin。同Pod容器重启保留Pod/RS UID；新Pod/RS需独立owner重新授权并更新材料。此处提供可实现的签发/交付契约与消费代码，本仓库尚未实现外部原owner自动provisioner，不能宣称现场自动签发或任意滚动升级已验收。后续同一真实Pod/授权窗口内的新任务无需逐任务人工签名。

新A本地测试扩展原D历史fixture为可选完整合法core/profile与分别签名Forward/Recovery，原record/candidate/AEAD仍真实；原owner先持有空的固定Secret，然后创建带固定SecretKeyRef、实际UID的Pending Pod（尚无pin/material data），原owner随后生成当前UID/RS材料与独立pin、更新同UID的原Secret。通过本地Secret投影/Kubelet状态模拟、**真实CLI同一env parser**、真实文件绑定/attach/current claim service入口与SQL/TLS完成unwrap；对比确认Secret UID、Pod UID/spec/完整core SHA与原Forward parent hash未替换，official role没有Secret update/patch/delete，Pending状态在生产authority中拒绝。该模拟不是现场Kubelet/CSI验收，原业务SQL/claim/密文/签名/TLS调用均实际执行。

重点结果：同Podactualservice与当前材料/SA/owner/原grant/core/缺pin负例及删除全部publisher文件后独立Recovery通过（首轮execution7.217s）；补owner/registry用途撤销、独立输入路径/摘要/数量、official named RS role及**实际service.admit** denied-SSAR后全部PASS16.781s，CLI实际输入测试PASS2.839s；早期DB入口同原core/签名/材料文件+严格只读SQL driver检验valid、base-role-only、缺/错pin、Recovery五种模式通过。此处SQL driver仅用于early SHOW GRANTS模式验证，actualservice消费的history/claim/KEK/TLS仍为上述真实本地SQL。初次完整七包PASS security21.107s/controller5.431s/adapter5.339s/execution77.331s/kms3.081s/v2-controller2.822s/grantsCLI编译；随后补startup与actualUnwrap共享HTTPS/确切keyversion/parseableCA契约，全部publisher suites再次PASS29.206s。空Secret预分配强化及最新D已提交修复同步后最终回归另记。

与D的后续接线边界：D实际六项factory/不可变publisher应使用上述service方法和ForEnvelope返回的exact Unwrapper，继续冻结原cipher/envelope receipts及最终locator/version、全帧/域认证、独立读回与真实终态。当前未宣称实际页面完整六项封存/发布成功；跨短token TTL的全帧正例、跨固定DEK/claim窗口拒绝与业务恢复仍要在后续本地流式用例验证。

A13.2c最终已同步监督42f321fa（D已提交formal MySQL材料修复，未复制D CaptureModules大装配WIP），空Secret预分配/不替换UID、所有当前材料/用途/registry/readiness/原SQL/TLS路径与实际CLI输入在最终完整回归中PASS：security21.561s/controller4.453s/adapter5.860s/execution77.417s/kms5.256s/v2-controller3.065s/grantsCLI编译通过。没有远侧部署、权限放宽、生产DDL或CompleteScan放行。

## 第十四切片：真实完整加密流跨token与固定DEK窗口

新增A实际SQL/TLS原密文流用例：原workspace含1.5MiB不可压缩数据，真实归档/压缩/多个CMBKGC01帧+强制EOF、原Envelope/opaque history与当前Acquire claim。正例在provider完成1秒batch凭证调用后，实际ciphertext reader延迟1.5秒，再通过C InspectWrappedStream读取全部明文压缩流并校验全帧AEAD/EOF，最终checksum/size与原candidate一致；原DEK权限窗口仍有效、同一对象ValidUntil不变，只login/decrypt各一次。明确遵守CredentialExpiresAt只限providerRPC、ExpiresAt限独立DEK使用，未人为clip到token TTL。

负例独立原Unwrap capability签5秒窗口，实际ciphertext reader延迟6秒，使完整DEK-use窗口耗尽；返回零StreamVerification，不接受任何完整产物、不自动重试provider。原SQL读回证实当前claim仍live，真实Renew得到新token也不能延长已过期原capability/既有对象，provider仍各一次；组件未伪造业务终态，原task仍validating供实际publisher处理。两suite PASS14.926s，监督独立复跑PASS14.776s；必要fixture options保持原调用兼容，所有现有publisher+service suites合计PASS39.076s。此项不冒充六域/业务终态，后续正式v2 publisher/finalizer已由监督分配A直接实现。

## 现场事实边界（最终集中更新）

未提供真实安装签发者记录/独立部署 pin、真实 owner task/workload 授权和现场 JWT/Transit 回执；代码接入和本地拒绝测试不能替代这些事实。本轮不索取或生成生产秘密。

A15.1 (publisher assembly input): original encrypted-plan part inventory and detached authenticated record access. Final workload reads precede a final short exact SQL snapshot; original plan ciphertext/keyref/profile/grant mutations reject. Every part still requires concrete ForPart. Local real SQL/TLS six inventory/detach cases PASS 12.486s. No artifact/terminal success claimed; native immutable transport and original-journal finalizer are ongoing separate WIP.

A15.1 follow-up: after final publisher workload GET, recheck original local custody grant and actual pinned record keys before the final exact SQL snapshot. Added original grant.json replacement and original record-key replacement negatives; all seven inventory variants passed in the focused SQL/TLS run (10.56s). Publisher GrantMount remains a separate negative; no DEK/publication-success claim.

A15.2: real original v2 native S3 JSON publication journal and query-only RunPublicationPass, current exact task claim/AcquireWithReceipt/explicit boundary Renew, immutable native presigned PUT bound to key/body SHA/length/content-type/If-None-Match/deadline, independent read principal exact-version complete GET, opaque action/version/current-claim receipt for same consumer TX. Original 096/097/098/099/101/102 DDL CHECK/ENUM/unique/FK test fixtures; original metadata capacity reservation retained. Expired original dispatch/zero-send-count/404 remain query-only unknown. Full body mismatch records original conflict and same-task failed terminal; no retry/resign/regenerate/rewrap. Independent target core reference + separately pinned env input, production early/full binder, exact publication SQL role/CLI. D capture_modules source bindings retained after sync35f797fa. Native31s PASS34.405s; actual target/GET authority+key/version mutation/unknown+receipt/conflict targeted PASS26.176s before capacity integration; supervisor independent post-capacity actual5suites+60s realclaim31s+explicitRenew receipt rejection PASS58.291s. Actual original-capacity corrected seed first case localPASS5.246/supervisor5.417. This slice is a concrete journal/finalizer recovery entry, not whole-artifact assembler, control-evidence capture, three-purpose full C publication, six-domain offline verification, succeeded/canceled completion or onsite certification. Control sidecar producer/independent verifier and artifact integration remain active work.

A16.1 data/reader ABI: systembackupcontrolevidence package adds fixed nine-group RR SQL projections, no actor/IP/freeform/details/credentials, u64be-length-prefixed lowercase canonical-record digest rolling hashes, original registered evidence readback, per-group canonical proof chunks (40 per inline <=8192 report, <=16 refs/group), explicit capacity_exceeded without truncation/window shortening. Scope + independently pinned schema/redaction/source/config identity, actual source-exclusion registered body required. Only A's computed original snapshot/redaction/exclusion summary can be complete; B/C/D remain incomplete pending their owned validators. PreparedSource serialization omits plaintext bodies; CaptureLocator is the public source mapping. Rebuild consumes every exact registered body and returns identical sidecar/proofs only in memory; Verify consumes both complete artifact plaintext streams and never repairs missing bodies from SQL. Parts control_evidence/control_evidence_proofs, operation capture-control-evidence; original C logical names control-evidence.enc/control-evidence-proofs.enc map to control/evidence.json.enc and control/evidence-proofs.json.enc without rewriting original AAD/envelope. Synthetic protocol 121-record chunks +8 integrity/redaction/owner/scope negatives +capacity unchanged PASS0.748s. Explicit RR actual original DDL data test: 121 real events +1 audit with secret marker +installation snapshot, registered readback/rebuild, foreign installation filtering, 641-event full-window capacity rejection PASS6.646s on36b63219. This is DATA/protocol evidence, not live capture/Job/provider authorization or full artifact success. Concrete original preparing capture Build and original current-Job mTLS key-use pull exist as separate WIP; D actual Worker/Job/observer/custody and A whole-artifact publisher remain active.

A16.2 worker slice: actual `capture-control-evidence` operation accepts only the original typed CaptureLocator, exact sidecar/proof part names/limits and dynamic original Generate permit. The worker uses the original reserved/current key-use, mTLS control client and bound workload bearer to pull registered bodies; an independently signed source-owner grant is distinct from Generate authority, rechecked locally before and after pull and during C writes. Canonical JSON goes straight to the original C frame writer, with no plaintext ConfigMap/env/staging or gzip/tar. Added kube.ControlEvidenceCaptureJob and locator-only WorkerConfigMap validation. Other operations explicitly reject mixed ControlEvidence fields. D still owns original plan/factory/observer/history admission; these worker changes alone do not make those paths ready.

Actual CLI test passed all 11 scenarios (0.62s test body; package3.460s): sidecar/proofs complete 121-event/four-chunk decrypted byte-for-byte readback plus ce.Verify; source scope mismatch/revoked grant, rejected source pull, wrong nonce, missing/forged proof, trailing JSON, claim lost and grant replacement after pull all reject without candidate/partial retention or resend. Named control/provider/source fixtures are explicit: this is not actual SQL/TokenReview authorization or whole-artifact success. Full affected regression passed worker35.813s, kube3.447s, CLI4.264s, control protocol0.456s, execution5.414s; grants CLI compiled. Service producer/pull/SQL grants remain separate WIP. Its server independently validates the source grant and now rechecks it after final original SQL, before response; actual SQL/mTLS positive and last-SQL revocation negative remain required.

A16.2 follow-up: production core already uses a control endpoint such as `/worker/v1`. The independent source mount now preserves and pins that EXACT original endpoint path (still rejects query/fragment/userinfo/opaque/raw-path); the authenticated pull derives only fixed `/control-evidence` on the same original TLS client/origin. Added a real CLI `/worker/v1` positive, bringing the focused suite to12 cases, PASS3.261s. This does not relax original endpoint equality, source signatures or current Job/key-use checks. Synced supervisor backup45ae224b while preserving source-service WIP via exact stash c168a07e3f7ce6dc34993d330c16819eee956d5b; no other stash applied/dropped.

A16.3 preparing producer slice: `DeploymentService.PrepareControlEvidenceLocator(ctx,originalInput,registeredSourceExclusionRef)` now runs the concrete service deploymentAuthorization + SQLExecutionAuthority.Bind on the live ORIGINAL preparing/capturing authority, fixed schema/redaction files, actual RR nine-group projection, capacity reservation, original configured evidence DATA retention, register/readback and final same guard before commit. Job/plan receives only CaptureLocator. Unknown commit returns zero locator; discarded canonical buffers are cleared. Static materials add optional `ControlEvidence` CaptureInput and `ControlEvidenceSource` independent source-owner mount (including separate ControllerGrantFile); enabling requires the one capture-control-evidence operation and an issuer distinct from its dynamic Generate issuer. Both real startup file entrypoints and early SQL role selection retain exact pins; grants CLI adds --control-evidence with explicit formal role, controller-only read-only metadata projections. Original six frontend RequestedParts remain unchanged.

Actual original preparing SQL test PASS6.666s (earlier expanded3.84s body/package7.054): random UUID/marker-owned schema, real signed six-part core/Forward/Recovery/current profile, original096/097/098/099/102 constraints plus original112 canonical_config_json; the new task/attempt has preparing state with NO maintenance owner/fence, actual AcquireWithReceipt and real service guard. 121+event declared-hour capture produces four chunks and retained canonical SQL bodies, independent Rebuild/Verify; data expiry exceeds task deadline. Missing source, wrong digest and changed policy reject without partial report registration. Subsequent641event window returns capacity_exceeded, earlier immutable bodies still verify. Real Renew rejects old authority. Prior fixture stop/resume observations and historical frozen15 schema/source-exclusion bodies are explicitly synthetic DATA setup: not actual source census, not physical Runtime/CSI recovery, not full NewDeploymentService activation. The current unapproved/unsupported full A registry remains fail-closed; it was not auto-frozen.

Startup read-only strict SHOW GRANTS fixture tests additionally pass control-valid, base-formal-role-only rejection, missing source-owner mount and Generate-issuer reuse rejection, alongside all prior startup cases (package3.309s). Related original journal/producer/startup regression PASS12.412s. Full affected non-SQL regression previously passed; service pull handler is still separate WIP and uncommitted pending actual original CE plan/Job/observer integration and final-SQL source-grant replacement negative. Its server now does an independent bounded source-grant re-read AFTER the final original SQL; no Kube/provider network follows that local check. A component pass does not establish artifact/finalizer success.
