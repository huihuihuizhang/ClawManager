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

## 现场事实边界（最终集中更新）

未提供真实安装签发者记录/独立部署 pin、真实 owner task/workload 授权和现场 JWT/Transit 回执；代码接入和本地拒绝测试不能替代这些事实。本轮不索取或生成生产秘密。
