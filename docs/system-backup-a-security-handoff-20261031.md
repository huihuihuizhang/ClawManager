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

- 监督者本机 MySQL 8.4.13，loopback端口59355，固定server_uuid `b9c4d686-d4d3-11f1-9eb5-745d22085e06`，未访问远侧。
- `go test -mod=readonly -p=1 -count=1 -tags=systembackup_mysql -timeout=180s ./internal/systembackupsecurity -run '^TestSQLSigningOwnerMySQL$' -v` 退出0；测试3.60s，进程包6.117s。
- 增补真实CHECK损坏拒绝并带三个历史seed回归后，最终 `-run '^Test(SQLSigningOwnerMySQL|(AConfigProof|DConfigWriter|DConfigMaintenanceReceipt)MySQLSeed)$'` 退出0，MySQL测试1.38s，包3.866s。旧tagged seed的候选SQL摘要仍指表名适配前内容，现按仓库中原fixture的**完整LF字节**重新固定两个测试pin，并显式LF归一化；不改fixture SQL、迁移或生产信任pin。错摘要/错字节/重复字段/未知字段负例继续拒绝。
- 三用途自动SQL→JWT→TLS Transit→历史公钥独立验签实际成功。源记录来自原backup/attempt/source journal/capture_result；Stage原事务回滚后不可签，提交后可签，原字节重复freeze幂等。
- 独立SQL签名用户只有六表SELECT及evidence INSERT，实际UPDATE源task和DELETE evidence均被MySQL拒绝；原owner推进claim版本后旧signer在登录前拒绝。
- 按本轮随机数据库/用户名、原服务器UUID与fixture marker核对后清理本次资源；未修改其他schema、系统库或停止共享服务器。该测试的最小DDL验证真实事务/CHECK/grants，不声称整套应用迁移/FK或正式六域业务采集通过。

## 现场事实边界（最终集中更新）

未提供真实安装签发者记录/独立部署 pin、真实 owner task/workload 授权和现场 JWT/Transit 回执；代码接入和本地拒绝测试不能替代这些事实。本轮不索取或生成生产秘密。
