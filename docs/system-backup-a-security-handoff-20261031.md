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

## 现场事实边界（最终集中更新）

未提供真实安装签发者记录/独立部署 pin、真实 owner task/workload 授权和现场 JWT/Transit 回执；代码接入和本地拒绝测试不能替代这些事实。本轮不索取或生成生产秘密。
