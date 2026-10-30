# A：执行密钥、KEK 与三用途签名集成复审

2026-10-30；复审基线 `1b51175e`，包含 A 的 `8c1acdcc`。本结论来自当前生产源码的调用搜索与接口核对；既有本地 fixture 测试不等于现场调用回执。

## 已接入的原链路

- 生产 controller `cmd/system-backup-v2-controller/public_capture.go` 调用 `NewDeploymentService`，后者组合原 `NewPublicCapture`。forward、独立 recovery、worker mTLS/TokenReview、加密执行日记与 functional task key 仍走该链路，不建立第二套执行授权。
- `PublicJobOwner.Authorize` 的 functional `acquire/complete` 在原 Job 行锁内派生 staging key，原事务提交为准入顺序点；已准入 worker 的停止仍需 `StopJob/Stopped` 证明。该 key 不是正式 backup KEK。
- `systembackupsecurity` 的 bootstrap/config mutation 原事务已调用 `stageBootstrapKEK`；D 的 registry Store 可保存精确 binding、用途/版本、撤销和历史引用事实，A 的 `PreparedAdmission.Recheck` 要求独立 mapping、两用途 capability 与完整 coverage。
- 公共 C 的原签名输入与 envelope 合同已有固定向量。A 的 `NewOriginalSigningResolver` 和 `NewJWTSigningTokenSource` 可构造三用途独立的短期凭据，并复用 `NewCredentialTransitSigner`，不改变签名原字节。

## 尚未接通的生产接点

| Owner | 当前源码事实 | 必须交付的接线与可验证回执 |
| --- | --- | --- |
| C/D 原 KEK 来源 | `BootstrapAdmissionSource.BootstrapAdmissionInput`、`MutationAdmissionSource.MutationAdmissionInput` 只有接口；`BootstrapComposition`、`MutationComposition` 只有构造实现，未发现生产 caller。`Bound.CompleteScan` 恒返回 `ErrKEKCoverage`。 | 从原注册/配置记录独立读取完整 mapping 与两用途能力；在同一 KEK fence 下完成 retained、inflight/unknown、hold/catalog、restore/prune 四分区历史回填和 writer 钩子，再把 composition 注入原 bootstrap/config mutation caller。提交后读回精确安装、identity/opaque registry version、provider numeric version、原 ref 字节与 SHA、撤销和引用。禁止把候选 JSON 或现有配置自身当独立来源。 |
| B capture | `worker.NewCaptureKeyJob` 在生产源码中尚无调用；它要求原 `Invocation.ProviderKey`、`systembackupkms.Config`、受控 `PermitMount`。 | 从最终 writer 的冻结 C `KeyBinding`、`KeyContext`、part/part_index、原 task/attempt、invocation SHA 与原 Job/Pod/SA 身份构造，不接受请求自报；接原 mTLS 控制的 reserve/begin/end，在实际 provider generate 前后复查。提交源码符号、镜像 digest 与合法/错用途/跨安装/错版本/撤销回执。 |
| B/D/C 签名 | `NewOriginalSigningResolver` 仅在测试中实例化；三个 `OriginalSigningAuthority.AuthorizeSigning` 原业务 reader 和生产 signer caller 均未发现。 | B 从冻结 capture 正文和完成证据调用 `capture_certificate`；D 在原发布事务事实下调用 `acceptance_record`；C/D 从不可变 catalog action/引用调用 `catalog_record`。各自重建 C 的原始 signing input 并比对 SHA，认证当前用途、安装、key/version、工作身份、期限及撤销；从独立历史 reader 取公钥，配置三个独立 JWT role/policy 和当前 source Recheck。 |
| D/B 运行与撤销 | functional staging key 的本地授权顺序已收紧；真实并发行为未测。 | 用包含本提交的新镜像验证原 Job 行锁与并发 Revoke 的顺序，以及已准入调用的 `StopJob/Stopped` 证明。forward 关闭时独立 recovery 必须仍可按旧 ref/version 读取历史日记；不能借失效 forward 恢复。 |

生产 readiness 目前仍明确拒绝 acceptance：`deployment_service.go` 的 `system_backup_v2_execution_readiness` 写入和 `deployment_platform.go` 的 profile 都将 `acceptance_ready` 固定为 `FALSE`。当前生产构造路径也没有给 `worker.Invocation.ProviderKey` 赋值；`NewCaptureKeyJob` 仅存在于定义和测试。B/D 必须提交原冻结 writer、ProviderKey 来源及 acceptance 发布接线，读回 readiness 和原 Job/SQL 记录后，才能开始正式 capture/acceptance 的现场验收。现有 OpenBao trust/key profile 回执不能替代此接线。

### recovery-only 启动复审（生产入口已修正，部署验收待完成）

原问题是 `NewDeploymentService` 在 forward grant 缺失/失效并关闭 forward 后，仍核对完整 capture/runtime-control 表权限。D 的 `b0a1015f` 令该 probe 只在 forward 模式运行，但 A 复审又发现生产命令在进入服务前无条件检查 capture 权限、失效 forward 的残留 profile/issuer 可阻断恢复，且 `/readyz` 会误报 `effective=enabled`。D 的 `ab9c3510` 将生产数据库入口改为原签名 Recovery 身份准入、失效或显式关闭的 Forward 指针切回独立 Recovery，并按实际 `ForwardEnabled` 报告健康模式；`PublishReadiness` 仍拒绝 recovery-only 的 forward 公布。本地签名 grant/隔离 SQL driver 与 HTTP 回归通过，覆盖过期或错配 forward 降级、错误恢复身份/账号/用途/key/签名拒绝和健康状态；这些测试尚未证明完整 Linux/Kubernetes 启动、真实 MySQL 仅恢复账号、旧 ref/version 历史读取、worker 禁发及 forward readiness 的现场拒绝。部署验收仍须逐项覆盖，不能通过给恢复账号补全 capture 权限来掩盖原问题。

## 材料与测试口径

### 10 月 30 日 D 现场增量的 A 复审

- `21dd2905`、`2c340c86` 记录了隔离测试 Pod 的 Agent 停止和恢复：原 PID 78、恢复 PID 87，原始回执字节与 SHA 已固定。它证明这一临时 Agent/镜像组合的生命周期调用，尚未证明生产 controller、真实用户实例、原 SQL 停止证明或最终 capture。
- `849a4e1b`、`bd38b9c7` 提供随机 namespace、两个一次性 PVC 的跨节点 seal 能力探针及固定镜像 digest。A 核对外层仅在内层 `execute=True` 探针正常返回后才标记 `passed`，失败与清理失败均抛出；本地 5 项 Python 测试通过。尚无 Kubernetes/Longhorn 现场回执，更不能据此放行生产 staging PVC。
- D 的隔离数据库副本预检 `35252e15` 已现场运行并清理；A 复审指出同名 MySQL Pod 替换可能使后续写入或清理落到另一实例。`834026bf` 已在每次操作前复核 namespace UID、Pod UID、server UUID，并在实际 CREATE、导入和 DROP 的同一次 Pod shell 内再次核对 server UUID。A 已核对提交的三处调用；修订版仅通过本地 Bash 语法检查，**尚未现场重跑**，旧现场回执不能证明新修订的运行结果。副本测试不等于现库迁移授权或数据保全验收。

上述增量没有提供 B 的最终 capture writer、正式 `NewCaptureKeyJob` 生产调用、原 KEK 映射及历史引用扫描、三用途签名业务 reader 或正式 provider role/permit。因此原表中的生产缺口和拒绝状态继续有效。

### C50 合并后的独立 recovery 复审

共享基线 `05c2f897` 接收公共 C 的 recovery 库存增量。A 逐项核对了 `recovery_inventory.go`、`execution_capture_gate.go` 与 `public_recovery.go`：丢失的 pause intent 仅在冻结 writer 清单、participant checkpoint 摘要及原 recovery 授权的同一事务下重建；重建行保持 `paused=false,resumed=false`，不能铸造停止或恢复 ACK。最终释放再次锁定库存，逐项要求原 writer 已恢复、participant 回到成功状态；`CollectorsStopped` 还要求已创建的 Job 同时有停止时间和撤销标志。恢复路径没有改用 forward grant。

这项源码接线仍需真实 SQL 锁序、旧引用及 worker 停止证明验证。C 的 `system_team_data_backup_jobs` 是独立业务任务，不能替代公共 `system_backup_v2_*` 的 KEK 历史映射或三用途签名。C 提议扩大的五张控制表仍处 `pending_owner_review`，D 保留原 35 表 fail-closed；A 不将其计为已准入。

A 曾启动 C50 后的四包隔离缓存回归；运行中 D 连续修改 `systembackupexecution`，该轮源码快照不再能证明稳定提交，已主动中止且未取得通过结果。专用 Go 缓存和临时构建目录均已删除；待 D 提交后针对受影响包复验。

复用已固定的 OpenBao v2.6.2、JWT trust readback SHA `595ab8034b889490a055b56094ffdd1d71ace5a188d10fa77eab19d3deb89244`、backup KEK v1 profile SHA `fd5c182837152d128d00ece72520a90baa924d07cc76311f151f4f2ab05d4e9f`。这些公开回执证明配置/属性，不证明 role、policy、permit、任务授权或真实 generate/unwrap；不重复昨日采集。

现场正式材料尚需：原 mapping/coverage 来源及 SQL 读回、B 冻结任务上下文和最终 writer、三个签名用途的原业务 reader、受控 provider role/policy/permit/JWT 引用、新部署镜像摘要、历史 ref/version 与当前独立 recovery grant。凭据、JWT、私钥和 DEK 只走受控挂载，不进 Git。没有这些材料时，生产 caller 应继续拒绝；本地测试只报告合成材料的结果。

### 端点校验复审增量

`818870bf` 将正式 KMS、候选解码/准入和 Transit signer 的 provider URL 收紧到有实际主机名、无路径、查询及片段分隔符；`fed94238` 将 worker 的原 Job 密钥预约入口与该规则对齐，避免无效端点先消耗单次预约。合成材料下 KMS、候选准入和候选解码包通过；签名端点定向测试与 worker 控制请求定向测试通过。签名包全包测试在既有 `TestBootstrapCandidateServiceConsumerIntegration/late_rbac_removed` 上达到 180 秒超时，不能报告全包通过。两轮隔离构建目录已删除。

另一 A 窗口维护的 `OriginalSigningResolver.exactSigningEndpoint` 仍只检查非空 `Host`，可在构造阶段接受 `https://:8200` 或尾随空 `#`；实际 `NewTransitSigner` 已拒绝这两种地址。应在该 resolver 的下一次提交中对齐校验并添加构造拒绝用例，避免配置先被接受、实际签名才失败。此发现不改变现有签名原字节或用途合同。
