# 原本停止实例物理证明最小接线合同草稿

供 root 和 A 审核；只提出接线合同和文件范围，不修改生产代码。目标是保留原本停止实例，并证明它在同一完整备份窗口内一直不能写、收尾后仍保持停止；不启动它，不用 SQL 状态或登记回执证明物理停止。

## 复用当前 A 候选

沿用 `.a-agent-stopped-52f47fc-20261102/source/clawmanager-agent`。当前可读的 `gateway/backup_protocol.go`、`slots/backup.go` 已有隔离备份请求、slot journal 和共享 writer reservation；`BackupRequest.Valid` 仍要求 ExpectedPID>0、ResumeGeneration>Generation，`stopForBackup` 初次进入仍要求 GatewayState 为 running 且 PID 匹配。因此不能把 ExpectedPID 改成 0 后直接声称它支持 originally-stopped。

可复用 `slots/command_writer.go` 的共享 writer 文件锁、精确 generation 检查及失败隔离机制；可复用 gateway 隔离生命周期和 `isolated_recovery_linux.go` 的 boot ID、PID start ticks、受控 process store 与 `/proc` 检查。maintenance command 当前会写 upgrading 状态，不能直接调用它来生成“保持停止”证明。A 候选仍可能继续变化，下面要求由 A 在该候选上扩展能力并冻结新合同，不重建旧分支。

## 最小合同和调用顺序

1. **从原冻结集合识别实例。** D 只消费 controller 已认证的原 Discovery、writers、SourceInventory 和 CaptureMetadata。要求原 writer 为 stopped/id、Original.Running=false，instance 身份/generation、checkpoint hash、RuntimeWriterSpec digest 与冻结 mount/policy 一致。SQL source row只用于防漂移比对，不决定物理真假。原本运行后被暂停的实例继续沿既有协议，不混用两个分支。
2. **冻结原节点、卷和模板身份。** 从原授权 owner mapping 与 pre-capture API 观察固定有限 node 名/UID、namespace UID、PVC/PV UID/spec SHA（或原 NFS server/export）、workspace subpath、runtime policy/template digest。实例无 Pod 时不得编造旧 Pod UID，也不得在收尾采用现有卷、现有模板或任意空闲节点补齐原 pin。若当前停止实例只有 SQL locator/空 material，须先补 owner 提供的原始模板与节点来源，否则在暂停任何源之前拒绝。
3. **先核对实际能力，后做 reservation。** capture DependenciesReady/初次冻结阶段验证原 observer/agent 身份、Linux 观察范围和可用性；这时不能伪造尚未取得的 gate epoch。原 gate acquire 后，由 stopped writer 的 before-stop/Pause 在同 task/attempt/epoch 下请求独立随机 challenge 的原始停止 reservation，绑定 config、writer checkpoint/spec digest、实例/用户/generation、原节点 UID、卷/模板 pin、observer pod UID、agent epoch、scope 和原到期时间。nonce 由 controller 受控生成并原样保留；不能使用随重试变化的 NOW 或另开任务。
4. **真实双重观察。** controller 对原 namespace 做完整有界 API 观察，覆盖 instance/user/generation 的 writer Pod 与 owner 链；不能只 GET 一个旧名称，Pending、Terminating、未知 owner 或 list 不完整均不得当作不存在。实际 native observer在其声明可见范围内核对受控 writer ledger、持有跨 create/upgrade/reconcile 路径生效的原锁，并检查实际进程、namespace、mount/打开 writer 和可能的残留后代。API 无 Pod只是一半证据；/proc 只看 observer 自己 PID namespace 时不能证明 Pro/其他 Pod 中没有进程。观察权限不足、旧锁状态未知或残留进程均拒绝且保留隔离。
5. **原窗口内持续保证。** 独立认证的响应必须回显完整 request/challenge、observer 身份、原 node/volume/template pins、原 reservation ID、观察时间及原 expiry，并限定结论为 still-stopped。Pause、每次 CheckPaused 和 post-collector/pre-FinishCapture 均核对同 reservation，native 锁持续阻止新 writer；不能在 SQL 事务内网络调用，不能在 recheck 续期或换 observer 来延长原窗口。
6. **停止实例 Resume 表示解除备份 reservation并保留停止。** 所有 collector 已被真实停止且当前 recovery fence 有效后，独立 observer再次确认仍停止，完成 release/complete；不得发送原 gateway resume、CreatePod 或增加 generation。未知 ACK 必须用同 request/nonce查询原状态，不能先删除 journal 或重新 reserve 抹掉不确定性。异常时保持 durable reconciliation，不写“已恢复”成功标志代替观察。
7. **进入原 SourceRecovery 证明。** D 保留原始认证响应字节和 request hash，A 验证 issuer/transport身份、scope、pins、epoch及时间。`ObserveSourceRecoveryRuntime` 返回独立 stopped facts；`observeSourceRecovery` 单独构造 stopped leaf，不要求虚构的 Recovered Pod。`validateProducerLeaves` 必须增加严格的 stopped 分支，将原 frozen stopped state、正向 native stopped witness、API全量观察、卷/模板 pins和同 reservation 的最终状态合在一起验证。只在原 FinishCapture 事务注册原 proof root/leaf，既有 SQL参考只负责防漂移，不能成为物理证明来源。

## 最小文件范围

| owner | 文件范围 | 目的 |
| --- | --- | --- |
| A native，现有候选内 | `gateway/backup_protocol.go`、`slots/backup.go`、`slots/writer.go`、`slots/worker.go`；仅必要时扩展既有 gateway Linux 观察文件 | 增加独立 originally-stopped 请求/响应、持久 reservation 和真实观察；复用现有鉴权和原锁，不弱化 running 协议。若当前隔离 agent无法观察 Pro节点，则先交付真实 node/CRI observer 合同，不能把 slot能力扩大宣称为整节点能力。 |
| D 与 A 原协议消费 | `backend/internal/services/runtime_agent_backup.go`，必要的新 stopped wire 文件；`systembackup/publicadapter/writers.go` 与 `runtime_control.go` | 添加 typed native client、原 stopped spec/pins及 reservation 生命周期；停止实例不执行 start/resume。 |
| D 原冻结与物理观察 | `systembackupexecution/production_source_runtime.go`、`production_source_profile.go`、`deployment_source_recovery.go`；必要时只扩展 `productionCaptureMetadata` | 初始冻结实际节点/卷/模板、能力预检查、原窗口内完整 API 观察与独立 native observation。不能在 capture 后补原 pin。 |
| A/D 原收尾验证 | `systembackupcontroller/runtime_source_recovery.go`、`runtime_source_recovery_semantics.go` | 消费完整 stopped proof，替换当前无条件拒绝的分支，保持 exact原集合、原事务、原引用和 epoch 约束。 |
| root 后续验证，另行授权执行 | 上述对应负例及真实 native/SQL 集成测试 | 旧实例持续停止、并发 start被拒、残留子进程、namespace不可见、节点/卷替换、旧nonce/旧epoch、observer重启、断线/ACK未知和释放失败必须覆盖；本次未执行。 |

## 仍缺的真实观察来源

- 停止 Pro 实例的**原模板和有限节点授权来源**：当前 runtime control 的 stopped material 为 `{}`，没有原 Pod 的物理 checkpoint，不能从这份 SQL capsule恢复出真实模板或历史运行节点。
- **Pro 节点级 native/CRI 观察者及其身份授权**：现有 Lite slot 内 `/proc`、GatewayState 或 Kubernetes Pod不存在均不能证明别的 PID namespace中无 writer；必须明确 observer 对哪些节点、容器、进程与挂载有实际可见性。
- **所有可启动 writer 的路径共享且持续生效的 fence**：原 create/reconcile/upgrade/agent 入口须受同 reservation 约束。单个 API名单、flock文件存在或 ledger文本不是全路径排他证明。
- **任务/epoch/challenge 与原卷/模板绑定的 native持久响应**：当前 running 协议 receipt未直接包含该完整 stopped合同；需 A 在既有候选补齐并提供冻结字节/schema，D再接，不自行制造响应或 SQL成功回执。

上述任一来源未到位，继续保留当前安全拒绝。不从fixture删除原 stopped实例，也不以 functional_test、SQL flag、空数组或仅元数据回执绕过。

## 剩余 24 个 owner 的真实实现状态

全树非测试 `BootstrapResourceValidator.Prepare` 实现目前只找到 RBAC、issuer registries、nonce 和 CA。前两者已覆盖 main 的三个 registry，后两类覆盖另外三个 reference；它们都不属于“接三项后剩余24”的集合。因此，**剩余24项中，没有一个完整的 BootstrapResourceValidator 可直接填槽即用**。这与“已有可复用客户端/领域验证逻辑”严格区分；也不表示远端服务一定不存在。

| 槽位集合 | 当前真实实现可复用到哪里 | 尚无的来源或接线 |
| --- | --- | --- |
| `reference:kek` | `systembackupkekadapter/bootstrap_source_factory.go`、`bootstrap_source_sql.go`、`coverage_owner_sql.go` 提供真实 SQL原始 mapping/capability/coverage准备；D有同事务 KEK消费。 | 不是现成的 resource validator替身；实际 original mapping、两用途caps、已adopted coverage和独立证据尚未提供；main未接独立 KEK。 |
| `capture_signing`、`acceptance_signing`、`catalog_signing` | 实际 publication signer/Transit客户端、原签名记录与分用途权限验证已存在，Vault现场有三用途公钥回执。 | 缺首次bootstrap的 owner Prepare/Recheck adapter及该安装真实授权/历史来源；客户端构造和公钥存在不能填owner槽。 |
| `catalog_read`、`catalog_append`、`catalog_snapshot` | C 的 publication catalog target、签名历史和当前独立读回可复用精确对象、凭据与scope检查。 | 未找到三槽的 bootstrap adapter；实际首次安装原catalog/快照完整性与原始 owner证据未进入main。snapshot完整来源不能由当前LIST补成。 |
| `artifact_write/read/delete/upload_issuer`、`evidence_store/write/read/delete/evidence_kek` | 现有artifact/evidence provider与凭据/加解封/读写逻辑是领域执行组件，适合由对应owner复用验证事实。 | 未找到这9槽的生产bootstrap validator；首次安装准确scope、用途隔离、原始保留/删除/历史密钥来源未在该入口实现完整Prepare/Recheck。 |
| `status_relay` | 既有 mTLS worker control、Job/task/attempt及密钥使用通路可复用。 | 未找到bootstrap status_relay owner adapter或与首次安装原始purpose绑定的完整来源；不能把服务健康或relay自报当授权。 |
| 6 registry：`parts`、`redis_sources`、`failure_domains`、`disaster_identity_mapping`、`source_writers`、`secret_allowlist` | 已有capture模块/Redis策略、failure-domain/Secret policy、writer registry等下游领域结构与核对代码。 | 当前bootstrap仅有registry文件读取与摘要检查；未找到这6槽的实际owner validator。各registry真实owner授权和完整来源需逐项交付，不能因为下游有结构就声称准入来源齐备。 |
| `cross_resources` | BootstrapConfig做有限结构/数值/闭集校验。 | 未找到完整跨资源原始权威来源和生产validator；安装、版本、scope、用途隔离与保留关系不能用各单项bool相与替代。 |

合计为 1 + 3 + 3 + 9 + 1 + 6 + 1 = 24。归属仍按既有 `docs/system-backup-a-bootstrap-resource-handoff-20261022.md` 的分项 owner，但“真实实现状态”由本轮当前源码搜索确定，不继承旧文档的完成结论。该方案仅供审核，未改生产、未构建、未测试、未远测或提交。
