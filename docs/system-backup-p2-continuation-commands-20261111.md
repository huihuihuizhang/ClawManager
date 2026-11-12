# 本次安装最后一轮接续命令与依赖

本文件保留 2026-11-11 离线核对的命令账本，并在开头追加次日操作员回传的现场结果；账本中的未执行步骤不能视为完成。所有 `*_F / *_H` 都必须从指定的真实回执或原始文件 pin 取得；它们不是允许手写签名、配置或“通过”状态的占位符。未知发送只读回原操作，不能重新 issue/apply。

2026-11-12 接续记录：现场已完成 runtime TLS 轮换和实例恢复，以及 Vault 固定镜像版本验证、持久化安装、JWT 加解密检查与重启读回。Vault owner 为 `/root/sbk/p2-cert-renewal.1KyqMtsd/vault-owner`，原报告 SHA256 为 `81f3158b175b13ad8eb1ce645c7c5d9214fb55c058d9f55a628b495ab190161f`；`production_owner_mapping_registered=false` 仍未消除。Node observer 新 PKI 尚未加载，配置登记和整单验收尚未执行。

续签后的配置生成必须显式追加 `--runtime-agent-tls-file /root/sbk/p2-cert-renewal.1KyqMtsd/runtime-agent.receipt.private.json` 和 `--runtime-agent-rotation-file /root/sbk/p2-cert-renewal.1KyqMtsd/runtime-rotation/completed.json`，并分别给出原始文件 SHA256。生成器检查两份真实材料的 CA、窗口、Namespace UID，并与所选完整记录中的 App CA ConfigMap、环境 pin 和两份 runtime Secret 挂载比较；这些记录比较不代替原作者的实时核验。它不改旧 writer selection，也不再静默复制其中的旧 CA。

上传后先校验原始 SHA，再把作为输入读取的 Python/JSON 文件设为 `0600`、ELF 设为 `0700`，目录设为 `0700`。本轮 Vault 第一次入口仅因安装器 `0644` 被拒绝，确认 owner 尚不存在后仅调整该文件权限并接续原输入；原失败日志和 intent 均保留。原 owner 返回非零时，修复后的 wrapper 同样非零退出；不能根据 wrapper 的进程退出码单独判定 Vault 完成，仍读回原报告及实际持久化/JWT 结果。

当前 App `322ba63b…` 与 worker `f125b3ee…` 的 OCI config 都没有 revision 标签。Go `-trimpath` 省略构建参数，不能从 ELF buildinfo 中缺少 `-ldflags` 推断内部版本为空。后续实际两个 App 启动日志均为 `page-20261105-03fa0a461930-tls-80628842` / `03fa0a461930642f1f0561ab872f35be0402468d`，三个版本覆盖环境变量均不存在。该现场读回保留为原 App 基线，不冒充新固定源码发布。只读 OCI DATA 导出可保留无标签的真实字节，完整配置编译仍拒绝据 tag 猜 BuildCommit。

`publish-p2-execution-candidates.py` 仅接受 `eca964d42b96c31cb381531889a39c23a366ffab` 的实际二进制构建回执，以原 App `322ba63b…` 和原 worker `f125b3ee…` 为固定底图，各增加一层，仅替换对应 ELF。原命令、环境、用户、工作目录、既有层不改。新增真实源码、二进制摘要及 backend tree 标签，只按不可变 digest 发布，不改 tag、不部署。随后复用固定哈希的原 `registry_image` 逐层校验压缩/解压摘要。发布及 OCI 字节通过仍不代表候选已经启动、已获原生任务权限或整单验收完成。

该发布已在现场通过：App `10.130.14.23:5000/clawmanager@sha256:8287aa71bcfc9e1596d761a9b46891575f3708323300839c98e075a22875e780`；worker `10.130.14.23:5000/clawmanager-backup-worker@sha256:754cfd2cd57357d148daf131ead46ec715db9e34d6cd5a5a5d03c59c52e22218`。两份 `registry-byte-verification.json` 保留在 `execution-image-candidates/{app,worker}`；尚未部署。

原 `GenerateOriginalObserverPKI` CLI 的 stdout 不是 host-materials `decodeExact` 所要求的 canonical JSON。`base-observer-definition` 现在把实际 stdout 另存为字段不变的 canonical ASCII 投影，并保留原 pin 和投影来源记录；不改证书、密钥文件或签名 payload，不重新 issue。现场已用同样规则通过原 host-materials 作者。随后从原运行 Pod 读回 Agent ELF：Hermes `be46bb05…`、OpenClaw `bc1ef9ab…`，均与 P1 的旧 Agent pin 不同；原作者已据此产生 `observer-host-current-agent` 的新 NodeBundles，尚未安装。

本次专用 `rotate-p2-node-observer-certificates.py` 从上述完整原 NodeBundles 提取小型私有载荷；准备前读回 controller 未启用、ready marker 不存在。节点执行时核对原 unit SHA、运行中 ELF/argv、Node machine/boot、原证书与 anchor 摘要及未变的服务路径；只允许两种 Agent 摘要参数变化。四个 observer 停止后取得原 `.owner.guard` 的锁，并再次确认原目录没有任何 durable 操作记录，才原位替换证书/anchor 和必要 unit 参数。保留每份原文件作 CAS 补偿，保留持久目录及 guard inode，逐服务检查启动成功。任何已有恢复记录、未知发送或漂移都停止，不能删记录绕过。完成后还需从管理端按新 receipt 验证全部八个 mTLS endpoint；此轮不提供 Longhorn 停写或整单成功声明。

该节点轮换已现场通过：两台节点分别输出 `NODE_OBSERVER_CERTIFICATES_ROTATED`，管理端输出 `NODE_OBSERVER_RENEWAL_ALL_TLS_PASSED`，精确覆盖两节点四种 endpoint；结果保留在 `node-cert-rotation/node-mtls-readback.json`。不再重做证书签发或节点轮换。

下一步 `activate-p2-app-execution-image.py` 先创建有 UID journal 的两个短暂探测 Pod，App 仅调用无 DB/监听器的实际配置导出入口并比较原配置，worker 不带任何凭据或控制授权，必须实际启动后拒绝缺失请求。原部署有两个 init，且 `sbk-app-backend-release` PVC 的文件遮住 `/usr/local/bin/clawreef-server`；第一次只镜像入口检查已在创建 plan/Pod/patch 前拒绝。修复版逐一匹配这两个原 init 的命令/参数 SHA 与只读挂载，仅解除旧程序文件挂载、其 `verify-sbk-app-backend` 校验 init 及未使用的 Pod volume 引用，保留 PVC 对象和文件、`wait-secret-broker`、全部业务卷/配置/凭据。探测从该精确后继 spec 创建，确保实际使用镜像内新 ELF。探测 Pod 删除读回后，对完整未变原 spec 作 CAS 更新；要求原两副本 RollingUpdate、现有 SQL gate 为 installation、续签 CA 保留，不执行自动迁移。最终读回每个 App 的 ELF、CA、SQL scope、实际启动版本、配置及运行实例。它不启用 controller 或提交任务，worker 的拒绝探测不能充当正式 capture 验证。

第二次探测已删除，但停在 `wait-secret-broker`，主容器为 `PodInitializing` / 空 imageID，尚未发送 App patch；该状态不应报作镜像摘要不符。已有 broker ingress 仅允许 `app=clawmanager-app`，独立探测刻意不使用生产 Service 标签。当前接续仅为无网络需求的本地配置导出探测省去依赖 init，生产 spec 仍保留原 broker wait，不修改任何网络策略；发送前先从现有 App 做限时、验证 CA/hostname 的实际 broker TLS 握手。原失败 Pod UID/终态与发送记录保留，只有确认旧 Pod 已删除、原 App spec 未变且无 patch intent，才建立独立的 `app-local` 只读探测记录。探测必须先真实终止，再核对 imageID 与结果，避免再次把未启动误判为镜像不符。

上述 App 接续已现场通过：原 App 的 broker TLS、两个入口探测、两个实际副本的 ELF/CA/SQL scope/有效配置/启动版本均读回一致，运行实例仍为 `[1,2,3,7,8]`。完成记录为 `execution-app-rollout/completed.json`，两个新 Pod UID 为 `62d61dc2-f8b1-4ffd-945a-1b539149b5ae`、`7a7e7e7f-dffa-451d-969b-67f335acb44f`；不再重做 App 切换。

后继 `prepare-p2-controller-relay.py` 复用原输入 PVC、两容器和原等待 shell，先 create-only 传输固定 SHA 的 v2 controller/C1 CLI 并在控制器侧读回，再以完整旧 spec CAS 固定两容器的已发布 App 基础镜像与等待程序。始终要求 `SYSTEM_BACKUP_ENABLED=false`、无 ready marker，不传 `controller.env`，不启动控制器或 relay。然后调用原 `relay-pki --mode issue` 与 `runtime-issuers --mode export-record-keys`；只有真实回执及文件 pin 读回才完成。六个必要原生工具均从与 App 相同的 `eca964d4` / backend tree `6361d0c8…` 构建；v2 controller 显式链接 `p2-eca964d4` 和真实提交，避免默认 unknown 版本被后续 publication source facts 拒绝。六种 purpose signer 不搬出原目录，只按原作者导出两份 random32。此阶段不声称 relay 已服务、配置已登记、controller 已启用或整单已通过。

## 1. ConfigurationData 的生成入口已分离

控制器首次镜像 patch 已现场生效，`read-00011` 停在 rollout 等待；新 controller 容器正常，installation-owner 以退出码 1 重启、日志为空。现场原命令 SHA 为 `3f6e6fb2e0728492f3372d4f879cbcfe0812dc279d485e769a897c69fd05b273`，要求目录 `65532:700`；node1 实测原 private PVC 中 `installer` 为 UID/GID 65532、mode `2770`，而 inputs 中 runtime 仍为 `700`。此时 relay PKI 未发送，三个 PVC UID 与绑定保持原值。

该权限接续已现场通过：新 Pod `sbk-d4f51b83b57e-controller-7b85dbbd7d-gbgg4`，UID `4aed9e71-693e-4440-b81e-f66cb55c351e`，输出 `P2_CONTROLLER_OWNER_PRIVATE_DIRECTORIES_READY` 和 `P2_CONTROLLER_WAITING_ROLLOUT_SETTLED_NOT_ACTIVATED`。同批原工具随后完成 relay PKI 及两份记录密钥导出，最终输出 `P2_CONTROLLER_RELAY_INPUTS_PREPARED_NOT_ACTIVATED`。原 record export pin 为 `24f53cf980bd1a7898b80879a8089bad1f221704cf2737f270be5b5876b74fef`；原回执与权限后继分别保留在 `controller-relay` 和其 `owner-directory-permissions` 子目录。控制器仍禁用，relay 尚未服务，不再重发本批签发或权限修复。

`settle-p2-controller-owner-permissions.py` 只接受这份已发送 desired spec、精确原 owner 命令及三个原 PVC，补入 `fsGroupChangePolicy=OnRootMismatch`；owner 仅在原 installer 目录非 symlink、UID/GID 均为 65532 且权限恰为 `2770` 时非递归恢复 `700`，其他未知状态拒绝。原 runtime 权限检查保持严格，不遍历或修改子文件。脚本 CAS 更新，等待实际两容器 Ready、读回目录权限与 disabled marker，并将后继记录置于 `controller-relay/owner-directory-permissions`。原 controller-plan 与原 patch intent 不改写；接续工具须验证这个完成记录绑定的原 plan pin 和派生 spec，才继续原 relay/record-key 作者。该修复的本地检查已通过；现场修复成功仍以真实回传为准。

控制器等待程序固定完成后，`refresh-p2-source-inputs.py` 在独立的 `p2-cert-renewal.1KyqMtsd/current-source-inputs` 保留新一轮只读材料：调用实际 `author-initial-source-coordinates`，核对当前两个 App、两个 runtime 的加载凭据、工作目录与续签 CA，再复用已校验的原 selection 工具执行 `prepare-selection`。新 base selection 必须保留八行 SQL 源及租户 Pro #2；不执行 stop/adopt，不覆盖 Redis/MinIO 的原完成回执。随后记录当前五组完整私有 Kubernetes API 对象；`capture-index.json` 类型为 `p2-current-kubernetes-inputs.v1`，不作为可分享的脱敏包。原操作 intent、失败输出或部分文件一律保留，未知发送不能自动重试。

该刷新已现场通过 `P2_CURRENT_SOURCE_INPUTS_READY_NO_HOLD`，坐标 pin 为 `bb211d05ceb4350f7321979b086e1a0c094958abc16dd40d92b5fbbde77ee403`，base writer pin 为 `e257df405483a0d6f7f86b94c55c1de335b6e16432d9e655a3f48a132307d8fc`。下一步 `prepare-p2-current-configuration.py` 只选择这份完成记录、实际 relay/observer/runtime PKI 和固定 App/worker 原始 OCI 元数据，编译配置 DATA 并调用原 `author-initial-source-inputs`。Core 的 Redis keeper 从独立原 Redis 完成回执及其 writer/keeper pin 交叉核对后投影，不修改新 base 或原 Redis writer。原作者发送前写 intent；未知发送与部分 native 输出停止，不能自动再发。四个真实输出 pin 全部读回且版本正确才完成初始材料阶段；此阶段仍不启用控制器或提交任务。

首轮配置 DATA 在旧 `source_core` 的宿主机路径前置停止，现场确认 native author intent 不存在。实际参与者是完整空列表，协议正确；`SharedNodes=null`，两个 Agent 的 `SharedRuntimeVolumes` 则完整指向同一 Longhorn ext4 工作卷。新 DATA helper 对这条分支要求坐标与原 writer 的完整 CSI 列表相等、覆盖全部 Agent，并逐个对照原始 Pod/Node/PVC/PV/driver/handle/container mount；返回空主机路径，不将 CSI handle 或容器路径捏造为宿主机 SourcePaths。此修改只允许初始 DATA 投影，正式执行仍必须提供后继 Longhorn 材料及真实停写证明；现有 runtime 执行检查不放宽。

`--resume-csi-data` 仅接受这次已确认的 pre-author DATA 情况：原 helper pin、原 ready-producers、当前原坐标/selection/PKI/镜像 pin 均匹配，配置文件、native intent 及部分 native 输出均不存在。接续只另存 DATA helper 后继 pin，保留原 execution window 和旧文件，不重发未知原生操作。后续若执行构造仍要求 host-path whole-node 范围，必须先补齐 CSI 与 runtime owner 的真实接线，不能用本 DATA 修复充当执行资格。

CSI DATA 接续随后已越过该检查，停在 Redis 源引用的 `ID` KeyError，仍无 native author intent。真实 `recovery.Reference` 使用小写 `id/version/sha256`，外层 RedisPolicy 保持 Go 导出字段名；配置投影按这份原始 wire 结构构造 Formal RedisScope，不接受大写替代字段。测试夹具同步采用真实字段名。后继 DATA 修复继续使用已保留的 `ready-producers.csi-successor.json` 与原窗口，不改变已有 helper pin 路径；CLI 错误只输出安全字段名和代码位置，避免再为同类缺项单独盘点，原配置和凭据正文不输出。

Redis DATA 修复后，现场已组装 `initial-source.inputs.json`，pin 为 `8394d48a963862bb0693cdc96b4884b06c8b5d9d1eccd0d4b4a14aef7c68cc55`，并首次发送原生 `author-initial-source-inputs`。该次返回非零，两份日志均空，四个输出文件均不存在；原 intent 和输入必须保留，不自动重发。原窗口 Until 为 `2026-11-12T06:56:20.550309Z`。

`system-backup-initial-source-inspect` 是独立只读诊断：按原始 definition pin 读文件，使用相同 Go 输入类型和现有 Core/profile 校验函数，检查输出坐标与原材料模板形态。该命令不接收连接/管理员/签发参数，不调用原生作者、不创建输出目录、不连接 SQL/Kubernetes，也不授予资格；结果只含阶段、布尔值和经过白名单约束的字段名，不包含解码错误里的输入值。诊断结果不能替代原材料作者回执。

该原生诊断已现场读回：DefinitionDecoded、DeploymentValid、ProfileValid、OutputPathsMatch 均为 true；Stage 为 `materials_decode`、Field 为 `CAFile`、MaterialsDecoded/MaterialsValid 为 false。原因是 `worker.ResourceSourceMount` 的 JSON tag 为 `server/ca_file/ca_sha256/token_file`，旧 DATA 模板却使用 Go 字段名。源的 CA、token 和端点本身不改动，原始失败定义 pin 保留。

`repair-p2-initial-source-wire.py` 只接受上述固定原定义、原 intent、空日志及空输出目录，并用固定 SHA 的同一只读原生工具复核失败。TLS 旧映射必须逐值等于实际 SourceAPI fragment，才可生成独立 wire-correction 候选；原 Core 和连接原样保留，四个 API 字段名改为真实 tag。新的未签名准备窗口取当前时间、API token 和两份实际证书期限的交集，不修改或延长已有 grant。新候选须先通过同一原生工具的全部六项检查，随后才写独立 intent 并调用原作者；退出码、所有原始输出均保留，未知发送禁止重试。后续消费者选择真实作者 receipt 中的四份文件 pin，不能继续消费旧失败模板或旧输入。

`prepare-p2-configuration-data.py --writer-receipt-file/sha256` 可直接消费真实 `original-writer-selection-materials.v1` 的 `Selection` 字段，也继续支持原生 material delivery 后继的 `WriterSelection` 字段；只选其真实 pin，不新造或改写 receipt。新脚本已通过加载凭据/CA/源数量拒绝检查及配置 DATA 回归；现场结果须等待实际命令回传，不能把本地测试记作 native selection、停写或整单验收成功。

真实旧链：`system-backup-zhanghui08-operator.py --action initial-source-inputs` → `initial-runtime.prepare_complete_source_arguments` → `initial-complete-inputs.prepare`。该入口先处理 provider/Redis，再生成 `initial-complete-source.inputs.json`，随后立即调用 Go 初始作者。它不是独立 DATA 导出器，且外层 operator 绑定另一个命名空间/目录；本次不直接调用它，不重跑 MinIO/Redis。

本次入口是 `prepare-p2-configuration-data.py`：

1. `--prepare-index` 从保留的真实产物建立 `ready-producers.json`，不现场手拼 Core 或捕获模板；新签发/刷新产物必须显式传入，不找“最新目录”。
2. 编译模式复用既有 `source_core`、`material_template`、`runtime_policies` 和 typed provider topology，生成 `configuration-data.json` 与 `assembly-inputs.json`。不调用 provider、Redis 或原生作者。记录内 API 对象仅表示采集时数据，不能冒充新 API 读回。
3. `assemble-p2-installation-candidate.py assemble` 校验五连接、真实账户、密钥用途与窗口，输出 `initial-source-inputs.json`。
4. `continue-p2-native-candidate.py --stage initial-source --execute-native` 才调用实际 Go 作者；退出 0 且真实回执为 `original-initial-source-inputs-authored.v1`、四个原始输出 pin 读回匹配，才完成此阶段。

依赖没有环：索引/编译均不消费初始作者的输出。原生作者只在最后一步发送一次。输出目录必须与定义内 `profile_file`/`capture_modules.path` 对应；部分输出不改写，不换目录绕过未知原生发送。

### 输入来源

| 输入 | 真实来源/取得方式 | 缺失或过期时 |
|---|---|---|
| Plan / Enrollment / IssuerPublic | P1 `fresh-backup-enrollment-r2/native`，索引固定读取 | 停止，不重做引导 |
| SQLMaterials / SQLOperation | `fresh-sql-prepare.faa4osWr/sql-operation` 的原始文件 | 查原 SQL owner journal；不从 DSN 猜 User@Host |
| Coordinates / StartupInputs | 已通过的 `p2-materials-1dd1ae71.lVSEBfl2` | 源范围变化才用实际 `author-initial-source-coordinates --running-only-runtime-test 1,2,3,7,8:4,5,6` 生成新回执，并用 `--coordinates-receipt-file/sha256` 显式接续 |
| WriterSelection | 原 Redis native finalize 的 writer selection | 有真实 Vault 等后继时用 `--writer-receipt-file/sha256` 选择该回执的 WriterSelection；不改旧文件 |
| MinIO / Redis fragments | 已通过的两个连接产物，代码内固定原 pin | 原操作 query/finalize；禁止重新 apply |
| SourceAPI / RuntimeIssuers | 已通过产物，允许明确选择真实刷新输出 | token 到期必须原 TokenRequest/身份核验；issuer 用原 owner query/prepare，不用 enrollment key 代替 purpose key |
| Raw Kubernetes index | 既有 collector `export/capture-index.json` 对应的 `remote_private_inputs` | 使用远侧完整私有记录；脱敏包作为运行输入会被拒绝。actor/Pod/卷变化后采集新的只读记录，明确选择新 index |
| WorkerDefinition | P1 `fresh-backup-bootstrap/worker-sa.definition.json` | 真实 SA UID 读回不符即停止 |
| EffectiveAppConfig | MinIO continuation 的 `effective-app-config.json`，由真实 App CLI 导出 | 配置发生变化时仅重新读取 `/usr/local/bin/clawreef-server --system-backup-source-config-data`，各 App Pod 结果须一致；不重跑 cutover |
| MinIOTLSReceipt | continuation 的 `minio.latest.receipt.json`，实际 `actual_tls_verified` 结果 | 准备态不能代替读回；必要时原 query，不能 apply |
| ExecutionProfile | 可消费既有真实 profile DATA；没有时按实际 TLS receipt/完整记录生成已有 same-cluster-copy 功能测试配置 | 保留七类风险，`attestation_missing` 不消除；不执行或声称隔离还原/灾备认证 |
| RelayPKI / ObserverReceipt | 实际 owner 签发到最终 runtime mirror 的新回执 | 旧 observer 已过期，必须真续签。签名 manifest 不搬路径、不改字节 |
| AppImage / WorkerImage | 下述 OCI 原始 manifest/config DATA | App 必须对应实际部署的固定 digest；worker 必须来自已选定的实际合格发布，不从品牌或当前 App 猜。缺合格 worker 发布输入即停止 |

运行中的 Pro 保留原 Pod spec 的 `:latest`。仅取该原 Pod UID 对应的就绪运行容器 `imageID`，要求同仓库、完整 `@sha256`；不解析当前 tag，不 rollout，不替换成 Lite。停机 Pro 没有运行 imageID 时仍要求既有不可变发布来源。

### DATA 编译命令

以下变量取自真实 producer 输出，`TOOL` 是本次冻结包，`DATA` 是新私有 DATA 目录，`MIRROR` 是实际 `/run/system-backup/runtime/...` 镜像目录；PKI 的真实签发输出必须已位于该 mirror 内。

```bash
python3 -B "$TOOL/prepare-p2-configuration-data.py" --prepare-index \
  --raw-index-file "$RAW_INDEX_F" --raw-index-sha256 "$RAW_INDEX_H" \
  --relay-receipt-file "$RELAY_F" --relay-receipt-sha256 "$RELAY_H" \
  --observer-receipt-file "$OBSERVER_F" --observer-receipt-sha256 "$OBSERVER_H" \
  --app-image-data-file "$APP_IMAGE_F" --app-image-data-sha256 "$APP_IMAGE_H" \
  --worker-image-data-file "$WORKER_IMAGE_F" --worker-image-data-sha256 "$WORKER_IMAGE_H" \
  --output-directory "$DATA"
# 如刷新过 API、issuer、coordinates、writer，追加对应的显式 *-file / *-sha256。
python3 -B "$TOOL/prepare-p2-configuration-data.py" \
  --inputs-file "$DATA/ready-producers.json" \
  --inputs-sha256 "$(sha256sum "$DATA/ready-producers.json" | cut -d ' ' -f 1)" \
  --output-directory "$DATA" --runtime-mirror "$MIRROR"
python3 -B "$TOOL/assemble-p2-installation-candidate.py" assemble \
  --inputs-file "$DATA/assembly-inputs.json" \
  --inputs-sha256 "$(sha256sum "$DATA/assembly-inputs.json" | cut -d ' ' -f 1)" \
  --output-directory "$DATA"
```

索引接续沿用第一次 NotBefore/Until；已过期即保留并停止，不覆盖窗口。生成的 `NativeOutputDirectory` 是初始作者的输出目录，应在首次 native 发送前创建空的 0700 目录；不能把 DATA 文件也放进这个要求为空的 native 目录。

OCI DATA 的准确形状是 `{Reference,Manifest:{File,SHA256},Config:{File,SHA256}}`。manifest/config 必须是 registry 实际原始字节；Reference 的 manifest digest、config descriptor 的 digest/size、linux/amd64 和真实 `org.opencontainers.image.revision` 全部校验。读取命令为固定 registry 的 `/v2/<repository>/manifests/sha256:<digest>`，再读取该 manifest 内 `/blobs/<config.digest>`；用既有 `system-backup-operator-deployment.registry_image(reference, actual_build_image, actual_build_commit)` 可做包含全部层的原发布资格核验。不能只根据 tag 输出上述对象。没有原发布期望值时先向原发布 owner 取得 build receipt，不把当前观察当作合格发布。

元数据读取已有本次实际入口，不需要手写上述 descriptor：

```bash
python3 -B "$TOOL/prepare-p2-configuration-data.py" --read-image-data \
  --image-reference "$APP_APPROVED_IMMUTABLE_REF" --output-directory "$APP_IMAGE_DATA"
python3 -B "$TOOL/prepare-p2-configuration-data.py" --read-image-data \
  --image-reference "$WORKER_APPROVED_IMMUTABLE_REF" --output-directory "$WORKER_IMAGE_DATA"
```

输出 `image-data.json` 的原始 pin 供索引使用；`NativeReleaseQualified=false` 是刻意保留的边界。这两次只读元数据请求不会验证 ELF/全部层，不代替原发布资格或实际 worker 启动验证；没有已选合格 worker ref 时不能用当前 App ref 自动填充。

## 2. 精确权限、证书加载和 Longhorn 后继

`prepare-p2-metadata-read-access.py` 从 plan、真实 SourceAPI fragment、完整 provider Namespace 对象生成独立 Role、RoleBinding、两个无自动 token 挂载的 actor SA 和 `access-guards.json`。它不调用 API，不更改原绑定。Role 仅 `longhorn-system` 中 `pods,services` 的 `get,list`；不添加 exec、写入、watch 或通配权限。

```bash
python3 -B "$TOOL/prepare-p2-metadata-read-access.py" \
  --plan-file "$PLAN_F" --plan-sha256 "$PLAN_H" \
  --source-api-file "$API_F" --source-api-sha256 "$API_H" \
  --provider-namespace-file "$PROVIDER_NS_F" --provider-namespace-sha256 "$PROVIDER_NS_H" \
  --output-directory "$ACCESS"
```

未来创建前，使用原 kubeconfig 分别 `get namespace <system/provider> -o json`、`-n <system> get serviceaccount <SourceAccount> -o json`，UID 必须等于 guards；已有 Role/Binding/actor 必须逐字段等于声明，不能覆盖。缺失才使用 `kubectl create --raw /apis/rbac.authorization.k8s.io/v1/namespaces/longhorn-system/roles -f longhorn-read.role.json`、同路径 `rolebindings` 创建绑定；actor 使用 `/api/v1/namespaces/clawmanager-sbk-validation-system/serviceaccounts`。任何 create 未知时先 GET 原名称核对，不重发。之后用已认证 sources kubeconfig 执行 `get --raw /api/v1/namespaces/longhorn-system/pods` 和 `/services`，以及其 SelfSubjectReview；读回 SA UID、两个集合成功才完成接线。

证书正确顺序为：真实 `observer-issue` → `base-observer-definition` → `base-host-materials` → 原 NodeBundles 安装和 mTLS → 原生 initial/mount 读取 → 最终 signed source registry → 最终 `host-materials`。不能等 Longhorn 作者完成后才首次加载新 CA，否则 mount/native 读取会仍遇到旧 CA。

`base-observer-definition` 输入 P1 的无 Longhorn host definition、新 observer definition/receipt，保持原二进制/CRI/目录，不能从已有 final hold 定义降级。`base-host-materials` 与 final host 调同一原生 CLI，但明确没有 LonghornVolumes/SourceRegistry，不声称物理停写。Node bundle 是原作者输出的精确 flat tar，先校验 pin，再运行其 `install.sh --apply`。发送未知时检查原 bundle/安装记录，不换 CA 或删除原记录。

原生 material delivery（Redis、provider、MinIO 及 source API 后继）可能同时产生新 Deployment/Core、template、selection 和 controller patch。先完成本次确有需要的 delivery、保留每份真实回执，最后才执行 `prepare-mount-materials` / `AuthorLonghornHold=true`，然后冻结新 Core；之后任何再改变 Core 的操作都必须重新走真实后继及签发，不混旧 Core。

## 3. 从真实签发到配置登记的命令账本

所有 `OWNER` 参数使用既有 `retry-p2-writer-selection.py.owner_arguments()` 的本次 P1 plan/public/enrollment/kubeconfig/installer DSN/CA/admin-password 文件；路径及哈希只用于定位，真实身份仍由 Go owner 验证。下面的 `pinflags(X)` 表示精确的 `--x-file <真实输出.File> --x-sha256 <真实输出.SHA256>`，每个输出来源列于表中，不允许编造文件。不要把旧 operator 的另一个 namespace/run 目录伪装成本次 run。

| 顺序/产生者 → 消费者 | 实际入口及必需追加参数 | 成功判据；失败接续 |
|---|---|---|
| relay PKI → 新 Core / Node / handover | `system-backup-c1-native-inputs relay-pki --mode issue $OWNER --inputs-file/sha256 <original-relay-pki-inputs.v1> --issuer-private-file/sha256 <原 enrollment signer>` | `original_relay_pki_material_issued_service_tls_not_yet_verified`；发送未知用同 inputs 的 `--mode query`，不 issue。inputs 由原 `operator-relay-bootstrap.prepare_pki` 选择实际 controller Pod、Service、最终 OutputDirectory、Until |
| runtime issuer → forward/mapping/verifier | `system-backup-original-enroll runtime-issuers --mode export-record-keys $OWNER --dsn-sha256 <installer原字节> --source-issuer-private-file/sha256 <原signer> --material-file/sha256 <真实runtime issuer> --output-directory <Core.key_directory>` | RecordKey/CaptureKey/Export 三份原始 pin；不是 runtime grant，不重发未知 export |
| Vault signing → config/request/source V2 | `system-backup-first-install-materials issue-signing-material $OWNER --source-issuer-private-file <原signer> --controller-deployment <同一controller> --controller-pod-name <最终Pod> --output-directory <私有目录> --vault-endpoint/cluster-id/jwt-mount <真实report> --capture-key/acceptance-key/catalog-key <真实三键> --vault-ca-file/sha256 <真实CA> --vault-owner-material-file/sha256 <真实owner> --vault-owner-material-is-init-json=true --until <原窗口>` | `original-publication-signing-material-result.v1`，Material/RecordPin/ResourceObserver/CaptureObserver；未知保留原 signer 输出，不造回执 |
| delivery 最终 selection → source facts | `system-backup-source-registries produce-facts $OWNER --source-selection-file/sha256 <当前后继>` | `original-source-registry-facts-receipt.v1`，SelectionSHA256 必须等于当前后继；Parts/SourceWriters/NativeRegistries 原 pin 读回 |
| 真实 9 registry /20 refs → disabled config DATA | `system-backup-first-install-materials author-disabled-config --definition-file/sha256 <original-disabled-config-selections.v1> --output-file <新config文件>` | `original-disabled-config-authored.v1`；定义由既有 `initial-input-assembly.prepare_disabled_config` 从确切 owner 输出目录识别实际唯一引用，staging size 来自实际 PVC；缺项或歧义停止，不填空引用 |
| config DATA + signing → request/BootstrapGrant | `system-backup-first-install-materials prepare-initial-request $OWNER --config-file/sha256 <Config> --signing-material-file/sha256 <Material> --matrix-key k8s-cluster --change-reason <本次原管理员安装请求> --until <原窗口> --output-directory <新私有目录>` | `original-initial-request-authored.v1`；RequestFiles 指向同 Config/Grant/原 CaptureObserver，不修改配置、不安装 grant |
| 新 Core + request + record export → first Forward | `system-backup-first-install-materials issue-initial-forward $OWNER --runtime-dsn-file <专用runtime> --runtime-issuers-file/sha256 <真实material> --request-files-file/sha256 <RequestFiles> --core-file/sha256 <最终Core> --controller-deployment/pod-name <最终身份> --until <原窗口> --profile-file/sha256 <Core.profile_file> --record-export-file/sha256 <Export> --output-directory <Core.forward_grant.path的父目录>` | `original-runtime-execution-result.v1`，Grant 路径与 Core 相同。SQL profile 是 `public-runtime-c1-minio-metadata-read.v1` 时必须选实际 `issue-initial-forward-minio-metadata` 入口，不用 bool 跳过 SQL 验证 |
| first Forward + config + signing → publication authorization | `system-backup-first-install-materials issue-publication-authorization $OWNER --source-issuer-private-file <原signer> --controller-deployment/pod-name <同身份> --runtime-dsn-file <runtime> --core-file/sha256 <新Core> --request-files-file/sha256 <RequestFiles> --config-file/sha256 <Config> --forward-grant-sha256 <Forward> --signing-material-file/sha256 <Material> --output-directory <新目录>` | RuntimeOwnerInputs 实际 pin；上述 SQL profile 对应 `issue-initial-publication-authorization-minio-metadata`。不把 signing 权限当 runtime SQL 权限 |
| provider observer + publication → 原生 KMS/grants | `system-backup-first-install-materials issue-initial-provider-authorities $OWNER --runtime-dsn-file <runtime> --runtime-issuers-file/sha256 <material> --request-files-file/sha256 <request> --core-file/sha256 <新Core> --controller-deployment/pod-name <最终身份> --until <原窗口> --forward-grant-file/sha256 <Forward> --provider-file/sha256 <真实observer source> --worker-jwt-identity-file <实际projected路径> --runtime-owner-inputs-file/sha256 <RuntimeOwnerInputs> --output-directory <新目录>` | 三种独立 capability、formal/permit grant、SQL metadata 真正 commit/readback；未知使用既有 `initial-provider-query`/原 owner query 读回同 material，不重 issue |
| metadata definition + consumption/request/bundle → signed V2 | `system-backup-source-registries issue-v2 $OWNER --definition-file/sha256 <真实V2 definition> --consumption-file/sha256 <实际consumption> --request-files-file/sha256 <RequestFiles> --bundle-file/sha256 <实际bundle> --issuer-private-file <原signer> --output-directory <新目录>` | 原签名消费通过，V2 Source.Deployment 等于最终 Core；还需真实 CaptureConsumer/CaptureConsumerPin，才可送 final host-materials |
| 实际数据库 credential + provider result + final source → capture 输入 | `system-backup-first-install-materials runtime-database-environment --worker-source-credential --plan-file/sha256 <P1 plan> --runtime-dsn-file/sha256 <source DSN> --tls-file/sha256 <source TLS DATA> --output-file <新私有credential>`；再 `author-capture-operational-inputs --inputs-file/sha256 <原始typed输入>` | 输入由既有 `operator-capture-mapping.prepare_inputs` 组装 Core/Forward/RequestFiles/SourceSelection/ProviderResult/ProviderObserver/真实credential/固定v12 schema/PartsRegistry/DatabaseAccount/Service；结果是 SourceDefinition/ComponentsTemplate/DatabaseIssueDefinition，不是已签 grant |
| 真实 runtime sources + capture输入 → runtime材料 | `system-backup-first-install-materials issue-runtime-materials $OWNER --runtime-dsn-file <runtime> --source-definition-file/sha256 <SourceDefinition> --components-template-file/sha256 <Components> --runtime-sources-file/sha256 <原typed sources> --runtime-owner-inputs-file/sha256 <publication> --output-definition-file <新文件> --output-components-file <新文件>` | 原生 SourceDefinition/ComponentsTemplate；sources 来自真实 provider/generate/unwrap/publisher JWT 等原 producer，不能手拼 capability |
| 最终 capture definition → signed mapping/material | 先 `bind-published-capture-database-inputs --inputs-file/sha256 <原+新definition/database issue/publication回执>`；再 first-install-materials 原默认入口，见下一段 | `original-six-part-source-material-result.v1`；结果须等于 Core.capture_modules.path，所有实际任务/源关系由原 owner 验证 |

capture 最终默认入口的完整参数：

```bash
"$BIN/system-backup-first-install-materials" "${OWNER[@]}" \
 --runtime-dsn-file "$RUNTIME_DSN_F" \
 --definition-file "$CAPTURE_DEF_F" --definition-sha256 "$CAPTURE_DEF_H" \
 --source-issuer-private-file "$ENROLLMENT_SIGNER_F" \
 --components-template-file "$COMPONENTS_F" --components-template-sha256 "$COMPONENTS_H" \
 --database-source-definition-file "$DB_ISSUE_F" --database-source-definition-sha256 "$DB_ISSUE_H" \
 --resolved-components-file "$CAPTURE_DIR/capture-components.resolved.json" \
 --intermediate-file "$CAPTURE_DIR/capture-materials.intermediate.json"
# 仅实际 SQL profile 为 public-runtime-c1-minio-metadata-read.v1 时追加 --minio-metadata-profile。
```

最后 compose 的真实入口是 `system-backup-bootstrap-enrolled prepare-composition`。必须给以下 15 个各自的 `--<name>-file/sha256`：`config,bootstrap-grant,consumption,facts-receipt,functional-receipt,minio-input,nonce-binding,artifact-ca-binding,evidence-ca-binding,catalog-location,kek-config,evidence,installer-dsn,signing-consumer,signing-consumer-pin`；并给 8 个真实目录：`mapping-directory,source-registry-directory,status-relay-directory,six-reference-directory,kek-window-directory,registry-directory,nonce-directory,output-directory`。这些是相应真实 owner 的输出，不能从本地 snapshot/零行计数产生。`facts-receipt/functional-receipt/evidence/consumption` 缺失时，执行已有 C1 native owner 的真实 capture/验证步骤取得；不能用一般 source-facts receipt 冒充 C1 完成回执。

prepare-composition 的 Deployment/Composition 输出读回后，调用：

```bash
"$BIN/system-backup-bootstrap-enrolled" --check \
 --deployment-file "$BOOT_DEP_F" --deployment-sha256 "$BOOT_DEP_H" \
 --composition-file "$COMPOSITION_F" --composition-sha256 "$COMPOSITION_H"
"$BIN/system-backup-bootstrap-enrolled" --apply \
 --deployment-file "$BOOT_DEP_F" --deployment-sha256 "$BOOT_DEP_H" \
 --composition-file "$COMPOSITION_F" --composition-sha256 "$COMPOSITION_H"
```

`--apply` 是实际创建 disabled config 的原子事务，不是 DATA check。只在所有原 owner 完成、同一 target/idempotency key 已明确时发送一次。失败/断线走 `query-original` 与实际原 journal；不直接 SQL 插行，不删已有 producer 表，不把旧 `PrepareOriginalWriterSet` 的 TenantPro 拒绝 guard 移除，不拿虚构 task 通过旧冷接管分支。若真实 C1 owner 在所选 tenant 范围拒绝，就停在其真实 Phase；没有合法 producer 输出不能跨到 compose。

## 4. 环境、ready、启用与当前不能跨过的边界

注册 disabled 配置不是 enabled 接单。正常启用仍须原页面 strong-auth 的配置操作取得真实 `operation-response.raw.json`、确认 config version 2，然后依次调用原 native：`reissue-enabled-forward`、`issue-enabled-publication-authorization`、`system-backup-enabled-provider-materials issue/query` 和原 enabled runtime-materials 作者。准确参数组装来源为 `system-backup-operator-enabled-publication.py` 的 `prepare/provider_materials/runtime_materials`；全部沿用最终 Core/同一 Pod/原 RequestFiles，不能把 version 1 的材料直接改 JSON 变成 version 2。

真实接管前先由 `relay-handover --mode issue/query` 等原 owner 停止/读回同一个只读 relay，并形成原生 normal handover；环境里的 `SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_FILE/SHA256` 必须引用该实际输出。没有原 Stop/签名/PKI/hand-over 就停止，不能写一个“已停止”布尔值。

环境组装来源为同模块 `database_environment`（调用实际 `runtime-database-environment` 输出私有 DB 环境）和 `activation_environment`（选实际 Config/Forward2/capture/formal/signers/publisher/target/MinIO readiness/recovery/metadata consent/handover）。发布方法是 `DeploymentStages.publish_controller_environment`，先传输并逐一核对 producer 原始字节，写 65532:600 的 `/run/system-backup/runtime/controller.env`，最后才写其 SHA256 到 `.ready`；实际 launcher 在读回这个摘要后启动 `system-backup-v2-controller`。

**现有大 operator 的发布方法还硬性读取其旧 `production-adoption`、MinIO 原 history projection 和 enabled selections；这些记录目前没有本次真实产物。它不是可以直接在本现场复制运行的启用快捷方式。** 本次包不伪造这些前置，也不发布 ready。需要先由本次原 owner 完成上表真实 C1/注册/enable/MinIO consent/handover 输出，再将其实际绑定接回对应原发布上下文；只通过离线 DATA 编译或 mTLS 不能跨过此边界。此处是明确未获得的真实执行依赖，不应对外声称“已可一键整单”。

现场成功判据是：实际 controller Pod/SA/可执行文件 SHA 与新 Core 一致，原生 normal handover 读回确认，实际 config version 2 与 Forward2/签名源一致，真实 readiness 通过后才提交整单；整单需同原 task/attempt 完成停写、所有捕获、恢复和原源读回。任何阶段未知发送或恢复未确认，保留原 journal/义务，优先恢复源，不创建新任务掩盖旧任务。
