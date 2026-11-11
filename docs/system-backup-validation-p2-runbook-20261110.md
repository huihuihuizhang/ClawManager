# 验证环境 P2 接续清单

本轮验收点为 `prepare-mount-materials` 产出两份材料且摘要可读回。目标为 `clawmanager-sbk-validation-system`，运行实例 `1,2,3,7,8`，延后实例 `4,5,6`。控制器保持 `SYSTEM_BACKUP_ENABLED=false`，页面验收留待签发及 Longhorn 停写、快照和恢复接线通过。

## 固定源码与工具

原现场工具来自 `a11b1d24d5fb9b067e302219f7db54c96a2b080c`，包含 SQL 准入与验证名单、零代次 Pro 挂载、Longhorn keeper 接线、共享 Longhorn 卷作者侧身份记录、验证引导预检和 OpenClaw 测试修复。2026-11-11 Hermes 修复后，使用包含本次精确 Lite 镜像识别的 `backup` 提交；完整提交号随交付写入 `SOURCE_REVISION`。旧 `a11b1d24` 工具不识别新的 Hermes 底座，不再用于本轮 P2。原主工作区的大量未提交改动继续保留，现场从 `backup` 的独立源码导出构建。

在有 Go 工具链的构建机使用仓库根目录和独占交付目录。构建产物是 Linux amd64。Windows 构建机的 `GOTMPDIR`、`GOCACHE`、`TEMP`、`TMP` 和交付目录使用 D 盘。保留交付文件和摘要，清理独占构建缓存。

```bash
set -euo pipefail
REV=$(git rev-parse HEAD)
test -z "$(git status --porcelain --untracked-files=no)"
: "${BIN:?现有独占交付目录的绝对路径}"
(
  cd backend
  for name in system-backup-first-adoption system-backup-first-install-materials system-backup-source-registries; do
    GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -o "$BIN/$name" "./cmd/$name" || exit
  done
)
printf '%s\n' "$REV" > "$BIN/SOURCE_REVISION"
(cd "$BIN" && sha256sum system-backup-first-adoption system-backup-first-install-materials system-backup-source-registries SOURCE_REVISION > SHA256SUMS)
```

现场把三份工具放入一个新目录，在该目录执行 `sha256sum -c SHA256SUMS`。`/root/sbk/bin` 现存工具属于上次交接批次。以下用 `$BIN` 指向本次交付目录。旧 `system-backup-zhanghui08-operator.py` 固定另一 namespace，模块摘要也落后于当前源码。本清单使用验证预检和具名 owner CLI 入口。

本地验证通过 11 项引导预检、6 项 OpenClaw 和私有目录层模型，以及 14 项卷分类、共享卷身份、租户挂载和 writer 参数定向用例。三份 CLI 包均已编译，`first-install-materials` 与 `source-registries` 在本轮选择器下没有匹配用例。真实 OCI 文件、现场凭据、五条连接和签发材料在恢复远测后验收。

## 恢复连接后从 P2 镜像核验继续

P1 引导和 P1.3 已通过。沿用已有控制器 UID 链、sources SA TokenReview、两条独立 MySQL 角色的 TLS 和 `server_uuid` 回执，以及两节点 observer mTLS 回执。控制器继续等待 `controller.env.ready`，接单保持暂停。只有引导对象被替换、身份与回执不符或原回执不可用时，才重跑 `system-backup-validation-bootstrap-preflight.py --mode observe` 并重新绑定受影响的材料。SQL 或 observer 连接拒绝时，仅复查对应的凭据和连接。

从源码目录按固定摘要采集 OCI 文件。`$RUN` 为本轮独占私有目录。脚本新建输出子目录。

```bash
set -euo pipefail
umask 077
python3 -B scripts/system-backup-runtime-startup-inputs.py \
  --image openclaw=10.130.14.23:5000/openclaw-lite@sha256:5d5f735bc8c0155d51841b574c98c6c02ca399085add0e3dc98b3d7e0ead3140 \
  --image hermes=10.130.14.23:5000/hermes-lite@sha256:279fa5b365f875de1fad93b0f58cda20599d2339fa067bf062e08ef80d770254 \
  --output-directory "$RUN/runtime-startup-images" > "$RUN/runtime-startup-images.receipt.json"
```

从回执取 `file` 和 `sha256`，设为 `$STARTUP`、`$STARTUP_SHA`。对照验证 Pod 的 `spec.containers[].image` 和 `status.containerStatuses[].imageID` 核验实际 manifest/config，并读回同 Pod 的 Agent mTLS。上次观测为基础镜像。如果候选缺失或 Pod 仍使用基础镜像，停在镜像步骤，先核对发布候选和验证环境 rollout。rollout 后刷新源坐标、Pod 和挂载身份，再重跑本节。

2026-11-11 已完成 Hermes 恢复：底座 manifest `47729188347a01d249d5a929e474b3bb9959a138c138031a84ec39a7c6412cc7`、底座 config `e946aefc144302ff072039ff52f0ddeb749f8155a6a017bc4b5edc7a9f58c7b4`、当前镜像 `279fa5b365f875de1fad93b0f58cda20599d2339fa067bf062e08ef80d770254`、Agent `be46bb0525623bb9fb7f1393a6b668d7c8f705a998c90517915751c2be9d0102`、更新后的发布清单 `bde2200cd129798edc17fbf6cd90f3e4e65aa9aa5c748f1e852faeb53566cf9c`。清单中的 `desktop_web_accepted=false` 保持不变；启动和备份能力通过不等于完整 Desktop Web 发布验收。实际 Pod 为 `hermes-runtime-5544b97c6d-bsxk8`，UID `d995ae33-ff70-4a95-bf2b-37bdbf9937f3`，实例 3 为 running、generation 8；TLS、控制鉴权、`shared-container-freeze.v1` 及 durable reservation 均通过。恢复回执为 `/root/sbk/p2-hermes-resume.hkysh2nm`。原发布及修复记录为 `/root/sbk/p2-hermes-repair.mezljmrw`。本次从更新 OCI 输入和源坐标开始，复用已通过的引导、TLS 与恢复结果。

收尾脚本源码保存在 `scripts/system-backup-field-tools/`。它按 Kubernetes 空字符串序列化规则比较 Env，并精确识别标准只读 ServiceAccount 投射卷；API 身份使用 `type=hermes`、`runtime_type=gateway`、`instance_mode=lite`。实际持有源的分类仍要求原有 native Node 证明；本次镜像兼容不会把 Secret 元数据当作已加载环境证明。

### 已通过的新材料回执

2026-11-11，`1dd1ae7179520223c944401a2cc38fb738e09540` 的三份 CLI 已上传至 `/root/sbk/p2-hermes-1dd1ae71`。现场真实 OCI 验收 `TestOriginalRuntimeImageActualInputs` 通过，一次性验收程序随后删除。正式材料目录为 `/root/sbk/p2-materials-1dd1ae71.lVSEBfl2`：

- `runtime-startup-images/runtime-startup-images.json`：`28e979483e004141f3452f13609057fc0cde5bb82e4ca1d34e299cb536087068`。
- `coordinates/initial-source-coordinates.json`：`4fe0083a3546c7a41c302861c65b805eea9ef981f9862e86f4bae043724b7980`。
- `coordinates/initial-source-kubernetes.private.json`：`2dc4ce78540b2194c6c94679908fadd83340cee95e4e8e5afd472fed75b0577a`。

源坐标回执版本为 `original-initial-source-data-authored.v1`，保留全部 8 个实例；`WriterQualified=false`、`BackupReady=false` 是该数据作者的固定语义。接着使用 `scripts/system-backup-field-tools/prepare-p2-writer-selection.py` 读取这些固定输入和真实 App/Runtime 环境，生成私有 source config，再调用同批工具的 `prepare-selection`。该脚本不重新采集已有坐标、不运行引导、不滚动部署，也不调用停写或 adopt。只有新 writer selection 回执读回通过后，才进入下面的 source-inputs 和 mount-materials。

第一次 writer selection 记录为 `/root/sbk/p2-writer-selection.4nqkam_7`，source config 摘要为 `281bef3b57ea2d63f9e626e9185b51e91efe6b85ccc58165407a6efed926dda1`，实际 App scope 为 `installation`。owner 拒绝，selection 与 journal 目录均为空，未停写。2026-11-11 05:29 UTC 的只读报告确认 observer 回执在有效期内、namespace/UID 匹配，source config 的 scope 和 RuntimeTestScope 与坐标一致；这不替代完整的 observer authority/endpoint 校验。

已确认的代码缺口是旧 selection 作者将运行中 Pro 限定为 system namespace 的 ownerless Pod，而实例 2 是 `clawmanager-sbk-validation-user-1` 中由 ReplicaSet/Deployment 管理的 Pro。新的 P2 作者把这类源记为 `TenantPro`，绑定原 SQL 身份、完整 API UID 链、实际持久卷和整租户控制器清单；源坐标同时输出 `TenantProSelections`。它仍只生成数据，旧 original native 停写/恢复消费者会明确拒绝未接入的租户控制器生命周期，不把 selection 数据当作已持有源的证明。正式停写支持需在后续 native owner 验收中接通，不能仅因 P2 材料生成成功就开放接单。

owner 错误回执新增有限的 `Failure.SelectionPhase`（如 `first_collection/observer_materials`、`first_collection/tenant_pro_controllers`），保留原有具体 source dependency，并隐藏原始 SQL、API 和凭据错误。重试使用新的私有 selection/journal 目录，沿用上述 source config 和 OCI 材料；不重跑已通过的引导、镜像发布与实例恢复。

### Writer selection 现场已通过

工具源码 `95b274c8084e7b600d198376813d0b044aff93dc`，远侧目录 `/root/sbk/p2-selection-95b274c8`，交付摘要均通过。成功记录 `/root/sbk/p2-writer-selection-retry.hmq_j5mb`：

- `selection/original-writer-selection.json`：`9d114d1ba974fa7997e695b385038dd43d8d7fdb30af6a61fd1477bed44f6c03`。
- `selection/original-source-coordinates.json`：`bf15eccc05781b45299c35ed8d92dd1b862b745c2338a6e8d55662773997dd60`。
- `SourceCount=8`、`DeploymentCount=10`、`ParticipantCount=0`。最后一项来自对当前 application scope 的真实 SQL 参与者查询，不表示实例被排除，也不证明后续 SQL gate 接线完整。
- 租户 Pro 实例 `2` 绑定 namespace `clawmanager-sbk-validation-user-1`、Deployment `clawreef-2-deployment`、UID `ae62057d-36bb-46d3-897b-bcbd40cde1b3`。

状态为 `actual_original_complete_base_selection_materialized_no_hold`，仅完成选源数据；未停写、未持有源、未完成 P2 挂载材料验收。下一步复用本批工具与现有凭据，准备 `original-initial-source-author-inputs.v1` 定义，再执行 `author-initial-source-inputs` 和 `prepare-mount-materials`。无需重新采集这批 writer selection。运行时控制器或源身份发生变化时才刷新受影响材料。

现场后续盘点确认 `complete_inputs`、`deployment_core`、`capture_template`、`execution_profile`、`mount_layouts` 均为 0；7 份连接候选全部是 SQL DSN，没有现成的完整 source-inputs 定义。不能直接执行依赖这些定义的挂载命令。接续使用现有 `system-backup-minio-first-hop-tls.py prepare`，通过原 enrollment plan 绑定实际 namespace、Kubernetes 身份、Service/Pod/ReplicaSet/Deployment 和固定 MinIO 镜像，先输出私有 TLS 计划；该阶段只读集群并在本地生成材料，不切换服务。若已有 TLS、镜像或启动参数不符，保留拒绝输出，复用真实原 CA 或补对应镜像接线，不能改成任意镜像或忽略校验。后续 apply/query/business cutover 处理同一份计划；真实 rollout 后刷新受影响的 writer 数据。交付脚本按 Git blob 的原始字节导出，不能将 Windows CRLF 工作副本直接复制到现场后改写依赖摘要。first-hop 的原 Git 摘要为 `e1659e3553a7672f9624422f6a678ae824ad0a63a16a8066a1889034463376ad`；App cutover 继续绑定该原始实现。

MinIO 已准备计划 `/root/sbk/p2-minio-prepare.9vnemhVi/minio-tls/plan.json`，摘要 `5f0c664f2a694ff997011aa8aa2b9c697dfdea1179438775ecad8a1837c27da3`，operation `a10011353367ae32b9b7dacb3bfb6a17`，CA 摘要 `1ee23762b1a38a93b709641a79191466e45f8b2bda208e0c1901d25018054450`，目前只有 `prepared_local_only`。用户已授权完成本次任务必要的配置与执行接线并推进整单验收，无需逐次请求切换确认，范围不扩展为通用安装改造。

`scripts/system-backup-field-tools/continue-p2-minio-connection.py` 固定消费该计划：先准备 App 根证书配置，原 owner apply MinIO，再原 owner apply App；重入时查询同一操作。完整读取所有 App 副本的已加载连接与原 config DATA，核对实际 MinIO 进程身份，进行带认证和固定 CA 的有限 S3 列表读取，输出私有 `minio-source-fragment.json`。没有归档 Skills 时只记录业务归档为空，不声称执行过 SDK 下载；S3 读取仍必须真实返回 200。材料包含 source_objects 连接和原模板片段，不产生 grant、停写证明或整单成功标志。脚本同时保留本次 source-inputs 作者需要的实际平台、节点、StorageClass 和 VolumeSnapshotClass 数据。后续正式停写仍需完成原租户 Pro 和 Longhorn native owner 接线，不能绕开现有拒绝或删减实例名单。

该 MinIO 批次现场已通过：`minio actual_tls_verified`、App 业务归档为空、两个副本已加载配置一致、认证 S3 列表返回 200。`/root/sbk/p2-minio-prepare.9vnemhVi/connection-continuation/minio-source-fragment.json` 摘要为 `c3b4eae48b3d78c12872742be55e6bc95f11bc9e594c83b8697728edc020ede8`。平台共 9 个 Deployment，既有控制器为 `sbk-d4f51b83b57e-controller`，UID `e4e27f27-8f02-40ab-8c62-09f2ffa3fafa`；App UID `8ebd4d4c-57b6-4a82-b310-fae596681a4e`，两者镜像均为 `10.130.14.23:5000/clawmanager@sha256:322ba63b49d21c4030be2760c88ae03457fbe9454ee138906066b29bc68541ca`。

下一个必要连接由 `continue-p2-redis-connection.py` 复用原 `system-backup-original-maintenance --mode redis-materials` 完成 prepare/apply/query/finalize，既有 Redis 为 `clawmanager-team-redis`，Deployment UID `dd724dc4-ad59-4a78-b5bb-50aba907e036`，镜像 `docker.io/library/redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf`。脚本按全部 App 副本实际加载的 URL 选择唯一 Service 和数据库，保留完整选源名单，作用域使用原 Teams key family `claw:team:`。它使用一个明确的私有 records 目录接续：apply 失联只查询原操作；finalize 失联通过 query-finalize 读回原 native 发送记录，不重新 finish。成功后的 reader/keeper 凭据、CA、真实 run ID 和 writer selection successor 都来自既有 native owner，脚本只导出 source_redis DATA。该 TLS 连接不会被写成整单已验收。

首次 Redis 记录 `/root/sbk/p2-redis-connection.b5dQ12Lt` 在 `0-prepare` 被拒绝；只读报告确认 native 输出目录为空、两个私有日志只有保留用的换行，安装账号 identity/extra 正常，Redis Deployment 的 `command` 为空、参数数量为 3。旧原生工具在读取/验证原生 Redis 之前强制要求 `Command=[redis-server]`，未进入 helper。修复只识别固定原镜像的两种明确原生入口：显式 `Command=[redis-server]`，或默认入口配 `Args=[redis-server,...]`；prepare 仍要求有效服务参数恰为 `--appendonly yes`。Pod/Deployment 参数、固定 imageID、UID 链、主进程 PID、原生版本/ACL 和持久卷核验保持不变，也不把未知脚本或 config 文件作为原生入口。

Redis owner 错误输出新增 `original-redis-native-material-failure.v1` 的固定 `Phase`，原 SQL/API/凭据错误只留在私有 cause。接续脚本仅对这次有固定旧二进制摘要、原启动形态及空 native 目录的“在 helper 前拒绝”建立私有 binding successor；保留原 binding、options 与日志，用同一 records 目录运行修复后的原 owner。任何已有 native intent、不同原镜像/启动形态或未知 prepare 状态仍拒绝，不重放。TLS/ACL 正式切换依旧只由原 owner 完成。

`8bbf4c61` 的 native 入口/身份拒绝/错误脱敏定向用例及 Linux 构建通过，现场已越过 `original_redis_pod` 和只读原生检查，第二次在 `capture_policy` 拒绝。原因是旧脚本模板把 `recovery.Reference` 写为大写字段，而原 Go 类型显式使用 `id/version/sha256`；严格 canonical roundtrip 因此拒绝。修复仅改接续脚本输入，不放宽 `decodeExact`，不重编或替换已经通过的 native owner：保留 `redis-source.policy.json`，生成同值同作用域的 `redis-source.policy.wire-v1.json`。只有原 `capture_policy` 拒绝回执、同 native 二进制摘要和空 native 输出目录同时匹配时，才为原 records 建立 binding-policy successor 后继续 prepare。执行修正脚本时 `--tool-directory` 继续指向 `/root/sbk/p2-redis-8bbf4c61`。

策略 wire 修复后，现场 `prepare` 和 `apply` 已被原 owner 确认；rollout 因单副本 RWO 的默认 RollingUpdate 卡住，尚未 finalize：旧 Pod `9101cf2d-f1bd-4536-aff1-d85b1ba44269` 在 node1、准备后 readiness=false；新 Pod `32e2a8a4-aa74-4857-a9d2-fdaafb928cee` 在 k8s-master，Pending/FailedAttachVolume。`settle-p2-redis-rwo-rollout.py` 为这份已发送的 intent 做有限补偿：验证 prepare/apply 原记录、Deployment UID/完整 desired spec、原 Bound RWO PVC/PV UID；用原 CAS/journal helper 临时切 Recreate，让控制器正常终止旧 Pod 并交接原卷。新 Pod ready 后恢复原 desired strategy，完整规格重新匹配原 intent，再由原 native query/finalize 结束。原 intent、PVC、数据路径、账号和 ACL 材料不改写；任何外来规格/卷身份变化或未知 CAS 都拒绝并保留恢复义务。

## 签发前材料闭环

在同一个 Bash 会话准备独立 pin、实际凭据文件和真实 owner 定义。`DSN` 指向同一 enrollment 的 `mysql-installer.dsn`，`CA` 使用该数据库实际验证过的 CA。本轮 `shared-container-freeze.v1` 由共享 Runtime 作者处理 Lite 实例。`PARTICIPANT_ARGS` 默认为空数组，必要时按 SQL 注册参与者与物理 writer 的真实映射追加 `--participant-writer ID=writer` 参数对。凭据保存在现场私有目录。先处理已知的 provider TLS rollout，再采 writer 坐标。

```bash
OWNER=(--plan-file "$PLAN" --plan-sha256 "$PLAN_SHA"
  --issuer-public-file "$PUB" --issuer-public-sha256 "$PUB_SHA"
  --enrollment-pin-file "$PIN" --enrollment-pin-sha256 "$PIN_SHA"
  --kubeconfig-file "$KUBE" --kubeconfig-sha256 "$KUBE_SHA"
  --dsn-file "$DSN" --database-ca-file "$CA" --local-admin-password-file "$PW")
mkdir -m 700 "$RUN/coordinates"
"$BIN/system-backup-first-install-materials" author-initial-source-coordinates "${OWNER[@]}" \
  --running-only-runtime-test '1,2,3,7,8:4,5,6' \
  --output-directory "$RUN/coordinates" > "$RUN/coordinates.receipt.json"
```

核对 `Version=original-initial-source-data-authored.v1`，按回执 pin 读回 `Coordinates` 与 `KubernetesSnapshot`。`SOURCE_CONFIG` 的 `installation_id`、`namespace`、`namespace_uid` 来自同一 enrollment，`application_scope` 取实际 App 的 `SYSTEM_BACKUP_SQL_GATE_SCOPE` 并与坐标的 `ApplicationScopes` 交叉核对。`runtime_sources` 使用 `shared_runtime_protocol=shared-container-freeze.v1`，填实际 `workspace_root`、`agent_token_file`、`agent_ca_file`、`agent_ca_sha256`，并分别从本次坐标复制 `current_stopped_pro_layouts` 和 `runtime_test_scope`。保留完整 `RuntimeTestScope`，包括原 SQL 实例摘要和 deferred 行。

```bash
mkdir -m 700 "$RUN/writer-selection" "$RUN/journal" "$RUN/source-inputs" "$RUN/mount-inputs"
"$BIN/system-backup-first-adoption" --action prepare-selection "${OWNER[@]}" \
  --source-config-file "$SOURCE_CONFIG" --source-config-sha256 "$SOURCE_CONFIG_SHA" \
  --runtime-startup-images-file "$STARTUP" --runtime-startup-images-sha256 "$STARTUP_SHA" \
  --observer-definition-file "$OBS_DEF" --observer-definition-sha256 "$OBS_DEF_SHA" \
  --observer-receipt-file "$OBS_REC" --observer-receipt-sha256 "$OBS_REC_SHA" \
  --selection-output-directory "$RUN/writer-selection" --journal-directory "$RUN/journal" \
  "${PARTICIPANT_ARGS[@]}" > "$RUN/writer-selection.receipt.json"
```

检查回执 `Version=original-writer-selection-materials.v1`，按 `Selection` 和 `SourceCoordinates` pin 回读，确认两个 RWX 挂载者及其 Pod、PVC/PV、CSI handle 和 Node UID。由 owner 基于该选择准备 SQL、source API、MinIO、Redis 共五条连接，并完成 Vault 前置。用实际控制器 UID 链、部署核心、执行 profile 和采集模板准备 `$SOURCE_DEF`，版本为 `original-initial-source-author-inputs.v1`。`ProfileFile` 与 `CaptureModules.Path` 分别指向本次 `$RUN/source-inputs` 内的 `execution-profile.json` 和 `capture-materials.json`。provider 凭据缺失或 rollout 结果不明时保留已有回执，按原操作 query/finalize，再生成定义。

```bash
"$BIN/system-backup-first-install-materials" author-initial-source-inputs "${OWNER[@]}" \
  --definition-file "$SOURCE_DEF" --definition-sha256 "$SOURCE_DEF_SHA" \
  --output-directory "$RUN/source-inputs" > "$RUN/source-inputs.receipt.json"
```

检查 `Version=original-initial-source-inputs-authored.v1`。将这个回执的 `SourceSelection.File` 和 `SourceSelection.SHA256` 设为 `$SOURCE_SELECTION`、`$SOURCE_SELECTION_SHA`。布局文件 `$LAYOUTS` 使用 `original-instance-mount-layout-selection.v1`，`Longhorn` 填入现场确认的 `ProviderNamespace`、`SnapshotClass`、`CloneClass`。仅为额外的 Lite 持久挂载填写 `Layouts`，现场只有主挂载时填 `[]`。主 workspace 和 Pro 主卷由 owner 路径推导。

```bash
"$BIN/system-backup-source-registries" prepare-mount-materials "${OWNER[@]}" \
  --source-selection-file "$SOURCE_SELECTION" --source-selection-sha256 "$SOURCE_SELECTION_SHA" \
  --mount-layouts-file "$LAYOUTS" --mount-layouts-sha256 "$LAYOUTS_SHA" \
  --output-directory "$RUN/mount-inputs" > "$RUN/mount-materials.receipt.json"
```

退出 `0` 后，核对 `Version=original-instance-mount-materials-receipt.v1`、`MountScopeSHA256`，逐份回读 `mount-materials-template.json` 与 `mount-source-selection.json`。确认实例 `1,3,7,8` 对应实际 RWX、实例 `2` 对应租户 RWO、实例 `4,5,6` 仍为 deferred。取本回执里的后继 `SourceSelection.File` 和 `SourceSelection.SHA256`，设为 `$NEXT_SELECTION`、`$NEXT_SELECTION_SHA`。

```bash
"$BIN/system-backup-source-registries" produce-facts "${OWNER[@]}" \
  --source-selection-file "$NEXT_SELECTION" --source-selection-sha256 "$NEXT_SELECTION_SHA" \
  > "$RUN/source-facts.receipt.json"
```

核对 `PartsRegistry` 与 `SourceWritersRegistry` 后进入签发。

| 失败点 | 处理 |
| --- | --- |
| 摘要、UID 或挂载漂移 | 保留本次回执，从受影响的材料来源重新采集 |
| 命令退出 `2` | 核对参数及输入种类，`prepare-mount-materials` 使用 author 回执的 `SourceSelection` |
| 命令退出 `1`、部分输出或回执丢失 | 保留原私有目录和 stderr，读回已落盘文件，确认阶段和是否产生副作用；确认可重试后使用新的输出目录 |
| 停写、快照或恢复结果不明 | 保留原任务、attempt、恢复义务和 keeper，按原资源日志对账 |

页面验收需同一 task/attempt 的 keeper 注册、停写、快照完成、解冻、原源恢复写读、keeper 回收、六域正式发布、独立读回和目录登记全部齐备。当前远测已恢复，Hermes 已恢复运行，现场从更新的 OCI 材料及源坐标继续。
