# 验证环境 P2 接续清单

本轮验收点为 `prepare-mount-materials` 产出两份材料且摘要可读回。目标为 `clawmanager-sbk-validation-system`，运行实例 `1,2,3,7,8`，延后实例 `4,5,6`。控制器保持 `SYSTEM_BACKUP_ENABLED=false`，页面验收留待签发及 Longhorn 停写、快照和恢复接线通过。

## 固定源码与工具

现场源码固定为 `a11b1d24d5fb9b067e302219f7db54c96a2b080c`。使用该提交的独立检出或 Git 源码导出。`a11b1d24` 包含 SQL 准入与验证名单、零代次 Pro 挂载、Longhorn keeper 接线、共享 Longhorn 卷的作者侧身份记录、验证引导预检和 OpenClaw 测试修复。原主工作区的镜像工具改动会移除当前私有 Agent 目录选项，Go 解码器改动会移除共享原生 TLS 候选支持，旧装配改动会删减源坐标和 provider 流程。现场使用本提交中的实现。

在有 Go 工具链的构建机使用仓库根目录和独占交付目录。构建产物是 Linux amd64。Windows 构建机的 `GOTMPDIR`、`GOCACHE`、`TEMP`、`TMP` 和交付目录使用 D 盘。保留交付文件和摘要，清理独占构建缓存。

```bash
set -euo pipefail
REV=a11b1d24d5fb9b067e302219f7db54c96a2b080c
test "$(git rev-parse HEAD)" = "$REV"
test -z "$(git status --porcelain --untracked-files=no)"
: "${BIN:?现有独占交付目录的绝对路径}"
(
  cd backend
  for name in system-backup-first-adoption system-backup-first-install-materials system-backup-source-registries; do
    GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -o "$BIN/$name" "./cmd/$name" || exit
  done
)
(cd "$BIN" && sha256sum system-backup-first-adoption system-backup-first-install-materials system-backup-source-registries > SHA256SUMS)
```

现场把三份工具放入一个新目录，在该目录执行 `sha256sum -c SHA256SUMS`。`/root/sbk/bin` 现存工具属于上次交接批次。以下用 `$BIN` 指向本次交付目录。旧 `system-backup-zhanghui08-operator.py` 固定另一 namespace，模块摘要也落后于当前源码。本清单使用验证预检和具名 owner CLI 入口。

本地验证通过 11 项引导预检、6 项 OpenClaw 和私有目录层模型，以及 14 项卷分类、共享卷身份、租户挂载和 writer 参数定向用例。三份 CLI 包均已编译，`first-install-materials` 与 `source-registries` 在本轮选择器下没有匹配用例。真实 OCI 文件、现场凭据、五条连接和签发材料在恢复远测后验收。

## 恢复连接后先核对前置状态

1. 在同一个验证 enrollment 下复查 `controller.env.ready` 仍未交付、接单仍暂停。用已有引导定义重读 namespace、SA、Deployment、ReplicaSet、Running Pod、三份 PVC 的 UID 链，和原引导回执核对。UID 变化时重做绑定材料。
2. 复查 sources SA 的 TokenReview、两条独立 MySQL 角色的 TLS 和 `server_uuid`、两节点 observer mTLS。旧 app SQL 回读计划曾因 rollout 漂移失败。使用当前计划或两角色的 TLS 直连证据。
3. 从源码目录按固定摘要采集 OCI 文件。`$RUN` 为本轮独占私有目录。脚本新建输出子目录。

```bash
set -euo pipefail
umask 077
python3 -B scripts/system-backup-validation-bootstrap-preflight.py --mode observe \
  --plan-file "$PLAN" --plan-sha256 "$PLAN_SHA" \
  --issuer-public-file "$PUB" --issuer-public-sha256 "$PUB_SHA" \
  --enrollment-pin-file "$PIN" --enrollment-pin-sha256 "$PIN_SHA" \
  --kubeconfig-file "$KUBE" --kubeconfig-sha256 "$KUBE_SHA" \
  --definition-file "$BOOT_DEF" --definition-sha256 "$BOOT_DEF_SHA" \
  --output-directory "$RUN"
python3 -B scripts/system-backup-runtime-startup-inputs.py \
  --image openclaw=10.130.14.23:5000/openclaw-lite@sha256:5d5f735bc8c0155d51841b574c98c6c02ca399085add0e3dc98b3d7e0ead3140 \
  --image hermes=10.130.14.23:5000/hermes-lite@sha256:a2473da0cf375ed128116af3083eccd3276665adac4ae2722edcbff6cc277353 \
  --output-directory "$RUN/runtime-startup-images" > "$RUN/runtime-startup-images.receipt.json"
```

从回执取 `file` 和 `sha256`，设为 `$STARTUP`、`$STARTUP_SHA`。对照验证 Pod 的 `spec.containers[].image` 和 `status.containerStatuses[].imageID` 核验实际 manifest/config，并读回同 Pod 的 Agent mTLS。上次观测为基础镜像。如果候选缺失或 Pod 仍使用基础镜像，停在镜像步骤，先核对发布候选和验证环境 rollout。rollout 后刷新源坐标、Pod 和挂载身份，再重跑本节。

## 签发前材料闭环

在同一个 Bash 会话准备独立 pin、实际凭据文件和真实 owner 定义。`DSN` 指向同一 enrollment 的 `mysql-installer.dsn`，`CA` 使用该数据库实际验证过的 CA。`CUSTODY_DIR`、`CUSTODY_KEY` 和摘要来自原 gateway custody。`PARTICIPANT_ARGS` 默认为空数组，必要时按 SQL 注册参与者与物理 writer 的真实映射追加 `--participant-writer ID=writer` 参数对。凭据保存在现场私有目录。先处理已知的 provider TLS rollout，再采 writer 坐标。

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
  --gateway-original-directory "$CUSTODY_DIR" \
  --gateway-original-key-file "$CUSTODY_KEY" --gateway-original-key-sha256 "$CUSTODY_KEY_SHA" \
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

页面验收需同一 task/attempt 的 keeper 注册、停写、快照完成、解冻、原源恢复写读、keeper 回收、六域正式发布、独立读回和目录登记全部齐备。本轮远测不可用，现场执行从 OCI 和实际 Pod 核验继续。
