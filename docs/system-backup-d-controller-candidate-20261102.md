# D：消费已审核私有材料的 controller 候选入口

核对基线 `b7ec7afe5d239c4b61f78b0f1567c29b8c52e581`。本轮仅新增 `scripts/system-backup-d-controller-candidate.py`、对应 `.test.py` 和本文。没有冷编译、kubectl、SSH、部署或 readiness 修改；共享 A/C SQL/签名变更由主审核统一验证。

## 现有入口的复用边界

| 现有文件 | 当前接口 | 本次处理 |
| --- | --- | --- |
| `deployments/k8s/team-data-backup/install.py` | `--private-dir/--namespace-uid/--deployment-uid/--check`，普通 Team 安装器；非 check 会创建/替换 Secret、PVC/RBAC、patch App | 不复用其副作用或数据面身份，不用于公共 six-part controller |
| `scripts/system-backup-d-deployment.mjs` | `--requirements`、`--input public.json --output manifest.json`，registration/bootstrap 的离线 List | 不套其旧路径/材料/迁移 Job；它不是 six-part 安装器 |
| `scripts/system-backup-d-read-deployment.mjs` | 组合 public read pins 和 App Deployment patch | 可继续用于其既有读权限范围，不承担 controller capture/signing 授权 |
| `systembackupexecution.LoadDeploymentConfig` / `bindDeploymentStartupInputs` / `CheckDeploymentDatabaseWithInputs` | 生产构造器中验证当前配置、签名身份、文件 pins、真实 DB/grants 和 provider 引用 | 保留为唯一生产验证边界，不复制成 Python 授权实现 |

因此新增入口仅做 **字节摘要/挂载引用预检与零副本候选输出**，没有新建授权状态机或完整 Kubernetes/schema verifier。输入仍须经过真实审核；脚本本身不能认证“owner 已审核”。不提供 `--apply`、bootstrap、生成 key/grant、创建 Secret/RBAC 或启用 forward 的选项。

## 最小剩余输入：一个私有 plan + 原文件

私有 `plan.json` 的字段必须恰好为以下集合；相对文件路径基于 plan 所在目录。没有默认 namespace、镜像、签名或秘密模板，避免把占位值误当真实材料。

| 字段 | 内容 |
| --- | --- |
| `schema_version` | `system-backup-controller-candidate.v1`；仅本离线工具的输入版本，不授予生产权限 |
| `release_commit` | 经过主审核的最终 40 位源码 commit，不能用旧 fix18 代替 |
| `namespace` / `namespace_uid` | 本次实际目标 `clawmanager-zhanghui08-system` / `337cfe30-2c17-4b8e-b32a-760778b8098e` |
| `app_image` / `worker_image` | 同一最终源码的真实 Registry `image@sha256`；controller 用 App digest，config.worker_image 必须等于 Worker digest |
| `service_account` | `{name, uid}`，独立 controller SA 的真实身份。离线只查形状/名称绑定，不宣称 UID 已在线核对 |
| `deployment` | `{file, sha256}`，已审核的 **JSON** Deployment 原文件及原字节 SHA256，不是 YAML；输出保留该模板，不自行新增权限/挂载/Secret |
| `files` | 已声明私有材料数组；每项严格 `{file, sha256, mount_path, kind, name, key}`，kind 仅 `Secret` 或 `ConfigMap`。file 为目录内相对原文件，mount_path 为容器绝对路径，name/key 是既有目标资源的真实引用 |

Deployment 必须是 `apps/v1 Deployment`、本 namespace、`replicas=0`、有效 matchLabels 与 template labels 对应，单容器且没有 initContainer/envFrom；镜像匹配 app_image，command 精确为 `['/usr/local/bin/system-backup-v2-controller']`、无附加 args。必须显式设置：

- `SYSTEM_BACKUP_EXECUTION_PROTOCOL=public-v1`、`SYSTEM_BACKUP_ENABLED=false`、`CLAWMANAGER_LEADER_ELECTION=true`。
- `POD_NAME` 用 Downward API `metadata.name`，fieldRef 的 `apiVersion` 允许缺省或精确 `v1`；其他版本、路径和额外字段拒绝。`DB_USER` / `DB_PASSWORD` 只准非 optional 的既有 secretKeyRef，禁止内联值。其他真实 DB/TLS/leader 配置仍由 owner 的完整模板提供，不能认为此预检已查完其语义。
- 下列六对 FILE/SHA256 env 必须对应 files 中实际原字节，且 config 中 formal_verifier/publication_signers/publisher_verifier/capture_modules/publication_target 的 path 与对应 env 一致。

```text
SYSTEM_BACKUP_PUBLIC_CONFIG_FILE / SYSTEM_BACKUP_PUBLIC_CONFIG_SHA256
SYSTEM_BACKUP_VERIFIER_MATERIALS_FILE / SYSTEM_BACKUP_VERIFIER_MATERIALS_SHA256
SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_FILE / SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_SHA256
SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_FILE / SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_SHA256
SYSTEM_BACKUP_CAPTURE_MATERIALS_FILE / SYSTEM_BACKUP_CAPTURE_MATERIALS_SHA256
SYSTEM_BACKUP_PUBLICATION_TARGET_FILE / SYSTEM_BACKUP_PUBLICATION_TARGET_SHA256
```

DeploymentConfig 必须为 `system-backup-public-deployment.v1`、six-part，namespace/UID/Worker 与 plan 一致；profile、capacity、source DSN、server cert/key、issuer cert/key、forward/recovery grant 原文件须在 files 中，两个 grant SHA env 与原字节一致，key_directory 下至少有已声明原文件。**这不是签名有效性、完整 key 集合或嵌套 provider 材料穷尽性证明**；A/C 仍须提供原正式签名、所有嵌套材料及当前授权。不得为了满足列表伪造 grant、key 或容量报告。

支持只读目录挂载的 Secret、ConfigMap 及它们的 projected sources，核对显式 items 或默认 key→文件映射；optional、歧义覆盖或 subPath/subPathExpr 会拒绝。需要 subPath 的真实安装模板，应由 D 后续扩展并验证该路径语义，不能临时改签名材料路径。所有 private 原文件要求位于 plan 目录内、非越界、摘要匹配；单文件最多 16MiB，最多 256 项。

**实际仍缺的材料不是 SSH 密钥：**最终已审 App/Worker digest、真实 controller SA 名称/UID、已审核零副本 Deployment（含具体存储/网络/SQL Secret 引用）、固定部署配置及其所有签名/密钥/六域/verifier/publisher 材料和 mount ledger。SA/RBAC/Secret/PVC 尚未创建时，本工具不会代建或把未存在的引用认定为真实；由主审核协调独立最小权限 provisioning，并在真正应用前在线核对。

## 可执行 Bash（用户自行连接/执行）

验收机已有 Python3 即可，不需要 Node/Go/Docker。只传仓库路径、私有 plan 路径和本轮新输出目录；文件中含私密原材料，权限应为目录 700、文件 600，不打包上传到 Git。示例先做无输出预检，再创建新的私有候选目录：

```bash
(
  set -euo pipefail
  umask 077
  : "${REPO_ROOT:?absolute checkout containing this script}"
  : "${CONTROLLER_PRIVATE_PLAN:?absolute private reviewed plan.json}"
  [[ "$REPO_ROOT" = /* && "$CONTROLLER_PRIVATE_PLAN" = /* ]]
  candidate_repo=$(realpath -e -- "$REPO_ROOT")
  candidate_plan=$(realpath -e -- "$CONTROLLER_PRIVATE_PLAN")
  candidate_script="$candidate_repo/scripts/system-backup-d-controller-candidate.py"
  python3 -B "$candidate_script" --plan "$candidate_plan"
  candidate_run=$(mktemp -d "$candidate_repo/.tmp-controller-candidate-XXXXXXXX")
  candidate_run=$(realpath -e -- "$candidate_run")
  [[ "$(dirname -- "$candidate_run")" = "$candidate_repo" && "$(basename -- "$candidate_run")" = .tmp-controller-candidate-* ]]
  python3 -B "$candidate_script" --plan "$candidate_plan" --output "$candidate_run/candidate"
  printf 'candidate_review_directory=%s\n' "$candidate_run"
)
```

退出 0 仅表示本离线结构/原字节/挂载检查通过，report 中始终 `authorization_verified=false`、`live_resources_verified=false`、`full_acceptance=false`。输出 `controller.paused.json` 与 `report.json`，目录/文件权限 700/600，创建前先完成验证，不覆盖已有输出。只读私有输入，不将秘密正文写 stdout/stderr；失败仅给固定拒绝文案，不打印异常原文。候选文件本身来自私有审核模板，应继续按私有文件保管。

退出 1 表示材料缺失、不匹配、输出目录已存在或其他拒绝；不能视为可安装。没有自动 kubectl，**不要把退出 0 接成自动 apply/scale**。最终应用前必须核对 namespace UID、SA UID、引用资源原 key/版本、Registry digest 与真实启动材料；保持生产构造器全部签名、grants、provider 和当前授权校验，再由主审核给出一次受控安装/激活命令。

审核完只删 stdout 给出的本轮候选目录（不删私有材料）：

```bash
: "${REPO_ROOT:?absolute checkout}"
: "${CONTROLLER_CANDIDATE_RUN:?exact candidate_review_directory printed by this run}"
candidate_repo=$(realpath -e -- "$REPO_ROOT")
candidate_run=$(realpath -e -- "$CONTROLLER_CANDIDATE_RUN")
[[ ! -L "$CONTROLLER_CANDIDATE_RUN" && "$(dirname -- "$candidate_run")" = "$candidate_repo" && "$(basename -- "$candidate_run")" = .tmp-controller-candidate-* ]] || exit 1
rm -rf -- "$candidate_run"
```

## 验证范围

本地 Python 3.10、`-B` 禁止 pycache；8 项测试是明确的 LOCAL STRUCTURE DATA，检查零副本且不声明授权、原文件变化、错误挂载对象、运行/forward 启用、内联 DB 密码、重复字段与越界文件拒绝、POD_NAME 默认/v1 兼容与错误版本/路径/字段拒绝，以及真实 CLI main 只生成候选/report、不打印私有正文且拒绝覆盖输出。它们不构成 Go DeploymentConfig 全语义校验、签名验收、Kubernetes server-side dry-run、真实 Secret 存在或成功备份证明。测试临时目录在本仓库根下创建并自行清理，不留测试构建产物。未运行远端命令，暂不冷编译 Go。

实际本地命令：`py -3.10 -B scripts/system-backup-d-controller-candidate.test.py`，8/8 PASS、退出 0；指定不存在 plan 的 CLI 反例退出 1，仅固定拒绝文案。Linux 对应命令为 `python3 -B scripts/system-backup-d-controller-candidate.test.py`。无远端测试，Bash 命令由主审核统一语法检查。
