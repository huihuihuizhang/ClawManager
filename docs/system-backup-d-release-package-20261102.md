# zhanghui08：同源 App/controller/Worker 构建与安装前置（2026-11-02）

本切片只核对现有源码入口和提供待执行 Bash 命令，没有 SSH、构建、冷编译、推送镜像或部署。用户明确新增内容从未部署，且不在其他 namespace；无需再跨 namespace 查找。

用户回传的现场事实（非本轮独立观测）：

| 项目 | 值 |
| --- | --- |
| 页面 origin | `https://10.130.14.23:32643/` |
| Kubernetes context | `kubernetes-admin@kubernetes` |
| namespace / UID | `clawmanager-zhanghui08-system` / `337cfe30-2c17-4b8e-b32a-760778b8098e` |
| 现 App tag / 实际 digest | `backup-test-zh-fix18` / `sha256:c16f07c25c6dc8362aa09b7a1e81f5d1204f2812ae542bbcb21a3946975c6c9d` |
| 新备份 controller | 该 namespace 未部署，其他 namespace 也未部署 |
| 主机工具 / 可用磁盘 | 仅确认 Bash/git/python3/kubectl；未找到 Node/npm/Go；可用约 1.8TB。Docker/Buildx、Registry 登录、架构尚未确认 |

旧 App digest 不是当前源码发行物。大磁盘和 kubectl 管理员 context 不代表构建工具、数据面权限或业务备份授权已具备。用户自行连接、自行执行；不需要向本对话提供 SSH 密钥。

## 可直接复用的构建出口

核对源码基线 `d91eada6eb141ce99232e93e2210dce0290ec4dc`，后续必须由审核者选择 **包含已通过审核 A/C 收尾的最终 commit**，不能直接把本基线当成可部署版本。

| 根 Dockerfile target | 实际内容 | 安装用途 |
| --- | --- | --- |
| `app` | 前端、App `/usr/local/bin/clawreef-server`、`/usr/local/bin/system-backup-v2-controller`，以及既有 CLI | App 镜像及独立 controller Pod 可以复用同一 digest |
| `backup-worker` | scratch、非 root，`/backup-worker` 与 `/system-backup-seal-custody` | 配置中的独立 capture/publish Worker Job 镜像；不能用 App 镜像冒充 |
| `backend-builder` | Go `1.26.1`，同一源码构建上述二进制 | 构建阶段；不是直接部署的运行镜像 |

`app` 默认入口最终运行 `/app/start.sh`，**不会自动启动公共 v2 controller**。独立 controller Deployment 需要显式覆盖容器 `command: ["/usr/local/bin/system-backup-v2-controller"]`，并提供自己的最小 SQL/Kubernetes/TLS 材料。不能把旧 `/usr/local/bin/system-backup-controller` 当公共 controller。

App 和 v2 controller 已写入 buildinfo commit，Worker 构建命令当前没有同样的 commit ldflags；三者同源应由冻结源码、同一 Dockerfile/context 和构建记录证明，不能编造 Worker 自报 SHA。Runtime 自身不由根 Dockerfile 构建；其备份协议和实际停写/原处恢复能力仍须单独匹配验证。

不要应用 `scripts/system-backup-controller-enabled-phase.sh`：它是旧隔离 MySQL smoke，创建 fixture/账号/授权。`system-backup-d-deployment.mjs` 是旧离线 registration/bootstrap 组合，不是当前 six-part 公共 controller 的完整安装器；`team-data-backup/install.py` 属于普通 Team 数据备份。均不能替代本次正式安装。

## 先取得这些审核材料，再生成最终安装清单

目前没有足够真实材料生成可执行 `kubectl apply` 清单。不能以占位 Secret、旧管理员 DSN、手工 readiness 或 fixture bootstrap 凑出成功。安装材料至少包括：

| 材料 / 真实接点 | 必须提供的事实 |
| --- | --- |
| 最终源码与镜像 | A/C 通过审核后的唯一 commit、App 和 Worker 的实际 Registry digest、支持现场节点的架构；App/controller 同一 digest |
| namespace 与身份 | 上述固定 UID、独立 controller/capture/publish/verifier ServiceAccount UID 与最小 RBAC/NetworkPolicy、controller leader lease；不继承 kubernetes-admin 作为 Pod 身份 |
| App API 准入 | `system_backup_tasks_live.go` 所用执行 profile、容量报告、READ_PINS path/hash、当前登录/操作授权；先核对是否已初始化，不盲跑 bootstrap/migration |
| controller 配置 | `DeploymentConfig` 的 six-part profile、installation/application scope、源 DB UUID/库名、Runtime sources、完整 writers、staging PVC/path、控制 URL/TLS、Worker digest；实际文件 hash 必须与签名绑定一致 |
| forward / recovery | `SYSTEM_BACKUP_PUBLIC_CONFIG_FILE` / `SHA256`、`SYSTEM_BACKUP_FORWARD_GRANT_SHA256`、`SYSTEM_BACKUP_RECOVERY_GRANT_SHA256`；真实原签名 grant/key mount、独立恢复权限；不把源只读连接当恢复 writer |
| startup materials | `configuredPublicStartupInputs()` 的 formal verifier、publication signer、publisher verifier、capture modules、publication target 文件和 hash；实际 purpose/key/ref、TLS CA、容量与独立 provider 身份 |
| 六域与内容 | DB/Redis/对象/工作区/部署资源/秘密来源，非空 Teams/Skills 的同任务范围及当前 registry；真实源凭据、卷/namespace/UID，不把旧 schema 已升级当默认 |
| 正式完成出口 | A 当前签名 typed 接口、C 真正 SQL cleanup 接线、acceptance/catalog 当前签名/固定版本登记读回、原任务唯一终态 CAS；须经过审核和组合验证，不只“函数已提供” |
| 原 writer 恢复 | Runtime 实际停止/退出及按原身份/原状态恢复协议和材料；原本停止者不能被启动；不是隔离目标业务恢复专项 |
| 发布与回退 | 原 App 配置和 digest 的恢复清单、新 controller 的独立恢复模式、未决任务/停写保护处置；不能回退到不认识当前活动记录的旧 controller |

`CheckDeploymentDatabaseWithInputs` 会核对部署身份、verifier/signing/capture/target/current policy 和精确 grants，不负责迁移或自动初始化。安装时保留这些检查。`SYSTEM_BACKUP_EXECUTION_PROTOCOL=public-v1` 选择真实 controller；`SYSTEM_BACKUP_ENABLED` 是授权执行输入，不能因 Pod health 就自动置 true。

当前原链 `PublishReadiness` / `PublicCapability` 仍限制 workspace/false；即使 C 的 SQL cleanup 和 A 的 typed 签名接口已交付，也须审核实际调用与完整 finalization 出口，不能先开放六域 readiness。本 runbook 不提供绕过它的 SQL 或开关。

## Bash 路径一：现场只读确认（已有 kubectl 即可）

只读本 namespace，不读取 Secret、不 exec Pod、不扫描其他 namespace。用户执行后将有限输出交审核者；namespace UID 不符立即停止。

```bash
(
  set -euo pipefail
  click_context='kubernetes-admin@kubernetes'
  click_namespace='clawmanager-zhanghui08-system'
  click_uid='337cfe30-2c17-4b8e-b32a-760778b8098e'
  observed_uid=$(kubectl --context="$click_context" get namespace "$click_namespace" -o jsonpath='{.metadata.uid}')
  [[ "$observed_uid" = "$click_uid" ]] || { printf '%s\n' 'Namespace UID mismatch; stop.' >&2; exit 1; }
  kubectl --context="$click_context" -n "$click_namespace" get deployments \
    -o 'custom-columns=NAME:.metadata.name,IMAGES:.spec.template.spec.containers[*].image,REPLICAS:.status.readyReplicas'
  kubectl --context="$click_context" -n "$click_namespace" get pods \
    -o 'custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,IMAGES:.spec.containers[*].image,IMAGE_IDS:.status.containerStatuses[*].imageID'
  for tool in bash git python3 kubectl docker node npm go; do
    if command -v "$tool" >/dev/null 2>&1; then printf '%s=present\n' "$tool"; else printf '%s=missing\n' "$tool"; fi
  done
)
```

该命令不证明 schema/授权/Runtime/最终成品可用，不需要再证明“新增内容未在其他 namespace”。现场节点架构应由部署 owner 从其既有资产记录提供，避免在这里扩大集群查询范围。

## Bash 路径二：审核后在独立构建机打包（不是当前无工具主机）

**仅在 A/C 接口、最终源码和构建范围通过审核后执行。** 需要 Git、tar、Docker Buildx、访问 Dockerfile 基础镜像及依赖源的网络；无需宿主机 Node/Go。先由构建机管理员配置 Registry/CA 信任，不打印凭据。架构由真实节点资产确定，不能默认 arm64/amd64。

下面不切换共享分支、不推镜像、不改集群。用审核后的 commit 导出冻结构建 context，仅把 App/Worker OCI 包和构建元数据留给审核；不要用有用户修改的工作区直接 `docker build .`。审核冻结源码时仍需确认无私密文件进入构建 context；不得通过 build-arg 传秘密。

```bash
# 所有变量都由审核者填写实际值，不使用本轮基线替代最终已审 commit：
# export REPO_ROOT=/absolute/path/to/ClawManager
# export RELEASE_COMMIT=<reviewed-full-40-hex-commit>
# export RELEASE_PLATFORM=linux/amd64   # 必须与现场相符
# export APP_IMAGE_TAG=registry.example/path/app:reviewed-release
# export WORKER_IMAGE_TAG=registry.example/path/backup-worker:reviewed-release
(
  set -euo pipefail
  umask 077
  : "${REPO_ROOT:?absolute source checkout required}"
  : "${RELEASE_COMMIT:?reviewed final commit required}"
  : "${RELEASE_PLATFORM:?actual reviewed node platform required}"
  : "${APP_IMAGE_TAG:?reviewed app tag required}"
  : "${WORKER_IMAGE_TAG:?reviewed worker tag required}"
  [[ "$REPO_ROOT" = /* && "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
  [[ "$RELEASE_PLATFORM" = linux/amd64 || "$RELEASE_PLATFORM" = linux/arm64 ]]
  release_repo=$(realpath -e -- "$REPO_ROOT")
  [[ "$(git -C "$release_repo" rev-parse "$RELEASE_COMMIT^{commit}")" = "$RELEASE_COMMIT" ]]
  docker buildx version
  release_run=$(mktemp -d "$release_repo/.tmp-backup-release-XXXXXXXX")
  release_run=$(realpath -e -- "$release_run")
  [[ "$(dirname -- "$release_run")" = "$release_repo" && "$(basename -- "$release_run")" = .tmp-backup-release-* ]]
  printf 'release_artifacts=%s\n' "$release_run"
  release_builder="sbk-release-$(basename -- "$release_run" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')"
  release_builder_created=0
  release_cleanup() {
    local cleanup_rc=0 release_resolved
    if [[ "$release_builder_created" = 1 ]]; then
      if docker buildx rm "$release_builder"; then
        release_builder_created=0
      else
        cleanup_rc=1
        printf 'Failed to remove this run builder: %s\n' "$release_builder" >&2
      fi
    fi
    # Builder removal failure must not skip this independent path-checked cleanup.
    if [[ ! -L "$release_run" ]] && release_resolved=$(realpath -e -- "$release_run") &&
       [[ "$release_resolved" = "$release_run" && "$(dirname -- "$release_resolved")" = "$release_repo" && "$(basename -- "$release_resolved")" = .tmp-backup-release-* ]]; then
      if ! rm -rf -- "$release_resolved/context"; then cleanup_rc=1; fi
    else
      cleanup_rc=1
      printf '%s\n' 'Refusing context cleanup: release path validation failed.' >&2
    fi
    return "$cleanup_rc"
  }
  release_on_exit() {
    local build_rc=$? cleanup_rc=0
    trap - EXIT
    if release_cleanup; then :; else cleanup_rc=$?; fi
    # Preserve the original build failure; otherwise report cleanup failure.
    if [[ "$build_rc" != 0 ]]; then exit "$build_rc"; fi
    exit "$cleanup_rc"
  }
  trap release_on_exit EXIT
  mkdir -- "$release_run/context"
  git -C "$release_repo" archive "$RELEASE_COMMIT" | tar -x -C "$release_run/context"
  printf '%s\n' "$RELEASE_COMMIT" >"$release_run/source-commit.txt"
  printf '%s\n' "$RELEASE_PLATFORM" >"$release_run/platform.txt"
  docker buildx create --name "$release_builder" --driver docker-container >/dev/null
  release_builder_created=1
  release_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  for release_target in app backup-worker; do
    if [[ "$release_target" = app ]]; then release_tag="$APP_IMAGE_TAG"; else release_tag="$WORKER_IMAGE_TAG"; fi
    docker buildx build --builder "$release_builder" --platform "$RELEASE_PLATFORM" \
      --file "$release_run/context/Dockerfile" --target "$release_target" \
      --build-arg "VERSION=backup-${RELEASE_COMMIT:0:12}" --build-arg "VCS_REF=$RELEASE_COMMIT" \
      --build-arg "BUILD_DATE=$release_date" --build-arg VITE_SYSTEM_BACKUP_LIVE_READ=1 \
      --tag "$release_tag" --metadata-file "$release_run/$release_target.metadata.json" \
      --output "type=oci,dest=$release_run/$release_target.oci.tar" "$release_run/context" \
      >"$release_run/$release_target.build.log" 2>&1
  done
  ( cd "$release_run"; sha256sum app.oci.tar backup-worker.oci.tar *.metadata.json source-commit.txt platform.txt >SHA256SUMS )
  printf 'package_complete=%s\n' "$release_run"
)
```

预期构建退出 0、两个 OCI tar、两个 metadata、source/platform、SHA256SUMS 和日志。tar SHA256 是文件校验，不是 Registry digest，也不是现场 imageID；导入受信 Registry 后应重新读回 manifest digest，由发行 owner 形成 `image@sha256` 清单。这里不提供未经 A/C 审核的 push/apply。EXIT 只清理本轮成功创建的 Buildx builder/cache，并独立校验路径后清理 context；builder 删除失败也会继续尝试 context 清理，错误聚合为非零。原构建失败时保留原退出码，构建成功而清理失败时返回清理错误，不使用全局 prune。OCI 包是待审核发行候选，审核后只删除上述唯一 release 目录；若是纯测试构建，测试结束即按同样范围清理。

## 尚缺的最终安装包与执行顺序

此刻交付的是构建出口和安装前置 runbook，**不是可直接启用的生产部署包**。材料齐备后，D 应在主审核协调下生成并交付以下实际文件，再提供单次 Bash apply 命令：

1. 固定 App/Worker digest 和源码的发行清单；源 namespace UID/当前 App digest 前置核验。
2. 该 namespace 的最小 SA/RBAC/NetworkPolicy/Lease、controller Deployment 与实际只读/私密挂载；不得带伪造的默认 installation 或 grant。
3. 真实文件/hash/ref 构成的私有安装材料清单（不把秘密正文放 Git），源六域、Runtime 与独立 publisher/verifier 的身份配置。
4. App 精确增量 patch、独立 controller 启动与健康/选主核验；Worker 由原任务生成 Job，不另起无任务长期 worker。
5. 一次页面点击、原 task 六域/Teams/Skills、物理停写/恢复、正式成品与 catalog/终态的证据命令，以及失败后原任务查询和保留保护路径。

暂不执行迁移、bootstrap、`SYSTEM_BACKUP_ENABLED=true`、readiness 更新、App 滚动或 controller 安装。不能因为新版二进制已进镜像就认为原授权/数据库已初始化。完整点击工具的独占目录 Bash 命令见 `docs/system-backup-d-live-click-entry-20261102.md`；当前无 Node/npm 的主机需要先准备独立浏览器验收机或已审核运行时，不能直接运行它。

本轮验证仅源码阅读和文档 diff 检查；没有执行上述 kubectl 或构建命令，没有构建产物，A/C 新接口由主审核统一验证。
