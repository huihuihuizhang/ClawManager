# D：真实页面点击入口与当前准入阻塞（2026-11-02）

核对基线 `171ad17ca37b9889c7ca23e9103ae8da3c74423c`。本轮新增 `e2e/backup-live-click.mjs`、`e2e/backup-live-contract.mjs`、`e2e/backup-live-contract.test.mjs` 和本文；不提交、不切换分支、不连接生产。共享工作区中的其他 owner 修改不属于本轮。`docs/deployment_cn.md` 和 `.worktrees/` 未动。

## 当前调用链与阻塞

1. `/admin/backups/records` 的 `BackupLiveWorkspace.createBackup` 调 `createSystemBackupTask`，固定六域、`task_purpose=acceptance`、原 JSON 和幂等键，要求 202/live。
2. App `backend/cmd/server/system_backup_tasks_live.go` 通过 `NewAdmittedTaskWriter` 和 `composeSystemBackupTaskApplication` 处理请求。`systembackupapi/deployment_admission.go:check` 在原事务读取有效 readiness，并检查 acceptance 和每项 supported_parts。
3. 真正 controller 入口是 `backend/cmd/system-backup-v2-controller/public_capture.go:runConfiguredPublic`，调用 `NewDeploymentServiceWithInputs`。`deployment_service.go:composeCaptureRuntime` 依次接 `attachRuntimeSources`、`attachProductionSources`、`NewPublicCapture`。
4. **旧交接的“BuildParts只有workspace”不是完整的当前事实。** `production_source_profile.go:attachProductionSources` 在 six-part 下清掉旧 BuildParts，以冻结源/writers 构造模块 factory，含 Teams/Skills inventory。不能继续平行重接这些模块。
5. **当前明确的第一道生产阻塞仍是 readiness**：`deployment_service.go:PublishReadiness` 固定 `supported_parts='workspace', acceptance_ready=FALSE`；`deployment_platform.go:PublicCapability` 亦固定 workspace/false。因此当前代码正常发布 readiness 后，页面六域 acceptance 请求应在采集前被 `not_ready` 拒绝。本文不建议手改表、扩大能力或提前置 true。后续解锁要以完整采集/正式发布能力的实证为依据。
6. `systembackupkekadapter/deployment.go:WireServices` 当前只有定义和测试调用，没有生产调用；该跨 owner 接线由主审核协调 A。最新 `ad-collector-current-read-reviewed-20261102.json` 仅证明当前检查合并后的组件行为，未提供 v14 同 task native 成功。

### readiness 最小可安全推进的顺序与精确依赖

不能仅因 six-part factory 已构造就把 acceptance readiness 置 true。当前不是缺一个条件表达式，而是下面的原任务成功出口尚未完成：

| 接点 / owner | 当前事实 | 接到生产 ready 前的最小条件 |
| --- | --- | --- |
| A `systembackupkekadapter.WireServices`；D 配合实际 bootstrap/mutation 构造 | 未发现生产调用；原 DB 授权窗内完整 native 尚未成功 | 审核者确定真实配置 bootstrap/mutation 调用点与原 SQL 身份，A 提供原签名输入与 permit；在原 30/5 界限、同量源和检查不减的条件下完成 DB 与 CE 采集 |
| D `composeCaptureRuntime` / `attachProductionSources` / `NewPublicCapture` | six-part 模块和源冻结已有连接 | 真实 runtime/provider/source scope、完整六域（含非空 Teams/Skills）及当前身份可用；原任务 writers 停止、采集、退出、按原状态恢复，保留原门禁证据；不重写 factory |
| C `completeOriginalPublicationThroughNativeCleanup` 后的封存目录收尾 | native cleanup 存在；共享 C 当前新增 `publication_record_seals.go` 提供 seal 接点，尚由审核者评审；不等于完整 SQL cleanup 日记已完成 | 原 seal/intent/capture hostpath 精确删除日记和完整 cleanup evidence，失败后只查原操作 |
| A 签名 + C `publication_continuation.go:publishNext` / `publishOriginalJSON` | `acceptance_put` 和 `catalog_registration_append` 明确返回 `ErrPublicationFinalizationRequired` | 消费真实 cleanup typed receipt；正式 acceptance/catalog 输入及独立签名授权；固定原版本写入与独立读回；不能仅删 guard |
| C 唯一终态权威 + D controller 调用 | `RunPublicationPass` 还不能证明正式 acceptance/catalog 后唯一成功 CAS | 提供当前 claim/attempt 下可重入的 typed 完成接口，确认五项固定摘要、登记/读回与原资源收尾后结算原任务，不创建第二状态机 |
| D `PublishReadiness` 与 `PublicCapability` | 两处仍固定 workspace/false | 上述实现和 native 出口通过审核后，再用同一能力判定同时生成 supported_parts 与 acceptance_ready；仍保留当前 grants/Kube/source/lease/config/profile/freshness 全部校验。workspace profile 行为不变；缺任意能力/依赖拒绝六域 |

当前可独立安全交付的是页面协议和乱序修正；直接修改 ready 将允许用户进入尚无 acceptance/catalog 出口的任务，故本轮不改生产 ready。C 的原 native/local-cleanup receipt 和 A 的签名/授权边界尚未有完整收尾签名，D 不在此虚构一个 bool/回调充当实现。下一生产切片应由审核者协调 C 的 cleanup→acceptance/catalog typed 接口和 A 的当前签名输入，D 再接 `RunPublicationPass` 调用出口；接口返回必须绑定原 claim、attempt、固定产物及当前验证，不能只返回 `error=nil` 即授予成功。

## 新入口的范围

`node e2e/backup-live-click.mjs` 使用真实 Playwright storage state，打开已运行的实际前端，点击一次真实“创建备份”按钮。无 `page.route`、无 fixture、无合成登录态、无 SQL/部署操作；不自动重试或取消。TLS 验证保持启用。Auth/MFA/授权不足按真实页面/API 拒绝。

监听实际请求，保存原幂等键及 body SHA256，要求六域 acceptance 请求且仅一次。只接受 202/live 和同幂等键回执，随后监听页面自己的原任务详情读取，核对 task/installation 身份。它不直接创建第二任务，也不另用服务端 API 模拟点击。

已按真实源码复核协议：`systembackupapi/tasks.go:Create` 在成功分支设置 live marker、Location 和 Retry-After，`writeJSON` 直接编码 `ProjectTask` 的裸 DTO。handler 在编码前核对原 endpoint/key；frontend Axios 没有成功响应拆 envelope 拦截器，`response.data` 即该 DTO。因此保留 live/endpoint/key 检查，移除脚本旧的通用 `.data` envelope 兼容。`backupApiRead.ts:taskPath` 和 `BackupLiveDetail` 确认实际详情路径为 `/api/v1/admin/system-backups/<id>`，不带查询参数。

详情只监听本次原 task URL，并核对 live/origin/row-version 三个头与正文精确一致。处理时在 `await response.json()` 之后调用 `advanceDetail`：小于创建初始版本或小于等于已处理版本的响应直接忽略，不改变 ready/失败状态；较新版本正常推进。历史详情响应不影响本次运行。

仅记录白名单字段，不保存 token、storage state、原始响应、业务内容、自由错误字符串、页面截图或 HAR。认证文件为只读输入。

- 退出 1：配置/依赖/认证缺失、按钮禁用、提交拒绝/不明、任务失败或超时。原任务可能仍运行，禁止盲目再点；先查保存的原 key/task，按原操作安全收敛。
- 退出 2：同一任务公开详情已 `succeeded`、六域请求、strong、committed/usable、acceptance_ready/eligible、verifier passed，且 manifest/index/marker/acceptance/catalog 五项摘要齐全；仍需独立实证。
- **不提供完整验收的退出 0**：当前公开 DTO 不能证明各域结果、非空 Teams/Skills、源 writer 实际停止与按原状态恢复。`full_acceptance` 始终 false，202 绝不算成功。不是要求先完成“从备份到隔离目标的完整业务恢复”。

这是可执行的现场采证入口，不是已执行的现场成功证据。公开投影就绪后，由审核者将该原 task 对齐 controller/worker 六域结果、源 writer 原物理回执及正式产物/catalog 校验，才能判完整备份。

## 依赖与启动

本机检查：未安装 `e2e/node_modules/@playwright/test`；未发现可复用 mysqld 或 9001/9002 监听（端口枚举命令未返回条目，不代替网络连通实测）。没有可复用的 TLS 数据库身份、已审核部署配置或真实登录态。本轮没有启动服务、安装依赖或执行现场点击。

现场前提：由部署 owner 在已授权隔离环境提供匹配源码的 App/controller/Worker/Runtime、TLS SQL/Redis/对象/卷/Teams/Skills 源、签名/KEK/独立 verifier/catalog 身份与最小 grants、原 Runtime 能力和 writer 恢复身份、有效容量报告及审批配置。Linux controller 必须实际运行/选主并发布匹配 config/profile readiness；当前 readiness 限制尚未解除。不要把旧 native fixture 的手工 readiness 输入复制到部署。

已具备上述私有配置后，服务启动入口如下（各自独立终端；仓库 `backend/` cwd；先由 owner 注入已审核环境，本文不生成或展示秘密）：

```sh
go run ./cmd/server
```

```sh
# Linux 环境；SYSTEM_BACKUP_EXECUTION_PROTOCOL=public-v1 及其余审核配置已注入
go run ./cmd/system-backup-v2-controller
```

前端本地入口（PowerShell，真实 API 反向代理默认 127.0.0.1:9001；不改代理去碰生产）：

```powershell
Set-Location 'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\frontend'
$env:VITE_SYSTEM_BACKUP_LIVE_READ = '1'
npm run dev -- --host 127.0.0.1
```

## zhanghui08 最终环境：Bash 点击命令

用户指定页面 `https://10.130.14.23:32643/admin/instances`。参数必须传 **origin** `https://10.130.14.23:32643/`；脚本在该 origin 打开 `/admin/backups/records`，不把 instances 路径传给 BACKUP_LIVE_URL。不需要本地前后端启动或 SSH。以下均为待执行命令，本轮没有连接该地址、安装或部署。

**当前 readiness 尚未具备完整备份条件，这套命令只能采真实拒绝/受阻证据，不能证明完整成功。** 不得改 readiness、绕过认证或关闭 TLS 来取得成功。

### 依赖、可信 CA 与真实登录态

只要求两个必填参数：`REPO_ROOT`（验收机实际 checkout 绝对路径）和 `BACKUP_LIVE_STORAGE_STATE`（实际管理员在该 origin 完成真实登录/MFA 后导出的 Playwright storage state 绝对路径）。认证文件是只读秘密输入，父目录权限 700、文件 600，不打印、不提交，不使用 fixture token、seeded admin 或其他 origin 的 state。

浏览器使用锁文件的 Playwright 及自带完整 Chromium，设置 `PLAYWRIGHT_CHANNEL=chromium`，不要求安装 Google Chrome。验收机需已具备 Node/npm 及 Chromium 所需 Linux 系统库；主命令安装 npm 依赖并下载独占浏览器。缺系统库时，由环境管理员在本轮打印的工具目录执行 `./node_modules/.bin/playwright install-deps chromium`，或使用 `install --with-deps chromium`；不借启动 flags 绕过环境故障。参考 [Playwright 官方浏览器文档](https://playwright.dev/docs/browsers)。

CA 沿用实际浏览器已受信的证书链。私有 CA 须由环境 owner 通过可信渠道核对并配置到该验收用户实际浏览器的信任库，服务端链完整且叶证书 SAN 包含 IP `10.130.14.23`；未信任或 SAN 不符就停止修复证书，不关闭 TLS 校验。Linux 信任库说明见 [Chromium 官方证书管理](https://chromium.googlesource.com/chromium/src.git/+/master/docs/linux/cert_management.md)。无需为本脚本额外提供 NSS 路径、昵称或指纹参数。`NODE_EXTRA_CA_CERTS=/absolute/trusted/root-ca.pem` 是可选的 Node/npm 下载信任配置，**不等于 Chromium 信任**；按现有环境设置即可。禁止 `NODE_TLS_REJECT_UNAUTHORIZED=0`、`ignoreHTTPSErrors` 和 `--ignore-certificate-errors`。

登录态生成是独立交互步骤。若需新建，在已安装 Playwright/Chromium 且配置好浏览器 CA 信任的交互环境，选择不存在的新私有输出文件，真实完成认证后关闭浏览器保存：

```bash
# cwd 是已安装 Playwright 的工具 e2e 目录；路径为实际用户指定的新私有输出。
: "${BACKUP_LIVE_STORAGE_STATE:?absolute new private output filename}"
[[ "$BACKUP_LIVE_STORAGE_STATE" = /* && ! -e "$BACKUP_LIVE_STORAGE_STATE" ]] || exit 1
if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
  printf '%s\n' 'No interactive display: do not run codegen; supply genuine state from an approved interactive browser session.' >&2
else
  ( umask 077
    ./node_modules/.bin/playwright codegen --browser chromium \
      --save-storage="$BACKUP_LIVE_STORAGE_STATE" \
      'https://10.130.14.23:32643/admin/instances'
  )
fi
```

**无 DISPLAY/Wayland 的 SSH shell 不得盲跑 codegen**；虚拟显示也不能替用户完成真实认证。可在可交互、可访问该 origin 的环境生成后，经私有渠道放到验收机；如会话绑定设备/IP、过期或不满足 MFA freshness，应重新真实登录，不改库续期。主命令不删除登录态输入。

### Bash 主命令：独占工具目录、安装、点击及日志

下面复制 `e2e/package.json`、`package-lock.json` 和三个 `backup-live*.mjs` 到唯一 mktemp run 目录的 `e2e/`，在其中 npm ci、安装本次独占 Chromium 并运行。复制脚本的 root 自然是 run 目录，receipt 也在 run 内。不触碰原 checkout 已有 `e2e/node_modules`，不启动、连接 SSH 或部署服务。Node/npm 和系统库的安装属于验收机环境准备，不在本命令自动改系统。

```bash
# 在外层设置两个真实绝对路径：
# export REPO_ROOT=/absolute/path/to/ClawManager
# export BACKUP_LIVE_STORAGE_STATE=/absolute/private/path/admin-state.json
# 可选：export NODE_EXTRA_CA_CERTS=/absolute/trusted/root-ca.pem
(
  set -euo pipefail
  umask 077
  : "${REPO_ROOT:?absolute checkout path required}"
  : "${BACKUP_LIVE_STORAGE_STATE:?absolute genuine authenticated state required}"
  [[ "$REPO_ROOT" = /* && "$BACKUP_LIVE_STORAGE_STATE" = /* ]]
  click_repo=$(realpath -e -- "$REPO_ROOT")
  click_state=$(realpath -e -- "$BACKUP_LIVE_STORAGE_STATE")
  [[ -d "$click_repo/e2e" && -f "$click_state" ]]
  command -v node >/dev/null
  command -v npm >/dev/null
  click_run=$(mktemp -d "$click_repo/.tmp-backup-live-bash-XXXXXXXX")
  click_run=$(realpath -e -- "$click_run")
  [[ "$(dirname -- "$click_run")" = "$click_repo" && "$(basename -- "$click_run")" = .tmp-backup-live-bash-* ]]
  printf 'logs_and_receipts=%s\ntool_cwd=%s/e2e\n' "$click_run" "$click_run"
  click_cleanup_builds() {
    [[ ! -L "$click_run" && "$(realpath -e -- "$click_run")" = "$click_run" && "$(dirname -- "$click_run")" = "$click_repo" ]] || return 1
    [[ "$(basename -- "$click_run")" = .tmp-backup-live-bash-* ]] || return 1
    rm -rf -- "$click_run/e2e/node_modules" "$click_run/browsers" "$click_run/npm-cache"
  }
  trap 'click_trap_rc=$?; printf "%s\n" "$click_trap_rc" >"$click_run/process-exit-code.txt"; click_cleanup_builds' EXIT
  mkdir -- "$click_run/e2e"
  for click_file in package.json package-lock.json backup-live-click.mjs backup-live-contract.mjs backup-live-contract.test.mjs; do
    click_source=$(realpath -e -- "$click_repo/e2e/$click_file")
    [[ "$click_source" = "$click_repo/e2e/$click_file" && -f "$click_source" ]]
    cp -- "$click_source" "$click_run/e2e/$click_file"
  done
  export PLAYWRIGHT_BROWSERS_PATH="$click_run/browsers"
  export npm_config_cache="$click_run/npm-cache"
  cd "$click_run/e2e"
  npm ci
  # chromium channel needs the full bundled browser; do not pass --only-shell.
  ./node_modules/.bin/playwright install chromium
  export BACKUP_LIVE_URL='https://10.130.14.23:32643/'
  export BACKUP_LIVE_STORAGE_STATE="$click_state"
  export BACKUP_LIVE_TIMEOUT_MS=600000
  export PLAYWRIGHT_CHANNEL=chromium
  set +e
  node ./backup-live-click.mjs >"$click_run/click.stdout.json" 2>"$click_run/click.stderr.log"
  click_rc=$?
  set -e
  printf '%s\n' "$click_rc" >"$click_run/exit-code.txt"
  printf 'click_exit=%s\nlogs_and_receipts=%s\n' "$click_rc" "$click_run"
  cat "$click_run/click.stdout.json"
  exit "$click_rc"
)
# 外层读取上一命令 $?；exit-code.txt 保存点击退出码，process-exit-code.txt 也记录安装等前置失败。
# 外层若启用 set -e，非零会结束外层脚本；自动编排时用 if 包装整个子 shell。
```

当前预期退出 **1**（按钮不可用、认证/依赖不足或 API not_ready），不是采集通过。未来公开成品条件齐全时退出 **2**，仍需同任务六模块（含非空 Teams/Skills）、源 writer 物理恢复及正式产物/catalog 实证；**不提供完整验收退出 0**。stdout 给出 receipt 绝对路径，其目录也在 run 内；`click.stdout.json`、`click.stderr.log`、退出码文件和 receipt 均保留供审核。stderr 是私有故障日志，审核前不对外上传。非零不得触发自动重试点击。

### 精准清理

EXIT trap 只删除本次 run 内的 npm 安装、独占浏览器二进制和 npm cache 等测试构建产物；保留复制工具、日志和 receipt。不会删除原 checkout 安装、认证输入、CA 配置或远端任务/产物。审核后将 `BACKUP_CLICK_RUN_DIR` 设为主命令打印的唯一绝对 run 路径，按 realpath 核验后只删整个本次 run，不枚举其他目录：

```bash
: "${REPO_ROOT:?absolute checkout path}"
: "${BACKUP_CLICK_RUN_DIR:?exact logs_and_receipts directory printed by this run}"
[[ "$REPO_ROOT" = /* && "$BACKUP_CLICK_RUN_DIR" = /* ]]
click_repo=$(realpath -e -- "$REPO_ROOT")
click_run=$(realpath -e -- "$BACKUP_CLICK_RUN_DIR")
[[ ! -L "$BACKUP_CLICK_RUN_DIR" && "$(dirname -- "$click_run")" = "$click_repo" && "$(basename -- "$click_run")" = .tmp-backup-live-bash-* ]] || exit 1
rm -rf -- "$click_run"
```

不生成前端 dist、Go 测试二进制或浏览器 trace/video。本节仅更新最终环境执行方案，脚本业务逻辑未变；安装、登录、点击、清理命令均尚未在该环境执行。前次本机 Git Bash `bash -n` 在启动阶段被 Windows 沙箱拒绝创建 signal pipe，未执行语法检查，不计为通过；本文命令只作静态核对。本轮未生成测试构建产物。

## 本轮验证及后续接口

- `node --check e2e/backup-live-click.mjs`：退出 0。
- `node e2e/backup-live-click.mjs --help`：退出 0，不连接网络。
- 不设置 BACKUP_LIVE_URL/state 运行：退出 1，`dependency_missing / full_acceptance=false / receipt=null`；无目录或构建产物生成。
- `node --test e2e/backup-live-contract.test.mjs`：当前沙箱子进程 `spawn EPERM`，未执行用例；随后使用 Node 自身的无子进程模式 `node --test --test-isolation=none e2e/backup-live-contract.test.mjs`，4/4 PASS、0 skipped、退出 0。覆盖裸创建 DTO/live/endpoint/key/Location 反例、原 task 详情头绑定、乱序/同版本不回退、新版本失败、缺 catalog 不可用。均为明确本地契约 DATA，不是现场证明。
- 未安装浏览器依赖，未运行浏览器/现场后端；不能将语法和配置反例写成点击通过。

A：协调 `WireServices` 的生产 bootstrap/mutation 实际调用位置和原授权窗内 DB 优化实证。公共 C：先完成原任务发布/清理/签名验收/catalog/终态，给出可独立验证的原 task 结果，之后 D 才能据实补 readiness。

只读投影接口建议（需审核者协调 read DTO owner，不在本轮越界改合同）：为 `BackupDetailResource` 提供服务端认证的原 task/attempt 证据引用，覆盖六域成功集合、Teams/Skills 非空摘要、writer 停止/原状态恢复回执和最终 catalog 绑定。不能用客户端 DTO 或任意 bool 授予成功。若当前证据下载已覆盖这些事实，优先给出其现有类型/路径，不新增第二结果权威。
