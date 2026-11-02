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

也可直接给已部署前端 origin，无需本地启动前端。E2E 依赖在 `e2e/` 执行 `npm ci`；Chrome 可用时默认 channel=chrome，缺 Chrome 由环境 owner 安装浏览器。登录态可用 Playwright `codegen --save-storage` 对实际登录页交互完成真实认证；私有 state 放到仓库根 `.tmp-*` 忽略目录，勿复用 seeded auth setup 的默认管理员。

## 远测命令与日志

以下 PowerShell 在运行浏览器的验收机执行，替换真实已授权 origin 和已完成认证的私有 state 路径；不需要 SSH，不在此步骤部署或改生产。值未提供前不要直接执行示例。

```powershell
Set-Location 'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager'
$env:BACKUP_LIVE_URL = 'https://REPLACE-WITH-AUTHORIZED-FRONTEND/'
$env:BACKUP_LIVE_STORAGE_STATE = 'C:\REPLACE-WITH-PRIVATE-STATE\admin.json'
$env:BACKUP_LIVE_TIMEOUT_MS = '600000'
$env:PLAYWRIGHT_CHANNEL = 'chrome'
node e2e/backup-live-click.mjs
$clickExit = $LASTEXITCODE
Write-Output "backup click exit=$clickExit"
```

stdout 给出唯一绝对 `receipt.json` 路径，目录 `.tmp-backup-live-click-*` 已被现有 `.gitignore` 忽略。当前生产限制下预期退出 1（按钮不可用或 API 拒绝），不是采集通过；未来公开成品条件齐全预期退出 2，需补上述同任务实证。不要把两个退出码改为成功。

记录审核结论后清理本次日志目录：将 `$clickReceiptDirectory` 设为 stdout 返回 receipt 的父目录，只删该目录。以下校验必须通过；不枚举/删除所有 `.tmp-*`，不删认证输入或他人目录。

```powershell
$clickRoot = (Resolve-Path -LiteralPath '.').Path
$clickDirectory = (Resolve-Path -LiteralPath $clickReceiptDirectory).Path
if ((Split-Path -Parent $clickDirectory) -ne $clickRoot -or
    (Split-Path -Leaf $clickDirectory) -notlike '.tmp-backup-live-click-*') { throw 'Unexpected cleanup target' }
Remove-Item -LiteralPath $clickDirectory -Recurse -Force
```

入口不生成构建文件、浏览器 trace/video 或下载。服务测试结束正常停止 `go run`/Vite，Go 临时运行二进制随退出回收；若另做构建，构建 owner 必须按 AGENTS 清理自己产物。

## 本轮验证及后续接口

- `node --check e2e/backup-live-click.mjs`：退出 0。
- `node e2e/backup-live-click.mjs --help`：退出 0，不连接网络。
- 不设置 BACKUP_LIVE_URL/state 运行：退出 1，`dependency_missing / full_acceptance=false / receipt=null`；无目录或构建产物生成。
- `node --test e2e/backup-live-contract.test.mjs`：当前沙箱子进程 `spawn EPERM`，未执行用例；随后使用 Node 自身的无子进程模式 `node --test --test-isolation=none e2e/backup-live-contract.test.mjs`，4/4 PASS、0 skipped、退出 0。覆盖裸创建 DTO/live/endpoint/key/Location 反例、原 task 详情头绑定、乱序/同版本不回退、新版本失败、缺 catalog 不可用。均为明确本地契约 DATA，不是现场证明。
- 未安装浏览器依赖，未运行浏览器/现场后端；不能将语法和配置反例写成点击通过。

A：协调 `WireServices` 的生产 bootstrap/mutation 实际调用位置和原授权窗内 DB 优化实证。公共 C：先完成原任务发布/清理/签名验收/catalog/终态，给出可独立验证的原 task 结果，之后 D 才能据实补 readiness。

只读投影接口建议（需审核者协调 read DTO owner，不在本轮越界改合同）：为 `BackupDetailResource` 提供服务端认证的原 task/attempt 证据引用，覆盖六域成功集合、Teams/Skills 非空摘要、writer 停止/原状态恢复回执和最终 catalog 绑定。不能用客户端 DTO 或任意 bool 授予成功。若当前证据下载已覆盖这些事实，优先给出其现有类型/路径，不新增第二结果权威。
