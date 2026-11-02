# 公共 C：正式发布收尾接点（2026-11-02）

基线 `backup@171ad17ca37b9889c7ca23e9103ae8da3c74423c`。仅本轮三个 Go 文件及本文属于 C；共享目录中其他 owner 的增量、用户 `docs/deployment_cn.md`、`.worktrees/` 不属于本交付。未提交、推送、连接服务器或执行生产变更。

## 当前真实主链及缺口

以生产调用为准：`RunPublicationPass` → `runPublicationForwardPreparation` → 原任务 C 全量校验/封装/原上传 → `completeOriginalPublicationThroughNativeCleanup`。内部已有固定版本完整 C 读回、正式 manifest、`_COMMITTED`、原上传退出、候选删除、Secret/Pod/Job 删除确认。

当前 first-forward 在 native cleanup 返回后结束；`runPublicationContinuation` 对 `acceptance_put` / `catalog_registration_append` 仍返回 `ErrPublicationFinalizationRequired`。因此现有 catalog transport 及 JSON 上传原语不能视为正式登记已完成，也不能据此设置成功终态。

最新 `ad-collector-current-read-reviewed-20261102.json` 的同任务现场仍在采集窗口失败；并无本轮六模块成品。本文及新增测试均不构成现场成功、完整恢复或 Teams/Skills 非空证据。

## 本轮补丁及接口

- `publicationRecordSeals(record)`：从当前独立 publisher 返回的原记录推导 C 与 envelope 两个精确 seal intent；核对原任务、attempt、config、Job UID/代数/unit、invocation、binding 及候选校验。已接入生产 `publicationJobInputs`，与原上传挂载命名保持一致。
- 本轮没有保留未被生产消费的 `originalLocalSeals` helper。本地删除及其完整封存集合枚举仍未接线。`publicationRecordSeals` 返回值仅在上传路径被实际消费；不执行删除、不签名、不生成 acceptance、不取得新 claim。

## 必须由审核者协调的下一个接口

1. C 后续补齐本地目录 SQL 删除日记及完整封存枚举：消费实际完成的 native receipt，逐成员重读当前独立 publisher 原记录，覆盖六个 container 内部原成员及控制证据，绑定同 task/attempt 的完整 C receipt；在原 `system_backup_v2_staging_resources` capture hostpath 行上做精确 CAS，围绕 `publicationLocalFiles.removeLocked` 的 authorize 回调保留当前 claim/owner/HMAC/时限及 deleting 状态检查；完整确认目录、seal 和 intent 缺失后才能写 cleanup evidence。中断后只查询原删除，不产生新根任务。
2. A 提供/审核当前 `acceptance_record` 与 `catalog_record` 的正式签名输入、签名重入及当前授权接点；正式 acceptance 必须引用实际完整 cleanup evidence，不能用 native-only 元数据代替。
3. C 消费上述 typed receipt 生成固定 manifest/marker/acceptance locator 的 catalog registration，并独立读回原版本。D 独占的构造/controller 调用处接到上述完整收尾，再由唯一 SQL 状态权威结算终态。不能直接解除 continuation 的 finalization guard。
4. D 页面现场验收必须保持一个 task/attempt，记录真实版本及固定版本读回；Teams/Skills SQL rows 和文件/对象须来自同一成品实际解包结果。不可硬编码非空计数；合法空源策略另行处理。

## 验证与远测

新增回归检查 seal 命名等价及任务/attempt/Job/代数/invocation/binding/候选篡改拒绝。既有文件清理回归检查同任务精确删除与外部任务保留。这些都是本地 fixture，不代表生产授权或成功。

本机验证记录（cwd 为仓库 `backend`）：默认缓存命令 `go test ./internal/systembackupexecution -run 'TestPublicationLocalSeals|TestPublicationLocalFiles' -count=1` 退出 1（缓存写权限拒绝）；改本轮独立缓存后的相同命令退出 1（收窄切片重命名时文件已移除，随后又遇 C 盘空间不足）。最终文件集合命令为 `GOMAXPROCS=2 go test -p 2 ./internal/systembackupexecution -run 'TestPublicationLocal|TestPublicationNativeCleanup' -count=1 -v`，退出 1，同样遇 C 盘空间不足，未进入测试执行，不算通过。三个 Go 文件的 `gofmt -l` 无输出；指定文件 `git diff --check` 退出 0。所有测试进程已退出，已删除本轮 `backend/.c-publication-test-cache`、`backend/.c-publication-test-tmp`。审核者要求暂不重跑、不推送未验证 Go 补丁。没有删除其他 owner 文件。

审核者在已授权的隔离 Linux 测试机执行以下完整命令；不适用于生产数据库。前提：Go 1.26.1+、Python 3、已备好依赖；`REPO_ROOT` 指向本补丁工作区。`A_SIGNING_MYSQL_CREDENTIALS_FILE` 用于原121上传用例，`TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS` 用于同任务 native cleanup 用例。后者要求 Host 为 `127.0.0.1`、ServerUUID 非空、CA/SAN 匹配及 TLS 1.3；只允许可丢弃的 owner 测试数据库及其建表/清理权限。不要打印凭据。此命令验证当前原上传到 native cleanup，仍不宣称 acceptance/catalog 成功。

```bash
set -euo pipefail
: "${REPO_ROOT:?absolute checkout path required}"
: "${A_SIGNING_MYSQL_CREDENTIALS_FILE:?isolated owner MySQL fixture file required}"
: "${TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS:?isolated task-owned SAN/TLS MySQL fixture file required}"
test -r "$A_SIGNING_MYSQL_CREDENTIALS_FILE"
test -r "$TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"
cd "$REPO_ROOT/backend"
work=$(mktemp -d "${TMPDIR:-/tmp}/c-publication-20261102.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
export GOCACHE="$work/cache" GOTMPDIR="$work/tmp" GOTELEMETRY=off GOMAXPROCS=2
mkdir -p "$GOCACHE" "$GOTMPDIR" "$REPO_ROOT/docs/evidence"
log="$REPO_ROOT/docs/evidence/c-publication-closeout-20261102-$(date -u +%Y%m%dT%H%M%SZ).jsonl"
go test -p 2 ./internal/systembackupexecution -run '^(TestPublicationLocal.*|TestPublicationJobOriginal121SingleSendSuspendedMySQL|TestDOriginalUploadedManifestMarkerAndNativeCleanupMySQL)$' -count=1 -json -timeout 10m 2>&1 | tee "$log"
python3 - "$log" <<'PY'
import json, sys
events = []
for line in open(sys.argv[1], encoding='utf-8'):
    try: events.append(json.loads(line))
    except ValueError: pass
required = {'TestPublicationLocalSealsMatchOriginalUploadCustodyData', 'TestPublicationJobOriginal121SingleSendSuspendedMySQL', 'TestDOriginalUploadedManifestMarkerAndNativeCleanupMySQL'}
assert not any(e.get('Action') == 'skip' for e in events), 'SKIP is not remote verification'
passed = {e.get('Test') for e in events if e.get('Action') == 'pass'}
assert required <= passed, 'required tests did not complete'
PY
```

预期退出码 0，指定 MySQL 用例不得 SKIP；日志是测试材料，不能标为真实页面完成证据。临时构建缓存/产物由 EXIT trap 删除，保留日志供审核；测试自身清理其归属 SQL/对象夹具。真实页面远测须由 D/审核者提供现场上下文和授权，本轮未擅自执行。
