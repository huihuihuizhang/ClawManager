# A：原 30 秒窗口 Linux testbinary 诊断入口

本轮新增 A 专用测试入口、Bash 打包/执行脚本，并同步旧 PowerShell 入口；保留原授权/撤权/窗口逻辑，按第8节优化后续同事务当前读。A 未 SSH、构建或运行 native。入口调用的仍是原 `runDOriginalUploadedManifestThroughRemoteCAnd102(t, true, true, true)`，等价于原 candidate-cleanup 用例的同任务完整路径：六模块/十一采集成员、原 capture certificate、上传、独立 C、manifest、marker、candidate cleanup。测试内只创建一个新的原任务，不续用已过期历史任务，也不修改原 30 秒 key 窗。它仍为隔离协议 fixture DATA；Kube/native API 含 fake tracker，不是页面/生产现场证明。

## 1. 最小可执行接点及当前门禁

- testbinary 用例：`TestAPermitTimingOriginalThirtySecondNativeMySQL`，文件 `backend/internal/systembackupexecution/a_permit_native_diagnostic_test.go`。
- 打包：`scripts/system-backup-a-permit-native-package.sh`，消费审核者统一编译的 Linux amd64 ELF，不自行调用 Go。
- 已有专用实例：包内 `run-diagnostic.sh`。先 TLS/UUID/全库可见性/空业务库 census，再调用原用例。
- 自建隔离实例：包内 `run-disposable.sh`。只启动本轮独占、digest 固定且已预加载的 MySQL 8.4 Docker 镜像，绑定 `127.0.0.1:63507`；新建带随机 owner label 的专用 volume、SAN/TLS 和随机 root 密码。退出时核对 label，删除自己的 container、volume、密码、证书和工作目录。不给它任何生产 data volume、DB endpoint、Kube config 或生产凭据。

审核者已将实际 `WithProviderPermitTiming` / `provider-permit-stage-timing DATA` 接点统一接入 D 的 `production_same_task_mysql_test.go:576`，本轮静态读回确认存在。**操作者不需要手工 apply patch。** 打包脚本同时核对实际原 handler 源码和 ELF 中的 hook marker、新测试名、linked commit；任何一项缺失就拒绝。不能把“源代码有 helper”当作 native 已可测。包检查只是必要条件，不替代审核者对完整构建来源的 pin。

## 2. 精确运行时文件集合

```text
bundle/
  bin/systembackupexecution.test
  backend/internal/systembackupexecution/              # 必须从这个 cwd 运行
  backend/internal/systembackupbusinessa/testdata/
    schema-registry-historical-15.json
  contracts/system-backup/v12/admin-control-redacted-examples.json
  run-diagnostic.sh
  run-disposable.sh
  SOURCE_COMMIT
  SOURCE_STATE                                       # 全工作区 clean / dirty
  SOURCE_STATUS                                      # git status（不展开其他目录）
  SOURCE_PATHS.nul                                   # backend/contracts/scripts 实际文件集合
  SOURCE_FILES.sha256                                # 上述每个实际文件的 SHA-256
  SHA256SUMS
```

这两个 JSON 是原用例直接读取的外部静态文件。原 signing/source/staging/credential/policy/workspace/CA 等其余输入均由该 fixture 在私有临时目录生成，不应从生产导出填入包。

本入口 **不需要随包复制 migrations 目录**：`internal/db/migrations.go` 使用 `//go:embed migrations/*.sql`，原 fixture 调用 `EmbeddedMigrationCatalog` 和 `ApplyPinnedMigrations`。构建时必须包含当轮完整且已审核的 migrations，binary 的内嵌 catalog 即实际使用版本；不能运行时塞一份旧 SQL 来修复 binary。其他测试（如 A journal 的窄 fixture）有直接读磁盘 SQL 的路径，不在本入口选择范围；禁止把 `-test.run` 改成全包后仍沿用本精简清单。无需整个 contracts、其他 testdata、Go源码、node/npm/go、mysql CLI、kubectl 或 worker 可执行程序。

工具依赖按阶段明确区分：snapshot/package 需要 Bash、Git、find、支持 `-z` 的 sort、cmp、sha256sum、od、tr 和 cp/chmod/mkdir 等文件工具；该脚本本身不调用 Go。`run-diagnostic.sh` 需要 Linux amd64、Bash、GNU coreutils/grep（尤其 sha256sum `--strict`、stat `-c`、mktemp/cp/chmod/tee/rm、uname），archive 解包命令另需 tar/gzip。原 CGO_ENABLED=0 的 testbinary 自带 Go runtime、HTTP/TLS services 和内嵌 migrations，目标机无需 Go/node/npm/mysql CLI/kubectl。可选 `run-disposable.sh` 额外要求 Docker daemon/CLI、openssl，以及已预加载的审核 MySQL8.4 digest 镜像；不 pull。PowerShell 验证入口只供有 Go、Git 和所需 module cache 的构建机使用，支持 PowerShell5.1/7语法，不是无Go现场的入口。若现场没有 Docker，不能默认为可运行自建实例方案；需在独立诊断机运行，或由 owner 事先提供同机 loopback 上的专用 SAN/TLS 实例。不要在现场安装 Go 临时冷编译。

## 3. 专用凭据与实例要求

使用现有 fixture 同一 JSON 格式；下面只有结构，不能拿占位值执行：

```json
{"Host":"127.0.0.1","Port":63507,"User":"root","Password":"<private>","CAFile":"/absolute/private/ca.crt","TLSServerName":"a-permit-native.local","ServerUUID":"<dedicated-instance-uuid>"}
```

凭据文件 chmod 0600 或 0400。CAFile 必须为目标 Linux 机器上的绝对路径；SAN 对应 TLSServerName，TLS 最低 1.3。`A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID` 是另行传入的专用实例 pin，必须同时匹配 JSON 和真实 `@@server_uuid`；仅凭 loopback/端口不证明隔离。A 入口在任何 fixture CREATE DATABASE/CREATE USER 之前只读核验这些条件，要求账户有显式全库可见性（SHOW GRANTS 中 global ALL PRIVILEGES 或 SHOW DATABASES），并确认除 mysql/sys/information_schema/performance_schema 外没有任何库。不接受原生产 MySQL 或带历史失败 fixture 库的实例。

原 fixture 需要创建/删除数据库、用户和精确 grants，并执行完整 migration；因此这里的 admin 只能存在于本轮独占 disposable 实例。入口不把该 admin 交给 worker：原 fixture 仍生成原有最小 collector 身份及精确表权限。既有 fixture 在核对 UUID 前就建库，故不能绕过新增入口直接跑旧测试名。

## 4. 审核者统一构建与打包（构建机 Bash）

前提：D 原 context hook 已实际接入、A 专用新测试已纳入冻结源码、全部 owner 改动经过审核，GOCACHE/GOTMPDIR 已指向审核者统一的独占大空间 scratch。以下只是交付命令，本轮未执行。构建前调用 `--snapshot`，记录全工作区 clean/dirty/status，以及 backend/contracts/scripts 中所有实际文件（含 dirty/untracked/ignored 文件）的路径/hash；拒绝 symlink。打包时重核 HEAD、状态、文件集合及全部 hash，变化即拒绝。snapshot 和 bundle 的父目录都必须已存在且在源树外，以免自包含或打包污染来源集合。不能只凭 binary 中出现某个 commit 字符串自证；源码 receipt 必须由审核者绑定实际构建命令/日志及冻结字节，不得事后新建 receipt 冒称构建前证明。审核者已启动的构建使用其已有真实构建来源记录核对，不能用本命令补造历史。

```bash
# cwd: 审核者的 ClawManager 仓库根目录；不要在生产 host 执行。
repo=$PWD
SOURCE_COMMIT=$(git rev-parse HEAD)
build_dir=$(mktemp -d "${GOTMPDIR:?set reviewer GOTMPDIR}/a-permit-elf.XXXXXXXX")
bash "$repo/scripts/system-backup-a-permit-native-package.sh" --snapshot "$build_dir/source-receipt"
(
  cd "$repo/backend"
  GOMAXPROCS=2 GOTELEMETRY=off GOTOOLCHAIN=local GOPROXY=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go test -c -vet=off -p=2 -ldflags "-X clawreef/internal/buildinfo.Commit=$SOURCE_COMMIT" \
    -o "$build_dir/systembackupexecution.test" ./internal/systembackupexecution
)
# compile-only exit 0 只代表 ELF 构建，不是 native 或现场通过。
bash "$repo/scripts/system-backup-a-permit-native-package.sh" \
  "$build_dir/systembackupexecution.test" "$build_dir/bundle" "$SOURCE_COMMIT" "$build_dir/source-receipt"
tar -C "$build_dir" -czf "$build_dir/a-permit-native-linux-amd64.tar.gz" bundle
sha256sum "$build_dir/a-permit-native-linux-amd64.tar.gz"
# 用审核记录中的独立 archive SHA-256 核验传输；不包含凭据或 production 材料。
# 产物交付且该轮验证结束后，删除自己的 $build_dir；不要删除统一缓存或他人 scratch。
```

## 5. 完整目标机 Bash 运行/清理

前提：archive 已由用户传到目标诊断机且经独立 SHA-256 核验；有足够磁盘/内存、可用的 loopback 63507；自建实例方案需要审核者指定的预加载 MySQL 8.4 digest，脚本不 pull、不安装任何软件。不将此诊断打到 `https://10.130.14.23:32643` 的生产数据库。

```bash
set -euo pipefail
umask 077
# cwd: 任意诊断工作目录；下面三个路径由用户在执行机指定。
archive=/absolute/verified/a-permit-native-linux-amd64.tar.gz
export A_PERMIT_NATIVE_SCRATCH=/absolute/private/diagnostic-scratch
logs=/absolute/private/new-a-permit-native-logs
export A_PERMIT_NATIVE_MYSQL_IMAGE='mysql:8.4@sha256:<independently-reviewed-preloaded-digest>'
export A_PERMIT_NATIVE_MYSQL_PORT=63507
test -d "$A_PERMIT_NATIVE_SCRATCH"
delivery=$(mktemp -d "$A_PERMIT_NATIVE_SCRATCH/a-permit-delivery.XXXXXXXX")
cleanup_delivery() {
  case "$delivery" in "$A_PERMIT_NATIVE_SCRATCH"/a-permit-delivery.????????) rm -rf -- "$delivery" ;; *) return 1 ;; esac
}
on_delivery_exit() {
  original_rc=$?
  trap - EXIT
  set +e
  cleanup_delivery
  cleanup_rc=$?
  if test "$original_rc" -ne 0; then exit "$original_rc"; fi
  exit "$cleanup_rc"
}
trap on_delivery_exit EXIT
tar -xzf "$archive" -C "$delivery"
bash "$delivery/bundle/run-disposable.sh" "$logs"
# EXIT trap 删除本轮解压的 binary/JSON/scripts；脚本内部已删除自己的运行副本和整个专用 MySQL。
# $logs 留作审核证据，不含密码；用户保管的原 archive 在本轮验证结束后按其已确认路径删除。
```

已有独占空 SAN/TLS 实例时，省去 Docker wrapper，用同一解压/清理流程调用：

```bash
bash "$delivery/bundle/run-diagnostic.sh" \
  /absolute/private/credentials.json "$independently_pinned_disposable_uuid" "$logs"
```

该模式不拥有用户给的实例、CA 或凭据，所以不删除它们。新增 A 入口不执行任何 DROP DATABASE：前置空库盘点和 schema 前缀/后续差集都不能绑定本次归属，也不解析日志作为删除授权。原 fixture 成功时仍只删除其自己直接持有的精确 schema；失败时原逻辑保留 schema，交专用实例 owner 审核后整体销毁其独占实例，不进行逐库扫描删除。

自建 Docker 模式固定 `docker create` 返回的完整 container ID，后续 start/exec/logs/删除均用该 ID 并验证 owner label；volume 校验 owner label 和创建时间。EXIT cleanup 聚合错误，不因 container/volume 删除失败跳过后续 volume 或私有 password/CA/work 清理；逐项确认残留，报告 `RESIDUAL` 或 `UNCONFIRMED`，不会将 daemon 查询失败当作不存在。create 回复不明而没有合法 ID 时只报告原创建 name/owner，不按可能被替换的 name 删除。原测试非零退出码优先保留；测试成功而清理失败返回非零。日志另存 original-exit-code/cleanup-exit-code。若容器仍存活，bind-mounted secret 的 inode 可能仍在容器内；即使主机 work 已删除也不得声称完整清理，必须处理所报精确残留 ID/volume。

若超时/SIGKILL/进程崩溃，Go cleanup 可能没执行；SIGKILL/主机故障连 shell trap 都无法保证执行，不能声称已经清理。按本次 ID/label 精确核查 container/volume 后清理，不能按通配符删其他资源。

日志：自建模式 `$logs/diagnostic/native.log`、`test-exit-code.txt` 和完整 SOURCE_* / SHA256SUMS 来源记录，另有 `$logs/mysql.log`、`original-exit-code.txt`、`cleanup-exit-code.txt`；直接模式位于 `$logs`，也保存 `run-original-exit-code.txt` 和 `run-cleanup-exit-code.txt`。原用例失败保留真实非零退出码，即使同时 tee/退出码日志写入失败也优先保留原失败码并报告日志问题；日志写入失败、SKIP、缺少实际 `provider-permit-stage-timing DATA` 或原入口 PASS 都使 runner 非零。预期诊断若仍命中原 30s 边界，应保存其失败，不可延长窗口使结果变绿。即使退出 0，也只表示该隔离 fixture 路径通过，仍不等于生产授权/页面/完整验收通过。

原 Windows/构建机 PowerShell 入口 `system-backup-a-permit-timing-validation.ps1` 已同步：`-Native` 只调用新增 A 安全入口，强制 `-DisposableServerUUID`，保存/恢复独立 UUID 环境变量，预检实际内置 hook、现存日志父目录；`-BuildRoot D:\owned-scratch` 可把独占 GOCACHE/GOTMPDIR 放到 D 盘。只删除该次成功新建的 GUID 目录，校验精确父路径、名字、owner marker 和非 reparse point，不采纳预存目录。失败保留原测试码，清理异常单独报告。旧 `system-backup-a-permit-timing-native.patch` 已删除，避免保留第二个人工接线步骤。未在本轮启动此脚本或编译。

## 6. PermitStage 静态审查结论

- `PreparedProviderPermitIssue.recheck` 每次 Stage 正常会经 registry 首次检查、ReferenceChange 回调、尾检查多次进入；当前 SQL guard、revocation、capability evidence、owner mapping、issuer file 和到期检查均有实时事实含义，不能删除或跨请求缓存它们。
- `recheckMapping` 已对**刚读回的当前完整 bytes/signature/issuer**做精确比较，只有相同才复用 request 内已认证数据；不同 revision 会重新解码/验签。`sqlPreparedCapability.recheck` 也已保留当前锁定 evidence read 并只复用相同不可变签名文档。重复签名解析的主要显然冗余已经处理，不重复实现旧优化。
- `authenticatedPermitIssuerGrant.recheck` 仍读取当前完整文件并验证 pin/配置/时间；将“文件没变”仅用 mtime、路径或旧 hash 推断会丢失当前撤权事实，不能用来优化。
- 明确可观察的纯 CPU 候选：`validatePermitIssuerGrant` 每次重新 `regexp.MustCompile` 同一窄名字常量；带 `{pod_uid}` 时 `workerJWTIdentityPath` 也重复编译同一 UID 常量；`reg.SameSecurityBinding` 对同一 request 中同一 exact binding 多次执行 JSON/semantic hashing。固定 regexp 预编译在语义上可保持匹配集合；binding 比较若要复用，必须先比较本次完整 current binding 与原已认证 binding，且保留所有上述实时读/撤权/时间检查。
- **不实施上述小型 CPU 缓存候选**：不能证明 regexp/semantic hashing 是主要来源。按审核者本轮实际数据和最新指令，仅实施第8节当前读批处理，不删除任何权限/时间检查。Authorize/Stage/Recheck 的父子耗时重叠，不相加。

本轮验证：三个 Bash 脚本 `bash -n` 退出 0（默认 sandbox 的 Git Bash signal pipe 被拒绝后，使用获准的只读语法检查完成）；Go 新测试文件 gofmt 检查及 diff/文档链接静态检查通过。未编译 Go、未启动 Docker/MySQL、未执行 native 或远测，未产生构建缓存/二进制；由审核者在其独占 TLS MySQL8.4.13 和统一缓存环境接手复测。wrapper 不执行 DROP、不会并发扫库删除，失败 schema 保留至该专用实例由其 owner 整体销毁。

## 7. 审核者首次 native 日志只读观察（不是 A 另起运行）

按审核者指示，只读 `.tmp-native-review-root.txt` 指向的 D 目录内 `c-local-cleanup-linked.log`，未读取 fixture credentials。日志已出现 `FAIL TestPublicationOriginalLocalCleanupSameTaskMySQL (226.86s)`；原任务由审核者报告为 `sbk_2e270017-3ee3-45de-b088-eda61f91787a`。固定数据库诊断为 `stage=database-using-key-check context=deadline key_remaining_us=-16567 context_remaining_us=-16567 source_remaining_us=-16567 elapsed_us=28381672 callback_entered=true callback_succeeded=false`。这说明当前仍未越过原数据库 key 窗，不能把新增 C local cleanup 当作已被该失败运行验收。

数据库 controller 完成调用快照：KeyCheck.Authorize 127次、27.410720s；PermitStage 127次、7.014015s；Collectors 127次、4.353781s；OriginalPlan 128次、3.709096s；Commit 127次、0.377444s。父子计时重叠，且 OriginalPlan/其他子段有128次而 Authorize 完成127次，表明快照边界可能仍含在途调用，不能求和成严格归因或把数字当原子回执。也不能跨不同机器/负载把它与旧 v13 直接判定性能回归。

全日志各模块的316个已完成 PermitStage 快照合计16.878194s，平均53.412ms；956次 Recheck 的 GuardAndRevocation 合计5.440336s，IssuerGrant 0.831525s，SecurityBinding 0.084929s。该集合没有 operation/task 维度，不能直接当数据库专属子阶段总计。它足以降低对 pure semantic JSON/regexp 优化的优先级：其中 SecurityBinding 的全用例已测成本只有约85ms，不能据此声称会修复30秒窗口。

最小下一建议（未改实现）：由 controller owner 优先审 `ExecutionAuthorityGuard.recheckOriginal` 单次实时复核内的 current SQL/held-read/owner 检查成本，以及外围 `OpenOriginalCapturePlan` / `ValidateCollectors`。只有在同一次实时复核内证明能合并 SQL 往返并保留原 owner 回调、原锁定事实、owner 检查之后的当前 SQL 时钟和原所有到期比较时才做 batching；不删除任一次 Stage/ReferenceChange/tail 复核，不缓存跨请求权限，不减数据库完整读取。现有 PinnedExecutionIdentity.current 已复用精确当前 bytes 的已认证数据，不重复接一套旧 JSON 缓存。没有已证明的主要 A 材料成本可以在此轮直接删减；等待该受测切片及每条实际 SQL/等待证据后再改。

## 8. 实施候选：A permit 已锁两行的后续当前读批处理

按审核者确认的数据库专属分段：129次 Stage 7.125s；388次 Recheck 3.747s，其中 GuardAndRevocation 2.332s、Capability 0.507s、Mapping 0.520s、IssuerGrant 0.347s。这个候选只减少 Capability/Mapping 的重复 SQL 往返；不声称消除 Guard 或原30秒失败，收益待同环境复测。

实际 Go 变更均在 `backend/internal/systembackupkekadapter`：

- `provider_permit_issuer.go`：首个 `recheck` 完整保留原 capability FOR SHARE → issuer 文件 → mapping FOR SHARE 顺序，成功后才创建私有 `heldProviderPermitRows`；ReferenceChange 回调和尾复核消费它。ReadCommitted 等其他调用仍走原顺序路径。
- `provider_permit_current_rows.go`：句柄只记录原 context/tx/issue/guard/authority/source/ref，没有缓存行内容或权限。后续一次 SELECT JOIN FOR SHARE 读取两条完整 CURRENT 行；所有键都已在同一未结束事务按原顺序锁定，所以优化器 join 顺序不引入初始锁序变化。foreign ctx/tx/guard/issue、改变原 scope/ref/source、取消或已结束 tx 均拒绝。
- `capability_records.go`：抽出相同 checksum/size/expiry 行校验及原 installation/database/time/精确 bytes 校验，由原单读与新批读共用，没有改 predicate 或放宽原 evidence bound。
- `provider_permit_current_rows_test.go`：foreign-scope/no-SQL 拒绝测试；可选专用 TLS MySQL 实际两表 DATA 差分测试，用原两次当前读作 oracle，比较 healthy、health/type/owner/encryption、size/checksum/expiry、当前不同 bytes、签名、真实签名撤权/续期、缺行和已完成 tx。该测试只在独立 UUID pin 验证后创建随机 `ad_a_permit_rows_<nonce>`，cleanup 只 DROP 它直接生成并持有的这个精确 schema，不扫库、不从日志推导归属，不把该 DATA query 测试当 provider authority 验收。

安全理由：每次 `RecheckAfter`/revocation、capability bounds、当前 issuer 文件和配置、mapping 签名/撤权/时间、security binding 均仍执行；所有原 SQL 时钟/最终 guard/commit/collector 检查保留。批读不减少源表、行或模块读取。mapping 的后续 SQL 在 issuer 文件之前读取，但该精确 mapping 行从首次原序读取起持续持有共享锁；issuer 文件检查是封闭的本地文件/纯校验过程，不会修改本事务 SQL，故不会漏掉该边界之间的同事务修改。任何在批读之前发生的本事务修改仍由当前 locking read 看见，外部修改不能穿过原行锁。

常见每次 Stage 三次复核从 capability/mapping **6次 SQL → 首次2次 + 后续2次批读 = 4次 SQL**；首次锁获取不变，逐次授权次数不变。新增计时桶 `Recheck.CurrentRows` 包含两行当前 SQL 读取和 capability 校验，`Recheck.Mapping` 在批读路径只包含 mapping 认证；对照旧时间时应比较相应合计，不误读桶迁移为全部收益。

交审核者统一缓存环境运行，A 未另起构建/连接数据库：

```bash
# cwd: repo/backend；GOCACHE/GOTMPDIR 沿用审核者独占环境。
GOMAXPROCS=2 go test -count=1 -p=2 ./internal/systembackupkekadapter \
  -run '^(TestHeldProviderPermitRows.*|TestSQLProviderCapabilityPreparationReadsAndRechecksOriginalEvidence|TestPreparedPermitCurrentOwnerMappingKeepsRevisionSemantics)$' -v
# Actual MySQL DATA 测试需要已配置的 TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS + 独立
# A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID；缺失会 SKIP，不能当实际 SQL 通过。
# 再运行已有 TestDeploymentProviderPermitActualHandlerMySQLAndTLS 与同任务 native，
# 使用它们原来的专用 fixture 环境/精确权限，验证完整 StageOriginal 当前授权链。
```

审核者已报告独立 frozen snapshot 的 A 整包回归通过（systembackupkekadapter 9.027s）；`TestHeldProviderPermitRowsCurrentMySQL` 的14个子例在 owner-pinned TLS MySQL 上实际通过（0.58s），原/批量当前证据篡改及 mapping 撤权/续期行为一致，独立SQL查询确认无 `ad_a_permit_rows_` 残留。审核日志 SHA256 为 `a4348a943fe61c8e31e82ba99d7c86117ee1ceedc44d3139518c1aa69fe469ba`。这是审核者执行并交付的结果，A 未自行启动编译或SQL。四个 Go 文件保持冻结；尚无同源组合 native 窗口通过结果，不报告性能提升数字或数据库采集成功。原冻结的 A native wrapper 未改（SHA256 `ab3fb1ba83e1c2c2334b80f3292d585a6ae3cbb594c9dfa79bd1a8b62edbd123`）。

## 9. 工具最终核对范围

本轮仅再核对 package/run/disposable/PowerShell 工具及本文档，不改四个 frozen Go 文件。入口名、runtime 文件集合、SOURCE receipt、清理及失败码规则以上述第1～5节为准。确认 `run-disposable.sh` 实际复制到包内并纳入 SHA256SUMS；source receipt 五个文件也全部纳入包校验并复制到执行日志目录。新增输出位置检查拒绝 bundle 放进源码树，避免打包本身污染冻结输入集合。runner 在 native 非零与 tee/退出码日志写入失败同时发生时仍保留 native 原非零码，清理失败单独报告。

只读语法/格式检查不执行这些脚本的 Docker/Go/SQL 操作。发行 owner 在实际 Linux 包交付时还需绑定其真实 build receipt/命令/平台及 archive SHA；本工具文档不能替代构建证明。工具文件及本文档的最终 SHA 由本次交接输出，避免在文件内写入其自身 hash 造成循环。
