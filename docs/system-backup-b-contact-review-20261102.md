# B：最新 backup 接点复核与离线诊断交接

## 本轮基线及保留范围

本轮从主仓库 `origin/backup` 拉取并快进至 `1c3504620e3b456daf95f53adc647f8dd8d002b0`。相对上一轮 `b98c4f09` 仅新增一个提交，修改排程文档并增加 `scripts/system-backup-supervisor-provider-preflight.sh`。没有新增 A/D/C 生产接线实现，也没有新的真实整链成功记录。

快进前记录了 42 个已存在未提交文件的路径与 SHA256，快进后逐个核对字节相同。未 stash、提交、推送或另建控制面。原 B 扫描缓冲/计时代码和原测试证据保留；其最初基线仍是 b98，不能把旧测试自动改写成 1c 的整链通过记录。精确记录在 `evidence/b-contact-review-20261102/`。

新 provider 脚本写死了交接中的 context、namespace、UID，只读取环境元数据和探测指定端点。它不是完整 provider、授权材料、实际镜像拉取或安装结果；本轮没有运行它，没有连接其现场。

## 逐项接点核对

| 接点 | 当前实际源码 | 已有能力与未关闭部分 |
| --- | --- | --- |
| 正式模块生产构造 | `deployment_service.go` → `NewPublicCapture(ModuleFactory)` → `production_capture_modules.go` | 已构造 Users/Instances、Teams、Skills、控制证据、资源/秘密及源 Redis 的正式请求。Users/Instances 的唯一 SQL 请求携带两个 C 的 inventory；不是尚待补一个空注册接口。现场 inventory 和材料没有随本轮新提交补齐 |
| Job 参数及材料 | `kube.attachFormalMaterials`、`deployment_capture_materials.go` | 已有固定 `--formal-config /run/backup/formal/materials.json` 和只读 ConfigMap/Secret 挂载。真实 UID/hash、原 grant/permit、source credential 和生产文件仍由 D/A 装配核验，不能以模板存在替代 |
| A key/source 入口 | `cmd/backup-worker/formal.go` 的 `NewDeliveredCaptureKeyJob`、`OpenFormalCaptureSources`、`RunFormalCapture`、`ReportCandidate` | 正式调用已存在。原有限表 grants、source grant 当前重读、独立源凭据及原 use 截止不变。没有从新代码取得可用的现场材料；本轮也未签发或生成材料 |
| Runtime 回调 | `deployment_runtime_sources.go` 的 `NewSQLRuntimeControl` / `BuildWriters`；`runtime_control.go` 的 `Callbacks` | 已连接 GatewayControl、Guard、Claim/CompleteRestart、ConfirmStopped/Resumed 等实际 SQL 回调。非空运行实例与原本 stopped 实例的完整物理观测仍需 D 在同一任务提供；不重复申请 reservation 或启用旧 controller |
| C 候选消费 | `worker_seal.go`、`publication_capture_files.go`、`publication_forward.go` | 已有正式候选读取、私有 custody、完整流认证及原上传/native cleanup 调用。不能写成 observer 尚不存在；本轮没有取得同原任务完整成功结果 |
| KEK 全覆盖 | `systembackupkekregistry/store.go: CompleteScan`、`coverage.go: AdoptCoverage` | 前者仍明确返回 `ErrKEKCoverage`；后者有正式事务原语，但本轮未查到非测试生产调用。SQL/S3 census 是原 owner 接收输入，不能由 B 变成 PreparedCoverage。原来源 adapter、历史 adoption 及 writer hook 仍需 A/公共 C/D 闭合 |
| 正式发布尾部 | `publication_continuation.go` 的 `publishNext` / `runPublicationContinuation` | `acceptance_put`、`catalog_registration_append` 仍返回 `ErrPublicationFinalizationRequired`。不是 B 更改 DTO 就能解除的门禁；需要公共 C 正式 final/sign/catalog 及 D 唯一终态消费 |

按本次授权仅推进备份采集窗口。本轮没有扩展隔离还原；`RestoreRunner` 的认证源缺口仍保留，不能因上述采集接点存在而宣称正式恢复可用。

## 本轮继续完成的 B 代码

新增 `scripts/system-backup-b-capture-timing.py`，用 Python 标准库读取上一轮 B 的 `database-capture-timing.v1` 日志。不访问网络、数据库、集群、密钥或控制表，不读取日志以外的材料，不修改日志或任务。

使用方必须独立从 D 原 invocation 账本取得 **Invocation.Hash() 对应的 SHA256**，不能填写 task ID、config hash、capture context hash，也不能从日志自行选择最有利的任务：

```powershell
python -B scripts/system-backup-b-capture-timing.py --log $workerLogFile --invocation-sha256 $originalInvocationSHA256
```

边界如下：

- 仅选择精确摘要对应的报告；其他合法 invocation 不合并。相同报告重复打印只计副本，不增加检查次数；同摘要出现不同报告一律拒绝，不选最后一条或较快一条。
- 严格版本、字段、固定阶段、整数范围、calls/failures/total/max、三个独立已知/未知期限。重复 JSON 字段、损坏/截断 JSON、非有限值、未知阶段和不一致 candidate 都拒绝；保留负剩余时间。
- 输入上限 64MiB、每行 16KiB；只读 regular 文件，分行有界读取。异常输出固定安全码，不输出原错误正文、路径或日志内容。
- 保留父子包含关系，明确不能相加；`key_check` 只表示 B 显式调用，不能冒充 A/controller 全部 RPC。Ready、key Job/source 打开和 ReportCandidate 不在 worker_total 内。
- 输出恒为 `diagnostic_only=true`、`authoritative_evidence=false`、`full_chain_passed=false`。退出 0 只表示工具完成诊断读取，不是窗口达标、授权有效或备份通过；读取拒绝退出 2。

测试 `scripts/system-backup-b-capture-timing.test.py` 使用合成日志和本机临时文件，覆盖上述边界、CLI 原文件不变、私密错误不外泄，以及 Go 实际 recorder 与 Python 固定阶段词汇兼容。本轮最终 10 个测试根全部 PASS，0 SKIP，约 0.308 秒；CLI 临时文件夹退出后实际确认不存在。未创建 Go 缓存/二进制；Python 使用 `-B`，没有生成本轮 pycache。

原 Go 计时/扫描 helper 源码未变，未无变化重复跑旧微基准。默认 module cache 仍缺 `github.com/cyberphone/json-canonicalization@v0.0.0-20261011152517-32a48195b9b2`，没有下载/安装/替换依赖，也未重试同一准备失败。包级编译、新增 domain/worker 撤权回归、真实 MySQL/原 30 秒组合仍未执行通过。

本轮新增的上游 provider 脚本已用本机既有 Git Bash 执行 `--noprofile --norc -n`，语法检查退出 0；只解析源码，没有执行脚本、网络探测或任何 kubectl 命令。

## 尚缺输入及接收人下一步

| Owner | 需要的接口或字段 | 接收 B 后的具体操作 |
| --- | --- | --- |
| A | 同一 invocation 的当前 key-check 分段、Authorize/SQLBind/KeyStateSQL、Generate/Begin/End 耗时及原 `Until`；真实用途 capability、grant/permit pin、provider 权限、原 KEK/signer 历史 | 与 B 固定摘要诊断对齐，定位控制热链；保持原撤权和原截止，不用扩大窗口或缓存授权掩盖问题 |
| D | `SYSTEM_BACKUP_CAPTURE_MATERIALS_FILE/SHA256`，已审核的 `ProductionCaptureInput`；原 config/forward/recovery、formal verifier/publisher/signers/target 文件及 hashes，实际 UID/hash 挂载和最小身份 | 通过已有构造和真实 mount observer 装配；不是新增 B API。材料正文保留在私有位置，不入 Git |
| D | 精确冻结源码及 Worker image digest、task/attempt/InvocationSHA256→Job UID/generation、Pod UID/SA UID；Ready/source-open/ReportCandidate 时序及真实运行/停止实例事实 | 给本工具传独立原摘要，收集同任务 B/A 日志，统一核对源停写和原状态恢复；B 不代写 source recovery 证明 |
| 公共 C + A/D | `PreparedCoverage` 原来源/历史/writer hook；同任务 final/local cleanup、acceptance/catalog 当前签名及固定对象版本独立读回 | 完成正式出口后由 D 结算唯一终态；B 不解除现有 `ErrKEKCoverage` 或 finalization guard |
| 两位业务 C | 同原 `SourceInventory.Teams/TeamFacts/Skills` 的实际对象版本/hash、workspace 映射及非空成员完整读回规则 | 沿已有共同 SQL 请求和 C 正式成品验证，不另建 SQL snapshot 或用空 fixture 冒充非空验收 |
| 环境/审核 owner | 已备好且可使用的原 Go 依赖缓存或冻结测试快照；获准写入的独占隔离 fixture、真实 MySQL UUID/TLS/SAN/有限源账号，以及需要的 Runtime/存储 | 先执行新增 B 包级回归，再与 A/D/C 跑同任务原窗口组合；本轮不安装依赖或执行真实迁移 |

目前可以接收 B 的代码和离线工具；仍不能把接点存在、工具 PASS 或新 provider 脚本视为完整链路通过。现场输入未到齐前，继续保留原门禁。
