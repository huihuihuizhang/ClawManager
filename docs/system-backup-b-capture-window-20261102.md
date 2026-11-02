# B：采集窗口诊断与扫描缓冲改动

本轮实际拉取并快进至主仓库 `backup@b98c4f093c88c3131fc5e792a3b665d97c186605`。以下是该基线上的本地未提交改动，不是新发行版本或整链通过记录。未安装依赖，未连接服务器、集群或真实数据库，未执行迁移、部署、提交或推送。

## 定位结论

最新基线已经包含四条完整 catalog 查询合为一个四列结果，以及 A 在原 held transaction 内的读取合并。本轮保留该实现，不重复移植。它的组件/真实 SQL 专项证据见 `evidence/supervisor-original-read-batching-review-20261102.json`，其中 `full_native_window_passed=false`。

仓库记录的较早 Linux 同任务失败是 139 次 HTTP key-check 累计 28.382927694 秒，SQL 快照尚未采集完成；另一个 Windows 冻结快照失败是 160 次控制 key-check、最终 key 窗口剩余 -2129 微秒。两者来源和调用口径不同，不能相加，不能据此计算本轮优化收益。历史计时指向控制侧 key-check 热链；本轮没有取得新的真实 SQL/控制 RPC 数据，不能断言当前剩余瓶颈已消除。

## 本轮实际改动与调用位置

1. `worker.RunFormalCapture` → `runFormalCapture` 为数据库 invocation 附加进程内 `domain.CaptureTimings`。`database_capture_timing.go` 包装原 `SourceAuthorize`，四个原显式 key-check 调用点经 `measuredCaptureKeyCheck` 执行；原函数、上下文、错误与调用次数不变，包括 cipher sink 的前后检查。
2. `domain.sourceReadGuard`、`sourceGuardedQuery.QueryContext`、`sourceRowsNext` 记录原 guard、实际 query 和实际 Next 的耗时。`captureWithCatalogMode` 分别记录连接、前后源会话核验、RR begin/commit、初始 catalog、精确 COUNT、MDL 后 catalog；worker 记录捕获、快照验证、编码压缩、DEK callback 及密文/envelope 落盘阶段。
3. `captureWithCatalogMode` 使用 `newCaptureScanSlots` 每张非空表分配一次扫描槽。每行仍先执行原 Next 前后检查，再 Scan、逐个 `rawCell` 拷贝、按原字节/行预算检查；Row map 按列数预分配，消费后清空扫描槽。没有合并业务行、跳过取行或复用快照中的 Cell 字节。
4. 新增标准库计时/扫描测试，以及实际 domain/worker 路径的撤权、失败和日志隐私用例。后者因缺失原依赖，尚未执行或完成包级类型检查。

## 输出合同与解读

每个通过初始输入校验的数据库 `runFormalCapture` 最多输出一条汇总：

```text
[system-backup-database-timing] {"schema_version":"database-capture-timing.v1",...}
```

字段只有原 `invocation_sha256`、`candidate_returned`、固定阶段的 `calls/failures/total_ns/max_ns`，以及原 key/source/request 三个独立截止的 `known/start_remaining_us/end_remaining_us`。负剩余时间保留；未知 key 截止不从 request、attempt 或模型推导。task/attempt/Job/Pod 由 D 使用该摘要关联其原 invocation 账本，不在此另建映射或任务。

不输出 SQL/表列名、行值、凭据/材料路径、endpoint、授权正文、错误正文、DEK 或业务内容。只在同步调用退出时汇总，不逐行打印、不启动异步 reporter。panic 继续传播，诊断不得把异常退出记作返回 candidate。

注意口径：

- `key_check` 只覆盖 B 在 `RunFormalCapture` 内显式发起的 Recheck，包括 sink；不是 A 内部或 controller 全部 key RPC 数。`SourceAuthorize` 仍位于 key-check 前后原位置，未合并、缓存或去重。
- `guard` 包含其内的 key/source 子检查；`domain_capture`、catalog/COUNT、`dek_use`、`cipher_staging`、`worker_total` 也有包含关系。不能把父阶段和子阶段相加。可用子指标识别热点，不能仅以父减子宣称某个未计量阶段的成本。
- `worker_total` 从 `runFormalCapture` 初始化诊断后开始，不覆盖 CLI Ready、`NewDeliveredCaptureKeyJob`、`OpenFormalCaptureSources` 或最后的 `ReportCandidate`。入口时原 key 剩余值用于发现进入 B 前已消耗的窗口；这些前后阶段需要 A/D 自身日志补充。
- Query/Next 是驱动边界的实耗时，不是服务器执行计划；session_before/session_after 包含原身份/grants/census 核验，其内部 SQL 不全经过 Query/Next 子计数。
- 汇总是诊断数据；不是领取历史、授权、renew、checkpoint、签名输入、成品证据或成功终态。`candidate_returned=true` 仅表示本函数返回未发布候选。

原 key/source/request deadline、只读单 RR、MDL catalog 重核、原会话授权核验、当前撤权检查、行值编码、容量和候选失败返回零值规则均保留。没有更改 A 控制 SQL、D claim/Job 编排、C 产物协议或 readiness。

## 本轮验证与准确限制

完整日志和最终源码摘要在 `evidence/b-capture-window-20261102/`。

| 验证 | 实际结果 |
| --- | --- |
| 标准库文件级测试：真实生产计时/扫描 helper | 5 个根用例 PASS，包含 context/deadline、隐私、并发快照、二进制/NULL/空值/大无符号值及 Scan 失败；是内存 driver，无网络/数据库 |
| 同范围 `go vet` | PASS |
| 扫描微基准，3 次 | 原逐行分配 272 B/op、10 allocs/op；逐表复用 176 B/op、8 allocs/op。只证明此三列扫描模型每行少 96 字节及 2 次分配，不代表整链时延收益 |
| 计时微基准，3 次 | 开/关均 0 B/op、0 allocs/op；开启约 42–45 ns/op，是本机局部单 span 模型，不是原控制 RPC 成本 |
| 本轮 9 个 Go 文件语法解析、gofmt、diff 空白检查 | PASS；语法解析不等于类型检查 |
| domain/worker 整包测试 | SETUP FAILED，0 个用例执行，原依赖 `github.com/cyberphone/json-canonicalization@v0.0.0-20261011152517-32a48195b9b2` 未在缓存；GOPROXY=off，未下载/安装/替换依赖 |
| 新增逐边界撤权差分、worker 错误/panic/未知截止用例 | 源码已写，受上述依赖阻塞，未执行，不计为 PASS |
| 真实 MySQL / 同任务六部分 / 30 秒窗口 / K8s / 页面验收 | 本轮未执行；不继承旧快照结论 |

## A / D / C 接收与所需输入

| 接收者 | 需要提供或处理的具体输入 | 用途 |
| --- | --- | --- |
| A | 同一原 invocation 的控制侧 key-check 入口/退出时间、Authorize 分段、SQLBind/KeyStateSQL 分段，以及原 key use `Until`；补充 Generate/Begin/End 段耗时 | 对齐 B 的显式检查，区分控制授权、SQL锁/网络及进入 B 前的窗口消耗；保留原撤权语义，不要求放宽截止 |
| D | 本轮冻结源码 SHA/dirty 文件 SHA、同版本 worker 镜像 digest；同一 task/attempt 下 invocation SHA→Job UID/generation、Pod UID/SA UID 的原账本关联；Ready/材料打开/ReportCandidate 时序 | 确保独立 SQL observer、HTTP 和 worker 看到同一原任务，避免混用旧二进制或不同任务 |
| A/D | 允许写入的独占隔离 fixture、真实 MySQL serverUUID、SAN/CA/TLS、有限源账号与原 source grant/permit 材料；由环境 owner 提供已准备好的依赖缓存或冻结测试快照 | 执行下述 domain/worker 回归及同任务原 30 秒组合；B 本轮不自行安装依赖或写入只读参考服务器 |
| 公共 C | 固定本轮同任务组合入口/请求范围和用于后续 final/local cleanup 的原候选消费；指出失败发生在采集、封装还是发布 | B 不重复采集、不另建影子任务或改变 envelope。采集未完成时不能把发布/清理未执行报成成功 |

依赖到齐后，先在隔离快照运行新增 `TestCaptureTimingDoesNotChangeQueryGuardsOrFailureResults`、`TestDatabaseCaptureTiming*`、`TestMeasuredCaptureKeyCheck*` 和受影响的 domain/worker 回归，再与 A/D/C 执行原窗口组合。组合仍失败则保留同一任务的第一失败与原期限记录，不移除授权检查、不扩大窗口、不改成成功。

本轮只处理备份采集窗口，不新增恢复或发布控制面。非秘密日志、源码摘要及检查记录保留，其他 owner 的目录和既有空目录不处理。

本轮自建 `.codex-temp/b-capture-window-20261102/cache` 与 `tmp` 的清理命令被自动审批以 `blocked by policy` 拒绝，未执行；两个目录仍保留。没有改用其他删除方式绕过拒绝，准确路径和结果见 `evidence/b-capture-window-20261102/cleanup.json`。
