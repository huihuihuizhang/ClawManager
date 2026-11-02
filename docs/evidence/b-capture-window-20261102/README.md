# 本轮 B 采集窗口证据

源码基线 `b98c4f093c88c3131fc5e792a3b665d97c186605`，精确本地文件摘要见 `source-pins.json`。源码未提交、未推送。完整说明与 A/D/C 输入见 `../../system-backup-b-capture-window-20261102.md`。

- `stdlib-final-tests.jsonl`：最终标准库 helper 的 5 个测试根 PASS，0 SKIP。不是整个 domain/worker 包或真实 MySQL。
- `stdlib-final-vet.*`：同范围 vet 退出 0。
- `final-benchmarks.txt`：最终源码上的本地扫描/计时微基准，各 3 次。不代表正式任务时延。
- `syntax-check.json`：9 个 Go 文件语法通过，不是类型检查。
- `package-tests.*`：最初整包尝试在准备阶段因原 JCS 依赖缺失失败，0 用例执行；没有下载、替换或伪造依赖。最终整包源仍未编译，未反复重试相同阻塞。
- `stdlib-component-tests.*`、`stdlib-vet.*`、`scan-benchmark.*`、`timing-benchmark.*` 是实现过程中较早快照的真实运行记录。最终结论仅取带 final 的对应日志，不把旧闭包计时器基准当作最终源码结果。
- `cleanup.json`：本轮自建缓存/临时目录清理被自动审批 `blocked by policy` 拒绝；未执行、未改用其他删除方式。目录尚存，其他 owner 的目录未清理。

最终 helper 测试命令（cwd 为 `backend/internal/systembackup/domain`）：

```powershell
go test -json -count=1 capture_timing.go capture_scan.go capture_timing_test.go capture_scan_test.go
go vet capture_timing.go capture_scan.go capture_timing_test.go capture_scan_test.go
go test -run '^$' -bench 'BenchmarkCapture(ScanSlots|TimingGuardOverhead)$' -benchmem -benchtime=200ms -count=3 capture_timing.go capture_scan.go capture_timing_test.go capture_scan_test.go
```

本轮使用 `GOTOOLCHAIN=local`、`GOPROXY=off`、`GOSUMDB=off`、`GOFLAGS=-mod=readonly`、`GOTELEMETRY=off`，GOCACHE/GOTMPDIR 指向本轮独占目录。没有创建数据库、连接服务器/Kubernetes、启动真实 Job 或执行迁移。不能据此宣称原 30 秒窗口或正式备份整链通过。
