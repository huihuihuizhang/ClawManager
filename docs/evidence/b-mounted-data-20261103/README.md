# B 额外挂载与现场只读观察证据

基线 `71e2f3186a28ff150bc183b86ffdfe491678a5e9`，源码未提交/推送。调用位置、材料字段、实际现场差集、支持边界和下一接收人见 `../../system-backup-b-mounted-data-handoff-20261103.md`。

- `field-writer-observation.json`：用户授权后，经 SSH/固定 context/namespace UID 运行本轮只读脚本的实际资源投影；10 Deployment、10 Pod、6 PVC、6 PV、2节点。没有 SQL 实例清单、Runtime 进程树或物理停写证明。
- `go-final-placement-tests.jsonl`：最终源码相关回归 43 根 PASS、2 根 Windows 条件 SKIP；明确未选择 MySQL/Native。fake Kubernetes 及原生产工厂/observer 元数据投影，不是真实挂载/加密 Job/停写验收。
- `inventory-tests.*`：7 根 Python 标准库模型测试 PASS，与真实现场读操作分开计量。
- `adapter-vet.*`：publicadapter vet 退出 0。
- `vet.*`：组合 vet 退出 1；上游未修改测试 `deployment_publication_startup_test.go:213` 复制含 atomic noCopy 的 DeploymentService。没有关闭 analyzer，不报 PASS。
- `go-focused*`、`go-regression*`、`go-factory*`、`go-final-tests*`、`go-placement*` 是开发阶段快照记录；部分初次失败是新测试构造共享指针/重复 Job 引用和 nil fixture pin map，已修正。最终仅统计 final-placement，不把多次重复执行相加。
- 本轮依赖原 module cache 已存在，GOTOOLCHAIN=local、GOPROXY/GOSUMDB=off、mod=readonly，未安装/替换依赖；仅使用本轮独占缓存/临时目录。
- `cleanup.json`：自动审批拒绝清理本轮 cache/tmp，reason 为 `blocked by policy`，目录仍保留。没有重试其他删除方式或处理其他 owner 产物。

本轮没有真实迁移、现场状态修改、停写保持/恢复、首次纳管、正式成品或页面整链通过结论。
