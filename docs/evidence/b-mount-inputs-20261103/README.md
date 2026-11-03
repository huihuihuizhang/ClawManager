# B 第 1～3 项隔离验证记录

共同基线 `backup@71e2f3186a28ff150bc183b86ffdfe491678a5e9`；未提交、未推送。详见 `../../system-backup-b-mount-inputs-handoff-20261103.md` 和 `summary.json`。

- `starting-worktree-pins.json`：本轮开始时已有未提交改动；不是新一轮测试的源码版本。
- `summary.json`：最终 21 个相关源码文件的 SHA256、测试准确范围、D/A 输入和未验证范围。
- `focused.*`：开发阶段定向检查。`regression-r1.*`：Windows 回归 49 根通过、5 根跳过。
- `authority-and-mapping.*`：额外相关原授权/材料回归，11 根通过、6 根跳过。
- `linux-final-build.*`、`linux-container-command.json`、`linux-regression.*`：最终 Linux 源码构建及禁网容器验证，55 根通过、1 根因未配置 disposable MySQL 跳过；无真实数据库/Agent/K8s/storage。`linux-build.*` 是新增完整 component 前的交叉构建准备，不代替最终构建。
- `field-writer-observation.*`：用户已授权服务器只读固定 GET 观察；无 SQL/Runtime 实例级归属结论、物理 fence 或首次纳管授权。
- `vet.*`：组合 vet 退出 1，唯一错误来自上游既存 D 测试的 atomic.Bool 值复制；没有关闭检查。
- `gofmt.*`、`diff-check.*`：格式和补丁检查。
- `cleanup.json`：本轮容器已自动删除，日志保留；测试二进制/标记删除被自动审批 `blocked by policy` 拒绝，没有换方式删除或重试旧缓存清理。

根测试计数不含子用例；不同平台/重复回归不相加为独立覆盖。日志原字节按本目录 .gitattributes 保留。本记录不表示完整六域备份、源物理停写/恢复、正式成品、目标恢复或真实迁移已经验收。
