# 离线安全材料验证记录 · 2026-11-01

基线 `0e797e4e0db1305cb4b4ea55456764b207e4d548`；独立分支 `offline/a-security-materials`。
这些结果只验证本地公开材料、协议与拒绝路径，**不代表生产 readiness 或现场验收**。

本机已有 Go 1.26.1；`GOTOOLCHAIN=local`、`GOPROXY=off`、`GOSUMDB=off`、`-mod=readonly`。
只读复用已有 module cache；构建/临时文件写入本 checkout 的 `backend/.cache`。
未连接数据库、Kubernetes、KMS、对象存储或远端 Git；未启动集成环境或监听端口。
测试签名/UID 仅是进程内明确标记 local_test 的 fixture；没有导出安装私钥或生产签名。

最终 Go 验证（默认 vet 开启）：

```text
go test -json -mod=readonly -p=2 -count=1 -timeout=180s \
  ./internal/systembackupoffline ./cmd/system-backup-offline-security \
  ./internal/systembackupsecurity ./internal/systembackupkekadapter \
  -run '^(TestOffline|TestTemplate|TestStrictPublicInput|TestSecretPolicyExactEntries|TestCapabilityCompleteCodesAndCurrentPins|TestCapabilityCodeContractParity|TestSourceSignedGrantRefusals|TestResourcePermissionRefusals|TestSQLSourceGrantsReuseConsumer|TestCoverage|TestEmptyCoverage)'
```

退出 0；15 个顶层测试，含子测试共 112 条 PASS：offline 3.170s、CLI 3.540s、security 3.040s、kekadapter 3.150s。
原始事件为 `go-tests.jsonl`；这不是四包所有测试/现场集成测试全跑。
`go build -mod=readonly -p=2 -o .cache/system-backup-offline-security.exe ./cmd/system-backup-offline-security` 退出 0。

覆盖：缺真实输入、重复/未知/大小写别名 JSON、错安装/用途/版本/issuer signature/pin、过期/未来/撤销、
独立 key/role/policy、SecretPolicy 逐项 required/额外/重复/同数量替换、六类 capability code 合同、
源 grant 恰好 24h 允许而 24h+1ns 和 25h 拒绝、源 namespace 与 worker namespace 分离、
Kubernetes 写/list/*/跨对象拒绝、SQL 写/通配/漏表/控制表/role/UUID/数据库拒绝、
KEK 四分区缺失/重复及逐引用替换/遗漏/额外/错 key/hash/lifecycle、epoch/DB/source revision 和 unwrap 撤销。
KeyBinding hash 还对照现有 C JCS 实现独立计算的 snake_case 固定向量。

Python 3.12 离线测试：

| 测试 | 结果 | 原始记录 |
| --- | --- | --- |
| 新 provider 材料编译入口 | 4 项 PASS / exit 0 | `provider-tests.txt` |
| 已有三用途 signing policy | 5 项 PASS / exit 0 | `existing-signing-policy-tests.txt` |
| 已有 KEK policy | 12 项 PASS / exit 0 | `existing-kek-policy-tests.txt` |

新入口测试禁止 provider 构造/socket 连接；KEK plan 由现有本地 Node planner 生成。
两个已有 apply 工具只运行 `.test.py`，没有执行 provider apply/revoke。

重建全部十种模板成功；unfilled trust/bundle 真正经 CLI 运行退出 **2**，
`unfilled-template-report.json` 保留所有未提供 slot，`production_ready:false`。
`source-hashes.json` 记录最终测试时新增 Go/Python 源码与测试文件的 SHA-256。
模板没有真实安装身份/签名/节点 UID，现场 capability、原权限认证、完整扫描、当前撤销和实际恢复均未验证。

早期人工检查发现并在最终测试前纠正两处一致性问题：source grant 的最长 24h 约束，以及
完整 KeyBinding 摘要必须使用 C 的 snake_case JCS 而非 Go DTO 的 PascalCase JSON。
最终证据不将较早版本或外部监督测试混作本轮完整源码证据。
