# A：原任务发布校验诊断（2026-11-01）

本次只定位原 capture 已到 validating 后的完整发布者 C/domain 校验，并验证捕获证书。没有完成远端最终发布、ACCEPTANCE、目录注册或独立 DR。

## 原失败保留与来源条件

D 的 `.tools/d-first-binding-a-d910-full.log` 仍为 FAIL：原任务 `sbk_ccad2719-cfd6-4fda-8dad-ef93fdac55d5` 完成全部十个 worker，capture runner/record 均 ok，进入 validating，之后发布校验返回通用 ErrExecutionRecord。返回零值不能证明第一项校验失败。

独立读取该次实际命令可确认：运行用了五个 A d910 测试 overlay，却没有 `-ldflags -X clawreef/internal/buildinfo.Commit=...`。源码默认 Commit 为 `unknown`；producer 原样冻结链接值，原测试只检查与 producer 相等，consumer 则按 `^[a-f0-9]{7,64}$` 拒绝该值。这是确定存在的无效来源条件。旧日志没有具体失败阶段，不能据此排除某个更早检查也会失败；不能修改旧 capture 来源后补跑成功，或将旧失败改记通过。

## 本次透明诊断与新任务

正常 merge backup `380dcc1e`、D `eff7b750` 后，集成 HEAD 为 `3584f2e759ffd4ae177679f13bd169da2d209b56`。合并前 WIP 以 stash 保留，之后 apply，stash 未删除。诊断仅给两个实际校验入口增加固定阶段标签与 `%w` 错误包装，保留原检查与 errors.Is 分类；不输出 payload、凭证、密钥、SQL 内容或源值。

构建新测试时显式链接上述实际 Git HEAD，捕获前生效，没有 ENV 显示覆盖，也没有修改 frozen SourceFacts。原 d910 五个测试文件在这次运行时全部保持原 SHA256。执行：

```text
go -C backend test -ldflags "-X clawreef/internal/buildinfo.Commit=3584f2e759ffd4ae177679f13bd169da2d209b56" ./internal/systembackupexecution -run '^TestAOriginalSixPartCertificatePublicationMySQL/current$' -count=1 -v -timeout=5m
```

本地 SAN/TLS MySQL 63507，由 fixture 检查实际 server UUID。新原任务 `sbk_16f11a8b-4276-4a19-8a66-99aab98e9ad6` 完成十个原 native worker、六项捕获与原 Store.Record validating，随后完整当前 C/domain、实际 C 派生完整计数、原完成时间/104 stage/task snapshot、签名输入 Stage/commit、恰好一次外部签名及独立公钥验签全部通过。默认 claim TTL/heartbeat 仍为 30/5 秒。SQL 源实际 880 次 Authorize，742.8417ms，完整 stream 25.1216318 秒；不据单次运行推广任意数据量。

证书 SHA256 `13624dfb465f23ea49e2a5050bb83d5b7d2ae44931c9fabcbd152399e55c27ca`。case 132.74s、package 136.010s、session 35989 terminal/exit0 已关闭，63507 已释放。完整日志 `.tools/a-firstbind-linked-publisher-diagnostic-v1.log`；结构化边界与日志哈希见 `docs/evidence/a-linked-publisher-diagnostic-20261101.json`。编译中的已知证书字节持久化和 forward WIP 未被这个测试调用，不作为本次通过内容。

## 防止重复无效运行

该次终态后，正式 A 发布 SQL 测试入口增加 opt-in 后、SQL/fixture 前的链接 commit 语法检查。默认不配置 SQL 时继续跳过；显式运行而仍为 unknown 时直接说明构建要求。纯 DATA 单测仍保留 producer 原样冻结和 consumer 拒 unknown；未放宽 consumer。此次入口修改没有回填到上面的已完成运行，后续独立复测应链接其自己的实际 Git HEAD。

用明确不存在的凭证路径作为 opt-in sentinel、默认 unknown 链接值，实际入口在 0.00s 先报链接要求；没有打开凭证/SQL，Go 测试预期 exit1（package 3.385s），外层脚本核对该拒绝后 exit0。日志 `.tools/a-publisher-build-preflight-expected-refusal.log`，不称 SQL fixture 通过。关闭全部 SQL opt-in 后，受影响 execution/skillhub 全包原生回归 PASS 7.918s/0.760s，session 37353 terminal0；日志 `.tools/a-publisher-diagnostics-local-packages-v1.log`。
