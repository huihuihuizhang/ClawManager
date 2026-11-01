# A：原始 registry 与 SecretPolicy 的发布输入

本项提供完整 MF 所需的原始 SQL 业务归类和 SecretPolicy 事实，不宣称完整 MF、upload-only Job、固定对象版本验收、marker、清理或终态发布完成。

## 独立 SecretPolicy v1

生产材料 `Discovery.SecretPolicy` 是独立的绝对路径、协议版本与完整文件 SHA-256 引用。协议为 `system-backup-secret-capture-policy.v1`；文件必须是精确 UTF-8 JCS。loader 在原 source-owner authority 下读取同任务原始 config snapshot 的 `secret_allowlist` version/SHA，并核对原 097 同 installation/config version/config SHA 对应的真实列，再读固定 pin 文件。缺失或不一致即拒绝实际 production freeze，不从本次 UID 选择集生成策略。

v1 entry 按安装 namespace 中一个具名 Kubernetes Secret 整对象计量，独立字段是 entry ID、Secret 名称、required、期望 type、用途；不包含本次 UID、内容或 supplied count。模式固定 `encrypted_full_object`，不声称按键覆盖。支持 Opaque、TLS、basic-auth、ssh-auth、dockerconfigjson；拒绝 service-account-token。可选 entry 缺失允许，每个 required 必须实际被选择，每个选择必须在策略中；不静默过滤额外 Secret。

固定策略随原始 SourceSnapshot、capture context、Invocation 和加密流 scope 冻结。worker 在实际 GET 后验证对象 kind/apiVersion/namespace/name/UID/type，独立完整 archive reader 再验证。仅在完整压缩数据读取成功后返回 coverage；其外层仍必须完成当前独立 Unwrap、完整 AEAD/EOF 和原始任务检查。required 数来自策略逐项标志，captured 数来自完整 reader 实际对象 callback。MF 输入 wrapper 还要求私有完整 C receipt、原 config pin 与冻结策略一致，不能凭总数替代逐项覆盖。输出严格使用 v12 的 `registry_version/registry_hash/required_entries/captured_entries`。

## 原始 schema registry 的 SQL 归类

source freeze 保存独立 pin 的完整 schema registry 字节，避免发布时改用当前 runtime 表分类。完整 C 的实际 SQL 行与非 NULL 原始 cell 字节数按该 registry 分到六个业务域；不能用粗粒度 mysql part category 覆盖，例如原 registry 把 `northbound_caller_policies` 归为 users。

CE 的 registry 校验与旧 A collector 的封闭 15 表 CaptureScope 分开。新的 metadata-only 校验可以识别完整、已冻结、交叉批准的额外 A 元数据；不会返回 CaptureScope 或扩大 SQL collector 权限。测试明确验证相同扩展不能通过旧 CaptureScope。

## 验证记录与范围

- 63507 / UUID `f3756194-d52b-11f1-b8cc-745d22085e06`，SAN/TLS；未操作 65298 或旧 59355。
- `TestAOriginalSixPartCertificatePublicationMySQL/current`：PASS，subtest 149.11 秒、package 152.394 秒，Go 自然 exit 0，handle 68452 已结束。原任务 `sbk_25c88962-226f-487b-a3f0-705f814513c3`；10 个实际捕获结果、validating、完整 C、六域 SQL 事实和原策略 version/SHA/required=1/captured=1 检查、实际 Stage、一次外部 Sign、精确已知字节复读及现有 8 项 SQL codec rollback fault 均通过。证书 SHA `b36dcf242e70327760d126c6f2c8b005c9f75b1816fc6478e934530a43f2cff8`。
- 启动前链接实际 Git HEAD `979f83436a03f6295572baeb67589fc7d572922f`，并保存当时全部 WIP Go source SHA ledger。该 HEAD 显式撤回未审容量候选 43dd，容量相关文件恢复已推 6a570758 行为。stash 均保留。
- native 命令启动后仅对汇总函数作 pure helper 分解、增加归档/SQL 计数单位错配拒绝和纯 DATA 测试；native 证明对应启动前 ledger，不能把后续文件 hash 冒称为该次 native 编译源。后续 helper 测试 PASS 3.283 秒，最终 5 包全量测试（SQL opt-in 关闭）全部通过：core 4.137、worker 36.056、businessa 3.685、CE 0.798、execution 8.407 秒，handle 47733 自然结束。
- 本地策略文件在 config admission 与源 UID 观察前独立声明，和生产 loader 共用协议。local 完整 registry 的批准明确标注测试 fixture，不是已安装部署的 owner 审批；旧失败日志保持原样。
- 策略/归档/汇总 DATA 负例涵盖 SHA/version、JCS alias/重复/未知字段、required 缺失、选择集额外对象、namespace/UID/type、service-account-token、不完整 EOF、仅总数、覆盖/payload 未完整及 config pin 重复等。没有伪造 SourceAuthority 或私有 checked receipt。

不新增生产部署、集群、KMS 或远程对象操作。最终生产接线继续要求完整 MF、真实原 C 容器、实际 upload-only Job、固定版本独立读回、候选删除证明、清理和终态顺序；原来的三个 post-Prepare 业务故障模式没有在本项补跑。
