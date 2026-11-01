# A：原捕获证书字节持久化与发送结果未知（2026-11-01，候选）

本项只延续实际原任务的完整 C/domain 校验与捕获证书。它不构成最终 manifest、上传 Job、ACCEPTANCE、目录注册或独立 DR。forward/index 的旧 WIP 不包含在交付范围。

## 原记录与单次发送边界

原始 `system_backup_v2_evidence` 的 immutable diagnostic 中保存完整准备 payload、单次 Sign 发送意图、已知签名字节。每类记录有封闭 descriptor 与 5600 字节分块；签名字节最大 16 KiB，每个 inline JSON 不超过原 8192 限制。descriptor 绑定实际安装、原 backup、capture attempt、完整当前 C/domain 私有摘要和完整字节 SHA256/长度/分块数量。没有新表或旁路状态机，也没有扩大原元数据容量、角色或公开 wire。

业务 ID 只由安装、原任务、捕获 attempt 派生，不含当前 publisher Pod、claim 或时钟。Prepare 在取 SQL issued_at 前检查原业务根/分块及旧 `sev_asign_` 证据：任何已存在记录，包括过期、不健康或只剩子块，均不能被解释为新准备许可。旧 inner 签名记录的保守检查目前按原任务范围阻止重新准备，不宣称支持跨 capture attempt 的重新签发。

Stage 保留来自实际 Acquire/Renew 的原 claim token，先锁同一原 task 行，再在调用者同一个原生事务中检查原完成时间、104 staging 行、task snapshot、真实签名输入和完整准备 payload，尾部再次检查。没有从 SQL 拼造 claim，也不在事务中执行 Kube/provider 网络。

SignCommitted 先按当前原 authority、公钥历史和原完整 C/domain 读取已知签名字节。存在时返回原 bytes/issued_at/expires_at/key/signature，不调用 Sign。没有已知结果时，只在本调用的全新发送意图事务 Commit 得到 ACK 后调用一次外部 Sign。发送意图已存在或其 Commit ACK 未知，只允许查询；提供方执行结果未知也禁止重签。实际结果成功且当前原事实仍匹配后，原签名字节全部存储、重组校验、Commit 后才对调用者返回；存储 ACK 未知通过原记录查询恢复。

存储还要求结果 payload 与原准备的 canonical payload 完全相同，独立验证目的、公钥历史、签名、十项原 checkpoint、原完成时间与实际 TTL。既存 descriptor 缺子块、根缺失而原子块仍在、字节/SHA/长度/顺序/字段别名错误，均返回损坏记录；真实全缺失才可返回 not-found。not-found 本身没有重签权限，发送意图仍然必须检查。

## 已完成验证

- 默认 SQL 关闭的 named signature/mapping DATA 单测只证明公开字节验证；不会据此创建实际 capture Authority 或宣称原任务完成。完整 current/unknown 候选初次编译与 DATA PASS 3.403s；新增 ACK fixture 后编译/DATA PASS 3.314s，SQL 均跳过。
- 本地 63507 实际 SAN/TLS、原 174 ledger、原 HTTP task、六项数据、十个原 worker、默认 30/5 claim policy 全部保留。current 原任务 `sbk_b0b8dd92-294f-41fa-b4dd-99aa0a1a62b7` 的实际原 Record validating 后，完整当前 C/domain、原 Stage、恰好一次外部 Sign、公开验签、六条实际准备/发送/结果证据、原 bytes 读回、重复写/重复 SignCommitted 的无 RPC 读回、拒绝重新 Prepare 全部 PASS。证据 bytes/row_version/created_at/updated_at/expires_at 前后独立 admin snapshot 相同。
- 同一 current 任务的 8 个真实 SQL codec 故障各在独立 admin 事务中执行并实际 affected=1，随后 readback 拒绝，再回滚：缺根、缺首子块、不健康根、过期根、根字段大小写别名、子块 index、子块长度、子块 checksum。每种还检查原记录不能变成重新准备许可；没有新 Sign，回滚后独立 snapshot 相同。这是原字节存储 codec 性质，不把 admin 故障事务当当前发布授权。
- current case 131.36s/package 134.628s，session 75776 terminal/exit0。原 SQL 源 880 次 Authorize/747.2917ms，stream 25.5143409s。证书 SHA256 `61e0ecbf672289f371c2e7bd0bfabe58fbe239d225d7b550c10153abafde0ae5`；日志 `.tools/a-certificate-durable-original-current-v1.log`，构建基准 linked `242e64b74e4ac57ce4728f877b6219f129bade23`，7 个当时 WIP 文件哈希在 `.tools/a-certificate-durable-wip-current-v1-freeze.json`。
- 提供方结果未知原任务 `sbk_a869e3c6-5d55-489e-b3d7-15bc7698be07` 的独立本地 TLS 提供方实际签名一次后故意返回 503、不交付签名结果；实际 SignCommitted 返回 unknown，重入保持查询且 Sign 仍为 1，重新 Prepare 拒绝。case 132.49s/package 135.773s，session 66773 terminal/exit0；日志 `.tools/a-certificate-durable-provider-unknown-v1.log`，linked `915cf5e44a5bbf292b3d7184762db27dfd58440b`。这证明该任务未重签，不宣称已知签名字节或远端产物。

## 原生 SQL Commit ACK 故障

只在原 fixture 的受限 controller 连接上选择既有透明 native MySQL connector，原 TLS/UTC/账号/参数与 SQL 均保持；其他情况仍走原连接路径。故障代理先调用底层真实 Commit，只有其成功后才丢一次 ACK，且分别在发送前或实际 provider Sign 后才置位。两个独立新任务将通过原 admin 连接完整读回原发送/签名字节记录，确认具体提交边界；不是 rollback 后模拟 unknown。

v1 `.tools/a-certificate-durable-native-commit-ack-v1.log`，session 76261 已 terminal/exit1，整体 FAIL269.07s/package272.357s；9 个当时 WIP 文件 SHA256 见 `.tools/a-certificate-durable-ack-v1-freeze.json`。其中发送意图 Commit ACK 丢失的原任务 `sbk_6e1f066d-a202-410b-98fe-e25600907e4b` PASS135.09s，独立读回完整原发送意图、无签名字节，重入只读且 Sign=0，重新 Prepare 拒绝。

同批签名字节存储案例 `sbk_c06060c9-7b91-4440-b1b7-75a475ade892` FAIL133.98s：底层实际 Sign=1，但独立读回未找到签名字节。具体代码核对发现，原 `SQLPublicationTaskSigners.check` 在提供方返回后合法地提交只读校验事务，v1 的通用 ACK 故障先命中了该只读 Commit，实际没有走到签名字节写入；这不是存储 ACK 恢复通过，更不能抹掉失败。发送意图单次屏障仍在，未据此重签。

只修改 test fault connector，保持只读事务及其 ACK 原样返回，仅允许写事务 Commit 成功后消耗故障标记；生产授权和存储代码未为这个故障作任何修改。补充 named driver-unit 检查原生事务选项保持不变、只读不消耗故障、写成功后只丢一次 ACK、原生 Commit 错误原样保留。该 unit 没有 SQL/任务/捕获/签名 authority，不充当原生 SQL 通过。

只重测已定位边界的 v2 `.tools/a-certificate-durable-store-write-commit-ack-v2.log`，session 41294 已 terminal/exit0，原任务 `sbk_60330eb6-5ec4-45f6-b2b5-6caffff8cd04` PASS case134.24s（父134.25s）/package137.568s。独立 admin 完整读回真实已提交的原发送意图及签名字节，当前 authority 与独立公钥历史验证通过；随后原 SignCommitted 返回完全相同 bytes/SHA，Sign 总数仍为 1。原 known-byte 重复/8类 SQL codec 故障检查也再次通过。证书 SHA256 `3b811e40022d68b60eaff9e6f9ce0ac593b321e1fb461be188e66078553418ff`。本轮实际 SQL 源 880 次 Authorize/758.5146ms、stream25.3585481s。全部 63507 句柄终态后已释放窗口。

driver-unit 的四种情形 PASS3.277s，session38107 terminal0。关闭全部 SQL opt-in 后，本地原生 execution/skillhub 全包 PASS7.903s/0.728s，session24253 terminal0；日志 `.tools/a-certificate-durable-full-local-packages-v1.log`。

最后字节审阅补上原 envelope 与 signature 字段的 typed canonical round-trip，仅比较，不替换任何原 bytes；拒绝 Go JSON 大小写别名和缺失字段。对应 named signed DATA 追加 outer/signature alias 负例，保持有效原字节与 exact prepared-payload 正例。本补充不改变当前授权、SQL 或单次发送规则。

最终 14 个签名/映射 DATA 与 4 个 ACK driver-unit 情形 PASS3.337s，session89781 terminal0；日志 `.tools/a-certificate-record-closed-envelope-data-v2.log`。完整原任务及 native ACK 的成功/失败边界、各日志 SHA256、当前 10 个 Go 文件 SHA256 均保留于 `docs/evidence/a-certificate-known-bytes-20261101.json`，不会把最后纯字节补充写成已重新执行原生 SQL。

3 个旧 postPrepare 业务故障未由这些 current/unknown 运行证明；不据此补记通过。没有验证跨 Pod 已发送但未获结果的提供方独立结果检索；当前安全行为是保守 query-only，无法取得已知结果时不会重签。
