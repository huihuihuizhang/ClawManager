# A：实际原 C 容器 writer 与可取消私有文件读取

此项将实际 publisher 的原私有 C 接到物理容器 writer；持久化发布目录、完整 MF、实际 upload-only Job、远程固定版本独立读回仍在继续接线，不构成发布完成。

`writeOriginalPublicationContainer` 只接受完整当前 C/domain 验证的私有 capture receipt。它 query-only 读取原已知签名证书，在当前原任务/历史签名校验下提取逐项 checkpoint pin；重新从当前 publisher 读取原 captured record，核对完整历史 input、plan/result/candidate/Invocation/checkpoint、原路径及 C/envelope SHA/长度，再读取控制器私有 observed copies。不会重新 GET 源资源、Unwrap、重加密、Sign 或直接 PUT artifact。原 C、envelope、AAD、StreamSpec 和原 checkpoint 字节保持不变。

原 098 完整 config snapshot 与 097 materialized 预算的一致性复用已验收的 `readPublicationLimitsTx`。writer 前后重查实际预算及已知证书。复制过程的 guard 只维护当前 publisher 任务 claim，不持有 DEK、provider use、源授权或已签发上传委托；不能把此 guard 包围旧 Unwrap/Sign/Job grant。短小实际任务未覆盖巨大文件跨租约的长期复制，不宣称已完成 900 GiB 读写。

codec 新的惰性 `Input.Open` 在实际发出单个 member 时打开它，完成或出错时先关闭，再打开下一项；避免最多 10,000 个 FD 和所有 envelope 同时驻留。惰性与 eager 字段互斥；open 部分失败、nil handle、C/envelope 校验失败或 Close 失败均不返回完整 Facts。相同实际 C 的 eager/lazy 输出逐字节一致。

`OpenFileGuarded`、`OpenObservedGuarded`、`OpenFormalObservedGuarded` 把当前 claim 检查加入原私有文件完整哈希，并保留独立 `ctx.Err()`：入口、每个读取循环和 EOF 均检查，不能让 context-unaware guard 忽略取消。监督原样 before-entry/during-hash 反例已作为永久测试保留；另外覆盖 guard 入口/循环/尾部触发取消、撤销和 nil guard。

监督旧 WIP red 0.733 秒证明取消失效，非提升 setup FAIL 0.764 秒只证明无法建原生文件，均保留。修复后的监督同一反例 native PASS 0.692 秒；A 最终原生本机全量 staging 13.463、codec 5.538、execution 8.839 秒（SQL opt-in 关闭）全部通过，handle 56416 自然 exit 0。

63507 / SAN-TLS UUID `f3756194-d52b-11f1-b8cc-745d22085e06` 的 `TestAOriginalSixPartContainerAssemblyMySQL` PASS：case 149.76、package 153.060 秒，handle 48671 自然 exit 0，连接已结束。启动前实际链接 HEAD `5302a9e845e3d3f921faf4ba001fb65d3ccfe483`，保存 WIP Go SHA ledger；原任务 `sbk_ff0348ab-69cc-4c28-ab46-b29b2f041eee`，10 个实际 workers/full C/六域 SQL/独立 SecretPolicy/实际 Stage/一次外部 Sign；证书 SHA `976f80684ed9b0018ef02ca6d0757bd0e615b1529d32ec74d8fcbd2eb16dbf63`。随后生产 writer 把 8 个业务 C 成员实际写为六个本地文件，总物理 53,952 字节；原 SHA/长度与完整容器结构读回一致。

测试中 Inspect 的 `named-LOCAL-file-structural-DATA` 明确只是本地文件结构读回 DATA，不是 native S3 version，也不是 Job/远程验收或 DR 证明。没有使用 65298 或旧 59355，没有部署和远程对象发布。早期 sandbox staging/setup 与 upload-only native fixture 失败保持原输出，不作为语义漏洞；随后完整原生本机执行已通过。

下一步继续：先持久化原 capture/证书绑定的发布输入与可恢复私有文件，再一次性构造全部 v12 MF 字段，把六个实际容器及原 control C 接入只读逐文件 Job mount。A 只在明确没有可恢复动作时进入新构造；D 的 unknown query-only、confirmed continuation、验收/catalog/最终 CAS 顺序保持优先。
