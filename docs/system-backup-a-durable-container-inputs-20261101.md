# A：原 104 内的持久化容器输入

本项是实际原 C 容器 writer 后的生产步骤：持久化私有目录与实际六文件描述，独立读回并精确重入。尚未构造完整 MF、发送 upload-only Job、上传远程对象、完成固定版本验收或终态。

不新增 publish-phase hostpath 行或另一台账。派生文件保留在同一实际 104 capture 资源拥有的任务目录内；先在当前 publisher 原事务中提交 capture receipt／原已知签名证书／原 104 resource、key version、row version、MAC 绑定的不可变计划，再创建派生子目录。子目录标记使用实际原 owner 私有 key、独立 HMAC domain 和完整计划 SHA；没有旧 capture Authority、DEK、SourceGrant 或 provider use。

目录打开检查 leaf 类型、symlink 和同一 inode。已有目录缺 marker 不修复、不接管。实际文件 create-only，已有文件必须重新完整哈希、完整容器解析，并将每个成员的 StreamSpec／原 checkpoint／路径／C 与 envelope SHA 和长度对照当前原 captured record。完整文件描述符写入同一原任务 immutable evidence；重入核对相同计划与文件描述，而非生成新文件身份。

Job 输入 reader 独立读取已提交的完整原计划、文件描述和原 104 行，校验原 098 完整 config snapshot 与 097 预算，原 capture result、所有权和 MAC；native marker/key 检查之后，再用同一当前 claim 重读 SQL。仅返回具体只读文件 subPath，不发 Job，不宣称 MF 或 artifact 已验证。Kube 构造器只允许本 task、精确 part 对应的单个容器文件，拒绝其他 task、错 part、目录、key、路径穿越。当前 service 的完整 MF／实际 Job 接线仍在 WIP，本提交只增加可被它消费的生产接口。

复制与 ReaderAt 结构读回可维护当前 publisher claim，但没有旧 provider grant/DEK；自定义 guard 不能忽略独立 context cancellation。原 104 row／completion／TTL 仍逐项固定；只有通过真实当前 Bind/claim 校验的 task row version 可以因显式续租改变，不能用比较 helper 制造当前 token。

## 验证

- 实际 SAN/TLS MySQL 63507，UUID `f3756194-d52b-11f1-b8cc-745d22085e06`。`TestAOriginalSixPartDurableContainerInputsMySQL` PASS 201.02 秒，package 204.507 秒，handle 57087 自然 exit 0；当前没有本项测试连接，窗口已明确交原 D。未重置、重放失败任务、改原时间窗或读取更少数据。
- 原任务 `sbk_8a394129-214b-4819-87e3-c33365c21fb5`；10 个真实 workers、完整 C／SQL 六域／独立 SecretPolicy／实际 Stage／一次 Sign 与既有精确 replay/SQL rollback fault 后，再调用真实持久化目录／六文件 producer，实际物理 53,994 bytes。原记录两项（计划、文件描述）、第二次完整重读与相同描述符、实际 Job 输入 reader 均通过；publish Job 0、102 action 0。
- 证书 SHA `684f993717980ac5c7215eb85d7e32db5455c2917f3bbfeda960a354f7f4fa7e`；计划 `sev_pub_containers_b6d0b37703a07c1ae257aa91439e99a5390043b03e6b74038b71be3ef4a3bc1a`。
- 捕获前链接真实 HEAD `1c4331f5de8296c2fd4855e285fe5df5b7e78de4`，完整 WIP source ledger 保留。此次编译还含未提交的原始发布策略负面声明及 MF/transport WIP；这些不列为本项交付，也不据此声称其已完成 native 验证。本项 8 个 Go 文件逐个 SHA 与启动 ledger 相同。
- 同步已推 c28f519d 后，暂存其余全部 WIP，只保留本项 8 Go，原生本机 SQL opt-in 关闭：execution 10.960、kube 2.803、container 3.116 秒全量 PASS，handle 10424 自然 exit 0，证实提交依赖闭合。所有 stash 保留。

旧原生 capture timing RED 均保留；此前 owner writer PASS 不覆盖监督的 RED。主线后来以不改原窗口/数据的安全等价 I/O 修复通过原完整 writer，见已有监督证据；本项 native 使用已同步版本。

后续仍继续完整 MF／正面安装安全证据／实际 Job／固定版本独立读回。历史恢复描述必须在 capture 前加入原加密 C，保留完整业务 scope、策略/registry 和成员关联；不可把 source paths 明文写 public index，也不能把旧 Invocation、lease、DEK、JWT 或 provider permit 当当前权限。
