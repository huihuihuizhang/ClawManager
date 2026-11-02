# D：当前 KEK binding 事务内只读接口（2026-11-02）

本切片补充 registry 的精确只读接点，供公共 C 在当前原事务中消费独立持久化的撤销事实。它返回 typed comparison facts，不授予 Generate/Unwrap 权限，也不产生 Ready、终态或新的证据。根审核已在冻结快照完成 registry 窄验证；C 已消费该 API，但本页不宣布 C 的完整业务链、同任务发布或页面结果通过。

## 实际接口与锁序

文件：`backend/internal/systembackupkekregistry/binding_read.go`。

```go
func (s *SQLStore) ReadBindingTx(
    ctx context.Context,
    view SQLReadView,
    installation string,
    pin ReferencePin,
) (BindingFacts, error)
```

调用者必须传入自己正在使用的**原事务**及其 context/read view，并先取得原流程所需的较早 domain、task、authorization、operation、evidence 等锁。`SQLReadView` 是原事务读取接口，不是新的授权凭据；本方法不代调用者选择数据库、建立事务或取得业务授权。

方法按原顺序执行：

1. 拒绝 nil receiver/context/view（含 typed nil）、已取消 context、空/越界 installation 或无效 pin。
2. 精确读取已有 `system_backup_v2_kek_fences` 的 installation 行并 `FOR SHARE`。缺 fence 即拒绝，绝不创建 fence。
3. 在同一传入 view 中，以 installation、identity_hash、registry_version 精确读取当前 binding，`LIMIT 2 FOR SHARE`。缺行、重复行或读错误均拒绝，不取任意第一行，不扫描整个 installation。
4. 用原 `readBindings` 共用的 `scanBindingRow` 复核 canonical core bytes、semantic core hash、key fingerprint、installation/key/config pin 对应、非零 row_version，以及独立 Generate/Unwrap 撤销解析。

`store.go` 仅提取原 scanner 和共用列清单；没有复制或放宽原校验。原 Bind、Stage、Revoke 语义不变。新 API 不调用 `Bind`，没有 INSERT/UPDATE/CompleteScan、网络、文件、事务创建/提交/回滚或配置写入。`Bind` 的 `INSERT IGNORE` 仍只属于原 writer 路径，不能拿它替代本只读接口。

成功返回原 typed `BindingFacts`，含当前 `Binding`、`BindingSHA256`、`RowVersion`、`GenerateRevoked`、`UnwrapRevoked`。返回含撤销的事实是正常行为；方法不把撤销清空，不把 generation 撤销当作 independent unwrap 撤销，也不把“没有撤销”解释为已获权限。原事务结束时由调用者释放共享锁。

## owner 与消费方职责

| owner / 接点 | 职责 |
| --- | --- |
| registry / D | 从同一原事务读当前精确 binding 与撤销事实，保留 fence-before-binding 锁序和原 scanner 校验；不签发授权、不补 source/coverage |
| 原 installation/KEK authority owner | 通过原 fence/授权协议维护真实 mapping、独立 purpose 撤销和保留材料；不能从候选 config 生成 owner 事实 |
| 公共 C 当前 gate | 将返回 Binding 与独立认证的原 mapping 做精确 pin 及 `SameSecurityBinding` 比较，并显式拒绝所需用途的撤销；Unwrap 消费须拒绝非nil `UnwrapRevoked`。继续保留当前授权、有效期、grant、source、签名和原 proof 的全部检查 |
| 原事务调用者 | 使用同一 ctx/tx，保持较早锁序、当前 scope 和 deadline，负责 commit/rollback；不能把一次读回当后续事务的缓存许可 |

本 API 不认证 owner 签名、不调用 KMS、不提供 PreparedCoverage、不生成 decision hash/time、Ready 或终态。缺失/冲突必须保留拒绝，不能为通过而创建 fence、替换 pin、移除撤销或换用另一事务。

## 冻结来源

以下为根审核消费的4个文件 SHA256，本次补文档时再次只读核对一致：

| 文件（同在 `backend/internal/systembackupkekregistry/`） | SHA256 |
| --- | --- |
| `binding_read.go` | `ccb421c62e3b48701d8fe864cdd0fbe500cc41d1f4c6ad90ca0ef875a070271e` |
| `binding_read_test.go` | `3811cc9af243d8531bbcfae04dc8e159fd319d3d02a65b4b7973b8065f7ec81f` |
| `binding_read_mysql_test.go` | `5656afcfc35a39b9fa9df75185152da8929a598eb4f1569e1537de7bf3191c02` |
| `store.go` | `b62f368a143ac019f564b3a6bff88949fa698cee6c4418ae4688d0086cb227fb` |

实现阶段 D 仅做 gofmt/静态检查，未自行运行测试、读取根私密凭据、编译、SQL 或远连。根审核另以冻结依赖建立独立快照完成下节验证；本次只新增本文，Go 文件继续冻结。

## 根审核实际窄验证

根审核在其新独占 loopback MySQL 8.4.13 上运行**整个 registry 包**，启用 `systembackup_mysql` tag：总耗时3.086秒，全部 PASS，无 SKIP，原普通单测也回归。环境为独立 UUID pin、SAN 身份验证的 TLS1.3 会话（`TLS_AES_128_GCM_SHA256`）、`require_secure_transport=1`；未使用旧无TLS helper或放宽安全传输要求。

两个真实 SQL 根确实执行：

| 测试 | 实际耗时及结果 |
| --- | --- |
| `TestReadBindingTxReadOnlyAndOriginalRevokeMySQL` | 1.36秒，PASS。调用者 `ReadOnly:true` 事务成功读原 binding；独立 writer 的原 Bind 在共享 fence 下得到1205锁等待错误；精确 binding 的 `FOR UPDATE NOWAIT` 得到3572。释放读事务后原 writer 的 Bind/Revoke/commit 成功，新只读事务读到当前 Unwrap 撤销，独立 Generate 状态保持区分 |
| `TestReadBindingTxMissingAndMalformedMySQL` | 0.37秒，PASS。缺 fence/缺 binding 拒绝且不写 fence；错误 core hash/fingerprint、零RV、两类坏撤销 JSON、刻意破坏唯一性的隔离测试重复行均拒绝 |

普通用例另覆盖原 typed refs/hash、canonical core、installation/pin 替换、扫描错误、撤销用途不匹配及无效输入不访问 SQL。破坏唯一性只发生在测试自己创建的随机 schema，生产 migration 不修改。

根审核测试后独立读回 server UUID，并确认业务 schema 数为0，测试自有 schema 已按精确名称、server UUID 和随机 marker 清理完成。整个 registry 实际 unit/TLS 测试日志 SHA256：`4da474493c09bc062f49c90b10542902f7e9f17d62773a44321633a4a8c3d99a`。

随后根审核正常 shutdown 本批 MySQL，并完整删除其自有 D 测试根（zip、安装目录、data、keys、credentials、source、cache、tmp）及 workspace 定位脚本，仅保留非秘密日志/pins；不保留测试构建或秘密材料。此清理由根审核执行，D本轮未自行连接数据库或删除根审核目录。

测试入口供根审核复现，工作目录为冻结快照的 `backend`：

```text
go test -tags systembackup_mysql ./internal/systembackupkekregistry -count=1
```

环境沿实际 TLS fixture：`TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS` 指向受控私密 JSON，`A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID` 为独立 UUID pin；读取 Host/Port/User/Password/CAFile/TLSServerName/ServerUUID，仅接受独占 loopback、高位非3306端口和受验证 TLS。缺少凭据时 SQL 用例会 SKIP；上面的实际运行无 SKIP。本文不读取、复制或公布凭据文件内容。

## 结论范围

本次证明的是根审核**root测试凭据下的 ReadOnlyTx**、共享锁行为、原 Revoke 与当前撤销读取边界。ReadOnlyTx 成功不代表生产 SELECT-only 账号已配齐权限，也不是现场 namespace、数据库账号、最小授权或安装接线的验证。独立 writer 指独立连接池/原事务，不应被写成已验证生产独立身份。

公共 C 消费 API 后，根审核另以32文件冻结快照运行统一 caller/组件检查，PASS，耗时4.405秒，日志 SHA256：`66ae7e2fc5ec648ce61755741008d7fb7fe14e5419fd35af75e0b97e8815ed98`。这项组件结果不等于正式 acceptance/catalog、同任务 SQL、Ready/decision metadata、唯一终态 CAS 或页面完整备份成功；这些仍各需实际证据。本页不将 registry 窄验证或组件 PASS 扩展为上述结果，也不以返回 BindingFacts 作为许可空壳。下一切片仅为 C 的 decision 实现，尚未授权 Ready/终态；D production caller 保持冻结。

本轮仅新增本文，无测试、编译、SQL、远程或提交操作，无新增构建产物。
