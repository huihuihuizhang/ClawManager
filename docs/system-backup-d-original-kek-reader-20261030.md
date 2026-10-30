# D 原安装 KEK reader 接入

`systembackupkekadapter.InstallationPreparation` 实现 `OriginalKEKPreparation`。
部署固定 Ed25519 原安装签发者公钥，读取原安装权威的签名记录。
签名输入为 `system-backup-original-kek.v1`、一个 NUL 字节、原始 JSON 字节。
记录包含完整 Binding（包括两个用途 ref 的原始字节）、Source、Revision、
NotBefore、Until 和两个独立撤销标志。Source.ContentSHA256 是 Go json.Marshal(Binding)
的 SHA256。候选 JSON 和 committed config 都不能签发或取代原安装记录。

SQLOriginalReader 只读 `system_backup_installation_kek_authority`。
正式版本化 DDL 为 `backend/internal/db/migrations/128_backup_installation_kek_authority.sql`，
由现有 embedded migration runner 和 `db.ApplyPinnedMigrations` 执行，进入 schema_migrations
和迁移 catalog hash。它创建当前表及追加历史表，不插入任何配置派生记录。

这是原安装权威需要维护的表，不由配置提交创建/回填。权威写入者必须先获得同一
installation KEK fence，再更新该记录；不得从配置快照回填。Recheck 使用原事务的
FOR SHARE 当前读，拒绝修订变化、撤销、期限变化、签名变化和删除。生产数据库必须
使用该表，不能令预读连接指向另一个数据库。

`WireServices` 同时设置 ConfigBootstrapService.KEK 和 ConfigMutationService.KEK，
复用 A admission.Prepare 和 D Bind → StageAdmission → Recheck → Commit。
两服务成功提交后执行 ReadCommitted；核对失败报告 commit unknown。

原权威签名记录写入者见 `InstallationAuthorityWriter` 和
`backend/cmd/system-backup-kek-authority/main.go`。原安装 owner 在独立签发环境生成
上述域分离签名；导入命令不持有私钥，不根据候选/已提交配置生成或签名映射。
部署必须独立固定 issuer 公钥、安装 ID、MySQL server UUID/database；不能从待导入
记录或候选配置选择可信 issuer。公钥文件为原始 32 字节，签名文件为原始 64 字节。

```powershell
system-backup-kek-authority `
  -installation-id <installation> -server-uuid <uuid> -database <database> `
  -dsn-file <owner-writer-dsn-file> -issuer-public-key-file <pinned-public-key-file> `
  -record-file <original-owner-record-file> -signature-file <original-owner-signature-file> `
  -expected-row-version 0
```

首次写入 expected=0；后续写入指定当前 row_version。写入者核验原签名、完整 binding、
两用途 ref、来源/版本/期限，然后在同一事务中核对数据库身份、取得 installation KEK
fence、CAS 当前记录、追加历史及推进 epoch。相同 binding 的撤销不能复活，旧 revision
不能重新使用；immutable binding 改动必须换新的 registry version。提交结果不明时，
应核对当前表与历史中的 record hash/revision，不得改 expected 值盲目重试。

**生产调用位置核查：目前没有生产调用 `WireServices` 的位置。**
`backend/internal/systembackupsecurity/bootstrap_deployment.go` 的 `Apply` 仍直接构造
`ConfigBootstrapService{DB: database, Admission: admission}`，未设置 KEK；候选部署路径
`bootstrap_deployment_candidates.go` 也未接入该装配。
`backend/cmd/server/main.go` 尚未构造 ConfigMutationService 或挂载 ConfigMutationHTTP。
`backend/cmd/system-backup-bootstrap/main.go` 的 linkedOwnerAdapters 仅接入部分 A registry
validator，并未提供 KEK capability/source。不能声称已有生产装配或以 wrapper 定义代替调用。

尚需 A/原安装 owner 提供真实签名记录、用途 capability preparer、C coverage/source，
在上述最终部署构造中调用 WireServices 并使用它返回的两服务；本交付补齐数据库来源的
建表及验证写入入口，不代表生产配置写入链已经启用。
三用途签名 resolver、policy/role 和真实 generate/unwrap 不属于此 reader 实现。

当前会话工具未暴露 list_threads/send_message_to_thread，无法自动通知 A 对话。
