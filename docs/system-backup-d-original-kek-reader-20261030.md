# D 原安装 KEK reader 接入

`systembackupkekadapter.InstallationPreparation` 实现 `OriginalKEKPreparation`。
部署固定 Ed25519 原安装签发者公钥，读取原安装权威的签名记录。
签名输入为 `system-backup-original-kek.v1`、一个 NUL 字节、原始 JSON 字节。
记录包含完整 Binding（包括两个用途 ref 的原始字节）、Source、Revision、
NotBefore、Until 和两个独立撤销标志。Source.ContentSHA256 是 Go json.Marshal(Binding)
的 SHA256。候选 JSON 和 committed config 都不能签发或取代原安装记录。

SQLOriginalReader 只读 `system_backup_installation_kek_authority`：

```sql
CREATE TABLE system_backup_installation_kek_authority (
 installation_id VARCHAR(128) NOT NULL,
 identity_hash CHAR(64) NOT NULL,
 registry_version VARCHAR(128) NOT NULL,
 signed_record MEDIUMBLOB NOT NULL,
 signature VARBINARY(64) NOT NULL,
 PRIMARY KEY (installation_id, identity_hash, registry_version)
);
```

这是原安装权威需要维护的表，不由配置提交创建/回填。权威写入者必须先获得同一
installation KEK fence，再更新该记录；不得从配置快照回填。Recheck 使用原事务的
FOR SHARE 当前读，拒绝修订变化、撤销、期限变化、签名变化和删除。生产数据库必须
使用该表，不能令预读连接指向另一个数据库。

`WireServices` 同时设置 ConfigBootstrapService.KEK 和 ConfigMutationService.KEK，
复用 A admission.Prepare 和 D Bind → StageAdmission → Recheck → Commit。
两服务成功提交后执行 ReadCommitted；核对失败报告 commit unknown。

尚需 A/原安装 owner 提供真实签名记录、用途 capability preparer、C coverage/source，
并在最终部署构造调用 WireServices。当前 bootstrap CLI 的 linkedOwnerAdapters 仍为空，
server 也没有配置 mutation 的生产装配；因此本提交不是生产启用声明。
三用途签名 resolver、policy/role 和真实 generate/unwrap 不属于此 reader 实现。

当前会话工具未暴露 list_threads/send_message_to_thread，无法自动通知 A 对话。
