# 未填写的离线材料模板

这些文件由 `system-backup-offline-security --template <kind>` 输出。
空字符串、null、零时间和空 map 表示未提供；没有伪造安装、UID、签名、公钥、批准或 coverage。
它们不能直接用于生产。`trust.template.json` 与 `bundle.template.json` 的检查应退出 **2**。

填写顺序、现有消费者字段和生产挂载路径见
[离线安全交付说明](../../docs/system-backup-offline-security-handoff-20261101.md)。
信任 pin 必须独立于材料来源审核。不要在这里写入任何真实 token、DSN、密码或私钥。
