# A：三用途签名 provider ACL 准备

`scripts/system-backup-a-apply-signing-policy.py` 为 `capture_certificate`、`acceptance_record`、`catalog_record` 各生成独立的 Transit `sign` 路径 ACL 和 Kubernetes JWT role。每条 ACL 只准 `update` 精确 key 路径，要求 `input` 和固定数字 `key_version`；role 固定 audience、namespace、ServiceAccount UID、Pod UID、20 秒 batch token 和唯一 policy。安装前读取三个 Ed25519 key 的指定版本公钥与安全元数据，核对 operator 提供的计划、SHA-256、CA pin、JWT mount 配置 pin；安装后使用现有 KEK policy 工具的精确读回函数。`--revoke` 只删除所选用途的 role/policy 并读回不存在，不声称原签名 key 已撤销。

该脚本只接收 `review_only_not_authorized` 计划；计划、provider key 元数据、role 成功安装均不构成原业务签名授权。原授权来自 `systembackupsecurity.OriginalSigningResolver` 的 `OriginalSigningAuthority`，其三个真实业务 reader/caller、原签名 mapping 的安装/版本/期限/撤销事实和对应短期 workload token 装配仍须接线。不能用测试 fixture、operator 计划或现有配置自证。

本地 `py -3 -B scripts/system-backup-a-apply-signing-policy.test.py` 五项测试退出 0：精确三用途 ACL/role、拒绝重复/错版本/错安装/错用途、自报授权和重复 JSON、provider 公钥 pin、单用途 role/policy 撤销。没有调用在线 provider，没有生成凭据，也没有构建产物。现场 JWT trust 与 KEK profile 的既有公开回执仍有效；不重复全量盘点。真实 generate/unwrap、错用途/错版本/撤销拒绝尚无现场回执，②不得宣布完成。

后续 A 收紧 `OriginalSigningResolver`：从已认证历史公钥保留每个当前用途的 `NotBefore/NotAfter`，在原业务 authority 调用前拒绝过早或过期 key，并把返回凭据期限压到 key 到期点；凭据复查也拒绝越过该窗口。定向负例用有效的业务 authority 和短期 token，分别模拟 key 尚未生效、已经到期及发放后到期。`go test -mod=readonly -p=1 -count=1 -timeout=180s ./internal/systembackupsecurity -run '^TestOriginalSigningResolver'`（默认 vet）退出 0，运行时间 3.617s；冷缓存编译较慢，本轮隔离缓存/临时目录及误建的空父目录均已删除。这只证明本地期限拒绝，不提供三个用途的生产业务 reader、在线凭据或 provider 调用回执。
