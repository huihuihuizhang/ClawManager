# D 独立交付：`4fe83bcd` 现库导入 profile

状态：已固定现场完整 ledger 和直接采集的只读全库结构，确认镜像内 94 项
catalog 对应 `acf59b79` 的 Git blob 原字节，并核对 `4fe83bcd` 差异；
已提供隔离副本只读预检，未执行现库迁移，未取得现库可导入证明。
此工作不包含 Runtime 镜像下载、构建或部署。

## 已核对的拒绝边界

- 现场测试库为 MySQL 8.4.8、`clawmanager`、server UUID
  `f1f5f76a-95f5-11f1-b08e-366835b4a029`；用户只读查询给出的
  `schema_migrations` 为 **97 行**，包含
  `080_add_system_backup_registration_runtime.sql`，并存在
  `system_maintenance_participants`。按 `ORDER BY filename` 导出的文件名
  LF 列表 SHA-256 为
  `5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903`。
  这些是 ledger 身份证据，不构成 schema 或数据等价证明。
- 现场完整文件名列表保存在
  [d-existing-db-ledger-20261030.txt](evidence/d-existing-db-ledger-20261030.txt)，
  恰为 97 行；审计脚本在运行前校验上述完整文件 SHA-256，拒绝 CRLF、
  重复项、非 ASCII 名称及输入变更。该列表先来自用户在远侧的只读查询，
  后由下述 App Pod 内直接只读采集再次核对。
- `4fe83bcde5a8a693dddb2635e9a3e397d6e3472e` 中旧备份迁移以
  `065_add_system_backup_control_metadata_core.sql` 至
  `080_add_system_backup_registration_runtime.sql` 命名；当前仓库迁移
  包含重编号的 `096_backup_v2_*` 至 `109_backup_v2_*`，还增加后续迁移。
  文件名相似不证明 SQL 或现存数据等价。
- 该 Git 提交的数据库迁移目录有 **137 个 SQL 文件**，其中 081、082
  在现场未应用；即便只取其余 135 项，现场 97 项也并不相同。
  当前目录有 168 项，旧目录中有 20 个文件名不再存在，当前目录有 51
  个新增文件名。不能把现场当作“4fe83bcd 仅缺 081/082”的库。
- 实际集合核对：现场 97 项中 **3 项不在 `4fe83bcd`**（
  `045_update_workbuddy_windows_runtime.sql`、`046_add_instance_pvc_name.sql`、
  `047_add_instance_runtime_variant.sql`）；旧提交有 **43 项未在现场 ledger**；
  现场有 **21 项不在当前 catalog**，当前 catalog 有 **92 项未在现场 ledger**。
  现场与旧提交及当前 catalog 的三方同名 SQL **0 项原字节不同**。
  此比较只对旧提交中能找到的原始 blob 成立；那 3 项的执行 SQL 来源
  尚未确认，原字节、摘要及 schema 效果仍需单独核对。
- 本地缓存的**现场实际 App 镜像 ID**
  `sha256:c16f07c25c6dc8362aa09b7a1e81f5d1204f2812ae542bbcb21a3946975c6c9d`
  离线执行其 `/usr/local/bin/clawreef-system-backup-migrate --catalog-only`，
  得到 94 项、catalog SHA-256
  `0de7fd12672eccc8b51fd38b6e3dd49e6342fe3e52da247267e9cd02ba420d93`；
  与现场 97 行 ledger 比较，差集**恰为上述 3 项**，无其他缺项。
  [镜像 catalog 证据](evidence/d-deployed-app-catalog-20261030.json)
  固定了镜像 ID、全部 94 个文件名和差集；它仍未恢复这 3 项的原 SQL 字节。
- Git 提交 `acf59b7933303b879af80ed192fa0ca4466c79d7` 的 94 个 SQL
  Git blob 原字节按 catalog 算法重算，**精确等于现场镜像 catalog**。
  由此确认这 94 项的版本化来源。`4fe83bcd` 中同名 94 项重算 catalog
  不同；逐项比较发现 `001_init_schema.sql`、
  `046_add_enterprise_auth_identity.sql` 两项原字节已变化。因此
  `4fe83bcd` 不是现场镜像的精确 SQL 来源，不能拿其全部原字节充当
  现场已执行历史。审计脚本同时输出两个 Git 提交的逐文件摘要与差集。
- 当前 `MigrationHistoryReview` 仅允许“当前 catalog 全部已应用、仅
  `109_backup_v2_add_system_backup_registration_runtime.sql` 待应用”的
  特定场景。现场 080 ledger 不满足这个合同。普通
  `system-backup-migrate --apply` 会拒绝未知历史项；不能为了让它通过
  而改写历史 ledger、直接重放旧 SQL，或仅替换 source SHA。
- 仓库已有的 `ImportBackupCopy` 是另一个受限方案：其内嵌
  `backup_import_map.json` 固定源提交 `d3c5715a…` 和 **136 项**完整
  migration，并要求隔离副本库名为 `cm_import_<32hex>`、完整源 schema
  指纹、源 ledger 全集、无未完成工作。现场 97 项相对该 map 有 3 项额外、
  42 项缺失；map 的 42 张待改名旧表在现场只有 35 张，15 条历史别名中
  只有 14 条对应现场 ledger，`081_fix_system_backup_prune_item_identity.sql`
  尚未应用。不能直接复用其 `--apply` 路径或只替换源提交 SHA。
- 用户提供的全库 `mysqldump --no-data` 文件 SHA-256 为
  `1f1fa2d156c2527587d21a727e1e273cb02635b0e1e3ce1391443cfce7f5a655`，
  大小 341234 字节；含 99 张表、无 INSERT、无视图、无 v2 表。它的表名
  全部属于现有 122 表参考 profile；缺少的 23 张表属于后来合入的业务
  结构。此结果符合用户说明的 A/D 现场基线与 B/C 后续合入顺序。
- 在本地无网络的临时 MySQL 8.4.8 容器中，只导入该 DDL 和 97 个迁移
  文件名，容器内 ledger SHA 与现场一致。用只读采集器取得的候选结构
  指纹为 `ec1b3e004d83fb6e82aebecf33d1d5ad1d88cb2e094325c26aea9d3530d5e28b`；
  [完整候选元数据](evidence/d-existing-db-source-schema-candidate-20261030.json)
  明确标记为**从 DDL 重建**，不冒充远侧直接采集。该候选有 99 表、
  1948 列、896 条索引记录、188 条外键记录、266 条 CHECK 记录。
  此指纹不能替代现场直接采集。
- 2026-10-30 在现场 App Pod 内运行同一只读采集器，绑定上述 server UUID、
  库名及 97 行 ledger SHA，得到 511588 字节的
  [现场直接采集元数据](evidence/d-existing-db-live-inventory-direct-20261030.json)，
  文件 SHA-256 为 `71b22c009b3ad9bdeef324d2cafd2aa4c1a646110f2080d1b6f42746f8f7013f`，
  结构指纹为 `140b053e6d3a40a8b5d7c305e3429020a1bc394b3c156167d9683072ec0908bf`。
  两份元数据都有 99 表、1948 列、896 条索引记录、188 条外键记录、
  266 条 CHECK 记录；表名/列清单、表、索引、外键、CHECK 元数据一致。
  唯一记录差异是 `system_artifact_leases.delete_source_guard` 的生成表达式：
  现场为 `concat(source_artifact_type, ':', source_public_id)`，本地从
  `mysqldump` 重建后表达式在 `source_public_id` 周围多一层
  `convert(... using utf8mb4)`。因此两个结构指纹**不相同**，不得把
  重建结构标作现场等价。直接采集固定了真实来源；仍需确认 3 项旧 SQL
  原字节，并在含真实行的隔离副本上验证迁移、重试与回滚。
  后续若以 `mysqldump` 重建隔离副本，必须分别核对现场直接指纹与副本
  指纹，并逐字段确认只有这一个生成表达式差异；副本指纹相等本身不证明
  行数据已完整复制。导入 profile 应把这一步列为显式来源到副本的桥接
  检查，不能仅用候选指纹冒充现场源指纹。
- 用户随后在同一测试 namespace 对 `information_schema.COLUMNS` 做只读
  查询：现场有 `system_backups`、`system_backup_configs`、
  `system_maintenance_participants`、`instances`、`runtime_pods`、
  `instance_runtime_bindings` 等旧表；输出中没有 `system_backup_v2_*` 表。
  当前执行代码查询 `system_backup_v2_backups`、
  `system_backup_v2_maintenance_participants` 等新版表。现场输出只包含
  列名、类型、空值和键标记；完整元数据已由上述直接采集补足，仍无行数据证明。
  因此替换 App/Runtime 镜像不能代替版本化现库升级。
- 同一现场只读计数：`users=8`、`instances=4`、`runtime_pods=9`、
  `instance_runtime_bindings=3`；旧备份配置、备份任务、participant 均为 0，
  活跃备份、非 idle gate、mutation lease 均为 0。这说明升级副本必须保留
  现有多用户与 3 条 Runtime 绑定，而不能以空库迁移代替验证；计数为零
  也不能替代隔离副本上的全表行与关系保全证明。
- 2026-10-30 远侧只读关系核对：`instances.user_id`、
  `instance_runtime_bindings.instance_id`、
  `instance_runtime_bindings.runtime_pod_id` 的孤儿数均为 0；运行状态为
  3 个 `lite/running` 和 1 个 `pro/stopped`。Workbuddy 实例数和
  `system_image_settings` 中的 Workbuddy 行数均为 0。这些是副本保全时的
  **现场基线计数**，不能单凭零孤儿证明全部表行、加密配置或工作区字节
  已复制。
- 同日按现场表名逐表只读 `COUNT(*)`：匹配到 **35 张**旧
  `system_backup*`、`system_maintenance*`、`system_restore*`、
  `system_artifact*` 控制表，未发现非零行。查询由多个连接顺序完成，不是
  原子快照；实施前必须在隔离副本的同一只读事务内重新证明 35 表全部为空。
  **不能因此直接顺序执行当前 catalog**：当前
  `079_add_system_backup_control.sql` 对 `system_backup_events`、
  `system_backup_installation_state` 等同名表使用 `CREATE TABLE IF NOT EXISTS`，
  会跳过已有旧表而留下不匹配的结构。转换必须先审查表名与约束冲突，
  选择有 journal 的版本化改名或数据为空时的显式处理，再在副本上验证。
- 同一现场的 `mysqldump --no-data` 只读输出进一步显示：`instances` 已有
  `pvc_name`、`runtime_variant` 及由 `owner` 生成的
  `owner_normalized`；`instance_runtime_bindings` 对 `instance_id` 唯一，
  对 `(runtime_pod_id,gateway_port)` 唯一，并以外键分别引用 `instances`
  与 `runtime_pods`；`system_maintenance_participants` 对
  `(origin_installation_id,scope,participant_id)` 唯一，以外键引用
  `system_maintenance_locks`，且有状态、检查点、时间等 CHECK 约束；
  `system_backup_installation_state` 的当前配置版本以外键引用
  `system_backup_configs`。这为 3 个额外历史迁移中的列效果提供了部分
  结构旁证，但不证明原 SQL 字节、全库数据迁移或新版表等价。

## 可重复运行的本地只读审计

在仓库根目录运行（无需现场数据库凭据，也不会写数据库）：

```powershell
py -3 -B scripts/system-backup-d-legacy-ledger-audit.py `
  --ledger-file docs/evidence/d-existing-db-ledger-20261030.txt `
  --expected-ledger-sha256 5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903 `
  --inventory-file docs/evidence/d-existing-db-live-inventory-direct-20261030.json
py -3 -B scripts/system-backup-d-legacy-ledger-audit.test.py
```

脚本直接从固定 Git 提交读取 blob 原字节；Windows `git archive` 会在这个
仓库导出 CRLF，不能用其输出计算旧 SQL 摘要。JSON 中
`current_catalog_sha256=d82eb65ecd839741255722bc8bdcd77de28c4fa25f8c1c25a622ba588f4156b5`
按当前 Go catalog 的规范化与长度前缀算法计算，并与仓库的 reviewed pin
比对；pin 不匹配时脚本拒绝输出审计通过结果。JSON 中
`schema_equivalence_verified=false` 与 `migration_authorized=false` 是固定
拒绝边界，不是可更改的准入开关。加入 `--inventory-file` 时，脚本还要求
现场 JSON 原字节 SHA、server UUID、库名、97 行 ledger、结构指纹与各元数据
计数都符合固定现场 profile；这仍是只读核对，不提供迁移授权。

## 现场全库结构采集入口

`system-backup-legacy-inventory` 是单独的只读命令，已加入 App 镜像构建。
它使用 `START TRANSACTION READ ONLY`，绑定 MySQL server UUID、库名和
上述 97 行 ledger SHA；两次读取 ledger 与完整
`information_schema` 表、列、索引、外键、CHECK 元数据，变化即拒绝。
输出包含结构元数据和迁移文件名，不含业务行、密码或 DSN；输出中的
`migration_authorized=false`、`schema_equivalence_verified=false` 固定为
false。它不调用 `ImportBackupCopy`，也不执行 DDL。

下面是后续复查时针对**已包含该命令且未自动升级现场库**的 App 镜像的
命令；本次现场采集使用了同一 Go 命令的临时 Linux 构建，按摘要校验后
复制进当前 App Pod 执行，没有替换 App 镜像或执行 DDL：

```bash
ns=clawmanager-zhanghui08-system
out=/tmp/clawmanager-zhanghui08-legacy-inventory.json
kubectl --context kubernetes-admin@kubernetes -n "$ns" exec deploy/clawmanager-app -- \
  /usr/local/bin/system-backup-legacy-inventory --app-env \
  --expected-server-uuid f1f5f76a-95f5-11f1-b08e-366835b4a029 \
  --expected-database clawmanager \
  --expected-ledger-sha256 5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903 \
  > "$out"
sha256sum "$out"
```

把 JSON 文件作为证据交接；采集成功只表示结构读取成功，不能执行迁移或
放行备份。当前现场 App 镜像仍未证明含有该新命令。

## 两条环境路径

**空白隔离测试库**：创建独立 MySQL 8.4.8 实例及空库，记录其真实
`@@server_uuid` 和 `DATABASE()`，使用当前构建内嵌 catalog 的
`system-backup-migrate --catalog-only` 取得精确 SHA，然后用独立私有
DSN 文件调用 `--apply`。此路径从空库顺序执行当前 migration；不能把
测试环境已有的 080 库称为空库，也不能把测试库原 server UUID 复制成
新库授权 pin。

**现库升级**：先制作隔离的数据库副本并保留原始迁移 ledger、表定义、
索引、外键、数据行数及关键主键/外键关系。导入 profile 必须固定原
server UUID/database、原始历史 SQL 字节与摘要、当前 catalog SHA、
审核人及审核引用；逐项证明旧迁移的实际表/列/约束和新版预期的关系，
为差异提供版本化 DDL/数据修复。先在副本上执行并验证可重跑、失败后的
恢复和应用查询；再制定现场升级及回退步骤。新库初始化成功不替代这条路径。

### 97 项现库副本的只读预检

`system-backup-legacy-preflight` 使用私有 DSN 文件连接独立的
`cm_import_<32hex>` 库，读取上文直接采集 JSON 的**原字节**并校验固定
SHA。它在只读事务内两次核对完整 ledger 与 schema，逐表要求 35 张旧控制
表全空，并拒绝已存在的导入 journal 和未完成备份工作。副本结构只接受现场
原指纹或已审查的 MySQL 8.4.8
`mysqldump` 重建指纹；输出固定为 `data_preservation_verified=false`、
`migration_authorized=false`。此预检**不写入**数据库，也不调用现有
136 项的 `ImportBackupCopy`。新构建的 App 镜像会包含同名可执行文件；
需要运行时应将它作为隔离操作员命令启动，不要为预检而滚动当前 App
Deployment，因为 App 启动路径另有数据库迁移行为。

对已经用测试数据建立的隔离副本，可在本地仓库 `backend` 目录运行：

```powershell
go run -mod=readonly ./cmd/system-backup-legacy-preflight `
  --dsn-file C:\private\cm-import.dsn `
  --source-inventory-file ..\docs\evidence\d-existing-db-live-inventory-direct-20261030.json `
  --timeout 5m
```

DSN 文件应只供操作员读取，并指向隔离副本；命令不会打印其内容。实际
隔离副本还须与现场源建立**行数据保全证明**，上述预检成功不能替代它。
本地临时 MySQL 8.4.8 集成试验用现场 no-data DDL 与 97 行 ledger 构造
空数据副本：预检接受 99 表的 `mysqldump_8_4_8` 结构，拒绝非隔离库和
额外列漂移。该试验未使用现场业务数据；测试容器、二进制、DSN、缓存及
镜像已清理。

### 2026-10-30 现场数据隔离副本预检

远侧测试环境的 `clawmanager` 现库估算 87 MiB、MySQL 数据目录空闲
1,923,712 MiB。操作员使用
[`scripts/system-backup-d-legacy-copy-preflight-remote.sh`](../scripts/system-backup-d-legacy-copy-preflight-remote.sh)
在同一 MySQL 8.4.8 Pod 内创建随机命名的
`cm_import_301564ebae734fbb8ff3da1aaf1b9024` 隔离库，以
`mysqldump --single-transaction --quick --skip-lock-tables` 导入现库数据；
未对原库执行 DDL 或转换。脚本先核对现场 server UUID、结构清单与命令
二进制 SHA；现场运行的脚本 SHA256 为
`46550f9f8e253202abf749e2d48fb1db28eaa2fcf00d39f76cf2f939158eed8b`。
预检在只读事务内完成并输出：

```text
state=read_only_schema_and_ledger_verified
copy_schema_variant=mysqldump_8_4_8
copy_schema_sha256=ec1b3e004d83fb6e82aebecf33d1d5ad1d88cb2e094325c26aea9d3530d5e28b
ledger_sha256=5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903
table_count=99 legacy_control_tables=35
data_preservation_verified=false migration_authorized=false
```

预检后的核心计数在原库与副本一致：`users=8`、`instances=4`、
`runtime_pods=9`、`instance_runtime_bindings=3`、`schema_migrations=97`。
这些计数不能代替逐表行摘要、外键关系复核或恢复可用性验证。同一 MySQL
Pod 上的临时副本也不是独立故障域备份。脚本在退出时执行副本和临时文件
清理；远侧独立只读核验返回 `COPY_ABSENT`、`POD_TEMP_ABSENT`。
本地测试构建二进制和 Go 缓存也已删除。
现场运行后又补入每次操作前的 namespace UID、Pod UID、MySQL server UUID
复查；执行 CREATE、dump/load 与 DROP 的 Pod shell 在同一次 exec 内再次
检查 MySQL server UUID，身份变化时拒绝继续写入并留下待人工核查的副本名。
第一轮现场结果对应上面的原脚本 SHA；身份复查修订在第二轮运行中验证。

第二次现场隔离副本运行使用脚本 SHA256
`4e72a5c511b28bfdf632f2ed3d37474f9946cf917834f8d41d1e072eeeb9c7c9`。
脚本在实际 CREATE/dump/load/DROP 的 Pod shell 内复核 server UUID；先验证
现库 99 表均为 InnoDB 且各有主键，再将按主键排序的数据流直接送入隔离库
和 SHA256 读取器，不落盘明文 SQL。副本重导出的数据流 SHA256 与导入流
同为 `a9f9383a2c0752f52199151ef4168033d51953945b20b05b6e5948f6d5405d8e`。
副本 `cm_import_68881873d47b40759473a6c9091a2249` 的只读预检仍通过，
99 表、97 项 ledger、35 张空旧控制表的指纹未变；核心行数仍为
8/4/9/3/97。独立收尾返回 `COPY_ABSENT` 与 `POD_TEMP_ABSENT`。
这证明此次 MySQL 8.4.8 SQL 序列化数据流的副本往返一致；源库继续运行，
因此不把它等同于停止写入后的完整备份或升级授权。预检 JSON 仍报告
`data_preservation_verified=false`、`migration_authorized=false`。

## 隔离升级探针：真实数据副本

2026-10-30 又在无网络的本地 MySQL 8.4.8 临时容器中用现场无数据 DDL（SHA256 `1f1fa2d156c2527587d21a727e1e273cb02635b0e1e3ce1391443cfce7f5a655`）及原 97 行 ledger 复现升级。直接执行当前缺失的 92 项迁移，在 `085_add_backup_capture_coordination.sql` 因旧 `system_backup_attempts` 缺少新版 `public_id` 外键目标而失败；根因是之前 `081` 的同名 `CREATE TABLE IF NOT EXISTS` 静默跳过旧表。对第二个全新隔离库，先一次性将 35 张旧控制表改名为确定的 `dlegacy_*`，保留其定义与外键，再执行同一 92 项迁移，全部成功：ledger 从 97 增至 189，旧表 35 张仍保留，新版 `system_backup_attempts.public_id` 和 `system_backup_v2_runtime_controls` 均存在。此试验无业务行，不能证明现场数据保全；本地容器和镜像随后删除。

操作员随后在现场 MySQL **随机隔离副本**运行了[升级探针](../scripts/system-backup-d-legacy-copy-upgrade-probe-remote.sh)，传输包 SHA256 为 `518c9421f92f02b5a9c2bba44c7ce1a639280e5ed27f4e06bcac594bc0150b3f`。输入由[固定字节生成器](../scripts/system-backup-d-legacy-upgrade-probe-build.py)从现场 inventory、97 行 ledger 和当前 migration catalog 重建并逐文件校验 SHA。原库仅作单事务 `mysqldump` 读取，探针先核对复制与重导出的完整数据流 SHA256 都为 `b9b3a11e8869949f258cbb1eaefea56bc405998b4fb3721aa66f02373228c97c`；在副本确认 35 张旧控制表为空后原子改名，执行 92 项迁移。结果 `UPGRADE_COPY_VERIFIED ledger=189 legacy_tables=35 core_identity_sha256=efcbae2af2d44c98932574eddeca0453861450e7126f5342e833a7530138aeca row_counts_non_decreasing=true`。原 99 张表的行数均未减少，`users/instances/runtime_pods/instance_runtime_bindings` 的主键及关键关系摘要前后相等。随机副本 `cm_import_a79db332fe944df58f22f0fd7c298cb5` 与 Pod 临时文件的独立收尾返回 `COPY_ABSENT`、`POD_TEMP_ABSENT`。

这证明**这一次真实数据副本**可跑通当前 92 项 SQL，并保存上述核心身份；尚未证明所有表原列的逐行字节一致、部分 DDL 失败后可原位重跑，也没有恢复 Workspace、启动 App/Controller、迁移原库或跑备份任务。三项额外历史 SQL 原字节仍未找到，不能把此探针改写成生产导入授权。后续正式 profile 应采用独立 journal、完整原列行证明、迁移后约束/应用查询、失败副本丢弃重建以及切换/回退步骤；旧版同名控制表须明确处理，不能靠 `IF NOT EXISTS`。

如需重新生成上述临时 SQL，运行 `py -3 -B scripts/system-backup-d-legacy-upgrade-probe-build.py --output-dir <临时目录>`；输入或当前 SQL catalog 任一字节变化时生成器会拒绝输出。生成文件属于测试产物，测试后删除。

## 本 profile 的交付出口

1. 已从 `4fe83bcd` Git blob 提取该提交的 137 项 SQL 原字节摘要，与现场
   **完整** 97 行 ledger 核对文件名，并直接采集现场实际 schema；仍需定位
   3 项额外历史 SQL 的真实来源和验证现有数据关系。
2. 固定旧→新版本化映射；对创建表、列类型、唯一键、外键、索引、默认值、
   时间语义及已有数据做差异测试。无法证明等价的项明确列为修复 DDL，
   不自动标为已应用。
3. 用隔离 MySQL 副本验证 080→目标 catalog 升级、重复运行、部分 DDL
   失败恢复，以及用户、实例、runtime binding、participant 主键和关系保留。
4. 提供独立的 `--preflight`、`--apply` 输入和现场回退命令；均绑定实际
   server UUID、库名、catalog、历史 SQL 摘要。输出不能含 DSN 或密钥。

第 1 项仍缺 3 项历史原 SQL，第 2 项仅验证了旧表隔离改名的候选路径，第 3 项仅有一次真实数据副本的结构迁移和有限保全证明；重复运行、部分失败恢复及完整逐行/约束验收未完成。第 4 项未完成，因此现库升级和备份准入仍关闭。
