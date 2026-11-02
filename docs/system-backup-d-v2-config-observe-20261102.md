# D：既有 v2 配置只读盘点（2026-11-02）

本工具用于判断现场是否已有可供后续认证检查的 v2 配置材料，还是需要补首次安装接线。既有合法、启用且通过原认证的 canonical config 可以供原任务使用，不要求每次重新 bootstrap；首次安装所需 owner、source、PreparedCoverage 不能由本盘点生成或推定。旧 `system-backup-d-field-preflight.sh --sql-pins` 查询 legacy 表，其结果不能替代本工具的 v2 观察。

本次交付只有 Python 标准库脚本，无 Go、ELF、bundle、构建、部署或迁移步骤。用户自行上传并执行；D/根审核未通过本工具连接现场、执行 SQL 或 kubectl。下面命令使用已有远端工具目录，不需要填写 `/absolute` 占位路径，也不调用原生测试入口。

## 固定身份及真实边界

| 项目 | 固定值 / 检查 |
| --- | --- |
| context | `kubernetes-admin@kubernetes`，无覆盖参数 |
| namespace / UID | `clawmanager-zhanghui08-system` / `337cfe30-2c17-4b8e-b32a-760778b8098e` |
| 工作负载 | 仅既有 `Deployment/mysql`，沿 controller owner 的 Deployment UID → ReplicaSet UID → Pod UID 定位 |
| 容器 | 明确 `-c mysql`，检查 Running/ready、部署镜像一致及 containerID；每次 SQL 前和输出前重查 namespace、Deployment、ReplicaSet、Pod 和容器身份 |
| 数据库及凭据 | 仅在该容器内部使用既有 `MYSQL_DATABASE` 及 `MYSQL_ROOT_PASSWORD` 或其明确的 `_FILE` 指针；不猜 database/installation，不读取 Secret API，不探测额外路径 |
| 认证缺项 | mysql CLI、现有 database、密码缺失/冲突、身份变化、多候选 Pod、容器重启等固定拒绝；不改环境、不安装工具、不换账号或回退额外凭据来源 |
| SQL | 仅固定 allowlist 的 SELECT，包在 `START TRANSACTION READ ONLY` / `ROLLBACK` 内；没有 apply、DDL、迁移、grant、写表、bootstrap 或任务创建 |
| 有界性 | 总观察预算180秒；kubectl request-timeout=20秒、普通外层最多25秒、exec外层最多40秒；SELECT含5秒 MAX_EXECUTION_TIME hint；列表最多16项且拒绝继续分页，state/config各最多11行并报告可能截断 |

mysql 通过容器内 socket 读取；这不是源库独立 observer 账号或 TLS 探测。客户端显式使用 `--no-defaults --no-login-paths`，不读取额外选项文件或 login-path 文件。只加 `--no-defaults` 不能排除 login-path，见 [MySQL 8.4 官方客户端选项](https://dev.mysql.com/doc/refman/8.4/en/mysql-command-options.html)。密码只进入该次 mysql 子进程环境，不在参数、输出或本地文件中出现；stdout仅接收固定 JSON 查询结果，stderr/异常正文不输出。

表/列先查 `information_schema`，缺失正常报告，不访问不存在列：

- `system_backup_v2_installation_state`：实际 installation 的 SHA256 指纹、active_config_version、last_effective_enabled、matrix_key、row_version。
- `system_backup_v2_configs`：仅与实际 installation active version 关联的 version/enabled/config_size_bytes/config_sha256，以及 canonical 存在、长度匹配、SHA匹配布尔值。canonical列不存在时相应值为null，不查询该列。
- `system_backup_installation_kek_authority`、v2 kek_bindings/kek_admissions：仅与实际 installation_state 关联的存在数量；authority是原 owner-managed 表，不是旧 legacy config 表。没有输出 signed_record、signature、core或observation正文。
- `system_backup_v2_evidence`：仅关联实际 installation、system/capability_snapshot、inline/healthy/none 且 inline_payload非空的候选数量。没有可信独立 source/issuer pin，不把这个计数分类或认证为 Generate/Unwrap 授权，不导出 payload。

输出包含 server UUID/version/database、固定 namespace/UID、派生 Pod名/UID及表/列存在情况。未输出 canonical 正文、signed_record、DSN、密码、Secret JSON、任意业务数据或用户记录。canonical 的长度/hash相等仅为字节一致性，不证明 JCS、签名、当前授权、配置准入、有效期、source 覆盖或 PreparedCoverage。两次 SQL 是分别有界的观察，不是跨部署/配置的原子 readiness 断言。

## 冻结文件及独立验证

| 文件 | SHA256 |
| --- | --- |
| `scripts/system-backup-d-v2-config-observe.py` | `765b22dddc7d4545e4a4d74f47a983c0fc02d37c13fdf512b75f11f25872c53c` |
| `scripts/system-backup-d-v2-config-observe.test.py` | `be16d89b46c2aeea8ba963b43bd86339f283f1c7d7afaa1fc5708881819448ff` |

根审核从上述冻结快照独立运行15项 mock，全部PASS，耗时0.030秒；原始测试日志SHA256为 `c32c66994a16cd5eb39959eb391b5b87af06132404dd8d88978e88ef13837e3e`。覆盖完整只读观察、缺表/列、canonical缺列、namespace/owner/Pod UID/container重启拒绝、数据库身份变化、秘密字段注入拒绝、认证缺项不回显、无默认/login-path回退、超时有界。没有执行真实 SQL、kubectl 或网络；根审核已准确删除测试临时树，无构建产物。mock PASS不代表现场配置、TLS、权限、coverage或首次安装授权已满足。

Python 源码小交付已冻结在本机：

```text
C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-v2-config-observe-delivery-765b22dd\system-backup-d-v2-config-observe.py
```

这是已核验源码副本，不是测试二进制；本次仅补本文，冻结Python和测试文件不修改。

## 本地 PowerShell 上传

在本地 Windows PowerShell 执行下面完整命令。目的地使用前序交付已给出的现场目录 `/tmp/clawmanager-native-07407aaca722415ebecf9265106c0ac0/`，上传单个小脚本；SSH用户名沿既有传输方式交互输入，无需向对话提供密钥。该目录若已被用户清理，上传会失败；不要据此自动创建/扫描其他路径。

```powershell
$ErrorActionPreference = 'Stop'
$ObserveFile = 'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-v2-config-observe-delivery-765b22dd\system-backup-d-v2-config-observe.py'
$ObserveExpected = '765b22dddc7d4545e4a4d74f47a983c0fc02d37c13fdf512b75f11f25872c53c'
if ((Get-FileHash -LiteralPath $ObserveFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ObserveExpected) {
  throw '冻结脚本摘要不符；停止上传'
}
$ObserveSshTarget = "$(Read-Host 'SSH用户名')@10.130.14.23"
& "$env:WINDIR\System32\OpenSSH\scp.exe" -P 22 `
  $ObserveFile `
  "${ObserveSshTarget}:/tmp/clawmanager-native-07407aaca722415ebecf9265106c0ac0/"
if ($LASTEXITCODE -ne 0) { throw '上传失败' }
```

## 远端当前目录直接运行

用户在既有远端 Bash 会话执行；不用解压包、不调用 `run-native`、不发任务、不修改配置。使用 `python3 -B`，不生成 pycache，不创建本地输出文件；请回传控制台完整 JSON 及 `observe_exit`。

```bash
(
  set -euo pipefail
  cd /tmp/clawmanager-native-07407aaca722415ebecf9265106c0ac0
  printf '%s  %s\n' \
    '765b22dddc7d4545e4a4d74f47a983c0fc02d37c13fdf512b75f11f25872c53c' \
    'system-backup-d-v2-config-observe.py' | sha256sum --check --strict -
  set +e
  python3 -B ./system-backup-d-v2-config-observe.py
  observe_rc=$?
  set -e
  printf 'observe_exit=%s\n' "$observe_rc"
  exit "$observe_rc"
)
```

退出0表示只读盘点完成，包括正常的missing结果，不表示配置可用或已获bootstrap/coverage授权。退出1表示固定拒绝/读失败，不能据此补造凭据或配置。`authenticated_config`、`tls_verified`、`permissions_verified`、`coverage_verified` 固定为false；`first_installation_decision`明确仍需owner审核。本工具不会根据计数、enabled或hash布尔自动创建配置/任务，也不代替正式准入。

本轮仅文档交付，无远连、SQL、编译或提交；前述现场执行命令由用户自行操作。
