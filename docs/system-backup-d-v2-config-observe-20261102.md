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
| `scripts/system-backup-d-v2-config-observe.py` | `a7a5fa84887842d285e4d397de25db6cd6778d799b9c36782620b2f08e63d660` |
| `scripts/system-backup-d-v2-config-observe.test.py` | `6a1c8105a13e5f33c02207a5f05e5a51a1ab46f8a77712fbcccc5325d865ebbb` |

本次修正 typed list 兼容性：旧版 `765b22dd…` 对 list item 强制要求 kind，现场合法的 ReplicaSetList/PodList item 省略 TypeMeta 时会错误拒绝。新版严格检查固定资源路径、父列表 kind/API version 和每项 namespace；item 省略 kind/apiVersion 可用于候选发现，显式错误值仍拒绝；选中后按名称单独 GET ReplicaSet/Pod，严格检查完整 TypeMeta、UID、owner 链和容器身份。没有放宽 namespace UID、owner、Pod UID 或 containerID 检查。拒绝 reason 细化为固定校验点，例如 `replicasetlist_kind_mismatch`、`pod_list_item_api_version_mismatch`、`pod_uid_changed`，不含 raw object/spec/env。

新版已静态 AST 解析通过，新增8项 mock（含子用例），交根审核统一运行；D 未执行测试、真实 SQL、kubectl、网络或构建。旧版根审核15项 mock PASS（0.030秒，日志SHA256 `c32c66994a16cd5eb39959eb391b5b87af06132404dd8d88978e88ef13837e3e`）仅是旧快照历史记录，不是新版验证结果。mock PASS不代表现场配置、TLS、权限、coverage或首次安装授权已满足。

Python 源码小交付已冻结在本机：

```text
C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-v2-config-observe-delivery-a7a5fa84\system-backup-d-v2-config-observe.py
```

这是已核验源码副本，不是测试二进制；旧版源码副本不覆盖，新上传应使用本次摘要。

## 本地 PowerShell 上传

在本地 Windows PowerShell 执行下面完整命令。目的地使用前序交付已给出的现场目录 `/tmp/clawmanager-native-07407aaca722415ebecf9265106c0ac0/`，上传单个小脚本；SSH用户名沿既有传输方式交互输入，无需向对话提供密钥。该目录若已被用户清理，上传会失败；不要据此自动创建/扫描其他路径。

```powershell
$ErrorActionPreference = 'Stop'
$ObserveFile = 'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-v2-config-observe-delivery-a7a5fa84\system-backup-d-v2-config-observe.py'
$ObserveExpected = 'a7a5fa84887842d285e4d397de25db6cd6778d799b9c36782620b2f08e63d660'
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
    'a7a5fa84887842d285e4d397de25db6cd6778d799b9c36782620b2f08e63d660' \
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

本轮交付兼容性修复、mock 和本文，无远连、SQL、编译或提交；前述现场执行命令由用户自行操作。

根审核随后从上述新摘要的独立源码快照运行23项mock，全部通过（0.098s），日志SHA256为`176ec6ee293fbe50318f5f3594caae5d8a62f6d79c62632028a07d5390487a0c`；临时树已删除，交付副本与新Python摘要相同。测试没有连接集群或执行SQL，新现场盘点仍待用户回传。原`workload_identity_changed`没有留下具体API响应，不能认定现场身份确实变化，也不能认定缺少配置；本次修复了代码中对合法typed list形状的已确认兼容缺陷。该形状及typed collection约定见[Kubernetes官方API Concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/#collections)。
