# 2026-11-03 08:30 后远测命令

开始前先执行[生产 MySQL 公开证书观察](system-backup-supervisor-mysql-public-cert-20261103.md)中的完整 Bash 代码块，回传证书 SAN、指纹和 Pod 身份摘要。此项无需数据库密码，默认路径观察与后面的 R8 隔离测试独立；R8 交付包及其四项校验和保持原值。

当前交付为 R8（723f51bc），与 R8 交付时编译的完整 Linux 服务同一源码；它固定在下文列出的提交，不代表后续 `backup` 新提交的现场验收。旧 R7（5ae6c853）已撤回，请勿再传输或执行。另增加只读 MinIO 前置观察，收集实际版本、身份和引用元数据；它不读取 Secret 值，也不证明五组操作权限。

此次只验证原 30 秒窗口和同一 RPC 的控制链差异。不会更新现场应用镜像，不能作为页面完整备份验收。完整备份发布、源业务恢复、独立读回、目录和真实成功仍须同一任务另行验收；本次不执行隔离还原，灾备资格未具备。

包的 Linux 源快照为 `723f51bc9834d4f6f417828968576903de3f29dd`。该源码包含安装 owner 首批及 migration134，但所选两项测试不验证 owner 安装／enrollment。Go 测试总超时15分钟，加上夹具启动、清理时间；原授权窗口保持30秒。仅创建自有隔离 MySQL TLS 夹具，使用 native AIO OFF，不能等同生产性能。

## 1. 本地 PowerShell 传输

用户自行连接并执行。以下命令创建新目录；目录已存在时停止，先核对已有内容，不覆盖重用。

```powershell
$payload = 'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-native-delivery-723f51bc-r8'
$files = @(
  "$payload\clawmanager-native-723f51bc.tar.gz"
  "$payload\run-native-723f51bc.sh"
  "$payload\system-backup-d-kube-mysql-fixture.py"
  "$payload\system-backup-c-minio-prerequisites.py"
)
& "$env:WINDIR\System32\OpenSSH\ssh.exe" root@10.130.14.23 'umask 077; mkdir -m 700 -- /tmp/clawmanager-native-723f51bc-r8'
if ($LASTEXITCODE -ne 0) { throw '远程目录创建失败，停止传输' }
& "$env:WINDIR\System32\OpenSSH\scp.exe" @files 'root@10.130.14.23:/tmp/clawmanager-native-723f51bc-r8/'
if ($LASTEXITCODE -ne 0) { throw '文件传输失败' }
& "$env:WINDIR\System32\OpenSSH\ssh.exe" root@10.130.14.23
```

## 2. 远程 Bash 执行

2026-11-03 08:30之后，在远程会话执行整个代码块。入口核验原 namespace UID；身份变化时拒绝创建夹具。成功或失败均记录清理结果，删除同一已核验归档及本次自有运行目录，保留诊断日志。

```bash
(
  set -euo pipefail
  cd /tmp/clawmanager-native-723f51bc-r8
  printf '%s\n' \
    'b8b356e5f1459d021d00476818ff60ff02d2e45f87f3359f218c13f4a31d95ce  clawmanager-native-723f51bc.tar.gz' \
    '2b93c7d2de339da76bbb778029a9da34f90b9c7834e3885d8f8a9ab7fc4c341a  run-native-723f51bc.sh' \
    'fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873  system-backup-d-kube-mysql-fixture.py' \
    'bbd58fc4e510fcf018cf4ddfa0cdab53a88e8d86f94fdb6ae5d0c362b6e651f0  system-backup-c-minio-prerequisites.py' \
    | sha256sum --check --strict -
  if python3 -I -B ./system-backup-c-minio-prerequisites.py; then
    printf 'minio_prerequisites_exit=0\n'
  else
    preflight_rc=$?
    printf 'minio_prerequisites_exit=%s\n' "$preflight_rc"
  fi
  bash ./run-native-723f51bc.sh
)
```

MinIO 前置观察与 SQL 夹具诊断相互独立；版本未知或前置拒绝时保留退出码，仍可运行后面的独立 SQL 夹具。请回传 MinIO JSON、前置退出码及完整终端摘要，包含两项测试的 PASS/FAIL、same-RPC 原版/候选指标、`entry_exit`、`delivery_cleanup_exit`、`residuals` 和日志目录。任一项失败、缺失或跳过均不算通过。

## 本地审查状态

最终精确源码的68项组件根测试通过、无跳过；完整 Linux 服务与本原生测试二进制均已编译，原生测试尚未执行。MinIO 前置脚本12项离线测试通过，包含真实 Go 模板的敏感字段投影检查。交付归档125个普通文件、246条校验和、ELF和源提交标识已独立核对。源快照是测试候选，尚未批准生产部署。

已结束的本地构建中间目录按所有权核对后清理。上述待测交付包保留至用户远测结束，随后删除本地构建归档。
