# 2026-11-03 08:30 后远测命令

此次只验证原 30 秒窗口和同一 RPC 的控制链差异。不会更新现场应用镜像，不能作为页面完整备份验收。完整备份发布、源业务恢复、独立读回、目录和真实成功仍须同一任务另行验收；本次不执行隔离还原，灾备资格未具备。

包的 Linux 源快照为 `5ae6c853c71d6ce01480c0f5960566bb311d248b`。安装 owner 首批和 migration134 不在该包内。Go 测试总超时15分钟，加上夹具启动、清理时间；原授权窗口保持30秒。仅创建自有隔离 MySQL TLS 夹具，使用 native AIO OFF，不能等同生产性能。

## 1. 本地 PowerShell 传输

用户自行连接并执行。以下命令创建新目录；目录已存在时停止，先核对已有内容，不覆盖重用。

```powershell
$payload = 'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-native-delivery-5ae6c853-r7'
$files = @(
  "$payload\clawmanager-native-5ae6c853.tar.gz"
  "$payload\run-native-5ae6c853.sh"
  "$payload\system-backup-d-kube-mysql-fixture.py"
)
& "$env:WINDIR\System32\OpenSSH\ssh.exe" root@10.130.14.23 'umask 077; mkdir -m 700 -- /tmp/clawmanager-native-5ae6c853-r7'
if ($LASTEXITCODE -ne 0) { throw '远程目录创建失败，停止传输' }
& "$env:WINDIR\System32\OpenSSH\scp.exe" @files 'root@10.130.14.23:/tmp/clawmanager-native-5ae6c853-r7/'
if ($LASTEXITCODE -ne 0) { throw '文件传输失败' }
& "$env:WINDIR\System32\OpenSSH\ssh.exe" root@10.130.14.23
```

## 2. 远程 Bash 执行

明早08:30之后，在远程会话执行整个代码块。入口核验原 namespace UID；身份变化时拒绝创建夹具。成功或失败均记录清理结果，删除同一已核验归档及本次自有运行目录，保留诊断日志。

```bash
(
  set -euo pipefail
  cd /tmp/clawmanager-native-5ae6c853-r7
  printf '%s\n' \
    '79f9c14367cf0add17cce5258bc2f86ee8d8ccd77c62509b26d6626bf161c63b  clawmanager-native-5ae6c853.tar.gz' \
    '5f6aaddb05d56bba170757d01ad0edf66be87d2c847f1603ecb6cb26050c135e  run-native-5ae6c853.sh' \
    'fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873  system-backup-d-kube-mysql-fixture.py' \
    | sha256sum --check --strict -
  bash ./run-native-5ae6c853.sh
)
```

请回传完整终端摘要，包含两项测试的 PASS/FAIL、same-RPC 原版/候选指标、`entry_exit`、`delivery_cleanup_exit`、`residuals` 和日志目录。任一项失败、缺失或跳过均不算通过。

## 本地审查状态

19项相关组件根测试通过、无跳过；Linux二进制已编译，原生测试尚未执行。交付归档125个普通文件、246条校验和、ELF和源提交标识已独立核对。源快照是测试候选，尚未批准生产部署。

已结束的本地构建中间目录按所有权核对后清理。上述待测交付包保留至用户远测结束，随后删除本地构建归档。
