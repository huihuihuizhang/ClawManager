# R9 原窗口远测命令（2026-11-03）

> R9 已在现场执行结束：两项 FAIL，分别在原 runtime guard 与 quiesce 阶段；entry1／cleanup0／无残留，尚无 collector 性能结果。已结束测试的本地交付包已删除。用户优先接线并进行首次真实页面备份试跑，性能对比后置。下文仅保留历史命令，不要再次执行。

源码固定为 `31ffbb36576c3119e21801421be07524db9eea2b`，同时修复两处历史固定控制表数量断言。最终同一 Linux amd64 程序已通过2项／13子例纯回归，零失败／跳过。真实 MySQL 原窗口及同 RPC 两项仍待本次远测，不能作为页面完整备份验收，也不会更新现场应用镜像。R8 不要重跑。

测试原授权窗口仍为30秒；整个测试程序超时15分钟，另加隔离夹具启动和清理。限定原 context／namespace UID，使用自有一次性 SAN/TLS MySQL 夹具（native AIO OFF）。成功或失败均清理自有资源和同一已核验归档，保留文本诊断。

## 本地 PowerShell 传输

用户自行连接。以下命令拒绝覆盖已存在的远程目录。

```powershell
$ErrorActionPreference = 'Stop'
$payload = 'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-native-delivery-31ffbb36-r9'
$expected = @{
  'clawmanager-native-31ffbb36.tar.gz' = '3475af54bc2126a19192a18a401897a6259e8f6ad91446035128518abe30e5f4'
  'run-native-31ffbb36.sh' = 'f1d3d6e3a166a8c297a55c0bfb3ece87513677c01ac568079294057cfd4f8fbc'
  'system-backup-d-kube-mysql-fixture.py' = 'fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873'
}
$files = @()
foreach ($name in $expected.Keys) {
  $file = Join-Path $payload $name
  if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected[$name]) { throw "交付校验失败：$name" }
  $files += $file
}
$sshPath = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
$scpPath = Join-Path $env:WINDIR 'System32\OpenSSH\scp.exe'
& $sshPath root@10.130.14.23 'umask 077; mkdir -m 700 -- /tmp/clawmanager-native-31ffbb36-r9'
if ($LASTEXITCODE -ne 0) { throw '远程目录创建失败，停止传输' }
& $scpPath @files 'root@10.130.14.23:/tmp/clawmanager-native-31ffbb36-r9/'
if ($LASTEXITCODE -ne 0) { throw '文件传输失败' }
```

## 远端 Bash 执行

在你连接的 `root@k8s-master` 远端会话完整执行：

```bash
(
  set -euo pipefail
  cd /tmp/clawmanager-native-31ffbb36-r9
  printf '%s\n' \
    '3475af54bc2126a19192a18a401897a6259e8f6ad91446035128518abe30e5f4  clawmanager-native-31ffbb36.tar.gz' \
    'f1d3d6e3a166a8c297a55c0bfb3ece87513677c01ac568079294057cfd4f8fbc  run-native-31ffbb36.sh' \
    'fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873  system-backup-d-kube-mysql-fixture.py' \
    | sha256sum --check --strict -
  bash ./run-native-31ffbb36.sh
)
```

回传入口输出中的 `native_log_sha256`、两项测试结果、原窗口计时及 `entry_exit`／`delivery_cleanup_exit`。新入口会直接显示已知 census／proposal 失败摘要。若还失败，保留 `review_logs` 指向的文本日志；不要重复执行已删除归档的同一目录。

尚未执行隔离还原；灾备资格未具备。页面成功、完整非空采集、源业务实际恢复、正式发布、独立读回和目录仍须同一真实任务单独验收。测试结束后本地交付包也按用户要求删除。
