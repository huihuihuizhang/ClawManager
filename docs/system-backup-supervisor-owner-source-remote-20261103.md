# 安装授权与采集来源补充远测：2026-11-03 08:30 后

此包独立于 R8，R8 的两项原窗口诊断保持原样。用户自行连接和执行。此包不更新现场镜像，不执行生产备份、隔离还原或生产权限变更。

运行 11 项检查：安装 owner 的真实隔离 TLS MySQL 生命周期、离线 issuer 两项、材料签名范围两项、独立来源观测三项、Linux 私有文件模式一项、MinIO 有效权限读取组件两项。后两项使用受控 TLS 协议及 fake Kubernetes，并不连接现场 MinIO。独立来源三项中 SQL 为真实隔离 MySQL，Kubernetes/Runtime/Redis/S3 为受控协议；“empty”不代表 Redis 完整空库遍历证明。所有选中根测试必须实际 PASS；跳过、缺失、重复、子测试跳过或非零退出均拒绝。

源快照明确为 `f4d73c79b509bc8d647c685887f729110632bb2b` 加六份逐字节冻结覆盖文件，覆盖标识 `bb7df95a9ec4`。这不是干净提交构建；包内 `SOURCE_REVIEW.json`、`SOURCE_FILES.sha256` 和 ELF SHA256 明确记录来源。A 的测试只应用真实 migration134 的两张 owner 表；已有迁移目录数量175不表示必须存在一个175号迁移文件。真实 Kubernetes enrollment、Vault 安装、其余生产 owner、完整 writer 恢复与同任务发布不由此包证明。

在本地 PowerShell 执行以下完整传输命令。远程目录必须新建；已有目录时停止，不覆盖。

```powershell
$payload = 'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-native-owner-source-bb7df95a9ec4'
$files = @(
  "$payload\clawmanager-native-owner-source-bb7df95a9ec4.tar.gz"
  "$payload\run-owner-source-bb7df95a9ec4.sh"
  "$payload\system-backup-d-kube-mysql-fixture.py"
)
& "$env:WINDIR\System32\OpenSSH\ssh.exe" root@10.130.14.23 'umask 077; mkdir -m 700 -- /tmp/clawmanager-owner-source-bb7df95a9ec4'
if ($LASTEXITCODE -ne 0) { throw '远程目录创建失败，停止传输' }
& "$env:WINDIR\System32\OpenSSH\scp.exe" @files 'root@10.130.14.23:/tmp/clawmanager-owner-source-bb7df95a9ec4/'
if ($LASTEXITCODE -ne 0) { throw '文件传输失败' }
& "$env:WINDIR\System32\OpenSSH\ssh.exe" root@10.130.14.23
```

08:30 后在远程 Bash 执行整个代码块。入口核对原 namespace UID，创建一个自有临时 namespace 中的 MySQL TLS fixture；无需用户手写 SQL 凭据，也不会使用生产数据库。MySQL 镜像固定为现场已有的 digest，native AIO OFF 不代表生产性能。owner 阶段超时5分钟、execution阶段10分钟，另加启动和清理时间；fixture 对内部 runner 的总等待上限18分钟。

```bash
(
  set -euo pipefail
  cd /tmp/clawmanager-owner-source-bb7df95a9ec4
  printf '%s\n' \
    '50dc0067011cced13150e8da1563c771cde27580046a510b42c6bcaa2ec2703a  clawmanager-native-owner-source-bb7df95a9ec4.tar.gz' \
    '7645e9a255b3086e73973144fa1ad65e9e1436c3fa20368ab65127ed163ff437  run-owner-source-bb7df95a9ec4.sh' \
    'fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873  system-backup-d-kube-mysql-fixture.py' \
    | sha256sum --check --strict -
  bash ./run-owner-source-bb7df95a9ec4.sh
)
```

请回传完整终端摘要，包含11项根测试结果、fixture报告、`entry_exit`、`delivery_cleanup_exit`、`residuals` 和日志目录。失败时先保留日志，不重复创建夹具。`fixture/diagnostic/selected-tests.json` 记录每阶段完整结果；原始日志保存在私有目录，不要直接上传其中的凭据文件。

入口在成功或失败后清理同一核验归档、本次自有运行目录与夹具 namespace，保留诊断日志。已有业务、Vault 持久数据不属于清理对象。已结束的本地编译工作目录及缓存删除；本地待测交付归档保留至用户远测结束，再按原 SHA256 核对后删除。

本地审核：带标签编译完成，两个 MinIO 组件根测试通过，真实 MySQL lifecycle 因没有远端隔离凭据显式跳过；两份 Linux/amd64 ELF 已编译。Bash 语法检查通过，判定器8种正反输入校验通过，121个普通归档文件及239条校验记录独立核对通过。此包的11项 Linux 原生检查尚未执行。

本次最终验收仍要求真实页面发起一个非空六域任务、完整采集原请求范围、源业务按原状态恢复、正式产物固定版本独立完整读回、签名目录可查询及同一任务真实成功。不执行隔离还原，灾备资格如实标为未具备。
