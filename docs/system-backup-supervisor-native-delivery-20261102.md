# 审核者交付：zhanghui08 隔离 Linux 原窗口诊断

首轮先以startup-only探针定位了 InnoDB `io_setup()` EAGAIN；AIO OFF修复的用户成功结果见下一段。原生执行入口见末节，使用单独固定的875e3960探针，不再调用归档内旧探针。前半节保留首轮交付来源和用户已执行命令，不能将其当作最新启动方案。

用户现已回传修复探针`startup-verified`：8.4.8、TLSv1.3/TLS_AES_128_GCM_SHA256、实际AIO OFF、原退出/诊断/清理均0且residuals空，native_started=false。记录见`evidence/supervisor-kube-startup-success-user-report-20261102.json`。现在可按末节给出的固定三文件命令进入原生诊断；此成功仅解决隔离数据库启动，未证明原30秒窗口、C正式发布或页面成功。

冻结源码 `51181049e97e4ff3946e75b6c1568dfe2e00b1a1`，clean detached worktree；构建前后核对3681文件。Linux amd64、CGO=0 testbinary编译退出0，不是已经运行native测试。46,870,961字节归档不含现场凭据、业务数据或安装材料。独立来源记录见 `evidence/supervisor-linux-native-delivery-20261102.json`。

用户自行传输以下两份交付到远端同一目录：

| 文件 | SHA256 |
| --- | --- |
| `clawmanager-native-51181049.tar.gz` | `266197f53f21f4ac8cdc3c0c079499ab298531005520e706d8e3054bf664d64c` |
| `run-remote-51181049.sh` | `4e95f6328043fc9cbecb2f57fbe72743ddb143d38fb50d2a54f00fc07790ed2c` |

脚本的仓库留档为 `scripts/system-backup-supervisor-native-51181049.sh`，与交付脚本bytes完全相同；若从仓库取脚本，可以保留原文件名，在下方两处使用该文件名。交付归档保存在审核者工作区 `.tmp-native-delivery-51181049/`，不能把缺失归档的git checkout当作已取得testbinary。

首轮用户在放置上述两文件的目录执行的历史Bash命令：

```bash
printf '%s  %s\n' '4e95f6328043fc9cbecb2f57fbe72743ddb143d38fb50d2a54f00fc07790ed2c' 'run-remote-51181049.sh' | sha256sum --check --strict - && bash ./run-remote-51181049.sh
```

要求Linux x86_64、Bash、Python3、kubectl及常规GNU工具，不需要宿主机Go/Node/Docker/MySQL/OpenSSL。固定context为用户确认的 `kubernetes-admin@kubernetes`。D工具只创建本轮随机 `sbk-apermit-*` namespace及其Secret/deny-all NetworkPolicy/MySQL Pod，固定现场私库MySQL digest；不修改 `clawmanager-zhanghui08-system`、App/controller、源库、现有卷或权限。它生成自身临时SAN/TLS材料和UUID pin，在独占实例跑原30秒策略的完整synthetic fixture/candidate-cleanup路径。镜像OpenSSL/TLS、节点架构或权限未实际验证时保留失败，不绕过。

运行入口先验证归档摘要及内部全部校验文件；测试输出保存在新建的 `clawmanager-native-logs-51181049.*`，控制台输出 `review_logs`、fixture归属/清理报告及数据库原窗口摘要。正常及错误退出都会按准确owner/UID清理本轮Kubernetes资源，擦除本轮秘密；外层检查精确realpath后删除自己的解压目录，并且只在归档仍匹配原SHA时删除该归档。保留日志。任何未确认清理项都在报告里保留，不能把本地文件删除当作全部资源已消失。

原测试非零退出码优先保留，报告/清理出错不得把7替成1。审核者已用真实归档提取/校验、假诊断程序跑3项本地控制流回归：成功0、测试7加报告9保留7、仅报告9返回9；均移除本轮归档/解压并保留日志。没有执行归档中的ELF、SQL或Kubernetes。脚本语法检查通过。

首轮用户远测和后续启动探针均在MySQL启动阶段失败，尚未实际执行归档ELF；准确报告见 `evidence/supervisor-kube-startup-user-report-20261102.json` 和 `evidence/supervisor-kube-startup-aio-user-report-20261102.json`。审核者未SSH、上传、连接集群或更新镜像。该包不含公共C新SQL本地清理/最终关系验证/acceptance WIP，不证明acceptance/catalog、真实Runtime物理恢复或页面备份成功。原生测试完成后删除本地剩余交付归档，不保留测试构建产物。

## startup-only 成功后的原生入口

仅在用户回传的修复探针确认 `startup-verified`、实际AIO为OFF、真实TLS1.3会话及清理完成后，执行本节。使用同一个已核对来源的51181049 Linux二进制；独立fixture工具固定为875e3960、SHA256 `fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873`。原archive不重打包、不重编译，因此二进制和3681文件来源receipt保持不变。该隔离数据库关闭原生AIO，结果不作生产等价性能基准。

新入口 `scripts/system-backup-supervisor-native-aio-875e3960.sh` 摘要为 `d88d94bc18cb92d3a7bc8e54bf63ca3e7cea937052c3baed4b86d26d0f635c8b`。它拒绝错误的外部探针，复制到本轮自有临时目录再次核对摘要后执行；保存单独 `delivery-toolchain.json` 记录二进制和fixture的不同来源，并输出清理前的启动诊断。原退出码优先级和准确路径/原摘要限定的归档清理规则不变。

本地 PowerShell 上传三份已审核文件：

```powershell
$SshTarget = "$(Read-Host 'SSH用户名')@10.130.14.23"
& "$env:WINDIR\System32\OpenSSH\scp.exe" -P 22 `
  'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-native-delivery-51181049\clawmanager-native-51181049.tar.gz' `
  'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-startup-delivery-fb8218f1\system-backup-d-kube-mysql-fixture.py' `
  'C:\Users\zhanghui08\Desktop\clawmanager\ClawManager\.tmp-startup-delivery-fb8218f1\run-native-aio-875e3960.sh' `
  "${SshTarget}:/tmp/clawmanager-native-07407aaca722415ebecf9265106c0ac0/"
if ($LASTEXITCODE -ne 0) { throw '上传失败' }
```

用户在远程Bash执行：

```bash
(
  set -euo pipefail
  cd /tmp/clawmanager-native-07407aaca722415ebecf9265106c0ac0
  printf '%s  %s\n' \
    'd88d94bc18cb92d3a7bc8e54bf63ca3e7cea937052c3baed4b86d26d0f635c8b' \
    'run-native-aio-875e3960.sh' | sha256sum --check --strict -
  bash ./run-native-aio-875e3960.sh
)
```

执行最长为原native15分钟加启动/清理时间；输出目录保持独立。入口自动删除本轮解压副本和仍匹配原摘要的远程archive，只保留非秘密日志/工具源码，不留下测试二进制。archive校验或独立探针预检失败发生在创建资源之前，尚未消费的archive保留以供纠正交付，不删除未知替换文件。

审核者已在Windows独立临时树运行Bash语法和5项控制流回归：成功0、测试7+summary9保留7、summary9返回9、仅归档删除失败返回1、错误探针在创建work前拒绝。使用实际归档提取及全部内部校验，fake fixture代替真实Python/ELF/kubectl；没有执行SQL或连接集群。原始日志SHA256为 `0aa3a03477c327eafe3da5b3a03fd94375d7afa0f3fd294c51dc99c127ebd208`；所有本轮临时归档副本/解压树已删除。该控制流回归不证明原生或页面成功。
