# 审核者交付：zhanghui08 隔离 Linux 原窗口诊断

冻结源码 `51181049e97e4ff3946e75b6c1568dfe2e00b1a1`，clean detached worktree；构建前后核对3681文件。Linux amd64、CGO=0 testbinary编译退出0，不是已经运行native测试。46,870,961字节归档不含现场凭据、业务数据或安装材料。独立来源记录见 `evidence/supervisor-linux-native-delivery-20261102.json`。

用户自行传输以下两份交付到远端同一目录：

| 文件 | SHA256 |
| --- | --- |
| `clawmanager-native-51181049.tar.gz` | `266197f53f21f4ac8cdc3c0c079499ab298531005520e706d8e3054bf664d64c` |
| `run-remote-51181049.sh` | `4e95f6328043fc9cbecb2f57fbe72743ddb143d38fb50d2a54f00fc07790ed2c` |

脚本的仓库留档为 `scripts/system-backup-supervisor-native-51181049.sh`，与交付脚本bytes完全相同；若从仓库取脚本，可以保留原文件名，在下方两处使用该文件名。交付归档保存在审核者工作区 `.tmp-native-delivery-51181049/`，不能把缺失归档的git checkout当作已取得testbinary。

用户在放置上述两文件的目录运行完整Bash命令：

```bash
printf '%s  %s\n' '4e95f6328043fc9cbecb2f57fbe72743ddb143d38fb50d2a54f00fc07790ed2c' 'run-remote-51181049.sh' | sha256sum --check --strict - && bash ./run-remote-51181049.sh
```

要求Linux x86_64、Bash、Python3、kubectl及常规GNU工具，不需要宿主机Go/Node/Docker/MySQL/OpenSSL。固定context为用户确认的 `kubernetes-admin@kubernetes`。D工具只创建本轮随机 `sbk-apermit-*` namespace及其Secret/deny-all NetworkPolicy/MySQL Pod，固定现场私库MySQL digest；不修改 `clawmanager-zhanghui08-system`、App/controller、源库、现有卷或权限。它生成自身临时SAN/TLS材料和UUID pin，在独占实例跑原30秒策略的完整synthetic fixture/candidate-cleanup路径。镜像OpenSSL/TLS、节点架构或权限未实际验证时保留失败，不绕过。

运行入口先验证归档摘要及内部全部校验文件；测试输出保存在新建的 `clawmanager-native-logs-51181049.*`，控制台输出 `review_logs`、fixture归属/清理报告及数据库原窗口摘要。正常及错误退出都会按准确owner/UID清理本轮Kubernetes资源，擦除本轮秘密；外层检查精确realpath后删除自己的解压目录，并且只在归档仍匹配原SHA时删除该归档。保留日志。任何未确认清理项都在报告里保留，不能把本地文件删除当作全部资源已消失。

原测试非零退出码优先保留，报告/清理出错不得把7替成1。审核者已用真实归档提取/校验、假诊断程序跑3项本地控制流回归：成功0、测试7加报告9保留7、仅报告9返回9；均移除本轮归档/解压并保留日志。没有执行归档中的ELF、SQL或Kubernetes。脚本语法检查通过。

本轮远测结果尚未取得；无SSH、上传、集群执行或镜像更新。该包不含公共C新SQL本地清理/最终关系验证WIP，不证明acceptance/catalog、真实Runtime物理恢复或页面备份成功。远测后由审核者按控制台报告继续定位；测试结束后删除本地剩余交付归档，不保留测试构建产物。
