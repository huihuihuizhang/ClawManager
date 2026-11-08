# 备份存储冻结探针

当前 Longhorn 停写候选使用普通 ext4 只读重配置。进程即使暂停，仍可能保留可写文件描述符或共享映射，导致重配置返回 `EBUSY`。此探针检查替代方案所需的一个前提：保留这些引用时，`FIFREEZE` 是否阻止写入，冻结期间 `syncfs` 与系统 `sync` 是否返回，`FITHAW` 后写入及读回是否恢复。

脚本只创建自己的 128 MiB 镜像、loop 设备和私有挂载命名空间，不接受目标卷参数。它不会选择业务卷，也不安装依赖。系统 `sync` 会涉及宿主机的全部文件系统，因此应在独立验证主机执行。需要 root、Linux 6.8.x x86_64，以及已安装的 Python 3、mkfs.ext4、losetup、mount、umount。

将仓库中的 `scripts/system-backup-ext4-freeze-canary.py` 复制到验证主机，在其所在目录用 Bash 执行：

```bash
set -o pipefail
sudo python3 -I -B ./system-backup-ext4-freeze-canary.py 2>&1 | tee ext4-freeze-canary.log
rc=${PIPESTATUS[0]}
printf 'canary_exit=%s\n' "$rc"
test "$rc" -eq 0
```

只有退出码为 0，且日志同时包含下列结果，才说明这个内核前提通过：

- `freeze_native_result` 的 `writers_blocked_and_resumed`、`content_readback`、`syncfs_completed_while_frozen`、`systemwide_sync_completed_while_frozen`、`snapshot_deadlock_canary_passed` 均为 `true`。
- `native_result` 的三个结果均为 `true`。
- `cleanup` 的 `complete` 和 `test_completed` 均为 `true`。

`watchdog_thaw`、`actor_cleanup_unconfirmed` 或失败结果不能作为通过证据。独立 watchdog 在超时或父进程退出时尝试解除本探针自己的冻结；正常结束会核对 loop 的 backing file，卸载并删除自建镜像和临时目录。清理失败会保留准确目录及 loop 信息供核对，不强制卸载或递归删除。

此结果不证明 Longhorn 实际 snapshot RPC、RWX 客户端排空、双卷共同停写、任务中断恢复或页面备份已成功。后续仍需在同一正式任务上验证这些环节，以及发布、独立读回和目录登记。当前生产停写实现尚未替换为冻结方案。
