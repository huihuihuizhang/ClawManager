# 一次性存储验证 R3

先在自建 ext4 loop 卷上证明探针能捕获另一个进程提前解冻，再在本轮新建的 Longhorn RWO/RWX 卷上运行一次。`k8s-master` 和 `node1` 已通过校准。上一轮降级的测试卷已清理，`node1` 磁盘恢复可调度，冻结快照待新一轮实测。R3 替换 R2 第 3.1 节要求使用现成追踪的部分，沿用 R2 的隔离、身份核对、10 秒快照等待、约 20 秒租约、独立读回和失败恢复。[R2 完整资源和恢复步骤](system-backup-storage-remote-acceptance-20261108.md)

## 1. 校准提前解冻探针

在 `k8s-master` 或 `node1` 的宿主机以 root 执行。使用同一已审核提交里的两个 Python 文件，放在同一目录。这里的挂载与写入全部由 canary 自建。探针在一个独立 tracefs 实例中短暂开启四个内核探点，覆盖 `freeze_super`、`thaw_super_locked` 的进入与返回。需要当前 Linux 6.8 内核可用的 tracefs、kprobe 和 BTF，脚本遇到拒绝直接退出。探点是宿主机级挂钩，实例内只采这两类调用，回执只输出目标设备的记录。选择适合执行原 canary 的节点时仍要考虑其中的全局 `sync`。

```bash
set -o pipefail
python3 -I -B scripts/system-backup-ext4-freeze-canary.py --trace-freeze \
  | tee trace-calibration.jsonl
```

校准通过需退出 0，同时出现 `calibration_foreign_thaw`、`freeze_trace_canary` 的 `FOREIGN_THAW_OBSERVED` 和 `cleanup.complete=true, test_completed=true`。独立子进程的成功解冻必须发生在父进程的冻结成功之后、父进程的预定解冻进入之前，且 TID 和设备完全匹配。探点丢失、缓冲区丢失、返回缺项、权限拒绝均判 `UNVERIFIED`。如果原生写阻塞、同步或恢复断言得到明确反例，记录实际失败项并停止。该校准仅验证探针和本节点自建卷。

## 2. 准备专用 Longhorn 卷

已有两台节点同次启动的校准回执时，可在 `k8s-master` 运行 `system-backup-storage-probe-prepare.sh CALIBRATION_DIR PRIOR_RUN_EVIDENCE_DIR` 合并本节的建卷及 keeper 检查。第一个目录保存 `k8s-master` 的 `trace-calibration.jsonl`，第二个保存此前转回的 `node1-calibration.jsonl`。脚本复核容量及身份，输出 `BOTH_HEALTHY_KEEPER_OK` 和本轮 `out`，供后续挂载身份核对及快照使用。

在已能使用 `kubernetes-admin@kubernetes` 的 Bash 终端设置本轮参数。以下沿用部署记录中的 `longhorn`、`longhorn-rwx` 及先前隔离 RWX 探针的镜像摘要。现场 StorageClass 校验失败即停止。探针 Pod 只使用该镜像里的 shell 工具，由清单覆盖启动命令。`clawmanager-sbk-validation-system` 是应用部署记录里的 namespace。本轮资源放在独占的 `sbk-storage-probe-*`。

```bash
set -euo pipefail
umask 077
export CTX=kubernetes-admin@kubernetes LH_NS=longhorn-system
export SNAP_CLASS=sbk-validation-longhorn-local SC_RWO=longhorn SC_RWX=longhorn-rwx
export TOOL_IMAGE=10.130.14.23:5000/mysql@sha256:5ea882b1859d3a61814e527215563d809a9f2bf70ffa24c9280f2ff6798f1977
k() { kubectl --context "$CTX" "$@"; }
k get storageclass "$SC_RWO" "$SC_RWX" -o json | jq -e '
  (.items|length==2) and all(.items[];
    .provisioner=="driver.longhorn.io" and .reclaimPolicy=="Delete" and
    .volumeBindingMode=="Immediate" and
    (.parameters.dataEngine // "v1")=="v1" and
    (.parameters.fsType // "ext4")=="ext4" and
    (.parameters.encrypted // "false")=="false" and
    (.parameters.fromBackup // "")=="" and (.parameters.backingImage // "")=="")'
export RUN_ID=$(python3 -I -B -c 'import uuid; print(uuid.uuid4().hex)')
export NS=sbk-storage-probe-$RUN_ID NONCE=$RUN_ID
export OUT=$PWD/$NS
mkdir -m 700 -- "$OUT"
```

依次执行 R2 第 0.1 节控制面预检和第 2 节的 RWX 源卷部分，取得 `$OUT/share-pod.json` 的 `.node`。若实际节点为 `node1`，先在那台节点重新校准。然后按 R2 第 2 节剩余步骤在该节点准备 RWO 源卷和 keeper，再完成第 3 节起始两段的挂载身份核对。第 0.1 节的取证能力由本轮校准判定。只接受本轮同一 Node 上的两个 ext4 后端挂载。任何身份不一致，按 R2 清理并停止。

删除原 RWO writer 或启动冻结前，核对两份测试卷都 `attached`、`healthy` 且 `Scheduled=True`。Pod Ready 只用于检查 Pod 状态。上一轮两卷因 `ReplicaSchedulingFailure` 降级并清理，实际冻结快照记 `NOT_RUN`。`node1` 恢复可调度后，重跑保持原副本配置和健康门槛。

用 R2 定义的 `node` 函数访问已核对的实际节点。以下复制三个脚本到本轮新建的 root:0700 节点目录并校验 SHA256。若管理终端就在已核对的实际节点上，可定义 `node() { bash -c "$1"; }`，把 `scp` 替换成将同样四个文件复制到 `"$REMOTE_DIR/"` 的本地 `cp`。

```bash
REMOTE_DIR=/var/tmp/sbk-storage-probe-$RUN_ID
node "umask 077; mkdir -m 700 -- '$REMOTE_DIR'"
(cd scripts && sha256sum system-backup-ext4-freeze-canary.py \
  system-backup-ext4-freeze-trace.py system-backup-storage-probe-lease.sh) > "$OUT/payload.sha256"
scp -o BatchMode=yes -o StrictHostKeyChecking=yes -i "$SSH_KEY" \
  scripts/system-backup-ext4-freeze-canary.py scripts/system-backup-ext4-freeze-trace.py \
  scripts/system-backup-storage-probe-lease.sh "$OUT/payload.sha256" "$NODE_SSH:$REMOTE_DIR/"
node "cd -- '$REMOTE_DIR' && sha256sum --check payload.sha256"
```

如果已经在该节点同一次 boot 完成第 1 节且核对了相同脚本，可把那份完整回执放到本轮节点目录的 `trace-calibration.jsonl`。否则用下面的命令校准。退出非零就停止。

```bash
node "cd -- '$REMOTE_DIR' && python3 -I -B ./system-backup-ext4-freeze-canary.py \
  --trace-freeze >trace-calibration.jsonl"
node "cat '$REMOTE_DIR/trace-calibration.jsonl'" > "$OUT/trace-calibration.jsonl"
```

记录本轮两卷的活跃 engine 身份，供解冻后对照。此命令只保存所选 engine 的字段。

```bash
engine_identity() {
  k -n "$LH_NS" get engines.longhorn.io -o json | jq -e --arg volume "$1" '
    [.items[] | select(.spec.volumeName==$volume and .spec.active==true and .status.currentState=="running")
      | {name:.metadata.name, uid:.metadata.uid, node:.spec.nodeID, manager:.status.instanceManagerName,
         image:.status.currentImage, ip:.status.ip, port:.status.port}]
    | if length==1 and (.[0].manager|type=="string" and length>0) then .[0] else error("engine identity unconfirmed") end'
}
engine_identity "$RWO_HANDLE" > "$OUT/rwo-engine-before.json"
engine_identity "$RWX_HANDLE" > "$OUT/rwx-engine-before.json"
```

## 3. 在共同冻结窗口尝试一次快照

本轮实际节点为 `node1` 时，可在 `k8s-master` 运行 `system-backup-storage-probe-cut.sh /absolute/path/to/run.env`，代替本节手工切换终端的命令。脚本用一次 SSH 认证复用连接，核对实际 ext4 挂载后启动两个租约，尝试一批快照并发送释放。两份解除均确认时，它会验证原卷写读，并把挂载、trace、快照及后端记录写入本轮 `cut-attempt/`。`CUT_EVIDENCE_READY` 只表示证据已收集，仍按第 4 节评定后端完成、克隆及清理。回执 `THAW_UNCONFIRMED_OR_ABNORMAL` 时保留原卷和 keeper，按 R2 恢复。节点本轮额外留下的 `locate.py` 和 `rwo-mount.json`、`rwx-mount.json` 在确认恢复后随本轮明确文件清理。

先在节点终端启动采集器，再按 R2 第 3.2 节启动两个租约。`DIR`、`RWO_HANDLE`、`RWX_HANDLE`、`MOUNT_RWO`、`MOUNT_RWX`、`SEED_SHA` 均为本轮已核对值。采集器最多运行 90 秒，租约仍按原预算解冻。

```bash
cd -- "$DIR"
sha256sum --check payload.sha256
nohup python3 -I -B ./system-backup-ext4-freeze-trace.py \
  --longhorn-probe "$DIR" "$RWO_HANDLE" "$RWX_HANDLE" >trace.jsonl 2>&1 </dev/null &
echo "$!" > trace.pid
```

管理终端先准备 R2 第 3.2 节的 `$OUT/cuts.json`，暂不执行其中的 `k create`、`k wait` 或独立 release 命令。确认采集器进程与本轮 `trace.pid` 一致且仍在运行，`trace.jsonl` 有 `TRACE_ARMED`，`trace/armed` 存在。先安装以下退出保护，再启动两个租约。两卷 `held` 都确认后，立刻执行后面的快照命令。

```bash
mark() { node "set -C; python3 -I -B -c 'import time; print(time.monotonic_ns())' > '$REMOTE_DIR/trace/$1'"; }
release_both() {
  node "d='$REMOTE_DIR'; if test ! -e \"\$d/trace/release\"; then
    (set -C; python3 -I -B -c 'import time; print(time.monotonic_ns())' > \"\$d/trace/release\") || :
  fi
  for name in rwo rwx; do
    if test -d \"\$d/\$name\"; then touch -- \"\$d/\$name/release\" || exit 4; fi
  done"
}
trap release_both EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
```

以下只执行一次。`start` 是提交请求前的节点单调时间，`ready` 是同轮两份新对象均读到 Ready 后的节点单调时间。任一步失败都马上写 release。另一个节点终端可在 SSH 失联时按 R2 使用本轮原目录释放。

```bash
if mark start && k --request-timeout=4s create -f "$OUT/cuts.json" &&
    k -n "$NS" --request-timeout=10s wait --for=jsonpath='{.status.readyToUse}'=true \
      volumesnapshot/cut-rwo volumesnapshot/cut-rwx --timeout=10s && mark ready; then
  printf '%s\n' READY_OBSERVED > "$OUT/cut-result.txt"
else
  printf '%s\n' CUT_UNCONFIRMED > "$OUT/cut-result.txt"
fi
release_both
trap - EXIT INT TERM
```

确认两个租约已退出，保留 exit-code、PID、`thaw-acknowledged` 和任何 `unknown`、`timed-out`。立即在节点给采集器发结束标记，等待其退出并保存输出。取证异常仍先完成实际解冻和恢复。

```bash
node "touch -- '$REMOTE_DIR/trace/stop'"
node "cat '$REMOTE_DIR/trace.jsonl'" > "$OUT/trace.jsonl"
```

上述 `cat` 在采集器退出后执行。若只有 `TRACE_ARMED`，仍没有最终结果。`WINDOW_OBSERVED` 表示同 boot、同设备及 diskseq 的四条成功调用与两个租约 PID 对上，且 `[start, ready]` 被共同冻结完整覆盖。`FAIL_EARLY_THAW` 表示实际成功解冻早于本轮 release。探针未给出确定结论时记录 `UNVERIFIED`，并保留已有的明确失败证据。

## 4. 取得结论并清理

上一节脚本成功保存 `cut-attempt/` 后，可在 `k8s-master` 运行 `system-backup-storage-probe-readback.sh /absolute/path/to/run.env`。它核对窗口、后端日志、绑定及引擎元数据，然后逐个创建克隆并只读验证 seed 一致、恢复后的标记缺失。只在两份读回均通过后按本轮 UID 清理并核对集群及节点回收。最终 `STORAGE_PROBE_PASS` 只用于本轮专用存储验收。

解冻后执行 R2 第 3.3 节的 Snapshot、Content、Longhorn Snapshot 只读取证。对照解冻前后的 engine 身份，并从已选 instance-manager 读取仅匹配本卷及本轮快照名的开始和完成记录。下面给出容器日志入口。日志源没有引擎操作记录、输出被轮换或无法关联时，按 `UNVERIFIED` 处理。取证命令失败后仍须完成原卷恢复和本轮清理。

```bash
for v in rwo rwx; do
  if [[ $v == rwo ]]; then handle=$RWO_HANDLE; else handle=$RWX_HANDLE; fi
  engine_identity "$handle" > "$OUT/$v-engine-after.json"
  cmp -- "$OUT/$v-engine-before.json" "$OUT/$v-engine-after.json"
  im=$(jq -er '.manager' "$OUT/$v-engine-before.json")
  backend=$(jq -er '.status.snapshotHandle | split("/")[-1] | select(length>0)' "$OUT/$v-content.json")
  k -n "$LH_NS" logs "$im" --since=10m --timestamps |
    grep -F -- "$handle" | grep -F -- "$backend" |
    grep -E 'Starting snapshot|Finished snapshot|Failed to snapshot' > "$OUT/$v-engine-cut.log"
done
```

对每卷核对 R2 的完整 UID/handle/lineage 链及同一实际 engine 中唯一的成功开始和完成记录。只有实际镜像和版本的本地 `snap` Ready 语义已核对，才能用请求前与 Ready 后的单调标记给该次后端操作作因果包围。记录可在解冻后读取，必须属于这次新建请求。单独的 Ready、对象时间、`held` 和日志时间戳不构成通过。[Longhorn v1.12.0 engine 快照路径](https://github.com/longhorn/longhorn-engine/blob/v1.12.0/pkg/controller/control.go) · [CSI Ready 回传路径](https://github.com/longhorn/longhorn-manager/blob/v1.12.0/csi/controller_server.go)

- `PASS` 需要同节点校准通过、两份实际后端操作有完整关联、`WINDOW_OBSERVED`、两卷正常解冻并实际写读恢复、keeper 保持原卷，以及 R2 第 4 节独立 clone 内容和回收检查通过。
- `FAIL` 记录实际提前解冻、watchdog 介入、已确认的操作失败或恢复及读回反例，并标明是在当前版本、测试配置和预算下观察到的结果。
- `UNVERIFIED` 记录缺失的确切证据。包括内核探点不支持、丢事件、没有后端成功记录、无法关联或恢复状态未知。缺证据仍须先处理恢复义务。

按 R2 的失败恢复和清理顺序，先释放租约并确认两卷真实写读，随后按 UID 清理本轮 namespace，核对 PV、Content 和 Longhorn 卷回收。采集器退出时删除它的 tracefs 实例和四个具名探点。若被强制终止，只能用 `trace.jsonl` 或校准日志中的 `TRACE_SESSION` / `trace_session` 的本轮组名，在确认采集器已结束后精确清理。下面在同一节点执行，`group` 取实际回执值。

```bash
[[ $group =~ ^sbk_[0-9a-f]{32}$ ]]
root=/sys/kernel/tracing
instance=$root/instances/$group
if [[ -d $instance ]]; then
  printf '0\n' > "$instance/tracing_on"
  if [[ -e $instance/events/$group/enable ]]; then printf '0\n' > "$instance/events/$group/enable"; fi
  rmdir -- "$instance"
fi
for suffix in freeze_dev freeze_rc thaw_dev thaw_rc; do
  event=$group/${group}_$suffix
  if awk -v event="$event" 'split($1, parts, ":")==2 && parts[2]==event {found=1} END {exit !found}' "$root/kprobe_events"; then
    printf -- '-:%s\n' "$event" >> "$root/kprobe_events"
  fi
done
```

回传校准回执、`cut-result.txt`、`trace.jsonl`、同轮后端完成证据、两个租约结果和恢复/清理结果。证据收集后删除节点本轮目录里新增的明确文件 `trace.pid`、`trace.jsonl`、`trace-calibration.jsonl`、`trace/{armed,start,ready,release,stop}` 和两个租约内的 `{freeze,unfreeze}.pid`，再按 R2 删除其余明确的本轮文件并 `rmdir` 空目录。
