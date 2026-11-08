# 唯一远测方案：先验证存储原语，再决定是否恢复完整任务开发

状态：**准备完成，未执行远测**。本方案只操作新建的 `sbk-storage-probe-<32位随机值>` namespace 和对应测试卷。不要在业务 PVC、业务 share-manager 或真实备份 task 上运行。两轮必须依次执行；任一步失败即停止，不扩大授权、不改超时、不改成功判据。

需要 Linux 6.8.x x86_64 验证节点、可用的 root SSH、kubectl、jq、Python 3、节点上的 crictl / fsfreeze / sha256sum / GNU stat / sync。工具镜像由现场提供实际不可变 digest，须已有 `sh`、`sleep`、`sync`、`sha256sum`；不临时安装依赖。StorageClass 和本地 `snap` VolumeSnapshotClass 须已经安装。执行前记录 Longhorn/CSI/engine 的实际镜像 digest；本候选按 Longhorn v1.12.0 检查过源码，其他版本先停止核对。

## 0. 输入、隔离与记录

以下在有集群管理连接的 Linux Bash 终端执行。先填真实值，任何占位值未填不运行：

```bash
set -euo pipefail
export KUBECONFIG=/实际路径/admin.kubeconfig
export CTX=实际kubectl-context
export LH_NS=实际Longhorn-namespace
export SC_RWO=实际RWO-StorageClass
export SC_RWX=实际RWX-StorageClass
export SNAP_CLASS=实际本地snap-VolumeSnapshotClass
export TOOL_IMAGE=实际镜像地址@sha256:实际64位摘要
export NODE_SSH=root@实际验证节点地址
export SSH_KEY=/实际路径/已配置的ssh私钥
export RUN_ID=$(python3 -c 'import uuid;print(uuid.uuid4().hex)')
export NS=sbk-storage-probe-$RUN_ID
export NONCE=$RUN_ID
export OUT=$PWD/$NS
mkdir -m 700 -- "$OUT"       # 已存在则停止，不复用旧执行
k() { kubectl --context "$CTX" "$@"; }
node() { ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -i "$SSH_KEY" "$NODE_SSH" "$@"; }
[[ $TOOL_IMAGE =~ @sha256:[0-9a-f]{64}$ ]]
k get storageclass "$SC_RWO" "$SC_RWX" -o json > "$OUT/storageclasses.json"
jq -e 'all(.items[]; .provisioner=="driver.longhorn.io" and .reclaimPolicy=="Delete")' "$OUT/storageclasses.json"
k get volumesnapshotclass "$SNAP_CLASS" -o json > "$OUT/snapshotclass.json"
jq -e '.driver=="driver.longhorn.io" and .parameters.type=="snap" and .deletionPolicy=="Delete"' "$OUT/snapshotclass.json"
```

保存 `kubectl config current-context`、节点 UID/bootID/kernelVersion、Longhorn 与 CSI 的版本及镜像 digest。仅记录选定对象的元数据和镜像，**不要导出 Secret、kubeconfig、share-manager 环境变量或所有 Pod 完整 YAML**。

## 1. 内核前置检查

在冻结包目录执行以下复制与第 1 轮命令；只复制两个公开探针，不复制任何凭据正文。节点目录必须本轮新建：

```bash
REMOTE_DIR=/var/tmp/sbk-storage-probe-$RUN_ID
node "umask 077; mkdir -m 700 -- '$REMOTE_DIR'"
(cd scripts; sha256sum system-backup-ext4-freeze-canary.py system-backup-storage-probe-lease.sh) > "$OUT/payload.sha256"
scp -o BatchMode=yes -o StrictHostKeyChecking=yes -i "$SSH_KEY" scripts/system-backup-ext4-freeze-canary.py scripts/system-backup-storage-probe-lease.sh "$OUT/payload.sha256" "$NODE_SSH:$REMOTE_DIR/"
node "cd -- '$REMOTE_DIR'; sha256sum --check payload.sha256"
set -o pipefail
node "cd -- '$REMOTE_DIR'; python3 -I -B ./system-backup-ext4-freeze-canary.py" 2>&1 | tee "$OUT/ext4-freeze-canary.log"
rc=${PIPESTATUS[0]}; printf 'exit=%s\n' "$rc"; test "$rc" -eq 0
```

要求 `freeze_native_result` 的写阻塞/恢复、内容读回、冻结期间 syncfs 和 system sync、`snapshot_deadlock_canary_passed` 全部为 true；`native_result` 全 true；最后 `cleanup.complete/test_completed` 全 true。出现 watchdog、未知结果或清理失败均不能进入第 3 节 Longhorn 冻结。这只证明该节点上的自建 ext4 loopback 行为，不能证明 Longhorn。

## 2. 创建两个专用测试源及只读 keeper

下面的生成器只产生测试资源 JSON，不连接集群。在 `$OUT/fixture.py` 保存：

```python
import json, os, re, sys
e=os.environ; ns=e['NS']; run=e['RUN_ID']; nonce=e['NONCE']; image=e['TOOL_IMAGE']
assert ns=='sbk-storage-probe-'+run and re.fullmatch('[0-9a-f]{32}',run)
assert re.search(r'@sha256:[0-9a-f]{64}$',image)
kind=sys.argv[1]; assert kind in ('rwx','rwo','readback','resume')
def pod(name, claim, readonly, node=''):
    cmd='exec 9</source; while :; do sleep 60; done' if readonly else "printf '%s' '"+nonce+"' >/source/seed; exec 3>>/source/idle-open; sync; while :; do sleep 60; done"
    spec={'automountServiceAccountToken':False,'restartPolicy':'Never','containers':[{'name':'probe','image':image,'command':['sh','-ec',cmd], 'securityContext':{'runAsUser':0,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'source','mountPath':'/source','readOnly':readonly}]}],'volumes':[{'name':'source','persistentVolumeClaim':{'claimName':claim,'readOnly':readonly}}]}
    if node: spec['nodeName']=node
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':ns,'labels':{'sbk-storage-probe':run}},'spec':spec}
def pvc(name, mode, storage, snapshot=None):
    spec={'accessModes':[mode],'storageClassName':storage,'resources':{'requests':{'storage':'1Gi'}}}
    if snapshot: spec['dataSource']={'apiGroup':'snapshot.storage.k8s.io','kind':'VolumeSnapshot','name':snapshot}
    return {'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':name,'namespace':ns,'labels':{'sbk-storage-probe':run}},'spec':spec}
if kind=='rwx': objects=[pvc('source-rwx','ReadWriteMany',e['SC_RWX']),pod('writer-rwx','source-rwx',False)]
elif kind=='rwo': objects=[pvc('source-rwo','ReadWriteOnce',e['SC_RWO']),pod('writer-rwo','source-rwo',False,e['NODE']),pod('keeper-rwo','source-rwo',True,e['NODE'])]
elif kind=='resume': objects=[pod('resume-rwo','source-rwo',False,e['NODE'])]
else: objects=[pvc('clone-'+v,'ReadWriteOnce',e['SC_RWO'],'cut-'+v) for v in ('rwo','rwx')]+[pod('read-'+v,'clone-'+v,True,e['NODE']) for v in ('rwo','rwx')]
print(json.dumps({'apiVersion':'v1','kind':'List','items':objects}))
```

```bash
k create namespace "$NS" -o json > "$OUT/namespace.json"   # 若已存在就停止
export NS_UID=$(jq -r '.metadata.uid' "$OUT/namespace.json")
python3 "$OUT/fixture.py" rwx > "$OUT/rwx.json"; k create -f "$OUT/rwx.json"
k -n "$NS" wait --for=condition=Ready pod/writer-rwx --timeout=120s
export RWX_PV=$(k -n "$NS" get pvc source-rwx -o jsonpath='{.spec.volumeName}')
k get pv "$RWX_PV" -o json > "$OUT/rwx-pv.json"
jq -e --arg ns "$NS" '.spec.claimRef.namespace==$ns and .spec.csi.driver=="driver.longhorn.io" and .spec.persistentVolumeReclaimPolicy=="Delete"' "$OUT/rwx-pv.json"
export RWX_HANDLE=$(jq -r '.spec.csi.volumeHandle' "$OUT/rwx-pv.json")
k -n "$LH_NS" get sharemanagers.longhorn.io "$RWX_HANDLE" -o json > "$OUT/sharemanager.json"
SM_UID=$(jq -r '.metadata.uid' "$OUT/sharemanager.json")
k -n "$LH_NS" get pods -o json | jq --arg uid "$SM_UID" '[.items[]|select(any(.metadata.ownerReferences[]?; .uid==$uid))|{name:.metadata.name,uid:.metadata.uid,node:.spec.nodeName,containers:.status.containerStatuses}]|if length==1 then .[0] else error("share-manager not unique") end' > "$OUT/share-pod.json"
export NODE=$(jq -r '.node' "$OUT/share-pod.json")
[[ -n $NODE && $NODE != null ]]
```

确认 `NODE_SSH` 就是这个 `NODE`，核对实际 Node UID、bootID 和内核。第 1 轮结果必须来自此实际节点；不同则先在此节点完成第 1 轮，不沿用另一台机器的结果。随后：

```bash
python3 "$OUT/fixture.py" rwo > "$OUT/rwo.json"; k create -f "$OUT/rwo.json"
k -n "$NS" wait --for=condition=Ready pod/writer-rwo pod/keeper-rwo --timeout=120s
for v in rwo rwx; do
  k -n "$NS" exec "writer-$v" -- sh -ec 'test -s /source/seed; sync; sha256sum /source/seed' | tee "$OUT/$v-seed.sha"
  k -n "$NS" get pvc "source-$v" -o json > "$OUT/$v-pvc.json"
  pv=$(jq -r '.spec.volumeName' "$OUT/$v-pvc.json")
  k get pv "$pv" -o json > "$OUT/$v-pv.json"
  jq -e --arg ns "$NS" --arg uid "$(jq -r '.metadata.uid' "$OUT/$v-pvc.json")" '.spec.claimRef.namespace==$ns and .spec.claimRef.uid==$uid and .spec.csi.driver=="driver.longhorn.io"' "$OUT/$v-pv.json"
done
export RWO_HANDLE=$(jq -r '.spec.csi.volumeHandle' "$OUT/rwo-pv.json")
export SEED_SHA=$(printf '%s' "$NONCE" | sha256sum | cut -d ' ' -f 1)
```

记录 keeper Pod UID、Node、原 container ID。删除 **本轮 writer-rwo** 前再核对 UID 与生成清单；只读 keeper 必须保持 Running，Longhorn 原 Volume 必须仍 attached 到同 Node，handle/UID 不变。`kubectl -n "$NS" delete pod writer-rwo --wait=true --timeout=30s` 后必须在 keeper 上 `test -r /source/seed` 并核对 checksum。失败即停止，不能改成重建源 PVC。

## 3. 两卷冻结、真实快照、解除

只在前述专用测试卷执行。通过选定 keeper 和 share-manager 的真实 container ID，在**同一个已核对节点**使用现有 `crictl inspect` 取得 PID，并核对输出的 Pod UID；不要猜 PID。保存过滤后的 PID/Pod UID/容器 ID，不保存完整 inspect。

在各 PID 的 `/proc/<PID>/mountinfo` 中，用 `/dev/longhorn/<HANDLE>` 的实际 major:minor 找到 ext4 挂载点，根必须为 `/`，唯一且与 seed 一致。RWO 目标为 keeper 的完整 PVC 挂载；RWX 目标为 share-manager 的后端 ext4，**不能对 NFS 客户端目录执行 fsfreeze**。组成实际路径 `MOUNT_RWO=/proc/<PID>/root/<挂载点>`、`MOUNT_RWX=...`，核对 PID starttime、mount namespace、Node UID/bootID。

使用第 1 节已核对并复制的 `system-backup-storage-probe-lease.sh`；节点目录必须属于这次 RUN_ID，root:700，禁止复用其他执行。此脚本只用于本测试；它以原 FD、seed 摘要和 Longhorn device 核对目标，最长约 20 秒后尝试解除已确认的冻结。watchdog 介入会判本轮失败，不是生产恢复能力证明。

在节点的独立 SSH 终端启动两份 lease（填入已观察的路径，**不要直接复制占位值执行**）：

```bash
RUN_ID=本轮32位值
SEED_SHA=本轮seed摘要
RWO_HANDLE=本轮实际handle
RWX_HANDLE=本轮实际handle
MOUNT_RWO=/proc/实际PID/root/实际挂载点
MOUNT_RWX=/proc/实际PID/root/实际挂载点
DIR=/var/tmp/sbk-storage-probe-$RUN_ID
cd -- "$DIR"
sha256sum --check payload.sha256
nohup bash ./system-backup-storage-probe-lease.sh "$MOUNT_RWO" "$RWO_HANDLE" "$SEED_SHA" "$DIR/rwo" >rwo.log 2>&1 </dev/null &
nohup bash ./system-backup-storage-probe-lease.sh "$MOUNT_RWX" "$RWX_HANDLE" "$SEED_SHA" "$DIR/rwx" >rwx.log 2>&1 </dev/null &
```

在启动 lease 前，在管理终端安装退出保护（连接失败时仍须依靠节点 watchdog，不能据 trap 返回判断已解除）：

```bash
REMOTE_DIR=/var/tmp/sbk-storage-probe-$RUN_ID
release_leases() { node "for d in '$REMOTE_DIR/rwo' '$REMOTE_DIR/rwx'; do if test -d \"\$d\"; then touch -- \"\$d/release\"; fi; done" || true; }
trap release_leases EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
```

管理终端确认两份 `held` 都存在且无 `unknown/timed-out` 后，立刻创建**同一批**快照并等待最多 10 秒。任意错误都先通知节点写入两个 `release` 文件，再收集结果，不重试创建另一批快照：

```bash
python3 - <<'PY' > "$OUT/cuts.json"
import json,os
e=os.environ
print(json.dumps({'apiVersion':'v1','kind':'List','items':[{'apiVersion':'snapshot.storage.k8s.io/v1','kind':'VolumeSnapshot','metadata':{'name':'cut-'+v,'namespace':e['NS']},'spec':{'volumeSnapshotClassName':e['SNAP_CLASS'],'source':{'persistentVolumeClaimName':'source-'+v}}} for v in ('rwo','rwx')]}))
PY
k create -f "$OUT/cuts.json"
k -n "$NS" wait --for=jsonpath='{.status.readyToUse}'=true volumesnapshot/cut-rwo volumesnapshot/cut-rwx --timeout=10s
```

**无论上一条是否成功，立即在节点执行**：

```bash
touch -- "$DIR/rwo/release" "$DIR/rwx/release"
```

要求两个 lease 的 `exit-code` 均为 0，有 `thaw-acknowledged`、没有 `unknown/timed-out`，实际 Snapshot/Content 的创建时间位于两个 held 的共同窗口。保存 Snapshot UID、bound Content UID、`snapshotHandle`；必须分别为 `snap://<本轮原HANDLE>/<后端快照名>`。若超时、快照回复丢失、identity 漂移、解除未确认，按失败步骤停止；禁止扩大 10/20 秒预算求通过。

## 4. 恢复读写、从快照独立读回

先在原 RWX writer 上创建新文件并 `sync; sha256sum`；为 RWO 原 PVC 按同一 fixture 规格创建一个**新名字**的写入检查 Pod，再确认新写入和读回成功。记录新 Pod UID。不能只凭 FITHAW 返回或 keeper Running 宣布恢复。

```bash
python3 "$OUT/fixture.py" resume > "$OUT/resume.json"; k create -f "$OUT/resume.json"
k -n "$NS" wait --for=condition=Ready pod/resume-rwo --timeout=60s
k -n "$NS" exec resume-rwo -- sh -ec 'printf resumed >/source/resumed; sync; test "$(cat /source/resumed)" = resumed; sha256sum /source/seed'
k -n "$NS" exec writer-rwx -- sh -ec 'printf resumed >/source/resumed; sync; test "$(cat /source/resumed)" = resumed; sha256sum /source/seed'
python3 "$OUT/fixture.py" readback > "$OUT/clones.json"; k create -f "$OUT/clones.json"
k -n "$NS" wait --for=condition=Ready pod/read-rwo pod/read-rwx --timeout=180s
for v in rwo rwx; do
  k -n "$NS" exec "read-$v" -- sh -ec 'test ! -e /source/resumed; sha256sum /source/seed' | tee "$OUT/$v-clone.sha"
done
```

克隆 PVC Bound 不足以通过：再核对 clone PV 的独立 UID/handle，Longhorn clone Volume 的 `status.cloneStatus.state=completed`、`sourceVolume` 和 `snapshot` 分别等于本轮原 HANDLE 和 Content 中的后端快照名。两份 clone seed 必须等于冻结前摘要，冻结后新增文件不能出现在 clone 中。

**唯一通过标准**：内核前置检查通过；两个冻结均确认；真实 CSI 快照在共同 held 窗口完成；两个解除均正常确认且原卷写读恢复；RWO 删除原 writer 后 keeper 保持同原卷；两份独立 clone 内容和 lineage 正确；清理完成。缺任一证据标为 FAIL/UNKNOWN。通过本轮也只允许进入完整任务联调，不能宣称正式备份、Node 认证交接或重启恢复已验证。

## 失败恢复与清理（成功、失败都必须执行）

1. 先在节点给两个已创建的 lease 目录写 `release`。不能先删 keeper、share-manager、PVC 或 namespace，不能重启节点、kill 两个持有 FD 的进程来“解除”。
2. 如仅 watchdog 解除了冻结，保留其 `timed-out`，本轮仍 FAIL。检查两个原卷实际写读后才清理。
3. 如有 `unknown` 或没有 thaw ACK：保留 namespace/keeper、FD 进程、原 UID/handle、日志和 Node 身份。核对 `parent.pid` 对应原进程及 `/proc/<PID>/fd/9` 仍指向本轮原 device。若**原 freeze ACK 确认、watchdog 明确 no-thaw-dispatched、原 FD/Node 未变**，可由现场 root 对此原 FD 执行 `fsfreeze --unfreeze /proc/<原父PID>/fd/9` 并记录结果；其他情况停止，不盲目重复 FITHAW，由存储管理员确认本轮测试卷状态后恢复。禁止据 404/租约过期判断已恢复。
4. 两卷写读恢复后，核对 namespace 当前 UID 等于 `$NS_UID`，以及清单中每个 PVC/Snapshot 的 UID 仍属于本轮；只删除这个独占测试 namespace：`k delete namespace "$NS" --wait=true --timeout=180s`。不删除 StorageClass、SnapshotClass、共享 RBAC、其他 namespace 或任何业务数据。
5. 等待本轮 PVC 对应 PV、Content 和 Longhorn source/clone Volume 自动回收，逐个按已记录 UID/handle 查验。未回收则记录“清理未完成”，不直接删除未知 Longhorn CR。节点只删除本轮已结束 lease 的明确文件，再 `rmdir` 已核对的测试目录；不递归删除父目录。第 1 轮 loopback 文件由 canary 自己核对并清理。

回传：退出码、完整 probe 日志、时间窗口、选定 Node/PVC/PV/Pod/Snapshot/Content/clone 的 UID/handle、写读摘要及清理结果。不回传任何凭据正文。

源码参考：[Longhorn engine v1.12.0 快照路径](https://github.com/longhorn/longhorn-engine/blob/v1.12.0/pkg/controller/control.go)、[CSI snapshot 路径](https://github.com/longhorn/longhorn-manager/blob/v1.12.0/csi/controller_server.go)。这些源码检查不能替代上述真实执行。
