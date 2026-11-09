#!/usr/bin/env bash
# One native cut on the dedicated, prepared R3 fixture.
set -euo pipefail
umask 077

stop() { printf '%s\n' "$*" >&2; exit 3; }
[[ $# == 1 && $1 =~ ^/var/tmp/sbk-thaw-calibration\.[A-Za-z0-9]{8}/sbk-storage-probe-[0-9a-f]{32}/run\.env$ ]] ||
  stop 'usage: system-backup-storage-probe-cut.sh /absolute/run.env'
run_dir=${1%/*}
[[ $(hostname -s) == k8s-master && ! -L $run_dir && ! -L $1 && $(stat -c %u:%a -- "$run_dir") == 0:700 ]] ||
  stop 'prepared run directory is not private or on k8s-master'
source "$1"
[[ $OUT == "$run_dir" && ${OUT##*/} == "$NS" && $RUN_ID =~ ^[0-9a-f]{32}$ && $NS == sbk-storage-probe-$RUN_ID &&
   $CTX == kubernetes-admin@kubernetes && $LH_NS == longhorn-system && $SNAP_CLASS == sbk-validation-longhorn-local &&
   $NODE == node1 && $NODE_BOOT =~ ^[0-9a-f-]{36}$ && $SEED_SHA =~ ^[0-9a-f]{64}$ &&
   $RWO_HANDLE =~ ^pvc-[0-9a-f-]{36}$ && $RWX_HANDLE =~ ^pvc-[0-9a-f-]{36}$ && $RWO_HANDLE != "$RWX_HANDLE" ]] ||
  stop 'prepared run identity mismatch'
BASE=${OUT%/*}
DIR=/var/tmp/sbk-storage-probe-$RUN_ID
E=$OUT/cut-attempt
k() { kubectl --context "$CTX" "$@"; }
lh() { k -n "$LH_NS" "$@"; }

[[ $(k get ns "$NS" -o jsonpath='{.metadata.uid}') == "$NS_UID" &&
   $(k get node "$NODE" -o jsonpath='{.status.nodeInfo.bootID}') == "$NODE_BOOT" ]] ||
  stop 'namespace or node identity changed'
writer=$(k -n "$NS" get pod writer-rwo --ignore-not-found -o name)
[[ -z $writer ]] || stop 'RWO writer is still present'
k -n "$NS" get volumesnapshots -o json | jq -e '.items|length==0' >/dev/null || stop 'snapshot already exists'
k get volumesnapshotclass "$SNAP_CLASS" -o json | jq -e '
  .driver=="driver.longhorn.io" and .parameters.type=="snap" and .deletionPolicy=="Delete"
' >/dev/null || stop 'snapshot class changed'

pod_pin() {
  k -n "$1" get pod "$2" -o json | jq -er --arg node "$NODE" --arg uid "$3" --arg cid "$4" '
    select(.metadata.uid==$uid and .metadata.deletionTimestamp==null and .spec.nodeName==$node and .status.phase=="Running")
    | .status.containerStatuses[] | select(.ready and .containerID==$cid) | .containerID
    | select(test("^containerd://[0-9a-f]{64}$")) | sub("^containerd://"; "")'
}
keeper_uid=$(jq -er .uid "$OUT/keeper-after.json")
share_uid=$(jq -er .uid "$OUT/share-pod.json")
[[ $keeper_uid =~ ^[0-9a-f-]{36}$ && $share_uid =~ ^[0-9a-f-]{36}$ ]]
rwo_cid=$(pod_pin "$NS" keeper-rwo "$keeper_uid" "$(jq -er .containerID "$OUT/keeper-after.json")")
rwx_cid=$(pod_pin "$LH_NS" "share-manager-$RWX_HANDLE" "$share_uid" \
  "$(jq -er '[.containers[] | select(.ready)] | if length==1 then .[0].containerID else error("share-manager container not unique") end' "$OUT/share-pod.json")")
for v in rwo rwx; do
  if [[ $v == rwo ]]; then handle=$RWO_HANDLE; else handle=$RWX_HANDLE; fi
  pvc_uid=$(jq -er .metadata.uid "$OUT/$v-pvc.json")
  pv=$(jq -er .metadata.name "$OUT/$v-pv.json")
  k -n "$NS" get pvc "source-$v" -o json | jq -e --arg uid "$pvc_uid" --arg pv "$pv" \
    '.metadata.uid==$uid and .spec.volumeName==$pv' >/dev/null
  k get pv "$pv" -o json | jq -e --arg ns "$NS" --arg uid "$pvc_uid" --arg handle "$handle" '
    .spec.claimRef.namespace==$ns and .spec.claimRef.uid==$uid and
    .spec.csi.driver=="driver.longhorn.io" and .spec.csi.volumeHandle==$handle' >/dev/null
  lh get volumes.longhorn.io "$handle" -o json | jq -e --arg node "$NODE" --arg uid "$(jq -er .uid "$OUT/$v-before.json")" '
    .metadata.uid==$uid and .spec.numberOfReplicas==2 and .status.currentNodeID==$node and
    .status.state=="attached" and .status.robustness=="healthy" and
    any(.status.conditions[]?; .type=="Scheduled" and .status=="True")' >/dev/null || stop "volume identity changed: $v"
done
mkdir -m 700 -- "$E" || stop 'cut attempt already recorded'
engine_pin() {
  lh get engines.longhorn.io -l "longhornvolume=$1" -o json | jq -ceS --arg v "$1" '
    [.items[] | select(.spec.volumeName==$v and .spec.active==true and .status.currentState=="running")
     | {name:.metadata.name,uid:.metadata.uid,node:.spec.nodeID,image:.status.currentImage,
        manager:.status.instanceManagerName,ip:.status.ip,port:.status.port}]
    | if length==1 and (.[0].manager // "" | length>0) then .[0] else error("engine not unique") end'
}
engine_pin "$RWO_HANDLE" > "$E/rwo-engine-before.json"
engine_pin "$RWX_HANDLE" > "$E/rwx-engine-before.json"
lh get settings.longhorn.io freeze-filesystem-for-snapshot -o jsonpath='{.value}{"\n"}' > "$E/freeze-setting.txt" || true
lh get daemonset longhorn-manager -o json | jq -er '.spec.template.spec.containers[] | select(.name=="longhorn-manager") | .image' > "$E/manager-image.txt"
if ! grep -Eq ':v1\.12\.0(@sha256:[0-9a-f]{64})?$' "$E/manager-image.txt" ||
   ! jq -es --arg node "$NODE" 'all(.[]; .node==$node and (.image|test(":v1\\.12\\.0(@sha256:[0-9a-f]{64})?$")))' \
      "$E/rwo-engine-before.json" "$E/rwx-engine-before.json" >/dev/null; then
  cat "$E/manager-image.txt" "$E/"*-engine-before.json
  stop 'Longhorn image or engine node requires review before freeze'
fi

NODE_IP=$(k get node "$NODE" -o json | jq -er '
  [.status.addresses[] | select(.type=="InternalIP" and (.address|test("^[0-9.]+$"))) | .address]
  | if length==1 then .[0] else error("IPv4 not unique") end')
SOCKET_DIR=$(mktemp -d /var/tmp/sbk-ssh.XXXXXXXX)
SOCKET=$SOCKET_DIR/control
node() { ssh -T -S "$SOCKET" -o BatchMode=yes -o ConnectTimeout=4 -o StrictHostKeyChecking=yes "root@$NODE_IP" "$@"; }
pending_release=0
release_both() {
  node bash -s -- "$DIR" <<'REMOTE'
d=$1
if [[ -d $d/trace && ! -e $d/trace/release ]]; then
  (set -C; python3 -I -B -c 'import time; print(time.monotonic_ns())' > "$d/trace/release") || true
fi
rc=0
for v in rwo rwx; do
  if [[ -d $d/$v ]]; then touch -- "$d/$v/release" || rc=4; fi
done
exit "$rc"
REMOTE
}
finish() {
  local rc=$?
  if ((pending_release)); then
    release_both || printf 'RELEASE_UNCONFIRMED node=%s directory=%s\n' "$NODE" "$DIR" >&2
  fi
  ssh -S "$SOCKET" -O exit "root@$NODE_IP" >/dev/null 2>&1 || true
  rmdir -- "$SOCKET_DIR" 2>/dev/null || true
  exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ssh -MNf -S "$SOCKET" -o ControlPersist=no -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "root@$NODE_IP"

cat > "$E/locate.py" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

boot, handle, uid, cid, seed = sys.argv[1:]
assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'node boot changed'
inspected = json.loads(subprocess.check_output(['crictl', 'inspect', cid], timeout=4))
assert inspected['status']['id'] == cid and inspected['status']['labels']['io.kubernetes.pod.uid'] == uid, 'CRI identity mismatch'
pid = int(inspected['info']['pid'])
assert pid > 1
proc = Path(f'/proc/{pid}')
def start():
    return (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
start_time = start()
dev = Path('/dev/longhorn', handle).stat()
assert stat.S_ISBLK(dev.st_mode)
device = f'{os.major(dev.st_rdev)}:{os.minor(dev.st_rdev)}'
matches = []
for line in (proc / 'mountinfo').read_text().splitlines():
    left, right = line.split(' - ', 1)
    fields, fs = left.split(), right.split()
    if fields[2] == device and fields[3] == '/' and fs[0] == 'ext4' and 'rw' in fs[2].split(','):
        matches.append((fields[0], fields[4]))
assert len(matches) == 1, 'writable ext4 superblock mount not unique'
mount_id, mount = matches[0]
assert re.fullmatch(r'/[a-zA-Z0-9_./-]+', mount) and '..' not in mount.split('/')
target = Path(f'/proc/{pid}/root{mount}')
assert not target.is_symlink() and target.stat().st_dev == dev.st_rdev
assert hashlib.sha256((target / 'seed').read_bytes()).hexdigest() == seed, 'seed mismatch'
diskseq = int(Path('/sys/dev/block', device, 'diskseq').read_text())
assert diskseq > 0 and start() == start_time
print(json.dumps(dict(path=str(target), pid=pid, start=start_time, mount_id=mount_id,
                      namespace=os.readlink(proc / 'ns/mnt'), device=device, diskseq=diskseq, uid=uid, cid=cid)))
PY
files=(system-backup-ext4-freeze-trace.py system-backup-storage-probe-lease.sh)
{ (cd -- "$BASE" && sha256sum -- "${files[@]}"); (cd -- "$OUT" && sha256sum trace-calibration.jsonl);
  (cd -- "$E" && sha256sum locate.py); } > "$E/payload.sha256"
node "umask 077; test \"\$(hostname -s)\" = '$NODE' && mkdir -m 700 -- '$DIR'"
tar -C "$BASE" -cf - "${files[@]}" -C "$OUT" trace-calibration.jsonl -C "$E" locate.py payload.sha256 |
  node "cd -- '$DIR' && tar -xf - && sha256sum --check payload.sha256"

jq -n --arg ns "$NS" --arg class "$SNAP_CLASS" '
  {apiVersion:"v1",kind:"List",items:[("rwo","rwx") as $v |
    {apiVersion:"snapshot.storage.k8s.io/v1",kind:"VolumeSnapshot",
     metadata:{namespace:$ns,name:("cut-"+$v)},
     spec:{volumeSnapshotClassName:$class,source:{persistentVolumeClaimName:("source-"+$v)}}}]}
' > "$E/cuts.json"
pending_release=1
started=0
if node bash -s -- "$DIR" "$NODE_BOOT" "$RWO_HANDLE" "$RWX_HANDLE" "$SEED_SHA" "$keeper_uid" "$rwo_cid" "$share_uid" "$rwx_cid" <<'REMOTE'
set -euo pipefail
cd -- "$1"
timeout 7s python3 -I -B locate.py "$2" "$3" "$6" "$7" "$5" > rwo-mount.json
timeout 7s python3 -I -B locate.py "$2" "$4" "$8" "$9" "$5" > rwx-mount.json
rwo=$(python3 -I -B -c 'import json; print(json.load(open("rwo-mount.json"))["path"])')
rwx=$(python3 -I -B -c 'import json; print(json.load(open("rwx-mount.json"))["path"])')
nohup python3 -I -B ./system-backup-ext4-freeze-trace.py --longhorn-probe "$1" "$3" "$4" >trace.jsonl 2>&1 </dev/null &
trace_pid=$!
for i in {1..40}; do
  [[ -f trace/armed ]] && break
  kill -0 "$trace_pid"
  sleep .1
done
[[ -f trace/armed ]]
nohup bash ./system-backup-storage-probe-lease.sh "$rwo" "$3" "$5" "$1/rwo" >rwo.log 2>&1 </dev/null &
nohup bash ./system-backup-storage-probe-lease.sh "$rwx" "$4" "$5" "$1/rwx" >rwx.log 2>&1 </dev/null &
for i in {1..40}; do
  [[ ! -e rwo/unknown && ! -e rwx/unknown && ! -e rwo/exit-code && ! -e rwx/exit-code ]]
  [[ -s rwo/held && -s rwx/held ]] && exit 0
  sleep .1
done
exit 3
REMOTE
then started=1; fi

mark() { node "set -C; python3 -I -B -c 'import time; print(time.monotonic_ns())' > '$DIR/trace/$1'"; }
cut=CUT_UNCONFIRMED
if ((started)) && mark start && k --request-timeout=4s create -f "$E/cuts.json" &&
  k -n "$NS" --request-timeout=10s wait --for=jsonpath='{.status.readyToUse}'=true \
    volumesnapshot/cut-rwo volumesnapshot/cut-rwx --timeout=10s && mark ready; then
  cut=READY_OBSERVED
fi
release_both || stop "RELEASE_UNCONFIRMED node=$NODE directory=$DIR"
pending_release=0
printf '%s\n' "$cut" | tee "$E/cut-result.txt"

node bash -s -- "$DIR" <<'REMOTE' | tee "$E/leases.txt"
set -eu
cd -- "$1"
for i in {1..28}; do
  [[ -s rwo/exit-code && -s rwx/exit-code ]] && break
  [[ ! -d rwo && ! -d rwx ]] && break
  sleep 1
done
for v in rwo rwx; do
  printf '%s\n' "$v"
  for f in exit-code freeze.pid unfreeze.pid thaw-acknowledged timed-out unknown; do
    if [[ -f $v/$f ]]; then printf '%s: ' "$f"; cat -- "$v/$f"; fi
  done
  if [[ -f $v.log ]]; then cat -- "$v.log"; fi
done
[[ ! -d trace ]] || touch trace/stop
REMOTE
for i in {1..10}; do
  node "test -f '$DIR/trace.jsonl' && cat '$DIR/trace.jsonl'" > "$E/trace.jsonl" || true
  if jq -es 'any(.[]; .status=="WINDOW_OBSERVED" or .status=="UNVERIFIED" or (.status|startswith("FAIL_")))' \
    "$E/trace.jsonl" >/dev/null 2>&1; then break; fi
  sleep 1
done
cat -- "$E/trace.jsonl"
for v in rwo rwx; do
  node "test -s '$DIR/$v-mount.json' && cat '$DIR/$v-mount.json'" > "$E/$v-mount-before.json" || true
done
node "test \"\$(cat '$DIR/rwo/exit-code')\" = 0 && test \"\$(cat '$DIR/rwx/exit-code')\" = 0 &&
  test -f '$DIR/rwo/thaw-acknowledged' && test -f '$DIR/rwx/thaw-acknowledged'" ||
  stop "THAW_UNCONFIRMED_OR_ABNORMAL node=$NODE directory=$DIR evidence=$E"

jq -e '.items[] | select(.kind=="Pod" and .metadata.name=="writer-rwo")
  | .metadata.name="resume-rwo" | .spec.containers[0].command=["sh","-ec","while :; do sleep 60; done"]' \
  "$OUT/rwo.json" > "$E/resume.json"
k create -f "$E/resume.json"
k -n "$NS" wait --for=condition=Ready pod/resume-rwo --timeout=60s
for pod in resume-rwo writer-rwx; do
  hash=$(k --request-timeout=15s -n "$NS" exec "$pod" -- sh -ec '
    printf resumed >/source/resumed; sync; test "$(cat /source/resumed)" = resumed; sha256sum /source/seed' |
    cut -d ' ' -f1)
  [[ $hash == "$SEED_SHA" ]] || stop "SOURCE_RECOVERY_UNCONFIRMED $pod"
done
printf 'SOURCE_WRITE_READ_OK\n'

mount_identity=unchanged
for v in rwo rwx; do
  if [[ $v == rwo ]]; then handle=$RWO_HANDLE; uid=$keeper_uid; cid=$rwo_cid
  else handle=$RWX_HANDLE; uid=$share_uid; cid=$rwx_cid; fi
  if ! node timeout 7s python3 -I -B "$DIR/locate.py" "$NODE_BOOT" "$handle" "$uid" "$cid" "$SEED_SHA" \
      > "$E/$v-mount-after.json" || ! cmp -s "$E/$v-mount-before.json" "$E/$v-mount-after.json"; then
    mount_identity=unconfirmed
  fi
done
printf 'MOUNT_IDENTITY=%s\n' "$mount_identity" | tee "$E/mount-result.txt"

for v in rwo rwx; do
  if [[ $v == rwo ]]; then handle=$RWO_HANDLE; else handle=$RWX_HANDLE; fi
  engine_pin "$handle" > "$E/$v-engine-after.json" || continue
  k -n "$NS" get volumesnapshot "cut-$v" -o json > "$E/$v-snapshot.json" || continue
  content=$(jq -er .status.boundVolumeSnapshotContentName "$E/$v-snapshot.json") || continue
  k get volumesnapshotcontent "$content" -o json > "$E/$v-content.json" || continue
  snapshot_handle=$(jq -er .status.snapshotHandle "$E/$v-content.json") || continue
  [[ $snapshot_handle == "snap://$handle/"* ]] || continue
  backend=${snapshot_handle##*/}
  lh get snapshots.longhorn.io "$backend" -o json > "$E/$v-backend-snapshot.json" || true
  im=$(jq -er .manager "$E/$v-engine-before.json")
  lh logs "$im" --since=10m --timestamps | grep -F -- "$handle" | grep -F -- "$backend" |
    grep -E 'Starting snapshot|Finished snapshot|Failed to snapshot' > "$E/$v-engine-cut.log" || true
  printf '%s backend=%s engine_log_lines=%s\n' "$v" "$backend" "$(wc -l < "$E/$v-engine-cut.log")"
done
printf 'CUT_EVIDENCE_READY=%s\n' "$E"
