#!/usr/bin/env bash
# One-time fixture preparation on k8s-master. No freeze or snapshot operations.
(
set -euo pipefail
umask 077
[[ $# == 2 ]] || { printf 'usage: %s CALIBRATION_DIR PRIOR_RUN_EVIDENCE_DIR\n' "$0" >&2; exit 2; }
BASE=$1
OLD_OUT=$2
export CTX=kubernetes-admin@kubernetes LH_NS=longhorn-system
export SC_RWO=longhorn SC_RWX=longhorn-rwx SNAP_CLASS=sbk-validation-longhorn-local
export TOOL_IMAGE=10.130.14.23:5000/mysql@sha256:5ea882b1859d3a61814e527215563d809a9f2bf70ffa24c9280f2ff6798f1977
k() { kubectl --context "$CTX" "$@"; }
lh() { k -n "$LH_NS" "$@"; }
stop() { printf 'STOP: %s\n' "$*" >&2; exit 3; }
[[ $(hostname -s) == k8s-master && $BASE =~ ^/var/tmp/sbk-thaw-calibration\.[A-Za-z0-9]{8}$ &&
   -d $BASE && ! -L $BASE && $(stat -c %u:%a -- "$BASE") == 0:700 ]] ||
  stop '需要在 k8s-master 使用本轮私有校准目录'
[[ ${OLD_OUT%/*} == "$BASE" && ${OLD_OUT##*/} =~ ^sbk-storage-probe-[0-9a-f]{32}$ &&
   -d $OLD_OUT && ! -L $OLD_OUT && $(stat -c %u:%a -- "$OLD_OUT") == 0:700 ]] ||
  stop '前一轮回执目录身份不符'

[[ $(lh get settings.longhorn.io storage-over-provisioning-percentage -o jsonpath='{.value}') == 100 &&
   $(lh get settings.longhorn.io storage-minimal-available-percentage -o jsonpath='{.value}') == 25 ]] ||
  stop 'Longhorn 调度参数已变'
lh get nodes.longhorn.io k8s-master node1 -o json | jq -e '
  (.items|length==2) and all(.items[];
    . as $n | .spec.allowScheduling and
    any(.status.conditions[]?; .type=="Ready" and .status=="True") and
    any(.spec.disks | to_entries[];
      . as $d | ($n.status.diskStatus[$d.key] // {}) as $s |
      $d.value.allowScheduling and
      any($s.conditions[]?; .type=="Schedulable" and .status=="True") and
      ($s.storageMaximum-$d.value.storageReserved-$s.storageScheduled)>=4294967296 and
      ($s.storageAvailable-$s.storageMaximum/4)>4294967296))
' >/dev/null || stop '两节点未各保有 4 GiB 调度及物理余量'
k get storageclass "$SC_RWO" "$SC_RWX" -o json | jq -e '
  (.items|length==2) and all(.items[];
    .provisioner=="driver.longhorn.io" and .reclaimPolicy=="Delete" and
    .volumeBindingMode=="Immediate" and .parameters.numberOfReplicas=="2" and
    (.parameters.dataEngine // "v1")=="v1" and (.parameters.fsType // "ext4")=="ext4" and
    (.parameters.encrypted // "false")=="false" and (.parameters.fromBackup // "")=="" and
    (.parameters.backingImage // "")=="" and
    (.parameters.nodeSelector // "")=="" and (.parameters.diskSelector // "")=="")
' >/dev/null || stop 'StorageClass 不符合隔离双副本配置'
k get volumesnapshotclass "$SNAP_CLASS" -o json | jq -e '
  .driver=="driver.longhorn.io" and .parameters.type=="snap" and .deletionPolicy=="Delete"
' >/dev/null || stop '快照类已变'

k get --raw /apis/snapshot.storage.k8s.io/v1 | jq -e '
  .groupVersion=="snapshot.storage.k8s.io/v1" and
  ((["volumesnapshots","volumesnapshotcontents","volumesnapshotclasses"]-[.resources[].name])|length==0)
' >/dev/null || stop 'Snapshot v1 API 前提已变'

RUN_ID=$(python3 -I -B -c 'import uuid; print(uuid.uuid4().hex)')
export RUN_ID
export NS=sbk-storage-probe-$RUN_ID NONCE=$RUN_ID
export OUT=$BASE/$NS
mkdir -m 700 -- "$OUT"
printf 'TEST_NAMESPACE=%s\nOUT=%s\n' "$NS" "$OUT"
NS_UID=
cleanup_on_error() {
  rc=$?
  if ((rc!=0)) && [[ -n $NS_UID && $(k get ns "$NS" -o jsonpath='{.metadata.uid}' 2>/dev/null) == "$NS_UID" ]]; then
    k -n "$NS" get pvc,pod -o wide >&2 || true
    k delete namespace "$NS" --wait=true --timeout=180s >&2 || true
  fi
  exit "$rc"
}
trap cleanup_on_error EXIT

fixture() {
  python3 -I -B - "$1" <<'PY'
import json
import os
import sys

e = os.environ
kind = sys.argv[1]
assert kind in ("rwo", "rwx")

def meta(name):
    return dict(name=name, namespace=e["NS"], labels={"sbk-storage-probe": e["RUN_ID"]})

def pod(name, readonly=False):
    cmd = "exec 9</source; while :; do sleep 60; done" if readonly else (
        "printf '%s' '" + e["NONCE"] + "' >/source/seed; exec 3>>/source/idle-open; "
        "sync; while :; do sleep 60; done"
    )
    c = dict(name="probe", image=e["TOOL_IMAGE"], command=["sh", "-ec", cmd],
             securityContext=dict(runAsUser=0, allowPrivilegeEscalation=False,
                                  readOnlyRootFilesystem=True, capabilities={"drop": ["ALL"]}),
             volumeMounts=[dict(name="source", mountPath="/source", readOnly=readonly)])
    spec = dict(automountServiceAccountToken=False, restartPolicy="Never", containers=[c],
                volumes=[dict(name="source", persistentVolumeClaim={
                    "claimName": "source-" + kind, "readOnly": readonly})])
    if kind == "rwo":
        spec["nodeName"] = e["NODE"]
    if name == "writer-rwo":
        # Keep the disposable writer's shutdown grace inside the API wait.
        spec["terminationGracePeriodSeconds"] = 5
    return dict(apiVersion="v1", kind="Pod", metadata=meta(name), spec=spec)

pvc = dict(apiVersion="v1", kind="PersistentVolumeClaim", metadata=meta("source-" + kind),
           spec=dict(storageClassName=e["SC_" + kind.upper()],
                     accessModes=["ReadWriteOnce" if kind == "rwo" else "ReadWriteMany"],
                     resources={"requests": {"storage": "1Gi"}}))
items = [pvc, pod("writer-" + kind)]
if kind == "rwo":
    items.append(pod("keeper-rwo", True))
print(json.dumps(dict(apiVersion="v1", kind="List", items=items)))
PY
}

source_handle() {
  local v=$1 pv
  k -n "$NS" get pvc "source-$v" -o json > "$OUT/$v-pvc.json"
  pv=$(jq -er '.spec.volumeName | select(length>0)' "$OUT/$v-pvc.json")
  k get pv "$pv" -o json > "$OUT/$v-pv.json"
  jq -er --arg ns "$NS" --arg uid "$(jq -r .metadata.uid "$OUT/$v-pvc.json")" '
    select(.spec.claimRef.namespace==$ns and .spec.claimRef.uid==$uid and
           .spec.csi.driver=="driver.longhorn.io" and .spec.persistentVolumeReclaimPolicy=="Delete")
    | .spec.csi.volumeHandle | select(test("^pvc-[0-9a-f-]{36}$"))
  ' "$OUT/$v-pv.json"
}

k create namespace "$NS" -o json > "$OUT/namespace.json"
NS_UID=$(jq -er .metadata.uid "$OUT/namespace.json")
fixture rwx > "$OUT/rwx.json"
k create -f "$OUT/rwx.json"
k -n "$NS" wait --for=condition=Ready pod/writer-rwx --timeout=120s
RWX_HANDLE=$(source_handle rwx)
SM_UID=$(lh get sharemanagers.longhorn.io "$RWX_HANDLE" -o jsonpath='{.metadata.uid}')
lh get pod "share-manager-$RWX_HANDLE" -o json | jq -ce --arg uid "$SM_UID" '
  select(any(.metadata.ownerReferences[]?; .uid==$uid))
  | {name:.metadata.name,uid:.metadata.uid,node:.spec.nodeName,containers:.status.containerStatuses}
' > "$OUT/share-pod.json"
NODE=$(jq -er '.node | select(.=="node1" or .=="k8s-master")' "$OUT/share-pod.json")
export NODE
NODE_BOOT=$(k get node "$NODE" -o jsonpath='{.status.nodeInfo.bootID}')
if [[ $NODE == node1 ]]; then CAL_LOG=$OLD_OUT/node1-calibration.jsonl; else CAL_LOG=$BASE/trace-calibration.jsonl; fi
jq -es --arg boot "$NODE_BOOT" '
  any(.[]; .phase=="freeze_trace_canary" and .status=="FOREIGN_THAW_OBSERVED" and .boot_id==$boot) and
  any(.[]; .phase=="cleanup" and .complete==true and .test_completed==true) and
  all(.[]; .phase!="failure")
' "$CAL_LOG" >/dev/null || stop '实际节点缺少同次启动的校准回执'
cp -- "$CAL_LOG" "$OUT/trace-calibration.jsonl"

fixture rwo > "$OUT/rwo.json"
k create -f "$OUT/rwo.json"
k -n "$NS" wait --for=condition=Ready pod/writer-rwo pod/keeper-rwo --timeout=120s
RWO_HANDLE=$(source_handle rwo)
lh wait --for=jsonpath='{.status.robustness}'=healthy \
  "volumes.longhorn.io/$RWO_HANDLE" "volumes.longhorn.io/$RWX_HANDLE" --timeout=120s
volume_identity() {
  lh get volumes.longhorn.io "$1" -o json | jq -ceS --arg node "$NODE" '
    select(.spec.numberOfReplicas==2 and .status.currentNodeID==$node and
           .status.state=="attached" and .status.robustness=="healthy" and
           any(.status.conditions[]?; .type=="Scheduled" and .status=="True"))
    | {uid:.metadata.uid,name:.metadata.name,node:.status.currentNodeID}'
}
volume_identity "$RWO_HANDLE" > "$OUT/rwo-before.json"
volume_identity "$RWX_HANDLE" > "$OUT/rwx-before.json"

SEED_SHA=$(printf '%s' "$NONCE" | sha256sum | cut -d ' ' -f1)
seed() { k --request-timeout=15s -n "$NS" exec "$1" -- sha256sum /source/seed | cut -d ' ' -f1; }
for pod in writer-rwx writer-rwo keeper-rwo; do
  [[ $(seed "$pod") == "$SEED_SHA" ]] || stop "$pod 的 seed 校验失败"
done
keeper_identity() {
  k -n "$NS" get pod keeper-rwo -o json | jq -ceS --arg node "$NODE" '
    select(.spec.nodeName==$node and .status.phase=="Running") | . as $p |
    .status.containerStatuses[] | select(.name=="probe" and .ready) |
    {uid:$p.metadata.uid,node:$p.spec.nodeName,containerID:.containerID}'
}
keeper_identity > "$OUT/keeper-before.json"
WRITER_UID=$(k -n "$NS" get pod writer-rwo -o json | jq -er --arg run "$RUN_ID" --arg node "$NODE" '
  select(.metadata.labels["sbk-storage-probe"]==$run and .spec.nodeName==$node) | .metadata.uid')
[[ $(k get ns "$NS" -o jsonpath='{.metadata.uid}') == "$NS_UID" &&
   $(k -n "$NS" get pod writer-rwo -o jsonpath='{.metadata.uid}') == "$WRITER_UID" ]] ||
  stop '删除前身份核对失败'
if ! k -n "$NS" delete pod writer-rwo --wait=true --timeout=30s; then
  k -n "$NS" get pod writer-rwo -o json | jq '{
    uid:.metadata.uid, deletionTimestamp:.metadata.deletionTimestamp,
    deletionGracePeriodSeconds:.metadata.deletionGracePeriodSeconds,
    terminationGracePeriodSeconds:.spec.terminationGracePeriodSeconds,
    finalizers:.metadata.finalizers, phase:.status.phase,
    containers:[.status.containerStatuses[]? | {name,ready,state}]
  }' | tee "$OUT/writer-termination.json" >&2 || true
  stop '未确认测试 writer 已完成删除'
fi
volume_identity "$RWO_HANDLE" > "$OUT/rwo-after.json"
keeper_identity > "$OUT/keeper-after.json"
cmp "$OUT/rwo-before.json" "$OUT/rwo-after.json"
cmp "$OUT/keeper-before.json" "$OUT/keeper-after.json"
[[ $(seed keeper-rwo) == "$SEED_SHA" ]] || stop 'keeper 未能读回原卷'

for key in CTX LH_NS SC_RWO SC_RWX SNAP_CLASS TOOL_IMAGE RUN_ID NS NONCE OUT NS_UID NODE NODE_BOOT RWX_HANDLE RWO_HANDLE SEED_SHA; do
  printf 'export %s=%q\n' "$key" "${!key}"
done > "$OUT/run.env"
trap - EXIT
jq -n --arg node "$NODE" --arg ns "$NS" --arg out "$OUT" --arg rwo "$RWO_HANDLE" --arg rwx "$RWX_HANDLE" \
  '{status:"BOTH_HEALTHY_KEEPER_OK",node:$node,namespace:$ns,out:$out,rwo:$rwo,rwx:$rwx}'
)
