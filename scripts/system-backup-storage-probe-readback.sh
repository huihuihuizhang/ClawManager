#!/usr/bin/env bash
# Validate the one recorded R3 cut, then read and reclaim its two clones.
set -euo pipefail
umask 077

stop() { printf 'UNVERIFIED: %s\n' "$*" >&2; exit 3; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 4; }
[[ $# == 1 && $1 =~ ^/var/tmp/sbk-thaw-calibration\.[A-Za-z0-9]{8}/sbk-storage-probe-[0-9a-f]{32}/run\.env$ ]] ||
  stop 'usage: system-backup-storage-probe-readback.sh /absolute/run.env'
run_dir=${1%/*}
[[ $(hostname -s) == k8s-master && ! -L $run_dir && ! -L $1 && $(stat -c %u:%a -- "$run_dir") == 0:700 ]] ||
  stop 'prepared run directory is not private or on k8s-master'
source "$1"
[[ $OUT == "$run_dir" && ${OUT##*/} == "$NS" && $RUN_ID =~ ^[0-9a-f]{32}$ && $NS == sbk-storage-probe-$RUN_ID &&
   $CTX == kubernetes-admin@kubernetes && $LH_NS == longhorn-system && $NODE == node1 &&
   $SC_RWO == longhorn && $RWO_HANDLE =~ ^pvc-[0-9a-f-]{36}$ && $RWX_HANDLE =~ ^pvc-[0-9a-f-]{36}$ &&
   $RWO_HANDLE != "$RWX_HANDLE" && $SEED_SHA =~ ^[0-9a-f]{64}$ ]] || stop 'prepared run identity mismatch'
E=$OUT/cut-attempt
R=$OUT/readback
DIR=/var/tmp/sbk-storage-probe-$RUN_ID
k() { kubectl --context "$CTX" "$@"; }
lh() { k -n "$LH_NS" "$@"; }
same_namespace() { [[ $(k get ns "$NS" -o jsonpath='{.metadata.uid}') == "$NS_UID" ]]; }
same_namespace && [[ $(k get node "$NODE" -o jsonpath='{.status.nodeInfo.bootID}') == "$NODE_BOOT" ]] ||
  stop 'namespace or node boot changed'
[[ $(cat "$E/cut-result.txt") == READY_OBSERVED && $(cat "$E/mount-result.txt") == MOUNT_IDENTITY=unchanged ]] ||
  stop 'cut or mount identity unconfirmed'
jq -es --arg boot "$NODE_BOOT" '
  any(.[]; .status=="WINDOW_OBSERVED" and .boot_id==$boot and .trace_cleanup_complete==true) and
  all(.[]; .status!="UNVERIFIED" and (.status|startswith("FAIL_")|not))
' "$E/trace.jsonl" >/dev/null || stop 'continuous window evidence incomplete'
group=$(jq -er 'select(.status=="TRACE_SESSION") | .group | select(test("^sbk_[0-9a-f]{32}$"))' "$E/trace.jsonl")
[[ $group =~ ^sbk_[0-9a-f]{32}$ ]] || stop 'trace session not unique'

for pod in resume-rwo writer-rwx; do
  hash=$(k --request-timeout=15s -n "$NS" exec "$pod" -- sh -ec '
    test "$(cat /source/resumed)" = resumed; sha256sum /source/seed
  ' | cut -d ' ' -f1)
  [[ $hash == "$SEED_SHA" ]] || stop "source readback changed: $pod"
done

mkdir -m 700 -- "$R" || stop 'readback attempt already recorded'
pvs=()
handles=()
contents=()
backends=()
for v in rwo rwx; do
  if [[ $v == rwo ]]; then handle=$RWO_HANDLE; else handle=$RWX_HANDLE; fi
  pvc_uid=$(jq -er .metadata.uid "$OUT/$v-pvc.json")
  pv=$(jq -er .metadata.name "$OUT/$v-pv.json")
  k -n "$NS" get pvc "source-$v" -o json | jq -e --arg uid "$pvc_uid" --arg pv "$pv" '
    .metadata.uid==$uid and .spec.volumeName==$pv
  ' >/dev/null || stop "source PVC changed: $v"
  k get pv "$pv" -o json | jq -e --arg ns "$NS" --arg uid "$pvc_uid" --arg h "$handle" '
    .spec.claimRef.namespace==$ns and .spec.claimRef.uid==$uid and .spec.csi.volumeHandle==$h and
    .spec.csi.driver=="driver.longhorn.io" and .spec.persistentVolumeReclaimPolicy=="Delete"
  ' >/dev/null || stop "source PV changed: $v"
  cmp -s "$E/$v-engine-before.json" "$E/$v-engine-after.json" || stop "engine changed during cut: $v"
  k -n "$NS" get volumesnapshot "cut-$v" -o json > "$R/$v-snapshot.json"
  jq -e --arg uid "$(jq -er .metadata.uid "$E/$v-snapshot.json")" --arg claim "source-$v" '
    .metadata.uid==$uid and .metadata.deletionTimestamp==null and .spec.source.persistentVolumeClaimName==$claim and
    .status.readyToUse==true and .status.error==null and (.status.creationTime | type=="string" and length>0)
  ' "$R/$v-snapshot.json" >/dev/null || stop "snapshot binding changed: $v"
  content=$(jq -er '.status.boundVolumeSnapshotContentName | select(length>0)' "$R/$v-snapshot.json")
  k get volumesnapshotcontent "$content" -o json > "$R/$v-content.json"
  snapshot_handle=$(jq -er --arg ns "$NS" --arg name "cut-$v" --arg volume "$handle" \
    --arg ref "$(jq -er .metadata.uid "$R/$v-snapshot.json")" --arg uid "$(jq -er .metadata.uid "$E/$v-content.json")" '
      select(.metadata.uid==$uid and .metadata.deletionTimestamp==null and .spec.driver=="driver.longhorn.io" and
        .spec.volumeSnapshotRef.namespace==$ns and .spec.volumeSnapshotRef.name==$name and .spec.volumeSnapshotRef.uid==$ref and
        .spec.source.volumeHandle==$volume and .spec.deletionPolicy=="Delete" and .status.readyToUse==true and .status.error==null)
      | .status.snapshotHandle | select(startswith("snap://"+$volume+"/"))
  ' "$R/$v-content.json") || stop "snapshot content identity not verified: $v"
  backend=${snapshot_handle##*/}
  [[ $backend =~ ^snapshot-[a-zA-Z0-9-]+$ ]] || stop "backend snapshot name unconfirmed: $v"
  lh get snapshots.longhorn.io "$backend" -o json > "$R/$v-backend.json"
  jq -e --arg h "$handle" --arg uid "$(jq -er .metadata.uid "$E/$v-backend-snapshot.json")" '
    .metadata.uid==$uid and .spec.volume==$h and .status.readyToUse==true and
    (.status.markRemoved // false)==false and (.status.error // "")=="" and (.status.creationTime | type=="string" and length>0)
  ' "$R/$v-backend.json" >/dev/null || stop "backend snapshot not proven: $v"
  engine=$(jq -er .name "$E/$v-engine-before.json")
  lh get engines.longhorn.io "$engine" -o json |
    jq -ce --arg uid "$(jq -er .uid "$E/$v-engine-before.json")" --arg h "$handle" --arg snap "$backend" \
      --arg created "$(jq -er .status.creationTime "$R/$v-backend.json")" '
      select(.metadata.uid==$uid and .spec.volumeName==$h and .status.currentState=="running")
      | .status.snapshots[$snap] | select(.created==$created and (.removed // false)==false)
    ' > "$R/$v-engine-snapshot.json" || stop "engine snapshot metadata not proven: $v"
  grep -F -- "$handle" "$E/$v-engine-cut.log" | grep -F -- "$backend" | awk '
    NR==1 && /Starting snapshot/ { started=1 }
    NR==2 && /Finished snapshot/ { finished=1 }
    END { exit !(NR==2 && started && finished) }
  ' || stop "unique backend start and completion not proven: $v"
  printf 'BACKEND_COMPLETION_OK %s %s\n' "$v" "$backend"
  cat -- "$E/$v-engine-cut.log"
  pvs+=("$pv")
  handles+=("$handle")
  contents+=("$content")
  backends+=("$backend")
  printf '%s\n' "$backend" > "$R/$v-backend-name.txt"
done

# One additional reader Pod at a time on the already selected node.
for v in rwo rwx; do
  same_namespace || stop 'namespace changed before clone'
  if [[ $v == rwo ]]; then handle=$RWO_HANDLE; else handle=$RWX_HANDLE; fi
  backend=$(cat "$R/$v-backend-name.txt")
  jq -n --arg ns "$NS" --arg class "$SC_RWO" --arg v "$v" --arg image "$TOOL_IMAGE" --arg node "$NODE" --arg run "$RUN_ID" '
    def meta($name): {name:$name,namespace:$ns,labels:{"sbk-storage-probe":$run}};
    {apiVersion:"v1",kind:"List",items:[
      {apiVersion:"v1",kind:"PersistentVolumeClaim",metadata:meta("clone-"+$v),
       spec:{storageClassName:$class,accessModes:["ReadWriteOnce"],resources:{requests:{storage:"1Gi"}},
             dataSource:{apiGroup:"snapshot.storage.k8s.io",kind:"VolumeSnapshot",name:("cut-"+$v)}}},
      {apiVersion:"v1",kind:"Pod",metadata:meta("read-"+$v),
       spec:{nodeName:$node,automountServiceAccountToken:false,restartPolicy:"Never",terminationGracePeriodSeconds:5,
             containers:[{name:"probe",image:$image,command:["sh","-ec","while :; do sleep 60; done"],
                          securityContext:{runAsUser:0,allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}},
                          volumeMounts:[{name:"source",mountPath:"/source",readOnly:true}]}],
             volumes:[{name:"source",persistentVolumeClaim:{claimName:("clone-"+$v),readOnly:true}}]}}]}
  ' > "$R/$v-clone.json"
  k create -f "$R/$v-clone.json"
  k -n "$NS" wait --for=condition=Ready "pod/read-$v" --timeout=180s
  k -n "$NS" get pvc "clone-$v" -o json > "$R/$v-pvc.json"
  clone_uid=$(jq -er .metadata.uid "$R/$v-pvc.json")
  pv=$(jq -er '.spec.volumeName | select(length>0)' "$R/$v-pvc.json")
  k get pv "$pv" -o json > "$R/$v-pv.json"
  clone=$(jq -er --arg ns "$NS" --arg uid "$clone_uid" '
    select(.spec.claimRef.namespace==$ns and .spec.claimRef.uid==$uid and .spec.csi.driver=="driver.longhorn.io" and
           .spec.persistentVolumeReclaimPolicy=="Delete") | .spec.csi.volumeHandle | select(test("^pvc-[0-9a-f-]{36}$"))
  ' "$R/$v-pv.json")
  for existing in "${handles[@]}"; do [[ $clone != "$existing" ]] || stop 'clone shares existing volume handle'; done
  if ! lh wait --for=jsonpath='{.status.cloneStatus.state}'=completed "volumes.longhorn.io/$clone" --timeout=120s; then
    lh get volumes.longhorn.io "$clone" -o json > "$R/$v-volume.json"
    jq '{cloneStatus:.status.cloneStatus, robustness:.status.robustness, conditions:.status.conditions}' "$R/$v-volume.json"
    if jq -e '.status.cloneStatus.state=="failed"' "$R/$v-volume.json" >/dev/null; then
      fail "clone reported failed: $v"
    fi
    stop "clone completion not confirmed: $v"
  fi
  lh get volumes.longhorn.io "$clone" -o json > "$R/$v-volume.json"
  if jq -e --arg h "$handle" --arg snap "$backend" '
    .status.cloneStatus as $c | ($c.sourceVolume // "")!="" and ($c.snapshot // "")!="" and
    ($c.sourceVolume!=$h or $c.snapshot!=$snap)
  ' "$R/$v-volume.json" >/dev/null; then
    fail "clone lineage mismatch: $v"
  fi
  jq -e --arg h "$handle" --arg snap "$backend" '
    .status.cloneStatus.sourceVolume==$h and .status.cloneStatus.snapshot==$snap and
    .status.cloneStatus.state=="completed" and .status.robustness=="healthy" and .spec.numberOfReplicas==2
  ' "$R/$v-volume.json" >/dev/null || stop "clone lineage or health not proven: $v"
  readback=$(k --request-timeout=15s -n "$NS" exec "read-$v" -- sh -ec '
    if test -e /source/resumed; then echo POST_THAW_MARKER_PRESENT
    elif test ! -f /source/seed; then echo SEED_MISSING
    else sha256sum /source/seed; fi' | cut -d ' ' -f1) || stop "clone read failed: $v"
  [[ $readback == "$SEED_SHA" ]] || fail "clone content mismatch: $v ($readback)"
  printf 'CLONE_READBACK_OK %s %s\n' "$v" "$clone"
  pvs+=("$pv")
  handles+=("$clone")
  same_namespace || stop 'namespace changed before reader removal'
  k -n "$NS" get pod "read-$v" -o json | jq -e --arg run "$RUN_ID" '
    .metadata.labels["sbk-storage-probe"]==$run' >/dev/null
  k -n "$NS" delete pod "read-$v" --wait=true --timeout=30s
done

same_namespace || stop 'namespace changed before cleanup'
expected_pvcs=$(jq -cs 'map({key:.metadata.name,value:.metadata.uid}) | from_entries' \
  "$OUT/rwo-pvc.json" "$OUT/rwx-pvc.json" "$R/rwo-pvc.json" "$R/rwx-pvc.json")
k -n "$NS" get pvc -o json | jq -e --argjson expected "$expected_pvcs" '
  ([.items[] | {key:.metadata.name,value:.metadata.uid}] | from_entries)==$expected
' >/dev/null || stop 'PVC inventory changed before cleanup'
k -n "$NS" get pod -o json | jq -e --arg run "$RUN_ID" '
  all(.items[]; .metadata.labels["sbk-storage-probe"]==$run and
    (.metadata.name=="keeper-rwo" or .metadata.name=="resume-rwo" or .metadata.name=="writer-rwx"))
' >/dev/null || stop 'foreign objects found in probe namespace'
expected_snapshots=$(jq -cs 'map({key:.metadata.name,value:.metadata.uid}) | from_entries' \
  "$R/rwo-snapshot.json" "$R/rwx-snapshot.json")
k -n "$NS" get volumesnapshots -o json | jq -e --argjson expected "$expected_snapshots" '
  ([.items[] | {key:.metadata.name,value:.metadata.uid}] | from_entries)==$expected
' >/dev/null || stop 'snapshot inventory changed before cleanup'
k delete namespace "$NS" --wait=true --timeout=180s
for i in {1..40}; do
  pv_left=$(k get pv "${pvs[@]}" --ignore-not-found -o name)
  content_left=$(k get volumesnapshotcontent "${contents[@]}" --ignore-not-found -o name)
  volume_left=$(lh get volumes.longhorn.io "${handles[@]}" --ignore-not-found -o name)
  snapshot_left=$(lh get snapshots.longhorn.io "${backends[@]}" --ignore-not-found -o name)
  [[ -z $pv_left && -z $content_left && -z $volume_left && -z $snapshot_left ]] && break
  sleep 3
done
if [[ -n $pv_left || -n $content_left || -n $volume_left || -n $snapshot_left ]]; then
  printf 'CLEANUP_PENDING\n%s\n%s\n%s\n%s\n' "$pv_left" "$content_left" "$volume_left" "$snapshot_left"
  exit 3
fi
printf 'CLUSTER_CLEANUP_OK\n'

ip=$(k get node "$NODE" -o json | jq -er '
  [.status.addresses[]|select(.type=="InternalIP" and (.address|test("^[0-9.]+$")))|.address]
  | if length==1 then .[0] else error("IPv4 not unique") end')
ssh -T -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "root@$ip" bash -s -- "$DIR" "$NODE_BOOT" "$group" <<'REMOTE'
set -euo pipefail
d=$1
[[ $(hostname -s) == node1 && $(cat /proc/sys/kernel/random/boot_id) == "$2" &&
   $d =~ ^/var/tmp/sbk-storage-probe-[0-9a-f]{32}$ && ! -L $d && $(stat -c %u:%a -- "$d") == 0:700 ]]
[[ $3 =~ ^sbk_[0-9a-f]{32}$ && ! -e /sys/kernel/tracing/instances/$3 ]]
probe_defs=$(cat /sys/kernel/tracing/kprobe_events)
[[ $probe_defs != *"$3/"* ]]
for v in rwo rwx; do
  [[ $(cat "$d/$v/exit-code") == 0 && -s $d/$v/thaw-acknowledged ]]
  rm -f -- "$d/$v/"{exit-code,parent.pid,watchdog.pid,held,freeze.pid,release,unfreeze.pid,thaw-acknowledged}
  rmdir -- "$d/$v"
done
rm -f -- "$d/trace/"{armed,start,ready,release,stop}
rmdir -- "$d/trace"
rm -f -- "$d/"{system-backup-ext4-freeze-trace.py,system-backup-storage-probe-lease.sh,trace-calibration.jsonl,locate.py,payload.sha256,rwo-mount.json,rwx-mount.json,trace.jsonl,rwo.log,rwx.log}
rmdir -- "$d"
printf 'NODE1_CLEANUP_OK\n'
REMOTE
printf 'STORAGE_PROBE_PASS evidence=%s\n' "$R"
