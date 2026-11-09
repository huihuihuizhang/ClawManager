#!/usr/bin/env bash
# Disposable storage experiment only. Not a production hold/recovery protocol.
# The runbook supplies two new probe PVCs, their actual backend mount and seed.
set -euo pipefail
export LC_ALL=C
[[ $# == 4 && $(id -u) == 0 && $(uname -s) == Linux ]] || exit 2
mount_path=$1
handle=$2
seed_sha=$3
lease_dir=$4
[[ $handle =~ ^pvc-[0-9a-f-]{36}$ && $seed_sha =~ ^[0-9a-f]{64}$ ]] || exit 2
[[ $lease_dir =~ ^/var/tmp/sbk-storage-probe-[0-9a-f]{32}/(rwo|rwx)$ ]] || exit 2
parent_dir=${lease_dir%/*}
[[ -d $parent_dir && ! -L $parent_dir && $(stat -c %u:%a -- "$parent_dir") == 0:700 ]] || exit 2
[[ $mount_path == /* && -d $mount_path && ! -L $mount_path ]] || exit 2
for tool in fsfreeze sha256sum stat date sleep; do command -v "$tool" >/dev/null; done
# These FDs keep this exact mounted filesystem alive even if the SSH closes.
exec 9< "$mount_path"
[[ $(stat -L -c %F /dev/longhorn/"$handle") == 'block special file' ]] || exit 2
[[ $(stat -L -c %d /proc/self/fd/9) == $(stat -L -c %r /dev/longhorn/"$handle") ]] || exit 2
[[ $(stat -L -f -c %t /proc/self/fd/9) == ef53 ]] || exit 2
[[ $(sha256sum /proc/self/fd/9/seed | cut -d ' ' -f 1) == "$seed_sha" ]] || exit 2
mkdir -m 700 -- "$lease_dir" # fail if an earlier experiment exists
lease_parent=$BASHPID
trap 'lease_exit=$?; if [[ $BASHPID == $lease_parent ]]; then printf "%s\n" "$lease_exit" > "$lease_dir/exit-code"; fi' EXIT
[[ $(stat -L -c %d /proc/self/fd/9) != $(stat -c %d "$lease_dir") ]] || exit 2
printf '%s\n' "$$" > "$lease_dir/parent.pid"
sync -f /proc/self/fd/9
freeze_call() (
  # exec keeps this exact TID for correlation. Evidence I/O must not block thaw.
  printf '%s\n' "$BASHPID" > "$lease_dir/$1.pid" || true
  exec fsfreeze "--$1" /proc/self/fd/9
)
(
  # Inherit FD 9; a parent/SSH loss does not change the target of this thaw.
  explicit=0
  for ((tick=0; tick<100; tick++)); do
    if [[ -f $lease_dir/release && -f $lease_dir/held ]]; then explicit=1; break; fi
    sleep 0.2
  done
  if [[ ! -f $lease_dir/held ]]; then
    : > "$lease_dir/no-thaw-dispatched"
    printf '%s\n' 'freeze result unknown; no inverse mutation sent' > "$lease_dir/unknown"
    exit 5
  fi
  if freeze_call unfreeze; then
    date -u +%FT%T.%NZ > "$lease_dir/thaw-acknowledged"
    if [[ $explicit == 1 ]]; then exit 0; fi
    printf '%s\n' 'watchdog used; experiment invalid' > "$lease_dir/timed-out"
    exit 4
  fi
  printf '%s\n' 'thaw result unconfirmed; do not delete Pods or volumes' > "$lease_dir/unknown"
  exit 5
) 9<&9 &
watchdog=$!
printf '%s\n' "$watchdog" > "$lease_dir/watchdog.pid"
if ! freeze_call freeze; then
  printf '%s\n' 'freeze failed/unconfirmed; do not infer success from EBUSY' > "$lease_dir/unknown"
  wait "$watchdog" || true
  exit 5
fi
date -u +%FT%T.%NZ > "$lease_dir/held"
if wait "$watchdog"; then
  [[ -f $lease_dir/thaw-acknowledged && ! -e $lease_dir/unknown && ! -e $lease_dir/timed-out ]]
else
  # The watchdog may have expired just before FIFREEZE acknowledged. Only its
  # explicit non-dispatch record permits this same-parent, same-FD cleanup.
  if [[ -f $lease_dir/no-thaw-dispatched ]]; then
    if freeze_call unfreeze; then
      date -u +%FT%T.%NZ > "$lease_dir/thaw-acknowledged"
    fi
  fi
  exit 5
fi
