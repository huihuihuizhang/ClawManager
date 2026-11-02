#!/usr/bin/env bash
# Offline delivery dispatch only. The independently reviewed release must
# contain three owner tools and SOURCE_COMMIT, all pinned by SHA256SUMS.
set -euo pipefail
umask 077

fail() { printf '%s\n' 'Owner delivery rejected; inspect the selected release and original inputs.' >&2; exit 1; }
[[ $# -ge 4 ]] || fail
release=$1
expected_commit=$2
expected_manifest=$3
action=$4
shift 4
[[ "$release" = /* && "$expected_commit" =~ ^[a-f0-9]{40}$ && "$expected_manifest" =~ ^[a-f0-9]{64}$ ]] || fail
[[ -d "$release" && ! -L "$release" ]] || fail
release=$(realpath -- "$release") || fail
[[ -f "$release/SHA256SUMS" && ! -L "$release/SHA256SUMS" ]] || fail
actual_manifest=$(sha256sum -- "$release/SHA256SUMS") || fail
[[ "${actual_manifest%% *}" = "$expected_manifest" ]] || fail

# No manifest entry may escape the selected package or execute a new name.
awk '
  !/^[a-f0-9]+  (SOURCE_COMMIT|system-backup-owner-enroll|system-backup-owner-authority|system-backup-source-materials)$/ { exit 1 }
  length($1) != 64 || seen[$2]++ { exit 1 }
  END { if (NR != 4) exit 1 }
' "$release/SHA256SUMS" || fail
for name in SOURCE_COMMIT system-backup-owner-enroll system-backup-owner-authority system-backup-source-materials; do
  [[ -f "$release/$name" && ! -L "$release/$name" ]] || fail
done
(cd -- "$release" && sha256sum --check --strict --status SHA256SUMS) || fail
[[ $(wc -c < "$release/SOURCE_COMMIT") -eq 41 ]] || fail
IFS= read -r actual_commit < "$release/SOURCE_COMMIT" || fail
[[ "$actual_commit" = "$expected_commit" ]] || fail
case "$action" in
  enroll) binary=system-backup-owner-enroll ;;
  authority) binary=system-backup-owner-authority ;;
  materials) binary=system-backup-source-materials ;;
  *) fail ;;
esac
[[ -x "$release/$binary" ]] || fail
exec "$release/$binary" "$@"
