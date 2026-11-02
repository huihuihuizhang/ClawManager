#!/usr/bin/env bash
# Reviewed isolated diagnostic delivery. No existing namespace/image changes.
set -euo pipefail
umask 077
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
archive="$base/clawmanager-native-51181049.tar.gz"
archive_sha='266197f53f21f4ac8cdc3c0c079499ab298531005520e706d8e3054bf664d64c'
[[ $(uname -s) = Linux && $(uname -m) = x86_64 ]] || { echo 'Linux x86_64 is required; no resources created.' >&2; exit 64; }
for tool in python3 kubectl sha256sum realpath mktemp tar; do command -v "$tool" >/dev/null; done
[[ -f $archive && ! -L $archive ]] || { echo 'Place the pinned archive beside this script.' >&2; exit 64; }
printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum --check --strict -
scratch_base=$(realpath -e -- "${TMPDIR:-/tmp}")
work=$(mktemp -d "$scratch_base/clawmanager-native-51181049.XXXXXXXX")
work=$(realpath -e -- "$work")
logs=''
cleanup() {
  local cleanup_rc=0 resolved actual_sha
  if [[ ! -L $work ]] && resolved=$(realpath -e -- "$work") &&
     [[ $resolved = "$work" && $(dirname -- "$resolved") = "$scratch_base" && $(basename -- "$resolved") = clawmanager-native-51181049.???????? ]]; then
    if ! rm -rf -- "$resolved"; then cleanup_rc=1; fi
    if [[ -e $resolved || -L $resolved ]]; then cleanup_rc=1; fi
  else
    echo "Refusing changed delivery-work cleanup: $work" >&2
    cleanup_rc=1
  fi
  # Only erase the same verified build artifact; never a replaced/new file.
  if [[ -f $archive && ! -L $archive && $(dirname -- "$archive") = "$base" ]]; then
    if actual_sha=$(sha256sum -- "$archive") && [[ ${actual_sha%% *} = "$archive_sha" ]]; then
      if ! rm -- "$archive"; then cleanup_rc=1; fi
    else
      echo 'Archive changed; refusing to remove replacement.' >&2
      cleanup_rc=1
    fi
  else
    echo 'Archive is missing/redirected; artifact erasure unconfirmed.' >&2
    cleanup_rc=1
  fi
  return "$cleanup_rc"
}
on_exit() {
  local original_rc=$? cleanup_rc=0
  trap - EXIT
  set +e
  if cleanup; then :; else cleanup_rc=$?; fi
  if [[ -n $logs && -d $logs ]]; then
    if ! printf '%s\n' "$original_rc" > "$logs/entry-exit-code.txt"; then cleanup_rc=1; fi
    if ! printf '%s\n' "$cleanup_rc" > "$logs/delivery-cleanup-exit-code.txt"; then cleanup_rc=1; fi
    printf 'review_logs=%s\nentry_exit=%s\ndelivery_cleanup_exit=%s\n' "$logs" "$original_rc" "$cleanup_rc"
  fi
  if [[ $original_rc -ne 0 ]]; then exit "$original_rc"; fi
  exit "$cleanup_rc"
}
trap on_exit EXIT
logs=$(mktemp -d "$base/clawmanager-native-logs-51181049.XXXXXXXX")
printf 'review_logs=%s\n' "$logs"
tar -xzf "$archive" -C "$work"
package="$work/clawmanager-native-51181049"
(cd -- "$package" && sha256sum --check --strict DELIVERY_SHA256SUMS >/dev/null)
mkdir -m 700 -- "$work/scratch"
printf '%s\n' 'Starting owned Kubernetes TLS fixture; native test timeout is 15 minutes plus startup/cleanup. Details: native-entry.log'
set +e
python3 -B "$package/tools/system-backup-d-kube-mysql-fixture.py" \
  --bundle "$package/bundle" --scratch "$work/scratch" --logs "$logs/fixture" \
  --context 'kubernetes-admin@kubernetes' \
  --mysql-image '10.130.14.23:5000/mysql@sha256:5ea882b1859d3a61814e527215563d809a9f2bf70ffa24c9280f2ff6798f1977' \
  --port 0 --cleanup-timeout 90 >"$logs/native-entry.log" 2>&1
test_rc=$?
set -e
report_rc=0
if [[ -f $logs/fixture/fixture.json ]]; then
  if ! cat -- "$logs/fixture/fixture.json"; then report_rc=1; fi
fi
set +e
python3 -B - "$logs" <<'SUMMARY'
import json
from pathlib import Path
import re
import sys
root = Path(sys.argv[1])
native = root / 'fixture/diagnostic/native.log'
if native.is_file():
    for line in native.read_text(errors='replace').splitlines():
        match = re.search(r'cumulative elapsed/count/failure DATA capture-database (\{.*\})', line)
        if match:
            facts = json.loads(match.group(1))['KeyCheck']
            print(json.dumps({'database_key_check': facts}))
        elif re.search(r'^--- (PASS|FAIL): TestAPermit|stage=database-|retained failed original SQL namespace', line):
            print(line[:1024])
print('Fixture data only; full_page_acceptance=false')
SUMMARY
summary_rc=$?
set -e
if [[ $test_rc -ne 0 ]]; then exit "$test_rc"; fi
if [[ $report_rc -ne 0 ]]; then exit "$report_rc"; fi
exit "$summary_rc"
