#!/usr/bin/env bash
# Run only the precompiled, isolated-instance original-task diagnostic.
set -euo pipefail
umask 077
if [[ $# != 3 ]]; then
  echo 'usage: run-diagnostic.sh /absolute/private-credentials.json dedicated-server-uuid /absolute/new-log-directory' >&2
  exit 64
fi
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
credentials=$1
server_uuid=$2
logs=$3
[[ $credentials = /* && -f $credentials && $logs = /* && ! -e $logs ]] || { echo 'absolute credentials and a NEW absolute log directory required' >&2; exit 64; }
[[ $server_uuid =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] || { echo 'independent disposable UUID pin required' >&2; exit 64; }
[[ $(uname -s) = Linux && $(uname -m) = x86_64 ]] || { echo 'bundle requires Linux amd64' >&2; exit 64; }
[[ -n ${A_PERMIT_NATIVE_SCRATCH:-} && $A_PERMIT_NATIVE_SCRATCH = /* && -d $A_PERMIT_NATIVE_SCRATCH ]] || { echo 'set A_PERMIT_NATIVE_SCRATCH to an existing private scratch directory' >&2; exit 64; }
[[ $(stat -c '%a' -- "$credentials") = 600 || $(stat -c '%a' -- "$credentials") = 400 ]] || { echo 'credential file must have mode 0600 or 0400' >&2; exit 64; }
(cd -- "$bundle" && sha256sum --check --strict SHA256SUMS >/dev/null)
scratch=$(cd -- "$A_PERMIT_NATIVE_SCRATCH" && pwd -P)
work=$(mktemp -d "$scratch/a-permit-native.XXXXXXXX")
cleanup() {
  case $work in
    "$scratch"/a-permit-native.????????)
      if [[ -L $work ]] || ! rm -rf -- "$work"; then echo "run work cleanup failed/refused: $work" >&2; return 1; fi ;;
    *) echo 'refusing cleanup outside own scratch' >&2; return 1 ;;
  esac
  if [[ -e $work || -L $work ]]; then echo "RESIDUAL run work: $work" >&2; return 1; fi
}
on_exit() {
  local original_rc=$? cleanup_rc=0
  trap - EXIT
  set +e
  if cleanup; then :; else cleanup_rc=$?; fi
  if [[ -d $logs ]]; then
    if ! printf '%s\n' "$original_rc" > "$logs/run-original-exit-code.txt"; then cleanup_rc=1; fi
    if ! printf '%s\n' "$cleanup_rc" > "$logs/run-cleanup-exit-code.txt"; then cleanup_rc=1; fi
  fi
  if [[ $original_rc -ne 0 ]]; then exit "$original_rc"; fi
  exit "$cleanup_rc"
}
trap on_exit EXIT
mkdir -m 700 -- "$logs"
mkdir -p -- "$work/bin" "$work/backend/internal/systembackupexecution" "$work/backend/internal/systembackupbusinessa/testdata" "$work/contracts/system-backup/v12" "$work/tmp"
cp -- "$bundle/bin/systembackupexecution.test" "$work/bin/"
cp -- "$bundle/backend/internal/systembackupbusinessa/testdata/schema-registry-historical-15.json" "$work/backend/internal/systembackupbusinessa/testdata/"
cp -- "$bundle/contracts/system-backup/v12/admin-control-redacted-examples.json" "$work/contracts/system-backup/v12/"
for evidence in SOURCE_COMMIT SOURCE_STATE SOURCE_STATUS SOURCE_FILES.sha256 SOURCE_PATHS.nul SHA256SUMS; do
  cp -- "$bundle/$evidence" "$logs/"
done
chmod 700 -- "$work/bin/systembackupexecution.test"
export TMPDIR="$work/tmp" GOMAXPROCS=2 GOTELEMETRY=off
export TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS="$credentials"
export A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID="$server_uuid"
set +e
(
  cd -- "$work/backend/internal/systembackupexecution"
  "$work/bin/systembackupexecution.test" -test.v -test.count=1 -test.parallel=1 -test.timeout=15m \
    '-test.run=^TestAPermitTimingOriginalThirtySecondNativeMySQL$'
) 2>&1 | tee "$logs/native.log"
pipeline_status=("${PIPESTATUS[@]}")
status=${pipeline_status[0]}
set -e
log_status=0
if ! printf '%s\n' "$status" > "$logs/test-exit-code.txt"; then echo 'test exit-code log write failed' >&2; log_status=1; fi
if [[ ${pipeline_status[1]} -ne 0 ]]; then echo 'diagnostic log write failed' >&2; log_status=1; fi
if [[ $status -ne 0 ]]; then exit "$status"; fi
if [[ $log_status -ne 0 ]]; then exit "$log_status"; fi
if grep -Eq '^\s*--- SKIP:' "$logs/native.log" || ! grep -Fq 'provider-permit-stage-timing DATA' "$logs/native.log" || ! grep -Fq -- '--- PASS: TestAPermitTimingOriginalThirtySecondNativeMySQL' "$logs/native.log"; then
  echo 'missing actual native PASS/timing context output (or skipped); not accepted' >&2
  exit 1
fi
echo 'native diagnostic passed; this is fixture DATA, not production/page acceptance'
