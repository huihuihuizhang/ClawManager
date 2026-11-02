#!/usr/bin/env bash
# Supplemental owned-fixture checks. No page or production acceptance.
set -euo pipefail
umask 077
[[ $# = 3 ]] || { echo 'expected private credentials, independent UUID and NEW log directory' >&2; exit 64; }
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
credentials=$1
server_uuid=$2
logs=$3
[[ $(uname -s) = Linux && $(uname -m) = x86_64 ]] || exit 64
[[ $credentials = /* && -f $credentials && ! -L $credentials && $logs = /* && ! -e $logs && ! -L $logs ]] || exit 64
[[ $(stat -c '%a' -- "$credentials") = 600 || $(stat -c '%a' -- "$credentials") = 400 ]] || exit 64
[[ $server_uuid =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] || exit 64
[[ ${A_PERMIT_NATIVE_SCRATCH:-} = /* && -d $A_PERMIT_NATIVE_SCRATCH && ! -L $A_PERMIT_NATIVE_SCRATCH ]] || exit 64
(cd -- "$bundle" && sha256sum --check --strict SHA256SUMS >/dev/null)
scratch=$(cd -- "$A_PERMIT_NATIVE_SCRATCH" && pwd -P)
work=$(mktemp -d "$scratch/owner-source-native.XXXXXXXX")
printf '%s\n' 'supervisor-owner-source-native-v1' > "$work/.owner"
cleanup() {
  local resolved
  [[ ! -L $work ]] && resolved=$(realpath -e -- "$work") &&
    [[ $resolved = "$work" && $(dirname -- "$resolved") = "$scratch" && $(basename -- "$resolved") = owner-source-native.???????? ]] &&
    [[ $(cat -- "$resolved/.owner") = supervisor-owner-source-native-v1 ]] || return 1
  rm -rf -- "$resolved" || return 1
  [[ ! -e $resolved && ! -L $resolved ]]
}
on_exit() {
  local original_rc=$? cleanup_rc=0
  trap - EXIT
  set +e
  if cleanup; then :; else cleanup_rc=$?; fi
  if [[ -d $logs ]]; then
    printf '%s\n' "$original_rc" > "$logs/run-original-exit-code.txt" || cleanup_rc=1
    printf '%s\n' "$cleanup_rc" > "$logs/run-cleanup-exit-code.txt" || cleanup_rc=1
  fi
  if [[ $original_rc -ne 0 ]]; then exit "$original_rc"; fi
  exit "$cleanup_rc"
}
trap on_exit EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
mkdir -m 700 -- "$logs"
mkdir -p -- "$work/bin" "$work/tmp" "$work/backend/internal/systembackupexecution" "$work/backend/internal/systembackupinstallationowner/install"
cp -- "$bundle/bin/execution.test" "$bundle/bin/owner.test" "$work/bin/"
cp -R -- "$bundle/backend/." "$work/backend/"
cp -R -- "$bundle/contracts" "$work/"
cp -- "$bundle/SOURCE_REVIEW.json" "$bundle/SOURCE_FILES.sha256" "$bundle/SHA256SUMS" "$logs/"
chmod 700 -- "$work/bin/execution.test" "$work/bin/owner.test"
: > "$logs/native.log"
owner_tests='TestOwnerAuthorityNativeTLSMySQLLifecycle|TestOwnerAuthorityGenerateIssuerCreateOnlyRawFormat|TestOwnerAuthorityGenerateIssuerCollisionLeavesOnlyOriginal|TestSourceMaterialAuthenticatedIssuerSignsExactOriginalScope|TestSourceMaterialIssuerRejectsUnauthenticatedOrDifferentOriginalInputs'
execution_tests='TestSourceDependenciesIndependentAllRunningTLSMySQL|TestSourceDependenciesIndependentEmptyTLSMySQL|TestSourceDependenciesIndependentOriginalDriftTLSMySQL|TestProductionMaterialWriteRequiresPrivateDistinctExactFiles|TestMinIOEffectiveSelfPolicyActualFiveCredentialGETs|TestMinIOEffectiveOwnerCurrentRevocableSourceWithoutEngineDeclaration'
result=0
run_phase() {
  local phase=$1 directory=$2 timeout=$3 selected=$4
  local -a codes
  set +e
  (
    cd -- "$work/backend/internal/$directory" || exit 64
    env -i PATH="$PATH" LANG=C TZ=UTC GOMAXPROCS=2 TMPDIR="$work/tmp" \
      TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS="$credentials" \
      A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID="$server_uuid" \
      "$work/bin/$phase.test" -test.v -test.count=1 -test.parallel=1 "-test.timeout=$timeout" "-test.run=^($selected)$"
  ) 2>&1 | tee "$logs/$phase.log" | tee -a "$logs/native.log"
  codes=("${PIPESTATUS[@]}")
  set -e
  printf '%s\n' "${codes[*]}" > "$logs/$phase-exit-codes.txt"
  if [[ ${codes[0]} -ne 0 || ${codes[1]} -ne 0 || ${codes[2]} -ne 0 ]]; then result=1; fi
}
run_phase owner systembackupinstallationowner/install 5m "$owner_tests"
run_phase execution systembackupexecution 10m "$execution_tests"
set +e
python3 -B - "$logs" "$owner_tests" "$execution_tests" <<'VERIFY'
import json
from pathlib import Path
import re
import sys
root = Path(sys.argv[1])
phases = {}
for phase, selected in zip(('owner', 'execution'), sys.argv[2:]):
    text = (root / (phase + '.log')).read_text(errors='replace')
    expected = set(selected.split('|'))
    actual = re.findall(r'^--- PASS: (Test\w+) \(', text, re.M)
    codes = (root / (phase + '-exit-codes.txt')).read_text().split()
    accepted = (len(actual) == len(expected) and set(actual) == expected
                and not re.search(r'^\s*--- (?:FAIL|SKIP):', text, re.M)
                and codes == ['0', '0', '0'] and '\nPASS\n' in '\n' + text)
    phases[phase] = {'expected': sorted(expected), 'observed_pass': actual,
                     'pipeline_exit_codes': codes, 'accepted': accepted}
accepted = all(item['accepted'] for item in phases.values())
report = {'scope': 'isolated fixture DATA only', 'phases': phases,
          'accepted': accepted, 'full_page_acceptance': False,
          'production_minio_verified': False, 'disaster_recovery_qualified': False}
(root / 'selected-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'supplemental_selected_tests_passed': accepted,
                  'full_page_acceptance': False}))
sys.exit(0 if accepted else 1)
VERIFY
verify_rc=$?
set -e
if [[ $result -ne 0 || $verify_rc -ne 0 ]]; then exit 1; fi
echo 'Supplemental owner/source fixture checks passed; production/page acceptance remains unverified.'
