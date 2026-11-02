#!/usr/bin/env bash
# Reviewer builds the ELF once; this step only stages runtime inputs.
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source_paths() { find backend contracts scripts -type f -print0 | LC_ALL=C sort -zu; }
if [[ $# = 2 && $1 = --snapshot ]]; then
  receipt=$2
  [[ $receipt = /* && ! -e $receipt && -d $(dirname -- "$receipt") ]] || { echo 'snapshot requires a NEW absolute directory with an existing parent' >&2; exit 64; }
  receipt_parent=$(cd -- "$(dirname -- "$receipt")" && pwd -P)
  [[ $receipt_parent != "$repo" && $receipt_parent != "$repo/"* ]] || { echo 'source receipt must be outside the source tree' >&2; exit 64; }
  mkdir -m 700 -- "$receipt"
  (
    cd -- "$repo"
    git rev-parse HEAD > "$receipt/SOURCE_COMMIT"
    git status --porcelain=v1 --untracked-files=normal > "$receipt/SOURCE_STATUS"
    if [[ -s $receipt/SOURCE_STATUS ]]; then printf 'dirty\n'; else printf 'clean\n'; fi > "$receipt/SOURCE_STATE"
    # Hash actual files, including dirty/untracked/ignored Go and embed inputs,
    # rather than assuming git HEAD is the complete filesystem build input.
    [[ -z $(find backend contracts scripts -type l -print -quit) ]] || { echo 'redirected source tree refused' >&2; exit 1; }
    source_paths > "$receipt/SOURCE_PATHS.nul"
    while IFS= read -r -d '' source_path; do
      [[ -f $source_path && ! -L $source_path ]] || { echo 'nonregular/redirected source input refused' >&2; exit 1; }
      sha256sum -- "$source_path"
    done < "$receipt/SOURCE_PATHS.nul" > "$receipt/SOURCE_FILES.sha256"
  )
  echo 'source snapshot recorded; reviewer must bind this receipt to the actual build before packaging'
  exit 0
fi
[[ $# = 4 ]] || { echo 'usage: package.sh /absolute/reviewed-linux-amd64.test /absolute/new-bundle-dir full-source-commit /absolute/source-receipt-dir (or --snapshot /absolute/new-receipt-dir BEFORE build)' >&2; exit 64; }
binary=$1
out=$2
commit=$3
receipt=$4
[[ $binary = /* && -f $binary && $out = /* && ! -e $out && $commit =~ ^[a-f0-9]{40}$ ]] || { echo 'absolute reviewed binary, NEW bundle path and exact commit required' >&2; exit 64; }
[[ -d $(dirname -- "$out") ]] || { echo 'bundle parent must already exist' >&2; exit 64; }
out_parent=$(cd -- "$(dirname -- "$out")" && pwd -P)
[[ $out_parent != "$repo" && $out_parent != "$repo/"* ]] || { echo 'bundle output must be outside the source tree' >&2; exit 64; }
[[ $receipt = /* && -d $receipt && $(cat "$receipt/SOURCE_COMMIT") = "$commit" ]] || { echo 'build source receipt/commit missing or mismatched' >&2; exit 64; }
[[ $(cat "$receipt/SOURCE_STATE") = clean || $(cat "$receipt/SOURCE_STATE") = dirty ]] || { echo 'explicit clean/dirty declaration required' >&2; exit 64; }
if [[ -s $receipt/SOURCE_STATUS ]]; then expected_state=dirty; else expected_state=clean; fi
[[ $(cat "$receipt/SOURCE_STATE") = "$expected_state" ]] || { echo 'clean/dirty declaration contradicts recorded status' >&2; exit 64; }
(
  cd -- "$repo"
  [[ $(git rev-parse HEAD) = "$commit" ]]
  [[ -z $(find backend contracts scripts -type l -print -quit) ]]
  cmp -- "$receipt/SOURCE_STATUS" <(git status --porcelain=v1 --untracked-files=normal)
  cmp -- "$receipt/SOURCE_PATHS.nul" <(source_paths)
  sha256sum --check --strict "$receipt/SOURCE_FILES.sha256" >/dev/null
)
# Do not package a binary built before D installs the real original context hook.
grep -Fq 'WithProviderPermitTiming' "$repo/backend/internal/systembackupexecution/production_same_task_mysql_test.go"
grep -Fq 'provider-permit-stage-timing DATA' "$repo/backend/internal/systembackupexecution/production_same_task_mysql_test.go"
[[ $(od -An -tx1 -N4 -- "$binary" | tr -d ' \n') = 7f454c46 ]] || { echo 'reviewed input must be an ELF testbinary' >&2; exit 64; }
grep -aFq 'provider-permit-stage-timing DATA' "$binary"
grep -aFq 'TestAPermitTimingOriginalThirtySecondNativeMySQL' "$binary"
grep -aFq "$commit" "$binary"
mkdir -p -- "$out/bin" "$out/backend/internal/systembackupexecution" "$out/backend/internal/systembackupbusinessa/testdata" "$out/contracts/system-backup/v12"
cp -- "$binary" "$out/bin/systembackupexecution.test"
cp -- "$repo/backend/internal/systembackupbusinessa/testdata/schema-registry-historical-15.json" "$out/backend/internal/systembackupbusinessa/testdata/"
cp -- "$repo/contracts/system-backup/v12/admin-control-redacted-examples.json" "$out/contracts/system-backup/v12/"
cp -- "$repo/scripts/system-backup-a-permit-native-run.sh" "$out/run-diagnostic.sh"
cp -- "$repo/scripts/system-backup-a-permit-native-disposable.sh" "$out/run-disposable.sh"
for evidence in SOURCE_COMMIT SOURCE_STATUS SOURCE_STATE SOURCE_PATHS.nul SOURCE_FILES.sha256; do
  cp -- "$receipt/$evidence" "$out/$evidence"
done
chmod 700 -- "$out/bin/systembackupexecution.test" "$out/run-diagnostic.sh" "$out/run-disposable.sh"
(
  cd -- "$out"
  sha256sum bin/systembackupexecution.test backend/internal/systembackupbusinessa/testdata/schema-registry-historical-15.json \
    contracts/system-backup/v12/admin-control-redacted-examples.json run-diagnostic.sh run-disposable.sh \
    SOURCE_COMMIT SOURCE_STATUS SOURCE_STATE SOURCE_PATHS.nul SOURCE_FILES.sha256 > SHA256SUMS
)
echo 'runtime bundle staged; reviewer must pin archive/checksums independently before transfer'
