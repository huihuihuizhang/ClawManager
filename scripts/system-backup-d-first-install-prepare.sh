#!/usr/bin/env bash
# Reviewable morning PUBLIC-input preparation only. No exec/SQL/Secret reads,
# deployments, accounts, permissions, certificate issuance or config activation.
set -euo pipefail
umask 077
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python_command=${SBK_PUBLIC_INPUTS_PYTHON:-python3}
: "${SBK_PUBLIC_OUTPUT_PARENT:?existing private absolute output directory required}"
: "${SBK_ORIGINAL_OWNER_SUBJECT:?independently retained original Kubernetes owner subject required}"
: "${SBK_ORIGINAL_OWNER_GROUPS_SHA256:?reviewed original owner sorted-groups SHA256 required}"
SBK_MYSQL_SERVICE=${SBK_MYSQL_SERVICE:-mysql}
SBK_MYSQL_DATABASE=${SBK_MYSQL_DATABASE:-clawmanager}
# Historical original comparison pin, never a fresh observation or fixture ID.
SBK_MYSQL_SERVER_UUID=${SBK_MYSQL_SERVER_UUID:-f1f5f76a-95f5-11f1-b08e-366835b4a029}
: "${SBK_MYSQL_SOURCE_ACCOUNT:?DBA-selected existing finite business source account user@host required}"
: "${SBK_MYSQL_CA_SHA256:?independently selected original production CA public file SHA256 required}"
[[ "$SBK_PUBLIC_OUTPUT_PARENT" = /* && -d "$SBK_PUBLIC_OUTPUT_PARENT" && ! -L "$SBK_PUBLIC_OUTPUT_PARENT" ]]
output_parent=$(realpath -- "$SBK_PUBLIC_OUTPUT_PARENT")
output_directory=$(mktemp -d "$output_parent/first-install-public-XXXXXXXX")
printf 'public_input_directory=%s\n' "$output_directory"
if inventory_receipt=$("$python_command" "$script_directory/system-backup-d-first-install-inputs.py" inventory \
  --owner-subject "$SBK_ORIGINAL_OWNER_SUBJECT" --owner-uid "${SBK_ORIGINAL_OWNER_UID:-}" \
  --owner-groups-sha256 "$SBK_ORIGINAL_OWNER_GROUPS_SHA256" --output-directory "$output_directory"); then
  printf '%s\n' "$inventory_receipt"
else
  code=$?
  printf '%s\n' "$inventory_receipt"
  exit "$code"
fi
inventory_sha=$("$python_command" -c 'import json,sys; print(json.load(sys.stdin)["sha256"])' <<<"$inventory_receipt")
census_arguments=()
if [[ -n "${SBK_CENSUS_DEFINER:-}" || -n "${SBK_CENSUS_DEFINITION_SHA256:-}" ]]; then
  : "${SBK_CENSUS_DEFINER:?actual DBA-owned census definer required}"
  census_arguments+=(--census-definer "$SBK_CENSUS_DEFINER")
  if [[ -n "${SBK_CENSUS_DEFINITION_SHA256:-}" ]]; then
    census_arguments+=(--census-definition-sha256 "$SBK_CENSUS_DEFINITION_SHA256")
  fi
fi
case "${SBK_CENSUS_PARTIAL_REVOKES:-0}" in
  0) ;;
  1) census_arguments+=(--census-partial-revokes) ;;
  *) printf '%s\n' 'Original partial_revokes selection must be 0 or 1.' >&2; exit 2 ;;
esac
"$python_command" "$script_directory/system-backup-d-first-install-inputs.py" sql-plan \
  --inventory-file "$output_directory/first-install-public-inputs.json" --inventory-sha256 "$inventory_sha" \
  --mysql-service "$SBK_MYSQL_SERVICE" --mysql-port "${SBK_MYSQL_PORT:-3306}" \
  --mysql-database "$SBK_MYSQL_DATABASE" --mysql-server-uuid "$SBK_MYSQL_SERVER_UUID" \
  --mysql-account "$SBK_MYSQL_SOURCE_ACCOUNT" --mysql-ca-sha256 "$SBK_MYSQL_CA_SHA256" \
  --mysql-tls-server-name "${SBK_MYSQL_TLS_SERVER_NAME:-$SBK_MYSQL_SERVICE.clawmanager-zhanghui08-system.svc}" \
  --output-directory "$output_directory" "${census_arguments[@]}"
printf '%s\n' 'PUBLIC CANDIDATES ONLY: review actual UID/owner/source bindings and 27 missing bootstrap owner slots before material composition.'
printf '%s\n' 'No credential file was opened and no MySQL/TLS session or full six-domain backup was attempted.'
