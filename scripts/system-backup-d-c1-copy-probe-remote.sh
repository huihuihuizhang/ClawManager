#!/usr/bin/env bash
# C1 reviewed178 catalog + original97 union199 upgrade on an exclusive copy.
# This is not the reviewed import profile and never upgrades clawmanager.
set -Eeuo pipefail
umask 077

ctx=kubernetes-admin@kubernetes
ns=clawmanager-zhanghui08-system
expected_ns_uid=337cfe30-2c17-4b8e-b32a-760778b8098e
expected_server=f1f5f76a-95f5-11f1-b08e-366835b4a029
expected_ledger=5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903
files=(rename upgrade counts-before counts-after c1-empty-after)
hashes=(
  b97754e940e7ce0267aecc0ae06e6afa75aa243e0698002238dd295f4eff7ab0
  c7a03dc94ad5bf509a10a3ebb978c7dfe1859f100915b1182bb4b4d46a3ee420
  178dcb814ad1cf9dc3a352620efd38ee0d220f1e1396602e130d0ad492d057cc
  cab88ac5d3361323ea49ae8ddc84923cb670d61512ad1029ce17ea4407338d47
  ee4dbb88d1d309fea0c3f535b3365f44eb0ebec69b71fef93515d410feeae028
)
[[ $# == 3 || $# == 4 ]] || { echo 'usage: bash producer BUNDLE_DIR PROOF_BINARY PROOF_BINARY_SHA256 [NEW_PRIVATE_LOG_DIRECTORY]' >&2; exit 2; }
bundle=$(realpath -- "$1")
host_bin=$(realpath -- "$2")
expected_bin=$3
[[ "$expected_bin" =~ ^[0-9a-f]{64}$ ]] || exit 2
run_id=$(tr -d - </proc/sys/kernel/random/uuid)
[[ "$run_id" =~ ^[0-9a-f]{32}$ ]] || exit 2
log_dir=$(realpath -m -- "${4:-$bundle/../upgrade198-evidence-$run_id}")
[[ ! -e "$log_dir" && -d "$(dirname -- "$log_dir")" ]] || { echo PRIVATE_LOG_DIRECTORY_MUST_BE_NEW >&2; exit 2; }
mkdir -m 700 -- "$log_dir"
echo "PRIVATE_COPY_LOGS_DIR=$log_dir"
pod_work="/tmp/sbk-d-upgrade177-$run_id"
[[ "$pod_work" =~ ^/tmp/sbk-d-upgrade177-[0-9a-f]{32}$ ]] || exit 2
pod_prefix="$pod_work/probe"
host_inventory="$bundle/inventory.json"
pod_bin="$pod_work/proof"
pod_inventory="$pod_work/inventory.json"
pod_dsn="$pod_work/copy.dsn"
pod_source_dsn="$pod_work/source.dsn"
expected_inventory=71b22c009b3ad9bdeef324d2cafd2aa4c1a646110f2080d1b6f42746f8f7013f
pod=
pod_uid=
copy_db=
cleanup_copy=0
cleanup_work=0
stage=package_identity

kraw() { kubectl --context "$ctx" -n "$ns" exec "$pod" -c mysql -- "$@" 2>/dev/null; }
identity() {
  local ns_uid current_uid server mysql_uid app_uid ready
  ns_uid=$(kubectl --context "$ctx" get namespace "$ns" -o jsonpath='{.metadata.uid}') || return 1
  current_uid=$(kubectl --context "$ctx" -n "$ns" get pod "$pod" -o jsonpath='{.metadata.uid}') || return 1
  mysql_uid=$(kubectl --context "$ctx" -n "$ns" get deployment mysql -o jsonpath='{.metadata.uid}') || return 1
  app_uid=$(kubectl --context "$ctx" -n "$ns" get deployment clawmanager-app -o jsonpath='{.metadata.uid}') || return 1
  ready=$(kubectl --context "$ctx" -n "$ns" get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="mysql")].ready}') || return 1
  [[ "$ns_uid" == "$expected_ns_uid" && "$current_uid" == "$pod_uid" && "$mysql_uid" == 27916932-fc61-432c-b515-081f18db34a8 && "$app_uid" == ed2c80de-9d24-4ca6-8f9c-877a990ac933 && "$ready" == true ]] || return 1
  server=$(kraw sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SELECT @@server_uuid"') || return 1
  [[ "$server" == "$expected_server" ]]
}
kexec() { identity || { echo 'MYSQL_IDENTITY_CHANGED' >&2; return 1; }; kraw "$@"; }
cleanup() {
  local result=$?
  trap - EXIT
  # Retain diagnostics before dropping the owned clone or deleting Pod temp.
  # No DSN, password, source dump, private key or credential file is exported.
  local evidence_ok=1 evidence_name
  if [[ "$cleanup_work" == 1 ]]; then
    if identity; then
      for evidence_name in live-inventory.json live-inventory-after-copy.json copy-inventory.json copy-inventory.stderr row-proof-before.json row-proof-after.json row-proof-before.stderr row-proof-after.stderr source-after-copy.stderr upgrade.log before.out after.out core.out source.out c1-empty-after.out; do
        if kraw test -f "$pod_work/$evidence_name"; then
          kubectl --context "$ctx" -n "$ns" cp -c mysql "$pod:$pod_work/$evidence_name" "$log_dir/$evidence_name" >/dev/null 2>&1 || evidence_ok=0
          [[ ! -f "$log_dir/$evidence_name" ]] || chmod 600 -- "$log_dir/$evidence_name"
        fi
      done
      kraw rm -f -- "$pod_dsn" "$pod_source_dsn" >/dev/null || evidence_ok=0
    else
      evidence_ok=0
    fi
    if [[ "$evidence_ok" != 1 ]]; then
      echo "PRIVATE_DIAGNOSTICS_INCOMPLETE: retain original Pod temp $pod_work; DSN cleanup requires same original identity" >&2
      cleanup_work=0
      result=1
    fi
  fi
  for evidence_name in row-proof-before.stderr row-proof-after.stderr source-after-copy.stderr copy-inventory.stderr; do
    if [[ -s "$log_dir/$evidence_name" ]]; then
      python3 - "$log_dir/$evidence_name" <<'SAFE_DIAGNOSTIC'
import json,re,sys
from pathlib import Path
for line in Path(sys.argv[1]).read_text(errors='replace').splitlines():
 try:
  d=json.loads(line)
  if isinstance(d,dict) and d.get('state')=='copy_proof_rejected' and re.fullmatch('[a-z_]{1,80}',d.get('reason','')):
   safe={k:d[k] for k in ('state','phase','reason','mysql_code') if k in d}
   b=d.get('row_budget')
   counts=('processed_rows','processed_bytes','snapshot_rows','largest_sql_row_bytes','max_rows','max_bytes','max_row_bytes','max_scratch_bytes')
   if isinstance(b,dict) and re.fullmatch('[a-z][a-z0-9_]{0,63}',b.get('table','')) and b.get('limit') in ('rows','largest_row_bytes','row_bytes','total_bytes','hash_scratch_bytes') and all(type(b.get(k)) is int and 0<=b[k]<2**63 for k in counts):
    safe['row_budget']={k:b[k] for k in ('table','limit',*counts)}
   print('COPY_PROOF_DIAGNOSTIC',json.dumps(safe))
 except (ValueError,TypeError): pass
SAFE_DIAGNOSTIC
    fi
  done
  if [[ "$cleanup_copy" == 1 ]]; then
    if identity; then
      kraw bash -euo pipefail -c 'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; [[ "$1" =~ ^cm_import_[0-9a-f]{32}$ ]]; [[ "$(mysql -uroot -N -B -e "SELECT @@server_uuid")" == "$2" ]]; mysql -uroot -e "DROP DATABASE IF EXISTS \`$1\`"; [[ -z "$(mysql -uroot -N -B -e "SHOW DATABASES" | grep -Fx "$1" || true)" ]]; printf "COPY_ABSENT\n"' bash "$copy_db" "$expected_server" || result=1
    else
      echo "CLEANUP_IDENTITY_CHANGED: inspect isolated $copy_db on $expected_server" >&2
      result=1
    fi
  fi
  if [[ "$cleanup_work" == 1 ]] && identity; then
    kraw sh -eu -c 'case "$1" in /tmp/sbk-d-upgrade177-????????????????????????????????) ;; *) exit 2;; esac; test -d "$1" && rm -rf -- "$1"' sh "$pod_work" >/dev/null || result=1
    if [[ "$(kraw sh -c 'test ! -e "$1" && printf POD_TEMP_ABSENT' sh "$pod_work")" != POD_TEMP_ABSENT ]]; then result=1; else echo POD_TEMP_ABSENT; fi
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'echo "COPY_UPGRADE177_FAILED stage=$stage line=$LINENO (private SQL stderr retained)" >&2' ERR

for i in "${!files[@]}"; do
  file="$bundle/${files[i]}.sql"
  [[ -f "$file" && ! -L "$file" ]] || { echo "INPUT_MISSING: $file" >&2; exit 1; }
  [[ "$(sha256sum "$file" | cut -d' ' -f1)" == "${hashes[i]}" ]] || { echo "INPUT_HASH_MISMATCH: ${files[i]}" >&2; exit 1; }
done
[[ "$(sha256sum "$host_bin" | cut -d' ' -f1)" == "$expected_bin" ]] || { echo 'ROW_PROOF_BINARY_HASH_MISMATCH' >&2; exit 1; }
[[ "$(sha256sum "$host_inventory" | cut -d' ' -f1)" == "$expected_inventory" ]] || { echo 'SOURCE_INVENTORY_HASH_MISMATCH' >&2; exit 1; }
mapfile -t pods < <(kubectl --context "$ctx" -n "$ns" get pods -o name | sed -n 's@^pod/\(mysql-[a-z0-9-]*\)$@\1@p')
[[ "${#pods[@]}" == 1 ]] || { echo 'MYSQL_POD_NOT_UNIQUE' >&2; exit 1; }
pod=${pods[0]}
pod_uid=$(kubectl --context "$ctx" -n "$ns" get pod "$pod" -o jsonpath='{.metadata.uid}')
# Prove the initially selected actual Pod belongs to the pinned Deployment;
# thereafter its original immutable Pod UID is rechecked on every operation.
rs_kind=$(kubectl --context "$ctx" -n "$ns" get pod "$pod" -o jsonpath='{.metadata.ownerReferences[?(@.controller==true)].kind}')
rs_name=$(kubectl --context "$ctx" -n "$ns" get pod "$pod" -o jsonpath='{.metadata.ownerReferences[?(@.controller==true)].name}')
rs_pin=$(kubectl --context "$ctx" -n "$ns" get pod "$pod" -o jsonpath='{.metadata.ownerReferences[?(@.controller==true)].uid}')
[[ "$rs_kind" == ReplicaSet && "$rs_name" =~ ^mysql-[a-z0-9-]+$ ]] || { echo 'ORIGINAL_MYSQL_OWNER_REFUSED' >&2; exit 1; }
rs_actual=$(kubectl --context "$ctx" -n "$ns" get replicaset "$rs_name" -o jsonpath='{.metadata.uid}')
owner_kind=$(kubectl --context "$ctx" -n "$ns" get replicaset "$rs_name" -o jsonpath='{.metadata.ownerReferences[?(@.controller==true)].kind}')
owner_uid=$(kubectl --context "$ctx" -n "$ns" get replicaset "$rs_name" -o jsonpath='{.metadata.ownerReferences[?(@.controller==true)].uid}')
[[ "$rs_pin" == "$rs_actual" && "$owner_kind" == Deployment && "$owner_uid" == 27916932-fc61-432c-b515-081f18db34a8 ]] || { echo 'ORIGINAL_MYSQL_DEPLOYMENT_OWNER_REFUSED' >&2; exit 1; }
identity || { echo 'SOURCE_IDENTITY_MISMATCH' >&2; exit 1; }
kexec mkdir -m 700 -- "$pod_work"
cleanup_work=1

for i in "${!files[@]}"; do
  kubectl --context "$ctx" -n "$ns" cp -c mysql "$bundle/${files[i]}.sql" "$pod:$pod_prefix-${files[i]}.sql"
  [[ "$(kexec sha256sum "$pod_prefix-${files[i]}.sql" | cut -d' ' -f1)" == "${hashes[i]}" ]] || { echo "POD_INPUT_HASH_MISMATCH: ${files[i]}" >&2; exit 1; }
done
kubectl --context "$ctx" -n "$ns" cp -c mysql "$host_bin" "$pod:$pod_bin"
kubectl --context "$ctx" -n "$ns" cp -c mysql "$host_inventory" "$pod:$pod_inventory"
[[ "$(kexec sha256sum "$pod_bin" | cut -d' ' -f1)" == "$expected_bin" ]] || exit 1
[[ "$(kexec sha256sum "$pod_inventory" | cut -d' ' -f1)" == "$expected_inventory" ]] || exit 1
kexec chmod 700 "$pod_bin"
kexec sh -eu -c '
  socket=$(MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SELECT @@socket")
  umask 077
  printf "root:%s@unix(%s)/clawmanager?parseTime=true\n" "$MYSQL_ROOT_PASSWORD" "$socket" > "$2"
  "$1" --dsn-file "$2" --source-inventory-file "$3" --phase source --timeout 5m > "$4/live-inventory.json"
' sh "$pod_bin" "$pod_source_dsn" "$pod_inventory" "$pod_work"
[[ "$(kexec sha256sum "$pod_work/live-inventory.json" | cut -d' ' -f1)" == "$expected_inventory" ]] || { echo 'FRESH_ORIGINAL_SCHEMA_CHANGED_NO_COPY_UPGRADE' >&2; exit 1; }

ledger=$(kexec sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -D clawmanager -e "SELECT filename FROM schema_migrations ORDER BY BINARY filename" | sha256sum | cut -d" " -f1')
[[ "$ledger" == "$expected_ledger" ]] || { echo 'SOURCE_LEDGER_CHANGED' >&2; exit 1; }
shape=$(kexec sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SELECT (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=0x636c61776d616e61676572 AND TABLE_TYPE=0x42415345205441424c45 AND ENGINE=0x496e6e6f4442),(SELECT COUNT(DISTINCT TABLE_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=0x636c61776d616e61676572 AND INDEX_NAME=0x5052494d415259)"')
[[ "$shape" == $'99\t99' ]] || { echo 'SOURCE_SCHEMA_SHAPE_CHANGED' >&2; exit 1; }
code_objects=$(kexec sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SELECT (SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=0x636c61776d616e61676572),(SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=0x636c61776d616e61676572),(SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=0x636c61776d616e61676572),(SELECT COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA=0x636c61776d616e61676572)"')
[[ "$code_objects" == $'0\t0\t0\t0' ]] || { echo 'UNREVIEWED_SOURCE_EXECUTABLE_SCHEMA_OBJECTS' >&2; exit 1; }
estimated=$(kexec sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -D clawmanager -e "SELECT CEIL(COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0)/1024/1024) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()"')
free=$(kexec df -Pm /var/lib/mysql | awk 'NR==2 {print $4}')
[[ "$estimated" =~ ^[0-9]+$ && "$free" =~ ^[0-9]+$ ]] && (( free >= estimated * 3 + 1024 )) || { echo 'COPY_CAPACITY_UNAVAILABLE' >&2; exit 1; }

copy_db="cm_import_$(tr -d - </proc/sys/kernel/random/uuid)"
[[ "$copy_db" =~ ^cm_import_[0-9a-f]{32}$ ]] || exit 1
[[ -z "$(kexec sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SHOW DATABASES"' | grep -Fx "$copy_db" || true)" ]] || exit 1
cleanup_copy=1
kexec bash -euo pipefail -c 'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; [[ "$1" =~ ^cm_import_[0-9a-f]{32}$ ]]; [[ "$(mysql -uroot -N -B -e "SELECT @@server_uuid")" == "$2" ]]; mysql -uroot -e "CREATE DATABASE \`$1\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"' bash "$copy_db" "$expected_server"
echo "COPY_CREATED: $copy_db"
kexec bash -euo pipefail -c '
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  work="$3"
  [[ "$(mysql -uroot -N -B -e "SELECT @@server_uuid")" == "$2" ]] || exit 3
  mysqldump -uroot --no-data --single-transaction --quick --skip-lock-tables --set-gtid-purged=OFF --no-tablespaces clawmanager | mysql -uroot "$1"
  options=(-uroot --single-transaction --quick --skip-lock-tables --skip-add-locks --set-gtid-purged=OFF --no-tablespaces --no-create-info --skip-triggers --order-by-primary --skip-extended-insert --hex-blob --skip-comments --skip-dump-date)
  umask 077
  fifo="$work/copy.fifo"
  mkfifo "$fifo"
  trap '\''rm -f "$fifo"'\'' EXIT
  sha256sum < "$fifo" > "$work/source.out" & hash_pid=$!
  if ! mysqldump "${options[@]}" clawmanager | tee "$fifo" | mysql -uroot "$1"; then kill "$hash_pid" 2>/dev/null || true; wait "$hash_pid" 2>/dev/null || true; exit 4; fi
  wait "$hash_pid"
  source_sha=$(cut -d" " -f1 "$work/source.out")
  copy_sha=$(mysqldump "${options[@]}" "$1" | sha256sum | cut -d" " -f1)
  [[ "$source_sha" == "$copy_sha" ]] || exit 5
  printf "DATA_STREAM_ROUNDTRIP_SHA256=%s\n" "$source_sha"
' bash "$copy_db" "$expected_server" "$pod_work"
stage=source_identity_after_copy
kexec sh -eu -c '"$1" --dsn-file "$2" --source-inventory-file "$3" --phase source --timeout 5m > "$4/live-inventory-after-copy.json" 2> "$4/source-after-copy.stderr"' sh "$pod_bin" "$pod_source_dsn" "$pod_inventory" "$pod_work"
[[ "$(kexec sha256sum "$pod_work/live-inventory-after-copy.json" | cut -d' ' -f1)" == "$expected_inventory" ]] || { echo 'SOURCE_SCHEMA_CHANGED_DURING_COPY' >&2; exit 1; }

kexec sh -c '
  socket=$(MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SELECT @@socket")
  umask 077
  printf "root:%s@unix(%s)/%s?parseTime=true\n" "$MYSQL_ROOT_PASSWORD" "$socket" "$1" > "$2"
' sh "$copy_db" "$pod_dsn"
stage=copy_schema_observation
kexec sh -c '"$1" --dsn-file "$2" --source-inventory-file "$3" --phase copy-inventory --timeout 5m > "$4/copy-inventory.json" 2> "$4/copy-inventory.stderr"' sh "$pod_bin" "$pod_dsn" "$pod_inventory" "$pod_work"
stage=before_original_99_table_row_proof
kexec sh -eu -c 'mkdir -m 700 "$4/row-hash-temp"; TMPDIR="$4/row-hash-temp" "$1" --dsn-file "$2" --source-inventory-file "$3" --phase c1-before --timeout 10m > "$4/row-proof-before.json" 2> "$4/row-proof-before.stderr"' sh "$pod_bin" "$pod_dsn" "$pod_inventory" "$pod_work"
before=$(kexec sed -n 's/.*"preservation_sha256":"\([0-9a-f]*\)".*/\1/p' "$pod_work/row-proof-before.json")
[[ "$before" =~ ^[0-9a-f]{64}$ ]] || { echo 'BEFORE_ROW_PROOF_MISSING' >&2; exit 1; }
echo "BEFORE_ORIGINAL_ROW_SHA256=$before"

stage=rename_and_101_migrations
kexec bash -euo pipefail -c '
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  db="$1"
  work="$2"
  [[ "$(mysql -uroot -N -B -e "SELECT @@server_uuid")" == "$3" ]] || exit 3
  [[ "$db" =~ ^cm_import_[0-9a-f]{32}$ ]] || exit 3
  mysql -uroot -N -B "$db" < "$work/probe-counts-before.sql" > "$work/before.out"
  old=$(awk '\''$1 ~ /^(system_backup|system_maintenance|system_restore|system_artifact)/ {n++; if ($2 != 0) bad++} END {if (bad) exit 1; print n}'\'' "$work/before.out") || exit 6
  [[ "$old" == 35 ]] || exit 6
  mysql -uroot -N -B "$db" -e "SELECT '\''users'\'',id,0,0 FROM users UNION ALL SELECT '\''instances'\'',id,user_id,0 FROM instances UNION ALL SELECT '\''bindings'\'',id,instance_id,runtime_pod_id FROM instance_runtime_bindings UNION ALL SELECT '\''pods'\'',id,0,0 FROM runtime_pods ORDER BY 1,2" | sha256sum | cut -d" " -f1 > "$work/core.out"
  mysql -uroot "$db" < "$work/probe-rename.sql"
  if ! mysql -uroot "$db" < "$work/probe-upgrade.sql" > "$work/upgrade.log" 2>&1; then
    marker=$(grep '\''^MIGRATION:'\'' "$work/upgrade.log" | tail -n 1 || true)
    code=$(grep -o '\''ERROR [0-9][0-9]*'\'' "$work/upgrade.log" | tail -n 1 || true)
    printf "UPGRADE_FAILED %s %s\n" "$marker" "$code"
    exit 7
  fi
  authority_rows=$(mysql -uroot -N -B "$db" -e "SELECT (SELECT COUNT(*) FROM system_backup_installation_kek_authority)+(SELECT COUNT(*) FROM system_backup_installation_kek_authority_history)+(SELECT COUNT(*) FROM system_backup_installation_owner_heads)+(SELECT COUNT(*) FROM system_backup_installation_owner_grants)+(SELECT COUNT(*) FROM system_backup_minio_owner_heads)+(SELECT COUNT(*) FROM system_backup_minio_owner_grants)+(SELECT COUNT(*) FROM system_backup_minio_owner_refs)+(SELECT COUNT(*) FROM system_backup_signing_resource_heads)+(SELECT COUNT(*) FROM system_backup_signing_resource_grants)")
  [[ "$authority_rows" == 0 ]] || { echo "NEW_AUTHORITY_ROWS_UNEXPECTED"; exit 9; }
  mysql -uroot -N -B "$db" < "$work/probe-counts-after.sql" > "$work/after.out"
  awk '\''NR==FNR {before[$1]=$2; next} {if ($2 < before[$1]) {print "ROW_COUNT_DECREASE:" $1 > "/dev/stderr"; bad=1}} END {exit bad}'\'' "$work/before.out" "$work/after.out"
  after_core=$(mysql -uroot -N -B "$db" -e "SELECT '\''users'\'',id,0,0 FROM users UNION ALL SELECT '\''instances'\'',id,user_id,0 FROM instances UNION ALL SELECT '\''bindings'\'',id,instance_id,runtime_pod_id FROM instance_runtime_bindings UNION ALL SELECT '\''pods'\'',id,0,0 FROM runtime_pods ORDER BY 1,2" | sha256sum | cut -d" " -f1)
  [[ "$after_core" == "$(cat "$work/core.out")" ]] || exit 8
  checks=$(mysql -uroot -N -B "$db" -e "SELECT (SELECT COUNT(*) FROM schema_migrations),(SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME LIKE '\''dlegacy\\_%'\''),(SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='\''system_backup_attempts'\'' AND COLUMN_NAME='\''public_id'\''),(SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='\''system_backup_v2_runtime_controls'\'')")
  [[ "$checks" == $'\''199\t35\t1\t1'\'' ]] || { echo "TARGET_SCHEMA_MISMATCH:$checks" >&2; exit 9; }
  printf "UPGRADE_DDL_COMPLETED_PENDING_ROW_PROOF ledger=199 legacy_tables=35 core_identity_sha256=%s\n" "$after_core"
' bash "$copy_db" "$pod_work" "$expected_server"
stage=c1_exact_eight_empty_tables_after_ddl
kexec sh -eu -c '
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  mysql -uroot -N -B "$1" < "$2/probe-c1-empty-after.sql" > "$2/c1-empty-after.out"
  awk '\''NF!=2 || $2!=0 {bad=1} END {if (NR!=8 || bad) exit 1}'\'' "$2/c1-empty-after.out"
' sh "$copy_db" "$pod_work"
echo 'COPY_C1_EIGHT_TABLES_EMPTY_VERIFIED'
stage=after_original_99_table_row_proof
kexec sh -c 'TMPDIR="$4/row-hash-temp" "$1" --dsn-file "$2" --source-inventory-file "$3" --phase c1-after --timeout 10m > "$4/row-proof-after.json" 2> "$4/row-proof-after.stderr"' sh "$pod_bin" "$pod_dsn" "$pod_inventory" "$pod_work"
after=$(kexec sed -n 's/.*"preservation_sha256":"\([0-9a-f]*\)".*/\1/p' "$pod_work/row-proof-after.json")
[[ "$after" =~ ^[0-9a-f]{64}$ ]] || { echo 'AFTER_ROW_PROOF_MISSING' >&2; exit 1; }
echo "AFTER_ORIGINAL_ROW_SHA256=$after"
if [[ "$after" != "$before" ]]; then
  before_rows=$(kexec grep -o '"name":"[^"]*","rows":[0-9]*,"sha256":"[0-9a-f]*"' "$pod_work/row-proof-before.json")
  after_rows=$(kexec grep -o '"name":"[^"]*","rows":[0-9]*,"sha256":"[0-9a-f]*"' "$pod_work/row-proof-after.json")
  [[ "$(printf '%s\n' "$before_rows" | wc -l)" == 99 && "$(printf '%s\n' "$after_rows" | wc -l)" == 99 ]] || exit 10
  echo 'ORIGINAL_ROW_TABLE_DIFFERENCES:' >&2
  diff -u <(printf '%s\n' "$before_rows") <(printf '%s\n' "$after_rows") >&2 || true
  exit 10
fi
before_models=$(kexec sed -n 's/.*"llm_existing_protocol_rows":\([0-9]*\),"llm_group_backfill_rows":0.*/\1/p' "$pod_work/row-proof-before.json")
after_models=$(kexec sed -n 's/.*"llm_existing_protocol_rows":\([0-9]*\),"llm_group_backfill_rows":\([0-9]*\).*/\1 \2/p' "$pod_work/row-proof-after.json")
[[ "$before_models" =~ ^[0-9]+$ && "$after_models" == "$before_models $before_models" ]] || { echo 'MODEL_BACKFILL_PROOF_MISSING' >&2; exit 11; }
echo "MODEL_GROUP_BACKFILL_VERIFIED rows=$before_models original_columns_except_updated_at_unchanged=true"
echo "UPGRADE_C1_COPY_VERIFIED ledger=199 all99_original_column_sha256=$after (only_llm_models_updated_at_exception)"
echo 'EXPERIMENT_ONLY_NOT_UPGRADE_AUTHORIZATION: original schema has not been upgraded; owned clone cleanup follows'
 
