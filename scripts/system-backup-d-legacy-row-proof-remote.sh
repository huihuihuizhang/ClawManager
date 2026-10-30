#!/usr/bin/env bash
# Exploratory upgrade and original-column row proof of a disposable copy.
# This is not the reviewed import profile and never upgrades clawmanager.
set -Eeuo pipefail

ctx=kubernetes-admin@kubernetes
ns=clawmanager-zhanghui08-system
expected_ns_uid=337cfe30-2c17-4b8e-b32a-760778b8098e
expected_server=f1f5f76a-95f5-11f1-b08e-366835b4a029
expected_ledger=5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903
files=(rename upgrade counts-before counts-after)
hashes=(
  d85f0e1f465606d3e06579d834a327f0ca08db74712badc251349e21d7b2cb15
  0ff4050dc12ea7824c6d779a68347813026fd4377517a42b5128e928626ff05f
  7823a24115375bf9202a8d5e608ac12dfa29808cd5270c540bf7ce4a1cae7671
  a14d72827cca30fef14a89d8582d937d6aa9a6ad33d28d7ba1aadcbc296bd01a
)
host_prefix=/tmp/sbk-d-upgrade-probe
pod_prefix=/tmp/sbk-d-upgrade-probe
host_bin=/tmp/sbk-d-legacy-row-proof
host_inventory=/tmp/sbk-d-live-inventory-71b22c00.json
pod_bin=/tmp/sbk-d-legacy-row-proof
pod_inventory=/tmp/sbk-d-live-inventory-71b22c00.json
pod_dsn=/tmp/sbk-d-legacy-row-proof.dsn
expected_bin=b3c06b80f5acbe52c4a3f5f6ac2e43ebc2cbc7c3a5304593b429b01b71461d29
expected_inventory=71b22c009b3ad9bdeef324d2cafd2aa4c1a646110f2080d1b6f42746f8f7013f
pod=
pod_uid=
copy_db=
cleanup_copy=0

kraw() { kubectl --context "$ctx" -n "$ns" exec "$pod" -c mysql -- "$@"; }
identity() {
  local ns_uid current_uid server
  ns_uid=$(kubectl --context "$ctx" get namespace "$ns" -o jsonpath='{.metadata.uid}') || return 1
  current_uid=$(kubectl --context "$ctx" -n "$ns" get pod "$pod" -o jsonpath='{.metadata.uid}') || return 1
  [[ "$ns_uid" == "$expected_ns_uid" && "$current_uid" == "$pod_uid" ]] || return 1
  server=$(kraw sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SELECT @@server_uuid"') || return 1
  [[ "$server" == "$expected_server" ]]
}
kexec() { identity || { echo 'MYSQL_IDENTITY_CHANGED' >&2; return 1; }; kraw "$@"; }
cleanup() {
  local result=$?
  trap - EXIT
  if [[ "$cleanup_copy" == 1 ]]; then
    if identity; then
      kraw sh -eu -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -e "DROP DATABASE IF EXISTS \`$1\`"' sh "$copy_db" >/dev/null || result=1
    else
      echo "CLEANUP_IDENTITY_CHANGED: inspect isolated $copy_db on $expected_server" >&2
      result=1
    fi
  fi
  if [[ -n "$pod" ]] && identity; then
    kraw sh -c 'rm -f /tmp/sbk-d-upgrade-probe-*.sql /tmp/sbk-d-upgrade-probe-*.out /tmp/sbk-d-upgrade-probe-*.log /tmp/sbk-d-upgrade-probe-*.fifo /tmp/sbk-d-legacy-row-proof /tmp/sbk-d-live-inventory-71b22c00.json /tmp/sbk-d-legacy-row-proof.dsn /tmp/sbk-d-row-proof-*.json' >/dev/null 2>&1 || true
  fi
  for file in "${files[@]}"; do rm -f "$host_prefix-$file.sql"; done
  rm -f "$host_bin" "$host_inventory"
  exit "$result"
}
trap cleanup EXIT

for i in "${!files[@]}"; do
  file="$host_prefix-${files[i]}.sql"
  [[ -f "$file" && ! -L "$file" ]] || { echo "INPUT_MISSING: $file" >&2; exit 1; }
  [[ "$(sha256sum "$file" | cut -d' ' -f1)" == "${hashes[i]}" ]] || { echo "INPUT_HASH_MISMATCH: ${files[i]}" >&2; exit 1; }
done
[[ "$(sha256sum "$host_bin" | cut -d' ' -f1)" == "$expected_bin" ]] || { echo 'ROW_PROOF_BINARY_HASH_MISMATCH' >&2; exit 1; }
[[ "$(sha256sum "$host_inventory" | cut -d' ' -f1)" == "$expected_inventory" ]] || { echo 'SOURCE_INVENTORY_HASH_MISMATCH' >&2; exit 1; }
mapfile -t pods < <(kubectl --context "$ctx" -n "$ns" get pods -o name | sed -n 's@^pod/\(mysql-[a-z0-9-]*\)$@\1@p')
[[ "${#pods[@]}" == 1 ]] || { echo 'MYSQL_POD_NOT_UNIQUE' >&2; exit 1; }
pod=${pods[0]}
pod_uid=$(kubectl --context "$ctx" -n "$ns" get pod "$pod" -o jsonpath='{.metadata.uid}')
identity || { echo 'SOURCE_IDENTITY_MISMATCH' >&2; exit 1; }

for i in "${!files[@]}"; do
  kubectl --context "$ctx" -n "$ns" cp -c mysql "$host_prefix-${files[i]}.sql" "$pod:$pod_prefix-${files[i]}.sql"
  [[ "$(kexec sha256sum "$pod_prefix-${files[i]}.sql" | cut -d' ' -f1)" == "${hashes[i]}" ]] || { echo "POD_INPUT_HASH_MISMATCH: ${files[i]}" >&2; exit 1; }
done
kubectl --context "$ctx" -n "$ns" cp -c mysql "$host_bin" "$pod:$pod_bin"
kubectl --context "$ctx" -n "$ns" cp -c mysql "$host_inventory" "$pod:$pod_inventory"
[[ "$(kexec sha256sum "$pod_bin" | cut -d' ' -f1)" == "$expected_bin" ]] || exit 1
[[ "$(kexec sha256sum "$pod_inventory" | cut -d' ' -f1)" == "$expected_inventory" ]] || exit 1
kexec chmod 700 "$pod_bin"

ledger=$(kexec sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -D clawmanager -e "SELECT filename FROM schema_migrations ORDER BY BINARY filename" | sha256sum | cut -d" " -f1')
[[ "$ledger" == "$expected_ledger" ]] || { echo 'SOURCE_LEDGER_CHANGED' >&2; exit 1; }
shape=$(kexec sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SELECT (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=0x636c61776d616e61676572 AND TABLE_TYPE=0x42415345205441424c45 AND ENGINE=0x496e6e6f4442),(SELECT COUNT(DISTINCT TABLE_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=0x636c61776d616e61676572 AND INDEX_NAME=0x5052494d415259)"')
[[ "$shape" == $'99\t99' ]] || { echo 'SOURCE_SCHEMA_SHAPE_CHANGED' >&2; exit 1; }
estimated=$(kexec sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -D clawmanager -e "SELECT CEIL(COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0)/1024/1024) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()"')
free=$(kexec df -Pm /var/lib/mysql | awk 'NR==2 {print $4}')
[[ "$estimated" =~ ^[0-9]+$ && "$free" =~ ^[0-9]+$ ]] && (( free >= estimated * 3 + 1024 )) || { echo 'COPY_CAPACITY_UNAVAILABLE' >&2; exit 1; }

copy_db="cm_import_$(tr -d - </proc/sys/kernel/random/uuid)"
[[ "$copy_db" =~ ^cm_import_[0-9a-f]{32}$ ]] || exit 1
[[ -z "$(kexec sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SHOW DATABASES"' | grep -Fx "$copy_db" || true)" ]] || exit 1
cleanup_copy=1
kexec sh -eu -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -e "CREATE DATABASE \`$1\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"' sh "$copy_db"
echo "COPY_CREATED: $copy_db"
kexec bash -euo pipefail -c '
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  [[ "$(mysql -uroot -N -B -e "SELECT @@server_uuid")" == "$2" ]] || exit 3
  mysqldump -uroot --no-data --single-transaction --quick --skip-lock-tables --set-gtid-purged=OFF --no-tablespaces clawmanager | mysql -uroot "$1"
  options=(-uroot --single-transaction --quick --skip-lock-tables --skip-add-locks --set-gtid-purged=OFF --no-tablespaces --no-create-info --skip-triggers --order-by-primary --skip-extended-insert --hex-blob --skip-comments --skip-dump-date)
  umask 077
  fifo="/tmp/sbk-d-upgrade-probe-$1.fifo"
  mkfifo "$fifo"
  trap '\''rm -f "$fifo"'\'' EXIT
  sha256sum < "$fifo" > /tmp/sbk-d-upgrade-probe-source.out & hash_pid=$!
  if ! mysqldump "${options[@]}" clawmanager | tee "$fifo" | mysql -uroot "$1"; then kill "$hash_pid" 2>/dev/null || true; wait "$hash_pid" 2>/dev/null || true; exit 4; fi
  wait "$hash_pid"
  source_sha=$(cut -d" " -f1 /tmp/sbk-d-upgrade-probe-source.out)
  copy_sha=$(mysqldump "${options[@]}" "$1" | sha256sum | cut -d" " -f1)
  [[ "$source_sha" == "$copy_sha" ]] || exit 5
  printf "DATA_STREAM_ROUNDTRIP_SHA256=%s\n" "$source_sha"
' bash "$copy_db" "$expected_server"

kexec sh -c '
  socket=$(MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "SELECT @@socket")
  umask 077
  printf "root:%s@unix(%s)/%s?parseTime=true\n" "$MYSQL_ROOT_PASSWORD" "$socket" "$1" > "$2"
' sh "$copy_db" "$pod_dsn"
kexec sh -c '"$1" --dsn-file "$2" --source-inventory-file "$3" --row-proof-phase before --timeout 10m > /tmp/sbk-d-row-proof-before.json' sh "$pod_bin" "$pod_dsn" "$pod_inventory"
before=$(kexec sed -n 's/.*"preservation_sha256":"\([0-9a-f]*\)".*/\1/p' /tmp/sbk-d-row-proof-before.json)
[[ "$before" =~ ^[0-9a-f]{64}$ ]] || { echo 'BEFORE_ROW_PROOF_MISSING' >&2; exit 1; }
echo "BEFORE_ORIGINAL_ROW_SHA256=$before"

kexec bash -euo pipefail -c '
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  db="$1"
  mysql -uroot -N -B "$db" < /tmp/sbk-d-upgrade-probe-counts-before.sql > /tmp/sbk-d-upgrade-probe-before.out
  old=$(awk '\''$1 ~ /^(system_backup|system_maintenance|system_restore|system_artifact)/ {n++; if ($2 != 0) bad++} END {if (bad) exit 1; print n}'\'' /tmp/sbk-d-upgrade-probe-before.out) || exit 6
  [[ "$old" == 35 ]] || exit 6
  mysql -uroot -N -B "$db" -e "SELECT '\''users'\'',id,0,0 FROM users UNION ALL SELECT '\''instances'\'',id,user_id,0 FROM instances UNION ALL SELECT '\''bindings'\'',id,instance_id,runtime_pod_id FROM instance_runtime_bindings UNION ALL SELECT '\''pods'\'',id,0,0 FROM runtime_pods ORDER BY 1,2" | sha256sum | cut -d" " -f1 > /tmp/sbk-d-upgrade-probe-core.out
  mysql -uroot "$db" < /tmp/sbk-d-upgrade-probe-rename.sql
  if ! mysql -uroot "$db" < /tmp/sbk-d-upgrade-probe-upgrade.sql > /tmp/sbk-d-upgrade-probe-upgrade.log 2>&1; then
    marker=$(grep '\''^MIGRATION:'\'' /tmp/sbk-d-upgrade-probe-upgrade.log | tail -n 1 || true)
    code=$(grep -o '\''ERROR [0-9][0-9]*'\'' /tmp/sbk-d-upgrade-probe-upgrade.log | tail -n 1 || true)
    printf "UPGRADE_FAILED %s %s\n" "$marker" "$code" >&2
    exit 7
  fi
  mysql -uroot -N -B "$db" < /tmp/sbk-d-upgrade-probe-counts-after.sql > /tmp/sbk-d-upgrade-probe-after.out
  awk '\''NR==FNR {before[$1]=$2; next} {if ($2 < before[$1]) {print "ROW_COUNT_DECREASE:" $1 > "/dev/stderr"; bad=1}} END {exit bad}'\'' /tmp/sbk-d-upgrade-probe-before.out /tmp/sbk-d-upgrade-probe-after.out
  after_core=$(mysql -uroot -N -B "$db" -e "SELECT '\''users'\'',id,0,0 FROM users UNION ALL SELECT '\''instances'\'',id,user_id,0 FROM instances UNION ALL SELECT '\''bindings'\'',id,instance_id,runtime_pod_id FROM instance_runtime_bindings UNION ALL SELECT '\''pods'\'',id,0,0 FROM runtime_pods ORDER BY 1,2" | sha256sum | cut -d" " -f1)
  [[ "$after_core" == "$(cat /tmp/sbk-d-upgrade-probe-core.out)" ]] || exit 8
  checks=$(mysql -uroot -N -B "$db" -e "SELECT (SELECT COUNT(*) FROM schema_migrations),(SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME LIKE '\''dlegacy\\_%'\''),(SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='\''system_backup_attempts'\'' AND COLUMN_NAME='\''public_id'\''),(SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='\''system_backup_v2_runtime_controls'\'')")
  [[ "$checks" == $'\''189\t35\t1\t1'\'' ]] || { echo "TARGET_SCHEMA_MISMATCH:$checks" >&2; exit 9; }
  printf "UPGRADE_COPY_VERIFIED ledger=189 legacy_tables=35 core_identity_sha256=%s row_counts_non_decreasing=true\n" "$after_core"
' bash "$copy_db"
kexec sh -c '"$1" --dsn-file "$2" --source-inventory-file "$3" --row-proof-phase after --timeout 10m > /tmp/sbk-d-row-proof-after.json' sh "$pod_bin" "$pod_dsn" "$pod_inventory"
after=$(kexec sed -n 's/.*"preservation_sha256":"\([0-9a-f]*\)".*/\1/p' /tmp/sbk-d-row-proof-after.json)
[[ "$after" =~ ^[0-9a-f]{64}$ ]] || { echo 'AFTER_ROW_PROOF_MISSING' >&2; exit 1; }
echo "AFTER_ORIGINAL_ROW_SHA256=$after"
if [[ "$after" != "$before" ]]; then
  before_rows=$(kexec grep -o '"name":"[^"]*","rows":[0-9]*,"sha256":"[0-9a-f]*"' /tmp/sbk-d-row-proof-before.json)
  after_rows=$(kexec grep -o '"name":"[^"]*","rows":[0-9]*,"sha256":"[0-9a-f]*"' /tmp/sbk-d-row-proof-after.json)
  [[ "$(printf '%s\n' "$before_rows" | wc -l)" == 99 && "$(printf '%s\n' "$after_rows" | wc -l)" == 99 ]] || exit 10
  echo 'ORIGINAL_ROW_TABLE_DIFFERENCES:' >&2
  diff -u <(printf '%s\n' "$before_rows") <(printf '%s\n' "$after_rows") >&2 || true
  exit 10
fi
before_models=$(kexec sed -n 's/.*"llm_existing_protocol_rows":\([0-9]*\),"llm_group_backfill_rows":0.*/\1/p' /tmp/sbk-d-row-proof-before.json)
after_models=$(kexec sed -n 's/.*"llm_existing_protocol_rows":\([0-9]*\),"llm_group_backfill_rows":\([0-9]*\).*/\1 \2/p' /tmp/sbk-d-row-proof-after.json)
[[ "$before_models" == 2 && "$after_models" == '2 2' ]] || { echo 'MODEL_BACKFILL_PROOF_MISSING' >&2; exit 11; }
echo 'MODEL_GROUP_BACKFILL_VERIFIED rows=2 original_columns_except_updated_at_unchanged=true'
echo 'EXPLORATORY_ONLY: source database untouched; clone cleanup follows'
