#!/usr/bin/env bash
set -euo pipefail

# Run from a checkout containing the migrations tested below. This script
# creates only run-labelled resources in a fresh namespace and deletes that
# namespace after the test. CONTROLLER_ENABLED_SMOKE=1 additionally exercises
# a dedicated DB user and two enabled controller replicas with both work gates
# off, against this namespace's fresh MySQL only. CONTROLLER_TRANSITION_SMOKE=1
# adds first-enable, failover and kill-switch checks there. SCHEMA_CAPTURE=1 and
# DDL_CAPTURE=1 leave private
# /tmp metadata TSVs for local comparison; remove them after downloading.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CONTEXT="${KUBE_CONTEXT:-kubernetes-admin@kubernetes}"
SOURCE_NAMESPACE="${SOURCE_NAMESPACE:-clawmanager-zhanghui08-system}"
EXPECTED_APP_DIGEST="${EXPECTED_APP_DIGEST:-4f8ed9600eff963103feec1fcc23f37397ef48ce3961e7542c41e4e0faed7cdd}"
TEST_NODE="${TEST_NODE:-node1}"
SCHEMA_CAPTURE="${SCHEMA_CAPTURE:-0}"
DDL_CAPTURE="${DDL_CAPTURE:-0}"
D_SCHEMA_COMPARE="${D_SCHEMA_COMPARE:-0}"
CONTROLLER_ENABLED_SMOKE="${CONTROLLER_ENABLED_SMOKE:-0}"
CONTROLLER_TRANSITION_SMOKE="${CONTROLLER_TRANSITION_SMOKE:-0}"
CONTROLLER_GRANT_DRIFT_SMOKE="${CONTROLLER_GRANT_DRIFT_SMOKE:-0}"
if [[ "$D_SCHEMA_COMPARE" == 1 ]]; then
  SCHEMA_CAPTURE=1
  DDL_CAPTURE=1
fi
EXPECTED_MIGRATIONS=91
RUN_ID="$(date -u +%y%m%d%H%M%S)-$(printf '%04x' "$RANDOM")"
RUN_NAMESPACE="sbk-mig-$RUN_ID"
RUN_NAMESPACE_UID=''
INIT_SQL=''
EXPECTED_LIST=''
APPLIED_LIST=''
SCHEMA_CAPTURE_DIR=''
SCHEMA_CAPTURE_READY=0
DDL_CAPTURE_READY=0

cleanup() {
  local status=$?
  trap - EXIT
  for file in "$INIT_SQL" "$EXPECTED_LIST" "$APPLIED_LIST"; do
    if [[ -n "$file" && -f "$file" ]]; then rm -f -- "$file"; fi
  done
  if [[ -n "$RUN_NAMESPACE_UID" ]]; then
    local current_uid
    current_uid="$(kubectl --context="$CONTEXT" get namespace "$RUN_NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    if [[ "$current_uid" == "$RUN_NAMESPACE_UID" ]]; then
      if kubectl --context="$CONTEXT" delete namespace "$RUN_NAMESPACE" --wait=true --timeout=180s >/dev/null; then
        printf 'CLEANED namespace=%s uid=%s\n' "$RUN_NAMESPACE" "$RUN_NAMESPACE_UID"
      else
        printf 'CLEANUP_PENDING namespace=%s uid=%s\n' "$RUN_NAMESPACE" "$RUN_NAMESPACE_UID" >&2
        status=1
      fi
    elif [[ -n "$current_uid" ]]; then
      printf 'CLEANUP_SKIPPED namespace UID changed: %s\n' "$RUN_NAMESPACE" >&2
      status=1
    fi
  fi
  if [[ -n "$SCHEMA_CAPTURE_DIR" ]]; then
    if [[ "$status" -eq 0 && ( "$SCHEMA_CAPTURE" == 0 || "$SCHEMA_CAPTURE_READY" == 1 ) && ( "$DDL_CAPTURE" == 0 || "$DDL_CAPTURE_READY" == 1 ) ]]; then
      if [[ "$SCHEMA_CAPTURE" == 1 ]]; then
        printf 'SCHEMA_CAPTURE fresh=%s live=%s\n' "$SCHEMA_CAPTURE_DIR/fresh.tsv" "$SCHEMA_CAPTURE_DIR/live.tsv"
        sha256sum "$SCHEMA_CAPTURE_DIR/fresh.tsv" "$SCHEMA_CAPTURE_DIR/live.tsv"
      fi
      if [[ "$DDL_CAPTURE" == 1 ]]; then
        printf 'DDL_CAPTURE fresh=%s live=%s\n' "$SCHEMA_CAPTURE_DIR/fresh-ddl.tsv" "$SCHEMA_CAPTURE_DIR/live-ddl.tsv"
        sha256sum "$SCHEMA_CAPTURE_DIR/fresh-ddl.tsv" "$SCHEMA_CAPTURE_DIR/live-ddl.tsv"
      fi
    else
      rm -f -- "$SCHEMA_CAPTURE_DIR/fresh.tsv" "$SCHEMA_CAPTURE_DIR/live.tsv" "$SCHEMA_CAPTURE_DIR/fresh-ddl.tsv" "$SCHEMA_CAPTURE_DIR/live-ddl.tsv"
      rmdir -- "$SCHEMA_CAPTURE_DIR"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

for tool in kubectl mktemp find sort diff od tr; do
  command -v "$tool" >/dev/null || { printf 'missing existing tool: %s\n' "$tool" >&2; exit 1; }
done
[[ "$SCHEMA_CAPTURE" == 0 || "$SCHEMA_CAPTURE" == 1 ]] || { echo 'SCHEMA_CAPTURE must be 0 or 1' >&2; exit 1; }
[[ "$DDL_CAPTURE" == 0 || "$DDL_CAPTURE" == 1 ]] || { echo 'DDL_CAPTURE must be 0 or 1' >&2; exit 1; }
[[ "$D_SCHEMA_COMPARE" == 0 || "$D_SCHEMA_COMPARE" == 1 ]] || { echo 'D_SCHEMA_COMPARE must be 0 or 1' >&2; exit 1; }
[[ "$CONTROLLER_ENABLED_SMOKE" == 0 || "$CONTROLLER_ENABLED_SMOKE" == 1 ]] || { echo 'CONTROLLER_ENABLED_SMOKE must be 0 or 1' >&2; exit 1; }
[[ "$CONTROLLER_TRANSITION_SMOKE" == 0 || "$CONTROLLER_TRANSITION_SMOKE" == 1 ]] || { echo 'CONTROLLER_TRANSITION_SMOKE must be 0 or 1' >&2; exit 1; }
[[ "$CONTROLLER_TRANSITION_SMOKE" == 0 || "$CONTROLLER_ENABLED_SMOKE" == 1 ]] || { echo 'controller transition requires CONTROLLER_ENABLED_SMOKE=1' >&2; exit 1; }
[[ "$CONTROLLER_GRANT_DRIFT_SMOKE" == 0 || "$CONTROLLER_GRANT_DRIFT_SMOKE" == 1 ]] || { echo 'CONTROLLER_GRANT_DRIFT_SMOKE must be 0 or 1' >&2; exit 1; }
[[ "$CONTROLLER_GRANT_DRIFT_SMOKE" == 0 || "$CONTROLLER_TRANSITION_SMOKE" == 1 ]] || { echo 'controller grant drift requires CONTROLLER_TRANSITION_SMOKE=1' >&2; exit 1; }
if [[ "$CONTROLLER_ENABLED_SMOKE" == 1 ]]; then
  [[ "$SCHEMA_CAPTURE" == 0 && "$DDL_CAPTURE" == 0 ]] || { echo 'controller smoke cannot run with metadata capture' >&2; exit 1; }
  for tool in awk sed grep cat; do
    command -v "$tool" >/dev/null || { printf 'missing existing tool: %s\n' "$tool" >&2; exit 1; }
  done
  for fixture in scripts/system-backup-controller-enabled-phase.sh scripts/system-backup-controller-enabled-fixture.mysql.sql scripts/system-backup-controller-enabled-grants.mysql.sql; do
    [[ -s "$fixture" ]] || { printf 'controller smoke fixture missing: %s\n' "$fixture" >&2; exit 1; }
  done
  if [[ "$CONTROLLER_TRANSITION_SMOKE" == 1 ]]; then
    [[ -s scripts/system-backup-controller-transition-phase.sh ]] || { echo 'controller transition phase missing' >&2; exit 1; }
  fi
  if [[ "$CONTROLLER_GRANT_DRIFT_SMOKE" == 1 ]]; then
    [[ -s scripts/system-backup-controller-grant-drift-phase.sh ]] || { echo 'controller grant drift phase missing' >&2; exit 1; }
  fi
fi
if [[ "$SCHEMA_CAPTURE" == 1 || "$DDL_CAPTURE" == 1 ]]; then
  command -v sha256sum >/dev/null || { echo 'missing existing tool: sha256sum' >&2; exit 1; }
fi
if [[ "$SCHEMA_CAPTURE" == 1 ]]; then
  [[ -s contracts/system-backup/v12/schema-hash-capture.mysql.sql ]] || { echo 'schema capture SQL is missing' >&2; exit 1; }
fi
if [[ "$DDL_CAPTURE" == 1 ]]; then
  [[ -s scripts/system-backup-d-ddl-capture.mysql.sql ]] || { echo 'D DDL capture SQL is missing' >&2; exit 1; }
fi
if [[ "$D_SCHEMA_COMPARE" == 1 ]]; then
  if command -v node >/dev/null; then
    [[ -s scripts/system-backup-d-live-compare.mjs ]] || { echo 'D live comparison script is missing' >&2; exit 1; }
  fi
fi
[[ -d backend/internal/db/migrations ]] || { echo 'run from the ClawManager checkout' >&2; exit 1; }
actual_count="$(find backend/internal/db/migrations -maxdepth 1 -type f -name '*.sql' | wc -l | tr -d ' ')"
[[ "$actual_count" == "$EXPECTED_MIGRATIONS" ]] || { printf 'checkout has %s migrations, expected %s\n' "$actual_count" "$EXPECTED_MIGRATIONS" >&2; exit 1; }

source_image_id="$(kubectl --context="$CONTEXT" --namespace="$SOURCE_NAMESPACE" get pods -l app=clawmanager-app -o jsonpath='{.items[0].status.containerStatuses[0].imageID}')"
app_image="${source_image_id#*://}"
[[ "$app_image" == *@sha256:"$EXPECTED_APP_DIGEST" ]] || {
  printf 'source app digest differs from the pinned test image: %s\n' "$source_image_id" >&2
  exit 1
}
mysql_image_id="$(kubectl --context="$CONTEXT" --namespace="$SOURCE_NAMESPACE" get pods -l app=mysql -o jsonpath='{.items[0].status.containerStatuses[0].imageID}')"
mysql_image="${mysql_image_id#*://}"
[[ "$mysql_image" == *@sha256:* ]] || { printf 'MySQL Pod has no immutable image digest: %s\n' "$mysql_image_id" >&2; exit 1; }
mysql_version="$(kubectl --context="$CONTEXT" --namespace="$SOURCE_NAMESPACE" exec deploy/mysql -- sh -c \
  'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --user="$MYSQL_USER" --database=clawmanager --batch --raw --skip-column-names --execute="SELECT VERSION()"')"
[[ "$mysql_version" == 8.0.* || "$mysql_version" == 8.4.* ]] || {
  printf 'source server is outside the MySQL 8.0/8.4 test matrix: %s\n' "$mysql_version" >&2
  exit 1
}
node_ready="$(kubectl --context="$CONTEXT" get node "$TEST_NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"
[[ "$node_ready" == 'True' ]] || { printf 'test node %s is not Ready\n' "$TEST_NODE" >&2; exit 1; }
for condition in MemoryPressure DiskPressure PIDPressure; do
  pressure="$(kubectl --context="$CONTEXT" get node "$TEST_NODE" -o jsonpath="{.status.conditions[?(@.type==\"$condition\")].status}")"
  [[ "$pressure" == 'False' ]] || { printf 'test node %s has %s=%s\n' "$TEST_NODE" "$condition" "$pressure" >&2; exit 1; }
done

umask 077
INIT_SQL="$(mktemp /tmp/sbk-mig-init.XXXXXXXX.sql)"
EXPECTED_LIST="$(mktemp /tmp/sbk-mig-expected.XXXXXXXX.txt)"
APPLIED_LIST="$(mktemp /tmp/sbk-mig-applied.XXXXXXXX.txt)"
kubectl --context="$CONTEXT" --namespace="$SOURCE_NAMESPACE" get configmap clawmanager-mysql-init -o jsonpath='{.data.001_init_schema\.sql}' > "$INIT_SQL"
[[ -s "$INIT_SQL" ]] || { echo 'source MySQL init SQL is empty' >&2; exit 1; }
find backend/internal/db/migrations -maxdepth 1 -type f -name '*.sql' -printf '%f\n' | sort > "$EXPECTED_LIST"
password="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"

RUN_NAMESPACE_UID="$(kubectl --context="$CONTEXT" create -f - -o jsonpath='{.metadata.uid}' <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $RUN_NAMESPACE
  labels:
    clawmanager.io/test-run: "$RUN_ID"
    clawmanager.io/test-purpose: migration-smoke
EOF
)"
[[ -n "$RUN_NAMESPACE_UID" ]] || { echo 'namespace creation did not return a UID' >&2; exit 1; }
printf 'RUN namespace=%s uid=%s app_image=%s mysql_image=%s mysql_version=%s\n' "$RUN_NAMESPACE" "$RUN_NAMESPACE_UID" "$app_image" "$mysql_image" "$mysql_version"

kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" create configmap mysql-init --from-file=001_init_schema.sql="$INIT_SQL" >/dev/null
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" create -f - >/dev/null <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: migration-db
  labels:
    clawmanager.io/test-run: "$RUN_ID"
type: Opaque
stringData:
  mysql-root-password: "$password"
  mysql-password: "$password"
---
apiVersion: v1
kind: Pod
metadata:
  name: mysql
  labels:
    app: mysql
    clawmanager.io/test-run: "$RUN_ID"
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  nodeSelector:
    kubernetes.io/hostname: $TEST_NODE
  containers:
    - name: mysql
      image: $mysql_image
      imagePullPolicy: IfNotPresent
      args: ["--innodb-use-native-aio=0"]
      resources:
        requests: {cpu: 250m, memory: 512Mi, ephemeral-storage: 512Mi}
        limits: {cpu: "1", memory: 1Gi, ephemeral-storage: 2Gi}
      env:
        - name: MYSQL_ROOT_PASSWORD
          valueFrom: {secretKeyRef: {name: migration-db, key: mysql-root-password}}
        - name: MYSQL_DATABASE
          value: clawmanager
        - name: MYSQL_USER
          value: clawmanager
        - name: MYSQL_PASSWORD
          valueFrom: {secretKeyRef: {name: migration-db, key: mysql-password}}
      readinessProbe:
        exec:
          command: ["sh", "-c", "MYSQL_PWD=\"\$MYSQL_ROOT_PASSWORD\" mysqladmin ping -h 127.0.0.1 -uroot --silent"]
        periodSeconds: 5
      volumeMounts:
        - {name: mysql-data, mountPath: /var/lib/mysql}
        - {name: mysql-init, mountPath: /docker-entrypoint-initdb.d}
  volumes:
    - name: mysql-data
      emptyDir: {sizeLimit: 1Gi}
    - name: mysql-init
      configMap: {name: mysql-init}
EOF
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" wait pod/mysql --for=condition=Ready --timeout=240s >/dev/null

mysql_query() {
  kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" exec pod/mysql -- sh -c \
    'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --user="$MYSQL_USER" --database=clawmanager --batch --raw --skip-column-names --execute="$1"' \
    query "$1"
}

initial_registration="$(mysql_query "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='clawmanager' AND TABLE_NAME='schema_migrations'")"
[[ "$initial_registration" == 0 ]] || { echo 'fresh database already has schema_migrations' >&2; exit 1; }
mysql_ip="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" get pod mysql -o jsonpath='{.status.podIP}')"
[[ -n "$mysql_ip" ]] || { echo 'temporary MySQL has no Pod IP' >&2; exit 1; }

kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" create -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: migration-app-egress
spec:
  podSelector: {matchLabels: {app: migration-app}}
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {app: mysql}}}]
      ports: [{protocol: TCP, port: 3306}]
---
apiVersion: v1
kind: Pod
metadata:
  name: migration-app
  labels:
    app: migration-app
    clawmanager.io/test-run: "$RUN_ID"
spec:
  restartPolicy: Never
  activeDeadlineSeconds: 240
  automountServiceAccountToken: false
  nodeSelector:
    kubernetes.io/hostname: $TEST_NODE
  containers:
    - name: migration-app
      image: $app_image
      imagePullPolicy: IfNotPresent
      command: ["/usr/local/bin/clawreef-server"]
      resources:
        requests: {cpu: 100m, memory: 256Mi, ephemeral-storage: 128Mi}
        limits: {cpu: "1", memory: 1Gi, ephemeral-storage: 1Gi}
      env:
        - {name: DB_HOST, value: "$mysql_ip"}
        - {name: DB_PORT, value: "3306"}
        - {name: DB_USER, value: clawmanager}
        - name: DB_PASSWORD
          valueFrom: {secretKeyRef: {name: migration-db, key: mysql-password}}
        - {name: DB_NAME, value: clawmanager}
        - {name: SERVER_ADDRESS, value: "127.0.0.1:9001"}
        - {name: SERVER_MODE, value: release}
        - {name: OBJECT_STORAGE_ENDPOINT, value: "127.0.0.1:1"}
        - {name: SYSTEM_BACKUP_ENABLED, value: "false"}
EOF

deadline=$((SECONDS + 210))
applied_count=0
while (( SECONDS < deadline )); do
  applied_count="$(mysql_query 'SELECT COUNT(*) FROM schema_migrations' 2>/dev/null || true)"
  [[ "$applied_count" == "$EXPECTED_MIGRATIONS" ]] && break
  sleep 5
done
[[ "$applied_count" == "$EXPECTED_MIGRATIONS" ]] || {
  printf 'migration replay stopped at %s/%s; app Pod phase: ' "$applied_count" "$EXPECTED_MIGRATIONS" >&2
  kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" get pod migration-app -o jsonpath='{.status.phase}' >&2 || true
  printf '\n' >&2
  exit 1
}
mysql_query 'SELECT filename FROM schema_migrations ORDER BY filename' > "$APPLIED_LIST"
diff -u "$EXPECTED_LIST" "$APPLIED_LIST"
column_types="$(mysql_query "SELECT CONCAT(TABLE_NAME,'.',COLUMN_NAME,'=',DATA_TYPE) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='clawmanager' AND ((TABLE_NAME='system_backup_operations' AND COLUMN_NAME IN ('external_action_public_ids_canonical_json','retry_of_operation_public_id')) OR (TABLE_NAME='system_backup_check_results' AND COLUMN_NAME IN ('expected_canonical_json','actual_canonical_json'))) ORDER BY TABLE_NAME,COLUMN_NAME")"
expected_types=$' system_backup_check_results.actual_canonical_json=blob\nsystem_backup_check_results.expected_canonical_json=blob\nsystem_backup_operations.external_action_public_ids_canonical_json=blob\nsystem_backup_operations.retry_of_operation_public_id=char'
expected_types="${expected_types# }"
[[ "$column_types" == "$expected_types" ]] || { printf 'unexpected D column types:\n%s\n' "$column_types" >&2; exit 1; }
printf 'PASS fresh-migration-replay=001..078 applied=%s exact_filenames=yes d_columns=blob/blob/blob/char\n' "$applied_count"
if [[ "$CONTROLLER_ENABLED_SMOKE" == 1 ]]; then
  # The sourced phase reuses this run's isolated MySQL, image and UID cleanup.
  source scripts/system-backup-controller-enabled-phase.sh
  if [[ "$CONTROLLER_TRANSITION_SMOKE" == 1 ]]; then
    source scripts/system-backup-controller-transition-phase.sh
    if [[ "$CONTROLLER_GRANT_DRIFT_SMOKE" == 1 ]]; then
      source scripts/system-backup-controller-grant-drift-phase.sh
    fi
  fi
fi
if [[ "$SCHEMA_CAPTURE" == 1 || "$DDL_CAPTURE" == 1 ]]; then
  SCHEMA_CAPTURE_DIR="$(mktemp -d /tmp/sbk-schema-compare.XXXXXXXX)"
fi
if [[ "$SCHEMA_CAPTURE" == 1 ]]; then
  capture_sql='contracts/system-backup/v12/schema-hash-capture.mysql.sql'
  kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" exec -i pod/mysql -- sh -c \
    'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --user="$MYSQL_USER" --database=clawmanager --batch --raw --skip-column-names --default-character-set=utf8mb4' \
    < "$capture_sql" > "$SCHEMA_CAPTURE_DIR/fresh.tsv"
  kubectl --context="$CONTEXT" --namespace="$SOURCE_NAMESPACE" exec -i deploy/mysql -- sh -c \
    'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --user="$MYSQL_USER" --database=clawmanager --batch --raw --skip-column-names --default-character-set=utf8mb4' \
    < "$capture_sql" > "$SCHEMA_CAPTURE_DIR/live.tsv"
  [[ -s "$SCHEMA_CAPTURE_DIR/fresh.tsv" && -s "$SCHEMA_CAPTURE_DIR/live.tsv" ]] || { echo 'schema capture was empty' >&2; exit 1; }
  SCHEMA_CAPTURE_READY=1
fi
if [[ "$DDL_CAPTURE" == 1 ]]; then
  capture_sql='scripts/system-backup-d-ddl-capture.mysql.sql'
  kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" exec -i pod/mysql -- sh -c \
    'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --user="$MYSQL_USER" --database=clawmanager --batch --raw --skip-column-names --default-character-set=utf8mb4' \
    < "$capture_sql" > "$SCHEMA_CAPTURE_DIR/fresh-ddl.tsv"
  kubectl --context="$CONTEXT" --namespace="$SOURCE_NAMESPACE" exec -i deploy/mysql -- sh -c \
    'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --user="$MYSQL_USER" --database=clawmanager --batch --raw --skip-column-names --default-character-set=utf8mb4' \
    < "$capture_sql" > "$SCHEMA_CAPTURE_DIR/live-ddl.tsv"
  [[ -s "$SCHEMA_CAPTURE_DIR/fresh-ddl.tsv" && -s "$SCHEMA_CAPTURE_DIR/live-ddl.tsv" ]] || { echo 'D DDL capture was empty' >&2; exit 1; }
  DDL_CAPTURE_READY=1
fi

if [[ "$D_SCHEMA_COMPARE" == 1 ]]; then
  if command -v node >/dev/null; then
    node scripts/system-backup-d-live-compare.mjs \
      --fresh-schema "$SCHEMA_CAPTURE_DIR/fresh.tsv" \
      --live-schema "$SCHEMA_CAPTURE_DIR/live.tsv" \
      --fresh-ddl "$SCHEMA_CAPTURE_DIR/fresh-ddl.tsv" \
      --live-ddl "$SCHEMA_CAPTURE_DIR/live-ddl.tsv"
  else
    # MySQL does not guarantee UNION ALL result order. Compare identical
    # read-only metadata records as multisets without retaining sorted files.
    fresh_schema_hash="$(LC_ALL=C sort "$SCHEMA_CAPTURE_DIR/fresh.tsv" | sha256sum)"
    live_schema_hash="$(LC_ALL=C sort "$SCHEMA_CAPTURE_DIR/live.tsv" | sha256sum)"
    fresh_ddl_hash="$(LC_ALL=C sort "$SCHEMA_CAPTURE_DIR/fresh-ddl.tsv" | sha256sum)"
    live_ddl_hash="$(LC_ALL=C sort "$SCHEMA_CAPTURE_DIR/live-ddl.tsv" | sha256sum)"
    fresh_schema_hash="${fresh_schema_hash%% *}"
    live_schema_hash="${live_schema_hash%% *}"
    fresh_ddl_hash="${fresh_ddl_hash%% *}"
    live_ddl_hash="${live_ddl_hash%% *}"
    printf 'D_COMPARE mode=sorted-raw-no-node schema_fresh_sha256=%s schema_live_sha256=%s ddl_fresh_sha256=%s ddl_live_sha256=%s\n' \
      "$fresh_schema_hash" "$live_schema_hash" "$fresh_ddl_hash" "$live_ddl_hash"
    if [[ "$fresh_schema_hash" != "$live_schema_hash" || "$fresh_ddl_hash" != "$live_ddl_hash" ]]; then
      echo 'D comparison unresolved: captured metadata records differ; run local canonical comparison from private captures' >&2
      exit 1
    fi
    printf 'PASS d-live-compare mode=sorted-raw-no-node schema-records=identical ddl-records=identical canonical-hash=not-computed\n'
  fi
  rm -f -- "$SCHEMA_CAPTURE_DIR/fresh.tsv" "$SCHEMA_CAPTURE_DIR/live.tsv" "$SCHEMA_CAPTURE_DIR/fresh-ddl.tsv" "$SCHEMA_CAPTURE_DIR/live-ddl.tsv"
  rmdir -- "$SCHEMA_CAPTURE_DIR"
  SCHEMA_CAPTURE_DIR=''
  printf 'PASS d-live-compare raw-captures=deleted\n'
fi
