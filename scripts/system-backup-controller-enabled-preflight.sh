#!/usr/bin/env bash
set -euo pipefail

# Read-only prerequisites for an enabled controller trial on the existing test
# installation. Expected missing prerequisites print BLOCKED and exit zero, so
# an interactive SSH shell with `set -e` does not close on that outcome.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CONTEXT="${KUBE_CONTEXT:-kubernetes-admin@kubernetes}"
NAMESPACE="${SOURCE_NAMESPACE:-clawmanager-zhanghui08-system}"
EXPECTED_APP_DIGEST="${EXPECTED_APP_DIGEST:-4f8ed9600eff963103feec1fcc23f37397ef48ce3961e7542c41e4e0faed7cdd}"
SECRET='clawmanager-system-backup-controller-db'
DEPLOYMENT='clawmanager-system-backup-controller'
blockers=()

for tool in kubectl awk find sort; do
  command -v "$tool" >/dev/null || { printf 'missing existing tool: %s\n' "$tool" >&2; exit 1; }
done
[[ -s deployments/k8s/system-backup-controller.yaml ]] || { echo 'controller manifest is missing' >&2; exit 1; }
namespace_uid="$(kubectl --context="$CONTEXT" get namespace "$NAMESPACE" -o jsonpath='{.metadata.uid}')"
[[ -n "$namespace_uid" ]] || { echo 'namespace has no UID' >&2; exit 1; }

app_pod="$(kubectl --context="$CONTEXT" --namespace="$NAMESPACE" get pods -l app=clawmanager-app -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$app_pod" ]] || { echo 'app Pod not found' >&2; exit 1; }
app_image_id="$(kubectl --context="$CONTEXT" --namespace="$NAMESPACE" get pod "$app_pod" -o jsonpath='{.status.containerStatuses[0].imageID}')"
app_image="${app_image_id#*://}"
if [[ "$app_image" != *@sha256:"$EXPECTED_APP_DIGEST" ]]; then
  blockers+=(app_image_digest_changed)
fi
binary_available=no
if kubectl --context="$CONTEXT" --namespace="$NAMESPACE" exec "$app_pod" -- test -x /usr/local/bin/clawreef-system-backup-controller >/dev/null 2>&1; then
  binary_available=yes
else
  blockers+=(controller_binary_missing)
fi
runtime_catalog=unverified
if [[ "$binary_available" == yes ]]; then
  # The controller validates its embedded catalog before opening a DB connection.
  # Explicit loopback port 1 and a dummy password keep this probe off the live DB.
  catalog_probe_output="$(kubectl --context="$CONTEXT" --namespace="$NAMESPACE" --request-timeout=20s exec "$app_pod" -- env \
    SYSTEM_BACKUP_CONTROLLER_ENABLED=true \
    CLAWMANAGER_LEADER_ELECTION=true \
    SYSTEM_BACKUP_ORIGIN_INSTALLATION_ID=installation_catalog_probe \
    DB_HOST=127.0.0.1 DB_PORT=1 DB_USER=sbk_controller DB_PASSWORD=catalog-probe-only DB_NAME=clawmanager \
    /usr/local/bin/clawreef-system-backup-controller 2>&1 || true)"
  if [[ "$catalog_probe_output" == *catalog_mismatch* ]]; then
    runtime_catalog=mismatch
    blockers+=(runtime_embedded_catalog_mismatch)
  elif [[ "$catalog_probe_output" == *'connect control database:'* ]]; then
    runtime_catalog=matches
  else
    blockers+=(runtime_catalog_unverified)
  fi
fi

mysql_query() {
  kubectl --context="$CONTEXT" --namespace="$NAMESPACE" exec deploy/mysql -- sh -c \
    'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --user="$MYSQL_USER" --database=clawmanager --batch --raw --skip-column-names --execute="$1"' \
    sh "$1"
}

read -r migrations state_rows state_id_count joined_rows config_rows first_enabled effective_enabled config_enabled identity_hash < <(
  mysql_query "SELECT
    (SELECT COUNT(*) FROM schema_migrations),
    (SELECT COUNT(*) FROM system_backup_installation_state),
    (SELECT COUNT(DISTINCT origin_installation_id) FROM system_backup_installation_state),
    (SELECT COUNT(*) FROM system_backup_installation_state AS s JOIN system_backup_configs AS c
       ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version),
    (SELECT COUNT(*) FROM system_backup_configs),
    (SELECT COUNT(*) FROM system_backup_installation_state WHERE first_enabled_at IS NOT NULL),
    (SELECT COUNT(*) FROM system_backup_installation_state WHERE last_effective_enabled=1),
    (SELECT COUNT(*) FROM system_backup_installation_state AS s JOIN system_backup_configs AS c
       ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version
      WHERE c.enabled=1),
    COALESCE((SELECT SHA2(origin_installation_id,256) FROM system_backup_installation_state LIMIT 1),'none')"
)
[[ "$migrations" =~ ^[0-9]+$ && "$state_rows" =~ ^[0-9]+$ && "$state_id_count" =~ ^[0-9]+$ && "$joined_rows" =~ ^[0-9]+$ && "$config_rows" =~ ^[0-9]+$ && "$first_enabled" =~ ^[0-9]+$ && "$effective_enabled" =~ ^[0-9]+$ && "$config_enabled" =~ ^[0-9]+$ ]] || {
  echo 'unexpected MySQL preflight result' >&2
  exit 1
}
[[ "$migrations" -ge 91 ]] || blockers+=(migration_count_below_embedded_catalog)
# The pinned image is expected to embed the 91 repository migrations through 078.
# Later migrations in this checkout are not part of that immutable image.
mapfile -t expected_migrations < <(find backend/internal/db/migrations -maxdepth 1 -type f -name '*.sql' -printf '%f\n' | awk 'substr($0,1,3) ~ /^[0-9][0-9][0-9]$/ && substr($0,1,3)+0 <= 78' | sort)
[[ "${#expected_migrations[@]}" == 91 ]] || { printf 'expected 91 pinned migration filenames in checkout, found %s\n' "${#expected_migrations[@]}" >&2; exit 1; }
mapfile -t registered_migrations < <(mysql_query 'SELECT filename FROM schema_migrations ORDER BY filename')
[[ "${#registered_migrations[@]}" == "$migrations" ]] || { echo 'migration row count changed during preflight or filename query failed' >&2; exit 1; }
declare -A registered=()
for filename in "${registered_migrations[@]}"; do registered["$filename"]=1; done
missing_migrations=()
for filename in "${expected_migrations[@]}"; do
  [[ -n "${registered[$filename]+present}" ]] || missing_migrations+=("$filename")
done
embedded_filenames=all_registered
if ((${#missing_migrations[@]})); then
  embedded_filenames="missing:${missing_migrations[0]}"
  blockers+=(embedded_migrations_missing)
fi
[[ "$state_rows" == 1 && "$state_id_count" == 1 ]] || blockers+=(installation_state_not_unique)
[[ "$joined_rows" == 1 ]] || blockers+=(active_config_missing_or_ambiguous)

secret_exists=no
secret_password_key=no
if kubectl --context="$CONTEXT" --namespace="$NAMESPACE" get secret "$SECRET" -o name >/dev/null 2>&1; then
  secret_exists=yes
  secret_password_key="$(kubectl --context="$CONTEXT" --namespace="$NAMESPACE" get secret "$SECRET" -o go-template='{{if index .data "password"}}yes{{else}}no{{end}}')"
fi
[[ "$secret_password_key" == yes ]] || blockers+=(dedicated_db_secret_password_missing)

deployment_exists=no
deployment_gate=absent
if kubectl --context="$CONTEXT" --namespace="$NAMESPACE" get deployment "$DEPLOYMENT" -o name >/dev/null 2>&1; then
  deployment_exists=yes
  deployment_gate="$(kubectl --context="$CONTEXT" --namespace="$NAMESPACE" get deployment "$DEPLOYMENT" -o go-template='{{range .spec.template.spec.containers}}{{range .env}}{{if eq .name "SYSTEM_BACKUP_CONTROLLER_ENABLED"}}{{.value}}{{end}}{{end}}{{end}}')"
  [[ "$deployment_gate" == false ]] || blockers+=(existing_controller_gate_not_disabled)
fi

printf 'RUN context=%s namespace=%s uid=%s app_image=%s binary_available=%s runtime_catalog=%s\n' "$CONTEXT" "$NAMESPACE" "$namespace_uid" "$app_image" "$binary_available" "$runtime_catalog"
printf 'DB migrations=%s expected_catalog_files=91 expected_filenames=%s installation_rows=%s installation_id_count=%s identity_sha256=%s active_config_joins=%s config_rows=%s first_enabled_rows=%s effective_enabled_rows=%s active_config_enabled_rows=%s\n' \
  "$migrations" "$embedded_filenames" "$state_rows" "$state_id_count" "$identity_hash" "$joined_rows" "$config_rows" "$first_enabled" "$effective_enabled" "$config_enabled"
printf 'K8S db_secret_exists=%s db_secret_password_key=%s controller_deployment_exists=%s controller_gate=%s\n' \
  "$secret_exists" "$secret_password_key" "$deployment_exists" "$deployment_gate"
if ((${#blockers[@]})); then
  printf 'BLOCKED enabled-controller-preflight reasons=%s\n' "$(IFS=,; echo "${blockers[*]}")"
else
  echo 'PASS enabled-controller-preflight=read-only prerequisites-present dedicated-db-grants=unverified enabled-trial=not-run'
fi
