#!/usr/bin/env bash
set -euo pipefail

# Isolated D-only smoke: actual manifest RBAC plus disabled health endpoints.
# Never enables the controller, connects to the live DB or creates a backup Job.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CONTEXT="${KUBE_CONTEXT:-kubernetes-admin@kubernetes}"
SOURCE_NAMESPACE="${SOURCE_NAMESPACE:-clawmanager-zhanghui08-system}"
EXPECTED_APP_DIGEST="${EXPECTED_APP_DIGEST:-4f8ed9600eff963103feec1fcc23f37397ef48ce3961e7542c41e4e0faed7cdd}"
TEST_NODE="${TEST_NODE:-node1}"
RUN_ID="$(date -u +%y%m%d%H%M%S)-$(printf '%04x' "$RANDOM")"
RUN_NAMESPACE="sbk-ctrl-$RUN_ID"
RUN_NAMESPACE_UID=''
LEADER_LEASE='clawmanager-system-backup-controller'
SERVICE_ACCOUNT='clawmanager-system-backup-controller'

cleanup() {
  local status=$?
  trap - EXIT
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
  exit "$status"
}
trap cleanup EXIT

for tool in kubectl awk sed grep; do
  command -v "$tool" >/dev/null || { printf 'missing existing tool: %s\n' "$tool" >&2; exit 1; }
done
manifest='deployments/k8s/system-backup-controller.yaml'
[[ -s "$manifest" ]] || { echo 'controller manifest is missing' >&2; exit 1; }
[[ "$(grep -c '^---$' "$manifest")" == 3 ]] || { echo 'controller manifest document layout changed' >&2; exit 1; }
awk '/name: SYSTEM_BACKUP_CONTROLLER_ENABLED/ {getline; if ($0 ~ /value: "false"/) found=1} END {exit !found}' "$manifest" || {
  echo 'controller disabled default is missing' >&2
  exit 1
}

source_image_id="$(kubectl --context="$CONTEXT" --namespace="$SOURCE_NAMESPACE" get pods -l app=clawmanager-app -o jsonpath='{.items[0].status.containerStatuses[0].imageID}')"
app_image="${source_image_id#*://}"
[[ "$app_image" == *@sha256:"$EXPECTED_APP_DIGEST" ]] || {
  printf 'source app digest differs from pinned smoke image: %s\n' "$source_image_id" >&2
  exit 1
}
node_ready="$(kubectl --context="$CONTEXT" get node "$TEST_NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"
[[ "$node_ready" == True ]] || { printf 'test node %s is not Ready\n' "$TEST_NODE" >&2; exit 1; }
for condition in MemoryPressure DiskPressure PIDPressure; do
  pressure="$(kubectl --context="$CONTEXT" get node "$TEST_NODE" -o jsonpath="{.status.conditions[?(@.type==\"$condition\")].status}")"
  [[ "$pressure" == False ]] || { printf 'test node %s has %s=%s\n' "$TEST_NODE" "$condition" "$pressure" >&2; exit 1; }
done

source_pod="$(kubectl --context="$CONTEXT" --namespace="$SOURCE_NAMESPACE" get pods -l app=clawmanager-app -o jsonpath='{.items[0].metadata.name}')"
binary_available=0
if kubectl --context="$CONTEXT" --namespace="$SOURCE_NAMESPACE" exec "$source_pod" -- sh -c \
  'test -x /usr/local/bin/clawreef-system-backup-controller && command -v wget >/dev/null' >/dev/null 2>&1; then
  binary_available=1
fi

RUN_NAMESPACE_UID="$(kubectl --context="$CONTEXT" create -f - -o jsonpath='{.metadata.uid}' <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $RUN_NAMESPACE
  labels:
    clawmanager.io/test-run: "$RUN_ID"
    clawmanager.io/test-purpose: controller-disabled-smoke
EOF
)"
[[ -n "$RUN_NAMESPACE_UID" ]] || { echo 'namespace creation returned no UID' >&2; exit 1; }
printf 'RUN namespace=%s uid=%s app_image=%s binary_available=%s\n' "$RUN_NAMESPACE" "$RUN_NAMESPACE_UID" "$app_image" "$binary_available"

# Reuse the ServiceAccount, Role and RoleBinding directly from the D manifest.
awk '/^---$/ {n++; if (n == 3) exit} {print}' "$manifest" |
  sed "s/namespace: clawmanager-system/namespace: $RUN_NAMESPACE/g" |
  kubectl --context="$CONTEXT" create -f - >/dev/null

kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" create -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: controller-smoke-deny-all
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
EOF

as_account="system:serviceaccount:$RUN_NAMESPACE:$SERVICE_ACCOUNT"
assert_can_i() {
  local expected="$1" verb="$2" resource="$3" answer
  local -a scope=()
  if [[ "$resource" != nodes ]]; then scope=(--namespace="$RUN_NAMESPACE"); fi
  if answer="$(kubectl --context="$CONTEXT" "${scope[@]}" --as="$as_account" auth can-i "$verb" "$resource")"; then
    :
  else
    :
  fi
  [[ "$answer" == "$expected" ]] || { printf 'RBAC mismatch %s %s: expected %s, got %s\n' "$verb" "$resource" "$expected" "$answer" >&2; return 1; }
}

assert_can_i yes create leases.coordination.k8s.io
for verb in get update patch; do
  assert_can_i yes "$verb" "leases.coordination.k8s.io/$LEADER_LEASE"
  assert_can_i no "$verb" leases.coordination.k8s.io/other-leader
done
for pair in 'list leases.coordination.k8s.io' 'watch leases.coordination.k8s.io' \
  "delete leases.coordination.k8s.io/$LEADER_LEASE" 'get secrets' 'create pods' \
  'create jobs.batch' 'create rolebindings.rbac.authorization.k8s.io' 'get nodes'; do
  read -r verb resource <<< "$pair"
  assert_can_i no "$verb" "$resource"
done
printf 'PASS controller-rbac lease-create=namespaced-any lease-get/update/patch=leader-only forbidden=other-lease-reads-or-writes/list/watch/delete/secrets/pods/jobs/rolebindings/nodes\n'

if [[ "$binary_available" != 1 ]]; then
  printf 'SKIP controller-disabled-health reason=binary-or-wget-absent-in-running-app-image\n'
  exit 0
fi

kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" create -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: controller-disabled
  labels:
    app: controller-disabled
    clawmanager.io/test-run: "$RUN_ID"
spec:
  restartPolicy: Never
  activeDeadlineSeconds: 120
  serviceAccountName: $SERVICE_ACCOUNT
  automountServiceAccountToken: false
  nodeSelector:
    kubernetes.io/hostname: $TEST_NODE
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: controller
      image: $app_image
      imagePullPolicy: IfNotPresent
      command: ["/usr/local/bin/clawreef-system-backup-controller"]
      resources:
        requests: {cpu: 25m, memory: 32Mi, ephemeral-storage: 32Mi}
        limits: {cpu: 250m, memory: 128Mi, ephemeral-storage: 128Mi}
      env:
        - {name: SYSTEM_BACKUP_CONTROLLER_ENABLED, value: "false"}
        - {name: SYSTEM_BACKUP_CONTROLLER_HEALTH_ADDRESS, value: ":9003"}
        - {name: DB_HOST, value: "127.0.0.1"}
        - {name: DB_PORT, value: "1"}
      readinessProbe:
        httpGet: {path: /readyz, port: 9003}
        periodSeconds: 5
      livenessProbe:
        httpGet: {path: /healthz, port: 9003}
        periodSeconds: 10
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
EOF
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" wait pod/controller-disabled --for=condition=Ready --timeout=90s >/dev/null
health="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" exec pod/controller-disabled -- wget -qO- http://127.0.0.1:9003/healthz)"
ready="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" exec pod/controller-disabled -- wget -qO- http://127.0.0.1:9003/readyz)"
[[ "$health" == ok && "$ready" == disabled ]] || {
  printf 'unexpected disabled health=%q ready=%q\n' "$health" "$ready" >&2
  exit 1
}
lease_names="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" get leases.coordination.k8s.io -o jsonpath='{.items[*].metadata.name}')"
[[ -z "$lease_names" ]] || { printf 'disabled controller created Lease: %s\n' "$lease_names" >&2; exit 1; }
printf 'PASS controller-disabled healthz=ok readyz=disabled db_endpoint=127.0.0.1:1 sa_token=off lease_created=no\n'
