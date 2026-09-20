#!/usr/bin/env bash
# Sourced only by system-backup-fresh-migration-smoke.sh after its fresh replay.
[[ "${CONTROLLER_ENABLED_SMOKE:-0}" == 1 && -n "${RUN_NAMESPACE_UID:-}" ]] || {
  echo 'controller phase requires the isolated migration smoke run' >&2
  return 1
}

installation_id="installation_${RUN_ID}"
controller_password="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
mysql_root_stream() {
  kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" exec -i pod/mysql -- sh -c \
    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --user=root --database=clawmanager --batch --raw --skip-column-names'
}

# All fixture writes are confined to this run's fresh MySQL emptyDir.
{
  printf "SET @installation_id='%s';\n" "$installation_id"
  cat scripts/system-backup-controller-enabled-fixture.mysql.sql
} | mysql_root_stream
fixture_state="$(mysql_query "SELECT CONCAT((SELECT COUNT(*) FROM system_backup_configs WHERE origin_installation_id='$installation_id' AND version=1 AND enabled=0),':',(SELECT COUNT(*) FROM system_backup_installation_state WHERE origin_installation_id='$installation_id' AND active_config_version=1 AND first_enabled_at IS NULL))")"
[[ "$fixture_state" == 1:1 ]] || { printf 'controller fixture rows invalid: %s\n' "$fixture_state" >&2; return 1; }

{
  printf "CREATE USER 'sbk_controller'@'%%' IDENTIFIED BY '%s';\n" "$controller_password"
  cat scripts/system-backup-controller-enabled-grants.mysql.sql
} | mysql_root_stream
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" create -f - >/dev/null <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: clawmanager-system-backup-controller-db
  labels: {clawmanager.io/test-run: "$RUN_ID"}
type: Opaque
stringData:
  password: "$controller_password"
EOF
unset controller_password

# The exact draft ServiceAccount, Role and RoleBinding are reused. No cluster
# role, Secret read, Pod write or Job write is granted to the controller.
awk '/^---$/ {n++; if (n == 3) exit} {print}' deployments/k8s/system-backup-controller.yaml |
  sed "s/namespace: clawmanager-system/namespace: $RUN_NAMESPACE/g" |
  kubectl --context="$CONTEXT" create -f - >/dev/null

kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" create -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: controller-smoke-mysql-ingress
spec:
  podSelector: {matchLabels: {app: mysql}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {matchLabels: {app: migration-app}}
        - podSelector: {matchLabels: {app: controller-enabled}}
        - podSelector: {matchLabels: {app: grant-negative}}
      ports: [{protocol: TCP, port: 3306}]
---
apiVersion: v1
kind: Pod
metadata:
  name: grant-negative
  labels: {app: grant-negative}
spec:
  restartPolicy: Never
  activeDeadlineSeconds: 120
  automountServiceAccountToken: false
  nodeSelector: {kubernetes.io/hostname: $TEST_NODE}
  containers:
    - name: mysql-client
      image: $mysql_image
      imagePullPolicy: IfNotPresent
      command:
        - sh
        - -ec
        - |
          export MYSQL_PWD="\$CONTROLLER_DB_PASSWORD"
          mysql --protocol=tcp --host="\$DB_HOST" --user=sbk_controller --database=clawmanager --batch --raw --skip-column-names --execute='SELECT COUNT(*) FROM schema_migrations' | grep -qx 91
          mysql --protocol=tcp --host="\$DB_HOST" --user=sbk_controller --database=clawmanager --batch --raw --skip-column-names --execute='SELECT CURRENT_USER(), CURRENT_ROLE()' | grep -Eq '^sbk_controller@.+[[:space:]]NONE$'
          if mysql --protocol=tcp --host="\$DB_HOST" --user=sbk_controller --database=clawmanager --execute='SELECT COUNT(*) FROM users' >/dev/null 2>&1; then echo 'unexpected users SELECT permission' >&2; exit 1; fi
          if mysql --protocol=tcp --host="\$DB_HOST" --user=sbk_controller --database=clawmanager --execute='DELETE FROM schema_migrations WHERE 1=0' >/dev/null 2>&1; then echo 'unexpected schema_migrations DELETE permission' >&2; exit 1; fi
          echo 'PASS dedicated-db-user positive=registered-migrations/current-user/no-role negative=users-select/schema-migrations-delete'
      resources:
        requests: {cpu: 25m, memory: 64Mi}
        limits: {cpu: 250m, memory: 256Mi}
      env:
        - {name: DB_HOST, value: "$mysql_ip"}
        - name: CONTROLLER_DB_PASSWORD
          valueFrom: {secretKeyRef: {name: clawmanager-system-backup-controller-db, key: password}}
EOF

deadline=$((SECONDS + 120))
while (( SECONDS < deadline )); do
  grant_phase="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" get pod grant-negative -o jsonpath='{.status.phase}')"
  [[ "$grant_phase" == Succeeded || "$grant_phase" == Failed ]] && break
  sleep 3
done
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" logs pod/grant-negative
[[ "${grant_phase:-}" == Succeeded ]] || { echo 'dedicated user positive/negative probe failed' >&2; return 1; }

kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" create -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: controller-enabled-smoke
  labels: {clawmanager.io/test-run: "$RUN_ID"}
spec:
  replicas: 2
  selector: {matchLabels: {app: controller-enabled}}
  template:
    metadata:
      labels: {app: controller-enabled, clawmanager.io/test-run: "$RUN_ID"}
    spec:
      serviceAccountName: clawmanager-system-backup-controller
      automountServiceAccountToken: true
      nodeSelector: {kubernetes.io/hostname: $TEST_NODE}
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
            requests: {cpu: 25m, memory: 64Mi}
            limits: {cpu: 250m, memory: 256Mi}
          env:
            - {name: SYSTEM_BACKUP_CONTROLLER_ENABLED, value: "true"}
            - {name: SYSTEM_BACKUP_ENABLED, value: "false"}
            - {name: SYSTEM_BACKUP_REQUIRED, value: "false"}
            - {name: SYSTEM_BACKUP_ORIGIN_INSTALLATION_ID, value: "$installation_id"}
            - {name: SYSTEM_BACKUP_CONTROLLER_HEALTH_ADDRESS, value: ":9003"}
            - {name: SYSTEM_BACKUP_CONTROLLER_LEADER_LEASE_NAME, value: "clawmanager-system-backup-controller"}
            - {name: CLAWMANAGER_LEADER_ELECTION, value: "true"}
            - {name: POD_NAME, valueFrom: {fieldRef: {fieldPath: metadata.name}}}
            - {name: POD_NAMESPACE, valueFrom: {fieldRef: {fieldPath: metadata.namespace}}}
            - {name: K8S_MODE, value: incluster}
            - {name: DB_HOST, value: "$mysql_ip"}
            - {name: DB_PORT, value: "3306"}
            - {name: DB_USER, value: sbk_controller}
            - name: DB_PASSWORD
              valueFrom: {secretKeyRef: {name: clawmanager-system-backup-controller-db, key: password}}
            - {name: DB_NAME, value: clawmanager}
            - {name: DB_MAX_OPEN_CONNS, value: "5"}
            - {name: DB_MAX_IDLE_CONNS, value: "2"}
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

if ! kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" rollout status deployment/controller-enabled-smoke --timeout=180s; then
  kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" logs -l app=controller-enabled --all-containers=true --prefix=true --tail=60 >&2 || true
  return 1
fi
mapfile -t controller_pods < <(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" get pods -l app=controller-enabled -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[[ "${#controller_pods[@]}" == 2 ]] || { printf 'expected two controller Pods, got %s\n' "${#controller_pods[@]}" >&2; return 1; }

leader_count=0
standby_count=0
for pod in "${controller_pods[@]}"; do
  ready="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" exec "$pod" -- wget -qO- http://127.0.0.1:9003/readyz)"
  case "$ready" in
    'leader config=disabled effective=disabled config_version=1 catalog=b3fe27c26b2'*) ((leader_count+=1)) ;;
    'standby config=disabled effective=disabled config_version=1 catalog=b3fe27c26b2'*) ((standby_count+=1)) ;;
    *) printf 'unexpected controller readyz %s: %s\n' "$pod" "$ready" >&2; return 1 ;;
  esac
done
[[ "$leader_count" == 1 && "$standby_count" == 1 ]] || { printf 'controller roles leader=%s standby=%s\n' "$leader_count" "$standby_count" >&2; return 1; }
lease_holder="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" get lease clawmanager-system-backup-controller -o jsonpath='{.spec.holderIdentity}')"
[[ "$lease_holder" == "system-backup-controller:${controller_pods[0]}" || "$lease_holder" == "system-backup-controller:${controller_pods[1]}" ]] || {
  printf 'unexpected leader Lease holder: %s\n' "$lease_holder" >&2
  return 1
}
state_flags="$(mysql_query "SELECT CONCAT(first_enabled_at IS NULL, last_effective_enabled=0, monitoring_armed=0) FROM system_backup_installation_state WHERE origin_installation_id='$installation_id'")"
[[ "$state_flags" == 111 ]] || { printf 'disabled effective state unexpectedly changed: %s\n' "$state_flags" >&2; return 1; }
printf 'PASS controller-enabled isolated=true replicas=2 leader=1 standby=1 grant-probe=accepted effective=disabled first-enabled=unset lease-holder=pod\n'
