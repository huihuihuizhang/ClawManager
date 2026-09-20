#!/usr/bin/env bash
# Sourced only after system-backup-controller-enabled-phase.sh. Every write is
# confined to that run's fresh MySQL emptyDir and run-labelled namespace.
[[ "${CONTROLLER_TRANSITION_SMOKE:-0}" == 1 && -n "${RUN_NAMESPACE_UID:-}" && -n "${installation_id:-}" ]] || {
  echo 'controller transition requires the isolated enabled-controller phase' >&2
  return 1
}

transition_state() {
  mysql_query "SELECT CONCAT(first_enabled_at IS NOT NULL, ':', last_effective_enabled, ':', monitoring_armed, ':', monitoring_armed_reason, ':', row_version, ':', COALESCE(DATE_FORMAT(first_enabled_at, '%Y-%m-%d %H:%i:%s.%f'), 'unset')) FROM system_backup_installation_state WHERE origin_installation_id='$installation_id'"
}

wait_controller_modes() {
  local expected_config="$1" expected_effective="$2" deadline=$((SECONDS + 180))
  local pod ready current_leader leaders standbys holder
  while (( SECONDS < deadline )); do
    mapfile -t controller_pods < <(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" get pods -l app=controller-enabled -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
    if [[ "${#controller_pods[@]}" == 2 ]]; then
      leaders=0
      standbys=0
      current_leader=''
      for pod in "${controller_pods[@]}"; do
        ready="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" exec "$pod" -- wget -qO- http://127.0.0.1:9003/readyz 2>/dev/null || true)"
        case "$ready" in
          "leader config=$expected_config effective=$expected_effective "*) ((leaders+=1)); current_leader="$pod" ;;
          "standby config=$expected_config effective=$expected_effective "*) ((standbys+=1)) ;;
        esac
      done
      holder="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" get lease clawmanager-system-backup-controller -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)"
      if [[ "$leaders" == 1 && "$standbys" == 1 && "$holder" == "system-backup-controller:$current_leader" ]]; then
        transition_leader="$current_leader"
        return 0
      fi
    fi
    sleep 3
  done
  kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" logs -l app=controller-enabled --all-containers=true --prefix=true --tail=60 >&2 || true
  printf 'controller modes did not settle: config=%s effective=%s\n' "$expected_config" "$expected_effective" >&2
  return 1
}

wait_transition_state() {
  local expected_prefix="$1" deadline=$((SECONDS + 180)) current
  while (( SECONDS < deadline )); do
    current="$(transition_state)"
    [[ "$current" == "$expected_prefix"* ]] && { transition_observed_state="$current"; return 0; }
    sleep 3
  done
  printf 'installation state did not reach %s; last=%s\n' "$expected_prefix" "$current" >&2
  return 1
}

# A nonempty task set would make this an integration run, which requires A/B/C.
task_count="$(mysql_query 'SELECT (SELECT COUNT(*) FROM system_backups) + (SELECT COUNT(*) FROM system_restore_drills) + (SELECT COUNT(*) FROM system_backup_preflights) + (SELECT COUNT(*) FROM system_backup_artifact_verifications) + (SELECT COUNT(*) FROM system_backup_operations)')"
[[ "$task_count" == 0 ]] || { printf 'isolated controller fixture contains %s tasks/operations\n' "$task_count" >&2; return 1; }

# This direct config-row update is a disposable fixture transition. Production
# config changes must create a new immutable version through the Admin API.
printf "UPDATE system_backup_configs SET enabled=1 WHERE origin_installation_id='%s' AND version=1 AND enabled=0;\n" "$installation_id" | mysql_root_stream
[[ "$(mysql_query "SELECT enabled FROM system_backup_configs WHERE origin_installation_id='$installation_id' AND version=1")" == 1 ]] || {
  echo 'test config did not enable' >&2
  return 1
}
wait_controller_modes enabled disabled
[[ "$(transition_state)" == "0:0:0:none:"*":unset" ]] || {
  echo 'first-enabled state changed before the deployment gate opened' >&2
  return 1
}

kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" set env deployment/controller-enabled-smoke SYSTEM_BACKUP_ENABLED=true >/dev/null
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" rollout status deployment/controller-enabled-smoke --timeout=180s >/dev/null
wait_controller_modes enabled enabled
wait_transition_state '1:1:1:previously_enabled:'
enabled_state="$transition_observed_state"
enabled_version="${enabled_state#1:1:1:previously_enabled:}"
enabled_version="${enabled_version%%:*}"
enabled_at="${enabled_state#1:1:1:previously_enabled:$enabled_version:}"
[[ "$enabled_version" =~ ^[0-9]+$ && "$enabled_at" != unset ]] || {
  printf 'first-enable projection invalid: %s\n' "$enabled_state" >&2
  return 1
}

# Deleting only the current leader Pod exercises lease transfer. The Deployment
# recreates its replica; the installation projection must remain byte-identical.
old_leader="$transition_leader"
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" delete pod "$old_leader" --wait=false >/dev/null
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" wait "pod/$old_leader" --for=delete --timeout=120s >/dev/null
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" rollout status deployment/controller-enabled-smoke --timeout=180s >/dev/null
wait_controller_modes enabled enabled
[[ "$transition_leader" != "$old_leader" ]] || { echo 'leader did not transfer to a different Pod' >&2; return 1; }
[[ "$(transition_state)" == "$enabled_state" ]] || {
  echo 'leader failover modified first-enable projection' >&2
  return 1
}

# A same-digest rolling restart replaces both Pods in sequence. This checks
# handoff during rollout without claiming a version-to-version upgrade.
before_restart_pods=("${controller_pods[@]}")
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" rollout restart deployment/controller-enabled-smoke >/dev/null
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" rollout status deployment/controller-enabled-smoke --timeout=180s >/dev/null
wait_controller_modes enabled enabled
for old_pod in "${before_restart_pods[@]}"; do
  for pod in "${controller_pods[@]}"; do
    [[ "$pod" != "$old_pod" ]] || { printf 'rolling restart retained old Pod %s\n' "$old_pod" >&2; return 1; }
  done
done
[[ "$(transition_state)" == "$enabled_state" ]] || {
  echo 'rolling restart modified first-enable projection' >&2
  return 1
}

kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" set env deployment/controller-enabled-smoke SYSTEM_BACKUP_ENABLED=false >/dev/null
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" rollout status deployment/controller-enabled-smoke --timeout=180s >/dev/null
wait_controller_modes enabled disabled
wait_transition_state '1:0:1:previously_enabled:'
disabled_state="$transition_observed_state"
disabled_version="${disabled_state#1:0:1:previously_enabled:}"
disabled_version="${disabled_version%%:*}"
disabled_at="${disabled_state#1:0:1:previously_enabled:$disabled_version:}"
[[ "$disabled_at" == "$enabled_at" && "$disabled_version" == "$((enabled_version + 1))" ]] || {
  printf 'kill-switch changed first-enable time or unexpected row version: before=%s after=%s\n' "$enabled_state" "$disabled_state" >&2
  return 1
}
printf 'PASS controller-transition isolated=true first-enable-once=yes failover=leader-transferred rolling-restart=both-pods-replaced projection-stable=yes kill-switch=disabled monitoring-armed=yes namespace-cleanup=pending\n'
