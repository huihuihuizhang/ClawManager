#!/usr/bin/env bash
# Sourced after the isolated transition phase. It only mutates that run's
# throwaway MySQL account and deletes no resources of its own.
[[ "${CONTROLLER_GRANT_DRIFT_SMOKE:-0}" == 1 && "${CONTROLLER_TRANSITION_SMOKE:-0}" == 1 && -n "${RUN_NAMESPACE_UID:-}" ]] || {
  echo 'grant drift requires the isolated controller transition phase' >&2
  return 1
}

wait_controller_modes enabled disabled
state_before_grant_drift="$(transition_state)"

# Removing a required direct grant must revoke readiness on both replicas.
# The controller health endpoint remains a process check, not authorization.
printf "REVOKE SELECT ON \`clawmanager\`.\`system_backup_configs\` FROM 'sbk_controller'@'%%';\n" | mysql_root_stream
deadline=$((SECONDS + 90))
while (( SECONDS < deadline )); do
  ready_replicas="$(kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" get deployment controller-enabled-smoke -o jsonpath='{.status.readyReplicas}')"
  [[ -z "$ready_replicas" || "$ready_replicas" == 0 ]] && break
  sleep 3
done
[[ -z "${ready_replicas:-}" || "$ready_replicas" == 0 ]] || {
  kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" logs -l app=controller-enabled --all-containers=true --prefix=true --tail=60 >&2 || true
  printf 'controller remained ready after required SELECT grant was revoked: %s replicas\n' "$ready_replicas" >&2
  return 1
}
[[ "$(transition_state)" == "$state_before_grant_drift" ]] || {
  echo 'grant drift modified installation state' >&2
  return 1
}

printf "GRANT SELECT ON \`clawmanager\`.\`system_backup_configs\` TO 'sbk_controller'@'%%';\n" | mysql_root_stream
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" rollout restart deployment/controller-enabled-smoke >/dev/null
kubectl --context="$CONTEXT" --namespace="$RUN_NAMESPACE" rollout status deployment/controller-enabled-smoke --timeout=180s >/dev/null
wait_controller_modes enabled disabled
[[ "$(transition_state)" == "$state_before_grant_drift" ]] || {
  echo 'grant restoration and restart modified installation state' >&2
  return 1
}
printf 'PASS controller-grant-drift isolated=true revoked-required-select=both-not-ready restored-grant=two-ready leader=1 standby=1 installation-projection=unchanged namespace-cleanup=pending\n'
