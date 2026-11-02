#!/usr/bin/env bash
# Read-only prerequisites. No Secret, credentials, workload exec, pull or apply.
set -euo pipefail
context='kubernetes-admin@kubernetes'
namespace='clawmanager-zhanghui08-system'
expected_uid='337cfe30-2c17-4b8e-b32a-760778b8098e'
k=(kubectl --context="$context" --request-timeout=20s)
actual_uid=$("${k[@]}" get namespace "$namespace" -o jsonpath='{.metadata.uid}')
[[ "$actual_uid" = "$expected_uid" ]] || { printf '%s\n' 'Namespace UID mismatch; stop.' >&2; exit 1; }
printf 'scope=provider-read-only-prerequisites\nnamespace_uid=%s\nhost_arch=' "$actual_uid"
uname -m
for tool in bash python3 kubectl docker buildctl ctr nerdctl openssl curl tar sha256sum; do
  if location=$(command -v "$tool"); then printf '%s=%s\n' "$tool" "$location"; else printf '%s=missing\n' "$tool"; fi
done
"${k[@]}" get nodes -o 'custom-columns=NAME:.metadata.name,UID:.metadata.uid,ARCH:.status.nodeInfo.architecture,RUNTIME:.status.nodeInfo.containerRuntimeVersion' || printf '%s\n' 'nodes_query_failed'
if ! "${k[@]}" get storageclasses -o json | python3 -c 'import json,sys; x=json.load(sys.stdin); print(json.dumps({"storageclasses":[{"name":v["metadata"]["name"],"provisioner":v.get("provisioner"),"binding_mode":v.get("volumeBindingMode"),"reclaim_policy":v.get("reclaimPolicy"),"default":v["metadata"].get("annotations",{}).get("storageclass.kubernetes.io/is-default-class")} for v in x["items"]]},sort_keys=True))'; then
  printf '%s\n' 'storageclass_query_failed'
fi
"${k[@]}" -n "$namespace" get pvc -o 'custom-columns=NAME:.metadata.name,UID:.metadata.uid,PHASE:.status.phase,SC:.spec.storageClassName,VOLUME:.spec.volumeName,CAPACITY:.status.capacity.storage' || printf '%s\n' 'pvc_query_failed'
if ! "${k[@]}" get --raw '/.well-known/openid-configuration' | python3 -c 'import json,sys; v=json.load(sys.stdin); print(json.dumps({"service_account_issuer":v.get("issuer"),"jwks_uri":v.get("jwks_uri")},sort_keys=True))'; then
  printf '%s\n' 'issuer_discovery_failed'
fi
if ! "${k[@]}" get --raw '/openid/v1/jwks' | python3 -c 'import hashlib,json,sys; v=json.load(sys.stdin); b=json.dumps(v,sort_keys=True,separators=(",",":")).encode(); print(json.dumps({"jwks_public_key_count":len(v.get("keys",[])),"jwks_json_sha256":hashlib.sha256(b).hexdigest()},sort_keys=True))'; then
  printf '%s\n' 'jwks_discovery_failed'
fi
if command -v docker >/dev/null; then
  python3 -c 'import subprocess; p=subprocess.run(["docker","version","--format","{{.Server.Version}}"],capture_output=True,text=True,timeout=8); print("docker_server_version="+(p.stdout.strip() if p.returncode==0 else "unavailable"))' || printf '%s\n' 'docker_server_query_failed'
fi
if command -v curl >/dev/null; then
  for endpoint in 'https://releases.hashicorp.com/' 'https://registry-1.docker.io/v2/' 'http://10.130.14.23:5000/v2/'; do
    printf 'connectivity %s ' "$endpoint"
    curl -q --connect-timeout 5 --max-time 10 -s -o /dev/null -w '%{http_code}\n' "$endpoint" || printf '%s\n' 'request_failed'
  done
fi
printf '%s\n' 'read_only_preflight_complete; node_image_pull_and_provider_not_tested'
