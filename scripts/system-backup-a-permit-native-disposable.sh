#!/usr/bin/env bash
# Optional fully owned MySQL fixture: never mount or connect production data.
set -euo pipefail
umask 077
[[ $# = 1 && $1 = /* && ! -e $1 ]] || { echo 'usage: run-disposable.sh /absolute/new-log-directory' >&2; exit 64; }
logs=$1
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ ${A_PERMIT_NATIVE_MYSQL_IMAGE:-} =~ ^mysql:8\.4@sha256:[a-f0-9]{64}$ ]] || { echo 'set independently reviewed, preloaded A_PERMIT_NATIVE_MYSQL_IMAGE=mysql:8.4@sha256:...' >&2; exit 64; }
port=${A_PERMIT_NATIVE_MYSQL_PORT:-63507}
[[ $port =~ ^[0-9]{4,5}$ && $port -gt 1023 && $port -lt 65536 && $port != 3306 ]] || { echo 'private loopback port required, not 3306' >&2; exit 64; }
[[ ${A_PERMIT_NATIVE_SCRATCH:-} =~ ^/[A-Za-z0-9_./-]+$ && -d $A_PERMIT_NATIVE_SCRATCH ]] || { echo 'private absolute scratch required (letters/digits/._/-)' >&2; exit 64; }
for tool in docker openssl sha256sum mktemp; do command -v "$tool" >/dev/null; done
docker image inspect "$A_PERMIT_NATIVE_MYSQL_IMAGE" >/dev/null
(cd -- "$bundle" && sha256sum --check --strict SHA256SUMS >/dev/null)
scratch=$(cd -- "$A_PERMIT_NATIVE_SCRATCH" && pwd -P)
work=$(mktemp -d "$scratch/a-permit-mysql.XXXXXXXX")
owner=${work##*/}
container=$owner
volume=$owner-data
container_created=0
container_creation_attempted=0
container_id=
volume_created=0
volume_creation_attempted=0
volume_created_at=
cleanup() {
  local cleanup_rc=0 identity remaining
  if [[ $container_creation_attempted = 1 && $container_created = 0 ]]; then
    echo "UNCONFIRMED container creation: name=$container owner=$owner; no valid returned ID, not deleting by name" >&2
    cleanup_rc=1
  fi
  if [[ $container_created = 1 ]]; then
    if identity=$(docker inspect --format '{{ index .Config.Labels "clawmanager.a-permit.owner" }}|{{ .Id }}' "$container_id") && [[ $identity = "$owner|$container_id" ]]; then
      if ! docker logs "$container_id" > "$logs/mysql.log" 2>&1; then
        echo 'fixture mysql log capture failed; cleanup continues' >&2
        cleanup_rc=1
      fi
      if ! docker rm --force --volumes "$container_id" >/dev/null; then
        echo "container removal failed: $container_id; cleanup continues" >&2
        cleanup_rc=1
      fi
    else
      echo "container ownership unavailable/changed; not removed: $container_id" >&2
      cleanup_rc=1
    fi
    if remaining=$(docker ps --all --quiet --no-trunc --filter "id=$container_id"); then
      if [[ -n $remaining ]]; then echo "RESIDUAL container: $container_id" >&2; cleanup_rc=1; fi
    else
      echo "UNCONFIRMED container cleanup: $container_id" >&2
      cleanup_rc=1
    fi
  fi
  if [[ $volume_created = 1 ]]; then
    if identity=$(docker volume inspect --format '{{ index .Labels "clawmanager.a-permit.owner" }}|{{ .CreatedAt }}' "$volume") && [[ -n $volume_created_at && $identity = "$owner|$volume_created_at" ]]; then
      if ! docker volume rm "$volume" >/dev/null; then
        echo "volume removal failed: $volume; cleanup continues" >&2
        cleanup_rc=1
      fi
    else
      echo "volume ownership unavailable/changed; not removed: $volume" >&2
      cleanup_rc=1
    fi
    if remaining=$(docker volume ls --quiet --filter "name=$volume"); then
      if grep -Fxq -- "$volume" <<< "$remaining"; then echo "RESIDUAL volume: $volume" >&2; cleanup_rc=1; fi
    else
      echo "UNCONFIRMED volume cleanup: $volume" >&2
      cleanup_rc=1
    fi
  fi
  if [[ $volume_creation_attempted = 1 && $volume_created = 0 ]]; then
    echo "UNCONFIRMED volume creation: $volume owner=$owner; inspect exact ownership manually" >&2
    cleanup_rc=1
  fi
  # Container/volume failures must not skip removal of our host secrets/work.
  case $work in
    "$scratch"/a-permit-mysql.????????)
      if [[ -L $work ]]; then echo "refusing redirected work cleanup: $work" >&2; cleanup_rc=1
      elif ! rm -rf -- "$work"; then echo "work removal failed: $work" >&2; cleanup_rc=1; fi
      ;;
    *) echo "refusing work cleanup outside owned scratch: $work" >&2; cleanup_rc=1 ;;
  esac
  if [[ -e $work || -L $work ]]; then echo "RESIDUAL work/secrets: $work" >&2; cleanup_rc=1; fi
  return "$cleanup_rc"
}
on_exit() {
  local original_rc=$? cleanup_rc=0
  trap - EXIT
  set +e
  if cleanup; then :; else cleanup_rc=$?; fi
  if [[ -d $logs ]]; then
    if ! printf '%s\n' "$original_rc" > "$logs/original-exit-code.txt"; then cleanup_rc=1; fi
    if ! printf '%s\n' "$cleanup_rc" > "$logs/cleanup-exit-code.txt"; then cleanup_rc=1; fi
  fi
  if [[ $cleanup_rc -ne 0 ]]; then echo 'cleanup incomplete; inspect the reported exact resources, do not assume they are absent' >&2; fi
  if [[ $original_rc -ne 0 ]]; then exit "$original_rc"; fi
  exit "$cleanup_rc"
}
trap on_exit EXIT
mkdir -m 700 -- "$logs"
mkdir -- "$work/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=A permit disposable CA' -keyout "$work/ca.key" -out "$work/tls/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=a-permit-native.local' -keyout "$work/tls/server.key" -out "$work/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:a-permit-native.local,IP:127.0.0.1' 'extendedKeyUsage=serverAuth' > "$work/server.ext"
openssl x509 -req -days 1 -in "$work/server.csr" -CA "$work/tls/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -extfile "$work/server.ext" -out "$work/tls/server.crt" >/dev/null 2>&1
# Host ancestors remain 0700. Inside this dedicated container mysqld must be
# able to read the mounted TLS files after dropping its root entrypoint UID.
chmod 755 -- "$work/tls"
chmod 444 -- "$work/tls/ca.crt" "$work/tls/server.crt" "$work/tls/server.key"
openssl rand -hex 32 > "$work/root-password"
docker volume inspect "$volume" >/dev/null 2>&1 && { echo 'unexpected existing fixture volume' >&2; exit 1; }
volume_creation_attempted=1
docker volume create --label "clawmanager.a-permit.owner=$owner" "$volume" >/dev/null
volume_created=1
volume_created_at=$(docker volume inspect --format '{{ .CreatedAt }}' "$volume")
container_creation_attempted=1
container_id=$(docker create --pull=never --name "$container" --label "clawmanager.a-permit.owner=$owner" \
  --publish "127.0.0.1:$port:3306" --mount "type=volume,src=$volume,dst=/var/lib/mysql" \
  --mount "type=bind,src=$work/tls,dst=/run/a-permit-tls,readonly" \
  --mount "type=bind,src=$work/root-password,dst=/run/secrets/mysql-root-password,readonly" \
  -e MYSQL_ROOT_PASSWORD_FILE=/run/secrets/mysql-root-password -e MYSQL_ROOT_HOST=% \
  "$A_PERMIT_NATIVE_MYSQL_IMAGE" --ssl-ca=/run/a-permit-tls/ca.crt --ssl-cert=/run/a-permit-tls/server.crt \
  --ssl-key=/run/a-permit-tls/server.key --require-secure-transport=ON --tls-version=TLSv1.3)
[[ $container_id =~ ^[a-f0-9]{64}$ ]] || { echo 'container create returned an invalid identity; inspect exclusive owner label manually' >&2; exit 1; }
container_created=1
docker start "$container_id" >/dev/null
ready=0
for ((attempt=0; attempt<90; attempt++)); do
  if docker exec --user 0:0 "$container_id" sh -c 'MYSQL_PWD="$(cat /run/secrets/mysql-root-password)"; export MYSQL_PWD; exec mysql --user=root --protocol=socket --batch --skip-column-names -e "SELECT @@server_uuid"' > "$work/server-uuid" 2>/dev/null; then ready=1; break; fi
  sleep 2
done
[[ $ready = 1 ]] || { echo 'disposable SAN/TLS MySQL did not become ready' >&2; exit 1; }
server_uuid=$(cat "$work/server-uuid")
[[ $server_uuid =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] || { echo 'disposable server UUID unavailable' >&2; exit 1; }
password=$(cat "$work/root-password")
printf '{"Host":"127.0.0.1","Port":%s,"User":"root","Password":"%s","CAFile":"%s","TLSServerName":"a-permit-native.local","ServerUUID":"%s"}\n' \
  "$port" "$password" "$work/tls/ca.crt" "$server_uuid" > "$work/credentials.json"
unset password
chmod 600 -- "$work/credentials.json"
bash "$bundle/run-diagnostic.sh" "$work/credentials.json" "$server_uuid" "$logs/diagnostic"
