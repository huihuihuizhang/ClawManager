#!/bin/sh
# Called by start.sh before server/nginx; stdout is an nginx location include.
set -eu
case "${SYSTEM_BACKUP_API_PROXY_ENABLED:-false}" in
  false|'') exit 0 ;;
  true) ;;
  *) echo 'Invalid system-backup API proxy selection' >&2; exit 1 ;;
esac
directory=/run/system-backup-api-tls
mkdir -m 0700 "$directory"
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 30 \
  -subj '/CN=ClawManager private backend API CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$directory/ca.key" -out "$directory/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:3072 -nodes -sha256 -subj '/CN=localhost' \
  -keyout "$directory/server.key" -out "$directory/server.csr" >/dev/null 2>&1
cat > "$directory/server.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EXT
openssl x509 -req -sha256 -days 30 -in "$directory/server.csr" \
  -CA "$directory/ca.pem" -CAkey "$directory/ca.key" -CAcreateserial \
  -extfile "$directory/server.ext" -out "$directory/server.pem" >/dev/null 2>&1
openssl verify -CAfile "$directory/ca.pem" -verify_hostname localhost "$directory/server.pem" >/dev/null 2>&1
# These are exact newly created private local files, never source/backup data.
rm -- "$directory/ca.key" "$directory/server.csr" "$directory/server.ext" "$directory/ca.srl"
cat <<'CONF'
location ~ ^/api/v1/admin/(system-backup[^/]*|system-restore-drills)(/|$) {
    proxy_pass https://127.0.0.1:9002;
    proxy_ssl_name localhost;
    proxy_ssl_server_name on;
    proxy_ssl_trusted_certificate /run/system-backup-api-tls/ca.pem;
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 2;
    proxy_ssl_protocols TLSv1.3;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-ClawManager-Runtime-Origin "";
    proxy_set_header Connection "";
    proxy_next_upstream off;
    proxy_redirect off;
    proxy_intercept_errors off;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    proxy_store off;
    proxy_connect_timeout 5s;
    proxy_read_timeout 90s;
    proxy_send_timeout 90s;
    add_header Cache-Control "no-store" always;
}
CONF
