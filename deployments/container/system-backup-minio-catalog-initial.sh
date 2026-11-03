#!/bin/sh
set -eu
umask 077
[ "$#" -eq 1 ] || exit 2
mode=$1
case "$mode" in capture|publish) ;; *) exit 2 ;; esac
binary=${MINIO_CATALOG_INITIAL_BINARY:-/usr/local/bin/system-backup-minio-catalog-initial}
[ -x "$binary" ] || exit 1
: "${ORIGINAL_PLAN_FILE:?}" "${ORIGINAL_PLAN_SHA256:?}"
: "${ORIGINAL_ISSUER_PUBLIC_FILE:?}" "${ORIGINAL_ISSUER_PUBLIC_SHA256:?}"
: "${ORIGINAL_KUBECONFIG_FILE:?}" "${ORIGINAL_KUBECONFIG_SHA256:?}"
: "${ORIGINAL_INSTALLER_DSN_FILE:?}" "${ORIGINAL_DATABASE_CA_FILE:?}"
: "${ORIGINAL_LOCAL_ADMIN_PASSWORD_FILE:?}"
: "${ORIGINAL_ENROLLMENT_PIN_FILE:?}" "${ORIGINAL_ENROLLMENT_PIN_SHA256:?}"
: "${MINIO_ORIGINAL_DEFINITION_FILE:?}" "${MINIO_ORIGINAL_DEFINITION_SHA256:?}"
: "${MINIO_CATALOG_INITIAL_OUTPUT_DIRECTORY:?}"
set -- "$mode" --plan-file "$ORIGINAL_PLAN_FILE" --plan-sha256 "$ORIGINAL_PLAN_SHA256" \
 --issuer-public-file "$ORIGINAL_ISSUER_PUBLIC_FILE" --issuer-public-sha256 "$ORIGINAL_ISSUER_PUBLIC_SHA256" \
 --kubeconfig-file "$ORIGINAL_KUBECONFIG_FILE" --kubeconfig-sha256 "$ORIGINAL_KUBECONFIG_SHA256" \
 --dsn-file "$ORIGINAL_INSTALLER_DSN_FILE" --database-ca-file "$ORIGINAL_DATABASE_CA_FILE" \
 --local-admin-password-file "$ORIGINAL_LOCAL_ADMIN_PASSWORD_FILE" \
 --enrollment-pin-file "$ORIGINAL_ENROLLMENT_PIN_FILE" --enrollment-pin-sha256 "$ORIGINAL_ENROLLMENT_PIN_SHA256" \
 --definition-file "$MINIO_ORIGINAL_DEFINITION_FILE" --definition-sha256 "$MINIO_ORIGINAL_DEFINITION_SHA256" \
 --output-directory "$MINIO_CATALOG_INITIAL_OUTPUT_DIRECTORY"
if [ "$mode" = capture ]; then
 : "${ORIGINAL_ISSUER_PRIVATE_FILE:?}"
 : "${MINIO_ORIGINAL_ADMIN_USER_FILE:?}" "${MINIO_ORIGINAL_ADMIN_PASSWORD_FILE:?}"
 set -- "$@" --issuer-private-file "$ORIGINAL_ISSUER_PRIVATE_FILE" \
  --admin-user-file "$MINIO_ORIGINAL_ADMIN_USER_FILE" --admin-password-file "$MINIO_ORIGINAL_ADMIN_PASSWORD_FILE"
else
 : "${MINIO_CATALOG_INITIAL_ENVELOPE_FILE:?}" "${MINIO_CATALOG_INITIAL_ENVELOPE_SHA256:?}"
 set -- "$@" --envelope-file "$MINIO_CATALOG_INITIAL_ENVELOPE_FILE" \
  --envelope-sha256 "$MINIO_CATALOG_INITIAL_ENVELOPE_SHA256"
fi
# Every attempt gets a fresh receipt directory. PUBLISH always reuses the exact
# original CAPTURE envelope; never recapture to repair an unknown native write.
case "$MINIO_CATALOG_INITIAL_OUTPUT_DIRECTORY" in /*) ;; *) exit 2 ;; esac
mkdir -m 700 "$MINIO_CATALOG_INITIAL_OUTPUT_DIRECTORY"
exec "$binary" "$@"
