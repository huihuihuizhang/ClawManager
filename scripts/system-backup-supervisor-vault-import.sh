#!/usr/bin/env bash
# User-run official image transport only. Does not deploy or alter workloads.
set -euo pipefail
umask 077
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
archive="$base/vault-official-2.2.1-linux-amd64.oci.tar"
archive_sha=b6e6a6230dad679c81827d27b62e23912e6f0f79ab71ff7c09fc6bdd6012a4de
digest=sha256:2194d86d9ddbb17a6d017c3b2e555e1d4431195f18c3cb2827e3f61320fb6855
ref=10.130.14.23:5000/clawmanager-backup-vault:2.2.1-2194d86d
[[ $(uname -s) = Linux && $(uname -m) = x86_64 && $EUID = 0 ]] || { echo 'Linux amd64 root on k8s-master required.' >&2; exit 64; }
for tool in kubectl python3 ctr curl sha256sum mktemp timeout; do command -v "$tool" >/dev/null; done
[[ -f $archive && ! -L $archive ]] || { echo 'Pinned official OCI archive missing.' >&2; exit 64; }
printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum --check --strict -
observed_uid=$(kubectl --context=kubernetes-admin@kubernetes --request-timeout=20s get namespace clawmanager-zhanghui08-system -o jsonpath='{.metadata.uid}')
[[ $observed_uid = 337cfe30-2c17-4b8e-b32a-760778b8098e ]] || { echo 'Namespace identity changed; refused.' >&2; exit 1; }
[[ $(hostname -s) = k8s-master ]] || { echo 'Run on the originally observed k8s-master node.' >&2; exit 1; }
scratch=$(mktemp -d /tmp/clawmanager-vault-image-XXXXXXXX)
cleanup() {
  local original_rc=$? cleanup_rc=0
  trap - EXIT
  set +e
  # Only exact files created in our still-owned directory; never recursive deletion.
  rm -f -- "$scratch/local-manifest" "$scratch/registry-manifest" "$scratch/registry-headers" "$scratch/images" || cleanup_rc=1
  rmdir -- "$scratch" || cleanup_rc=1
  if [[ $original_rc -ne 0 ]]; then exit "$original_rc"; fi
  exit "$cleanup_rc"
}
trap cleanup EXIT
timeout --signal=TERM --kill-after=10s 240s ctr -n k8s.io images import --platform linux/amd64 "$archive"
ctr -n k8s.io images ls > "$scratch/images"
python3 -B - "$scratch/images" "$ref" "$digest" <<'PY'
from pathlib import Path
import sys
rows=[line.split() for line in Path(sys.argv[1]).read_text().splitlines()]
matches=[row for row in rows if row and row[0]==sys.argv[2]]
if len(matches)!=1 or len(matches[0])<3 or matches[0][2]!=sys.argv[3]:
    raise SystemExit('Imported reference does not point to the pinned original manifest.')
PY
ctr -n k8s.io content get "$digest" > "$scratch/local-manifest"
printf '%s  %s\n' "${digest#sha256:}" "$scratch/local-manifest" | sha256sum --check --strict -
# The observed private registry uses HTTP. This flag applies only to image transport.
timeout --signal=TERM --kill-after=10s 240s ctr -n k8s.io images push --platform linux/amd64 --plain-http "$ref"
curl --fail --silent --show-error --noproxy 10.130.14.23 --connect-timeout 10 --max-time 120 --proto '=http' \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  -D "$scratch/registry-headers" -o "$scratch/registry-manifest" \
  'http://10.130.14.23:5000/v2/clawmanager-backup-vault/manifests/2.2.1-2194d86d'
printf '%s  %s\n' "${digest#sha256:}" "$scratch/registry-manifest" | sha256sum --check --strict -
python3 -B - "$scratch/registry-headers" "$digest" <<'PY'
from pathlib import Path
import sys
headers=[line.split(':',1)[1].strip() for line in Path(sys.argv[1]).read_text().splitlines() if line.lower().startswith('docker-content-digest:')]
if headers!=[sys.argv[2]]:
    raise SystemExit('Private registry digest header differs from the verified original manifest.')
PY
# Erase the same verified transfer archive after successful import and readback.
[[ -f $archive && ! -L $archive ]]
printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum --check --strict -
rm -- "$archive"
printf 'official_image_import_and_registry_readback=passed\nimage=%s\nprovider_installed=false\ntransfer_archive_deleted=true\n' "${ref%:*}@$digest"
