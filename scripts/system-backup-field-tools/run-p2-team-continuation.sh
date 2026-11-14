#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "$(readlink -f -- "$0")")"
sha256sum -c SHA256SUMS
chmod 0700 system-backup-source-registries system-backup-first-install-materials system-backup-v2-controller
python3 -B preflight-p2-team-continuation.py "$@"
image_dir="$PWD/image-work"
python3 -B build-p2-controller-overlay.py --directory "$image_dir"
image_sha=$(sha256sum "$image_dir/image.json")
python3 -B continue-p2-nov14.py --image-receipt "$image_dir/image.json" --image-sha256 "${image_sha%% *}" "$@"
