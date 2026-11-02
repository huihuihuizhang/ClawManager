#!/usr/bin/env bash
# Isolated fixture DATA only. Never deploys App/controller or reads production DB.
set -euo pipefail
exec python3 -B "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/system-backup-d-kube-mysql-fixture.py" "$@"
