"""Compile existing reviewed public plans offline; no apply/revoke/token option.

Output is review-only provider ACL/role data, never installation authority.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


signing = module("offline_signing_policy", "system-backup-a-apply-signing-policy.py")
kek = signing._kek


def read_local(filename):
    # Do not dereference UNC/device paths or symlinks/junctions, including parents.
    kek.require(isinstance(filename, str) and filename and not filename.startswith(("\\\\", "//")) and "://" not in filename)
    path = Path(filename).absolute()
    kek.require(":" not in str(path)[len(path.drive):])
    for part in (path, *path.parents):
        kek.require(not part.is_symlink() and not part.is_junction())
    kek.require(path.is_file() and 0 < path.stat().st_size <= 65536)
    with path.open("rb") as source:
        raw = source.read(65537)
    kek.require(0 < len(raw) <= 65536)
    return raw


def compile_plan(kind, raw, expected_sha, endpoint=None, workload_raw=None, workload_sha=None):
    kek.require(hashlib.sha256(raw).hexdigest() == expected_sha)
    if kind == "signing":
        url = urlsplit(endpoint or "")
        kek.require(url.scheme == "https" and url.hostname and not url.username and not url.password and not url.path and not url.query and not url.fragment and not any(c in endpoint for c in "?#\r\n"))
        kek.require(workload_raw is None and workload_sha is None)
        _, policies, roles = signing.reviewed_plan(raw, endpoint)
    else:
        kek.require(kind == "kek" and endpoint is None and workload_raw is not None)
        kek.require(len(workload_raw) <= 8192 and hashlib.sha256(workload_raw).hexdigest() == workload_sha)
        plan = kek.decode(raw)
        policies = kek.policies(plan)
        roles = kek.workload_roles(policies, kek.decode(workload_raw))
    return {"status": "review_only_not_authorized", "production_ready": False,
            "plan_sha256": expected_sha, "workload_sha256": workload_sha, "policies": policies, "roles": roles,
            "unverified": ["original_installation_authority", "provider_key_and_jwt_trust_readback",
                           "workload_identity_and_current_permission", "provider_acl_semantics",
                           "expiry_revocation_and_actual_use"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("signing", "kek"), required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--endpoint")
    parser.add_argument("--workload")
    parser.add_argument("--workload-sha256")
    args = parser.parse_args(argv)
    try:
        result = compile_plan(args.kind, read_local(args.plan), args.plan_sha256,
                              args.endpoint, read_local(args.workload) if args.workload else None, args.workload_sha256)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"status": "rejected", "production_ready": False,
                          "reason": "invalid_or_unavailable_local_material"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
