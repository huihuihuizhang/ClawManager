#!/usr/bin/env python3
"""Observe pinned node Pod slots and named PVC topology; never change the cluster.

Run again after confirmed writer stop and before publication. Each invocation
reports only its current observations; no planned replica reduction is credited.
Use -I -B. Output is JSON and includes no Pod names from any namespace.
"""

import argparse
from datetime import datetime, timezone
import json
import re
import subprocess
import sys


NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
UID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
CONTEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,252}\Z")
POD_PHASES = "{range .items[*]}P|{.status.phase}|{.metadata.deletionTimestamp}{\"\\n\"}{end}"


class ObservationError(Exception):
    pass


def kubectl(context, args, stage, json_output=True):
    # No shell, raw stderr, temporary files, Secrets, exec, or write operations.
    try:
        result = subprocess.run(
            ["kubectl", "--context=" + context, "--request-timeout=10s", "get", *args],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=False,
        )
        if result.returncode or len(result.stdout) > 16 << 20:
            raise ObservationError(stage)
        raw = result.stdout.decode("utf-8", errors="strict")
        return json.loads(raw) if json_output else raw
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        raise ObservationError(stage) from None


def identity(obj, name, uid, stage):
    metadata = obj.get("metadata", {})
    if (metadata.get("name") != name or metadata.get("uid") != uid
            or metadata.get("deletionTimestamp")):
        raise ObservationError(stage)


def summarize_node(node, raw_phases, required_slots):
    value = node.get("status", {}).get("allocatable", {}).get("pods", "")
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,8}", value):
        raise ObservationError("node_allocatable")
    counts = {"Pending": 0, "Running": 0, "Succeeded": 0, "Failed": 0, "Unknown": 0}
    terminating = 0
    for line in raw_phases.splitlines():
        fields = line.split("|")
        if len(fields) != 3 or fields[0] != "P":
            raise ObservationError("pod_phase_row")
        phase = fields[1] or "Unknown"
        if phase not in counts:
            raise ObservationError("pod_phase_value")
        counts[phase] += 1
        terminating += bool(fields[2])
        if sum(counts.values()) > 1000000:
            raise ObservationError("pod_observation_limit")
    bound = sum(counts.values())
    nonterminal = bound - counts["Succeeded"] - counts["Failed"]
    conditions = node.get("status", {}).get("conditions", [])
    ready = [c.get("status") for c in conditions if c.get("type") == "Ready"] == ["True"]
    pressures = [c.get("type") for c in conditions
                 if c.get("type") in ("MemoryPressure", "DiskPressure", "PIDPressure")
                 and c.get("status") != "False"]
    spec = node.get("spec", {})
    headroom = int(value) - bound
    return {
        "name": node["metadata"]["name"], "uid": node["metadata"]["uid"],
        "resource_version": node["metadata"].get("resourceVersion"),
        "allocatable_pods": int(value), "bound_pods": bound,
        "nonterminal_pods": nonterminal, "terminating_bound_pods": terminating,
        "phases": counts, "headroom_all_bound": headroom,
        "headroom_nonterminal": int(value) - nonterminal,
        "required_additional_slots": required_slots,
        "conservative_slot_shortfall": max(0, required_slots - headroom),
        "ready": ready, "unschedulable": bool(spec.get("unschedulable", False)),
        "pressures": pressures,
        "taints": [{"key": t.get("key"), "effect": t.get("effect")}
                   for t in spec.get("taints", [])],
    }


def summarize_claim(namespace, claim, volume):
    metadata, spec = claim.get("metadata", {}), claim.get("spec", {})
    pv_metadata, pv_spec = volume.get("metadata", {}), volume.get("spec", {})
    ref = pv_spec.get("claimRef", {})
    if (metadata.get("namespace") != namespace or not metadata.get("uid")
            or metadata.get("deletionTimestamp") or claim.get("status", {}).get("phase") != "Bound"
            or not spec.get("volumeName") or pv_metadata.get("name") != spec["volumeName"]
            or not pv_metadata.get("uid") or pv_metadata.get("deletionTimestamp")
            or ref.get("namespace") != namespace or ref.get("name") != metadata.get("name")
            or ref.get("uid") != metadata["uid"]):
        raise ObservationError("claim_volume_binding")
    kinds = [k for k in ("hostPath", "local", "nfs", "csi") if k in pv_spec]
    return {
        "claim": metadata["name"], "claim_uid": metadata["uid"],
        "volume": pv_metadata["name"], "volume_uid": pv_metadata["uid"],
        "access_modes": spec.get("accessModes", []),
        "volume_mode": spec.get("volumeMode", "Filesystem"),
        "storage_class": spec.get("storageClassName"),
        "storage_kind": kinds[0] if len(kinds) == 1 else "other",
        "csi_driver": pv_spec.get("csi", {}).get("driver"),
        # Only public node-selector terms; never host paths, network exports,
        # volume handles, mount options, annotations, or credential references.
        "required_node_affinity": pv_spec.get("nodeAffinity", {}).get("required"),
        "job_volume_topology_fit": "not_verified",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--namespace-uid", required=True)
    parser.add_argument("--node", action="append", required=True,
                        metavar="NAME=UID:ADDITIONAL_SLOTS",
                        help="explicit node identity and conservative planned slot budget")
    parser.add_argument("--claim", action="append", default=[], help="exact source/staging PVC name")
    parser.add_argument("--stage", choices=("before-stop", "after-stop", "before-publish"), required=True)
    args = parser.parse_args()
    nodes = []
    try:
        if (not CONTEXT.fullmatch(args.context) or not NAME.fullmatch(args.namespace)
                or not UID.fullmatch(args.namespace_uid) or not 1 <= len(args.node) <= 32
                or len(args.claim) > 64 or len(set(args.claim)) != len(args.claim)
                or any(not NAME.fullmatch(c) for c in args.claim)):
            raise ObservationError("arguments")
        for item in args.node:
            name, sep, rest = item.partition("=")
            uid, colon, slots = rest.partition(":")
            if (not sep or not colon or not NAME.fullmatch(name) or not UID.fullmatch(uid)
                    or not re.fullmatch(r"[1-9][0-9]{0,3}", slots)
                    or any(n[0] == name for n in nodes)):
                raise ObservationError("node_arguments")
            nodes.append((name, uid, int(slots)))
        started = datetime.now(timezone.utc).isoformat()
        ns_args = ["namespace", args.namespace, "-o", "json"]
        identity(kubectl(args.context, ns_args, "namespace"), args.namespace,
                 args.namespace_uid, "namespace_identity")
        observations, claims = [], []
        for name, uid, slots in nodes:
            node_args = ["node", name, "-o", "json"]
            node = kubectl(args.context, node_args, "node")
            identity(node, name, uid, "node_identity")
            phases = kubectl(args.context, ["pods", "--all-namespaces",
                             "--field-selector=spec.nodeName=" + name,
                             "-o", "jsonpath=" + POD_PHASES], "pod_phases", False)
            observation = summarize_node(node, phases, slots)
            identity(kubectl(args.context, node_args, "node_recheck"), name, uid, "node_identity")
            observations.append(observation)
        for name in args.claim:
            claim = kubectl(args.context, ["pvc", name, "--namespace=" + args.namespace,
                                          "-o", "json"], "claim")
            if claim.get("metadata", {}).get("name") != name:
                raise ObservationError("claim_identity")
            pv_name = claim.get("spec", {}).get("volumeName", "")
            if not NAME.fullmatch(pv_name):
                raise ObservationError("claim_not_bound")
            volume = kubectl(args.context, ["pv", pv_name, "-o", "json"], "volume")
            claims.append(summarize_claim(args.namespace, claim, volume))
        identity(kubectl(args.context, ns_args, "namespace_recheck"), args.namespace,
                 args.namespace_uid, "namespace_identity")
        blocked = any(n["conservative_slot_shortfall"] or not n["ready"]
                      or n["unschedulable"] or n["pressures"] for n in observations)
        print(json.dumps({
            "schema_version": "system-backup-scheduling-observation.v1",
            "status": "BLOCKED_OBSERVED_SLOTS_OR_NODE" if blocked else "OBSERVED_SLOTS_ONLY",
            "stage": args.stage, "namespace": args.namespace, "namespace_uid": args.namespace_uid,
            "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
            "nodes": observations, "claims": claims, "read_only": True,
            "scheduler_fit": "not_verified", "observations_atomic": False,
            "planned_writer_releases_credited": 0,
            "unverified": ["job_node_affinity", "taints_tolerations", "cpu_memory_ephemeral_storage",
                           "volume_topology_attachment", "quota_admission", "image_cache"],
        }, sort_keys=True))
        return 2 if blocked else 0
    except ObservationError as error:
        print(json.dumps({"status": "UNAVAILABLE", "stage": str(error), "read_only": True,
                          "scheduler_fit": "not_verified"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
