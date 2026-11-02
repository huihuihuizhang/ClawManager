#!/usr/bin/env python3
"""Read-only inventory of existing v2 config metadata; never an authorization proof.

Run: python3 -B system-backup-d-v2-config-observe.py
Fixed context/namespace/UID and Deployment/mysql only. No local output files.
Missing v2 tables/columns are reported normally; missing workload identity or
existing credentials is refused. No bootstrap, migration, grants or task writes.
Only state/config metadata and counts leave the Pod; canonical/signed bodies,
passwords and SQL/kubectl stderr never do. Root socket access is not a TLS,
independent authorization, canonical authentication or PreparedCoverage proof.
Each kubectl has a timeout; total observation budget is 180 seconds. Listings
stop at 16 items, SQL row groups at 11; results are separate observations, not
an atomic deployment/configuration readiness assertion.
"""
import argparse
import json
import re
import subprocess
import sys
import time
from urllib.parse import urlencode

CONTEXT = "kubernetes-admin@kubernetes"
NAMESPACE = "clawmanager-zhanghui08-system"
NAMESPACE_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
HASH = re.compile(r"[0-9a-f]{64}")
STATE = "system_backup_v2_installation_state"
CONFIG = "system_backup_v2_configs"
MAPPING = "system_backup_installation_kek_authority"
BINDING = "system_backup_v2_kek_bindings"
ADMISSION = "system_backup_v2_kek_admissions"
EVIDENCE = "system_backup_v2_evidence"
EXPECTED = {
    STATE: {"origin_installation_id", "active_config_version", "last_effective_enabled", "matrix_key", "row_version"},
    CONFIG: {"origin_installation_id", "version", "enabled", "config_size_bytes", "config_sha256", "canonical_config_json"},
    MAPPING: {"installation_id", "identity_hash", "registry_version", "signed_record", "signature"},
    BINDING: {"installation_id", "identity_hash", "registry_version"},
    ADMISSION: {"installation_id", "config_version", "config_sha256"},
    EVIDENCE: {"owner_target_type", "owner_target_public_id", "evidence_type", "storage_state", "observed_health", "encryption", "inline_payload"},
}

# Password and database are resolved INSIDE the already identified mysql container.
# Never read a Secret, a default mysql option file, a guessed path or host credentials.
# Both password forms present is ambiguous and is refused. Stderr is never emitted.
AUTH_SHELL = r'''set +x
set +v
set -eu
command -v mysql >/dev/null 2>&1 || exit 41
db=${MYSQL_DATABASE:-}
case "$db" in ''|*[!A-Za-z0-9_]*) exit 42;; esac
[ "${#db}" -le 64 ] || exit 42
if [ -n "${MYSQL_ROOT_PASSWORD:-}" ] && [ -n "${MYSQL_ROOT_PASSWORD_FILE:-}" ]; then exit 43; fi
if [ -n "${MYSQL_ROOT_PASSWORD:-}" ]; then
  MYSQL_PWD=$MYSQL_ROOT_PASSWORD
elif [ -n "${MYSQL_ROOT_PASSWORD_FILE:-}" ]; then
  case "$MYSQL_ROOT_PASSWORD_FILE" in /*) ;; *) exit 43;; esac
  [ -f "$MYSQL_ROOT_PASSWORD_FILE" ] && [ -r "$MYSQL_ROOT_PASSWORD_FILE" ] || exit 43
  MYSQL_PWD=$(cat -- "$MYSQL_ROOT_PASSWORD_FILE") || exit 43
else
  exit 43
fi
[ -n "$MYSQL_PWD" ] && [ "${#MYSQL_PWD}" -le 4096 ] || exit 43
export MYSQL_PWD
exec mysql --no-defaults --no-login-paths --user=root --protocol=socket --connect-timeout=5 --local-infile=0 --batch --raw --skip-column-names --database="$db"
'''


class Refused(Exception):
    def __init__(self, reason):
        self.reason = reason


def require(ok, reason="unexpected_observation_shape"):
    if not ok:
        raise Refused(reason)


def select(expression, source=""):
    return "SELECT /*+ MAX_EXECUTION_TIME(5000) */ " + expression + (" FROM " + source if source else "") + ";"


def readonly(statements):
    return ("START TRANSACTION READ ONLY;\n" + "\n".join(statements) + "\nROLLBACK;\n").encode()


def metadata_sql():
    tables = ",".join("'" + name + "'" for name in EXPECTED)
    column_filters = " OR ".join("(TABLE_NAME='" + table + "' AND COLUMN_NAME IN ("
        + ",".join("'" + name + "'" for name in sorted(names)) + "))" for table, names in EXPECTED.items())
    return readonly([
        select("JSON_OBJECT('kind','server','server_uuid',@@server_uuid,'server_version',VERSION(),'database',DATABASE())"),
        select("JSON_OBJECT('kind','table','table',TABLE_NAME)",
               "information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' AND TABLE_NAME IN (" + tables + ") ORDER BY TABLE_NAME LIMIT 7"),
        select("JSON_OBJECT('kind','column','table',TABLE_NAME,'column',COLUMN_NAME)",
               "information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND (" + column_filters + ") ORDER BY TABLE_NAME,COLUMN_NAME LIMIT 128"),
    ])


def build_summary_sql(columns):
    """Construct only allowlisted SELECTs, and never name an absent column."""
    statements = [select("JSON_OBJECT('kind','server','server_uuid',@@server_uuid,'server_version',VERSION(),'database',DATABASE())")]
    skipped = {}
    state_ready = EXPECTED[STATE] <= columns.get(STATE, set())
    if state_ready:
        statements.append(select("JSON_OBJECT('kind','installation','installation_sha256',SHA2(s.origin_installation_id,256),"
            "'active_config_version',s.active_config_version,'last_effective_enabled',s.last_effective_enabled,"
            "'matrix_key',s.matrix_key,'row_version',s.row_version)", STATE + " s ORDER BY s.origin_installation_id LIMIT 11"))
    else:
        skipped["installation_rows"] = "missing_required_columns"
    config_base = EXPECTED[CONFIG] - {"canonical_config_json"}
    if state_ready and config_base <= columns.get(CONFIG, set()):
        canonical = "'canonical_present',NULL,'canonical_length_matches',NULL,'canonical_hash_matches',NULL"
        if "canonical_config_json" in columns[CONFIG]:
            canonical = ("'canonical_present',c.canonical_config_json IS NOT NULL,"
                         "'canonical_length_matches',IF(c.canonical_config_json IS NULL,NULL,OCTET_LENGTH(c.canonical_config_json)=c.config_size_bytes),"
                         "'canonical_hash_matches',IF(c.canonical_config_json IS NULL,NULL,BINARY SHA2(c.canonical_config_json,256)=BINARY c.config_sha256)")
        statements.append(select("JSON_OBJECT('kind','config','installation_sha256',SHA2(s.origin_installation_id,256),"
            "'version',c.version,'enabled',c.enabled,'config_size_bytes',c.config_size_bytes,'config_sha256',c.config_sha256," + canonical + ")",
            CONFIG + " c JOIN " + STATE + " s ON s.origin_installation_id=c.origin_installation_id AND s.active_config_version=c.version ORDER BY s.origin_installation_id LIMIT 11"))
    else:
        skipped["active_config_rows"] = "missing_required_columns"
    # Counts are associated with existing installation rows, not a guessed ID.
    # They prove existence only, not mapping/permission/signature/coverage validity.
    for table, kind in ((MAPPING, "kek_mapping_count"), (BINDING, "kek_binding_count"), (ADMISSION, "kek_admission_count")):
        if state_ready and EXPECTED[table] <= columns.get(table, set()):
            suffix = ""
            if table == MAPPING:
                suffix = " AND OCTET_LENGTH(x.signed_record)>0 AND OCTET_LENGTH(x.signature)>0"
            statements.append(select("JSON_OBJECT('kind','" + kind + "','count',COUNT(*))", table + " x WHERE EXISTS (SELECT 1 FROM "
                + STATE + " s WHERE s.origin_installation_id=x.installation_id)" + suffix))
        else:
            skipped[kind] = "missing_required_columns"
    if state_ready and EXPECTED[EVIDENCE] <= columns.get(EVIDENCE, set()):
        statements.append(select("JSON_OBJECT('kind','capability_snapshot_count','count',COUNT(*))", EVIDENCE
            + " x WHERE x.owner_target_type='system' AND x.evidence_type='capability_snapshot' AND x.storage_state='inline'"
            + " AND x.observed_health='healthy' AND x.encryption='none' AND OCTET_LENGTH(x.inline_payload)>0 AND EXISTS (SELECT 1 FROM " + STATE
            + " s WHERE s.origin_installation_id=x.owner_target_public_id)"))
    else:
        skipped["capability_snapshot_count"] = "missing_required_columns"
    return readonly(statements), skipped


def rows(raw):
    require(len(raw) <= 131072, "sql_output_limit")
    lines = raw.decode("utf-8").splitlines()
    require(len(lines) <= 160, "sql_row_limit")
    return [json.loads(line) for line in lines if line.strip()]


def server(row):
    require(set(row) == {"kind", "server_uuid", "server_version", "database"} and row["kind"] == "server")
    require(type(row["server_uuid"]) is str and UUID.fullmatch(row["server_uuid"]))
    require(type(row["server_version"]) is str and re.fullmatch(r"[A-Za-z0-9.+_-]{1,128}", row["server_version"]))
    require(type(row["database"]) is str and re.fullmatch(r"[A-Za-z0-9_]{1,64}", row["database"]))
    return {key: row[key] for key in ("server_uuid", "server_version", "database")}


def integer(value):
    return type(value) is int and 0 <= value <= 18446744073709551615


def validate_summary(row):
    kind = row.get("kind")
    if kind == "installation":
        require(set(row) == {"kind", "installation_sha256", "active_config_version", "last_effective_enabled", "matrix_key", "row_version"})
        require(type(row["installation_sha256"]) is str and HASH.fullmatch(row["installation_sha256"]))
        require(integer(row["active_config_version"]) and integer(row["row_version"]))
        require(type(row["last_effective_enabled"]) is int and row["last_effective_enabled"] in (0, 1))
        require(row["matrix_key"] in ("k8s-cluster", "k3s-cluster", "k8s-single-node", "k3s-single-node"))
    elif kind == "config":
        require(set(row) == {"kind", "installation_sha256", "version", "enabled", "config_size_bytes", "config_sha256", "canonical_present", "canonical_length_matches", "canonical_hash_matches"})
        require(type(row["installation_sha256"]) is str and HASH.fullmatch(row["installation_sha256"]))
        require(type(row["config_sha256"]) is str and HASH.fullmatch(row["config_sha256"]))
        require(integer(row["version"]) and integer(row["config_size_bytes"]))
        require(type(row["enabled"]) is int and row["enabled"] in (0, 1))
        for key in ("canonical_present", "canonical_length_matches", "canonical_hash_matches"):
            require(row[key] is None or (type(row[key]) is int and row[key] in (0, 1)))
    elif kind in ("kek_mapping_count", "kek_binding_count", "kek_admission_count", "capability_snapshot_count"):
        require(set(row) == {"kind", "count"} and integer(row["count"]))
    else:
        raise Refused("unexpected_summary_kind")
    return row


class Observer:
    def __init__(self):
        self.deadline = time.monotonic() + 180
        self.deployment_uid = self.rs_uid = self.pod_uid = None
        self.rs_name = self.pod_name = self.container_id = None
        self.mysql_image = None
        self.selector = None

    def command(self, args, data=None):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "observation_deadline")
        try:
            result = subprocess.run(["kubectl", "--context=" + CONTEXT, "--request-timeout=20s"] + args,
                input=data, capture_output=True, timeout=min(40 if data is not None else 25, remaining))
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("kubectl_unavailable_or_timeout") from None
        if result.returncode:
            if data is not None and result.returncode in (41, 42, 43):
                raise Refused({41: "mysql_cli_missing", 42: "existing_MYSQL_DATABASE_missing_or_unsupported", 43: "existing_root_password_missing_or_ambiguous"}[result.returncode])
            raise Refused("kubectl_or_mysql_read_failed")
        require(len(result.stdout) <= 2097152, "kubectl_output_limit")
        return result.stdout

    def get(self, kind, name):
        args = ["get", kind, name, "-o", "json"]
        if kind != "namespace":
            args = ["-n", NAMESPACE] + args
        return json.loads(self.command(args))

    def namespace(self):
        item = self.get("namespace", NAMESPACE)
        self.type_meta(item, "Namespace")
        require(item["metadata"]["name"] == NAMESPACE and item["metadata"]["uid"] == NAMESPACE_UID
                and not item["metadata"].get("deletionTimestamp"), "namespace_identity_changed")

    def type_meta(self, item, kind, listed=False):
        version = "apps/v1" if kind in ("Deployment", "ReplicaSet", "ReplicaSetList") else "v1"
        point = kind.lower() + ("_list_item" if listed else "")
        require(type(item) is dict, point + "_shape_invalid")
        # Typed Kubernetes lists can omit their items' TypeMeta. An explicitly
        # supplied value must still match; single-resource GETs require both.
        require((listed and "kind" not in item) or item.get("kind") == kind, point + "_kind_mismatch")
        require((listed and "apiVersion" not in item) or item.get("apiVersion") == version, point + "_api_version_mismatch")

    def metadata(self, item, kind, name=None, uid=None, listed=False):
        self.type_meta(item, kind, listed)
        point = kind.lower() + ("_list_item" if listed else "")
        meta = item.get("metadata")
        require(type(meta) is dict, point + "_metadata_invalid")
        require(meta.get("namespace") == NAMESPACE, point + "_namespace_mismatch")
        require(not meta.get("deletionTimestamp"), point + "_deleting")
        require(type(meta.get("name")) is str and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", meta["name"]), point + "_name_invalid")
        require(type(meta.get("uid")) is str and UUID.fullmatch(meta["uid"]), point + "_uid_invalid")
        require(name is None or meta["name"] == name, point + "_name_changed")
        require(uid is None or meta["uid"] == uid, point + "_uid_changed")
        return meta

    def owned_by(self, item, kind, name, uid):
        owners = [owner for owner in item["metadata"].get("ownerReferences", []) if owner.get("controller") is True]
        return len(owners) == 1 and owners[0].get("apiVersion") == "apps/v1" and owners[0].get("kind") == kind and owners[0].get("name") == name and owners[0].get("uid") == uid

    def listing(self, resource):
        require(resource in ("replicasets", "pods"), "unsupported_listing_resource")
        kind, path = ("ReplicaSet", "/apis/apps/v1/") if resource == "replicasets" else ("Pod", "/api/v1/")
        query = urlencode({"labelSelector": self.selector, "limit": "16"})
        obj = json.loads(self.command(["get", "--raw=" + path + "namespaces/" + NAMESPACE + "/" + resource + "?" + query]))
        self.type_meta(obj, kind + "List")
        require(type(obj.get("metadata")) is dict and type(obj.get("items")) is list, kind.lower() + "list_shape_invalid")
        require(not obj["metadata"].get("continue") and len(obj["items"]) <= 16, "workload_listing_limit")
        for item in obj["items"]:
            self.type_meta(item, kind, listed=True)
            require(type(item.get("metadata")) is dict and item["metadata"].get("namespace") == NAMESPACE,
                    kind.lower() + "_list_item_namespace_mismatch")
        return obj["items"]

    def container(self, pod):
        containers = [item for item in pod["spec"]["containers"] if item.get("name") == "mysql"]
        statuses = [item for item in pod.get("status", {}).get("containerStatuses", []) if item.get("name") == "mysql"]
        require(len(containers) == len(statuses) == 1 and pod.get("status", {}).get("phase") == "Running", "mysql_container_not_ready")
        require(statuses[0].get("ready") is True and "running" in statuses[0].get("state", {}), "mysql_container_not_ready")
        image = containers[0].get("image")
        container_id = statuses[0].get("containerID", "")
        require(type(image) is str and image and type(container_id) is str and re.fullmatch(r"(?:containerd|docker|cri-o)://[a-f0-9]{12,128}", container_id), "mysql_container_identity_missing")
        require((self.mysql_image is None or self.mysql_image == image) and (self.container_id is None or self.container_id == container_id), "mysql_container_restarted_or_changed")
        self.mysql_image, self.container_id = image, container_id

    def discover(self):
        self.namespace()
        deployment = self.get("deployment", "mysql")
        self.deployment_uid = self.metadata(deployment, "Deployment", "mysql")["uid"]
        selector = deployment["spec"]["selector"]
        require(not selector.get("matchExpressions") and selector.get("matchLabels"), "unsupported_deployment_selector")
        labels = selector["matchLabels"]
        require(len(labels) <= 8 and all(re.fullmatch(r"[A-Za-z0-9_./-]{1,253}", k) and re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", v) for k, v in labels.items()), "unsupported_deployment_selector")
        self.selector = ",".join(k + "=" + v for k, v in sorted(labels.items()))
        desired = [item for item in deployment["spec"]["template"]["spec"]["containers"] if item.get("name") == "mysql"]
        require(len(desired) == 1, "mysql_container_identity_missing")
        self.mysql_image = desired[0]["image"]
        replicas = {}
        for rs in self.listing("replicasets"):
            if self.owned_by(rs, "Deployment", "mysql", self.deployment_uid) and not rs["metadata"].get("deletionTimestamp"):
                meta = self.metadata(rs, "ReplicaSet", listed=True)
                replicas[meta["uid"]] = meta["name"]
        candidates = []
        for pod in self.listing("pods"):
            if pod["metadata"].get("deletionTimestamp") or pod.get("status", {}).get("phase") != "Running":
                continue
            for uid, name in replicas.items():
                if self.owned_by(pod, "ReplicaSet", name, uid):
                    meta = self.metadata(pod, "Pod", listed=True)
                    candidates.append((meta["name"], meta["uid"], name, uid))
        require(len(candidates) == 1, "mysql_pod_missing_or_ambiguous")
        self.pod_name, self.pod_uid, self.rs_name, self.rs_uid = candidates[0]
        # The list discovers candidates only. Re-read the selected resources by
        # name and UID, requiring full single-object TypeMeta and owner chains.
        self.recheck()

    def recheck(self):
        self.namespace()
        deployment = self.get("deployment", "mysql")
        self.metadata(deployment, "Deployment", "mysql", self.deployment_uid)
        desired = [item for item in deployment["spec"]["template"]["spec"]["containers"] if item.get("name") == "mysql"]
        require(len(desired) == 1 and desired[0].get("image") == self.mysql_image, "deployment_container_changed")
        rs = self.get("replicaset", self.rs_name)
        self.metadata(rs, "ReplicaSet", self.rs_name, self.rs_uid)
        require(self.owned_by(rs, "Deployment", "mysql", self.deployment_uid), "replicaset_owner_changed")
        pod = self.get("pod", self.pod_name)
        self.metadata(pod, "Pod", self.pod_name, self.pod_uid)
        require(self.owned_by(pod, "ReplicaSet", self.rs_name, self.rs_uid), "pod_owner_changed")
        self.container(pod)

    def sql(self, text):
        self.recheck()
        return rows(self.command(["-n", NAMESPACE, "exec", "-i", self.pod_name, "-c", "mysql", "--", "/bin/sh", "-c", AUTH_SHELL], text))

    def run(self):
        self.discover()
        observed = self.sql(metadata_sql())
        require(observed and observed[0].get("kind") == "server")
        identity = server(observed[0])
        tables, columns = set(), {name: set() for name in EXPECTED}
        for row in observed[1:]:
            require(row.get("table") in EXPECTED)
            if row.get("kind") == "table":
                require(set(row) == {"kind", "table"} and row["table"] not in tables)
                tables.add(row["table"])
            elif row.get("kind") == "column":
                require(set(row) == {"kind", "table", "column"} and row["column"] in EXPECTED[row["table"]])
                columns[row["table"]].add(row["column"])
            else:
                raise Refused("unexpected_metadata_kind")
        for name in EXPECTED:
            if name not in tables:
                columns[name] = set()
        query, skipped = build_summary_sql(columns)
        summary = self.sql(query)
        require(summary and server(summary[0]) == identity, "database_identity_changed")
        safe_rows = [validate_summary(row) for row in summary[1:]]
        require(sum(row["kind"] == "installation" for row in safe_rows) <= 11 and sum(row["kind"] == "config" for row in safe_rows) <= 11)
        self.recheck()
        return {"schema_version": "d-v2-config-observe.v1", "read_only": True, "context": CONTEXT,
            "namespace": NAMESPACE, "namespace_uid": NAMESPACE_UID, "deployment_uid": self.deployment_uid,
            "pod": self.pod_name, "pod_uid": self.pod_uid, "container": "mysql", **identity,
            "tables": {name: {"present": name in tables, "columns": {key: key in columns[name] for key in sorted(EXPECTED[name])},
                              "missing_columns": sorted(EXPECTED[name] - columns[name])} for name in EXPECTED},
            "observations": safe_rows, "skipped": skipped,
            "row_limit_per_installation_or_config_group": 11,
            "rows_may_be_truncated": {kind: sum(row["kind"] == kind for row in safe_rows) == 11 for kind in ("installation", "config")},
            "generate_unwrap_classification": "not_authenticated_or_classified; capability_snapshot_count is candidate existence only",
            "authenticated_config": False, "tls_verified": False, "permissions_verified": False, "coverage_verified": False,
            "first_installation_decision": "requires_owner_review; no configuration or task created"}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        report = Observer().run()
    except Refused as error:
        print(json.dumps({"schema_version": "d-v2-config-observe.v1", "read_only": True, "status": "refused", "reason": error.reason}))
        return 1
    except Exception:
        print(json.dumps({"schema_version": "d-v2-config-observe.v1", "read_only": True, "status": "refused", "reason": "private_error_details_withheld"}))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
