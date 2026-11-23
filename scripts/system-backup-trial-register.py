#!/usr/bin/env python3
"""Render the registered trial resources and bind a profile to an observed Job."""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys


TEMPLATE = Path(__file__).resolve().parents[1] / "deployments/k8s/system-backup-trial-prepare.yaml.template"
REVISION_ANNOTATION = "clawmanager.io/trial-environment-revision"
MATERIAL_ANNOTATION = "clawmanager.io/trial-material-namespace"
COMMAND = "/usr/local/bin/system-backup-trial-prepare"
PLACEHOLDER = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
WORKSPACE_BLOCK = re.compile(r"^ *# trial-workspace-begin\r?\n.*?^ *# trial-workspace-end\r?\n", re.MULTILINE | re.DOTALL)
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]{0,254}@sha256:[a-f0-9]{64}")
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
SHA256 = re.compile(r"[a-f0-9]{64}")
DATABASE = re.compile(r"[a-z][a-z0-9_]{0,63}")

PLACEMENT = {"cluster", "namespace", "image", "service_account", "artifact_claim", "key_secret"}
OPTIONAL_PLACEMENT = {"artifact_storage_class", "workspace_claim", "workspace_storage_class", "instance_storage_class"}
ACCOUNT_FIELDS = {
    "source": {"source_read_secret"},
    "target": {"restore_write_secret", "restore_read_secret"},
}
PREPARATION = {
    "revision", "job_name", "service_account", "profile_configmap", "database", "server_uuid",
    "account_host", "owner_dsn_secret", "ca_configmap", "run_as_user", "run_as_group", "volume_group",
}


def unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON field")
    return result


def load_json(path):
    limit = 1 << 20
    if path == "-":
        raw = sys.stdin.buffer.read(limit + 1)
    else:
        with Path(path).open("rb") as stream:
            raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("registration input exceeds the size limit")
    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("registration input must be UTF-8 JSON") from exc


def require_fields(obj, required, optional, label):
    if not isinstance(obj, dict) or not required <= obj.keys() or obj.keys() - required - optional:
        raise ValueError(f"missing or unexpected fields in {label}")


def matches(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def dns_name(value):
    return isinstance(value, str) and len(value) <= 253 and all(matches(part, LABEL) for part in value.split("."))


def mysql_host(value):
    if value in ("%", "localhost"):
        return True
    if not isinstance(value, str) or "%" in value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def output_secrets(placement, side):
    roles = ["source_read_secret"] if side == "source" else ["restore_write_secret", "restore_read_secret", "runtime_secret"]
    return [placement["key_secret"]] + [placement[role] for role in roles if role in placement]


def validate(config):
    require_fields(config, {"migration_catalog_sha256", "target_isolation_confirmed", "source", "target"}, set(), "registration")
    if not matches(config["migration_catalog_sha256"], SHA256) or config["target_isolation_confirmed"] is not True:
        raise ValueError("a pinned migration catalog and confirmed target isolation are required")
    for side, accounts in ACCOUNT_FIELDS.items():
        placement = config[side]
        required = PLACEMENT | accounts | {"prepare"}
        optional = OPTIONAL_PLACEMENT.copy()
        if side == "target":
            required.add("instance_storage_class")
            optional.add("runtime_secret")
        require_fields(placement, required, optional, side)
        if not matches(placement["namespace"], LABEL) or not matches(placement["image"], IMAGE):
            raise ValueError(f"invalid namespace or unpinned image in {side}")
        if any(not dns_name(value) for key, value in placement.items() if key not in {"namespace", "image", "prepare"}):
            raise ValueError(f"invalid resource name in {side}")
        if ("workspace_storage_class" in placement and "workspace_claim" not in placement) or placement.get("workspace_claim") == placement["artifact_claim"]:
            raise ValueError(f"invalid workspace and artifact claims in {side}")
        job = placement["prepare"]
        require_fields(job, PREPARATION, set(), f"{side}.prepare")
        if not matches(job["revision"], LABEL) or not matches(job["job_name"], LABEL):
            raise ValueError(f"invalid Job name or revision in {side}")
        if any(not dns_name(job[key]) for key in ("service_account", "profile_configmap", "owner_dsn_secret", "ca_configmap")):
            raise ValueError(f"invalid preparation resource name in {side}")
        if not matches(job["database"], DATABASE) or not matches(job["server_uuid"], UUID) or not mysql_host(job["account_host"]):
            raise ValueError(f"invalid MySQL identity in {side}")
        if any(type(job[key]) is not int or not 0 < job[key] < 2**31 for key in ("run_as_user", "run_as_group", "volume_group")):
            raise ValueError(f"invalid non-root IDs in {side}")
        outputs = output_secrets(placement, side)
        if job["service_account"] == placement["service_account"] or len(set(outputs)) != len(outputs) or job["owner_dsn_secret"] in outputs:
            raise ValueError(f"preparation and application identities or Secrets overlap in {side}")
    source, target = config["source"], config["target"]
    if not target["namespace"].startswith("cm-drill-") or not target["prepare"]["database"].startswith("cm_drill_trial_"):
        raise ValueError("the target namespace and database must be trial-isolated")
    if source["prepare"]["server_uuid"] == target["prepare"]["server_uuid"]:
        raise ValueError("the source and target MySQL UUIDs must differ")
    if source["cluster"] == target["cluster"] and source["namespace"] == target["namespace"]:
        raise ValueError("source and target namespaces must differ on the same cluster")


def template_inputs(config, side):
    local, source, target = config[side], config["source"], config["target"]
    job = local["prepare"]
    claims = [local["artifact_claim"]]
    if "workspace_claim" in local:
        claims.append(local["workspace_claim"])
    return {
        "NAMESPACE": local["namespace"], "APP_IMAGE_DIGEST": local["image"],
        "APP_SERVICE_ACCOUNT": local["service_account"], "PREPARE_SERVICE_ACCOUNT": job["service_account"],
        "PREPARE_JOB_NAME": job["job_name"], "PROFILE_REVISION": job["revision"],
        "LOCAL_OUTPUT_SECRET_NAMES_JSON": json.dumps(output_secrets(local, side)),
        "LOCAL_PVC_NAMES_JSON": json.dumps(claims),
        "PREPARE_UID": str(job["run_as_user"]), "PREPARE_GID": str(job["run_as_group"]),
        "TRIAL_VOLUME_GID": str(job["volume_group"]), "MYSQL_DATABASE": job["database"],
        "MYSQL_ACCOUNT_HOST": job["account_host"], "MIGRATION_CATALOG_SHA256": config["migration_catalog_sha256"],
        "SOURCE_MYSQL_UUID": source["prepare"]["server_uuid"], "TARGET_MYSQL_UUID": target["prepare"]["server_uuid"],
        "TARGET_NAMESPACE": target["namespace"], "TARGET_INSTANCE_STORAGE_CLASS": target["instance_storage_class"],
        "TARGET_ISOLATION_CONFIRMED": "true", "ARCHIVE_WRITE_MOUNT_READ_ONLY": "false" if side == "source" else "true",
        "WORKSPACE_MOUNT_READ_ONLY": "true" if side == "source" else "false",
        "ENVIRONMENT_PROFILE_CONFIGMAP": job["profile_configmap"], "MYSQL_OWNER_DSN_SECRET": job["owner_dsn_secret"],
        "MYSQL_CA_CONFIGMAP": job["ca_configmap"], "ARTIFACT_PVC": local["artifact_claim"],
        "WORKSPACE_PVC": local.get("workspace_claim", ""),
    }


def render_template(template, values, workspace):
    if len(WORKSPACE_BLOCK.findall(template)) != 3:
        raise ValueError("unexpected workspace blocks in preparation template")
    if not workspace:
        template = WORKSPACE_BLOCK.sub("", template)
    names = set(PLACEHOLDER.findall(template))
    expected = values.keys() if workspace else values.keys() - {"WORKSPACE_MOUNT_READ_ONLY", "WORKSPACE_PVC"}
    if names != expected:
        raise ValueError("preparation template and renderer variables do not match")
    rendered = PLACEHOLDER.sub(lambda match: values[match[1]], template)
    if "${" in rendered:
        raise ValueError("unresolved preparation template placeholder")
    return rendered.rstrip() + "\n"


def resource(api_version, kind, namespace, name, **fields):
    return {"apiVersion": api_version, "kind": kind, "metadata": {"namespace": namespace, "name": name}, **fields}


def registration_manifests(config, side):
    source, target = config["source"], config["target"]
    values = template_inputs(config, side)
    rendered = render_template(TEMPLATE.read_text(encoding="utf-8"), values, "workspace_claim" in config[side])
    if side == "source" and source["cluster"] == target["cluster"]:
        api = "rbac.authorization.k8s.io/v1"
        name = source["prepare"]["job_name"] + "-target-key"
        role = resource(api, "Role", source["namespace"], name, rules=[{
            "apiGroups": [""], "resources": ["secrets"], "resourceNames": [source["key_secret"]], "verbs": ["get"],
        }])
        binding = resource(api, "RoleBinding", source["namespace"], name,
                           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
                           subjects=[{"kind": "ServiceAccount", "name": target["prepare"]["service_account"], "namespace": target["namespace"]}])
        rendered += "".join("---\n" + json.dumps(obj, indent=2) + "\n" for obj in (role, binding))
    return rendered


def placeholders(config, side):
    local = config[side]
    items = []
    for name in output_secrets(local, side):
        secret = resource("v1", "Secret", local["namespace"], name, type="Opaque")
        secret["metadata"]["annotations"] = {MATERIAL_ANNOTATION: local["namespace"]}
        items.append(secret)
    return {"apiVersion": "v1", "kind": "List", "items": items}


def bind_profile(config, side, observed):
    local = config[side]
    job = local["prepare"]
    values = template_inputs(config, side)
    try:
        metadata = observed["metadata"]
        pod = observed["spec"]["template"]["spec"]
        container, = pod["containers"]
        security = pod["securityContext"]
        worker_security = container["securityContext"]
        env = {item["name"]: item.get("value") for item in container["env"]}
        volumes = {item["name"]: item for item in pod["volumes"]}
        mounts = {item["mountPath"]: (item["name"], item.get("readOnly", False)) for item in container["volumeMounts"]}
        uid = metadata["uid"]
        env_variables = {
            "PREPARE_DATABASE": "MYSQL_DATABASE", "PREPARE_ACCOUNT_HOST": "MYSQL_ACCOUNT_HOST",
            "PREPARE_MIGRATION_CATALOG_SHA256": "MIGRATION_CATALOG_SHA256", "SOURCE_UUID": "SOURCE_MYSQL_UUID",
            "RESTORE_UUID": "TARGET_MYSQL_UUID", "RESTORE_NAMESPACE": "TARGET_NAMESPACE",
            "RESTORE_STORAGE_CLASS": "TARGET_INSTANCE_STORAGE_CLASS", "RESTORE_ISOLATED": "TARGET_ISOLATION_CONFIRMED",
        }
        expected_env = {"SYSTEM_BACKUP_TRIAL_" + name: values[key] for name, key in env_variables.items()}
        expected_env.update({
            "SYSTEM_BACKUP_TRIAL_ENVIRONMENT_PROFILE_FILE": "/trial/profile/environment.json",
            "SYSTEM_BACKUP_TRIAL_PREPARE_OWNER_DSN_FILE": "/trial/owner/dsn",
            "SYSTEM_BACKUP_TRIAL_READ_DIR": "/trial/archive-read",
            "SYSTEM_BACKUP_TRIAL_WRITE_DIR": "/trial/archive-write",
            "SSL_CERT_FILE": "/trial/ca/ca-bundle.crt",
        })
        expected_mounts = {
            "/trial/profile": ("profile", True), "/trial/owner": ("owner", True), "/trial/ca": ("database-ca", True),
            "/trial/archive-read": ("archive", True), "/trial/archive-write": ("archive", side == "target"),
        }
        if "workspace_claim" in local:
            expected_env["SYSTEM_BACKUP_TRIAL_PREPARE_WORKSPACE_DIR"] = "/trial/workspace"
            expected_mounts["/trial/workspace"] = ("workspace", side == "source")
            if volumes["workspace"]["persistentVolumeClaim"]["claimName"] != local["workspace_claim"]:
                raise ValueError("unregistered workspace claim")
        if (observed["apiVersion"] != "batch/v1" or observed["kind"] != "Job" or metadata["name"] != job["job_name"]
                or metadata["namespace"] != local["namespace"] or metadata["annotations"][REVISION_ANNOTATION] != job["revision"]
                or not matches(uid, UUID) or metadata.get("deletionTimestamp")):
            raise ValueError("unregistered Job identity")
        if (pod["serviceAccountName"] != job["service_account"] or pod.get("initContainers")
                or security.get("runAsNonRoot") is not True or security.get("runAsUser") != job["run_as_user"]
                or security.get("runAsGroup") != job["run_as_group"] or security.get("fsGroup") != job["volume_group"]
                or worker_security.get("allowPrivilegeEscalation") is not False or worker_security.get("readOnlyRootFilesystem") is not True
                or container["image"] != local["image"] or container["command"] != [COMMAND] or container.get("args")
                or env != expected_env or len(env) != len(container["env"])):
            raise ValueError("unregistered Job execution")
        if (set(volumes) != {name for name, _ in expected_mounts.values()} or len(volumes) != len(pod["volumes"])
                or mounts != expected_mounts or len(mounts) != len(container["volumeMounts"])
                or any(item.get("subPath") or item.get("subPathExpr") for item in container["volumeMounts"])
                or volumes["profile"]["configMap"]["name"] != job["profile_configmap"]
                or volumes["owner"]["secret"]["secretName"] != job["owner_dsn_secret"]
                or volumes["owner"]["secret"]["defaultMode"] != 0o440
                or volumes["database-ca"]["configMap"]["name"] != job["ca_configmap"]
                or volumes["archive"]["persistentVolumeClaim"]["claimName"] != local["artifact_claim"]):
            raise ValueError("unregistered Job mounts")
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("observed Job does not match the registered preparation") from exc
    result = {"revision": job["revision"], "side": side, "prepare_job": {"name": job["job_name"], "uid": uid}}
    for endpoint in ("source", "target"):
        result[endpoint] = {key: value for key, value in config[endpoint].items() if key != "prepare"}
    return resource("v1", "ConfigMap", local["namespace"], job["profile_configmap"], data={"environment.json": json.dumps(result, indent=2) + "\n"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="approved registration JSON with resource references")
    parser.add_argument("--side", required=True, choices=("source", "target"))
    modes = parser.add_subparsers(dest="operation", required=True)
    modes.add_parser("placeholders", help="render empty named Secrets for first-time creation")
    modes.add_parser("render", help="render the suspended Job and its scoped roles")
    profile = modes.add_parser("profile", help="bind the ConfigMap to the observed Kubernetes Job")
    profile.add_argument("--job", required=True, help="observed Job JSON path or - for stdin")
    args = parser.parse_args()
    try:
        if args.config == "-":
            raise ValueError("use a file for the registration configuration")
        config = load_json(args.config)
        validate(config)
        if args.operation == "render":
            output = registration_manifests(config, args.side)
        else:
            data = placeholders(config, args.side) if args.operation == "placeholders" else bind_profile(config, args.side, load_json(args.job))
            output = json.dumps(data, indent=2) + "\n"
    except (OSError, ValueError) as exc:
        parser.exit(2, f"trial registration: {exc}\n")
    sys.stdout.write(output)


if __name__ == "__main__":
    main()
