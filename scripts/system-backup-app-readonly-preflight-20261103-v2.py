#!/usr/bin/env python3
"""Original app/MySQL read-only diagnostic. No server start, DDL or rollout.

Requires kubectl and Python 3.10+. Credentials stay in the original MySQL Pod.
Only whitelisted non-secret app settings, identities and migration names leave
the cluster. Target database must be taken from the original private config.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

NS = "clawmanager-zhanghui08-system"
NS_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
APP = "clawmanager-app"
APP_UID = "ed2c80de-9d24-4ca6-8f9c-877a990ac933"
MYSQL_UID = "27916932-fc61-432c-b515-081f18db34a8"
CATALOG_SHA = "19c41f6e801a75da527d56b5ca15e93aa2580a0ce3ac4237629e87d59a6c8d72"
FLAGS = (
    "DB_NAME", "SYSTEM_BACKUP_READ_SESSIONS_ENABLED", "SYSTEM_BACKUP_READ_LIVE_ENABLED",
    "SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED", "SYSTEM_BACKUP_SQL_GATE_SCOPE",
    "SYSTEM_BACKUP_API_PROXY_ENABLED", "SYSTEM_BACKUP_API_TLS_ADDRESS",
    "SYSTEM_BACKUP_API_TLS_CERT_FILE", "SYSTEM_BACKUP_API_TLS_KEY_FILE",
    "SYSTEM_BACKUP_REGISTRATION_INSTALLATION_ID", "SYSTEM_BACKUP_READ_SESSIONS_SERVER_UUID",
    "SYSTEM_BACKUP_EXECUTION_PROTOCOL", "SYSTEM_BACKUP_V2_EXECUTION_ENABLED",
    "SYSTEM_BACKUP_EXECUTION_PROFILE_FILE", "SYSTEM_BACKUP_CAPACITY_REPORT_FILE",
    "SYSTEM_BACKUP_READ_PINS_PATH", "SYSTEM_BACKUP_READ_PINS_SHA256",
    "SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE", "SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_SHA256",
    "OBJECT_STORAGE_TLS_CA_FILE", "OBJECT_STORAGE_TLS_CA_SHA256",
    "RUNTIME_AGENT_CA_FILE", "RUNTIME_AGENT_CA_SHA256",
)
REPORT = {"schema_version": "app_readonly_preflight.v1", "read_only": True,
          "observed_at": datetime.now(timezone.utc).isoformat(), "backup_readiness_established": False,
          "independent_installation_authorization": False}


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def kube(*args, stdin=None):
    command = ["kubectl", "--context", "kubernetes-admin@kubernetes", "--namespace", NS, *args]
    result = subprocess.run(command, input=stdin, text=True, capture_output=True, timeout=75)
    need(result.returncode == 0, "read_only_command_failed_private_stderr_not_echoed")
    need(len(result.stdout) < 8 * 1024 * 1024, "read_only_output_too_large")
    return result.stdout


def get(kind, name):
    return json.loads(kube("get", kind, name, "-o", "json"))


def dep(name, uid):
    value = get("deployment", name)
    need(value["metadata"]["uid"] == uid, "original_deployment_uid_changed:" + name)
    return value


def ready_original_pod(deployment, container):
    selector = deployment["spec"]["selector"]
    need(not selector.get("matchExpressions"), "selector_expression_requires_original_owner_review")
    labels = ",".join(k + "=" + v for k, v in sorted(selector["matchLabels"].items()))
    candidates = []
    for pod in json.loads(kube("get", "pods", "-l", labels, "-o", "json"))["items"]:
        if pod["metadata"].get("deletionTimestamp") or pod.get("status", {}).get("phase") != "Running":
            continue
        owners = [x for x in pod["metadata"].get("ownerReferences", []) if x.get("controller") and x["kind"] == "ReplicaSet"]
        if len(owners) != 1:
            continue
        rs = get("replicaset", owners[0]["name"])
        if rs["metadata"]["uid"] != owners[0]["uid"] or not any(x.get("controller") and x["uid"] == deployment["metadata"]["uid"] for x in rs["metadata"].get("ownerReferences", [])):
            continue
        if any(x["name"] == container and x.get("ready") for x in pod["status"].get("containerStatuses", [])):
            candidates.append(pod)
    need(len(candidates) == 1, "one_original_ready_pod_required:" + container)
    return candidates[0]


def classify(flags):
    fatal, unknown, not_ready = [], [], []
    for name in ("SYSTEM_BACKUP_READ_SESSIONS_ENABLED", "SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED", "SYSTEM_BACKUP_API_PROXY_ENABLED"):
        if flags[name] not in ("", "false", "true"):
            fatal.append("invalid_startup_switch:" + name)
    if flags["SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED"] == "true":
        if flags["SYSTEM_BACKUP_READ_SESSIONS_ENABLED"] != "true" or flags["SYSTEM_BACKUP_READ_LIVE_ENABLED"] != "true":
            fatal.append("config_mutation_requires_sessions_and_live_true")
        if not flags["SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE"] or not re.fullmatch(r"[0-9a-f]{64}", flags["SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_SHA256"]):
            fatal.append("config_mutation_composition_file_and_literal_sha_missing_or_invalid")
        unknown.append("actual_private_canonical_31_source_factory_and_effective_JWT_secret_validation")
    if flags["SYSTEM_BACKUP_READ_SESSIONS_ENABLED"] == "true":
        if not flags["SYSTEM_BACKUP_REGISTRATION_INSTALLATION_ID"] or not flags["SYSTEM_BACKUP_READ_SESSIONS_SERVER_UUID"]:
            fatal.append("session_installation_or_server_uuid_missing")
        unknown.append("actual_independent_UTC_SQL_session_identity_and_effective_JWT_secret_validation")
    elif flags["SYSTEM_BACKUP_REGISTRATION_INSTALLATION_ID"]:
        unknown.append("selected_registration_requires_actual_SQL_session_revocation_support")
    if flags["SYSTEM_BACKUP_SQL_GATE_SCOPE"]:
        unknown.append("actual_independent_backup_HTTP_control_credential_and_SQL_gate_constructor")
    for prefix in ("OBJECT_STORAGE_TLS_CA", "RUNTIME_AGENT_CA"):
        file, sha = flags[prefix + "_FILE"], flags[prefix + "_SHA256"]
        if file or sha:
            if not file or not re.fullmatch(r"[0-9a-f]{64}", sha):
                fatal.append("selected_CA_file_and_sha_missing_or_invalid:" + prefix)
            unknown.append("actual_selected_CA_constructor:" + prefix)
    if flags["SYSTEM_BACKUP_API_PROXY_ENABLED"] != "true":
        cert, key = flags["SYSTEM_BACKUP_API_TLS_CERT_FILE"], flags["SYSTEM_BACKUP_API_TLS_KEY_FILE"]
        address = flags["SYSTEM_BACKUP_API_TLS_ADDRESS"]
        if bool(cert) != bool(key) or address not in ("", "127.0.0.1:9002") or address and not cert:
            fatal.append("invalid_private_API_TLS_selection")
        elif cert or key:
            unknown.append("actual_private_API_certificate_key_constructor")
    else:
        unknown.append("new_entrypoint_generated_private_API_TLS_and_nginx_startup")
    if flags["SYSTEM_BACKUP_READ_LIVE_ENABLED"] != "true":
        not_ready.append("live_reads_not_selected_routes_unavailable_not_startup_fatal")
    else:
        not_ready.append("cursor_key_read_pins_and_publication_inputs_require_real_authorizer_readback_missing_inputs_are_not_main_fatal")
    if flags["SYSTEM_BACKUP_EXECUTION_PROTOCOL"] != "public-v1" or flags["SYSTEM_BACKUP_V2_EXECUTION_ENABLED"] != "true" or not flags["SYSTEM_BACKUP_EXECUTION_PROFILE_FILE"]:
        not_ready.append("execution_not_selected_or_profile_missing_POST_not_ready_not_startup_fatal")
    else:
        not_ready.append("actual_admitted_writer_profile_capacity_coverage_and_current_receipt_still_required")
    return {"source_proven_fatal": fatal, "private_or_native_validation_required": unknown, "backup_not_ready_or_unverified_only": not_ready,
            "limit": "Environment is observed, not full effective YAML configuration. No private material is parsed and no server is started. Ordinary non-backup startup constructors remain outside this diagnostic."}


def main(args):
    need(args.observe or args.database, "use_observe_or_supply_original_database")
    if args.database:
        need(re.fullmatch(r"[A-Za-z0-9_]{1,64}", args.database), "invalid_original_database")
    if args.expected_server_uuid:
        need(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", args.expected_server_uuid), "invalid_expected_original_server_uuid")
    raw = args.catalog.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == CATALOG_SHA, "reviewed_177_catalog_changed")
    catalog = json.loads(raw)
    need(len(catalog["filenames"]) == 177, "reviewed_catalog_count_changed")
    need(get("namespace", NS)["metadata"]["uid"] == NS_UID, "original_namespace_uid_changed")
    app = dep(APP, APP_UID)
    app_pod = ready_original_pod(app, APP)
    containers = [c for c in app["spec"]["template"]["spec"]["containers"] if c["name"] == APP]
    need(len(containers) == 1, "original_app_container_not_unique")
    REPORT["application"] = {"namespace": NS, "namespace_uid": NS_UID, "deployment": APP, "deployment_uid": APP_UID,
                              "resource_version": app["metadata"]["resourceVersion"], "pod_uid": app_pod["metadata"]["uid"], "image": containers[0]["image"]}
    statuses = [c for c in app_pod.get("status", {}).get("containerStatuses", []) if c["name"] == APP]
    need(len(statuses) == 1 and statuses[0].get("ready"), "original_app_ready_container_status_missing")
    REPORT["application"]["ready_container_image_id"] = statuses[0].get("imageID")
    REPORT["application"]["ready_container_image"] = statuses[0].get("image")
    REPORT["application"]["image_id_interpretation"] = "raw Pod status.imageID observation only; repository manifest digest not inferred"
    script = "\n".join('printf "%s\\t%s\\n" ' + key + ' "${' + key + '-}"' for key in FLAGS)
    flags = dict(line.split("\t", 1) for line in kube("exec", app_pod["metadata"]["name"], "-c", APP, "--", "sh", "-c", script).splitlines())
    need(set(flags) == set(FLAGS), "whitelisted_app_settings_incomplete")
    REPORT["observed_nonsecret_settings"] = flags
    REPORT["startup"] = classify(flags)
    mysql = dep("mysql", MYSQL_UID)
    mysql_pod = ready_original_pod(mysql, "mysql")
    if not args.database:
        observed = kube("exec", mysql_pod["metadata"]["name"], "-c", "mysql", "--", "sh", "-c", 'printf "%s\\n" "${MYSQL_DATABASE-}"').strip()
        need(re.fullmatch(r"[A-Za-z0-9_]{1,64}", observed), "original_MYSQL_DATABASE_not_set_observe_cannot_guess")
        args.database = observed
        REPORT["database_name_source"] = "observed_original_mysql_pod_MYSQL_DATABASE_not_independent_authority"
    else:
        REPORT["database_name_source"] = "operator_supplied_original_configuration"
    if flags["DB_NAME"]:
        REPORT["application_database_match"] = flags["DB_NAME"] == args.database
        if not REPORT["application_database_match"]:
            REPORT["startup"]["private_or_native_validation_required"].append("observed_app_and_mysql_database_names_differ_ledger_is_mysql_database_only")
    else:
        REPORT["application_database_match"] = None
        REPORT["startup"]["private_or_native_validation_required"].append("DB_NAME_unset_verify_observed_database_against_effective_private_YAML")

    def sql(query):
        # SELECT-only READ ONLY transaction. Existing password stays in Pod env,
        # never process argv, result JSON, local DSN or terminal stderr.
        shell = 'set -eu; test "${MYSQL_DATABASE:-}" = "$1"; if [ -n "${MYSQL_USER:-}" ] && [ -n "${MYSQL_PASSWORD:-}" ]; then probe_user="$MYSQL_USER"; export MYSQL_PWD="$MYSQL_PASSWORD"; elif [ -n "${MYSQL_ROOT_PASSWORD:-}" ]; then probe_user=root; export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; else exit 2; fi; exec mysql --protocol=socket --batch --raw --skip-column-names --user="$probe_user" --database="$1"'
        return kube("exec", "-i", mysql_pod["metadata"]["name"], "-c", "mysql", "--", "sh", "-c", shell, "readonly-preflight", args.database,
                    stdin="START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY;\n" + query + "\nCOMMIT;\n").splitlines()

    identity = sql("SELECT @@server_uuid,DATABASE();")
    need(len(identity) == 1 and len(identity[0].split("\t")) == 2, "original_mysql_identity_unavailable")
    server_uuid, database = identity[0].split("\t")
    REPORT["database"] = {"server_uuid": server_uuid, "database": database, "mysql_deployment_uid": MYSQL_UID,
                          "mysql_pod_uid": mysql_pod["metadata"]["uid"], "identity_compared_to_expected": bool(args.expected_server_uuid)}
    need(database == args.database and (not args.expected_server_uuid or server_uuid == args.expected_server_uuid), "actual_original_mysql_identity_pin_mismatch")
    present = sql("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='schema_migrations';")
    need(present in (["0"], ["1"]), "migration_ledger_presence_unknown")
    names = [] if present == ["0"] else sql("SELECT filename FROM schema_migrations ORDER BY filename;")
    need(len(names) == len(set(names)) and all(re.fullmatch(r"[0-9]{3}_[A-Za-z0-9_-]+\.sql", n) for n in names), "actual_migration_ledger_invalid")
    missing = sorted(set(catalog["filenames"]) - set(names))
    gated = bool(flags["SYSTEM_BACKUP_SQL_GATE_SCOPE"].strip())
    REPORT["migrations"] = {"catalog_sha256": catalog["catalog_sha256"], "catalog_count": 177, "ledger_table_present": present == ["1"],
                            "actual_applied": names, "missing": missing, "historical_extra": sorted(set(names) - set(catalog["filenames"])),
                            "next_app_start_would_attempt_pending_DDL": bool(missing) and not gated,
                            "next_gated_app_start_would_fail_missing_migrations": bool(missing) and gated,
                            "rollback_reverses_DDL": False, "ledger_names_do_not_prove_original_SQL_or_schema_equivalence": True}
    if REPORT["application_database_match"] is False:
        REPORT["next_step"] = "NO_ROLLOUT: observed app/MySQL database names differ; ledger describes original MySQL database only, resolve actual app configuration first"
    elif missing:
        REPORT["next_step"] = "DO_NOT_REPLACE_APP_IMAGE_YET: review actual pending/historical ledger and original offline migration before rollout; this tool applies nothing"
    elif REPORT["startup"]["source_proven_fatal"]:
        REPORT["next_step"] = "DO_NOT_REPLACE_APP_IMAGE_YET: resolve the reported source-proven fatal selections"
    elif REPORT["startup"]["private_or_native_validation_required"]:
        REPORT["next_step"] = "NO_PENDING_EMBEDDED_DDL: validate the listed actual private/native startup inputs before guarded app-only image replacement"
    else:
        REPORT["next_step"] = "NO_PENDING_EMBEDDED_DDL_OR_NEW_OPT_IN_FATAL_FROM_OBSERVED_ENV: root may review guarded app-only image replacement; verify backup coordination idle separately; backup readiness remains unverified"
    REPORT["status"] = "read_only_diagnostic_complete"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observe", action="store_true", help="Observe original UID-pinned MySQL Pod database env and UUID; grants no installation authority")
    parser.add_argument("--database", help="Original DB name from private existing config; if absent --observe reads original MYSQL_DATABASE")
    parser.add_argument("--expected-server-uuid", help="Original independent MySQL UUID pin, if already available")
    parser.add_argument("--catalog", required=True, type=Path)
    arguments = parser.parse_args()
    code = 0
    try:
        main(arguments)
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        REPORT["status"] = "read_only_probe_blocked"
        REPORT["reason"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        REPORT["next_step"] = "NO_ROLLOUT: resolve original identity/private read access or config selection; no mutation was performed"
        code = 2
    print(json.dumps(REPORT, ensure_ascii=False, indent=2))
    sys.exit(code)
