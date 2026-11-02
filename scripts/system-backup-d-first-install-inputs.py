#!/usr/bin/env python3
"""UID/owner-pinned public first-install inputs; never deploys or reads Secrets."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

NAMESPACE = "clawmanager-zhanghui08-system"
NAMESPACE_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
WORKLOADS = ("deployments", "replicasets", "pods", "statefulsets", "daemonsets",
             "jobs", "cronjobs", "replicationcontrollers", "horizontalpodautoscalers")
RESOURCES = WORKLOADS + ("serviceaccounts", "services", "persistentvolumeclaims", "configmaps")
KINDS = dict(zip(WORKLOADS, ("Deployment", "ReplicaSet", "Pod", "StatefulSet", "DaemonSet",
                            "Job", "CronJob", "ReplicationController", "HorizontalPodAutoscaler")))
_serial = 0


class Refused(Exception):
    pass


def require(ok, reason="public_input_shape_rejected"):
    if not ok:
        raise Refused(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def text(value):
    return isinstance(value, str) and 0 < len(value) <= 512 and all(ord(c) >= 32 for c in value)


def write_public(directory, name, result):
    require(directory and Path(directory).is_absolute(), "private_output_directory_required")
    directory = Path(directory)
    require(not directory.is_symlink() and directory.is_dir()
            and (os.name != "posix" or directory.stat().st_mode & 0o077 == 0), "private_output_directory_required")
    raw, output = canonical(result), directory / name
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        require(file.write(raw) == len(raw), "public_output_write_failed")
    return {"file": str(output), "sha256": sha(raw)}


def prepare_sql_plan(args):
    require(args.inventory_file and Path(args.inventory_file).is_absolute()
            and not Path(args.inventory_file).is_symlink(), "selected_inventory_required")
    require(re.fullmatch(r"[a-f0-9]{64}", args.inventory_sha256 or ""), "selected_inventory_pin_required")
    with open(args.inventory_file, "rb") as file:
        raw = file.read((8 << 20) + 1)
    require(len(raw) <= 8 << 20 and sha(raw) == args.inventory_sha256, "inventory_pin_changed")
    inventory = json.loads(raw)
    require(inventory.get("schema_version") == "zhanghui08-original-first-install-public-inputs.v1"
            and inventory.get("namespace") == NAMESPACE and inventory.get("namespace_uid") == NAMESPACE_UID,
            "original_inventory_required")
    require(re.fullmatch(r"[a-f0-9]{64}", args.mysql_ca_sha256 or "")
            and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", args.mysql_server_uuid or "")
            and re.fullmatch(r"[A-Za-z0-9_]{1,64}", args.mysql_database or "")
            and re.fullmatch(r"[A-Za-z0-9_]+@[A-Za-z0-9_.:%-]+", args.mysql_account or "")
            and args.mysql_account.split("@", 1)[0] != "root", "original_DBA_public_selections_required")
    service = [x for x in inventory["public_objects"].get("services", {}).get("items", [])
               if x["name"] == args.mysql_service and x["namespace"] == NAMESPACE]
    require(len(service) == 1 and args.mysql_port in [p["port"] for p in service[0]["ports"]],
            "actual_original_service_port_required")
    census = {"schema_version": "mysql-full-schema-census.v1", "Definer": args.census_definer or "",
              "DefinitionSHA256": args.census_definition_sha256 or "", "PartialRevokes": args.census_partial_revokes}
    if args.census_definer or args.census_definition_sha256:
        require(re.fullmatch(r"[A-Za-z0-9_]+@[A-Za-z0-9_.:%-]+", args.census_definer or "")
                and (not args.census_definition_sha256 or re.fullmatch(r"[a-f0-9]{64}", args.census_definition_sha256)),
                "original_census_pin_required")
    owner = inventory["owner"]
    require(text(owner["subject"]) and re.fullmatch(r"[a-f0-9]{64}", owner["groups_sha256"]), "original_owner_required")
    host = service[0].get("cluster_ip")
    if host and host != "None":
        address_ip = ipaddress.ip_address(host)
        require(not address_ip.is_loopback and not address_ip.is_unspecified and not address_ip.is_multicast,
                "actual_original_service_address_required")
        address = ("[" + host + "]" if address_ip.version == 6 else host) + ":" + str(args.mysql_port)
    else:
        address = service[0]["name"] + "." + NAMESPACE + ".svc:" + str(args.mysql_port)
    plan = {"Version": "original-production-source-sql-plan.v1", "Purpose": "functional_test",
            "InventorySHA256": args.inventory_sha256, "Namespace": NAMESPACE, "NamespaceUID": NAMESPACE_UID,
            "OwnerSubject": owner["subject"], "OwnerUID": owner["uid"], "OwnerGroupsSHA256": owner["groups_sha256"],
            "Service": service[0]["name"], "ServiceUID": service[0]["uid"], "Port": args.mysql_port,
            "Address": address,
            "Database": args.mysql_database, "ServerUUID": args.mysql_server_uuid, "Account": args.mysql_account,
            "TLSServerName": args.mysql_tls_server_name or service[0]["name"] + "." + NAMESPACE + ".svc",
            "CASHA256": args.mysql_ca_sha256, "Census": census}
    receipt = write_public(args.output_directory, "source-sql-plan.candidate.json", plan)
    print(json.dumps({"status": "PUBLIC_SQL_PLAN_CANDIDATE_REVIEW_REQUIRED", **receipt,
                      "mysql_address": address,
                      "private_credentials_read": False, "sql_called": False, "acceptance_ready": False}))
    return 0


def quoted(expression):
    # Only selected public fields reach kubectl stdout; env values, commands,
    # args, annotations, Secret data and ConfigMap data are never selected.
    parts = expression.lstrip(".").split(".")
    template = '{{printf "%q" (or .' + parts[-1] + ' "")}}'
    for parent in reversed(parts[:-1]):
        template = "{{with ." + parent + "}}" + template + '{{else}}""{{end}}'
    return template


def boolean(expression):
    parts = expression.lstrip(".").split(".")
    template = "{{if ." + parts[-1] + "}}true{{else}}false{{end}}"
    for parent in reversed(parts[:-1]):
        template = "{{with ." + parent + "}}" + template + "{{else}}false{{end}}"
    return template


def number(expression):
    parts = expression.lstrip(".").split(".")
    template = "{{or ." + parts[-1] + " 0}}"
    for parent in reversed(parts[:-1]):
        template = "{{with ." + parent + "}}" + template + "{{else}}0{{end}}"
    return template


def object_template(fields):
    return "{" + ",".join(json.dumps(k) + ":" + v for k, v in fields.items()) + "}"


def array_template(expression, item):
    global _serial
    _serial += 1
    first = "$first" + str(_serial)
    parts = expression.lstrip(".").split(".")
    template = ("[{{" + first + " := true}}{{range ." + parts[-1] + "}}{{if not " + first
                + "}},{{end}}{{" + first + " = false}}" + item + "{{end}}]")
    for parent in reversed(parts[:-1]):
        template = "{{with ." + parent + "}}" + template + "{{else}}[]{{end}}"
    return template


def identity_fields():
    return {"name": quoted(".metadata.name"), "namespace": quoted(".metadata.namespace"),
            "uid": quoted(".metadata.uid"), "resource_version": quoted(".metadata.resourceVersion"),
            "generation": number(".metadata.generation"), "deleting": boolean(".metadata.deletionTimestamp")}


def spec_fields(prefix):
    env = object_template({"name": quoted(".name"),
                           "secret_name": quoted(".valueFrom.secretKeyRef.name"),
                           "secret_key": quoted(".valueFrom.secretKeyRef.key"),
                           "configmap_name": quoted(".valueFrom.configMapKeyRef.name"),
                           "configmap_key": quoted(".valueFrom.configMapKeyRef.key")})
    mount = object_template({"volume": quoted(".name"), "path": quoted(".mountPath"),
                             "sub_path": quoted(".subPath"), "read_only": boolean(".readOnly"),
                             "sub_path_expression_present": boolean(".subPathExpr")})
    env_from = object_template({"secret_name": quoted(".secretRef.name"), "configmap_name": quoted(".configMapRef.name")})
    port = object_template({"name": quoted(".name"), "port": number(".containerPort"), "protocol": quoted(".protocol")})
    container = object_template({"name": quoted(".name"), "image": quoted(".image"),
                                 "environment_references": array_template(".env", env),
                                 "environment_from_references": array_template(".envFrom", env_from),
                                 "ports": array_template(".ports", port),
                                 "mounts": array_template(".volumeMounts", mount)})
    key_path = object_template({"key": quoted(".key"), "path": quoted(".path")})
    projection = object_template({"secret_name": quoted(".secret.name"),
                                  "configmap_name": quoted(".configMap.name"),
                                  "service_account_token_path": quoted(".serviceAccountToken.path"),
                                  "service_account_token_audience": quoted(".serviceAccountToken.audience"),
                                  "secret_items": array_template(".secret.items", key_path),
                                  "configmap_items": array_template(".configMap.items", key_path)})
    volume = object_template({"name": quoted(".name"), "claim": quoted(".persistentVolumeClaim.claimName"),
                              "secret_name": quoted(".secret.secretName"), "configmap_name": quoted(".configMap.name"),
                              "secret_items": array_template(".secret.items", key_path),
                              "configmap_items": array_template(".configMap.items", key_path),
                              "nfs_server": quoted(".nfs.server"), "nfs_path": quoted(".nfs.path"),
                              "host_path": quoted(".hostPath.path"),
                              "projected_references": array_template(".projected.sources", projection)})
    return {"service_account": quoted(prefix + ".serviceAccountName"), "node": quoted(prefix + ".nodeName"),
            "containers": array_template(prefix + ".containers", container),
            "init_containers": array_template(prefix + ".initContainers", container),
            "volumes": array_template(prefix + ".volumes", volume)}


def projection(resource):
    fields = identity_fields()
    owner = object_template({"kind": quoted(".kind"), "name": quoted(".name"),
                             "uid": quoted(".uid"), "controller": boolean(".controller")})
    fields["owners"] = array_template(".metadata.ownerReferences", owner)
    if resource in WORKLOADS:
        fields["desired_replicas"] = number(".spec.replicas")
        fields["replicas_field_present"] = "{{if ne .spec.replicas nil}}true{{else}}false{{end}}"
        if resource == "pods":
            fields.update(spec_fields(".spec"))
            fields["phase"] = quoted(".status.phase")
            fields["container_statuses"] = array_template(".status.containerStatuses", object_template({
                "name": quoted(".name"), "image_id": quoted(".imageID"),
                "container_id": quoted(".containerID"), "restart_count": number(".restartCount"),
                "ready": boolean(".ready"), "running": boolean(".state.running")}))
        elif resource == "cronjobs":
            fields.update(spec_fields(".spec.jobTemplate.spec.template.spec"))
            fields["suspended"] = boolean(".spec.suspend")
        elif resource == "horizontalpodautoscalers":
            fields["scale_target"] = object_template({"kind": quoted(".spec.scaleTargetRef.kind"),
                                                       "name": quoted(".spec.scaleTargetRef.name")})
        else:
            fields.update(spec_fields(".spec.template.spec"))
    elif resource == "persistentvolumeclaims":
        fields["volume_name"] = quoted(".spec.volumeName")
        fields["phase"] = quoted(".status.phase")
    elif resource == "services":
        fields["cluster_ip"] = quoted(".spec.clusterIP")
        fields["external_name"] = quoted(".spec.externalName")
        fields["selector"] = ('{ {{$first := true}}{{range $key, $value := .spec.selector}}'
                              '{{if not $first}},{{end}}{{$first = false}}'
                              '{{printf "%q:%q" $key $value}}{{end}} }')
        fields["ports"] = array_template(".spec.ports", object_template({"name": quoted(".name"),
                                                                          "port": number(".port")}))
    return object_template(fields)


def listing_template(resource):
    require(resource in RESOURCES)
    return ('{"list_resource_version":' + quoted(".metadata.resourceVersion") + ',"items":'
            + array_template(".items", projection(resource)) + "}")


class Inventory:
    def __init__(self, args):
        require(args.namespace == NAMESPACE and args.namespace_uid == NAMESPACE_UID, "original_namespace_pin_required")
        require(re.fullmatch(r"[A-Za-z0-9_.@:-]{1,253}", args.context), "context_rejected")
        require(text(args.owner_subject) and isinstance(args.owner_uid, str), "original_owner_pin_required")
        self.args, self.until = args, time.monotonic() + 300

    def command(self, args):
        remaining = self.until - time.monotonic()
        require(remaining > 0, "inventory_deadline")
        try:
            result = subprocess.run(["kubectl", "--context=" + self.args.context, "--request-timeout=15s", *args],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=min(20, remaining), check=False)
        except (OSError, subprocess.SubprocessError):
            raise Refused("bounded_kubernetes_read_unavailable") from None
        require(result.returncode == 0 and len(result.stdout) <= 8 << 20, "bounded_kubernetes_read_failed")
        return result.stdout

    def namespace(self):
        template = object_template(identity_fields())
        item = json.loads(self.command(["get", "namespace", self.args.namespace, "-o=go-template=" + template]))
        require(item["name"] == NAMESPACE and item["uid"] == NAMESPACE_UID and not item["deleting"],
                "namespace_identity_changed")
        return item

    def owner(self):
        document = json.loads(self.command(["auth", "whoami", "-o=json"]))
        require(document.get("kind") == "SelfSubjectReview" and document.get("apiVersion") == "authentication.k8s.io/v1",
                "self_subject_review_shape_rejected")
        info = document.get("status", {}).get("userInfo", {})
        groups = info.get("groups", [])
        require(info.get("username") == self.args.owner_subject and info.get("uid", "") == self.args.owner_uid,
                "original_owner_changed")
        require(isinstance(groups, list) and 1 <= len(groups) <= 64 and all(text(g) for g in groups)
                and len(set(groups)) == len(groups) and "system:authenticated" in groups
                and "system:unauthenticated" not in groups, "owner_groups_rejected")
        groups = sorted(groups)
        digest = sha(json.dumps(groups, separators=(",", ":"), ensure_ascii=False).encode())
        if self.args.mode == "inventory":
            require(digest == self.args.owner_groups_sha256, "original_owner_groups_changed")
        return {"subject": info["username"], "uid": info.get("uid", ""), "groups": groups,
                "groups_sha256": digest, "authentication_source": "actual_kubernetes_self_subject_review"}

    def listing(self, resource):
        require(resource in RESOURCES)
        template = listing_template(resource)
        result = json.loads(self.command(["-n", NAMESPACE, "get", resource, "--chunk-size=100",
                                          "-o=go-template=" + template]))
        items = result.get("items")
        require(isinstance(items, list) and len(items) <= 2000, "public_resource_limit")
        seen = set()
        for item in items:
            require(item["namespace"] == NAMESPACE and text(item["name"]) and text(item["uid"])
                    and item["uid"] not in seen, "resource_identity_rejected")
            seen.add(item["uid"])
        result["items"] = sorted(items, key=lambda x: x["name"])
        return result

    def bound_volume(self, claim):
        name = claim["volume_name"]
        require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", name), "bound_volume_name_rejected")
        fields = identity_fields()
        fields.update({"claim_namespace": quoted(".spec.claimRef.namespace"),
                       "claim_name": quoted(".spec.claimRef.name"), "claim_uid": quoted(".spec.claimRef.uid"),
                       "csi_driver": quoted(".spec.csi.driver"), "csi_volume_handle": quoted(".spec.csi.volumeHandle"),
                       "nfs_server": quoted(".spec.nfs.server"), "nfs_path": quoted(".spec.nfs.path"),
                       "host_path": quoted(".spec.hostPath.path")})
        # Never list cluster-wide PVs: follow only this namespace's exact
        # bound PVC, and require all three actual claimRef coordinates.
        item = json.loads(self.command(["get", "persistentvolume", name,
                                        "-o=go-template=" + object_template(fields)]))
        require(item["name"] == name and item["claim_namespace"] == NAMESPACE
                and item["claim_name"] == claim["name"] and item["claim_uid"] == claim["uid"],
                "bound_volume_claim_identity_changed")
        return item

    def collect(self):
        namespace, owner = self.namespace(), self.owner()
        first, missing = {}, []
        for resource in RESOURCES:
            try:
                first[resource] = self.listing(resource)
            except Refused:
                missing.append("public_list_unavailable:" + resource)
        # Stable projected facts are useful assembly inputs, never a claim of
        # atomic source census or physical writer completeness.
        for resource, original in first.items():
            try:
                if self.listing(resource) != original:
                    missing.append("public_projection_changed:" + resource)
            except Refused:
                missing.append("public_recheck_unavailable:" + resource)
        volumes = []
        for claim in first.get("persistentvolumeclaims", {}).get("items", []):
            if claim["volume_name"]:
                try:
                    volume = self.bound_volume(claim)
                    require(self.bound_volume(claim) == volume, "bound_volume_changed")
                    volumes.append(volume)
                except Refused:
                    missing.append("bound_volume_unavailable_or_changed:" + claim["name"])
        require(self.namespace() == namespace and self.owner() == owner, "namespace_or_owner_changed")
        accounts = {x["name"]: x["uid"] for x in first.get("serviceaccounts", {}).get("items", [])}
        candidates, refs, graph = [], [], []
        for resource in WORKLOADS:
            for item in first.get(resource, {}).get("items", []):
                graph.append({"kind": KINDS[resource], "name": item["name"], "uid": item["uid"],
                              "generation": item["generation"], "owners": item["owners"],
                              "deleting": item["deleting"], "desired_replicas": item["desired_replicas"],
                              "replicas_field_present": item["replicas_field_present"]})
                if resource == "deployments":
                    candidates.append({"deployment": item["name"], "deployment_uid": item["uid"],
                                       "service_account": item["service_account"],
                                       "service_account_uid": accounts.get(item["service_account"]),
                                       "role_selected": False})
                for container in item.get("containers", []) + item.get("init_containers", []):
                    for ref in container["environment_references"]:
                        if ref["secret_name"] or ref["configmap_name"]:
                            refs.append({"workload_kind": KINDS[resource], "workload": item["name"],
                                         "workload_uid": item["uid"], "container": container["name"],
                                         "environment_reference": ref})
                    for ref in container["environment_from_references"]:
                        refs.append({"workload_kind": KINDS[resource], "workload": item["name"],
                                     "workload_uid": item["uid"], "container": container["name"],
                                     "environment_from_reference": ref})
                for volume in item.get("volumes", []):
                    if volume["secret_name"] or volume["configmap_name"] or volume["projected_references"]:
                        refs.append({"workload_kind": KINDS[resource], "workload": item["name"],
                                     "workload_uid": item["uid"], "volume_reference": volume})
        known = {(x["kind"], x["name"], x["uid"]) for x in graph}
        topology = []
        for item in graph:
            for owner_ref in item["owners"]:
                if (owner_ref["kind"], owner_ref["name"], owner_ref["uid"]) not in known:
                    topology.append({"kind": item["kind"], "name": item["name"],
                                     "reason": "owner_reference_not_in_original_inventory", "owner": owner_ref})
            if item["replicas_field_present"] and item["desired_replicas"] == 0:
                topology.append({"kind": item["kind"], "name": item["name"],
                                 "reason": "zero_replicas_requires_owner_disposition_and_if_business_native_stopped_proof"})
            if item["kind"] in ("StatefulSet", "DaemonSet", "Job", "CronJob", "HorizontalPodAutoscaler", "ReplicationController"):
                topology.append({"kind": item["kind"], "name": item["name"],
                                 "reason": "explicit_business_or_control_owner_disposition_required_no_automatic_exclusion"})
        pending = [
            "production_mysql_public_CA_and_leaf_SAN_chain_from_DBA_then_actual_TLS13_handshake_and_original_server_UUID",
            "A_actual_installer_and_consumer_finite_SQL_accounts_current_grants_local_admin_and_head_grant_lifecycle",
            "D_source_readonly_business_table_account_and_controller_finite_runtime_control_account",
            "choose_actual_distinct_controller_worker_source_resources_secrets_publisher_verifier_SA_UIDs_or_review_create_manifests",
            "full_SQL_API_native_writer_closure_and_provider_control_resource_nonoverlap_ownership_mapping",
            "owner_selected_private_source_credential_files_CA_pins_and_service_account_projected_tokens_via_secure_delivery",
            "C_actual_MinIO_original_owner_permission_source_and_immutable_object_root_versioning",
            "D_real_Redis_TLS_ACL_identity_scope_and_Teams_Skills_workspace_ownership_inputs",
            "original_core_profile_capacity_staging_mounts_Forward_and_Recovery_grants_and_seven_operation_material_mounts",
            "bootstrap_27_missing_compiled_owner_slots_then_real_disabled_v1_admission",
            "complete_nonempty_six_domain_capture_source_recovery_independent_EOF_catalog_terminal_CAS",
        ]
        return {"schema_version": "zhanghui08-original-first-install-public-inputs.v1",
                "status": "PUBLIC_INPUTS_COLLECTED_REVIEW_REQUIRED" if not missing else "PARTIAL_PUBLIC_INPUTS",
                "namespace": NAMESPACE, "namespace_uid": NAMESPACE_UID, "owner": owner,
                "projection_sha256": sha(canonical({"public_objects": first, "bound_persistentvolumes": volumes})), "public_objects": first,
                "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "bound_persistentvolumes": volumes,
                "deployment_identity_candidates": candidates, "service_account_candidates": accounts,
                "credential_references_only": refs, "writer_graph_inventory_only": graph,
                "topology_review_items": topology,
                "public_input_blockers": missing, "pending_sources": pending,
                "private_secret_api_requested": False, "configmap_values_selected": False,
                "container_files_or_env_values_selected": False, "sql_or_runtime_or_provider_called": False,
                "cluster_mutated": False, "source_scope_complete": False, "acceptance_ready": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("owner", "inventory", "sql-plan", "templates"))
    parser.add_argument("--context", default="kubernetes-admin@kubernetes")
    parser.add_argument("--namespace", default=NAMESPACE)
    parser.add_argument("--namespace-uid", default=NAMESPACE_UID)
    parser.add_argument("--owner-subject")
    parser.add_argument("--owner-uid", default="")
    parser.add_argument("--owner-groups-sha256")
    parser.add_argument("--output-directory")
    parser.add_argument("--inventory-file")
    parser.add_argument("--inventory-sha256")
    parser.add_argument("--mysql-service")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-database")
    parser.add_argument("--mysql-server-uuid")
    parser.add_argument("--mysql-account")
    parser.add_argument("--mysql-tls-server-name")
    parser.add_argument("--mysql-ca-sha256")
    parser.add_argument("--census-definer")
    parser.add_argument("--census-definition-sha256")
    parser.add_argument("--census-partial-revokes", action="store_true")
    args = parser.parse_args(argv)
    if args.mode == "templates":
        print(json.dumps({resource: listing_template(resource) for resource in RESOURCES}))
        return 0
    if args.mode == "sql-plan":
        return prepare_sql_plan(args)
    observer = Inventory(args)
    if args.mode == "owner":
        observer.namespace()
        print(json.dumps({"schema_version": "original-owner-public-comparison.v1", "owner": observer.owner(),
                          "namespace": NAMESPACE, "namespace_uid": NAMESPACE_UID,
                          "status": "REVIEW_THIS_PRINCIPAL_AGAINST_ORIGINAL_OWNER_NOT_AN_ENROLLMENT"}))
        return 0
    require(re.fullmatch(r"[a-f0-9]{64}", args.owner_groups_sha256 or ""), "selected_owner_groups_pin_required")
    result = observer.collect()
    # A failed write remains visible for explicit review; never overwrite or
    # delete a pre-existing file, and never serialize partial private inputs.
    receipt = write_public(args.output_directory, "first-install-public-inputs.json", result)
    print(json.dumps({"status": result["status"], **receipt,
                      "public_input_blockers": result["public_input_blockers"], "acceptance_ready": False}))
    return 0 if not result["public_input_blockers"] else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Refused, KeyError, TypeError, ValueError, OSError, UnicodeError):
        print(json.dumps({"status": "BLOCKED", "reason": "original_public_input_preparation_rejected",
                          "cluster_mutated": False, "acceptance_ready": False}))
        sys.exit(2)
