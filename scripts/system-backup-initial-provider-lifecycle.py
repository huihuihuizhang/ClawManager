"""Original TLS lifecycle and deployment-owned functional profile DATA.

Called by the original operator, never executed on import. No synthetic native
receipts, authorization, restore target UID, signed registry or Passed fields.
"""
from pathlib import Path
import json
import re
import sys


def tool(m, stages, name):
    relative = "scripts/" + name
    expected = stages.op.pins["files"].get(relative)
    m.need(expected is not None, "sealed_original_provider_tool_required")
    path = stages.root / relative
    m.read(path, expected, private=False)
    return path


class OriginalTLSLifecycle:
    """Each send uses the existing durable call intent; queries never apply.

    Separate method names are deliberate: prepare does not install, and an
    unknown apply is reconciled by query instead of replaying its send.
    """
    def __init__(self, m, stages):
        self.m, self.s = m, stages
        common, enrolled, _, _ = stages.common()
        self.common = common
        self.plan = enrolled["Plan"]
        self.first = tool(m, stages, "system-backup-minio-first-hop-tls.py")
        self.app = tool(m, stages, "system-backup-minio-app-tls-cutover.py")
        tool(m, stages, "system-backup-first-page-tls-only.py")
        self.first_directory = stages.directory / "original-minio-first-hop-tls"
        self.app_directory = stages.directory / "original-minio-business-tls"
        # Existing owner tools create these directories with 0700. Do not
        # precreate them or manufacture/reuse a different operation plan.
        self.connection = ["--kubeconfig-file", stages.op.kube,
            "--kubeconfig-sha256", m.digest(m.read(stages.op.kube)),
            "--installation-plan-file", self.plan["File"],
            "--installation-plan-sha256", self.plan["SHA256"], "--service", "minio"]

    def first_call(self, action, plan_sha=None, suffix=""):
        flags = [*self.connection, "--state-directory", self.first_directory]
        if plan_sha is not None:
            flags += ["--plan-sha256", plan_sha]
        return self.s.call("initial-minio-tls-" + action + suffix,
            [sys.executable, "-B", self.first, action, *flags])

    def app_call(self, action, first_sha, app_sha=None, suffix=""):
        # Password is an original private file locator, never argv content.
        index = self.common.index("--local-admin-password-file")
        flags = [*self.connection, "--first-hop-helper", self.first,
            "--state-directory", self.app_directory,
            "--minio-state-directory", self.first_directory,
            "--minio-plan-sha256", first_sha,
            "--local-admin-password-file", self.common[index + 1],
            "--app-deployment", "clawmanager-app"]
        if app_sha is not None:
            flags += ["--plan-sha256", app_sha]
        return self.s.call("initial-business-minio-tls-" + action + suffix,
            [sys.executable, "-B", self.app, action, *flags])

    def prepare(self):
        first, first_receipt = self.first_call("prepare")
        self.m.need(first.get("state") == "prepared_local_only", "actual_minio_tls_prepare_required")
        first_sha = first["plan_sha256"]
        app, app_receipt = self.app_call("prepare", first_sha)
        self.m.need(app.get("state") == "business_cutover_prepared_only", "actual_business_tls_prepare_required")
        return self.s.retain("initial-provider-tls.plans.json", {
            "FirstPlanSHA256": first_sha, "AppPlanSHA256": app["plan_sha256"],
            "FirstPrepareReceipt": first_receipt, "AppPrepareReceipt": app_receipt})

    def apply(self, plans_pin):
        plans = self.m.decode(self.m.pinned(plans_pin))
        first, _ = self.first_call("apply", plans["FirstPlanSHA256"])
        self.m.need(first.get("state") == "actual_tls_verified", "actual_minio_tls_apply_required")
        app, _ = self.app_call("apply", plans["FirstPlanSHA256"], plans["AppPlanSHA256"])
        self.m.need(app.get("state") == "actual_business_app_object_reads_verified", "actual_business_tls_apply_required")
        return self.query(plans_pin)

    def query(self, plans_pin, suffix=""):
        plans = self.m.decode(self.m.pinned(plans_pin))
        first, first_receipt = self.first_call("query", plans["FirstPlanSHA256"], suffix)
        app, app_receipt = self.app_call("query", plans["FirstPlanSHA256"], plans["AppPlanSHA256"], suffix)
        self.m.need(first.get("state") == "actual_tls_verified" and
                    app.get("state") == "actual_business_app_object_reads_verified",
                    "actual_original_provider_and_business_reads_required")
        return {"TLS": first_receipt, "Business": app_receipt, "Plans": plans_pin}

    def finalize(self, plans_pin, providers, environment):
        # Dedicated query stages ensure this does not return the apply-stage
        # receipt as if it were a fresh post-rollout observation.
        result = self.query(plans_pin, "-finalize")
        fragment = providers.minio_fragment(self.m, self.s, result["TLS"], environment)
        before = current_app_roster(self.m, self.s)
        after = current_app_roster(self.m, self.s)
        self.m.need(before == after, "post_tls_app_roster_changed")
        result["MinIOFragment"] = fragment
        result["CurrentAppRoster"] = before
        # This is an explicit new selector snapshot. The old writer/source
        # selection is never edited to retain stale pre-rollout Pod/CRI IDs.
        return self.s.retain("initial-provider-tls.finalized.json", result)


def current_app_roster(m, stages):
    dep = stages.get("deployment", "clawmanager-app")
    m.need(dep["metadata"]["uid"] == stages.scope["app_deployment_uid"] and
           not dep["metadata"].get("deletionTimestamp"), "same_original_app_deployment_after_tls_required")
    replicas = dep["spec"].get("replicas", 1)
    selector = dep["spec"]["selector"]
    m.need(replicas > 0 and selector.get("matchLabels") and not selector.get("matchExpressions") and
           dep.get("status", {}).get("observedGeneration", 0) >= dep["metadata"].get("generation", 1) and
           dep["status"].get("updatedReplicas") == replicas and dep["status"].get("availableReplicas") == replicas,
           "stable_actual_app_rollout_required")
    label = ",".join(k + "=" + v for k, v in sorted(selector["matchLabels"].items()))
    ns = dep["metadata"]["namespace"]
    pods = m.decode(stages.op.k("-n", ns, "get", "pods", "-l", label, "-o", "json"))["items"]
    actors = []
    def controller(obj, kind):
        refs = [r for r in obj["metadata"].get("ownerReferences", []) if r.get("controller")]
        m.need(len(refs) == 1 and refs[0]["kind"] == kind, "actual_post_tls_controller_required")
        return refs[0]
    for pod in pods:
        if pod["metadata"].get("deletionTimestamp"):
            continue
        owner = controller(pod, "ReplicaSet")
        rs = stages.get("replicaset", owner["name"])
        parent = controller(rs, "Deployment")
        m.need(rs["metadata"]["uid"] == owner["uid"] and parent["uid"] == dep["metadata"]["uid"] and
               len(pod["spec"]["containers"]) == 1, "same_post_tls_app_owner_required")
        container = pod["spec"]["containers"][0]
        states = [s for s in pod["status"].get("containerStatuses", []) if s["name"] == container["name"]]
        m.need(len(states) == 1 and states[0].get("ready") and states[0].get("containerID") and
               states[0].get("imageID") and "running" in states[0].get("state", {}), "actual_post_tls_app_cri_required")
        actors.append({"Pod": pod["metadata"]["name"], "PodUID": pod["metadata"]["uid"],
            "ReplicaSet": rs["metadata"]["name"], "ReplicaSetUID": rs["metadata"]["uid"],
            "Container": container["name"], "ContainerID": states[0]["containerID"], "ImageID": states[0]["imageID"]})
    m.need(len(actors) == replicas, "complete_post_tls_app_roster_required")
    return {"Deployment": dep["metadata"]["name"], "DeploymentUID": dep["metadata"]["uid"],
        "SpecSHA256": m.digest(m.encoded(dep["spec"])), "Actors": sorted(actors, key=lambda x: x["PodUID"])}


def author_functional_profile(m, stages, permission_definition_pin, finalized_tls_pin):
    """Write actual deployment config DATA, not a provisioned RestoreTarget.

    The restore config is an immutable finite isolation policy. Its hash covers
    its actual complete bytes, never an empty object/string or a made-up proof.
    The existing B RestoreTarget check is still required before restore IO.
    """
    _, _, plan, _ = stages.common()
    target = plan["Target"]
    definition = m.decode(m.pinned(permission_definition_pin))
    grant = definition["Grant"]
    provider = grant["Provider"]
    tls = m.decode(m.pinned(finalized_tls_pin))
    actual = m.decode(m.pinned(tls["TLS"]))
    m.need(grant["Installation"] == target["InstallationID"] and grant["NamespaceUID"] == target["NamespaceUID"] and
           provider["Endpoint"] == actual["endpoint"] and provider["CASHA256"] == actual["ca_sha256"] and
           provider["SPKISHA256"] == actual["spki_sha256"], "post_tls_original_permission_definition_required")
    # Never patch the original owner's signed provider selector after rollout.
    for key, obj in (("Deployment", "deployment"), ("ReplicaSet", "replicaset"), ("Pod", "pod"),
                     ("Service", "service"), ("ServiceAccount", "service_account")):
        m.need(provider[key] == {"Name": actual["objects"][obj]["name"], "UID": actual["objects"][obj]["uid"]},
               "original_owner_must_reproduce_stale_post_tls_selector")
        resource = "serviceaccount" if obj == "service_account" else obj
        live = stages.get(resource, provider[key]["Name"])
        m.need(live["metadata"]["uid"] == provider[key]["UID"] and not live["metadata"].get("deletionTimestamp"),
               "same_live_post_tls_native_provider_required")
        if obj == "pod":
            status = [s for s in live["status"].get("containerStatuses", []) if s["name"] == actual["container"]]
            m.need(len(status) == 1 and status[0].get("ready") and "running" in status[0].get("state", {}) and
                   status[0]["containerID"] == actual["container_id"] and status[0]["imageID"] == actual["image_id"],
                   "same_live_post_tls_native_cri_required")
    m.need(provider["Container"] == actual["container"] and provider["ImageID"] == actual["image_id"],
           "original_owner_actual_post_tls_container_required")
    publication_pin = {"File": definition["TargetFile"], "SHA256": definition["TargetSHA256"]}
    publication = m.decode(m.pinned(publication_pin))
    m.need(publication["schema_version"] == "system-backup-native-publication-s3.v1" and
           publication["installation_id"] == target["InstallationID"] and publication["endpoint"] == provider["Endpoint"] and
           publication["ca_sha256"] == provider["CASHA256"] and publication["root"] == target["InstallationID"] + "/",
           "actual_original_native_publication_target_required")
    for name in ("read", "write"):
        m.pinned({"File": publication[name + "_credential_file"], "SHA256": publication[name + "_credential_sha256"]})
    current = current_app_roster(m, stages)
    m.need(current == tls["CurrentAppRoster"], "initial_writer_author_must_use_current_post_tls_roster")
    cluster = m.decode(stages.op.k("get", "namespace", "kube-system", "-o", "json"))
    nodes = m.decode(stages.op.k("get", "nodes", "-o", "json"))["items"]
    m.need(cluster["metadata"]["uid"] and nodes and all(n["metadata"].get("uid") for n in nodes),
           "actual_cluster_identity_and_nodes_required")
    kinds = {"k3s" if "k3s" in n["status"]["nodeInfo"]["kubeletVersion"] else "kubernetes" for n in nodes}
    m.need(len(kinds) == 1, "one_actual_source_orchestrator_required")
    domain = "cluster:" + cluster["metadata"]["uid"]
    m.need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", domain), "actual_cluster_domain_token_required")
    identity = {"KubernetesAPI": plan["KubernetesAPI"], "KubernetesCASHA256": plan["KubernetesCASHA256"],
                "KubeSystemUID": cluster["metadata"]["uid"]}
    identity_pin = stages.retain("initial-functional-domain-identity.json", identity)
    failure = stages.retain("initial-functional-failure-domains.json", {
        "schema_version": "system-backup-original-failure-domains.v1", "origin_installation_id": target["InstallationID"],
        "registry_version": "initial-functional-domains-v1", "history": [{"sequence": 1, "domain_id": domain,
        "identity_sha256": identity_pin["SHA256"], "state": "active", "previous_sha256": ""}]})
    # All providers belong to the original namespace; classify conservatively.
    # These strings do not waive transport, native permissions or restore proof.
    risks = sorted(["attestation_missing", "same_failure_domain", "source_overlap",
        "artifact_credential_source_dependent", "kek_source_dependent", "signing_key_source_dependent", "catalog_source_dependent"])
    ref = "isolated-policy-" + m.digest(target["InstallationID"].encode())[:24]
    policy = stages.retain("initial-functional-restore-target-policy.json", {
        "schema_version": "original-functional-restore-target-policy.v1", "installation_id": target["InstallationID"],
        "reference": ref, "source_namespace": target["Namespace"], "source_namespace_uid": target["NamespaceUID"],
        "source_database": target["Database"], "source_database_server_uuid": target["ServerUUID"],
        "target_namespace_prefix": "cm-drill-", "target_database_prefix": "cm_drill_",
        "target_kind": "isolated_drill", "admin_policy": "replace_bootstrap_with_source_admin",
        "start_policy": "stopped_tasks_disabled", "source_namespace_reuse": "forbidden",
        "source_database_reuse": "forbidden", "source_volume_reuse": "forbidden",
        "required_observation_schema": "system-backup-b-restore-target.v1",
        "publication_target": publication_pin, "failure_domain_identity": identity_pin})
    profile_data = {"installation_id": target["InstallationID"],
        "revision": "initial-functional-v1", "source_orchestrator": next(iter(kinds)), "source_profile": "cluster",
        "target_class": "same-cluster-copy", "target_risks": risks, "target_failure_domain_id": domain,
        "restore_target_ref": ref, "restore_target_sha256": policy["SHA256"]}
    # The profile pin is compared to Go CanonicalIdentity, which marshals this
    # exact struct field order (not RFC8785 sorted object keys). Values here
    # are ASCII tokens/identifiers, so no Go HTML/string-escape ambiguity.
    profile_raw = json.dumps(profile_data, ensure_ascii=False, separators=(",", ":")).encode()
    profile_path = stages.directory / "initial-execution-profile.json"
    if profile_path.exists():
        m.need(m.read(profile_path) == profile_raw, "initial_profile_changed_no_replacement")
        profile = m.pin(profile_path)
    else:
        profile = m.write(profile_path, profile_raw)
    return stages.retain("initial-functional-profile-data.result.json", {"ExecutionProfile": profile,
        "RestoreTargetPolicy": policy, "FailureDomains": failure, "DomainIdentity": identity_pin,
        "ClassificationData": {"SchemaVersion": "system-backup-original-functional-classification.v1",
        "Profile": "functional-backup.non-dr.v1", "TaskPurpose": "functional_test", "TargetClass": "same-cluster-copy",
        "TargetFailureDomain": domain, "RecoveryEvidenceStatus": "not_provided", "SourceDomains": [domain],
        "TargetRisks": risks, "FailureRegistryFile": failure["File"], "FailureRegistrySHA256": failure["SHA256"]},
        "OriginalPermissionDefinition": permission_definition_pin, "ActualTLSFinalization": finalized_tls_pin})


def vault_prepare(m, stages, providers, state_pin, report_pin, ca_pin, init_pin):
    options = providers.vault_options_fragment(m, stages, state_pin, report_pin, ca_pin, init_pin)
    return stages.retain("initial-vault-provider-options.private.json", options)


def vault_observe(m, stages, options_pin, original_writer_pin, phase):
    """Real existing Go owner observation; apply/query/finalize each its own IO.

    provider-materials performs authenticated live reads and create-only local
    output. It neither changes Vault IAM nor acquires a writer hold. It can
    therefore be repeated into a NEW private directory to query fresh state.
    """
    m.need(phase in ("apply", "query", "finalize"), "finite_vault_provider_phase_required")
    options = m.decode(m.pinned(options_pin))
    original = m.decode(m.pinned(original_writer_pin))
    m.need(not original.get("PreAdoptionVaultDependencies") and not original.get("VaultProviderDependencies"),
           "original_base_writer_selection_required_for_provider_observation")
    common, _, _, _ = stages.common()
    root = stages.runtime_mirror()
    directory = root / ("initial-vault-provider-" + phase)
    if not directory.exists():
        directory.mkdir(mode=0o700)
    m.need(directory.resolve(strict=True) == directory and not directory.is_symlink(), "private_vault_output_directory_required")
    flags = ["--mode", "provider-materials", "--selection-file", original_writer_pin["File"],
             "--selection-sha256", original_writer_pin["SHA256"], "--output-directory", directory]
    keys = {"Deployment": "deployment", "Service": "service", "Claim": "claim", "DataMountPath": "data-mount",
        "Endpoint": "endpoint", "ClusterID": "cluster-id", "TransitMount": "transit-mount", "KeyName": "key-name",
        "KeyVersion": "key-version", "JWTMount": "jwt-mount"}
    for key, flag in keys.items():
        flags += ["--provider-" + flag, options[key]]
    for key, flag in (("CA", "ca"), ("OwnerToken", "owner-token")):
        m.pinned(options[key])
        flags += ["--provider-" + flag + "-file", options[key]["File"],
                  "--provider-" + flag + "-sha256", options[key]["SHA256"]]
    result, receipt = stages.call("initial-vault-provider-" + phase,
        [stages.binary("system-backup-original-maintenance"), *common, *flags])
    m.need(result.get("Version") == "pre-adoption-vault-materials.v1" and
           result.get("State") == "actual_installed_dependency_inputs_only_no_adoption_or_task_authority",
           "actual_original_vault_provider_observation_required")
    for key in ("InstalledObserver", "WriterSelection"):
        m.pinned(result[key])
    return stages.retain("initial-vault-provider-" + phase + ".result.json", {
        "Receipt": receipt, "InstalledObserver": result["InstalledObserver"], "WriterSelection": result["WriterSelection"],
        "OriginalWriterSelection": original_writer_pin, "Options": options_pin})
