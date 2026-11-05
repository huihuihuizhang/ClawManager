"""Use the original Redis native owner; never invent run IDs or TLS facts."""
import base64
from pathlib import Path
import time
from urllib.parse import urlsplit


def source_environment(m, stages, assembly, app):
    container = app["spec"]["template"]["spec"]["containers"][0]
    names = {item["name"] for item in container.get("env", [])}
    for ref in container.get("envFrom", []):
        key = "secretRef" if "secretRef" in ref else "configMapRef"
        m.need(key in ref and not ref[key].get("optional", False), "required_original_redis_environment_source")
        obj = stages.get("secret" if key == "secretRef" else "configmap", ref[key]["name"])
        names.update(ref.get("prefix", "") + name for name in obj.get("data", {}))
    selected = "PLATFORM_REDIS_URL" if "PLATFORM_REDIS_URL" in names else "TEAM_REDIS_URL"
    return assembly.original_app_environment(m, stages, app, selected)


def native_mode(m, stages, common, writer_pin, base, prepared, mode, stage):
    options = {**base, "Mode": mode, "Intent": prepared["Intent"] if prepared is not None else {"File": "", "SHA256": ""}}
    definition = stages.retain(stage + ".options.json", options)
    value, receipt = stages.call(stage, [stages.binary("system-backup-original-maintenance"), "--mode", "redis-materials", *common,
        "--selection-file", writer_pin["File"], "--selection-sha256", writer_pin["SHA256"],
        "--redis-materials-file", definition["File"], "--redis-materials-sha256", definition["SHA256"]])
    m.need(value["Version"] == "original-redis-native-materials.v1", "actual_original_redis_native_owner_required")
    return value, receipt


def finalize_once(m, stages, common, writer_pin, base, prepared):
    original = "initial-redis-finalize"
    intent_path = stages.directory / (original + ".send-unknown.json")
    completed = stages.directory / (original + ".readback.json")
    if intent_path.exists() and not completed.exists():
        # The native owner MUST find the original matching finalize.sent and
        # use verify-finished. Missing native send evidence is a refusal, never
        # permission to retry finish/apply. Local receipt materialization remains
        # create-only and follows genuine live TLS/account/native readback.
        prefix = "initial-redis-finalize-readback-"
        index = sum(1 for _ in stages.directory.glob(prefix + "*.send-unknown.json"))
        return native_mode(m, stages, common, writer_pin, base, prepared, "query-finalize", prefix + str(index))
    return native_mode(m, stages, common, writer_pin, base, prepared, "finalize", original)


def query_once(m, stages, common, writer_pin, base, prepared):
    # A rollout may make native query exit nonzero before its Pod becomes ready.
    # Each retry is a NEW read-only observation of the SAME original intent.
    # Its failed send record is retained; apply/finalize are never replayed.
    prefix = "initial-redis-query-fresh-"
    index = sum(1 for _ in stages.directory.glob(prefix + "*.send-unknown.json"))
    stage = prefix + str(index)
    try:
        value, _ = native_mode(m, stages, common, writer_pin, base, prepared, "query", stage)
        return value
    except Exception:
        m.need((stages.directory / (stage + ".send-unknown.json")).exists(), "original_redis_query_failed_before_original_intent")
        stages.retain(stage + ".unconfirmed.json", {"version": "operator-original-redis-query-unconfirmed.v1", "original_intent": prepared["Intent"],
            "state": "native_read_not_confirmed_requires_new_query", "apply_replayed": False, "backup_ready": False})
        return None


def resume(m, stages):
    result_path = stages.directory / "initial-redis-source-inputs.result.json"
    if result_path.exists():
        result = m.decode(m.read(result_path))
        m.pinned(result["native_receipt"]); m.pinned(result["writer_selection"])
        stages.a.deployment_writer_selection_file = Path(result["writer_selection"]["File"])
        stages.a.deployment_writer_selection_sha256 = result["writer_selection"]["SHA256"]
        return result
    lineage = m.decode(m.read(stages.directory / "initial-redis-prepare.result.json"))
    m.need(lineage["version"] == "operator-initial-redis-prepare.v1", "actual_original_redis_prepare_lineage_required")
    writer_pin = lineage["writer_selection"]; m.pinned(writer_pin)
    prepared = m.decode(m.pinned(lineage["native_receipt"])); m.pinned(prepared["Intent"])
    common, enrolled, _, _ = stages.common()
    observed = query_once(m, stages, common, writer_pin, lineage["base_options"], prepared)
    if observed is None or observed["State"] != "desired_specs_ready_requires_native_finalize":
        return {"version": "operator-initial-redis-query.v1", "state": "same_original_rollout_not_confirmed_query_again_or_recover", "original_intent": prepared["Intent"], "backup_ready": False}
    final, receipt = finalize_once(m, stages, common, writer_pin, lineage["base_options"], prepared)
    m.need(final["State"] == "native_tls_and_accounts_read_back_not_a_hold", "actual_original_redis_native_finalize_required")
    writer_pin = final["WriterSelection"]; writer = m.decode(m.pinned(writer_pin))
    keeper = m.decode(m.pinned(final["KeeperSelection"])); policy = m.decode(m.pinned(final["Policy"]))
    m.need(len(writer["RedisReadKeepers"]) == 1 and writer["RedisReadKeepers"][0] == keeper and keeper["Native"]["Policy"] == policy, "same_actual_original_redis_keeper_and_policy_required")
    return finish(m, stages, enrolled, writer_pin, keeper, policy, receipt)


def recover(m, stages, mode):
    lineage = m.decode(m.read(stages.directory / "initial-redis-prepare.result.json"))
    m.need(lineage["version"] == "operator-initial-redis-prepare.v1", "actual_original_redis_prepare_lineage_required")
    m.pinned(lineage["writer_selection"])
    prepared = m.decode(m.pinned(lineage["native_receipt"]))
    m.pinned(prepared["Intent"])
    common, _, _, _ = stages.common()
    stage = "initial-redis-" + mode
    if mode == "query":
        stage += "-fresh-" + str(sum(1 for _ in stages.directory.glob(stage + "-fresh-*.send-unknown.json")))
    value, receipt = native_mode(m, stages, common, lineage["writer_selection"], lineage["base_options"], prepared, mode, stage)
    result = {"version": "operator-initial-redis-recovery.v1", "mode": mode, "native_receipt": receipt, "actual_native_state": value["State"], "backup_ready": False}
    stages.retain(stage + ".result.json", result)
    return result


def prepare(m, stages, assembly):
    result_path = stages.directory / "initial-redis-source-inputs.result.json"
    if result_path.exists():
        result = m.decode(m.read(result_path))
        m.need(result["version"] == "operator-initial-redis-source-inputs.v1", "original_redis_source_result_required")
        m.pinned(result["native_receipt"])
        m.pinned(result["writer_selection"])
        assembly.bind(m, stages.a, "deployment_writer_selection", result["writer_selection"])
        return result
    common, enrolled, plan, _ = stages.common()
    writer_pin = assembly.optional_pin(m, stages.a, "deployment_writer_selection")
    m.need(writer_pin is not None, "actual_original_complete_writer_selection_required_before_redis_materials")
    writer = m.decode(m.pinned(writer_pin))
    existing = writer.get("RedisReadKeepers", [])
    m.need(len(existing) <= 1, "one_original_redis_source_supported")
    native_receipt = None
    if existing:
        keeper = existing[0]
        policy = keeper["Native"]["Policy"]
    else:
        app = stages.get("deployment", "clawmanager-app")
        m.need(app["metadata"]["uid"] == stages.scope["app_deployment_uid"], "same_original_app_required_for_redis_source")
        raw = source_environment(m, stages, assembly, app)
        endpoint = urlsplit(raw.decode("utf-8"))
        m.need(endpoint.scheme == "redis" and endpoint.hostname and not endpoint.query and not endpoint.fragment,
               "original_plain_redis_requires_native_TLS_producer_or_actual_existing_keeper")
        database_text = endpoint.path.strip("/") or "0"
        m.need(database_text.isdigit() and 0 <= int(database_text) <= 65535, "actual_original_redis_database_required")
        database = int(database_text)
        services = m.decode(stages.op.k("-n", plan["Target"]["Namespace"], "get", "services", "-o", "json"))["items"]
        matches = []
        for service in services:
            name, namespace = service["metadata"]["name"], service["metadata"]["namespace"]
            names = {name, name + "." + namespace, name + "." + namespace + ".svc", name + "." + namespace + ".svc.cluster.local", service["spec"].get("clusterIP")}
            if endpoint.hostname in names and any(p["port"] == (endpoint.port or 6379) for p in service["spec"]["ports"]):
                matches.append(service)
        m.need(len(matches) == 1 and matches[0]["spec"].get("selector"), "one_actual_original_redis_service_required")
        service = matches[0]
        labels = service["spec"]["selector"]
        pods = m.decode(stages.op.k("-n", plan["Target"]["Namespace"], "get", "pods", "-l", ",".join(k+"="+v for k,v in sorted(labels.items())), "-o", "json"))["items"]
        m.need(len(pods) == 1 and not pods[0]["metadata"].get("deletionTimestamp"), "one_actual_original_redis_pod_required")
        owner = [x for x in pods[0]["metadata"].get("ownerReferences", []) if x.get("controller") and x["kind"] == "ReplicaSet"]
        m.need(len(owner) == 1, "actual_original_redis_replica_owner_required")
        replica = stages.get("replicaset", owner[0]["name"])
        dep_refs = [x for x in replica["metadata"].get("ownerReferences", []) if x.get("controller") and x["kind"] == "Deployment"]
        m.need(replica["metadata"]["uid"] == owner[0]["uid"] and len(dep_refs) == 1, "actual_original_redis_deployment_graph_required")
        deployment = stages.get("deployment", dep_refs[0]["name"])
        m.need(deployment["metadata"]["uid"] == dep_refs[0]["uid"] and any(d["Name"] == dep_refs[0]["name"] and d["UID"] == dep_refs[0]["uid"] and d["Role"] == "writer" for d in writer["Deployments"]), "same_original_redis_writer_required")
        descriptor = stages.retain("initial-redis-source.description.json", {"Version": "original-redis-source-coordinate.v1", "NamespaceUID": plan["Target"]["NamespaceUID"],
            "Service": service["metadata"]["name"], "ServiceUID": service["metadata"]["uid"], "Deployment": deployment["metadata"]["name"], "DeploymentUID": deployment["metadata"]["uid"],
            "Database": database, "BusinessPrefixes": ["claw:team:"]})
        # The prefix is the production Team owner key family in team_service.go,
        # not a sampled keyset or a claim that the current keyspace is empty.
        policy_input = stages.retain("initial-redis-source.policy.json", {"Policy": {"Source": {"ID": "redis-" + service["metadata"]["uid"], "Version": "source-" + stages.operation[:16], "SHA256": descriptor["SHA256"]},
            "Topology": "shared_keyspace", "CaptureMode": "scan_dump", "TTLPolicy": "preserve_absolute", "Purpose": "functional_test", "DB": database,
            "Prefixes": ["claw:team:"], "MaxItems": 10000, "MaxBytes": 32 << 20, "MaxClockSkew": 5000}, "ServerID": "", "ExcludePrefixes": ["cm:restore-history:"]})
        directory = stages.runtime_mirror() / "initial-redis-native"
        directory.mkdir(mode=0o700, exist_ok=True)
        helper = m.pin(stages.binary("system-backup-original-maintenance"), private=False, limit=128 << 20)
        base = {"Version": "original-redis-native-material-options.v1", "Mode": "prepare", "Deployment": deployment["metadata"]["name"], "Service": service["metadata"]["name"],
            "OutputDirectory": str(directory), "Policy": policy_input, "Helper": helper}
        prepared, prepare_pin = native_mode(m, stages, common, writer_pin, base, None, "prepare", "initial-redis-prepare")
        m.need(prepared["State"] == "native_prepared_loopback_isolated_requires_apply", "actual_original_redis_prepare_required")
        stages.retain("initial-redis-prepare.result.json", {"version": "operator-initial-redis-prepare.v1", "writer_selection": writer_pin, "base_options": base,
            "native_receipt": prepare_pin, "app_uid": app["metadata"]["uid"], "backup_ready": False})
        applied, _ = native_mode(m, stages, common, writer_pin, base, prepared, "apply", "initial-redis-apply")
        m.need(applied["State"] == "rollout_sent_requires_query_and_finalize", "actual_original_redis_apply_required")
        ready = False
        for attempt in range(60):
            observed = query_once(m, stages, common, writer_pin, base, prepared)
            if observed is not None and observed["State"] == "desired_specs_ready_requires_native_finalize":
                ready = True
                break
            time.sleep(2)
        m.need(ready, "original_redis_rollout_unconfirmed_query_or_recover_original_intent")
        final, native_receipt = finalize_once(m, stages, common, writer_pin, base, prepared)
        m.need(final["State"] == "native_tls_and_accounts_read_back_not_a_hold", "actual_original_redis_native_finalize_required")
        writer_pin = final["WriterSelection"]
        writer = m.decode(m.pinned(writer_pin))
        keeper = m.decode(m.pinned(final["KeeperSelection"]))
        policy = m.decode(m.pinned(final["Policy"]))
        m.need(len(writer["RedisReadKeepers"]) == 1 and writer["RedisReadKeepers"][0] == keeper and keeper["Native"]["Policy"] == policy,
               "same_actual_original_redis_keeper_and_policy_required")
    return finish(m, stages, enrolled, writer_pin, keeper, policy, native_receipt)


def finish(m, stages, enrolled, writer_pin, keeper, policy, native_receipt):
    for field in ("CA", "KeeperCredential", "ReaderCredential", "CustodyKey"):
        m.pinned(keeper[field])
    credential = m.decode(m.pinned(keeper["ReaderCredential"]))
    source_issuer = base64.b64encode(m.pinned(enrolled["IssuerPublic"])).decode()
    address = keeper["ServerName"] + ":" + str(keeper["Port"])
    connection = {"Purpose": "source_redis", "Endpoint": "rediss://" + address, "Account": credential["username"], "ServerUUID": "", "Database": "",
        "CA": keeper["CA"], "Credential": keeper["ReaderCredential"], "IdentitySHA256": "", "ScopeSHA256": ""}
    mount = {"GrantFile": str(stages.runtime_mirror() / "redis-source.grant.json"), "GrantSHA256": "", "Issuer": source_issuer,
        "CredentialFile": keeper["ReaderCredential"]["File"], "CredentialSHA256": keeper["ReaderCredential"]["SHA256"],
        "Redis": {"Address": address, "ServerName": keeper["ServerName"], "CAFile": keeper["CA"]["File"], "CASHA256": keeper["CA"]["SHA256"]}, "Objects": None,
        "RedisScope": {"ID": policy["Policy"]["Source"]["ID"], "ServerID": policy["ServerID"], "Database": policy["Policy"]["DB"], "KeyPrefix": ""},
        "ObjectPrefixes": None, "RedisPrefixes": policy["Policy"]["Prefixes"], "RedisExcludedPrefixes": policy["ExcludePrefixes"]}
    result = {"version": "operator-initial-redis-source-inputs.v1", "connection": connection, "source_mount": mount, "capture_policy": policy,
        "writer_selection": writer_pin, "keeper_selection": keeper, "native_receipt": native_receipt or writer_pin, "native_source_qualified": False, "backup_ready": False}
    stages.retain("initial-redis-source-inputs.result.json", result)
    stages.a.deployment_writer_selection_file = Path(writer_pin["File"])
    stages.a.deployment_writer_selection_sha256 = writer_pin["SHA256"]
    return result
