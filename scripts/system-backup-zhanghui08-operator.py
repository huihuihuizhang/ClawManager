#!/usr/bin/env python3
"""Existing original199/TLS/SQL/enrollment tools, fixed zhanghui08 scope.

Release sealing records real built bytes; it grants no production authority.
Field dispatch never creates a replacement native operation after an unknown send.
Later installation stages refuse until their actual producer is integrated.
"""
import argparse
import hashlib
import getpass
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tarfile
from types import SimpleNamespace as types_namespace
try:
    import fcntl
except ImportError:
    fcntl = None

sys.dont_write_bytecode = True
CONTEXT = "kubernetes-admin@kubernetes"
NS = "clawmanager-zhanghui08-system"
NS_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
MYSQL_UID = "27916932-fc61-432c-b515-081f18db34a8"
APP_UID = "ed2c80de-9d24-4ca6-8f9c-877a990ac933"
PASSWORD = Path("/root/.clawmanager-backup-install/admin-password")
PAGE_FIX = "21de0cf77c96801a84e89dc8aa7267233d7a90db"
COPY_NAME = "system-backup-upgrade199-copy-linux-amd64-20261105-r2.tar.gz"
COPY_SHA = "f82d59d1bf62558be69157a7a0d1f0d052bcd0a37361e3386598d65b5aaba7e5"
PROOF_NAME = COPY_NAME
PROOF_ARCHIVE_SHA = COPY_SHA
PROOF_SHA = "74f4c69383c9281687efe5247e9383cdf331f7cdcbeb1da1da64dc310fb5f655"
NATIVE_SHA = "f38c13d97dca4fc9e55837a879be0b2e1c45519ba8798202885584042e2abb8a"
NATIVE = "scripts/system-backup-original-upgrade199.py"
PROOF_MEMBER = "upgrade199-copy/system-backup-legacy-upgrade177-proof"

COPY_QUALIFIER = "scripts/system-backup-upgrade199-copy-qualification.py"

COPY_QUALIFIER_SHA = "186d0cd78181b4a5390b69e2b61e41397f7b95e19505414c1eeeaac08b56e308"

SQL = "scripts/system-backup-original-sql-accounts.py"
DEPLOYMENT_MODULE_SHA = "b69327c689f6fa15d08ee5d07eed266a79c2166e55a584b96523d0c1fcf235be"
BUSINESS_RUNTIME_SHA = "76e02dbae75008015dbe5080f0b8fc55a6069e2f4948e06c2ce0704f6e019ef7"
RECORD_EXPORT_SHA = "868c66ae0dddd7e5b25dd503a7b6309699ddc7831f8f1f74b5f53b5f940a0af4"
INITIAL_RUNTIME_SHA = "28e7cf35ae3294c85380ed0f2c4e51fbcd0b325f047d879dc4739104af791c5f"
RUNTIME_ISSUER_SHA = "6e3fe96bf1bb2cc4bd2b8383763f440d775b6b867dfcfe7549249fbdd71629d2"
OWNER_ASSEMBLY_SHA = "cbe8cc6be2fbd4192224a7758433bbc706659dc5c3388d42e2cfa080e1f17839"
WORKSPACE_SHA = "bd7149e99b15db2fedadc062b1cf1d559ad441bf4fa1f067874647147c7d85a6"
EARLY_PREFLIGHT_SHA = "39a51caba7b646b1f4bf1ccd9ba643099bf91abb2eb0a6a251dc342cbdfaf8e1"
WORKSPACE_ACTIONS = ("workspace-source-preflight", "workspace-source-preflight-cleanup", "workspace-localization-probe", "workspace-localize", "workspace-query", "workspace-abort-probe", "workspace-restore-nfs")
DB_ACTIONS = ("prepare", "backup", "apply", "query", "recover", "recover-controller",
              "rollback", "release", "finish-release", "cancel", "cleanup", "early-query", "early-cancel")
REPEATABLE = {"query", "recover", "recover-controller", "rollback", "finish-release", "cancel", "cleanup", "early-query", "early-cancel"}
IMPLEMENTED_STAGES = ("new-image", "materials", "host-observer", "rollout-refresh", "adopt", "composition", "enable")
BLOCKERS = {"page": ["Use the sealed first-page-once entry only after actual live readiness; retain original task, publication and original source recovery readbacks."]}

class Stop(Exception):
    pass


def require(value, code):
    if not value:
        raise Stop(code)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def regular(path, private=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, "regular_absolute_original_file_required")
    s = path.stat()
    require(stat.S_ISREG(s.st_mode), "regular_file_required")
    if private and os.name == "posix":
        require(s.st_uid == os.geteuid() and not s.st_mode & 0o077, "private_original_operator_file_required")
    return path


def load(path):
    return json.loads(regular(path).read_bytes())


def sync_dir(path):
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def create(path, raw):
    with Path(path).open("xb") as f:
        os.chmod(path, 0o600)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    sync_dir(Path(path).parent)


def save(path, value):
    create(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def capture(argv, limit=4 << 20):
    r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=60, check=False)
    require(r.returncode == 0 and len(r.stdout) <= limit, "native_read_unconfirmed")
    return r.stdout


REQUIRED_BUILT_BINARIES = (
    "system-backup-source-tls-bootstrap", "system-backup-original-enroll", "system-backup-first-adoption", "system-backup-first-adoption-production", "system-backup-original-archive-reader", "system-backup-source-registries", "system-backup-bootstrap-enrolled",
    "system-backup-first-install-materials", "system-backup-original-observer-pki", "system-backup-observer-deployment-materials",
    "backup-node-observer", "backup-gateway-node-observer", "backup-stopped-pro-node-observer",
    "system-backup-original-maintenance", "system-backup-c1-native-inputs",
)


def built_binary_pins(root, receipt):
    files = {}
    for name in REQUIRED_BUILT_BINARIES:
        binary = regular(root / "bin" / name)
        require(sha(binary) == receipt["binaries"][name], "built_binary_pin_changed")
        with binary.open("rb") as f:
            header = f.read(20)
        require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00", "linux_amd64_binary_required")
        files["bin/" + name] = sha(binary)
    return files


def seal_release(a):
    root = a.release_directory.resolve(strict=True)
    receipt = load(root / "build-receipt.json")
    commit = receipt["commit"]
    require(re.fullmatch(r"[a-f0-9]{40}", commit), "release_commit_invalid")
    regular(a.source_repository / ".git" / "HEAD") if (a.source_repository / ".git").is_dir() else None
    r = subprocess.run(["git", "-C", str(a.source_repository), "merge-base", "--is-ancestor", PAGE_FIX, commit],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    require(r.returncode == 0, "release_must_contain_page_fix_21de0cf7")
    files = {}
    names = [NATIVE, COPY_QUALIFIER, SQL, "scripts/system-backup-zhanghui08-operator.py", "scripts/system-backup-first-page-once.py",
             "scripts/system-backup-first-page-inputs.py", "scripts/system-backup-d-first-install-inputs.py",
             "build-receipt.json", COPY_NAME, PROOF_NAME, "scripts/system-backup-d-enable.py",
             "scripts/system-backup-d-enable-readback.py", "scripts/system-backup-d-enable-resolve.py", "scripts/system-backup-operator-deployment.py"]
    names += ["scripts/system-backup-initial-provider-topology.py"]
    names += ["scripts/system-backup-initial-input-assembly.py", "scripts/system-backup-initial-source-data.py", "scripts/system-backup-initial-redis-sources.py", "scripts/system-backup-initial-complete-inputs.py", "scripts/system-backup-initial-provider-fragments.py", "scripts/system-backup-initial-provider-lifecycle.py", "scripts/system-backup-minio-first-hop-tls.py", "scripts/system-backup-minio-app-tls-cutover.py", "scripts/system-backup-first-page-tls-only.py"]
    names += ["scripts/system-backup-publication-owner-assembly.py", "scripts/system-backup-runtime-issuers.py", "scripts/system-backup-runtime-record-keys.py", "scripts/system-backup-initial-runtime.py", "scripts/system-backup-business-runtime.py", "scripts/system-backup-workspace-localization.py", "scripts/system-backup-workspace-native.py", "scripts/system-backup-workspace-source-preflight.py", "scripts/system-backup-agent-runtime-layer/agent_runtime_layer.py", "scripts/system-backup-runtime-startup-inputs.py", "agent-prebuilt-shared-native-236d56d85fea-linux-amd64.tar.gz"]
    names += ["scripts/system-backup-operator-nonce.py", "scripts/system-backup-operator-c1-mysql-bridge.py", "scripts/system-backup-c1-host-mysql-bridge.py", "scripts/system-backup-operator-first-adoption-production.py"]
    names += ["scripts/system-backup-operator-adoption-locations.py", "tools/mc"]
    names += ["scripts/system-backup-operator-minio-recovery.py"]
    names += ["scripts/system-backup-initial-input-assembly.py"]
    names += ["scripts/system-backup-initial-source-data.py", "scripts/system-backup-initial-redis-sources.py"]
    names += ["scripts/system-backup-operator-c1-inputs.py", "scripts/system-backup-original-c1-pending-input.py", "scripts/system-backup-operator-c1-native.py", "scripts/system-backup-operator-c1-authors.py", "scripts/system-backup-operator-relay-bootstrap.py", "scripts/system-backup-operator-live-capacity.py", "scripts/system-backup-capacity-report-transport.py"]
    names += ["scripts/system-backup-operator-minio-consent.py", "scripts/system-backup-operator-enabled-publication.py"]
    names += ["scripts/system-backup-operator-capture-mapping.py", "contracts/system-backup/v12/schema-registry.json"]
    names += ["scripts/system-backup-operator-archive-inputs.py", "scripts/system-backup-minio-hostpath-cold-source.py"]
    for name in names:
        files[name] = sha(regular(root / name))
    require(files["tools/mc"] == adoption_locations_module().MC_SHA, "exact_original_mc_release_required")
    require(files[NATIVE] == NATIVE_SHA and files[COPY_QUALIFIER] == COPY_QUALIFIER_SHA and files[COPY_NAME] == COPY_SHA and files[PROOF_NAME] == PROOF_ARCHIVE_SHA,
            "reviewed_native_or_archives_changed")
    # Extract one exact ELF, never tar paths/links or an archive-provided script.
    proof = root / "bin/system-backup-legacy-upgrade177-proof"
    with tarfile.open(root / PROOF_NAME, "r:gz") as t:
        entry = t.getmember(PROOF_MEMBER)
        require(entry.isfile() and entry.size < 64 << 20, "proof_archive_entry_invalid")
        raw = t.extractfile(entry).read()
    require(hashlib.sha256(raw).hexdigest() == PROOF_SHA, "original_readproof_bytes_changed")
    if proof.exists():
        require(sha(regular(proof)) == PROOF_SHA, "existing_proof_changed")
    else:
        create(proof, raw)
        os.chmod(proof, 0o700)
    files["bin/system-backup-legacy-upgrade177-proof"] = PROOF_SHA
    require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,100}", name) for name in receipt["binaries"]), "finite_actual_release_binary_roster_required")
    require({"system-backup-source-tls-bootstrap", "system-backup-original-enroll", "system-backup-first-adoption", "system-backup-first-adoption-production", "system-backup-original-archive-reader", "system-backup-source-registries", "system-backup-bootstrap-enrolled", "system-backup-original-nonce-material", "system-backup-c1-native-inputs", "system-backup-c1-s3-materials", "system-backup-minio-catalog-initial", "system-backup-enabled-provider-materials", "system-backup-control-evidence-source-grant"} <= set(receipt["binaries"]), "final_installation_binary_roster_incomplete")
    for name in sorted(receipt["binaries"]):
        binary = regular(root / "bin" / name)
        require(sha(binary) == receipt["binaries"][name], "built_binary_pin_changed")
        with binary.open("rb") as f:
            h = f.read(20)
        require(h[:6] == b"\x7fELF\x02\x01" and h[18:20] == b"\x3e\x00", "linux_amd64_binary_required")
        files["bin/" + name] = sha(binary)
    # This is only a byte/location manifest; no identity or permission assertion.
    save(root / "operator-release-pins.json", {"version": "zhanghui08-operator-release-files.v1", "commit": commit,
         "page_fix_ancestor": PAGE_FIX, "files": files, "production_authority": False})
    return {"state": "release_real_file_pins_created_no_authority", "release_pins_sha256": sha(root / "operator-release-pins.json")}


class Operator:
    def __init__(self, a):
        self.a = a
        self.root = a.release_directory.resolve(strict=True)
        self.run = a.run_directory
        self.kube = None
        self.pins = None
        self.status = {}

    def release(self):
        pins_path = self.root / "operator-release-pins.json"
        self.pins = load(pins_path)
        require(self.pins["version"] == "zhanghui08-operator-release-files.v1", "release_pins_schema_invalid")
        for name, digest in self.pins["files"].items():
            p = self.root / name
            require(not Path(name).is_absolute() and ".." not in Path(name).parts and sha(regular(p)) == digest, "release_bytes_changed")
        require(self.pins["files"][NATIVE] == NATIVE_SHA, "r3_native_entry_required")

    def k(self, *args):
        argv = ["kubectl", "--context", CONTEXT]
        if self.kube:
            argv += ["--kubeconfig", str(self.kube)]
        return capture([*argv, "--request-timeout=30s", *args])

    def actual_scope(self):
        ns = json.loads(self.k("get", "namespace", NS, "-o", "json"))
        system = json.loads(self.k("get", "namespace", "kube-system", "-o", "json"))
        mysql = json.loads(self.k("-n", NS, "get", "deployment", "mysql", "-o", "json"))
        app = json.loads(self.k("-n", NS, "get", "deployment", "clawmanager-app", "-o", "json"))
        require(ns["metadata"]["uid"] == NS_UID and mysql["metadata"]["uid"] == MYSQL_UID and app["metadata"]["uid"] == APP_UID,
                "original_namespace_or_deployments_changed")
        return {"namespace_uid": NS_UID, "cluster_uid": system["metadata"]["uid"], "mysql_deployment_uid": MYSQL_UID,
                "app_deployment_uid": APP_UID, "app_replicas": app["spec"].get("replicas", 1), "app": app}

    def init(self):
        self.release()
        require(self.run.is_absolute() and self.run.parent.resolve(strict=True) == self.run.parent, "private_run_parent_required")
        self.run.mkdir(mode=0o700)
        sync_dir(self.run.parent)
        save(self.run / "release-pin.json", {"file": str(self.root / "operator-release-pins.json"), "sha256": sha(self.root / "operator-release-pins.json")})
        scope = self.actual_scope()
        self.kube = self.run / "operator.kubeconfig.json"
        raw = capture([
            "kubectl", "--context", CONTEXT, "config", "view", "--raw", "--flatten", "--minify", "-o", "json"])
        config = json.loads(raw)
        require(config.get("current-context") == CONTEXT and len(config["contexts"]) == 1, "exact_static_context_required")
        require(all(not u.get("user", {}).get("exec") and not u.get("user", {}).get("auth-provider") for u in config["users"]), "static_original_kubeconfig_required")
        require(all(c.get("cluster", {}).get("server", "").startswith("https://")
                    and c["cluster"].get("certificate-authority-data")
                    and not c["cluster"].get("insecure-skip-tls-verify") for c in config["clusters"]), "original_strict_tls_kubeconfig_required")
        create(self.kube, raw)
        require(self.actual_scope()["cluster_uid"] == scope["cluster_uid"], "original_cluster_changed")
        scope.pop("app")
        save(self.run / "operation.json", {"version": "zhanghui08-operator-operation.v1", "operation": secrets.token_hex(16),
             "scope": scope, "kubeconfig_sha256": sha(self.kube), "release_sha256": sha(self.root / "operator-release-pins.json")})
        return {"state": "original_operator_scope_retained_no_sql_or_deployment_mutation"}

    def open(self):
        regular(self.run / "operation.json", private=True)
        require(self.run.resolve(strict=True) == self.run and (os.name != "posix" or not self.run.stat().st_mode & 0o077), "private_original_run_required")
        self.release()
        op = load(self.run / "operation.json")
        require(op["release_sha256"] == sha(self.root / "operator-release-pins.json"), "same_release_required")
        self.kube = regular(self.run / "operator.kubeconfig.json", private=True)
        require(sha(self.kube) == op["kubeconfig_sha256"], "original_kubeconfig_changed")
        scope = self.actual_scope()
        require(scope["cluster_uid"] == op["scope"]["cluster_uid"], "original_cluster_changed")
        return scope

    def invoke(self, stage, argv, repeat=False, env=None):
        # Permanent logical send record is created before any mutation. Query
        # and explicit same-operation recovery use new receipt files only.
        stem = stage + ("-" + secrets.token_hex(8) if repeat else "")
        intent = self.run / (stem + ".send-unknown.json")
        if intent.exists():
            raise Stop("stage_already_sent_use_same_operation_query_or_recovery")
        dispatch = {"stage": stage, "argv": [str(s) for s in argv]}
        if stage.startswith("db-"):
            dispatch["native_operation_directory"] = str(self.run / "original199")
        save(intent, dispatch)
        out = self.run / (stem + ".stdout.private")
        err = self.run / (stem + ".stderr.private")
        with out.open("xb") as stdout, err.open("xb") as stderr:
            os.chmod(out, 0o600); os.chmod(err, 0o600)
            try:
                result = subprocess.run([str(s) for s in argv], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                        timeout=7200, check=False, env=env)
            finally:
                stdout.flush(); os.fsync(stdout.fileno()); stderr.flush(); os.fsync(stderr.fileno())
        sync_dir(self.run)
        require(result.returncode == 0, "stage_unconfirmed_retain_same_operation_and_private_receipts")
        value = json.loads(out.read_bytes())
        save(self.run / (stem + ".readback.json"), {"stage": stage, "stdout": str(out), "stdout_sha256": sha(out),
             "stderr_sha256": sha(err), "native_state": value.get("state", value.get("State", value.get("status"))), "subprocess_exit": 0})
        return value, out

    def completed(self, stage):
        receipt = load(self.run / (stage + ".readback.json"))
        require(receipt["stage"] == stage and sha(regular(Path(receipt["stdout"]), private=True)) == receipt["stdout_sha256"],
                "retained_producer_receipt_changed")
        return receipt

    def db(self, action):
        self.open()
        if action == "prepare":
            early_preflight_module().require_early_shapes(self)
        env = dict(os.environ)
        env["KUBECONFIG"] = str(self.kube)
        argv = [sys.executable, "-B", self.root / NATIVE, action, "--operation-directory", self.run / "original199"]
        if action == "prepare":
            require(self.a.copy_receipts_directory is not None and self.a.copy_receipts_directory.is_absolute(), "fresh_copy199_native_receipts_directory_required")
            argv += ["--copy-receipts-directory", self.a.copy_receipts_directory]
            argv += ["--v3-archive", self.root / COPY_NAME, "--original-proof", self.root / "bin/system-backup-legacy-upgrade177-proof", "--original-proof-sha256", PROOF_SHA]
        value, out = self.invoke("db-" + action, argv, repeat=action in REPEATABLE, env=env)
        return {"state": value.get("state"), "private_receipt": str(out), "original_database_upgraded": value.get("original_database_upgraded", False)}

    def upgraded_released(self):
        scope = self.open()
        native = self.run / "original199"
        require((native / "original-upgraded-readback.json").is_file() and not (native / "original-rollback-readback.json").exists()
                and (native / "released.json").is_file() and (native / "cleanup-completed.json").is_file(), "upgraded_released_original_operation_required")
        require(scope["app_replicas"] == 0, "application_must_remain_stopped_until_complete_tls_deployment")
        return scope

    def source_helpers(self):
        return types_namespace(load=load, require=require, NS=NS, sync_dir=sync_dir)

    def adoption_locations_module(self):
        return adoption_locations_module()

    def minio_recovery_module(self):
        return minio_recovery_module()

    def relay_bootstrap_module(self):
        return relay_bootstrap_module()

    def live_capacity_module(self):
        return live_capacity_module()

    def capture_mapping_module(self):
        return capture_mapping_module()

    def production_adoption_module(self):
        return production_adoption_module()

    def c1_authors_module(self):
        return c1_authors_module()

    def c1_inputs_module(self):
        return c1_inputs_module()

    def archive_inputs_module(self):
        return archive_inputs_module()

    def deployment_stages(self):
        return deployment_module().DeploymentStages(self)

    def nonce_mount_profile(self, pod_spec):
        return nonce_module().mount_for_host(self, pod_spec)

    def verify_nonce_readable(self, stages, identity):
        return nonce_module().verify_readable(stages, identity)

    def invoke_complete_adoption(self, actual_complete_cli_argv):
        # The actual full17 branch calls this BEFORE constructing C1/context.
        # One original ELF/Go process owns all real source pointers and ctx.
        return c1_mysql_bridge_module().invoke_complete(self, actual_complete_cli_argv)

    def workspace_upgrade_released(self):
        # new-image has already restarted the application. The DB/TLS staging
        # guard intentionally requires app0 and cannot be reused here.
        scope = self.open()
        native = self.run / "original199"
        require((native / "original-upgraded-readback.json").is_file() and not (native / "original-rollback-readback.json").exists()
                and (native / "released.json").is_file() and (native / "cleanup-completed.json").is_file(), "upgraded_released_original_operation_required")
        return scope

    def tls(self, action):
        self.upgraded_released()
        if action == "apply":
            require(not (self.run / "tls-rollback.send-unknown.json").exists(), "original_tls_rollback_started_no_apply")
        regular(PASSWORD, private=True)
        binary = self.root / "bin/system-backup-source-tls-bootstrap"
        directory = self.run / "mysql-tls"
        common = [binary, "--kubeconfig-file", self.kube, "--kubeconfig-sha256", sha(self.kube), "--namespace", NS,
                  "--local-admin-password-file", PASSWORD, "--helper-file", binary,
                  "--helper-sha256", self.pins["files"]["bin/system-backup-source-tls-bootstrap"], "--output-directory", directory]
        if action == "inspect":
            directory.mkdir(mode=0o700)
            sync_dir(self.run)
        else:
            inspected = load(Path(self.completed("tls-inspect")["stdout"]))
            plan = load(Path(inspected["PlanFile"]))
            require(sha(Path(inspected["PlanFile"])) == inspected["PlanSHA256"], "original_tls_plan_changed")
            common += ["--plan-file", inspected["PlanFile"], "--plan-sha256", inspected["PlanSHA256"],
                       "--operation", inspected["Operation"], "--local-admin-username", plan["AdminUsername"]]
        # The existing TLS CLI has inspect/apply/rollback, not a query mode.
        value, out = self.invoke("tls-" + action, [*common, "--mode", action])
        if action == "apply":
            require(value.get("OperatorSQLTLSVerified") is True, "actual_tls_transport_not_verified")
        return {"state": value.get("State"), "private_receipt": str(out), "configuration_enabled": False}

    def sql(self, action):
        scope = self.upgraded_released()
        runtime_profile = "public-runtime-c1-minio-metadata-read.v1"
        if action not in ("inspect", "prepare"):
            original_prepare = load(Path(self.completed("sql-prepare")["stdout"]))
            original_operation = load(self.pin_value({"File":original_prepare["operation_file"],"SHA256":original_prepare["operation_sha256"]}))
            profiles = {"original198-sql-accounts-operation.v1":"controller-historical14.v1", "original198-sql-accounts-operation.v2":"public-runtime-publication-permits-control-evidence.v1", "original-c1-sql-accounts-operation.v3":"public-runtime-c1-installer-bootstrap.v1", "original-c1-minio-metadata-sql-accounts-operation.v4":"public-runtime-c1-minio-metadata-read.v1"}
            require(original_operation["Version"] in profiles,"retained_original_sql_operation_version_required")
            runtime_profile = profiles[original_operation["Version"]]
            require(original_prepare.get("runtime_profile",runtime_profile)==runtime_profile,"retained_sql_profile_mismatch")
        if action in ("apply", "enroll"):
            require(not list(self.run.glob("sql-rollback*.send-unknown.json")), "sql_rollback_started_query_original_only")
        regular(PASSWORD, private=True)
        tls_output = Path(self.completed("tls-apply")["stdout"])
        binary = self.root / "bin/system-backup-original-enroll"
        common = [sys.executable, "-B", self.root / SQL, action, "--tool-file", binary,
                  "--tool-sha256", self.pins["files"]["bin/system-backup-original-enroll"],
                  "--tls-receipt-file", tls_output, "--tls-receipt-sha256", sha(tls_output),
                  "--kubeconfig-file", self.kube, "--kubeconfig-sha256", sha(self.kube),
                  "--namespace", NS, "--namespace-uid", NS_UID, "--cluster-uid", scope["cluster_uid"],
                  "--inventory-directory", self.run / "sql-inventory", "--operation-directory", self.run / "sql-accounts",
                  "--runtime-profile", runtime_profile]
        stem = "sql-" + action + ("-" + secrets.token_hex(8) if action in ("query", "rollback") else "")
        common += ["--receipt-file", self.run / (stem + ".native.private.json")]
        if action != "inspect":
            inspected = Path(self.completed("sql-inspect")["stdout"])
            inv = load(inspected)
            common += ["--inventory-sha256", inv["inventory_sha256"]]
        if action == "prepare":
            require(self.a.sql_account_host is not None, "select_actual_sql_account_host_before_prepare_no_default_percent")
            common += ["--account-host", self.a.sql_account_host]
        elif action not in ("inspect",):
            prepared = load(Path(self.completed("sql-prepare")["stdout"]))
            common += ["--prepare-receipt-file", prepared["receipt_file"], "--prepare-receipt-sha256", prepared["receipt_sha256"]]
        if self.a.allow_wildcard_host:
            common += ["--allow-wildcard-host"]
        if action == "enroll":
            common += ["--pre-enroll-query-receipt-file", self.run / "enrollment-pre-query.private.json", "--enrollment-output-directory", self.run / "original-enrollment"]
        # Preserve host acknowledgement for this same operation, not argv on a
        # later command accidentally widening a different account plan.
        selected = self.run / "sql-account-host-selection.json"
        if action == "prepare":
            save(selected, {"host": self.a.sql_account_host, "allow_wildcard_host": self.a.allow_wildcard_host})
        elif action not in ("inspect",):
            selection = load(selected)
            require(bool(selection["allow_wildcard_host"]) == self.a.allow_wildcard_host, "retain_original_sql_host_acknowledgement")
        value, out = self.invoke("sql-" + action, common, repeat=action in ("query", "rollback"))
        return {"state": value.get("state"), "private_receipt": str(out), "configuration_enabled": False}

    def observe(self):
        self.open()
        env = dict(os.environ); env["KUBECONFIG"] = str(self.kube)
        value, out = self.invoke("observe", [sys.executable, "-B", self.root / "scripts/system-backup-first-page-once.py"], repeat=True, env=env)
        return {"state": value["status"], "private_receipt": str(out), "backup_readiness_proved": False}

    def status_read(self):
        self.open()
        stages = [load(p) for p in sorted(self.run.glob("*.readback.json"))]
        return {"state": "operator_receipts_only_not_fresh_native_success", "stages": stages, "blocked_installation_stages": {k: v for k, v in BLOCKERS.items() if k == "page"},
                "unknown_actions": [p.name for p in self.run.glob("*.send-unknown.json") if not p.with_name(p.name.replace(".send-unknown.json", ".readback.json")).exists()],
                "configuration_enabled": False, "page_acceptance": False}

    def pin_value(self, pin):
        file = regular(Path(pin["File"]), private=True)
        require(sha(file) == pin["SHA256"], "actual_producer_file_pin_changed")
        return file

    def enrollment(self):
        wrapped = load(Path(self.completed("sql-enroll")["stdout"]))
        actual = regular(Path(wrapped["receipt_file"]), private=True)
        require(sha(actual) == wrapped["receipt_sha256"], "original_enrollment_receipt_changed")
        produced = load(actual)
        require(produced["Version"] == "original-native-enrollment-produced.v1", "actual_original_enrollment_required")
        for key in ("Plan", "IssuerPublic", "Enrollment", "Receipt"):
            self.pin_value(produced[key])
        return produced

    def owner_common(self):
        self.open()
        produced = self.enrollment()
        accounts = load(self.run / "sql-accounts/sql-accounts-materials.public.json")
        require((accounts["version"],accounts.get("runtime_profile")) in (("original198-sql-account-materials.v1","public-runtime-publication-permits-control-evidence.v1"),("original-c1-sql-account-materials.v3","public-runtime-c1-minio-metadata-read.v1")), "native_sql_account_materials_required")
        dsn = self.pin_value(accounts["files"]["mysql-installer.dsn"])
        tls = accounts["source_tls"]
        ca = regular(Path(tls["ca_file"]), private=True)
        require(sha(ca) == tls["ca_sha256"], "original_database_ca_changed")
        regular(PASSWORD, private=True)
        return ["-plan-file", produced["Plan"]["File"], "-plan-sha256", produced["Plan"]["SHA256"],
                "-issuer-public-file", produced["IssuerPublic"]["File"], "-issuer-public-sha256", produced["IssuerPublic"]["SHA256"],
                "-kubeconfig-file", self.kube, "-kubeconfig-sha256", sha(self.kube), "-dsn-file", dsn,
                "-database-ca-file", ca, "-local-admin-password-file", PASSWORD,
                "-enrollment-pin-file", produced["Enrollment"]["File"], "-enrollment-pin-sha256", produced["Enrollment"]["SHA256"]]

    def sql_role_inputs(self):
        self.open()
        enrolled = self.enrollment()
        plan = load(self.pin_value(enrolled["Plan"]))
        prepared = load(Path(self.completed("sql-prepare")["stdout"]))
        operation = load(self.pin_value({"File": prepared["operation_file"], "SHA256": prepared["operation_sha256"]}))
        materials = load(self.run / "sql-accounts/sql-accounts-materials.public.json")
        profiles = {"original198-sql-accounts-operation.v2":("original198-sql-account-materials.v1","public-runtime-publication-permits-control-evidence.v1"),"original-c1-minio-metadata-sql-accounts-operation.v4":("original-c1-sql-account-materials.v3","public-runtime-c1-minio-metadata-read.v1")}
        require(operation["Version"] in profiles and
                (materials["version"],materials.get("runtime_profile")) == profiles[operation["Version"]] and
                operation["ServerUUID"] == materials["server_uuid"] == plan["Target"]["ServerUUID"] and
                operation["Database"] == materials["database"] == plan["Target"]["Database"],
                "actual_original_public_runtime_sql_profile_required")
        actual = {a["Role"]: a for a in operation["Accounts"]}
        require(len(actual) == len(operation["Accounts"]) == 6, "original_sql_role_operation_ambiguous")
        roles = {}
        for role in ("installer", "business", "runtime", "source"):
            account = actual[role]
            dsn = materials["files"]["mysql-" + role + ".dsn"]
            path = self.pin_value(dsn)
            credential = load(self.pin_value(materials["files"]["mysql-" + role + "-credential.json"]))
            require(credential["username"] == account["User"] and path.read_bytes().startswith((account["User"] + ":").encode()),
                    "original_sql_role_credential_user_mismatch")
            roles[role] = {"dsn": dsn, "username": account["User"], "account": account["User"] + "@" + account["Host"]}
        require(len({r["account"] for r in roles.values()}) == 4 and len({r["dsn"]["SHA256"] for r in roles.values()}) == 4 and
                roles["business"]["account"] == plan["Target"]["DatabaseAccount"] and
                roles["installer"]["account"] == plan["InstallerDatabaseAccount"],
                "original_business_runtime_source_principals_must_remain_distinct")
        return {"version": "operator-original-sql-role-locators.v1", "roles": roles,
                "plan": enrolled["Plan"], "native_authority_proved": False}

    def bind_sql_role_arguments(self, action):
        values = self.sql_role_inputs()["roles"]
        role, field = ("runtime", "owner_runtime_dsn") if action == "publication-materials" else ("business", "compose_installer_dsn")
        selected = values[role]["dsn"]
        supplied = getattr(self.a, field + "_file", None)
        supplied_sha = getattr(self.a, field + "_sha256", None)
        require((supplied is None) == (supplied_sha is None), "sql_role_file_and_pin_must_be_selected_together")
        if supplied is not None:
            require(supplied_sha == selected["SHA256"] and sha(regular(supplied, private=True)) == supplied_sha,
                    "caller_sql_role_is_not_original_producer_principal")
        # This existing CLI option is named installer-dsn, but its output is
        # BootstrapDeployment.DSNFile: the A2 BUSINESS consumer, not admin SQL.
        setattr(self.a, field + "_file", Path(selected["File"]))
        setattr(self.a, field + "_sha256", selected["SHA256"])
        if action == "publication-materials":
            core_file = getattr(self.a, "owner_core_file", None)
            core_sha = getattr(self.a, "owner_core_sha256", None)
            require(core_file is not None and core_sha is not None, "actual_core_source_producer_pin_required")
            core = load(self.pin_value({"File": str(core_file), "SHA256": core_sha}))
            source = values["source"]
            # Final mount paths may differ from the private producer directory;
            # only a real exact-byte delivery of mysql-source is acceptable.
            source_file = regular(Path(core["source_dsn_file"]), private=True)
            require(sha(source_file) == source["dsn"]["SHA256"] and core["source_user"] == source["username"],
                    "core_source_capture_must_use_original_readonly_source_role")
        return values

    def prepare_writer_selection(self):
        common = self.owner_common()
        images = business_runtime_module().verify_current(self)
        startup = images["startup_images"]
        self.pin_value(startup)
        host = load(self.run / "deployment/host-observer.result.json")
        require(host["version"] == "operator-host-observer-result.v1", "actual_original_host_observer_receipt_required")
        for name in ("pki_definition", "pki_receipt"):
            self.pin_value(host[name])
        source_file = getattr(self.a, "writer_source_config_file", None)
        source_sha = getattr(self.a, "writer_source_config_sha256", None)
        if source_file is None and getattr(self.a, "deployment_source_selection_file", None) is None:
            initial_runtime_module().prepare_writer_source_arguments(self)
            source_file = self.a.writer_source_config_file
            source_sha = self.a.writer_source_config_sha256
        if source_file is None:
            selected_file = getattr(self.a, "deployment_source_selection_file", None)
            selected_sha = getattr(self.a, "deployment_source_selection_sha256", None)
            require(selected_file is not None and selected_sha is not None, "actual_original_source_config_producer_locator_required")
            selected = load(self.pin_value({"File": str(selected_file), "SHA256": selected_sha}))
            source_file = self.pin_value(selected["Deployment"]); source_sha = selected["Deployment"]["SHA256"]
        source = {"File": str(source_file), "SHA256": source_sha}
        self.pin_value(source)
        output, journal = self.run / "original-writer-selection", self.run / "original-writer-journal"
        output.mkdir(mode=0o700); journal.mkdir(mode=0o700); sync_dir(self.run)
        flags = ["-action", "prepare-selection", *common, "-source-config-file", source["File"], "-source-config-sha256", source["SHA256"],
                 "-runtime-startup-images-file", startup["File"], "-runtime-startup-images-sha256", startup["SHA256"],
                 "-observer-definition-file", host["pki_definition"]["File"], "-observer-definition-sha256", host["pki_definition"]["SHA256"],
                 "-observer-receipt-file", host["pki_receipt"]["File"], "-observer-receipt-sha256", host["pki_receipt"]["SHA256"],
                 "-selection-output-directory", output, "-journal-directory", journal]
        custody = (getattr(self.a, "writer_gateway_original_directory", None), getattr(self.a, "writer_gateway_original_key_file", None), getattr(self.a, "writer_gateway_original_key_sha256", None))
        require(all(v is None for v in custody) or all(v is not None for v in custody), "complete_actual_original_gateway_custody_locators_required")
        if custody[0] is not None:
            self.pin_value({"File": str(custody[1]), "SHA256": custody[2]})
            flags += ["-gateway-original-directory", custody[0], "-gateway-original-key-file", custody[1], "-gateway-original-key-sha256", custody[2]]
        for item in getattr(self.a, "writer_participant", None) or []:
            flags += ["-participant-writer", item]
        value, out = self.invoke("writer-selection", [self.root / "bin/system-backup-first-adoption", *flags])
        require(value.get("Version") == "original-writer-selection-materials.v1" and value.get("State") == "actual_original_complete_base_selection_materialized_no_hold",
                "actual_original_writer_selection_producer_unconfirmed")
        self.pin_value(value["Selection"])
        return {"state": value["State"], "selection": value["Selection"], "startup_images": startup, "private_receipt": str(out),
                "native_qualified": False, "source_held": False, "backup_ready": False}

    def bind_writer_selection_argument(self):
        file = getattr(self.a, "deployment_writer_selection_file", None)
        pin = getattr(self.a, "deployment_writer_selection_sha256", None)
        require((file is None) == (pin is None), "original_writer_selection_file_and_pin_required_together")
        if file is None:
            native = load(Path(self.completed("writer-selection")["stdout"]))
            require(native.get("Version") == "original-writer-selection-materials.v1" and native.get("State") == "actual_original_complete_base_selection_materialized_no_hold",
                    "actual_original_writer_selection_receipt_missing")
            self.a.deployment_writer_selection_file = self.pin_value(native["Selection"])
            self.a.deployment_writer_selection_sha256 = native["Selection"]["SHA256"]
        else:
            self.pin_value({"File": str(file), "SHA256": pin})

    def business_runtime(self, action):
        require(action in ("runtime-images", "runtime-rollout", "runtime-query"), "unknown_runtime_stage")
        require(self.a.action == action, "runtime_dispatch_action_changed")
        value = business_runtime_module().dispatch(self)
        require(value.get("native_qualified") is False and value.get("backup_ready") is False,
                "runtime_rollout_cannot_mint_native_qualification")
        return value

    def web_modules(self):
        # Imports only same-release, independently sealed existing modules.
        modules = []
        for name in ("system-backup-d-enable.py", "system-backup-d-enable-resolve.py"):
            spec = importlib.util.spec_from_file_location(name.replace("-", "_"), self.root / "scripts" / name)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            modules.append(module)
        return modules

    def with_original_kube(self, call):
        previous = os.environ.get("KUBECONFIG")
        os.environ["KUBECONFIG"] = str(self.kube)
        try:
            return call()
        finally:
            if previous is None: os.environ.pop("KUBECONFIG", None)
            else: os.environ["KUBECONFIG"] = previous

    def actual_pods(self, selected):
        controller = selected["Controller"]
        require(controller["Namespace"] == NS and controller["NamespaceUID"] == NS_UID, "original_controller_namespace_changed")
        pod = json.loads(self.k("-n", NS, "get", "pod", controller["Pod"], "-o", "json"))
        require(pod["metadata"]["uid"] == controller["PodUID"] and pod["spec"].get("serviceAccountName", "default") == controller["ServiceAccount"], "controller_rolled_reissue_uid_bound_materials_before_metadata")
        pods = json.loads(self.k("-n", NS, "get", "pods", "-o", "json"))["items"]
        matches = []
        for current in pods:
            refs = [r for r in current["metadata"].get("ownerReferences", []) if r.get("controller")]
            if len(refs) != 1 or refs[0]["kind"] != "ReplicaSet" or current["metadata"].get("deletionTimestamp"):
                continue
            rs = json.loads(self.k("-n", NS, "get", "replicaset", refs[0]["name"], "-o", "json"))
            parents = [r for r in rs["metadata"].get("ownerReferences", []) if r.get("controller")]
            if rs["metadata"]["uid"] == refs[0]["uid"] and len(parents) == 1 and parents[0]["kind"] == "Deployment" and parents[0]["uid"] == APP_UID:
                matches.append(current["metadata"]["name"])
        require(len(matches) == 1, "unique_running_original_app_pod_required")
        return types_namespace(context=CONTEXT, namespace=NS, namespace_uid=NS_UID, app_pod=matches[0], controller_pod=controller["Pod"])

    def rollout_refresh(self):
        common = self.owner_common()
        post_adoption = self.a.action == "post-adoption-facts"
        original = None
        if post_adoption:
            self.require_adopted()
            original = load(self.run / "final-rollout-binding.json")
        successor = self.run / "deployment/materials.source-api-successor.result.json"
        if self.a.delivery_receipt_file is None and (self.run / "deployment/initial-source-api-inputs.result.json").exists() and not successor.exists():
            initial_runtime_module().prepare_source_api_successor_arguments(self)
        delivered_path = self.a.delivery_receipt_file or (successor if successor.exists() else self.run / "deployment/materials.result.json")
        require(delivered_path.is_file(), "actual_final_Dmain_delivery_receipt_missing_input")
        receipt_file = regular(delivered_path, private=True)
        delivered = load(receipt_file)
        if delivered.get("version") == "operator-materials-result.v1":
            deploy = deployment_module().DeploymentStages(self)
            deploy.check_host(delivered["host"])
            original_minio = load(self.pin_value(delivered["original_minio_delivery_receipt"]))
            require(original_minio.get("Version") == "formal-minio-material-delivery.v1", "actual_original_minio_delivery_required")
            for key in ("SourceSelection", "WriterSelection", "Deployment", "DeploymentPatch", "SecretManifests"):
                self.pin_value(original_minio[key])
            # These are separate final comparison locators. The immutable Go
            # receipt above is retained without pretending it had a new Pod UID.
            require(delivered.get("final_source_facts_produced") is False, "D1_owns_final_create_only_facts_dispatch")
        else:
            require(delivered.get("Version") == "formal-minio-material-delivery.v1", "actual_formal_minio_delivery_receipt_required")
        for key in ("SourceSelection", "WriterSelection", "Deployment"):
            self.pin_value(delivered[key])
        selection = load(Path(delivered["SourceSelection"]["File"]))
        e, _ = self.web_modules()
        args = self.actual_pods(selection)
        before = self.with_original_kube(lambda: e.r.identity(args))
        if post_adoption:
            require(before["controller"] == original["identity"]["controller"], "controller_changed_reissue_uid_bound_grants")
        stage = "post-adoption-facts" if post_adoption else "rollout-refresh"
        value, out = self.invoke(stage, [self.root / "bin/system-backup-source-registries", "produce-facts", *common,
            "-source-selection-file", delivered["SourceSelection"]["File"], "-source-selection-sha256", delivered["SourceSelection"]["SHA256"]])
        after = self.with_original_kube(lambda: e.r.identity(args))
        require(before == after, "identity_changed_during_actual_facts_reissue_required")
        require(value["SelectionSHA256"] == delivered["SourceSelection"]["SHA256"], "facts_source_selection_changed")
        destination = "post-adoption-source-binding.json" if post_adoption else "final-rollout-binding.json"
        save(self.run / destination, {"delivery_receipt": {"File": str(receipt_file), "SHA256": sha(receipt_file)},
             "source_selection": delivered["SourceSelection"], "writer_selection": original["writer_selection"] if post_adoption else delivered["WriterSelection"],
             "deployment": delivered["Deployment"], "identity": after, "facts_receipt": {"File": str(out), "SHA256": sha(out)}})
        return {"state": "actual_final_pod_identity_and_source_facts_retained_not_adopted", "app_pod": args.app_pod, "controller_pod": args.controller_pod}

    def final_binding(self):
        self.open()
        source = self.run / "post-adoption-source-binding.json"
        binding = load(source if source.exists() else self.run / "final-rollout-binding.json")
        for key in ("delivery_receipt", "source_selection", "writer_selection", "deployment", "facts_receipt"):
            self.pin_value(binding[key])
        return binding

    def check_final_identity(self, binding):
        e, _ = self.web_modules()
        args = self.actual_pods(load(Path(binding["source_selection"]["File"])))
        expected = binding["identity"]
        recovered = self.run / "post-adoption-pod-comparison.json"
        if recovered.exists():
            after = load(recovered)
            require(after["controller"] == expected["controller"], "controller_changed_reissue_uid_bound_grants")
            expected = after
        require(self.with_original_kube(lambda: e.r.identity(args)) == expected, "final_pod_identity_changed_stop_reissue_bound_materials")
        return args

    def prepare_relay_runtime_trust(self):
        return c1_authors_module().prepare_relay_runtime_trust(self, production_adoption_module(), relay_bootstrap_module())

    def initial_runtime(self, action):
        require(action in ("initial-forward", "initial-publication", "initial-provider", "initial-provider-query", "initial-runtime") and self.a.action == action,
                "initial_issuer_action_changed")
        # Caller flags and core source are bound to the ORIGINAL real role
        # outputs; the native issuer independently checks all live authority.
        module = initial_runtime_module()
        if action == "initial-provider-query":
            module.restore_query_arguments(self)
        relay_trust = self.prepare_relay_runtime_trust()
        module.prepare_core_arguments(self)
        c1_authors_module().validate_core_relay_trust(self, relay_trust)
        self.bind_sql_role_arguments("publication-materials")
        if action == "initial-runtime" and (self.run / "adopt.readback.json").exists():
            production_adoption_module().runtime_continuation(self, module)
        if action == "initial-runtime":
            capture_mapping_module().prepare_inputs(self, production_adoption_module(), module)
        value = module.dispatch(self)
        if action == "initial-runtime":
            value["actual_capture_mapping"] = capture_mapping_module().finalize_mappings(self, production_adoption_module(), module, value)
        require(value.get("backup_ready") is False, "initial_material_action_cannot_claim_backup_ready")
        return value

    def original_runtime_sql_metadata(self):
        # Locators from actual provider CLI output only. This client gate does
        # not authenticate the signature/rows or claim that a census exists;
        # A's same-context, same-hold source Attach does that after SQL cut.
        file = getattr(self.a, "runtime_provider_receipt_file", None)
        digest = getattr(self.a, "runtime_provider_receipt_sha256", None)
        require((file is None) == (digest is None), "actual_provider_receipt_file_and_pin_required_together")
        produced = None
        if file is None:
            provider_path = self.run / "deployment/initial-provider.result.json"
            if not provider_path.exists():
                provider_path = self.run / "deployment/initial-provider-recovered.result.json"
            produced = load(provider_path)
            if produced.get("version") == "operator-initial-provider-recovered.v1":
                module = initial_runtime_module()
                tools = module.load("system-backup-operator-deployment.py", module.DEPLOYMENT_SHA)
                actual = module.read_provider_result(tools, produced)
                self.pin_value(actual["SQLMetadataReceipt"])
                return {"provider_query_receipt": produced["native_receipt"],
                        "provider_original_pending": produced["pending_provider_result"],
                        "provider_original_dispatch": produced["original_dispatch"],
                        "metadata": actual["SQLMetadataReceipt"]}
            require(produced.get("version") == "operator-initial-provider-authorities.v1", "actual_original_initial_provider_stage_receipt_required")
            native_pin = produced["native_receipt"]
        else:
            native_pin = {"File": str(file), "SHA256": digest}
        native = load(self.pin_value(native_pin))
        if produced is not None:
            require(native == produced["actual_producer_output"], "actual_initial_provider_native_output_changed")
        require(native.get("Version") == "original-runtime-provider-authorities-result.v1" and
                native.get("State") == "original_authority_and_capabilities_committed_readback_verified",
                "provider_sql_install_pending_or_unknown_no_adoption_no_resign")
        metadata_pin = native["SQLMetadataReceipt"]
        metadata_file = self.pin_value(metadata_pin)
        committed_file = regular(metadata_file.parent / "runtime-provider-authorities-committed.json", private=True)
        require(load(committed_file) == native, "actual_provider_committed_readback_marker_changed")
        return {"provider_cli_receipt": native_pin, "provider_committed_record": {"File": str(committed_file), "SHA256": sha(committed_file)},
                "metadata": metadata_pin}

    def require_current_runtime_qualification(self):
        # Deployment/runtime readback only. Genuine source ownership, native
        # physical writer proof and prepare/hold remain the original factory's
        # mandatory boundary; an inline-NFS locator is never that proof.
        binding = self.final_binding()
        core = load(self.pin_value(binding["deployment"]))
        work = core.get("workspace", {})
        nfs = work.get("nfs")
        if nfs is not None:
            require(work.get("claim", "") == "" and nfs.get("original_paths") and nfs.get("provider"),
                    "original_scoped_inline_NFS_input_and_provider_binding_required")
            scope = self.open()
            app = scope["app"]
            require(app["metadata"]["uid"] == scope["app_deployment_uid"] and core["namespace_uid"] == scope["namespace_uid"],
                    "original_application_UID_changed_before_NFS_capture")
            volumes = [v for v in app["spec"]["template"]["spec"].get("volumes", [])
                       if v.get("nfs", {}).get("server") == nfs["server"] and v["nfs"].get("path") == nfs["export"]]
            require(len(volumes) == 1, "actual_application_must_keep_original_inline_NFS_source")
            # The same signed Core is consumed by the Go NFS provider/SQL-path
            # checks and mandatory native source factory. No migration receipt
            # is manufactured and no shared server/foreign writer is stopped.
        else:
            workspace_module().verify_localized(self)
        return business_runtime_module().verify_current(self)

    def adoption(self, action):
        if action == "adopt":
            self.require_current_runtime_qualification()
        common = self.owner_common()
        binding = self.final_binding()
        argv = [self.root / "bin/system-backup-first-adoption", "-action"]
        if action == "adopt-prepare-issuers":
            self.check_final_identity(binding)
            directory = self.run / "adoption-issuers"; directory.mkdir(mode=0o700); sync_dir(self.run)
            value, out = self.invoke(action, [*argv, "prepare-issuers", *common, "-issuer-output-directory", directory])
            self.pin_value(value)
        elif action == "adopt-query":
            # Actual owner query only. It cannot substitute for the full
            # source-recovery receipt or authorize another adoption dispatch.
            return production_adoption_module().query(self)
        else:
            self.check_final_identity(binding)
            return production_adoption_module().adopt(self)
        return {"state": value.get("State", "actual_issuer_material_file_pinned"), "private_receipt": str(out), "page_backup_completed": False}

    def require_adopted(self):
        value = load(Path(self.completed("adopt")["stdout"]))
        production_adoption_module().validate_adoption(self, value)

    def composition(self, action):
        if action == "composition":
            self.require_current_runtime_qualification()
        self.require_adopted()
        binding = self.final_binding(); self.check_final_identity(binding)
        source = self.run / "composition-input-pins.json"
        if action == "composition-check":
            require((self.a.composition_file is None) == (self.a.deployment_file is None), "actual_composition_and_deployment_must_be_selected_together")
            prepared_path = self.run / "deployment/composition-prepare.result.json"
            if self.a.composition_file is None and prepared_path.exists():
                prepared = load(prepared_path)
                require(prepared["version"] == "operator-composition-prepare-result.v1", "actual_original_composition_producer_required")
                actual = prepared["actual_producer_output"]
                require(actual["Version"] == "original-composition-data-assembly-result.v1" and actual["configuration_mutated"] is False, "actual_data_assembly_receipt_required")
                composition = self.pin_value(actual["Composition"])
                deployment = self.pin_value(actual["Deployment"])
            else:
                composition_path = self.a.composition_file or self.run / "original-composition.json"
                deployment_path = self.a.deployment_file or self.run / "bootstrap-deployment.json"
                require(composition_path.is_file() and deployment_path.is_file(), "actual_signed_composition_and_final_deployment_missing_input")
                composition = regular(composition_path, private=True); deployment = regular(deployment_path, private=True)
            consumption_path = getattr(self.a, "bootstrap_consumption_file", None)
            actual_consumption = None
            if self.a.composition_file is None and prepared_path.exists():
                # Retain the exact real Go producer dispatch, not a fresh JSON
                # request or a guessed path after a lost original submission.
                receipt = self.pin_value(prepared["receipt"])
                require(load(receipt) == actual, "original_composition_producer_receipt_changed")
                sent = load(self.run / "deployment/prepare-composition.send-unknown.json")
                argv = sent["argv"]
                require(sent["stage"] == "prepare-composition" and argv[1] == "prepare-composition" and
                        argv.count("--consumption-file") == 1 and argv.count("--consumption-sha256") == 1,
                        "original_composition_consumption_dispatch_required")
                actual_consumption = {"File": argv[argv.index("--consumption-file") + 1],
                                      "SHA256": argv[argv.index("--consumption-sha256") + 1]}
                actual_path = self.pin_value(actual_consumption)
                require(consumption_path is None or consumption_path == actual_path, "original_composition_consumption_must_not_change")
                consumption_path = actual_path
            consumption_path = consumption_path or self.run / "bootstrap-consumption.json"
            require(consumption_path.is_file(), "actual_original_bootstrap_consumption_producer_input_missing")
            consumption = regular(consumption_path, private=True)
            pins = {"composition": {"File": str(composition), "SHA256": sha(composition)}, "deployment": {"File": str(deployment), "SHA256": sha(deployment)}, "consumption": actual_consumption or {"File": str(consumption), "SHA256": sha(consumption)}}
            save(source, pins)
        else:
            self.completed("composition-check")
            pins = load(source)
        for pin in pins.values(): self.pin_value(pin)
        value, out = self.invoke(action, [self.root / "bin/system-backup-bootstrap-enrolled", "--check" if action == "composition-check" else "--apply",
            "--deployment-file", pins["deployment"]["File"], "--deployment-sha256", pins["deployment"]["SHA256"],
            "--composition-file", pins["composition"]["File"], "--composition-sha256", pins["composition"]["SHA256"]])
        if action == "composition":
            require(value.get("status") == "disabled_config_initialized", "original_disabled_config_initialization_not_verified")
        return {"state": value.get("status"), "private_receipt": str(out), "configuration_enabled": False}

    def authenticated_api(self, e, ca, pin):
        enrollment = self.enrollment()
        plan = load(Path(enrollment["Plan"]["File"]))
        password = regular(PASSWORD, private=True).read_bytes().decode("utf-8")
        api = e.API("https://10.130.14.23:32643", ca, pin, "login_pre_auth")
        request = e.urllib.request.Request(api.origin + "/api/v1/auth/login", data=e.r.canonical({"username": plan["LocalAdminUsername"], "password": password}),
            headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
        password = None
        with api.opener.open(request, timeout=30) as response:
            require(response.code == 200 and response.headers.get_content_type() == "application/json", "normal_login_unconfirmed")
            login = e.r.decode(response.read(e.r.MAX + 1))
        token = login.get("data", {}).get("access_token")
        require(isinstance(token, str) and token and not any(c.isspace() for c in token), "normal_login_session_missing")
        api = e.API(api.origin, ca, pin, token)
        code, _, current = api.request("/api/v1/auth/me")
        user = current.get("data", {})
        require(code == 200 and user.get("username") == plan["LocalAdminUsername"] and user.get("role") == "admin", "normal_login_actor_not_original_admin")
        return api, plan["Target"]["InstallationID"]

    def composition_query(self):
        common = self.owner_common()
        require((self.run / "composition.send-unknown.json").exists(), "no_original_configuration_dispatch_to_query")
        pins = load(self.run / "composition-input-pins.json")
        for pin in pins.values(): self.pin_value(pin)
        value, out = self.invoke("composition-query", [self.root / "bin/system-backup-bootstrap-enrolled", "query-original", *common,
            "-bootstrap-deployment-file", pins["deployment"]["File"], "-bootstrap-deployment-sha256", pins["deployment"]["SHA256"],
            "-consumption-file", pins["consumption"]["File"], "-consumption-sha256", pins["consumption"]["SHA256"]], repeat=True)
        require(value.get("State") == "original_bootstrap_commit_exact_readback_only_no_new_write" and value.get("Result", {}).get("version") == 1,
                "original_bootstrap_readback_unconfirmed")
        seal = self.run / "original-composition-query-verified.json"
        if not seal.exists():
            save(seal, {"inspection": {"File": str(out), "SHA256": sha(out)}, "input_pins_sha256": sha(self.run / "composition-input-pins.json")})
        return {"state": value["State"], "operation_public_id": value["Result"]["operation_public_id"], "resubmit_allowed": False, "configuration_enabled": False}

    def assemble_composition(self):
        self.owner_common()
        deploy = deployment_module().DeploymentStages(self)
        _, _, _, sql = deploy.common()
        source = self.a.composition_source_directory or deploy.runtime_mirror() / "composition-sources"
        require(source.is_absolute() and source.resolve(strict=True) == source, "actual_composition_component_export_directory_required")
        files = {"classification-files-file": "functional-materials.receipt.json", "minio-terminal-file": "minio-terminal.receipt.json",
                 "signing-consumer-file": "signing-consumer.json", "signing-consumer-pin-file": "signing-consumer.sha256",
                 "kek-file": "installation-kek.material.json", "nonce-binding-file": "nonce.binding.json",
                 "artifact-ca-binding-file": "artifact-ca.binding.json", "evidence-ca-binding-file": "evidence-ca.binding.json",
                 "candidate-selections-file": "candidate-selections.json", "evidence-file": "original-evidence.json",
                 "capacity-report-file": "capacity-report.json"}
        require(all((source / name).is_file() for name in files.values()), "actual_original_composition_component_exports_missing")
        for name in files.values(): regular(source / name, private=True)
        business = sql["files"]["mysql-business.dsn"]; self.pin_value(business)
        flags = ["--capture-consumer-file", "/run/system-backup/installation-owner/capture-consumer.json",
                 "--mapping-directory", source / "original-mapping", "--registry-directory", source / "registries",
                 "--nonce-directory", source / "nonce", "--business-dsn-file", business["File"],
                 "--composition-output-file", self.run / "original-composition.json",
                 "--deployment-output-file", self.run / "bootstrap-deployment.json"]
        for flag, name in files.items(): flags += ["--" + flag, source / name]
        value, out = self.invoke("composition-assemble", [self.root / "bin/system-backup-bootstrap-enrolled", "assemble-original", *flags])
        require(value.get("State") == "original_composition_and_deployment_assembled_not_installed" and value.get("ConfigurationMutated") is False,
                "original_composition_assembly_unconfirmed")
        self.pin_value(value["Composition"]); self.pin_value(value["Deployment"])
        return {"state": value["State"], "composition": value["Composition"], "deployment": value["Deployment"], "private_receipt": str(out)}


    def require_configuration(self):
        if (self.run / "adopt.readback.json").exists():
            value = load(Path(self.completed("adopt")["stdout"]))
            production_adoption_module().validate_adoption(self, value)
            return
        completed = self.run / "composition.readback.json"
        if completed.exists():
            value = load(Path(self.completed("composition")["stdout"]))
            require(value.get("status") == "disabled_config_initialized", "original_disabled_configuration_not_verified")
            return
        verified = load(self.run / "original-composition-query-verified.json")
        require(verified["input_pins_sha256"] == sha(self.run / "composition-input-pins.json"), "original_composition_input_pins_changed")
        value = load(self.pin_value(verified["inspection"]))
        require(value.get("State") == "original_bootstrap_commit_exact_readback_only_no_new_write" and value.get("Result", {}).get("version") == 1,
                "original_disabled_configuration_not_verified")

    def normal_api(self, action):
        if action == "enable":
            self.require_current_runtime_qualification()
        self.open()
        e, resolver = self.web_modules()
        ca_pin_file = self.run / "web-ca-binding.json"
        if action == "enable":
            self.require_adopted(); self.require_configuration()
            binding = self.final_binding(); self.check_final_identity(binding)
            if (self.run/"production-adoption/capacity-collector-start-intent.json").exists():
                live_capacity_module().query(self)
            else:
                live_capacity_module().start(self, production_adoption_module(), c1_mysql_bridge_module(), c1_native_module())
            ca_path = self.a.web_ca_file or self.run / "web-ca.pem"
            require(ca_path.is_file(), "independently_delivered_web_ca_missing_input")
            ca = regular(ca_path)
            save(ca_pin_file, {"File": str(ca), "SHA256": sha(ca)})
        else:
            binding = self.final_binding()
        ca_pin = load(ca_pin_file); ca = regular(Path(ca_pin["File"]))
        require(sha(ca) == ca_pin["SHA256"], "original_web_ca_changed")
        api, installation = self.authenticated_api(e, ca, ca_pin["SHA256"])
        journal = self.run / "enable-journal"
        if action == "enable":
            save(self.run / "enable.send-unknown.json", {"stage": action, "installation": installation, "journal_directory": str(journal)})
            def prompt(message):
                if message == "Existing local admin password (hidden): ": return regular(PASSWORD, private=True).read_bytes().decode("utf-8")
                require(message == "Current enrolled TOTP code (hidden): ", "unexpected_strong_auth_prompt")
                return getpass.getpass(message)
            result = e.enable(api, installation, journal, lambda: self.check_final_identity(binding), prompt=prompt, verify_readiness=False)
            save(self.run / "enable.readback.json", result)
        elif action in ("enable-resolve", "enable-operation-export"):
            original, bound = resolver.journal(journal, installation)
            result = resolver.resolve(api, original, bound)
            if action == "enable-operation-export":
                require(result.get("status") == "ORIGINAL_ENABLE_COMMIT_VERIFIED" and result.get("config_version") == 2,
                        "original_enable_version2_commit_required_before_byte_export")
                self.check_final_identity(binding)
                raw, operation = api.operation_bytes(result["operation_public_id"])
                require(operation.get("schema_version") == "system-backup-operation.v1" and operation.get("origin_installation_id") == installation and
                        operation.get("idempotency_key") == original["idempotency_key"] and operation.get("request_hash") == bound["request_hash"] and
                        operation.get("actor_id") == bound["actor_id"] and operation.get("actor_type") == "admin" and operation.get("target_type") == "system" and
                        operation.get("target_public_id") == installation and operation.get("endpoint") == "updateSystemBackupConfig" and
                        operation.get("status") == "succeeded" and operation.get("result_config_version") == 2 and operation.get("http_status") == 200,
                        "original_enable_http_operation_binding_changed")
                self.check_final_identity(binding)
                e.save_bytes(journal, "operation-response-observed-" + secrets.token_hex(8) + ".raw.json", raw)
                output = journal / "operation-response.raw.json"
                if output.exists():
                    require(regular(output, private=True).read_bytes() == raw, "original_enable_http_operation_bytes_changed_retain_both_sources")
                else:
                    e.save_bytes(journal, output.name, raw)
                result = {"status": "ORIGINAL_ENABLE_HTTP_OPERATION_BYTES_RETAINED", "operation": {"File": str(output), "SHA256": sha(output)},
                          "operation_public_id": operation["public_id"], "native_enable_authority_proved": False,
                          "deployment_readiness_verified": False, "resubmit_allowed": False}
            # Historical commit readback does not imply present readiness.
            save(self.run / ("enable-resolve-" + secrets.token_hex(8) + ".readback.json"), result)
        else:
            self.check_final_identity(binding)
            result = e.r.verify_api(api, installation, False)
            self.check_final_identity(binding)
            save(self.run / ("readiness-" + secrets.token_hex(8) + ".readback.json"), result)
        return result


def deployment_module():
    path = regular(Path(__file__).resolve().with_name("system-backup-operator-deployment.py"))
    require(sha(path) == DEPLOYMENT_MODULE_SHA, "reviewed_deployment_module_changed")
    spec = importlib.util.spec_from_file_location("original_operator_deployment", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def owner_assembly_module():
    path = regular(Path(__file__).resolve().with_name("system-backup-publication-owner-assembly.py"))
    require(sha(path) == OWNER_ASSEMBLY_SHA, "reviewed_owner_assembly_module_changed")
    spec = importlib.util.spec_from_file_location("original_owner_input_assembly", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def runtime_issuer_module():
    path = regular(Path(__file__).resolve().with_name("system-backup-runtime-issuers.py"))
    require(sha(path) == RUNTIME_ISSUER_SHA, "reviewed_runtime_issuer_module_changed")
    spec = importlib.util.spec_from_file_location("original_runtime_issuer_material", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def business_runtime_module():
    path = regular(Path(__file__).resolve().with_name("system-backup-business-runtime.py"))
    require(sha(path) == BUSINESS_RUNTIME_SHA, "reviewed_business_runtime_module_changed")
    spec = importlib.util.spec_from_file_location("original_business_runtime_rollout", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record_export_module():
    path = regular(Path(__file__).resolve().with_name("system-backup-runtime-record-keys.py"))
    require(sha(path) == RECORD_EXPORT_SHA, "reviewed_record_export_module_changed")
    spec = importlib.util.spec_from_file_location("original_runtime_record_export", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def initial_runtime_module():
    path = regular(Path(__file__).resolve().with_name("system-backup-initial-runtime.py"))
    require(sha(path) == INITIAL_RUNTIME_SHA, "reviewed_initial_runtime_module_changed")
    spec = importlib.util.spec_from_file_location("original_initial_runtime_issuers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_EXACT_MODULES = {}


def exact_module(name, expected):
    path = regular(Path(__file__).resolve().with_name(name))
    require(sha(path) == expected, "reviewed_workspace_entry_dependency_changed")
    if name in _EXACT_MODULES:
        return _EXACT_MODULES[name]
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _EXACT_MODULES[name] = module
    return module


def workspace_module():
    return exact_module("system-backup-workspace-localization.py", WORKSPACE_SHA)


def early_preflight_module():
    return exact_module("system-backup-workspace-source-preflight.py", EARLY_PREFLIGHT_SHA)


def nonce_module():
    return exact_module("system-backup-operator-nonce.py", "82cc9588564b5c5ac11e67fbdb44be56f434cc2142679ee79f745b59bf2591e3")


def c1_mysql_bridge_module():
    return exact_module("system-backup-operator-c1-mysql-bridge.py", "9c11524728cda9bfa07333ff1e36aae1c364b7f08e8c9827320bad313672e985")


def c1_native_module():
    return exact_module("system-backup-operator-c1-native.py", "4ea935ba88ea47af46283e4c03cc3707b5b748ca5d09258bc6b0e6b0490a9766")


def live_capacity_module():
    return exact_module("system-backup-operator-live-capacity.py", "16063a272ee080c10b1748e089f59821e8b2c2c573c643fc488020e0d66ec0e1")


def c1_authors_module():
    return exact_module("system-backup-operator-c1-authors.py", "20512097e2e24011389694fc2c2b51a92b24f5bf8682dc5b1e251bd116ab6460")


def relay_bootstrap_module():
    return exact_module("system-backup-operator-relay-bootstrap.py", "0f94b8b520756df24fdc5722209708259a8b4d436c38fb26412f38ea88976247")


def production_adoption_module():
    return exact_module("system-backup-operator-first-adoption-production.py", "9dab99390a92de35eac4c45033e37d616b7b85736cbabf2592a0ed19f4781225")


def adoption_locations_module():
    return exact_module("system-backup-operator-adoption-locations.py", "ba0d8be54933807210e2a5d41d933d3721ba3e65aa0c2246d8ac94509d71cf0f")


def minio_recovery_module():
    return exact_module("system-backup-operator-minio-recovery.py", "f77f0ff3e7abefb24e257716dfde892f822580b1e4ca7e6a265f9f521245d552")


def c1_inputs_module():
    return exact_module("system-backup-operator-c1-inputs.py", "655258e7de58aa90600cec2e4695c7eda84621448cca7606e085c01057edc693")


def archive_inputs_module():
    return exact_module("system-backup-operator-archive-inputs.py", "39bc5ac510f4c979541f9b41f448309d15e43fc5789e9c4421a91d11ddf7dbc0")


def minio_consent_module():
    return exact_module("system-backup-operator-minio-consent.py", "2285d0a5c31adf8ed3a774c39b2302c6e87d61b449431fe4a8e4d645475f2a97")


def capture_mapping_module():
    return exact_module("system-backup-operator-capture-mapping.py", "2e2d8524d7a28f39427e8d39219369512658588568f11566a6eafa6a874363c0")


def enabled_publication_module():
    return exact_module("system-backup-operator-enabled-publication.py", "36547ca5ac5c3a0a5499f9494037dda5054a0f2e2d86e55afcb2d8071d73576a")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choices = ["seal-release", "init", "observe", "status", "sql-role-inputs", *["db-" + a for a in DB_ACTIONS],
               "tls-inspect", "tls-apply", "tls-rollback", "materials-signing", "runtime-issuers", "runtime-issuers-query", "runtime-record-keys", "initial-forward", "initial-publication", "initial-provider", "initial-provider-query", "initial-runtime", "writer-selection", "runtime-images", "runtime-rollout", "runtime-query", "deployment-query", "publication-materials", "prepare-composition", "post-adoption-facts", "adopt-prepare-issuers", "adopt-query", *production_adoption_module().PREPARE, "composition-check", "composition-query", "enable-resolve", "enable-operation-export", "readiness", *["sql-" + a for a in ("inspect", "prepare", "apply", "query", "rollback", "enroll")], *IMPLEMENTED_STAGES, *WORKSPACE_ACTIONS, "nonce-issue", "nonce-resume", "nonce-bind", "c1-mysql-mount-probe", "composition-assemble", *BLOCKERS]
    choices += list(minio_recovery_module().ACTIONS)
    choices += list(c1_inputs_module().ACTIONS)
    choices += list(c1_native_module().ACTIONS)
    choices += list(c1_authors_module().ACTIONS)
    choices += list(live_capacity_module().ACTIONS)
    choices += list(archive_inputs_module().ACTIONS)
    choices += list(minio_consent_module().ACTIONS)
    choices += list(enabled_publication_module().ACTIONS)
    choices += ["initial-runtime-test-scope", "initial-runtime-test-scope-query"]
    choices += ["initial-source-inputs", "initial-providers-prepare", "initial-providers-apply", "initial-providers-query", "initial-providers-finalize"]
    choices += ["initial-source-coordinates", "initial-source-api-inputs", "initial-source-api-finalize", "initial-redis-source", "initial-redis-query", "initial-redis-recover", "initial-redis-recover-finalize"]
    choices += list(capture_mapping_module().ACTIONS)
    parser.add_argument("action", choices=choices)
    parser.add_argument("--release-directory", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--run-directory", type=Path, default=Path("/root/.clawmanager-backup-install/zhanghui08-original199-20261105"))
    parser.add_argument("--source-repository", type=Path)
    parser.add_argument("--sql-account-host")
    parser.add_argument("--allow-wildcard-host", action="store_true")
    parser.add_argument("--delivery-receipt-file", type=Path)
    parser.add_argument("--composition-file", type=Path)
    parser.add_argument("--deployment-file", type=Path)
    parser.add_argument("--web-ca-file", type=Path)
    parser.add_argument("--copy-receipts-directory", type=Path)
    parser.add_argument("--composition-source-directory", type=Path)
    parser.add_argument("--bootstrap-consumption-file", type=Path)
    parser.add_argument("--runtime-provider-receipt-file", type=Path)
    parser.add_argument("--runtime-provider-receipt-sha256")
    for name in ("writer-source-config", "writer-gateway-original-key"):
        parser.add_argument("--" + name + "-file", type=Path)
        parser.add_argument("--" + name + "-sha256")
    parser.add_argument("--writer-gateway-original-directory", type=Path)
    parser.add_argument("--writer-participant", action="append")
    try:
        deployment = deployment_module()
        deployment.register_arguments(parser)
        owner_inputs = owner_assembly_module()
        owner_inputs.register_arguments(parser)
        business_runtime_module().register_arguments(parser)
        initial_runtime_module().register_arguments(parser)
        early_preflight = early_preflight_module()
        nonce_module().register_arguments(parser)
        production_adoption_module().register_arguments(parser)
        adoption_locations_module().register_arguments(parser)
        minio_recovery_module().register_arguments(parser)
        c1_inputs_module().register_arguments(parser)
        archive_inputs_module().register_arguments(parser)
    except Exception:
        print(json.dumps({"state": "STOP_REVIEWED_DEPLOYMENT_MODULE_MISSING_OR_CHANGED"}))
        return 3
    parser.set_defaults(deployment_vault_state_directory=Path("/root/sbk-vault-owner-20261102-01"))
    a = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if a.action == "seal-release":
            require(a.source_repository is not None, "actual_source_repository_required_for_page_fix_ancestry")
            result = seal_release(a)
        else:
            require(fcntl is not None and os.geteuid() == 0, "original_linux_root_operator_required")
            tool = Operator(a)
            if a.action == "init":
                result = tool.init()
            else:
                with (a.run_directory / "operator-command.lock").open("a+b") as lock:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    if a.action == "c1-mysql-mount-probe":
                        result = c1_mysql_bridge_module().probe(tool)
                    elif a.action in ("nonce-issue", "nonce-resume", "nonce-bind"):
                        result = nonce_module().dispatch(tool)
                    elif a.action in WORKSPACE_ACTIONS:
                        if a.action == "workspace-source-preflight": result = early_preflight_module().dispatch(tool)
                        elif a.action == "workspace-source-preflight-cleanup": result = early_preflight_module().cleanup(tool)
                        else: result = workspace_module().dispatch(tool)
                    elif a.action == "new-image" and (tool.run / "deployment/workspace-localization.plan.json").exists():
                        result = workspace_module().verify_app_overlay(tool)
                    elif a.action == "sql-role-inputs":
                        result = tool.sql_role_inputs()
                    elif a.action in ("runtime-images", "runtime-rollout", "runtime-query"):
                        result = tool.business_runtime(a.action)
                    elif a.action in ("new-image", "host-observer", "materials", "materials-signing", "deployment-query"):
                        if a.action in ("host-observer", "materials", "materials-signing"):
                            business_runtime_module().verify_current(tool)
                        if a.action == "materials":
                            tool.prepare_relay_runtime_trust()
                            initial_runtime_module().bind_complete_source_arguments(tool)
                            tool.bind_writer_selection_argument()
                        if a.action in ("host-observer", "materials", "materials-signing"):
                            tool.require_current_runtime_qualification()
                        if a.action == "materials":
                            initial_runtime_module().prepare_minio_options_arguments(tool)
                        result = deployment.dispatch(tool, a.action)
                        if a.action == "materials" and (tool.run / "deployment/initial-source-api-inputs.result.json").exists():
                            result = initial_runtime_module().prepare_source_api_successor_arguments(tool)
                    elif a.action in ("initial-runtime-test-scope", "initial-runtime-test-scope-query"):
                        result = initial_runtime_module().prepare_runtime_test_scope_arguments(tool, query_only=a.action.endswith("-query"))
                    elif a.action == "initial-source-inputs":
                        tool.require_current_runtime_qualification()
                        pin = initial_runtime_module().prepare_complete_source_arguments(tool)
                        result = load(tool.pin_value(pin))
                    elif a.action.startswith("initial-providers-"):
                        result = initial_runtime_module().prepare_complete_source_arguments(tool, a.action.removeprefix("initial-providers-"))
                    elif a.action in ("initial-redis-source", "initial-redis-query", "initial-redis-recover", "initial-redis-recover-finalize"):
                        if a.action == "initial-redis-source":
                            tool.require_current_runtime_qualification()
                        mode = "prepare" if a.action == "initial-redis-source" else a.action.removeprefix("initial-redis-")
                        result = initial_runtime_module().prepare_redis_source_arguments(tool, mode)
                    elif a.action == "initial-source-api-inputs":
                        result = initial_runtime_module().prepare_source_api_arguments(tool)
                    elif a.action == "initial-source-coordinates":
                        result = initial_runtime_module().prepare_source_coordinates_arguments(tool)
                    elif a.action == "initial-source-api-finalize":
                        result = initial_runtime_module().prepare_source_api_successor_arguments(tool)
                    elif a.action in ("initial-forward", "initial-publication", "initial-provider", "initial-provider-query", "initial-runtime"):
                        result = tool.initial_runtime(a.action)
                    elif a.action == "runtime-record-keys":
                        result = record_export_module().prepare(tool)
                    elif a.action == "writer-selection":
                        result = tool.prepare_writer_selection()
                    elif a.action in ("runtime-issuers", "runtime-issuers-query"):
                        result = runtime_issuer_module().prepare(tool, query=a.action.endswith("-query"))
                    elif a.action in ("publication-materials", "prepare-composition"):
                        tool.bind_sql_role_arguments(a.action)
                        if a.action == "prepare-composition":
                            minio_recovery_module().bind_terminal_argument(tool)
                        result = owner_inputs.dispatch(tool)
                    elif a.action in ("rollout-refresh", "post-adoption-facts"): result = tool.rollout_refresh()
                    elif a.action in production_adoption_module().PREPARE: result = production_adoption_module().prepare(tool, a.action, initial_runtime_module())
                    elif a.action in minio_recovery_module().ACTIONS: result = minio_recovery_module().dispatch(tool, a.action, production_adoption_module())
                    elif a.action in live_capacity_module().ACTIONS: result = live_capacity_module().dispatch(tool, production_adoption_module(), c1_mysql_bridge_module(), c1_native_module())
                    elif a.action in c1_authors_module().ACTIONS: result = c1_authors_module().dispatch(tool, production_adoption_module(), relay_bootstrap_module(), c1_native_module())
                    elif a.action in c1_native_module().ACTIONS: result = c1_native_module().prepare_capacity(tool, production_adoption_module(), c1_mysql_bridge_module(), {"adopt-prepare-capacity":"issue", "adopt-query-capacity":"query", "adopt-rollback-capacity":"rollback"}[a.action])
                    elif a.action in c1_inputs_module().ACTIONS: result = c1_inputs_module().prepare(tool, production_adoption_module(), query=a.action == "adopt-query-c1-evidence-material")
                    elif a.action in archive_inputs_module().ACTIONS: result = archive_inputs_module().prepare(tool, production_adoption_module(), query=a.action == "adopt-query-archive-materials")
                    elif a.action in minio_consent_module().ACTIONS: result = minio_consent_module().prepare(tool, production_adoption_module(), initial_runtime_module(), query=a.action == "minio-runtime-consent-query")
                    elif a.action in capture_mapping_module().ACTIONS: result = capture_mapping_module().dispatch(tool, production_adoption_module(), initial_runtime_module())
                    elif a.action in enabled_publication_module().ACTIONS: result = enabled_publication_module().dispatch(tool, production_adoption_module(), initial_runtime_module())
                    elif a.action in ("adopt-prepare-issuers", "adopt", "adopt-query"): result = tool.adoption(a.action)
                    elif a.action == "composition-assemble": result = tool.assemble_composition()
                    elif a.action == "composition-query": result = tool.composition_query()
                    elif a.action in ("composition-check", "composition"): result = tool.composition(a.action)
                    elif a.action in ("enable", "enable-resolve", "enable-operation-export", "readiness"): result = tool.normal_api(a.action)
                    elif a.action in BLOCKERS:
                        if a.action == "page":
                            tool.require_current_runtime_qualification()
                        print(json.dumps({"state": "STOP_MISSING_ACTUAL_PRODUCER_NOT_IMPLEMENTED", "stage": a.action, "required_callpoints": BLOCKERS[a.action]}))
                        return 2
                    elif a.action.startswith("db-"): result = tool.db(a.action[3:])
                    elif a.action.startswith("tls-"): result = tool.tls(a.action[4:])
                    elif a.action.startswith("sql-"): result = tool.sql(a.action[4:])
                    elif a.action == "observe": result = tool.observe()
                    else: result = tool.status_read()
        print(json.dumps(result))
        return 0
    except early_preflight.EarlyPreflightRefused as error:
        print(json.dumps(error.result))
        return 3
    except Stop as error:
        print(json.dumps({"state": "STOP_RETAIN_SAME_OPERATION", "reason_code": str(error), "action": a.action,
                          "run_directory": str(a.run_directory), "automatic_retry": False, "original_adoption_completed": False}))
        return 3
    except (Exception, KeyboardInterrupt):
        print(json.dumps({"state": "STOP_PRIVATE_ERROR_OR_UNKNOWN_NATIVE_OUTCOME", "action": a.action,
                          "run_directory": str(a.run_directory), "automatic_retry": False, "original_adoption_completed": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
