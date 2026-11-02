"""Mock only. No kubectl, SQL, subprocess execution, filesystem writes or network."""
import copy
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

SCRIPT = Path(__file__).with_name("system-backup-d-v2-config-observe.py")
spec = importlib.util.spec_from_file_location("v2observe", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
DEPLOY_UID = "11111111-2222-3333-4444-555555555555"
RS_UID = "22222222-2222-3333-4444-555555555555"
POD_UID = "33333333-2222-3333-4444-555555555555"
SERVER_UID = "44444444-2222-3333-4444-555555555555"


def wire(items):
    return ("\n".join(json.dumps(item) for item in items) + "\n").encode()


def owner(kind, name, uid):
    return {"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": True}


def obj(kind, name, uid):
    return {"kind": kind, "metadata": {"namespace": m.NAMESPACE, "name": name, "uid": uid}}


class ObserveTests(unittest.TestCase):
    def setUp(self):
        self.ns = {"metadata": {"name": m.NAMESPACE, "uid": m.NAMESPACE_UID}}
        self.deployment = obj("Deployment", "mysql", DEPLOY_UID)
        self.deployment["spec"] = {"selector": {"matchLabels": {"app": "mysql"}},
            "template": {"spec": {"containers": [{"name": "mysql", "image": "private/mysql@sha256:" + "a" * 64}]}}}
        self.rs = obj("ReplicaSet", "mysql-rs", RS_UID)
        self.rs["metadata"]["ownerReferences"] = [owner("Deployment", "mysql", DEPLOY_UID)]
        self.pod = obj("Pod", "mysql-rs-pod", POD_UID)
        self.pod["metadata"]["ownerReferences"] = [owner("ReplicaSet", "mysql-rs", RS_UID)]
        self.pod["spec"] = copy.deepcopy(self.deployment["spec"]["template"]["spec"])
        self.pod["status"] = {"phase": "Running", "containerStatuses": [{"name": "mysql", "ready": True,
            "state": {"running": {}}, "containerID": "containerd://" + "b" * 64}]}
        self.server = {"kind": "server", "server_uuid": SERVER_UID, "server_version": "8.4.8", "database": "actual_container_database"}
        self.tables = set(m.EXPECTED)
        self.columns = {table: set(names) for table, names in m.EXPECTED.items()}
        self.summary = [self.server,
            {"kind": "installation", "installation_sha256": "c" * 64, "active_config_version": 7,
             "last_effective_enabled": 1, "matrix_key": "k8s-cluster", "row_version": 12},
            {"kind": "config", "installation_sha256": "c" * 64, "version": 7, "enabled": 1,
             "config_size_bytes": 1234, "config_sha256": "d" * 64, "canonical_present": 1,
             "canonical_length_matches": 1, "canonical_hash_matches": 1},
            {"kind": "kek_mapping_count", "count": 1}, {"kind": "kek_binding_count", "count": 1},
            {"kind": "kek_admission_count", "count": 1}, {"kind": "capability_snapshot_count", "count": 2}]
        self.calls, self.sql_calls = [], []
        self.exec_rc = 0
        self.patch = patch.object(m.subprocess, "run", side_effect=self.subprocess)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def subprocess(self, args, input=None, capture_output=None, timeout=None):
        self.assertEqual(args[:3], ["kubectl", "--context=" + m.CONTEXT, "--request-timeout=20s"])
        self.assertTrue(capture_output)
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 40)
        self.calls.append(args)
        cmd = args[3:]
        if "exec" in cmd:
            self.assertEqual(cmd[:8], ["-n", m.NAMESPACE, "exec", "-i", "mysql-rs-pod", "-c", "mysql", "--"])
            self.assertEqual(cmd[8:], ["/bin/sh", "-c", m.AUTH_SHELL])
            self.assertIsInstance(input, bytes)
            sql = input.decode()
            self.assertTrue(sql.startswith("START TRANSACTION READ ONLY;\n"))
            self.assertTrue(sql.endswith("\nROLLBACK;\n"))
            for statement in sql.split(";")[1:-2]:
                self.assertTrue(statement.strip().startswith("SELECT /*+ MAX_EXECUTION_TIME(5000) */"))
            self.sql_calls.append(sql)
            if self.exec_rc:
                return SimpleNamespace(returncode=self.exec_rc, stdout=b"private canonical text", stderr=b"password=DO_NOT_LEAK")
            if "information_schema.COLUMNS" in sql:
                output = [self.server] + [{"kind": "table", "table": table} for table in sorted(self.tables)]
                output += [{"kind": "column", "table": table, "column": column} for table in sorted(self.tables) for column in sorted(self.columns[table])]
                return SimpleNamespace(returncode=0, stdout=wire(output), stderr=b"")
            return SimpleNamespace(returncode=0, stdout=wire(self.summary), stderr=b"")
        self.assertIsNone(input)
        if cmd[:2] == ["get", "namespace"]:
            output = self.ns
        elif cmd[:3] == ["-n", m.NAMESPACE, "get"]:
            output = {"deployment": self.deployment, "replicaset": self.rs, "pod": self.pod}[cmd[3]]
        elif cmd[0] == "get" and "/replicasets?" in cmd[1]:
            self.assertIn("/namespaces/" + m.NAMESPACE + "/", cmd[1])
            self.assertIn("labelSelector=app%3Dmysql", cmd[1])
            self.assertIn("limit=16", cmd[1])
            output = {"metadata": {}, "items": [self.rs]}
        elif cmd[0] == "get" and "/pods?" in cmd[1]:
            self.assertIn("/namespaces/" + m.NAMESPACE + "/", cmd[1])
            output = {"metadata": {}, "items": [self.pod]}
        else:
            self.fail("Unexpected mock command; no external execution allowed")
        return SimpleNamespace(returncode=0, stdout=json.dumps(output).encode(), stderr=b"")

    def test_complete_metadata_is_read_only_and_not_an_authorization(self):
        report = m.Observer().run()
        self.assertEqual(report["database"], "actual_container_database")
        self.assertEqual(report["server_uuid"], SERVER_UID)
        self.assertEqual(report["pod_uid"], POD_UID)
        self.assertFalse(report["authenticated_config"])
        self.assertFalse(report["tls_verified"])
        self.assertFalse(report["permissions_verified"])
        self.assertFalse(report["coverage_verified"])
        self.assertEqual(len(self.sql_calls), 2)
        self.assertIn("BINARY SHA2(c.canonical_config_json,256)=BINARY c.config_sha256", self.sql_calls[1])
        encoded = json.dumps(report)
        self.assertNotIn("signed_record", json.dumps(report["observations"]))
        self.assertNotIn("canonical_config_json", json.dumps(report["observations"]))
        self.assertNotIn("DO_NOT_LEAK", encoded)
        self.assertFalse(any("secret" in arg or arg in ("apply", "create", "patch", "delete") for args in self.calls for arg in args))

    def test_missing_tables_report_normally_without_data_queries(self):
        self.tables = set()
        self.summary = [self.server]
        report = m.Observer().run()
        self.assertTrue(all(not item["present"] for item in report["tables"].values()))
        self.assertEqual(report["observations"], [])
        self.assertNotIn(" FROM ", self.sql_calls[1])

    def test_missing_canonical_column_is_never_queried(self):
        self.columns[m.CONFIG].remove("canonical_config_json")
        for key in ("canonical_present", "canonical_length_matches", "canonical_hash_matches"):
            self.summary[2][key] = None
        report = m.Observer().run()
        self.assertIn("canonical_config_json", report["tables"][m.CONFIG]["missing_columns"])
        self.assertNotIn("c.canonical_config_json", self.sql_calls[1])

    def test_missing_state_column_skips_all_installation_scoped_queries(self):
        self.columns[m.STATE].remove("origin_installation_id")
        self.summary = [self.server]
        report = m.Observer().run()
        self.assertEqual(report["skipped"]["active_config_rows"], "missing_required_columns")
        self.assertNotIn(" FROM ", self.sql_calls[1])

    def test_namespace_uid_change_refuses_before_exec(self):
        self.ns["metadata"]["uid"] = POD_UID
        with self.assertRaises(m.Refused): m.Observer().run()
        self.assertFalse(self.sql_calls)

    def test_foreign_replicaset_owner_refuses_before_exec(self):
        self.rs["metadata"]["ownerReferences"][0]["uid"] = POD_UID
        with self.assertRaises(m.Refused): m.Observer().run()
        self.assertFalse(self.sql_calls)

    def test_pod_owner_changed_after_discovery_refuses_before_exec(self):
        observer = m.Observer()
        observer.discover()
        self.pod["metadata"]["ownerReferences"][0]["uid"] = DEPLOY_UID
        with self.assertRaises(m.Refused): observer.sql(m.metadata_sql())
        self.assertFalse(self.sql_calls)

    def test_mysql_restart_after_discovery_refuses_before_exec(self):
        observer = m.Observer()
        observer.discover()
        self.pod["status"]["containerStatuses"][0]["containerID"] = "containerd://" + "e" * 64
        with self.assertRaises(m.Refused): observer.sql(m.metadata_sql())
        self.assertFalse(self.sql_calls)

    def test_pod_uid_change_after_discovery_refuses_before_exec(self):
        observer = m.Observer()
        observer.discover()
        self.pod["metadata"]["uid"] = DEPLOY_UID
        with self.assertRaises(m.Refused): observer.sql(m.metadata_sql())
        self.assertFalse(self.sql_calls)

    def test_missing_named_mysql_container_refuses_before_exec(self):
        self.pod["spec"]["containers"][0]["name"] = "unrelated"
        with self.assertRaises(m.Refused): m.Observer().run()
        self.assertFalse(self.sql_calls)

    def test_server_identity_change_discards_observations(self):
        self.summary[0] = dict(self.server, server_uuid=DEPLOY_UID)
        with self.assertRaises(m.Refused): m.Observer().run()

    def test_unexpected_raw_payload_field_is_never_printed(self):
        self.summary[2]["canonical_config_json"] = "PRIVATE BODY"
        output = io.StringIO()
        with patch.object(m.sys, "argv", [str(SCRIPT)]), redirect_stdout(output):
            self.assertEqual(m.main(), 1)
        self.assertNotIn("PRIVATE BODY", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "refused")

    def test_missing_credential_is_fixed_refusal_without_stderr(self):
        self.exec_rc = 43
        output = io.StringIO()
        with patch.object(m.sys, "argv", [str(SCRIPT)]), redirect_stdout(output):
            self.assertEqual(m.main(), 1)
        self.assertEqual(json.loads(output.getvalue())["reason"], "existing_root_password_missing_or_ambiguous")
        self.assertNotIn("DO_NOT_LEAK", output.getvalue())
        self.assertNotIn("private canonical", output.getvalue())
        self.assertEqual(len(self.sql_calls), 1)

    def test_no_default_or_login_file_fallback_and_no_password_in_args(self):
        self.assertIn("mysql --no-defaults --no-login-paths", m.AUTH_SHELL)
        self.assertIn("MYSQL_DATABASE", m.AUTH_SHELL)
        self.assertIn("MYSQL_ROOT_PASSWORD_FILE", m.AUTH_SHELL)
        self.assertNotIn("--password", m.AUTH_SHELL)
        self.assertNotIn("printenv", m.AUTH_SHELL)
        self.assertNotIn("echo", m.AUTH_SHELL)
        self.assertEqual(m.AUTH_SHELL.count("cat --"), 1)

    def test_timeout_is_bounded_and_error_details_withheld(self):
        with patch.object(m.subprocess, "run", side_effect=m.subprocess.TimeoutExpired("private", 1)):
            with self.assertRaises(m.Refused) as error: m.Observer().run()
        self.assertEqual(error.exception.reason, "kubectl_unavailable_or_timeout")


if __name__ == "__main__":
    unittest.main()
