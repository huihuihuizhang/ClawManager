"""Mock-only transport regressions; no kubectl/MySQL/process is executed."""
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name("system-backup-app-readonly-preflight-20261103-v2.py")
SPEC = importlib.util.spec_from_file_location("readonly_preflight", SOURCE)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
CATALOG = SOURCE.parent.parent / "docs/evidence/system-backup-d-app-upgrade-catalog-20261103.json"
UUID = "11111111-1111-4111-8111-111111111111"


class ReadonlyTests(unittest.TestCase):
    def setUp(self):
        tool.REPORT = {"read_only": True, "independent_installation_authorization": False, "backup_readiness_established": False}

    def observe(self, missing=0, ledger_present=True):
        names = json.loads(CATALOG.read_text(encoding="utf-8"))["filenames"]
        flags = {key: "" for key in tool.FLAGS}
        flags["DB_NAME"] = "original_database"
        calls = []

        def fake_get(kind, name):
            if kind == "namespace":
                return {"metadata": {"uid": tool.NS_UID}}
            uid = tool.APP_UID if name == tool.APP else tool.MYSQL_UID
            return {"metadata": {"uid": uid, "resourceVersion": "123"}, "spec": {"template": {"spec": {"containers": [{"name": tool.APP, "image": "original:fix18"}]}}}}

        def fake_kube(*args, stdin=None):
            calls.append((args, stdin))
            self.assertEqual(args[0], "exec")
            if stdin is None:
                if args[1] == "original-app":
                    return "\n".join(key + "\t" + value for key, value in flags.items())
                return "original_database\n"
            self.assertTrue(stdin.startswith("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY;\n"))
            self.assertTrue(stdin.endswith("\nCOMMIT;\n"))
            self.assertNotIn("--password", str(args))
            self.assertNotIn("tcp", str(args))
            if "SELECT @@server_uuid" in stdin:
                return UUID + "\toriginal_database\n"
            if "information_schema.TABLES" in stdin:
                return "1\n" if ledger_present else "0\n"
            self.assertIn("SELECT filename FROM schema_migrations ORDER BY filename", stdin)
            return "\n".join(names[missing:]) + "\n"

        def pod(dep, container):
            return {"metadata": {"name": "original-app" if container == tool.APP else "original-mysql", "uid": "pod-uid"}, "status": {"containerStatuses": [{"name": container, "ready": True, "image": "original:fix18", "imageID": "containerd://sha256:" + "a" * 64}]}}

        args = types.SimpleNamespace(observe=True, database=None, expected_server_uuid=None, catalog=CATALOG)
        with patch.object(tool, "get", side_effect=fake_get), patch.object(tool, "ready_original_pod", side_effect=pod), patch.object(tool, "kube", side_effect=fake_kube):
            tool.main(args)
        return names, calls

    def test_observe_needs_no_known_database_or_uuid_and_grants_no_authority(self):
        self.observe()
        self.assertEqual(tool.REPORT["database"]["server_uuid"], UUID)
        self.assertFalse(tool.REPORT["database"]["identity_compared_to_expected"])
        self.assertFalse(tool.REPORT["independent_installation_authorization"])
        self.assertEqual(tool.REPORT["application"]["ready_container_image_id"], "containerd://sha256:" + "a" * 64)
        self.assertIn("not inferred", tool.REPORT["application"]["image_id_interpretation"])
        self.assertEqual(tool.REPORT["migrations"]["missing"], [])
        self.assertFalse(tool.REPORT["migrations"]["next_app_start_would_attempt_pending_DDL"])

    def test_actual_missing_names_are_reported_without_running_pending_sql(self):
        names, calls = self.observe(missing=2)
        self.assertEqual(tool.REPORT["migrations"]["missing"], names[:2])
        self.assertTrue(tool.REPORT["migrations"]["next_app_start_would_attempt_pending_DDL"])
        self.assertTrue(tool.REPORT["next_step"].startswith("DO_NOT_REPLACE_APP_IMAGE_YET"))
        self.assertTrue(all("CREATE TABLE" not in (stdin or "") for _, stdin in calls))

    def test_absent_ledger_reports_all177_without_creating_schema_migrations(self):
        names, calls = self.observe(ledger_present=False)
        self.assertFalse(tool.REPORT["migrations"]["ledger_table_present"])
        self.assertEqual(tool.REPORT["migrations"]["missing"], names)
        self.assertEqual(len([stdin for _, stdin in calls if stdin]), 2)

    def test_startup_fatal_is_separate_from_only_backup_not_ready(self):
        flags = {key: "" for key in tool.FLAGS}
        result = tool.classify(flags)
        self.assertFalse(result["source_proven_fatal"])
        self.assertTrue(result["backup_not_ready_or_unverified_only"])
        flags["SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED"] = "true"
        result = tool.classify(flags)
        self.assertIn("config_mutation_requires_sessions_and_live_true", result["source_proven_fatal"])
        self.assertTrue(result["private_or_native_validation_required"])


if __name__ == "__main__":
    unittest.main()
