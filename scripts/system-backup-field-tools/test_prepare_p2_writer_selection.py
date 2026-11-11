import ast
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import unittest

SOURCE = Path(__file__).with_name("prepare-p2-writer-selection.py")
SPEC = importlib.util.spec_from_file_location("selection_helper", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class SourceConfigTests(unittest.TestCase):
    def fixture(self):
        rows = [{"ID": number, "Status": "running" if number in (1, 2, 3, 7, 8)
                 else "stopped" if number == 5 else "error"} for number in range(1, 9)]
        return {"Version": "original-initial-source-coordinates.v1", "Namespace": HELPER.NS,
            "InstallationID": "actual-installation", "NamespaceUID": "actual-namespace",
            "ApplicationScopes": ["actual-app-scope", "other-original-scope"], "Instances": rows,
            "RuntimeTestScope": {"Version": "explicit-running-tenant-runtime-test-scope.v3",
                "InstallationID": "actual-installation", "NamespaceUID": "actual-namespace",
                "OriginalInstancesSHA256": "a" * 64, "Deferred": [copy.deepcopy(row) for row in rows if row["ID"] in (4, 5, 6)]},
            "StoppedProLayouts": []}

    def config(self, data, scope="actual-app-scope", workspace="/workspaces"):
        return HELPER.source_config(data, scope, workspace, "/private/control-token", {"File": "/private/ca.pem", "SHA256": "b" * 64})

    def test_preserves_authored_scope_without_selecting_another_sql_scope(self):
        data = self.fixture()
        original = copy.deepcopy(data)
        config = self.config(data)
        self.assertEqual(config["application_scope"], "actual-app-scope")
        self.assertEqual(config["runtime_sources"]["runtime_test_scope"], data["RuntimeTestScope"])
        self.assertEqual(config["runtime_sources"]["shared_runtime_protocol"], "shared-container-freeze.v1")
        self.assertEqual(config["runtime_sources"]["current_stopped_pro_layouts"], [])
        config["runtime_sources"]["runtime_test_scope"]["Deferred"].clear()
        self.assertEqual(data, original)

    def test_refuses_unapproved_scope_or_root(self):
        for scope, root in (("", "/workspaces"), ("invented", "/workspaces"), ("actual-app-scope", "/workspaces/"), ("actual-app-scope", "/")):
            with self.subTest(scope=scope, root=root), self.assertRaises(RuntimeError):
                self.config(self.fixture(), scope, root)

    def test_refuses_roster_or_target_changes(self):
        for change in ("namespace", "installation", "deferred", "active-error", "additional-instance", "scope-version"):
            data = self.fixture()
            if change == "namespace":
                data["Namespace"] = "other"
            elif change == "installation":
                data["RuntimeTestScope"]["InstallationID"] = "other"
            elif change == "deferred":
                data["RuntimeTestScope"]["Deferred"].pop()
            elif change == "active-error":
                data["Instances"][2]["Status"] = "error"
            elif change == "additional-instance":
                data["Instances"].append({"ID": 9, "Status": "running"})
            else:
                data["RuntimeTestScope"]["Version"] = "unapproved"
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.config(data)

    def test_loaded_environment_transport_uses_quoted_values(self):
        shell = shutil.which("sh")
        if os.name == "nt":
            shell = r"C:\Program Files\Git\usr\bin\sh.exe"
        if not shell or not Path(shell).is_file():
            self.skipTest("POSIX shell unavailable")
        tree = ast.parse(SOURCE.read_bytes())
        command = next(node.value.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "command" for target in node.targets))
        env = dict(os.environ, SYSTEM_BACKUP_SQL_GATE_SCOPE="actual-app-scope", RUNTIME_WORKSPACE_ROOT="/workspaces",
                   RUNTIME_AGENT_CONTROL_TOKEN='fixture-$(printf SHOULD_NOT_EXECUTE)-token')
        result = subprocess.run([shell, "-c", command], env=env, capture_output=True, check=True)
        self.assertEqual(result.stdout.split(b"\0"), [env[name].encode() for name in (
            "SYSTEM_BACKUP_SQL_GATE_SCOPE", "RUNTIME_AGENT_CONTROL_TOKEN", "RUNTIME_WORKSPACE_ROOT")])


if __name__ == "__main__":
    unittest.main()
