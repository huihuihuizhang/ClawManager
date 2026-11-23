import copy
import json
from pathlib import Path
import runpy
import unittest


ROOT = Path(__file__).resolve().parents[1]
REGISTER = runpy.run_path(str(ROOT / "scripts/system-backup-trial-register.py"))
EXAMPLE = ROOT / "deployments/k8s/system-backup-trial-registration.example.json"


class TrialRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        REGISTER["validate"](self.config)

    def test_catalog_pin_and_workspace_modes_are_fully_rendered(self):
        source = REGISTER["registration_manifests"](self.config, "source")
        target = REGISTER["registration_manifests"](self.config, "target")
        for result in (source, target):
            self.assertNotIn("${", result)
            self.assertIn('value: "' + self.config["migration_catalog_sha256"] + '"', result)
            self.assertIn("suspend: true", result)
            self.assertIn("defaultMode: 288", result)
        self.assertNotIn("/trial/workspace", source)
        self.assertIn("/trial/workspace", target)
        self.assertIn("mountPath: /trial/archive-write\n              readOnly: false", source)
        self.assertIn("mountPath: /trial/archive-write\n              readOnly: true", target)

    def test_same_cluster_delegates_only_named_source_key(self):
        source = REGISTER["registration_manifests"](self.config, "source")
        role, binding = [json.loads(part) for part in source.split("\n---\n")[-2:]]
        self.assertEqual(role["rules"], [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["trial-key"], "verbs": ["get"]}])
        self.assertEqual(binding["subjects"][0]["namespace"], self.config["target"]["namespace"])
        self.config["target"]["cluster"] = "another-cluster"
        self.assertNotIn("-target-key", REGISTER["registration_manifests"](self.config, "source"))

    def test_placeholders_do_not_include_sql_owner_or_secret_material(self):
        items = REGISTER["placeholders"](self.config, "target")["items"]
        self.assertEqual({item["metadata"]["name"] for item in items}, {"trial-key", "trial-target-reader", "trial-target-writer", "trial-target-runtime"})
        self.assertTrue(all(item["type"] == "Opaque" and "data" not in item and "stringData" not in item for item in items))

    def test_yaml_like_names_stay_strings(self):
        self.config["source"]["prepare"]["service_account"] = "null"
        self.config["source"]["prepare"]["job_name"] = "true"
        REGISTER["validate"](self.config)
        rendered = REGISTER["registration_manifests"](self.config, "source")
        self.assertIn('name: "true"', rendered)
        self.assertIn('serviceAccountName: "null"', rendered)

    def test_rejects_unresolved_placeholders_and_unsafe_registration(self):
        values = REGISTER["template_inputs"](self.config, "target")
        template = REGISTER["TEMPLATE"].read_text(encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "variables do not match"):
            REGISTER["render_template"](template.replace("MIGRATION_CATALOG_SHA256}", "WRONG_SHA256}"), values, True)
        for path, value in (
            (("migration_catalog_sha256",), "${MIGRATION_CATALOG_SHA256}"),
            (("target", "prepare", "owner_dsn_secret"), "trial-key"),
            (("target", "restore_read_secret"), "trial-target-writer"),
            (("target", "namespace"), "default"),
            (("target", "image"), "registry.example/clawmanager:latest"),
            (("target", "prepare", "server_uuid"), self.config["source"]["prepare"]["server_uuid"]),
            (("source", "prepare", "job_name"), "prepare\n---"),
        ):
            with self.subTest(path=path):
                config = copy.deepcopy(self.config)
                node = config
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
                with self.assertRaises(ValueError):
                    REGISTER["validate"](config)


if __name__ == "__main__":
    unittest.main()
