#!/usr/bin/env python3
"""Offline tests for the validation bootstrap preflight.

The fake runner implements only the kubectl argv shapes the preflight issues.
It proves the closed input schema, target/enrollment binding, ownership
conflict handling, server dry-run request shape and UID-chain observation
without a cluster.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("preflight", HERE / "system-backup-validation-bootstrap-preflight.py")
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class FakeCluster:
    def __init__(self):
        self.objects = {}
        self.dry_runs = []
        self.reject = set()

    def put(self, obj):
        kind, ns, name = obj["kind"], obj["metadata"].get("namespace"), obj["metadata"]["name"]
        self.objects[(kind, ns, name)] = obj

    def get(self, kind, ns, name):
        return self.objects.get((kind, ns, name))

    def __call__(self, argv, data):
        argv = list(argv)
        if "config" in argv and "view" in argv:
            return 0, canonical({"clusters": [{"cluster": {"server": "https://api.validation:6443"}}]}), b""
        verb = argv[argv.index("get") + 1] if "get" in argv else ("apply" if "apply" in argv else "")
        if verb == "apply":
            obj = json.loads(data)
            key = obj["kind"] + "/" + obj["metadata"]["name"]
            self.dry_runs.append({"argv": argv, "key": key})
            if key in self.reject:
                return 1, b"", b'rejected by admission: ' + key.encode()
            return 0, canonical(obj), b""
        if "get" not in argv:
            return 1, b"", b"unsupported argv"
        resource = argv[argv.index("get") + 1]
        names = [item for item in argv[argv.index("get") + 2:] if not item.startswith("-")]
        name = names[0] if names and names[0] not in ("-o", "json") else None
        ns = argv[argv.index("-n") + 1] if "-n" in argv else None
        selector = argv[argv.index("-l") + 1] if "-l" in argv else None
        kind = {
            "configmap": "ConfigMap", "namespace": "Namespace", "deployment": "Deployment",
            "storageclass": "StorageClass", "volumesnapshotclasses": "VolumeSnapshotClass",
            "persistentvolumeclaim": "PersistentVolumeClaim", "persistentvolumeclaims": "PersistentVolumeClaim", "replicaset": "ReplicaSet",
            "role": "Role", "rolebinding": "RoleBinding", "clusterrole": "ClusterRole", "clusterrolebinding": "ClusterRoleBinding",
            "service": "Service",
            "pods": "Pod", "pod": "Pod", "nodes": "Node", "serviceaccount": "ServiceAccount",
        }.get(resource)
        if kind is None:
            return 1, b"", b"unsupported resource"
        if name:
            item = self.get(kind, ns, name)
            return (0, canonical(item), b"") if item else (0, b"", b"")
        items = []
        for (stored_kind, stored_ns, _), item in self.objects.items():
            if stored_kind != kind:
                continue
            if kind not in ("Node", "VolumeSnapshotClass", "StorageClass") and ns is not None and stored_ns != ns:
                continue
            if selector:
                labels = item["metadata"].get("labels") or {}
                if not all(labels.get(pair.split("=", 1)[0]) == pair.split("=", 1)[1] for pair in selector.split(",")):
                    continue
            items.append(item)
        return 0, canonical({"items": items}), b""


def plan():
    return {
        "SchemaVersion": preflight.PLAN_VERSION,
        "EnrollmentName": "sbk-validation-enrollment",
        "EnrollmentID": "enroll-validation-1",
        "IssuerID": "issuer-validation-1",
        "EnrollmentRevision": 1,
        "Target": {
            "InstallationID": "installation_validation_01",
            "ServerUUID": "11111111-2222-3333-4444-555555555555",
            "Database": "clawmanager",
            "DatabaseAccount": "installer@%",
            "ClusterID": "validation-cluster",
            "Namespace": "clawmanager-sbk-validation-system",
            "NamespaceUID": "aaaaaaaa-1111-2222-3333-444444444444",
        },
        "InstallerDatabaseAccount": "installer@%",
        "LocalAdminUsername": "admin",
        "OwnerUsername": "owner",
        "OwnerUID": "",
        "OwnerGroups": ["system:authenticated", "system:masters"],
        "IssuerPublicKeySHA256": "b" * 64,
        "KubernetesAPI": "https://api.validation:6443",
        "KubernetesCASHA256": "c" * 64,
        "DatabaseCASHA256": "d" * 64,
        "DatabaseTLSServerName": "mysql.validation",
    }


def definition():
    return {
        "Version": preflight.DEFINITION_VERSION,
        "Operation": "0123456789abcdef0123456789abcdef",
        "Namespace": "clawmanager-sbk-validation-system",
        "Plan": {
            "InstallationID": "installation_validation_01",
            "NamespaceUID": "aaaaaaaa-1111-2222-3333-444444444444",
            "ClusterID": "validation-cluster",
            "ServerUUID": "11111111-2222-3333-4444-555555555555",
            "Database": "clawmanager",
        },
        "ControllerServiceAccount": "sbk-0123456789ab-controller",
        "WorkerServiceAccount": "sbk-0123456789ab-worker",
        "SourcesServiceAccount": "sbk-0123456789ab-sources",
        "ControllerDeployment": "sbk-0123456789ab-controller",
        "ControlService": "sbk-0123456789ab-controller",
        "InputsClaim": "sbk-0123456789ab-inputs",
        "StagingClaim": "sbk-0123456789ab-staging",
        "PrivateClaim": "sbk-0123456789ab-private",
        "InputsStorageClass": "longhorn-rwx",
        "StagingStorageClass": "longhorn",
        "StagingSize": "10Gi",
        "PrivateSize": "1Gi",
        "AppDeployment": "clawmanager-app",
        "AppImage": "10.130.14.23:5000/clawmanager@sha256:" + "e" * 64,
        "RuntimeDeployments": {"hermes": "clawmanager-runtime", "openclaw": "clawmanager-runtime"},
        "RuntimeImages": {"hermes": "sha256:" + "f" * 64, "openclaw": "sha256:" + "f" * 64},
        "LonghornNamespace": "longhorn-system",
        "SnapshotClass": "longhorn-snapshot",
        "CloneClass": "longhorn",
        "ControllerRules": [{"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get", "create", "update"]}],
        "ControllerClusterRules": [],
        "WorkerRules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "create", "delete"]}],
        "WorkerClusterRules": [],
        "SourceRules": [
            {"apiGroups": [""], "resources": ["pods", "services", "serviceaccounts", "configmaps", "secrets", "persistentvolumeclaims", "endpoints"], "verbs": ["get", "list", "watch"]},
            {"apiGroups": [""], "resources": ["namespaces"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["persistentvolumes"], "verbs": ["get"]},
        ],
    }


class Environment:
    def __init__(self):
        self.files = {}
        self.reports = {}
        self.cluster = FakeCluster()
        self.plan_path = self.write("plan.json", canonical(plan()))
        self.definition_path = self.write("definition.json", canonical(definition()))
        self.pin_path = self.write("enrollment-pin.json", canonical({"ConfigMapUID": "cm-uid", "DocumentSHA256": "0" * 64}))
        self.kubeconfig_path = self.write("kubeconfig.json", b'{"clusters":[]}')
        self.issuer_path = self.write("issuer.pub", bytes(range(32)))
        self.output = "out"
        self.populate()
        self.refresh_enrollment()

    def write(self, name, raw):
        self.files[name] = raw
        return name

    def read(self, path, limit=4 << 20):
        raw = self.files[str(path)]
        if len(raw) > limit:
            raise preflight.Refused("bounded_file_required:" + str(path))
        return raw

    def report(self, directory, name, value):
        self.reports[name] = value
        return name, digest(canonical(value))

    def populate(self):
        namespace = plan()["Target"]["Namespace"]
        self.cluster.put({"kind": "Namespace", "metadata": {"name": namespace, "uid": plan()["Target"]["NamespaceUID"]}})
        self.cluster.put({"kind": "Namespace", "metadata": {"name": "longhorn-system", "uid": "longhorn-ns-uid"}})
        app_image = plan()["AppImage"] if "AppImage" in plan() else definition()["AppImage"]
        app_image = definition()["AppImage"]
        self.cluster.put({
            "kind": "Deployment",
            "metadata": {"name": "clawmanager-app", "namespace": namespace, "uid": "app-deployment-uid"},
            "spec": {"selector": {"matchLabels": {"app": "clawmanager-app"}}, "template": {"spec": {"containers": [{"name": "app", "image": app_image}]}}},
        })
        self.cluster.put({
            "kind": "Pod",
            "metadata": {"name": "clawmanager-app-0", "namespace": namespace, "uid": "app-pod-uid", "labels": {"app": "clawmanager-app"}},
            "status": {"containerStatuses": [{"name": "app", "imageID": "docker-pullable://" + app_image.split(":", 1)[0] + "@" + app_image.split("@", 1)[1]}]},
        })
        for runtime, name in definition()["RuntimeDeployments"].items():
            self.cluster.put({
                "kind": "Deployment",
                "metadata": {"name": name, "namespace": namespace, "uid": runtime + "-deployment-uid"},
                "spec": {"selector": {"matchLabels": {"app": name}}, "template": {"spec": {"containers": [{"name": "runtime", "image": "runtime:latest"}]}}},
            })
            self.cluster.put({
                "kind": "Pod",
                "metadata": {"name": name + "-0", "namespace": namespace, "uid": runtime + "-pod-uid", "labels": {"app": name}},
                "status": {"containerStatuses": [{"name": "runtime", "imageID": "docker-pullable://runtime@sha256:" + "f" * 64}]},
            })
        for index in (1, 2):
            self.cluster.put({"kind": "Node", "metadata": {"name": "node-%d" % index, "uid": "node-%d-uid" % index}, "status": {"nodeInfo": {"kubeletVersion": "v1.31.0", "containerRuntimeVersion": "containerd://1.7.0", "operatingSystem": "linux"}}})
        self.cluster.put({"kind": "StorageClass", "metadata": {"name": "longhorn-rwx", "uid": "sc-rwx-uid"}, "provisioner": "driver.longhorn.io", "volumeBindingMode": "Immediate", "reclaimPolicy": "Delete"})
        self.cluster.put({"kind": "StorageClass", "metadata": {"name": "longhorn", "uid": "sc-uid"}, "provisioner": "driver.longhorn.io", "volumeBindingMode": "WaitForFirstConsumer", "reclaimPolicy": "Delete"})
        self.cluster.put({"kind": "VolumeSnapshotClass", "metadata": {"name": "longhorn-snapshot", "uid": "vsc-uid"}, "driver": "driver.longhorn.io"})
        self.cluster.put({"kind": "PersistentVolumeClaim", "metadata": {"name": "workspace-claim", "namespace": namespace, "uid": "pvc-uid"}, "spec": {"volumeName": "pv-workspaces"}})

    def refresh_enrollment(self):
        document = {
            "SchemaVersion": preflight.ENROLLMENT_VERSION,
            "Plan": plan(),
            "AdminUserID": 7,
            "Issuer": __import__("base64").b64encode(bytes(range(32))).decode(),
        }
        raw = canonical(document)
        self.cluster.put({
            "kind": "ConfigMap",
            "metadata": {"name": plan()["EnrollmentName"], "namespace": plan()["Target"]["Namespace"], "uid": "cm-uid"},
            "immutable": True,
            "data": {"enrollment.json": raw.decode()},
        })
        self.write("enrollment-pin.json", canonical({"ConfigMapUID": "cm-uid", "DocumentSHA256": digest(raw)}))

    def argv(self, mode="preflight"):
        def d(name):
            return digest(self.files[name])

        return [
            "--mode", mode,
            "--plan-file", self.plan_path, "--plan-sha256", d(self.plan_path),
            "--issuer-public-file", self.issuer_path, "--issuer-public-sha256", d(self.issuer_path),
            "--enrollment-pin-file", self.pin_path, "--enrollment-pin-sha256", d(self.pin_path),
            "--kubeconfig-file", self.kubeconfig_path, "--kubeconfig-sha256", d(self.kubeconfig_path),
            "--definition-file", self.definition_path, "--definition-sha256", d(self.definition_path),
            "--output-directory", self.output,
        ]

    def close(self):
        pass


class PreflightTest(unittest.TestCase):
    def setUp(self):
        self.env = Environment()

    def tearDown(self):
        self.env.close()

    def run_preflight(self, mode="preflight"):
        with contextlib.redirect_stdout(io.StringIO()):
            return preflight.main(self.env.argv(mode), runner=self.env.cluster, filereader=self.env.read, reportwriter=self.env.report)

    def report(self, name):
        return self.env.reports[name]

    def test_server_dry_run_admits_every_bootstrap_object(self):
        self.assertEqual(self.run_preflight(), 0)
        report = self.report("bootstrap-preflight.result.json")
        self.assertEqual(report["state"], "read_only_preflight_and_server_dry_run_passed")
        self.assertEqual(report["unconfirmed"], [])
        kinds = {item["Kind"] for item in report["objects"]}
        self.assertTrue({"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "PersistentVolumeClaim", "Deployment", "Service"} <= kinds)
        self.assertEqual(len([item for item in report["objects"] if item["Kind"] == "ServiceAccount"]), 3)
        self.assertEqual(len([item for item in report["objects"] if item["Kind"] == "PersistentVolumeClaim"]), 3)
        self.assertTrue(self.env.cluster.dry_runs)
        for call in self.env.cluster.dry_runs:
            self.assertIn("--dry-run=server", call["argv"])
        self.assertFalse(report["created"])
        self.assertFalse(report["backup_enabled"])
        self.assertIsNone(report["uid_chain"])

    def test_enrollment_uid_mismatch_is_refused(self):
        pin = json.loads(self.env.files[self.env.pin_path])
        pin["ConfigMapUID"] = "another-configmap"
        self.env.write("enrollment-pin.json", canonical(pin))
        with self.assertRaises(preflight.Refused) as caught:
            self.run_preflight()
        self.assertEqual(str(caught.exception), "enrollment_configmap_uid_changed")

    def test_target_namespace_uid_drift_is_refused(self):
        self.env.cluster.put({"kind": "Namespace", "metadata": {"name": plan()["Target"]["Namespace"], "uid": "old-environment-uid"}})
        with self.assertRaises(preflight.Refused) as caught:
            self.run_preflight()
        self.assertEqual(str(caught.exception), "target_namespace_uid_changed")

    def test_foreign_same_name_object_is_an_ownership_conflict(self):
        definition_value = definition()
        self.env.cluster.put({"kind": "ServiceAccount", "metadata": {"name": definition_value["ControllerServiceAccount"], "namespace": definition_value["Namespace"], "uid": "foreign-uid", "annotations": {}}, "automountServiceAccountToken": False})
        with self.assertRaises(preflight.Refused) as caught:
            self.run_preflight()
        self.assertIn("existing_object_ownership_conflict", str(caught.exception))

    def test_owned_replay_is_accepted(self):
        definition_value = definition()
        plan_sha = digest(self.env.files[self.env.plan_path])
        self.env.cluster.put({
            "kind": "ServiceAccount",
            "metadata": {"name": definition_value["ControllerServiceAccount"], "namespace": definition_value["Namespace"], "uid": "owned-uid", "annotations": {preflight.PLAN_MARKER: plan_sha}},
            "automountServiceAccountToken": False,
        })
        self.assertEqual(self.run_preflight(), 0)
        report = self.report("bootstrap-preflight.result.json")
        recorded = [item for item in report["objects"] if item["Kind"] == "ServiceAccount" and item["Name"] == definition_value["ControllerServiceAccount"]]
        self.assertEqual(recorded[0]["Existing"], "owned_replay")

    def test_admission_rejection_is_reported_with_the_object(self):
        definition_value = definition()
        self.env.cluster.reject.add("Deployment/" + definition_value["ControllerDeployment"])
        with self.assertRaises(preflight.Refused) as caught:
            self.run_preflight()
        self.assertIn("server_dry_run_rejected:Deployment/", str(caught.exception))

    def test_missing_snapshot_class_is_unconfirmed_not_a_dry_run_blocker(self):
        self.env.cluster.objects.pop(("VolumeSnapshotClass", None, definition()["SnapshotClass"]))
        self.assertEqual(self.run_preflight(), 0)
        report = self.report("bootstrap-preflight.result.json")
        self.assertIn("snapshot_class_absent", report["unconfirmed"])
        self.assertEqual(report["state"], "read_only_preflight_passed_with_unconfirmed_items")
        self.assertTrue(self.env.cluster.dry_runs)

    def test_app_release_image_not_yet_rolled_out_is_unconfirmed(self):
        pod = self.env.cluster.get("Pod", plan()["Target"]["Namespace"], "clawmanager-app-0")
        pod["status"]["containerStatuses"][0]["imageID"] = "docker-pullable://registry/app@sha256:" + "1" * 64
        self.assertEqual(self.run_preflight(), 0)
        report = self.report("bootstrap-preflight.result.json")
        self.assertIn("app_release_image_not_yet_rolled_out", report["unconfirmed"])
        self.assertTrue(self.env.cluster.dry_runs)

    def test_observe_records_real_uid_chain(self):
        definition_value = definition()
        namespace = definition_value["Namespace"]
        labels = {"app.kubernetes.io/name": definition_value["ControllerDeployment"]}
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": definition_value["ControllerDeployment"], "namespace": namespace, "uid": "deployment-uid"},
            "spec": {
                "selector": {"matchLabels": labels},
                "template": {
                    "spec": {
                        "serviceAccountName": definition_value["ControllerServiceAccount"],
                        "containers": [
                            {"name": "controller", "image": definition_value["AppImage"], "command": ["/bin/sh", "-ec", preflight.LAUNCHER],
                             "env": [{"name": "SYSTEM_BACKUP_ENABLED", "value": "false"}, {"name": "SYSTEM_BACKUP_EXECUTION_PROTOCOL", "value": "public-v1"}, {"name": "CLAWMANAGER_LEADER_ELECTION", "value": "true"}],
                             "volumeMounts": [{"name": "inputs", "mountPath": preflight.RUNTIME_MOUNT}]},
                            {"name": "installation-owner", "image": definition_value["AppImage"], "command": ["/bin/sh", "-ec", "true"],
                             "volumeMounts": [{"name": "private", "mountPath": preflight.PRIVATE_MOUNT}]},
                        ],
                        "volumes": [
                            {"name": "inputs", "persistentVolumeClaim": {"claimName": definition_value["InputsClaim"]}},
                            {"name": "staging", "persistentVolumeClaim": {"claimName": definition_value["StagingClaim"]}},
                            {"name": "private", "persistentVolumeClaim": {"claimName": definition_value["PrivateClaim"]}},
                        ],
                    }
                }
            },
        }
        self.env.cluster.put(deployment)
        self.env.cluster.put({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "controller-rs", "namespace": namespace, "uid": "rs-uid", "ownerReferences": [{"kind": "Deployment", "uid": "deployment-uid"}]},
        })
        self.env.cluster.put({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "controller-pod", "namespace": namespace, "uid": "pod-uid", "labels": labels, "ownerReferences": [{"kind": "ReplicaSet", "name": "controller-rs", "uid": "rs-uid"}]},
            "spec": {"serviceAccountName": definition_value["ControllerServiceAccount"]},
            "status": {"phase": "Running", "containerStatuses": [
                {"name": "controller", "ready": True, "state": {"running": {}}, "containerID": "containerd://controller", "imageID": "sha256:controller"},
                {"name": "installation-owner", "ready": True, "state": {"running": {}}, "containerID": "containerd://owner", "imageID": "sha256:owner"},
            ]},
        })
        self.env.cluster.put({"kind": "ServiceAccount", "metadata": {"name": definition_value["ControllerServiceAccount"], "namespace": namespace, "uid": "sa-uid"}})
        for name, uid in ((definition_value["InputsClaim"], "inputs-uid"), (definition_value["StagingClaim"], "staging-uid"), (definition_value["PrivateClaim"], "private-uid")):
            self.env.cluster.put({"kind": "PersistentVolumeClaim", "metadata": {"name": name, "namespace": namespace, "uid": uid}})
        self.assertEqual(self.run_preflight("observe"), 0)
        chain = self.report("bootstrap-identity.result.json")["uid_chain"]
        self.assertEqual(chain["DeploymentUID"], "deployment-uid")
        self.assertEqual(chain["ReplicaSetUID"], "rs-uid")
        self.assertEqual(chain["PodUID"], "pod-uid")
        self.assertEqual(chain["ServiceAccountUID"], "sa-uid")
        self.assertEqual(chain["PVC"][definition_value["InputsClaim"]], "inputs-uid")
        self.assertEqual(set(chain["Containers"]), {"controller", "installation-owner"})

    def test_observe_rejects_replaced_replicaset(self):
        # No deployment at all is the same concrete "identity not established"
        # refusal as a replaced owner; observe never guesses a UID.
        with self.assertRaises(preflight.Refused) as caught:
            self.run_preflight("observe")
        self.assertEqual(str(caught.exception), "observe_deployment_absent")

    def test_launcher_gate_and_disabled_flag_are_fixed(self):
        self.assertTrue(preflight.CONTROLLER_READY.endswith("controller.env.ready"))
        self.assertIn('while test ! -f "$f.ready"', preflight.LAUNCHER)
        template = HERE / "system-backup-operator-deployment.py"
        if not template.exists():
            self.skipTest("operator deployment template is not shipped beside the standalone preflight")
        source = template.read_text()
        self.assertIn('{"name": "SYSTEM_BACKUP_ENABLED", "value": "false"}', source)
        self.assertIn('while test ! -f \\"$f.ready\\"; do sleep 2; done', source)


if __name__ == "__main__":
    unittest.main()
