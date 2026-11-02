"""LOCAL MOCK DATA only. No Kubernetes, real MySQL, network or native bundle."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fixture", ROOT / "scripts/system-backup-d-kube-mysql-fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
NS_UID = "11111111-2222-3333-4444-555555555555"
POD_UID = "99999999-2222-3333-4444-555555555555"


class Process:
    pid = 12345

    def __init__(self, result=None):
        self.result = result
        self.ended = False
        self.terminated = False

    def poll(self):
        return self.result if self.ended else None

    def wait(self, timeout=None):
        self.ended = True
        return self.result or 0

    def terminate(self):
        self.terminated = True
        self.result = 0
        self.ended = True


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".tmp-d-kube-mysql-test-", dir=ROOT)
        self.root = Path(self.temp.name).resolve()
        self.assertEqual(self.root.parent, ROOT)
        args = SimpleNamespace(bundle=self.root / "bundle", scratch=self.root, logs=self.root / "logs",
                               context="mock-context", mysql_image=fixture.MYSQL_IMAGE,
                               port=0, cleanup_timeout=1, startup_only=False,
                               include_init_logs=False, include_container_logs=False)
        self.f = fixture.Fixture(args)
        self.resources = {}
        self.calls = []
        self.ns = None
        self.f.command = self.command
        self.forward = Process()
        self.runner = Process(result=7)
        self.version = "8.0.36"
        self.events = []

    def tearDown(self):
        self.temp.cleanup()

    def command(self, args, data=None, timeout=45, stream=False):
        self.calls.append((args, data))
        if args[:2] == ["get", "namespace"]:
            return b"" if self.ns is None else json.dumps(self.ns).encode()
        if args[0] == "create" and data["kind"] == "Namespace":
            self.ns = json.loads(json.dumps(data))
            self.ns["metadata"]["uid"] = NS_UID
            return json.dumps(self.ns).encode()
        if "--raw=/api/v1/namespaces/" + self.f.namespace in args:
            self.assertEqual(data["preconditions"], {"uid": NS_UID})
            self.ns = None
            return b"{}"
        if args[0] == "get" and any("/events?" in arg for arg in args):
            self.assertIn("involvedObject.uid%3D" + POD_UID, args[1])
            self.assertIn("limit=24", args[1])
            self.assertLessEqual(timeout, 10)
            return json.dumps({"items": self.events}).encode()
        if "create" in args:
            self.resources[data["kind"]] = data
            if data["kind"] == "Pod":
                data["metadata"]["uid"] = POD_UID
                data["status"] = {"containerStatuses": [{"name": "mysql", "imageID": "docker-pullable://" + self.f.args.mysql_image}],
                                  "initContainerStatuses": [{"name": "tls", "imageID": "containerd://sha256:" + "a" * 64}]}
            return b"{}"
        if "get" in args and "pod" in args:
            return json.dumps(self.resources["Pod"]).encode()
        if "wait" in args:
            self.assertTrue(stream)
            self.assertEqual(timeout, 260)
            self.assertIn("--timeout=240s", args)
            return b""
        self.assertFalse(stream)
        if "logs" in args:
            self.assertIn(args[args.index("-c") + 1], ("tls", "mysql"))
            self.assertIn("--tail=40", args)
            self.assertIn("--limit-bytes=4096", args)
            return ("startup error " + self.f.password + " " + fixture.base64.b64encode(self.f.password.encode()).decode()
                    + "\n-----BEGIN PRIVATE KEY-----\nPRIVATE VALUE\n-----END PRIVATE KEY-----\nSELECT secret FROM fixture;\n").encode()
        if "exec" in args:
            if "cat" in args: return b"-----BEGIN CERTIFICATE-----\nLOCAL MOCK CA\n-----END CERTIFICATE-----\n"
            self.assertIn("--ssl-mode=VERIFY_IDENTITY", args[-1])
            self.assertIn("--protocol=TCP", args[-1])
            return (self.version + "\t" + NS_UID + "\tTLSv1.3\t1\nSsl_cipher\tTLS_AES_256_GCM_SHA384\nSsl_version\tTLSv1.3\n").encode()
        self.fail("unhandled local mock command")

    def popen(self, args, **kwargs):
        if "port-forward" in args:
            self.assertIn("--request-timeout=0", args)
            self.assertNotIn("--request-timeout=25s", args)
            self.assertIn("--address=127.0.0.1", args)
            self.assertEqual(args[-1], ":3306")
            kwargs["stdout"].write(b"Forwarding from 127.0.0.1:63509 -> 3306\n")
            kwargs["stdout"].flush()
            return self.forward
        self.assertEqual(args[0], "bash")
        credential = json.loads(Path(args[2]).read_text())
        self.assertEqual(credential["Host"], "127.0.0.1")
        self.assertEqual(credential["TLSServerName"], "localhost")
        self.assertEqual(credential["ServerUUID"], NS_UID)
        self.assertEqual(credential["Port"], 63509)
        self.assertNotIn(credential["Password"], json.dumps(self.calls[:-1]))
        return self.runner

    def run_fixture(self):
        with patch.object(fixture.subprocess, "Popen", self.popen):
            return self.f.run()

    def test_full_mock_uses_four_owned_resources_and_retains_test_failure(self):
        code = self.run_fixture()
        self.assertEqual(code, 7)
        self.assertEqual(set(self.resources), {"Secret", "NetworkPolicy", "Pod"})
        pod = self.resources["Pod"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(all("emptyDir" in v or "secret" in v for v in pod["volumes"]))
        self.assertIn("DNS:localhost,IP:127.0.0.1", pod["initContainers"][0]["command"][-1])
        self.assertIn("--tls-version=TLSv1.3", pod["containers"][0]["args"])
        self.assertEqual(self.resources["NetworkPolicy"]["spec"]["ingress"], [])
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.f.finish(code), 7)
        self.assertTrue(self.forward.terminated)
        self.assertIsNone(self.ns)
        self.assertFalse(self.f.work.exists())
        self.assertEqual(json.loads((self.f.logs / "fixture.json").read_text())["cleanup_exit_code"], 0)
        report = json.loads((self.f.logs / "fixture.json").read_text())
        self.assertEqual(report["server_version"], "8.0.36")
        self.assertEqual(set(report["observed_image_ids"]), {"mysql", "tls"})

    def test_changed_namespace_uid_refuses_delete_but_removes_local_secrets(self):
        self.run_fixture()
        self.ns["metadata"]["uid"] = POD_UID
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.f.finish(7), 7)
        self.assertFalse(any(args[0] == "delete" for args, _ in self.calls))
        self.assertFalse(self.f.work.exists())
        self.assertTrue(self.forward.terminated)
        self.assertTrue(self.f.residuals)

    def test_owner_change_refuses_delete_and_cleanup_failure_returns_nonzero(self):
        self.run_fixture()
        self.ns["metadata"]["labels"][fixture.LABEL] = "foreign"
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.f.finish(0), 1)
        self.assertFalse(any(args[0] == "delete" for args, _ in self.calls))
        self.assertFalse(self.f.work.exists())

    def test_process_stop_failure_does_not_skip_namespace_or_secret_cleanup(self):
        self.run_fixture()
        with patch.object(self.f, "stop", side_effect=RuntimeError("LOCAL MOCK STOP FAILURE")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.f.finish(7), 7)
        self.assertIsNone(self.ns)
        self.assertFalse(self.f.work.exists())
        self.assertTrue(any("process" in residual for residual in self.f.residuals))

    def test_delete_error_does_not_skip_local_secret_cleanup(self):
        self.run_fixture()
        original = self.f.command
        def fail_delete(args, data=None, timeout=45, stream=False):
            if args[0] == "delete": raise fixture.Refused()
            return original(args, data, timeout, stream)
        self.f.command = fail_delete
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.f.finish(0), 1)
        self.assertFalse(self.f.work.exists())
        self.assertTrue(self.f.residuals)

    def test_create_ack_loss_can_only_recover_matching_owner(self):
        self.f.attempted = True
        self.ns = {"metadata": {"name": self.f.namespace, "uid": NS_UID, "labels": {fixture.LABEL: self.f.owner}}}
        self.assertTrue(self.f.namespace_identity(recover=True))
        self.assertEqual(self.f.uid, NS_UID)
        self.f.uid = None
        self.ns["metadata"]["labels"][fixture.LABEL] = "foreign"
        with self.assertRaises(fixture.Refused): self.f.namespace_identity(recover=True)

    def test_foreign_process_group_is_never_signaled(self):
        process = Process()
        with patch.object(fixture.os, "getpgid", return_value=99999, create=True), patch.object(fixture.os, "killpg", create=True) as kill:
            with self.assertRaises(fixture.Refused): self.f.stop(process, group=True)
            kill.assert_not_called()

    def test_unsupported_version_rejects_before_runner_and_records_observation(self):
        self.version = "8.0.15"
        with self.assertRaises(fixture.Refused): self.run_fixture()
        self.assertIsNone(self.f.runner)
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.f.finish(1), 1)
        report = json.loads((self.f.logs / "fixture.json").read_text())
        self.assertEqual(report["server_version"], "8.0.15")
        self.assertIsNone(self.ns)
        self.assertFalse(self.f.work.exists())

    def test_84_version_is_observed_not_assumed_from_reference(self):
        self.version = "8.4.8"
        self.assertEqual(self.run_fixture(), 7)
        self.assertEqual(self.f.server_version, "8.4.8")
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.f.finish(7), 7)

    def parse_args(self, extra):
        argv = ["fixture", "--scratch", str(self.root), "--logs", str(self.root / "parse-logs")] + extra
        with patch.object(fixture.sys, "argv", argv), patch.object(fixture.sys, "platform", "linux"), \
                patch.object(fixture.os, "uname", return_value=SimpleNamespace(machine="x86_64"), create=True), \
                patch.object(fixture.shutil, "which", side_effect=lambda tool: tool if tool in ("bash", "kubectl") else None), \
                patch.object(fixture.subprocess, "run") as run:
            result = fixture.parse()
            run.assert_not_called()
            return result

    def test_startup_only_parse_needs_no_bundle_checksum_or_elf(self):
        args = self.parse_args(["--startup-only", "--include-container-logs"])
        self.assertIsNone(args.bundle)
        self.assertTrue(args.startup_only)
        self.assertTrue(args.include_container_logs)

    def test_normal_mode_still_rejects_missing_bundle(self):
        argv = ["fixture", "--scratch", str(self.root), "--logs", str(self.root / "parse-logs")]
        with patch.object(fixture.sys, "argv", argv), patch.object(fixture.sys, "platform", "linux"), \
                patch.object(fixture.os, "uname", return_value=SimpleNamespace(machine="x86_64"), create=True), \
                patch.object(fixture.shutil, "which", return_value="mock-tool"), patch.object(fixture.subprocess, "run") as run:
            with self.assertRaises(fixture.Refused): fixture.parse()
            run.assert_not_called()

    def test_startup_only_never_launches_native_or_creates_credentials(self):
        self.f.args.startup_only = True
        self.f.args.bundle = None
        self.assertEqual(self.run_fixture(), 0)
        self.assertIsNone(self.f.runner)
        self.assertFalse((self.f.work / "credentials.json").exists())
        self.assertEqual(self.f.session_tls["Ssl_version"], "TLSv1.3")
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.f.finish(0), 0)
        report = json.loads((self.f.logs / "fixture.json").read_text())
        self.assertFalse(report["native_started"])
        self.assertEqual(report["mode"], "startup-only")
        self.assertIsNone(self.ns)
        self.assertFalse(self.f.work.exists())
        self.assertFalse(any("logs" in args for args, _ in self.calls))

    def test_ready_failure_collects_owned_status_events_and_redacted_logs_before_delete(self):
        self.f.args.startup_only = True
        self.f.args.include_container_logs = True
        original = self.f.command
        def fail_ready(args, data=None, timeout=45, stream=False):
            if "wait" in args:
                self.resources["Pod"]["status"].update({"phase": "Failed", "reason": "Error",
                    "conditions": [{"type": "Ready", "status": "False", "reason": "ContainersNotReady"}]})
                self.resources["Pod"]["status"]["initContainerStatuses"][0]["state"] = {
                    "terminated": {"reason": "Error", "exitCode": 1, "message": "failed " + self.f.password}}
                self.events = [{"involvedObject": {"uid": POD_UID, "name": "mysql", "kind": "Pod", "namespace": self.f.namespace},
                                "reason": "Failed", "message": "owned " + self.f.password},
                               {"involvedObject": {"uid": NS_UID}, "message": "foreign event"}]
                raise fixture.Refused()
            return original(args, data, timeout, stream)
        self.f.command = fail_ready
        with self.assertRaises(fixture.Refused): self.run_fixture()
        password = self.f.password
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.f.finish(1), 1)
        text = (self.f.logs / "startup-diagnostics.json").read_text()
        summary = json.loads(text)
        self.assertNotIn(password, text)
        self.assertNotIn(fixture.base64.b64encode(password.encode()).decode(), text)
        self.assertNotIn("PRIVATE VALUE", text)
        self.assertNotIn("SELECT secret", text)
        self.assertNotIn("foreign event", text)
        self.assertEqual(summary["pod"]["init_containers"][0]["current"]["exitCode"], 1)
        self.assertEqual(set(summary["log_tails"]), {"tls", "mysql"})
        self.assertEqual(len(summary["events"]), 1)
        delete_index = next(i for i, (args, _) in enumerate(self.calls) if args[0] == "delete")
        self.assertTrue(all(i < delete_index for i, (args, _) in enumerate(self.calls) if "logs" in args or any("/events?" in a for a in args)))
        self.assertIsNone(self.f.runner)
        self.assertIsNone(self.ns)
        self.assertFalse(self.f.work.exists())

    def test_diagnostic_failure_preserves_original_failure_and_still_cleans(self):
        self.assertEqual(self.run_fixture(), 7)
        with patch.object(self.f, "collect_startup_diagnostics", side_effect=RuntimeError("mock")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.f.finish(7), 7)
        self.assertIsNone(self.ns)
        self.assertFalse(self.f.work.exists())
        self.assertEqual(json.loads((self.f.logs / "fixture.json").read_text())["diagnostics_exit_code"], 1)

    def test_diagnostic_failure_does_not_replace_success_or_cleanup_result(self):
        self.f.args.startup_only = True
        self.assertEqual(self.run_fixture(), 0)
        with patch.object(self.f, "collect_startup_diagnostics", side_effect=RuntimeError("mock")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.f.finish(0), 0)
        report = json.loads((self.f.logs / "fixture.json").read_text())
        self.assertEqual(report["original_exit_code"], 0)
        self.assertEqual(report["cleanup_exit_code"], 0)
        self.assertEqual(report["diagnostics_exit_code"], 1)
        self.assertIsNone(self.ns)
        self.assertFalse(self.f.work.exists())

    def test_http_bases_keep_bounded_short_requests_and_unlimited_stream_requests(self):
        completed = SimpleNamespace(returncode=0, stdout=b"")
        with patch.object(fixture.subprocess, "run", return_value=completed) as run:
            fixture.Fixture.command(self.f, ["get", "namespace", self.f.namespace])
            self.assertIn("--request-timeout=25s", run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["timeout"], 45)
            fixture.Fixture.command(self.f, ["delete", "--raw=/api/v1/namespaces/" + self.f.namespace, "-f", "-"], {"preconditions": {"uid": NS_UID}})
            self.assertIn("--request-timeout=25s", run.call_args.args[0])
            fixture.Fixture.command(self.f, ["wait", "--timeout=240s"], timeout=260, stream=True)
            self.assertIn("--request-timeout=0", run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["timeout"], 260)


if __name__ == "__main__":
    unittest.main()
