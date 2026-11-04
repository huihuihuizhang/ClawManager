"""Offline refusal regressions; these are not field TLS/owner acceptance."""
import copy
import datetime as dt
import importlib.util
import http.server
from pathlib import Path
import ssl
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location("readback", Path(__file__).with_name("system-backup-d-enable-readback.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class API:
    def __init__(self):
        self.config = {"schema_version": "system-backup-config.v1", "origin_installation_id": "installation_real",
                       "version": 2, "row_version": 4, "active": True, "effective_enabled": True,
                       "config": {"enabled": True}}
        self.overview = {"schema_version": "system-backup-overview.v1", "origin_installation_id": "installation_real",
                         "config_version": 2, "effective_enabled": True, "backup_recovery_readiness": True,
                         "source_writer_state": "clean", "observed_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        self.overview.update({k: "healthy" for k in ("controller_health", "database_health", "artifact_target_health",
                                                     "evidence_store_health", "catalog_health")})
        self.live = "live"
        self.overview_status = 200
        self.probe_status = 400
        self.flip = False
        self.reads = 0
        self.calls = []

    def request(self, path, method="GET"):
        self.calls.append((path, method))
        if method == "PUT":
            return self.probe_status, {}, {"code": "validation_failed"}
        if path == m.OVERVIEW:
            return self.overview_status, {}, self.overview
        self.reads += 1
        value = copy.deepcopy(self.config)
        if self.flip and self.reads > 1:
            value["version"] += 1
        return 200, {"X-System-Backup-Data-Source": self.live}, value


class RefusalTests(unittest.TestCase):
    def test_success_requires_matching_live_reads(self):
        api = API()
        result = m.verify_api(api, "installation_real", True)
        self.assertEqual(result["mutation_route"], "invalid_body_rejected_400")
        self.assertEqual(api.calls, [(m.CONFIG, "GET"), (m.CONFIG, "PUT"), (m.OVERVIEW, "GET"), (m.CONFIG, "GET")])

    def test_disabled_and_persisted_effective_are_insufficient(self):
        api = API()
        api.config["config"]["enabled"] = False
        with self.assertRaisesRegex(m.Refused, "config_not_enabled"):
            m.verify_api(api, "installation_real", False)

    def test_unavailable_overview_is_not_readiness(self):
        api = API()
        api.overview_status = 503
        with self.assertRaisesRegex(m.Refused, "readiness_endpoint_unavailable"):
            m.verify_api(api, "installation_real", False)

    def test_another_installation_is_refused(self):
        with self.assertRaisesRegex(m.Refused, "active_config_identity_invalid"):
            m.verify_api(API(), "installation_other", True)

    def test_stale_and_future_readiness_are_refused(self):
        for seconds in (-120, 120):
            with self.subTest(seconds=seconds):
                api = API()
                api.overview["observed_at"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()
                with self.assertRaisesRegex(m.Refused, "readiness_observation_stale"):
                    m.verify_api(api, "installation_real", False)

    def test_config_race_is_refused(self):
        api = API()
        api.flip = True
        with self.assertRaisesRegex(m.Refused, "config_changed_during_readback"):
            m.verify_api(api, "installation_real", False)

    def test_missing_route_and_http_backend_are_refused(self):
        for status in (404, 405, 426, 401, 502):
            with self.subTest(status=status):
                api = API()
                api.probe_status = status
                with self.assertRaisesRegex(m.Refused, "mutation_route_probe_failed"):
                    m.verify_api(api, "installation_real", True)

    def test_fixture_and_changed_overview_version_are_refused(self):
        api = API()
        api.live = "fixture"
        with self.assertRaisesRegex(m.Refused, "active_config_not_live"):
            m.verify_api(api, "installation_real", False)
        api = API()
        api.overview["config_version"] = 3
        with self.assertRaisesRegex(m.Refused, "readiness_identity_mismatch"):
            m.verify_api(api, "installation_real", False)

    def test_degraded_sources_are_refused(self):
        api = API()
        api.overview["source_writer_state"] = "unknown"
        with self.assertRaisesRegex(m.Refused, "readiness_not_healthy"):
            m.verify_api(api, "installation_real", False)

    def test_http_and_duplicate_members_are_refused(self):
        with self.assertRaisesRegex(m.Refused, "https_origin_required"):
            m.API("http://example.invalid", None, "", "token")
        with self.assertRaisesRegex(m.Refused, "duplicate_json_member"):
            m.decode(b'{"version":1,"version":2}')


class ActualTLSTests(unittest.TestCase):
    """Real local socket handshakes; keys/certs exist only in TemporaryDirectory."""
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        cls.tmp = tempfile.TemporaryDirectory()
        directory = Path(cls.tmp.name)
        def certificate(name):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            now = dt.datetime.now(dt.timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
            ca = directory / (name + ".pem")
            ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            secret = directory / (name + ".key")
            secret.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
            return ca, secret
        cls.ca, key = certificate("localhost")
        cls.wrong_ca, _ = certificate("untrusted")
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.send_response(302 if self.path == "/redirect" else 200)
                self.send_header("Content-Type", "application/json")
                if self.path == "/redirect":
                    self.send_header("Location", "https://127.0.0.1:1/must-not-forward-token")
                self.end_headers()
                self.wfile.write(b'{"observed":true}')
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cls.ca), str(key))
        cls.server.socket = tls.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=lambda: cls.server.serve_forever(poll_interval=0.01), daemon=True)
        cls.thread.start()
        cls.origin = "https://localhost:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.tmp.cleanup()

    def test_actual_trusted_tls(self):
        api = m.API(self.origin, self.ca, m.sha(self.ca.read_bytes()), "test-token")
        self.assertEqual(api.request("/check")[0], 200)

    def test_wrong_ca_and_hostname_fail_real_handshake(self):
        api = m.API(self.origin, self.wrong_ca, m.sha(self.wrong_ca.read_bytes()), "test-token")
        with self.assertRaises(m.urllib.error.URLError):
            api.request("/check")
        api = m.API(self.origin.replace("localhost", "127.0.0.1"), self.ca, m.sha(self.ca.read_bytes()), "test-token")
        with self.assertRaises(m.urllib.error.URLError):
            api.request("/check")

    def test_redirect_does_not_forward_credentials(self):
        api = m.API(self.origin, self.ca, m.sha(self.ca.read_bytes()), "test-token")
        self.assertEqual(api.request("/redirect")[0], 302)


if __name__ == "__main__":
    unittest.main()
