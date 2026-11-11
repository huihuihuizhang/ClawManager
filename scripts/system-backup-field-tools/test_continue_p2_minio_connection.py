import datetime
import http.server
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest


file = Path(__file__).with_name('continue-p2-minio-connection.py')
spec = importlib.util.spec_from_file_location('field_minio_connection', file)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RequiredMinIOConnection(unittest.TestCase):
    def test_retained_plan_cannot_be_replaced_or_rebound(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp).resolve() / 'plan.json'
            pin = m.retain(target, b'{"operation":"original"}')
            self.assertEqual(m.private(target, pin['SHA256']), b'{"operation":"original"}')
            with self.assertRaisesRegex(RuntimeError, 'retained material changed'):
                m.retain(target, b'{"operation":"replacement"}')
            with self.assertRaisesRegex(RuntimeError, 'pin changed'):
                m.private(target, '0' * 64)

    def test_unreviewed_helper_is_refused_before_import(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'system-backup-minio-first-hop-tls.py').write_text('raise AssertionError("executed")')
            with self.assertRaisesRegex(RuntimeError, 'helper bytes changed'):
                m.module(root, 'system-backup-minio-first-hop-tls.py')

    def test_wire_scope_is_encoded_and_secret_is_never_transmitted(self):
        now = datetime.datetime(2026, 11, 11, 1, 2, 3, tzinfo=datetime.timezone.utc)
        raw = m.signed_list_request('minio.original.svc:9000', 'actual-bucket', 'scope/a b+/', 'fixture-access', 'fixture-secret', now)
        self.assertIn(b'GET /actual-bucket?list-type=2&max-keys=1&prefix=scope%2Fa%20b%2B%2F HTTP/1.1', raw)
        self.assertIn(b'Credential=fixture-access/20261111/us-east-1/s3/aws4_request', raw)
        self.assertNotIn(b'fixture-secret', raw)
        with self.assertRaises(RuntimeError):
            m.signed_list_request('minio.original.svc:9000', 'bucket', 'scope/', 'injected\r\nheader', 'secret', now)

    def test_s3_signature_matches_independent_curl_signer(self):
        curl = shutil.which('curl.exe') or shutil.which('curl')
        if not curl:
            self.skipTest('independent curl signer unavailable')
        seen = {}
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen['path'], seen['authorization'] = self.path, self.headers['Authorization']
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host = 'minio.original.svc:9000'
            now = datetime.datetime(2026, 11, 11, 1, 2, 3, tzinfo=datetime.timezone.utc)
            raw = m.signed_list_request(host, 'actual-bucket', 'scope/a b/', 'fixture-access', 'fixture-secret', now)
            first, *headers = raw.decode().split('\r\n')
            path = first.split()[1]
            expected = next(h.partition(': ')[2] for h in headers if h.startswith('Authorization:'))
            result = subprocess.run([curl, '--silent', '--show-error', '--fail', '--noproxy', '*', '--max-time', '5',
                '--aws-sigv4', 'aws:amz:us-east-1:s3', '--user', 'fixture-access:fixture-secret',
                '--connect-to', 'minio.original.svc:9000:127.0.0.1:' + str(server.server_port),
                '-H', 'X-Amz-Date: 20261111T010203Z',
                '-H', 'X-Amz-Content-Sha256: ' + m.digest(b''),
                'http://' + host + path], capture_output=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(seen['path'], path)
            self.assertEqual(seen['authorization'], expected)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
