"""Offline real-ELF checks and loopback HTTP Registry protocol tests only."""
import contextlib
import copy
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import threading
import unittest
from unittest import mock
import urllib.parse

SPEC = importlib.util.spec_from_file_location("agent_runtime_layer", Path(__file__).with_name("agent_runtime_layer.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
SECRET = "TEST_SECRET_ENV_NEVER_STDOUT"


def elf():
    raw = bytearray(256)
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<16sHHIQQQIHHHHHH", raw, 0, ident, 2, 62, 1, 0x400080, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 0x400000, 0, 256, 256, 4096)
    return bytes(raw)


def tar_bytes(symlink_parent=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        if symlink_parent:
            member = tarfile.TarInfo("usr/local/bin")
            member.type, member.linkname = tarfile.SYMTYPE, "../../elsewhere"
            archive.addfile(member)
        member = tarfile.TarInfo("original-business-content")
        member.mode, member.size = 0o644, 5
        archive.addfile(member, io.BytesIO(b"hello"))
    return output.getvalue()


class LocalRegistry:
    def __init__(self, case, media=m.DOCKER_MANIFEST, index=False, fault=None):
        self.case, self.fault = case, fault
        self.requests, self.blobs, self.manifests = [], {}, {}
        self.root = None
        self.published = False
        self.post_count = 0
        self.foreign_origin = "http://127.0.0.1:9"
        self.agent = elf()
        self.repository = "openclaw-lite"
        plain = tar_bytes(symlink_parent=fault == "symlink_parent")
        compressed = m.stored_gzip(plain)
        layer_media = "application/vnd.oci.image.layer.v1.tar+gzip" if media == m.OCI_MANIFEST else "application/vnd.docker.image.rootfs.diff.tar.gzip"
        self.layer = {"mediaType": layer_media, "size": len(compressed), "digest": m.digest(compressed)}
        self.blobs[self.layer["digest"]] = compressed
        diff_id = m.digest(plain) if fault != "diffid" else "sha256:" + "a" * 64
        self.config = {"architecture": "amd64" if fault != "arm64" else "arm64", "os": "linux",
            "created": "2025-01-01T00:00:00Z", "config": {"Env": ["PRIVATE=" + SECRET], "Entrypoint": ["/original/start"],
            "Cmd": ["--original"], "User": "1001:1001", "WorkingDir": "/original", "Labels": {"source": "original"}},
            "rootfs": {"type": "layers", "diff_ids": [diff_id]},
            "history": [{"created_by": "original", "empty_layer": False}], "other_original": {"keep": True}}
        config_raw = m.encode(self.config)
        self.config_descriptor = {"mediaType": m.OCI_CONFIG if media == m.OCI_MANIFEST else m.DOCKER_CONFIG,
            "size": len(config_raw), "digest": m.digest(config_raw)}
        self.blobs[self.config_descriptor["digest"]] = config_raw
        self.manifest = {"schemaVersion": 2, "mediaType": media, "config": self.config_descriptor, "layers": [self.layer],
            "annotations": {"keep-original": "yes"}}
        if fault == "external_layer":
            self.layer["urls"] = ["https://untrusted.invalid/elsewhere"]
        if fault == "foreign_layer":
            self.layer["mediaType"] = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
        raw = m.encode(self.manifest)
        self.child_digest = m.digest(raw)
        self.manifests[self.child_digest] = raw
        if index:
            item = {"mediaType": media, "digest": self.child_digest, "size": len(raw), "platform": {"os": "linux", "architecture": "amd64"}}
            doc = {"schemaVersion": 2, "mediaType": m.OCI_INDEX if media == m.OCI_MANIFEST else m.DOCKER_INDEX,
                "manifests": [item, copy.deepcopy(item)] if fault == "duplicate_platform" else [item]}
            raw = m.encode(doc)
            self.manifests[m.digest(raw)] = raw
        self.root = m.digest(raw)
        self.profile = {"repository": self.repository, "base": self.root,
            "agent_sha": hashlib.sha256(self.agent).hexdigest(), "agent_size": len(self.agent)}
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, code, raw=b"", headers=None):
                self.send_response(code)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                if raw:
                    try:
                        self.wfile.write(raw)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            def do_GET(self):
                fixture.requests.append(("GET", self.path))
                path = urllib.parse.urlsplit(self.path).path
                if "/manifests/" in path:
                    reference = path.split("/manifests/", 1)[1]
                    raw = fixture.manifests.get(reference)
                    if raw is None:
                        return self.reply(404)
                    if (fixture.fault == "base_body" and reference == fixture.root) or (fixture.fault == "manifest_readback" and fixture.published and reference not in (fixture.root, fixture.child_digest)):
                        raw = b"corrupt manifest"
                    media_type = json.loads(fixture.manifests[reference])["mediaType"]
                    return self.reply(200, raw, {"Docker-Content-Digest": reference, "Content-Type": media_type})
                reference = path.split("/blobs/", 1)[-1]
                raw = fixture.blobs.get(reference)
                if raw is None:
                    return self.reply(404)
                if fixture.fault == "redirect" and reference == fixture.config_descriptor["digest"]:
                    return self.reply(302, headers={"Location": fixture.foreign_origin + "/leak"})
                if fixture.fault == "config_body" and reference == fixture.config_descriptor["digest"]:
                    raw = raw[:-1] + b"X"
                if fixture.fault == "layer_crc" and reference == fixture.layer["digest"]:
                    raw = raw[:-8] + b"\x01" + raw[-7:]
                if fixture.fault == "uploaded_blob_readback" and reference not in (fixture.layer["digest"], fixture.config_descriptor["digest"]):
                    raw = raw[:-1] + bytes([raw[-1] ^ 1])
                return self.reply(200, raw, {"Docker-Content-Digest": reference})

            def do_POST(self):
                fixture.requests.append(("POST", self.path))
                fixture.post_count += 1
                location = "/v2/" + fixture.repository + "/blobs/uploads/test-upload?_state=a%2Bb"
                if fixture.fault == "foreign_location":
                    location = fixture.foreign_origin + location
                if fixture.fault == "repository_location":
                    location = "/v2/other-repo/blobs/uploads/test-upload"
                if fixture.fault == "encoded_location":
                    location = "/v2/" + fixture.repository + "/blobs/uploads/%2e%2e"
                return self.reply(202, headers={"Location": location})

            def do_PUT(self):
                fixture.requests.append(("PUT", self.path))
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                value = urllib.parse.urlsplit(self.path)
                sha = m.digest(raw)
                if "/blobs/uploads/" in value.path:
                    query = urllib.parse.parse_qs(value.query)
                    case.assertEqual(query.get("digest"), [sha])
                    case.assertEqual(query.get("_state"), ["a+b"])
                    fixture.blobs[sha] = raw
                    header = "sha256:" + "f" * 64 if fixture.fault == "upload_digest" else sha
                    return self.reply(201, headers={"Docker-Content-Digest": header,
                        "Location": "/v2/" + fixture.repository + "/blobs/" + sha})
                reference = value.path.split("/manifests/", 1)[-1]
                case.assertEqual(reference, sha)
                fixture.manifests[sha] = raw
                fixture.published = True
                return self.reply(201, headers={"Docker-Content-Digest": sha})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        self.patch = mock.patch.object(m, "REGISTRY_ORIGIN", self.origin)
        self.patch.start()
        case.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.patch.stop()

    def run(self, push=True):
        return m.build(m.Registry(self.repository), "openclaw", self.profile, self.agent, push=push)


class RegistryTests(unittest.TestCase):
    def test_pushed_preserves_runtime_and_original_layers_and_is_idempotent(self):
        for media, indexed in ((m.OCI_MANIFEST, False), (m.DOCKER_MANIFEST, False), (m.OCI_MANIFEST, True), (m.DOCKER_MANIFEST, True)):
            with self.subTest(media=media, index=indexed):
                fixture = LocalRegistry(self, media, indexed)
                result = fixture.run()
                self.assertEqual(result["status"], "image-pushed")
                new_manifest = json.loads(fixture.manifests[result["manifest_digest"]])
                new_config = json.loads(fixture.blobs[result["config_digest"]])
                self.assertEqual(new_manifest["layers"][:-1], fixture.manifest["layers"])
                self.assertEqual(new_config["config"], fixture.config["config"])
                self.assertEqual(new_config["rootfs"]["diff_ids"][:-1], fixture.config["rootfs"]["diff_ids"])
                preserved = copy.deepcopy(new_config)
                preserved["rootfs"]["diff_ids"].pop()
                preserved["history"].pop()
                self.assertEqual(preserved, fixture.config)
                self.assertNotIn(SECRET, m.encode(result).decode())
                self.assertFalse(result["tag_written"])
                for key in ("page", "native", "live", "workload_mutated", "deployment_identity_rechecked"):
                    self.assertIs(result[key], False)
                posts, puts = fixture.post_count, len([x for x in fixture.requests if x[0] == "PUT"])
                self.assertEqual(fixture.run(), result)
                self.assertEqual(posts, fixture.post_count)
                self.assertEqual(puts, len([x for x in fixture.requests if x[0] == "PUT"]))
                self.assertTrue(all("/manifests/sha256:" in path for method, path in fixture.requests if method == "PUT" and "/manifests/" in path))

    def test_build_does_not_upload_or_publish(self):
        fixture = LocalRegistry(self)
        result = fixture.run(push=False)
        self.assertEqual(result["status"], "image-built")
        self.assertEqual({method for method, _ in fixture.requests}, {"GET"})
        self.assertFalse(fixture.published)

    def test_corrupt_or_incompatible_base_refuses_before_upload(self):
        for fault in ("base_body", "config_body", "layer_crc", "diffid", "arm64", "symlink_parent", "external_layer", "foreign_layer", "duplicate_platform", "redirect"):
            with self.subTest(fault=fault):
                fixture = LocalRegistry(self, index=fault == "duplicate_platform", fault=fault)
                with self.assertRaises(m.Refused):
                    fixture.run()
                self.assertFalse(any(method != "GET" for method, _ in fixture.requests))
                self.assertFalse(fixture.published)

    def test_upload_location_failure_digest_and_readback_refuse(self):
        for fault in ("foreign_location", "repository_location", "encoded_location", "upload_digest", "uploaded_blob_readback", "manifest_readback"):
            with self.subTest(fault=fault):
                fixture = LocalRegistry(self, fault=fault)
                with self.assertRaises(m.Refused):
                    fixture.run()
                if fault != "manifest_readback":
                    self.assertFalse(fixture.published)
                if "location" in fault:
                    self.assertFalse(any(method == "PUT" for method, _ in fixture.requests))

    def test_origin_and_repository_urls_cannot_escape(self):
        fixture = LocalRegistry(self)
        registry = m.Registry(fixture.repository)
        for path in ("http://other.invalid/v2/openclaw-lite/blobs/uploads/x", "//other.invalid/leak",
                     fixture.origin + "@other.invalid/v2/openclaw-lite/x", "/v2/other/x", "/v2/openclaw-lite/../other/x",
                     "/v2/openclaw-lite/%2fother/x", "/v2/openclaw-lite/x#secret", "/v2/openclaw-lite/x\r\nX:a"):
            with self.subTest(path=path), self.assertRaises(m.Refused):
                registry.url(path)
        self.assertEqual(fixture.requests, [])

    def test_cli_stdout_excludes_config_env_and_credentials(self):
        fixture = LocalRegistry(self)
        output = io.StringIO()
        with mock.patch.dict(m.PROFILES, {"openclaw": fixture.profile}), mock.patch.object(m, "agent_from_bundle", return_value=fixture.agent), contextlib.redirect_stdout(output):
            m.main(["--runtime", "openclaw", "--bundle", "/unused-fixture-bundle", "--push"])
        self.assertNotIn(SECRET, output.getvalue())
        self.assertNotIn("Env", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "image-pushed")

    def test_redirect_and_foreign_upload_never_send_credentials_to_canary(self):
        received = []

        class Canary(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                received.append((self.command, self.headers.get("Authorization")))
                self.send_response(500)
                self.end_headers()

            do_POST = do_PUT = do_GET

        server = ThreadingHTTPServer(("127.0.0.1", 0), Canary)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        for fault, code in (("redirect", "registry_redirect_refused"), ("foreign_location", "registry_origin_or_repository")):
            with self.subTest(fault=fault):
                fixture = LocalRegistry(self, fault=fault)
                fixture.foreign_origin = "http://127.0.0.1:" + str(server.server_port)
                registry = m.Registry(fixture.repository, authorization="Bearer test-credential-only")
                with self.assertRaises(m.Refused) as caught:
                    m.build(registry, "openclaw", fixture.profile, fixture.agent, push=True)
                self.assertEqual(str(caught.exception), code)
                self.assertEqual(received, [])


class OfflineTests(unittest.TestCase):
    def test_real_frozen_bundle_both_static_linux_amd64_elfs(self):
        default = Path(__file__).resolve().parent.parent / ".tmp-supervisor-agent-build-20261103/release-inputs/agent-prebuilt-2408962c473d-linux-amd64.tar.gz"
        bundle = Path(os.environ.get("A_AGENT_RUNTIME_BUNDLE", str(default)))
        self.assertTrue(bundle.is_file(), "actual pinned release input is required; no skipped input check")
        for runtime in sorted(m.PROFILES):
            with self.subTest(runtime=runtime):
                agent = m.agent_from_bundle(bundle, runtime)
                self.assertEqual(hashlib.sha256(agent).hexdigest(), m.PROFILES[runtime]["agent_sha"])
                compressed, diff_id = m.agent_layer(agent)
                plain = gzip.decompress(compressed)
                self.assertEqual(m.digest(plain), diff_id)
                with tarfile.open(fileobj=io.BytesIO(plain)) as archive:
                    members = archive.getmembers()
                    self.assertEqual([x.name for x in members], [m.TARGET])
                    self.assertEqual(members[0].mode, 0o555)
                    self.assertEqual(archive.extractfile(members[0]).read(), agent)

    def test_elf_sha_architecture_dynamic_and_truncation_refuse(self):
        good = elf()
        for fault in ("sha", "arm64", "dynamic", "truncated", "entry"):
            raw = bytearray(good)
            if fault == "arm64":
                struct.pack_into("<H", raw, 18, 183)
            elif fault == "dynamic":
                struct.pack_into("<I", raw, 64, 3)
            elif fault == "truncated":
                raw = raw[:100]
            elif fault == "entry":
                struct.pack_into("<Q", raw, 24, 0x900000)
            profile = {"agent_size": len(raw), "agent_sha": hashlib.sha256(raw).hexdigest() if fault != "sha" else "a" * 64}
            with self.subTest(fault=fault), self.assertRaises(m.Refused):
                m.validate_elf(bytes(raw), profile)

    def test_layer_deterministic_and_json_duplicate_rejected(self):
        agent = elf()
        self.assertEqual(m.agent_layer(agent), m.agent_layer(agent))
        self.assertEqual(m.stored_gzip(b"abc"), m.stored_gzip(b"abc"))
        for value in (b'{"Env":1,"Env":2}', b'{"v":NaN}', b'[]'):
            with self.subTest(value=value), self.assertRaises(m.Refused):
                m.decode(value)

    def test_bundle_corruption_fails_before_registry(self):
        with tempfile.TemporaryDirectory(prefix="a-agent-registry-") as directory:
            path = Path(directory) / "invalid.tar.gz"
            path.write_bytes(b"not-the-pinned-bundle")
            with self.assertRaisesRegex(m.Refused, "bundle_sha"):
                m.agent_from_bundle(path, "openclaw")

    def test_credential_file_shape_and_no_body_in_error(self):
        with tempfile.TemporaryDirectory(prefix="a-agent-registry-credentials-") as directory:
            path = Path(directory) / "registry.json"
            for value, prefix in (({"username": "fixture", "password": SECRET}, "Basic "), ({"bearer_token": "fixture-token"}, "Bearer ")):
                with self.subTest(shape=prefix):
                    path.write_bytes(m.encode(value))
                    path.chmod(0o600)
                    self.assertTrue(m.credentials(path).startswith(prefix))
            path.write_bytes(m.encode({"username": SECRET, "unexpected": SECRET}))
            with self.assertRaises(m.Refused) as caught:
                m.credentials(path)
            self.assertNotIn(SECRET, str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
