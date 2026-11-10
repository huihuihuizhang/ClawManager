"""Offline layer/whiteout models and loopback Registry only; no Agent runs."""
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


m = module("candidate_agent_runtime_layer", HERE / "agent_runtime_layer.py")
old_test = HERE / "test_agent_runtime_layer.py"
if not old_test.is_file():
    old_test = ROOT / "scripts/system-backup-agent-runtime-layer/test_agent_runtime_layer.py"
t = module("original_layer_model", old_test)
t.m = m


def base_tar(fault=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as out:
        for name in ("usr", "usr/local", "usr/local/bin", "etc", "etc/services.d", "etc/services.d/openclaw-agent", "bin"):
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.uid, item.gid = tarfile.DIRTYPE, 0o755, 0, 0
            if fault == "parent_symlink" and name == "etc/services.d":
                item.type, item.linkname = tarfile.SYMTYPE, "elsewhere"
            if fault == "parent_hardlink" and name == "etc/services.d":
                item.type, item.linkname = tarfile.LNKTYPE, "elsewhere"
            if fault == "parent_owner" and name == "etc":
                item.uid = 1000
            if fault == "parent_writable" and name == "usr/local/bin":
                item.mode = 0o777
            out.addfile(item)
        prefix = b"#!/usr/bin/with-contenv bash\nset -euo pipefail\n\n"
        original = prefix + m.WRAPPER.split(b"fi\n\n", 1)[1]
        if fault == "service_bytes":
            original += b"# substituted\n"
        for name, data, mode in ((m.SERVICE, original, 0o755), ("bin/sleep", b"original-immutable-base-executable", 0o755)):
            item = tarfile.TarInfo(name)
            item.mode, item.size = mode, len(data)
            if fault == "service_symlink" and name == m.SERVICE:
                item.type, item.linkname, item.size = tarfile.SYMTYPE, "elsewhere", 0
            if fault == "service_owner" and name == m.SERVICE:
                item.uid = 1000
            if fault == "sleep_nonexec" and name == "bin/sleep":
                item.mode = 0o644
            out.addfile(item, io.BytesIO(data) if item.isfile() else None)
        if fault == "whiteout_service":
            out.addfile(tarfile.TarInfo("etc/services.d/openclaw-agent/.wh.run"))
    return stream.getvalue()


def fixture(case, fault=None):
    f = t.LocalRegistry(case)
    # Controlled fixture uses synthetic ELF and explicit patched profile pins.
    # Production constants remain immutable; the real bundle is not read here.
    elf = t.elf()
    f.agent = elf + b"\x00" * (m.PROFILES["openclaw"]["agent_size"] - len(elf))
    plains = [base_tar(fault)]
    if fault in ("whiteout_service", "opaque_parent"):
        plains = [base_tar()]
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as archive:
            archive.addfile(tarfile.TarInfo("etc/services.d/openclaw-agent/" + (".wh.run" if fault == "whiteout_service" else ".wh..wh..opq")))
        plains.append(out.getvalue())
    layers = []
    for plain in plains:
        compressed = m.stored_gzip(plain)
        descriptor = {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": len(compressed), "digest": m.digest(compressed)}
        f.blobs[descriptor["digest"]] = compressed
        layers.append(descriptor)
    f.config["rootfs"]["diff_ids"] = [m.digest(p) for p in plains]
    f.config["history"] = [{"created_by": "original"} for _ in plains]
    cfg = m.encode(f.config)
    f.config_descriptor.update(digest=m.digest(cfg), size=len(cfg))
    f.blobs[m.digest(cfg)] = cfg
    f.manifest.update(config=f.config_descriptor, layers=layers)
    data = m.encode(f.manifest)
    f.root = f.child_digest = m.digest(data)
    f.manifests[f.root] = data
    f.profile.update(base=f.root, agent_sha=m.digest(f.agent)[7:], agent_size=len(f.agent))
    for name, value in (("OPENCLAW_BASE", f.root), ("OPENCLAW_AGENT_SHA", f.profile["agent_sha"])):
        active = patch.object(m, name, value)
        active.start()
        case.addCleanup(active.stop)
    return f


class OpenClawServiceLayer(unittest.TestCase):
    def test_exact_two_members_roundtrip_config_and_deterministic_receipt(self):
        f = fixture(self)
        first = m.build(m.Registry(f.repository), "openclaw", f.profile, f.agent, push=True, service_gate=True)
        self.assertTrue(first["openclaw_shared_service_gate"])
        self.assertFalse(first["legacy_state_migrated"])
        self.assertEqual(first["service_wrapper_sha256"], m.WRAPPER_SHA)
        image = json.loads(f.manifests[first["manifest_digest"]])
        self.assertEqual(image["layers"][:-1], f.manifest["layers"])
        config = json.loads(f.blobs[first["config_digest"]])
        self.assertEqual(config["config"], f.config["config"])
        config["rootfs"]["diff_ids"].pop()
        config["history"].pop()
        self.assertEqual(config, f.config)
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(f.blobs[first["appended_layer_digest"]]))) as archive:
            members = archive.getmembers()
            self.assertEqual([x.name for x in members], [m.TARGET, m.SERVICE])
            for member, mode in zip(members, (0o555, 0o755)):
                self.assertEqual((member.mode, member.uid, member.gid, member.mtime), (mode, 0, 0, 0))
            self.assertEqual(archive.extractfile(m.SERVICE).read(), m.WRAPPER)
        before = f.post_count
        self.assertEqual(first, m.build(m.Registry(f.repository), "openclaw", f.profile, f.agent, push=True, service_gate=True))
        self.assertEqual(before, f.post_count)
        self.assertNotIn(t.SECRET, m.encode(first).decode())

    def test_wrong_service_parent_whiteout_and_sleep_refuse_before_upload(self):
        for fault in ("parent_symlink", "parent_hardlink", "parent_owner", "parent_writable", "service_bytes", "service_symlink", "service_owner", "whiteout_service", "opaque_parent", "sleep_nonexec"):
            with self.subTest(fault=fault):
                f = fixture(self, fault)
                with self.assertRaises(m.Refused):
                    m.build(m.Registry(f.repository), "openclaw", f.profile, f.agent, push=True, service_gate=True)
                self.assertFalse(any(method != "GET" for method, _ in f.requests))

    def test_other_base_agent_hermes_and_arbitrary_wrapper_refuse(self):
        f = fixture(self)
        for fault in ("base", "agent", "hermes", "wrapper"):
            with self.subTest(fault=fault):
                profile = copy.deepcopy(f.profile)
                runtime = "openclaw"
                if fault == "base":
                    profile["base"] = "sha256:" + "0" * 64
                if fault == "agent":
                    profile["agent_sha"] = "0" * 64
                if fault == "hermes":
                    runtime = "hermes"
                with patch.object(m, "WRAPPER", b"arbitrary") if fault == "wrapper" else patch.object(m, "WRAPPER", m.WRAPPER):
                    with self.assertRaises(m.Refused):
                        m.build(m.Registry(f.repository), runtime, profile, f.agent, service_gate=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
