"""In-memory OCI/tar source models; no image installation or Agent execution."""
import contextlib
import gzip
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest

spec = importlib.util.spec_from_file_location("private_directory_layer", Path(__file__).with_name("agent_runtime_layer.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RegistryBytes:
    def __init__(self, blob, plain):
        self._blob = blob
        self.layer = {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": m.digest(blob), "size": len(blob)}
        self.config = {"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": [m.digest(plain)]}}
        raw = m.encode(self.config)
        self.image = {"schemaVersion": 2, "mediaType": m.OCI_MANIFEST, "config": {"mediaType": m.OCI_CONFIG, "digest": m.digest(raw), "size": len(raw)}, "layers": [self.layer]}

    def live(self):
        pass

    def path(self, *args):
        return "/in-memory-layer-model"

    @contextlib.contextmanager
    def request(self, *args, **kwargs):
        response = io.BytesIO(self._blob)
        response.status = 200
        yield response

    @contextlib.contextmanager
    def blob(self, descriptor):
        assert descriptor == self.layer
        with self.request("GET", self.path("blobs", descriptor["digest"])) as response:
            yield response

    def manifest(self, reference):
        return m.encode(self.image), self.image

    def json_blob(self, descriptor):
        return m.encode(self.config), self.config


def make_tar(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for member, content in members:
            archive.addfile(member, io.BytesIO(content) if content else None)
    return output.getvalue()


class SharedPrivateDirectoryLayerTests(unittest.TestCase):
    def test_exact_directory_metadata_and_preserved_service_wrapper(self):
        for runtime in ("openclaw", "hermes"):
            service = runtime == "openclaw"
            agent = b"fixture bytes, not an executed Agent ELF"
            blob, diff = m.agent_layer(agent, service_gate=service, private_runtime=runtime)
            plain = gzip.decompress(blob)
            self.assertEqual(diff, m.digest(plain))
            with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as archive:
                members = archive.getmembers()
                self.assertEqual([entry.name.rstrip("/") for entry in members], [m.TARGET] + ([m.SERVICE] if service else []) + [m.PRIVATE_AGENT_DIRS[runtime]])
                directory = members[-1]
                self.assertTrue(directory.isdir())
                self.assertEqual((directory.uid, directory.gid, directory.mode, directory.size, directory.mtime), (0, 0, 0o700, 0, 0))
            registry = RegistryBytes(blob, plain)
            m.check_layer(registry, registry.layer, diff, agent=agent, service_gate=service, private_runtime=runtime)

    def test_changed_directory_metadata_type_or_roster_refuses(self):
        agent = b"fixture ELF transport bytes"
        blob, _ = m.agent_layer(agent, private_runtime="hermes")
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(blob)), mode="r:") as archive:
            original = [(entry, archive.extractfile(entry).read() if entry.isfile() else b"") for entry in archive]
        for fault in ("mode", "owner", "group", "symlink", "foreign-path", "missing", "extra"):
            with self.subTest(fault=fault):
                import copy
                members = copy.deepcopy(original)
                directory = members[-1][0]
                if fault == "mode": directory.mode = 0o755
                elif fault == "owner": directory.uid = 1
                elif fault == "group": directory.gid = 1
                elif fault == "symlink": directory.type, directory.linkname = tarfile.SYMTYPE, "/workspaces"
                elif fault == "foreign-path": directory.name = "var/lib/foreign-agent"
                elif fault == "missing": members.pop()
                else: members.append(copy.deepcopy(members[-1]))
                plain = make_tar(members)
                registry = RegistryBytes(m.stored_gzip(plain), plain)
                with self.assertRaises(m.Refused):
                    m.check_layer(registry, registry.layer, m.digest(plain), agent=agent, private_runtime="hermes")

    def test_base_private_directory_ancestor_alias_refuses(self):
        for parent in ("var", "var/lib", "var/lib/clawmanager-agent"):
            with self.subTest(parent=parent):
                alias = tarfile.TarInfo(parent)
                alias.type, alias.linkname, alias.mode = tarfile.SYMTYPE, "/workspaces", 0o777
                plain = make_tar([(alias, b"")])
                registry = RegistryBytes(m.stored_gzip(plain), plain)
                with self.assertRaises(m.Refused):
                    m.resolve_base(registry, m.digest(m.encode(registry.image)), private_runtime="hermes")


if __name__ == "__main__":
    unittest.main()
