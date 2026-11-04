"""Canonical fixed-source hardlink tests; no actual image layer or ELF runs."""
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

here = Path(__file__).resolve().parent
root = here.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


m = load("r4_candidate", here / "agent_runtime_layer.py")
dependency = here / "test_openclaw_sleep_chain.py"
if not dependency.is_file():
    dependency = root / ".a-openclaw-sleep-chain-r3-20261104/scripts/system-backup-agent-runtime-layer/test_openclaw_sleep_chain.py"
t = load("canonical_source_chain_models", dependency)
t.m = m
t.SOURCE = m.COREUTILS_SOURCE
original_layer = t.layer


def canonical_layer(fault=None, hardlink=False):
    value = original_layer(fault=fault, hardlink=hardlink)
    if fault != "whiteout_source":
        return value
    # The r3 model whiteout names its former cargo-local source. In this
    # canonical-source variant, remove the ACTUAL archive-root source instead.
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(value)) as old, tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as new:
        for item in old:
            content = old.extractfile(item).read() if item.isfile() else None
            if item.name == "usr/lib/cargo/bin/coreutils/.wh.coreutils":
                item.name = "usr/bin/.wh.coreutils"
            new.addfile(item, io.BytesIO(content) if content is not None else None)
    return output.getvalue()


t.layer = canonical_layer


class CanonicalSourceChain(t.FixedSleepChain):
    def test_canonical_source_digest_length_mode_and_kind_are_exact(self):
        for fault in ("digest", "mode", "owner", "link"):
            with self.subTest(fault=fault), patch.object(m, "SLEEP_SHA", m.digest(t.PAYLOAD)[7:]), patch.object(m, "SLEEP_SIZE", len(t.PAYLOAD)):
                source = io.BytesIO(t.layer(hardlink=True))
                dest = io.BytesIO()
                with tarfile.open(fileobj=source) as old, tarfile.open(fileobj=dest, mode="w", format=tarfile.USTAR_FORMAT) as new:
                    for item in old:
                        content = old.extractfile(item).read() if item.isfile() else None
                        if item.name == m.COREUTILS_SOURCE:
                            if fault == "digest":
                                content += b"corrupt"
                                item.size = len(content)
                            if fault == "mode":
                                item.mode = 0o777
                            if fault == "owner":
                                item.uid = 1000
                            if fault == "link":
                                item.type, item.linkname, item.size, content = tarfile.SYMTYPE, "/arbitrary", 0, None
                        new.addfile(item, io.BytesIO(content) if content is not None else None)
                with self.assertRaises(m.Refused):
                    m.validate_service_state(t.read(dest.getvalue()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
