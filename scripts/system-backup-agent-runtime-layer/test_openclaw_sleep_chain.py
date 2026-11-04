import importlib.util
import io
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("sleep_chain_r3", Path(__file__).with_name("agent_runtime_layer.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PAYLOAD = b"model fixed sleep ELF content, not actual native binary"
SOURCE = "usr/lib/cargo/bin/coreutils/coreutils"


def layer(fault=None, hardlink=False):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in tuple(dict.fromkeys(m.TRACKED[:-1] + m.GATE_PATHS[:3] + ("usr/bin",) + m.SLEEP_PARENTS)):
            member = tarfile.TarInfo(name)
            member.type, member.mode = tarfile.DIRTYPE, 0o755
            if fault == "parent_link" and name == "usr/lib/cargo/bin":
                member.type, member.linkname = tarfile.SYMTYPE, "/elsewhere"
            if fault == "parent_owner" and name == "usr/lib/cargo":
                member.uid = 1
            archive.addfile(member)
        for name, target in (("bin", "usr/bin"), ("usr/bin/sleep", "../lib/cargo/bin/coreutils/sleep")):
            member = tarfile.TarInfo(name)
            member.type, member.mode, member.linkname = tarfile.SYMTYPE, 0o777, target
            if fault == "other_symlink" and name == "usr/bin/sleep":
                member.linkname = "../lib/cargo/bin/coreutils/other"
            archive.addfile(member)
        original = b"#!/usr/bin/with-contenv bash\nset -euo pipefail\n\n" + m.WRAPPER.split(b"fi\n\n", 1)[1]
        member = tarfile.TarInfo(m.SERVICE)
        member.mode, member.size = 0o755, len(original)
        archive.addfile(member, io.BytesIO(original))
        def regular(name, data=PAYLOAD):
            member = tarfile.TarInfo(name)
            member.mode, member.size = 0o755, len(data)
            if fault == "target_owner":
                member.uid = 1
            archive.addfile(member, io.BytesIO(data))
        if hardlink:
            if fault != "forward_link":
                regular(SOURCE)
            if fault == "whiteout_source":
                archive.addfile(tarfile.TarInfo("usr/lib/cargo/bin/coreutils/.wh.coreutils"))
            member = tarfile.TarInfo(m.SLEEP_TARGET)
            member.type, member.mode, member.linkname = tarfile.LNKTYPE, 0o755, SOURCE
            if fault == "outside_link":
                member.linkname = "usr/bin/other"
            if fault == "link_mode":
                member.mode = 0o777
            archive.addfile(member)
            if fault == "forward_link":
                regular(SOURCE)
        else:
            regular(m.SLEEP_TARGET, PAYLOAD + b"tampered" if fault == "wrong_digest" else PAYLOAD)
    return out.getvalue()


class Registry:
    def __init__(self, content):
        self.content = content
    def live(self):
        pass
    def blob(self, descriptor):
        return io.BytesIO(self.content)


def read(plain, state=None):
    blob = m.stored_gzip(plain)
    descriptor = {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": len(blob), "digest": m.digest(blob)}
    whiteouts, entries = m.check_layer(Registry(blob), descriptor, m.digest(plain), service_gate=True, base_state=state)
    final = dict(state or {})
    for path, opaque in whiteouts:
        for item in list(final):
            if item.startswith(path + "/") or not opaque and item == path:
                final.pop(item)
    final.update(entries)
    return final


class FixedSleepChain(unittest.TestCase):
    def test_exact_symlink_chain_regular_or_ordered_hardlink_content(self):
        for hardlink in (False, True):
            with self.subTest(hardlink=hardlink), patch.object(m, "SLEEP_SHA", m.digest(PAYLOAD)[7:]), patch.object(m, "SLEEP_SIZE", len(PAYLOAD)):
                state = read(layer(hardlink=hardlink))
                m.validate_service_state(state)
                self.assertEqual(state[m.SLEEP_TARGET][5], m.digest(PAYLOAD)[7:])
                self.assertEqual(state[m.SLEEP_TARGET][0], "resolved-hardlink" if hardlink else "regular")

    def test_wrong_chain_parent_content_or_unresolved_hardlink_refuse(self):
        for fault, hardlink in (("parent_link", False), ("parent_owner", False), ("other_symlink", False), ("target_owner", False), ("wrong_digest", False), ("forward_link", True), ("outside_link", True), ("whiteout_source", True), ("link_mode", True)):
            with self.subTest(fault=fault), patch.object(m, "SLEEP_SHA", m.digest(PAYLOAD)[7:]), patch.object(m, "SLEEP_SIZE", len(PAYLOAD)), self.assertRaises(m.Refused):
                m.validate_service_state(read(layer(fault=fault, hardlink=hardlink)))

    def test_final_fs_model_cannot_substitute_for_actual_tar_source(self):
        # Production SHA/size pins remain exact Root-reported native content.
        self.assertEqual(m.SLEEP_SHA, "48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0")
        self.assertEqual(m.SLEEP_SIZE, 11352352)
        with self.assertRaises(m.Refused):
            m.validate_service_state(read(layer()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
