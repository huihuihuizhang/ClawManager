"""Pure stream tar models. POSIX backslash is data, never a separator."""
import gzip
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest

spec = importlib.util.spec_from_file_location("layer_posix_r2", Path(__file__).with_name("agent_runtime_layer.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def archive(names):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        for name in names:
            member = tarfile.TarInfo(name)
            member.mode, member.size = 0o644, 4
            stream.addfile(member, io.BytesIO(b"body"))
    return target.getvalue()


class Reader:
    def __init__(self, content):
        self.content = content
        self.stream = None
    def live(self):
        pass
    def blob(self, descriptor):
        self.stream = io.BytesIO(self.content)
        return self.stream


def check(names, gate=False, corrupt=False, wrong_diff=False):
    plain = archive(names)
    compressed = m.stored_gzip(plain)
    if corrupt:
        compressed = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
    reader = Reader(compressed)
    descriptor = {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": len(compressed), "digest": m.digest(compressed)}
    diff = "sha256:" + "f" * 64 if wrong_diff else m.digest(plain)
    return m.check_layer(reader, descriptor, diff, service_gate=gate)


class POSIXLayerNames(unittest.TestCase):
    def test_real_systemd_literal_backslash_and_unrelated_aliases_are_data(self):
        actual = r"usr/lib/systemd/system/system-systemd\x2dmute\x2dconsole.slice"
        for gate in (False, True):
            with self.subTest(gate=gate):
                whiteouts, entries = check([actual, r"usr\local\bin\clawmanager-agent", r"etc\services.d\openclaw-agent\run"], gate=gate)
                self.assertEqual(whiteouts, [])
                self.assertEqual(entries, [])
        whiteouts, entries = check([actual, m.TARGET])
        self.assertEqual(entries, [(m.TARGET, "regular")])
        self.assertEqual(whiteouts, [])

    def test_absolute_and_dotdot_still_refuse(self):
        for name in ("/usr/absolute", "../escape", "usr/../escape", r"usr/../escape\literal"):
            with self.subTest(name=name), self.assertRaisesRegex(m.Refused, "layer_path"):
                check([name])

    def test_backslash_layer_crc_diffid_and_exact_whiteout_still_checked(self):
        actual = r"usr/lib/systemd/system/system-systemd\x2dmute\x2dconsole.slice"
        for corrupt, wrong_diff in ((True, False), (False, True)):
            with self.subTest(corrupt=corrupt, wrong_diff=wrong_diff), self.assertRaises(m.Refused):
                check([actual], corrupt=corrupt, wrong_diff=wrong_diff)
        whiteouts, entries = check([actual, r"etc\services.d/.wh.run", "etc/services.d/openclaw-agent/.wh.run"], gate=True)
        self.assertEqual(whiteouts, [(r"etc\services.d/run", False), (m.SERVICE, False)])
        self.assertEqual(entries, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
