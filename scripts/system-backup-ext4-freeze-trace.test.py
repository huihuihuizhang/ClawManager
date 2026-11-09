"""Offline regressions for the one-time freeze trace evidence gate."""

from pathlib import Path
import runpy
import struct
import unittest


probe = runpy.run_path(str(Path(__file__).with_name("system-backup-ext4-freeze-trace.py")))
probes = {"freeze_dev": ("freeze", "dev"), "freeze_rc": ("freeze", "rc"),
          "thaw_dev": ("thaw", "dev"), "thaw_rc": ("thaw", "rc")}
clean_stats = "overrun: 0\ncommit overrun: 0\ndropped events: 0\n"


def rows(*events):
    return "\n".join(f" worker-{tid} [002] d..1. 1.{stamp:06}: {name}: (function) {field}={value}"
                     for tid, stamp, name, field, value in events)


def call(operation, device, tid, start, end, rc=0):
    return dict(operation=operation, device=device, tid=tid, start_ns=start, end_ns=end, rc=rc)


class FreezeTraceTest(unittest.TestCase):
    def test_superblock_offset_comes_from_btf_layout(self):
        names = b"\0super_block\0s_dev\0"
        types = struct.pack("<6I", 1, (4 << 24) | 1, 256, 13, 1, 192)
        header = struct.pack("<HBB5I", 0xEB9F, 1, 0, 24, 0, len(types), len(types), len(names))
        self.assertEqual(probe["super_device_offset"](header + types + names), 24)

    def test_independent_thaw_has_its_own_tid_and_success_return(self):
        trace = rows((40, 10, "freeze_dev", "dev", 7), (40, 20, "freeze_rc", "rc", 0),
                     (80, 30, "thaw_dev", "dev", 8), (81, 40, "thaw_dev", "dev", 7),
                     (80, 50, "thaw_rc", "rc", 0), (81, 60, "thaw_rc", "rc", 0),
                     (40, 70, "thaw_dev", "dev", 7), (40, 80, "thaw_rc", "rc", -22))
        profile = "freeze_dev 1 0\nfreeze_rc 1 0\nthaw_dev 3 0\nthaw_rc 3 0\n"
        calls = probe["trace_calls"](trace, probes, profile, [clean_stats])
        status, target = probe["cycle_status"](calls, 7, 40)
        self.assertEqual(status, "FOREIGN_THAW_OBSERVED")
        self.assertEqual([c["tid"] for c in target if c["rc"] == 0], [40, 81])
        for damaged, counts, stats in (
            (trace.rsplit("\n", 1)[0], profile, clean_stats),
            (trace, profile.replace("thaw_rc 3 0", "thaw_rc 3 1"), clean_stats),
            (trace, profile, clean_stats.replace("dropped events: 0", "dropped events: 1")),
            (trace, profile.replace("freeze_rc 1 0", "freeze_rc 2 0"), clean_stats),
        ):
            with self.subTest(profile=counts, stats=stats, rows=len(damaged.splitlines())):
                with self.assertRaises(RuntimeError):
                    probe["trace_calls"](damaged, probes, counts, [stats])

    def test_common_window_requires_both_lease_pids_and_conservative_bounds(self):
        judge = probe["storage_window"]
        calls = [call("freeze", 7, 41, 1_000, 3_000), call("freeze", 8, 42, 1_000, 4_000),
                 call("thaw", 7, 81, 18_000, 19_000), call("thaw", 8, 82, 18_000, 20_000)]
        owners = {7: (41, 81), 8: (42, 82)}
        marks = (7_000, 12_000, 15_000)
        self.assertEqual(judge(calls, {7, 8}, marks, owners)[0], "WINDOW_OBSERVED")
        self.assertEqual(judge(calls, {7, 8}, marks, {7: (41, 81)})[0], "UNVERIFIED")
        self.assertEqual(judge(calls, {7, 8}, (4_001, 12_000, 15_000), owners)[0], "UNVERIFIED")
        early = calls[:2] + [call("thaw", 8, 999, 8_000, 10_000)]
        self.assertEqual(judge(early, {7, 8}, (7_000, 0, 15_000), {})[0], "FAIL_EARLY_THAW")
        overlap = calls[:2] + [call("thaw", 8, 999, 14_999, 17_001)]
        self.assertEqual(judge(overlap, {7, 8}, marks, {})[0], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
