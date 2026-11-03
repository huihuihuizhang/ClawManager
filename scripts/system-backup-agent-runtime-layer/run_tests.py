#!/usr/bin/env python3
"""Run only offline and loopback tests, emitting a non-secret JSON receipt."""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_agent_runtime_layer

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bundle", type=Path, help="absolute path to the separately pinned prebuilt Agent bundle")
args = parser.parse_args()
if args.bundle is not None:
    if not args.bundle.is_absolute():
        parser.error("--bundle requires an absolute path")
    os.environ["A_AGENT_RUNTIME_BUNDLE"] = str(args.bundle)


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subcase_count = 0

    def addSubTest(self, test, subtest, error):
        self.subcase_count += 1
        super().addSubTest(test, subtest, error)


suite = unittest.defaultTestLoader.loadTestsFromModule(test_agent_runtime_layer)
result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
print(json.dumps({"scope": "offline-real-pinned-ELF-and-loopback-HTTP-registry-model-only",
    "roots": result.testsRun, "subcases": result.subcase_count, "failed": len(result.failures),
    "errors": len(result.errors), "skipped": len(result.skipped), "passed": result.wasSuccessful(),
    "field_network": False, "SSH": False, "docker": False, "buildkit": False,
    "page": False, "native": False, "live": False}, sort_keys=True))
sys.exit(0 if result.wasSuccessful() else 1)
