"""Run bounded integration checks against an explicitly owned LOCAL MySQL.

This driver is not an activation or deployment tool. Required tests that skip,
time out or disappear fail the selected stage. Evidence is local and ignored.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from contextlib import nullcontext
from local_storage import disposable_storage

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "be7da27dff85c2daf3321b8245ffdab024e67853"
STAGES = {
    "import": [
        ("./internal/db", ["TestBackupCopyImportPreservesRowsLedgerAndReentry",
                             "TestBackupCopyImportRejectsUnknownSchemaBeforeDDL",
                             "TestBackupCopyImportRejectsNonisolatedDatabase"], "real_mysql_exact_backup_source"),
    ],
    "schema": [
        ("./internal/db", ["TestMergedMigrationsMySQL/fresh", "TestMergedMigrationsMySQL/upgrade",
                           "TestMigrationCaptureExclusionRealMySQL"], "real_mysql"),
        ("./internal/systembackup", ["TestSchemaContractMatchesFreshMigrations"], "real_mysql"),
    ],
    "control": [
        ("./internal/systembackup", ["TestEngineSwitchPreservesOldHistoryAndExcludesActiveCapture",
                                      "TestConcurrentEnginesShareOneCaptureGate"], "real_mysql"),
        ("./internal/services", ["TestMaterializeWorkerStopTimeoutDoesNotAllowOverlappingRestart",
                                 "TestMaterializeWorkerStopJoinsJobsAndReleasesUnstartedClaims"], "model_boundary"),
        ("./internal/services/k8s", ["TestBrokerOwnerTeamCreateReplayDoesNotRotateOrAdoptForeignSecret",
                                     "TestSecretBrokerRejectsNoncanonicalTenantPrefixes"], "fake_kubernetes_http"),
    ],
    "data": [
        ("./internal/systembackup", ["TestFullSchemaTeamRestorePreservesScopeHistoryAndInterruptedResults",
                                      "TestLiveTeamBackupKeepsSnapshotWhileSourceTaskCompletes"], "real_mysql_only"),
    ],
    "storage": [
        ("./internal/systembackup", ["TestImmutableStoreConditionalCreateAndExactVersion",
                                      "TestRedisHistoryPreservesBinaryStreamsAndDoesNotReplay",
                                      "TestSixRealSourcesPublishAndDataOnlyRestore"], "real_mysql_redis_objects_files_fake_kubernetes"),
    ],
}


def command(args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, **kwargs)


def owned_mysql(name):
    item = json.loads(command(["docker", "inspect", name]))[0]
    if item.get("Config", {}).get("Labels", {}).get("codex.task") != "backup-team-integration":
        raise ValueError("MySQL container is not owned by this integration task")
    if not item["State"]["Running"] or item["Config"]["Image"] != "mysql:8.4":
        raise ValueError("unexpected MySQL image or stopped container")
    ports = item["NetworkSettings"]["Ports"]["3306/tcp"]
    if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
        raise ValueError("MySQL must be bound only to loopback")
    if "MYSQL_ALLOW_EMPTY_PASSWORD=yes" not in item["Config"]["Env"]:
        raise ValueError("unexpected local MySQL credentials")
    return item["Id"], ports[0]["HostPort"]


def candidate_tree_hash():
    # HEAD/diff alone omit the newly ported libraries before the first commit.
    paths = command(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"]).split(b"\0")
    digest = hashlib.sha256()
    for raw in sorted(set(path for path in paths if path)):
        path = ROOT / os.fsdecode(raw)
        value = path.read_bytes() if path.is_file() else b"<deleted>"
        for part in (raw, hashlib.sha256(value).digest()):
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--mysql-container", required=True)
    args = parser.parse_args()
    container, port = owned_mysql(args.mysql_container)
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = ROOT / "team-optimization-docs" / "backup-team-integration" / run_id
    if subprocess.run(["git", "check-ignore", "--quiet", str(output / "result.json")], cwd=ROOT).returncode != 0:
        raise ValueError("evidence directory must be ignored by Git")
    output.mkdir(parents=True)
    baseline_dir = output / "baseline-migrations"
    baseline_dir.mkdir()
    files = command(["git", "ls-tree", "-r", "--name-only", BASELINE, "backend/internal/db/migrations"]).decode().splitlines()
    for path in files:
        if path.endswith(".sql"):
            (baseline_dir / Path(path).name).write_bytes(command(["git", "show", f"{BASELINE}:{path}"]))
    env = os.environ.copy()
    # Inherit no opt-in production/cluster test variables. The selected cases
    # use only disposable loopback MySQL and in-process controlled boundaries.
    for key in list(env):
        if key.startswith(("TEST_SYSTEM_BACKUP_", "CLAWMANAGER_MERGE_TEST_")):
            del env[key]
    env.update(TEST_SYSTEM_BACKUP_MYSQL_PORT=port, CLAWMANAGER_MERGE_TEST_MYSQL_PORT=port,
               CLAWMANAGER_MERGE_TEST_BASELINE_MIGRATIONS=str(baseline_dir))
    if args.stage == "import":
        profile = json.loads((ROOT / "backend/internal/db/backup_import_map.json").read_text(encoding="utf-8"))
        source = profile["source_git_sha"]
        source_dir = output / "source-migrations"
        source_dir.mkdir()
        for filename, digest in profile["migrations"].items():
            raw = command(["git", "show", f"{source}:backend/internal/db/migrations/{filename}"])
            normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            if hashlib.sha256(normalized).hexdigest() != digest:
                raise ValueError("source migration differs from reviewed import profile")
            (source_dir / filename).write_bytes(raw)
        env["CLAWMANAGER_BACKUP_SOURCE_MIGRATIONS"] = str(source_dir)
    storage = disposable_storage() if args.stage == "storage" else nullcontext(({}, {}))
    with storage as (storage_env, cleanup):
        env.update(storage_env)
        results = run_stage(args.stage, env, output)
    report = {"stage": args.stage, "baseline": BASELINE,
              "head": command(["git", "rev-parse", "HEAD"]).decode().strip(),
              "candidate_tree_sha256": candidate_tree_hash(),
              "mysql_container_id": container, "results": results,
              "passed": len(results) == len(STAGES[args.stage]) and all(r["passed"] for r in results) and not cleanup.get("cleanup_failed"),
              "limits": "Does not establish v2 execution, real Kubernetes/model/browser/image or deployment acceptance. Storage stage uses a controlled K8s boundary and fixture object administrator.",
              "cleanup": cleanup or "Per-test databases cleaned where implemented; disposable MySQL retained for follow-up."}
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(output / "result.json")
    return 0 if report["passed"] else 1


def run_stage(stage, env, output):
    results = []
    for index, (package, required, kind) in enumerate(STAGES[stage]):
        roots = sorted({name.split("/")[0] for name in required})
        log = output / f"{index}.jsonl"
        cmd = ["go", "test", "-json", "-count=1", "-timeout=8m", package, "-run", "^(" + "|".join(roots) + ")$"]
        timed_out = False
        with log.open("wb") as sink:
            try:
                code = subprocess.run(cmd, cwd=ROOT / "backend", env=env, stdout=sink,
                                      stderr=subprocess.STDOUT, timeout=510).returncode
            except subprocess.TimeoutExpired:
                code, timed_out = 124, True
        states = {}
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("Test") and event.get("Action") in ("pass", "fail", "skip"):
                states[event["Test"]] = event["Action"]
        missing = [name for name in required if states.get(name) != "pass"]
        result = {"package": package, "kind": kind, "exit_code": code, "timeout": timed_out,
                  "required": {name: states.get(name, "missing") for name in required},
                  "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                  "passed": code == 0 and not missing}
        results.append(result)
        print(f'{package}: {"PASS" if result["passed"] else "FAIL"} ({kind})', flush=True)
        if not result["passed"]:
            break
    return results


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError, KeyError) as exc:
        # Do not echo environment, credentials or external command output.
        print(f"Integration driver rejected the setup: {type(exc).__name__}", file=sys.stderr)
        sys.exit(2)
