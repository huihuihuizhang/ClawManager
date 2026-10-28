"""Regenerate source provenance; requires the reviewed backup commit locally.

This is a review aid, not a merge or activation tool. It never fetches, stages,
commits, pushes or executes a source fixture. Hashes refer to source Git blobs
and current working-tree bytes respectively.
"""
import hashlib
import io
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SOURCE = "4fe83bcde5a8a693dddb2635e9a3e397d6e3472e"
MANIFEST = ROOT / "docs/backup-team-integration/source-map.json"


def git(*args, **kwargs):
    return subprocess.check_output(["git", *args], cwd=ROOT, **kwargs)


def main():
    if git("rev-parse", SOURCE).decode().strip() != SOURCE:
        raise ValueError("unreviewed source")
    prior = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if prior["backup_source"] != SOURCE:
        prior.setdefault("previous_reviewed_sources", []).append(prior["backup_source"])
        prior["backup_source"] = SOURCE
    dispositions = {item["path"]: item["disposition"] for item in prior["ports"]}
    sql_map = json.loads((ROOT / "docs/backup-team-integration/sql-map.json").read_text(encoding="utf-8"))
    reverse_sql = {target: source for source, target in sql_map["files"].items()}
    source_paths = set(filter(None, git("ls-tree", "-r", "--name-only", "-z", SOURCE).decode().split("\0")))
    changed = set(filter(None, git("diff", "--name-only", "-z", prior["team_baseline"]).decode().split("\0")))
    changed.update(filter(None, git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")))
    changed.discard(MANIFEST.relative_to(ROOT).as_posix())
    records = []
    for path in sorted(changed):
        if not (ROOT / path).is_file():
            raise ValueError("unexpected deletion requires explicit review: " + path)
        source_path = path if path in source_paths else None
        if path in {
            "backend/internal/systembackupapi/public_sql_writer.go",
            "backend/internal/systembackupapi/public_sql_writer_test.go",
        }:
            source_path = path.replace("public_sql_writer", "sql_writer")
        if path.startswith("backend/cmd/system-backup-v2-controller/"):
            source_path = path.replace("backend/cmd/system-backup-v2-controller/", "backend/cmd/system-backup-controller/", 1)
            if source_path not in source_paths:
                source_path = None
        original = reverse_sql.get(Path(path).name)
        if path.startswith("docs/backup-team-integration/reference/") and Path(path).suffix == ".sql":
            original = Path(path).name
        if path == "docs/backup-team-integration/reference/schema-registry-4fe83bcd.json":
            source_path = "contracts/system-backup/v12/schema-registry.json"
        if original:
            matches = [candidate for candidate in source_paths if Path(candidate).name == original]
            if len(matches) != 1:
                raise ValueError("ambiguous source SQL mapping: " + original)
            source_path = matches[0]
        records.append({"path": path, "source_path": source_path,
                        "source_sha256": None,
                        "working_tree_sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                        "disposition": dispositions.get(path, "integration-owned adaptation" if not source_path else "reviewed source port with Team compatibility adaptation")})
    requested = [record for record in records if record["source_path"]]
    queries = "\n".join(SOURCE + ":" + record["source_path"] for record in requested) + "\n"
    stream = io.BytesIO(git("cat-file", "--batch", input=queries.encode()))
    for record in requested:
        header = stream.readline().decode().strip().split()
        if len(header) != 3 or header[1] != "blob":
            raise ValueError("missing source blob: " + record["source_path"])
        raw = stream.read(int(header[2]))
        if stream.read(1) != b"\n":
            raise ValueError("invalid source object framing")
        record["source_sha256"] = hashlib.sha256(raw).hexdigest()
    prior["ports"] = records
    prior["status"] = "in_progress_not_activation_ready"
    prior["hash_basis"] = "source Git blob SHA256; target current worktree SHA256"
    prior["activation"] = "legacy retained; explicit public-v1 workspace functional composition exists; complete full-domain publication/restore not activation ready"
    MANIFEST.write_text(json.dumps(prior, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"Mapped {len(records)} paths; source blobs found for {len(requested)}")


if __name__ == "__main__":
    main()
