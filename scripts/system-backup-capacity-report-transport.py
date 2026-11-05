"""Forward only real native capacity samples to the original readonly inputs PVC.

Started once by the sealed operator. No arbitrary command, cached sample replay,
SQL credential body, admin password or signing key is accepted by this process.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys


def need(ok):
    if not ok:
        raise ValueError("original_live_capacity_transport_rejected")


def read(path, digest=None, limit=262144):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 0 and not before.st_mode & 0o022 and 0 < before.st_size <= limit)
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        need((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino))
        raw = source.read(limit+1)
        after = os.fstat(source.fileno())
    need(len(raw) <= limit and (opened.st_size, opened.st_mtime_ns) == (after.st_size, after.st_mtime_ns))
    need(digest is None or hashlib.sha256(raw).hexdigest() == digest)
    return raw


def pin(value, limit=262144):
    return read(value["File"], value["SHA256"], limit)


def atomic(path, raw):
    path = Path(path)
    need(path.parent.resolve(strict=True) == path.parent and not path.is_symlink())
    temporary = path.with_name(path.name+".inflight-"+str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def sample(raw, plan):
    need(0 < len(raw) <= 4096 and raw.endswith(b"\n"))
    body = raw[:-1]
    value = json.loads(body)
    need(set(value) == {"server_uuid", "database", "observed_at", "allocated_bytes", "available_bytes"})
    need(value["server_uuid"] == plan["ServerUUID"] and value["database"] == plan["Database"])
    need(all(type(value[k]) is int and 0 <= value[k] < 1<<63 for k in ("allocated_bytes", "available_bytes")))
    observed = datetime.datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
    age = (datetime.datetime.now(datetime.timezone.utc)-observed).total_seconds()
    need(0 <= age < 5)
    return body


def run(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-file", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    args = parser.parse_args(argv)
    need(sys.platform == "linux" and os.geteuid() == 0)
    plan = json.loads(read(args.plan_file, args.plan_sha256))
    need(plan["Version"] == "original-live-capacity-report-transport.v1")
    need(plan["Namespace"] == "clawmanager-zhanghui08-system")
    need(plan["ReportFile"] == "/run/system-backup/runtime/registration-capacity.current.json")
    need(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == plan["BootID"])
    need(Path(plan["ReportFile"]).parent.resolve(strict=True) == Path(plan["ReportFile"]).parent)
    for key in ("Helper", "Kubeconfig", "NativeInput", "BridgePlan"):
        pin(plan[key])
    bridge = json.loads(pin(plan["BridgePlan"]))
    need(bridge["action"] == "invoke-capacity-collector" and bridge["argv"][1] == "capacity-collect" and bridge["argv"][2:] == ["--inputs-file", plan["NativeInput"]["File"], "--inputs-sha256", plan["NativeInput"]["SHA256"]])
    need(Path(bridge["caller"]["File"]).name == "system-backup-c1-native-inputs")
    pin(bridge["caller"], 128<<20)
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
    def k(*items, raw=None):
        result = subprocess.run(["kubectl", "--context", "kubernetes-admin@kubernetes", "--kubeconfig", plan["Kubeconfig"]["File"], "--request-timeout=3s", "-n", plan["Namespace"], *items], input=raw, stdin=subprocess.DEVNULL if raw is None else None, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=4, env=environment)
        need(result.returncode == 0 and len(result.stdout) <= 262144)
        return result.stdout
    def current_host():
        # CRI/process/mount identity is checked in the fixed host helper.
        # Each sample ALSO rechecks the actual Kubernetes MySQL Pod UID/CID;
        # the native Go report itself rechecks live SQL UUID/datadir/auto.cnf.
        expected = bridge["mysql"]["native_container"]
        mysql = json.loads(k("get", "pod", expected["pod"], "-o", "json"))
        need(mysql["metadata"]["uid"] == expected["pod_uid"] and not mysql["metadata"].get("deletionTimestamp") and mysql["status"].get("phase") == "Running")
        states = [v for v in mysql["status"].get("containerStatuses", []) if v.get("containerID") == expected["container_id"]]
        need(len(states) == 1 and states[0].get("ready") and "running" in states[0].get("state", {}) and states[0]["imageID"].removeprefix("docker-pullable://").rsplit("@", 1)[-1] == expected["image_digest"])
        pod = json.loads(k("get", "pod", plan["Host"]["Pod"], "-o", "json"))
        dep = json.loads(k("get", "deployment", plan["Host"]["Deployment"], "-o", "json"))
        host = plan["Host"]
        encoded = lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        need(pod["metadata"]["uid"] == host["PodUID"] and not pod["metadata"].get("deletionTimestamp") and dep["metadata"]["uid"] == host["DeploymentUID"] and not dep["metadata"].get("deletionTimestamp"))
        need(hashlib.sha256(encoded(pod["spec"])).hexdigest() == host["PodSpecSHA256"] and hashlib.sha256(encoded(dep["spec"])).hexdigest() == host["DeploymentSpecSHA256"])
        states = {s["name"]: s for s in pod["status"]["containerStatuses"]}
        need(all(states[name]["containerID"] == s["ContainerID"] and states[name]["imageID"] == s["ImageID"] and "running" in states[name]["state"] for name, s in host["Containers"].items()))
    current_host()
    previous = "absent"
    # A lost start reply never permits replay or replacement of an old report.
    need(not Path(plan["ReportFile"]).exists())
    publish = '''umask 077; test ! -L "$1"; test "$(stat -c %u:%a "$(dirname "$1")")" = 65532:700
if test "$2" = absent; then test ! -e "$1"; else test -f "$1"; test "$(sha256sum "$1" | cut -d ' ' -f 1)" = "$2"; fi
temp=$(mktemp "$(dirname "$1")/.capacity-XXXXXXXX"); trap 'rm -f -- "$temp"' EXIT HUP INT TERM
cat > "$temp"; chmod 640 "$temp"; test "$(sha256sum "$temp" | cut -d ' ' -f 1)" = "$3"
mv -f -- "$temp" "$1"; sync "$(dirname "$1")"; sha256sum "$1"'''
    child = subprocess.Popen([sys.executable, "-I", "-B", plan["Helper"]["File"], "--plan-file", plan["BridgePlan"]["File"], "--plan-sha256", plan["BridgePlan"]["SHA256"]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment, bufsize=0)
    watch = selectors.DefaultSelector()
    watch.register(child.stdout, selectors.EVENT_READ)
    pending = b""
    try:
        while True:
            need(watch.select(5))
            block = os.read(child.stdout.fileno(), 4097)
            need(block and len(pending)+len(block) <= 8192)
            pending += block
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                body = sample(line+b"\n", plan)
                current_host()
                digest = hashlib.sha256(body).hexdigest()
                result = k("exec", "-i", plan["Host"]["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", publish, "sh", plan["ReportFile"], previous, digest, raw=body)
                need(result.decode().split()[0] == digest)
                # Recheck current host and freshness AFTER the actual atomic
                # remote write. Local readers receive these exact native bytes.
                current_host()
                sample(line+b"\n", plan)
                atomic(plan["ReportFile"], body)
                previous = digest
    finally:
        watch.close()
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


if __name__ == "__main__":
    try:
        run(sys.argv[1:])
    except Exception:
        raise SystemExit("ORIGINAL_CAPACITY_TRANSPORT_STOPPED_REPORT_WILL_EXPIRE")
