#!/usr/bin/env python3
"""Native host-node raw cut component. NOT an authorized first-adoption CLI.

Only an independently authenticated original hostPath/B maintenance coordinator
may invoke this component. prepare records native observations, not authority.
stream never stops/starts writers, changes RBAC, repairs MinIO or signs evidence.
Its archive contains EVERY reachable file, including .minio.sys; logical history,
unknown operations, retention, all scope discovery and SQL adoption remain absent.
Linux x86_64/aarch64, one xl-single drive only. Raw-copy supports shared-filesystem
hostPath subdirectories; it never claims an immutable cut or B hold by itself.
Only prepare and pipe-only stream exist. No plaintext archive file is created.
"""
import argparse
import base64
import ctypes
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time


class Refused(Exception):
    pass


PROFILE = "original-minio-hostpath-native-raw-cut.v1"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(condition, reason):
    if not condition:
        raise Refused(reason)


def read_private(path, expected=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
              info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
              "private original input type/owner/mode")
        raw = stream.read(1024 * 1024 + 1)
    check(len(raw) <= 1024 * 1024 and (expected is None or sha(raw) == expected),
          "private original input size/byte pin")
    return raw


def mount_text():
    return Path("/proc/self/mountinfo").read_text()


def unescape(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)


def source_mount(root):
    check(str(root) != "/" and root.is_absolute() and str(root) == os.path.realpath(root),
          "original path must be canonical and must not be node root")
    rows = []
    for line in mount_text().splitlines():
        left, right = line.split(" - ", 1)
        a, b = left.split(), right.split()
        rows.append({"id": a[0], "device": a[2], "root": unescape(a[3]),
                     "path": unescape(a[4]), "options": a[5],
                     "filesystem": b[0], "source": unescape(b[1])})
    selected = [r for r in rows if r["path"] == str(root) or
                str(root).startswith(r["path"].rstrip("/") + "/")]
    check(selected, "original hostPath mount missing")
    selected = max(selected, key=lambda row: len(row["path"]))
    check(selected["root"] == "/" and selected["filesystem"] in ("ext4", "xfs") and
          selected["source"].startswith("/dev/") and "rw" in selected["options"].split(","),
          "unsupported original filesystem/bind/subtree/read-only mount")
    check(not any(r["path"].startswith(str(root) + "/") for r in rows),
          "nested mount would exclude original bytes")
    info = root.stat()
    check(selected["device"] == f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}",
          "mount/device identity changed")
    device = os.stat(selected["source"])
    check(stat.S_ISBLK(device.st_mode) and device.st_rdev == info.st_dev,
          "original filesystem block device changed")
    return selected


def node_identity():
    return {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "machine_id": Path("/etc/machine-id").read_text().strip(),
            "hostname": platform.node()}


def inspect(endpoint, container):
    check(re.fullmatch(r"[a-f0-9]{64}", container) is not None and
          endpoint.startswith("unix:///"), "explicit original native CRI identity required")
    result = subprocess.run(["crictl", "--runtime-endpoint", endpoint,
                             "inspect", "--output", "json", container],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=15, check=False)
    check(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024,
          "original CRI inspection failed; missing/GC is not stopped proof")
    value = json.loads(result.stdout)
    check(value["status"]["id"] == container, "original CRI container identity changed")
    return value


def pid_start(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw[raw.rfind(")") + 2:].split()[19]


def format_identity(root):
    path = root / ".minio.sys" / "format.json"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_dev == root.stat().st_dev,
              "original MinIO format is not a single local regular file")
        raw = stream.read(65537)
    check(len(raw) <= 65536, "original MinIO format exceeds profile")
    value = json.loads(raw)
    xl = value.get("xl", {})
    check(value.get("version") == "1" and value.get("format") == "xl-single" and
          xl.get("version") == "3" and xl.get("distributionAlgo") == "SIPMOD+PARITY" and
          xl.get("sets") == [[xl.get("this")]] and
          re.fullmatch(r"[a-f0-9-]{36}", xl.get("this", "")) and
          re.fullmatch(r"[a-f0-9-]{36}", value.get("id", "")),
          "unsupported original MinIO format/drive/root set; no migration or repair")
    return {"format_sha256": sha(raw), "deployment_id": value["id"],
            "drive_id": xl["this"], "sets": xl["sets"]}


def native_plan(args):
    root = Path(args.root)
    mount = source_mount(root)
    native = inspect(args.cri_endpoint, args.container_id)
    status = native["status"]
    pid = native.get("info", {}).get("pid", 0)
    check(status["state"] == "CONTAINER_RUNNING" and isinstance(pid, int) and pid > 1,
          "prepare requires actual original running container/PID")
    labels = status.get("labels", {})
    check(labels.get("io.kubernetes.pod.uid") == args.pod_uid and
          labels.get("io.kubernetes.container.name") == args.container_name,
          "original runtime Pod/container labels differ")
    return {"profile": PROFILE, "authority": "UNBOUND_NATIVE_OBSERVATION_NOT_B_HOLD",
            "root": str(root), "mount": mount, "node": node_identity(), "cut_mode": "raw-copy",
            "container_id": args.container_id, "cri_endpoint": args.cri_endpoint,
            "pod_uid": args.pod_uid, "container_name": args.container_name,
            "pid": pid, "pid_start": pid_start(pid), "format": format_identity(root),
            "observed_unix_ns": time.time_ns()}


def stopped(plan):
    check(node_identity() == plan["node"], "original native node/boot changed")
    native = inspect(plan["cri_endpoint"], plan["container_id"])
    status = native["status"]
    finished = status.get("finishedAt", "")
    # crictl's native JSON presents RFC3339Nano, not an integer nanosecond field.
    check(isinstance(finished, str) and re.fullmatch(
          r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z", finished),
          "native CRI finished timestamp is absent/unsupported")
    finished_time = datetime.datetime.fromisoformat(finished.replace("Z", "+00:00")).timestamp()
    check(finished_time >= plan["observed_unix_ns"] / 1000000000 and
          finished_time <= time.time() and status["state"] == "CONTAINER_EXITED" and
          native.get("info", {}).get("pid") == 0,
          "original native runtime has not proved EXITED/pid0")
    labels = status.get("labels", {})
    check(labels.get("io.kubernetes.pod.uid") == plan["pod_uid"] and
          labels.get("io.kubernetes.container.name") == plan["container_name"],
          "original exited runtime labels changed")
    try:
        check(pid_start(plan["pid"]) != plan["pid_start"], "original native PID remains alive")
    except FileNotFoundError:
        pass
    return {"id": status["id"], "state": status["state"], "finishedAt": status["finishedAt"],
            "exitCode": status.get("exitCode")}


def metadata(fd):
    info = os.fstat(fd)
    attrs = {name: base64.b64encode(os.getxattr(fd, name)).decode()
             for name in sorted(os.listxattr(fd))}
    return {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
            "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
            "nlink": info.st_nlink, "xattrs_base64": attrs}


class HashReader:
    def __init__(self, stream, deadline):
        self.stream, self.deadline, self.hash, self.count = stream, deadline, hashlib.sha256(), 0

    def read(self, size):
        check(time.monotonic() < self.deadline, "raw cut deadline exceeded")
        raw = self.stream.read(size)
        self.hash.update(raw)
        self.count += len(raw)
        return raw


def archive_tree(tar, directory_fd, relative, device, rows, limits, deadline):
    check(time.monotonic() < deadline, "raw cut deadline exceeded")
    check(len(rows) < limits[0] and relative.count("/") <= 128, "full EOF exceeds profile")
    meta = metadata(directory_fd)
    check(meta["device"] == device and stat.S_ISDIR(meta["mode"]), "source directory changed")
    item = tarfile.TarInfo("source/" + relative)
    item.type, item.mode, item.uid, item.gid = tarfile.DIRTYPE, stat.S_IMODE(meta["mode"]), meta["uid"], meta["gid"]
    item.mtime = meta["mtime_ns"] // 1000000000
    tar.addfile(item)
    rows.append({"path": relative, "type": "directory", "metadata": meta})
    names = sorted(os.listdir(directory_fd))
    for name in names:
        check(name not in (".", "..") and "/" not in name and "\x00" not in name and
              not any(0xD800 <= ord(c) <= 0xDFFF for c in name), "unsupported original filename")
        check(len(rows) < limits[0], "full file count exceeds profile")
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        check(info.st_dev == device and (stat.S_ISDIR(info.st_mode) or
              stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
              "link/special/cross-filesystem source cannot be silently excluded")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME |
                     (os.O_DIRECTORY if stat.S_ISDIR(info.st_mode) else 0), dir_fd=directory_fd)
        with os.fdopen(fd, "rb") if stat.S_ISREG(info.st_mode) else FDDirectory(fd) as stream:
            actual = os.fstat(fd)
            check((actual.st_dev, actual.st_ino, actual.st_mode) ==
                  (info.st_dev, info.st_ino, info.st_mode), "original inode changed at open")
            path = (relative + "/" + name).lstrip("/")
            if stat.S_ISDIR(info.st_mode):
                archive_tree(tar, fd, path, device, rows, limits, deadline)
                continue
            before = metadata(fd)
            limits[1] -= before["size"]
            check(limits[1] >= 0, "full byte count exceeds profile")
            reader = HashReader(stream, deadline)
            item = tarfile.TarInfo("source/" + path)
            item.size, item.mode, item.uid, item.gid = before["size"], stat.S_IMODE(before["mode"]), before["uid"], before["gid"]
            item.mtime = before["mtime_ns"] // 1000000000
            tar.addfile(item, reader)
            check(reader.read(1) == b"" and reader.count == before["size"] and metadata(fd) == before,
                  "original file EOF/metadata changed")
            rows.append({"path": path, "type": "file", "metadata": before,
                         "sha256": reader.hash.hexdigest()})
    check(sorted(os.listdir(directory_fd)) == names and
          metadata(directory_fd) == meta, "original directory changed during full traversal")


class FDDirectory:
    def __init__(self, fd):
        self.fd = fd

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        os.close(self.fd)


class Discard:
    def write(self, raw):
        return len(raw)


def stream_raw(args):
    """Pipe-only plaintext; caller encrypts and waits for native success BEFORE
    writing authenticated EOF. A partial/failed stream must never be sealed.
    B retains actual original hold throughout; no JSON can grant that authority.
    """
    check(stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode),
          "raw plaintext export requires an original encrypted-producer pipe")
    raw = read_private(args.plan_file, args.plan_sha256)
    plan = json.loads(raw)
    check(plan["profile"] == PROFILE and plan["cut_mode"] == "raw-copy",
          "stream mode requires original raw-copy plan; no filesystem freeze")
    root = Path(plan["root"])
    check(source_mount(root) == plan["mount"] and format_identity(root) == plan["format"],
          "original stream source identity changed")
    before = stopped(plan)
    check(args.max_files > 0 and args.max_bytes > 0 and 0 < args.max_seconds <= 600,
          "explicit finite original stream EOF bounds required")
    deadline = time.monotonic() + args.max_seconds
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME)
    def expired(unused_signum, unused_frame):
        raise Refused("original native raw stream exceeded deadline")
    old = {sig: signal.signal(sig, expired) for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT)}
    signal.alarm(args.max_seconds)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syncfs.argtypes, libc.syncfs.restype = [ctypes.c_int], ctypes.c_int
        check(libc.syncfs(fd) == 0, "native original stream syncfs failed")
        rows, verified = [], []
        started = time.time_ns()
        with tarfile.open(fileobj=sys.stdout.buffer, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            archive_tree(tar, fd, "", os.fstat(fd).st_dev, rows,
                         [args.max_files, args.max_bytes], deadline)
            with tarfile.open(fileobj=Discard(), mode="w|", format=tarfile.PAX_FORMAT) as second:
                archive_tree(second, fd, "", os.fstat(fd).st_dev, verified,
                             [args.max_files, args.max_bytes], deadline)
            check(rows == verified, "original second full tree/EOF differs")
            after = stopped(plan)
            check(source_mount(root) == plan["mount"] and format_identity(root) == plan["format"],
                  "original final stream source identity changed")
            manifest = canonical({"profile": PROFILE, "status": "RAW_PIPE_ONLY_NOT_ADOPTABLE",
                                  "plan_sha256": sha(raw), "original_plan": plan,
                                  "started_unix_ns": started, "stopped_before": before,
                                  "stopped_after": after, "complete_reachable_tree": rows,
                                  "excluded_paths": [], "B_hold_validated": False,
                                  "logical_history_classified": False, "adoptable": False})
            item = tarfile.TarInfo("raw-cut-manifest.json")
            item.size, item.mode = len(manifest), 0o400
            tar.addfile(item, io.BytesIO(manifest))
        sys.stdout.buffer.flush()
        check(time.monotonic() < deadline, "original full stream EOF deadline exceeded")
    finally:
        signal.alarm(0)
        os.close(fd)
        for sig, handler in old.items():
            signal.signal(sig, handler)


def main():
    check(sys.platform == "linux" and platform.machine() in ("x86_64", "aarch64") and
          os.geteuid() == 0, "original Linux host native operator required")
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    prepare = actions.add_parser("prepare")
    for name in ("root", "cri-endpoint", "container-id", "pod-uid", "container-name"):
        prepare.add_argument("--" + name, required=True)
    stream = actions.add_parser("stream")
    for name in ("plan-file", "plan-sha256"):
        stream.add_argument("--" + name, required=True)
    for name in ("max-files", "max-bytes", "max-seconds"):
        stream.add_argument("--" + name, type=int, required=True)
    args = parser.parse_args()
    if args.action == "stream":
        stream_raw(args)
        return
    print(canonical(native_plan(args)).decode())


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # No original payloads, runtime diagnostics or credentials escape.
        print("original hostPath native raw cut refused: " + type(error).__name__, file=sys.stderr)
        sys.exit(2)
