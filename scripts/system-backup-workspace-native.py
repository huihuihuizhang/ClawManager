#!/usr/bin/env python3
"""Finite root Linux deployment migration actor; stdin RPC over pinned SSH.

This is never a backup observer/hold/source authority. The controller must
authenticate the original operation and complete Kubernetes/SQL universe.
Real mount FDs survive original client exit, then syncfs/fsync must succeed.
Unknown state refuses; there is no timeout-driven success or automatic replay.
"""
import array
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

VERSION = "original-workspace-localization-native.v1"
NS = "clawmanager-zhanghui08-system"
ROOT = "/data/clawmanager-zhanghui08/system/workspaces"
EXPORT = "/exports/workspaces"
CRI_SHA = "d9f541aa6a3a1fce15392d4366da5f97b47683aa55a825909ad8c0a624c7f4f3"
NFS_MAGIC, EXT4_MAGIC, XFS_MAGIC = 0x6969, 0xEF53, 0x58465342
MAX = 4 << 20


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(values):
        out = {}
        for key, value in values:
            need(key not in out, "duplicate_json_key")
            out[key] = value
        return out
    need(0 < len(raw) <= MAX, "native_json_limit")
    return json.loads(raw, object_pairs_hook=pairs)


def file_bytes(path, limit=MAX):
    with open(path, "rb") as source:
        raw = source.read(limit + 1)
    need(len(raw) <= limit, "native_file_limit")
    return raw


def fs_magic(fd):
    # Linux amd64 statfs: f_type is the first signed native long. The buffer is
    # deliberately larger than struct statfs; no guessed later layout is read.
    buf = ctypes.create_string_buffer(512)
    libc = ctypes.CDLL(None, use_errno=True)
    need(libc.fstatfs(fd, buf) == 0, "native_fstatfs_failed")
    return ctypes.c_long.from_buffer(buf).value & 0xFFFFFFFF


def syncfs(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    need(libc.syncfs(fd) == 0, "native_syncfs_or_writeback_failed")


def process(pid, base=None):
    base = Path("/proc") / str(pid) if base is None else Path(base)
    raw = file_bytes(base / "stat", 65536).decode()
    close = raw.rfind(")")
    need(close > 0, "native_process_stat")
    fields = raw[close + 2:].split()
    # Fields start at task state (3): flags=9, starttime=22.
    need(len(fields) > 19, "native_process_stat")
    flags = int(fields[6])
    return {"pid": pid, "start": fields[19], "flags": flags,
            "pidns": os.readlink(base / "ns/pid"), "mntns": os.readlink(base / "ns/mnt"), "netns": os.readlink(base / "ns/net"),
            "cgroup": file_bytes(base / "cgroup", 65536).decode()}


def unescape_mount(value):
    need(not re.search(r"\\(?![0-7]{3})", value), "unknown_mount_escape")
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


def mounts(pid):
    out = []
    for line in file_bytes(Path("/proc") / str(pid) / "mountinfo").decode().splitlines():
        before, separator, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        need(separator and len(fields) >= 6 and len(tail) == 3, "unknown_mountinfo")
        out.append({"id": int(fields[0]), "parent": int(fields[1]), "device": fields[2],
                    "root": unescape_mount(fields[3]), "path": unescape_mount(fields[4]),
                    "options": fields[5].split(","), "type": tail[0], "source": unescape_mount(tail[1]),
                    "super_options": tail[2].split(",")})
    return out


def same_process(a, b):
    return all(a[key] == b[key] for key in ("pid", "start", "pidns", "mntns", "netns", "cgroup"))


def nfsd_controls(record, directory):
    """Create NFSD superblock in the ACTUAL server network namespace.

    An inherited /proc/fs/nfsd mount can refer to another network namespace.
    Never use it. A short-lived child clones the host mount namespace, makes
    propagation private, joins only the pinned original server netns, mounts
    nfsd there and passes the real control FDs back. No host mount is changed.
    The open FDs retain that namespace's superblock after the child exits.
    """
    pid = record["pid"]["pid"]
    need(record["pid"]["netns"] != os.readlink("/proc/self/ns/net"), "dedicated_server_network_namespace_required")
    net = os.open("/proc/" + str(pid) + "/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    need(os.readlink("/proc/self/fd/" + str(net)) == record["pid"]["netns"] and same_process(record["pid"], process(pid)), "original_server_network_namespace_changed")
    target = directory / ("server-nfsd-control-" + record["item"]["pod_uid"])
    target.mkdir(mode=0o700)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    child = os.fork()
    if child == 0:
        left.close()
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            need(libc.unshare(0x00020000) == 0, "private_control_mount_namespace_failed")
            need(libc.mount(None, b"/", None, 0x40000 | 0x4000, None) == 0, "private_control_mount_propagation_failed")
            need(libc.setns(net, 0x40000000) == 0, "actual_server_netns_entry_failed")
            need(os.readlink("/proc/self/ns/net") == record["pid"]["netns"], "actual_server_netns_entry_mismatch")
            need(libc.mount(b"nfsd", os.fsencode(target), b"nfsd", 0, None) == 0, "server_netns_nfsd_mount_failed")
            fds = [os.open(target / name, (os.O_RDWR if name == "threads" else os.O_RDONLY) | (os.O_DIRECTORY if name == "clients" else 0) | os.O_CLOEXEC) for name in ("threads", "versions", "exports", "clients")]
            need(all(fs_magic(fd) == 0x6E667364 for fd in fds), "actual_nfsd_control_filesystem_required")
            right.sendmsg([b"actual-server-netns-nfsd"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
            os._exit(0)
        except BaseException:
            os._exit(1)
    right.close()
    left.settimeout(30)
    received = []
    reaped=False
    try:
        raw, ancillary, flags, _ = left.recvmsg(64, socket.CMSG_SPACE(4 * array.array("i").itemsize))
        for level, kind, data in ancillary:
            need(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS, "unknown_native_control_fd_response")
            values = array.array("i")
            values.frombytes(data)
            received.extend(values)
        _, status = os.waitpid(child, 0)
        reaped=True
        need(status == 0 and raw == b"actual-server-netns-nfsd" and flags == 0 and len(received) == 4, "actual_server_nfsd_controls_unconfirmed")
        need(same_process(record["pid"], process(pid)), "original_server_changed_during_control_open")
        record["netns_fd"] = net
        for fd in received:
            os.set_inheritable(fd,False)
        return dict(zip(("threads_fd", "versions_fd", "exports_fd", "clients_fd"), received))
    except BaseException:
        for fd in received:
            os.close(fd)
        os.close(net)
        raise
    finally:
        left.close()
        if not reaped:
            try:
                os.kill(child,signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child,0)


def parse_exports(raw):
    """Closed exportfs -s profile: one original fsid=0 root, no aliases."""
    rows = []
    for line in raw.decode().splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"(/[^\s\\]+)\s+([^\s()]+)\(([^()\s]+)\)", line.strip())
        need(match is not None, "unknown_native_export_format")
        path, client, options = match.groups()
        options = options.split(",")
        need(path == EXPORT and "fsid=0" in options and "rw" in options and "ro" not in options,
             "original_single_root_export_required")
        need("crossmnt" not in options and "nohide" not in options and not any(x.startswith(("replicas=", "refer=")) for x in options),
             "export_alias_or_referral_unknown")
        rows.append({"path": path, "client": client, "options": options})
    need(len(rows) == 1, "complete_single_export_profile_required")
    return rows


def mount_pin(fd):
    value = os.fstat(fd)
    info = file_bytes("/proc/self/fdinfo/" + str(fd), 65536).decode()
    match = re.search(r"(?m)^mnt_id:\s+([0-9]+)$", info)
    need(match and stat.S_ISDIR(value.st_mode), "native_root_mount_pin")
    return {"device": value.st_dev, "inode": value.st_ino, "mount_id": int(match[1]), "filesystem": fs_magic(fd)}


def tree(fd, fsync_files=False):
    """No symlink following. Complete file EOF and stable metadata, bounded."""
    result = []
    total = 0

    def walk(directory, prefix):
        nonlocal total
        os.lseek(directory, 0, os.SEEK_SET)
        entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
        need(len(result) + len(entries) <= 100000, "native_source_tree_limit")
        for entry in entries:
            name = entry.name
            need(name not in ("", ".", "..") and "/" not in name and "\x00" not in name, "native_tree_name")
            relative = prefix + name
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            record = {"path_hex": os.fsencode(relative).hex(), "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid,
                      "gid": before.st_gid, "mtime_ns": before.st_mtime_ns}
            if stat.S_ISDIR(before.st_mode):
                record["kind"] = "directory"
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                try:
                    need((os.fstat(child).st_dev, os.fstat(child).st_ino) == (before.st_dev, before.st_ino), "native_tree_replaced")
                    result.append(record)
                    walk(child, relative + "/")
                finally:
                    os.close(child)
            elif stat.S_ISLNK(before.st_mode):
                record.update(kind="symlink", target_hex=os.fsencode(os.readlink(name, dir_fd=directory)).hex())
                result.append(record)
            elif stat.S_ISREG(before.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                try:
                    opened = os.fstat(child)
                    need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "native_file_replaced")
                    if fsync_files:
                        os.fsync(child)
                    digest, count = hashlib.sha256(), 0
                    while True:
                        raw = os.read(child, 1 << 20)
                        if not raw:
                            break
                        count += len(raw)
                        total += len(raw)
                        need(total <= 1 << 40 and count <= opened.st_size, "native_tree_byte_limit")
                        digest.update(raw)
                    after = os.fstat(child)
                    need((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                         (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) and count == after.st_size,
                         "native_file_changed")
                    record.update(kind="regular", size=count, sha256=digest.hexdigest())
                    result.append(record)
                finally:
                    os.close(child)
            else:
                raise Refused("unknown_native_source_file_type")
            after = os.stat(name, dir_fd=directory, follow_symlinks=False)
            need((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "native_tree_changed")

    walk(fd, "")
    return {"entries": len(result), "bytes": total, "tree_sha256": sha(encoded(result))}


class Actor:
    def __init__(self, definition):
        need(os.name == "posix" and os.geteuid() == 0 and os.uname().machine == "x86_64", "native_root_linux_amd64_required")
        need(set(definition) == {"version", "operation", "node", "cri_binary", "cri_endpoint", "containers", "server", "direction", "session"}, "closed_native_definition")
        need(definition["version"] == VERSION and re.fullmatch(r"[a-f0-9]{32}", definition["operation"]), "original_native_operation")
        need(re.fullmatch(r"[a-f0-9]{32}", definition["session"]), "native_original_session_identity")
        need(definition["direction"] in ("to-local", "to-nfs", "probe", "observe-restored-server"), "finite_native_direction")
        if definition["direction"] == "observe-restored-server":
            need(not definition["containers"] and definition["server"] is not None,"read_only_server_observation_requires_empty_client_scope")
        self.definition, self.clients, self.server, self.sent = definition, [], None, set()
        self.clients_closed, self.server_closed = False, definition["server"] is None
        node = definition["node"]
        need(file_bytes("/etc/machine-id", 1024).decode().strip() == node["machine_id"] and
             file_bytes("/proc/sys/kernel/random/boot_id", 1024).decode().strip() == node["boot_id"], "original_native_node_identity")
        binary = Path(definition["cri_binary"])
        need(binary.is_absolute() and binary.resolve(strict=True) == binary and stat.S_ISREG(binary.stat().st_mode) and binary.stat().st_uid == 0 and binary.stat().st_mode & 0o022 == 0,
             "native_cri_binary_custody")
        need(sha(file_bytes(binary, 64 << 20)) == CRI_SHA and definition["cri_endpoint"] in ("unix:///run/containerd/containerd.sock", "unix:///run/k3s/containerd/containerd.sock"), "native_cri_release_or_endpoint")
        self.binary = str(binary)
        self.cri(["--version"], expected=b"crictl version v1.31.1\n")
        self.directory = Path("/var/lib/clawmanager-system-backup") / definition["operation"] / ("workspace-localization-" + definition["direction"])
        # Only root-owned ancestors; never repair/chmod somebody else's path.
        for parent in reversed([self.directory, *self.directory.parents][:-1]):
            if parent.exists() or parent.is_symlink():
                st = parent.lstat()
                need(stat.S_ISDIR(st.st_mode) and not parent.is_symlink() and st.st_uid == 0 and st.st_mode & 0o022 == 0, "native_journal_parent")
            else:
                parent.mkdir(mode=0o700)
                parent_fd = os.open(parent.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
        need(stat.S_IMODE(self.directory.stat().st_mode) == 0o700, "private_native_journal")
        self.journal = os.open(self.directory / (definition["session"] + ".events.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        parent_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.sequence, self.previous = 0, ""
        self.event("prepared_original_definition", definition)
        for item in definition["containers"]:
            self.clients.append(self.prepare_client(item))
        if definition["server"] is not None:
            self.server = self.prepare_server(definition["server"])

    def event(self, action, data):
        self.sequence += 1
        record = {"version": VERSION, "operation": self.definition["operation"], "node": self.definition["node"],
                  "sequence": self.sequence, "previous_sha256": self.previous, "action": action,
                  "observed_at_ns": time.time_ns(), "data": data}
        raw = encoded(record)
        pending = memoryview(raw + b"\n")
        while pending:
            written = os.write(self.journal, pending)
            need(written > 0, "native_journal_short_write")
            pending = pending[written:]
        os.fsync(self.journal)
        self.previous = sha(raw)

    def cri(self, args, expected=None):
        value = subprocess.run([self.binary, "--runtime-endpoint", self.definition["cri_endpoint"], "--timeout", "15s", *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
        need(value.returncode == 0 and len(value.stdout) <= MAX, "native_cri_command_unconfirmed")
        if expected is not None:
            need(value.stdout == expected, "native_cri_version")
        return value.stdout

    def inspect(self, item):
        need(item["namespace"] == NS and item["node"] == self.definition["node"]["name"] and re.fullmatch(r"containerd://[a-f0-9]{64}", item["container_id"]), "original_native_container_coordinates")
        cid = item["container_id"].split("://", 1)[1]
        actual = decode(self.cri(["inspect", "--output", "json", cid]))
        status = actual["status"]
        need(status["id"] == cid and all(status["labels"].get(key) == value for key, value in {
            "io.kubernetes.pod.uid": item["pod_uid"], "io.kubernetes.pod.namespace": NS,
            "io.kubernetes.pod.name": item["pod"]}.items()), "original_native_cri_identity")
        image = status.get("imageRef", "")
        need(re.fullmatch(r"sha256:[a-f0-9]{64}", item.get("image_digest", "")) is not None and
             image.rsplit("@", 1)[-1] == item["image_digest"], "actual_cri_and_kubernetes_image_digest_mismatch")
        return actual

    def root(self, item, destination, allowed):
        actual = self.inspect(item)
        need(actual["status"]["state"] in ("CONTAINER_RUNNING", 1), "original_native_container_not_running")
        pid = int(actual["info"]["pid"])
        before = process(pid)
        selected = [entry for entry in mounts(pid) if entry["path"] == destination]
        need(len(selected) == 1 and selected[0]["type"] in allowed and "rw" in selected[0]["options"], "actual_native_source_mount")
        fd = os.open("/proc/" + str(pid) + "/root" + destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(same_process(before, process(pid)), "native_incarnation_drift")
        namespaces = [os.open("/proc/" + str(pid) + "/ns/" + name, os.O_RDONLY | os.O_CLOEXEC) for name in ("pid", "mnt")]
        return {"item": item, "pid": before, "fd": fd, "namespaces": namespaces, "mount": selected[0], "pin": mount_pin(fd)}

    def prepare_client(self, item):
        record = self.root(item, "/workspaces", ("nfs", "nfs4", "ext4", "xfs"))
        if record["pin"]["filesystem"] == NFS_MAGIC:
            need(record["mount"]["source"] == item["nfs_server"] + ":/" and record["mount"]["root"] == "/" and
                 any(option.startswith("vers=4") for option in record["mount"]["super_options"]), "exact_nfs_v4_root_mapping")
        else:
            need(record["pin"]["filesystem"] in (EXT4_MAGIC, XFS_MAGIC), "client_native_filesystem")
            need(self.definition["direction"] == "to-nfs", "original_forward_source_must_be_nfs")
            local = os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                need((os.fstat(local).st_dev,os.fstat(local).st_ino) == (os.fstat(record["fd"]).st_dev,os.fstat(record["fd"]).st_ino),"local_client_actual_original_pvc_inode_required")
            finally:
                os.close(local)
        self.event("actual_client_mount_fd_opened", {key: record[key] for key in ("item", "pid", "mount", "pin")})
        return record

    def server_exec(self, args):
        need(self.server is not None and same_process(self.server["pid"], process(self.server["pid"]["pid"])), "original_native_server_changed")
        return self.cri(["exec", "--sync", self.server["item"]["container_id"].split("://", 1)[1], *args])

    def prepare_server(self, item):
        record = self.root(item, EXPORT, ("ext4", "xfs"))
        need(record["pin"]["filesystem"] in (EXT4_MAGIC, XFS_MAGIC), "server_native_filesystem")
        hostfd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need((os.fstat(hostfd).st_dev, os.fstat(hostfd).st_ino) == (os.fstat(record["fd"]).st_dev, os.fstat(record["fd"]).st_ino), "same_original_pvc_native_inode")
        record["hostfd"] = hostfd
        if self.definition["direction"] != "observe-restored-server":
            lines=record["pid"]["cgroup"].splitlines()
            need(len(lines) == 1 and lines[0].startswith("0::/"),"original_server_cgroup_v2_freezer_required")
            relative=lines[0][3:]
            parts=Path(relative).parts
            cid=item["container_id"].split("://",1)[1]
            need(relative.startswith("/") and relative != "/" and all(part not in (".","..") for part in parts) and cid in parts[-1],"exact_original_server_container_cgroup_required")
            directory=os.open("/sys/fs/cgroup",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                need(fs_magic(directory) == 0x63677270,"actual_cgroup_v2_control_filesystem_required")
                for part in parts[1:]:
                    next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                    os.close(directory)
                    directory=next_fd
                record["user_freeze_fd"]=os.open("cgroup.freeze",os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                record["user_events_fd"]=os.open("cgroup.events",os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                need(all(fs_magic(record[key]) == 0x63677270 for key in ("user_freeze_fd","user_events_fd")),"actual_original_server_freezer_inode_required")
                need(self.read_fd(record["user_freeze_fd"]).strip() == b"0" and self.server_user_frozen(record) is False,"original_server_freezer_already_owned_or_unknown")
                record["user_freeze_owned"]=False
            finally:
                os.close(directory)
        self.server = record
        raw = self.server_exec(["/usr/sbin/exportfs", "-s"])
        record["exports"] = parse_exports(raw)
        record["exports_raw_sha256"] = sha(raw)
        config = self.server_exec(["/bin/cat","/etc/exports"])
        config_rows = b"\n".join(line for line in config.splitlines() if line.strip() and not line.lstrip().startswith(b"#"))
        config_export = parse_exports(config_rows)[0]
        actual_export = record["exports"][0]
        need(config_export["path"] == actual_export["path"] and config_export["client"] == actual_export["client"] and set(config_export["options"]).issubset(actual_export["options"]), "actual_original_export_config_mapping_required")
        record["exports_config_sha256"] = sha(config)
        controls_directory = self.directory / self.definition["session"]
        controls_directory.mkdir(mode=0o700)
        record.update(nfsd_controls(record, controls_directory))
        need(all(fs_magic(record[name]) == 0x6E667364 for name in ("threads_fd", "versions_fd", "exports_fd")), "actual_nfsd_kernel_control_filesystem_required")
        kernel_exports = self.read_fd(record["exports_fd"])
        kernel_rows = b"\n".join(line for line in kernel_exports.splitlines() if line.strip() and not line.lstrip().startswith(b"#"))
        record["kernel_exports"] = parse_exports(kernel_rows)
        record["original_threads"] = int(self.read_fd(record["threads_fd"]).strip())
        need(0 < record["original_threads"] <= 1024, "actual_nfsd_threads_required")
        versions = self.read_fd(record["versions_fd"]).decode().split()
        record["versions"]=versions
        need(any(value in versions for value in ("+4", "+4.1", "+4.2")), "native_nfs4_server_required")
        self.event("actual_server_export_and_pvc_inode", {"item": item, "pid": record["pid"], "mount": record["mount"], "pin": record["pin"], "exports": record["exports"], "versions": versions})
        return record

    @staticmethod
    def read_fd(fd):
        # NFSD transaction files cache the first response per open file.
        # lseek does not refresh it. Reopen the pinned inode for EACH actual
        # observation, and read through EOF so a short seq_read is not EOF.
        fresh=os.open("/proc/self/fd/"+str(fd),os.O_RDONLY|os.O_CLOEXEC)
        try:
            parts=[]
            count=0
            while True:
                block=os.read(fresh,min(65536,MAX+1-count))
                if not block:
                    return b"".join(parts)
                parts.append(block)
                count+=len(block)
                need(count <= MAX,"native_control_file_limit")
        finally:
            os.close(fresh)

    @staticmethod
    def write_control(fd,value):
        fresh=os.open("/proc/self/fd/"+str(fd),os.O_RDWR|os.O_CLOEXEC)
        try:
            need(fs_magic(fresh) == 0x6E667364 and os.write(fresh,value) == len(value),"actual_namespace_pinned_nfsd_control_write_unconfirmed")
        finally:
            os.close(fresh)

    @staticmethod
    def server_user_frozen(record):
        rows=Actor.read_fd(record["user_events_fd"]).decode("ascii").splitlines()
        values={}
        for row in rows:
            fields=row.split()
            need(len(fields) == 2 and fields[0] not in values,"unknown_actual_server_cgroup_events")
            values[fields[0]]=fields[1]
        need(values.get("frozen") in ("0","1"),"actual_server_frozen_event_required")
        return values["frozen"] == "1"

    def server_user_freeze(self,frozen):
        record=self.server
        need(record is not None and "user_freeze_fd" in record and same_process(record["pid"],process(record["pid"]["pid"])),"same_original_server_user_scope_required")
        current=self.read_fd(record["user_freeze_fd"]).strip()
        need(current in (b"0",b"1"),"actual_original_server_freezer_value_unknown")
        if frozen:
            need(current == b"0", "original_server_scope_already_frozen")
            self.event("original_server_user_freeze_send_unknown",{"pid":record["pid"]})
            record["user_freeze_owned"]=True
        else:
            need(record["user_freeze_owned"],"cannot_thaw_another_server_scope_owner")
            self.event("original_server_user_thaw_send_unknown",{"pid":record["pid"]})
        fresh=os.open("/proc/self/fd/"+str(record["user_freeze_fd"]),os.O_RDWR|os.O_CLOEXEC)
        try:
            need(fs_magic(fresh) == 0x63677270 and os.write(fresh,b"1\n" if frozen else b"0\n") == 2,"actual_server_user_freezer_write_unconfirmed")
        finally:
            os.close(fresh)
        deadline=time.monotonic()+30
        while self.server_user_frozen(record) != frozen:
            need(time.monotonic()<deadline,"actual_server_user_freezer_transition_unconfirmed")
            time.sleep(0.05)
        need(same_process(record["pid"],process(record["pid"]["pid"])),"original_server_changed_during_freezer_transition")
        self.event("original_server_user_freezer_observed",{"pid":record["pid"],"frozen":frozen})

    def original_processes_absent(self, records=None):
        records = self.clients if records is None else records
        def cgroup_within(current, old):
            roots = {}
            for line in old.splitlines():
                hierarchy, controllers, path = line.split(":", 2)
                roots[(hierarchy, controllers)] = path.rstrip("/")
            for line in current.splitlines():
                hierarchy, controllers, path = line.split(":", 2)
                root = roots.get((hierarchy, controllers))
                if root and (path == root or path.startswith(root + "/")):
                    return True
            return False
        for round_number in range(2):
            for entry in Path("/proc").iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    tasks = list((entry / "task").iterdir())
                except FileNotFoundError:
                    continue
                for task in tasks:
                    try:
                        current = process(int(task.name), task)
                    except FileNotFoundError:
                        # An unreadable still-existing user task is unknown,
                        # never silently treated as an exited process leader.
                        try:
                            raw = file_bytes(task / "stat", 65536).decode()
                        except FileNotFoundError:
                            continue
                        fields = raw[raw.rfind(")") + 2:].split()
                        need(fields and (fields[0] in ("Z", "X") or int(fields[6]) & 0x200000), "native_task_scope_unreadable")
                        continue
                    if current["flags"] & 0x200000:
                        continue
                    for record in records:
                        old = record["pid"]
                        need(current["pidns"] != old["pidns"] and current["mntns"] != old["mntns"] and not cgroup_within(current["cgroup"], old["cgroup"]) and (record is not self.server or current["netns"] != old["netns"]), "original_client_process_scope_present")
            for record in records:
                cid = record["item"]["container_id"].split("://", 1)[1]
                actual = decode(self.cri(["ps", "-a", "--id", cid, "--output", "json"]))
                containers = actual["containers"]
                need(isinstance(containers, list) and len(containers) <= 1, "original_cri_exit_unknown")
                if containers:
                    need(containers[0]["id"] == cid and containers[0]["state"] in ("CONTAINER_EXITED", 2), "original_client_cri_not_exited")

    def source_mount_census(self):
        """All actual /proc mount namespaces on THIS original source node.

        This identifies unmapped same-server NFS mounts, including a stopped
        Pod's kubelet mount or a host alias. It is not a process/FD writer fence
        and cannot prove that a remote external NFS client does not exist.
        """
        targets={record["item"]["nfs_server"] for record in self.clients}
        targets.update(record["item"]["nfs_backend"] for record in self.clients if record["item"].get("nfs_backend"))
        if self.server is not None:
            targets.add(self.server["item"]["nfs_server"])
            if self.server["item"].get("nfs_backend"):
                targets.add(self.server["item"]["nfs_backend"])
        owned_namespaces={record["pid"]["mntns"]:record["item"]["pod_uid"] for record in self.clients}
        pods={record["item"]["pod_uid"] for record in self.clients}
        cids={record["item"]["container_id"].split("://",1)[1] for record in self.clients}
        rounds=[]
        for _ in range(2):
            seen=set()
            found=[]
            for entry in Path("/proc").iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    tasks=list((entry/"task").iterdir())
                except FileNotFoundError:
                    continue
                for task in tasks:
                    try:
                        namespace=os.readlink(task/"ns/mnt")
                        if namespace in seen:
                            continue
                        # Read task mountinfo, not just its process leader's
                        # mountinfo: a single task can unshare its mountns.
                        entries=mounts(str(entry.name)+"/task/"+task.name)
                        need(namespace == os.readlink(task/"ns/mnt"),"source_mount_namespace_changed_during_read")
                    except FileNotFoundError:
                        try:
                            raw=file_bytes(task/"stat",65536).decode()
                        except FileNotFoundError:
                            continue
                        fields=raw[raw.rfind(")")+2:].split()
                        need(fields and (fields[0] in ("Z","X") or int(fields[6])&0x200000),"source_mount_namespace_unreadable")
                        continue
                    seen.add(namespace)
                    for mount in entries:
                        if mount["type"] not in ("nfs","nfs4"):
                            continue
                        addresses={value.split("=",1)[1] for value in mount["super_options"] if value.startswith(("addr=","mountaddr="))}
                        textual=mount["source"].rsplit(":",1)[0].strip("[]")
                        if textual not in targets and not addresses.intersection(targets):
                            continue
                        need(mount["root"] == "/","unmapped_nfs_subtree_alias_requires_actual_owner")
                        path=mount["path"]
                        owned=namespace in owned_namespaces and path == "/workspaces"
                        owned=owned or any(path == "/var/lib/kubelet/pods/"+uid+"/volumes/kubernetes.io~nfs/workspaces" for uid in pods)
                        owned=owned or any(path == "/run/containerd/io.containerd.runtime.v2.task/k8s.io/"+cid+"/rootfs/workspaces" for cid in cids)
                        need(owned,"unmapped_actual_source_node_nfs_mount_alias")
                        found.append({"namespace":namespace,"mount":mount})
            rounds.append(sorted(found,key=lambda item:(item["namespace"],item["mount"]["id"])))
        need(rounds[0] == rounds[1],"actual_complete_nfs_mount_namespace_census_changed")
        return {"node":self.definition["node"],"source_nfs_mounts":rounds[1],"only_mount_mapping_observed":True,"backup_ready":False}

    def source_node_network(self):
        """Actual host IPv4 interfaces, including the real CNI source address.

        NFS connections may be SNATed to a host CNI interface rather than the
        Kube Node InternalIP. No guessed pod CIDR or DNS-derived IP is accepted.
        """
        import fcntl
        before=socket.if_nameindex()
        addresses=[]
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as query:
            for index,name in before:
                encoded_name=os.fsencode(name)
                need(0 < len(encoded_name) < 16,"unknown_source_interface_name")
                try:
                    raw=fcntl.ioctl(query.fileno(),0x8915,struct.pack("256s",encoded_name))
                except OSError as error:
                    need(error.errno == errno.EADDRNOTAVAIL,"actual_source_interface_address_unreadable")
                    continue
                need(len(raw) >= 24 and struct.unpack("H",raw[16:18])[0] == socket.AF_INET,"actual_source_ipv4_interface_required")
                address=ipaddress.IPv4Address(raw[20:24])
                if not address.is_loopback and not address.is_unspecified:
                    addresses.append({"index":index,"interface":name,"address":str(address)})
        need(before == socket.if_nameindex() and addresses,"actual_source_network_interface_census_changed")
        return {"node":self.definition["node"],"ipv4_interfaces":sorted(addresses,key=lambda item:(item["index"],item["address"])),"backup_ready":False}

    def source_nfs_client_census(self):
        """Complete actual NFSD v4 client info AND state EOF, no control writes.

        Client IP and delegation state are DATA. The driver matches every IP
        against actual original source-node replies and rejects unknown state
        kinds. This does not itself prove delegation flush or an admission gate.
        """
        need(self.server is not None and not self.server_closed,"actual_original_nfsd_client_directory_required")
        need(same_process(self.server["pid"],process(self.server["pid"]["pid"])),"original_server_changed_during_client_census")
        versions=self.read_fd(self.server["versions_fd"]).decode("ascii").split()
        need(any(value in versions for value in ("+4","+4.1","+4.2")) and not any(value in versions for value in ("+2","+3")),"stateless_nfs_protocol_client_ownership_not_provable_by_v4_census")
        directory=self.server["clients_fd"]
        need(fs_magic(directory) == 0x6E667364,"actual_server_netns_nfsd_clients_filesystem_required")
        names=sorted(os.listdir(directory))
        need(len(names) <= 4096 and all(re.fullmatch(r"[0-9]+",name) for name in names),"complete_finite_nfsd_client_directory_required")
        clients=[]
        total=0
        for name in names:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            try:
                values={}
                for leaf in ("info","states"):
                    fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=child)
                    try:
                        need(fs_magic(fd) == 0x6E667364,"actual_nfsd_client_leaf_filesystem_required")
                        values[leaf]=self.read_fd(fd)
                        total+=len(values[leaf])
                        need(total <= 1<<20,"actual_nfsd_client_and_state_total_limit")
                    finally:
                        os.close(fd)
                fd=os.open("info",os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=child)
                try:
                    values["info_after"]=self.read_fd(fd)
                    total+=len(values["info_after"])
                    need(total <= 1<<20,"actual_nfsd_client_and_state_total_limit")
                finally:
                    os.close(fd)
            finally:
                os.close(child)
            info=values["info"].decode("ascii")
            address=re.findall(r'(?m)^address: "([0-9.]+):([0-9]+)"$',info)
            identity=re.findall(r"(?m)^clientid: (0x[0-9a-f]+)$",info)
            minor=re.findall(r"(?m)^minor version: ([012])$",info)
            need(len(address) == 1 and len(identity) == 1 and len(minor) == 1 and 0 <= int(address[0][1]) <= 65535,"unknown_actual_nfsd_client_identity_or_address_format")
            actual_ip=str(ipaddress.IPv4Address(address[0][0]))
            after=values["info_after"].decode("ascii")
            need(re.findall(r'(?m)^address: "([0-9.]+):([0-9]+)"$',after) == address and re.findall(r"(?m)^clientid: (0x[0-9a-f]+)$",after) == identity and re.findall(r"(?m)^minor version: ([012])$",after) == minor,"actual_nfsd_client_identity_changed_across_states_eof")
            states=values["states"]
            kinds=[]
            for line in states.splitlines():
                if not line.strip():
                    continue
                kind=re.match(br"^- 0x[0-9a-f]+: \{ type: ([a-z_]+),",line)
                need(kind is not None,"unknown_actual_nfsd_state_record_format")
                kinds.append(kind[1].decode("ascii"))
            item={"directory":name,"client_id":identity[0],"minor_version":int(minor[0]),"address":actual_ip,"port":int(address[0][1]),"info_ascii":info,"states_bytes_hex":states.hex(),"info_sha256":sha(values["info"]),"states_sha256":sha(values["states"]),"state_kinds":kinds}
            clients.append(item)
        need(names == sorted(os.listdir(directory)),"actual_nfsd_client_census_changed_before_eof")
        need(same_process(self.server["pid"],process(self.server["pid"]["pid"])),"original_server_changed_during_client_census")
        result={"server":self.server["item"],"node":self.definition["node"],"versions":versions,"clients":clients,"complete_client_directory_and_states_eof":True,"delegation_flush_proved":False,"network_admission_fence_proved":False,"backup_ready":False}
        self.event("actual_nfsd_v4_clients_and_states_eof",result)
        return result

    def sync_clients(self):
        self.original_processes_absent()
        result = []
        for record in self.clients:
            need(mount_pin(record["fd"]) == record["pin"], "original_mount_fd_replaced")
            syncfs(record["fd"])
            value = tree(record["fd"], fsync_files=True)
            syncfs(record["fd"])
            self.event("actual_original_client_syncfs_fsync_eof_completed", {"item": record["item"], "pin": record["pin"], "tree": value})
            result.append({"pod_uid": record["item"]["pod_uid"], "pin": record["pin"], "tree": value})
        self.original_processes_absent()
        self.client_result = result
        return result

    def isolate_server(self, recovery=False):
        need(self.server is not None and (getattr(self,"recovery_synced",False) if recovery else hasattr(self,"client_result")), "actual_client_commit_before_server_isolation")
        # This is confined to the independently pinned original server CRI.
        # No shell, caller command, arbitrary target export or global host NFSD.
        raw=self.server_exec(["/usr/sbin/exportfs", "-s"])
        need(parse_exports(raw) == self.server["exports"], "original_export_table_changed")
        self.server_exec(["/usr/sbin/exportfs", "-ua"])
        self.server_exec(["/usr/sbin/exportfs", "-f"])
        need(not self.server_exec(["/usr/sbin/exportfs", "-s"]).strip(), "native_export_table_not_empty")
        # Write to the actual namespace-pinned NFSD mount opened BEFORE stop;
        # merely stopping its Pod never counts as a kernel-server shutdown.
        self.write_control(self.server["threads_fd"],b"0\n")
        deadline = time.monotonic() + 30
        while int(self.read_fd(self.server["threads_fd"]).strip()) != 0:
            need(time.monotonic() < deadline, "native_nfsd_threads_not_drained")
            time.sleep(0.05)
        # The original supervisor must not re-create NFSD between the zero
        # observation and its guarded Deployment stop. Freeze only this exact
        # original CID's user cgroup; kernel NFSD is checked separately.
        self.server_user_freeze(True)
        need(int(self.read_fd(self.server["threads_fd"]).strip()) == 0,"native_nfsd_restarted_before_user_scope_frozen")
        exports = self.read_fd(self.server["exports_fd"])
        need(not [line for line in exports.splitlines() if line.strip() and not line.lstrip().startswith(b"#")], "native_kernel_exports_remain")
        syncfs(self.server["hostfd"])
        if recovery:
            self.server_result={"full_tree_integrity_proved":False,"recovery_only":True}
            return {"pin":self.server["pin"],"nfsd_threads":0,"kernel_exports":0,"full_tree_integrity_proved":False}
        value = tree(self.server["hostfd"], fsync_files=True)
        syncfs(self.server["hostfd"])
        need(all(item["tree"] == value for item in self.client_result), "client_server_complete_tree_not_identical")
        self.event("actual_server_exports_empty_nfsd_zero_and_local_sync_completed", {"pin": self.server["pin"], "tree": value})
        self.server_result = value
        return {"pin": self.server["pin"], "tree": value, "nfsd_threads": 0, "kernel_exports": 0}

    def verify_isolated(self):
        need(self.server is not None and hasattr(self, "server_result"), "server_isolation_not_observed")
        need(int(self.read_fd(self.server["threads_fd"]).strip()) == 0, "native_nfsd_restarted")
        exports = self.read_fd(self.server["exports_fd"])
        need(not [line for line in exports.splitlines() if line.strip() and not line.lstrip().startswith(b"#")], "native_kernel_export_reappeared")
        need(mount_pin(self.server["hostfd"])["inode"] == self.server["pin"]["inode"], "original_server_pvc_root_replaced")
        try:
            current=process(self.server["pid"]["pid"])
        except FileNotFoundError:
            current=None
        if current is not None and same_process(current,self.server["pid"]):
            need(self.server.get("user_freeze_owned") and self.server_user_frozen(self.server),"original_server_supervisor_not_fenced")
        return {"pin": self.server["pin"], "tree_at_cut": self.server_result, "nfsd_threads": 0, "kernel_exports": 0}

    def call(self, action):
        if self.definition["direction"] == "observe-restored-server":
            need(action in ("probe","verify-server-restored","release-restored-observation","abort-before-mutation"),"restored_server_observer_cannot_mutate_source_or_exports")
        need(action in ("probe", "source-mount-census", "source-node-network", "source-nfs-client-census", "preflight-tree-profile", "sync-clients", "isolate-server", "isolate-server-for-recovery", "verify-isolated", "close-client-fds", "finalize-server-stop", "verify-server-restored", "confirm-application-exit", "confirm-client-exit", "confirm-server-exit", "close-server-fds", "close-dead-server-for-recovery", "stop-original-clients", "stop-original-application", "stop-original-server", "release-restored-observation", "abort-before-mutation", "restore-original-server", "sync-clients-for-recovery", "close-recovery-client-fds"), "finite_native_action_required")
        if action in ("sync-clients", "isolate-server", "isolate-server-for-recovery", "close-client-fds", "close-server-fds", "close-dead-server-for-recovery", "finalize-server-stop", "stop-original-clients", "stop-original-application", "stop-original-server", "release-restored-observation", "restore-original-server", "sync-clients-for-recovery", "close-recovery-client-fds"):
            need(action not in self.sent, "original_native_send_unknown_no_replay")
            self.event(action + "_send_unknown", {})
            self.sent.add(action)
        if action == "preflight-tree-profile":
            # Reject unsupported file types/permissions before any client is
            # stopped. Concurrent activity may refuse this preflight safely.
            need(not self.sent,"tree_preflight_before_mutations_only")
            for record in self.clients:
                tree(record["fd"])
            if self.server:
                tree(self.server["hostfd"])
            return {"complete_finite_tree_profile_read":True,"no_backup_proof":True}
        if action == "probe":
            return {"clients": [{key: value[key] for key in ("item", "pid", "mount", "pin")} for value in self.clients],
                    "server": None if self.server is None else {key: self.server[key] for key in ("item", "pid", "mount", "pin", "exports", "kernel_exports", "versions")}}
        if action == "source-mount-census":
            return self.source_mount_census()
        if action == "source-node-network":
            return self.source_node_network()
        if action == "source-nfs-client-census":
            return self.source_nfs_client_census()
        if action == "confirm-application-exit":
            records = [record for record in self.clients if record["item"].get("role") == "application"]
            if records:
                self.original_processes_absent(records)
            return {"actual_application_scopes_absent": len(records)}
        if action == "confirm-client-exit":
            self.original_processes_absent()
            return {"actual_client_scopes_absent": len(self.clients)}
        if action in ("stop-original-clients","stop-original-application","stop-original-server"):
            # Recovery only, after guarded DP replicas=0. Runtime stop applies
            # solely to exact original CIDs, never a shell/process-name kill.
            records=[self.server] if action == "stop-original-server" else [record for record in self.clients if action != "stop-original-application" or record["item"].get("role") == "application"]
            need(all(record is not None for record in records),"original_stop_records_required")
            for record in records:
                cid = record["item"]["container_id"].split("://",1)[1]
                values = decode(self.cri(["ps","-a","--id",cid,"--output","json"]))["containers"]
                need(len(values) <= 1 and (not values or values[0]["id"] == cid), "recovery_original_cri_identity_unknown")
                if values and values[0]["state"] in ("CONTAINER_RUNNING",1):
                    self.inspect(record["item"])
                    self.cri(["stop","--timeout","60",cid])
            return {"original_container_stop_acknowledged":len(records),"process_exit_proved":False}
        if action == "confirm-server-exit":
            need(self.server is not None, "actual_server_required")
            self.original_processes_absent([self.server])
            return {"actual_server_scopes_absent": 1}
        if action == "sync-clients":
            return self.sync_clients()
        if action == "sync-clients-for-recovery":
            need(not self.clients_closed,"original_recovery_fds_closed")
            self.original_processes_absent()
            result=[]
            for record in self.clients:
                need(mount_pin(record["fd"]) == record["pin"],"original_recovery_mount_changed")
                syncfs(record["fd"])
                result.append({"pod_uid":record["item"]["pod_uid"],"pin":record["pin"]})
            self.original_processes_absent()
            self.recovery_synced=True
            # Operational reversal only. No claim that a failed tree/commit
            # migration was proved, no backup readiness or native hold proof.
            return {"original_mount_syncfs_completed":result,"full_tree_integrity_proved":False,"backup_ready":False}
        if action == "close-recovery-client-fds":
            need(getattr(self,"recovery_synced",False) and not self.clients_closed,"original_recovery_sync_not_observed")
            self.original_processes_absent()
            self.close_client_mounts()
            return {"original_recovery_mounts_released":len(self.clients)}
        if action == "isolate-server":
            return self.isolate_server()
        if action == "isolate-server-for-recovery":
            return self.isolate_server(recovery=True)
        if action == "verify-isolated":
            return self.verify_isolated()
        if action == "finalize-server-stop":
            self.original_processes_absent([self.server])
            self.verify_isolated()
            syncfs(self.server["hostfd"])
            value = tree(self.server["hostfd"], fsync_files=True)
            syncfs(self.server["hostfd"])
            need(value == self.server_result, "server_source_changed_after_isolation")
            return {"pin": self.server["pin"], "tree": value, "nfsd_threads": 0, "kernel_exports": 0}
        if action == "verify-server-restored":
            need(self.server is not None and sha(self.server_exec(["/usr/sbin/exportfs", "-s"])) == self.server["exports_raw_sha256"], "restored_server_export_changed")
            need(int(self.read_fd(self.server["threads_fd"]).strip()) > 0, "restored_nfsd_not_running")
            return {"pin": self.server["pin"], "exports": self.server["exports"], "original_cri":self.server["item"],"actual_nfsd_threads":int(self.read_fd(self.server["threads_fd"]).strip())}

        if action == "restore-original-server":
            need(self.server is not None and not self.server_closed,"same_live_original_server_required_for_in_place_restore")
            if self.server.get("user_freeze_owned"):
                self.server_user_freeze(False)
            need(sha(self.server_exec(["/bin/cat","/etc/exports"])) == self.server["exports_config_sha256"],"original_export_config_changed")
            raw=self.server_exec(["/usr/sbin/exportfs","-s"])
            need(not raw.strip() or parse_exports(raw) == self.server["exports"],"foreign_export_appeared_cannot_restore")
            kernel=self.read_fd(self.server["exports_fd"])
            rows=b"\n".join(line for line in kernel.splitlines() if line.strip() and not line.lstrip().startswith(b"#"))
            need(not rows.strip() or parse_exports(rows) == self.server["kernel_exports"],"foreign_kernel_export_appeared_cannot_restore")
            self.server_exec(["/usr/sbin/exportfs","-ra"])
            value=(str(self.server["original_threads"])+"\n").encode()
            self.write_control(self.server["threads_fd"],value)
            need(parse_exports(self.server_exec(["/usr/sbin/exportfs","-s"])) == self.server["exports"] and int(self.read_fd(self.server["threads_fd"]).strip()) > 0,"original_nfsd_restore_readback_unconfirmed")
            return self.call("verify-server-restored")

        if action == "release-restored-observation":
            need((not self.clients or self.clients_closed) and self.server is not None and not self.server_closed, "restored_server_observation_only")
            self.call("verify-server-restored")
            self.close_server_controls()
            self.clients_closed = True
            return {"fresh_restored_server_observation_released":True}
        if action == "abort-before-mutation":
            need(not self.sent, "native_mutation_already_sent_cannot_abort")
            if self.server is not None:
                self.close_server_controls()
            self.close_client_mounts()
            return {"unmutated_probe_fds_released":True}

        if action == "close-server-fds":
            need(self.server is not None and hasattr(self, "server_result"), "original_server_close_unconfirmed")
            self.original_processes_absent([self.server])
            self.verify_isolated()
            self.close_server_controls()
            return {"server_mount_and_control_fds_closed": True}
        if action == "close-dead-server-for-recovery":
            need(self.server is not None and not self.server_closed,"original_dead_server_controls_required")
            self.original_processes_absent([self.server])
            self.original_processes_absent()
            raw=self.read_fd(self.server["exports_fd"])
            rows=b"\n".join(line for line in raw.splitlines() if line.strip() and not line.lstrip().startswith(b"#"))
            need(not rows.strip() or parse_exports(rows) == self.server["kernel_exports"],"foreign_dead_server_kernel_export_cannot_shutdown")
            self.write_control(self.server["threads_fd"],b"0\n")
            deadline=time.monotonic()+30
            while int(self.read_fd(self.server["threads_fd"]).strip()) != 0:
                need(time.monotonic()<deadline,"dead_server_nfsd_shutdown_unconfirmed")
                time.sleep(0.05)
            raw=self.read_fd(self.server["exports_fd"])
            need(not [line for line in raw.splitlines() if line.strip() and not line.lstrip().startswith(b"#")],"dead_server_kernel_exports_not_drained")
            syncfs(self.server["hostfd"])
            self.original_processes_absent([self.server])
            pin=self.server["pin"]
            need(mount_pin(self.server["hostfd"])["device"] == pin["device"] and mount_pin(self.server["hostfd"])["inode"] == pin["inode"],"dead_server_original_pvc_inode_changed")
            self.close_server_controls()
            return {"same_original_server_scopes_absent":True,"nfsd_threads":0,"kernel_exports":0,"pin":pin,"full_tree_integrity_proved":False,"client_commit_proved":False}
        need(hasattr(self, "client_result"), "client_commit_not_observed")
        self.close_client_mounts()
        return {"client_mount_fds_closed": len(self.clients)}

    def close_client_mounts(self):
        for value in self.clients:
            os.close(value["fd"])
            for fd in value["namespaces"]:
                os.close(fd)
        self.clients_closed = True

    def close_server_controls(self):
        for name in ("fd", "hostfd", "threads_fd", "versions_fd", "exports_fd", "clients_fd", "netns_fd"):
            os.close(self.server[name])
        for fd in self.server["namespaces"]:
            os.close(fd)
        for name in ("user_freeze_fd","user_events_fd"):
            if name in self.server:
                os.close(self.server[name])
        self.server_closed = True


def root_peer(connection):
    import struct
    _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == 0, "native_actor_root_peer_required")


def stream_write(stream,raw):
    pending=memoryview(raw)
    while pending:
        count=stream.write(pending)
        need(count is not None and count > 0,"native_transport_short_write_unconfirmed")
        pending=pending[count:]


def serve(listener, definition):
    """The root owner retains original FDs across transport disconnects.

    Never daemon-recreate a missing original incarnation. Actor construction
    creates the original journal exclusively; an existing journal without its
    live owner is a blocking native uncertainty, not permission to reprepare.
    """
    actor = Actor(definition)
    source_sha256=sha(file_bytes(__file__))
    actor.event("persistent_original_actor_started", process(os.getpid()))
    replies, actions = {}, {}
    while True:
        connection, _ = listener.accept()
        try:
            root_peer(connection)
            stream = connection.makefile("rwb", buffering=0)
            hello = stream.readline(MAX + 1)
            need(hello == encoded(definition) + b"\n", "same_original_actor_definition_required")
            stream_write(stream,encoded({"version":VERSION,"native_source_sha256":source_sha256,"definition_sha256":sha(encoded(definition)),"session":definition["session"],"owner":process(os.getpid())}) + b"\n")
            while True:
                raw = stream.readline(MAX + 1)
                if not raw:
                    break
                request = decode(raw)
                need(set(request) == {"operation", "action", "nonce"} and request["operation"] == definition["operation"] and re.fullmatch(r"[a-f0-9]{64}", request["nonce"]), "original_native_rpc_identity")
                prior = replies.get(request["nonce"])
                if prior is not None:
                    need(all(prior.get(key) == value for key,value in request.items()), "native_rpc_nonce_reuse_mismatch")
                    result = prior
                else:
                    try:
                        if request["action"] == "session-status":
                            data = {"owner":process(os.getpid()), "replies":decode(encoded(actions)) if actions else {}, "clients_closed":actor.clients_closed,"server_closed":actor.server_closed}
                        elif request["action"] == "retire-owner":
                            need(actor.clients_closed and actor.server_closed,"original_fds_not_released_owner_must_remain")
                            data = {"all_original_fds_released":True}
                        else:
                            data = actor.call(request["action"])
                        actor.event(request["action"] + "_observed", {"request":request,"data":data})
                        result = {"version": VERSION, **request, "node": definition["node"], "session": definition["session"], "journal_sha256": actor.previous, "data": data}
                    except Exception as error:
                        actor.event("native_action_unconfirmed", {"request":request})
                        result = {"version": VERSION, **request, "error": str(error) if isinstance(error, Refused) else "native_action_unconfirmed"}
                    replies[request["nonce"]] = result
                    if request["action"] not in ("session-status","retire-owner"):
                        actions[request["action"]] = result
                    actor.event("retained_original_rpc_response", result)
                stream_write(stream,encoded(result) + b"\n")
                if request["action"] == "retire-owner" and "data" in result:
                    return
        except (Exception, BrokenPipeError):
            # No timeout thaw/close, no new native incarnation. Reconnection
            # must present exactly the original definition and request nonce.
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass
            connection.close()


def main():
    need(os.name == "posix" and os.geteuid() == 0, "native_root_required")
    need(sys.argv[1:] in ([],["--attach-only"]),"finite_native_entry_mode_required")
    attach_only=bool(sys.argv[1:])
    first = sys.stdin.buffer.readline(MAX + 1)
    definition = decode(first)
    need(definition["version"] == VERSION and re.fullmatch(r"[a-f0-9]{32}", definition["operation"]) and re.fullmatch(r"[a-f0-9]{32}", definition["session"]), "original_native_operation")
    # Abstract sockets have a strict length bound and leave no replaceable
    # filesystem socket path. Both ends independently require SO_PEERCRED uid0.
    address = b"\0cm-workspace-" + definition["operation"].encode() + b"-" + definition["session"].encode()
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.connect(address)
    except (ConnectionRefusedError, FileNotFoundError):
        need(not attach_only,"original_persistent_owner_missing_no_reprepare")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(address)
        listener.listen(1)
        child = os.fork()
        if child == 0:
            connection.close()
            os.setsid()
            null = os.open("/dev/null", os.O_RDWR)
            for fd in (0,1,2):
                os.dup2(null,fd)
            if null > 2:
                os.close(null)
            try:
                serve(listener,definition)
            except BaseException:
                os._exit(1)
            os._exit(0)
        listener.close()
        connection.connect(address)
    root_peer(connection)
    stream = connection.makefile("rwb",buffering=0)
    stream_write(stream,encoded(definition)+b"\n")
    hello = decode(stream.readline(MAX+1))
    need(hello["version"] == VERSION and hello.get("native_source_sha256") == sha(file_bytes(__file__)) and hello["definition_sha256"] == sha(encoded(definition)) and hello["session"] == definition["session"], "original_live_actor_handshake_failed")
    for raw in sys.stdin.buffer:
        need(0 < len(raw) <= MAX, "native_rpc_limit")
        stream_write(stream,raw)
        reply = stream.readline(MAX+1)
        need(0 < len(reply) <= MAX, "original_actor_reply_unconfirmed")
        sys.stdout.buffer.write(reply)
        sys.stdout.buffer.flush()
    # Only the relay closes on SSH EOF. The actual owner and FDs remain live.
    stream.close()
    connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Original root-private journal, FDs and uncertain operation must be
        # inspected by the same controller; no restored/success flag on EOF.
        sys.exit(1)
