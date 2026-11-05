"""Original MySQL-node private mount namespace for the ONE full Go caller.

Only a readonly bind of the original held MySQL directory is introduced.
The host filesystem paths containing original issuer-signed nonce materials
and every other original input remain unchanged. No Pod or source is stopped.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys

NATIVE_SHA = "fa5aff4df941e9854937b3ea41ad2c46afd38cf1e1019a64f0d618a099209e9d"
CRI_SHA = "d9f541aa6a3a1fce15392d4366da5f97b47683aa55a825909ad8c0a624c7f4f3"
DATADIR = "/var/lib/mysql"
HOST_SOURCE = "/data/clawmanager-zhanghui08/system/mysql"


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)+"\n").encode()


def file_bytes(path, expected=None, private=True, limit=4 << 20):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_original_bridge_file_required")
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, "original_bridge_regular_file_required")
    if private:
        need(before.st_uid == 0 and before.st_mode & 0o077 == 0, "original_bridge_private_root_file_required")
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        raw = source.read(limit+1)
        after = os.fstat(source.fileno())
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    need(stamp(before) == stamp(opened) == stamp(after) and len(raw) == before.st_size, "original_bridge_file_changed")
    need(expected is None or hashlib.sha256(raw).hexdigest() == expected, "original_bridge_file_sha_changed")
    return raw


def save(path, value):
    raw = encoded(value)
    with path.open("xb") as target:
        os.chmod(path, 0o600)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def inode(fd):
    st = os.fstat(fd)
    return {"device": st.st_dev, "inode": st.st_ino}


def original_node(plan):
    need(Path("/etc/machine-id").read_text().strip() == plan["node"]["machine_id"] and Path("/proc/sys/kernel/random/boot_id").read_text().strip() == plan["node"]["boot_id"], "run_bridge_on_actual_original_mysql_node_only")


def load_native(plan):
    path = Path(plan["native_helper"]["File"])
    file_bytes(path, NATIVE_SHA, private=False)
    need(plan["native_helper"]["SHA256"] == NATIVE_SHA, "reviewed_original_native_helper_required")
    spec = importlib.util.spec_from_file_location("c1_original_mysql_native_identity", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def original_mysql(plan, native):
    file_bytes(plan["cri"]["File"], CRI_SHA, private=False, limit=64 << 20)
    need(plan["cri"]["SHA256"] == CRI_SHA and plan["cri"]["Endpoint"] in ("unix:///run/containerd/containerd.sock", "unix:///run/k3s/containerd/containerd.sock"), "actual_original_cri_release_and_endpoint_required")
    actor = native.Actor.__new__(native.Actor)
    actor.binary = plan["cri"]["File"]
    actor.definition = {"cri_endpoint": plan["cri"]["Endpoint"], "node": {"name": plan["node"]["name"]}}
    actor.cri(["--version"], expected=b"crictl version v1.31.1\n")
    record = actor.root(plan["mysql"]["native_container"], DATADIR, ("ext4", "xfs"))
    need(record["mount"]["root"] == HOST_SOURCE, "actual_mysql_mount_root_must_be_original_pv_hostpath")
    return actor, record


def recheck(actor, record, native):
    current = actor.inspect(record["item"])
    need(current["status"]["state"] in ("CONTAINER_RUNNING", 1) and int(current["info"]["pid"]) == record["pid"]["pid"] and native.same_process(record["pid"], native.process(record["pid"]["pid"])), "original_mysql_container_or_process_changed")
    selected = [m for m in native.mounts(record["pid"]["pid"]) if m["path"] == DATADIR]
    need(selected == [record["mount"]] and "rw" in selected[0]["options"], "original_mysql_mount_changed_or_was_remounted")


def recheck_live_mysql(plan, record, native):
    """Bounded real CRI/process/mount read while the collector stays alive."""
    item = plan["mysql"]["native_container"]
    cid = item["container_id"].split("://", 1)[1]
    file_bytes(plan["cri"]["File"], CRI_SHA, private=False, limit=64 << 20)
    result = subprocess.run([plan["cri"]["File"], "--runtime-endpoint", plan["cri"]["Endpoint"], "--timeout", "2s", "inspect", "--output", "json", cid], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3)
    need(result.returncode == 0 and len(result.stdout) <= 4 << 20, "original_mysql_live_cri_check_unconfirmed")
    current = json.loads(result.stdout)
    status = current["status"]
    labels = status["labels"]
    need(status["id"] == cid and status["state"] in ("CONTAINER_RUNNING", 1) and all(labels.get(key) == value for key, value in {"io.kubernetes.pod.uid": item["pod_uid"], "io.kubernetes.pod.namespace": item["namespace"], "io.kubernetes.pod.name": item["pod"]}.items()), "original_mysql_live_pod_container_drift")
    need(status.get("imageRef", "").rsplit("@", 1)[-1] == item["image_digest"] and int(current["info"]["pid"]) == record["pid"]["pid"] and native.same_process(record["pid"], native.process(record["pid"]["pid"])), "original_mysql_live_process_or_image_drift")
    selected = [m for m in native.mounts(record["pid"]["pid"]) if m["path"] == DATADIR]
    need(selected == [record["mount"]] and "rw" in selected[0]["options"], "original_mysql_live_mount_drift")


def resolver_bytes(fd):
    before = os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 65536, "actual_original_container_resolver_regular_file_required")
    raw = os.pread(fd, 65537, 0)
    after = os.fstat(fd)
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and len(raw) == before.st_size, "actual_original_container_resolver_changed")
    return raw


def original_resolver(record, native):
    entries = [entry for entry in native.mounts(record["pid"]["pid"]) if entry["path"] == "/etc/resolv.conf"]
    need(len(entries) == 1, "actual_original_mysql_resolv_conf_mount_required")
    fd = os.open("/proc/"+str(record["pid"]["pid"])+"/root/etc/resolv.conf", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = resolver_bytes(fd)
        need(native.same_process(record["pid"], native.process(record["pid"]["pid"])), "original_mysql_changed_during_resolver_open")
        nameservers, search = [], []
        for line in raw.decode("ascii").splitlines():
            words = line.split("#", 1)[0].split(";", 1)[0].split()
            if not words:
                continue
            if words[0] == "nameserver":
                need(len(words) == 2, "unknown_actual_original_nameserver_line")
                address = ipaddress.ip_address(words[1])
                need(not address.is_loopback and not address.is_unspecified and not address.is_multicast, "original_pod_dns_must_be_reachable_outside_its_loopback_namespace")
                nameservers.append(str(address))
            if words[0] == "search":
                search = words[1:]
        domains = {name.removeprefix(native.NS+".svc.").rstrip(".") for name in search if name.startswith(native.NS+".svc.")}
        need(0 < len(nameservers) <= 3 and len(domains) == 1, "actual_original_clusterfirst_nameservers_and_search_domain_required")
        return {"fd": fd, "mount": entries[0], "inode": inode(fd), "sha256": hashlib.sha256(raw).hexdigest(), "nameservers": nameservers, "cluster_domain": next(iter(domains)), "search": search}
    except BaseException:
        os.close(fd)
        raise


def recheck_resolver(record, resolver, native):
    entries = [entry for entry in native.mounts(record["pid"]["pid"]) if entry["path"] == "/etc/resolv.conf"]
    need(entries == [resolver["mount"]] and inode(resolver["fd"]) == resolver["inode"] and hashlib.sha256(resolver_bytes(resolver["fd"])).hexdigest() == resolver["sha256"], "actual_original_mysql_resolver_drifted")
    current = os.open("/proc/"+str(record["pid"]["pid"])+"/root/etc/resolv.conf", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(inode(current) == resolver["inode"], "actual_original_mysql_resolver_mount_replaced")
    finally:
        os.close(current)


def clone_original_fds(libc, record, resolver):
    # open_tree checks that the held source mount belongs to the current
    # mount namespace. Clone only while temporarily in that ORIGINAL namespace;
    # never attach/remount/write there. Restore the held host namespace before
    # any path operation or private-namespace mount.
    need(len(list(Path("/proc/self/task").iterdir())) == 1,
         "original_mount_clone_requires_single_threaded_process")
    # setns(mnt) may change root/cwd to the selected namespace root.
    # Resolve namespace identity only through the pre-held HOST procfs FD;
    # an ordinary source Pod procfs need not expose the host helper PID.
    host_proc = os.open("/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    host_cwd = host_root = host_ns = -1
    try:
        host_cwd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        host_root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        host_ns = os.open("self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC, dir_fd=host_proc)
        host_id = os.readlink("self/ns/mnt", dir_fd=host_proc)
    except BaseException:
        for fd in (host_ns, host_root, host_cwd, host_proc):
            if fd >= 0:
                os.close(fd)
        raise
    source_ns = record["namespaces"][1]
    source_id = record["pid"]["mntns"]
    clones = []
    libc.syscall.restype = ctypes.c_long
    try:
        need(os.readlink("self/fd/"+str(source_ns), dir_fd=host_proc) == source_id,
             "held_original_mysql_mount_namespace_changed")
        try:
            need(libc.setns(source_ns, 0x00020000) == 0,
                 "actual_original_mysql_clone_namespace_entry_failed")
            need(os.readlink("self/ns/mnt", dir_fd=host_proc) == source_id,
                 "actual_original_mysql_clone_namespace_not_selected")
            for fd in (record["fd"], resolver["fd"]):
                clone = libc.syscall(ctypes.c_long(428), ctypes.c_int(fd),
                                     ctypes.c_char_p(b""),
                                     ctypes.c_uint(1 | os.O_CLOEXEC | 0x1000))
                if clone < 0:
                    raise Refused("original_mount_clone_open_tree_errno_"+str(ctypes.get_errno()))
                clones.append(clone)
                need(inode(clone) == inode(fd), "original_detached_mount_inode_mismatch")
        finally:
            # Even a clone failure must restore the original host namespace.
            # If restore fails the process refuses; no caller is dispatched.
            need(libc.setns(host_ns, 0x00020000) == 0,
                 "original_host_mount_namespace_restore_failed")
            need(os.readlink("self/ns/mnt", dir_fd=host_proc) == host_id,
                 "original_host_mount_namespace_not_restored")
            restored_root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                need(inode(restored_root) == inode(host_root),
                     "original_host_root_not_restored")
            finally:
                os.close(restored_root)
            os.fchdir(host_cwd)
        return tuple(clones)
    except BaseException:
        for fd in clones:
            os.close(fd)
        raise
    finally:
        for fd in (host_ns, host_root, host_cwd, host_proc):
            os.close(fd)


def attach_original_fd(libc, clone, source_fd, target, reason):
    # Only attach the already-detached original clone after host restoration
    # and unshare/private propagation. Linux amd64 move_mount=429, kernel >=5.2.
    need(inode(clone) == inode(source_fd), reason+"_detached_inode_mismatch")
    result = libc.syscall(ctypes.c_long(429), ctypes.c_int(clone),
                          ctypes.c_char_p(b""), ctypes.c_int(-100),
                          ctypes.c_char_p(os.fsencode(target)),
                          ctypes.c_uint(0x00000004))
    if result != 0:
        raise Refused(reason+"_move_mount_errno_"+str(ctypes.get_errno()))


def private_dns(libc, plan, record, resolver, native, resolver_clone):
    # /etc/resolv.conf may be the host's systemd symlink. Preserve the link;
    # bind only its existing canonical file INSIDE this private namespace.
    target = Path("/etc/resolv.conf").resolve(strict=True)
    need(target.is_file() and target.stat().st_uid == 0 and target.stat().st_mode & 0o022 == 0 and target.parent.resolve(strict=True) == target.parent and target.parent.stat().st_uid == 0 and target.parent.stat().st_mode & 0o022 == 0, "original_host_resolver_target_must_be_root_controlled")
    before = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        host_inode = inode(before)
        attach_original_fd(libc, resolver_clone, resolver["fd"], target, "actual_original_resolver_fd_private_bind")
        need(libc.mount(None, os.fsencode(target), None, 0x1000 | 0x20 | 1 | 2 | 4 | 8, None) == 0, "actual_original_resolver_private_readonly_bind_failed")
        mounted = os.open("/etc/resolv.conf", os.O_RDONLY | os.O_CLOEXEC)
        try:
            need(inode(mounted) == resolver["inode"] and hashlib.sha256(resolver_bytes(mounted)).hexdigest() == resolver["sha256"] and os.fstatvfs(mounted).f_flag & os.ST_RDONLY, "private_resolver_not_actual_original_readonly_file")
        finally:
            os.close(mounted)
        entries = [entry for entry in native.mounts("self") if entry["path"] == str(target)]
        need(len(entries) == 1 and "ro" in entries[0]["options"] and entries[0]["root"] == resolver["mount"]["root"] and entries[0]["device"] == resolver["mount"]["device"], "private_original_resolver_mount_identity_mismatch")
        host = os.open("/proc/1/root"+str(target), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(inode(host) == host_inode, "original_host_resolver_changed_outside_private_namespace")
        finally:
            os.close(host)
    finally:
        os.close(before)
    services = plan["dns_services"]
    need(0 < len(services) <= 64, "actual_current_clusterip_service_roster_required")
    queries = {service["name"]+"."+native.NS+".svc."+resolver["cluster_domain"] for service in services}
    aliases = {name.lower().rstrip(".") for name in queries} | {service["name"]+"."+native.NS+".svc" for service in services}
    hosts = file_bytes("/etc/hosts", private=False, limit=65536)
    for line in hosts.decode("utf-8").splitlines():
        words = line.split("#", 1)[0].split()
        need(not any(word.lower().rstrip(".") in aliases for word in words[1:]), "host_hosts_override_for_actual_cluster_service_refused")
    answers = []
    for service in services:
        name = service["name"]+"."+native.NS+".svc."+resolver["cluster_domain"]
        actual = sorted({str(ipaddress.ip_address(entry[4][0])) for entry in socket.getaddrinfo(name+".", None, socket.AF_UNSPEC, socket.SOCK_STREAM)})
        need(actual == sorted(service["cluster_ips"]), "actual_service_dns_does_not_match_current_original_service_clusterips")
        answers.append({"service": service, "original_fqdn": name, "actual_resolved_ips": actual})
    recheck_resolver(record, resolver, native)
    return {"original_mysql_resolver_mount": resolver["mount"], "original_mysql_resolver_inode": resolver["inode"], "resolver_sha256": resolver["sha256"], "nameservers": resolver["nameservers"], "search": resolver["search"], "private_resolver_target": str(target), "private_mount": entries[0], "current_service_answers": answers, "original_hosts_sha256": hashlib.sha256(hosts).hexdigest(), "hosts_entries_added": False, "original_urls_sni_ca_unchanged": True, "provider_tls_still_required_by_real_caller": True}


def caller_environment():
    # The new Go process must read the actual bound resolv.conf regardless of
    # host libc/NSS/systemd-resolved settings. Keep other GODEBUG selections.
    environment = dict(os.environ)
    options = [entry for entry in environment.get("GODEBUG", "").split(",") if entry and not entry.startswith("netdns=")]
    environment["GODEBUG"] = ",".join(options+["netdns=go"])
    for name in ("LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES"):
        environment.pop(name, None)
    return environment


def run(plan_file, plan_sha):
    need(os.geteuid() == 0 and sys.platform == "linux" and os.uname().machine == "x86_64", "original_linux_amd64_root_bridge_required")
    plan = json.loads(file_bytes(plan_file, plan_sha))
    need(plan["version"] == "original-c1-host-mysql-private-mount.v1" and plan["datadir"] == DATADIR and plan["host_source"] == HOST_SOURCE and re.fullmatch(r"[a-f0-9]{32}", plan["operation"]), "fixed_original_mysql_bridge_profile_required")
    original_node(plan)
    directory = Path(plan["receipt_directory"])
    need(directory.is_absolute() and directory.resolve(strict=True) == directory and directory.stat().st_uid == 0 and directory.stat().st_mode & 0o077 == 0, "original_bridge_private_receipt_directory_required")
    need(not any(directory.iterdir()), "original_bridge_already_dispatched_retain_original_outcome")
    native = load_native(plan)
    actor, record = original_mysql(plan, native)
    resolver = original_resolver(record, native)
    host_fd = target_fd = mounted_fd = datadir_clone = resolver_clone = -1
    try:
        source = Path(HOST_SOURCE)
        need(source.resolve(strict=True) == source, "original_mysql_hostpath_must_not_be_symlinked")
        host_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(inode(host_fd) == inode(record["fd"]) and native.fs_magic(host_fd) in (native.EXT4_MAGIC, native.XFS_MAGIC), "original_mysql_pvc_and_actual_container_must_be_same_directory_inode")
        before_namespace = os.readlink("/proc/self/ns/mnt")
        need(before_namespace == os.readlink("/proc/1/ns/mnt"), "bridge_must_begin_in_original_mysql_node_host_namespace")
        target = Path(DATADIR)
        need(target.parent.resolve(strict=True) == target.parent and target.parent.stat().st_uid == 0 and target.parent.stat().st_mode & 0o022 == 0, "original_root_owned_datadir_mount_parent_required")
        if not target.exists():
            target.mkdir(mode=0o700)
        need(target.resolve(strict=True) == target and target.stat().st_uid == 0 and target.stat().st_mode & 0o022 == 0, "original_root_owned_nonsymlink_mount_target_required")
        target_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        original_target_inode = inode(target_fd)
        libc = ctypes.CDLL(None, use_errno=True)
        recheck(actor, record, native)
        recheck_resolver(record, resolver, native)
        datadir_clone, resolver_clone = clone_original_fds(libc, record, resolver)
        recheck(actor, record, native)
        recheck_resolver(record, resolver, native)
        need(libc.unshare(0x00020000) == 0, "actual_private_mysql_mount_namespace_required")
        need(os.readlink("/proc/self/ns/mnt") != before_namespace, "private_mysql_mount_namespace_not_created")
        need(libc.mount(None, b"/", None, 0x40000 | 0x4000, None) == 0, "private_mysql_mount_propagation_required")
        attach_original_fd(libc, datadir_clone, record["fd"], target, "original_mysql_fd_private_mount")
        # MS_BIND|MS_REMOUNT makes THIS mount readonly. Never remount the
        # filesystem superblock or MySQL's original writable container mount.
        need(libc.mount(None, os.fsencode(target), None, 0x1000 | 0x20 | 1 | 2 | 4 | 8, None) == 0, "original_mysql_private_bind_readonly_failed")
        mounted_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(inode(mounted_fd) == inode(record["fd"]) == inode(host_fd), "private_datadir_is_not_same_original_mysql_inode")
        dns = private_dns(libc, plan, record, resolver, native, resolver_clone)
        entries = [m for m in native.mounts("self") if m["path"] == DATADIR]
        need(len(entries) == 1 and "ro" in entries[0]["options"] and entries[0]["root"] == HOST_SOURCE and entries[0]["device"] == record["mount"]["device"] and os.fstatvfs(mounted_fd).f_flag & os.ST_RDONLY, "actual_private_mysql_bind_is_not_readonly_original_mount")
        host_target = os.open("/proc/1/root"+DATADIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(inode(host_target) == original_target_inode, "host_mysql_target_changed_outside_private_namespace")
        finally:
            os.close(host_target)
        auto = file_bytes(target/"auto.cnf", private=False, limit=4096)
        need(b"server-uuid="+plan["server_uuid"].encode("ascii") in [line.strip() for line in auto.splitlines()], "original_auto_cnf_does_not_match_enrolled_live_sql_identity")
        recheck(actor, record, native)
        for pin in plan["original_nonce_files"]:
            file_bytes(pin["File"], pin["SHA256"], limit=4 << 20)
        observation = {"version": "original-c1-host-mysql-private-bind-observed.v1", "operation": plan["operation"], "node": plan["node"], "mysql": plan["mysql"], "actual_cri_process": record["pid"], "actual_mysql_mount": record["mount"], "private_mount": entries[0], "same_original_inode": inode(mounted_fd), "host_namespace": before_namespace, "private_namespace": os.readlink("/proc/self/ns/mnt"), "original_nonce_files": plan["original_nonce_files"], "original_nonce_paths_preserved": bool(plan["original_nonce_files"]), "capacity_only_transport": plan["action"] in ("invoke-capacity", "invoke-capacity-collector"), "mysql_original_mount_still_writable": True, "sql_capacity_must_still_be_collected_by_real_caller": True, "backup_ready": False, "DR": False}
        observation["actual_original_cluster_dns_bridge"] = dns
        save(directory/"actual-private-mount-before-caller.json", observation)
        if plan["action"] == "probe":
            print(json.dumps({"state": "actual_original_mysql_private_readonly_mount_cluster_dns_and_nonce_paths_observed_not_sql_capacity_or_backup_authority", "private_receipt_directory": str(directory), "backup_ready": False}))
            return 0
        need(plan["action"] in ("invoke-complete", "invoke-capacity", "invoke-capacity-collector") and isinstance(plan["argv"], list) and plan["argv"] and all(isinstance(a, str) and "\x00" not in a for a in plan["argv"]), "actual_single_complete_caller_argv_required")
        caller = Path(plan["caller"]["File"])
        allowed = {"invoke-complete": "system-backup-first-adoption-production", "invoke-capacity": "system-backup-c1-native-inputs", "invoke-capacity-collector": "system-backup-c1-native-inputs"}
        need(caller.name == allowed[plan["action"]] and plan["argv"][0] == str(caller), "only_fixed_original_native_owner_elf_may_run")
        if plan["action"] == "invoke-capacity":
            args = plan["argv"]
            need(len(args) > 4 and args[1] == "capacity" and args.count("--mode") == 1 and args[args.index("--mode")+1] in ("issue", "query", "rollback") and not plan["original_nonce_files"], "fixed_capacity_owner_subcommand_required")
        elif plan["action"] == "invoke-capacity-collector":
            args = plan["argv"]
            need(len(args) == 6 and args[1] == "capacity-collect" and args[2] == "--inputs-file" and args[4] == "--inputs-sha256" and not plan["original_nonce_files"], "fixed_readonly_capacity_collector_only")
        else:
            need(bool(plan["original_nonce_files"]), "complete_adoption_requires_original_nonce_bindings")
        raw = file_bytes(caller, plan["caller"]["SHA256"], private=False, limit=128 << 20)
        need(raw[:6] == b"\x7fELF\x02\x01" and raw[18:20] == b"\x3e\x00", "actual_root_built_same_release_linux_amd64_caller_required")
        child = subprocess.Popen(plan["argv"], stdin=subprocess.DEVNULL, env=caller_environment())
        def forward_signal(number, frame):
            if child.poll() is None:
                child.send_signal(number)
        previous = {number: signal.signal(number, forward_signal) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        try:
            if plan["action"] == "invoke-capacity-collector":
                try:
                    while True:
                        try:
                            code = child.wait(timeout=1)
                            break
                        except subprocess.TimeoutExpired:
                            original_node(plan)
                            recheck_live_mysql(plan, record, native)
                            recheck_resolver(record, resolver, native)
                            need(inode(mounted_fd) == inode(record["fd"]) and os.fstatvfs(mounted_fd).f_flag & os.ST_RDONLY, "original_mysql_live_readonly_inode_drift")
                except BaseException:
                    if child.poll() is None:
                        child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
                    raise
            else:
                code = child.wait()
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
        original_node(plan)
        recheck(actor, record, native)
        recheck_resolver(record, resolver, native)
        need(hashlib.sha256(file_bytes("/etc/hosts", private=False, limit=65536)).hexdigest() == dns["original_hosts_sha256"], "original_hosts_changed_during_complete_caller")
        need(inode(mounted_fd) == inode(record["fd"]), "original_mysql_directory_changed_during_complete_caller")
        save(directory/"actual-private-mount-after-caller.json", {"version": "original-c1-mount-after-caller.v1", "operation": plan["operation"], "caller_exit": code, "same_original_inode": inode(mounted_fd), "mysql_original_mount_still_writable": True, "backup_ready": False})
        return code if 0 <= code <= 125 else 3
    finally:
        for fd in (mounted_fd, target_fd, host_fd, datadir_clone, resolver_clone, resolver["fd"], record["fd"], *record["namespaces"]):
            if fd >= 0:
                os.close(fd)
        # The private namespace and its bind die on process exit. Never issue
        # a global umount. If the host target was absent, leave the empty root
        # mountpoint as an explicit operational artifact after interruption.
        # It contains no copied auto.cnf/data and is not a test/build artifact.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-file", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        return run(args.plan_file, args.plan_sha256)
    except (Exception, KeyboardInterrupt):
        print(json.dumps({"state": "STOP_OR_UNKNOWN_ORIGINAL_MYSQL_MOUNT_BRIDGE_RETAIN_ORIGINAL_CALLER_AND_PRIVATE_RECEIPTS", "backup_ready": False}))
        return 3


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
