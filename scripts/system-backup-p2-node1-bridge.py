"""Ship SHA-pinned P2 C1 inputs between the enrolled master and MySQL node."""

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
from collections import deque
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import time


BASE = Path("/root/sbk/p2-vault-jwt-rsa-23cbf0b0-20261116")
SQL_ROOT = Path("/root/sbk-validation-tls-inspect.7LVU7vpE")
RUNTIME = Path("/run/system-backup")
INSTANCE_ROOTS = (
    BASE, SQL_ROOT, RUNTIME,
    Path("/root/sbk/p2-api-runtime-inputs.WWN62yPS"),
    Path("/root/sbk/p2-remote-1a466c69-01"),
    Path("/root/sbk/p2-minio-prepare.9vnemhVi"),
    Path("/root/sbk/p2-install-tools-20261116"),
    Path("/root/sbk/p2-cert-renewal.1KyqMtsd"),
    Path("/root/sbk/p2-materials-1dd1ae71.lVSEBfl2"),
    Path("/root/sbk/p2-redis-connection.b5dQ12Lt"),
)
STATIC = Path("/root/p2-c1-static-832-901")
STATIC_STAGE_SHA = "365bfa8199953f7826ccdfcad274a43fce11db58cbbd346fbb2164817925ee13"
PRODUCTION_SHA = "32d6b9ee3eebad2b38ddcf392307adcd55dbed634299bd84789bd4f7732601a8"
MAX_INPUT = 2 << 20
MAX_FRAME = 8 << 20
FORMAT = "p2-c1-node1-handoff.v1"
NAMESPACE = "clawmanager-sbk-validation-system"
OWNER_POD = "sbk-d4f51b83b57e-controller-59445db996-s6hgn"
OWNER_UID = "aa811725-f7cc-40bc-b64f-f7467ce4477b"
OWNER_CID = "e9c58fa5478b"


def require(condition, stage):
    if not condition:
        raise ValueError(stage)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def pinned_read(path, digest, limit):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= limit, "pinned_file_type_or_size")
    raw = path.read_bytes()
    require(sha(raw) == digest, "pinned_file_digest")
    return raw


def within(path, roots):
    return any(path.is_relative_to(root) for root in roots)


def path_string(value):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 511:
        return None
    path = Path(value)
    return path if str(path) == value and ".." not in path.parts else None


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def signed_record(value):
    """Read file locators inside the native signed JSON envelopes."""
    for record_key, signature_key in (
        ("Record", "Signature"),
        ("record", "signature"),
        ("Payload", "Signature"),
        ("payload", "signature"),
    ):
        record, signature = value.get(record_key), value.get(signature_key)
        if not isinstance(record, str) or not isinstance(signature, str):
            continue
        try:
            if len(base64.b64decode(signature, validate=True)) != 64:
                continue
            decoded = base64.b64decode(record, validate=True)
            if len(decoded) <= MAX_INPUT:
                parsed = json.loads(decoded)
                if isinstance(parsed, dict):
                    return parsed
        except (binascii.Error, UnicodeError, ValueError):
            continue
    return None


def input_scope(argv, journal, static):
    """Follow existing file locators only, keeping output directories empty."""
    require(journal.parent == BASE and journal.name.startswith("c1-direct-run-"), "journal_scope")
    require(argv[1:3] == ["--action", "run-minio-metadata"], "original_c1_action")
    require(sha(Path(argv[0]).read_bytes()) == PRODUCTION_SHA, "original_c1_elf")
    static_sizes = {(entry["name"], entry["size"]): entry for entry in static}
    todo = deque(argv)
    files = {}
    output_dirs = set()
    while todo:
        value = todo.popleft()
        if isinstance(value, dict):
            todo.extend(value.values())
            record = signed_record(value)
            if record is not None:
                todo.append(record)
            continue
        if isinstance(value, list):
            todo.extend(value)
            continue
        path = path_string(value)
        if path is None or path in files or not within(path, INSTANCE_ROOTS) or not path.exists():
            continue
        st = path.lstat()
        require(path.resolve(strict=True) == path, "ambiguous_native_input_path")
        if stat.S_ISDIR(st.st_mode):
            if path.is_relative_to(journal):
                output_dirs.add(str(path))
            continue
        require(st.st_uid == 0 and stat.S_ISREG(st.st_mode) and not st.st_mode & 0o022, "native_input_owner_or_mode")
        if st.st_size > MAX_INPUT:
            entry = static_sizes.get((path.name, st.st_size))
            require(entry is not None, "unqualified_large_native_input")
            pinned_read(path, entry["sha"], entry["size"])
            files[path] = {"SHA256": entry["sha"], "Size": st.st_size, "Static": True}
            continue
        raw = path.read_bytes()
        files[path] = {"SHA256": sha(raw), "Size": len(raw), "Static": False}
        if path.suffix == ".json" and raw:
            try:
                todo.append(json.loads(raw))
            except (UnicodeError, ValueError):
                continue
    require(Path(argv[0]) in files and len(files) < 512, "missing_native_caller_or_excessive_inputs")
    return files, sorted(output_dirs)


def pack_inputs(argv, journal, static, dispatch, until_ns):
    files, directories = input_scope(argv, journal, static)
    items = {
        str(path): dict(entry, Mode=stat.S_IMODE(path.stat().st_mode))
        for path, entry in files.items()
    }
    manifest = {
        "Version": FORMAT,
        "DispatchID": dispatch,
        "UntilNS": until_ns,
        "Argv": argv,
        "Journal": str(journal),
        "Files": items,
        "Directories": directories,
    }
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz", compresslevel=2) as archive:
        add_member(archive, "manifest.json", encode(manifest))
        for path, entry in files.items():
            if not entry["Static"]:
                raw = path.read_bytes()
                require(len(raw) == entry["Size"] and sha(raw) == entry["SHA256"], "native_input_changed_during_pack")
                add_member(archive, str(path).lstrip("/"), raw)
    payload = out.getvalue()
    require(len(payload) < MAX_FRAME, "native_input_package_too_large")
    return payload


def add_member(archive, name, raw):
    entry = tarfile.TarInfo(name)
    entry.size = len(raw)
    entry.mode = 0o600
    archive.addfile(entry, io.BytesIO(raw))


def stage_inputs(payload, destination, dispatch, *, now_ns=None):
    now_ns = time.time_ns() if now_ns is None else now_ns
    static = json.loads(pinned_read(STATIC / "verified.safe.json", STATIC_STAGE_SHA, MAX_INPUT))
    known = {entry["sha"]: entry["size"] for entry in static["Objects"]}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        members = {}
        for entry in archive:
            require(entry.isfile() and 0 <= entry.size <= MAX_INPUT and entry.name not in members, "package_member_type_or_size")
            require(len(members) < 512, "too_many_package_members")
            members[entry.name] = entry
        manifest = json.load(archive.extractfile(members.pop("manifest.json")))
        require(manifest["Version"] == FORMAT and manifest["DispatchID"] == dispatch, "unexpected_native_dispatch")
        require(0 < manifest["UntilNS"] - now_ns < 120 * 10**9, "native_dispatch_expired")
        journal = Path(manifest["Journal"])
        argv = manifest["Argv"]
        require(journal.parent == BASE and journal.name.startswith("c1-direct-run-"), "journal_scope")
        require(argv[1:3] == ["--action", "run-minio-metadata"], "original_c1_action")
        files = {path_string(name): entry for name, entry in manifest["Files"].items()}
        require(all(path is not None and within(path, INSTANCE_ROOTS) for path in files), "native_input_scope")
        require(files.get(Path(argv[0]), {}).get("SHA256") == PRODUCTION_SHA, "original_c1_elf")
        require(set(members) == {str(path).lstrip("/") for path, entry in files.items() if not entry["Static"]}, "unexpected_package_file_set")
        for path, entry in files.items():
            relative = path.relative_to("/")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            mode = entry["Mode"]
            require(mode & ~0o777 == 0 and mode & 0o022 == 0, "native_input_mode")
            if entry["Static"]:
                require(known.get(entry["SHA256"]) == entry["Size"], "unqualified_static_input")
                raw = pinned_read(STATIC / entry["SHA256"], entry["SHA256"], entry["Size"])
            else:
                member = members[str(relative)]
                raw = archive.extractfile(member).read()
                require(len(raw) == entry["Size"] and sha(raw) == entry["SHA256"], "native_input_digest")
            write_new(target, raw, mode)
        for name in manifest["Directories"]:
            path = path_string(name)
            require(path is not None and path.is_relative_to(journal), "native_output_directory_scope")
            (destination / path.relative_to("/")).mkdir(mode=0o700, parents=True, exist_ok=True)
        return manifest


def encrypt_frame(payload, directory, certificate, signing_key):
    with tempfile.TemporaryDirectory(dir=directory, prefix="p2-frame-") as scratch:
        scratch = Path(scratch)
        recipient = scratch / "recipient.pem"
        write_new(recipient, certificate)
        encrypted = subprocess.run(
            ["openssl", "cms", "-encrypt", "-aes-256-gcm", "-binary", "-outform", "DER", str(recipient)],
            input=payload, capture_output=True, check=True, timeout=8,
        ).stdout
        digest = scratch / "digest.bin"
        write_new(digest, hashlib.sha256(encrypted).digest())
        signature = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(signing_key), "-rawin", "-in", str(digest)],
            capture_output=True, check=True, timeout=5,
        ).stdout
        require(len(signature) == 64 and len(encrypted) < MAX_FRAME, "bad_transport_frame")
        return signature + encrypted


def decrypt_frame(frame, directory, signing_public, certificate, private_key):
    require(65 < len(frame) < MAX_FRAME + 64, "bad_transport_frame")
    signature, encrypted = frame[:64], frame[64:]
    with tempfile.TemporaryDirectory(dir=directory, prefix="p2-verify-") as scratch:
        scratch = Path(scratch)
        key, sig, digest = (scratch / n for n in ("sender.pem", "signature.bin", "digest.bin"))
        write_new(key, signing_public)
        write_new(sig, signature)
        write_new(digest, hashlib.sha256(encrypted).digest())
        subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key), "-rawin", "-in", str(digest), "-sigfile", str(sig)],
            capture_output=True, check=True, timeout=5,
        )
    return subprocess.run(
        ["openssl", "cms", "-decrypt", "-inform", "DER", "-binary", "-recip", str(certificate), "-inkey", str(private_key)],
        input=encrypted, capture_output=True, check=True, timeout=8,
    ).stdout


def selected_container(pod_uid, name, prefix):
    cri = ["crictl", "--runtime-endpoint", "unix:///run/containerd/containerd.sock"]
    status = json.loads(subprocess.check_output(cri + ["ps", "-o", "json"], timeout=5))
    selected = [
        item for item in status["containers"]
        if item["labels"].get("io.kubernetes.pod.uid") == pod_uid
        and item["labels"].get("io.kubernetes.container.name") == name
        and item["id"].startswith(prefix)
        and item["state"] == "CONTAINER_RUNNING"
    ]
    require(len(selected) == 1, "original_node1_container_replaced")
    return json.loads(subprocess.check_output(cri + ["inspect", selected[0]["id"]], timeout=5))


def original_mysql_volume():
    mysql = selected_container("f5c77a56-2ac7-4fd7-8d14-eb87d3c8e52d", "mysql", "8d4c35eeadff")
    volume = Path("/proc") / str(mysql["info"]["pid"]) / "root/var/lib/mysql"
    mounts = [
        m for m in mysql["status"]["mounts"]
        if m["containerPath"] == "/var/lib/mysql" and not m["readonly"]
    ]
    require(len(mounts) == 1, "original_mysql_mount_missing")
    source = Path(mounts[0]["hostPath"])
    require(source.parent.name == "pvc-b27d53bc-3d41-4bfb-9b77-bbf1beb616b6", "original_mysql_volume_replaced")
    require(source.samefile(volume) and not os.statvfs(volume).f_flag & os.ST_RDONLY, "original_mysql_mount_identity")
    return source


def original_broker():
    prefix = Path("/proc/3298146")
    require(os.readlink(prefix / "ns/net") == "net:[4026541577]", "original_node1_broker_replaced")
    raw = (prefix / "root/etc/resolv.conf").read_bytes()
    require(b"nameserver 10.96.0.10" in raw and len(raw) < 1024, "original_node1_resolver")
    dest = Path("/etc/resolv.conf").resolve(strict=True)
    require(
        dest == Path("/run/systemd/resolve/stub-resolv.conf")
        and dest.stat().st_uid == dest.parent.stat().st_uid == 992
        and stat.S_IMODE(dest.stat().st_mode) == 0o644
        and stat.S_IMODE(dest.parent.stat().st_mode) == 0o755,
        "original_systemd_resolver_target",
    )
    return prefix.name, raw, dest


MOUNT_AND_RUN = """
source=$1
inode=$2
resolver=$3
resolv_target=$4
mirror=$5
shift 5
mount --bind "$source" /var/lib/mysql
mount -o remount,bind,ro,nosuid,nodev,noexec /var/lib/mysql
test "$(stat -c '%d:%i' /var/lib/mysql)" = "$inode"
test "$(findmnt -n -o OPTIONS /var/lib/mysql | cut -d, -f1)" = ro
mount --bind "$resolver" "$resolv_target"
mount -o remount,bind,ro "$resolv_target"
cmp -s "$resolver" /etc/resolv.conf
for root in /root/sbk /root/sbk-validation-tls-inspect.7LVU7vpE /run/system-backup; do
    mount --bind "$mirror$root" "$root"
done
export GODEBUG=netdns=go
unset LOCALDOMAIN RES_OPTIONS HOSTALIASES
exec "$@"
"""


def start_native(mirror, manifest, stdout, stderr, created):
    source = original_mysql_volume()
    pid, resolver, resolv_target = original_broker()
    metadata = source.stat()
    inode = f"{metadata.st_dev}:{metadata.st_ino}"
    resolver_file = mirror / "resolver.actual"
    write_new(resolver_file, resolver)
    for target in (Path("/var/lib/mysql"), Path("/root/sbk"), SQL_ROOT, RUNTIME):
        if not target.exists():
            target.mkdir(mode=0o700)
            created.append(target)
        require(
            target.is_dir() and target.resolve(strict=True) == target
            and target.stat().st_uid == 0 and not target.stat().st_mode & 0o022,
            "controlled_private_mount_target",
        )
    require(
        manifest["UntilNS"] - time.time_ns() > 50 * 10**9,
        "remaining_native_consumption_window",
    )
    argv = manifest["Argv"]
    mounted_exe = mirror / Path(argv[0]).relative_to("/")
    pinned_read(mounted_exe, PRODUCTION_SHA, 80 << 20)
    command = [
        "nsenter", "--target", pid, "--net", "unshare", "--mount", "--propagation", "private",
        "--", "sh", "-eu", "-c", MOUNT_AND_RUN, "p2-c1",
        str(source), inode, str(resolver_file), str(resolv_target), str(mirror), *argv,
    ]
    return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)


def transport_names(dispatch):
    require(re.fullmatch(r"p2-c1-20[0-9]{6}-[0-9]{3}", dispatch), "native_dispatch_name")
    return f"{dispatch}.ready", f"{dispatch}.status"


def owner_tmp():
    current = selected_container(OWNER_UID, "installation-owner", OWNER_CID)
    return Path("/proc") / str(current["info"]["pid"]) / "root/tmp"


def kubernetes_owner():
    kubectl = ["kubectl", "--request-timeout=6s", "-n", NAMESPACE]
    p = json.loads(subprocess.check_output(kubectl + ["get", "pod", OWNER_POD, "-o", "json"], timeout=8))
    require(p["metadata"]["uid"] == OWNER_UID and p["spec"]["nodeName"] == "node1", "original_owner_pod_replaced")
    selected = [
        s for s in p["status"]["containerStatuses"]
        if s["name"] == "installation-owner" and s["ready"]
        and s["containerID"].startswith("containerd://" + OWNER_CID)
    ]
    require(len(selected) == 1, "original_owner_container_replaced")
    return kubectl + ["exec", "-i", OWNER_POD, "-c", "installation-owner", "--"]


def publish_status(path, data, owner):
    fd, temporary = tempfile.mkstemp(prefix=".p2-c1-status-", dir=path.parent)
    try:
        os.fchown(fd, owner.st_uid, owner.st_gid)
        with os.fdopen(fd, "wb") as out:
            out.write(encode(data))
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def receive_once(dispatch, public, keys, record, wait_seconds):
    require(os.geteuid() == 0 and record.parent == Path("/root"), "native_receiver_root_scope")
    ready, status = transport_names(dispatch)
    owner = owner_tmp()
    frame = owner / ready
    state_file = owner / status
    require(not state_file.exists(), "native_operation_already_reported")
    deadline = time.monotonic() + wait_seconds
    while not frame.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    require(owner_tmp() == owner, "original_owner_container_replaced")
    st = frame.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_size < MAX_FRAME + 64 and stat.S_IMODE(st.st_mode) == 0o600, "native_frame_mode")
    created = []
    body = frame.read_bytes()
    state = {"DispatchID": dispatch, "FrameSHA256": sha(body), "Phase": "verify", "Done": False}
    process = None
    try:
        payload = decrypt_frame(body, keys, public, keys / "receiver-cert.pem", keys / "receiver-key.pem")
        record.mkdir(mode=0o700)
        mirror = record / "mirror"
        mirror.mkdir(mode=0o700)
        manifest = stage_inputs(payload, mirror, dispatch)
        journal_path = Path(manifest["Journal"])
        require(journal_path.name == "c1-direct-run-" + dispatch.removeprefix("p2-c1-"), "native_journal_dispatch_mismatch")
        state["Phase"] = "starting"
        publish_status(state_file, state, st)
        journal = mirror / journal_path.relative_to("/")
        stdout = record / "native.stdout"
        stderr = record / "native.stderr"
        write_new(record / "dispatch.intent.json", encode({"DispatchID": dispatch, "FrameSHA256": state["FrameSHA256"]}))
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = start_native(mirror, manifest, out, err, created)
            state["Phase"] = "native_started"
            publish_status(state_file, state, st)
            head = journal / "head1/head1.result.json"
            while process.poll() is None:
                if head.is_file() and "Head1" not in state:
                    raw = head.read_bytes()
                    try:
                        result = json.loads(raw)
                    except ValueError:
                        result = {}
                    if result.get("Authority", {}).get("HeadRevision") == 1:
                        state["Head1"] = base64.b64encode(raw).decode()
                        publish_status(state_file, state, st)
                time.sleep(0.5)
        original_mysql_volume()
        state.update(
            Phase="native_returned", Done=True, ExitCode=process.returncode,
            Stdout=base64.b64encode(stdout.read_bytes()).decode(),
        )
        write_new(record / "dispatch.result.json", encode(state))
        publish_status(state_file, state, st)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        if process is not None:
            process.wait()
        failure = encode({
            "Stage": "node1_c1_bridge_result_unconfirmed" if process else "node1_c1_bridge_preflight",
            "Detail": str(exc) if isinstance(exc, ValueError) else type(exc).__name__,
        })
        state.update(Phase="bridge_failed", Done=True, ExitCode=1, Stdout=base64.b64encode(failure).decode())
        publish_status(state_file, state, st)
        raise
    finally:
        for path in reversed(created):
            path.rmdir()
        frame.unlink(missing_ok=True)


def send_and_wait(argv, journal, static, dispatch, until_ns, keys, recipient, timeout):
    ready, status = transport_names(dispatch)
    package = pack_inputs(argv, journal, static, dispatch, until_ns)
    frame = encrypt_frame(package, keys, recipient, keys / "sender-key.pem")
    frame_sha = sha(frame)
    actor = kubernetes_owner()
    prepare = """
    umask 077
    test ! -e "$1"
    f=$(mktemp /tmp/.p2-c1-frame.XXXXXXXX)
    trap 'rm -f -- "$f"' EXIT
    cat > "$f"
    test "$(sha256sum "$f" | cut -d ' ' -f 1)" = "$2"
    ln -- "$f" "$1"
    """
    subprocess.run(
        actor + ["sh", "-ec", prepare, "p2-c1", "/tmp/" + ready, frame_sha],
        input=frame, capture_output=True, check=True, timeout=8,
    )
    deadline = time.monotonic() + timeout
    original_head = journal / "head1/head1.result.json"
    while time.monotonic() < deadline:
        status_process = subprocess.run(actor + ["cat", "/tmp/" + status], capture_output=True, timeout=8)
        if status_process.returncode == 0:
            require(len(status_process.stdout) < MAX_INPUT, "native_status_limit")
            state = json.loads(status_process.stdout)
            require(state["DispatchID"] == dispatch and state["FrameSHA256"] == frame_sha, "native_status_binding")
            if "Head1" in state and not original_head.exists():
                write_new(original_head, base64.b64decode(state["Head1"], validate=True))
            if state["Done"]:
                stdout = base64.b64decode(state["Stdout"], validate=True)
                subprocess.run(actor + ["rm", "-f", "--", "/tmp/" + status], capture_output=True, timeout=8)
                return subprocess.CompletedProcess(argv, state["ExitCode"], stdout, b"")
        time.sleep(0.75)
    raise TimeoutError("native_dispatch_result_unconfirmed")


def main():
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="action", required=True)
    inspect = subcommands.add_parser("inspect")
    inspect.add_argument("--sent", type=Path, required=True)
    inspect.add_argument("--static-receipt", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == "inspect":
        argv = json.loads(args.sent.read_bytes())["Argv"]
        static = json.loads(pinned_read(args.static_receipt, STATIC_STAGE_SHA, MAX_INPUT))
        files, directories = input_scope(argv, args.sent.parent, static["Objects"])
        sizes = [v["Size"] for v in files.values() if not v["Static"]]
        print(json.dumps({
            "Result": "p2-c1-node1-stage-scope",
            "NativeInputs": len(files),
            "Prepositioned": len(files) - len(sizes),
            "StreamBytes": sum(sizes),
            "OutputDirectories": len(directories),
        }, sort_keys=True))


if __name__ == "__main__":
    main()
