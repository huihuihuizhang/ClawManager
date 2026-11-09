"""Optional tracefs evidence for the disposable Linux 6.8 ext4 canary."""

from collections import Counter
from contextlib import ExitStack, contextmanager
import errno
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import struct
import sys
import time
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def super_device_offset(btf):
    """Read super_block.s_dev from the running kernel's little-endian BTF."""
    magic, version, flags, header, type_off, type_len, str_off, str_len = struct.unpack_from(
        "<HBB5I", btf
    )
    require(magic == 0xEB9F and version == 1 and flags == 0 and header >= 24,
            "unsupported vmlinux BTF header")
    require(type_off + type_len <= str_off and header + str_off + str_len <= len(btf),
            "invalid vmlinux BTF sections")
    types = btf[header + type_off:header + type_off + type_len]
    names = btf[header + str_off:header + str_off + str_len]

    def named(index, name):
        return names[index:index + len(name) + 1] == name + b"\0"

    offsets = []
    pos = 0
    while pos < len(types):
        name, info, size = struct.unpack_from("<III", types, pos)
        kind, count = (info >> 24) & 31, info & 0xFFFF
        require(1 <= kind <= 19, "unknown vmlinux BTF type")
        pos += 12
        # Type header extensions and the element sizes for variable records.
        payload = {1: 4, 3: 12, 14: 4, 17: 4}.get(kind, 0)
        payload += count * {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}.get(kind, 0)
        require(pos + payload <= len(types), "truncated vmlinux BTF type")
        if kind == 4 and named(name, b"super_block"):
            for member in range(count):
                field, _, bits = struct.unpack_from("<III", types, pos + 12 * member)
                if named(field, b"s_dev"):
                    require(bits % 8 == 0 and bits // 8 + 4 <= size,
                            "unsupported super_block.s_dev layout")
                    offsets.append(bits // 8)
        pos += payload
    require(len(offsets) == 1, "super_block.s_dev BTF field missing or ambiguous")
    return offsets[0]


TRACE_ROW = re.compile(
    r"^\s*.+-(\d+)\s+\[\d+\].*?\s(\d+)\.(\d{1,9}):\s+"
    r"(\w+):\s+.*\b(dev|rc)=(-?\d+)\s*$"
)
LOSS_FIELDS = ("overrun", "commit overrun", "dropped events")


def trace_calls(trace, probes, profile, cpu_stats):
    """Pair calls by operation and TID and reject incomplete captures."""
    totals = {}
    for line in profile.splitlines():
        fields = line.split()
        if fields and fields[0] in probes:
            name, hits, missed = fields
            require(name not in totals and int(missed) == 0, "probe misses or duplicate counters")
            totals[name] = int(hits)
    require(totals.keys() == probes.keys(), "probe counters incomplete")
    require(cpu_stats, "trace buffer statistics unavailable")
    for stats in cpu_stats:
        counters = dict(re.findall(r"^\s*(overrun|commit overrun|dropped events):\s*(\d+)\s*$",
                                   stats, re.MULTILINE))
        require(all(counters.get(field) == "0" for field in LOSS_FIELDS), "trace buffer loss or unknown")

    calls, pending, observed = [], {}, Counter()
    for line in trace.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        row = TRACE_ROW.fullmatch(line)
        require(row is not None, "unrecognized trace row")
        tid, seconds, fraction, event, field, value = row.groups()
        require(event in probes, "unexpected event in private trace instance")
        operation, expected_field = probes[event]
        require(field == expected_field, "trace payload does not match event")
        observed[event] += 1
        tid, value = int(tid), int(value)
        ns = int(seconds) * 1_000_000_000 + int(fraction.ljust(9, "0"))
        key = operation, tid
        if field == "dev":
            require(key not in pending, "overlapping probe entry for one thread")
            pending[key] = value, ns
        else:
            require(key in pending, "probe return without entry")
            device, start = pending.pop(key)
            require(start <= ns, "probe return precedes entry")
            calls.append(dict(operation=operation, tid=tid, device=device,
                              start_ns=start, end_ns=ns, rc=value))
    require(not pending and all(observed[event] == hits for event, hits in totals.items()),
            "unpaired or missing trace records")
    return calls


def cycle_status(calls, device, owner_tid):
    target = [call for call in calls if call["device"] == device]
    own_freeze = [c for c in target if c["operation"] == "freeze" and c["tid"] == owner_tid and c["rc"] == 0]
    own_thaw = [c for c in target if c["operation"] == "thaw" and c["tid"] == owner_tid]
    if len(target) != 3 or len(own_freeze) != 1 or len(own_thaw) != 1 or own_thaw[0]["rc"] != -errno.EINVAL:
        return "UNVERIFIED", target
    freeze, thaw = own_freeze[0], own_thaw[0]
    if any(c["operation"] == "thaw" and c["tid"] != owner_tid and c["rc"] == 0 and
           freeze["end_ns"] < c["start_ns"] <= c["end_ns"] < thaw["start_ns"] for c in target):
        return "FOREIGN_THAW_OBSERVED", target
    return "UNVERIFIED", target


def kernel_device(dev):
    # In-kernel dev_t encoding, distinct from libc's st_dev encoding.
    return (os.major(dev) << 20) | os.minor(dev)


def write_tracefs(path, command):
    # tracefs accepts one command per write. Python append mode seeks to EOF,
    # which kprobe_events rejects. O_TRUNC would remove existing host probes.
    payload = (command + "\n").encode("ascii")
    try:
        fd = os.open(path, os.O_WRONLY)
        try:
            require(os.write(fd, payload) == len(payload), f"short tracefs write to {path}: {command!r}")
        finally:
            os.close(fd)
    except OSError as exc:
        raise RuntimeError(f"tracefs write to {path}: {command!r}: {exc}") from exc


@contextmanager
def capture_calls(announce):
    """Enable only our four probes in a fresh tracefs instance."""
    root = Path("/sys/kernel/tracing")
    offset = super_device_offset(Path("/sys/kernel/btf/vmlinux").read_bytes())
    group = "sbk_" + uuid.uuid4().hex
    instance = root / "instances" / group
    control = root / "kprobe_events"
    probes = {}

    def probe(command):
        try:
            write_tracefs(control, command)
        except RuntimeError as exc:
            try:
                lines = (root / "error_log").read_text(errors="replace").splitlines()
            except OSError:
                raise exc
            for i in range(len(lines) - 1, 0, -1):
                if lines[i].strip() == "Command: " + command:
                    raise RuntimeError(f"{exc} ({lines[i - 1].strip()})") from exc
            raise

    announce(group)
    with ExitStack() as cleanup:
        instance.mkdir()
        cleanup.callback(instance.rmdir)
        tracing = instance / "tracing_on"
        write_tracefs(tracing, "0")
        write_tracefs(instance / "buffer_size_kb", "32")
        clock = instance / "trace_clock"
        write_tracefs(clock, "mono")
        require("[mono]" in clock.read_text(), "monotonic trace clock unavailable")
        # thaw_super_locked also covers the VFS emergency thaw path.
        for op, symbol in (("freeze", "freeze_super"), ("thaw", "thaw_super_locked")):
            for field, kind, arg in (("dev", "p", f"dev=+{offset}(%di):u32"),
                                     ("rc", "r64", "rc=$retval:s32")):
                event = f"{group}_{op}_{field}"
                path = f"{group}/{event}"
                probe(f"{kind}:{path} {symbol} {arg}")
                cleanup.callback(probe, f"-:{path}")
                probes[event] = op, field

        enable = instance / "events" / group / "enable"
        cleanup.callback(write_tracefs, enable, "0")
        cleanup.callback(write_tracefs, tracing, "0")
        write_tracefs(enable, "1")
        write_tracefs(tracing, "1")

        def collect():
            write_tracefs(tracing, "0")
            write_tracefs(enable, "0")
            return trace_calls((instance / "trace").read_text(), probes,
                               (root / "kprobe_profile").read_text(),
                               [p.read_text() for p in instance.glob("per_cpu/cpu*/stats")])

        yield collect, group


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def trace_freeze(directory, exercise, emit):
    """Verify an independently injected thaw of the pinned disposable loop."""
    dev = os.fstat(directory).st_dev
    with capture_calls(lambda group: emit(phase="trace_session", group=group)) as (collect, _):
        injected = exercise()
        status, target = cycle_status(collect(), kernel_device(dev), os.getpid())
        foreign = [c for c in target if c["operation"] == "thaw" and c["rc"] == 0]
        require(status == "FOREIGN_THAW_OBSERVED" and len(foreign) == 1 and foreign[0]["tid"] == injected,
                "independent early thaw was not proven by the trace")
    emit(phase="freeze_trace_canary", status=status, boot_id=boot_id(),
         device=f"{os.major(dev)}:{os.minor(dev)}", clock="mono", calls=target)


def device_identity(handle):
    require(re.fullmatch(r"pvc-[0-9a-f-]{36}", handle), "invalid disposable Longhorn handle")
    device = (Path("/dev/longhorn") / handle).stat()
    require(stat.S_ISBLK(device.st_mode), "Longhorn handle is not a block device")
    major_minor = f"{os.major(device.st_rdev)}:{os.minor(device.st_rdev)}"
    diskseq = int((Path("/sys/dev/block") / major_minor / "diskseq").read_text())
    require(diskseq > 0, "disk sequence is unavailable")
    return kernel_device(device.st_rdev), diskseq


def storage_window(calls, devices, marks, owners):
    target = [c for c in calls if c["device"] in devices]
    start, ready, release = marks
    # trace's text timestamps may be rounded to microseconds.
    margin = 1_000
    for device in devices:
        freezes = [c for c in target if c["device"] == device and c["operation"] == "freeze" and c["rc"] == 0]
        thaws = [c for c in target if c["device"] == device and c["operation"] == "thaw" and c["rc"] == 0]
        if any(f["end_ns"] + margin < t["start_ns"] and t["end_ns"] + margin < release
               for f in freezes for t in thaws):
            return "FAIL_EARLY_THAW", target
    if len(target) != 4 or not 0 < start < ready <= release:
        return "UNVERIFIED", target
    for device in devices:
        freeze = [c for c in target if c["device"] == device and c["operation"] == "freeze" and c["rc"] == 0]
        thaw = [c for c in target if c["device"] == device and c["operation"] == "thaw" and c["rc"] == 0]
        if len(freeze) != 1 or len(thaw) != 1 or owners.get(device) != (freeze[0]["tid"], thaw[0]["tid"]) or not (
            freeze[0]["end_ns"] + margin < start and release + margin < thaw[0]["start_ns"]
        ):
            return "UNVERIFIED", target
    return "WINDOW_OBSERVED", target


def longhorn_probe(run_dir, rwo, rwx):
    require(os.geteuid() == 0 and platform.system() == "Linux" and platform.machine() == "x86_64" and
            platform.release().startswith("6.8."), "root Linux 6.8.x x86_64 required")
    root = Path(run_dir)
    require(re.fullmatch(r"/var/tmp/sbk-storage-probe-[0-9a-f]{32}", run_dir) and root.resolve() == root,
            "invalid disposable run directory")
    info = root.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            "run directory must be root:0700")
    calibration = [json.loads(row) for row in (root / "trace-calibration.jsonl").read_text().splitlines()]
    current_boot = boot_id()
    require(any(r.get("phase") == "freeze_trace_canary" and r.get("status") == "FOREIGN_THAW_OBSERVED" and
                r.get("boot_id") == current_boot for r in calibration) and
            any(r.get("phase") == "cleanup" and r.get("complete") is True and r.get("test_completed") is True
                for r in calibration), "same-boot early-thaw calibration and cleanup required")
    handles = (rwo, rwx)
    identities = tuple(device_identity(handle) for handle in handles)
    devices = {d for d, _ in identities}
    require(len(devices) == 2, "two distinct disposable devices required")
    state = root / "trace"
    state.mkdir(mode=0o700)

    def announce(group):
        print(json.dumps(dict(status="TRACE_SESSION", group=group, boot_id=current_boot)), flush=True)

    with capture_calls(announce) as (collect, group):
        print(json.dumps(dict(status="TRACE_ARMED", group=group, boot_id=current_boot)), flush=True)
        (state / "armed").touch(exist_ok=False)
        deadline = time.monotonic() + 90
        while not (state / "stop").exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        calls = collect()
        require((state / "stop").exists(), "collector expired")
    require(boot_id() == current_boot and tuple(device_identity(h) for h in handles) == identities,
            "boot or device identity changed")

    def marker(name):
        path = state / name
        return int(path.read_text()) if path.is_file() else 0

    owners = {}
    watchdog_used = False
    for name, (device, _) in zip(("rwo", "rwx"), identities):
        lease = root / name
        watchdog_used |= (lease / "timed-out").is_file()
        exit_code = lease / "exit-code"
        successful = exit_code.is_file() and exit_code.read_text().strip() == "0"
        invalid = any((lease / bad).exists() for bad in ("unknown", "timed-out", "no-thaw-dispatched"))
        if successful and not invalid and (lease / "thaw-acknowledged").is_file():
            owners[device] = tuple(int((lease / f"{operation}.pid").read_text())
                                   for operation in ("freeze", "unfreeze"))
    marks = {name: marker(name) for name in ("start", "ready", "release")}
    status, target = storage_window(calls, devices, tuple(marks.values()), owners)
    if status == "UNVERIFIED" and watchdog_used:
        status = "FAIL_WATCHDOG"
    print(json.dumps(dict(status=status, boot_id=current_boot, clock="mono", devices=identities,
                          calls=target, marks_ns=marks, lease_tids=owners, trace_cleanup_complete=True)), flush=True)
    return 0 if status == "WINDOW_OBSERVED" else 4 if status.startswith("FAIL_") else 3


if __name__ == "__main__":
    def interrupted(signum, _frame):
        raise RuntimeError(f"collector interrupted by signal {signum}")

    try:
        require(len(sys.argv) == 5 and sys.argv[1] == "--longhorn-probe",
                "usage: --longhorn-probe RUN_DIR RWO_HANDLE RWX_HANDLE")
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, interrupted)
        raise SystemExit(longhorn_probe(*sys.argv[2:]))
    except Exception as exc:
        print(json.dumps(dict(status="UNVERIFIED", reason=str(exc))), flush=True)
        raise SystemExit(3)
