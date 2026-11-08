"""Root-run Linux 6.8 x86_64 canary; creates its OWN image/loop/mount only.

No target arguments are accepted. No business volume or existing mount is
selected. Does not install packages. Run with python3 -I -B after review.
"""
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def emit(**record):
    print(json.dumps(record, sort_keys=True), flush=True)


def run(*args):
    result = subprocess.run(args, check=True, text=True, capture_output=True, timeout=30)
    return result.stdout.strip()


libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                     ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]


def checked(rc, operation):
    if rc < 0:
        code = ctypes.get_errno()
        raise OSError(code, operation + ": " + os.strerror(code))
    return rc


def reconfigure(fd, mode):
    # Linux x86_64: fspick=433; fsconfig=431. Same calls as candidate owner.
    cfg = checked(libc.syscall(433, fd, ctypes.c_char_p(b""), 0x9), "fspick")
    try:
        checked(libc.syscall(431, int(cfg), 0, ctypes.c_char_p(mode.encode()),
                             ctypes.c_void_p(), 0), "FSCONFIG_SET_FLAG")
        ctypes.set_errno(0)
        rc = libc.syscall(431, int(cfg), 7, ctypes.c_void_p(), ctypes.c_void_p(), 0)
        return 0 if rc == 0 else ctypes.get_errno()
    finally:
        os.close(cfg)


def mount_state(target, loop):
    rows = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
    matches = [r for r in rows if len(r) >= 10 and r[4] == str(target)]
    require(len(matches) == 1, "owned mount missing or ambiguous")
    row = matches[0]
    sep = row.index("-", 6)
    block = os.stat(loop)
    require(stat.S_ISBLK(block.st_mode) and row[sep + 1] == "ext4" and row[3] == "/" and
            os.stat(target).st_dev == block.st_rdev and
            row[2] == str(os.major(block.st_rdev)) + ":" + str(os.minor(block.st_rdev)),
            "owned loop/mount identity mismatch")
    mode = row[sep + 3].split(",")[0]
    require(mode in ("ro", "rw"), "unrecognized superblock mode")
    return mode


def same_loop(loop, image):
    if not re.fullmatch(r"/dev/loop[0-9]+", loop):
        return False
    # Match the allocated device's current kernel backing file before cleanup.
    backing = Path("/sys/class/block") / Path(loop).name / "loop/backing_file"
    return os.path.realpath(backing.read_text().strip()) == str(image)


def freeze_exercise(directory, writer, mapping):
    """Test ordinary open writers, shared faults and both sync forms frozen."""
    actors = {}
    frozen = False
    cancel_read, cancel_write = os.pipe()
    watchdog = os.fork()
    if watchdog == 0:
        try:
            os.close(cancel_write)
            watchdog_triggered = False
            # Independent thaw helper, on THIS disposable filesystem only.
            # A lost parent closes its cancel pipe; EOF also triggers own-FD thaw.
            while True:
                ready = select.select([cancel_read], [], [], 20)[0]
                message = os.read(cancel_read, 1) if ready else None
                if message == b"C":
                    break
                try:
                    fcntl.ioctl(directory, 0xC0045878, 0)
                    watchdog_triggered = True
                    emit(phase="watchdog_thaw", test_invalid=True)
                    break
                except OSError as exc:
                    if exc.errno == errno.EINVAL and message == b"":
                        # All parent FDs are closed and this filesystem is not
                        # frozen; no orphan helper needs to retain its mount.
                        break
                    if exc.errno != errno.EINVAL:
                        emit(phase="watchdog_thaw_unconfirmed", errno=exc.errno, test_invalid=True)
                    if message == b"":
                        time.sleep(0.05)
                    # An in-progress freeze may not yet be thawable. Retain the
                    # own-FD watchdog until it thaws or the parent cancels it.
            os._exit(4 if watchdog_triggered else 0)
        finally:
            os._exit(5)
    os.close(cancel_read)
    try:
        for name in ("direct_writer", "mmap_writer", "syncfs", "systemwide_sync"):
            go_read, go_write = os.pipe()
            result_read, result_write = os.pipe()
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(go_write)
                    os.close(result_read)
                    os.close(cancel_write)
                    try:
                        require(os.read(go_read, 1) == b"G", "actor start lost")
                        os.write(result_write, b"S")
                        started = time.monotonic()
                        if name == "direct_writer":
                            require(os.pwrite(writer, b"direct", 0) == 6, "short pwrite")
                        elif name == "mmap_writer":
                            ctypes.memmove(mapping + 64, b"mapped", 6)
                        elif name == "syncfs":
                            checked(libc.syncfs(directory), "frozen syncfs")
                        else:
                            os.sync()  # Linux sync(2), same systemwide operation.
                        result = {"ok": True, "seconds": time.monotonic() - started}
                    except Exception as exc:
                        result = {"ok": False, "failure": str(exc)}
                    os.write(result_write, b"D" + json.dumps(result).encode())
                    os._exit(0)
                finally:
                    os._exit(6)
            os.close(go_read)
            os.close(result_write)
            actors[name] = {"pid": pid, "go": go_write, "result": result_read, "completion": None}

        # Open FD and MAP_SHARED are already retained. No repeated FIFREEZE
        # is used to query state. This successful ioctl is the freeze event.
        fcntl.ioctl(directory, 0xC0045877, 0)
        frozen = True
        emit(phase="freeze_acquired", writable_fd_retained=True, shared_mapping_retained=True)
        for actor in actors.values():
            os.write(actor["go"], b"G")
        for name, actor in actors.items():
            require(select.select([actor["result"]], [], [], 1)[0], name + " did not start")
            require(os.read(actor["result"], 1) == b"S", name + " lost start acknowledgement")
        end = time.monotonic() + 3
        while time.monotonic() < end:
            pending = [a["result"] for a in actors.values() if a["completion"] is None]
            if not pending:
                break
            ready = select.select(pending, [], [], max(0, end - time.monotonic()))[0]
            for name, actor in actors.items():
                if actor["result"] in ready:
                    data = os.read(actor["result"], 4096)
                    require(data.startswith(b"D"), name + " exited without completion")
                    actor["completion"] = json.loads(data[1:])
        during = {name: actor["completion"] for name, actor in actors.items()}
        emit(phase="while_frozen", observation_seconds=3, completions=during,
             systemwide_sync_scope="all host superblocks; not limited by mount namespace")
    finally:
        thaw_error = None
        thaw_confirmed = not frozen
        if frozen:
            try:
                fcntl.ioctl(directory, 0xC0045878, 0)
                thaw_confirmed = True
                emit(phase="thaw_acknowledged")
            except OSError as exc:
                thaw_error = exc
                # EINVAL on this already-frozen exact ext4 FD means a helper
                # thawed it first. Timing is invalid, but cleanup can proceed.
                thaw_confirmed = exc.errno == errno.EINVAL
                emit(phase="parent_thaw_failed", errno=exc.errno, test_invalid=True)
        if thaw_confirmed:
            os.write(cancel_write, b"C")
        os.close(cancel_write)
        if thaw_confirmed:
            _, watchdog_status = os.waitpid(watchdog, 0)
        else:
            # EOF asks the helper to continue its own-FD thaw attempts. Do not
            # cancel a recovery obligation whose result remains unknown.
            _, watchdog_status = os.waitpid(watchdog, os.WNOHANG)
            watchdog_status = -1
            emit(phase="watchdog_retained", pid=watchdog, test_invalid=True)
        # Writers get time to finish after thaw; terminate only canary actors.
        for name, actor in actors.items():
            if actor["completion"] is None:
                ready = select.select([actor["result"]], [], [], 5)[0]
                if ready:
                    data = os.read(actor["result"], 4096)
                    if data.startswith(b"D"):
                        actor["completion"] = json.loads(data[1:])
            waited, status = os.waitpid(actor["pid"], os.WNOHANG)
            reap_until = time.monotonic() + 1
            while waited == 0 and time.monotonic() < reap_until:
                time.sleep(0.01)
                waited, status = os.waitpid(actor["pid"], os.WNOHANG)
            if waited == 0:
                os.kill(actor["pid"], signal.SIGKILL)
                kill_until = time.monotonic() + 1
                while waited == 0 and time.monotonic() < kill_until:
                    time.sleep(0.01)
                    waited, status = os.waitpid(actor["pid"], os.WNOHANG)
                if waited == 0:
                    status = -1
                    emit(phase="actor_cleanup_unconfirmed", actor=name, pid=actor["pid"])
            actor["exit_status"] = status
            os.close(actor["go"])
            os.close(actor["result"])

    require(thaw_error is None, "parent thaw did not complete normally")
    require(watchdog_status == 0, "watchdog thawed the filesystem; timing result invalid")
    require(during["direct_writer"] is None and during["mmap_writer"] is None,
            "a writer completed while frozen")
    require(all(a["completion"] and a["completion"].get("ok") and a["exit_status"] == 0 for a in actors.values()),
            "an actor failed to complete after thaw")
    os.fsync(writer)
    require(os.pread(writer, 6, 0) == b"direct" and os.pread(writer, 6, 64) == b"mapped",
            "post-thaw content readback failed")
    emit(phase="freeze_native_result", writers_blocked_and_resumed=True, content_readback=True,
         syncfs_completed_while_frozen=during["syncfs"] is not None,
         systemwide_sync_completed_while_frozen=during["systemwide_sync"] is not None,
         snapshot_deadlock_canary_passed=bool(during["systemwide_sync"] and during["systemwide_sync"].get("ok")))
    require(all(during[name] and during[name].get("ok") for name in ("syncfs", "systemwide_sync")),
            "sync did not complete within the frozen observation window")


def exercise(target, loop):
    directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    filename = target / "writer.bin"
    writer = -1
    mapping = None
    try:
        writer = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        os.ftruncate(writer, 4096)
        os.pwrite(writer, b"seed", 0)
        os.fsync(writer)
        os.close(writer)
        writer = -1

        def attempt(name, expected):
            checked(libc.syncfs(directory), "syncfs")
            code = reconfigure(directory, "ro")
            mode = mount_state(target, loop)
            emit(phase=name, errno=code, errno_name=errno.errorcode.get(code, "OK"),
                 superblock_mode=mode, expected_errno=expected)
            require(code == expected and mode == ("ro" if expected == 0 else "rw"),
                    name + ": unexpected native result")

        attempt("no_open_writer", 0)
        try:
            unexpected = os.open(filename, os.O_RDWR | os.O_CLOEXEC)
        except OSError as exc:
            require(exc.errno == errno.EROFS, "RO write denial returned unexpected errno")
        else:
            os.close(unexpected)
            raise RuntimeError("RO superblock accepted writable open")
        require(reconfigure(directory, "rw") == 0 and mount_state(target, loop) == "rw",
                "baseline RW restoration failed")

        writer = os.open(filename, os.O_RDWR | os.O_CLOEXEC)
        attempt("idle_open_writable_fd_after_syncfs", errno.EBUSY)
        os.pwrite(writer, b"fd-alive", 0)

        # Raw mmap avoids Python mmap's duplicate FD. This tests a VMA's own
        # file reference after the original writable FD has actually closed.
        mapping = libc.mmap(None, 4096, 3, 1, writer, 0)  # PROT_RW, MAP_SHARED
        require(mapping != ctypes.c_void_p(-1).value, "MAP_SHARED failed")
        ctypes.memmove(mapping, b"map-alive", 9)
        attempt("writable_fd_and_shared_mapping_after_syncfs", errno.EBUSY)
        freeze_exercise(directory, writer, mapping)
        os.close(writer)
        writer = -1
        attempt("shared_mapping_after_original_fd_closed", errno.EBUSY)
        checked(libc.munmap(mapping, 4096), "munmap")
        mapping = None

        attempt("all_writable_references_closed", 0)
        require(reconfigure(directory, "rw") == 0 and mount_state(target, loop) == "rw",
                "final RW restoration failed")
        writer = os.open(filename, os.O_RDWR | os.O_CLOEXEC)
        os.pwrite(writer, b"restored", 0)
        os.fsync(writer)
        require(os.pread(writer, 8, 0) == b"restored", "final RW content readback failed")
        emit(phase="native_result", open_fd_and_mapping_block_normal_ro=True,
             writable_references_closed_allows_ro=True, rw_write_readback=True)
    finally:
        if mapping is not None:
            checked(libc.munmap(mapping, 4096), "cleanup munmap")
        if writer >= 0:
            os.close(writer)
        os.close(directory)


def main():
    require(len(sys.argv) == 1, "no target/device/mount arguments are accepted")
    require(os.geteuid() == 0 and platform.system() == "Linux" and
            platform.machine() == "x86_64" and platform.release().startswith("6.8."),
            "root Linux 6.8.x x86_64 required")
    for binary in ("mkfs.ext4", "losetup", "mount", "umount"):
        require(shutil.which(binary) is not None, binary + " must already be installed")
    before = os.readlink("/proc/self/ns/mnt")
    checked(libc.unshare(0x00020000), "unshare(CLONE_NEWNS)")
    require(os.readlink("/proc/self/ns/mnt") != before, "mount namespace did not change")
    run("mount", "--make-rprivate", "/")
    base = Path(tempfile.mkdtemp(prefix="clawmanager-ext4-canary-", dir="/var/tmp"))
    require(base.parent == Path("/var/tmp") and base.name.startswith("clawmanager-ext4-canary-") and
            base.lstat().st_uid == 0 and stat.S_IMODE(base.lstat().st_mode) == 0o700,
            "private canary directory invalid")
    image, target = base / "owned.img", base / "mount"
    loop = ""
    mounted = False
    complete = False
    emit(phase="created", directory=str(base), kernel=platform.release(),
         mount_namespace=os.readlink("/proc/self/ns/mnt"))
    try:
        fd = os.open(image, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.ftruncate(fd, 128 << 20)
        finally:
            os.close(fd)
        # Format the self-created regular file BEFORE allocating a loop device.
        # No mkfs invocation ever receives a block-device path.
        run("mkfs.ext4", "-q", "-F", str(image))
        loop = run("losetup", "--find", "--show", "--nooverlap", str(image))
        require(same_loop(loop, image), "allocated loop backing mismatch")
        target.mkdir(mode=0o700)
        run("mount", "-t", "ext4", "-o", "nodev,nosuid,noexec", "--", loop, str(target))
        mounted = True
        require(mount_state(target, loop) == "rw", "fresh ext4 is not RW")
        emit(phase="mounted_owned_loop", loop=loop, image=str(image), mount=str(target))
        exercise(target, loop)
        complete = True
    finally:
        # No forced/lazy unmount and no recursive deletion. A failed identity
        # or cleanup check leaves exact owned paths in the log for Root review.
        try:
            if mounted:
                mount_state(target, loop)
                require(same_loop(loop, image), "cleanup loop ownership mismatch")
                run("umount", "--", str(target))
                mounted = False
            if loop:
                require(same_loop(loop, image), "cleanup detach ownership mismatch")
                run("losetup", "--detach", loop)
                loop = ""
            if target.exists():
                target.rmdir()
            if image.exists():
                image.unlink()
            base.rmdir()
            emit(phase="cleanup", complete=True, test_completed=complete)
        except Exception as exc:
            emit(phase="cleanup", complete=False, directory=str(base), loop=loop,
                 mounted=mounted, failure=str(exc))
            raise
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        emit(phase="failure", failure=str(exc), tested=False)
        raise SystemExit(3)
