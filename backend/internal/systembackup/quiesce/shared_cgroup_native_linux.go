//go:build linux

package quiesce

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// This private primitive is NOT a reservation, permission, writer census, IO
// flush, or consistent backup proof. Its owner must first authenticate the
// original shared-agent reservation/journal and CRI identity, durably record a
// recovery obligation OUTSIDE the target, and maintain the original SQL/object
// gates. NodeObserver remains read-only. Only a reviewed lifecycle owner may
// use these methods; no request DTO can manufacture that owner.
//
// Linux semantics: https://docs.kernel.org/admin-guide/cgroup-v2.html
// cgroup.freeze is asynchronous; only cgroup.events frozen=1 confirms completion.
// Processes can still be killed or migrated. The owner must independently
// revalidate membership, volumes, other writers, and the source window.
type sharedCgroupPin struct {
	Path, BootID  string
	Device, Inode uint64
	Root          observedProcess
}

type sharedCgroupHandle struct {
	fd   int
	proc string
	pin  sharedCgroupPin
	// Set BEFORE attempting a write: even a failed write has an unknown result.
	owned bool
}

func sharedCgroupBoot(ctx context.Context, proc string) (string, error) {
	raw, err := observationRead(ctx, filepath.Join(proc, "sys/kernel/random/boot_id"), 256)
	value := strings.TrimSpace(string(raw))
	if err != nil || value == "" {
		return "", observationFailure("shared_cgroup_boot")
	}
	return value, nil
}

// mount is the reviewed, writable native cgroup-v2 mount, NOT a caller-selected
// cgroup directory. root is the actual CRI container process, using its exact
// container cgroup (not observationPodCgroup's broader Pod scope).
// Reopening is allowed only with an original authenticated, persisted pin.
func openSharedCgroup(ctx context.Context, mount, proc string, root observedProcess, original *sharedCgroupPin) (*sharedCgroupHandle, error) {
	bad := func() (*sharedCgroupHandle, error) { return nil, observationFailure("shared_cgroup_identity") }
	if ctx == nil || ctx.Err() != nil || !absoluteObservationPath(mount) || !absoluteObservationPath(proc) || !absoluteObservationPath(root.Cgroup) || root.Cgroup == "/" || root.PID <= 1 || root.Start == "" {
		return bad()
	}
	self, err := observationProcess(ctx, filepath.Join(proc, strconv.Itoa(os.Getpid())))
	if err != nil || withinObservation(self.Cgroup, root.Cgroup) {
		return bad()
	}
	actual, err := observationProcess(ctx, filepath.Join(proc, strconv.Itoa(root.PID)))
	if original == nil && (err != nil || !reflect.DeepEqual(actual, root)) {
		return bad()
	}
	boot, err := sharedCgroupBoot(ctx, proc)
	if err != nil {
		return bad()
	}
	fd, err := unix.Open(mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return bad()
	}
	for _, part := range strings.Split(strings.TrimPrefix(root.Cgroup, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if e != nil {
			return bad()
		}
		fd = next
	}
	h := &sharedCgroupHandle{fd: fd, proc: proc, pin: sharedCgroupPin{Path: root.Cgroup, BootID: boot, Root: root}}
	fail := func() (*sharedCgroupHandle, error) { h.close(); return bad() }
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fail()
	}
	h.pin.Device, h.pin.Inode = uint64(st.Dev), st.Ino
	if original != nil {
		if !reflect.DeepEqual(h.pin, *original) {
			return fail()
		}
		h.owned = true
	}
	frozen, populated, err := h.state(ctx)
	if err != nil || original == nil && (!populated || frozen) {
		return fail()
	}
	if original == nil && h.identity(ctx) != nil || h.fixed(ctx) != nil {
		return fail()
	}
	return h, nil
}

func (h *sharedCgroupHandle) close() {
	if h != nil && h.fd >= 0 {
		unix.Close(h.fd)
		h.fd = -1
	}
}

func (h *sharedCgroupHandle) fixed(ctx context.Context) error {
	if h == nil || h.fd < 0 || ctx == nil || ctx.Err() != nil {
		return observationFailure("shared_cgroup_handle")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return observationFailure("shared_cgroup_deadline")
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	boot, err := sharedCgroupBoot(ctx, h.proc)
	if err != nil || boot != h.pin.BootID || unix.Fstatfs(h.fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || unix.Fstat(h.fd, &st) != nil || uint64(st.Dev) != h.pin.Device || st.Ino != h.pin.Inode {
		return observationFailure("shared_cgroup_replaced")
	}
	return nil
}

func (h *sharedCgroupHandle) identity(ctx context.Context) error {
	if h.fixed(ctx) != nil {
		return observationFailure("shared_cgroup_replaced")
	}
	actual, err := observationProcess(ctx, filepath.Join(h.proc, strconv.Itoa(h.pin.Root.PID)))
	self, se := observationProcess(ctx, filepath.Join(h.proc, strconv.Itoa(os.Getpid())))
	if err != nil || se != nil || !reflect.DeepEqual(actual, h.pin.Root) || withinObservation(self.Cgroup, h.pin.Path) {
		return observationFailure("shared_cgroup_incarnation")
	}
	return nil
}

func (h *sharedCgroupHandle) file(ctx context.Context, name string, flags int) (*os.File, error) {
	if h.fixed(ctx) != nil || name != "cgroup.freeze" && name != "cgroup.events" {
		return nil, ErrNodeObservation
	}
	fd, err := unix.Openat(h.fd, name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrNodeObservation
	}
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || unix.Fstat(fd, &st) != nil || uint64(st.Dev) != h.pin.Device {
		unix.Close(fd)
		return nil, ErrNodeObservation
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (h *sharedCgroupHandle) state(ctx context.Context) (bool, bool, error) {
	f, err := h.file(ctx, "cgroup.events", unix.O_RDONLY)
	if err != nil {
		return false, false, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	closeErr := f.Close()
	if err != nil || closeErr != nil || len(raw) == 0 || len(raw) > 4096 {
		return false, false, ErrNodeObservation
	}
	return parseSharedCgroupEvents(raw)
}

func parseSharedCgroupEvents(raw []byte) (bool, bool, error) {
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || values[fields[0]] != "" || fields[1] != "0" && fields[1] != "1" || fields[0] != "frozen" && fields[0] != "populated" {
			return false, false, ErrNodeObservation
		}
		values[fields[0]] = fields[1]
	}
	if len(values) != 2 {
		return false, false, ErrNodeObservation
	}
	return values["frozen"] == "1", values["populated"] == "1", nil
}

func (h *sharedCgroupHandle) write(ctx context.Context, value string) error {
	f, err := h.file(ctx, "cgroup.freeze", unix.O_WRONLY)
	if err != nil {
		return err
	}
	n, err := f.WriteString(value)
	closeErr := f.Close()
	if err != nil || closeErr != nil || n != len(value) {
		return observationFailure("shared_cgroup_write_unknown")
	}
	return nil
}

func (h *sharedCgroupHandle) wait(ctx context.Context, frozen bool) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		actual, _, err := h.state(ctx)
		if err != nil {
			return err
		}
		if actual == frozen {
			return nil
		}
		select {
		case <-ctx.Done():
			return observationFailure("shared_cgroup_transition_unknown")
		case <-tick.C:
		}
	}
}

func (h *sharedCgroupHandle) freeze(ctx context.Context) error {
	if h.identity(ctx) != nil {
		return observationFailure("shared_cgroup_incarnation")
	}
	frozen, populated, err := h.state(ctx)
	if err != nil || !populated || frozen && !h.owned {
		return observationFailure("shared_cgroup_not_original_idle")
	}
	h.owned = true
	if !frozen {
		if err = h.write(ctx, "1\n"); err != nil {
			return err
		}
	}
	if h.wait(ctx, true) != nil || h.identity(ctx) != nil {
		return observationFailure("shared_cgroup_freeze_unconfirmed")
	}
	return nil
}

func (h *sharedCgroupHandle) checkFrozen(ctx context.Context) error {
	if h == nil || !h.owned || h.identity(ctx) != nil {
		return observationFailure("shared_cgroup_incarnation")
	}
	frozen, populated, err := h.state(ctx)
	if err != nil || !frozen || !populated {
		return observationFailure("shared_cgroup_not_frozen")
	}
	return nil
}

// Release only the fd-pinned ORIGINAL cgroup. If its original CRI process has
// disappeared/reused its PID, still release our own physical freeze, but return
// an error: source recovery MUST NOT be claimed or the SQL gate released as a
// successful recovery. A replacement path/inode is never written.
func (h *sharedCgroupHandle) thaw(ctx context.Context) error {
	if h == nil || !h.owned || h.fixed(ctx) != nil {
		return observationFailure("shared_cgroup_replaced")
	}
	identityErr := h.identity(ctx)
	if err := h.write(ctx, "0\n"); err != nil {
		return err
	}
	if err := h.wait(ctx, false); err != nil {
		return err
	}
	if identityErr != nil || h.identity(ctx) != nil {
		return observationFailure("shared_cgroup_recovery_incarnation")
	}
	return nil
}
