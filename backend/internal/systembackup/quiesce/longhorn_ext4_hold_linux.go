//go:build linux

package quiesce

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func (v longhornExt4Volume) observe(ctx context.Context) (bool, error) {
	p := v.pin
	if ctx == nil || ctx.Err() != nil || p.BootID == "" || p.UniqueMountID == 0 || p.Device == 0 ||
		p.RootInode == 0 || p.DiskSequence == 0 || p.ErrorCount != 0 || p.MountPoint == "/" ||
		!absoluteObservationPath(p.MountPoint) || p.Source == "" {
		return false, observationFailure("longhorn_ext4_pin_invalid")
	}
	boot, err := observationRead(ctx, "/proc/sys/kernel/random/boot_id", 64)
	if err != nil || strings.TrimSpace(string(boot)) != p.BootID {
		return false, observationFailure("longhorn_ext4_boot_changed")
	}
	_, mountID, _, err := observationFDInfo(ctx, "/proc/self", strconv.Itoa(v.mountFD))
	if err != nil || mountID != p.MountID {
		return false, observationFailure("longhorn_ext4_mount_changed")
	}
	raw, err := observationRead(ctx, filepath.Join(v.mountProc, "mountinfo"), observationReadLimit)
	if err != nil {
		return false, err
	}
	device := fmt.Sprintf("%d:%d", unix.Major(p.Device), unix.Minor(p.Device))
	found, readOnly := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != mountID {
			continue
		}
		sep := mountSeparator(fields)
		if found || sep < 0 || fields[2] != device || fields[3] != "/" || fields[sep+1] != "ext4" {
			return false, observationFailure("longhorn_ext4_mount_changed")
		}
		point, pointErr := mountUnescape(fields[4])
		source, sourceErr := mountUnescape(fields[sep+2])
		mode, _, _ := strings.Cut(fields[sep+3], ",")
		if pointErr != nil || sourceErr != nil || point != p.MountPoint || source != p.Source || (mode != "ro" && mode != "rw") {
			return false, observationFailure("longhorn_ext4_superblock_changed")
		}
		found, readOnly = true, mode == "ro"
	}
	if !found {
		return false, observationFailure("longhorn_ext4_mount_changed")
	}
	var dir, block, host unix.Stat_t
	if unix.Fstat(v.mountFD, &dir) != nil || unix.Fstat(v.blockFD, &block) != nil ||
		unix.Fstat(v.hostRootFD, &host) != nil || dir.Mode&unix.S_IFMT != unix.S_IFDIR ||
		block.Mode&unix.S_IFMT != unix.S_IFBLK || host.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(dir.Dev) != p.Device || uint64(dir.Ino) != p.RootInode ||
		uint64(block.Rdev) != p.Device || uint64(host.Dev) == p.Device {
		return false, observationFailure("longhorn_ext4_device_changed")
	}
	var unique unix.Statx_t
	if unix.Statx(v.mountFD, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID_UNIQUE, &unique) != nil ||
		unique.Mask&unix.STATX_MNT_ID_UNIQUE == 0 || unique.Mnt_id != p.UniqueMountID {
		return false, observationFailure("longhorn_ext4_unique_mount_changed")
	}
	if _, err := v.blockSample(ctx, false); err != nil {
		return false, err
	}
	return readOnly, ctx.Err()
}

// Read the stock kernel counters from the same device incarnation. Sample
// on both sides of the provider snapshot.
func (v longhornExt4Volume) blockSample(ctx context.Context, idle bool) (longhornExt4WriteCounters, error) {
	var out longhornExt4WriteCounters
	p := v.pin
	device := fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(p.Device), unix.Minor(p.Device))
	link, err := os.Readlink(device)
	if err != nil || link == "" {
		return out, observationFailure("longhorn_ext4_disk_unobserved")
	}
	seq, err := observationRead(ctx, filepath.Join(device, "diskseq"), 64)
	if err != nil || strings.TrimSpace(string(seq)) != strconv.FormatUint(p.DiskSequence, 10) {
		return out, observationFailure("longhorn_ext4_disk_changed")
	}
	health, err := observationRead(ctx, filepath.Join("/sys/fs/ext4", filepath.Base(link), "errors_count"), 64)
	if err != nil || strings.TrimSpace(string(health)) != strconv.FormatUint(p.ErrorCount, 10) {
		return out, observationFailure("longhorn_ext4_error_count_changed")
	}
	if !idle {
		return out, nil
	}
	raw, err := observationRead(ctx, filepath.Join(device, "stat"), 4096)
	if err != nil {
		return out, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 15 || fields[8] != "0" {
		return out, observationFailure("longhorn_ext4_device_io_unconfirmed")
	}
	for _, field := range []struct {
		index int
		dst   *uint64
	}{{4, &out.Completed}, {6, &out.Sectors}, {11, &out.Discards}, {13, &out.DiscardSectors}} {
		value, err := strconv.ParseUint(fields[field.index], 10, 64)
		if err != nil {
			return out, observationFailure("longhorn_ext4_block_stat_invalid")
		}
		*field.dst = value
	}
	return out, ctx.Err()
}

func (v longhornExt4Volume) qualify(ctx context.Context) error {
	ro, err := v.observe(ctx)
	if err != nil {
		return err
	}
	if ro {
		return observationFailure("longhorn_ext4_initial_rw_required")
	}
	return nil
}
