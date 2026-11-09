//go:build linux

package main

import (
	"context"

	"clawreef/internal/systembackup/quiesce"
	"golang.org/x/sys/unix"
)

func keepLonghornAttachment(ctx context.Context, root string) error {
	if root != "/source" {
		return quiesce.ErrNodeObservation
	}
	parent, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, "source", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// The container's root filesystem is also read-only. Require a separate
	// mount before keeping the descriptor. The Node owner must still verify
	// the mounted volume's identity against the original PVC and device.
	var rootMount, sourceMount unix.Statx_t
	if unix.Statx(parent, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &rootMount) != nil ||
		unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sourceMount) != nil ||
		rootMount.Mask&unix.STATX_MNT_ID == 0 || sourceMount.Mask&unix.STATX_MNT_ID == 0 ||
		rootMount.Mnt_id == sourceMount.Mnt_id {
		return quiesce.ErrNodeObservation
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || fs.Flags&unix.ST_RDONLY == 0 {
		return quiesce.ErrNodeObservation
	}
	<-ctx.Done()
	return nil
}
