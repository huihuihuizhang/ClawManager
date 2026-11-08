//go:build linux

package main

import (
	"clawreef/internal/systembackup/quiesce"
	"context"
	"golang.org/x/sys/unix"
)

func keepLonghornAttachment(ctx context.Context, root string) error {
	if root != "/source" {
		return quiesce.ErrNodeObservation
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return quiesce.ErrNodeObservation
	}
	<-ctx.Done()
	return nil
}
