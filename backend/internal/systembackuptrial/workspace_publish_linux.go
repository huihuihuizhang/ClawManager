//go:build linux

package systembackuptrial

import (
	"os"

	"golang.org/x/sys/unix"
)

func publishWorkspaceFiles(root *os.Root, candidate, target string) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	fd := int(directory.Fd())
	if err := unix.Renameat2(fd, candidate, fd, target, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return directory.Sync()
}
