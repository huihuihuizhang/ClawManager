//go:build linux

package quiesce

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func originalHistoryDirectoryNativeIdentity(ctx context.Context, p observedPath, boot string) (os.FileInfo, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrNodeObservation
	}
	b, err := observationRead(ctx, "/proc/sys/kernel/random/boot_id", 256)
	if err != nil || strings.TrimSpace(string(b)) != boot {
		return nil, ErrNodeObservation
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(p.Path, "/"), "/") {
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrNodeObservation
		}
	}
	info, err := os.Lstat(p.Path)
	if err != nil || !info.IsDir() {
		return nil, ErrNodeObservation
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != p.Device || st.Ino != p.Inode {
		return nil, ErrNodeObservation
	}
	// Require the original exact mount entry in this process's namespace.
	// Bind-mount aliases, hidden submounts or an off-node path cannot substitute.
	raw, err := observationRead(ctx, "/proc/self/mountinfo", observationReadLimit)
	if err != nil {
		return nil, ErrNodeObservation
	}
	best := ""
	length := -1
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if mountSeparator(f) < 0 {
			return nil, ErrNodeObservation
		}
		mp, e := mountUnescape(f[4])
		if e != nil {
			return nil, ErrNodeObservation
		}
		if mp != p.Path && withinObservation(mp, p.Path) {
			return nil, ErrNodeObservation
		}
		if withinObservation(p.Path, mp) && len(mp) > length {
			best = line
			length = len(mp)
		}
	}
	if best == "" || best != p.Mount || ctx.Err() != nil {
		return nil, ErrNodeObservation
	}
	return info, nil
}

func sameOriginalHistoryDirectoryNative(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.IsDir() && b.IsDir() && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func openOriginalHistoryDirectoryNative(ctx context.Context, p observedPath, boot string) (*os.File, os.FileInfo, error) {
	before, err := originalHistoryDirectoryNativeIdentity(ctx, p, boot)
	if err != nil {
		return nil, nil, ErrNodeObservation
	}
	f, err := os.Open(p.Path)
	if err != nil {
		return nil, nil, ErrNodeObservation
	}
	if checkOriginalHistoryDirectoryNative(ctx, f, before, p, boot) != nil {
		f.Close()
		return nil, nil, ErrNodeObservation
	}
	return f, before, nil
}

func checkOriginalHistoryDirectoryNative(ctx context.Context, f *os.File, initial os.FileInfo, p observedPath, boot string) error {
	current, err := originalHistoryDirectoryNativeIdentity(ctx, p, boot)
	if err != nil || f == nil {
		return ErrNodeObservation
	}
	opened, err := f.Stat()
	if err != nil || !sameOriginalHistoryDirectoryNative(initial, current) || !sameOriginalHistoryDirectoryNative(initial, opened) {
		return ErrNodeObservation
	}
	return nil
}
