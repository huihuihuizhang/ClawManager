//go:build linux

package quiesce

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Actual own-process FD/mmap/mount coordinates only. These are not CRI/native
// actor positives, and do not mint a VerifiedNodeObservation or held-gate proof.
func TestOriginalRecoveryUnknownNativeFDAndMapCoordinates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if e := os.Mkdir(source, 0700); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(source, "data")
	if e := os.WriteFile(file, make([]byte, 4096), 0600); e != nil {
		t.Fatal(e)
	}
	sources := observationTestSources(t, source)
	outside, e := os.OpenFile(filepath.Join(dir, "outside"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer outside.Close()
	if e = observationRecoveryUnknownHandles(ctx, "/proc/self", "/proc", sources); e != nil {
		t.Fatal("actual unrelated same-FS writer refused", e)
	}
	writer, e := os.OpenFile(file, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	if observationRecoveryUnknownHandles(ctx, "/proc/self", "/proc", sources) == nil {
		t.Fatal("unknown native source FD accepted without a precomputed inode entry")
	}
	mapped, e := unix.Mmap(int(writer.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if mapped != nil {
			unix.Munmap(mapped)
		}
	}()
	if e = writer.Close(); e != nil {
		t.Fatal(e)
	}
	if observationRecoveryUnknownHandles(ctx, "/proc/self", "/proc", sources) == nil {
		t.Fatal("unknown native shared source map accepted after FD close")
	}
	if e = unix.Munmap(mapped); e != nil {
		t.Fatal(e)
	}
	mapped = nil
	// The unchanged inode scan still catches hard-link aliases whose pathname
	// itself lies outside the selected source, before coordinate fallback.
	alias := filepath.Join(dir, "alias")
	if e = os.Link(file, alias); e != nil {
		t.Fatal(e)
	}
	aliased, e := os.OpenFile(alias, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer aliased.Close()
	o := &NodeObserver{HostRoot: "/"}
	files, e := o.files(ctx, sources)
	if e != nil {
		t.Fatal(e)
	}
	if observationWritableHandles(ctx, "/proc/self", "/proc", files, sources) == nil {
		t.Fatal("native source hard-link writer escaped original inode check")
	}
}
