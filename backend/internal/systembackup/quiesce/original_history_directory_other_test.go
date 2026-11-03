//go:build !linux

package quiesce

import (
	"context"
	"testing"
	"time"
)

func TestOriginalHistoryDirectoryNonLinuxRefusesNativeAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	v, b := originalHistoryDirectoryTestProof(t, observedPath{Path: "/original", Device: 1, Inode: 2, Mount: "mount"}, "boot", time.Now().Add(time.Second))
	if r, e := OpenOriginalNodeHistoryDirectory(ctx, v, b, "boot", "/original"); e == nil || r != nil {
		t.Fatal("nonLinux native access accepted")
	}
}
