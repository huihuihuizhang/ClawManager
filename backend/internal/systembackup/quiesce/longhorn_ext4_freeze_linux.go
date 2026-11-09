//go:build linux

package quiesce

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The configured owner uses the real kernel functions. The private operations
// boundary permits deterministic interrupted-syscall regression without touching
// any existing mount; no HTTP/config input can install another operations set.
func (v longhornExt4Volume) freezeNativeOps() longhornExt4FreezeOps {
	if v.freeze != nil && v.freeze.ops != nil {
		return *v.freeze.ops
	}
	return longhornExt4FreezeOps{observe: v.observe, sample: v.freezeSample, sync: unix.Syncfs, ioctl: longhornExt4FreezeIoctl}
}

func longhornExt4FreezeIoctl(fd int, request uint) error {
	// The qualified prototype targets Linux x86_64. Its existing x/sys
	// version does not export these Linux UAPI ioctl constants.
	if runtime.GOARCH != "amd64" || (request != longhornFreezeIOCTL && request != longhornThawIOCTL) {
		return ErrNodeObservation
	}
	_, _, code := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), 0)
	if code != 0 {
		return code
	}
	return nil
}

// Counters require the selected whole-device normal block IO accounting path.
// Native provider identities/attachment and source writer coverage still apply;
// this is not a proof against an out-of-band backend writer bypassing the device.
func (v longhornExt4Volume) freezeSample(ctx context.Context) (longhornExt4WriteCounters, error) {
	var empty longhornExt4WriteCounters
	if runtime.GOARCH != "amd64" || strconv.IntSize != 64 {
		return empty, ErrNodeObservation
	}
	device := filepath.Join("/sys/dev/block", strconv.FormatUint(uint64(unix.Major(v.pin.Device)), 10)+":"+strconv.FormatUint(uint64(unix.Minor(v.pin.Device)), 10))
	if _, err := os.Lstat(filepath.Join(device, "partition")); !os.IsNotExist(err) {
		return empty, observationFailure("longhorn_ext4_whole_device_required")
	}
	accounting, err := observationRead(ctx, filepath.Join(device, "queue/iostats"), 64)
	if err != nil || strings.TrimSpace(string(accounting)) != "1" {
		return empty, observationFailure("longhorn_ext4_io_accounting_required")
	}
	first, err := v.blockSample(ctx, true)
	if err != nil {
		return empty, err
	}
	second, err := v.blockSample(ctx, true)
	if err != nil || first != second {
		return empty, observationFailure("longhorn_ext4_device_io_unconfirmed")
	}
	return second, nil
}
