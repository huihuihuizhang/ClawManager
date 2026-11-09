//go:build !linux

package quiesce

import "context"

// Non-Linux builds support deterministic state-machine regression only. No
// installed Node owner can use a native freeze implementation on this platform.
func (v longhornExt4Volume) freezeNativeOps() longhornExt4FreezeOps {
	if v.freeze != nil && v.freeze.ops != nil {
		return *v.freeze.ops
	}
	return longhornExt4FreezeOps{
		observe: func(context.Context) (bool, error) { return false, ErrNodeObservation },
		sample: func(context.Context) (longhornExt4WriteCounters, error) {
			return longhornExt4WriteCounters{}, ErrNodeObservation
		},
		sync:  func(int) error { return ErrNodeObservation },
		ioctl: func(int, uint) error { return ErrNodeObservation },
	}
}
