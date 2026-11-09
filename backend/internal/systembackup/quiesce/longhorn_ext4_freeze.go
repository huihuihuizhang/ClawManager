package quiesce

import (
	"context"
	"time"
)

// The authenticated Node owner constructs the pin from the selected
// Longhorn attachment, its actual mount namespace and /dev/longhorn device.
// The owner serializes all transitions and holds the supplied descriptors.
type longhornExt4Pin struct {
	BootID, MountID, MountPoint, Source string
	UniqueMountID, Device, RootInode    uint64
	DiskSequence, ErrorCount            uint64
}

type longhornExt4Volume struct {
	freeze     *longhornExt4FreezeCustody
	pin        longhornExt4Pin
	mountFD    int
	blockFD    int
	hostRootFD int
	mountProc  string
}

// Persist this record in the existing root-owned native journal under the
// authenticated operation, gate generation, provider and exact volume key.
type longhornExt4Hold struct {
	Mechanism string `json:",omitempty"`
	Pin       longhornExt4Pin
	Phase     string
	StartedAt time.Time
	ExpiresAt time.Time
	Writes    longhornExt4WriteCounters
}

type longhornExt4WriteCounters struct {
	Completed, Sectors, Discards, DiscardSectors uint64
}

const longhornFreezeCounterMechanism = "ext4-freeze-stable-block-counters.v1"

// Volatile custody belongs to the continuously running serialized Node owner.
// No journal or EBUSY result can reconstruct a successful ioctl acknowledgement.
type longhornExt4FreezeOps struct {
	observe func(context.Context) (bool, error)
	sample  func(context.Context) (longhornExt4WriteCounters, error)
	sync    func(int) error
	ioctl   func(int, uint) error
}

type longhornExt4FreezeCustody struct {
	ops                                        *longhornExt4FreezeOps
	key                                        string
	freezeSent, owned, thawSent, thawSucceeded bool
}

// Linux generic ioctl encoding (int argument); native use is Linux-only.
const longhornFreezeIOCTL uint = 0xC0045877
const longhornThawIOCTL uint = 0xC0045878

func (v longhornExt4Volume) freezeAcquire(ctx context.Context, record longhornExt4Hold, persist func(longhornExt4Hold) error) (longhornExt4Hold, error) {
	if v.freeze == nil || v.freeze.key == "" || v.freeze.freezeSent || record.Pin != v.pin || record.Phase != "prepared" || persist == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(record.ExpiresAt) {
		return record, ErrNodeObservation
	}
	ro, err := v.freezeNativeOps().observe(ctx)
	if err != nil || ro {
		return record, observationFailure("longhorn_ext4_initial_rw_required")
	}
	if _, err := v.freezeNativeOps().sample(ctx); err != nil {
		return record, err
	}
	if err := v.freezeNativeOps().sync(v.mountFD); err != nil {
		return record, err
	}
	record.Phase = "freeze-intent"
	if err := persist(record); err != nil {
		return record, err
	}
	if ctx.Err() != nil || !time.Now().Before(record.ExpiresAt) {
		return record, ErrNodeObservation
	}
	v.freeze.freezeSent = true
	if err := v.freezeNativeOps().ioctl(v.mountFD, longhornFreezeIOCTL); err != nil {
		return record, err
	}
	v.freeze.owned = true
	record.Phase = "freeze-acknowledged"
	if err := persist(record); err != nil {
		return record, err
	}
	record.Writes, err = v.freezeNativeOps().sample(ctx)
	if err != nil {
		return record, err
	}
	record.Phase, record.StartedAt = "held", time.Now().UTC()
	if err := persist(record); err != nil {
		return record, err
	}
	_, err = v.freezeRecheck(ctx, record)
	return record, err
}

// The proof is stable source-device bytes since the acknowledged freeze, not a
// fresh observation of Linux's shared userspace freeze bit or a read-only mount.
func (v longhornExt4Volume) freezeRecheck(ctx context.Context, record longhornExt4Hold) (time.Time, error) {
	if v.freeze == nil || !v.freeze.owned || v.freeze.thawSent || record.Pin != v.pin || record.Phase != "held" || record.StartedAt.IsZero() {
		return time.Time{}, observationFailure("longhorn_ext4_freeze_custody_lost")
	}
	ro, err := v.freezeNativeOps().observe(ctx)
	if err != nil || ro {
		return time.Time{}, observationFailure("longhorn_ext4_freeze_device_changed")
	}
	writes, err := v.freezeNativeOps().sample(ctx)
	now := time.Now().UTC()
	if err != nil || writes != record.Writes || now.Before(record.StartedAt) || !now.Before(record.ExpiresAt) {
		return time.Time{}, observationFailure("longhorn_ext4_hold_lost")
	}
	return now, nil
}

// The existing authenticated Recovery path calls this independently of Forward
// expiry. Unknown acquire/thaw windows never authorize another inverse syscall.
func (v longhornExt4Volume) freezeRelease(ctx context.Context, record longhornExt4Hold, persist func(longhornExt4Hold) error) (longhornExt4Hold, error) {
	if record.Pin != v.pin || persist == nil || ctx == nil || ctx.Err() != nil {
		return record, ErrNodeObservation
	}
	if record.Phase != "released" && record.Phase != "prepared" && (v.freeze == nil || (!v.freeze.owned && !v.freeze.thawSucceeded)) {
		return record, observationFailure("longhorn_ext4_freeze_custody_lost")
	}
	ro, err := v.freezeNativeOps().observe(ctx)
	if err != nil || ro {
		return record, observationFailure("longhorn_ext4_freeze_device_changed")
	}
	if record.Phase == "released" {
		return record, nil
	}
	if record.Phase == "prepared" && (v.freeze == nil || !v.freeze.freezeSent) {
		record.Phase = "released"
		return record, persist(record)
	}
	if v.freeze == nil || (!v.freeze.owned && !v.freeze.thawSucceeded) {
		return record, observationFailure("longhorn_ext4_freeze_custody_lost")
	}
	switch record.Phase {
	case "freeze-intent", "freeze-acknowledged", "held", "thaw-intent":
	default:
		return record, ErrNodeObservation
	}
	if !v.freeze.thawSucceeded {
		if v.freeze.thawSent {
			return record, observationFailure("longhorn_ext4_thaw_unknown")
		}
		// A changed device baseline invalidates capture and cannot establish that
		// the current userspace freeze still belongs to our original operation.
		if !record.StartedAt.IsZero() {
			writes, err := v.freezeNativeOps().sample(ctx)
			if err != nil || writes != record.Writes {
				return record, observationFailure("longhorn_ext4_hold_lost")
			}
		}
		record.Phase = "thaw-intent"
		if err := persist(record); err != nil {
			return record, err
		}
		if err := ctx.Err(); err != nil {
			return record, err
		}
		v.freeze.thawSent, v.freeze.owned = true, false
		if err := v.freezeNativeOps().ioctl(v.mountFD, longhornThawIOCTL); err != nil {
			return record, err
		}
		v.freeze.thawSucceeded = true
	}
	record.Phase = "released"
	// This closes OUR userspace freeze only. The caller still has to verify
	// actual Node/filesystem source recovery and original writer readiness.
	return record, persist(record)
}
