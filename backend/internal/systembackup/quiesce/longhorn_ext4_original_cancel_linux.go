//go:build linux

package quiesce

import "context"

// Recovery can win the owner lock before a delayed original RWX register.
// Close that exact registration durably without a freeze or thaw syscall.
// Unlike a retained held/unknown operation, absence here permits no inverse IO.
// The caller has already verified the recovery mTLS identity, installed source
// and current provider/device, under the original serialized owner lock.
func (a *longhornExt4Actions) closeUnregisteredOriginal(ctx context.Context, key string, source LonghornExt4Source, volume longhornExt4Volume, r LonghornExt4Request) (longhornExt4Event, error) {
	var zero longhornExt4Event
	if ctx == nil || ctx.Err() != nil || r.Version != LonghornExt4Protocol || r.Action != "release" ||
		source.Keeper != nil || r.Keeper != nil || r.Claim.TaskPublicID != "" || r.Claim.OriginalOperationID == "" ||
		!r.Claim.matchesBinding(r.Binding) || !longhornExt4RequestMatches(source, r) || key != longhornExt4SourceKey(source) ||
		!validObservationHash(r.RegistrationBoundarySHA256) || !validObservationHash(r.RecoveryBoundarySHA256) ||
		r.DrainBoundarySHA256 != "" || volume.pin != source.Pin || volume.freeze == nil ||
		volume.freeze.freezeSent || volume.freeze.owned || volume.freeze.thawSent || volume.freeze.thawSucceeded {
		return zero, ErrNodeObservation
	}
	if _, found, err := a.load(key); err != nil || found {
		return zero, ErrNodeObservation
	}
	if err := a.checkDeviceObligations(key, source); err != nil {
		return zero, err
	}
	readOnly, err := volume.freezeNativeOps().observe(ctx)
	if err != nil || readOnly {
		return zero, ErrNodeObservation
	}
	event := longhornExt4Event{Version: LonghornExt4Protocol, Key: key, Source: source,
		RegistrationBoundarySHA256: r.RegistrationBoundarySHA256, RecoveryBoundarySHA256: r.RecoveryBoundarySHA256,
		Hold: longhornExt4Hold{Mechanism: longhornFreezeCounterMechanism, Pin: source.Pin, Phase: "released", ExpiresAt: longhornExt4ForwardUntil(source.Binding, source.Claim)}}
	if err := a.persist(&event); err != nil {
		return zero, err
	}
	return event, nil
}

func longhornExt4RegisterEventMatches(event longhornExt4Event, r LonghornExt4Request) bool {
	return event.Hold.Phase == "prepared" && event.RegistrationBoundarySHA256 == r.RegistrationBoundarySHA256
}
