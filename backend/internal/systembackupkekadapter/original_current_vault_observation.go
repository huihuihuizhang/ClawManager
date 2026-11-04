package systembackupkekadapter

import (
	kms "clawreef/internal/systembackupkms"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"
)

// Real independent native permission/key observation only, not execution.
type OriginalCurrentVaultObservation struct {
	origin         *OriginalCurrentVaultObservation
	ctx            context.Context
	native         *ObservedVaultPermissions
	started, until time.Time
	proof          string
}

func (*OriginalCurrentVaultObservation) MarshalJSON() ([]byte, error) { return nil, kms.ErrPermission }
func (o *VaultPermissionObserver) ObserveOriginalCurrent(ctx context.Context) (*OriginalCurrentVaultObservation, error) {
	if o == nil || ctx == nil || ctx.Err() != nil {
		return nil, kms.ErrPermission
	}
	start := time.Now().UTC().Truncate(time.Microsecond)
	until := start.Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	// Reading TTL never renews or extends the original observer credential.
	ttl, err := o.originalCurrentObserverTTL(ctx)
	if err != nil {
		return nil, err
	}
	if end := start.Add(time.Duration(ttl) * time.Second); end.Before(until) {
		until = end
	}
	active, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	native, err := o.Observe(active)
	if err != nil {
		return nil, err
	}
	ttl, err = o.originalCurrentObserverTTL(active)
	if err != nil {
		return nil, err
	}
	if end := time.Now().Add(time.Duration(ttl) * time.Second); end.Before(until) {
		until = end
	}
	raw, err := json.Marshal([]ProviderCapabilityFacts{native.generate, native.unwrap})
	if err != nil || !time.Now().Before(until) {
		return nil, kms.ErrPermission
	}
	sum := sha256.Sum256(raw)
	result := &OriginalCurrentVaultObservation{ctx: ctx, native: native, started: start, until: until, proof: hex.EncodeToString(sum[:])}
	result.origin = result
	return result, nil
}
func (o *VaultPermissionObserver) originalCurrentObserverTTL(ctx context.Context) (int64, error) {
	raw, err := o.read(ctx, "/v1/auth/token/lookup-self")
	if err != nil {
		return 0, err
	}
	defer clear(raw)
	var reply struct {
		TTL int64 `json:"ttl"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.TTL < 1 || reply.TTL > 86400 {
		return 0, kms.ErrPermission
	}
	return reply.TTL, nil
}
func (o *OriginalCurrentVaultObservation) Facts(ctx context.Context) (string, time.Time, time.Time, error) {
	if o == nil || o.origin != o || o.native == nil || ctx == nil || !reflect.ValueOf(ctx).Comparable() || ctx != o.ctx || ctx.Err() != nil || !time.Now().Before(o.until) {
		return "", time.Time{}, time.Time{}, kms.ErrPermission
	}
	return o.proof, o.started, o.until, nil
}

// InspectOriginalCurrentMapping authenticates original owner bytes only. It
// issues no provider execution, coverage or config permission.
func InspectOriginalCurrentMapping(raw, signature, key []byte, now time.Time) (OriginalRecord, error) {
	return authenticate(raw, signature, key, now)
}
