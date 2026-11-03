package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"reflect"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
)

// ObservedOriginalVaultDependency is availability/permission evidence for the
// original KEK dependency. It neither authorizes a task nor says that any
// business source was frozen, scanned, copied or recovered. Its only producer
// reads the actual independently signed original mapping and performs the
// existing complete native permission observation, without a committed-config
// dependency (first adoption has not committed a registry binding yet).
type ObservedOriginalVaultDependency struct {
	origin         *ObservedOriginalVaultDependency
	ctx            context.Context
	observer       *VaultPermissionObserver
	permissions    *ObservedVaultPermissions
	original       OriginalRecord
	raw, signature []byte
	started, until time.Time
}

func (*ObservedOriginalVaultDependency) MarshalJSON() ([]byte, error) { return nil, kms.ErrPermission }
func (*ObservedOriginalVaultDependency) String() string               { return "ObservedOriginalVaultDependency" }
func (*ObservedOriginalVaultDependency) GoString() string             { return "ObservedOriginalVaultDependency" }

func originalDependencyContext(a, b context.Context) bool {
	return !nilSource(a) && !nilSource(b) && reflect.TypeOf(a).Comparable() && reflect.TypeOf(b).Comparable() && a == b
}

// ObserveOriginalProviderDependency authenticates the original mapping already
// owned by the installation authority, not a candidate or caller-supplied
// observation. Issuer/reference are independent deployment pins, identical to
// the existing KEK owner input. No SQL locks are held across provider I/O.
func (o *VaultPermissionObserver) ObserveOriginalProviderDependency(ctx context.Context, db *sql.DB, installation string, reference reg.ReferencePin, issuer ed25519.PublicKey) (*ObservedOriginalVaultDependency, error) {
	if o == nil || db == nil || nilSource(ctx) || ctx.Err() != nil || len(issuer) != ed25519.PublicKeySize || installation == "" || !authorityHash.MatchString(reference.IdentityHash) || !authorityExact(reference.Version) {
		return nil, kms.ErrPermission
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, kms.ErrPermission
	}
	started := time.Now().UTC()
	raw, signature, err := (SQLOriginalReader{DB: db}).ReadOriginal(ctx, installation, reference)
	if err != nil {
		return nil, kms.ErrPermission
	}
	original, err := authenticate(raw, signature, issuer, started)
	if err != nil || original.Binding.InstallationID != installation || original.Binding.ConfigRef != reference || !reflect.DeepEqual(original.Binding, o.cfg.Binding) {
		return nil, kms.ErrPermission
	}
	permissions, err := o.Observe(ctx)
	if err != nil {
		return nil, kms.ErrPermission
	}
	again, againSignature, err := (SQLOriginalReader{DB: db}).ReadOriginal(ctx, installation, reference)
	if err != nil || !bytes.Equal(raw, again) || !bytes.Equal(signature, againSignature) {
		return nil, kms.ErrPermission
	}
	now := time.Now().UTC()
	current, err := authenticate(again, againSignature, issuer, now)
	if err != nil || !reflect.DeepEqual(original, current) || !now.Before(deadline) {
		return nil, kms.ErrPermission
	}
	until := permissions.observed.Add(10 * time.Second)
	for _, bound := range []time.Time{original.Until, deadline} {
		if bound.Before(until) {
			until = bound
		}
	}
	p := &ObservedOriginalVaultDependency{ctx: ctx, observer: o, permissions: permissions, original: original, raw: bytes.Clone(raw), signature: bytes.Clone(signature), started: started, until: until}
	p.origin = p
	if p.Recheck(ctx, original.Binding, now) != nil {
		return nil, kms.ErrPermission
	}
	return p, nil
}

// Binding is detached comparison DATA only. It cannot manufacture this opaque
// observation, an admitted registry row, source ownership or any grant.
func (p *ObservedOriginalVaultDependency) Binding() (reg.Binding, error) {
	if p == nil || p.origin != p || p.observer == nil {
		return reg.Binding{}, kms.ErrPermission
	}
	b := p.original.Binding
	b.GenerateRef.RawJSON = bytes.Clone(b.GenerateRef.RawJSON)
	b.UnwrapRef.RawJSON = bytes.Clone(b.UnwrapRef.RawJSON)
	return b, nil
}

func (p *ObservedOriginalVaultDependency) ValidUntil(ctx context.Context) (time.Time, error) {
	if p == nil || p.Recheck(ctx, p.original.Binding, time.Now().UTC()) != nil {
		return time.Time{}, kms.ErrPermission
	}
	return p.until, nil
}

// Recheck is deliberately local: no provider/filesystem/SQL work in a final
// SQL lock prefix. The existing original KEK admission separately rechecks its
// signed mapping and revocations under its unchanged original lock order.
func (p *ObservedOriginalVaultDependency) Recheck(ctx context.Context, binding reg.Binding, now time.Time) error {
	if p == nil || p.origin != p || p.observer == nil || p.permissions == nil || p.permissions.owner != p.observer || !originalDependencyContext(ctx, p.ctx) || ctx.Err() != nil || now.IsZero() || now.Before(p.started) || now.Before(p.permissions.observed) || !now.Before(p.until) || now.Sub(p.permissions.observed) > 10*time.Second || !reflect.DeepEqual(binding, p.original.Binding) || !reflect.DeepEqual(binding, p.observer.cfg.Binding) || !reflect.DeepEqual(binding, p.permissions.generate.Binding) || !reflect.DeepEqual(binding, p.permissions.unwrap.Binding) || len(p.raw) == 0 || len(p.signature) != ed25519.SignatureSize {
		return kms.ErrPermission
	}
	return nil
}
