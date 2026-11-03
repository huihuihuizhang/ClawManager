package systembackupbootstrapsecurity

import (
	"bytes"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// Exact paired public registries are trust material, not personnel MFA or
// provider task grants. Original composition and mutation authority are separate.
type EnableOnlyIssuerObservation struct {
	mu                                sync.Mutex
	origin                            *EnableOnlyIssuerObservation
	failed                            atomic.Bool
	ctx                               context.Context
	files                             sec.RegistrationFiles
	installation                      string
	provider, strong                  sec.BootstrapRegistryRef
	started, until, floor, inputFloor time.Time
	tx                                *sql.Tx
}

func sameEnableOnlyIssuerContext(a, b context.Context) bool {
	return a != nil && b != nil && reflect.ValueOf(a).Comparable() && reflect.ValueOf(b).Comparable() && a == b
}
func (*EnableOnlyIssuerObservation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (o *EnableOnlyIssuerObservation) ValidUntil() time.Time {
	if o == nil || o.origin != o || o.failed.Load() {
		return time.Time{}
	}
	return o.until
}
func (v *Issuers) ObserveEnableOnly(ctx context.Context, in sec.ConfigMutationResourceInput) (*EnableOnlyIssuerObservation, error) {
	if v == nil || v.now == nil || !sameEnableOnlyIssuerContext(ctx, ctx) || ctx.Err() != nil || sec.ValidateEnableOnlyConfigMutation(in) != nil || !filepath.IsAbs(v.directory) || filepath.Clean(v.directory) != v.directory {
		return nil, sec.ErrRegistrationUnavailable
	}
	started := v.now().UTC().Truncate(time.Microsecond)
	until := started.Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	files := sec.RegistrationFiles{RegistryDirectory: v.directory}
	var provider, strong sec.BootstrapRegistryRef
	for _, kind := range []string{"provider_proof_issuers", "strong_auth_issuers"} {
		pair, ok := in.RegistryPair(kind)
		if !ok || pair.Current != pair.Proposed || !bytes.Equal(pair.CurrentJSON, pair.ProposedJSON) {
			return nil, sec.ErrRegistrationUnavailable
		}
		raw, e := files.RegistryBytes(kind, pair.Current.Version, pair.Current.SHA256)
		if e != nil || !bytes.Equal(raw, pair.CurrentJSON) {
			return nil, sec.ErrRegistrationUnavailable
		}
		if kind == "provider_proof_issuers" {
			provider = pair.Current
		} else {
			strong = pair.Current
		}
	}
	if validateEnableOnlyIssuerFiles(ctx, files, in.InstallationID(), provider, strong, started) != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return nil, sec.ErrRegistrationUnavailable
	}
	o := &EnableOnlyIssuerObservation{ctx: ctx, files: files, installation: in.InstallationID(), provider: provider, strong: strong, started: started, until: until}
	o.origin = o
	return o, nil
}
func validateEnableOnlyIssuerFiles(ctx context.Context, files sec.RegistrationFiles, installation string, providerPin, strongPin sec.BootstrapRegistryRef, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || now.IsZero() {
		return sec.ErrRegistrationUnavailable
	}
	raw, err := files.RegistryBytes(providerPin.Kind, providerPin.Version, providerPin.SHA256)
	if err != nil {
		return sec.ErrRegistrationUnavailable
	}
	provider, err := sec.DecodeProviderIssuerRegistry(raw, providerPin.Version, providerPin.SHA256, now)
	if err != nil || provider.Scope.InstallationID != installation {
		return sec.ErrRegistrationUnavailable
	}
	raw, err = files.RegistryBytes(strongPin.Kind, strongPin.Version, strongPin.SHA256)
	if err != nil {
		return sec.ErrRegistrationUnavailable
	}
	strong, err := sec.DecodeStrongAuthIssuerRegistry(raw, strongPin.Version, strongPin.SHA256, now)
	if err != nil {
		return sec.ErrRegistrationUnavailable
	}
	providerActive, totpActive := false, false
	for _, key := range provider.Keys {
		if !closedSet(key.TargetTypes, []string{"external_action", "backup_staging", "restore_resource"}) || !closedSet(key.ProofTypes, []string{"provider_presence", "provider_absence", "ownership"}) {
			return sec.ErrRegistrationUnavailable
		}
		// Every declared capability must have a compatible counterpart.
		for _, target := range key.TargetTypes {
			if (target == "external_action" && !has(key.ProofTypes, "provider_presence") && !has(key.ProofTypes, "provider_absence")) || (target != "external_action" && !has(key.ProofTypes, "ownership")) {
				return sec.ErrRegistrationUnavailable
			}
		}
		for _, proof := range key.ProofTypes {
			if (proof == "ownership" && !has(key.TargetTypes, "backup_staging") && !has(key.TargetTypes, "restore_resource")) || (proof != "ownership" && !has(key.TargetTypes, "external_action")) {
				return sec.ErrRegistrationUnavailable
			}
		}
		if !key.Revoked && !now.Before(key.NotBefore) && now.Add(5*time.Minute).Before(key.NotAfter) {
			providerActive = true
		}
		for _, other := range strong.Keys {
			if bytes.Equal(key.PublicKey, other.PublicKey) {
				return sec.ErrRegistrationUnavailable
			}
		}
	}
	for _, key := range strong.Keys {
		if !key.Revoked && !now.Before(key.NotBefore) && now.Add(5*time.Minute).Before(key.NotAfter) && has(key.Policy.Methods, "totp") && has(key.Policy.AMR, "otp") {
			totpActive = true
		}
	}
	// Match the existing registration runtime's five-minute key runway and its
	// real TOTP issuer. Historical-only trust must not pass initial admission.
	if !providerActive || !totpActive || ctx.Err() != nil {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func (o *EnableOnlyIssuerObservation) fail() error {
	if o != nil {
		o.failed.Store(true)
		if o.origin != nil {
			o.origin.failed.Store(true)
		}
	}
	return sec.ErrRegistrationUnavailable
}
func (o *EnableOnlyIssuerObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if o == nil {
		return sec.ErrRegistrationUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.origin != o || o.failed.Load() || !sameEnableOnlyIssuerContext(ctx, o.ctx) || ctx.Err() != nil || tx == nil || o.tx != nil && o.tx != tx || !o.inputFloor.IsZero() && now.Before(o.inputFloor) || now.Before(o.started) || !now.Before(o.until) || !time.Now().Before(o.until) {
		return o.fail()
	}
	if validateEnableOnlyIssuerFiles(ctx, o.files, o.installation, o.provider, o.strong, now) != nil {
		return o.fail()
	}
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(now) || !o.floor.IsZero() && tail.Before(o.floor) || !tail.Before(o.until) || validateEnableOnlyIssuerFiles(ctx, o.files, o.installation, o.provider, o.strong, tail) != nil || ctx.Err() != nil || !time.Now().Before(o.until) {
		return o.fail()
	}
	o.tx = tx
	o.floor = tail
	o.inputFloor = now
	return nil
}
