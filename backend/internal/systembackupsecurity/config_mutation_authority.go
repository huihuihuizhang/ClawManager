package systembackupsecurity

import (
	"context"
	"database/sql"
	"time"
)

// ConfigMutationAuthoritySources are deployment-owned functions. Missing any
// source rejects construction; none may be supplied by a request or read grant.
// Tx functions must neither commit nor perform provider/network calls.
// CheckSession must validate current identity/revocation, and ensure the locked
// DB session remains valid through the actor's authenticated expiry bound.
// StrongAuth must use A's issuer/key-purpose verification and all retained keys;
// ReserveMetadata must account for BOTH configs' budgets and physical capacity;
// RedactReason must apply A's reviewed redaction policy.
type ConfigMutationAuthoritySources struct {
	CheckSession    func(context.Context, *sql.Tx, string, RegistrationActor, time.Time) error
	RegistryBytes   func(string, string, string) ([]byte, error)
	StrongAuth      func(context.Context, *sql.Tx, RegistrationActor, string, ConfigValues, []string, time.Time) (VerifyConfig, error)
	ReserveMetadata func(context.Context, *sql.Tx, ConfigValues, ConfigValues, int, time.Time) (ConfigMutationCapacityReservation, error)
	RedactReason    func(context.Context, *string) (*string, error)
}

type PinnedConfigMutationAuthority struct {
	installation string
	sources      ConfigMutationAuthoritySources
}

func NewPinnedConfigMutationAuthority(installation string, sources ConfigMutationAuthoritySources) (*PinnedConfigMutationAuthority, error) {
	if !configMutationInstallation.MatchString(installation) || sources.CheckSession == nil || sources.RegistryBytes == nil || sources.StrongAuth == nil || sources.ReserveMetadata == nil || sources.RedactReason == nil {
		return nil, ErrRegistrationUnavailable
	}
	return &PinnedConfigMutationAuthority{installation, sources}, nil
}

func (a *PinnedConfigMutationAuthority) valid(ctx context.Context, tx *sql.Tx, installation string, now time.Time) bool {
	return a != nil && ctx != nil && ctx.Err() == nil && tx != nil && installation == a.installation && !now.IsZero() && a.sources.CheckSession != nil && a.sources.RegistryBytes != nil && a.sources.StrongAuth != nil && a.sources.ReserveMetadata != nil && a.sources.RedactReason != nil
}
func (a *PinnedConfigMutationAuthority) Authorize(ctx context.Context, tx *sql.Tx, actor RegistrationActor, installation string, current, proposed ConfigValues, risk ConfigMutationRisk, now time.Time) error {
	if !a.valid(ctx, tx, installation, now) || len(current.CanonicalJSON()) < 2 || len(proposed.CanonicalJSON()) < 2 {
		return ErrRegistrationUnavailable
	}
	if err := a.sources.CheckSession(ctx, tx, installation, actor, now); err != nil {
		return registrationBoundaryError(err)
	}
	oldPin, newPin := configMutationRBACPin(current), configMutationRBACPin(proposed)
	oldRaw, err := a.sources.RegistryBytes(oldPin.Kind, oldPin.Version, oldPin.SHA256)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	if len(oldRaw) < 2 || len(oldRaw) > 262144 {
		return ErrRegistrationUnavailable
	}
	oldRaw = append([]byte(nil), oldRaw...)
	newRaw, err := a.sources.RegistryBytes(newPin.Kind, newPin.Version, newPin.SHA256)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	if len(newRaw) < 2 || len(newRaw) > 262144 {
		return ErrRegistrationUnavailable
	}
	newRaw = append([]byte(nil), newRaw...)
	comparison, err := VerifyConfigMutationRBAC(installation, actor, current, proposed, oldRaw, newRaw, risk)
	if err != nil {
		return err
	}
	// A privileged caller still needs MFA for an actual RBAC change. Do not
	// silently discover a stronger risk here and let the caller's earlier false
	// classification skip nonce/proof handling in the transaction service.
	if comparison.Risk() != risk {
		return ErrRegistrationUnavailable
	}
	return nil
}
func (a *PinnedConfigMutationAuthority) StrongAuth(ctx context.Context, tx *sql.Tx, actor RegistrationActor, installation string, current ConfigValues, versions []string, now time.Time) (VerifyConfig, error) {
	if !a.valid(ctx, tx, installation, now) || len(current.CanonicalJSON()) < 2 || len(versions) == 0 {
		return VerifyConfig{}, ErrRegistrationUnavailable
	}
	return a.sources.StrongAuth(ctx, tx, actor, installation, current, append([]string(nil), versions...), now)
}
func (a *PinnedConfigMutationAuthority) Reserve(ctx context.Context, tx *sql.Tx, current, proposed ConfigValues, bytes int, now time.Time) (ConfigMutationCapacityReservation, error) {
	if a == nil || !a.valid(ctx, tx, a.installation, now) || len(current.CanonicalJSON()) < 2 || len(proposed.CanonicalJSON()) < 2 || bytes < 1 || bytes > 1048576 {
		return nil, ErrRegistrationUnavailable
	}
	r, err := a.sources.ReserveMetadata(ctx, tx, current, proposed, bytes, now)
	if err != nil {
		return nil, registrationBoundaryError(err)
	}
	if nilConfigMutationBoundary(r) || !now.Before(r.ValidUntil()) {
		return nil, ErrRegistrationUnavailable
	}
	return r, nil
}
func (a *PinnedConfigMutationAuthority) RedactReason(ctx context.Context, reason *string) (*string, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || a.sources.RedactReason == nil {
		return nil, ErrRegistrationUnavailable
	}
	var input *string
	if reason != nil {
		copy := *reason
		input = &copy
	}
	redacted, err := a.sources.RedactReason(ctx, input)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	if redacted == nil {
		return nil, nil
	}
	copy := *redacted
	return &copy, nil
}
