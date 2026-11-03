package systembackupinstallationowner

import (
	"bytes"
	"context"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Detached SQL data, not an approval or a transaction capability. Only the
// concrete resource check can retain this tuple under the caller's guarded
// transaction. Indexed revocation remains observable without a live provider.
type SigningResourceSnapshot struct {
	pin                                    SigningResourceTrustPin
	grant                                  SigningResourceGrant
	head                                   SigningResourceHead
	cas                                    SigningResourceCAS
	raw, signature, headRaw, headSignature []byte
}

func (*SigningResourceSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrOwner }

func (s *SigningResourceSnapshot) Comparison() (SigningResourceCAS, error) {
	if s == nil {
		return SigningResourceCAS{}, ErrOwner
	}
	return s.cas, nil
}

func (s *SigningResourceSnapshot) SignedRecords() (grant, grantSignature, head, headSignature []byte, err error) {
	if s == nil {
		return nil, nil, nil, nil, ErrOwner
	}
	return bytes.Clone(s.raw), bytes.Clone(s.signature), bytes.Clone(s.headRaw), bytes.Clone(s.headSignature), nil
}

func (s *SigningResourceSnapshot) Declarations() (SigningResourceGrant, SigningResourceHead, error) {
	if s == nil {
		return SigningResourceGrant{}, SigningResourceHead{}, ErrOwner
	}
	g, e := InspectSigningResourceGrant(s.raw, s.signature, s.pin)
	h, f := InspectSigningResourceHead(s.headRaw, s.headSignature, s.pin)
	if e != nil || f != nil {
		return SigningResourceGrant{}, SigningResourceHead{}, ErrOwner
	}
	return g, h, nil
}

func (s *SigningResourceSnapshot) RequireCurrent(now time.Time) error {
	if s == nil || !validTime(now) || s.cas.State != "active" || now.Before(s.grant.NotBefore) || !now.Before(s.grant.Until) || now.Before(s.head.NotBefore) || !now.Before(s.head.Until) {
		return ErrOwner
	}
	return nil
}

// Candidate L2 only: original admin and capture/MinIO prefixes precede this
// domain. Read acceptance head/grant BEFORE catalog head/grant. No operation,
// config or provider I/O occurs here, and all time uses the shared SampleTime.
// A raw *sql.Tx cannot satisfy this interface or create a retained guard.
func ReadSigningResourceCandidate(ctx context.Context, q pd.BootstrapReadSQL, pin SigningResourceTrustPin) (*SigningResourceSnapshot, error) {
	return readSigningResourceCurrent(ctx, q, pin, pin.Target.DatabaseAccount)
}

// Detached current-row DATA for D's actual authenticated installer lifecycle.
// The caller selects the independent plan's distinct installer account and
// supplies its authenticated SQL-clock view under the already-held admin
// prefix. This does NOT mint a terminal guard or authenticate a password/key.
func ReadSigningResourceForInstaller(ctx context.Context, q pd.BootstrapReadSQL, pin SigningResourceTrustPin, installerAccount string) (*SigningResourceSnapshot, error) {
	if !validText(installerAccount) || installerAccount == pin.Target.DatabaseAccount {
		return nil, ErrOwner
	}
	return readSigningResourceCurrent(ctx, q, pin, installerAccount)
}

func readSigningResourceCurrent(ctx context.Context, q pd.BootstrapReadSQL, pin SigningResourceTrustPin, expectedAccount string) (*SigningResourceSnapshot, error) {
	if !sameContext(ctx, ctx) || ctx.Err() != nil || nilInterface(q) || !signingPinValid(pin) {
		return nil, ErrOwner
	}
	before, e := q.SampleTime(ctx)
	if e != nil || !validTime(before) {
		return nil, ErrOwner
	}
	var account, server, database string
	if q.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE()`).Scan(&account, &server, &database) != nil || account != expectedAccount || server != pin.Target.ServerUUID || database != pin.Target.Database {
		return nil, ErrOwner
	}
	var username, role, provider string
	var active bool
	if q.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, pin.Actor.UserID).Scan(&username, &role, &active, &provider) != nil || username != pin.Actor.Username || role != "admin" || !active || provider != "local" {
		return nil, ErrOwner
	}
	s := &SigningResourceSnapshot{pin: pin}
	s.pin.Issuer = bytes.Clone(pin.Issuer)
	var epoch, grantRevision uint64
	if q.QueryRowContext(ctx, SigningResourceHeadReadSQL, pin.Target.InstallationID, pin.EnrollmentID, pin.AuthorityID, pin.Purpose).Scan(&s.cas.HeadRevision, &epoch, &s.cas.GrantID, &grantRevision, &s.cas.HeadSHA256, &s.headRaw, &s.headSignature, &s.cas.State, &s.cas.HeadRowVersion) != nil || s.cas.HeadRowVersion == 0 || s.cas.HeadRowVersion > 9007199254740991 || digest(s.headRaw) != s.cas.HeadSHA256 {
		return nil, ErrOwner
	}
	s.head, e = InspectSigningResourceHead(s.headRaw, s.headSignature, pin)
	if e != nil || s.head.HeadRevision != s.cas.HeadRevision || s.head.PermissionEpoch != epoch || s.head.CurrentGrantID != s.cas.GrantID || s.head.CurrentGrantRevision != grantRevision || s.head.State != s.cas.State {
		return nil, ErrOwner
	}
	var grantState string
	if q.QueryRowContext(ctx, SigningResourceGrantReadSQL, pin.Target.InstallationID, pin.EnrollmentID, pin.AuthorityID, pin.Purpose, pin.GrantID, pin.GrantRevision).Scan(&s.cas.PermissionEpoch, &s.cas.GrantSHA256, &s.raw, &s.signature, &grantState, &s.cas.GrantRowVersion) != nil || s.cas.GrantRowVersion == 0 || s.cas.GrantRowVersion > 9007199254740991 || s.cas.PermissionEpoch != epoch || s.cas.GrantSHA256 != pin.GrantSHA256 || grantState != s.cas.State {
		return nil, ErrOwner
	}
	s.grant, e = InspectSigningResourceGrant(s.raw, s.signature, pin)
	if e != nil || !s.grant.NotBefore.Equal(s.head.NotBefore) || !s.grant.Until.Equal(s.head.Until) {
		return nil, ErrOwner
	}
	s.cas.GrantRevision = grantRevision
	after, e := q.SampleTime(ctx)
	if e != nil || !validTime(after) || after.Before(before) || ctx.Err() != nil {
		return nil, ErrOwner
	}
	// Revoked snapshots are DATA for independent current-state diagnostics.
	// The concrete admission check always calls RequireCurrent, including replay.
	return s, nil
}
