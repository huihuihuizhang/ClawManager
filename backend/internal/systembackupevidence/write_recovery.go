package systembackupevidence

import (
	"context"
	"crypto/x509"
	"database/sql"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// WriteRecoveryConfig is deployment-owned admission for a separate recovery
// worker. The evidence claim is its short-lived database lease; terminal task
// leases and GC operations are never borrowed. Current read ref/config drift,
// certificate/admission expiry and claim takeover revoke this authority.
type WriteRecoveryConfig struct {
	Registry                             SQLRegistry
	ConfigVersion                        int64
	ConfigSHA256, Root                   string
	Store, Read                          KeyRef
	ClientCAPEM                          []byte
	ClientCASHA256, CertificateSHA256    string
	Issuer, Audience, Subject, TokenFile string
	ExpiresAt                            time.Time
	// Persist a bounded health/reconciliation signal. No raw provider errors.
	Failure func(context.Context, string, string)
}

type SQLWriteRecovery struct {
	c         WriteRecoveryConfig
	roots     *x509.CertPool
	principal string
}
type RecoveryStat interface {
	Stat(context.Context, Ref) (ObjectInfo, error)
}

var _ S3WebIdentityAuthority = (*SQLWriteRecovery)(nil)

func NewSQLWriteRecovery(c WriteRecoveryConfig) (*SQLWriteRecovery, error) {
	u, err := url.Parse(c.Issuer)
	if c.Registry.DB == nil || c.Registry.Policy == nil || c.Failure == nil || !installationPattern.MatchString(c.Registry.Installation) || c.Registry.ServerUUID == "" || c.Registry.Database == "" ||
		c.ConfigVersion < 1 || !digestPattern.MatchString(c.ConfigSHA256) || !safeKey(c.Root) || !c.Store.valid() || !c.Read.valid() ||
		!digestPattern.MatchString(c.CertificateSHA256) || !digestPattern.MatchString(c.ClientCASHA256) || len(c.ClientCAPEM) == 0 || len(c.ClientCAPEM) > 65536 || hash(c.ClientCAPEM) != c.ClientCASHA256 ||
		!filepath.IsAbs(c.TokenFile) || !time.Now().Before(c.ExpiresAt) || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(c.Issuer, "?#") || !s3Token([]byte(c.Issuer), 9, 2048) || !s3Token([]byte(c.Audience), 1, 255) || !s3Token([]byte(c.Subject), 6, 255) {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.ClientCAPEM) {
		return nil, ErrInvalid
	}
	c.ClientCAPEM = nil
	principal := hash(canonical(struct {
		Installation, Certificate, ConfigHash, Subject string
		ConfigVersion                                  int64
		Read                                           KeyRef
	}{c.Registry.Installation, c.CertificateSHA256, c.ConfigSHA256, c.Subject, c.ConfigVersion, c.Read}))
	return &SQLWriteRecovery{c: c, roots: roots, principal: principal}, nil
}

func (a *SQLWriteRecovery) AuthenticateRequest(r *http.Request) (context.Context, error) {
	if a == nil {
		return nil, ErrAuth
	}
	return authenticatePinnedPeer(r, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
}

type recoveryGrant struct {
	record Record
	until  time.Time
	lease  string
}

// locked executes all admission, owner locks, manifest and optional mutation
// checks in one transaction. It never performs provider or filesystem I/O.
func (a *SQLWriteRecovery) locked(ctx context.Context, id string, claimed bool, fn func(*sqlLocked, time.Duration) error) (recoveryGrant, error) {
	fail := func(e error) (recoveryGrant, error) { return recoveryGrant{}, boundary(e) }
	if a == nil || !idPattern.MatchString(id) {
		return fail(ErrDenied)
	}
	until, err := pinnedPeerExpiry(ctx, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
	if err != nil {
		return fail(ErrDenied)
	}
	var access evidenceAccess
	if claimed {
		var ok bool
		access, ok = evidenceAccessFrom(ctx, "recovery", id)
		if !ok {
			return fail(ErrDenied)
		}
	}
	c, s := a.c, a.c.Registry
	tx, _, err := s.begin(ctx)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	retry, err := a.lockConfig(ctx, tx)
	if err != nil {
		return fail(err)
	}
	i := Identity{Installation: s.Installation, ID: id}
	if tx.QueryRowContext(ctx, "SELECT owner_target_type,owner_target_public_id FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&i.OwnerType, &i.OwnerID) != nil {
		return fail(ErrUnavailable)
	}
	if s.Policy.LockScope(ctx, tx, s.Installation, i) != nil {
		return fail(ErrDenied)
	}
	r, err := s.load(ctx, tx, id)
	if err != nil {
		return fail(err)
	}
	// System producer capability snapshots have a separate historical
	// authority. The legacy worker is bound to today's active config.
	if r.Manifest.Identity.OwnerType == "system" && r.Manifest.Identity.Type == "capability_snapshot" {
		return fail(ErrDenied)
	}
	if r.Manifest.Identity.OwnerType != i.OwnerType || r.Manifest.Identity.OwnerID != i.OwnerID || r.Ref.Identity != c.Store.Identity || r.Ref.Version != c.Store.Version {
		return fail(ErrDenied)
	}
	if !oneOf(r.State, "pending", "write_unknown") || r.Ref.ImmutableVersion != "" {
		return fail(ErrState)
	}
	key, err := keyFor(c.Root, r.Manifest.Identity)
	if err != nil || key != r.Ref.RelativeKey {
		return fail(ErrIntegrity)
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		return fail(ErrUnavailable)
	}
	if now.Before(r.OwnerDeadline) {
		return fail(ErrState)
	}
	if claimed {
		if r.Claim != access.Claim || r.RowVersion != access.RowVersion || !now.Before(r.ClaimUntil) {
			return fail(ErrConflict)
		}
		until = earlier(until, r.ClaimUntil)
	} else if r.Claim != "" && now.Before(r.ClaimUntil) {
		return fail(ErrConflict)
	}
	if !now.Before(until) || time.Since(now) > 5*time.Second || time.Until(now) > 5*time.Second {
		return fail(ErrDenied)
	}
	locked := &sqlLocked{registry: s, tx: tx, record: r, now: now}
	if fn != nil {
		if err = fn(locked, retry); err != nil {
			return fail(err)
		}
	}
	r = locked.record
	if !claimed {
		until = earlier(until, r.ClaimUntil)
	}
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(until) || time.Since(now) > 5*time.Second || time.Until(now) > 5*time.Second {
		return fail(ErrDenied)
	}
	lease := hash(canonical(struct {
		Principal     string
		Record        Record
		ConfigVersion int64
		Read          KeyRef
	}{a.principal, r, c.ConfigVersion, c.Read}))
	if tx.Commit() != nil {
		return fail(ErrUnavailable)
	}
	if ctx.Err() != nil || !time.Now().Before(until) {
		return fail(ErrDenied)
	}
	return recoveryGrant{record: r, until: until, lease: lease}, nil
}

func (a *SQLWriteRecovery) AuthorizeS3(ctx context.Context, scope S3Scope) (S3WebIdentityGrant, error) {
	access, ok := ctx.Value(evidenceAccessKey{}).(evidenceAccess)
	if a == nil || !ok || scope.Operation != S3Stat || scope.Object != (ObjectInfo{}) || scope.Offset != 0 || scope.Length != 0 || !scope.Deadline.IsZero() || scope.Ref.ImmutableVersion != "" {
		return S3WebIdentityGrant{}, ErrDenied
	}
	g, err := a.locked(ctx, access.ID, true, func(tx *sqlLocked, _ time.Duration) error {
		if tx.record.Ref != scope.Ref {
			return ErrDenied
		}
		return nil
	})
	if err != nil {
		return S3WebIdentityGrant{}, ErrDenied
	}
	token, expires, err := readProjectedToken(a.c.TokenFile, a.c.Issuer, a.c.Audience, a.c.Subject)
	if err != nil {
		return S3WebIdentityGrant{}, ErrDenied
	}
	if ctx.Err() != nil || !time.Now().Before(g.until) {
		wipe(token)
		return S3WebIdentityGrant{}, ErrDenied
	}
	return S3WebIdentityGrant{Authorization: S3Authorization{Scope: scope, Evidence: g.record.Manifest.Identity, ConfigVersion: a.c.ConfigVersion, AccessKind: "recovery", PrincipalHash: a.principal, LeaseHash: g.lease, Subject: a.c.Subject, ExpiresAt: g.until}, Token: token, TokenExpiresAt: expires}, nil
}

func (a *SQLWriteRecovery) signal(id, code string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a.c.Failure(ctx, id, code)
}

// Reconcile checks an existing deterministic key only. The narrow store cannot
// expose Put/Delete/Range/Absent or KEK methods. A failed Stat, including 404,
// leaves write_unknown and every ref/chunk intact. No owner row is updated.
// Runtime must use this same authority in the S3Store's STS resolver.
func (a *SQLWriteRecovery) Reconcile(ctx context.Context, id string, store RecoveryStat) error {
	if a == nil || store == nil || !idPattern.MatchString(id) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	claim, err := claimID()
	if err != nil {
		return err
	}
	g, err := a.locked(ctx, id, false, func(tx *sqlLocked, _ time.Duration) error {
		// The scanner is only a hint. Recheck scheduling under the evidence
		// lock so stale candidates and direct calls cannot bypass backoff.
		var due sql.NullTime
		if tx.tx.QueryRowContext(ctx, "SELECT next_reconcile_at FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", id).Scan(&due) != nil {
			return ErrUnavailable
		}
		if due.Valid && tx.now.Before(due.Time) {
			return ErrConflict
		}
		r := tx.record
		r.Claim = claim
		r.ClaimUntil = earlier(tx.now.Add(30*time.Second), a.c.ExpiresAt)
		r.RowVersion++
		if tx.Audit(ctx, Audit{ID: claim, Action: "evidence.recovery.intent", EvidenceID: id, ActorID: a.principal}) != nil {
			return ErrAudit
		}
		return tx.Save(ctx, r)
	})
	if err != nil {
		return err
	}
	ctx = withEvidenceAccess(ctx, "recovery", g.record)
	info, observed := store.Stat(ctx, g.record.Ref)
	if observed == nil && !matchObject(g.record, info) {
		observed = ErrIntegrity
	}
	_, err = a.locked(ctx, id, true, func(tx *sqlLocked, retry time.Duration) error {
		r := tx.record
		if r.Ref != g.record.Ref || hash(canonical(r.Manifest)) != hash(canonical(g.record.Manifest)) {
			return ErrConflict
		}
		switch observed {
		case nil:
			r.State = "ready"
			r.Failure = "none"
			r.Ref.ImmutableVersion = info.Version
		case ErrIntegrity:
			r.State = "write_failed"
			r.Failure = "checksum_mismatch"
		default:
			r.State = "write_unknown"
			r.Failure = "provider_unavailable"
		}
		r.Claim = ""
		r.ClaimUntil = time.Time{}
		r.RowVersion++
		if tx.Audit(ctx, Audit{ID: claim, Action: "evidence.recovery.result", EvidenceID: id, ActorID: a.principal, Outcome: r.State}) != nil {
			return ErrAudit
		}
		return tx.saveRecoveryResult(ctx, r, retry)
	})
	if err != nil {
		a.signal(id, "evidence_incomplete")
		return err
	}
	if observed != nil {
		code := "evidence_incomplete"
		if observed == ErrIntegrity {
			code = "checksum_mismatch"
		}
		a.signal(id, code)
	}
	return boundaryOrNil(observed)
}
