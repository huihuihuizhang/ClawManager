package systembackupevidence

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// GCAuthorityConfig is reviewed deployment admission, never request JSON. A
// separate GC worker certificate, projected token and delete credential mapping
// are required. One authority is tied to one system evidence_gc operation claim.
type GCAuthorityConfig struct {
	Registry                             SQLRegistry
	ConfigVersion                        int64
	ConfigSHA256, Root                   string
	Store, Delete                        KeyRef
	OperationID, OperationClaim          string
	OperationRowVersion                  int64
	ClientCAPEM                          []byte
	ClientCASHA256, CertificateSHA256    string
	Issuer, Audience, Subject, TokenFile string
	ExpiresAt                            time.Time
}

type SQLGCAuthority struct {
	c         GCAuthorityConfig
	roots     *x509.CertPool
	principal string
	journal   *gcFailureJournal
}

var _ S3WebIdentityAuthority = (*SQLGCAuthority)(nil)
var gcOperationID = regexp.MustCompile(`^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func NewSQLGCAuthority(c GCAuthorityConfig) (*SQLGCAuthority, error) {
	u, err := url.Parse(c.Issuer)
	if c.Registry.DB == nil || nilSystemAdapter(c.Registry.Policy) || !installationPattern.MatchString(c.Registry.Installation) || c.Registry.ServerUUID == "" || c.Registry.Database == "" ||
		c.ConfigVersion < 1 || !digestPattern.MatchString(c.ConfigSHA256) || !safeKey(c.Root) || !c.Store.valid() || !c.Delete.valid() ||
		!gcOperationID.MatchString(c.OperationID) || !s3Token([]byte(c.OperationClaim), 1, 128) || c.OperationRowVersion < 1 ||
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
		Installation, Certificate, Operation, Claim, ConfigHash, Subject string
		Version, Row                                                     int64
	}{c.Registry.Installation, c.CertificateSHA256, c.OperationID, c.OperationClaim, c.ConfigSHA256, c.Subject, c.ConfigVersion, c.OperationRowVersion}))
	return &SQLGCAuthority{c: c, roots: roots, principal: principal}, nil
}

func (a *SQLGCAuthority) AuthenticateRequest(r *http.Request) (context.Context, error) {
	if a == nil {
		return nil, ErrAuth
	}
	if a.journal != nil && a.journal.check() != nil {
		return nil, ErrUnavailable
	}
	return authenticatePinnedPeer(r, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
}

type gcGrant struct {
	record Record
	until  time.Time
	lease  string
}

// AuthorizeS3 permits only exact immutable-version Stat and Delete. No producer,
// plaintext read, KEK, unversioned delete or deadline-expired PUT is granted.
func (a *SQLGCAuthority) AuthorizeS3(ctx context.Context, scope S3Scope) (S3WebIdentityGrant, error) {
	grant, err := a.authorize(ctx, scope)
	if err != nil {
		return S3WebIdentityGrant{}, ErrDenied
	}
	token, expires, err := readProjectedToken(a.c.TokenFile, a.c.Issuer, a.c.Audience, a.c.Subject)
	if err != nil {
		return S3WebIdentityGrant{}, ErrDenied
	}
	if ctx.Err() != nil || !time.Now().Before(grant.until) || a.journal != nil && a.journal.check() != nil {
		wipe(token)
		return S3WebIdentityGrant{}, ErrDenied
	}
	return S3WebIdentityGrant{Authorization: S3Authorization{Scope: scope, Evidence: grant.record.Manifest.Identity, ConfigVersion: a.c.ConfigVersion, AccessKind: "gc", PrincipalHash: a.principal, LeaseHash: grant.lease, Subject: a.c.Subject, ExpiresAt: grant.until}, Token: token, TokenExpiresAt: expires}, nil
}

func (a *SQLGCAuthority) authorize(ctx context.Context, scope S3Scope) (gcGrant, error) {
	deny := func() (gcGrant, error) { return gcGrant{}, ErrDenied }
	if a == nil || a.journal != nil && a.journal.check() != nil {
		return deny()
	}
	until, err := pinnedPeerExpiry(ctx, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
	if err != nil {
		return deny()
	}
	access, ok := ctx.Value(evidenceAccessKey{}).(evidenceAccess)
	if !ok || !idPattern.MatchString(access.ID) {
		return deny()
	}
	if _, ok = evidenceAccessFrom(ctx, "gc", access.ID); !ok {
		return deny()
	}
	c, s := a.c, a.c.Registry
	if !scope.Ref.valid(true) || scope.Ref.Identity != c.Store.Identity || scope.Ref.Version != c.Store.Version || scope.Offset != 0 || scope.Length != 0 || !scope.Deadline.IsZero() ||
		!(scope.Operation == S3Stat && scope.Object == (ObjectInfo{}) || scope.Operation == S3Delete && scope.Object.Version == scope.Ref.ImmutableVersion) {
		return deny()
	}
	tx, _, err := s.begin(ctx)
	if err != nil {
		return deny()
	}
	defer tx.Rollback()
	if _, err := a.lockConfig(ctx, tx); err != nil {
		return deny()
	}
	// The mandatory D policy locks the owner/reference scope before evidence.
	// GC remains allowed while scheduled backups are disabled.
	i := Identity{Installation: s.Installation, ID: access.ID}
	if tx.QueryRowContext(ctx, "SELECT owner_target_type,owner_target_public_id FROM system_backup_v2_evidence WHERE public_id=?", access.ID).Scan(&i.OwnerType, &i.OwnerID) != nil || s.Policy.LockScope(ctx, tx, s.Installation, i) != nil {
		return deny()
	}
	op, err := a.lockOperation(ctx, tx)
	if err != nil {
		return deny()
	}
	opUntil, deadline, rowVersion := op.until, op.deadline, op.rowVersion
	r, err := s.load(ctx, tx, access.ID)
	if err != nil || r.Manifest.Identity.OwnerType != i.OwnerType || r.Manifest.Identity.OwnerID != i.OwnerID || r.State != "deleting" || r.Ref != scope.Ref || r.Claim != access.Claim || r.RowVersion != access.RowVersion {
		return deny()
	}
	key, err := keyFor(c.Root, r.Manifest.Identity)
	if err != nil || key != r.Ref.RelativeKey {
		return deny()
	}
	if scope.Operation == S3Delete && scope.Object != (ObjectInfo{Version: r.Ref.ImmutableVersion, SHA256: r.Manifest.ObjectHash, Size: r.Manifest.ObjectSize}) {
		return deny()
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || now.Before(r.ExpiresAt) || now.Before(r.ProtectedUntil) || s.Policy.Deletable(ctx, tx, r, now) != nil {
		return deny()
	}
	until = earlier(earlier(earlier(until, opUntil), deadline), r.ClaimUntil)
	// Deletable itself can wait on locks; resample after every policy check.
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(until) || time.Since(now) > 5*time.Second || time.Until(now) > 5*time.Second {
		return deny()
	}
	lease := hash(canonical(struct {
		Access                               evidenceAccess
		Manifest                             Manifest
		Ref                                  Ref
		ClaimUntil, OperationUntil, Deadline time.Time
		OperationRow                         int64
	}{access, r.Manifest, r.Ref, r.ClaimUntil, opUntil, deadline, rowVersion}))
	if a.journal != nil && a.journal.check() != nil || tx.Commit() != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return deny()
	}
	return gcGrant{record: r, until: until, lease: lease}, nil
}

// GCAbsenceVerifier wraps the independently trusted C-owned proof verifier.
// An absence proof cannot be requested or accepted after GC authorization loss.
// This wrapper authenticates the caller; it does not manufacture provider proof.
type GCAbsenceVerifier struct {
	Authority *SQLGCAuthority
	Verifier  S3AbsenceVerifier
}

func (v GCAbsenceVerifier) VerifyAbsent(ctx context.Context, request S3AbsenceRequest) (S3AbsenceProof, error) {
	if v.Authority == nil || nilSystemAdapter(v.Verifier) {
		return S3AbsenceProof{}, ErrDenied
	}
	scope := S3Scope{Ref: request.Ref, Operation: S3Stat}
	before, err := v.Authority.authorize(ctx, scope)
	if err != nil {
		return S3AbsenceProof{}, ErrDenied
	}
	proof, err := v.Verifier.VerifyAbsent(ctx, request)
	if err != nil {
		return S3AbsenceProof{}, ErrUnavailable
	}
	after, err := v.Authority.authorize(ctx, scope)
	if err != nil || after.lease != before.lease || proof.Request != request || ctx.Err() != nil {
		return S3AbsenceProof{}, ErrDenied
	}
	return proof, nil
}
