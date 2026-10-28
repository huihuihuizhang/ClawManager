package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackupsecurity"
)

// SensitiveDownloadProof is supplied by the A security runtime. VerifyAndConsume
// must bind a fresh proof to the authenticated actor, evidence ID, claim and
// byte range, and consume its nonce in the supplied claim/audit transaction.
// An implementation that only checks a session or RBAC does not satisfy it.
type SensitiveDownloadProof interface {
	VerifyAndConsume(context.Context, *sql.Tx, *http.Request, Actor, Record, int64, int64) error
}

// DownloadAuthorityConfig is deployment-owned. SQLRegistry's mandatory policy
// still supplies authoritative owner visibility/locking and audit; this adapter
// adds the live authenticated session, pinned RBAC and exact read credentials.
// It is not an alternative permissive SQLPolicy or an HTTP configuration DTO.
type DownloadAuthorityConfig struct {
	Registry                                                 SQLRegistry
	JWTSecret                                                []byte
	ConfigVersion                                            int64
	ConfigSHA256, RBACVersion, RBACSHA256, RegistryDirectory string
	Root                                                     string
	Store, Read                                              KeyRef
	Issuer, Audience, Subject, TokenFile                     string
	ExpiresAt                                                time.Time
	SensitiveStepUp                                          SensitiveDownloadProof
}

type SQLDownloadAuthority struct {
	c       DownloadAuthorityConfig
	journal *DownloadFailureJournal
}

var _ BoundDownloadAuthenticator = (*SQLDownloadAuthority)(nil)
var _ S3WebIdentityAuthority = (*SQLDownloadAuthority)(nil)

func NewSQLDownloadAuthority(c DownloadAuthorityConfig) (*SQLDownloadAuthority, error) {
	u, err := url.Parse(c.Issuer)
	if c.Registry.DB == nil || c.Registry.Policy == nil || !installationPattern.MatchString(c.Registry.Installation) || c.Registry.ServerUUID == "" || c.Registry.Database == "" ||
		len(c.JWTSecret) < 32 || c.ConfigVersion < 1 || !digestPattern.MatchString(c.ConfigSHA256) || !digestPattern.MatchString(c.RBACSHA256) || !versionPattern.MatchString(c.RBACVersion) ||
		!filepath.IsAbs(c.RegistryDirectory) || !safeKey(c.Root) || !c.Store.valid() || !c.Read.valid() || !filepath.IsAbs(c.TokenFile) || !time.Now().Before(c.ExpiresAt) ||
		err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(c.Issuer, "?#") || !s3Token([]byte(c.Issuer), 9, 2048) ||
		!s3Token([]byte(c.Audience), 1, 255) || !s3Token([]byte(c.Subject), 6, 255) {
		return nil, ErrInvalid
	}
	c.JWTSecret = append([]byte(nil), c.JWTSecret...)
	return &SQLDownloadAuthority{c: c}, nil
}

func downloadActor(a systembackupsecurity.RegistrationActor) Actor {
	return Actor{ID: strconv.FormatInt(a.UserID, 10), Session: a.Session}
}

func (a *SQLDownloadAuthority) Authenticate(r *http.Request) (Actor, error) {
	_, actor, err := a.AuthenticateContext(r)
	return actor, err
}

func (a *SQLDownloadAuthority) AuthenticateContext(r *http.Request) (context.Context, Actor, error) {
	if a == nil || r == nil || r.TLS == nil || !time.Now().Before(a.c.ExpiresAt) || a.journal != nil && a.journal.Check() != nil {
		return nil, Actor{}, ErrAuth
	}
	actor, err := (systembackupsecurity.JWTRegistrationAuthenticator{Secret: a.c.JWTSecret}).Authenticate(r)
	if err != nil || r.Context().Err() != nil {
		return nil, Actor{}, ErrAuth
	}
	ctx := withVerifiedDownloadActor(r.Context(), a.c.Registry, actor)
	return context.WithValue(ctx, a, actor), downloadActor(actor), nil
}

func (a *SQLDownloadAuthority) AuthorizeSensitiveDownload(ctx context.Context, request *http.Request, actor Actor, record Record, start, end int64, locked Locked) error {
	tx, ok := locked.(*sqlLocked)
	if a == nil || request == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(a.c.SensitiveStepUp) ||
		!ok || tx.tx == nil || tx.registry.DB != a.c.Registry.DB || tx.registry.Installation != a.c.Registry.Installation ||
		tx.Record().Claim != record.Claim || tx.Record().RowVersion != record.RowVersion ||
		tx.Record().Manifest.Identity != record.Manifest.Identity ||
		start < 0 || end < start || end >= record.Manifest.Identity.ContentSize ||
		!oneOf(record.Manifest.Identity.Classification, "confidential", "sensitive") {
		return ErrDenied
	}
	if err := a.c.SensitiveStepUp.VerifyAndConsume(ctx, tx.tx, request, actor, record, start, end); err != nil {
		return ErrDenied
	}
	return nil
}

type downloadGrant struct {
	record           Record
	actor            Actor
	until            time.Time
	principal, lease string
}

func (a *SQLDownloadAuthority) AuthorizeDownload(ctx context.Context, actor Actor, r Record) error {
	g, err := a.authorize(ctx)
	if err != nil || g.actor != actor || g.record.Ref != r.Ref || g.record.RowVersion != r.RowVersion || g.record.Claim != r.Claim ||
		hash(canonical(g.record.Manifest)) != hash(canonical(r.Manifest)) {
		if c := committedDownloadFrom(ctx); c != nil {
			c.fail()
		}
		return ErrDenied
	}
	return nil
}

func (a *SQLDownloadAuthority) AuthorizeS3(ctx context.Context, scope S3Scope) (S3WebIdentityGrant, error) {
	deny := func() (S3WebIdentityGrant, error) {
		if c := committedDownloadFrom(ctx); c != nil {
			c.fail()
		}
		return S3WebIdentityGrant{}, ErrDenied
	}
	if scope.Object != (ObjectInfo{}) || !scope.Deadline.IsZero() ||
		!(scope.Operation == S3Stat && scope.Offset == 0 && scope.Length == 0 || scope.Operation == S3Range && scope.Offset >= 0 && scope.Length > 0 && scope.Length <= ChunkSize+28) {
		return deny()
	}
	g, err := a.authorize(ctx)
	if err != nil || scope.Ref != g.record.Ref || scope.Operation == S3Range && scope.Offset > g.record.Manifest.ObjectSize-scope.Length {
		return deny()
	}
	if c := committedDownloadFrom(ctx); c != nil && (!c.live(ctx, a) || !c.allowsS3(scope)) {
		return deny()
	}
	token, expiry, err := readProjectedToken(a.c.TokenFile, a.c.Issuer, a.c.Audience, a.c.Subject)
	if err != nil {
		return deny()
	}
	if ctx.Err() != nil || !time.Now().Before(g.until) {
		wipe(token)
		return deny()
	}
	if c := committedDownloadFrom(ctx); c != nil && !c.live(ctx, a) {
		wipe(token)
		return deny()
	}
	return S3WebIdentityGrant{Authorization: S3Authorization{Scope: scope, Evidence: g.record.Manifest.Identity, ConfigVersion: a.c.ConfigVersion, AccessKind: "download", PrincipalHash: g.principal, LeaseHash: g.lease, Subject: a.c.Subject, ExpiresAt: g.until}, Token: token, TokenExpiresAt: expiry}, nil
}

// DownloadKeys binds the wrapped DEK to the database envelope before invoking
// the underlying keyring, then checks revocation again before returning a DEK.
// The underlying Transit resolver still needs real short-lived unwrap ACLs.
// No task write/wrap permission is inherited by the download session.
type DownloadKeys struct {
	Authority *SQLDownloadAuthority
	Keys      Keys
}

func (k DownloadKeys) Wrap(ctx context.Context, _ KeyRef, _ []byte) ([]byte, error) {
	if c := committedDownloadFrom(ctx); c != nil {
		c.fail()
	}
	return nil, ErrKey
}

func (k DownloadKeys) Unwrap(ctx context.Context, key KeyRef, wrapped []byte) (plain []byte, resultErr error) {
	defer func() {
		if resultErr != nil {
			if c := committedDownloadFrom(ctx); c != nil {
				c.fail()
			}
		}
	}()
	if k.Authority == nil || k.Keys == nil || len(wrapped) == 0 || len(wrapped) > 4096 {
		return nil, ErrKey
	}
	before, err := k.Authority.authorize(ctx)
	if err != nil || key != before.record.Manifest.Key {
		return nil, ErrKey
	}
	header := canonical(envelope{Framing, before.record.Manifest.Identity, key, base64.StdEncoding.EncodeToString(wrapped)})
	if hash(header) != before.record.Manifest.EnvelopeHash {
		return nil, ErrKey
	}
	dek, err := k.Keys.Unwrap(ctx, key, wrapped)
	if err != nil || len(dek) != 32 {
		wipe(dek)
		return nil, ErrKey
	}
	after, err := k.Authority.authorize(ctx)
	if err != nil || before.principal != after.principal || before.lease != after.lease || !time.Now().Before(before.until) || ctx.Err() != nil {
		wipe(dek)
		return nil, ErrKey
	}
	return dek, nil
}
