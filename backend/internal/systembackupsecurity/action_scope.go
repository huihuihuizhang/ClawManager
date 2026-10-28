package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sync"
	"time"
)

const CreateSystemBackup = "createSystemBackup"
const CreateSystemBackupPreflight = "createSystemBackupPreflight"

var ErrSystemBackupActionValidation = errors.New("validation_failed")

// SystemBackupActionAuthorizer uses the SAME login recorder and deployment pins
// as reads. It covers only v12's two first-chain create actions. Their policy is
// operate + idempotency, with recent_strong_auth=none. It does not grant config,
// provider, sensitive-download, cancel, restore, or destructive permissions.
type SystemBackupActionAuthorizer struct{ read *SystemBackupReadAuthorizer }

// LoadSystemBackupActionAuthorizer reads the existing SystemBackupReadPins
// format; no second session key, new role registry, or authorization file exists.
func LoadSystemBackupActionAuthorizer(sessions *SQLLoginSessions, path, digest string) (*SystemBackupActionAuthorizer, error) {
	a, err := LoadSystemBackupReadAuthorizer(sessions, path, digest)
	if err != nil {
		return nil, err
	}
	return &SystemBackupActionAuthorizer{read: a}, nil
}

// Copies share the transaction binding. Never pass a client-supplied actor to
// the business service; use Actor only AFTER AuthorizeAction succeeds there.
type SystemBackupActionScope struct{ state *actionScopeState }
type actionScopeState struct {
	mu             sync.Mutex
	config         readScopeConfig
	actor          RegistrationActor
	ctx            context.Context
	tx             *sql.Tx
	failed         bool
	operation, key string
}
type actionScopeContextKey struct{}

func (SystemBackupActionScope) String() string               { return "SystemBackupActionScope" }
func (SystemBackupActionScope) GoString() string             { return "SystemBackupActionScope" }
func (SystemBackupActionScope) MarshalJSON() ([]byte, error) { return nil, ErrRegistrationUnavailable }
func (*SystemBackupActionScope) UnmarshalJSON([]byte) error  { return ErrRegistrationUnavailable }

// Scope performs transport/session-token checks only. Live SQL session,
// credential revocation and RBAC MUST be checked in the business transaction.
// D still owns decoding, request hash/idempotency persistence, effective-enabled,
// capacity, business admission, audit/evidence, and the single commit.
func (a *SystemBackupActionAuthorizer) Scope(r *http.Request, operation string) (*SystemBackupActionScope, error) {
	if a == nil || a.read == nil || a.read.sessions == nil {
		return nil, ErrRegistrationUnavailable
	}
	if r == nil || r.Context().Err() != nil {
		return nil, ErrSystemBackupReadAuthentication
	}
	path := ""
	switch operation {
	case CreateSystemBackup:
		path = "/api/v1/admin/system-backups"
	case CreateSystemBackupPreflight:
		path = "/api/v1/admin/system-backup-preflights"
	default:
		return nil, ErrRegistrationPermission
	}
	if r.URL == nil || r.Method != http.MethodPost || r.URL.Path != path || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.TLS == nil {
		return nil, ErrRegistrationPermission
	}
	if len(r.Header.Values("Idempotency-Key")) != 1 || !validIdempotencyKey(r.Header.Get("Idempotency-Key")) {
		return nil, ErrSystemBackupActionValidation
	}
	actor, err := (JWTRegistrationAuthenticator{Secret: a.read.sessions.secret}).Authenticate(r)
	if err != nil || actor.SessionIssuedAt.IsZero() || !time.Now().Before(actor.SessionExpiresAt) {
		return nil, ErrSystemBackupReadAuthentication
	}
	s := &SystemBackupActionScope{state: &actionScopeState{config: readScopeConfig{database: a.read.sessions.identity, pins: a.read.pins}, actor: actor, operation: operation, key: r.Header.Get("Idempotency-Key")}}
	s.state.ctx = context.WithValue(r.Context(), actionScopeContextKey{}, s.state)
	return s, nil
}

func (s *SystemBackupActionScope) Context() context.Context {
	if s == nil || s.state == nil {
		return nil
	}
	return s.state.ctx
}
func (s *SystemBackupActionScope) Actor() RegistrationActor {
	if s == nil || s.state == nil {
		return RegistrationActor{}
	}
	return s.state.actor
}
func (s *SystemBackupActionScope) IdempotencyKey() string {
	if s == nil || s.state == nil {
		return ""
	}
	return s.state.key
}

// Call before business locks, for fresh work AND exact committed replays. On
// any failure the caller must roll back. No transaction is opened or committed.
func (s *SystemBackupActionScope) AuthorizeAction(ctx context.Context, tx *sql.Tx) (string, error) {
	if err := s.check(ctx, tx); err != nil {
		return "", err
	}
	return s.state.config.pins.InstallationID, nil
}

// Call again after business writes, before commit. It rejects another request,
// transaction, expired/revoked credentials, changed pins, and ignored failures.
func (s *SystemBackupActionScope) RecheckAction(ctx context.Context, tx *sql.Tx, installation string) error {
	if s == nil || s.state == nil {
		return ErrRegistrationPermission
	}
	if installation != s.state.config.pins.InstallationID {
		s.state.mu.Lock()
		s.state.failed = true
		s.state.mu.Unlock()
		return ErrRegistrationPermission
	}
	return s.check(ctx, tx)
}
func (s *SystemBackupActionScope) check(ctx context.Context, tx *sql.Tx) error {
	if s == nil || s.state == nil {
		return ErrRegistrationPermission
	}
	p := s.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || ctx == nil || ctx.Err() != nil || p.ctx == nil || p.ctx.Err() != nil || ctx.Value(actionScopeContextKey{}) != p || tx == nil || (p.tx != nil && p.tx != tx) || !time.Now().Before(p.actor.SessionExpiresAt) {
		p.failed = true
		return ErrRegistrationPermission
	}
	p.tx = tx
	if err := p.config.checkSessionPermissions(ctx, tx, p.actor, []string{"system_backup.operate"}); err != nil {
		p.failed = true
		return err
	}
	return nil
}
