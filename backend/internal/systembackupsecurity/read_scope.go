package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// SystemBackupReadPins is a deployment-owned, SHA-256 pinned file. It has no
// user, token or request-derived fields. Rotation requires a new pin and
// reloading the authorizer; a stale pin fails closed against current SQL.
type SystemBackupReadPins struct {
	InstallationID    string `json:"installation_id"`
	ConfigVersion     int64  `json:"config_version"`
	RBACVersion       string `json:"rbac_registry_version"`
	RBACSHA256        string `json:"rbac_registry_sha256"`
	RegistryDirectory string `json:"registry_directory"`
}

// SystemBackupReadAuthorizer is tied to the same session recorder that
// registered access tokens at login. A missing recorder cannot grant reads.
type SystemBackupReadAuthorizer struct {
	sessions *SQLLoginSessions
	pins     SystemBackupReadPins
}

// SystemBackupReadScope is a request-bound systembackupread.ScopeProvider.
// Construct a fresh scope from the authenticated HTTP request for each read;
// neither query parameters nor cursors may select its installation.
type SystemBackupReadScope struct {
	config       readScopeConfig
	actor        RegistrationActor
	boundContext context.Context
}

type readScopeContextKey struct{}

type readScopeConfig struct {
	database DatabaseIdentity
	pins     SystemBackupReadPins
}

var readInstallationPattern = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)

var ErrSystemBackupReadAuthentication = errors.New("system_backup_read_authentication_required")

// LoadSystemBackupReadAuthorizer is the production construction path. The
// caller supplies a fixed absolute file path and its deployment-reviewed hash.
// The session recorder supplies the database identity, installation and JWT
// key; the file cannot select a different installation or token authority.
func LoadSystemBackupReadAuthorizer(sessions *SQLLoginSessions, path, digest string) (*SystemBackupReadAuthorizer, error) {
	if sessions == nil || sessions.db == nil || !sessions.identity.valid() ||
		!readInstallationPattern.MatchString(sessions.installation) || len(sessions.secret) < 32 ||
		!filepath.IsAbs(path) || !providerHashPattern.MatchString(digest) {
		return nil, ErrRegistrationUnavailable
	}
	raw, err := boundedFile(path, 32768)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	var pins SystemBackupReadPins
	if decodePinnedRegistry(raw, digest, &pins) != nil || pins.InstallationID != sessions.installation ||
		pins.ConfigVersion < 1 || !registryVersionPath.MatchString(pins.RBACVersion) ||
		strings.Contains(pins.RBACVersion, "..") || !providerHashPattern.MatchString(pins.RBACSHA256) ||
		!filepath.IsAbs(pins.RegistryDirectory) {
		return nil, ErrRegistrationUnavailable
	}
	return &SystemBackupReadAuthorizer{sessions: sessions, pins: pins}, nil
}

func (a *SystemBackupReadAuthorizer) Scope(request *http.Request) (*SystemBackupReadScope, error) {
	if a == nil || a.sessions == nil {
		return nil, ErrRegistrationUnavailable
	}
	if request == nil || request.Context().Err() != nil {
		return nil, ErrSystemBackupReadAuthentication
	}
	if request.Method != http.MethodGet {
		return nil, ErrRegistrationPermission
	}
	actor, err := (JWTRegistrationAuthenticator{Secret: a.sessions.secret}).Authenticate(request)
	if err != nil || actor.SessionIssuedAt.IsZero() || !time.Now().Before(actor.SessionExpiresAt) {
		return nil, ErrSystemBackupReadAuthentication
	}
	scope := &SystemBackupReadScope{config: readScopeConfig{database: a.sessions.identity, pins: a.pins}, actor: actor}
	scope.boundContext = context.WithValue(request.Context(), readScopeContextKey{}, scope)
	return scope, nil
}

// Context is the only context accepted by this scope and may be wrapped by
// timeout/cancellation contexts. The request's cancellation still propagates.
func (s *SystemBackupReadScope) Context() context.Context {
	if s == nil {
		return nil
	}
	return s.boundContext
}

func (s *SystemBackupReadScope) AuthorizeRead(ctx context.Context, tx *sql.Tx) (string, error) {
	if err := s.check(ctx, tx); err != nil {
		return "", err
	}
	return s.config.pins.InstallationID, nil
}

func (s *SystemBackupReadScope) RecheckRead(ctx context.Context, tx *sql.Tx, installation string) error {
	if s == nil || installation != s.config.pins.InstallationID {
		return ErrRegistrationPermission
	}
	return s.check(ctx, tx)
}

func (s *SystemBackupReadScope) check(ctx context.Context, tx *sql.Tx) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.boundContext == nil || s.boundContext.Err() != nil ||
		ctx.Value(readScopeContextKey{}) != s || tx == nil || !time.Now().Before(s.actor.SessionExpiresAt) {
		return ErrRegistrationPermission
	}
	return s.config.checkSessionPermissions(ctx, tx, s.actor, []string{"system_backup.read"})
}

// Shared by read scopes and the two first-chain actions. Permissions are fixed
// by those constructors, never accepted from HTTP input or a caller's role.
func (c readScopeConfig) checkSessionPermissions(ctx context.Context, tx *sql.Tx, actor RegistrationActor, permissions []string) error {
	if err := c.database.check(ctx, tx); err != nil {
		return err
	}
	// Follow the existing registration lock order: installation, config,
	// then user/session. Holding these locks through the caller's commit closes
	// the final-check race with config rotation and session revocation.
	if err := lockRegistrationInstallations(ctx, tx); err != nil {
		return err
	}
	current, err := lockRegistrationConfig(ctx, tx, c.pins.InstallationID)
	if err != nil {
		return err
	}
	if current.Version != c.pins.ConfigVersion || current.RBACRegistryVersion != c.pins.RBACVersion || current.RBACRegistrySHA256 != c.pins.RBACSHA256 {
		return ErrRegistrationUnavailable
	}
	until, err := CheckRegistrationSessionUntil(ctx, tx, c.pins.InstallationID, actor)
	if err != nil {
		return err
	}
	if !time.Now().Before(until) {
		return ErrRegistrationPermission
	}
	raw, err := (RegistrationFiles{RegistryDirectory: c.pins.RegistryDirectory}).RegistryBytes("rbac_bindings", current.RBACRegistryVersion, current.RBACRegistrySHA256)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	defer wipeSecret(raw)
	return AuthorizeEvidencePermissions(raw, current.RBACRegistrySHA256, current.RBACRegistryVersion,
		c.pins.InstallationID, actor, permissions)
}
