package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Compose the real authenticator, pinned authority and SQL session check with
// the real mutation service. This transport is a model, not a MySQL lock test.
type mutationASessionState struct {
	base          *mutationTestState
	actor         RegistrationActor
	password      string
	credential    string
	expires       time.Time
	revoked       bool
	finalRevoke   bool
	revokedBefore *time.Time
	sessionChecks int
}

type mutationASessionConnector struct{ s *mutationASessionState }

func (c mutationASessionConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c mutationASessionConnector) Connect(context.Context) (driver.Conn, error) {
	return &mutationASessionConn{mutationTestConn{c.s.base}, c.s}, nil
}

type mutationASessionConn struct {
	mutationTestConn
	session *mutationASessionState
}

func (c *mutationASessionConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.session
	if !s.base.activeTx {
		return nil, errors.New("session query outside caller transaction")
	}
	switch {
	case strings.HasPrefix(query, "SELECT password_hash FROM users"):
		if len(args) != 1 || args[0].Value != s.actor.UserID || !strings.Contains(query, "FOR UPDATE") {
			return nil, errors.New("wrong credential lock")
		}
		return registrationRow(s.password), nil
	case strings.HasPrefix(query, "SELECT user_id,subject,credential_hash"):
		if len(args) != 2 || args[0].Value != "installation_synthetic" || args[1].Value != s.actor.Session || !strings.Contains(query, "FOR UPDATE") {
			return nil, errors.New("wrong session scope or lock")
		}
		s.sessionChecks++
		revoked := s.revoked || s.finalRevoke && len(s.base.working.writes) > 0
		return registrationRow(s.actor.UserID, s.actor.Subject, s.credential, s.expires, revoked, s.base.now), nil
	case strings.HasPrefix(query, "SELECT revoked_before"):
		if len(args) != 2 || args[0].Value != "installation_synthetic" || args[1].Value != s.actor.UserID || !strings.Contains(query, "FOR UPDATE") {
			return nil, errors.New("wrong revocation scope or lock")
		}
		if s.revokedBefore == nil {
			return &registrationTestRows{width: 1}, nil
		}
		return registrationRow(*s.revokedBefore), nil
	}
	return c.mutationTestConn.QueryContext(ctx, query, args)
}

func mutationASessionIntegrationFixture(t *testing.T) (ConfigMutationService, RegistrationActor, []byte, *mutationASessionState) {
	t.Helper()
	svc, _, _, base, _ := mutationTransactionFixture(t)
	base.now = time.Now().UTC().Truncate(time.Microsecond)
	secret := []byte(strings.Repeat("s", 32))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 42, "token_type": "access", "iat": base.now.Add(-time.Minute).Unix(), "exp": base.now.Add(time.Hour).Unix(),
	})
	rawToken, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("PUT", "https://control.example/api/v1/admin/system-backup-config", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	actor, err := (JWTRegistrationAuthenticator{Secret: secret}).Authenticate(req)
	if err != nil {
		t.Fatal("synthetic access authentication", err)
	}
	s := &mutationASessionState{base: base, actor: actor, password: "synthetic-current-password-hash", credential: registrationHash("synthetic-current-password-hash"), expires: actor.SessionExpiresAt}
	db := sql.OpenDB(mutationASessionConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	svc.DB = db
	sessions, err := NewSQLLoginSessions(db, svc.Database, svc.InstallationID, secret)
	if err != nil {
		t.Fatal(err)
	}
	registry := configRBACFixture(t, "v1", [3]string{"42", actor.Subject, "config_admin"}, [3]string{"7", "user:7", "security_admin"})
	current := configWithRBAC(t, registry, "v1")
	base.data.rows[1] = current
	oldAuthority := svc.Authority
	authority, err := NewPinnedConfigMutationAuthority(svc.InstallationID, ConfigMutationAuthoritySources{
		CheckSession: func(ctx context.Context, tx *sql.Tx, installation string, actor RegistrationActor, now time.Time) error {
			// The model records the sql.Tx handle at its first boundary call;
			// authentication/authorization is still the actual SQL helper below.
			if base.tx == nil {
				base.tx = tx
			}
			if base.tx != tx {
				return ErrRegistrationUnavailable
			}
			return sessions.CheckConfigMutationSession(ctx, tx, installation, actor, now)
		},
		RegistryBytes: func(kind, version, digest string) ([]byte, error) {
			if kind != "rbac_bindings" || version != "v1" || digest != registrationHash(string(registry)) {
				return nil, ErrRegistrationUnavailable
			}
			return append([]byte(nil), registry...), nil
		},
		// Ordinary writes must not invent a proof source. A security mutation
		// would fail closed until actual strong-auth material is supplied.
		StrongAuth: func(context.Context, *sql.Tx, RegistrationActor, string, ConfigValues, []string, time.Time) (VerifyConfig, error) {
			return VerifyConfig{}, ErrRegistrationUnavailable
		},
		ReserveMetadata: oldAuthority.Reserve,
		RedactReason:    oldAuthority.RedactReason,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.Authority = authority
	raw, err := json.Marshal(map[string]any{"expected_version": 1, "change_reason": nil, "config": json.RawMessage(current.CanonicalJSON())})
	if err != nil {
		t.Fatal(err)
	}
	return svc, actor, raw, s
}

func TestConfigMutationARealSessionAuthorityComposition(t *testing.T) {
	for _, name := range []string{"active", "password-change", "revoked", "shortened", "revoked-at-issue", "revoked-during-prepare", "revoked-at-final-check"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, s := mutationASessionIntegrationFixture(t)
			switch name {
			case "password-change":
				s.password = "synthetic-new-password-hash"
			case "revoked":
				s.revoked = true
			case "shortened":
				s.expires = s.expires.Add(-time.Microsecond)
			case "revoked-at-issue":
				v := actor.SessionIssuedAt
				s.revokedBefore = &v
			case "revoked-during-prepare":
				s.base.callback = func() { s.revoked = true }
			case "revoked-at-final-check":
				s.finalRevoke = true
			}
			result, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "a-session-chain", raw, nil)
			if name == "active" {
				if err != nil || result.Version != 2 || s.base.data.active != 2 || s.base.strongCalls != 0 || s.sessionChecks < 4 {
					t.Fatal("composed ordinary write", err, result.Version, s.sessionChecks)
				}
				return
			}
			mutationARequireRollback(t, s.base, result, err)
			if err != ErrRegistrationPermission {
				t.Fatal("session failure category", err)
			}
		})
	}
}

func TestConfigMutationARealSessionRevokedReplayDoesNotReadResponse(t *testing.T) {
	svc, actor, raw, s := mutationASessionIntegrationFixture(t)
	first, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "a-session-first", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	writes := len(s.base.data.writes)
	s.revoked = true
	replayed, err := svc.ObserveCommitted(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "a-session-observe", raw)
	if err != ErrRegistrationPermission || replayed.HTTPStatus != 0 || s.base.reads != 0 || len(s.base.data.writes) != writes || s.base.data.active != first.Version || s.base.activeTx {
		t.Fatal("revoked actor received original response or changed state", err, replayed.HTTPStatus, s.base.reads)
	}
}
