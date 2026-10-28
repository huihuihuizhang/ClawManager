package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMFARequiresAuthorizationInsideCredentialTransaction(t *testing.T) {
	state := &registrationTestState{}
	db := sql.OpenDB(registrationTestConnector{state})
	defer db.Close()
	box, err := NewTOTPSecretBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := SQLTOTPService{DB: db, InstallationID: "installation_unit", Box: box}
	actor := RegistrationActor{UserID: 44, Subject: "user:44", Session: strings.Repeat("a", 64)}
	if _, err = svc.BeginEnrollment(context.Background(), actor, "synthetic password"); err != ErrRegistrationUnavailable {
		t.Fatal("missing permission callback accepted", err)
	}
	svc.Authorize = func(_ context.Context, tx *sql.Tx, _ RegistrationActor) error {
		if tx == nil {
			t.Fatal("permission checked outside transaction")
		}
		state.authorizations++
		return ErrRegistrationPermission
	}
	if _, err = svc.BeginEnrollment(context.Background(), actor, "synthetic password"); err != ErrRegistrationPermission {
		t.Fatal("revoked permission accepted", err)
	}
	if state.authorizations != 1 || state.rollbacks != 1 || state.commits != 0 || len(state.queries) != 0 || len(state.pending) != 0 {
		t.Fatal("denied MFA accessed credentials or committed")
	}
	svc.Authorize = func(context.Context, *sql.Tx, RegistrationActor) error {
		return errors.New("PRIVATE authority failure")
	}
	if _, err = svc.BeginEnrollment(context.Background(), actor, "synthetic password"); err != ErrRegistrationUnavailable {
		t.Fatal("authority error escaped", err)
	}
}

type mfaPermissionState struct {
	base          *registrationTestState
	identity      DatabaseIdentity
	activeVersion int64
	orphan        bool
}
type mfaPermissionConnector struct{ s *mfaPermissionState }

func (c mfaPermissionConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c mfaPermissionConnector) Connect(context.Context) (driver.Conn, error) {
	return &mfaPermissionConn{registrationTestConn: registrationTestConn{c.s.base}, m: c.s}, nil
}

type mfaPermissionConn struct {
	registrationTestConn
	m *mfaPermissionState
}

func (c *mfaPermissionConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	switch {
	case q == "SELECT @@server_uuid,DATABASE()":
		return registrationRow(c.m.identity.ServerUUID, c.m.identity.Database), nil
	case strings.Contains(q, "SELECT active_config_version"):
		if c.m.activeVersion == 0 {
			return &registrationTestRows{width: 1}, nil
		}
		return registrationRow(c.m.activeVersion), nil
	case strings.Contains(q, "SELECT version FROM system_backup_v2_configs"):
		if c.m.orphan {
			return registrationRow(int64(1)), nil
		}
		return &registrationTestRows{width: 1}, nil
	}
	return c.registrationTestConn.QueryContext(ctx, q, args)
}
func TestMFAUsesCurrentConfigAndClosedBootstrapGrant(t *testing.T) {
	for _, name := range []string{"fresh-v1", "active-v1", "stale-runtime", "changed-pin", "orphan-config", "fresh-non-v1", "revoked-role"} {
		t.Run(name, func(t *testing.T) {
			raw := `{"schema_version":"system-backup-registration-rbac.draft.v1","version":"rbac-v1","installation_id":"installation_unit","bindings":[{"actor_id":"44","subject":"user:44","role":"security_admin"}]}`
			if name == "revoked-role" {
				raw = strings.Replace(raw, "security_admin", "viewer", 1)
			}
			cfg := RegistrationConfig{Version: 1, RBACRegistryVersion: "rbac-v1", RBACRegistrySHA256: registrationHash(raw), ProviderRegistryVersion: "p1", ProviderRegistrySHA256: strings.Repeat("a", 64), StrongAuthRegistryVersion: "s1", StrongAuthRegistrySHA256: strings.Repeat("b", 64), NonceKeyVersion: "v1"}
			identity := DatabaseIdentity{ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "synthetic"}
			state := &mfaPermissionState{base: &registrationTestState{config: cfg}, identity: identity, activeVersion: 1}
			if name == "fresh-v1" || name == "fresh-non-v1" || name == "orphan-config" {
				state.activeVersion = 0
			}
			if name == "stale-runtime" {
				state.activeVersion = 2
			}
			if name == "fresh-non-v1" {
				cfg.Version = 2
			}
			if name == "orphan-config" {
				state.orphan = true
			}
			if name == "changed-pin" {
				state.base.config.RBACRegistrySHA256 = strings.Repeat("c", 64)
			}
			db := sql.OpenDB(mfaPermissionConnector{state})
			defer db.Close()
			tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			a := configuredAuthority{database: identity, expected: cfg, PinnedRegistrationAuthority: PinnedRegistrationAuthority{InstallationID: "installation_unit", RegistryBytes: func(kind, version, digest string) ([]byte, error) {
				if kind != "rbac_bindings" || version != "rbac-v1" || digest != registrationHash(raw) {
					return nil, ErrRegistrationUnavailable
				}
				return []byte(raw), nil
			}}}
			err = a.AuthorizeMFA(context.Background(), tx, RegistrationActor{UserID: 44, Subject: "user:44"})
			if name == "fresh-v1" || name == "active-v1" {
				if err != nil {
					t.Fatal("valid grant rejected", err)
				}
			} else if err == nil {
				t.Fatal("stale/revoked bootstrap grant admitted")
			}
			if name == "revoked-role" && err != ErrRegistrationPermission {
				t.Fatal("wrong revoked-role result", err)
			}
		})
	}
}

func TestMFAUnknownRoutesAndMissingPolicyFailClosed(t *testing.T) {
	api := RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: fixedRegistrationAuth{actor: RegistrationActor{UserID: 44, Subject: "user:44"}}}}
	for _, tc := range []struct {
		path string
		want int
	}{{strongAuthBase + "/enroll", 503}, {strongAuthBase + "/bootstrap", 404}, {"/api/v1/admin/system-backup-config/bootstrap", 404}} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(`{"password":"synthetic"}`))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		if w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(tc.path, w.Code)
		}
	}
}
