package systembackupsecurity

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func actionScopeFixture(t *testing.T, role string) (*SystemBackupActionAuthorizer, *sql.DB, *readScopeTestState, *http.Request, string) {
	t.Helper()
	root := t.TempDir()
	raw := `{"schema_version":"system-backup-registration-rbac.draft.v1","version":"rbac-v1","installation_id":"installation_synthetic","bindings":[{"actor_id":"42","subject":"user:42","role":"` + role + `"}]}`
	digest := registrationHash(raw)
	file := filepath.Join(root, "rbac_bindings", "rbac-v1", digest+".json")
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secret := []byte(strings.Repeat("k", 32))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": int64(42), "token_type": "access", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix()}).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	identity := DatabaseIdentity{ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "synthetic"}
	state := &readScopeTestState{base: &registrationTestState{config: RegistrationConfig{ProviderRegistryVersion: "p1", ProviderRegistrySHA256: strings.Repeat("a", 64), StrongAuthRegistryVersion: "s1", StrongAuthRegistrySHA256: strings.Repeat("b", 64), RBACRegistryVersion: "rbac-v1", RBACRegistrySHA256: digest, NonceKeyVersion: "v1"}}, identity: identity, session: registrationHash(token), until: now.Add(time.Hour)}
	db := sql.OpenDB(readScopeTestConnector{state})
	t.Cleanup(func() { _ = db.Close() })
	sessions, err := NewSQLLoginSessions(db, identity, "installation_synthetic", secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sessions.Close)
	pins, err := json.Marshal(SystemBackupReadPins{InstallationID: "installation_synthetic", ConfigVersion: 1, RBACVersion: "rbac-v1", RBACSHA256: digest, RegistryDirectory: root})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "pins.json")
	if err = os.WriteFile(path, pins, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadSystemBackupActionAuthorizer(sessions, path, registrationHash(string(pins)))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://example.invalid/api/v1/admin/system-backups", nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Idempotency-Key", "synthetic-create-backup-42")
	return a, db, state, r, file
}

func TestSystemBackupActionScopePolicyAndSession(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "security_admin"} {
		for _, operation := range []string{CreateSystemBackup, CreateSystemBackupPreflight, CancelSystemBackup, CancelSystemBackupPreflight} {
			t.Run(role+"/"+operation, func(t *testing.T) {
				a, db, state, r, _ := actionScopeFixture(t, role)
				if operation == CreateSystemBackupPreflight {
					r.URL.Path = "/api/v1/admin/system-backup-preflights"
				}
				if operation == CancelSystemBackup {
					r.URL.Path = "/api/v1/admin/system-backups/sbk_12345678-1234-4234-8234-123456789abc/cancel"
				}
				if operation == CancelSystemBackupPreflight {
					r.URL.Path = "/api/v1/admin/system-backup-preflights/spf_12345678-1234-4234-8234-123456789abc/cancel"
				}
				scope, err := a.Scope(r, operation)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := db.BeginTx(scope.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				installation, err := scope.AuthorizeAction(scope.Context(), tx)
				if role == "viewer" {
					if !errors.Is(err, ErrRegistrationPermission) {
						t.Fatal("viewer allowed", err)
					}
					return
				}
				if err != nil || installation != "installation_synthetic" || scope.Actor().UserID != 42 || scope.IdempotencyKey() != r.Header.Get("Idempotency-Key") {
					t.Fatal(installation, err)
				}
				if err = scope.RecheckAction(scope.Context(), tx, installation); err != nil {
					t.Fatal(err)
				}
				state.revoked = true
				if err = scope.RecheckAction(scope.Context(), tx, installation); !errors.Is(err, ErrRegistrationPermission) {
					t.Fatal("revoked session allowed", err)
				}
				state.revoked = false
				if err = scope.RecheckAction(scope.Context(), tx, installation); !errors.Is(err, ErrRegistrationPermission) {
					t.Fatal("ignored failure was reset", err)
				}
			})
		}
	}
}

func TestSystemBackupActionScopeBoundaries(t *testing.T) {
	for _, mode := range []string{"context", "other_tx_copy", "installation", "inactive", "credential", "missing_session", "sql", "config", "file", "cancel", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			a, db, state, r, file := actionScopeFixture(t, "operator")
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			scope, err := a.Scope(r, CreateSystemBackup)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(scope.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			installation, err := scope.AuthorizeAction(scope.Context(), tx)
			if err != nil {
				t.Fatal(err)
			}
			checkCtx, checkTx := scope.Context(), tx
			switch mode {
			case "context":
				checkCtx = context.Background()
			case "other_tx_copy":
				copy := *scope
				scope = &copy
				checkTx, err = db.BeginTx(scope.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
				if err != nil {
					t.Fatal(err)
				}
				defer checkTx.Rollback()
			case "installation":
				installation = "installation_other"
			case "inactive":
				state.inactive = true
			case "credential":
				state.until = time.Now().Add(-time.Second)
			case "missing_session":
				state.missingSession = true
			case "sql":
				state.sessionFailure = true
			case "config":
				state.base.config.RBACRegistrySHA256 = strings.Repeat("c", 64)
			case "file":
				if err = os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "expiry":
				scope.state.actor.SessionExpiresAt = time.Now().Add(-time.Second)
			}
			err = scope.RecheckAction(checkCtx, checkTx, installation)
			if err == nil {
				t.Fatal("late change accepted")
			}
			if mode == "sql" && !errors.Is(err, ErrProviderEvidenceStorage) {
				t.Fatal("storage classified as permission", err)
			}
			if _, err = scope.AuthorizeAction(scope.Context(), tx); err == nil {
				t.Fatal("ignored failure accepted")
			}
		})
	}
}

func TestSystemBackupActionScopeTransportClosed(t *testing.T) {
	for _, mode := range []string{"missing_auth", "duplicate_auth", "missing_key", "duplicate_key", "bad_key", "plaintext", "get", "path", "query", "encoded", "operation"} {
		t.Run(mode, func(t *testing.T) {
			a, _, _, r, _ := actionScopeFixture(t, "operator")
			operation := CreateSystemBackup
			switch mode {
			case "missing_auth":
				r.Header.Del("Authorization")
			case "duplicate_auth":
				r.Header.Add("Authorization", r.Header.Get("Authorization"))
			case "missing_key":
				r.Header.Del("Idempotency-Key")
			case "duplicate_key":
				r.Header.Add("Idempotency-Key", r.Header.Get("Idempotency-Key"))
			case "bad_key":
				r.Header.Set("Idempotency-Key", "bad key")
			case "plaintext":
				r.TLS = nil
			case "get":
				r.Method = "GET"
			case "path":
				r.URL.Path = "/api/v1/admin/system-backup-provider-proofs"
			case "query":
				r.URL.RawQuery = "installation=other"
			case "encoded":
				r.URL.RawPath = "/api/v1/admin/%73ystem-backups"
			case "operation":
				operation = "registerSystemBackupProviderProof"
			}
			if _, err := a.Scope(r, operation); err == nil {
				t.Fatal("invalid transport accepted")
			}
		})
	}
}

func TestSystemBackupActionPolicyMatchesContract(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/admin-operation-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Operations []struct {
			ID          string   `json:"operation_id"`
			Method      string   `json:"method"`
			Path        string   `json:"path"`
			Permissions []string `json:"required_permissions"`
			Conditional []any    `json:"conditional_permissions"`
			Strong      string   `json:"recent_strong_auth"`
			Idempotency bool     `json:"idempotency_required"`
			Kill        string   `json:"kill_switch"`
		} `json:"operations"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range doc.Operations {
		if p.ID != CreateSystemBackup && p.ID != CreateSystemBackupPreflight {
			continue
		}
		found++
		path := "/admin/system-backups"
		if p.ID == CreateSystemBackupPreflight {
			path = "/admin/system-backup-preflights"
		}
		if p.Method != "POST" || p.Path != path || strings.Join(p.Permissions, ",") != "system_backup.operate" || len(p.Conditional) != 0 || p.Strong != "none" || !p.Idempotency || p.Kill != "requires_effective_enabled" {
			t.Fatalf("policy changed: %+v", p)
		}
	}
	if found != 2 {
		t.Fatal("missing operation policy", found)
	}
}
