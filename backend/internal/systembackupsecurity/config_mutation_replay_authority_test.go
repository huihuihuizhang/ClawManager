package systembackupsecurity

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Actual JWT/session/password/revocation, canonical config checks and file RBAC
// compose over the existing SQL protocol model, not InnoDB or real credentials.
type replayAuthorizationFixture struct {
	a               *SQLConfigMutationReplayAuthorizer
	svc             ConfigMutationService
	s               *mutationASessionState
	input           ConfigMutationResponseReplayPreparation
	directory, path string
}

func replayWriteRBAC(t *testing.T, root string, raw []byte, version string) string {
	t.Helper()
	path := filepath.Join(root, "rbac_bindings", version, registrationHash(string(raw))+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func newReplayAuthorizationFixture(t *testing.T) *replayAuthorizationFixture {
	t.Helper()
	svc, actor, raw, s := mutationASessionIntegrationFixture(t)
	if _, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "replay-authority-first", raw, nil); err != nil {
		t.Fatal(err)
	}
	sessions, err := NewSQLLoginSessions(svc.DB, svc.Database, svc.InstallationID, []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Logf("LOCAL_REPLAY_RBAC_TEMP path=%s", root)
	registry := configRBACFixture(t, "v1", [3]string{"42", actor.Subject, "config_admin"}, [3]string{"7", "user:7", "security_admin"})
	path := replayWriteRBAC(t, root, registry, "v1")
	a, err := NewSQLConfigMutationReplayAuthorizer(svc.InstallationID, svc.Database, sessions, root)
	if err != nil {
		t.Fatal(err)
	}
	p := s.base.data.receipt
	in, err := NewConfigMutationResponseReplayPreparation(ConfigMutationResponseReplayFacts{Database: svc.Database, Installation: svc.InstallationID, Actor: actor, Operation: p.publicID, Endpoint: ConfigUpdateEndpoint, IdempotencyKey: "mutation_key_0123456789", RequestHash: p.hash, EvidenceID: p.evidenceID, ResponseHash: p.responseHash, Version: p.version, AuthorizedAt: s.base.now, ValidUntil: actor.SessionExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	return &replayAuthorizationFixture{a, svc, s, in, root, path}
}
func (f *replayAuthorizationFixture) rotate(t *testing.T, role string) {
	t.Helper()
	raw := configRBACFixture(t, "v2", [3]string{"42", f.s.actor.Subject, role}, [3]string{"7", "user:7", "security_admin"})
	f.s.base.data.rows[3] = configWithRBAC(t, raw, "v2")
	f.s.base.data.active = 3
	f.s.base.data.stateVersion++
	replayWriteRBAC(t, f.directory, raw, "v2")
}
func (f *replayAuthorizationFixture) risk(t *testing.T, security, destructive bool) {
	t.Helper()
	var audit map[string]any
	if json.Unmarshal(f.s.base.data.audit, &audit) != nil {
		t.Fatal("fixture audit")
	}
	audit["security_boundary"], audit["protection_reduction"] = security, destructive
	f.s.base.data.audit, _ = json.Marshal(audit)
}
func TestConfigMutationReplayActualSQLSessionAndFileRBAC(t *testing.T) {
	for _, name := range []string{"active", "rotated-current-config", "rotated-provider-references", "rotated-current-permission-removed", "original-security-risk", "original-destructive-risk", "original-both-risks-current-security-admin", "revoked", "password-changed", "session-shortened", "revoked-before-issue", "canonical-missing", "materialized-drift", "registry-missing", "registry-corrupted", "audit-missing", "null-security-risk", "null-destructive-risk", "duplicate-risk", "database"} {
		t.Run(name, func(t *testing.T) {
			f := newReplayAuthorizationFixture(t)
			want := ErrRegistrationUnavailable
			switch name {
			case "active":
				want = nil
			case "rotated-current-config":
				f.rotate(t, "config_admin")
				want = nil
			case "rotated-provider-references":
				f.rotate(t, "config_admin")
				var doc map[string]json.RawMessage
				if json.Unmarshal(f.s.base.data.rows[3].CanonicalJSON(), &doc) != nil {
					t.Fatal("rotated config")
				}
				var refs []BootstrapSecretRef
				if json.Unmarshal(doc["references"], &refs) != nil {
					t.Fatal("rotated refs")
				}
				for i := range refs {
					if refs[i].Purpose == "evidence_store" || refs[i].Purpose == "evidence_kek" {
						refs[i].Version = "new-active-version"
					}
				}
				doc["references"], _ = json.Marshal(refs)
				raw, _ := json.Marshal(doc)
				values, err := DecodeConfigValues(raw)
				if err != nil {
					t.Fatal(err)
				}
				f.s.base.data.rows[3] = values
				want = nil
			case "rotated-current-permission-removed":
				f.rotate(t, "viewer")
				want = ErrRegistrationPermission
			case "original-security-risk":
				f.risk(t, true, false)
				want = ErrRegistrationPermission
			case "original-destructive-risk":
				f.risk(t, false, true)
				want = ErrRegistrationPermission
			case "original-both-risks-current-security-admin":
				f.rotate(t, "security_admin")
				f.risk(t, true, true)
				want = nil
			case "revoked":
				f.s.revoked = true
				want = ErrRegistrationPermission
			case "password-changed":
				f.s.password = "synthetic-new-password-hash"
				want = ErrRegistrationPermission
			case "session-shortened":
				f.s.expires = f.s.expires.Add(-time.Microsecond)
				want = ErrRegistrationPermission
			case "revoked-before-issue":
				v := f.s.actor.SessionIssuedAt
				f.s.revokedBefore = &v
				want = ErrRegistrationPermission
			case "canonical-missing":
				f.s.base.missingCanonical = true
			case "materialized-drift":
				f.s.base.materializedDrift = true
			case "registry-missing":
				if err := os.Remove(f.path); err != nil {
					t.Fatal(err)
				}
			case "registry-corrupted":
				if err := os.WriteFile(f.path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "audit-missing":
				f.s.base.data.audit = nil
			case "null-security-risk", "null-destructive-risk":
				var audit map[string]json.RawMessage
				if json.Unmarshal(f.s.base.data.audit, &audit) != nil {
					t.Fatal("fixture audit")
				}
				key := "security_boundary"
				if name == "null-destructive-risk" {
					key = "protection_reduction"
				}
				audit[key] = json.RawMessage("null")
				f.s.base.data.audit, _ = json.Marshal(audit)
			case "duplicate-risk":
				f.s.base.data.audit = append([]byte(`{"security_boundary":true,`), f.s.base.data.audit[1:]...)
			case "database":
				f.s.base.wrongDatabase = true
			}
			commits, strong := f.s.base.commits, f.s.base.strongCalls
			tx, err := f.svc.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err = f.a.AuthorizeReplay(context.Background(), tx, f.input, f.s.base.now); err != want {
				t.Fatal("replay authorization", name, err, "want", want)
			}
			if len(f.s.base.working.writes) != 0 || f.s.base.commits != commits || f.s.base.strongCalls != strong {
				t.Fatal("read authorization wrote/committed/consumed proof")
			}
		})
	}
}
func TestConfigMutationReplayAuthorizerRejectsDifferentReceipt(t *testing.T) {
	for _, name := range []string{"operation", "evidence", "response-hash", "version", "expired"} {
		t.Run(name, func(t *testing.T) {
			f := newReplayAuthorizationFixture(t)
			facts := f.input.Facts()
			switch name {
			case "operation":
				facts.Operation = "sop_aaaaaaaa-1234-1234-1234-123456789abc"
			case "evidence":
				facts.EvidenceID++
			case "response-hash":
				facts.ResponseHash = strings.Repeat("f", 64)
			case "version":
				facts.Version++
			case "expired":
				facts.ValidUntil = facts.AuthorizedAt.Add(time.Microsecond)
				f.s.base.now = facts.ValidUntil
			}
			in, err := NewConfigMutationResponseReplayPreparation(facts)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := f.svc.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err = f.a.AuthorizeReplay(context.Background(), tx, in, f.s.base.now); err != ErrRegistrationUnavailable {
				t.Fatal("different receipt admitted", err)
			}
		})
	}
}
func TestConfigMutationReplayAuthorizerRequiresFixedDeploymentSources(t *testing.T) {
	f := newReplayAuthorizationFixture(t)
	for _, name := range []string{"nil-session", "wrong-session-installation", "wrong-session-db", "relative-files"} {
		t.Run(name, func(t *testing.T) {
			sessions := f.a.sessions
			directory := f.directory
			copy := *sessions
			switch name {
			case "nil-session":
				sessions = nil
			case "wrong-session-installation":
				copy.installation = "installation_other"
				sessions = &copy
			case "wrong-session-db":
				copy.identity.Database = "other"
				sessions = &copy
			case "relative-files":
				directory = "relative"
			}
			if a, err := NewSQLConfigMutationReplayAuthorizer(f.svc.InstallationID, f.svc.Database, sessions, directory); a != nil || err != ErrRegistrationUnavailable {
				t.Fatal("incomplete source accepted", err)
			}
		})
	}
}
