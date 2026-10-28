package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

// Actual SQL adapter/codec/session/file RBAC over explicit protocol SQL. This
// does not claim InnoDB locking, installed 081 or deployment authorization.
type operationStoreModel struct {
	session *mutationASessionState
	mode    string
}
type operationStoreConnector struct{ s *operationStoreModel }

func (c operationStoreConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c operationStoreConnector) Connect(context.Context) (driver.Conn, error) {
	return &operationStoreConn{mutationASessionConn{mutationTestConn{c.s.session.base}, c.s.session}, c.s}, nil
}

type operationStoreConn struct {
	mutationASessionConn
	model *operationStoreModel
}

func (c *operationStoreConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	d := c.model.session.base.working
	if strings.HasPrefix(q, "SELECT schema_version,public_id,origin_installation_id,operation_type") {
		p := d.operationPolicy
		f := d.receipt
		if f == nil {
			return &registrationTestRows{width: 26}, nil
		}
		if len(args) != 5 || args[0].Value != p.InstallationID || args[1].Value != "42" || args[2].Value != p.Endpoint || args[3].Value != p.IdempotencyKey || args[4].Value != p.OperationPublicID {
			return nil, errors.New("wrong exact operation scope")
		}
		if c.model.mode == "operation-updated" {
			p.UpdatedAt = p.UpdatedAt.Add(time.Second)
		}
		if c.model.mode == "operation-version" {
			p.RowVersion++
		}
		var resource driver.Value
		if c.model.mode == "result-resource" {
			resource = "unexpected"
		}
		return registrationRow("system-backup-operation.v1", p.OperationPublicID, p.InstallationID, "config_update", "system", p.InstallationID, "admin", "42", p.Endpoint, p.IdempotencyKey, p.RequestHash, "succeeded", resource, p.Version, false, "none", nil, int64(200), p.RowVersion, p.DeadlineAt, p.StartedAt, p.FinishedAt, p.CreatedAt, p.UpdatedAt, f.evidenceID, f.responseHash), nil
	}
	if strings.HasPrefix(q, "SELECT id,schema_version,public_id,owner_target_type") {
		raw := append([]byte(nil), d.response...)
		checksum := d.evidenceHash
		expiry := d.expires
		if c.model.mode == "body-corrupt" {
			raw[0] = '!'
		}
		if c.model.mode == "expired" {
			expiry = c.model.session.base.now
		}
		return registrationRow(d.evidenceID, "system-backup-evidence.v1", d.evidencePublicID, "system", "installation_synthetic", "diagnostic", "inline", "none", "healthy", raw, checksum, int64(len(raw)), "application/json", "none", "internal", expiry, d.evidenceCreated, int64(1), int64(0)), nil
	}
	if strings.HasPrefix(q, "SELECT storage_provider_role,") {
		values := make([]driver.Value, 14)
		if c.model.mode == "external-metadata" {
			values[0] = "evidence"
		}
		return registrationRow(values...), nil
	}
	if strings.HasPrefix(q, "SELECT chunk_index FROM") {
		if c.model.mode == "extra-chunk" {
			return registrationRow(int64(0)), nil
		}
		return &registrationTestRows{width: 1}, nil
	}
	return c.mutationASessionConn.QueryContext(ctx, q, args)
}
func operationStoreFixture(t *testing.T) (ConfigMutationService, RegistrationActor, []byte, *mutationASessionState, *SQLOperationResponses, *operationStoreModel) {
	t.Helper()
	svc, actor, raw, s := mutationASessionIntegrationFixture(t)
	model := &operationStoreModel{session: s}
	db := sql.OpenDB(operationStoreConnector{model})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	svc.DB = db
	sessions, err := NewSQLLoginSessions(db, svc.Database, svc.InstallationID, []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Logf("LOCAL_OPERATION_RBAC_TEMP path=%s", root)
	registry := configRBACFixture(t, "v1", [3]string{"42", actor.Subject, "config_admin"}, [3]string{"7", "user:7", "security_admin"})
	replayWriteRBAC(t, root, registry, "v1")
	store, err := NewSQLOperationResponses(db, svc.Database, svc.InstallationID, sessions, root)
	if err != nil {
		t.Fatal(err)
	}
	svc.Responses = store
	return svc, actor, raw, s, store, model
}
func TestConfigOperationWriterStoresExactTerminalOperationAndReplaysOriginal(t *testing.T) {
	svc, actor, raw, s, _, _ := operationStoreFixture(t)
	started := s.base.now
	s.base.afterCAS = func() { s.base.now = started.Add(time.Second) }
	first, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "operation-first", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeCanonicalConfigOperationResponse(first.Response)
	if err != nil || !p.CreatedAt.Equal(started) || !p.FinishedAt.Equal(started.Add(time.Second)) || !p.UpdatedAt.Equal(p.FinishedAt) || p.Version != 2 || !bytes.Equal(first.Response, s.base.data.response) {
		t.Fatal("precomputed/non-Operation response", err)
	}
	fromSQL, err := CanonicalConfigOperationResponse(s.base.data.operationPolicy)
	if err != nil || !bytes.Equal(first.Response, fromSQL) {
		t.Fatal("SQL public facts diverge from receipt", err)
	}
	writes, strong := len(s.base.data.writes), s.base.strongCalls
	second, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "operation-replay", raw, nil)
	if err != nil || !second.Replayed || !bytes.Equal(second.Response, first.Response) || len(s.base.data.writes) != writes || s.base.strongCalls != strong {
		t.Fatal("replay reconstructed/reexecuted", err)
	}
}
func TestConfigOperationStoreRejectsSQLOrSavedResponseDrift(t *testing.T) {
	for _, name := range []string{"operation-updated", "operation-version", "result-resource", "body-corrupt", "expired", "external-metadata", "extra-chunk", "current-revoked", "legacy-config-resource"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, s, store, model := operationStoreFixture(t)
			if _, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "operation-first", raw, nil); err != nil {
				t.Fatal(err)
			}
			model.mode = name
			if name == "current-revoked" {
				s.revoked = true
			}
			if name == "legacy-config-resource" {
				body, err := configMutationResponse(svc.InstallationID, actor, 2, s.base.data.rows[2], nil, s.base.now, true)
				if err != nil {
					t.Fatal(err)
				}
				s.base.data.response = body
				s.base.data.evidenceHash = registrationHash(string(body))
				s.base.data.receipt.responseHash = s.base.data.evidenceHash
			}
			f := s.base.data.receipt
			in, err := NewConfigMutationResponseReplayPreparation(ConfigMutationResponseReplayFacts{Database: svc.Database, Installation: svc.InstallationID, Actor: actor, Operation: f.publicID, Endpoint: ConfigUpdateEndpoint, IdempotencyKey: "mutation_key_0123456789", RequestHash: f.hash, EvidenceID: f.evidenceID, ResponseHash: f.responseHash, Version: f.version, AuthorizedAt: s.base.now, ValidUntil: actor.SessionExpiresAt})
			if err != nil {
				t.Fatal(err)
			}
			before := len(s.base.data.writes)
			if out, err := store.Read(context.Background(), in); out != nil || err != ErrRegistrationUnavailable || s.base.activeTx || len(s.base.data.writes) != before {
				t.Fatal("bad original returned or wrote", err)
			}
		})
	}
}
func TestConfigOperationStoreFailureAfterResponseRollsBackAllEffects(t *testing.T) {
	svc, actor, raw, s, _, _ := operationStoreFixture(t)
	s.base.failWrite = 6
	result, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "operation-rollback", raw, nil)
	mutationARequireRollback(t, s.base, result, err)
}

func TestConfigOperationReadFinalGuardRechecksOriginalSQLAndCurrentPermission(t *testing.T) {
	for _, name := range []string{"operation-version", "extra-chunk", "current-revoked"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, s, store, model := operationStoreFixture(t)
			if _, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "operation-first", raw, nil); err != nil {
				t.Fatal(err)
			}
			f := s.base.data.receipt
			in, err := NewConfigMutationResponseReplayPreparation(ConfigMutationResponseReplayFacts{Database: svc.Database, Installation: svc.InstallationID, Actor: actor, Operation: f.publicID, Endpoint: ConfigUpdateEndpoint, IdempotencyKey: "mutation_key_0123456789", RequestHash: f.hash, EvidenceID: f.evidenceID, ResponseHash: f.responseHash, Version: f.version, AuthorizedAt: s.base.now, ValidUntil: actor.SessionExpiresAt})
			if err != nil {
				t.Fatal(err)
			}
			read, err := store.Read(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			model.mode = name
			if name == "current-revoked" {
				s.revoked = true
			}
			tx, err := svc.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if read.Recheck(context.Background(), tx, s.base.now) != ErrRegistrationUnavailable {
				t.Fatal("changed SQL/permission survived final guard")
			}
		})
	}
}
