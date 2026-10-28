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

// Observe the actual Operation INSERT, rather than reconstructing its facts
// from the adapter's own response policy. The remaining SQL/session transport
// is the explicit model; this is not an InnoDB or deployment acceptance.
type operationAStoreObservation struct {
	model    *operationStoreModel
	row      map[string]any
	attack   string
	injected int
}

func (o *operationAStoreObservation) Driver() driver.Driver { return registrationTestDriver{} }
func (o *operationAStoreObservation) Connect(context.Context) (driver.Conn, error) {
	parent := operationStoreConn{mutationASessionConn{mutationTestConn{o.model.session.base}, o.model.session}, o.model}
	return &operationAStoreConn{parent, o}, nil
}

type operationAStoreConn struct {
	operationStoreConn
	observation *operationAStoreObservation
}

func (c *operationAStoreConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(query, "INSERT INTO system_backup_v2_operations") {
		row, err := operationBindingSQLRow(query, args)
		if err != nil {
			return nil, err
		}
		// The existing formal schema default is independent of the encoder.
		row["schema_version"] = "system-backup-operation.v1"
		c.observation.row = row
	}
	return c.operationStoreConn.ExecContext(ctx, query, args)
}

func (c *operationAStoreConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	var rows driver.Rows
	var err error
	if strings.HasPrefix(query, "SELECT schema_version,public_id,origin_installation_id,operation_type") {
		columns := operationASelectedColumns(query)
		values := make([]driver.Value, len(columns))
		for i, column := range columns {
			value, exists := c.observation.row[column]
			if !exists {
				return nil, errors.New("A observer has no actual INSERT fact for " + column)
			}
			values[i], err = driver.DefaultParameterConverter.ConvertValue(value)
			if err != nil {
				return nil, err
			}
		}
		rows = registrationRow(values...)
	} else {
		rows, err = c.operationStoreConn.QueryContext(ctx, query, args)
	}
	if err != nil {
		return nil, err
	}
	return &operationAAttackRows{Rows: rows, observation: c.observation, query: query}, nil
}

func operationASelectedColumns(query string) []string {
	return strings.Split(strings.TrimPrefix(strings.Split(query, " FROM ")[0], "SELECT "), ",")
}

type operationAAttackRows struct {
	driver.Rows
	observation *operationAStoreObservation
	query       string
}

func (r *operationAAttackRows) Next(values []driver.Value) error {
	if r.observation.attack == "chunk-read-failure" && strings.HasPrefix(r.query, "SELECT chunk_index FROM") {
		r.observation.injected++
		return errors.New("synthetic chunk read failure")
	}
	if err := r.Rows.Next(values); err != nil {
		return err
	}
	column, replacement := "", any(nil)
	switch r.observation.attack {
	case "foreign-actor":
		if strings.HasPrefix(r.query, "SELECT schema_version,public_id,origin_installation_id,operation_type") {
			column, replacement = "actor_id", "43"
		}
	case "foreign-request":
		if strings.HasPrefix(r.query, "SELECT schema_version,public_id,origin_installation_id,operation_type") {
			column, replacement = "request_hash", strings.Repeat("f", 64)
		}
	case "foreign-evidence-owner":
		column, replacement = "owner_target_public_id", "installation_other"
	case "evidence-created-before-completion":
		column, replacement = "created_at", r.observation.model.session.base.now.Add(-time.Second)
	case "empty-external-metadata":
		column, replacement = "storage_provider_role", []byte{}
	case "evidence-retention-extension":
		column, replacement = "expires_at", r.observation.model.session.base.data.expires.Add(time.Hour)
	case "evidence-row-replaced":
		column, replacement = "public_id", "sev_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	}
	// Evidence attacks must not alter the operation query, so that the test
	// isolates the independent saved-evidence binding.
	if r.observation.attack != "foreign-actor" && r.observation.attack != "foreign-request" && !strings.Contains(r.query, " FROM system_backup_v2_evidence ") {
		return nil
	}
	for i, name := range operationASelectedColumns(r.query) {
		if column != "" && name == column {
			values[i] = replacement
			r.observation.injected++
		}
	}
	return nil
}

func (r *operationAAttackRows) Close() error {
	err := r.Rows.Close()
	if r.observation.attack == "chunk-close-failure" && strings.HasPrefix(r.query, "SELECT chunk_index FROM") {
		r.observation.injected++
		return errors.New("synthetic chunk close failure")
	}
	return err
}

func operationAActualStoreFixture(t *testing.T, endpoint string) (ConfigMutationService, RegistrationActor, []byte, *operationAStoreObservation, *SQLOperationResponses) {
	t.Helper()
	svc, actor, raw, session, store, model := operationStoreFixture(t)
	observation := &operationAStoreObservation{model: model}
	db := sql.OpenDB(observation)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	svc.DB = db
	store.db = db
	if endpoint == ConfigRollbackEndpoint {
		raw = []byte(`{"expected_version":1,"change_reason":"synthetic rollback","rollback_from_version":1}`)
	}
	started := session.base.now
	session.base.afterCAS = func() { session.base.now = started.Add(2 * time.Second) }
	return svc, actor, raw, observation, store
}

func operationAStoredInput(t *testing.T, svc ConfigMutationService, actor RegistrationActor, o *operationAStoreObservation, endpoint string) ConfigMutationResponseReplayPreparation {
	t.Helper()
	f := o.model.session.base.data.receipt
	in, err := NewConfigMutationResponseReplayPreparation(ConfigMutationResponseReplayFacts{Database: svc.Database, Installation: svc.InstallationID, Actor: actor, Operation: f.publicID, Endpoint: endpoint, IdempotencyKey: "mutation_key_0123456789", RequestHash: f.hash, EvidenceID: f.evidenceID, ResponseHash: f.responseHash, Version: f.version, AuthorizedAt: o.model.session.base.now, ValidUntil: actor.SessionExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestConfigOperationAActualStoreRejectsContradictorySQL(t *testing.T) {
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		t.Run(endpoint, func(t *testing.T) {
			for _, attack := range []string{"foreign-actor", "foreign-request", "foreign-evidence-owner", "evidence-created-before-completion", "empty-external-metadata", "chunk-read-failure", "chunk-close-failure", "coherent-hash-foreign-body"} {
				t.Run(attack, func(t *testing.T) {
					svc, actor, raw, o, store := operationAActualStoreFixture(t, endpoint)
					if _, err := svc.Mutate(context.Background(), actor, endpoint, "mutation_key_0123456789", "a-store-original", raw, nil); err != nil {
						t.Fatal("valid actual-store write failed before attack", err)
					}
					s := o.model.session.base
					o.attack = attack
					if attack == "coherent-hash-foreign-body" {
						p, err := DecodeCanonicalConfigOperationResponse(s.data.response)
						if err != nil {
							t.Fatal(err)
						}
						p.ActorID = 43
						s.data.response, err = CanonicalConfigOperationResponse(p)
						if err != nil {
							t.Fatal(err)
						}
						s.data.evidenceHash = registrationHash(string(s.data.response))
						s.data.receipt.responseHash = s.data.evidenceHash
						o.row["redacted_response_sha256"] = s.data.evidenceHash
						o.injected++
					}
					before := len(s.data.writes)
					out, err := store.Read(context.Background(), operationAStoredInput(t, svc, actor, o, endpoint))
					if o.injected == 0 || out != nil || err != ErrRegistrationUnavailable || s.activeTx || len(s.data.writes) != before || s.commits != 1 {
						t.Fatal("contradictory original response escaped read boundary", o.injected, err)
					}
				})
			}
		})
	}
}

func TestConfigOperationAActualStoreKeepsPrivateReadSnapshot(t *testing.T) {
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		t.Run(endpoint, func(t *testing.T) {
			for _, attack := range []string{"caller-buffer", "evidence-retention-extension", "evidence-row-replaced", "current-session-revoked"} {
				t.Run(attack, func(t *testing.T) {
					svc, actor, raw, o, store := operationAActualStoreFixture(t, endpoint)
					result, err := svc.Mutate(context.Background(), actor, endpoint, "mutation_key_0123456789", "a-store-original", raw, nil)
					if err != nil {
						t.Fatal(err)
					}
					in := operationAStoredInput(t, svc, actor, o, endpoint)
					read, err := store.Read(context.Background(), in)
					if err != nil || !bytes.Equal(read.Bytes(), result.Response) {
						t.Fatal("valid original snapshot failed", err)
					}
					o.attack = attack
					if attack == "caller-buffer" {
						borrowed := read.Bytes()
						borrowed[0] = '!'
						o.injected++
					}
					if attack == "current-session-revoked" {
						o.model.session.revoked = true
						o.injected++
					}
					s := o.model.session.base
					before := len(s.data.writes)
					tx, err := svc.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
					if err != nil {
						t.Fatal(err)
					}
					err = read.Recheck(context.Background(), tx, s.now)
					if rollbackErr := tx.Rollback(); rollbackErr != nil {
						t.Fatal(rollbackErr)
					}
					if attack == "caller-buffer" {
						if err != nil || !bytes.Equal(read.Bytes(), result.Response) {
							t.Fatal("caller changed private snapshot", err)
						}
					} else if err != ErrRegistrationUnavailable {
						t.Fatal("changed original or authority survived final recheck", err)
					}
					if o.injected == 0 || s.activeTx || s.commits != 1 || len(s.data.writes) != before {
						t.Fatal("read recheck wrote or attack did not execute")
					}
				})
			}
		})
	}
}
