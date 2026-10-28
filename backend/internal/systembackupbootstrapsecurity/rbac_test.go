package systembackupbootstrapsecurity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

func sha(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

type fixture struct {
	validator *RBAC
	grant     sec.OfflineBootstrapGrant
	config    sec.BootstrapConfig
	path      string
}

func newFixture(t *testing.T, mutate func(map[string]any), rawMutation func([]byte) []byte) fixture {
	t.Helper()
	r := map[string]any{"schema_version": "system-backup-registration-rbac.draft.v1", "version": "rbac-test-v1", "installation_id": "installation_test",
		"bindings": []any{map[string]any{"actor_id": "42", "subject": "user:42", "role": "security_admin"}}}
	if mutate != nil {
		mutate(r)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if rawMutation != nil {
		raw = rawMutation(raw)
	}
	seedRaw, err := os.ReadFile(filepath.Join("..", "systembackupevidence", "testdata", "download_mfa_probe_inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var seed struct {
		Effective json.RawMessage `json:"effective_config"`
	}
	if err = json.Unmarshal(seedRaw, &seed); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(seed.Effective, &doc); err != nil {
		t.Fatal(err)
	}
	doc["enabled"] = false
	for _, value := range doc["registries"].([]any) {
		pin := value.(map[string]any)
		if pin["registry_kind"] == "rbac_bindings" {
			pin["version"] = "rbac-test-v1"
			pin["sha256"] = sha(raw)
		}
	}
	configRaw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	config, err := sec.DecodeBootstrapConfig(configRaw)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "rbac_bindings", "rbac-test-v1", sha(raw)+".json")
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	grant := sec.OfflineBootstrapGrant{InstallationID: "installation_test", ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "isolated_db",
		Username: "test-admin", UserID: 42, MatrixKey: "k8s-cluster", ConfigSHA256: config.SHA256(), IdempotencyKey: "bootstrap-test-key-001", ChangeReason: "test-only initial configuration"}
	return fixture{NewRBAC(dir), grant, config, path}
}

type dbState struct {
	server, database         string
	queries, writes, commits int
	queryError               bool
	cancel                   context.CancelFunc
}
type connector struct{ s *dbState }

func (c connector) Driver() driver.Driver                        { return testDriver{} }
func (c connector) Connect(context.Context) (driver.Conn, error) { return &connection{c.s}, nil }

type testDriver struct{}

func (testDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type connection struct{ s *dbState }

func (*connection) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (*connection) Close() error                        { return nil }
func (c *connection) Begin() (driver.Tx, error)         { return &transaction{c.s}, nil }
func (c *connection) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.s.queries++
	if q != "SELECT @@server_uuid,DATABASE()" || len(args) != 0 {
		return nil, errors.New("unexpected query")
	}
	if c.s.queryError {
		return nil, errors.New("PRIVATE_DATABASE_ERROR")
	}
	if c.s.cancel != nil {
		c.s.cancel()
	}
	return &rows{values: []driver.Value{c.s.server, c.s.database}}, nil
}
func (c *connection) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.s.writes++
	return nil, errors.New("unexpected write")
}

type transaction struct{ s *dbState }

func (t *transaction) Commit() error { t.s.commits++; return nil }
func (*transaction) Rollback() error { return nil }

type rows struct {
	values []driver.Value
	sent   bool
}

func (*rows) Columns() []string { return []string{"server_uuid", "database"} }
func (*rows) Close() error      { return nil }
func (r *rows) Next(dest []driver.Value) error {
	if r.sent {
		return io.EOF
	}
	copy(dest, r.values)
	r.sent = true
	return nil
}
func begin(t *testing.T, s *dbState) *sql.Tx {
	t.Helper()
	db := sql.OpenDB(connector{s})
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return tx
}

func TestRBACPrepareAndBorrowedTransactionRecheck(t *testing.T) {
	f := newFixture(t, nil, nil)
	check, err := f.validator.Prepare(context.Background(), f.grant, f.config)
	if err != nil {
		t.Fatal(err)
	}
	s := &dbState{server: f.grant.ServerUUID, database: f.grant.Database}
	tx := begin(t, s)
	if err = check.Recheck(context.Background(), tx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if s.queries != 1 || s.writes != 0 || s.commits != 0 {
		t.Fatal("validator did not preserve borrowed read-only transaction")
	}
	if _, err = json.Marshal(check); err == nil {
		t.Fatal("private observation serialized")
	}
	if fmt.Sprintf("%#v", check) != "BootstrapRBACCheck" {
		t.Fatal("private observation exposed")
	}
}

func TestRBACRejectsInvalidPinnedRegistryAndActor(t *testing.T) {
	cases := map[string]func(map[string]any){
		"wrong_installation":        func(r map[string]any) { r["installation_id"] = "installation_other" },
		"wrong_version":             func(r map[string]any) { r["version"] = "old-v1" },
		"wrong_schema":              func(r map[string]any) { r["schema_version"] = "other" },
		"unknown_field":             func(r map[string]any) { r["approved"] = true },
		"operator_cannot_bootstrap": func(r map[string]any) { r["bindings"].([]any)[0].(map[string]any)["role"] = "operator" },
		"wrong_actor":               func(r map[string]any) { r["bindings"].([]any)[0].(map[string]any)["actor_id"] = "43" },
		"wrong_subject":             func(r map[string]any) { r["bindings"].([]any)[0].(map[string]any)["subject"] = "user:43" },
		"duplicate_actor": func(r map[string]any) {
			r["bindings"] = append(r["bindings"].([]any), map[string]any{"actor_id": "42", "subject": "user:42", "role": "viewer"})
		},
		"other_user_asserts_admin_subject": func(r map[string]any) {
			r["bindings"] = append(r["bindings"].([]any), map[string]any{"actor_id": "43", "subject": "user:42", "role": "viewer"})
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, change, nil)
			if check, err := f.validator.Prepare(context.Background(), f.grant, f.config); err == nil || check != nil {
				t.Fatal("invalid role file accepted")
			}
		})
	}
	t.Run("duplicate_key", func(t *testing.T) {
		f := newFixture(t, nil, func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), `"version":`, `"version":"old","version":`, 1))
		})
		if check, err := f.validator.Prepare(context.Background(), f.grant, f.config); err == nil || check != nil {
			t.Fatal("duplicate field accepted")
		}
	})
}

func TestRBACRejectsInvalidGrantPathAndContext(t *testing.T) {
	for name, change := range map[string]func(*fixture){
		"grant_hash":         func(f *fixture) { f.grant.ConfigSHA256 = strings.Repeat("0", 64) },
		"grant_database":     func(f *fixture) { f.grant.Database = "db;write" },
		"grant_user":         func(f *fixture) { f.grant.UserID = 0 },
		"grant_key":          func(f *fixture) { f.grant.IdempotencyKey = "short" },
		"grant_matrix":       func(f *fixture) { f.grant.MatrixKey = "other" },
		"grant_reason":       func(f *fixture) { f.grant.ChangeReason = " " },
		"relative_directory": func(f *fixture) { f.validator = NewRBAC("relative") },
		"nil_validator":      func(f *fixture) { f.validator = nil },
		"missing_file": func(f *fixture) {
			if err := os.Remove(f.path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil, nil)
			change(&f)
			if check, err := f.validator.Prepare(context.Background(), f.grant, f.config); err == nil || check != nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	f := newFixture(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if check, err := f.validator.Prepare(ctx, f.grant, f.config); err == nil || check != nil {
			t.Fatal("invalid context accepted")
		}
	}
}

func TestRBACRecheckRejectsDriftCancellationAndDatabaseFailure(t *testing.T) {
	for _, name := range []string{"changed_file", "removed_file", "wrong_server", "wrong_database", "query_error", "canceled_during_query", "nil_transaction", "zero_clock"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil, nil)
			check, err := f.validator.Prepare(context.Background(), f.grant, f.config)
			if err != nil {
				t.Fatal(err)
			}
			s := &dbState{server: f.grant.ServerUUID, database: f.grant.Database}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "changed_file":
				if err = os.WriteFile(f.path, []byte(`{"approved":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "removed_file":
				if err = os.Remove(f.path); err != nil {
					t.Fatal(err)
				}
			case "wrong_server":
				s.server = "other"
			case "wrong_database":
				s.database = "other"
			case "query_error":
				s.queryError = true
			case "canceled_during_query":
				s.cancel = cancel
			}
			tx := begin(t, s)
			now := time.Now().UTC()
			if name == "nil_transaction" {
				tx = nil
			}
			if name == "zero_clock" {
				now = time.Time{}
			}
			if err = check.Recheck(ctx, tx, now); err == nil {
				t.Fatal("invalid recheck accepted")
			}
			if strings.Contains(err.Error(), "PRIVATE") || s.writes != 0 || s.commits != 0 {
				t.Fatal("raw error or transaction effects escaped")
			}
		})
	}
}
