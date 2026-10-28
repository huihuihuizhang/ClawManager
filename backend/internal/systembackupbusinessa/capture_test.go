package systembackupbusinessa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Test-only snapshot: standalone MySQL probes cannot read the source checkout.
// The repository test below keeps it byte-for-byte equal to the draft registry.
// registryFixture's synthetic approvals are confined to this test binary.
//
//go:embed testdata/schema-registry.json
var businessRegistryFixtureJSON []byte

// Explicit historical capability fixture for synthetic successful 15-table
// verifier tests. This is not the current canonical registry or an approval.
//
//go:embed testdata/schema-registry-historical-15.json
var historicalBusinessRegistryFixtureJSON []byte

func TestEmbeddedBusinessRegistryFixtureMatchesCanonical(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/schema-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, businessRegistryFixtureJSON) {
		t.Fatal("embedded business registry fixture drifted; synchronize testdata/schema-registry.json with the canonical registry")
	}
}

func registryFixture(t *testing.T, freeze bool) map[string]any {
	t.Helper()
	var document map[string]any
	raw := businessRegistryFixtureJSON
	if freeze {
		raw = historicalBusinessRegistryFixtureJSON
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if freeze {
		freezeSyntheticRegistry(document)
	}
	return document
}

func freezeSyntheticRegistry(document map[string]any) {
	// Synthetic gate fixture, never a live schema observation or approval.
	document["contract_status"] = "frozen"
	hash := document["schema_hash"].(map[string]any)
	hash["status"] = "observed"
	hash["hash"] = strings.Repeat("a", 64)
	hash["evidence"] = map[string]any{"public_id": "sev_fixture", "sha256": strings.Repeat("b", 64)}
	objects := document["objects"].([]any)
	summary := document["summary"].(map[string]any)
	summary["object_count"] = len(objects)
	summary["policy_recorded"] = len(objects)
	summary["policy_pending"] = 0
	summary["cross_review_pending"] = 0
	for _, raw := range objects {
		object := raw.(map[string]any)
		object["decision_status"] = "frozen"
		object["approved_cross_reviewers"] = object["required_cross_reviewers"]
	}
}

func TestExtendedInventoryDoesNotExpandClosedACaptureScope(t *testing.T) {
	document := registryFixture(t, false)
	if scope, err := pinnedScope(t, document); err == nil || scope != nil {
		t.Fatal("new pending inventory was admitted")
	}
	// Even fabricated freeze/summary/reviewer flags cannot make these
	// unimplemented tables part of the production collector's closed policy.
	freezeSyntheticRegistry(document)
	if scope, err := pinnedScope(t, document); err == nil || scope != nil {
		t.Fatal("unsupported new A tables silently entered the collector")
	}
}

func registryBytes(t *testing.T, document map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pinnedScope(t *testing.T, document map[string]any) (*CaptureScope, error) {
	t.Helper()
	raw := registryBytes(t, document)
	digest := sha256.Sum256(raw)
	return NewPinnedCaptureScope(raw, hex.EncodeToString(digest[:]))
}

func object(t *testing.T, document map[string]any, name string) map[string]any {
	t.Helper()
	for _, raw := range document["objects"].([]any) {
		candidate := raw.(map[string]any)
		if candidate["name"] == name {
			return candidate
		}
	}
	t.Fatalf("missing registry object %s", name)
	return nil
}

func TestCaptureTableAllowlist(t *testing.T) {
	if got, err := pinnedScope(t, registryFixture(t, false)); err == nil || got != nil {
		t.Fatalf("draft registry admitted: %v, %v", got, err)
	}
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	got := scope.Tables()
	if len(got) != 15 || !sortStrings(got) || !reflect.DeepEqual(got, []string{
		"audit_events", "chat_messages", "chat_sessions", "cost_records", "enterprise_auth_settings",
		"instance_gateway_token_aliases", "llm_models", "model_invocations", "northbound_auth_challenges",
		"northbound_caller_policies", "northbound_sessions", "risk_hits", "risk_rules", "user_quotas", "users",
	}) {
		t.Fatalf("wrong closed table scope: %v", got)
	}
	if scope.RegistrySHA256() == "" || scope.SchemaSHA256() != strings.Repeat("a", 64) {
		t.Fatalf("scope lost registry identity: %+v", scope)
	}
	got[0] = "system_backup_v2_backups"
	if scope.Tables()[0] == "system_backup_v2_backups" {
		t.Fatal("caller mutated capture scope table names")
	}
}

func TestPinnedScopeRejectsWrongDigest(t *testing.T) {
	raw := registryBytes(t, registryFixture(t, true))
	if scope, err := NewPinnedCaptureScope(raw, strings.Repeat("0", 64)); err == nil || scope != nil {
		t.Fatalf("wrong digest admitted: %+v, %v", scope, err)
	}
	if scope, err := NewPinnedCaptureScope(raw, "bad"); err == nil || scope != nil {
		t.Fatalf("malformed digest admitted: %+v, %v", scope, err)
	}
}

func sortStrings(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] >= values[i] {
			return false
		}
	}
	return true
}

func TestCaptureTableAllowlistFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, map[string]any)
	}{
		{"missing schema evidence", func(_ *testing.T, d map[string]any) { d["schema_hash"].(map[string]any)["evidence"] = nil }},
		{"pending global review", func(_ *testing.T, d map[string]any) { d["summary"].(map[string]any)["cross_review_pending"] = 1 }},
		{"unreviewed user secret", func(t *testing.T, d map[string]any) {
			object(t, d, "enterprise_auth_settings")["approved_cross_reviewers"] = []any{}
		}},
		{"wrong secret classification", func(t *testing.T, d map[string]any) {
			object(t, d, "llm_models")["data_classification"] = "confidential"
		}},
		{"cross-category table", func(t *testing.T, d map[string]any) { object(t, d, "users")["category"] = "ai_gateway" }},
		{"missing AI table", func(t *testing.T, d map[string]any) {
			objects := d["objects"].([]any)
			for i, raw := range objects {
				if raw.(map[string]any)["name"] == "risk_hits" {
					d["objects"] = append(objects[:i], objects[i+1:]...)
					d["summary"].(map[string]any)["object_count"] = len(objects) - 1
					d["summary"].(map[string]any)["policy_recorded"] = len(objects) - 1
					return
				}
			}
			t.Fatal("risk_hits fixture missing")
		}},
		{"extra user table", func(t *testing.T, d map[string]any) { object(t, d, "system_backup_v2_backups")["category"] = "users" }},
		{"wrong verifier", func(t *testing.T, d map[string]any) { object(t, d, "audit_events")["verifier_id"] = "other" }},
		{"unreviewed other domain", func(t *testing.T, d map[string]any) { object(t, d, "audit_logs")["approved_cross_reviewers"] = []any{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := registryFixture(t, true)
			tc.edit(t, document)
			if got, err := pinnedScope(t, document); err == nil || got != nil {
				t.Fatalf("invalid registry admitted: %v, %v", got, err)
			}
		})
	}
}

type countState struct {
	costRows func() driver.Rows

	failure   string
	queries   []string
	counts    map[string]int64
	safety    map[string]int64
	begin     driver.TxOptions
	commits   int
	rollbacks int
}

type countConnector struct{ state *countState }

func (c countConnector) Connect(context.Context) (driver.Conn, error) {
	return &countConn{c.state}, nil
}
func (c countConnector) Driver() driver.Driver { return countDriver{c.state} }

type countDriver struct{ state *countState }

func (d countDriver) Open(string) (driver.Conn, error) { return &countConn{d.state}, nil }

type countConn struct{ state *countState }

func (c *countConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *countConn) Close() error              { return nil }
func (c *countConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected begin") }
func (c *countConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.state.begin = opts
	return countTx{c.state}, nil
}
func (c *countConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.queries = append(c.state.queries, query)
	if strings.Contains(query, "information_schema.TABLES") {
		if len(args) != 1 {
			return nil, errors.New("unbound table inspection")
		}
		table, ok := args[0].Value.(string)
		if !ok {
			return nil, errors.New("invalid table inspection")
		}
		if c.state.failure == "engine:"+table {
			return nil, errors.New("injected engine failure")
		}
		if c.state.failure == "myisam:"+table {
			return &countRows{columns: []string{"ENGINE"}, values: [][]driver.Value{{"MyISAM"}}}, nil
		}
		return &countRows{columns: []string{"ENGINE"}, values: [][]driver.Value{{"InnoDB"}}}, nil
	}
	if query == costAggregateQuery {
		if c.state.failure == "cost-query" {
			return nil, errors.New("injected cost query failure")
		}
		if c.state.costRows != nil {
			return c.state.costRows(), nil
		}
		return fixtureCostSQLRows(tFixtureCount(c.state)), nil
	}
	for table := range tables {
		if query == "SELECT COUNT(*) FROM `"+table+"`" {
			if len(args) != 0 || c.state.failure == "count:"+table {
				return nil, errors.New("injected count failure")
			}
			rows := int64(2)
			if count, ok := c.state.counts[table]; ok {
				rows = count
			}
			return &countRows{columns: []string{"COUNT(*)"}, values: [][]driver.Value{{rows}}}, nil
		}
	}
	for _, rule := range restoreSafetyRules {
		if query == rule.query {
			if c.state.failure == "safety:"+rule.table || len(args) != len(rule.args) {
				return nil, errors.New("injected restore safety failure")
			}
			if rule.table == "users" && args[0].Value != DisabledUserPasswordHash {
				return nil, errors.New("unbound password reset sentinel")
			}
			return &countRows{columns: []string{"COUNT(*)"}, values: [][]driver.Value{{c.state.safety[rule.table]}}}, nil
		}
	}
	return nil, errors.New("out of scope count query")
}

type countTx struct{ state *countState }

func (t countTx) Commit() error {
	t.state.commits++
	if t.state.failure == "commit" {
		return errors.New("injected commit failure")
	}
	return nil
}
func (t countTx) Rollback() error { t.state.rollbacks++; return nil }

type countRows struct {
	columns []string
	values  [][]driver.Value
}

func (r *countRows) Columns() []string { return r.columns }
func (r *countRows) Close() error      { return nil }
func (r *countRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}

func countDB(t *testing.T, state *countState) *sql.DB {
	t.Helper()
	db := sql.OpenDB(countConnector{state})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSQLCountCollector(t *testing.T) {
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	state := &countState{}
	snapshot, err := (SQLCountCollector{DB: countDB(t, state)}).CollectSnapshot(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tables) != 15 || state.commits != 1 || state.rollbacks != 0 || len(state.queries) != 31 ||
		state.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || !state.begin.ReadOnly {
		t.Fatalf("incomplete read-only snapshot: %+v %+v", snapshot, state)
	}
	for _, item := range snapshot.Tables {
		if item.Rows != 2 || strings.HasPrefix(item.Table, "system_backup") {
			t.Fatalf("out of scope or non-redacted count: %+v", item)
		}
	}
	for _, failure := range []string{"count:users", "myisam:users", "commit"} {
		t.Run(failure, func(t *testing.T) {
			state := &countState{failure: failure}
			got, err := (SQLCountCollector{DB: countDB(t, state)}).CollectSnapshot(context.Background(), scope)
			if err == nil || len(got.Tables) != 0 {
				t.Fatalf("partial snapshot returned: %+v, %v", got, err)
			}
		})
	}
	state = &countState{}
	if draft, err := pinnedScope(t, registryFixture(t, false)); err == nil || draft != nil {
		t.Fatal("draft registry constructed a scope", err)
	}
	got, err := (SQLCountCollector{DB: countDB(t, state)}).CollectSnapshot(context.Background(), nil)
	if err == nil || len(got.Tables) != 0 || len(state.queries) != 0 {
		t.Fatalf("draft registry reached SQL: %+v, %v, %v", got, err, state.queries)
	}
	if got, err := (SQLCountCollector{DB: countDB(t, state)}).CollectSnapshot(nil, scope); err == nil || len(got.Tables) != 0 {
		t.Fatalf("nil context admitted: %+v, %v", got, err)
	}
}
