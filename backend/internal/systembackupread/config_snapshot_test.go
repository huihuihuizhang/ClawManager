package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type configFixture struct {
	row        []driver.Value
	rows       [][]driver.Value
	queries    int
	rechecks   int
	deny       bool
	revoke     bool
	queryError bool
}

func (f *configFixture) AuthorizeRead(_ context.Context, tx *sql.Tx) (string, error) {
	if tx == nil || f.deny {
		return "", ErrDenied
	}
	return "installation_test", nil
}
func (f *configFixture) RecheckRead(_ context.Context, tx *sql.Tx, installation string) error {
	f.rechecks++
	if tx == nil || f.revoke || installation != "installation_test" {
		return ErrDenied
	}
	return nil
}

type configConnector struct{ f *configFixture }
type configConn struct{ f *configFixture }

func (c configConnector) Connect(context.Context) (driver.Conn, error) { return &configConn{c.f}, nil }
func (configConnector) Driver() driver.Driver                          { return pageDriver{} }
func (*configConn) Prepare(string) (driver.Stmt, error)                { return nil, errors.New("unexpected prepare") }
func (*configConn) Close() error                                       { return nil }
func (*configConn) Begin() (driver.Tx, error)                          { return pageTx{}, nil }
func (*configConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return pageTx{}, nil
}
func (c *configConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.f.queries++
	if c.f.queryError {
		return nil, errors.New("synthetic config query failure")
	}
	if strings.Contains(query, "ORDER BY c.version DESC LIMIT ? FOR SHARE") {
		continuation := strings.Contains(query, "c.version<=? AND c.version<?")
		if !strings.Contains(query, "c.canonical_config_json") ||
			!strings.Contains(query, configMaterializedSelect()) ||
			!strings.Contains(query, "c.origin_installation_id=s.origin_installation_id") ||
			!strings.Contains(query, "WHERE s.origin_installation_id=?") ||
			len(args) != 2 && len(args) != 4 || args[0].Value != "installation_test" ||
			continuation != (len(args) == 4) {
			return nil, errors.New("unsafe config list query")
		}
		limit, err := strconv.Atoi(fmt.Sprint(args[len(args)-1].Value))
		if err != nil || limit < 2 || limit > 501 {
			return nil, errors.New("invalid config list limit")
		}
		result := make([][]driver.Value, 0, limit)
		for _, row := range c.f.rows {
			version := row[2].(int64)
			if continuation {
				cutoff, _ := strconv.ParseInt(fmt.Sprint(args[1].Value), 10, 64)
				before, _ := strconv.ParseInt(fmt.Sprint(args[2].Value), 10, 64)
				if version > cutoff || version >= before {
					continue
				}
			}
			result = append(result, row)
			if len(result) == limit {
				break
			}
		}
		return &pageRows{columns: configColumns, values: result}, nil
	}
	if strings.Contains(query, "FROM system_backup_v2_configs AS c") {
		if strings.Contains(query, "canonical_config_json") || !strings.Contains(query, configMaterializedSelect()) ||
			!strings.HasSuffix(query, "FOR SHARE") || len(args) != 2 ||
			args[0].Value != "installation_test" || fmt.Sprint(args[1].Value) != "1" {
			return nil, errors.New("unsafe legacy config query")
		}
		if c.f.row == nil {
			return &pageRows{columns: legacyConfigColumns}, nil
		}
		row := append([]driver.Value{}, c.f.row[:6]...)
		row = append(row, c.f.row[7:10]...)
		row = append(row, c.f.row[12:]...)
		return &pageRows{columns: legacyConfigColumns, values: [][]driver.Value{row}}, nil
	}
	versionQuery := strings.Contains(query, "WHERE s.origin_installation_id=? AND c.version=?")
	if !strings.Contains(query, "c.canonical_config_json") ||
		!strings.Contains(query, configMaterializedSelect()) || !strings.HasSuffix(query, "FOR SHARE") ||
		!strings.Contains(query, "WHERE s.origin_installation_id=?") ||
		strings.Contains(query, "SELECT *") || len(args) == 0 || args[0].Value != "installation_test" ||
		versionQuery && len(args) != 2 ||
		!versionQuery && (len(args) != 1 || !strings.Contains(query, "c.version=s.active_config_version")) {
		return nil, errors.New("unsafe or unavailable config query")
	}
	if c.f.row == nil || versionQuery && fmt.Sprint(args[1].Value) != fmt.Sprint(c.f.row[2]) {
		return &pageRows{columns: configColumns}, nil
	}
	return &pageRows{columns: configColumns, values: [][]driver.Value{c.f.row}}, nil
}

var configColumns = append([]string{"schema_version", "origin_installation_id", "version", "row_version", "config_sha256", "config_size_bytes", "canonical_config_json", "created_by", "change_reason", "created_at", "active_config_version", "last_effective_enabled"}, configMaterializedColumns...)
var legacyConfigColumns = append([]string{"schema_version", "origin_installation_id", "version", "row_version", "config_sha256", "config_size_bytes", "created_by", "change_reason", "created_at"}, configMaterializedColumns...)

func TestConfigMaterializedProjectionMatchesMigrationColumns(t *testing.T) {
	raw, err := os.ReadFile("../db/migrations/097_backup_v2_add_system_backup_config_and_operations.sql")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, column := range configMaterializedColumns {
		if seen[column] || !regexp.MustCompile(`(?m)^\s*`+regexp.QuoteMeta(column)+`\s`).Match(raw) {
			t.Fatal("materialized ConfigValues column missing or duplicated in projection", column)
		}
		seen[column] = true
	}
}

func configTestFixture(t *testing.T) *configFixture {
	t.Helper()
	config := configResourceFixture(t)
	expected, ok := configExpectedMaterialized(config.canonical)
	if !ok {
		t.Fatal("invalid complete config fixture")
	}
	row := []driver.Value{"system-backup-config.v1", "installation_test", int64(1), int64(1),
		config.configSHA256, int64(len(config.canonical)), config.canonical, "42", nil,
		time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), int64(1), false}
	for _, value := range expected {
		row = append(row, value)
	}
	return &configFixture{row: row}
}

func TestReadActiveConfigRequiresAuthorizedMatchingCanonicalRow(t *testing.T) {
	f := configTestFixture(t)
	db := sql.OpenDB(configConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	row, err := r.ReadActiveConfig(context.Background())
	if err != nil || row.installationID != "installation_test" || row.version != 1 || f.rechecks != 1 || f.queries != 1 {
		t.Fatal("authorized canonical config not read", row.version, err, f.queries, f.rechecks)
	}
	if raw, err := json.Marshal(row); !errors.Is(err, ErrInvalid) || len(raw) != 0 {
		t.Fatal("internal config escaped as a wire resource", string(raw), err)
	}
	for _, target := range []string{"retention_seconds", "source_size_safety_factor", "parts_registry_sha256", "artifact_read_identity_hash"} {
		found := false
		for i, name := range configMaterializedColumns {
			if name != target {
				continue
			}
			found = true
			prior := f.row[12+i]
			f.row[12+i] = "invalid"
			if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Fatal("canonical config disagreed with materialized controller value", target, err)
			}
			f.row[12+i] = prior
			break
		}
		if !found {
			t.Fatal("missing materialized target", target)
		}
	}
	f.row[6] = []byte(`{"enabled":true}`)
	if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("hash mismatch was accepted", err)
	}
	f.row[6] = nil
	if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("legacy row without canonical bytes was accepted", err)
	}
	f = configTestFixture(t)
	db2 := sql.OpenDB(configConnector{f})
	defer db2.Close()
	r, err = NewReader(db2, f)
	if err != nil {
		t.Fatal(err)
	}
	f.row[8] = ""
	if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("invalid persisted change reason was accepted", err)
	}
}

func TestReadActiveConfigFailsClosedOnScopeAndDatabaseChanges(t *testing.T) {
	f := configTestFixture(t)
	db := sql.OpenDB(configConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	f.deny = true
	if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrDenied) || f.queries != 0 {
		t.Fatal("denied caller queried config", err)
	}
	f.deny = false
	f.revoke = true
	if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked config read escaped", err)
	}
	f.revoke = false
	f.row[1] = "installation_other"
	if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cross-install config escaped", err)
	}
	f.row = nil
	f.revoke = true
	if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal("revocation racing a miss became 404", err)
	}
	f.revoke = false
	if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatal("authorized missing config was not distinguished", err)
	}
	f.queryError = true
	if _, err := r.ReadActiveConfig(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("query failure became a successful empty config", err)
	}
}

func TestReadConfigVersionUsesExactVersionAndActiveState(t *testing.T) {
	f := configTestFixture(t)
	f.row[2] = int64(2)
	f.row[10] = int64(1)
	f.row[11] = true // The installation is enabled, but this version is historical.
	db := sql.OpenDB(configConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	row, err := r.ReadConfigVersion(context.Background(), 2)
	if err != nil || row.version != 2 || row.active || row.effective || f.rechecks != 1 {
		t.Fatal("historical version was not read as inactive", row.version, row.active, row.effective, err)
	}
	if _, err := r.ReadConfigVersion(context.Background(), 3); !errors.Is(err, ErrNotFound) {
		t.Fatal("different version matched historical row", err)
	}
	if _, err := r.ReadConfigVersion(context.Background(), 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero version was queried", err)
	}
	f.revoke = true
	if _, err := r.ReadConfigVersion(context.Background(), 3); !errors.Is(err, ErrDenied) {
		t.Fatal("revocation racing historical miss became 404", err)
	}
	f.revoke = false
	f.row[1] = "installation_other"
	if _, err := r.ReadConfigVersion(context.Background(), 2); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cross-install historical config escaped", err)
	}
}
