package install

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// database/sql protocol models exercise the ACTUAL typed source read. They
// neither emulate successful physical hold/admin authentication nor mint a
// valid originalHistorySQLMetadata/SourceSet/PreparedCoverage.
type historyMetadataSQLModel struct {
	columns, keys, values           [][]driver.Value
	valueNames                      []string
	queries                         []string
	readOnly, tailError, closeError bool
}
type historyMetadataDriver struct{ model *historyMetadataSQLModel }
type historyMetadataConn struct{ model *historyMetadataSQLModel }
type historyMetadataTx struct{}
type historyMetadataRows struct {
	names                 []string
	rows                  [][]driver.Value
	at                    int
	tailError, closeError bool
}

var historyMetadataDriverID atomic.Uint64

func (d historyMetadataDriver) Open(string) (driver.Conn, error) {
	return &historyMetadataConn{d.model}, nil
}
func (*historyMetadataConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*historyMetadataConn) Close() error { return nil }
func (c *historyMetadataConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *historyMetadataConn) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	c.model.readOnly = options.ReadOnly
	return historyMetadataTx{}, nil
}
func (historyMetadataTx) Commit() error   { return errors.New("model does not permit commit") }
func (historyMetadataTx) Rollback() error { return nil }
func (c *historyMetadataConn) QueryContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	m := c.model
	m.queries = append(m.queries, query)
	if strings.Contains(query, "information_schema.COLUMNS") {
		return &historyMetadataRows{names: []string{"name", "type", "nullable", "extra", "charset", "collation"}, rows: m.columns}, nil
	}
	if strings.Contains(query, "information_schema.KEY_COLUMN_USAGE") {
		return &historyMetadataRows{names: []string{"name"}, rows: m.keys}, nil
	}
	if strings.HasPrefix(query, "SELECT * FROM system_backup_installation_state ORDER BY singleton_id") {
		if m.readOnly && strings.HasSuffix(query, " FOR SHARE") {
			return nil, errors.New("locking statement refused by read-only model")
		}
		return &historyMetadataRows{names: m.valueNames, rows: m.values, tailError: m.tailError, closeError: m.closeError}, nil
	}
	return nil, errors.New("unexpected query")
}
func (r *historyMetadataRows) Columns() []string { return r.names }
func (r *historyMetadataRows) Close() error {
	if r.closeError {
		return errors.New("close failed")
	}
	return nil
}
func (r *historyMetadataRows) Next(dst []driver.Value) error {
	if r.at >= len(r.rows) {
		if r.tailError {
			return errors.New("unread tail")
		}
		return io.EOF
	}
	copy(dst, r.rows[r.at])
	r.at++
	return nil
}

func newHistoryMetadataModel(t *testing.T) (*sql.DB, *historyMetadataSQLModel) {
	t.Helper()
	m := &historyMetadataSQLModel{
		columns: [][]driver.Value{
			{"singleton_id", "tinyint", "NO", "", "", ""},
			{"origin_installation_id", "varchar(64)", "NO", "", "utf8mb4", "utf8mb4_0900_ai_ci"},
			{"config_version", "bigint unsigned", "NO", "", "", ""},
			{"controller_seen_at", "datetime(6)", "YES", "", "", ""},
		}, keys: [][]driver.Value{{"singleton_id"}},
		values:     [][]driver.Value{{int64(1), []byte("installation_original"), int64(0), nil}},
		valueNames: []string{"singleton_id", "origin_installation_id", "config_version", "controller_seen_at"},
	}
	name := fmt.Sprintf("original-history-metadata-%d", historyMetadataDriverID.Add(1))
	sql.Register(name, historyMetadataDriver{m})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal("model database open failed")
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, m
}

func TestOriginalHistoryMetadataTypedSingletonReadAndLockMode(t *testing.T) {
	for _, locked := range []bool{false, true} {
		t.Run(fmt.Sprintf("locked-%v", locked), func(t *testing.T) {
			db, m := newHistoryMetadataModel(t)
			tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: !locked})
			if err != nil {
				t.Fatal("model transaction failed")
			}
			defer tx.Rollback()
			row, err := readOriginalHistorySingletonRow(context.Background(), tx, "installation_original", locked)
			if err != nil || len(row.cells) != 4 || string(row.cells[0]) != "1" || string(row.cells[2]) != "0" || row.cells[3] != nil {
				t.Fatal("actual typed row or NULL identity lost")
			}
			if len(m.queries) != 3 || strings.Contains(m.queries[2], " WHERE ") || strings.HasSuffix(m.queries[2], " FOR SHARE") != locked {
				t.Fatal("row omission or wrong lock mode")
			}
			retained := row.cells[1]
			row.clear()
			for _, value := range retained {
				if value != 0 {
					t.Fatal("private row buffer not cleared")
				}
			}
		})
	}
}

func TestOriginalHistoryMetadataRejectsUnknownSchemaOrOriginalValues(t *testing.T) {
	cases := []string{"extra-column", "missing-column", "wrong-type", "extra-key", "wrong-key", "foreign-installation", "configured-version", "other-singleton", "additional-row", "no-row", "invalid-seen", "unread-tail", "close-error", "wrong-order"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			db, m := newHistoryMetadataModel(t)
			switch name {
			case "extra-column":
				m.columns = append(m.columns, []driver.Value{"unclassified", "varchar(10)", "YES", "", "utf8mb4", "utf8mb4_0900_ai_ci"})
			case "missing-column":
				m.columns = m.columns[:3]
			case "wrong-type":
				m.columns[2][1] = "varchar(128)"
			case "extra-key":
				m.keys = append(m.keys, []driver.Value{"config_version"})
			case "wrong-key":
				m.keys[0][0] = "origin_installation_id"
			case "foreign-installation":
				m.values[0][1] = []byte("installation_other")
			case "configured-version":
				m.values[0][2] = int64(1)
			case "other-singleton":
				m.values[0][0] = int64(2)
			case "additional-row":
				m.values = append(m.values, []driver.Value{int64(2), []byte("installation_other"), int64(0), nil})
			case "no-row":
				m.values = nil
			case "invalid-seen":
				m.values[0][3] = []byte("not-an-original-timestamp")
			case "unread-tail":
				m.tailError = true
			case "close-error":
				m.closeError = true
			case "wrong-order":
				m.valueNames = []string{"origin_installation_id", "singleton_id", "config_version", "controller_seen_at"}
			}
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal("model transaction failed")
			}
			defer tx.Rollback()
			row, err := readOriginalHistorySingletonRow(context.Background(), tx, "installation_original", true)
			if err == nil || row.cells != nil {
				row.clear()
				t.Fatal("unclassified original SQL source accepted")
			}
		})
	}
}

func TestOriginalHistoryMetadataPreservesExactHeartbeatBytes(t *testing.T) {
	for _, heartbeat := range []driver.Value{[]byte("2026-11-04 01:02:03.123456"), time.Date(2026, 11, 4, 1, 2, 3, 123456000, time.UTC)} {
		db, model := newHistoryMetadataModel(t)
		model.values[0][3] = heartbeat
		tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal("model transaction failed")
		}
		row, err := readOriginalHistorySingletonRow(context.Background(), tx, "installation_original", false)
		_ = tx.Rollback()
		if err != nil || row.cells[3] == nil {
			t.Fatal("actual original heartbeat lost")
		}
		want := "2026-11-04 01:02:03.123456"
		if value, ok := heartbeat.(time.Time); ok {
			want = value.Format(time.RFC3339Nano)
		}
		if string(row.cells[3]) != want {
			t.Fatal("original driver bytes normalized")
		}
		row.clear()
	}
}

func originalMetadataFactsFixture() a.SQLCoverageCensusFacts {
	f := a.SQLCoverageCensusFacts{Database: reg.DatabaseIdentity{ServerUUID: "original-server", Database: "original_db"}, InstallationID: "installation_original", ObservedAt: time.Now()}
	for _, name := range []string{originalHistorySingletonTable, "system_backup_config_versions", "system_backup_v2_configs", "system_backup_tasks"} {
		table := a.SQLCoverageTable{Partition: reg.RetainedArtifacts, Table: name, SchemaSHA256: strings.Repeat("a", 64), RowsSHA256: strings.Repeat("b", 64)}
		if name == originalHistorySingletonTable {
			table.Rows, table.Bytes = 1, 30
		}
		f.Tables = append(f.Tables, table)
	}
	return f
}

func TestOriginalHistoryMetadataOnlyExactSingletonCanBeClassified(t *testing.T) {
	if !originalHistorySingletonOnly(originalMetadataFactsFixture()) {
		t.Fatal("exact reviewed singleton DATA shape rejected")
	}
	for _, name := range []string{"all-zero", "extra-singleton", "config-history", "task-history", "extra-source-row", "duplicate-table", "bad-schema", "missing-version-table"} {
		t.Run(name, func(t *testing.T) {
			f := originalMetadataFactsFixture()
			switch name {
			case "all-zero":
				f.Tables[0].Rows, f.Tables[0].Bytes = 0, 0
			case "extra-singleton":
				f.Tables[0].Rows = 2
			case "config-history":
				f.Tables[1].Rows, f.Tables[1].Bytes = 1, 12
			case "task-history":
				f.Tables[3].Rows, f.Tables[3].Bytes = 1, 12
			case "extra-source-row":
				f.Tables = append(f.Tables, a.SQLCoverageTable{Table: "system_backup_v2_evidence", Rows: 1, Bytes: 4, SchemaSHA256: strings.Repeat("c", 64), RowsSHA256: strings.Repeat("d", 64)})
			case "duplicate-table":
				f.Tables = append(f.Tables, f.Tables[0])
			case "bad-schema":
				f.Tables[0].SchemaSHA256 = "unknown"
			case "missing-version-table":
				f.Tables = f.Tables[:3]
			}
			if originalHistorySingletonOnly(f) {
				t.Fatal("nonempty/unclassified source DATA allowed")
			}
		})
	}
	first := originalMetadataFactsFixture()
	later := first
	later.ObservedAt = first.ObservedAt.Add(time.Second)
	if !sameOriginalHistorySQLFacts(first, later) {
		t.Fatal("sampling time affected original content equality")
	}
	later.Tables = append([]a.SQLCoverageTable(nil), first.Tables...)
	later.Tables[0].RowsSHA256 = strings.Repeat("c", 64)
	if sameOriginalHistorySQLFacts(first, later) || reflect.DeepEqual(first.Tables, later.Tables) {
		t.Fatal("original row byte/hash change hidden")
	}
}

func TestOriginalHistoryMetadataCannotMintFromMissingOriginalOwners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if result, err := prepareOriginalHistorySQLMetadata(ctx, nil, nil); err == nil || result != nil {
		t.Fatal("missing source owner minted classification")
	}
	zero := &originalHistorySQLMetadata{}
	if _, err := json.Marshal(zero); err == nil {
		t.Fatal("private classification serialized")
	}
	if zero.classifiesOriginalSQL(ctx, originalMetadataFactsFixture()) || zero.recheckBeforeSQL(ctx) == nil {
		t.Fatal("zero classification became an authority")
	}
}
