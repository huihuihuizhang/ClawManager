package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

type migrationPinState struct {
	server, database                         string
	applied                                  []string
	activeGate                               int64
	connections, releases, identities, gates int
	writes                                   []string
	recorded                                 []string
	ledgerMissing                            bool
}
type migrationPinDriver struct{}

func (migrationPinDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector required")
}

type migrationPinConnector struct{ state *migrationPinState }

func (c migrationPinConnector) Driver() driver.Driver { return migrationPinDriver{} }
func (c migrationPinConnector) Connect(context.Context) (driver.Conn, error) {
	c.state.connections++
	return &migrationPinConn{s: c.state}, nil
}

type migrationPinConn struct {
	s                  *migrationPinState
	locked, identified bool
	locks              int
}

func (*migrationPinConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*migrationPinConn) Close() error { return nil }
func (*migrationPinConn) Begin() (driver.Tx, error) {
	return nil, errors.New("DDL must use advisory lock")
}

type migrationPinRows struct {
	width  int
	values [][]driver.Value
}

func (r *migrationPinRows) Columns() []string { return make([]string, r.width) }
func (*migrationPinRows) Close() error        { return nil }
func (r *migrationPinRows) Next(out []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(out, r.values[0])
	r.values = r.values[1:]
	return nil
}
func pinRow(v ...driver.Value) driver.Rows { return &migrationPinRows{len(v), [][]driver.Value{v}} }
func (c *migrationPinConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT CONCAT(") {
		return pinRow("cm:migrate:fixture"), nil
	}
	if strings.HasPrefix(q, "SELECT GET_LOCK(") {
		c.locks++
		c.locked = true
		return pinRow(int64(1)), nil
	}
	if strings.HasPrefix(q, "SELECT RELEASE_LOCK(") {
		if !c.locked {
			return nil, errors.New("lock absent")
		}
		c.locks--
		c.locked = c.locks > 0
		c.s.releases++
		return pinRow(int64(1)), nil
	}
	if !c.locked {
		return nil, errors.New("query outside migration exclusion")
	}
	if q == "SELECT @@server_uuid,DATABASE()" {
		c.identified = true
		c.s.identities++
		return pinRow(c.s.server, c.s.database), nil
	}
	if !c.identified {
		return nil, errors.New("query before database pin check")
	}
	if strings.Contains(q, "information_schema.COLUMNS") {
		return pinRow(int64(0), int64(0), int64(0)), nil
	}
	if strings.Contains(strings.ToLower(q), "information_schema.tables") {
		if c.s.ledgerMissing {
			return pinRow(int64(0)), nil
		}
		return pinRow(int64(1)), nil
	}
	if q == "SELECT filename FROM schema_migrations" {
		rows := &migrationPinRows{width: 1}
		for _, s := range c.s.applied {
			rows.values = append(rows.values, []driver.Value{s})
		}
		return rows, nil
	}
	if strings.Contains(q, "SELECT COUNT(*) FROM `system_backup_") {
		c.s.gates++
		return pinRow(c.s.activeGate), nil
	}
	return nil, errors.New("unexpected query")
}
func (c *migrationPinConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !c.locked || !c.identified || c.s.gates != 5 || c.s.activeGate != 0 {
		return nil, errors.New("unguarded DDL")
	}
	c.s.writes = append(c.s.writes, q)
	if strings.HasPrefix(q, "INSERT INTO schema_migrations") {
		if len(args) != 2 {
			return nil, errors.New("invalid ledger insert")
		}
		c.s.recorded = append(c.s.recorded, args[0].Value.(string))
	}
	return driver.RowsAffected(1), nil
}

func TestPinnedMigrationTargetAndCaptureExclusion(t *testing.T) {
	catalog, err := EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"idempotent", "wrong-server", "wrong-database", "wrong-catalog", "unknown-ledger", "active-capture", "apply-runtime"} {
		t.Run(name, func(t *testing.T) {
			target := MigrationTarget{ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "clawmanager", CatalogSHA256: catalog.Hash}
			state := &migrationPinState{server: target.ServerUUID, database: target.Database, applied: append([]string(nil), catalog.Filenames...)}
			switch name {
			case "wrong-server":
				state.server = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
			case "wrong-database":
				state.database = "other_installation"
			case "wrong-catalog":
				target.CatalogSHA256 = strings.Repeat("a", 64)
			case "unknown-ledger":
				state.applied = append(state.applied, "999_unknown.sql")
			case "active-capture":
				state.applied = state.applied[:len(state.applied)-1]
				state.activeGate = 1
			case "apply-runtime":
				// This case exercises the four-table registration runtime, not
				// whichever unrelated migration was appended most recently.
				state.applied = nil
				for _, filename := range catalog.Filenames {
					if filename != "109_backup_v2_add_system_backup_registration_runtime.sql" {
						state.applied = append(state.applied, filename)
					}
				}
			}
			database := sql.OpenDB(migrationPinConnector{state})
			defer database.Close()
			err = ApplyPinnedMigrations(context.Background(), database, target)
			if name == "idempotent" || name == "apply-runtime" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe migration admitted")
			}
			if name == "wrong-catalog" {
				if state.connections != 0 {
					t.Fatal("catalog mismatch opened database")
				}
				return
			}
			if state.connections != 1 || state.identities != 1 || state.releases != 2 {
				t.Fatal("target and DDL did not share one released connection")
			}
			if name != "apply-runtime" && len(state.writes) != 0 {
				t.Fatal("rejection/retry executed DDL")
			}
			if name == "apply-runtime" {
				if len(state.writes) != 5 || state.gates != 5 {
					t.Fatal("runtime migration was not guarded or recorded exactly once")
				}
				for _, q := range state.writes[:4] {
					if !strings.HasPrefix(q, "CREATE TABLE IF NOT EXISTS system_backup_") {
						t.Fatal("unexpected runtime migration write")
					}
				}
			}
		})
	}
}

func TestRuntimeMigrationPreservesProvenAddendumDDL(t *testing.T) {
	formal, err := embeddedMigrations.ReadFile("migrations/109_backup_v2_add_system_backup_registration_runtime.sql")
	if err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile("../../../docs/backup-team-integration/reference/080_add_system_backup_registration_runtime.sql")
	if err != nil {
		t.Fatal(err)
	}
	var mapping backupImportMap
	if json.Unmarshal(backupImportMapJSON, &mapping) != nil {
		t.Fatal("invalid import map")
	}
	for before, after := range mapping.Tables {
		previous = []byte(strings.ReplaceAll(string(previous), before, after))
	}
	if !reflect.DeepEqual(splitSQLStatements(string(formal)), splitSQLStatements(string(previous))) {
		t.Fatal("formal migration diverged from previously validated runtime DDL")
	}
}
