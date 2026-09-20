package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

type bootstrapSchemaState struct {
	ledgerExists bool
	gateExists   bool
	queries      []string
	ddlCount     int
}

type bootstrapSchemaConnector struct{ state *bootstrapSchemaState }

func (c bootstrapSchemaConnector) Connect(context.Context) (driver.Conn, error) {
	return &bootstrapSchemaConn{state: c.state}, nil
}
func (c bootstrapSchemaConnector) Driver() driver.Driver {
	return bootstrapSchemaDriver{state: c.state}
}

type bootstrapSchemaDriver struct{ state *bootstrapSchemaState }

func (d bootstrapSchemaDriver) Open(string) (driver.Conn, error) {
	return &bootstrapSchemaConn{state: d.state}, nil
}

type bootstrapSchemaConn struct{ state *bootstrapSchemaState }

func (*bootstrapSchemaConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared statement")
}
func (*bootstrapSchemaConn) Close() error { return nil }
func (*bootstrapSchemaConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}

func (c *bootstrapSchemaConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "information_schema.tables") || len(args) != 1 {
		return nil, errors.New("unexpected schema query")
	}
	table, ok := args[0].Value.(string)
	if !ok {
		return nil, errors.New("schema query table name is not a string")
	}
	c.state.queries = append(c.state.queries, table)
	var count int64
	switch table {
	case schemaMigrationsTable:
		if c.state.ledgerExists {
			count = 1
		}
	case "system_maintenance_locks":
		if c.state.gateExists {
			count = 1
		}
	default:
		return nil, errors.New("unexpected schema table name")
	}
	return &bootstrapSchemaRows{count: count}, nil
}

func (c *bootstrapSchemaConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(query, "CREATE TABLE IF NOT EXISTS schema_migrations") {
		return nil, errors.New("unexpected schema DDL")
	}
	c.state.ddlCount++
	return driver.RowsAffected(0), nil
}

type bootstrapSchemaRows struct {
	count int64
	read  bool
}

func (*bootstrapSchemaRows) Columns() []string { return []string{"count"} }
func (*bootstrapSchemaRows) Close() error      { return nil }
func (r *bootstrapSchemaRows) Next(dest []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read = true
	dest[0] = r.count
	return nil
}

func TestMigrationBootstrapAvoidsDDLWhenLedgerAlreadyExists(t *testing.T) {
	state := &bootstrapSchemaState{ledgerExists: true, gateExists: true}
	db := sql.OpenDB(bootstrapSchemaConnector{state: state})
	defer db.Close()
	if err := ensureSchemaMigrationsTable(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if state.ddlCount != 0 || len(state.queries) != 1 || state.queries[0] != schemaMigrationsTable {
		t.Fatalf("existing ledger bootstrap queries=%v ddl=%d", state.queries, state.ddlCount)
	}
}

func TestMigrationBootstrapCreatesLedgerOnlyOnFreshSchema(t *testing.T) {
	state := &bootstrapSchemaState{}
	db := sql.OpenDB(bootstrapSchemaConnector{state: state})
	defer db.Close()
	if err := ensureSchemaMigrationsTable(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if state.ddlCount != 1 || len(state.queries) != 2 {
		t.Fatalf("fresh schema bootstrap queries=%v ddl=%d", state.queries, state.ddlCount)
	}
}

func TestMigrationBootstrapRejectsMissingLedgerBesideGate(t *testing.T) {
	state := &bootstrapSchemaState{gateExists: true}
	db := sql.OpenDB(bootstrapSchemaConnector{state: state})
	defer db.Close()
	if err := ensureSchemaMigrationsTable(context.Background(), db); err == nil {
		t.Fatal("missing migration ledger beside capture gate was accepted")
	}
	if state.ddlCount != 0 || len(state.queries) != 2 {
		t.Fatalf("corrupt schema bootstrap queries=%v ddl=%d", state.queries, state.ddlCount)
	}
}
