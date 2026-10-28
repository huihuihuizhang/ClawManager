package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fieldInspectionFixture() fieldSQLRequest {
	return fieldSQLRequest{SchemaVersion: fieldSQLRequestVersion, Mode: "metadata", DSNEnv: "SYSTEM_BACKUP_DOWNLOAD_DSN_FILE", ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "fixture_db", ExpectedUser: "download_user", Tables: []string{"users"}}
}

type fieldInspectionModel struct {
	request                             fieldSQLRequest
	fault                               string
	queries                             []string
	identities, begin, rollback, commit int
	cancel                              context.CancelFunc
}
type fieldInspectionConnector struct{ m *fieldInspectionModel }
type fieldInspectionDriver struct{}

func (fieldInspectionDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }
func (c fieldInspectionConnector) Driver() driver.Driver       { return fieldInspectionDriver{} }
func (c fieldInspectionConnector) Connect(context.Context) (driver.Conn, error) {
	return &fieldInspectionConn{c.m}, nil
}

type fieldInspectionConn struct{ m *fieldInspectionModel }

func (*fieldInspectionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("PRIVATE SQL prepare forbidden")
}
func (*fieldInspectionConn) Begin() (driver.Tx, error) {
	return nil, errors.New("PRIVATE non-context transaction forbidden")
}
func (*fieldInspectionConn) Close() error { return nil }
func (c *fieldInspectionConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.m.begin++
	if !o.ReadOnly || o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("PRIVATE unsafe transaction")
	}
	if c.m.fault == "begin" {
		return nil, errors.New("PRIVATE DSN=secret begin")
	}
	return &fieldInspectionTx{c.m}, nil
}

type fieldInspectionTx struct{ m *fieldInspectionModel }

func (t *fieldInspectionTx) Commit() error {
	t.m.commit++
	return errors.New("PRIVATE unexpected commit")
}
func (t *fieldInspectionTx) Rollback() error {
	t.m.rollback++
	if t.m.fault == "rollback" {
		return errors.New("PRIVATE rollback")
	}
	if t.m.fault == "cancel_after_rollback" {
		t.m.cancel()
	}
	return nil
}

type fieldInspectionRows struct {
	width int
	data  [][]driver.Value
	fault string
}

func (r *fieldInspectionRows) Columns() []string { return make([]string, r.width) }
func (r *fieldInspectionRows) Close() error {
	if r.fault == "close" {
		return errors.New("PRIVATE close")
	}
	return nil
}
func (r *fieldInspectionRows) Next(out []driver.Value) error {
	if len(r.data) == 0 {
		if r.fault == "stream" {
			return errors.New("PRIVATE stream")
		}
		return io.EOF
	}
	copy(out, r.data[0])
	r.data = r.data[1:]
	return nil
}
func (c *fieldInspectionConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	m := c.m
	m.queries = append(m.queries, q)
	if m.fault == "query" {
		return nil, errors.New("PRIVATE password=secret SQL")
	}
	if strings.HasPrefix(q, "SELECT @@server_uuid,DATABASE(),CURRENT_USER()") {
		m.identities++
		server, user, role := m.request.ServerUUID, m.request.ExpectedUser+"@%", "NONE"
		if m.fault == "server" {
			server = "different-server"
		}
		if m.fault == "user" {
			user = "different@%"
		}
		if m.fault == "late_role" && m.identities == 2 {
			role = "ACTIVE"
		}
		if m.fault == "identity_scan" {
			return &fieldInspectionRows{width: 5, data: [][]driver.Value{{nil, nil, nil, nil, nil}}}, nil
		}
		return &fieldInspectionRows{width: 5, data: [][]driver.Value{{server, m.request.Database, user, role, "2026-10-21T00:00:00.000001Z"}}}, nil
	}
	if strings.HasPrefix(q, "SELECT @@server_uuid,DATABASE(),@@datadir") {
		return &fieldInspectionRows{width: 4, data: [][]driver.Value{{m.request.ServerUUID, m.request.Database, "/var/lib/mysql/", "2026-10-21T00:00:00.000002Z"}}}, nil
	}
	if q == "SHOW GRANTS" {
		grant := "GRANT SELECT ON `fixture_db`.`users` TO 'download_user'@'%'"
		if m.fault == "bad_grant" {
			grant = "PRIVATE password=secret"
		}
		rows := &fieldInspectionRows{width: 1, data: [][]driver.Value{{grant}}}
		if m.fault == "grant_stream" {
			rows.fault = "stream"
		}
		if m.fault == "grant_close" {
			rows.fault = "close"
		}
		return rows, nil
	}
	for n, expected := range fieldMetadataSQL(m.request.Tables) {
		if q == expected {
			rows := &fieldInspectionRows{width: 1}
			if n == 0 && m.fault != "missing_table" {
				for _, table := range m.request.Tables {
					raw, _ := json.Marshal(map[string]any{"kind": "table", "table": table, "engine": "InnoDB", "collation": "utf8mb4_0900_ai_ci"})
					rows.data = append(rows.data, []driver.Value{raw})
				}
			}
			if n == 1 {
				raw := []byte(`{"kind":"column","table":"users","name":"id","ordinal":1}`)
				if m.fault == "metadata_json" {
					raw = []byte(`{"kind":"column","kind":"table","table":"users"}`)
				}
				if m.fault == "oversized_record" {
					raw = bytes.Repeat([]byte("x"), 65537)
				}
				rows.data = [][]driver.Value{{raw}}
				if m.fault == "metadata_stream" {
					rows.fault = "stream"
				}
				if m.fault == "metadata_close" {
					rows.fault = "close"
				}
			}
			return rows, nil
		}
	}
	return nil, errors.New("PRIVATE unknown SQL")
}

func TestFieldInspectionRequestAndModeBoundary(t *testing.T) {
	r := fieldInspectionFixture()
	raw, _ := json.Marshal(r)
	if _, err := decodeFieldSQLRequest(raw); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*fieldSQLRequest)
	}{
		{"unknown_mode", func(r *fieldSQLRequest) { r.Mode = "execute" }},
		{"arbitrary_env", func(r *fieldSQLRequest) { r.DSNEnv = "PASSWORD_FILE" }},
		{"table_injection", func(r *fieldSQLRequest) { r.Tables = []string{"users);DROP TABLE users"} }},
		{"duplicate_table", func(r *fieldSQLRequest) { r.Tables = []string{"users", "users"} }},
		{"null_tables", func(r *fieldSQLRequest) { r.Tables = nil }},
		{"identity_with_tables", func(r *fieldSQLRequest) { r.Mode = "identity" }},
		{"wrong_uuid", func(r *fieldSQLRequest) { r.ServerUUID = "unbound" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := r
			test.edit(&v)
			b, _ := json.Marshal(v)
			if _, err := decodeFieldSQLRequest(b); err != errFieldSQLInspection {
				t.Fatal("request admitted")
			}
		})
	}
	for _, b := range [][]byte{append(raw, []byte(` {}`)...), []byte(strings.Replace(string(raw), `"mode":"metadata"`, `"mode":"metadata","mode":"identity"`, 1)), []byte(strings.Replace(string(raw), `"mode":"metadata"`, `"mode":"metadata","sql":"DELETE FROM users"`, 1)), bytes.Repeat([]byte(" "), 65537)} {
		if _, err := decodeFieldSQLRequest(b); err != errFieldSQLInspection {
			t.Fatal("unclosed JSON admitted")
		}
	}
	if !fieldInspectionFlags([]string{"inspect-sql-evidence"}, 0) {
		t.Fatal("mode rejected")
	}
	for _, names := range [][]string{{"inspect-sql-evidence", "runtime"}, {"inspect-sql-evidence", "download-runtime"}, {"inspect-sql-evidence", "check-activation"}, {"inspect-sql-evidence", "collect-capacity"}, {"inspect-sql-evidence", "listen"}} {
		if fieldInspectionFlags(names, 0) {
			t.Fatal("conflicting mode admitted")
		}
	}
	if fieldInspectionFlags([]string{"inspect-sql-evidence"}, 1) {
		t.Fatal("positional admitted")
	}
}

func TestFieldInspectionReadsOriginalDSNWithoutExport(t *testing.T) {
	r := fieldInspectionFixture()
	dir := t.TempDir()
	file := filepath.Join(dir, "dsn")
	getenv := func(name string) string {
		if name != r.DSNEnv {
			t.Fatal("unexpected credential reference")
		}
		return file
	}
	for _, test := range []struct {
		name, dsn string
		ok        bool
	}{
		{"original", "download_user:PRIVATE-password@tcp(mysql.invalid:3306)/fixture_db?parseTime=true&tls=true", true},
		{"wrong_user", "other:PRIVATE-password@tcp(mysql.invalid:3306)/fixture_db", false},
		{"wrong_database", "download_user:PRIVATE-password@tcp(mysql.invalid:3306)/other", false},
		{"multi_statements", "download_user:PRIVATE-password@tcp(mysql.invalid:3306)/fixture_db?multiStatements=true", false},
		{"malformed", "PRIVATE-password", false},
		{"oversize", strings.Repeat("x", 8193), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(file, []byte(test.dsn), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := fieldInspectionDSN(r, getenv)
			if test.ok {
				if err != nil || cfg.User != r.ExpectedUser || cfg.DBName != r.Database || cfg.MultiStatements || cfg.TLSConfig != "true" {
					t.Fatal("original DSN not preserved")
				}
			} else if err != errFieldSQLInspection || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("credential error leaked or accepted")
			}
		})
	}
	if _, err := fieldInspectionDSN(r, func(string) string { return dir }); err != errFieldSQLInspection {
		t.Fatal("directory admitted")
	}
	if _, err := fieldInspectionDSN(r, func(string) string { return "relative-dsn" }); err != errFieldSQLInspection {
		t.Fatal("relative path admitted")
	}
}

func TestFieldInspectionOneReadOnlyConnectionRollbackAndCompleteMetadata(t *testing.T) {
	r := fieldInspectionFixture()
	r.Tables = []string{"users", "audit_logs"}
	m := &fieldInspectionModel{request: r}
	db := sql.OpenDB(fieldInspectionConnector{m})
	defer db.Close()
	result, err := inspectFieldSQL(context.Background(), db, r)
	if err != nil || !result.ReadOnly || !result.RolledBack || m.begin != 1 || m.rollback != 1 || m.commit != 0 || m.identities != 2 || len(result.Metadata) != 3 || len(m.queries) != 11 {
		t.Fatalf("incomplete inspection: %v %#v", err, m)
	}
	for _, q := range m.queries {
		if !strings.HasPrefix(q, "SELECT ") && q != "SHOW GRANTS" {
			t.Fatal("non-read query")
		}
	}
	queries := fieldMetadataSQL(r.Tables)
	if len(queries) != 8 || !strings.Contains(queries[3], "OR (REFERENCED_TABLE_SCHEMA=DATABASE()") || !strings.Contains(queries[5], "UNIQUE_CONSTRAINT_SCHEMA=DATABASE()") || !strings.Contains(queries[7], "information_schema.ROUTINES") {
		t.Fatal("cross-schema or routine metadata omitted")
	}
}

func TestFieldInspectionFailureReturnsNoPartialPublicResult(t *testing.T) {
	for _, fault := range []string{"begin", "query", "server", "user", "late_role", "identity_scan", "bad_grant", "grant_stream", "grant_close", "metadata_json", "oversized_record", "missing_table", "metadata_stream", "metadata_close", "rollback", "cancel_after_rollback"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := fieldInspectionFixture()
			m := &fieldInspectionModel{request: r, fault: fault, cancel: cancel}
			db := sql.OpenDB(fieldInspectionConnector{m})
			defer db.Close()
			result, err := inspectFieldSQL(ctx, db, r)
			if err != errFieldSQLInspection || !reflect.DeepEqual(result, fieldSQLResult{}) || m.commit != 0 {
				t.Fatal("failure returned data or driver detail")
			}
		})
	}
}

func TestFieldInspectionIdentityOnlyForOriginalCapacitySQLTime(t *testing.T) {
	r := fieldInspectionFixture()
	r.Mode = "identity"
	r.Tables = []string{}
	raw, _ := json.Marshal(r)
	if _, err := decodeFieldSQLRequest(raw); err != nil {
		t.Fatal(err)
	}
	m := &fieldInspectionModel{request: r}
	db := sql.OpenDB(fieldInspectionConnector{m})
	defer db.Close()
	result, err := inspectFieldSQL(context.Background(), db, r)
	if err != nil || result.CapacityIdentity == nil || result.CapacityIdentity.ServerUUID != r.ServerUUID || len(m.queries) != 3 || len(result.Metadata) != 0 || len(result.Grants) != 0 || m.rollback != 1 || m.commit != 0 {
		t.Fatal("identity mode widened or incomplete")
	}
}

func TestFieldInspectionInvalidInputNeverEmitsOrLoadsCredentials(t *testing.T) {
	for _, input := range []string{"", `{"password":"PRIVATE"}`, strings.Repeat(" ", 65537)} {
		var output bytes.Buffer
		loaded := false
		err := runFieldSQLInspection(context.Background(), strings.NewReader(input), &output, func(string) string { loaded = true; return "PRIVATE" })
		if err != errFieldSQLInspection || output.Len() != 0 || loaded {
			t.Fatal("invalid request used credentials or emitted data")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if runFieldSQLInspection(ctx, strings.NewReader("{}"), &output, func(string) string { return "PRIVATE" }) != errFieldSQLInspection || output.Len() != 0 {
		t.Fatal("canceled request admitted")
	}
}
