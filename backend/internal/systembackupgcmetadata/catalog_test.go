package systembackupgcmetadata

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type metadataModel struct {
	t                                                   *testing.T
	rows                                                map[string][][]driver.Value
	grants                                              []string
	queries                                             []string
	identityReads, grantReads, connects, begins, writes int
	identityChange                                      func(int, []driver.Value)
	grantsChange                                        func(int, []string) []string
	faultKind, fault                                    string
	onQuery                                             func(string)
	remaining                                           time.Duration
	openRows                                            int
	viewFault                                           string
	viewResponse                                        func([]driver.Value) [][]driver.Value
}
type metadataDriver struct{}

func (metadataDriver) Open(string) (driver.Conn, error)               { return nil, errors.New("no DSN or network") }
func (m *metadataModel) Connect(context.Context) (driver.Conn, error) { m.connects++; return m, nil }
func (*metadataModel) Driver() driver.Driver                          { return metadataDriver{} }
func (*metadataModel) Close() error                                   { return nil }
func (m *metadataModel) Prepare(string) (driver.Stmt, error) {
	m.t.Error("unexpected prepare")
	return nil, ErrUnavailable
}
func (m *metadataModel) Begin() (driver.Tx, error) {
	m.begins++
	m.t.Error("observer must not begin a transaction")
	return nil, ErrUnavailable
}
func (m *metadataModel) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	m.writes++
	m.t.Error("observer issued a write")
	return nil, ErrUnavailable
}

type metadataRows struct {
	width, index        int
	data                [][]driver.Value
	readFail, closeFail bool
	closed, extraSet    bool
	onClose             func()
}

func (r *metadataRows) Columns() []string { return make([]string, r.width) }
func (r *metadataRows) Close() error {
	if !r.closed {
		r.closed = true
		if r.onClose != nil {
			r.onClose()
		}
	}
	if r.closeFail {
		return errors.New("PRIVATE close program definition")
	}
	return nil
}
func (r *metadataRows) HasNextResultSet() bool { return r.extraSet }
func (r *metadataRows) NextResultSet() error {
	if !r.extraSet {
		return io.EOF
	}
	r.extraSet = false
	return nil
}
func (m *metadataModel) ownRows(r *metadataRows) driver.Rows {
	m.openRows++
	r.onClose = func() { m.openRows-- }
	return r
}
func (r *metadataRows) Next(out []driver.Value) error {
	if r.readFail && r.index > 0 {
		return errors.New("PRIVATE partial program read")
	}
	if r.index >= len(r.data) {
		return io.EOF
	}
	copy(out, r.data[r.index])
	r.index++
	return nil
}
func (m *metadataModel) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if m.openRows != 0 {
		m.t.Error("query before previous rows closed")
	}
	if len(args) != 0 {
		m.t.Error("unexpected query parameter")
	}
	m.queries = append(m.queries, q)
	deadline, ok := ctx.Deadline()
	if !ok {
		m.t.Error("unbounded observer read")
	} else {
		m.remaining = time.Until(deadline)
		if m.remaining > maxReadTime {
			m.t.Error("observer increased its five-second bound")
		}
	}
	if q == identitySQL {
		m.identityReads++
		v := []driver.Value{"11111111-2222-4333-8444-555555555555", "metadata_test", "gc_observer@localhost", "NONE", int64(42), time.Now().UTC().Truncate(time.Microsecond), int64(0), "8.4.8", "utf8mb4", "utf8mb4", "utf8mb4"}
		if m.identityChange != nil {
			m.identityChange(m.identityReads, v)
		}
		return m.ownRows(&metadataRows{width: 11, data: [][]driver.Value{v}}), nil
	}
	if q == grantsSQL {
		m.grantReads++
		ss := append([]string(nil), m.grants...)
		if m.grantsChange != nil {
			ss = m.grantsChange(m.grantReads, ss)
		}
		var data [][]driver.Value
		for _, s := range ss {
			data = append(data, []driver.Value{s})
		}
		return m.ownRows(&metadataRows{width: 1, data: data}), nil
	}
	if strings.HasPrefix(q, "SHOW CREATE VIEW ") {
		if m.onQuery != nil {
			m.onQuery("view-create")
		}
		if m.viewFault == "query" {
			return nil, errors.New("PRIVATE show view failure")
		}
		for _, row := range m.rows["views"] {
			d := definitions[4]
			v := viewRef{schema: row[cell(d, "TABLE_SCHEMA")].(string), name: row[cell(d, "TABLE_NAME")].(string)}
			expected, _ := viewCreateSQL(v)
			if q != expected {
				continue
			}
			data := []driver.Value{v.name, "CREATE ALGORITHM=UNDEFINED DEFINER=`metadata_owner`@`localhost` SQL SECURITY INVOKER VIEW `" + strings.ReplaceAll(v.name, "`", "``") + "` AS " + row[cell(d, "VIEW_DEFINITION")].(string), row[cell(d, "CHARACTER_SET_CLIENT")], row[cell(d, "COLLATION_CONNECTION")]}
			rows := [][]driver.Value{data}
			if m.viewResponse != nil {
				rows = m.viewResponse(data)
			}
			width := 4
			if m.viewFault == "scan" {
				width = 3
			}
			return m.ownRows(&metadataRows{width: width, data: rows, readFail: m.viewFault == "read", closeFail: m.viewFault == "close", extraSet: m.viewFault == "resultset"}), nil
		}
		m.t.Error("unbound view query", q)
		return nil, ErrUnavailable
	}
	for _, d := range definitions {
		if q != d.query() {
			continue
		}
		if m.onQuery != nil {
			m.onQuery(d.kind)
		}
		if m.faultKind == d.kind && m.fault == "query" {
			return nil, errors.New("PRIVATE query definition body")
		}
		width := len(d.columns())
		if m.faultKind == d.kind && m.fault == "scan" {
			width++
		}
		return m.ownRows(&metadataRows{width: width, data: m.rows[d.kind], readFail: m.faultKind == d.kind && m.fault == "read", closeFail: m.faultKind == d.kind && m.fault == "close"}), nil
	}
	m.t.Error("unreviewed query", q)
	return nil, ErrUnavailable
}

func baseRecord(d definition, values map[string]driver.Value) []driver.Value {
	defaults := map[string]driver.Value{"SQL_MODE": "STRICT_TRANS_TABLES", "DEFINER": "metadata_owner@localhost", "CHARACTER_SET_CLIENT": "utf8mb4", "COLLATION_CONNECTION": "utf8mb4_bin", "DATABASE_COLLATION": "utf8mb4_bin", "ROUTINE_CATALOG": "def", "SPECIFIC_CATALOG": "def", "TABLE_CATALOG": "def", "ORIGINATOR": "1"}
	for k, v := range values {
		defaults[k] = v
	}
	if d.body != "" {
		if body, ok := defaults[d.body].(string); ok {
			defaults[d.body+"_BYTES"] = strconv.Itoa(len(body))
		}
	}
	var row []driver.Value
	for _, k := range d.columns() {
		row = append(row, defaults[k])
	}
	return row
}
func stringType() map[string]driver.Value {
	return map[string]driver.Value{"DATA_TYPE": "varchar", "CHARACTER_MAXIMUM_LENGTH": "4", "CHARACTER_OCTET_LENGTH": "16", "CHARACTER_SET_NAME": "utf8mb4", "COLLATION_NAME": "utf8mb4_bin", "DTD_IDENTIFIER": "varchar(4)"}
}
func fill(a, b map[string]driver.Value) map[string]driver.Value {
	for k, v := range b {
		a[k] = v
	}
	return a
}
func fixture(t *testing.T) (*metadataModel, *Source) {
	t.Helper()
	m := &metadataModel{t: t, rows: map[string][][]driver.Value{}, grants: []string{"GRANT SELECT, SHOW VIEW, TRIGGER, EVENT ON *.* TO 'gc_observer'@'localhost'", "GRANT SHOW_ROUTINE ON *.* TO 'gc_observer'@'localhost'"}}
	m.rows["triggers"] = [][]driver.Value{baseRecord(definitions[0], map[string]driver.Value{"TRIGGER_SCHEMA": "sample", "TRIGGER_NAME": "trigger_a", "EVENT_OBJECT_SCHEMA": "sample", "EVENT_OBJECT_TABLE": "owner_table", "ACTION_TIMING": "BEFORE", "EVENT_MANIPULATION": "DELETE", "ACTION_ORDER": "1", "ACTION_ORIENTATION": "ROW", "ACTION_STATEMENT": "SET @observed=1"})}
	m.rows["routines"] = [][]driver.Value{baseRecord(definitions[1], fill(map[string]driver.Value{"SPECIFIC_NAME": "function_f", "ROUTINE_SCHEMA": "sample", "ROUTINE_NAME": "function_f", "ROUTINE_TYPE": "FUNCTION", "ROUTINE_BODY": "SQL", "ROUTINE_DEFINITION": "RETURN 'value'", "EXTERNAL_LANGUAGE": "SQL", "PARAMETER_STYLE": "SQL", "IS_DETERMINISTIC": "YES", "SQL_DATA_ACCESS": "NO SQL", "SECURITY_TYPE": "DEFINER"}, stringType())), baseRecord(definitions[1], map[string]driver.Value{"SPECIFIC_NAME": "procedure_p", "ROUTINE_SCHEMA": "sample", "ROUTINE_NAME": "procedure_p", "ROUTINE_TYPE": "PROCEDURE", "DATA_TYPE": "", "DTD_IDENTIFIER": "", "ROUTINE_BODY": "SQL", "ROUTINE_DEFINITION": "BEGIN SELECT 1; END", "EXTERNAL_LANGUAGE": "SQL", "PARAMETER_STYLE": "SQL", "IS_DETERMINISTIC": "NO", "SQL_DATA_ACCESS": "READS SQL DATA", "SECURITY_TYPE": "INVOKER"})}
	m.rows["parameters"] = [][]driver.Value{baseRecord(definitions[2], fill(map[string]driver.Value{"SPECIFIC_SCHEMA": "sample", "SPECIFIC_NAME": "function_f", "ROUTINE_TYPE": "FUNCTION", "ORDINAL_POSITION": "0"}, stringType())), baseRecord(definitions[2], fill(map[string]driver.Value{"SPECIFIC_SCHEMA": "sample", "SPECIFIC_NAME": "function_f", "ROUTINE_TYPE": "FUNCTION", "ORDINAL_POSITION": "1", "PARAMETER_MODE": "IN", "PARAMETER_NAME": "argument"}, stringType())), baseRecord(definitions[2], map[string]driver.Value{"SPECIFIC_SCHEMA": "sample", "SPECIFIC_NAME": "procedure_p", "ROUTINE_TYPE": "PROCEDURE", "ORDINAL_POSITION": "1", "PARAMETER_MODE": "INOUT", "PARAMETER_NAME": "result", "DATA_TYPE": "bigint", "NUMERIC_PRECISION": "20", "NUMERIC_SCALE": "0", "DTD_IDENTIFIER": "bigint"})}
	m.rows["events"] = [][]driver.Value{baseRecord(definitions[3], map[string]driver.Value{"EVENT_SCHEMA": "sample", "EVENT_NAME": "event_a", "TIME_ZONE": "+00:00", "EVENT_BODY": "SQL", "EVENT_DEFINITION": "BEGIN SELECT 1; END", "EVENT_TYPE": "ONE TIME", "EXECUTE_AT": "2027-01-01 00:00:00", "STATUS": "DISABLED", "ON_COMPLETION": "PRESERVE"})}
	m.rows["views"] = [][]driver.Value{baseRecord(definitions[4], map[string]driver.Value{"TABLE_SCHEMA": "sample", "TABLE_NAME": "view_a", "VIEW_DEFINITION": "select 1 AS a", "CHECK_OPTION": "NONE", "IS_UPDATABLE": "NO", "SECURITY_TYPE": "INVOKER"})}
	db := sql.OpenDB(m)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	pin, err := GrantsDigest(m.grants)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{DB: db, ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "metadata_test", Account: "gc_observer@localhost", Version: "8.4.8", GrantsSHA256: pin})
	if err != nil {
		t.Fatal(err)
	}
	return m, s
}
func cell(d definition, name string) int {
	for n, k := range d.columns() {
		if k == name {
			return n
		}
	}
	panic("unknown fixture field")
}
func denied(t *testing.T, m *metadataModel, s *Source, ctx context.Context) {
	t.Helper()
	o, err := s.Read(ctx)
	if !errors.Is(err, ErrUnavailable) || o != (Observation{}) || strings.Contains(fmt.Sprint(err), "PRIVATE") || m.begins != 0 || m.writes != 0 {
		t.Fatal("incomplete capture escaped or changed transaction", err, o)
	}
}
func repin(t *testing.T, m *metadataModel, s *Source) {
	t.Helper()
	p, e := GrantsDigest(m.grants)
	if e != nil {
		t.Fatal(e)
	}
	s.c.GrantsSHA256 = p
}

func TestReadCompleteProgramsAndOpaqueObservation(t *testing.T) {
	m, s := fixture(t)
	o, err := s.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := o.Digests()
	if p.Triggers.Rows != 1 || p.Routines.Rows != 2 || p.Parameters.Rows != 3 || p.Events.Rows != 1 || p.Views.Rows != 1 || p.ViewCreates.Rows != 1 || !digestPattern.MatchString(p.Combined) || m.identityReads != 2 || m.grantReads != 2 || len(m.queries) != 10 || m.connects != 1 || m.begins != 0 || m.writes != 0 || m.openRows != 0 {
		t.Fatal("capture scope or connection protocol", p, m.queries)
	}
	a, b := o.Interval()
	if b.Before(a) || b.Sub(a) > maxReadTime {
		t.Fatal("interval")
	}
	if _, err = json.Marshal(o); !errors.Is(err, ErrInvalid) {
		t.Fatal("observation became a public capability")
	}
	if strings.Contains(fmt.Sprintf("%#v %+v", o, o), "value") {
		t.Fatal("program body exposed")
	}
	q := Queries()
	if len(q) != 7 {
		t.Fatal("query catalog")
	}
	for _, v := range q {
		if strings.Contains(v.SQL, " WHERE ") || strings.Contains(v.SQL, "FOR UPDATE") || strings.HasPrefix(v.SQL, "CALL ") {
			t.Fatal("filtered or side-effecting catalog")
		}
	}
	q[2].SQL = "PRIVATE replacement"
	if Queries()[2].SQL == q[2].SQL {
		t.Fatal("query catalog mutable")
	}
}

func TestIndependentFramingGoldenAndNullEmpty(t *testing.T) {
	m, s := fixture(t)
	pin, _ := GrantsDigest(m.grants)
	if pin != "80efcf1b5ee62e4b3ccc30bbe6f673abdbe2c37ea5eafda5ff82701933f957a6" {
		t.Fatal("independent grant framing vector", pin)
	}
	before := append([]string(nil), m.grants...)
	reversed := []string{m.grants[1], m.grants[0]}
	p, _ := GrantsDigest(reversed)
	if p != pin || !reflect.DeepEqual(before, m.grants) {
		t.Fatal("grant ordering or mutation")
	}
	for k := range m.rows {
		m.rows[k] = nil
	}
	o, e := s.Read(context.Background())
	if e != nil || o.Digests().Triggers.SHA256 != "067ecda4a0afbb92f9d58f651af4482f1162406a79ef3502dff6316cbf82c85e" {
		t.Fatal("independent empty catalog vector", e, o.Digests())
	}
	m, s = fixture(t)
	a, e := s.Read(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	m.rows["routines"][0][cell(definitions[1], "EXTERNAL_NAME")] = ""
	b, e := s.Read(context.Background())
	if e != nil || a.Digests() == b.Digests() {
		t.Fatal("NULL collapsed to empty", e)
	}
	row := m.rows["views"][0]
	row[cell(definitions[4], "VIEW_DEFINITION")] = "SELECT 'a\x00<&中文'"
	row[cell(definitions[4], "VIEW_DEFINITION_BYTES")] = strconv.Itoa(len(row[cell(definitions[4], "VIEW_DEFINITION")].(string)))
	c, e := s.Read(context.Background())
	if e != nil || c.Digests() == b.Digests() {
		t.Fatal("length framed UTF-8/NUL body lost", e)
	}
}

func TestPrivilegeCoverageCannotBeReplacedByHash(t *testing.T) {
	for _, mode := range []string{"SELECT", "SHOW VIEW", "SHOW_ROUTINE", "TRIGGER", "EVENT", "schema_limited", "execute_only", "grant_option", "role", "proxy", "foreign_recipient", "duplicate_privilege", "duplicate_statement", "changed_pin", "oversize", "invalid_utf8", "late_revoke", "late_role_grant", "allowed_backticks", "allowed_usage"} {
		t.Run(mode, func(t *testing.T) {
			m, s := fixture(t)
			switch mode {
			case "SELECT", "SHOW VIEW", "TRIGGER", "EVENT":
				m.grants[0] = strings.ReplaceAll(m.grants[0], mode+", ", "")
				m.grants[0] = strings.ReplaceAll(m.grants[0], ", "+mode+" ON", " ON")
			case "SHOW_ROUTINE":
				m.grants = m.grants[:1]
			case "schema_limited":
				m.grants[0] = strings.ReplaceAll(m.grants[0], "*.*", "`metadata_test`.*")
			case "execute_only":
				m.grants = []string{"GRANT EXECUTE ON *.* TO 'gc_observer'@'localhost'"}
			case "grant_option":
				m.grants[0] += " WITH GRANT OPTION"
			case "role":
				m.grants = append(m.grants, "GRANT `role_a` TO 'gc_observer'@'localhost'")
			case "proxy":
				m.grants = append(m.grants, "GRANT PROXY ON 'other'@'%' TO 'gc_observer'@'localhost'")
			case "foreign_recipient":
				m.grants[0] = strings.ReplaceAll(m.grants[0], "gc_observer", "other_observer")
			case "duplicate_privilege":
				m.grants[0] = strings.ReplaceAll(m.grants[0], "SELECT,", "SELECT, SELECT,")
			case "duplicate_statement":
				m.grants = append(m.grants, m.grants[0])
				denied(t, m, s, context.Background())
				return
			case "changed_pin":
				s.c.GrantsSHA256 = strings.Repeat("a", 64)
				denied(t, m, s, context.Background())
				return
			case "oversize":
				m.grants[0] = strings.Repeat("s", 2049)
				denied(t, m, s, context.Background())
				return
			case "invalid_utf8":
				m.grants[0] = "\xff"
				denied(t, m, s, context.Background())
				return
			case "late_revoke":
				m.grantsChange = func(n int, ss []string) []string {
					if n == 2 {
						return ss[:1]
					}
					return ss
				}
			case "late_role_grant":
				m.grantsChange = func(n int, ss []string) []string {
					if n == 2 {
						return append(ss, "GRANT `role_a` TO 'gc_observer'@'localhost'")
					}
					return ss
				}
			case "allowed_backticks":
				for n := range m.grants {
					m.grants[n] = strings.ReplaceAll(m.grants[n], "'gc_observer'@'localhost'", "`gc_observer`@`localhost`")
				}
			case "allowed_usage":
				m.grants = append(m.grants, "GRANT USAGE ON *.* TO 'gc_observer'@'localhost'")
			}
			repin(t, m, s)
			if strings.HasPrefix(mode, "allowed_") {
				if _, e := s.Read(context.Background()); e != nil {
					t.Fatal(e)
				}
				return
			}
			denied(t, m, s, context.Background())
		})
	}
}

func TestObserverIdentityAndLiveConnection(t *testing.T) {
	for _, stage := range []int{1, 2} {
		for _, mode := range []string{"server", "database", "account", "role", "zero_connection", "new_connection", "future_clock", "old_clock", "clock_offset", "version", "client", "connection_charset", "results", "backward_clock"} {
			t.Run(fmt.Sprint(stage)+"/"+mode, func(t *testing.T) {
				m, s := fixture(t)
				m.identityChange = func(n int, v []driver.Value) {
					if n != stage {
						return
					}
					switch mode {
					case "server":
						v[0] = "other-server"
					case "database":
						v[1] = "other-db"
					case "account":
						v[2] = "root@localhost"
					case "role":
						v[3] = "`role_a`@`%`"
					case "zero_connection":
						v[4] = int64(0)
					case "new_connection":
						if n == 1 {
							v[4] = int64(43)
						} else {
							v[4] = int64(44)
						}
					case "future_clock":
						v[5] = time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
					case "old_clock":
						v[5] = time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
					case "clock_offset":
						v[6] = int64(1)
					case "version":
						v[7] = "8.4.9"
					case "client":
						v[8] = "latin1"
					case "connection_charset":
						v[9] = "latin1"
					case "results":
						v[10] = "latin1"
					case "backward_clock":
						if n == 2 {
							v[5] = time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
						} else {
							v[5] = time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
						}
					}
				}
				denied(t, m, s, context.Background())
			})
		}
	}
}

func TestEveryDomainFailureReturnsNoPartialCatalog(t *testing.T) {
	for _, d := range definitions {
		for _, mode := range []string{"query", "scan", "read", "close", "duplicate", "reversed", "null_key", "oversize_key", "invalid_utf8"} {
			t.Run(d.kind+"/"+mode, func(t *testing.T) {
				m, s := fixture(t)
				switch mode {
				case "query", "scan", "read", "close":
					m.faultKind, m.fault = d.kind, mode
				case "duplicate":
					m.rows[d.kind] = append(m.rows[d.kind], append([]driver.Value(nil), m.rows[d.kind][0]...))
				case "reversed":
					if len(m.rows[d.kind]) > 1 {
						a := m.rows[d.kind]
						a[0], a[len(a)-1] = a[len(a)-1], a[0]
					} else {
						a := append([]driver.Value(nil), m.rows[d.kind][0]...)
						a[cell(d, d.keys[1])] = "aaa"
						m.rows[d.kind] = append(m.rows[d.kind], a)
					}
				case "null_key":
					m.rows[d.kind][0][cell(d, d.keys[0])] = nil
				case "oversize_key":
					m.rows[d.kind][0][cell(d, d.keys[0])] = strings.Repeat("a", 257)
				case "invalid_utf8":
					m.rows[d.kind][0][cell(d, d.keys[0])] = "\xff"
				}
				denied(t, m, s, context.Background())
			})
		}
	}
	for _, d := range definitions {
		if d.body == "" {
			continue
		}
		for _, mode := range []string{"null", "empty", "wrong_length", "noncanonical_length", "too_big", "bad_utf8"} {
			t.Run(d.kind+"/body/"+mode, func(t *testing.T) {
				m, s := fixture(t)
				row := m.rows[d.kind][0]
				b, n := cell(d, d.body), cell(d, d.body+"_BYTES")
				switch mode {
				case "null":
					row[b] = nil
				case "empty":
					row[b] = ""
					row[n] = "0"
				case "wrong_length":
					row[n] = "1"
				case "noncanonical_length":
					row[n] = "0001"
				case "too_big":
					row[b] = strings.Repeat("a", maxFieldBytes+1)
					row[n] = strconv.Itoa(maxFieldBytes + 1)
				case "bad_utf8":
					row[b] = "\xff"
					row[n] = "1"
				}
				denied(t, m, s, context.Background())
			})
		}
	}
}

func TestRoutineSignaturesAndReturnMetadata(t *testing.T) {
	for _, mode := range []string{"orphan", "missing_return", "return_type", "return_name", "return_mode", "parameter_gap", "parameter_mode", "parameter_name", "wrong_kind", "procedure_return", "function_out", "same_name_distinct_kind"} {
		t.Run(mode, func(t *testing.T) {
			m, s := fixture(t)
			d := definitions[2]
			rows := m.rows["parameters"]
			switch mode {
			case "orphan":
				rows[0][cell(d, "SPECIFIC_NAME")] = "unknown"
			case "missing_return":
				m.rows["parameters"] = rows[1:]
			case "return_type":
				rows[0][cell(d, "COLLATION_NAME")] = "utf8mb4_general_ci"
			case "return_name":
				rows[0][cell(d, "PARAMETER_NAME")] = "return_name"
			case "return_mode":
				rows[0][cell(d, "PARAMETER_MODE")] = "OUT"
			case "parameter_gap":
				rows[1][cell(d, "ORDINAL_POSITION")] = "2"
			case "parameter_mode":
				rows[2][cell(d, "PARAMETER_MODE")] = "unknown"
			case "parameter_name":
				rows[2][cell(d, "PARAMETER_NAME")] = nil
			case "wrong_kind":
				rows[0][cell(d, "ROUTINE_TYPE")] = "UNKNOWN"
			case "procedure_return":
				rows[2][cell(d, "ORDINAL_POSITION")] = "0"
			case "function_out":
				rows[1][cell(d, "PARAMETER_MODE")] = "OUT"
			case "same_name_distinct_kind":
				r := append([]driver.Value(nil), m.rows["routines"][1]...)
				r[cell(definitions[1], "SPECIFIC_NAME")] = "function_f"
				r[cell(definitions[1], "ROUTINE_NAME")] = "function_f"
				m.rows["routines"] = append(m.rows["routines"][:1], r, m.rows["routines"][1])
				p := append([]driver.Value(nil), rows[2]...)
				p[cell(d, "SPECIFIC_NAME")] = "function_f"
				m.rows["parameters"] = append(rows[:2], p, rows[2])
			}
			if mode == "same_name_distinct_kind" {
				if _, e := s.Read(context.Background()); e != nil {
					t.Fatal(e)
				}
				return
			}
			denied(t, m, s, context.Background())
		})
	}
}

func TestEveryProjectedCellChangesOrRejectsItsDigest(t *testing.T) {
	for _, d := range definitions {
		for _, field := range d.columns() {
			t.Run(d.kind+"/"+field, func(t *testing.T) {
				m, s := fixture(t)
				before, e := s.Read(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				row := m.rows[d.kind][0]
				at := cell(d, field)
				if row[at] == nil {
					row[at] = "changed"
				} else {
					row[at] = fmt.Sprint(row[at]) + "_changed"
				}
				if field == d.body {
					row[cell(d, d.body+"_BYTES")] = strconv.Itoa(len(row[at].(string)))
				}
				after, e := s.Read(context.Background())
				if e == nil && after.Digests() == before.Digests() {
					t.Fatal("projection field was omitted", d.kind, field)
				}
				if e != nil && (!errors.Is(e, ErrUnavailable) || after != (Observation{})) {
					t.Fatal("projection failure returned partial catalog", e)
				}
			})
		}
	}
}

func TestCatalogBoundsAndOriginalContext(t *testing.T) {
	for _, n := range []int{10000, 10001} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			m, s := fixture(t)
			d := definitions[0]
			rows := make([][]driver.Value, n)
			for i := range rows {
				rows[i] = append([]driver.Value(nil), m.rows["triggers"][0]...)
				rows[i][cell(d, "TRIGGER_NAME")] = fmt.Sprintf("t%05d", i)
			}
			m.rows["triggers"] = rows
			o, e := s.Read(context.Background())
			if n == 10000 {
				if e != nil || o.Digests().Triggers.Rows != 10000 {
					t.Fatal("legal bound refused", e)
				}
			} else if !errors.Is(e, ErrUnavailable) || o != (Observation{}) {
				t.Fatal("row bound bypassed", e)
			}
		})
	}
	t.Run("field_exact_bound", func(t *testing.T) {
		m, s := fixture(t)
		d := definitions[4]
		m.rows["views"][0][cell(d, d.body)] = strings.Repeat("a", maxFieldBytes)
		m.rows["views"][0][cell(d, d.body+"_BYTES")] = strconv.Itoa(maxFieldBytes)
		if _, e := s.Read(context.Background()); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("aggregate_bytes", func(t *testing.T) {
		m, s := fixture(t)
		d := definitions[4]
		var rows [][]driver.Value
		for n := 0; n < 1100; n++ {
			row := append([]driver.Value(nil), m.rows["views"][0]...)
			row[cell(d, "TABLE_NAME")] = fmt.Sprintf("v%05d", n)
			row[cell(d, d.body)] = strings.Repeat("a", maxFieldBytes)
			row[cell(d, d.body+"_BYTES")] = strconv.Itoa(maxFieldBytes)
			rows = append(rows, row)
		}
		m.rows["views"] = rows
		denied(t, m, s, context.Background())
	})
	t.Run("caller_deadline", func(t *testing.T) {
		m, s := fixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, e := s.Read(ctx); e != nil || m.remaining > 2*time.Second {
			t.Fatal("caller context replaced", e)
		}
	})
	t.Run("canceled_before", func(t *testing.T) {
		m, s := fixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		denied(t, m, s, ctx)
		if m.connects != 0 {
			t.Fatal("opened connection after cancel")
		}
	})
	t.Run("canceled_during", func(t *testing.T) {
		m, s := fixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m.onQuery = func(k string) {
			if k == "events" {
				cancel()
			}
		}
		denied(t, m, s, ctx)
	})
	t.Run("empty_without_privilege", func(t *testing.T) {
		m, s := fixture(t)
		for k := range m.rows {
			m.rows[k] = nil
		}
		m.grants = m.grants[:1]
		repin(t, m, s)
		denied(t, m, s, context.Background())
	})
}

func TestConfigurationAndZeroValue(t *testing.T) {
	_, s := fixture(t)
	for _, mode := range []string{"database", "server", "root", "account", "version", "pin", "nil_db"} {
		t.Run(mode, func(t *testing.T) {
			c := s.c
			switch mode {
			case "database":
				c.Database = "other;DROP"
			case "server":
				c.ServerUUID = "unknown"
			case "root":
				c.Account = "root@localhost"
			case "account":
				c.Account = "observer';--"
			case "version":
				c.Version = "8.0.36"
			case "pin":
				c.GrantsSHA256 = ""
			case "nil_db":
				c.DB = nil
			}
			if _, e := New(c); !errors.Is(e, ErrInvalid) {
				t.Fatal("bad deployment profile accepted", e)
			}
		})
	}
	var zero Source
	if _, e := zero.Read(context.Background()); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	var nilSource *Source
	if _, e := nilSource.Read(context.Background()); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e := s.Read(nil); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	for _, ss := range [][]string{nil, {"same", "same"}, {strings.Repeat("x", 2049)}, {"\xff"}, {"contains\x00nul"}} {
		if _, e := GrantsDigest(ss); !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid offline digest input", e)
		}
	}
}
