package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

type pageFixture struct {
	rows       [][]driver.Value
	queries    []string
	table      string
	deny       bool
	recheckErr bool
	rechecks   int
	badQuery   bool
}

func (f *pageFixture) AuthorizeRead(_ context.Context, tx *sql.Tx) (string, error) {
	if tx == nil || f.deny {
		return "", ErrDenied
	}
	return "installation_test", nil
}

func (f *pageFixture) RecheckRead(_ context.Context, tx *sql.Tx, installation string) error {
	f.rechecks++
	if tx == nil || installation != "installation_test" || f.recheckErr {
		return ErrDenied
	}
	return nil
}

type pageConnector struct{ f *pageFixture }
type pageDriver struct{}
type pageConn struct{ f *pageFixture }
type pageTx struct{}
type pageRows struct {
	columns []string
	values  [][]driver.Value
	next    int
}

func (c pageConnector) Connect(context.Context) (driver.Conn, error) { return &pageConn{f: c.f}, nil }
func (pageConnector) Driver() driver.Driver                          { return pageDriver{} }
func (pageDriver) Open(string) (driver.Conn, error)                  { return nil, errors.New("use connector") }
func (*pageConn) Prepare(string) (driver.Stmt, error)                { return nil, errors.New("use QueryContext") }
func (*pageConn) Close() error                                       { return nil }
func (*pageConn) Begin() (driver.Tx, error)                          { return pageTx{}, nil }
func (*pageConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return pageTx{}, nil
}
func (pageTx) Commit() error          { return nil }
func (pageTx) Rollback() error        { return nil }
func (r *pageRows) Columns() []string { return r.columns }
func (r *pageRows) Close() error      { return nil }
func (r *pageRows) Next(dest []driver.Value) error {
	if r.next >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.next])
	r.next++
	return nil
}

func (c *pageConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.f.queries = append(c.f.queries, query)
	if c.f.badQuery {
		return nil, errors.New("synthetic database failure")
	}
	if strings.Contains(query, "config_snapshot_json") || strings.Contains(query, "failure_message") || strings.Contains(query, "SELECT *") ||
		!strings.Contains(query, c.f.table) || len(args) == 0 || args[0].Value != "installation_test" {
		return nil, errors.New("unscoped or sensitive SQL")
	}
	if strings.HasPrefix(query, "SELECT COALESCE(MAX(id),0)") {
		return &pageRows{columns: []string{"cutoff"}, values: [][]driver.Value{{int64(3)}}}, nil
	}
	if strings.Contains(query, "WHERE origin_installation_id=? AND public_id=?") {
		if len(args) != 2 || !strings.HasPrefix(query, "SELECT "+taskProjectionColumns+" FROM ") {
			return nil, errors.New("incorrect detail base query")
		}
		for _, row := range c.f.rows {
			if row[1] == args[1].Value {
				return &pageRows{columns: taskColumns, values: [][]driver.Value{row}}, nil
			}
		}
		return &pageRows{columns: taskColumns}, nil
	}
	if !strings.Contains(query, "WHERE origin_installation_id=? AND id<?") || !strings.Contains(query, "ORDER BY id DESC LIMIT ?") {
		return nil, errors.New("incorrect keyset query")
	}
	upper, err := strconv.ParseUint(fmt.Sprint(args[1].Value), 10, 64)
	if err != nil {
		return nil, err
	}
	limit, err := strconv.Atoi(fmt.Sprint(args[len(args)-1].Value))
	if err != nil {
		return nil, err
	}
	status := ""
	if len(args) == 4 {
		status = args[2].Value.(string)
	}
	values := make([][]driver.Value, 0)
	for _, row := range c.f.rows {
		if uint64(row[0].(int64)) < upper && (status == "" || row[11] == status) {
			values = append(values, row)
		}
		if len(values) == limit {
			break
		}
	}
	return &pageRows{columns: taskColumns, values: values}, nil
}

var taskColumns = strings.Split(taskProjectionColumns, ",")

func makePageFixture(table, taskType, prefix string) *pageFixture {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	row := func(id int64, suffix string) []driver.Value {
		return []driver.Value{id, prefix + "00000000-0000-4000-8000-00000000000" + suffix,
			"installation_test", taskType, "admin", "42", "createSystemBackup",
			"request-key-123456", strings.Repeat("a", 64), "req_test", nil,
			"pending", "none", "none", true, int64(1), false, "none",
			int64(1), now.Add(time.Hour), now, now, "system-backup-task.v1"}
	}
	return &pageFixture{table: table, rows: [][]driver.Value{row(3, "3"), row(2, "2"), row(1, "1")}}
}

func TestTaskPagesBindInstallationAndKeyset(t *testing.T) {
	f := makePageFixture("system_backup_v2_backups", "backup", "sbk_")
	db := sql.OpenDB(pageConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.ListTasks(context.Background(), PageRequest{Kind: BackupTask, Limit: 2})
	if err != nil || len(first.Items) != 2 || first.CutoffID != 3 || first.BeforeID != 2 || !first.HasMore || first.Consistency != "stable_cutoff" {
		t.Fatal("first page", first, err)
	}
	second, err := r.ListTasks(context.Background(), PageRequest{InstallationID: first.InstallationID, Kind: BackupTask, Limit: 2, CutoffID: first.CutoffID, BeforeID: first.BeforeID})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != 1 || second.HasMore || f.rechecks != 2 {
		t.Fatal("second page", second, err)
	}
	for _, query := range f.queries {
		if strings.Contains(query, "config_snapshot_json") || strings.Contains(query, "failure_message") {
			t.Fatal("sensitive projection", query)
		}
	}
	if encoded, err := json.Marshal(first); !errors.Is(err, ErrInvalid) || len(encoded) != 0 {
		t.Fatal("internal page became a wire response", string(encoded), err)
	}
}

func TestTaskPagesFailClosedOnAuthorityAndDatabase(t *testing.T) {
	f := makePageFixture("system_backup_v2_backups", "backup", "sbk_")
	db := sql.OpenDB(pageConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	f.deny = true
	if page, err := r.ListTasks(context.Background(), PageRequest{Kind: BackupTask, Limit: 2}); !errors.Is(err, ErrDenied) || len(page.Items) != 0 || len(f.queries) != 0 {
		t.Fatal("denied request queried tasks", page, err)
	}
	f.deny = false
	f.recheckErr = true
	if page, err := r.ListTasks(context.Background(), PageRequest{Kind: BackupTask, Limit: 2}); !errors.Is(err, ErrDenied) || len(page.Items) != 0 {
		t.Fatal("revoked authority returned a page", page, err)
	}
	f.recheckErr = false
	f.badQuery = true
	if page, err := r.ListTasks(context.Background(), PageRequest{Kind: BackupTask, Limit: 2}); !errors.Is(err, ErrUnavailable) || len(page.Items) != 0 {
		t.Fatal("database failure became an empty page", page, err)
	}
	if page, err := r.ListTasks(context.Background(), PageRequest{Kind: BackupTask, Limit: 2, BeforeID: 1}); !errors.Is(err, ErrInvalid) || len(page.Items) != 0 {
		t.Fatal("unsigned page position accepted", page, err)
	}
	f.badQuery = false
	if page, err := r.ListTasks(context.Background(), PageRequest{InstallationID: "installation_other", Kind: BackupTask, Limit: 2, CutoffID: 3, BeforeID: 2}); !errors.Is(err, ErrDenied) || len(page.Items) != 0 {
		t.Fatal("cursor reused across installations", page, err)
	}
}

func TestTaskPagesRejectOutOfOrderAndDuplicateDatabaseRows(t *testing.T) {
	for _, mutation := range []struct {
		name string
		edit func(*pageFixture)
	}{
		{"ascending", func(f *pageFixture) { f.rows[0], f.rows[1] = f.rows[1], f.rows[0] }},
		{"duplicate", func(f *pageFixture) { f.rows[1] = append([]driver.Value(nil), f.rows[0]...) }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			f := makePageFixture("system_backup_v2_backups", "backup", "sbk_")
			mutation.edit(f)
			db := sql.OpenDB(pageConnector{f})
			defer db.Close()
			reader, err := NewReader(db, f)
			if err != nil {
				t.Fatal(err)
			}
			page, err := reader.ListTasks(context.Background(), PageRequest{Kind: BackupTask, Limit: 3})
			if !errors.Is(err, ErrUnavailable) || len(page.Items) != 0 {
				t.Fatal("invalid row order returned partial page", page, err)
			}
		})
	}
}

func TestTaskPagesRejectUnknownStoredSchemaVersion(t *testing.T) {
	f := makePageFixture("system_backup_v2_backups", "backup", "sbk_")
	f.rows[0][len(f.rows[0])-1] = "system-backup-task.v2"
	db := sql.OpenDB(pageConnector{f})
	defer db.Close()
	reader, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	page, err := reader.ListTasks(context.Background(), PageRequest{Kind: BackupTask, Limit: 2})
	if !errors.Is(err, ErrUnavailable) || len(page.Items) != 0 {
		t.Fatal("unknown stored schema was projected as v1", page, err)
	}
}

func TestTaskPagesUseFourDistinctTables(t *testing.T) {
	for _, test := range []struct {
		kind   TaskKind
		table  string
		prefix string
	}{
		{BackupTask, "system_backup_v2_backups", "sbk_"},
		{DrillTask, "system_backup_v2_restore_drills", "sdr_"},
		{PreflightTask, "system_backup_v2_preflights", "spf_"},
		{VerificationTask, "system_backup_v2_artifact_verifications", "sav_"},
	} {
		t.Run(string(test.kind), func(t *testing.T) {
			f := makePageFixture(test.table, string(test.kind), test.prefix)
			db := sql.OpenDB(pageConnector{f})
			defer db.Close()
			r, err := NewReader(db, f)
			if err != nil {
				t.Fatal(err)
			}
			page, err := r.ListTasks(context.Background(), PageRequest{Kind: test.kind, Limit: 1, Status: "pending"})
			if err != nil || len(page.Items) != 1 || page.Items[0].Kind != test.kind || page.Consistency != "eventual" || !page.HasMore {
				t.Fatal("wrong task query", page, err)
			}
		})
	}
}

func TestReadServiceContinuesOnlyAuthorizedInstallation(t *testing.T) {
	f := makePageFixture("system_backup_v2_backups", "backup", "sbk_")
	db := sql.OpenDB(pageConnector{f})
	defer db.Close()
	s, err := NewService(db, f, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.ListTasks(context.Background(), BackupTask, "", 2, "")
	if err != nil || len(first.Page.Items) != 2 || first.NextCursor == "" {
		t.Fatal("first page", first, err)
	}
	second, err := s.ListTasks(context.Background(), BackupTask, "", 2, first.NextCursor)
	if err != nil || len(second.Page.Items) != 1 || second.NextCursor != "" || second.Page.Items[0].ID != 1 {
		t.Fatal("second page", second, err)
	}
	if result, err := s.ListTasks(context.Background(), DrillTask, "", 2, first.NextCursor); !errors.Is(err, ErrInvalid) || len(result.Page.Items) != 0 {
		t.Fatal("cross-resource cursor reached database", result, err)
	}
	if encoded, err := json.Marshal(first); !errors.Is(err, ErrInvalid) || len(encoded) != 0 {
		t.Fatal("internal result serialized", string(encoded), err)
	}
}
