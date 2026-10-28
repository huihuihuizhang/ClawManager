package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

type operationListFixture struct {
	rows         [][]driver.Value
	installation string
	queries      []string
	rechecks     int
	revoke       bool
	failQuery    bool
}

func (f *operationListFixture) AuthorizeRead(_ context.Context, tx *sql.Tx) (string, error) {
	if tx == nil {
		return "", ErrDenied
	}
	return f.installation, nil
}
func (f *operationListFixture) RecheckRead(_ context.Context, tx *sql.Tx, installation string) error {
	f.rechecks++
	if tx == nil || f.revoke || installation != f.installation {
		return ErrDenied
	}
	return nil
}

type operationListConnector struct{ f *operationListFixture }
type operationListConn struct{ f *operationListFixture }

func (c operationListConnector) Connect(context.Context) (driver.Conn, error) {
	return &operationListConn{c.f}, nil
}
func (operationListConnector) Driver() driver.Driver { return pageDriver{} }
func (*operationListConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*operationListConn) Close() error              { return nil }
func (*operationListConn) Begin() (driver.Tx, error) { return pageTx{}, nil }
func (*operationListConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return pageTx{}, nil
}
func (c *operationListConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.f.queries = append(c.f.queries, query)
	if c.f.failQuery {
		return nil, errors.New("database unavailable")
	}
	if !strings.Contains(query, "system_backup_v2_operations") || len(args) == 0 || args[0].Value != c.f.installation ||
		strings.Contains(query, "failure_message") || strings.Contains(query, "response_evidence") ||
		strings.Contains(query, "external_action_public_ids_canonical_json") || strings.Contains(query, "SELECT *") {
		return nil, errors.New("unsafe operation list SQL")
	}
	if strings.HasPrefix(query, "SELECT COALESCE(MAX(id),0)") {
		var maximum int64
		for _, row := range c.f.rows {
			if row[0].(int64) > maximum {
				maximum = row[0].(int64)
			}
		}
		return &pageRows{columns: []string{"max_id"}, values: [][]driver.Value{{maximum}}}, nil
	}
	if !strings.Contains(query, "SELECT id,"+operationProjectionColumns) ||
		!strings.Contains(query, "WHERE origin_installation_id=? AND id<? ORDER BY id DESC LIMIT ?") || len(args) != 3 {
		return nil, errors.New("incorrect operation keyset SQL")
	}
	upper, err := strconv.ParseUint(fmt.Sprint(args[1].Value), 10, 64)
	if err != nil {
		return nil, err
	}
	limit, err := strconv.Atoi(fmt.Sprint(args[2].Value))
	if err != nil {
		return nil, err
	}
	values := make([][]driver.Value, 0, limit)
	for _, row := range c.f.rows {
		if uint64(row[0].(int64)) < upper {
			values = append(values, row)
		}
		if len(values) == limit {
			break
		}
	}
	return &pageRows{columns: append([]string{"id"}, operationColumns...), values: values}, nil
}

func makeOperationListFixture() *operationListFixture {
	base := operationTestFixture().row
	f := &operationListFixture{installation: "installation_test"}
	for id := int64(3); id >= 1; id-- {
		row := append([]driver.Value{id}, base...)
		row[2] = fmt.Sprintf("sop_00000000-0000-4000-8000-%012d", id)
		f.rows = append(f.rows, row)
	}
	return f
}

func TestOperationListPaginatesAuthorizedRedactedRows(t *testing.T) {
	f := makeOperationListFixture()
	db := sql.OpenDB(operationListConnector{f})
	defer db.Close()
	service, err := NewService(db, f, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.ListOperationDTO(context.Background(), 2, "")
	if err != nil || len(first.Items) != 2 || first.NextCursor == nil || first.Consistency != "stable_cutoff" ||
		first.Items[0].PublicID != "sop_00000000-0000-4000-8000-000000000003" {
		t.Fatal("first operation page", first, err)
	}
	second, err := service.ListOperationDTO(context.Background(), 2, *first.NextCursor)
	if err != nil || len(second.Items) != 1 || second.NextCursor != nil ||
		second.Items[0].PublicID != "sop_00000000-0000-4000-8000-000000000001" || f.rechecks != 2 {
		t.Fatal("second operation page", second, err)
	}
	for _, query := range f.queries {
		if strings.Contains(query, "failure_message") || strings.Contains(query, "response_evidence") {
			t.Fatal("sensitive column selected", query)
		}
	}
	for _, token := range []string{*first.NextCursor + "x", ""} {
		if token == "" {
			if _, err := service.ListOperationDTO(context.Background(), 3, *first.NextCursor); !errors.Is(err, ErrInvalid) {
				t.Fatal("cursor limit changed", err)
			}
			continue
		}
		if _, err := service.ListOperationDTO(context.Background(), 2, token); !errors.Is(err, ErrInvalid) {
			t.Fatal("tampered cursor accepted", err)
		}
	}
	if _, err := service.cursor.Decode(*first.NextCursor, BackupTask, "", 2); !errors.Is(err, ErrInvalid) {
		t.Fatal("operation cursor accepted by task domain", err)
	}
	f.installation = "installation_other"
	if _, err := service.ListOperationDTO(context.Background(), 2, *first.NextCursor); !errors.Is(err, ErrDenied) {
		t.Fatal("cross-installation cursor accepted", err)
	}
}

func TestOperationListFailsClosedBeforeReturningRows(t *testing.T) {
	f := makeOperationListFixture()
	db := sql.OpenDB(operationListConnector{f})
	defer db.Close()
	service, err := NewService(db, f, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	f.revoke = true
	if result, err := service.ListOperationDTO(context.Background(), 2, ""); !errors.Is(err, ErrDenied) || len(result.Items) != 0 {
		t.Fatal("revoked operation page returned", result, err)
	}
	f.revoke = false
	f.rows[1][3] = "installation_other"
	if result, err := service.ListOperationDTO(context.Background(), 2, ""); !errors.Is(err, ErrUnavailable) || len(result.Items) != 0 {
		t.Fatal("cross-installation database row returned", result, err)
	}
	f.rows = nil
	f.failQuery = true
	if result, err := service.ListOperationDTO(context.Background(), 2, ""); !errors.Is(err, ErrUnavailable) || len(result.Items) != 0 {
		t.Fatal("database failure became an empty list", result, err)
	}
	f.failQuery = false
	if result, err := service.ListOperationDTO(context.Background(), 2, ""); err != nil || len(result.Items) != 0 || result.Items == nil || result.NextCursor != nil {
		t.Fatal("authorized empty list failed", result, err)
	}
}
