package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const operationTestID = "sop_00000000-0000-4000-8000-000000000001"

type operationFixture struct {
	row        []driver.Value
	queries    int
	rechecks   int
	deny       bool
	revoke     bool
	queryError bool
}

func (f *operationFixture) AuthorizeRead(_ context.Context, tx *sql.Tx) (string, error) {
	if tx == nil || f.deny {
		return "", ErrDenied
	}
	return "installation_test", nil
}
func (f *operationFixture) RecheckRead(_ context.Context, tx *sql.Tx, installation string) error {
	f.rechecks++
	if tx == nil || f.revoke || installation != "installation_test" {
		return ErrDenied
	}
	return nil
}

type operationConnector struct{ f *operationFixture }
type operationConn struct{ f *operationFixture }

func (c operationConnector) Connect(context.Context) (driver.Conn, error) {
	return &operationConn{c.f}, nil
}
func (operationConnector) Driver() driver.Driver { return pageDriver{} }
func (*operationConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*operationConn) Close() error              { return nil }
func (*operationConn) Begin() (driver.Tx, error) { return pageTx{}, nil }
func (*operationConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return pageTx{}, nil
}
func (c *operationConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.f.queries++
	if c.f.queryError {
		return nil, errors.New("synthetic query failure")
	}
	if !strings.Contains(query, operationProjectionColumns) ||
		!strings.Contains(query, "FROM system_backup_v2_operations") ||
		!strings.Contains(query, "WHERE origin_installation_id=? AND public_id=? FOR SHARE") ||
		strings.Contains(query, "failure_message") || strings.Contains(query, "external_action_public_ids_canonical_json") ||
		strings.Contains(query, "redacted_response_evidence_id") || len(args) != 2 ||
		args[0].Value != "installation_test" || args[1].Value != operationTestID {
		return nil, errors.New("unsafe operation projection")
	}
	if c.f.row == nil {
		return &pageRows{columns: operationColumns}, nil
	}
	return &pageRows{columns: operationColumns, values: [][]driver.Value{c.f.row}}, nil
}

var operationColumns = strings.Split(strings.ReplaceAll(operationProjectionColumns, "\n", ""), ",")

func operationTestFixture() *operationFixture {
	created := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	return &operationFixture{row: []driver.Value{
		"system-backup-operation.v1", operationTestID, "installation_test", "config_update", "system", "installation_test",
		"admin", "42", "updateSystemBackupConfig", strings.Repeat("i", 16), strings.Repeat("a", 64), "succeeded",
		nil, int64(2), false, "none", int64(200), int64(1), created.Add(time.Hour), nil,
		created.Add(time.Minute), created, created.Add(time.Minute),
	}}
}

func TestOperationProjectionMatchesMigrationWithoutSensitiveColumns(t *testing.T) {
	raw, err := os.ReadFile("../db/migrations/097_backup_v2_add_system_backup_config_and_operations.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range operationColumns {
		if !regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(column) + `\s`).Match(raw) {
			t.Fatal("operation projection column absent from migration", column)
		}
	}
}

func TestGetOperationProjectsAuthorizedRedactedResource(t *testing.T) {
	f := operationTestFixture()
	db := sql.OpenDB(operationConnector{f})
	defer db.Close()
	service, err := NewService(db, f, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	dto, err := service.GetOperationDTO(context.Background(), operationTestID)
	if err != nil || dto.PublicID != operationTestID || dto.ResultConfigVersion == nil || *dto.ResultConfigVersion != 2 ||
		f.queries != 1 || f.rechecks != 1 {
		t.Fatal("authorized operation was not projected", err, f.queries, f.rechecks)
	}
	encoded, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil || body["failure_message"] != nil {
		t.Fatal("operation failure message was not redacted", err)
	}
	for _, name := range []string{"redacted_response_evidence_id", "external_action_public_ids_canonical_json", "claim_owner"} {
		if strings.Contains(string(encoded), `"`+name+`"`) {
			t.Fatal("sensitive operation column escaped", name)
		}
	}
	raw, err := service.reader.GetOperation(context.Background(), operationTestID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(raw); !errors.Is(err, ErrInvalid) {
		t.Fatal("internal operation snapshot serialized", err)
	}
}

func TestGetOperationFailsClosedOnScopeMissingAndCorruptRows(t *testing.T) {
	f := operationTestFixture()
	db := sql.OpenDB(operationConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetOperation(context.Background(), "sop_invalid"); !errors.Is(err, ErrInvalid) || f.queries != 0 {
		t.Fatal("invalid operation ID reached database", err)
	}
	f.deny = true
	if _, err := r.GetOperation(context.Background(), operationTestID); !errors.Is(err, ErrDenied) || f.queries != 0 {
		t.Fatal("denied operation queried database", err)
	}
	f.deny = false
	f.row[2] = "installation_other"
	if _, err := r.GetOperation(context.Background(), operationTestID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cross-install operation escaped", err)
	}
	f.row = nil
	f.revoke = true
	if _, err := r.GetOperation(context.Background(), operationTestID); !errors.Is(err, ErrDenied) {
		t.Fatal("revocation racing miss became 404", err)
	}
	f.revoke = false
	if _, err := r.GetOperation(context.Background(), operationTestID); !errors.Is(err, ErrNotFound) {
		t.Fatal("authorized missing operation was not 404", err)
	}
	f.queryError = true
	if _, err := r.GetOperation(context.Background(), operationTestID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("database failure became missing operation", err)
	}
}

func TestGetOperationRejectsInvalidResultAndState(t *testing.T) {
	f := operationTestFixture()
	db := sql.OpenDB(operationConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		index int
		value driver.Value
	}{
		{"schema", 0, "future"}, {"result version", 13, nil}, {"target", 5, "installation_other"},
		{"status", 11, "running"}, {"category", 15, "secret"}, {"time", 18, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := f.row[tc.index]
			f.row[tc.index] = tc.value
			if _, err := r.GetOperation(context.Background(), operationTestID); !errors.Is(err, ErrUnavailable) {
				t.Fatal("invalid operation row escaped", err)
			}
			f.row[tc.index] = prior
		})
	}
}
