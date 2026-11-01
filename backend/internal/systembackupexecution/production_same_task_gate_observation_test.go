package systembackupexecution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

type dOriginalGateLockData struct {
	Connection                       uint64
	Transaction, Table, Mode, Status string
}

func dOriginalGateNOWAITQuery(query string, cause error) bool {
	var rejection *mysql.MySQLError
	return strings.HasPrefix(query, "SELECT phase,generation,fencing_token FROM system_backup_gate") && strings.HasSuffix(query, "FOR UPDATE NOWAIT") && errors.As(cause, &rejection) && rejection.Number == 3572
}

// A read-only PFS observation after an ACTUAL refusal, through the fixture's
// existing admin pool. No PROCESS/PFS privilege is added to the controller.
// Locks can disappear before this sample: an empty sample is not proof that
// the refused request had no blocker. No SQL text, arguments or credentials.
func readDOriginalGateLocks(ctx context.Context, f *dOriginalSixPartTask) ([]dOriginalGateLockData, error) {
	if ctx == nil || f == nil || f.db == nil {
		return nil, errors.New("original gate lock observation unavailable")
	}
	rows, err := f.db.QueryContext(ctx, `SELECT COALESCE(t.PROCESSLIST_ID,0),l.ENGINE_TRANSACTION_ID,l.OBJECT_NAME,l.LOCK_MODE,l.LOCK_STATUS FROM performance_schema.data_locks l JOIN performance_schema.threads t ON t.THREAD_ID=l.THREAD_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME IN ('system_backup_gate','system_backup_gate_admissions') AND l.LOCK_TYPE='RECORD' ORDER BY t.PROCESSLIST_ID,l.OBJECT_NAME,l.LOCK_MODE`, f.database)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []dOriginalGateLockData
	for rows.Next() {
		var value dOriginalGateLockData
		if err = rows.Scan(&value.Connection, &value.Transaction, &value.Table, &value.Mode, &value.Status); err != nil {
			return nil, err
		}
		if len(result) >= 128 {
			return nil, errors.New("original gate lock DATA exceeds bound")
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func logDOriginalGateLocks(t *testing.T, f *dOriginalSixPartTask) []dOriginalGateLockData {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now().UTC()
	values, err := readDOriginalGateLocks(ctx, f)
	if err != nil {
		t.Log("original gate refusal lock DATA unavailable; no absence conclusion", started.Format(time.RFC3339Nano))
		return nil
	}
	t.Log("original gate real3572 read-only lock DATA", started.Format(time.RFC3339Nano), f.database, f.publicID, "rows", len(values))
	for _, value := range values {
		t.Log("original gate lock DATA", fmt.Sprintf("connection=%d transaction=%s table=%s mode=%s status=%s", value.Connection, value.Transaction, value.Table, value.Mode, value.Status))
	}
	return values
}

func TestOriginalGateDiagnosticRequiresActualGateNOWAITRejection(t *testing.T) {
	query := "SELECT phase,generation,fencing_token FROM system_backup_gate WHERE scope=? FOR UPDATE NOWAIT"
	cause := &mysql.MySQLError{Number: 3572}
	if !dOriginalGateNOWAITQuery(query, fmt.Errorf("actual driver: %w", cause)) {
		t.Fatal("lost actual wrapped3572")
	}
	for _, bad := range []struct {
		query string
		cause error
	}{{query, nil}, {query, errors.New("3572 text is not driver evidence")}, {query, &mysql.MySQLError{Number: 1205}}, {"SELECT something ELSE FOR UPDATE NOWAIT", cause}, {strings.TrimSuffix(query, " NOWAIT"), cause}} {
		if dOriginalGateNOWAITQuery(bad.query, bad.cause) {
			t.Fatal("diagnostic accepted unrelated/non-driver event")
		}
	}
}
