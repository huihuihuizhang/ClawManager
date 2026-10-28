package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// Real database/sql with a deterministic transport model. These tests verify
// the storage adapter's control flow, not real MySQL locking/JSON/FK behavior.
type downloadAuditAState struct {
	now                                                 time.Time
	offset, affected, reportedID, insertedID            int64
	actor                                               int64
	body                                                []byte
	created                                             time.Time
	action, resourceType                                string
	resource                                            driver.Value
	begin, commit, rollback, writes, reads, clocks, ids int
	writeErr, affectedErr, idErr                        bool
}
type downloadAuditAConnector struct{ s *downloadAuditAState }

func (c downloadAuditAConnector) Connect(context.Context) (driver.Conn, error) {
	return &downloadAuditAConn{s: c.s}, nil
}
func (downloadAuditAConnector) Driver() driver.Driver { return downloadAuditADriver{} }

type downloadAuditADriver struct{}

func (downloadAuditADriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector required")
}

type downloadAuditAConn struct{ s *downloadAuditAState }

func (*downloadAuditAConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*downloadAuditAConn) Close() error { return nil }
func (c *downloadAuditAConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *downloadAuditAConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.s.begin++
	return &downloadAuditATx{s: c.s}, nil
}

type downloadAuditATx struct{ s *downloadAuditAState }

func (t *downloadAuditATx) Commit() error   { t.s.commit++; return nil }
func (t *downloadAuditATx) Rollback() error { t.s.rollback++; return nil }
func (c *downloadAuditAConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	s := c.s
	if q != downloadIntentInsertSQL || len(args) != 3 {
		return nil, errors.New("unexpected SQL write")
	}
	s.writes++
	if s.writeErr {
		return nil, errors.New("PRIVATE_SQL_CREDENTIAL")
	}
	s.actor = args[0].Value.(int64)
	s.body = append([]byte(nil), args[1].Value.([]byte)...)
	s.created = args[2].Value.(time.Time)
	s.action, s.resourceType = "system_backup.evidence_download.intent", "system_backup"
	return downloadAuditAResult{s}, nil
}

type downloadAuditAResult struct{ s *downloadAuditAState }

func (r downloadAuditAResult) RowsAffected() (int64, error) {
	if r.s.affectedErr {
		return 0, errors.New("PRIVATE_ROWS")
	}
	return r.s.affected, nil
}
func (r downloadAuditAResult) LastInsertId() (int64, error) {
	r.s.ids++
	if r.s.idErr {
		return 0, errors.New("PRIVATE_ID")
	}
	return r.s.reportedID, nil
}
func (c *downloadAuditAConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	switch q {
	case downloadIntentClockSQL:
		s.clocks++
		return &downloadAuditARows{values: []driver.Value{s.now, s.offset}}, nil
	case downloadIntentReadSQL:
		s.reads++
		if len(args) != 1 || args[0].Value != s.insertedID {
			return &downloadAuditARows{}, nil
		}
		return &downloadAuditARows{values: []driver.Value{s.actor, s.action, s.resourceType, s.resource, append([]byte(nil), s.body...), s.created}}, nil
	}
	return nil, errors.New("unexpected SQL read; MAX/latest guesses are forbidden")
}

type downloadAuditARows struct {
	values []driver.Value
	done   bool
}

func (r *downloadAuditARows) Columns() []string {
	names := make([]string, len(r.values))
	for i := range names {
		names[i] = "value"
	}
	if len(names) == 0 {
		return []string{"missing"}
	}
	return names
}
func (*downloadAuditARows) Close() error { return nil }
func (r *downloadAuditARows) Next(dest []driver.Value) error {
	if r.done || len(r.values) == 0 {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

func downloadAuditAFixture(t *testing.T) (*downloadAuditAState, *sql.DB, *sql.Tx, DownloadAdmissionIntent) {
	t.Helper()
	s := &downloadAuditAState{now: time.Date(2026, 10, 16, 0, 0, 0, 123456000, time.UTC), affected: 1, reportedID: 37, insertedID: 37}
	db := sql.OpenDB(downloadAuditAConnector{s})
	db.SetMaxOpenConns(2)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	f := DownloadAdmissionIntent{Installation: "installation_test", OperationID: "sop_11111111-2222-4333-8444-555555555555", EvidenceID: "sev_11111111-2222-4333-8444-555555555555", RequestHash: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), Claim: "aev_" + strings.Repeat("c", 32), ActorID: 42, EvidenceRowVersion: 7, End: 8192}
	return s, db, tx, f
}

func TestDownloadAdmissionAuditAActualIDAndBorrowedTransaction(t *testing.T) {
	s, db, tx, f := downloadAuditAFixture(t)
	store := SQLDownloadAdmissionAudits{}
	a, err := store.StageIntent(context.Background(), tx, f)
	if err != nil {
		t.Fatal(err)
	}
	if s.writes != 1 || s.ids != 1 || s.begin != 1 || s.commit != 0 || s.rollback != 0 || a.id != 37 {
		t.Fatal("storage guessed ID, inserted twice or owned the transaction")
	}
	if s.created.Nanosecond() != 0 || !s.created.Equal(s.now.Truncate(time.Second)) {
		t.Fatal("published TIMESTAMP(0) was not bound at exact second precision")
	}
	if bytes.Contains(s.body, []byte(f.Claim)) || !bytes.Contains(s.body, []byte(hash([]byte(f.Claim)))) {
		t.Fatal("raw claim leaked or digest missing")
	}
	if _, err := json.Marshal(a); err == nil {
		t.Fatal("audit anchor serialized as authority")
	}
	// MySQL JSON may reorder/space the original object without changing it.
	var pretty bytes.Buffer
	if json.Indent(&pretty, s.body, "", "  ") != nil {
		t.Fatal("fixture JSON invalid")
	}
	s.body = pretty.Bytes()
	s.now = s.now.Add(time.Second)
	id, err := store.RecheckIntent(context.Background(), tx, a)
	if err != nil || id != 37 || s.writes != 1 {
		t.Fatal("exact same-row recheck failed or rewrote intent", err)
	}
	foreign, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Rollback()
	before := s.reads
	if id, err := store.RecheckIntent(context.Background(), foreign, a); err == nil || id != 0 || s.reads != before {
		t.Fatal("anchor accepted on another transaction")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if id, err := store.RecheckIntent(context.Background(), tx, a); err == nil || id != 0 {
		t.Fatal("ended transaction retained usable audit anchor")
	}
}

func TestDownloadAdmissionAuditAFailuresReturnNoAnchor(t *testing.T) {
	for _, kind := range []string{"insert", "rows-error", "zero-rows", "many-rows", "id-error", "zero-id", "oversized-id", "wrong-id", "timezone", "precision", "clock-zero", "cancelled", "invalid-facts"} {
		t.Run(kind, func(t *testing.T) {
			s, _, tx, f := downloadAuditAFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "insert":
				s.writeErr = true
			case "rows-error":
				s.affectedErr = true
			case "zero-rows":
				s.affected = 0
			case "many-rows":
				s.affected = 2
			case "id-error":
				s.idErr = true
			case "zero-id":
				s.reportedID = 0
			case "oversized-id":
				s.reportedID = 2147483648
			case "wrong-id":
				s.reportedID = 38
			case "timezone":
				s.offset = 3600000000
			case "precision":
				s.now = s.now.Add(time.Nanosecond)
			case "clock-zero":
				s.now = time.Time{}
			case "cancelled":
				cancel()
			case "invalid-facts":
				f.Claim = "client-claim"
			}
			a, err := (SQLDownloadAdmissionAudits{}).StageIntent(ctx, tx, f)
			if err == nil || a.id != 0 || a.tx != nil || strings.Contains(err.Error(), "PRIVATE_") || s.commit != 0 || s.rollback != 0 {
				t.Fatal("failure leaked an anchor, private error, or changed caller transaction")
			}
		})
	}
}

func TestDownloadAdmissionAuditACallbackDriftRejected(t *testing.T) {
	for _, kind := range []string{"actor", "action", "resource-type", "resource-id", "created", "body-missing", "body-extra", "body-number-type", "body-range", "clock-regression", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, _, tx, f := downloadAuditAFixture(t)
			a, err := (SQLDownloadAdmissionAudits{}).StageIntent(context.Background(), tx, f)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var body map[string]any
			decoder := json.NewDecoder(bytes.NewReader(s.body))
			decoder.UseNumber()
			if decoder.Decode(&body) != nil {
				t.Fatal("fixture JSON invalid")
			}
			switch kind {
			case "actor":
				s.actor++
			case "action":
				s.action = "other"
			case "resource-type":
				s.resourceType = "other"
			case "resource-id":
				s.resource = int64(1)
			case "created":
				s.created = s.created.Add(time.Second)
			case "body-missing":
				delete(body, "request_hash")
			case "body-extra":
				body["raw_nonce"] = "PRIVATE_NONCE"
			case "body-number-type":
				body["range_start"] = "0"
			case "body-range":
				body["range_end"] = json.Number("8191")
			case "clock-regression":
				s.now = s.now.Add(-time.Microsecond)
			case "cancelled":
				cancel()
			}
			if strings.HasPrefix(kind, "body-") {
				s.body = canonical(body)
			}
			id, err := (SQLDownloadAdmissionAudits{}).RecheckIntent(ctx, tx, a)
			if err == nil || id != 0 || s.writes != 1 || s.commit != 0 || s.rollback != 0 || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("later callback drift returned usable ID or changed intent/transaction")
			}
		})
	}
}
