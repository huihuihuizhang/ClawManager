package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type claimReceiptModel struct {
	mu                                                 sync.Mutex
	row                                                taskClaimSnapshot
	receipts                                           int
	begin, commit, rollback, cas, insert, reads        int
	isolation                                          driver.IsolationLevel
	readOnly                                           bool
	casLoser, receiptError, receiptZero, commitUnknown bool
	drift                                              string
}
type claimReceiptDriver struct{ model *claimReceiptModel }
type claimReceiptConn struct {
	model    *claimReceiptModel
	pending  taskClaimSnapshot
	receipts int
	inTx     bool
}
type claimReceiptTx struct{ conn *claimReceiptConn }
type claimReceiptRows struct {
	values []driver.Value
	read   bool
}

func (d claimReceiptDriver) Open(string) (driver.Conn, error) {
	return &claimReceiptConn{model: d.model}, nil
}
func (c *claimReceiptConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not allowed")
}
func (c *claimReceiptConn) Close() error { return nil }
func (c *claimReceiptConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unbounded begin not allowed")
}
func (c *claimReceiptConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.model.mu.Lock()
	c.model.begin++
	c.model.isolation = o.Isolation
	c.model.readOnly = o.ReadOnly
	c.pending = c.model.row
	c.receipts = c.model.receipts
	c.inTx = true
	return claimReceiptTx{c}, nil
}
func (tx claimReceiptTx) Commit() error {
	c := tx.conn
	c.model.commit++
	c.model.row = c.pending
	c.model.receipts = c.receipts
	c.inTx = false
	defer c.model.mu.Unlock()
	if c.model.commitUnknown {
		return errors.New("commit acknowledgment lost")
	}
	return nil
}
func (tx claimReceiptTx) Rollback() error {
	c := tx.conn
	c.model.rollback++
	c.inTx = false
	c.model.mu.Unlock()
	return nil
}
func (c *claimReceiptConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !c.inTx {
		return nil, errors.New("write escaped original transaction")
	}
	s := c.model
	switch {
	case strings.HasPrefix(q, "UPDATE "):
		s.cas++
		for _, required := range []string{"row_version = row_version + 1", "origin_installation_id = ? AND public_id = ? AND row_version = ?", "next_reconcile_at IS NULL OR next_reconcile_at <= UTC_TIMESTAMP(6)"} {
			if !strings.Contains(q, required) {
				return nil, errors.New("claim guard missing")
			}
		}
		if len(args) != 6 || args[2].Value != c.pending.installation || args[3].Value != c.pending.publicID || args[4].Value != int64(c.pending.version) || s.casLoser {
			return fixedResult(0), nil
		}
		owner, ok := args[0].Value.(string)
		if !ok {
			return nil, errors.New("owner missing")
		}
		micros, ok := args[1].Value.(int64)
		if !ok {
			return nil, errors.New("TTL missing")
		}
		c.pending.owner = owner
		c.pending.version++
		c.pending.heartbeat = c.pending.now
		c.pending.until = c.pending.heartbeat.Add(time.Duration(micros) * time.Microsecond)
		return fixedResult(1), nil
	case strings.HasPrefix(q, "INSERT INTO system_backup_v2_events "):
		s.insert++
		if len(args) != 6 || args[0].Value != c.pending.installation || args[1].Value != c.pending.kind || args[2].Value != c.pending.publicID || args[3].Value != TaskClaimAcquiredEvent || args[4].Value != c.pending.status || args[5].Value != c.pending.requestID {
			return nil, errors.New("receipt binding changed")
		}
		if s.receiptError {
			return nil, errors.New("receipt storage failed")
		}
		if s.receiptZero {
			return fixedResult(0), nil
		}
		c.receipts++
		return fixedResult(1), nil
	}
	return nil, errors.New("unexpected write")
}
func (c *claimReceiptConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if !c.inTx {
		return nil, errors.New("read escaped original transaction")
	}
	s := c.model
	s.reads++
	if !strings.Contains(q, " WHERE origin_installation_id=? AND public_id=? FOR UPDATE") || len(args) != 2 || args[0].Value != c.pending.installation || args[1].Value != c.pending.publicID {
		return nil, errors.New("unbound read")
	}
	r := c.pending
	r.now = r.heartbeat.Add(time.Duration(s.reads) * time.Second)
	if s.reads == 2 {
		switch s.drift {
		case "schema":
			r.schema = "other"
		case "installation":
			r.installation = "installation_other"
		case "publicID":
			r.publicID = "sbk_22222222-2222-4222-8222-222222222222"
		case "kind":
			r.kind = "preflight"
		case "requestID":
			r.requestID = "another-request"
		case "status":
			r.status = "preparing"
		case "owner":
			r.owner = "controller:other"
		case "version":
			r.version++
		case "lease":
			r.until = r.until.Add(time.Second)
		case "heartbeat-and-lease":
			r.heartbeat = r.heartbeat.Add(time.Second)
			r.until = r.until.Add(time.Second)
		case "clock-backward":
			r.now = r.heartbeat.Add(500 * time.Millisecond)
		case "clock-expired":
			r.now = r.until
		}
	}
	return &claimReceiptRows{values: []driver.Value{r.schema, r.installation, r.publicID, r.kind, r.requestID, r.status, r.owner, r.until, int64(r.version), r.heartbeat, r.now}}, nil
}
func (r *claimReceiptRows) Columns() []string { return make([]string, len(r.values)) }
func (r *claimReceiptRows) Close() error      { return nil }
func (r *claimReceiptRows) Next(out []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read = true
	copy(out, r.values)
	return nil
}

var claimReceiptSequence atomic.Uint64

func newClaimReceiptModel(t *testing.T, kind TargetKind) (*claimReceiptModel, *sql.DB, Target) {
	t.Helper()
	prefix := map[TargetKind]string{TargetBackup: "sbk_", TargetDrill: "sdr_", TargetPreflight: "spf_", TargetArtifactVerify: "sav_"}[kind]
	target := Target{Kind: kind, PublicID: prefix + "11111111-1111-4111-8111-111111111111"}
	m := &claimReceiptModel{row: taskClaimSnapshot{schema: "system-backup-task.v1", installation: "installation_test", publicID: target.PublicID, kind: string(kind), requestID: "original-request-1", status: "pending", version: 7, now: time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)}}
	name := fmt.Sprintf("task_claim_receipt_%d", claimReceiptSequence.Add(1))
	sql.Register(name, claimReceiptDriver{m})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return m, db, target
}

func TestTaskClaimAndReceiptCommitTogetherForAllTaskKinds(t *testing.T) {
	for _, kind := range []TargetKind{TargetBackup, TargetDrill, TargetPreflight, TargetArtifactVerify} {
		t.Run(string(kind), func(t *testing.T) {
			m, db, target := newClaimReceiptModel(t, kind)
			token, err := (SQLTaskClaimStore{DB: db, InstallationID: "installation_test"}).AcquireWithReceipt(context.Background(), target, "controller:pod-1", 7, validPolicy())
			if err != nil || token.Target != target || token.Owner != "controller:pod-1" || token.RowVersion != 8 {
				t.Fatalf("token=%#v err=%v", token, err)
			}
			if m.begin != 1 || m.commit != 1 || m.rollback != 0 || m.cas != 1 || m.insert != 1 || m.reads != 2 || m.receipts != 1 || m.row.version != 8 || m.isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || m.readOnly {
				t.Fatalf("transaction facts %#v", m)
			}
		})
	}
}
func TestTaskClaimReceiptFailuresRollbackCAS(t *testing.T) {
	for _, failure := range []string{"CAS loser", "receipt SQL error", "receipt zero rows"} {
		t.Run(failure, func(t *testing.T) {
			m, db, target := newClaimReceiptModel(t, TargetBackup)
			m.casLoser = failure == "CAS loser"
			m.receiptError = failure == "receipt SQL error"
			m.receiptZero = failure == "receipt zero rows"
			token, err := (SQLTaskClaimStore{DB: db, InstallationID: "installation_test"}).AcquireWithReceipt(context.Background(), target, "controller:pod-1", 7, validPolicy())
			if err == nil || token != (ClaimToken{}) || m.commit != 0 || m.rollback != 1 || m.row.version != 7 || m.receipts != 0 {
				t.Fatalf("unsafe rollback token=%#v err=%v facts=%#v", token, err, m)
			}
			if m.casLoser && (!errors.Is(err, ErrClaimNotAcquired) || m.insert != 0) {
				t.Fatal("CAS loser emitted receipt or lost classification")
			}
		})
	}
}
func TestTaskClaimReceiptFinalDriftRollsBackTogether(t *testing.T) {
	for _, drift := range []string{"schema", "installation", "publicID", "kind", "requestID", "status", "owner", "version", "lease", "heartbeat-and-lease", "clock-backward", "clock-expired"} {
		t.Run(drift, func(t *testing.T) {
			m, db, target := newClaimReceiptModel(t, TargetBackup)
			m.drift = drift
			token, err := (SQLTaskClaimStore{DB: db, InstallationID: "installation_test"}).AcquireWithReceipt(context.Background(), target, "controller:pod-1", 7, validPolicy())
			if !errors.Is(err, ErrTaskClaimReceipt) || token != (ClaimToken{}) || m.commit != 0 || m.rollback != 1 || m.insert != 1 || m.row.version != 7 || m.receipts != 0 {
				t.Fatalf("unsafe final drift token=%#v err=%v facts=%#v", token, err, m)
			}
		})
	}
}
func TestTaskClaimUnknownCommitReturnsNoTokenAndNeverRetries(t *testing.T) {
	m, db, target := newClaimReceiptModel(t, TargetBackup)
	m.commitUnknown = true
	store := SQLTaskClaimStore{DB: db, InstallationID: "installation_test"}
	token, err := store.AcquireWithReceipt(context.Background(), target, "controller:pod-1", 7, validPolicy())
	if !errors.Is(err, ErrTaskClaimCommitUnknown) || token != (ClaimToken{}) || m.begin != 1 || m.cas != 1 || m.commit != 1 || m.receipts != 1 || m.row.version != 8 {
		t.Fatalf("ambiguous outcome token=%#v err=%v facts=%#v", token, err, m)
	}
	// The first commit actually persisted in this model. Reusing its original
	// expected version cannot manufacture another receipt or usable token.
	m.commitUnknown = false
	token, err = store.AcquireWithReceipt(context.Background(), target, "controller:pod-1", 7, validPolicy())
	if !errors.Is(err, ErrClaimNotAcquired) || token != (ClaimToken{}) || m.receipts != 1 || m.insert != 1 || m.commit != 1 {
		t.Fatalf("original-version retry duplicated receipt token=%#v err=%v facts=%#v", token, err, m)
	}
}
func TestSQLDeadlineAcquireUsesCommonTaskReceiptEntry(t *testing.T) {
	m, db, target := newClaimReceiptModel(t, TargetBackup)
	token, err := (SQLDeadlineStore{DB: db}).Acquire(context.Background(), "installation_test", DeadlineCandidate{Target: target, RowVersion: 7}, "controller:pod-1", validPolicy())
	if err != nil || token.RowVersion != 8 || m.receipts != 1 || m.commit != 1 || m.cas != 1 {
		t.Fatalf("deadline caller bypassed receipt token=%#v err=%v facts=%#v", token, err, m)
	}
}
func TestTaskClaimRejectsOperationsAndInvalidScopesBeforeTransaction(t *testing.T) {
	m, db, _ := newClaimReceiptModel(t, TargetBackup)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []struct {
		ctx          context.Context
		installation string
		target       Target
		owner        string
		version      uint64
		policy       LeasePolicy
	}{
		{context.Background(), "installation_test", Target{TargetOperation, "sop_11111111-1111-4111-8111-111111111111"}, "controller:pod-1", 7, validPolicy()},
		{context.Background(), "other", Target{TargetBackup, m.row.publicID}, "controller:pod-1", 7, validPolicy()},
		{ctx, "installation_test", Target{TargetBackup, m.row.publicID}, "controller:pod-1", 7, validPolicy()},
		{context.Background(), "installation_test", Target{TargetBackup, m.row.publicID}, "", 7, validPolicy()},
		{context.Background(), "installation_test", Target{TargetBackup, m.row.publicID}, "controller:pod-1", ^uint64(0), validPolicy()},
	} {
		token, err := (SQLTaskClaimStore{DB: db, InstallationID: input.installation}).AcquireWithReceipt(input.ctx, input.target, input.owner, input.version, input.policy)
		if err == nil || token != (ClaimToken{}) || m.begin != 0 {
			t.Fatalf("invalid claim reached SQL token=%#v err=%v", token, err)
		}
	}
}
