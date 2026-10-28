package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

type recordPlanRunner struct{ d.Runner }

func (recordPlanRunner) Prepare(context.Context, d.Input, d.Ports) (d.Plan, error) {
	raw := []byte("{\n  \"original\": true\n}")
	return d.Plan{SchemaVersion: b.PlanVersion, CanonicalJSON: raw, SHA256: recordHash(raw)}, nil
}
func TestExecutionRecordsTaskPlanRoundtripAndBinding(t *testing.T) {
	s, m, _ := newRecordStore(t)
	in := d.Input{Authority: m.base.a, ConfigSnapshot: bytes.Clone(m.base.config), ProfileID: "linux", ProfileRevision: "v1", Backup: &d.BackupSpec{SourceOrchestrator: "kubernetes", SourceProfile: "cluster", MatrixKey: "k8s-cluster", DatasourceTopology: "in_cluster", Runner: "k8s", TaskPurpose: "functional_test", RequestedParts: []string{"mysql"}}}
	runner, err := d.BindTaskRunner(recordPlanRunner{}, b.PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runner.Prepare(context.Background(), in, &executionPortsTest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SavePlan(context.Background(), in, plan); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadPlan(context.Background(), in)
	if err != nil || !bytes.Equal(got.CanonicalJSON, plan.CanonicalJSON) || got.SHA256 != plan.SHA256 {
		t.Fatal("plan changed", err)
	}
	scheduler := &workStoreTest{w: &ExecutionWork{Step: ExecutionPrepare, Input: in}}
	store := DurableExecutionStore{Scheduler: scheduler, Records: s}
	if work, err := store.Next(context.Background()); err != nil || work != nil || scheduler.record != 1 || scheduler.out.Plan.SHA256 != plan.SHA256 {
		t.Fatal("committed plan redispatched instead of reconciled", err)
	}
	in.ProfileRevision = "different"
	if _, err := s.LoadPlan(context.Background(), in); err == nil {
		t.Fatal("profile drift accepted")
	}
}

type recordRow struct {
	hash, ref string
	sealed    []byte
}
type recordModel struct {
	base         *executionModel
	row, pending *recordRow
	unknown      bool
	inserts      int
}
type recordDriver struct{ m *recordModel }
type recordConn struct {
	*executionConn
	m *recordModel
}
type recordTx struct{ c *recordConn }

func (v recordDriver) Open(string) (driver.Conn, error) {
	return &recordConn{&executionConn{m: v.m.base}, v.m}, nil
}
func (c *recordConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if _, err := c.executionConn.BeginTx(ctx, o); err != nil {
		return nil, err
	}
	c.m.pending = nil
	return recordTx{c}, nil
}
func (t recordTx) Commit() error {
	if t.c.m.pending != nil {
		t.c.m.row = t.c.m.pending
	}
	t.c.active = false
	t.c.m.base.commits++
	if t.c.m.unknown {
		return errors.New("commit reply lost")
	}
	return nil
}
func (t recordTx) Rollback() error { t.c.m.pending = nil; t.c.active = false; return nil }

type recordRows struct {
	values []driver.Value
	done   bool
}

func (r *recordRows) Columns() []string {
	if len(r.values) == 3 {
		return []string{"hash", "ref", "sealed"}
	}
	return []string{"hash"}
}
func (r *recordRows) Close() error { return nil }
func (r *recordRows) Next(v []driver.Value) error {
	if r.done || r.values == nil {
		return io.EOF
	}
	copy(v, r.values)
	r.done = true
	return nil
}
func (c *recordConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasSuffix(q, "WHERE 1=0") {
		return &recordRows{}, nil
	}
	if strings.HasPrefix(q, "SELECT payload_sha256") {
		if len(args) != 5 || args[0].Value != c.m.base.a.InstallationID || args[1].Value != c.m.base.a.TaskPublicID {
			return nil, errors.New("scope missing")
		}
		if c.m.row == nil {
			return &recordRows{}, nil
		}
		if strings.Contains(q, "key_ref") {
			return &recordRows{values: []driver.Value{c.m.row.hash, c.m.row.ref, c.m.row.sealed}}, nil
		}
		if !c.active || !strings.HasSuffix(q, "FOR SHARE") {
			return nil, errors.New("unlocked receipt")
		}
		return &recordRows{values: []driver.Value{c.m.row.hash}}, nil
	}
	return c.executionConn.QueryContext(ctx, q, args)
}
func (c *recordConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !c.active || !strings.HasPrefix(q, "INSERT INTO system_backup_v2_execution_records") || len(args) != 8 {
		return nil, errors.New("unexpected write")
	}
	c.m.inserts++
	c.m.pending = &recordRow{args[5].Value.(string), args[6].Value.(string), bytes.Clone(args[7].Value.([]byte))}
	return driver.RowsAffected(1), nil
}

type recordKeys struct {
	returned []byte
	wrong    bool
}

func (k *recordKeys) Resolve(_ context.Context, _ d.Authority, ref string) (string, []byte, error) {
	k.returned = bytes.Repeat([]byte{7}, 32)
	if k.wrong {
		k.returned[0] = 8
	}
	return "key-v1", k.returned, nil
}

var recordDriverID atomic.Uint64

func newRecordStore(t *testing.T) (SQLExecutionRecords, *recordModel, *recordKeys) {
	t.Helper()
	auth, base := newExecutionModel(t)
	m := &recordModel{base: base}
	name := fmt.Sprintf("record-model-%d", recordDriverID.Add(1))
	sql.Register(name, recordDriver{m})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	auth.DB = db
	keys := &recordKeys{}
	return SQLExecutionRecords{Authority: auth, Keys: keys}, m, keys
}
func TestExecutionRecordsEncryptedReadbackAndConflict(t *testing.T) {
	s, m, k := newRecordStore(t)
	ctx := context.Background()
	raw := []byte("{\n  \"secret\": \"exact original bytes\"\n}")
	if err := s.write(ctx, m.base.a, "plan", raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(m.row.sealed, []byte("secret")) || !bytes.Equal(k.returned, make([]byte, 32)) {
		t.Fatal("plaintext or uncleared key")
	}
	got, err := s.read(ctx, m.base.a, "plan")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("readback changed bytes", err)
	}
	if err := s.write(ctx, m.base.a, "plan", raw); err != nil || m.inserts != 1 {
		t.Fatal("identical retry inserted", err)
	}
	if err := s.write(ctx, m.base.a, "plan", []byte(`{"different":true}`)); !errors.Is(err, ErrExecutionRecord) || m.inserts != 1 {
		t.Fatal("overwrote original", err)
	}
	k.wrong = true
	if _, err := s.read(ctx, m.base.a, "plan"); err == nil {
		t.Fatal("wrong key accepted")
	}
	k.wrong = false
	m.row.sealed[len(m.row.sealed)-1] ^= 1
	if _, err := s.read(ctx, m.base.a, "plan"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
func TestExecutionRecordsUnknownCommitReadBeforeRetry(t *testing.T) {
	s, m, _ := newRecordStore(t)
	m.unknown = true
	raw := []byte(`{"original":true}`)
	if err := s.write(context.Background(), m.base.a, "plan", raw); !errors.Is(err, ErrExecutionCommitUnknown) {
		t.Fatal(err)
	}
	if err := s.write(context.Background(), m.base.a, "plan", raw); err != nil || m.inserts != 1 {
		t.Fatal("uncertain commit was repeated", err)
	}
}
func TestExecutionRecordsAuthorityLossRollsBack(t *testing.T) {
	s, m, _ := newRecordStore(t)
	auth := s.Authority.Authorization.(*executionAuth)
	n := 0
	auth.onRecheck = func() {
		n++
		if n == 2 {
			m.base.drift = "version"
		}
	}
	if err := s.write(context.Background(), m.base.a, "plan", []byte(`{"original":true}`)); err == nil || m.row != nil {
		t.Fatal("lost claim committed", err)
	}
}
func TestExecutionRecordsResultReplayNeverPromotesFailure(t *testing.T) {
	raw := []byte(`{"schema_version":"system-backup-execution-result.v1","plan_sha256":"abc","results":[],"failed":true}`)
	out, err := decodeExecutionResult(raw, "abc")
	if err != nil || out.Err == nil {
		t.Fatal("failed capture promoted", err)
	}
	if _, err := decodeExecutionResult(raw, "other"); err == nil {
		t.Fatal("wrong plan accepted")
	}
}
func TestExecutionRecordsMissingOwnersDoNotClaim(t *testing.T) {
	scheduler := &workStoreTest{}
	store := DurableExecutionStore{Scheduler: scheduler}
	if _, err := store.Next(context.Background()); err == nil || scheduler.next != 0 {
		t.Fatal("missing custody claimed work")
	}
}
