package systembackupproducer

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fenceTestRow struct {
	epoch, version int64
	revoked        bool
}

type fenceTestEnvironment struct {
	db      *fakeDB
	rows    map[string]fenceTestRow
	allow   bool
	fail    string
	badHash bool
	checks  int
}

func (e *fenceTestEnvironment) PrepareRecoveryFence(context.Context, RecoveryFenceRequest) (RecoveryFenceSession, error) {
	if e.fail == "prepare" {
		return nil, ErrUnavailable
	}
	return e, nil
}
func (e *fenceTestEnvironment) LockInstallation(context.Context, SQL, RecoveryFenceRequest) error {
	if e.fail == "installation" {
		return ErrUnavailable
	}
	return nil
}
func (e *fenceTestEnvironment) Authorize(_ context.Context, _ SQL, r RecoveryFenceRequest, _ RecoveryFenceRow) (RecoveryFenceAdmission, error) {
	if e.fail == "authorize" {
		return RecoveryFenceAdmission{}, ErrUnavailable
	}
	h, _ := RecoveryFenceHash(r)
	if e.badHash {
		h = Hash(strings.Repeat("f", 64))
	}
	return RecoveryFenceAdmission{VerifiedRequestHash: h, IdentityExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout)), ManagementAllowed: e.allow}, nil
}
func (e *fenceTestEnvironment) Audit(_ context.Context, _ SQL, _ RecoveryFenceRequest, stage string) error {
	if e.fail == "audit:"+stage {
		return ErrUnavailable
	}
	return nil
}
func (e *fenceTestEnvironment) Recheck(_ context.Context, _ ReadSQL, _ RecoveryFenceRequest, _ RecoveryFenceRow, _ time.Time) error {
	e.checks++
	if e.fail == "recheck" || !e.allow {
		return ErrGuardRequired
	}
	return nil
}

func setupRecoveryFence(t *testing.T) (*RecoveryFenceManager, RecoveryFenceRequest, *fenceTestEnvironment, *fakeDB) {
	t.Helper()
	r, err := DecodeResult(fixtures(t).Positive[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 9, 1, 0, 0, 0, time.UTC)
	db := &fakeDB{now: now, server: string(r.Scope.ServerUUID), database: string(r.Scope.Database)}
	e := &fenceTestEnvironment{db: db, rows: make(map[string]fenceTestRow), allow: true}
	var snapshot map[string]fenceTestRow
	db.beginRecord = func() {
		snapshot = make(map[string]fenceTestRow, len(e.rows))
		for k, v := range e.rows {
			snapshot[k] = v
		}
	}
	db.rollbackRecord = func() { e.rows = snapshot }
	db.queryRecord = func(q string, args []driver.NamedValue) (driver.Rows, error) {
		if q != recoveryFenceSelect && q != recoveryFenceRecheck || len(args) != 2 {
			return nil, ErrInvalid
		}
		identity := args[1].Value.([]byte)
		row, found := e.rows[string(identity)]
		if !found {
			return &emptyFenceRows{}, nil
		}
		var revoked driver.Value
		if row.revoked {
			revoked = db.now
		}
		return &fakeRows{values: []driver.Value{row.epoch, revoked, row.version}}, nil
	}
	db.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
		if e.fail == "cas" {
			return driver.RowsAffected(0), nil
		}
		switch q {
		case recoveryFenceInsert:
			if e.fail == "new_identity_insert" && len(e.rows) != 0 {
				return driver.RowsAffected(0), nil
			}
			identity := string(args[1].Value.([]byte))
			if _, exists := e.rows[identity]; exists {
				return driver.RowsAffected(0), nil
			}
			e.rows[identity] = fenceTestRow{epoch: args[2].Value.(int64), version: args[3].Value.(int64)}
			return driver.RowsAffected(1), nil
		case recoveryFenceUpdate:
			identity := string(args[4].Value.([]byte))
			row, exists := e.rows[identity]
			if !exists || row.epoch != args[5].Value.(int64) || row.version != args[6].Value.(int64) || row.revoked != (args[7].Value.(int64) == 1) {
				return driver.RowsAffected(0), nil
			}
			row.epoch, row.version = args[0].Value.(int64), args[2].Value.(int64)
			row.revoked = args[1].Value != nil
			e.rows[identity] = row
			return driver.RowsAffected(1), nil
		}
		return nil, ErrInvalid
	}
	conn := sql.OpenDB(fakeConnector{db})
	t.Cleanup(func() { conn.Close() })
	manager, err := NewRecoveryFenceManager(conn, r.Scope, e)
	if err != nil {
		t.Fatal(err)
	}
	manager.clock = func() time.Time { return db.now }
	request := RecoveryFenceRequest{Scope: r.Scope, Operation: "register", IdentityHash: Hash(strings.Repeat("a", 64)), ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: Hash(strings.Repeat("b", 64))}
	return manager, request, e, db
}

type emptyFenceRows struct{}

func (*emptyFenceRows) Columns() []string         { return []string{"epoch", "revoked", "version"} }
func (*emptyFenceRows) Close() error              { return nil }
func (*emptyFenceRows) Next([]driver.Value) error { return io.EOF }

func TestRecoveryFenceLifecycle(t *testing.T) {
	m, r, e, _ := setupRecoveryFence(t)
	ctx := context.Background()
	registered, err := m.ChangeFence(ctx, r)
	if err != nil || registered.Epoch != "1" || registered.RowVersion != "1" || registered.Revoked {
		t.Fatal("register", registered, err)
	}
	if _, err := m.ChangeFence(ctx, r); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate register", err)
	}
	r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "rotate", "1", "1"
	rotated, err := m.ChangeFence(ctx, r)
	if err != nil || rotated.Epoch != "2" || rotated.RowVersion != "2" || rotated.Revoked {
		t.Fatal("same identity rotate", rotated, err)
	}
	if _, err := m.ChangeFence(ctx, r); !errors.Is(err, ErrConflict) {
		t.Fatal("stale epoch", err)
	}
	r.ExpectedEpoch, r.ExpectedRowVersion = "2", "2"
	next := Hash(strings.Repeat("c", 64))
	r.NextIdentityHash = &next
	changed, err := m.ChangeFence(ctx, r)
	if err != nil || changed.IdentityHash != next || changed.Epoch != "3" || changed.RowVersion != "1" || changed.Revoked {
		t.Fatal("identity rotate", changed, err)
	}
	oldKey, _ := hex.DecodeString(string(r.IdentityHash))
	if !e.rows[string(oldKey)].revoked {
		t.Fatal("old identity remained active")
	}
	r.IdentityHash, r.NextIdentityHash, r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = next, nil, "revoke", "3", "1"
	revoked, err := m.ChangeFence(ctx, r)
	if err != nil || !revoked.Revoked || revoked.Epoch != "4" || revoked.RowVersion != "2" {
		t.Fatal("revoke", revoked, err)
	}
	if _, err := m.ChangeFence(ctx, r); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate revoke", err)
	}
	r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "rotate", "4", "2"
	if got, err := m.ChangeFence(ctx, r); !errors.Is(err, ErrConflict) || got != (RecoveryFenceRow{}) {
		t.Fatal("revoked identity was revived", got, err)
	}
	newKey, _ := hex.DecodeString(string(next))
	if row := e.rows[string(newKey)]; row.epoch != 4 || row.version != 2 || !row.revoked {
		t.Fatal("rejected rotation changed revoked row", row)
	}
	if e.checks != 4 {
		t.Fatal("missing final guards", e.checks)
	}
}

func TestRecoveryFenceFailuresRollback(t *testing.T) {
	for _, failure := range []string{"denied", "digest", "prepare", "installation", "authorize", "audit:intent", "audit:result", "recheck", "cas", "commit_unknown"} {
		t.Run(failure, func(t *testing.T) {
			m, r, e, db := setupRecoveryFence(t)
			switch failure {
			case "denied":
				e.allow = false
			case "digest":
				e.badHash = true
			case "commit_unknown":
				db.commitError = true
			default:
				e.fail = failure
			}
			got, err := m.ChangeFence(context.Background(), r)
			if err == nil || !reflect.DeepEqual(got, RecoveryFenceRow{}) {
				t.Fatal(got, err)
			}
			if failure != "commit_unknown" && len(e.rows) != 0 {
				t.Fatal("failed transaction changed row")
			}
			if failure == "commit_unknown" && !errors.Is(err, ErrCommitUnknown) {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoveryFenceIdentityRotationRollback(t *testing.T) {
	for _, failure := range []string{"new_identity_insert", "audit:result", "recheck"} {
		t.Run(failure, func(t *testing.T) {
			m, r, e, _ := setupRecoveryFence(t)
			if _, err := m.ChangeFence(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			before := make(map[string]fenceTestRow)
			for k, v := range e.rows {
				before[k] = v
			}
			next := Hash(strings.Repeat("c", 64))
			r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion, r.NextIdentityHash = "rotate", "1", "1", &next
			e.fail = failure
			got, err := m.ChangeFence(context.Background(), r)
			if err == nil || !reflect.DeepEqual(got, RecoveryFenceRow{}) || !reflect.DeepEqual(e.rows, before) {
				t.Fatal("partial identity rotation", failure, got, err, e.rows)
			}
		})
	}
}

func TestRecoveryFenceConcurrentRotationSingleWinner(t *testing.T) {
	m, r, e, _ := setupRecoveryFence(t)
	if _, err := m.ChangeFence(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	m.db.SetMaxOpenConns(1)
	r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "rotate", "1", "1"
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.ChangeFence(context.Background(), r)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrConflict):
			conflict++
		default:
			t.Fatal(err)
		}
	}
	key, _ := hex.DecodeString(string(r.IdentityHash))
	if success != 1 || conflict != 1 || e.rows[string(key)].epoch != 2 {
		t.Fatal("concurrent CAS", success, conflict, e.rows)
	}
}

func TestRecoveryFenceMissingAndRevokedRows(t *testing.T) {
	m, r, e, _ := setupRecoveryFence(t)
	r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "rotate", "1", "1"
	if _, err := m.ChangeFence(context.Background(), r); !errors.Is(err, ErrConflict) {
		t.Fatal("rotate missing row", err)
	}
	r.Operation = "revoke"
	if _, err := m.ChangeFence(context.Background(), r); !errors.Is(err, ErrConflict) {
		t.Fatal("revoke missing row", err)
	}
	r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "register", "0", "0"
	if _, err := m.ChangeFence(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "revoke", "1", "1"
	if _, err := m.ChangeFence(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "register", "0", "0"
	if _, err := m.ChangeFence(context.Background(), r); !errors.Is(err, ErrConflict) {
		t.Fatal("revoked identity hash reused", err)
	}
	key, _ := hex.DecodeString(string(r.IdentityHash))
	if row := e.rows[string(key)]; row.epoch != 2 || !row.revoked {
		t.Fatal("revoked row changed", row)
	}
}
