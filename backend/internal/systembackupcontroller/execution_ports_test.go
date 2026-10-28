package systembackupcontroller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dispatch "clawreef/internal/systembackupdispatch"
)

// This driver verifies the transaction/lock/identity protocol, not MySQL
// isolation or a real A authorization. Native field acceptance is separate.
type executionModel struct {
	a                         dispatch.Authority
	now                       time.Time
	status, attempt, gate     string
	config                    []byte
	reads, commits, rollbacks int
	queries                   []string
	drift                     string
	clockShift                time.Duration
}
type executionDriver struct{ m *executionModel }
type executionConn struct {
	m      *executionModel
	active bool
}
type executionTx struct{ c *executionConn }

func (d executionDriver) Open(string) (driver.Conn, error) { return &executionConn{m: d.m}, nil }
func (c *executionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare forbidden")
}
func (c *executionConn) Close() error { return nil }
func (c *executionConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unbounded begin forbidden")
}
func (c *executionConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || o.ReadOnly {
		return nil, errors.New("wrong isolation")
	}
	c.active = true
	return executionTx{c}, nil
}
func (t executionTx) Commit() error   { t.c.m.commits++; t.c.active = false; return nil }
func (t executionTx) Rollback() error { t.c.m.rollbacks++; t.c.active = false; return nil }
func (c *executionConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if !c.active {
		return nil, errors.New("escaped transaction")
	}
	m := c.m
	m.queries = append(m.queries, q)
	row := func(v ...driver.Value) (driver.Rows, error) { return &claimReceiptRows{values: v}, nil }
	a := m.a
	switch {
	case strings.HasPrefix(q, "SELECT gate_state"):
		if len(args) != 2 || args[0].Value != a.InstallationID || args[1].Value != CaptureGateScope || !strings.HasSuffix(q, "FOR UPDATE") {
			return nil, errors.New("bad gate scope")
		}
		var lease, hold driver.Value
		if m.gate == "held" {
			lease = m.now.Add(time.Minute)
			hold = m.now.Add(time.Minute)
		}
		fence := int64(a.MaintenanceFencingToken)
		if m.drift == "fence" {
			fence++
		}
		return row(m.gate, a.MaintenanceOwner, fence, int64(1), lease, hold)
	case strings.HasPrefix(q, "SELECT schema_version,row_version,active_config_version"):
		return row("system-backup-installation-state.v1", int64(1), int64(1))
	case strings.HasPrefix(q, "SELECT schema_version,enabled"):
		return row("system-backup-config.v1", m.drift != "disabled")
	case strings.HasPrefix(q, "SELECT schema_version"):
		m.reads++
		version := int64(a.ClaimRowVersion)
		owner := a.ClaimOwner
		cfg := m.config
		if m.drift == "version" {
			version++
		}
		if m.drift == "owner" {
			owner = "other"
		}
		if m.drift == "config" {
			cfg = []byte(`{"x":2}`)
		}
		until := m.now.Add(30 * time.Second)
		if m.drift == "expired" {
			until = m.now
		}
		return row("system-backup-task.v1", a.InstallationID, a.TaskType, a.RequestID, m.status, owner, version, until, a.DeadlineAt, int64(a.ConfigVersion), cfg, int64(len(cfg)), a.ConfigSHA256)
	case strings.HasPrefix(q, "SELECT canonical_config_json"):
		return row(m.config)
	case strings.HasPrefix(q, "SELECT status,row_version"):
		return row(m.attempt, int64(1))
	case strings.HasPrefix(q, "SELECT attempt_no"):
		latest := int64(a.AttemptNo)
		if m.drift == "attempt" {
			latest++
		}
		return row(latest)
	case strings.HasPrefix(q, "SELECT maintenance_lock_owner"):
		return row(a.MaintenanceOwner, int64(a.MaintenanceFencingToken))
	case q == "SELECT UTC_TIMESTAMP(6)":
		return row(m.now.Add(m.clockShift))
	}
	return nil, fmt.Errorf("unexpected query: %s", q)
}

var executionModelCounter atomic.Uint64

func newExecutionModel(t *testing.T) (SQLExecutionAuthority, *executionModel) {
	t.Helper()
	now := time.Date(2026, 10, 28, 2, 0, 0, 0, time.UTC)
	cfg := []byte(`{"x":1}`)
	sum := sha256.Sum256(cfg)
	m := &executionModel{now: now, config: cfg, status: "capturing", attempt: "running", gate: "held"}
	m.a = dispatch.Authority{InstallationID: "installation_test", TaskPublicID: "sbk_01234567-89ab-cdef-0123-456789abcdef", TaskType: "backup", RequestID: "request-1", ConfigVersion: 1, ConfigSHA256: hex.EncodeToString(sum[:]), AttemptNo: 1, Phase: "capture", ClaimOwner: "controller-1", ClaimRowVersion: 2, MaintenanceOwner: "capture-1", MaintenanceFencingToken: 1, DeadlineAt: now.Add(time.Minute)}
	name := fmt.Sprintf("execution-model-%d", executionModelCounter.Add(1))
	sql.Register(name, executionDriver{m})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return SQLExecutionAuthority{DB: db, InstallationID: m.a.InstallationID, DeploymentEnabled: true, Authorization: &executionAuth{until: now.Add(time.Minute)}}, m
}

type executionAuth struct {
	until     time.Time
	deny      bool
	onRecheck func()
}

func (a *executionAuth) AuthorizeExecution(context.Context, *sql.Tx, dispatch.Authority, time.Time) (ExecutionAuthorizationGuard, error) {
	if a.deny {
		return nil, ErrExecutionAuthority
	}
	return a, nil
}
func (a *executionAuth) RecheckExecution(context.Context, *sql.Tx, dispatch.Authority, time.Time) error {
	if a.onRecheck != nil {
		a.onRecheck()
	}
	if a.deny {
		return ErrExecutionAuthority
	}
	return nil
}
func (a *executionAuth) ValidUntil() time.Time { return a.until }

func TestExecutionAuthorityChecksLockedPublicRecords(t *testing.T) {
	s, m := newExecutionModel(t)
	if err := s.Check(context.Background(), m.a); err != nil {
		t.Fatal(err)
	}
	if m.reads != 2 || m.commits != 0 || m.rollbacks != 1 || !strings.HasPrefix(m.queries[0], "SELECT gate_state") {
		t.Fatalf("unexpected protocol: %+v", m)
	}
}
func TestExecutionAuthorityRejectsInvalidOrStaleWork(t *testing.T) {
	for _, drift := range []string{"fence", "version", "owner", "config", "expired", "disabled", "cancel", "sealed", "gate", "attempt"} {
		t.Run(drift, func(t *testing.T) {
			s, m := newExecutionModel(t)
			m.drift = drift
			switch drift {
			case "cancel":
				m.status = "canceling"
			case "sealed":
				m.attempt = "sealed"
			case "gate":
				m.gate = "releasing"
			}
			if s.Check(context.Background(), m.a) == nil {
				t.Fatal("stale work admitted")
			}
			if m.commits != 0 {
				t.Fatal("check committed")
			}
		})
	}
}
func TestExecutionAuthorityFinalRecheckAndFailureLatch(t *testing.T) {
	s, m := newExecutionModel(t)
	tx, err := s.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	g, err := s.Bind(context.Background(), tx, m.a)
	if err != nil {
		t.Fatal(err)
	}
	s.Authorization.(*executionAuth).onRecheck = func() { m.drift = "version" }
	if g.Recheck(context.Background(), tx) == nil {
		t.Fatal("post callback drift accepted")
	}
	m.drift = ""
	if g.Recheck(context.Background(), tx) == nil {
		t.Fatal("failed guard revived")
	}
}
func TestExecutionAuthorityRequiresRealAuthorization(t *testing.T) {
	s, m := newExecutionModel(t)
	var absent *executionAuth
	s.Authorization = absent
	if s.Check(context.Background(), m.a) == nil {
		t.Fatal("typed nil owner accepted")
	}
	s.Authorization = &executionAuth{until: m.now.Add(time.Minute), deny: true}
	if s.Check(context.Background(), m.a) == nil {
		t.Fatal("owner denial ignored")
	}
	s.Authorization = &executionAuth{until: m.now}
	if s.Check(context.Background(), m.a) == nil {
		t.Fatal("expired authorization accepted")
	}
}
func TestExecutionAuthorityDiscoveryAndPreflightHaveNoCaptureFence(t *testing.T) {
	for _, preflight := range []bool{false, true} {
		t.Run(fmt.Sprint(preflight), func(t *testing.T) {
			s, m := newExecutionModel(t)
			m.a.MaintenanceOwner = ""
			m.a.MaintenanceFencingToken = 0
			m.gate = "idle"
			m.status = "preparing"
			m.attempt = "preparing"
			if preflight {
				m.a.TaskType = "preflight"
				m.a.TaskPublicID = "spf_01234567-89ab-cdef-0123-456789abcdef"
				m.a.Phase = "preflight"
				m.status = "running"
				m.attempt = "running"
			}
			if err := s.Check(context.Background(), m.a); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type executionNilContext struct{}

func (*executionNilContext) Deadline() (time.Time, bool) { panic("typed nil context used") }
func (*executionNilContext) Done() <-chan struct{}       { panic("typed nil context used") }
func (*executionNilContext) Err() error                  { panic("typed nil context used") }
func (*executionNilContext) Value(any) any               { panic("typed nil context used") }

func TestExecutionAuthorityCopySharesFailureAndOriginalContext(t *testing.T) {
	s, m := newExecutionModel(t)
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	g, err := s.Bind(ctx, tx, m.a)
	if err != nil {
		t.Fatal(err)
	}
	copyGuard := *g
	other, cancel := context.WithCancel(ctx)
	defer cancel()
	if g.Recheck(other, tx) == nil {
		t.Fatal("substituted context accepted")
	}
	if copyGuard.Recheck(ctx, tx) == nil {
		t.Fatal("copy bypassed shared failure latch")
	}
}
func TestExecutionAuthorityRejectsTypedNilContext(t *testing.T) {
	s, m := newExecutionModel(t)
	var ctx *executionNilContext
	if s.Check(ctx, m.a) == nil {
		t.Fatal("typed nil context accepted")
	}
	if g, err := s.Bind(ctx, nil, m.a); err == nil || g != nil {
		t.Fatal("typed nil bind accepted")
	}
}

func TestExecutionAuthorityOriginalBoundAndMonotonicRecheck(t *testing.T) {
	s, m := newExecutionModel(t)
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	g, err := s.Bind(ctx, tx, m.a)
	if err != nil {
		t.Fatal(err)
	}
	if !g.ValidUntil().Equal(m.now.Add(30 * time.Second)) {
		t.Fatal("guard did not expose original shortest lease bound")
	}
	m.clockShift = time.Second
	if err := g.Recheck(ctx, tx); err != nil {
		t.Fatal(err)
	}
	m.clockShift = 0
	if g.Recheck(ctx, tx) == nil || !g.ValidUntil().IsZero() {
		t.Fatal("SQL clock rolled back or failed guard retained a bound")
	}
}

func TestExecutionAuthorityReadLocksDoNotRequireHistoryWriteGrants(t *testing.T) {
	s, m := newExecutionModel(t)
	if err := s.Check(context.Background(), m.a); err != nil {
		t.Fatal(err)
	}
	for _, q := range m.queries {
		if strings.Contains(q, "system_backup_v2_configs") || strings.Contains(q, "system_backup_v2_attempts") {
			if strings.Contains(q, "FOR UPDATE") || !strings.HasSuffix(q, "FOR SHARE") {
				t.Fatal("read-only history acquired a write privilege requirement")
			}
		}
	}
}
