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

// Protocol/rollback model only. It does not certify native MySQL isolation,
// real A grants, physical capacity, scheduling or B execution.
type backupStartEvent struct {
	kind, status, request      string
	attempt, previous, current driver.Value
}
type backupStartModel struct {
	claim       *claimReceiptModel
	config      []byte
	hash        string
	spec        dispatch.BackupSpec
	deadline    time.Time
	attempts    map[string]string
	events      map[int64]backupStartEvent
	sequence    int64
	fail, drift string
	existing    bool
	queries     []string
	listClosed  bool
	finalEvents int
	startClocks int
	claimReads  int
}
type backupStartDriver struct{ m *backupStartModel }
type backupStartConn struct {
	base     claimReceiptConn
	m        *backupStartModel
	attempts map[string]string
	events   map[int64]backupStartEvent
	started  time.Time
}
type backupStartTx struct{ c *backupStartConn }
type startCandidateRows struct {
	*claimReceiptRows
	m *backupStartModel
}

func (r *startCandidateRows) Close() error { r.m.listClosed = true; return nil }

type startResult int64

func (r startResult) RowsAffected() (int64, error) { return 1, nil }
func (r startResult) LastInsertId() (int64, error) { return int64(r), nil }
func (d backupStartDriver) Open(string) (driver.Conn, error) {
	return &backupStartConn{m: d.m, base: claimReceiptConn{model: d.m.claim}}, nil
}
func (c *backupStartConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare forbidden")
}
func (c *backupStartConn) Close() error { return nil }
func (c *backupStartConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unbounded begin forbidden")
}
func (c *backupStartConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if _, err := c.base.BeginTx(ctx, o); err != nil {
		return nil, err
	}
	c.attempts = map[string]string{}
	for k, v := range c.m.attempts {
		c.attempts[k] = v
	}
	c.events = map[int64]backupStartEvent{}
	for k, v := range c.m.events {
		c.events[k] = v
	}
	return backupStartTx{c}, nil
}
func (t backupStartTx) Commit() error {
	t.c.m.attempts = t.c.attempts
	t.c.m.events = t.c.events
	return (claimReceiptTx{&t.c.base}).Commit()
}
func (t backupStartTx) Rollback() error { return (claimReceiptTx{&t.c.base}).Rollback() }
func (c *backupStartConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !c.base.inTx {
		return nil, errors.New("write outside transaction")
	}
	m := c.m
	m.queries = append(m.queries, q)
	switch {
	case strings.HasPrefix(q, "UPDATE system_backup_v2_backups SET status="):
		for _, required := range []string{"row_version=?", "controller_lease_expires_at>UTC_TIMESTAMP(6)", "deadline_at>UTC_TIMESTAMP(6)", "system_backup_v2_attempts", "system_backup_v2_job_observations", "system_backup_v2_staging_resources", "system_backup_v2_external_actions"} {
			if !strings.Contains(q, required) {
				return nil, errors.New("unsafe start CAS")
			}
		}
		if len(args) != 4 || args[0].Value != c.base.pending.installation || args[1].Value != c.base.pending.publicID || args[2].Value != c.base.pending.owner || args[3].Value != int64(c.base.pending.version) || c.base.pending.status != "pending" || m.existing || m.fail == "status" {
			return fixedResult(0), nil
		}
		c.base.pending.status = "preparing"
		c.base.pending.version++
		c.started = m.claim.row.now
		return fixedResult(1), nil
	case strings.HasPrefix(q, "UPDATE "):
		return c.base.ExecContext(ctx, q, args)
	case strings.HasPrefix(q, "INSERT INTO system_backup_v2_attempts"):
		if len(args) != 2 || args[0].Value != c.base.pending.publicID {
			return nil, errors.New("unbound attempt")
		}
		phase := args[1].Value.(string)
		if m.fail == phase {
			return nil, errors.New("attempt insert failed")
		}
		if _, ok := c.attempts[phase]; ok {
			return nil, errors.New("duplicate attempt")
		}
		c.attempts[phase] = "preparing"
		return fixedResult(1), nil
	case strings.HasPrefix(q, "INSERT INTO system_backup_v2_events"):
		m.sequence++
		id := m.sequence
		if strings.Contains(q, "Controller acquired task claim.") {
			if _, err := c.base.ExecContext(ctx, q, args); err != nil {
				return nil, err
			}
			c.events[id] = backupStartEvent{kind: TaskClaimAcquiredEvent, status: "pending", request: c.base.pending.requestID}
			return startResult(id), nil
		}
		if len(args) != 6 || args[0].Value != c.base.pending.installation || args[1].Value != c.base.pending.publicID || args[5].Value != c.base.pending.requestID {
			return nil, errors.New("unbound core event")
		}
		kind := args[2].Value.(string)
		if m.fail == kind {
			return nil, errors.New("core event insert failed")
		}
		c.events[id] = backupStartEvent{kind: kind, status: "preparing", request: c.base.pending.requestID, attempt: int64(1), previous: args[3].Value, current: args[4].Value}
		return startResult(id), nil
	}
	return nil, fmt.Errorf("unexpected write: %s", q)
}
func (c *backupStartConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT public_id,row_version") {
		if c.base.inTx || len(args) != 3 || args[0].Value != c.m.claim.row.installation || !strings.Contains(q, "next_reconcile_at<=UTC_TIMESTAMP(6)") {
			return nil, errors.New("unsafe schedule query")
		}
		return &startCandidateRows{claimReceiptRows: &claimReceiptRows{values: []driver.Value{c.m.claim.row.publicID, int64(c.m.claim.row.version)}}, m: c.m}, nil
	}
	if !c.base.inTx {
		return nil, errors.New("read outside transaction")
	}
	m := c.m
	m.queries = append(m.queries, q)
	r := c.base.pending
	now := m.claim.row.now
	row := func(v ...driver.Value) (driver.Rows, error) { return &claimReceiptRows{values: v}, nil }
	switch {
	case strings.HasPrefix(q, "SELECT gate_state, generation"):
		return row("idle", int64(1), int64(0), "", int64(1))
	case strings.HasPrefix(q, "SELECT gate_state,COALESCE"):
		return row("idle", "", int64(0), int64(1), nil, nil)
	case strings.HasPrefix(q, "SELECT active_config_version"):
		return row(int64(1))
	case strings.HasPrefix(q, "SELECT enabled"):
		return row(m.fail != "disabled")
	case strings.HasPrefix(q, "SELECT schema_version,row_version,active_config_version"):
		return row("system-backup-installation-state.v1", int64(1), int64(1))
	case strings.HasPrefix(q, "SELECT schema_version,enabled"):
		return row("system-backup-config.v1", m.drift != "disabled")
	case strings.HasPrefix(q, "SELECT schema_version,origin_installation_id,public_id"):
		m.claimReads++
		if m.fail == "entry_clock" {
			now = now.Add(2 * time.Second)
		}
		if m.fail == "claim_exit_clock" {
			step := time.Second
			if m.claimReads == 2 {
				step = 2 * time.Second
			}
			now = now.Add(step)
		}
		if m.fail == "budget_clock" && m.startClocks >= 3 {
			now = now.Add(2 * time.Second)
		}
		if m.drift == "rollback_after_auth" {
			now = now.Add(2 * time.Second)
		}
		if m.drift == "rollback_after_fixed" {
			now = now.Add(5 * time.Second)
		}
		return row(r.schema, r.installation, r.publicID, r.kind, r.requestID, r.status, r.owner, r.until, int64(r.version), r.heartbeat, now)
	case strings.HasPrefix(q, "SELECT request_id,config_version"):
		if r.status != "pending" {
			return nil, sql.ErrNoRows
		}
		return row(r.requestID, int64(1), m.config, int64(len(m.config)), m.hash, m.deadline, m.spec.SourceOrchestrator, m.spec.SourceProfile, m.spec.MatrixKey, m.spec.DatasourceTopology, m.spec.Runner, m.spec.TaskPurpose, strings.Join(m.spec.RequestedParts, ","))
	case strings.HasPrefix(q, "SELECT schema_version,origin_installation_id,task_type"):
		return row(r.schema, r.installation, r.kind, r.requestID, r.status, r.owner, int64(r.version), r.until, m.deadline, int64(1), m.config, int64(len(m.config)), m.hash)
	case strings.HasPrefix(q, "SELECT canonical_config_json"):
		return row(m.config)
	case strings.HasPrefix(q, "SELECT attempt_no"):
		return row(int64(1))
	case strings.HasPrefix(q, "SELECT status,row_version"):
		phase := args[len(args)-1].Value.(string)
		status, ok := c.attempts[phase]
		if !ok {
			return nil, sql.ErrNoRows
		}
		if phase == "secret_capture" && m.drift == "secret" {
			status = "failed"
		}
		return row(status, int64(1))
	case strings.HasPrefix(q, "SELECT config_snapshot_json,source_orchestrator"):
		parts := strings.Join(m.spec.RequestedParts, ",")
		if m.drift == "parts" {
			parts = "mysql"
		}
		return row(m.config, m.spec.SourceOrchestrator, m.spec.SourceProfile, m.spec.MatrixKey, m.spec.DatasourceTopology, m.spec.Runner, m.spec.TaskPurpose, parts, c.started, c.started)
	case strings.HasPrefix(q, "SELECT schema_version,event_type"):
		m.finalEvents++
		id := args[0].Value.(int64)
		e, ok := c.events[id]
		if !ok {
			return nil, sql.ErrNoRows
		}
		kind := e.kind
		if m.drift == "receipt" && kind == TaskClaimAcquiredEvent {
			kind = "attempt_finished"
		}
		return row("system-backup-event.v1", kind, e.status, e.request, e.attempt, e.previous, e.current)
	case strings.HasPrefix(q, "SELECT UTC_TIMESTAMP(6)"):
		if strings.Contains(q, "TIMESTAMPDIFF") {
			m.startClocks++
		}
		if m.fail == "entry_clock" {
			step := 2 * time.Second
			if m.startClocks == 1 && strings.Contains(q, "TIMESTAMPDIFF") {
				step = 5 * time.Second
			}
			now = now.Add(step)
		}
		if m.fail == "claim_exit_clock" && m.claimReads >= 3 {
			now = now.Add(time.Second)
		}
		if m.fail == "budget_clock" {
			if m.startClocks == 2 && strings.Contains(q, "TIMESTAMPDIFF") {
				now = now.Add(5 * time.Second)
			} else if m.startClocks >= 3 {
				now = now.Add(2 * time.Second)
			}
		}
		if m.drift == "rollback_after_auth" || m.drift == "rollback_after_fixed" {
			now = now.Add(4 * time.Second)
		}
		if m.drift == "auth_expired_last" && m.finalEvents >= 3 {
			now = now.Add(2 * time.Second)
		}
		if m.drift == "expired" {
			now = m.deadline
		}
		if strings.Contains(q, "TIMESTAMPDIFF") {
			var offset int64
			if m.fail == "timezone" {
				offset = 3600000000
			}
			return row(now, offset)
		}
		return row(now)
	}
	return nil, fmt.Errorf("unexpected query: %s", q)
}

type startBudget struct {
	until     time.Time
	deny      bool
	onRecheck func()
	rechecks  int
}

func (b *startBudget) AdmitStart(_ context.Context, _ *sql.Tx, in BackupStart, _ time.Time) (BackupStartGuard, error) {
	// Mutating an observation passed to an owner must not affect final CAS data.
	in.Spec.RequestedParts[0] = "forged"
	in.ConfigSnapshot[0] = 'x'
	if b.deny {
		return nil, ErrBackupStart
	}
	return b, nil
}
func (b *startBudget) RecheckStart(context.Context, *sql.Tx, BackupStart, time.Time) error {
	b.rechecks++
	if b.onRecheck != nil {
		b.onRecheck()
	}
	if b.deny {
		return ErrBackupStart
	}
	return nil
}
func (b *startBudget) ValidUntil() time.Time { return b.until }

var startModelCounter atomic.Uint64

func newBackupStartModel(t *testing.T) (SQLBackupStartStore, *backupStartModel, Target) {
	t.Helper()
	now := time.Date(2026, 10, 28, 4, 0, 0, 0, time.UTC)
	cfg := []byte(`{"x":1}`)
	sum := sha256.Sum256(cfg)
	target := Target{Kind: TargetBackup, PublicID: "sbk_01234567-89ab-cdef-0123-456789abcdef"}
	m := &backupStartModel{config: cfg, hash: hex.EncodeToString(sum[:]), deadline: now.Add(time.Hour), attempts: map[string]string{}, events: map[int64]backupStartEvent{}, spec: dispatch.BackupSpec{SourceOrchestrator: "kubernetes", SourceProfile: "cluster", MatrixKey: "k8s-cluster", DatasourceTopology: "in_cluster", Runner: "k8s", TaskPurpose: "acceptance", RequestedParts: []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"}}}
	m.claim = &claimReceiptModel{row: taskClaimSnapshot{schema: "system-backup-task.v1", installation: "installation_test", publicID: target.PublicID, kind: "backup", requestID: "request-start", status: "pending", version: 1, now: now}}
	name := fmt.Sprintf("backup-start-%d", startModelCounter.Add(1))
	sql.Register(name, backupStartDriver{m})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	a := SQLExecutionAuthority{DB: db, InstallationID: "installation_test", DeploymentEnabled: true, Authorization: &executionAuth{until: now.Add(time.Minute)}}
	return SQLBackupStartStore{Authority: a, Admission: &startBudget{until: now.Add(time.Minute)}, Policy: validPolicy()}, m, target
}
func TestBackupStartCommitsClaimBothUnitsAndEventsAtomically(t *testing.T) {
	s, m, target := newBackupStartModel(t)
	out, err := s.Start(context.Background(), target, "controller-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if m.claim.begin != 1 || m.claim.commit != 1 || m.claim.cas != 1 || m.claim.receipts != 1 || m.claim.row.status != "preparing" || m.claim.row.version != 3 || len(m.attempts) != 2 || len(m.events) != 3 || out.Authority.ClaimRowVersion != 3 || out.Authority.AttemptNo != 1 || out.Spec.TaskPurpose != "acceptance" || len(out.Spec.RequestedParts) != 6 || out.ConfigSnapshot[0] != '{' {
		t.Fatalf("incomplete atomic start: %+v", m)
	}
	if !strings.HasPrefix(m.queries[0], "SELECT gate_state") {
		t.Fatal("gate lock was not first")
	}
}
func TestBackupStartFailuresRollbackWholeWriteSet(t *testing.T) {
	for _, fail := range []string{"status", "capture", "secret_capture", "task_status_changed", "attempt_started", "disabled", "budget", "auth", "existing", "timezone"} {
		t.Run(fail, func(t *testing.T) {
			s, m, target := newBackupStartModel(t)
			m.fail = fail
			switch fail {
			case "budget":
				s.Admission.(*startBudget).deny = true
			case "auth":
				s.Authority.Authorization.(*executionAuth).deny = true
			case "existing":
				m.existing = true
			}
			out, err := s.Start(context.Background(), target, "controller-1", 1)
			if err == nil || out.Authority.TaskPublicID != "" || m.claim.commit != 0 || m.claim.rollback != 1 || m.claim.row.version != 1 || m.claim.receipts != 0 || len(m.attempts) != 0 || len(m.events) != 0 {
				t.Fatalf("partial write escaped rollback: %s %+v", fail, m)
			}
		})
	}
}
func TestBackupStartFinalGuardRejectsDriftInEitherUnitInputOrReceipt(t *testing.T) {
	for _, drift := range []string{"secret", "parts", "receipt", "expired", "disabled"} {
		t.Run(drift, func(t *testing.T) {
			s, m, target := newBackupStartModel(t)
			s.Authority.Authorization.(*executionAuth).onRecheck = func() { m.drift = drift }
			if out, err := s.Start(context.Background(), target, "controller-1", 1); err == nil || out.Authority.TaskPublicID != "" || m.claim.commit != 0 || m.claim.receipts != 0 || len(m.attempts) != 0 {
				t.Fatal("post-authorization drift committed")
			}
		})
	}
}
func TestBackupStartUnknownCommitReturnsNoAuthorityAndDoesNotReplay(t *testing.T) {
	s, m, target := newBackupStartModel(t)
	m.claim.commitUnknown = true
	out, err := s.Start(context.Background(), target, "controller-1", 1)
	if !errors.Is(err, ErrTaskClaimCommitUnknown) || out.Authority.TaskPublicID != "" || m.claim.begin != 1 || m.claim.commit != 1 || m.claim.receipts != 1 || len(m.attempts) != 2 || len(m.events) != 3 {
		t.Fatal("unknown commit granted authority or retried")
	}
	m.claim.commitUnknown = false
	if _, err = s.Start(context.Background(), target, "controller-1", 1); !errors.Is(err, ErrClaimNotAcquired) || m.claim.receipts != 1 || len(m.events) != 3 {
		t.Fatal("original version replay duplicated start")
	}
}
func TestBackupStartMissingOwnersAndTypedNilContextNeverOpenTransaction(t *testing.T) {
	for _, missing := range []string{"auth", "budget", "context"} {
		t.Run(missing, func(t *testing.T) {
			s, m, target := newBackupStartModel(t)
			var ctx context.Context = context.Background()
			switch missing {
			case "auth":
				var absent *executionAuth
				s.Authority.Authorization = absent
			case "budget":
				var absent *startBudget
				s.Admission = absent
			case "context":
				var absent *executionNilContext
				ctx = absent
			}
			if _, err := s.Start(ctx, target, "controller-1", 1); err == nil || m.claim.begin != 0 {
				t.Fatal("missing owner reached SQL")
			}
		})
	}
}
func TestBackupStartRejectsInvalidOriginalSpec(t *testing.T) {
	for _, kind := range []string{"purpose", "matrix", "partial", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			s, m, target := newBackupStartModel(t)
			switch kind {
			case "purpose":
				m.spec.TaskPurpose = ""
			case "matrix":
				m.spec.MatrixKey = "k3s-cluster"
			case "partial":
				m.spec.RequestedParts = m.spec.RequestedParts[:1]
			case "duplicate":
				m.spec.RequestedParts[1] = "mysql"
			}
			if _, err := s.Start(context.Background(), target, "controller-1", 1); err == nil || m.claim.commit != 0 {
				t.Fatal("invalid task spec started")
			}
		})
	}
}
func TestBackupStartNextConsumesPersistedScheduleAndClosesCursor(t *testing.T) {
	s, m, _ := newBackupStartModel(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := s.StartNext(ctx, "controller-1", 1)
	if err != nil || result == nil || !m.listClosed || m.claim.commit != 1 || len(m.attempts) != 2 {
		t.Fatalf("schedule/start caller failed: %v", err)
	}
}

func TestBackupStartFinalClockCannotOutliveOriginalAuthorization(t *testing.T) {
	s, m, target := newBackupStartModel(t)
	a := s.Authority.Authorization.(*executionAuth)
	a.until = m.claim.row.now.Add(time.Second)
	a.onRecheck = func() { m.drift = "auth_expired_last" }
	if result, err := s.Start(context.Background(), target, "controller-1", 1); err == nil || result.Authority.TaskPublicID != "" || m.claim.commit != 0 {
		t.Fatal("final fixed SQL outlived A authority")
	}
}

func TestBackupStartPreservesAuthorityAndFixedSQLClockFloors(t *testing.T) {
	for _, drift := range []string{"rollback_after_auth", "rollback_after_fixed"} {
		t.Run(drift, func(t *testing.T) {
			s, m, target := newBackupStartModel(t)
			s.Authority.Authorization.(*executionAuth).onRecheck = func() { m.drift = drift }
			out, err := s.Start(context.Background(), target, "controller-1", 1)
			if err == nil || out.Authority.TaskPublicID != "" || m.claim.commit != 0 || m.claim.receipts != 0 || len(m.attempts) != 0 {
				t.Fatal("SQL clock floor rollback committed")
			}
		})
	}
}

func TestBackupStartPreservesEntryClaimAndBudgetClockFloors(t *testing.T) {
	for _, mode := range []string{"entry_clock", "claim_exit_clock", "budget_clock"} {
		t.Run(mode, func(t *testing.T) {
			s, m, target := newBackupStartModel(t)
			m.fail = mode
			out, err := s.Start(context.Background(), target, "controller-1", 1)
			if err == nil || out.Authority.TaskPublicID != "" || m.claim.commit != 0 || m.claim.receipts != 0 || len(m.attempts) != 0 {
				t.Fatal("earlier SQL clock high-water mark lost")
			}
			if mode == "budget_clock" && s.Admission.(*startBudget).rechecks != 0 {
				t.Fatal("budget callback ran after observed SQL rollback")
			}
		})
	}
}

func TestBackupStartFinalHistoryReadsPreserveAppendOnlyPermissions(t *testing.T) {
	s, m, target := newBackupStartModel(t)
	if _, err := s.Start(context.Background(), target, "controller-1", 1); err != nil {
		t.Fatal(err)
	}
	for _, q := range m.queries {
		if !strings.HasPrefix(q, "SELECT ") {
			continue
		}
		if strings.Contains(q, "system_backup_v2_events") || strings.Contains(q, "system_backup_v2_configs") || strings.Contains(q, "system_backup_v2_attempts") {
			if strings.Contains(q, "FOR UPDATE") || !strings.HasSuffix(q, "FOR SHARE") {
				t.Fatal("history verifier requested write grants")
			}
		}
	}
}
