package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	app "clawreef/internal/systembackup"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

// SQLCaptureGate maps the public execution epoch onto the application's ONE
// admission gate. Acquisition closes new writes; held additionally proves every
// physical writer paused. Only held authorizes collectors. Its journal is facts,
// not another task state machine. Recovery uses an independently signed grant.
type SQLCaptureGate struct {
	Authority          SQLExecutionAuthority
	Recovery           SQLRecoveryAuthority
	Records            SQLExecutionRecords
	AcquisitionTimeout time.Duration
	HoldTimeout        time.Duration
}

func (g SQLCaptureGate) ready() bool {
	return g.Authority.DB != nil && g.Authority.ApplicationScope != "" && g.Recovery.DB == g.Authority.DB && g.Recovery.ApplicationScope == g.Authority.ApplicationScope && g.Recovery.Identity != nil && g.AcquisitionTimeout >= 10*time.Second && g.AcquisitionTimeout <= 600*time.Second && g.HoldTimeout >= 30*time.Second && g.HoldTimeout <= time.Hour
}

func describeExecutionPlan(in d.Input, p d.Plan) (b.Discovery, error) {
	inner, e := d.UnwrapTaskPlan(in, p, b.PlanVersion)
	if e != nil {
		return b.Discovery{}, e
	}
	defer clear(inner.CanonicalJSON)
	return b.DescribePlan(in, inner)
}

// PrepareCapture never rediscoveries a plan. A previous capture is recovery
// work, never permission to repeat the source read.
func (g SQLCaptureGate) PrepareCapture(ctx context.Context, c ClaimedBackup) (*ExecutionWork, error) {
	if !g.ready() {
		return nil, d.ErrNotReady
	}
	db := g.Authority.DB
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	in, e := c.ExecutionInput(ctx, tx)
	if e != nil {
		return nil, e
	}
	tx.Rollback()
	if c.Status == "capturing" || c.Status == "canceling" {
		if e = g.Recovery.Check(ctx, in.Authority); e != nil {
			return nil, e
		}
		if released, e := g.ReconcileReleasedCapture(ctx, in.Authority); e != nil {
			return nil, e
		} else if released {
			w := ExecutionWork{Step: ExecutionRecover, Input: in}
			out := ExecutionOutcome{Recovery: d.RecoveryResult{CollectorsStopped: true, WritersResumed: true}}
			if e = g.FinishCapture(ctx, w, out); e != nil {
				return nil, e
			}
			return nil, nil
		}
		p, e := g.Records.LoadRecoveryPlan(ctx, in, g.Recovery)
		if e != nil {
			return nil, e
		}
		return &ExecutionWork{Step: ExecutionRecover, Input: in, Plan: p}, nil
	}
	if c.Status != "ready_for_capture" && c.Status != "acquiring_gate" && c.Status != "preparing" {
		return nil, ErrExecutionRecoveryRequired
	}
	if e = g.Authority.Check(ctx, in.Authority); e != nil && (c.Status == "ready_for_capture" || c.Status == "preparing" || c.Status == "acquiring_gate") {
		if e = g.FailUntouched(ctx, in.Authority); e != nil {
			return nil, e
		}
		return nil, nil
	}
	if c.Status == "preparing" {
		return nil, ErrExecutionRecoveryRequired
	}
	p, e := g.Records.LoadPlan(ctx, in)
	if e != nil {
		return nil, e
	}
	x, e := describeExecutionPlan(in, p)
	if e != nil {
		return nil, e
	}
	ids := make([]string, 0, len(x.Writers))
	for _, w := range x.Writers {
		if len(w.ID) > 128 {
			return nil, d.ErrNotReady
		}
		ids = append(ids, w.ID)
	}
	sort.Strings(ids)
	raw, _ := json.Marshal(x.Writers)
	registry := recordHash(raw)
	gate := app.Gate{DB: db}
	scope := g.Authority.ApplicationScope
	if c.Status == "ready_for_capture" {
		// Registration is allowed only while idle. Existing participants MUST be
		// covered; never delete an unrecognised writer to make capture proceed.
		for _, id := range ids {
			if e = gate.RegisterParticipant(ctx, scope, id); e != nil {
				return nil, e
			}
		}
		if e = g.checkParticipants(ctx, ids); e != nil {
			return nil, e
		}
		tx, e = db.BeginTx(ctx, nil)
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		guard, e := g.Authority.Bind(ctx, tx, in.Authority)
		if e != nil {
			return nil, e
		}
		if e = guard.Recheck(ctx, tx); e != nil {
			return nil, e
		}
		r, e := tx.ExecContext(ctx, "UPDATE system_backup_v2_backups SET status='acquiring_gate',row_version=row_version+1 WHERE public_id=? AND row_version=? AND controller_owner=?", in.Authority.TaskPublicID, in.Authority.ClaimRowVersion, in.Authority.ClaimOwner)
		if ok, z := exactlyOneRow(r); e != nil || z != nil || !ok {
			return nil, ErrClaimLost
		}
		if e = tx.Commit(); e != nil {
			return nil, ErrExecutionCommitUnknown
		}
		in.Authority.ClaimRowVersion++
		c.Status = "acquiring_gate"
	}
	claim := app.VersionedGateClaim{InstallationID: in.Authority.InstallationID, TaskID: in.Authority.TaskPublicID, ControllerOwner: in.Authority.ClaimOwner, RowVersion: in.Authority.ClaimRowVersion}
	journal := func(ctx context.Context, tx *sql.Tx, ownership app.GateOwnership) error {
		return g.stageCaptureEpoch(ctx, tx, in, ownership, registry, raw, ids)
	}
	ownership, phase, e := gate.ResolveVersionedCapture(ctx, scope, claim, registry)
	if e != nil {
		ownership, e = gate.BeginVersionedCaptureJournal(ctx, scope, claim, registry, g.AcquisitionTimeout, g.HoldTimeout, journal)
		if e != nil {
			return nil, e
		}
	} else {
		// Upgrade compatibility for a pre-atomic acquisition. Its original
		// generation is reused, never reacquired or given new deadlines.
		if phase != "acquiring" {
			return nil, ErrExecutionRecoveryRequired
		}
		tx, e = db.BeginTx(ctx, nil)
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		if e = journal(ctx, tx, ownership); e != nil {
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, ErrExecutionCommitUnknown
		}
	}
	in.Authority.ClaimRowVersion++
	in.Authority.MaintenanceOwner = in.Authority.TaskPublicID
	in.Authority.MaintenanceFencingToken = ownership.Generation
	return &ExecutionWork{Step: ExecutionCapture, Input: in, Plan: p}, nil
}

// stageCaptureEpoch commits the physical acquiring transition, public original
// epoch, attempt and task projection in the same SQL transaction.
func (g SQLCaptureGate) stageCaptureEpoch(ctx context.Context, tx *sql.Tx, in d.Input, ownership app.GateOwnership, registry string, raw []byte, ids []string) error {
	scope := g.Authority.ApplicationScope
	guard, e := g.Authority.Bind(ctx, tx, in.Authority)
	if e != nil {
		return e
	}
	if e = guard.Recheck(ctx, tx); e != nil {
		return e
	}
	if e = g.checkParticipantsTx(ctx, tx, ids); e != nil {
		return e
	}
	var acquire, hold time.Time
	if e = tx.QueryRowContext(ctx, "SELECT acquire_deadline,hold_deadline FROM system_backup_gate WHERE scope=? AND owner=? AND generation=? AND phase='acquiring' FOR SHARE", scope, ownership.Owner, ownership.Generation).Scan(&acquire, &hold); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_captures(task_public_id,application_scope,gate_generation,acquire_token,registry_sha256,writers_json,acquire_until,hold_until) VALUES(?,?,?,?,?,?,?,?)`, in.Authority.TaskPublicID, scope, ownership.Generation, ownership.Token, registry, raw, acquire, hold)
	if e != nil {
		return e
	}
	r, e := tx.ExecContext(ctx, `UPDATE system_backup_v2_maintenance_locks SET gate_state='acquiring',generation=?,fencing_token=?,lock_owner=?,heartbeat_at=UTC_TIMESTAMP(6),lease_expires_at=?,gate_acquisition_timeout_seconds=?,acquiring_started_at=UTC_TIMESTAMP(6),acquisition_deadline_at=?,absolute_hold_deadline_at=NULL,row_version=row_version+1 WHERE origin_installation_id=? AND scope=? AND gate_state='idle'`, ownership.Generation, ownership.Generation, in.Authority.TaskPublicID, hold, int(g.AcquisitionTimeout/time.Second), acquire, in.Authority.InstallationID, CaptureGateScope)
	if ok, z := exactlyOneRow(r); e != nil || z != nil || !ok {
		return ErrGateFenceLost
	}
	r, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_attempts SET status='running',started_at=UTC_TIMESTAMP(6),row_version=row_version+1 WHERE target_type='backup' AND target_public_id=? AND phase IN ('capture','secret_capture') AND status='preparing'", in.Authority.TaskPublicID)
	if e != nil {
		return e
	}
	r, e = tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status='capturing',maintenance_lock_owner=?,maintenance_fencing_token=?,row_version=row_version+1 WHERE public_id=? AND row_version=? AND controller_owner=? AND status='acquiring_gate'`, in.Authority.TaskPublicID, ownership.Generation, in.Authority.TaskPublicID, in.Authority.ClaimRowVersion, in.Authority.ClaimOwner)
	if ok, z := exactlyOneRow(r); e != nil || z != nil || !ok {
		return ErrClaimLost
	}
	return nil
}

func (g SQLCaptureGate) checkParticipants(ctx context.Context, ids []string) error {
	tx, e := g.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	return g.checkParticipantsTx(ctx, tx, ids)
}
func (g SQLCaptureGate) checkParticipantsTx(ctx context.Context, tx *sql.Tx, ids []string) error {
	rows, e := tx.QueryContext(ctx, "SELECT participant_id FROM system_backup_participants WHERE scope=? ORDER BY participant_id FOR SHARE", g.Authority.ApplicationScope)
	if e != nil {
		return e
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return e
		}
		found = append(found, id)
	}
	if rows.Err() != nil || len(found) != len(ids) {
		return ErrExecutionAuthority
	}
	for i := range ids {
		if ids[i] != found[i] {
			return ErrExecutionAuthority
		}
	}
	return nil
}

func (g SQLCaptureGate) Check(ctx context.Context, a d.Authority) error {
	return g.Authority.Check(ctx, a)
}

func (g SQLCaptureGate) BeforeResume(ctx context.Context, a d.Authority) error {
	return g.CollectorsStopped(ctx, a)
}
func (g SQLCaptureGate) CheckRecovery(ctx context.Context, a d.Authority, id string, s d.WriterState) error {
	if e := g.Recovery.Check(ctx, a); e != nil {
		return e
	}
	var raw []byte
	var hash string
	if e := g.Authority.DB.QueryRowContext(ctx, "SELECT original_json,original_sha256 FROM system_backup_v2_runtime_writers WHERE task_public_id=? AND writer_id=?", a.TaskPublicID, id).Scan(&raw, &hash); e != nil {
		return e
	}
	want, _ := json.Marshal(s)
	if !bytes.Equal(raw, want) || recordHash(raw) != hash {
		return ErrExecutionRecord
	}
	return nil
}
func (g SQLCaptureGate) PauseIntent(ctx context.Context, a d.Authority, id string, s d.WriterState) error {
	if !g.ready() || id == "" || len(id) > 128 || s.UID == "" || s.Generation <= 0 {
		return d.ErrNotReady
	}
	tx, e := g.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	guard, e := g.Authority.Bind(ctx, tx, a)
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(s)
	hash := recordHash(raw)
	var old []byte
	var digest string
	e = tx.QueryRowContext(ctx, "SELECT original_json,original_sha256 FROM system_backup_v2_runtime_writers WHERE task_public_id=? AND writer_id=? FOR UPDATE", a.TaskPublicID, id).Scan(&old, &digest)
	if e == nil {
		if !bytes.Equal(raw, old) || digest != hash {
			return ErrExecutionRecord
		}
	} else if errors.Is(e, sql.ErrNoRows) {
		// Membership and original identity are verified against the immutable plan.
		var frozen []byte
		var registry string
		if e = tx.QueryRowContext(ctx, "SELECT writers_json,registry_sha256 FROM system_backup_v2_runtime_captures WHERE task_public_id=? FOR SHARE", a.TaskPublicID).Scan(&frozen, &registry); e != nil || recordHash(frozen) != registry {
			return ErrExecutionRecord
		}
		var writers []b.FrozenWriter
		if json.Unmarshal(frozen, &writers) != nil {
			return ErrExecutionRecord
		}
		matched := false
		for _, w := range writers {
			if w.ID == id && (d.WriterState{UID: w.Original.UID, Generation: w.Original.Generation, Running: w.Original.Running, Checkpoint: w.Original.Checkpoint}) == s {
				matched = true
			}
		}
		if !matched {
			return ErrExecutionRecord
		}
		var n int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_participants WHERE scope=? AND participant_id=? AND generation=?", g.Authority.ApplicationScope, id, a.MaintenanceFencingToken).Scan(&n); e != nil || n != 1 {
			return ErrExecutionAuthority
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_runtime_writers(task_public_id,writer_id,original_json,original_sha256) VALUES(?,?,?,?)", a.TaskPublicID, id, raw, hash)
		if e != nil {
			return e
		}
	} else {
		return e
	}
	if e = guard.Recheck(ctx, tx); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return ErrExecutionCommitUnknown
	}
	return nil
}

func (g SQLCaptureGate) ownership(ctx context.Context, a d.Authority) (app.GateOwnership, error) {
	var o app.GateOwnership
	var token sql.NullInt64
	o.Owner = a.TaskPublicID
	o.Generation = a.MaintenanceFencingToken
	var acquire uint64
	e := g.Authority.DB.QueryRowContext(ctx, "SELECT application_scope,acquire_token,held_token FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND gate_generation=?", a.TaskPublicID, a.MaintenanceFencingToken).Scan(&o.Scope, &acquire, &token)
	if e != nil || o.Scope != g.Authority.ApplicationScope {
		return o, ErrExecutionAuthority
	}
	o.Token = acquire
	if token.Valid {
		o.Token = uint64(token.Int64)
	}
	// Reconcile a lost held-transition acknowledgement from the actual SAME
	// generation. This never grants forward IO or accepts a later generation.
	var actualOwner, phase string
	var generation, actual uint64
	if e = g.Authority.DB.QueryRowContext(ctx, "SELECT COALESCE(owner,''),phase,generation,fencing_token FROM system_backup_gate WHERE scope=?", o.Scope).Scan(&actualOwner, &phase, &generation, &actual); e != nil {
		return o, e
	}
	if generation != o.Generation || actualOwner != o.Owner || (phase != "acquiring" && phase != "held" && phase != "releasing") {
		return o, ErrExecutionRecoveryRequired
	}
	if actual != acquire && actual != acquire+1 {
		return o, ErrExecutionAuthority
	}
	if token.Valid && uint64(token.Int64) != actual {
		return o, ErrExecutionAuthority
	}
	o.Token = actual
	return o, nil
}

// FinalizeRecovery also accounts for writers which never received a durable
// pause intent. Since every stop is preceded by that intent, those participants
// were not changed by this execution. Existing intents still require Resume ACK.
func (g SQLCaptureGate) FinalizeRecovery(ctx context.Context, a d.Authority) error {
	if e := g.Recovery.Check(ctx, a); e != nil {
		return e
	}
	var alreadyStopped, alreadyResumed sql.NullTime
	if e := g.Authority.DB.QueryRowContext(ctx, "SELECT collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=?", a.TaskPublicID).Scan(&alreadyStopped, &alreadyResumed); e != nil {
		return e
	}
	if alreadyStopped.Valid && alreadyResumed.Valid {
		return nil
	}
	if e := g.CollectorsStopped(ctx, a); e != nil {
		return e
	}
	if e := g.Recovery.Check(ctx, a); e != nil {
		return e
	}
	o, e := g.ownership(ctx, a)
	if e != nil {
		return e
	}
	gate := app.Gate{DB: g.Authority.DB}
	if e = gate.BeginRelease(ctx, o); e != nil {
		return e
	}
	rows, e := g.Authority.DB.QueryContext(ctx, "SELECT p.participant_id FROM system_backup_participants p WHERE p.scope=? AND p.generation=? AND NOT EXISTS(SELECT 1 FROM system_backup_v2_runtime_writers w WHERE w.task_public_id=? AND w.writer_id=p.participant_id)", o.Scope, o.Generation, a.TaskPublicID)
	if e != nil {
		return e
	}
	var untouched []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		untouched = append(untouched, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range untouched {
		if e = gate.AckResumed(ctx, o, id, false); e != nil {
			return e
		}
	}
	var active int
	if g.Authority.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_writers WHERE task_public_id=? AND resumed=FALSE", a.TaskPublicID).Scan(&active) != nil || active != 0 {
		return ErrExecutionRecoveryRequired
	}
	return g.finishRelease(ctx, a, o)
}

func (g SQLCaptureGate) finishRelease(ctx context.Context, a d.Authority, o app.GateOwnership) error {
	tx, e := g.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var admission string
	if e = tx.QueryRowContext(ctx, "SELECT scope FROM system_backup_gate_admissions WHERE scope=? FOR UPDATE", o.Scope).Scan(&admission); e != nil {
		return e
	}
	if e = g.Recovery.CheckTx(ctx, tx, a); e != nil {
		return e
	}
	if e = (app.Gate{DB: g.Authority.DB}).FinishReleaseTx(ctx, tx, o); e != nil {
		return e
	}
	if e = g.projectReleaseTx(ctx, tx, a); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return ErrExecutionCommitUnknown
	}
	return nil
}

func (g SQLCaptureGate) projectReleaseTx(ctx context.Context, tx *sql.Tx, a d.Authority) error {
	if _, e := tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_captures SET source_resumed_at=COALESCE(source_resumed_at,UTC_TIMESTAMP(6)) WHERE task_public_id=? AND collectors_stopped_at IS NOT NULL", a.TaskPublicID); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, "UPDATE system_backup_v2_maintenance_locks SET gate_state='idle',lock_owner=NULL,heartbeat_at=NULL,lease_expires_at=NULL,gate_acquisition_timeout_seconds=NULL,quiesce_max_hold_seconds=NULL,acquiring_started_at=NULL,held_at=NULL,release_started_at=NULL,acquisition_deadline_at=NULL,absolute_hold_deadline_at=NULL,row_version=row_version+1 WHERE origin_installation_id=? AND scope=? AND lock_owner=? AND fencing_token=?", a.InstallationID, CaptureGateScope, a.TaskPublicID, a.MaintenanceFencingToken); e != nil {
		return e
	}
	return nil
}

func (g SQLCaptureGate) Paused(ctx context.Context, a d.Authority, id string, ack d.WriterACK) error {
	if !ack.Stopped {
		return ErrExecutionRecord
	}
	if e := g.Authority.Check(ctx, a); e != nil {
		return e
	}
	var raw []byte
	var hash string
	var s d.WriterState
	if e := g.Authority.DB.QueryRowContext(ctx, "SELECT original_json,original_sha256 FROM system_backup_v2_runtime_writers WHERE task_public_id=? AND writer_id=?", a.TaskPublicID, id).Scan(&raw, &hash); e != nil || json.Unmarshal(raw, &s) != nil || recordHash(raw) != hash || s.UID != ack.UID || s.Generation != ack.Generation {
		return ErrExecutionRecord
	}
	o, e := g.ownership(ctx, a)
	if e != nil {
		return e
	}
	gate := app.Gate{DB: g.Authority.DB}
	if e = gate.AckPaused(ctx, o, id, hash); e != nil {
		return e
	}
	if _, e = g.Authority.DB.ExecContext(ctx, "UPDATE system_backup_v2_runtime_writers SET paused=TRUE,row_version=row_version+1 WHERE task_public_id=? AND writer_id=? AND original_sha256=?", a.TaskPublicID, id, hash); e != nil {
		return e
	}
	var active int
	if e = g.Authority.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_participants WHERE scope=? AND (generation<>? OR state<>'paused')", o.Scope, o.Generation).Scan(&active); e != nil {
		return e
	}
	if active != 0 {
		return nil
	}
	// Public claim was checked above; the original business gate repeats the
	// claim check in its own held transition, after all physical ACKs exist.
	claim := app.VersionedGateClaim{InstallationID: a.InstallationID, TaskID: a.TaskPublicID, ControllerOwner: a.ClaimOwner, RowVersion: a.ClaimRowVersion}
	held, e := gate.HoldVersionedCapture(ctx, claim, o)
	if e != nil {
		return e
	}
	tx, e := g.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_captures SET held_token=? WHERE task_public_id=? AND gate_generation=? AND held_token IS NULL", held.Token, a.TaskPublicID, o.Generation); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_maintenance_locks SET gate_state='held',held_at=UTC_TIMESTAMP(6),quiesce_max_hold_seconds=?,absolute_hold_deadline_at=(SELECT hold_until FROM system_backup_v2_runtime_captures WHERE task_public_id=?),row_version=row_version+1 WHERE origin_installation_id=? AND scope=? AND lock_owner=? AND fencing_token=? AND gate_state='acquiring'", int(g.HoldTimeout/time.Second), a.TaskPublicID, a.InstallationID, CaptureGateScope, a.TaskPublicID, o.Generation); e != nil {
		return e
	}
	return tx.Commit()
}

// ValidateCollectors is the admission required immediately before source IO;
// generic Check while acquiring is deliberately insufficient.
func (g SQLCaptureGate) ValidateCollectors(ctx context.Context, a d.Authority) error {
	if e := g.Authority.Check(ctx, a); e != nil {
		return e
	}
	o, e := g.ownership(ctx, a)
	if e != nil {
		return e
	}
	return (app.Gate{DB: g.Authority.DB}).ValidateCapture(ctx, o)
}

// CollectorsStopped is called ONLY by the Job owner after revocation and actual
// process stop proof for the entire durable resource inventory. No public API
// maps directly to this function; absent Jobs or TTL expiry are not proof.
func (g SQLCaptureGate) CollectorsStopped(ctx context.Context, a d.Authority) error {
	tx, e := g.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = g.Recovery.CheckTx(ctx, tx, a); e != nil {
		return e
	}
	var unresolved int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND create_dispatched=TRUE AND stopped_at IS NULL", a.TaskPublicID).Scan(&unresolved); e != nil || unresolved != 0 {
		return ErrExecutionRecoveryRequired
	}
	_, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_captures SET collectors_stopped_at=COALESCE(collectors_stopped_at,UTC_TIMESTAMP(6)) WHERE task_public_id=? AND gate_generation=?", a.TaskPublicID, a.MaintenanceFencingToken)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func (g SQLCaptureGate) Resumed(ctx context.Context, a d.Authority, id string) error {
	if e := g.Recovery.Check(ctx, a); e != nil {
		return e
	}
	var stopped sql.NullTime
	if e := g.Authority.DB.QueryRowContext(ctx, "SELECT collectors_stopped_at FROM system_backup_v2_runtime_captures WHERE task_public_id=?", a.TaskPublicID).Scan(&stopped); e != nil || !stopped.Valid {
		return ErrExecutionRecoveryRequired
	}
	o, e := g.ownership(ctx, a)
	if e != nil {
		return e
	}
	gate := app.Gate{DB: g.Authority.DB}
	if e = gate.BeginRelease(ctx, o); e != nil {
		return e
	}
	if e = gate.AckResumed(ctx, o, id, false); e != nil {
		return e
	}
	if _, e = g.Authority.DB.ExecContext(ctx, "UPDATE system_backup_v2_runtime_writers SET resumed=TRUE,row_version=row_version+1 WHERE task_public_id=? AND writer_id=?", a.TaskPublicID, id); e != nil {
		return e
	}
	var active int
	if e = g.Authority.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_participants WHERE scope=? AND (state<>'running' OR resume_result NOT IN ('succeeded','forced'))", o.Scope).Scan(&active); e != nil {
		return e
	}
	if active != 0 {
		return nil
	}
	return g.finishRelease(ctx, a, o)
}

func (g SQLCaptureGate) EnsureJob(context.Context, d.Authority, d.JobIntent) (d.JobBinding, error) {
	return d.JobBinding{}, d.ErrNotReady
}
func (g SQLCaptureGate) ObserveJob(context.Context, d.Authority, d.JobBinding) (d.JobObservation, error) {
	return d.JobObservation{}, d.ErrNotReady
}
func (g SQLCaptureGate) StopJob(context.Context, d.Authority, d.JobBinding) error {
	return d.ErrNotReady
}

var _ d.Ports = SQLCaptureGate{}
