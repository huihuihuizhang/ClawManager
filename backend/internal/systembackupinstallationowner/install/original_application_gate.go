package install

import (
	"context"
	"database/sql"
	"reflect"
	"sort"
	"time"

	legacy "clawreef/internal/systembackup"
	c "clawreef/internal/systembackupcontroller"
)

type OriginalMaintenanceParticipant struct{ ID, WriterID string }
type originalApplicationGate struct {
	scope, owner      string
	generation, token uint64
	phase             string
	participants      []OriginalMaintenanceParticipant
	unknown           bool
}

type originalApplicationGateRecord struct {
	Scope, Owner, Phase string
	Generation, Token   uint64
	Participants        []OriginalMaintenanceParticipant
	Unknown             bool
}

func (g originalApplicationGate) record() originalApplicationGateRecord {
	return originalApplicationGateRecord{g.scope, g.owner, g.phase, g.generation, g.token, append([]OriginalMaintenanceParticipant(nil), g.participants...), g.unknown}
}

// Actual application admission, separate from the V2 capture gate. No task
// or final grant is synthesized. Original operator authentication authorizes
// this original operation; SQL owner/generation/readback and physical source
// proofs authorize its transitions. Expired leases are never treated as gone.
func (s *PreparedOriginalWriterSet) beginApplicationGate(ctx context.Context) error {
	p := s.owner
	scope := s.selection.ApplicationScope
	if p.checkCurrentGate(ctx, c.GateAcquiring) != nil || scope == "" || len(scope) > 128 || s.application.scope != "" {
		return ErrInstall
	}
	if (legacy.Gate{DB: p.operator.installer.db}).EnsureScope(ctx, scope) != nil {
		return ErrInstall
	}
	if s.journal.append(ctx, "application/"+scope, "admission_close_send_unknown", nil, s.selection.Participants) != nil {
		return ErrInstall
	}
	tx, err := p.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	var prior sql.NullString
	var deadline sql.NullTime
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT owner,close_until,UTC_TIMESTAMP(6) FROM system_backup_gate_admissions WHERE scope=? FOR UPDATE NOWAIT`, scope).Scan(&prior, &deadline, &now) != nil || prior.Valid {
		return ErrInstall
	}
	var phase string
	var generation, token uint64
	if tx.QueryRowContext(ctx, `SELECT phase,generation,fencing_token FROM system_backup_gate WHERE scope=? FOR UPDATE NOWAIT`, scope).Scan(&phase, &generation, &token) != nil || phase != "idle" || generation == ^uint64(0) {
		return ErrInstall
	}
	locked, err := (c.SQLCoordinationTransaction{Tx: tx}).LockGate(ctx, p.token.Key)
	if err != nil || locked != p.token.GateSnapshot {
		return ErrInstall
	}
	if _, err = p.operator.lockAdmin(ctx, tx); err != nil {
		return ErrInstall
	}
	head, err := p.operator.current(ctx, tx, false)
	if err != nil || head.cas != p.initial || !now.Before(p.until) {
		return ErrInstall
	}
	rows, err := tx.QueryContext(ctx, `SELECT participant_id,state,resume_result FROM system_backup_participants WHERE scope=? ORDER BY participant_id FOR UPDATE`, scope)
	if err != nil {
		return ErrInstall
	}
	var actual []string
	for rows.Next() {
		var id string
		var state, result string
		if rows.Scan(&id, &state, &result) != nil || state != "running" || result != "none" && result != "succeeded" && result != "forced" {
			rows.Close()
			return ErrInstall
		}
		actual = append(actual, id)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return ErrInstall
	}
	known := map[string]bool{}
	for _, w := range s.deployments {
		known[w.ID()] = true
	}
	for _, w := range s.proPods {
		known[w.ID()] = true
	}
	for _, g := range s.gateways {
		known[g.ID()] = true
	}
	for _, o := range s.stoppedObservations {
		known[o.baseline.SourceKey] = true
	}
	wanted := []string{}
	seen := map[string]bool{}
	for _, participant := range s.selection.Participants {
		if participant.ID == "" || seen[participant.ID] || !known[participant.WriterID] {
			return ErrInstall
		}
		seen[participant.ID] = true
		wanted = append(wanted, participant.ID)
	}
	sort.Strings(wanted)
	if actual == nil {
		actual = []string{}
	}
	if !reflect.DeepEqual(actual, wanted) {
		return ErrInstall
	}
	owner := "adoption:" + p.operation
	if _, err = tx.ExecContext(ctx, `UPDATE system_backup_gate_admissions SET owner=?,close_until=?,updated_at=UTC_TIMESTAMP(6) WHERE scope=?`, owner, p.until, scope); err != nil {
		return ErrInstall
	}
	if _, err = tx.ExecContext(ctx, `UPDATE system_backup_gate SET phase='acquiring',generation=generation+1,owner=?,registry_hash=?,acquire_deadline=LEAST(TIMESTAMPADD(MICROSECOND,?,UTC_TIMESTAMP(6)),?),hold_deadline=?,updated_at=UTC_TIMESTAMP(6) WHERE scope=?`, owner, s.inventorySHA, p.policy.AcquisitionTimeout.Microseconds(), p.until, p.until, scope); err != nil {
		return ErrInstall
	}
	if _, err = tx.ExecContext(ctx, `UPDATE system_backup_participants SET generation=?,state='pausing',resume_result='none',checkpoint_hash=NULL,updated_at=UTC_TIMESTAMP(6) WHERE scope=?`, generation+1, scope); err != nil {
		return ErrInstall
	}
	s.application = originalApplicationGate{scope: scope, owner: owner, generation: generation + 1, token: token, phase: "acquiring", participants: append([]OriginalMaintenanceParticipant(nil), s.selection.Participants...), unknown: true}
	if s.journal.append(ctx, "application/"+scope, "application_acquire_commit_unknown", nil, s.application.record()) != nil {
		return ErrInstall
	}
	if tx.Commit() != nil {
		return ErrCommitUnknown
	}
	s.application.unknown = false
	if s.checkApplicationGate(ctx, "acquiring") != nil {
		return ErrCommitUnknown
	}
	return s.journal.append(ctx, "application/"+scope, "admission_closed_readback", nil, s.application.record())
}

func (s *PreparedOriginalWriterSet) checkApplicationGate(ctx context.Context, phases ...string) error {
	g := s.application
	if g.scope == "" || s.owner.check(ctx) != nil {
		return ErrInstall
	}
	allowed := false
	for _, phase := range phases {
		if phase == g.phase {
			allowed = true
		}
	}
	if !allowed {
		return ErrInstall
	}
	tx, err := s.owner.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	var phase, owner, inventory string
	var generation, token uint64
	var live bool
	if tx.QueryRowContext(ctx, `SELECT phase,COALESCE(owner,''),generation,fencing_token,registry_hash,hold_deadline>UTC_TIMESTAMP(6) FROM system_backup_gate WHERE scope=? FOR SHARE`, g.scope).Scan(&phase, &owner, &generation, &token, &inventory, &live) != nil || !live || phase != g.phase || owner != g.owner || generation != g.generation || token != g.token || inventory != s.inventorySHA {
		return ErrInstall
	}
	var admission bool
	if tx.QueryRowContext(ctx, `SELECT owner=? AND close_until>UTC_TIMESTAMP(6) FROM system_backup_gate_admissions WHERE scope=? FOR SHARE`, g.owner, g.scope).Scan(&admission) != nil || !admission || tx.Rollback() != nil {
		return ErrInstall
	}
	return nil
}

// Call only after actual complete native I/O. The private verifier performs
// local opaque observation checks and same-transaction SQL, never network I/O.
func (s *PreparedOriginalWriterSet) holdApplicationGate(ctx context.Context, proof *originalHeldReadiness) error {
	if proof == nil || proof.set != s || s.checkApplicationGate(ctx, "acquiring") != nil {
		return ErrInstall
	}
	tx, err := s.owner.operator.installer.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	var generation, token uint64
	var phase, owner string
	if tx.QueryRowContext(ctx, `SELECT phase,owner,generation,fencing_token FROM system_backup_gate WHERE scope=? FOR UPDATE`, s.application.scope).Scan(&phase, &owner, &generation, &token) != nil || phase != "acquiring" || owner != s.application.owner || generation != s.application.generation || token != s.application.token {
		return ErrInstall
	}
	coord := c.SQLCoordinationTransaction{Tx: tx}
	if proof.VerifyParticipantsPaused(ctx, coord, s.owner.token.Key, s.owner.token.Generation) != nil {
		return ErrInstall
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_mutation_leases WHERE scope=? AND released_at IS NULL`, s.application.scope).Scan(&count) != nil || count != 0 {
		return ErrInstall
	}
	if _, err = tx.ExecContext(ctx, `UPDATE system_backup_participants SET state='paused',checkpoint_hash=?,updated_at=UTC_TIMESTAMP(6) WHERE scope=? AND generation=? AND state='pausing'`, proof.digest, s.application.scope, generation); err != nil {
		return ErrInstall
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_gate SET phase='held',fencing_token=fencing_token+1,updated_at=UTC_TIMESTAMP(6) WHERE scope=? AND phase='acquiring' AND owner=? AND generation=? AND fencing_token=? AND acquire_deadline>UTC_TIMESTAMP(6) AND hold_deadline>UTC_TIMESTAMP(6)`, s.application.scope, owner, generation, token)
	if err != nil {
		return ErrInstall
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrInstall
	}
	if s.journal.append(ctx, "application/"+s.application.scope, "application_hold_commit_unknown", nil, proof.digest) != nil {
		return ErrInstall
	}
	s.application.unknown = true
	if tx.Commit() != nil {
		return ErrCommitUnknown
	}
	s.application.token++
	s.application.phase = "held"
	s.application.unknown = false
	if s.checkApplicationGate(ctx, "held") != nil {
		return ErrCommitUnknown
	}
	return nil
}
