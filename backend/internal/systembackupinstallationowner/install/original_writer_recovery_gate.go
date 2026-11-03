package install

import (
	"context"
	"database/sql"
	"reflect"
	"time"

	"clawreef/internal/systembackup/domain"
	c "clawreef/internal/systembackupcontroller"
)

// Original recovery changes both actual gates in one SQL transaction. It never
// renews their original acquisition/hold deadlines. Expired original capture
// authority remains unusable; A's separate fresh fence authorizes recovery.
func (s *PreparedOriginalWriterSet) lockOriginalRecovery(ctx context.Context, tx *sql.Tx, fence *originalWriterRecoveryFence) error {
	if tx == nil || fence == nil || fence.owner != s.owner || fence.operator == nil || !fence.operator.live(ctx) {
		return ErrInstall
	}
	// Same ordering as original admission closure: admission, application gate,
	// V2 capture gate, then the actual administrator/head rows.
	var admission sql.NullString
	if tx.QueryRowContext(ctx, `SELECT owner FROM system_backup_gate_admissions WHERE scope=? FOR UPDATE`, s.application.scope).Scan(&admission) != nil || !admission.Valid || admission.String != s.application.owner {
		return ErrInstall
	}
	var phase, owner, inventory string
	var generation, token uint64
	if tx.QueryRowContext(ctx, `SELECT phase,COALESCE(owner,''),generation,fencing_token,registry_hash FROM system_backup_gate WHERE scope=? FOR UPDATE`, s.application.scope).Scan(&phase, &owner, &generation, &token, &inventory) != nil || phase != s.application.phase || owner != s.application.owner || generation != s.application.generation || token != s.application.token || inventory != s.inventorySHA {
		return ErrInstall
	}
	actual, err := (c.SQLCoordinationTransaction{Tx: tx}).LockGate(ctx, s.owner.token.Key)
	if err != nil || actual != s.owner.token.GateSnapshot {
		return ErrInstall
	}
	return fence.lockAuthority(ctx, tx)
}

func originalExactlyOne(result sql.Result, err error) error {
	if err != nil || result == nil {
		return ErrInstall
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrInstall
	}
	return nil
}

func (s *PreparedOriginalWriterSet) beginOriginalRecovery(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if fence.check(ctx) != nil || s.application.scope == "" || s.application.unknown || s.owner.commitUnknown || s.actualHold != nil && s.actualHold.adoptionUnknown {
		return ErrCommitUnknown
	}
	if s.owner.token.State == c.GateReleasing && s.application.phase == "releasing" {
		return nil
	}
	if s.owner.token.State != c.GateAcquiring && s.owner.token.State != c.GateHeld || s.application.phase != "acquiring" && s.application.phase != "held" {
		return ErrInstall
	}
	tx, err := fence.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	if s.lockOriginalRecovery(ctx, tx, fence) != nil {
		return ErrInstall
	}
	var outstanding uint64
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_mutation_leases WHERE scope=? AND released_at IS NULL`, s.application.scope).Scan(&outstanding) != nil || outstanding != 0 {
		return ErrInstall
	}
	count, err := (c.SQLCoordinationTransaction{Tx: tx}).CountOutstandingMutationLeases(ctx, s.owner.token.Key, s.owner.token.Generation)
	if err != nil || count != 0 {
		return ErrInstall
	}
	expected := s.owner.token
	expected.State = c.GateReleasing
	expected.RowVersion++
	if s.journal.append(ctx, "", "original_release_begin_commit_unknown", nil, struct {
		Gate        c.GateToken
		Application originalApplicationGateRecord
	}{expected, originalApplicationGateRecord{Scope: s.application.scope, Owner: s.application.owner, Phase: "releasing", Generation: s.application.generation, Token: s.application.token, Participants: s.application.participants}}) != nil {
		return ErrInstall
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_maintenance_locks SET gate_state='releasing',release_started_at=UTC_TIMESTAMP(6),state_changed_at=UTC_TIMESTAMP(6),row_version=row_version+1 WHERE origin_installation_id=? AND scope=? AND gate_state=? AND generation=? AND fencing_token=? AND lock_owner=? AND row_version=?`, s.owner.token.Key.InstallationID, s.owner.token.Key.Scope, s.owner.token.State, s.owner.token.Generation, s.owner.token.FencingToken, s.owner.token.Owner, s.owner.token.RowVersion)
	if originalExactlyOne(result, err) != nil {
		return ErrInstall
	}
	result, err = tx.ExecContext(ctx, `UPDATE system_backup_gate SET phase='releasing',updated_at=UTC_TIMESTAMP(6) WHERE scope=? AND phase=? AND owner=? AND generation=? AND fencing_token=? AND registry_hash=?`, s.application.scope, s.application.phase, s.application.owner, s.application.generation, s.application.token, s.inventorySHA)
	if originalExactlyOne(result, err) != nil {
		return ErrInstall
	}
	result, err = tx.ExecContext(ctx, `UPDATE system_backup_participants SET state='resuming',resume_result='none',updated_at=UTC_TIMESTAMP(6) WHERE scope=? AND generation=?`, s.application.scope, s.application.generation)
	if err != nil {
		return ErrInstall
	}
	// Regardless of COMMIT's transport result, settle this exact expected
	// transition with an independent locking read before touching any source.
	_ = tx.Commit()
	return s.readOriginalRecoveryBegin(ctx, fence, expected)

}

func (s *PreparedOriginalWriterSet) finishOriginalRecovery(ctx context.Context, fence *originalWriterRecoveryFence, proof *originalRecoveredReadiness) error {
	if proof == nil || proof.set != s || proof.digest == "" || fence.check(ctx) != nil {
		return ErrInstall
	}
	tx, err := fence.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	if s.lockOriginalRecovery(ctx, tx, fence) != nil || s.owner.token.State != c.GateReleasing || s.application.phase != "releasing" {
		return ErrInstall
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil {
		return ErrInstall
	}
	actual, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil || !reflect.DeepEqual(actual, proof.expected) {
		return ErrInstall
	}
	if proof.admissionAbort != nil {
		if proof.admissionAbort.recheckLocal(s, proof) != nil {
			return ErrInstall
		}
	} else {
		for _, node := range s.nodes {
			native := proof.nodes[node]
			if native == nil {
				return ErrOriginalRecoveryNativeProof
			}
			if proof.nodeAction == "recovery-reconciled" {
				request, ok := proof.requests[node]
				facts := proof.facts[node]
				// Local opaque checks only: no API, native RPC or filesystem I/O in
				// this final SQL prefix. The private journal mutation barrier remains
				// closed and the entire set is held under the same mutex.
				if !ok || facts == nil || facts.recheckLocal(proof.boundary, request) != nil || native.RecheckOriginalRecoveryScope(ctx, request, nil, node.boot, now) != nil {
					return ErrOriginalRecoveryNativeProof
				}
			} else if native.Recheck(ctx, node.request.Binding, proof.nodeAction, node.boot, now) != nil {
				return ErrOriginalRecoveryNativeProof
			}
		}
		for _, gateway := range s.gateways {
			if !gateway.stopDispatched {
				continue
			}
			phase := "recovered"
			if !gateway.state.Running {
				phase = "recovered-stopped"
			}
			if gateway.proof == nil || gateway.proof.Recheck(ctx, gateway.request.Binding, phase, gateway.boot, originalObjectSHA(gateway.state), hash(gateway.raw), hash(gateway.completion), now) != nil {
				return ErrOriginalRecoveryNativeProof
			}
		}
		for _, source := range s.stopped {
			if source.proof == nil || source.proof.Recheck(ctx, source.request.Binding, "recovered-stopped", source.boot, source.state.Checkpoint, source.request.OriginalReservationIdentitySHA256, originalObjectSHA(source.state), source.claim.NativeRequestSHA256, now) != nil {
				return ErrOriginalRecoveryNativeProof
			}
		}
	}
	var outstanding uint64
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_mutation_leases WHERE scope=? AND released_at IS NULL`, s.application.scope).Scan(&outstanding) != nil || outstanding != 0 {
		return ErrInstall
	}
	count, err := (c.SQLCoordinationTransaction{Tx: tx}).CountOutstandingMutationLeases(ctx, s.owner.token.Key, s.owner.token.Generation)
	if err != nil || count != 0 {
		return ErrInstall
	}
	// Exact actual enrolled set; its paused/resuming state is replaced only now,
	// after all concrete actors and native receipts have actually been checked.
	rows, err := tx.QueryContext(ctx, `SELECT participant_id,generation,state FROM system_backup_participants WHERE scope=? ORDER BY participant_id FOR UPDATE`, s.application.scope)
	if err != nil {
		return ErrInstall
	}
	participants := map[string]bool{}
	for rows.Next() {
		var id, state string
		var generation uint64
		if rows.Scan(&id, &generation, &state) != nil || generation != s.application.generation || state != "resuming" {
			rows.Close()
			return ErrInstall
		}
		participants[id] = true
	}
	if rows.Err() != nil || rows.Close() != nil || len(participants) != len(s.application.participants) {
		return ErrInstall
	}
	for _, participant := range s.application.participants {
		if !participants[participant.ID] {
			return ErrInstall
		}
	}
	if s.journal.append(ctx, "", "original_sources_release_commit_unknown", nil, struct {
		Gate        c.GateToken
		ProofSHA256 string
		Expected    []domain.SourceInstance
	}{s.owner.token, proof.digest, proof.expected}) != nil {
		return ErrInstall
	}
	if _, err = tx.ExecContext(ctx, `UPDATE system_backup_participants SET state='running',resume_result='succeeded',updated_at=UTC_TIMESTAMP(6) WHERE scope=? AND generation=? AND state='resuming'`, s.application.scope, s.application.generation); err != nil {
		return ErrInstall
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_gate SET phase='idle',owner=NULL,acquire_deadline=NULL,hold_deadline=NULL,updated_at=UTC_TIMESTAMP(6) WHERE scope=? AND phase='releasing' AND owner=? AND generation=? AND fencing_token=? AND registry_hash=?`, s.application.scope, s.application.owner, s.application.generation, s.application.token, s.inventorySHA)
	if originalExactlyOne(result, err) != nil {
		return ErrInstall
	}
	result, err = tx.ExecContext(ctx, `UPDATE system_backup_gate_admissions SET owner=NULL,close_until=NULL,updated_at=UTC_TIMESTAMP(6) WHERE scope=? AND owner=?`, s.application.scope, s.application.owner)
	if originalExactlyOne(result, err) != nil {
		return ErrInstall
	}
	result, err = tx.ExecContext(ctx, `UPDATE system_backup_v2_maintenance_locks SET gate_state='idle',lock_owner=NULL,heartbeat_at=NULL,lease_expires_at=NULL,gate_acquisition_timeout_seconds=NULL,quiesce_max_hold_seconds=NULL,acquiring_started_at=NULL,held_at=NULL,release_started_at=NULL,acquisition_deadline_at=NULL,absolute_hold_deadline_at=NULL,state_changed_at=UTC_TIMESTAMP(6),row_version=row_version+1 WHERE origin_installation_id=? AND scope=? AND gate_state='releasing' AND generation=? AND fencing_token=? AND lock_owner=? AND row_version=?`, s.owner.token.Key.InstallationID, s.owner.token.Key.Scope, s.owner.token.Generation, s.owner.token.FencingToken, s.owner.token.Owner, s.owner.token.RowVersion)
	if originalExactlyOne(result, err) != nil {
		return ErrInstall
	}
	// A transport error is unknown, not rollback. Read the exact expected
	// terminal rows independently even when COMMIT did not return success.
	_ = tx.Commit()
	// A successful commit alone is not a readback. Inspect the exact original
	// gate generation and current source projection in a new transaction.
	return s.readOriginalRecoveryReleased(ctx, fence, proof)
}

func (s *PreparedOriginalWriterSet) readOriginalRecoveryReleased(ctx context.Context, fence *originalWriterRecoveryFence, proof *originalRecoveredReadiness) error {
	tx, err := fence.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrCommitUnknown
	}
	defer tx.Rollback()
	// Lock in the same order as the write path; locking reads also settle
	// a previous unknown commit before the consistent source snapshot starts.
	var admission sql.NullString
	if tx.QueryRowContext(ctx, `SELECT owner FROM system_backup_gate_admissions WHERE scope=? FOR UPDATE`, s.application.scope).Scan(&admission) != nil || admission.Valid {
		return ErrCommitUnknown
	}
	var phase string
	var owner sql.NullString
	var generation, token uint64
	if tx.QueryRowContext(ctx, `SELECT phase,owner,generation,fencing_token FROM system_backup_gate WHERE scope=? FOR UPDATE`, s.application.scope).Scan(&phase, &owner, &generation, &token) != nil || phase != "idle" || owner.Valid || generation != s.application.generation || token != s.application.token {
		return ErrCommitUnknown
	}
	actual, err := (c.SQLCoordinationTransaction{Tx: tx}).LockGate(ctx, s.owner.token.Key)
	want := s.owner.token.GateSnapshot
	want.State = c.GateIdle
	want.Owner = ""
	want.RowVersion++
	if err != nil || actual != want || fence.lockAuthority(ctx, tx) != nil {
		return ErrCommitUnknown
	}
	sources, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil || !reflect.DeepEqual(sources, proof.expected) || tx.Rollback() != nil {
		return ErrCommitUnknown
	}
	s.owner.token.GateSnapshot = want
	s.application.phase = "idle"
	if s.actualHold != nil {
		s.actualHold.closed = true
	}
	if s.journal.append(ctx, "", "original_sources_released_readback", nil, struct {
		Gate        c.GateSnapshot
		ProofSHA256 string
	}{want, proof.digest}) != nil {
		return ErrCommitUnknown
	}
	return nil
}

func (s *PreparedOriginalWriterSet) readOriginalRecoveryBegin(ctx context.Context, fence *originalWriterRecoveryFence, expected c.GateToken) error {
	tx, err := fence.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrCommitUnknown
	}
	defer tx.Rollback()
	var admission sql.NullString
	if tx.QueryRowContext(ctx, `SELECT owner FROM system_backup_gate_admissions WHERE scope=? FOR UPDATE`, s.application.scope).Scan(&admission) != nil || !admission.Valid || admission.String != s.application.owner {
		return ErrCommitUnknown
	}
	var phase, owner, inventory string
	var generation, token uint64
	if tx.QueryRowContext(ctx, `SELECT phase,COALESCE(owner,''),generation,fencing_token,registry_hash FROM system_backup_gate WHERE scope=? FOR UPDATE`, s.application.scope).Scan(&phase, &owner, &generation, &token, &inventory) != nil || phase != "releasing" || owner != s.application.owner || generation != s.application.generation || token != s.application.token || inventory != s.inventorySHA {
		return ErrCommitUnknown
	}
	actual, err := (c.SQLCoordinationTransaction{Tx: tx}).LockGate(ctx, expected.Key)
	if err != nil || actual != expected.GateSnapshot || fence.lockAuthority(ctx, tx) != nil || tx.Rollback() != nil {
		return ErrCommitUnknown
	}
	s.owner.token = expected
	s.application.phase = "releasing"
	if fence.check(ctx) != nil {
		return ErrCommitUnknown
	}
	return s.journal.append(ctx, "", "original_release_begin_readback", nil, expected)
}
