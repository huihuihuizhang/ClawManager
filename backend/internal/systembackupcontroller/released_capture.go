package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

// releasedCaptureProofTx verifies the historical gap between physical release
// and its public projection. Idle alone never proves recovery. All observations
// are bound to the original epoch and frozen writer identities.
func releasedCaptureProofTx(ctx context.Context, tx *sql.Tx, a d.Authority, scope string) error {
	var raw []byte
	var digest string
	var epoch, acquire, actual uint64
	var held sql.NullInt64
	var stopped sql.NullTime
	if tx.QueryRowContext(ctx, `SELECT gate_generation,acquire_token,held_token,registry_sha256,writers_json,collectors_stopped_at FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND application_scope=? FOR SHARE`, a.TaskPublicID, scope).Scan(&epoch, &acquire, &held, &digest, &raw, &stopped) != nil || epoch != a.MaintenanceFencingToken || !stopped.Valid || recordHash(raw) != digest {
		return ErrExecutionRecoveryRequired
	}
	var owner, phase string
	var generation uint64
	if tx.QueryRowContext(ctx, "SELECT COALESCE(owner,''),phase,generation,fencing_token FROM system_backup_gate WHERE scope=? FOR SHARE", scope).Scan(&owner, &phase, &generation, &actual) != nil || owner != "" || phase != "idle" || generation != epoch || (actual != acquire && actual != acquire+1) || (held.Valid && uint64(held.Int64) != actual) {
		return ErrExecutionRecoveryRequired
	}
	var closed, unresolved int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_gate_admissions WHERE scope=? AND owner IS NULL AND close_until IS NULL", scope).Scan(&closed) != nil || closed != 1 {
		return ErrExecutionRecoveryRequired
	}
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND create_dispatched=TRUE AND (stopped_at IS NULL OR revoked=FALSE)", a.TaskPublicID).Scan(&unresolved) != nil || unresolved != 0 {
		return ErrExecutionRecoveryRequired
	}
	var frozen []b.FrozenWriter
	if json.Unmarshal(raw, &frozen) != nil || len(frozen) == 0 {
		return ErrExecutionRecord
	}
	expected := map[string]d.WriterState{}
	for _, w := range frozen {
		if _, exists := expected[w.ID]; exists || w.ID == "" {
			return ErrExecutionRecord
		}
		expected[w.ID] = d.WriterState{UID: w.Original.UID, Generation: w.Original.Generation, Running: w.Original.Running, Checkpoint: w.Original.Checkpoint}
	}
	rows, e := tx.QueryContext(ctx, "SELECT participant_id,generation,state,resume_result,checkpoint_hash FROM system_backup_participants WHERE scope=? ORDER BY participant_id FOR SHARE", scope)
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	requiredReceipts := map[string]bool{}
	for rows.Next() {
		var id, state, result string
		var gen uint64
		var checkpoint sql.NullString
		if rows.Scan(&id, &gen, &state, &result, &checkpoint) != nil {
			rows.Close()
			return ErrExecutionRecord
		}
		if _, ok := expected[id]; !ok || seen[id] || gen != epoch || state != "running" || result != "succeeded" {
			rows.Close()
			return ErrExecutionRecoveryRequired
		}
		if checkpoint.Valid {
			original, _ := json.Marshal(expected[id])
			if checkpoint.String != recordHash(original) {
				rows.Close()
				return ErrExecutionRecoveryRequired
			}
			requiredReceipts[id] = true
		}
		seen[id] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(seen) != len(expected) {
		return ErrExecutionRecoveryRequired
	}
	rows, e = tx.QueryContext(ctx, "SELECT writer_id,original_json,original_sha256,resumed FROM system_backup_v2_runtime_writers WHERE task_public_id=? FOR SHARE", a.TaskPublicID)
	if e != nil {
		return e
	}
	defer rows.Close()
	writerReceipts := map[string]bool{}
	for rows.Next() {
		var id, h string
		var original []byte
		var resumed bool
		if rows.Scan(&id, &original, &h, &resumed) != nil {
			return ErrExecutionRecord
		}
		want, ok := expected[id]
		canonical, _ := json.Marshal(want)
		if !ok || writerReceipts[id] || !resumed || recordHash(original) != h || !bytes.Equal(original, canonical) {
			return ErrExecutionRecoveryRequired
		}
		writerReceipts[id] = true
	}
	if e = rows.Err(); e != nil {
		return e
	}
	// A writer which never received a pause intent can remain untouched. A
	// recorded pause checkpoint, however, cannot lose its whole resume receipt.
	for id := range requiredReceipts {
		if !writerReceipts[id] {
			return ErrExecutionRecoveryRequired
		}
	}
	return nil
}

// ReconcileReleasedCapture never resumes a runtime or re-reads source data. It
// completes only a projection whose physical release is independently proven.
func (g SQLCaptureGate) ReconcileReleasedCapture(ctx context.Context, a d.Authority) (bool, error) {
	tx, e := g.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	var phase string
	if e = tx.QueryRowContext(ctx, "SELECT phase FROM system_backup_gate WHERE scope=?", g.Authority.ApplicationScope).Scan(&phase); e != nil {
		return false, e
	}
	if phase != "idle" {
		return false, nil
	}
	if e = g.Recovery.CheckTx(ctx, tx, a); e != nil {
		return false, e
	}
	if e = releasedCaptureProofTx(ctx, tx, a, g.Authority.ApplicationScope); e != nil {
		return false, e
	}
	if e = g.projectReleaseTx(ctx, tx, a); e != nil {
		return false, e
	}
	if e = tx.Commit(); e != nil {
		return false, ErrExecutionCommitUnknown
	}
	return true, nil
}
