package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

type recoveryParticipant struct {
	ID, State, Result string
	Generation        uint64
	Checkpoint        sql.NullString
}
type recoveryWriterReceipt struct {
	ID, Digest string
	Original   []byte
	Resumed    bool
}

func stampPauseWitnessTx(ctx context.Context, tx *sql.Tx, scope string, epoch uint64, id, digest string) error {
	var generation uint64
	var phase string
	var checkpoint sql.NullString
	if e := tx.QueryRowContext(ctx, "SELECT generation,state,checkpoint_hash FROM system_backup_participants WHERE scope=? AND participant_id=? FOR UPDATE", scope, id).Scan(&generation, &phase, &checkpoint); e != nil {
		return e
	}
	if generation != epoch || (phase != "pausing" && phase != "paused") || (checkpoint.Valid && checkpoint.String != digest) {
		return ErrExecutionRecoveryRequired
	}
	if checkpoint.Valid {
		return nil
	}
	result, e := tx.ExecContext(ctx, "UPDATE system_backup_participants SET checkpoint_hash=?,updated_at=UTC_TIMESTAMP(6) WHERE scope=? AND participant_id=? AND generation=? AND checkpoint_hash IS NULL", digest, scope, id, epoch)
	if e != nil {
		return e
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrExecutionRecord
	}
	return nil
}

// A missing intent is untouched only when the independent physical participant
// also has no pause checkpoint. A lost row is never evidence of an absent stop.
func validateRecoveryInventory(epoch uint64, frozen []b.FrozenWriter, participants []recoveryParticipant, receipts []recoveryWriterReceipt, final bool) ([]string, error) {
	if epoch == 0 || len(frozen) == 0 || len(frozen) > 10000 || len(participants) != len(frozen) {
		return nil, ErrExecutionRecoveryRequired
	}
	expected := map[string][]byte{}
	for _, w := range frozen {
		if w.ID == "" || expected[w.ID] != nil || w.Original.UID == "" || w.Original.Generation <= 0 {
			return nil, ErrExecutionRecord
		}
		expected[w.ID], _ = json.Marshal(d.WriterState{UID: w.Original.UID, Generation: w.Original.Generation, Running: w.Original.Running, Checkpoint: w.Original.Checkpoint})
	}
	known := map[string]recoveryWriterReceipt{}
	for _, r := range receipts {
		if _, duplicate := known[r.ID]; duplicate || expected[r.ID] == nil || !bytes.Equal(expected[r.ID], r.Original) || recordHash(r.Original) != r.Digest || (final && !r.Resumed) {
			return nil, ErrExecutionRecoveryRequired
		}
		known[r.ID] = r
	}
	seen := map[string]bool{}
	untouched := []string{}
	for _, p := range participants {
		if expected[p.ID] == nil || seen[p.ID] || p.Generation != epoch {
			return nil, ErrExecutionRecoveryRequired
		}
		seen[p.ID] = true
		receipt, exists := known[p.ID]
		if p.Checkpoint.Valid && (p.Checkpoint.String != recordHash(expected[p.ID]) || !exists) {
			return nil, ErrExecutionRecoveryRequired
		}
		if !exists {
			if p.Checkpoint.Valid || (p.State != "pausing" && !(p.State == "running" && p.Result == "succeeded")) {
				return nil, ErrExecutionRecoveryRequired
			}
			untouched = append(untouched, p.ID)
		} else if receipt.Resumed && (p.State != "running" || p.Result != "succeeded") {
			return nil, ErrExecutionRecoveryRequired
		}
		if final && (p.State != "running" || p.Result != "succeeded") {
			return nil, ErrExecutionRecoveryRequired
		}
	}
	return untouched, nil
}

// Called only inside the current recovery-authorized transaction. The frozen
// set and both independent receipt sets are locked until the release decision.
func recoveryInventoryTx(ctx context.Context, tx *sql.Tx, a d.Authority, scope string, final bool) ([]string, error) {
	return reconcileRecoveryInventoryTx(ctx, tx, a, scope, final, false)
}

func reconcileRecoveryInventoryTx(ctx context.Context, tx *sql.Tx, a d.Authority, scope string, final, repair bool) ([]string, error) {
	var raw []byte
	var digest string
	var epoch uint64
	if e := tx.QueryRowContext(ctx, "SELECT gate_generation,registry_sha256,writers_json FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND application_scope=? FOR SHARE", a.TaskPublicID, scope).Scan(&epoch, &digest, &raw); e != nil {
		return nil, e
	}
	if epoch != a.MaintenanceFencingToken || recordHash(raw) != digest {
		return nil, ErrExecutionRecoveryRequired
	}
	var frozen []b.FrozenWriter
	if json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrExecutionRecord
	}
	rows, e := tx.QueryContext(ctx, "SELECT participant_id,generation,state,resume_result,checkpoint_hash FROM system_backup_participants WHERE scope=? ORDER BY participant_id FOR SHARE", scope)
	if e != nil {
		return nil, e
	}
	participants := []recoveryParticipant{}
	for rows.Next() {
		var p recoveryParticipant
		if e = rows.Scan(&p.ID, &p.Generation, &p.State, &p.Result, &p.Checkpoint); e != nil {
			rows.Close()
			return nil, e
		}
		participants = append(participants, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	rows, e = tx.QueryContext(ctx, "SELECT writer_id,original_json,original_sha256,resumed FROM system_backup_v2_runtime_writers WHERE task_public_id=? ORDER BY writer_id FOR SHARE", a.TaskPublicID)
	if e != nil {
		return nil, e
	}
	receipts := []recoveryWriterReceipt{}
	for rows.Next() {
		var r recoveryWriterReceipt
		if e = rows.Scan(&r.ID, &r.Original, &r.Digest, &r.Resumed); e != nil {
			rows.Close()
			return nil, e
		}
		receipts = append(receipts, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	var missing []recoveryWriterReceipt
	if repair {
		expected := map[string][]byte{}
		for _, w := range frozen {
			expected[w.ID], _ = json.Marshal(d.WriterState{UID: w.Original.UID, Generation: w.Original.Generation, Running: w.Original.Running, Checkpoint: w.Original.Checkpoint})
		}
		known := map[string]bool{}
		for _, r := range receipts {
			known[r.ID] = true
		}
		for _, p := range participants {
			if known[p.ID] || !p.Checkpoint.Valid {
				continue
			}
			original := expected[p.ID]
			if len(original) == 0 || p.Generation != epoch || recordHash(original) != p.Checkpoint.String {
				return nil, ErrExecutionRecoveryRequired
			}
			// This recreates only the original INTENT, never a pause/resume ACK.
			// The real source writer must subsequently confirm recovery.
			r := recoveryWriterReceipt{ID: p.ID, Original: original, Digest: recordHash(original)}
			missing = append(missing, r)
			receipts = append(receipts, r)
		}
	}
	untouched, e := validateRecoveryInventory(epoch, frozen, participants, receipts, final)
	if e != nil {
		return nil, e
	}
	for _, r := range missing {
		if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_runtime_writers(task_public_id,writer_id,original_json,original_sha256,paused,resumed) VALUES(?,?,?,?,FALSE,FALSE)", a.TaskPublicID, r.ID, r.Original, r.Digest); e != nil {
			return nil, e
		}
	}
	if len(missing) > 0 {
		_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,message,request_id) VALUES(?,'backup',?,'diagnostic.d.recovery_intent_repaired','warning','Original recovery intents reconstructed from frozen identities and independent pause witnesses. Runtime recovery remains unconfirmed until actual resume acknowledgements.',?)", a.InstallationID, a.TaskPublicID, a.RequestID)
		if e != nil {
			return nil, e
		}
	}
	return untouched, nil
}

// RepairOriginalPauseIntents reconstructs metadata only, under current recovery
// authority and the complete immutable inventory. It does not acknowledge
// collector exit or resume any source; those remain separately required. A
// matching independent witness permits the original intent, never success.
func (g SQLCaptureGate) RepairOriginalPauseIntents(ctx context.Context, a d.Authority) error {
	tx, e := g.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = g.Recovery.CheckTx(ctx, tx, a); e != nil {
		return e
	}
	if _, e = reconcileRecoveryInventoryTx(ctx, tx, a, g.Authority.ApplicationScope, false, true); e != nil {
		return e
	}
	if e = g.Recovery.CheckTx(ctx, tx, a); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return ErrExecutionCommitUnknown
	}
	return nil
}
