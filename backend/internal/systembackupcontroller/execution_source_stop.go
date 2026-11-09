package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

// CheckSourceStopTx is a preparation-only fence. It permits no collector IO
// and never substitutes for ValidateCollectors. The exact original writer
// must still be running under the acquiring gate, with a durable pause intent.
func (g SQLCaptureGate) CheckSourceStopTx(ctx context.Context, tx *sql.Tx, a d.Authority, id string, original d.WriterState) (*b.RuntimeWriterSpec, error) {
	if tx == nil || a.TaskType != "backup" || a.Phase != "capture" || id == "" {
		return nil, ErrExecutionAuthority
	}
	guard, err := g.Authority.Bind(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	var scope, owner, phase, registry string
	var generation, acquire, gateGeneration, token uint64
	var writers, raw []byte
	var within, paused, resumed bool
	err = tx.QueryRowContext(ctx, `SELECT r.application_scope,r.gate_generation,r.acquire_token,r.registry_sha256,r.writers_json,g.owner,g.phase,g.generation,g.fencing_token,UTC_TIMESTAMP(6)<r.acquire_until
FROM system_backup_v2_runtime_captures r JOIN system_backup_gate g ON g.scope=r.application_scope
WHERE r.task_public_id=? FOR SHARE`, a.TaskPublicID).Scan(&scope, &generation, &acquire, &registry, &writers, &owner, &phase, &gateGeneration, &token, &within)
	if err != nil || scope != g.Authority.ApplicationScope || generation != a.MaintenanceFencingToken || owner != a.TaskPublicID ||
		phase != "acquiring" || gateGeneration != generation || token != acquire || !within || recordHash(writers) != registry {
		return nil, ErrExecutionAuthority
	}
	var frozen []b.FrozenWriter
	if json.Unmarshal(writers, &frozen) != nil {
		return nil, ErrExecutionRecord
	}
	matched := 0
	for _, writer := range frozen {
		if writer.ID == id && (d.WriterState{UID: writer.Original.UID, Generation: writer.Original.Generation, Running: writer.Original.Running, Checkpoint: writer.Original.Checkpoint}) == original {
			matched++
		}
	}
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT original_json,original_sha256,paused,resumed FROM system_backup_v2_runtime_writers WHERE task_public_id=? AND writer_id=? FOR SHARE`, a.TaskPublicID, id).Scan(&raw, &digest, &paused, &resumed)
	want, _ := json.Marshal(original)
	if err != nil || matched != 1 || paused || resumed || !bytes.Equal(raw, want) || recordHash(raw) != digest {
		return nil, ErrExecutionRecord
	}
	var members int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_participants WHERE scope=? AND participant_id=? AND generation=? AND state='pausing' AND resume_result='none'`, scope, id, generation).Scan(&members)
	if err != nil || members != 1 {
		return nil, ErrExecutionRecord
	}
	row, err := readRuntimeControl(ctx, tx, a, id)
	if errors.Is(err, sql.ErrNoRows) {
		// Platform participants have no runtime source reservation.
		return nil, guard.Recheck(ctx, tx)
	}
	if err != nil || row.Claimed || row.Completed || row.Stopped.Valid {
		return nil, ErrExecutionRecord
	}
	current, err := sourceRow(ctx, tx, row.Spec.Source.ID)
	if err != nil || current != row.Spec.Source || !runtimeStateMatches(row.Spec, flow.State{UID: original.UID, Generation: original.Generation, Running: original.Running, Checkpoint: original.Checkpoint}, "before-stop") || guard.Recheck(ctx, tx) != nil {
		return nil, ErrExecutionRecord
	}
	spec := row.Spec
	return &spec, nil
}

func (g SQLCaptureGate) PrepareSourceStop(ctx context.Context, a d.Authority, id string, original d.WriterState) (*b.RuntimeWriterSpec, error) {
	if g.Authority.DB == nil {
		return nil, d.ErrNotReady
	}
	tx, err := g.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return g.CheckSourceStopTx(ctx, tx, a, id, original)
}
