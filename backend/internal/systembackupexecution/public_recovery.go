package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// Pending reads the original intent ledger, including pause-without-ACK. It
// never derives old running state from today's power state. Unknown dispatched
// creates remain blocked; absence is attested only before create dispatch.
func (o *PublicJobOwner) Pending(ctx context.Context, a d.Authority) (b.RecoverySnapshot, error) {
	out := b.RecoverySnapshot{Pauses: []flow.PauseRecord{}, Jobs: []d.JobBinding{}, Undispatched: []string{}}
	_, _, desc, e := o.input(ctx, a, true)
	if e != nil {
		return out, e
	}
	// Reconstruct authenticated original INTENTS before the runner validates
	// every pause. This does not acknowledge stop/resume or permit source IO.
	if e = o.Gate.RepairOriginalPauseIntents(ctx, a); e != nil {
		return out, e
	}
	tx, e := o.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if e = o.Gate.Recovery.CheckTx(ctx, tx, a); e != nil {
		return out, e
	}
	expected := map[string]flow.State{}
	for _, w := range desc.Writers {
		expected[w.ID] = w.Original
	}
	rows, e := tx.QueryContext(ctx, "SELECT writer_id,original_json,original_sha256 FROM system_backup_v2_runtime_writers WHERE task_public_id=? ORDER BY created_at,writer_id FOR UPDATE", a.TaskPublicID)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var id, digest string
		var raw []byte
		var state d.WriterState
		if rows.Scan(&id, &raw, &digest) != nil || hash(raw) != digest || json.Unmarshal(raw, &state) != nil {
			rows.Close()
			return out, c.ErrExecutionRecord
		}
		s := flow.State{UID: state.UID, Generation: state.Generation, Running: state.Running, Checkpoint: state.Checkpoint}
		original, ok := expected[id]
		if !ok || original != s {
			rows.Close()
			return out, c.ErrExecutionRecord
		}
		out.Pauses = append(out.Pauses, flow.PauseRecord{WriterID: id, Original: s})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	repository, e := o.rows(a.TaskPublicID)
	if e != nil {
		return out, e
	}
	var missing []b.JobPart
	for _, part := range desc.Parts {
		record, e := repository.Load(ctx, tx, kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: part.Intent.Namespace, Name: part.Intent.Name}})
		if errors.Is(e, sql.ErrNoRows) || e == nil && !record.CreateDispatched {
			out.Undispatched = append(out.Undispatched, part.Intent.JobUnitKey)
			continue
		}
		if e != nil {
			return out, e
		}
		var raw, process []byte
		var binding d.JobBinding
		if e = tx.QueryRowContext(ctx, "SELECT binding_json,process_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? FOR UPDATE", a.TaskPublicID, part.Intent.Namespace, part.Intent.Name).Scan(&raw, &process); e != nil {
			return out, e
		}
		if len(raw) == 0 || len(process) == 0 || record.UID == "" {
			missing = append(missing, part)
			continue
		}
		if json.Unmarshal(raw, &binding) != nil || binding.UID != record.UID || binding.Name != part.Intent.Name || binding.Namespace != part.Intent.Namespace || binding.JobUnitKey != part.Intent.JobUnitKey || binding.Generation != part.Intent.Generation {
			return out, c.ErrExecutionRecoveryRequired
		}
		out.Jobs = append(out.Jobs, binding)
	}
	if e = o.Gate.Recovery.CheckTx(ctx, tx, a); e != nil {
		return out, e
	}
	tx.Rollback() // No SQL transaction is kept during original-resource lookup.
	for _, part := range missing {
		binding, z := o.recoverJobIdentity(ctx, a, part)
		if z != nil {
			return out, z
		}
		out.Jobs = append(out.Jobs, binding)
	}
	if e = o.Gate.Recovery.Check(ctx, a); e != nil {
		return out, e
	}
	return out, nil
}

var _ b.RecoveryInventory = (*PublicJobOwner)(nil)
