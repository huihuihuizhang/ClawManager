package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// ResolveLegacyMutation requires proof of the exact token -> original process
// association AND remote effect completion. Configuration alone is not proof.
// Missing or ambiguous identity remains blocked; no bulk/TTL delete is exposed.
func (s SQLStore) ResolveLegacyMutation(ctx context.Context, t Task, token string, p AppProcess, proof func(context.Context, AppProcess, MutationPermit) error) error {
	if !p.valid() || !identifier.MatchString(token) || len(token) > 112 || proof == nil {
		return ErrInvalid
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	var owner string
	var closed bool
	if tx.QueryRowContext(ctx, "SELECT task_id,closed FROM system_backup_maintenance WHERE id=1 FOR UPDATE").Scan(&owner, &closed) != nil || owner != t.ID || !closed {
		return ErrFence
	}
	var permit MutationPermit
	e = tx.QueryRowContext(ctx, "SELECT token,participant,process_id FROM system_backup_mutations WHERE token=? FOR UPDATE", token).Scan(&permit.Token, &permit.Participant, &permit.Process)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil || permit.Token != token || permit.Process != "" {
		return ErrConflict
	}
	if proof(ctx, p, permit) != nil {
		return ErrNotReady
	}
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	raw, _ := json.Marshal(struct {
		Process AppProcess
		Permit  MutationPermit
	}{p, permit})
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_mutation_resolutions(task_id,process_id,permits_json,resolved_at_ms) VALUES(?,?,?,"+dbNow+")", t.ID, "legacy-"+token, raw); e != nil {
		return ErrNotReady
	}
	if e = changed(tx.ExecContext(ctx, "DELETE FROM system_backup_mutations WHERE token=? AND process_id=''", token)); e != nil {
		return e
	}
	if tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
