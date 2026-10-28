package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"clawreef/internal/systembackup/flow"
)

// Enter persists a mutation permit while holding the same row lock used by
// CloseGate. No TTL silently forgets a live operation. A crashed participant's
// permit must be resolved using independent process termination evidence.
func (s SQLStore) Enter(ctx context.Context, participant string) (func() error, error) {
	return s.enter(ctx, participant, "")
}
func (s SQLStore) enter(ctx context.Context, participant, process string) (func() error, error) {
	if !identifier.MatchString(participant) {
		return nil, ErrInvalid
	}
	token, e := NewID()
	if e != nil {
		return nil, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var closed bool
	if tx.QueryRowContext(ctx, "SELECT closed FROM system_backup_maintenance WHERE id=1 FOR UPDATE").Scan(&closed) != nil {
		return nil, ErrNotReady
	}
	if closed {
		return nil, ErrConflict
	}
	if process != "" {
		var revoked bool
		if tx.QueryRowContext(ctx, "SELECT revoked FROM system_backup_app_processes WHERE process_id=? FOR UPDATE", process).Scan(&revoked) != nil || revoked {
			return nil, ErrNotReady
		}
	}
	query := "INSERT INTO system_backup_mutations(token,participant,created_at_ms) VALUES(?,?," + dbNow + ")"
	args := []any{token, participant}
	if process != "" {
		query = "INSERT INTO system_backup_mutations(token,participant,process_id,created_at_ms) VALUES(?,?,?," + dbNow + ")"
		args = append(args, process)
	}
	if _, e = tx.ExecContext(ctx, query, args...); e != nil || tx.Commit() != nil {
		return nil, ErrNotReady
	}
	return func() error {
		release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, e := s.DB.ExecContext(release, "DELETE FROM system_backup_mutations WHERE token=?", token)
		if e != nil {
			return ErrNotReady
		}
		return nil
	}, nil
}
func (s SQLStore) CloseGate(ctx context.Context, t Task, holdUntil time.Time) error {
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	current, e := load(ctx, tx, t.ID)
	if e != nil || current.Status != "acquiring_gate" || !current.CanCancel {
		return ErrConflict
	}
	n, e := now(ctx, tx)
	if e != nil || holdUntil.UnixMilli() <= n || holdUntil.UnixMilli() > current.Deadline {
		return ErrInvalid
	}
	var owner string
	var closed bool
	if tx.QueryRowContext(ctx, "SELECT task_id,closed FROM system_backup_maintenance WHERE id=1 FOR UPDATE").Scan(&owner, &closed) != nil {
		return ErrNotReady
	}
	if closed && owner != t.ID {
		return ErrConflict
	}
	_, e = tx.ExecContext(ctx, "UPDATE system_backup_maintenance SET task_id=?,generation=?,hold_until_ms=IF(closed,LEAST(hold_until_ms,?),?),closed=TRUE WHERE id=1", t.ID, t.Generation, holdUntil.UnixMilli(), holdUntil.UnixMilli())
	if e != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
func (s SQLStore) GateDrained(ctx context.Context, tx *sql.Tx, t Task, recovery bool) error {
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	current, e := load(ctx, tx, t.ID)
	if e != nil {
		return e
	}
	var owner string
	var closed bool
	var until int64
	if tx.QueryRowContext(ctx, "SELECT task_id,closed,hold_until_ms FROM system_backup_maintenance WHERE id=1 FOR UPDATE").Scan(&owner, &closed, &until) != nil {
		return ErrNotReady
	}
	n, e := now(ctx, tx)
	if e != nil || !closed || owner != t.ID {
		return ErrFence
	}
	if !recovery && (until <= n || !current.CanCancel || (current.Status != "acquiring_gate" && current.Status != "capturing")) {
		return ErrFence
	}
	var count int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_mutations").Scan(&count) != nil {
		return ErrNotReady
	}
	if count != 0 {
		return ErrNotReady
	}
	return nil
}

// OpenGate never deletes mutation permits and never trusts a lease timeout as
// proof of process termination. All source pause records must be reconciled.
func (s SQLStore) OpenGate(ctx context.Context, t Task) error {
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
	if tx.QueryRowContext(ctx, "SELECT task_id,closed FROM system_backup_maintenance WHERE id=1 FOR UPDATE").Scan(&owner, &closed) != nil {
		return ErrNotReady
	}
	if !closed {
		return nil
	}
	if owner != t.ID {
		return ErrFence
	}
	var pending int
	if tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM system_backup_pauses WHERE task_id=? AND resumed=FALSE)+"+pendingWorkersSQL, t.ID, t.ID, t.ID).Scan(&pending) != nil || pending != 0 {
		return ErrConflict
	}
	_, e = tx.ExecContext(ctx, "UPDATE system_backup_maintenance SET closed=FALSE,task_id='',generation=0,hold_until_ms=0 WHERE id=1")
	if e != nil || s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}

// PauseJournal is the concrete flow journal on the SAME control DB and claim.
// flow.Identity.Generation identifies the original capture attempt; takeover
// generation lives on Task and does not replace the persisted original state.
type PauseJournal struct {
	Store    SQLStore
	Task     Task
	Identity flow.Identity
	Writers  []string
}

func (j PauseJournal) registry() ([]byte, error) {
	if len(j.Writers) == 0 || len(j.Writers) > 10000 {
		return nil, ErrInvalid
	}
	writers := append([]string(nil), j.Writers...)
	sort.Strings(writers)
	for i, w := range writers {
		if w == "" || len(w) > 255 || (i > 0 && w == writers[i-1]) {
			return nil, ErrInvalid
		}
	}
	b, e := json.Marshal(struct {
		Identity flow.Identity
		Writers  []string
	}{j.Identity, writers})
	return b, e
}

// Register freezes the complete discovery result before the first pause. It
// never overwrites the inventory on takeover or accepts a shorter writer list.
func (j PauseJournal) Register(ctx context.Context) error {
	b, e := j.registry()
	if e != nil || !j.identity(j.Identity) {
		return ErrInvalid
	}
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		return ErrFence
	}
	var old []byte
	e = tx.QueryRowContext(ctx, "SELECT registry_json FROM system_backup_capture_registry WHERE task_id=? FOR UPDATE", j.Task.ID).Scan(&old)
	if e == nil {
		if string(old) != string(b) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return ErrNotReady
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_capture_registry(task_id,registry_json) VALUES(?,?)", j.Task.ID, b)
	if e != nil || j.Store.Fence(ctx, tx, j.Task) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}

func (j PauseJournal) identity(id flow.Identity) bool {
	return id == j.Identity && id.Task == j.Task.ID && id.Attempt != "" && id.Phase != "" && id.Generation > 0
}
func (j PauseJournal) transaction(ctx context.Context, id flow.Identity, recovery bool, fn func(*sql.Tx) error) error {
	if !j.identity(id) {
		return ErrFence
	}
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	registry, e := j.registry()
	if e != nil {
		return ErrInvalid
	}
	var recorded []byte
	// Use the task row as the first lock everywhere, avoiding inversion with
	// Register and resource journal operations.
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		return ErrFence
	}
	if tx.QueryRowContext(ctx, "SELECT registry_json FROM system_backup_capture_registry WHERE task_id=? FOR UPDATE", j.Task.ID).Scan(&recorded) != nil || string(recorded) != string(registry) {
		return ErrFence
	}
	if e = j.Store.GateDrained(ctx, tx, j.Task, recovery); e != nil {
		return e
	}
	if e = fn(tx); e != nil {
		return e
	}
	if j.Store.GateDrained(ctx, tx, j.Task, recovery) != nil || tx.Commit() != nil {
		return ErrFence
	}
	return nil
}
func (j PauseJournal) CheckFence(ctx context.Context, id flow.Identity) error {
	return j.transaction(ctx, id, false, func(*sql.Tx) error { return nil })
}
func (j PauseJournal) PauseIntent(ctx context.Context, id flow.Identity, writer string, state flow.State) error {
	registered := false
	for _, name := range j.Writers {
		registered = registered || name == writer
	}
	if !registered {
		return ErrInvalid
	}
	if writer == "" || len(writer) > 255 || state.UID == "" || state.Generation <= 0 || len(state.Checkpoint) > 128<<10 {
		return ErrInvalid
	}
	b, _ := json.Marshal(state)
	return j.transaction(ctx, id, false, func(tx *sql.Tx) error {
		var old []byte
		e := tx.QueryRowContext(ctx, "SELECT original_json FROM system_backup_pauses WHERE task_id=? AND writer_id=? FOR UPDATE", id.Task, writer).Scan(&old)
		if e == nil {
			if string(old) != string(b) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return ErrNotReady
		}
		var ordinal int64
		if tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(ordinal),0)+1 FROM system_backup_pauses WHERE task_id=?", id.Task).Scan(&ordinal) != nil {
			return ErrNotReady
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_pauses(task_id,writer_id,ordinal,original_json) VALUES(?,?,?,?)", id.Task, writer, ordinal, b)
		if e != nil {
			return ErrNotReady
		}
		return nil
	})
}
func (j PauseJournal) CheckRecoveryFence(ctx context.Context, id flow.Identity, writer string, state flow.State) error {
	return j.transaction(ctx, id, true, func(tx *sql.Tx) error {
		var active int
		if tx.QueryRowContext(ctx, "SELECT "+pendingWorkersSQL, id.Task, id.Task).Scan(&active) != nil || active != 0 {
			return ErrNotReady
		}
		var b []byte
		if tx.QueryRowContext(ctx, "SELECT original_json FROM system_backup_pauses WHERE task_id=? AND writer_id=? FOR UPDATE", id.Task, writer).Scan(&b) != nil {
			return ErrNotReady
		}
		var original flow.State
		if json.Unmarshal(b, &original) != nil || original != state {
			return ErrConflict
		}
		return nil
	})
}
func (j PauseJournal) Paused(ctx context.Context, id flow.Identity, writer string, ack flow.ACK) error {
	return j.transaction(ctx, id, false, func(tx *sql.Tx) error {
		var b []byte
		var resumed bool
		if tx.QueryRowContext(ctx, "SELECT original_json,resumed FROM system_backup_pauses WHERE task_id=? AND writer_id=? FOR UPDATE", id.Task, writer).Scan(&b, &resumed) != nil {
			return ErrNotReady
		}
		var state flow.State
		if json.Unmarshal(b, &state) != nil || state.UID != ack.UID || state.Generation != ack.Generation || !ack.Stopped || resumed {
			return ErrConflict
		}
		_, e := tx.ExecContext(ctx, "UPDATE system_backup_pauses SET acknowledged=TRUE WHERE task_id=? AND writer_id=?", id.Task, writer)
		if e != nil {
			return ErrNotReady
		}
		return nil
	})
}
func (j PauseJournal) Resumed(ctx context.Context, id flow.Identity, writer string) error {
	return j.transaction(ctx, id, true, func(tx *sql.Tx) error {
		var present int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_pauses WHERE task_id=? AND writer_id=?", id.Task, writer).Scan(&present) != nil || present != 1 {
			return ErrConflict
		}
		_, e := tx.ExecContext(ctx, "UPDATE system_backup_pauses SET resumed=TRUE WHERE task_id=? AND writer_id=?", id.Task, writer)
		if e != nil {
			return ErrNotReady
		}
		return nil
	})
}
func (j PauseJournal) PendingPauses(ctx context.Context, id flow.Identity) ([]flow.PauseRecord, error) {
	out := []flow.PauseRecord{}
	e := j.transaction(ctx, id, true, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, "SELECT writer_id,original_json FROM system_backup_pauses WHERE task_id=? AND resumed=FALSE ORDER BY ordinal LIMIT 10001", id.Task)
		if e != nil {
			return ErrNotReady
		}
		defer rows.Close()
		for rows.Next() {
			var p flow.PauseRecord
			var b []byte
			if rows.Scan(&p.WriterID, &b) != nil || json.Unmarshal(b, &p.Original) != nil {
				return ErrNotReady
			}
			out = append(out, p)
		}
		if rows.Err() != nil || len(out) > 10000 {
			return ErrNotReady
		}
		return nil
	})
	return out, e
}
func (j PauseJournal) ClaimRestart(ctx context.Context, writer string, state flow.State) (bool, error) {
	claimed := false
	e := j.transaction(ctx, j.Identity, true, func(tx *sql.Tx) error {
		var b []byte
		var sent bool
		if tx.QueryRowContext(ctx, "SELECT original_json,restart_dispatched FROM system_backup_pauses WHERE task_id=? AND writer_id=? FOR UPDATE", j.Task.ID, writer).Scan(&b, &sent) != nil {
			return ErrNotReady
		}
		var original flow.State
		if json.Unmarshal(b, &original) != nil || original != state {
			return ErrConflict
		}
		if sent {
			return nil
		}
		e := changed(tx.ExecContext(ctx, "UPDATE system_backup_pauses SET restart_dispatched=TRUE WHERE task_id=? AND writer_id=? AND restart_dispatched=FALSE", j.Task.ID, writer))
		claimed = e == nil
		return e
	})
	return claimed && e == nil, e
}
