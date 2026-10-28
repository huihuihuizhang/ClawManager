package control

import (
	"clawreef/internal/systembackup/kube"
	"context"
	"database/sql"
)

func (s SQLStore) resourceJournal(t Task, recovery bool) (kube.SQLJournal, error) {
	if !identifier.MatchString(t.ID) || t.Generation <= 0 || t.Owner == "" {
		return kube.SQLJournal{}, ErrInvalid
	}
	rows, e := kube.NewMappedResourceRows(t.ID, "system_backup_resources", "created", kube.ResourceColumns{Scope: "task_id", Kind: "kind", Namespace: "namespace_name", Name: "resource_name", Owner: "owner_marker", RequestHash: "request_sha256", RequestJSON: "request_json", Revision: "row_version", Dispatched: "dispatched", UID: "uid", ResourceVersion: "resource_version", Lifecycle: "lifecycle"})
	if e != nil {
		return kube.SQLJournal{}, e
	}
	var mapped kube.ResourceRows = rows
	if recovery {
		mapped = cleanupRows{rows}
	}
	return kube.SQLJournal{DB: s.DB, Rows: mapped, Fence: func(ctx context.Context, tx *sql.Tx) error {
		if e := s.Fence(ctx, tx, t); e != nil {
			return e
		}
		if recovery {
			return nil
		}
		current, e := load(ctx, tx, t.ID)
		if e != nil {
			return e
		}
		n, e := now(ctx, tx)
		if e != nil || !current.CanCancel || current.Deadline <= n {
			return ErrFence
		}
		return nil
	}}, nil
}
func (s SQLStore) ResourceJournal(t Task) (kube.SQLJournal, error) {
	return s.resourceJournal(t, false)
}

type cleanupRows struct{ kube.ResourceRows }

func (cleanupRows) Insert(context.Context, *sql.Tx, kube.ResourceRecord) error { return ErrFence }

type cleanupJournal struct{ kube.SQLJournal }

func (cleanupJournal) RecordCreate(context.Context, kube.ResourceRecord) (kube.ResourceRecord, error) {
	return kube.ResourceRecord{}, ErrFence
}
func (s SQLStore) CleanupJournal(t Task) (kube.ResourceJournal, error) {
	j, e := s.resourceJournal(t, true)
	if e != nil {
		return nil, e
	}
	return cleanupJournal{j}, nil
}
