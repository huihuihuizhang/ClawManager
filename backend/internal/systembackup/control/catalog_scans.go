package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"clawreef/internal/systembackup/recovery"
)

type CatalogScans struct {
	Store SQLStore
	Task  Task
	Trust recovery.Trust
}

func (j CatalogScans) Load(ctx context.Context, id string) (recovery.ScanState, error) {
	var state recovery.ScanState
	var raw []byte
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return state, e
	}
	defer tx.Rollback()
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		return state, ErrFence
	}
	e = tx.QueryRowContext(ctx, "SELECT state_json FROM system_backup_catalog_scans WHERE scan_id=? AND task_id=?", id, j.Task.ID).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return state, nil
	}
	if e != nil || json.Unmarshal(raw, &state) != nil {
		return state, ErrNotReady
	}
	return state, nil
}
func (j CatalogScans) Start(ctx context.Context, id string, s recovery.Snapshot) (recovery.ScanState, error) {
	state := recovery.ScanState{Snapshot: s}
	raw, e := recovery.Marshal(state)
	if e != nil {
		return state, ErrInvalid
	}
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return state, e
	}
	defer tx.Rollback()
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		return state, ErrFence
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_catalog_scans(scan_id,task_id,state_json) VALUES(?,?,?)", id, j.Task.ID, raw); e != nil || tx.Commit() != nil {
		return state, ErrNotReady
	}
	return state, nil
}
func (j CatalogScans) CommitPage(ctx context.Context, id string, previous, next recovery.ScanState, page recovery.ScanPage, records []recovery.ScannedRecord) error {
	if next.Page != previous.Page+1 || next.Count != previous.Count+int64(len(records)) || next.Snapshot != previous.Snapshot || previous.Complete || next.Complete {
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
	var stored []byte
	if tx.QueryRowContext(ctx, "SELECT state_json FROM system_backup_catalog_scans WHERE scan_id=? AND task_id=? FOR UPDATE", id, j.Task.ID).Scan(&stored) != nil {
		return ErrNotReady
	}
	p, _ := recovery.Marshal(previous)
	n, _ := recovery.Marshal(next)
	if string(stored) == string(n) {
		return nil
	}
	if string(stored) != string(p) {
		return ErrConflict
	}
	pageRaw, e := recovery.Marshal(page)
	if e != nil {
		return ErrInvalid
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_catalog_pages(scan_id,page_no,page_json) VALUES(?,?,?)", id, previous.Page, pageRaw); e != nil {
		return ErrNotReady
	}
	for _, r := range records {
		raw, e := recovery.Marshal(r)
		if e != nil {
			return ErrInvalid
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_catalog_records(scan_id,key_hash,object_key,record_json) VALUES(?,?,?,?)", id, recovery.Hash([]byte(r.Key)), r.Key, raw); e != nil {
			return ErrNotReady
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_catalog_scans SET state_json=? WHERE scan_id=? AND task_id=?", n, id, j.Task.ID); e != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
func (j CatalogScans) Finish(ctx context.Context, id string, expected recovery.ScanState) error {
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		return ErrFence
	}
	var raw []byte
	if tx.QueryRowContext(ctx, "SELECT state_json FROM system_backup_catalog_scans WHERE scan_id=? AND task_id=? FOR UPDATE", id, j.Task.ID).Scan(&raw) != nil {
		return ErrNotReady
	}
	var actual recovery.ScanState
	if json.Unmarshal(raw, &actual) != nil {
		return ErrNotReady
	}
	if actual.Complete {
		expected.Complete = true
	}
	want, _ := recovery.Marshal(expected)
	if string(raw) != string(want) {
		return ErrConflict
	}
	if actual.Complete {
		return nil
	}
	rows, e := tx.QueryContext(ctx, "SELECT record_json FROM system_backup_catalog_records WHERE scan_id=? ORDER BY object_key", id)
	if e != nil {
		return ErrNotReady
	}
	records := []recovery.ScannedRecord{}
	for rows.Next() {
		var raw []byte
		var r recovery.ScannedRecord
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &r) != nil || len(records) >= 100000 {
			rows.Close()
			return ErrNotReady
		}
		records = append(records, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrNotReady
	}
	if recovery.ValidateInventory(actual, records, j.Trust) != nil {
		return ErrConflict
	}
	pageRows, e := tx.QueryContext(ctx, "SELECT page_json FROM system_backup_catalog_pages WHERE scan_id=? ORDER BY page_no", id)
	if e != nil {
		return ErrNotReady
	}
	pages := []recovery.ScanPage{}
	for pageRows.Next() {
		var b []byte
		var p recovery.ScanPage
		if pageRows.Scan(&b) != nil || json.Unmarshal(b, &p) != nil || len(pages) >= 100001 {
			pageRows.Close()
			return ErrNotReady
		}
		pages = append(pages, p)
	}
	e = pageRows.Err()
	pageRows.Close()
	if e != nil || recovery.ValidatePages(actual, pages, records) != nil {
		return ErrConflict
	}
	actual.Complete = true
	raw, _ = recovery.Marshal(actual)
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_catalog_scans SET state_json=? WHERE scan_id=? AND task_id=?", raw, id, j.Task.ID); e != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
