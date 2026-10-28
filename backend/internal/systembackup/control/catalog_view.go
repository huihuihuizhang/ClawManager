package control

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"clawreef/internal/systembackup/recovery"
)

// These projections intentionally omit object paths, bootstrap references,
// signatures, private plans, credentials and provider addresses.
type CatalogItem struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	SHA256       string `json:"sha256"`
	Backup       string `json:"backup,omitempty"`
	Origin       string `json:"origin,omitempty"`
	Matrix       string `json:"matrix,omitempty"`
	Attempt      int64  `json:"attempt,omitempty"`
	DecisionTime int64  `json:"decision_time,omitempty"`
	DeletedAt    int64  `json:"deleted_at,omitempty"`
}
type CatalogView struct {
	ScanID         string        `json:"scan_id"`
	Complete       bool          `json:"complete"`
	Count          int64         `json:"count"`
	SnapshotSHA256 string        `json:"snapshot_sha256"`
	Items          []CatalogItem `json:"items"`
	Next           string        `json:"next,omitempty"`
}
type TaskReport struct {
	Version           string             `json:"version"`
	TaskID            string             `json:"task_id"`
	Kind              string             `json:"kind"`
	Status            string             `json:"status"`
	FailureCode       string             `json:"failure_code,omitempty"`
	CreatedAt         int64              `json:"created_at"`
	RecordID          string             `json:"record_id,omitempty"`
	RecordSHA256      string             `json:"record_sha256,omitempty"`
	Verified          bool               `json:"verified"`
	RestoreAuthorized bool               `json:"restore_authorized"`
	Scan              *CatalogView       `json:"scan,omitempty"`
	Acceptance        *AcceptanceSummary `json:"acceptance,omitempty"`
}

type AcceptanceSummary struct {
	LocalAcceptance bool `json:"local_acceptance"`
	Registered      bool `json:"registered"`
}

func acceptanceProjection(raw []byte, readErr error) (recovery.PublicationResult, error) {
	var p recovery.PublicationResult
	if readErr != nil || len(raw) > recovery.MaxDocument || json.Unmarshal(raw, &p) != nil || p.Core.Acceptance.Key != "_ACCEPTANCE" || p.Core.Acceptance.Version == "" || p.Core.Acceptance.Size <= 0 || !revision.MatchString(p.Core.Acceptance.SHA256) {
		return p, ErrNotReady
	}
	if p.LocalAcceptance {
		if p.Registration == nil {
			return p, ErrConflict
		}
		key, e := p.Registration.Key()
		if e != nil || p.Registration.Type != "artifact_registered" || p.Registration.Registration.Core != p.Core || p.RegistrationObject.Key != key || p.RegistrationObject.Version == "" || p.RegistrationObject.Size <= 0 || !revision.MatchString(p.RegistrationObject.SHA256) {
			return p, ErrConflict
		}
	} else if p.Registration != nil || p.RegistrationObject != (recovery.Object{}) {
		return p, ErrConflict
	}
	return p, nil
}

type catalogCursor struct{ Scan, Snapshot, After string }

func projectRecord(raw []byte) (CatalogItem, error) {
	var s recovery.ScannedRecord
	if len(raw) > 2*recovery.MaxDocument || json.Unmarshal(raw, &s) != nil {
		return CatalogItem{}, ErrNotReady
	}
	key, e := s.Record.Key()
	if e != nil || key != s.Key || key != s.Object.Key || recovery.Hash(s.Signed) != s.Object.SHA256 || int64(len(s.Signed)) != s.Object.Size {
		return CatalogItem{}, ErrConflict
	}
	var envelope recovery.Envelope
	if json.Unmarshal(s.Signed, &envelope) != nil || !sameDocument(envelope.Payload, s.Record) {
		return CatalogItem{}, ErrConflict
	}
	out := CatalogItem{ID: s.Record.ID, Type: s.Record.Type, SHA256: s.Object.SHA256}
	if r := s.Record.Registration; r != nil {
		out.Backup = r.Identity.Backup
		out.Origin = r.Identity.Origin
		out.Attempt = r.Identity.Attempt
		out.Matrix = r.Matrix
		out.DecisionTime = r.DecisionTime
	}
	if d := s.Record.Deletion; d != nil {
		out.DeletedAt = d.DeletedAt
	}
	return out, nil
}
func scanView(ctx context.Context, tx *sql.Tx, id string) (CatalogView, error) {
	v := CatalogView{ScanID: id, Items: []CatalogItem{}}
	var raw []byte
	e := tx.QueryRowContext(ctx, "SELECT state_json FROM system_backup_catalog_scans WHERE scan_id=? AND task_id=?", id, id).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	var state recovery.ScanState
	if e != nil || json.Unmarshal(raw, &state) != nil {
		return v, ErrNotReady
	}
	b, e := recovery.Marshal(state.Snapshot)
	if e != nil {
		return v, ErrNotReady
	}
	v.Complete = state.Complete
	v.Count = state.Count
	v.SnapshotSHA256 = recovery.Hash(b)
	return v, nil
}
func (s SQLStore) CatalogPage(ctx context.Context, id, cursor string, limit int) (CatalogView, error) {
	if !identifier.MatchString(id) || limit < 1 || limit > 100 || len(cursor) > 1024 {
		return CatalogView{}, ErrInvalid
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return CatalogView{}, e
	}
	defer tx.Rollback()
	v, e := scanView(ctx, tx, id)
	if e != nil {
		return v, e
	}
	if !v.Complete {
		return v, ErrNotReady
	}
	after := ""
	if cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(cursor)
		var c catalogCursor
		if err != nil || json.Unmarshal(b, &c) != nil || c.Scan != id || c.Snapshot != v.SnapshotSHA256 || !revision.MatchString(c.After) {
			return v, ErrInvalid
		}
		after = c.After
	}
	rows, e := tx.QueryContext(ctx, "SELECT key_hash,record_json FROM system_backup_catalog_records WHERE scan_id=? AND key_hash>? ORDER BY key_hash LIMIT ?", id, after, limit+1)
	if e != nil {
		return v, ErrNotReady
	}
	defer rows.Close()
	last := ""
	for rows.Next() {
		var hash string
		var raw []byte
		if rows.Scan(&hash, &raw) != nil || !revision.MatchString(hash) || hash <= after || last != "" && hash <= last {
			return v, ErrNotReady
		}
		if len(v.Items) == limit {
			b, _ := json.Marshal(catalogCursor{id, v.SnapshotSHA256, last})
			v.Next = base64.RawURLEncoding.EncodeToString(b)
			break
		}
		item, e := projectRecord(raw)
		if e != nil {
			return v, e
		}
		prefix := "registrations/"
		record := item.ID
		if item.Type == "artifact_deleted" {
			prefix = "tombstones/"
			record = "sbr_" + item.ID[4:]
		}
		if recovery.Hash([]byte(prefix+record+".json")) != hash {
			return v, ErrConflict
		}
		v.Items = append(v.Items, item)
		last = hash
	}
	if rows.Err() != nil {
		return v, ErrNotReady
	}
	return v, nil
}
func (s SQLStore) CatalogDetail(ctx context.Context, id, record, kind string) (CatalogItem, error) {
	lookup := record
	if kind == "artifact_deleted" && strings.HasPrefix(record, "sbd_") {
		lookup = "sbr_" + record[4:]
	}
	if !identifier.MatchString(id) || !catalogRecordID.MatchString(lookup) || kind != "artifact_registered" && kind != "artifact_deleted" || kind == "artifact_deleted" && !strings.HasPrefix(record, "sbd_") {
		return CatalogItem{}, ErrInvalid
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return CatalogItem{}, e
	}
	defer tx.Rollback()
	v, e := scanView(ctx, tx, id)
	if e != nil {
		return CatalogItem{}, e
	}
	if !v.Complete {
		return CatalogItem{}, ErrNotReady
	}
	prefix := "registrations/"
	if kind == "artifact_deleted" {
		prefix = "tombstones/"
	}
	key := prefix + lookup + ".json"
	var raw []byte
	e = tx.QueryRowContext(ctx, "SELECT record_json FROM system_backup_catalog_records WHERE scan_id=? AND key_hash=? AND object_key=?", id, recovery.Hash([]byte(key)), key).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return CatalogItem{}, ErrNotFound
	}
	if e != nil {
		return CatalogItem{}, ErrNotReady
	}
	out, e := projectRecord(raw)
	if e != nil {
		return out, e
	}
	if out.ID != record || out.Type != kind {
		return CatalogItem{}, ErrConflict
	}
	return out, nil
}
func (s SQLStore) Report(ctx context.Context, id string) (TaskReport, error) {
	if !identifier.MatchString(id) {
		return TaskReport{}, ErrInvalid
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return TaskReport{}, e
	}
	defer tx.Rollback()
	t, e := load(ctx, tx, id)
	if e != nil {
		return TaskReport{}, e
	}
	out := TaskReport{Version: "backup-report.v1", TaskID: t.ID, Kind: t.Request.Kind, Status: t.Status, FailureCode: t.FailureCode, CreatedAt: t.CreatedAt}
	if t.Request.Purpose == "acceptance" {
		var raw []byte
		err := tx.QueryRowContext(ctx, "SELECT result_json FROM system_backup_recovery_publications WHERE task_id=?", t.ID).Scan(&raw)
		if err == nil {
			p, e := acceptanceProjection(raw, nil)
			if e != nil {
				return out, e
			}
			out.Acceptance = &AcceptanceSummary{p.LocalAcceptance, p.Registration != nil}
			if p.Registration != nil {
				out.RecordID = p.Registration.ID
				out.RecordSHA256 = p.RegistrationObject.SHA256
			}
		} else if !errors.Is(err, sql.ErrNoRows) || t.Status == "succeeded" {
			return out, ErrNotReady
		}
	}
	if t.Request.Kind == "catalog_import" {
		out.RecordID = t.Request.Artifact
		out.RecordSHA256 = t.Request.RecordSHA256
		out.Verified = t.Status == "succeeded"
	}
	if t.Request.Kind == "catalog_scan" {
		v, e := scanView(ctx, tx, id)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return out, e
		}
		if e == nil {
			out.Scan = &v
		}
	}
	return out, nil
}
