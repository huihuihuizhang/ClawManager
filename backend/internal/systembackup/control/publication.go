package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"clawreef/internal/systembackup/artifact"
)

type Publication struct {
	Bundle artifact.Bundle `json:"bundle"`
	KeyID  string          `json:"key_id"`
}

func publicationBytes(p Publication) ([]byte, string, error) {
	published, e := artifact.PublishedBundle(p.Bundle)
	if e != nil || !identifier.MatchString(p.KeyID) {
		return nil, "", ErrInvalid
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > 4<<20 {
		return nil, "", ErrInvalid
	}
	b, _ := json.Marshal(published)
	sum := sha256.Sum256(b)
	return raw, hex.EncodeToString(sum[:]), nil
}

// PreparePublication persists exact staging receipts, wrapped keys and signing
// key identity before closing cancellation or touching the external directory.
func (s SQLStore) PreparePublication(ctx context.Context, t Task, p Publication) error {
	raw, hash, e := publicationBytes(p)
	if e != nil || p.Bundle.ID != t.ID {
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
	current, e := load(ctx, tx, t.ID)
	if e != nil || current.Request.Kind != "backup" || current.Status != "publishing" {
		return ErrConflict
	}
	var previous []byte
	e = tx.QueryRowContext(ctx, "SELECT intent_json FROM system_backup_publications WHERE task_id=? FOR UPDATE", t.ID).Scan(&previous)
	if e == nil {
		if !bytes.Equal(previous, raw) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) || !current.CanCancel {
		return ErrConflict
	}
	// Source recovery is a precondition, not a post-publication best effort.
	var pending int
	if tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM system_backup_pauses WHERE task_id=? AND resumed=FALSE)+(SELECT COUNT(*) FROM system_backup_maintenance WHERE task_id=? AND closed=TRUE)+"+pendingWorkersSQL, t.ID, t.ID, t.ID, t.ID).Scan(&pending) != nil || pending != 0 {
		return ErrConflict
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_publications(task_id,intent_json,published_sha256) VALUES(?,?,?)", t.ID, raw, hash)
	if e != nil || s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}

func (s SQLStore) publication(ctx context.Context, t Task) (Publication, string, error) {
	var p Publication
	var raw []byte
	var hash string
	tx, e := s.begin(ctx)
	if e != nil {
		return p, "", e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return p, "", ErrFence
	}
	if tx.QueryRowContext(ctx, "SELECT intent_json,published_sha256 FROM system_backup_publications WHERE task_id=? FOR UPDATE", t.ID).Scan(&raw, &hash) != nil || len(raw) > 4<<20 || json.Unmarshal(raw, &p) != nil {
		return p, "", ErrNotReady
	}
	canonical, actual, e := publicationBytes(p)
	if e != nil || actual != hash || p.Bundle.ID != t.ID || !bytes.Equal(canonical, raw) {
		return Publication{}, "", ErrConflict
	}
	return p, hash, nil
}

// PublicationFence is rechecked at each directory IO boundary. A stale owner
// cannot extend publication or certify a newly read external result.
func (s SQLStore) PublicationFence(ctx context.Context, t Task, id, action string) error {
	if id != t.ID || (action != "read" && action != "publish") {
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
	current, e := load(ctx, tx, t.ID)
	if e != nil || current.CanCancel || current.Request.Kind != "backup" || (current.Status != "publishing" && current.Status != "finalization_unknown") || (action == "publish" && current.Status != "publishing") {
		return ErrFence
	}
	var started int64
	if tx.QueryRowContext(ctx, "SELECT commit_started_at_ms FROM system_backup_publications WHERE task_id=? FOR UPDATE", t.ID).Scan(&started) != nil || started <= 0 {
		return ErrFence
	}
	return nil
}

// Publisher connects immutable ciphertext publication to the authoritative
// cancellation window and result journal. It does not provide P0 acceptance
// for unrelated domains or enable production restore.
type Publisher struct {
	Store     SQLStore
	Directory artifact.Directory
	Signers   map[string]ed25519.PrivateKey
}

func (p Publisher) directory(t Task, keyID string) (artifact.Directory, error) {
	d := p.Directory
	if len(d.VerifyKeys[keyID]) != ed25519.PublicKeySize {
		return d, ErrNotReady
	}
	d.VerifyKeys = map[string]ed25519.PublicKey{keyID: d.VerifyKeys[keyID]}
	d.Authorize = func(ctx context.Context, id, action string) error {
		return p.Store.PublicationFence(ctx, t, id, action)
	}
	return d, nil
}
func (p Publisher) Publish(ctx context.Context, t Task, intent Publication, open func(artifact.Part) (io.ReadCloser, error)) error {
	// A takeover after commit started must first resolve the original write.
	// It cannot infer from an absent marker that the previous writer never ran.
	if !t.CanCancel {
		return p.Reconcile(ctx, t)
	}
	if e := p.Store.PreparePublication(ctx, t, intent); e != nil {
		return e
	}
	committed, e := p.Store.BeginCommit(ctx, t)
	if e != nil {
		return e
	}
	frozen, _, e := p.Store.publication(ctx, committed)
	if e != nil {
		return e
	}
	d, e := p.directory(committed, frozen.KeyID)
	if e != nil {
		return e
	}
	if d.Publish(ctx, frozen.Bundle, frozen.KeyID, p.Signers[frozen.KeyID], open) != nil {
		return ErrNotReady
	}
	return p.Reconcile(ctx, committed)
}

// Reconcile is read-only against the artifact store: a missing/partial/bad
// object stays unknown. It never turns GET absence into success or a retry PUT.
// The caller owns a fresh normal or finalization claim for the entire read.
func (p Publisher) Reconcile(ctx context.Context, t Task) error {
	intent, expected, e := p.Store.publication(ctx, t)
	if e != nil {
		return e
	}
	d, e := p.directory(t, intent.KeyID)
	if e != nil {
		return e
	}
	actual, e := d.Read(ctx, t.ID)
	if e != nil {
		return ErrNotReady
	}
	raw, _ := json.Marshal(actual)
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expected {
		return ErrConflict
	}
	tx, e := p.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if p.Store.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	current, e := load(ctx, tx, t.ID)
	if e != nil || current.CanCancel || (current.Status != "publishing" && current.Status != "finalization_unknown") {
		return ErrConflict
	}
	var digest string
	var started int64
	if tx.QueryRowContext(ctx, "SELECT published_sha256,commit_started_at_ms FROM system_backup_publications WHERE task_id=? FOR UPDATE", t.ID).Scan(&digest, &started) != nil || digest != expected || started <= 0 {
		return ErrConflict
	}
	_, e = tx.ExecContext(ctx, "UPDATE system_backup_publications SET committed=TRUE,confirmed_at_ms=IF(confirmed_at_ms=0,"+dbNow+",confirmed_at_ms) WHERE task_id=?", t.ID)
	if e != nil || p.Store.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
