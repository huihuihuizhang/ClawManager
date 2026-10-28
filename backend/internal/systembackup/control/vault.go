package control

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
)

// Vault holds immutable plans, restart specifications and task identities. Keys
// come from mounted controller secrets, never from source database settings.
// Versioned keys must remain available until all tasks using them are retired.
type Vault struct {
	Store        SQLStore
	WriteVersion string
	Keys         map[string][]byte
}
type sealedRecord struct {
	kind, version     string
	nonce, ciphertext []byte
}

func recordAAD(t Task, name, kind, version string) []byte {
	b, _ := json.Marshal([]string{"clawmanager/control-record/v1", t.ID, t.ProfileRevision, name, kind, version})
	return b
}
func (v Vault) aead(version string) (cipher.AEAD, error) {
	if !identifier.MatchString(version) || len(v.Keys[version]) != 32 {
		return nil, ErrNotReady
	}
	block, e := aes.NewCipher(v.Keys[version])
	if e != nil {
		return nil, ErrNotReady
	}
	return cipher.NewGCM(block)
}
func validRecordKey(t Task, name, kind string) bool {
	return identifier.MatchString(t.ID) && revision.MatchString(t.ProfileRevision) && identifier.MatchString(name) && identifier.MatchString(kind) && len(kind) <= 32
}
func (v Vault) seal(t Task, name, kind string, plain []byte) (sealedRecord, error) {
	a, e := v.aead(v.WriteVersion)
	if e != nil || !validRecordKey(t, name, kind) || len(plain) == 0 || len(plain) > 4<<20 {
		return sealedRecord{}, ErrInvalid
	}
	n := make([]byte, a.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return sealedRecord{}, ErrNotReady
	}
	return sealedRecord{kind, v.WriteVersion, n, a.Seal(nil, n, plain, recordAAD(t, name, kind, v.WriteVersion))}, nil
}
func (v Vault) open(t Task, name, kind string, r sealedRecord) ([]byte, error) {
	if r.kind != kind || !validRecordKey(t, name, kind) || len(r.ciphertext) < 16 || len(r.ciphertext) > 4<<20+16 {
		return nil, ErrConflict
	}
	a, e := v.aead(r.version)
	if e != nil || len(r.nonce) != a.NonceSize() {
		return nil, ErrNotReady
	}
	b, e := a.Open(nil, r.nonce, r.ciphertext, recordAAD(t, name, kind, r.version))
	if e != nil {
		return nil, ErrConflict
	}
	return b, nil
}
func readRecord(ctx context.Context, tx *sql.Tx, t Task, name string) (sealedRecord, error) {
	var r sealedRecord
	e := tx.QueryRowContext(ctx, "SELECT record_kind,key_version,nonce,ciphertext FROM system_backup_private_records WHERE task_id=? AND record_name=? FOR UPDATE", t.ID, name).Scan(&r.kind, &r.version, &r.nonce, &r.ciphertext)
	return r, e
}
func (v Vault) Get(ctx context.Context, t Task, name, kind string) ([]byte, error) {
	if !validRecordKey(t, name, kind) {
		return nil, ErrInvalid
	}
	tx, e := v.Store.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if v.Store.Fence(ctx, tx, t) != nil {
		return nil, ErrFence
	}
	r, e := readRecord(ctx, tx, t, name)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, ErrNotReady
	}
	return v.open(t, name, kind, r)
}

// Put never replaces a stored record. Retrying after a lost COMMIT reply reads
// and compares authenticated plaintext instead of creating another key/plan.
func (v Vault) Put(ctx context.Context, t Task, name, kind string, plain []byte) error {
	candidate, e := v.seal(t, name, kind, plain)
	if e != nil {
		return e
	}
	tx, e := v.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if v.Store.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	previous, e := readRecord(ctx, tx, t, name)
	if e == nil {
		b, e := v.open(t, name, kind, previous)
		defer clear(b)
		if e != nil || !bytes.Equal(b, plain) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return ErrNotReady
	}
	current, e := load(ctx, tx, t.ID)
	if e != nil {
		return e
	}
	timestamp, e := now(ctx, tx)
	if e != nil || !current.CanCancel || current.Deadline <= timestamp {
		return ErrFence
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_private_records(task_id,record_name,record_kind,key_version,nonce,ciphertext) VALUES(?,?,?,?,?,?)", t.ID, name, kind, candidate.version, candidate.nonce, candidate.ciphertext)
	if e != nil || v.Store.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
