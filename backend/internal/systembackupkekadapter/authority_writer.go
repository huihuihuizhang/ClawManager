package systembackupkekadapter

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
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	refs "clawreef/internal/systembackupbootstrapsecurity"
	reg "clawreef/internal/systembackupkekregistry"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var ErrAuthorityWrite = errors.New("installation KEK authority write rejected")
var ErrAuthorityCommitUnknown = errors.New("installation KEK authority commit unknown; inspect row and history before retry")

type InstallationAuthorityWriter struct {
	db           *sql.DB
	installation string
	database     reg.DatabaseIdentity
	issuer       ed25519.PublicKey
}

// NewInstallationAuthorityWriter takes offline deployment pins, not config
// request fields. Only the installation owner possesses the signing key.
func NewInstallationAuthorityWriter(db *sql.DB, installation string, database reg.DatabaseIdentity, issuer ed25519.PublicKey) (*InstallationAuthorityWriter, error) {
	if db == nil || !regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`).MatchString(installation) || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(database.ServerUUID) || !regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(database.Database) || len(issuer) != ed25519.PublicKeySize {
		return nil, ErrAuthorityWrite
	}
	return &InstallationAuthorityWriter{db, installation, database, append(ed25519.PublicKey(nil), issuer...)}, nil
}

var authorityHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var authorityVersion = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func authorityExact(s string) bool {
	return authorityVersion.MatchString(s) && s != "latest" && s != "current" && s != "default"
}
func authoritySource(s reg.SourceRecord) bool {
	return s.SourceID != "" && len(s.SourceID) <= 256 && s.RecordID != "" && len(s.RecordID) <= 256 && authorityExact(s.RecordVersion) && authorityHash.MatchString(s.ContentSHA256)
}

// decodeOwnerRecord also accepts revoked and expired records for history and
// invalidation. Only a new active record must have a currently usable window.
func decodeOwnerRecord(raw, sig []byte, key ed25519.PublicKey) (OriginalRecord, error) {
	var r OriginalRecord
	if len(raw) == 0 || len(raw) > 65536 || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte("system-backup-original-kek.v1\x00"), raw...), sig) {
		return r, ErrAuthorityWrite
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return r, ErrAuthorityWrite
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || !authoritySource(r.Source) || !authorityExact(r.Revision) || r.NotBefore.IsZero() || !r.NotBefore.Before(r.Until) {
		return OriginalRecord{}, ErrAuthorityWrite
	}
	b := r.Binding
	rawBinding, _ := json.Marshal(b)
	h := sha256.Sum256(rawBinding)
	u, e := url.Parse(b.Provider.Endpoint)
	pv, pe := strconv.ParseUint(b.Key.ProviderVersion, 10, 32)
	if b.InstallationID == "" || len(b.InstallationID) > 128 || !authorityHash.MatchString(b.ConfigRef.IdentityHash) || !authorityExact(b.ConfigRef.Version) || b.Key.IdentityHash != b.ConfigRef.IdentityHash || b.Key.RegistryVersion != b.ConfigRef.Version || b.Key.Provider != "external-kms" || b.Key.ProviderKeyID == "" || len(b.Key.ProviderKeyID) > 256 || pe != nil || pv == 0 || strconv.FormatUint(pv, 10) != b.Key.ProviderVersion || e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.ContainsAny(b.Provider.Endpoint, "?#\r\n") || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`).MatchString(b.Provider.KeyName) || !authorityHash.MatchString(b.Provider.ProviderIdentityHash) || !authorityHash.MatchString(b.Provider.ScopeHash) || !authorityHash.MatchString(b.Provider.CAPEMSHA256) || !authoritySource(b.Provider.CASource) || hex.EncodeToString(h[:]) != r.Source.ContentSHA256 {
		return OriginalRecord{}, ErrAuthorityWrite
	}
	for _, ref := range []struct {
		r       reg.TypedReference
		purpose string
	}{{b.GenerateRef, "data_key_generation"}, {b.UnwrapRef, "kek_unwrap"}} {
		parsed, err := refs.DecodeSecurityReference(ref.r.RawJSON, ref.r.SHA256)
		if err != nil || parsed.Kind() != "external_kms_key" || parsed.Purpose() != ref.purpose || parsed.ProviderIdentity() != b.Provider.ProviderIdentityHash || parsed.ScopeHash() != b.Provider.ScopeHash {
			return OriginalRecord{}, ErrAuthorityWrite
		}
	}
	return r, nil
}

func ownerTransition(old, next OriginalRecord) bool {
	return reflect.DeepEqual(old.Binding, next.Binding) && old.Source.SourceID == next.Source.SourceID && old.Source.RecordID == next.Source.RecordID && old.Revision != next.Revision && (!old.GenerateRevoked || next.GenerateRevoked) && (!old.UnwrapRevoked || next.UnwrapRevoked)
}

// Put imports an independently signed installation-owner record. It never
// derives records from candidate or committed config and holds no private key.
// expectedRowVersion=0 means initial insert only. A successful write advances
// the same KEK fence used by admissions, invalidating prepared snapshots.
func (w *InstallationAuthorityWriter) Put(ctx context.Context, raw, sig []byte, expectedRowVersion uint64) (uint64, error) {
	if w == nil || w.db == nil || len(w.issuer) != ed25519.PublicKeySize || ctx == nil || ctx.Err() != nil {
		return 0, ErrAuthorityWrite
	}
	raw = append([]byte(nil), raw...)
	sig = append([]byte(nil), sig...)
	r, err := decodeOwnerRecord(raw, sig, w.issuer)
	if err != nil || r.Binding.InstallationID != w.installation || expectedRowVersion == ^uint64(0) {
		return 0, ErrAuthorityWrite
	}
	tx, err := w.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return 0, ErrAuthorityWrite
	}
	defer tx.Rollback()
	var database reg.DatabaseIdentity
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&database.ServerUUID, &database.Database, &now) != nil || database != w.database {
		return 0, ErrAuthorityWrite
	}
	if _, err = tx.ExecContext(ctx, `INSERT IGNORE INTO system_backup_v2_kek_fences(installation_id,epoch) VALUES (?,0)`, w.installation); err != nil {
		return 0, ErrAuthorityWrite
	}
	var epoch uint64
	if tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE`, w.installation).Scan(&epoch) != nil || epoch == ^uint64(0) {
		return 0, ErrAuthorityWrite
	}
	key := r.Binding.ConfigRef
	var oldRaw, oldSig []byte
	var oldVersion uint64
	err = tx.QueryRowContext(ctx, `SELECT signed_record,signature,row_version FROM system_backup_installation_kek_authority WHERE installation_id=? AND identity_hash=? AND registry_version=? FOR UPDATE`, w.installation, key.IdentityHash, key.Version).Scan(&oldRaw, &oldSig, &oldVersion)
	if errors.Is(err, sql.ErrNoRows) {
		if expectedRowVersion != 0 {
			return 0, ErrAuthorityWrite
		}
	} else if err != nil || oldVersion != expectedRowVersion || oldVersion == 0 {
		return 0, ErrAuthorityWrite
	} else {
		old, e := decodeOwnerRecord(oldRaw, oldSig, w.issuer)
		if e != nil || !ownerTransition(old, r) {
			return 0, ErrAuthorityWrite
		}
	}
	if !r.GenerateRevoked && !r.UnwrapRevoked && (now.Before(r.NotBefore) || !now.Before(r.Until)) {
		return 0, ErrAuthorityWrite
	}
	next := expectedRowVersion + 1
	h := sha256.Sum256(raw)
	digest := hex.EncodeToString(h[:])
	if _, err = tx.ExecContext(ctx, `INSERT INTO system_backup_installation_kek_authority_history(installation_id,identity_hash,registry_version,row_version,record_revision,record_sha256,signed_record,signature) VALUES (?,?,?,?,?,?,?,?)`, w.installation, key.IdentityHash, key.Version, next, r.Revision, digest, raw, sig); err != nil {
		return 0, ErrAuthorityWrite
	}
	if expectedRowVersion == 0 {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `INSERT INTO system_backup_installation_kek_authority(installation_id,identity_hash,registry_version,signed_record,signature,record_revision,record_sha256,row_version) VALUES (?,?,?,?,?,?,?,?)`, w.installation, key.IdentityHash, key.Version, raw, sig, r.Revision, digest, next)
		if err == nil {
			n, e := result.RowsAffected()
			if e != nil || n != 1 {
				return 0, ErrAuthorityWrite
			}
		}
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE system_backup_installation_kek_authority SET signed_record=?,signature=?,record_revision=?,record_sha256=?,row_version=?,updated_at=UTC_TIMESTAMP(6) WHERE installation_id=? AND identity_hash=? AND registry_version=? AND row_version=?`, raw, sig, r.Revision, digest, next, w.installation, key.IdentityHash, key.Version, expectedRowVersion)
		if err == nil {
			n, e := result.RowsAffected()
			if e != nil || n != 1 {
				return 0, ErrAuthorityWrite
			}
		}
	}
	if err != nil {
		return 0, ErrAuthorityWrite
	}
	fenceResult, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=?`, w.installation)
	if err != nil {
		return 0, ErrAuthorityWrite
	}
	if n, e := fenceResult.RowsAffected(); e != nil || n != 1 {
		return 0, ErrAuthorityWrite
	}
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil || (!r.GenerateRevoked && !r.UnwrapRevoked && (now.Before(r.NotBefore) || !now.Before(r.Until))) {
		return 0, ErrAuthorityWrite
	}
	if tx.Commit() != nil {
		return 0, ErrAuthorityCommitUnknown
	}
	var observed uint64
	var storedHash string
	if w.db.QueryRowContext(ctx, `SELECT row_version,record_sha256 FROM system_backup_installation_kek_authority WHERE installation_id=? AND identity_hash=? AND registry_version=?`, w.installation, key.IdentityHash, key.Version).Scan(&observed, &storedHash) != nil || observed != next || storedHash != digest {
		return 0, ErrAuthorityCommitUnknown
	}
	return next, nil
}
