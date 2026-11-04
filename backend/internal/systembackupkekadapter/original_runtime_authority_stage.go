package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"reflect"
	"sort"
	"time"

	kms "clawreef/internal/systembackupkms"
)

type OriginalRuntimeCapabilityImport struct {
	Raw       []byte
	Pin       ProviderCapabilityPin
	Operation kms.Operation
}

// First-install-only transaction hook for the original authenticated installer.
// Uses the SAME original mapping decoder and capability signature validator as
// existing readers/writer. It never commits, replaces an existing mapping,
// creates a KEK binding or interprets file hashes as native permission.
func (w *InstallationAuthorityWriter) StageInitialRuntimeAuthorities(ctx context.Context, tx *sql.Tx, raw, signature []byte, capabilities []OriginalRuntimeCapabilityImport, now time.Time) error {
	if w == nil || tx == nil || ctx == nil || ctx.Err() != nil || len(capabilities) != 3 {
		return ErrAuthorityWrite
	}
	raw = bytes.Clone(raw)
	signature = bytes.Clone(signature)
	r, e := decodeOwnerRecord(raw, signature, w.issuer)
	if e != nil || r.Binding.InstallationID != w.installation || r.GenerateRevoked || r.UnwrapRevoked || now.Before(r.NotBefore) || !now.Before(r.Until) {
		return ErrAuthorityWrite
	}
	var sqlNow time.Time
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&server, &database, &sqlNow) != nil || server != w.database.ServerUUID || database != w.database.Database || sqlNow.Before(now) || !sqlNow.Before(r.Until) {
		return ErrAuthorityWrite
	}
	records := append([]OriginalRuntimeCapabilityImport(nil), capabilities...)
	for n := range records {
		records[n].Raw = bytes.Clone(records[n].Raw)
		records[n].Pin.Issuer = bytes.Clone(records[n].Pin.Issuer)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Pin.Source.RecordID < records[j].Pin.Source.RecordID })
	seen := map[string]bool{}
	generate, unwrap := 0, 0
	for _, c := range records {
		record, e := InspectProviderCapabilityMaterial(c.Raw, c.Pin, r.Binding, c.Operation, r.Until, sqlNow)
		if e != nil || record.Until.After(r.Until) || seen[c.Pin.Source.RecordID] {
			return ErrAuthorityWrite
		}
		seen[c.Pin.Source.RecordID] = true
		if c.Operation == kms.Generate {
			generate++
		} else if c.Operation == kms.Unwrap {
			unwrap++
		} else {
			return ErrAuthorityWrite
		}
		if !reflect.DeepEqual(record.Facts.Binding, r.Binding) {
			return ErrAuthorityWrite
		}
	}
	if generate != 1 || unwrap != 2 {
		return ErrAuthorityWrite
	}
	if _, e = tx.ExecContext(ctx, `INSERT IGNORE INTO system_backup_v2_kek_fences(installation_id,epoch) VALUES (?,0)`, w.installation); e != nil {
		return ErrAuthorityWrite
	}
	var epoch uint64
	if tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE`, w.installation).Scan(&epoch) != nil || epoch == ^uint64(0) {
		return ErrAuthorityWrite
	}
	var exists uint64
	e = tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_installation_kek_authority WHERE installation_id=? AND identity_hash=? AND registry_version=? FOR UPDATE`, w.installation, r.Binding.ConfigRef.IdentityHash, r.Binding.ConfigRef.Version).Scan(&exists)
	if e != sql.ErrNoRows {
		return ErrAuthorityWrite
	}
	digest := sha256.Sum256(raw)
	sum := hex.EncodeToString(digest[:])
	key := r.Binding.ConfigRef
	if _, e = tx.ExecContext(ctx, `INSERT INTO system_backup_installation_kek_authority_history(installation_id,identity_hash,registry_version,row_version,record_revision,record_sha256,signed_record,signature) VALUES (?,?,?,1,?,?,?,?)`, w.installation, key.IdentityHash, key.Version, r.Revision, sum, raw, signature); e != nil {
		return ErrAuthorityWrite
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO system_backup_installation_kek_authority(installation_id,identity_hash,registry_version,signed_record,signature,record_revision,record_sha256,row_version) VALUES (?,?,?,?,?,?,?,1)`, w.installation, key.IdentityHash, key.Version, raw, signature, r.Revision, sum); e != nil {
		return ErrAuthorityWrite
	}
	for _, c := range records {
		digest := sha256.Sum256(c.Raw)
		sum := hex.EncodeToString(digest[:])
		result, e := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,observed_health,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,expires_at,row_version,created_at,updated_at) VALUES (?,'system',?,'capability_snapshot','inline','none','healthy',?,?,?,'application/json','none','internal',?,1,?,?)`, c.Pin.Source.RecordID, w.installation, c.Raw, sum, len(c.Raw), r.Until, sqlNow, sqlNow)
		if e != nil {
			return ErrAuthorityWrite
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return ErrAuthorityWrite
		}
	}
	result, e := tx.ExecContext(ctx, `UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=? AND epoch=?`, w.installation, epoch)
	if e != nil {
		return ErrAuthorityWrite
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrAuthorityWrite
	}
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&sqlNow) != nil || sqlNow.Before(now) || !sqlNow.Before(r.Until) {
		return ErrAuthorityWrite
	}
	return nil
}
