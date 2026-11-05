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

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	sec "clawreef/internal/systembackupsecurity"
)

// CheckOriginalRuntimeCapability compares an existing signed material with a
// NEW genuine observer result. It neither signs nor installs/renews a record.
func (p *ObservedVaultPermissions) CheckOriginalRuntimeCapability(raw []byte, pin ProviderCapabilityPin, binding reg.Binding, operation kms.Operation, until, now time.Time) error {
	if p == nil || p.owner == nil || p.observed.IsZero() || now.Before(p.observed) || now.Sub(p.observed) > time.Minute {
		return ErrAuthorityWrite
	}
	r, e := InspectProviderCapabilityMaterial(raw, pin, binding, operation, until, now)
	if e != nil {
		return e
	}
	want := p.generate
	if operation == kms.Unwrap {
		want = p.unwrap
	} else if operation != kms.Generate {
		return ErrAuthorityWrite
	}
	if !reflect.DeepEqual(r.Facts, want) {
		return ErrAuthorityWrite
	}
	return nil
}

// StageEnabledRuntimeCapabilities appends three genuinely newly observed
// config2 permissions beside the UNCHANGED committed original KEK mapping.
// The caller retains original local admin, head, ctx/view and normal-enable
// proof. This method commits nothing and never updates mapping/binding/grants.
func (w *InstallationAuthorityWriter) StageEnabledRuntimeCapabilities(ctx context.Context, tx *sql.Tx, raw, signature []byte, caps []OriginalRuntimeCapabilityImport, proof *sec.OriginalEnabledOnlyLineage, oldSHA, currentSHA string, formal, publisher ControllerVerifierWorkload, now time.Time) error {
	if w == nil || tx == nil || ctx == nil || ctx.Err() != nil || len(caps) != 3 || proof == nil || !proof.Matches(w.installation, oldSHA, 2, currentSHA) {
		return ErrAuthorityWrite
	}
	authorized, e := proof.AuthorizationConfigSHA256(ctx, tx)
	if e != nil || authorized != oldSHA {
		return ErrAuthorityWrite
	}
	diagnosticUntil, e := proof.OriginalDiagnosticUntil(ctx, tx)
	if e != nil {
		return ErrAuthorityWrite
	}
	mapping, e := decodeOwnerRecord(raw, signature, w.issuer)
	if e != nil || mapping.Binding.InstallationID != w.installation || mapping.GenerateRevoked || mapping.UnwrapRevoked || now.Before(mapping.NotBefore) || !now.Before(mapping.Until) || formal.ConfigVersion != 2 || formal.ConfigSHA256 != currentSHA || formal.GrantSHA256 == "" || publisher.ConfigVersion != 2 || publisher.ConfigSHA256 != currentSHA || publisher.GrantSHA256 == "" || publisher.GrantSHA256 == formal.GrantSHA256 || publisher.ControllerOwner != "public:"+publisher.PodUID || publisher.ControllerOwner == formal.ControllerOwner {
		return ErrAuthorityWrite
	}
	var database reg.DatabaseIdentity
	var sqlNow time.Time
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&database.ServerUUID, &database.Database, &sqlNow) != nil || database != w.database || sqlNow.Before(now) || !sqlNow.Before(mapping.Until) || !sqlNow.Before(diagnosticUntil) {
		return ErrAuthorityWrite
	}
	// Installation state/admin/head prefixes are already held by the real
	// owner. The existing KEK fence precedes mapping/evidence locks.
	var epoch uint64
	if tx.QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE", w.installation).Scan(&epoch) != nil || epoch == 0 || epoch == ^uint64(0) {
		return ErrAuthorityWrite
	}
	var currentRaw, currentSignature []byte
	var rowVersion uint64
	if tx.QueryRowContext(ctx, "SELECT signed_record,signature,row_version FROM system_backup_installation_kek_authority WHERE installation_id=? AND identity_hash=? AND registry_version=? FOR SHARE", w.installation, mapping.Binding.ConfigRef.IdentityHash, mapping.Binding.ConfigRef.Version).Scan(&currentRaw, &currentSignature, &rowVersion) != nil || rowVersion == 0 || !bytes.Equal(currentRaw, raw) || !bytes.Equal(currentSignature, signature) {
		return ErrAuthorityWrite
	}
	records := append([]OriginalRuntimeCapabilityImport(nil), caps...)
	sort.Slice(records, func(i, j int) bool { return records[i].Pin.Source.RecordID < records[j].Pin.Source.RecordID })
	seen := map[string]bool{}
	generate, formalUnwrap, publisherUnwrap := 0, 0, 0
	for _, c := range records {
		r, e := InspectProviderCapabilityMaterial(c.Raw, c.Pin, mapping.Binding, c.Operation, mapping.Until, sqlNow)
		if e != nil || r.Until.After(mapping.Until) || r.Until.After(diagnosticUntil) || seen[c.Pin.Source.RecordID] {
			return ErrAuthorityWrite
		}
		seen[c.Pin.Source.RecordID] = true
		if c.Operation == kms.Generate && r.Facts.Permission.ControllerVerifier == nil {
			generate++
		} else if c.Operation == kms.Unwrap && r.Facts.Permission.ControllerVerifier != nil && *r.Facts.Permission.ControllerVerifier == formal {
			formalUnwrap++
		} else if c.Operation == kms.Unwrap && r.Facts.Permission.ControllerVerifier != nil && *r.Facts.Permission.ControllerVerifier == publisher {
			publisherUnwrap++
		} else {
			return ErrAuthorityWrite
		}
	}
	if generate != 1 || formalUnwrap != 1 || publisherUnwrap != 1 {
		return ErrAuthorityWrite
	}
	for _, c := range records {
		r, e := InspectProviderCapabilityMaterial(c.Raw, c.Pin, mapping.Binding, c.Operation, mapping.Until, sqlNow)
		if e != nil {
			return ErrAuthorityWrite
		}
		sum := sha256.Sum256(c.Raw)
		result, e := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,observed_health,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,expires_at,row_version,created_at,updated_at) VALUES (?,'system',?,'capability_snapshot','inline','none','healthy',?,?,?,'application/json','none','internal',?,1,?,?)`, c.Pin.Source.RecordID, w.installation, c.Raw, hex.EncodeToString(sum[:]), len(c.Raw), r.Until, sqlNow, sqlNow)
		if e != nil {
			return ErrAuthorityWrite
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return ErrAuthorityWrite
		}
	}
	result, e := tx.ExecContext(ctx, "UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=? AND epoch=?", w.installation, epoch)
	if e != nil {
		return ErrAuthorityWrite
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrAuthorityWrite
	}
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&sqlNow) != nil || sqlNow.Before(now) || !sqlNow.Before(mapping.Until) || !sqlNow.Before(diagnosticUntil) {
		return ErrAuthorityWrite
	}
	return nil
}

// ReadEnabledRuntimeCapabilities checks exact committed rows in the caller's
// original locking view. A signed pending file alone never establishes COMMIT.
func (w *InstallationAuthorityWriter) ReadEnabledRuntimeCapabilities(ctx context.Context, tx *sql.Tx, raw, signature []byte, caps []OriginalRuntimeCapabilityImport, proof *sec.OriginalEnabledOnlyLineage, oldSHA, currentSHA string, now time.Time) error {
	if w == nil || tx == nil || ctx == nil || len(caps) != 3 || proof == nil || !proof.Matches(w.installation, oldSHA, 2, currentSHA) {
		return ErrAuthorityWrite
	}
	old, e := proof.AuthorizationConfigSHA256(ctx, tx)
	if e != nil || old != oldSHA {
		return ErrAuthorityWrite
	}
	m, e := decodeOwnerRecord(raw, signature, w.issuer)
	if e != nil || m.Binding.InstallationID != w.installation || m.GenerateRevoked || m.UnwrapRevoked || now.Before(m.NotBefore) || !now.Before(m.Until) {
		return ErrAuthorityWrite
	}
	var database reg.DatabaseIdentity
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&database.ServerUUID, &database.Database) != nil || database != w.database {
		return ErrAuthorityWrite
	}
	var epoch uint64
	if tx.QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE", w.installation).Scan(&epoch) != nil || epoch == 0 {
		return ErrAuthorityWrite
	}
	actual, actualSignature, e := (SQLOriginalReader{DB: w.db}).RecheckOriginal(ctx, tx, w.installation, m.Binding.ConfigRef)
	if e != nil || !bytes.Equal(actual, raw) || !bytes.Equal(actualSignature, signature) {
		return ErrAuthorityWrite
	}
	records := append([]OriginalRuntimeCapabilityImport(nil), caps...)
	sort.Slice(records, func(i, j int) bool { return records[i].Pin.Source.RecordID < records[j].Pin.Source.RecordID })
	seen := map[string]bool{}
	for _, c := range records {
		if seen[c.Pin.Source.RecordID] {
			return ErrAuthorityWrite
		}
		seen[c.Pin.Source.RecordID] = true
		evidence, e := readCapabilityEvidence(ctx, tx, w.installation, c.Pin, true)
		if e != nil || !bytes.Equal(evidence.raw, c.Raw) {
			return ErrAuthorityWrite
		}
		r, e := authenticateProviderCapability(evidence, c.Pin, m.Binding, c.Operation, now)
		if e != nil || !evidence.until.Equal(r.Until) {
			return ErrAuthorityWrite
		}
	}
	return nil
}
