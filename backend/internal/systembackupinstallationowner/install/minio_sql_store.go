package install

import (
	"bytes"
	"context"
	"database/sql"
	"reflect"

	ma "clawreef/internal/systembackupminioauthority"
)

type MinIOSQLReceipt struct {
	Version, State, InstallationID, EnrollmentID, AuthorityID string
	GrantSHA256, HeadSHA256, ReferenceSetSHA256               ma.Digest
	Comparison                                                ma.SQLExpected
	Replayed                                                  bool
}

func minioSQLSameExpected(a, b ma.SQLExpected) bool { return reflect.DeepEqual(a, b) }

func minioSQLReceipt(snapshot *ma.SQLCurrentSnapshot, pin ma.SQLTrustPin, replayed bool) (MinIOSQLReceipt, error) {
	e, _, err := snapshot.Comparison()
	if err != nil {
		return MinIOSQLReceipt{}, ErrInstall
	}
	return MinIOSQLReceipt{Version: "original-minio-sql-metadata-receipt.v1", State: e.State, InstallationID: pin.Target.InstallationID, EnrollmentID: pin.Enrollment.ID, AuthorityID: pin.AuthorityID, GrantSHA256: e.GrantSHA256, HeadSHA256: e.HeadSHA256, ReferenceSetSHA256: e.ReferenceSetSHA256, Comparison: e, Replayed: replayed}, nil
}

// ImportMinIOSQLAuthority atomically creates or terminally revokes exactly
// seven original metadata rows. It takes NO private key/native Passed/source
// callback and never touches config/task/history. SQL is revocation authority.
// This metadata receipt is not native permission/capability/backup readiness.
func (i *Installer) ImportMinIOSQLAuthority(ctx context.Context, password []byte, enrollment EnrollmentPin, pin ma.SQLTrustPin, raw []byte, sha string) (MinIOSQLReceipt, error) {
	var zero MinIOSQLReceipt
	pin.IssuerPublic = bytes.Clone(pin.IssuerPublic)
	s, e := i.authenticate(ctx, password)
	if e != nil {
		return zero, ErrInstall
	}
	b, g, h, refs, e := minioSQLBundle(ctx, s, enrollment, pin, raw, sha)
	if e != nil {
		return zero, e
	}
	before, absent, e := minioSQLRead(ctx, s, pin)
	if e != nil {
		return zero, e
	}
	if !absent && minioSQLExact(before, b, h) {
		return minioSQLReceipt(before, pin, true)
	}
	if b.Action == ma.SQLActionInstall {
		if !absent {
			return zero, ErrInstall
		}
		now, e := i.database(ctx, i.db, s.until)
		if e != nil || now.Before(g.NotBefore) || !now.Before(g.Until) || s.minioSQLKubernetes(ctx, g, refs, now) != nil {
			return zero, ErrInstall
		}
	} else {
		if absent || !minioSQLCanIncrement(b.Expected) || minioSQLRevokeTransition(before, b, h) != nil {
			return zero, ErrInstall
		}
	}
	if s.minioSQLPin(ctx, enrollment, pin) != nil {
		return zero, ErrInstall
	}
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	now, e := s.lockAdmin(ctx, tx)
	if e != nil {
		return zero, ErrInstall
	}
	absent, e = minioSQLLock(ctx, tx, pin, true)
	if e != nil {
		return zero, e
	}
	if !absent {
		locked, e := ma.ReadSQLCurrentForInstaller(ctx, tx, pin)
		if e != nil {
			return zero, ErrInstall
		}
		if minioSQLExact(locked, b, h) {
			return minioSQLReceipt(locked, pin, true)
		}
		if b.Action != ma.SQLActionRevoke || minioSQLRevokeTransition(locked, b, h) != nil {
			return zero, ErrInstall
		}
	} else if b.Action != ma.SQLActionInstall {
		return zero, ErrInstall
	}
	if b.Action == ma.SQLActionInstall {
		if now.Before(g.NotBefore) || !now.Before(g.Until) || minioSQLInsert(ctx, tx, pin, b, g, h, refs) != nil {
			return zero, ErrInstall
		}
	} else if minioSQLRevokeRows(ctx, tx, pin, b) != nil {
		return zero, ErrInstall
	}
	final, e := ma.ReadSQLCurrentForInstaller(ctx, tx, pin)
	if e != nil || !minioSQLExact(final, b, h) {
		return zero, ErrInstall
	}
	now, e = s.lockAdmin(ctx, tx)
	if e != nil || b.Action == ma.SQLActionInstall && minioSQLOriginalWindow(final, now) != nil {
		return zero, ErrInstall
	}
	if tx.Commit() != nil {
		return zero, ErrCommitUnknown
	}
	committed, missing, e := minioSQLRead(ctx, s, pin)
	if e != nil || missing || !minioSQLExact(committed, b, h) {
		return zero, ErrCommitUnknown
	}
	if s.minioSQLPin(ctx, enrollment, pin) != nil {
		return zero, ErrCommitUnknown
	}
	if b.Action == ma.SQLActionInstall {
		_, now, e := committed.Comparison()
		if e != nil || s.minioSQLKubernetes(ctx, g, refs, now) != nil {
			return zero, ErrCommitUnknown
		}
	}
	// Close the post-commit owner/source tail with a fresh ORIGINAL SQL
	// snapshot. A concurrent revoke or elapsed initial window is not success.
	committed, missing, e = minioSQLRead(ctx, s, pin)
	if e != nil || missing || !minioSQLExact(committed, b, h) {
		return zero, ErrCommitUnknown
	}
	if b.Action == ma.SQLActionInstall {
		_, now, e := committed.Comparison()
		if e != nil || minioSQLOriginalWindow(committed, now) != nil {
			return zero, ErrCommitUnknown
		}
	}
	return minioSQLReceipt(committed, pin, false)
}

// ResolveMinIOSQLAuthority reads only exact original committed tuple/bytes.
// It never signs, mutates, probes MinIO, renews windows or repairs mixed state.
func (i *Installer) ResolveMinIOSQLAuthority(ctx context.Context, password []byte, enrollment EnrollmentPin, pin ma.SQLTrustPin, raw []byte, sha string) (MinIOSQLReceipt, error) {
	var zero MinIOSQLReceipt
	pin.IssuerPublic = bytes.Clone(pin.IssuerPublic)
	s, e := i.authenticate(ctx, password)
	if e != nil {
		return zero, ErrInstall
	}
	b, _, h, _, e := minioSQLBundle(ctx, s, enrollment, pin, raw, sha)
	if e != nil {
		return zero, e
	}
	current, absent, e := minioSQLRead(ctx, s, pin)
	if e != nil || absent || !minioSQLExact(current, b, h) {
		return zero, ErrInstall
	}
	return minioSQLReceipt(current, pin, true)
}

func minioSQLRevokeTransition(current *ma.SQLCurrentSnapshot, b ma.SQLBundle, h ma.SQLHead) error {
	e, _, err := current.Comparison()
	if err != nil || !minioSQLSameExpected(e, b.Expected) || e.State != ma.StateActive || !minioSQLCanIncrement(e) {
		return ErrInstall
	}
	_, old, _, err := current.Declarations()
	if err != nil {
		return ErrInstall
	}
	old.HeadRevision++
	old.State = ma.StateRevoked
	want, err := ma.EncodeSQLHead(old)
	if err != nil || !bytes.Equal(want, b.Head) || !reflect.DeepEqual(old, h) {
		return ErrInstall
	}
	g, gs, _, _, refs, err := current.SignedRecords()
	if err != nil || !bytes.Equal(g, b.Grant) || !bytes.Equal(gs, b.GrantSignature) || !reflect.DeepEqual(refs, b.References) {
		return ErrInstall
	}
	return nil
}

func minioSQLInsert(ctx context.Context, tx *sql.Tx, p ma.SQLTrustPin, b ma.SQLBundle, g ma.SQLGrant, h ma.SQLHead, refs []ma.SQLReferenceRecord) error {
	if one(tx.ExecContext(ctx, `INSERT INTO system_backup_minio_owner_heads(installation_id,enrollment_id,authority_id,head_revision,permission_epoch,current_grant_id,current_grant_revision,head_sha256,signed_head,signature,head_state,row_version) VALUES(?,?,?,?,?,?,?,?,?,?,'active',1)`, p.Target.InstallationID, p.Enrollment.ID, p.AuthorityID, h.HeadRevision, h.PermissionEpoch, h.CurrentGrantID, h.CurrentGrantRevision, string(ma.Digest(hash(b.Head))), b.Head, b.HeadSignature)) != nil {
		return ErrInstall
	}
	if one(tx.ExecContext(ctx, `INSERT INTO system_backup_minio_owner_grants(installation_id,enrollment_id,authority_id,grant_id,record_revision,permission_epoch,record_sha256,signed_record,signature,grant_state,row_version) VALUES(?,?,?,?,?,?,?,?,?,'active',1)`, p.Target.InstallationID, p.Enrollment.ID, p.AuthorityID, g.GrantID, g.RecordRevision, g.PermissionEpoch, string(ma.Digest(hash(b.Grant))), b.Grant, b.GrantSignature)) != nil {
		return ErrInstall
	}
	for n, signed := range b.References {
		r := refs[n].Reference
		if one(tx.ExecContext(ctx, `INSERT INTO system_backup_minio_owner_refs(installation_id,enrollment_id,authority_id,grant_id,record_revision,purpose,descriptor_sha256,provider_identity_hash,scope_hash,identity_hash,identity_version,ref_sha256,signed_ref,signature,ref_state,row_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',1)`, p.Target.InstallationID, p.Enrollment.ID, p.AuthorityID, g.GrantID, g.RecordRevision, string(signed.Purpose), string(r.DescriptorSHA256), string(r.ProviderIdentityHash), string(r.ScopeSHA256), string(r.IdentityHash), r.IdentityVersion, hash(signed.Record), signed.Record, signed.Signature)) != nil {
			return ErrInstall
		}
	}
	return nil
}

func minioSQLRevokeRows(ctx context.Context, tx *sql.Tx, p ma.SQLTrustPin, b ma.SQLBundle) error {
	e := b.Expected
	if one(tx.ExecContext(ctx, `UPDATE system_backup_minio_owner_heads SET head_revision=?,head_sha256=?,signed_head=?,signature=?,head_state='revoked',row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND head_revision=? AND permission_epoch=? AND current_grant_id=? AND current_grant_revision=? AND head_sha256=? AND row_version=? AND head_state='active'`, e.HeadRevision+1, hash(b.Head), b.Head, b.HeadSignature, p.Target.InstallationID, p.Enrollment.ID, p.AuthorityID, e.HeadRevision, e.PermissionEpoch, e.CurrentGrantID, e.CurrentGrantRevision, string(e.HeadSHA256), e.HeadRowVersion)) != nil {
		return ErrInstall
	}
	if one(tx.ExecContext(ctx, `UPDATE system_backup_minio_owner_grants SET grant_state='revoked',row_version=row_version+1 WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND grant_id=? AND record_revision=? AND permission_epoch=? AND record_sha256=? AND row_version=? AND grant_state='active'`, p.Target.InstallationID, p.Enrollment.ID, p.AuthorityID, e.CurrentGrantID, e.CurrentGrantRevision, e.PermissionEpoch, string(e.GrantSHA256), e.GrantRowVersion)) != nil {
		return ErrInstall
	}
	for _, r := range e.ReferenceRows {
		if one(tx.ExecContext(ctx, `UPDATE system_backup_minio_owner_refs SET ref_state='revoked',row_version=row_version+1 WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND grant_id=? AND record_revision=? AND purpose=? AND ref_sha256=? AND row_version=? AND ref_state='active'`, p.Target.InstallationID, p.Enrollment.ID, p.AuthorityID, e.CurrentGrantID, e.CurrentGrantRevision, string(r.Purpose), string(r.SHA256), r.RowVersion)) != nil {
			return ErrInstall
		}
	}
	return nil
}
