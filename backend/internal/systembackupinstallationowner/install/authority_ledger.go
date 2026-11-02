package install

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	owner "clawreef/internal/systembackupinstallationowner"
)

func one(result sql.Result, e error) error {
	if e != nil {
		return ErrInstall
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrInstall
	}
	return nil
}
func (s *authenticatedOperator) writeHead(ctx context.Context, tx *sql.Tx, b AuthorityBundle) error {
	p := s.installer.plan
	state := "active"
	if b.SchemaVersion == RevocationBundleVersion {
		state = "revoked"
	}
	if b.Expected == (HeadCAS{}) {
		return one(tx.ExecContext(ctx, `INSERT INTO system_backup_installation_owner_heads(installation_id,enrollment_id,head_revision,head_sha256,signed_head,signature,head_state,row_version) VALUES(?,?,?,?,?,?,'active',1)`, p.Target.InstallationID, p.EnrollmentID, uint64(1), hash(b.Head), b.Head, b.HeadSignature))
	}
	return one(tx.ExecContext(ctx, `UPDATE system_backup_installation_owner_heads SET head_revision=?,head_sha256=?,signed_head=?,signature=?,head_state=?,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE installation_id=? AND enrollment_id=? AND row_version=? AND head_revision=? AND head_sha256=? AND head_state='active'`, b.Expected.HeadRevision+1, hash(b.Head), b.Head, b.HeadSignature, state, p.Target.InstallationID, p.EnrollmentID, b.Expected.HeadRowVersion, b.Expected.HeadRevision, b.Expected.HeadSHA256))
}
func validateTransition(previous currentAuthority, b AuthorityBundle) error {
	// The caller's actual SQL clock is used by nextHead at the active call
	// site. Revocation below preserves the old signed window even if expired.
	if previous.cas != b.Expected || b.Expected.State == "revoked" {
		return ErrInstall
	}
	if b.SchemaVersion == RevocationBundleVersion {
		if previous.cas.HeadRevision == 0 || previous.cas.HeadRevision == ^uint64(0) || !bytes.Equal(previous.recordRaw, b.Record) || !bytes.Equal(previous.recordSig, b.RecordSignature) {
			return ErrInstall
		}
		h := previous.head
		h.Revision++
		h.State = "revoked"
		raw, e := owner.EncodeHead(h)
		if e != nil || !bytes.Equal(raw, b.Head) {
			return ErrInstall
		}
	}
	return nil
}

// ImportCapture consumes an already frozen independently signed bundle. It
// never receives an issuer private key and never re-signs after an SQL error.
func (i *Installer) ImportCapture(ctx context.Context, password []byte, enrollment EnrollmentPin, raw []byte, rawSHA string, files RequestFiles) (AuthorityReceipt, error) {
	var zero AuthorityReceipt
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	b, r, _, e := s.decodeBundle(raw, rawSHA, enrollment)
	if e != nil || b.SchemaVersion != AuthorityBundleVersion {
		return zero, ErrInstall
	}
	before, now, e := snapshot(ctx, s)
	if e != nil {
		return zero, e
	}
	if exactCommitted(before, b) {
		return s.receipt(before, true), nil
	}
	if before.cas != b.Expected {
		return zero, ErrInstall
	}
	request, e := readRequest(i, files)
	if e != nil {
		return zero, e
	}
	defer request.observer.Close()
	filePins, e := canonical(files)
	if e != nil || hash(filePins) != b.RequestFilesSHA256 || !requestWindow(r, request, now) || owner.VerifyInstallationRequest(b.Record, b.RecordSignature, b.Pin, request.grant, request.config) != nil {
		return zero, ErrInstall
	}
	observation, e := owner.ObserveInstallationCapture(ctx, b.Record, b.RecordSignature, b.Pin, request.grant, request.config, request.observer)
	if e != nil {
		return zero, ErrInstall
	}
	if s.authority(ctx, enrollment) != nil || request.recheck(i) != nil {
		return zero, ErrInstall
	}
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	now, e = s.lockAdmin(ctx, tx)
	if e != nil {
		return zero, e
	}
	locked, e := s.current(ctx, tx, true)
	if e != nil {
		return zero, e
	}
	if exactCommitted(locked, b) {
		if _, e = s.lockAdmin(ctx, tx); e != nil {
			return zero, e
		}
		return s.receipt(locked, true), nil
	}
	if validateTransition(locked, b) != nil {
		return zero, ErrInstall
	}
	h, e := nextHead(locked, r, now)
	if e != nil {
		return zero, e
	}
	h.RecordSHA256 = hash(b.Record)
	expectedHead, e := owner.EncodeHead(h)
	if e != nil || !bytes.Equal(expectedHead, b.Head) {
		return zero, ErrInstall
	}
	var existing string
	e = tx.QueryRowContext(ctx, `SELECT record_sha256 FROM system_backup_installation_owner_grants WHERE installation_id=? AND enrollment_id=? AND grant_id=? AND record_revision=? FOR UPDATE`, i.plan.Target.InstallationID, i.plan.EnrollmentID, r.GrantID, r.Revision).Scan(&existing)
	if !errors.Is(e, sql.ErrNoRows) {
		return zero, ErrInstall
	}
	if s.writeHead(ctx, tx, b) != nil {
		return zero, ErrInstall
	}
	if one(tx.ExecContext(ctx, `INSERT INTO system_backup_installation_owner_grants(installation_id,enrollment_id,grant_id,record_revision,record_sha256,signed_record,signature,grant_state,row_version) VALUES(?,?,?,?,?,?,?,'active',1)`, i.plan.Target.InstallationID, i.plan.EnrollmentID, r.GrantID, r.Revision, hash(b.Record), b.Record, b.RecordSignature)) != nil {
		return zero, ErrInstall
	}
	final, e := s.current(ctx, tx, true)
	if e != nil || !exactCommitted(final, b) {
		return zero, ErrInstall
	}
	if request.checkPinnedFiles() != nil {
		return zero, ErrInstall
	}
	now, e = s.lockAdmin(ctx, tx)
	if e != nil || !requestWindow(r, request, now) || observation.Check(ctx, now, hash(b.Record)) != nil || locked.cas.HeadRevision > 0 && (now.Before(locked.head.NotBefore) || !now.Before(locked.head.Until)) {
		return zero, ErrInstall
	}
	if tx.Commit() != nil {
		return zero, ErrCommitUnknown
	}
	return s.confirmCommitted(ctx, b, false)
}

func (s *authenticatedOperator) confirmCommitted(ctx context.Context, b AuthorityBundle, replayed bool) (AuthorityReceipt, error) {
	c, _, e := snapshot(ctx, s)
	if e != nil || !exactCommitted(c, b) || !s.live(ctx) {
		return AuthorityReceipt{}, ErrCommitUnknown
	}
	return s.receipt(c, replayed), nil
}

// Resolve only reads the exact original result. It does no provider I/O,
// signing, renewal, import, rollback of authority or successful-row repair.
func (i *Installer) Resolve(ctx context.Context, password []byte, enrollment EnrollmentPin, raw []byte, rawSHA string) (AuthorityReceipt, error) {
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return AuthorityReceipt{}, ErrInstall
	}
	b, _, _, e := s.decodeBundle(raw, rawSHA, enrollment)
	if e != nil {
		return AuthorityReceipt{}, ErrInstall
	}
	return s.confirmCommitted(ctx, b, true)
}
