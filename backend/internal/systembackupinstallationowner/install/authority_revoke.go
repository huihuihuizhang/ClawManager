package install

import (
	"context"
	"crypto/ed25519"
	"database/sql"

	owner "clawreef/internal/systembackupinstallationowner"
)

// IssueRevocation preserves original record/head windows and signatures. A
// revoked head is terminal here; no issuer command reactivates that enrollment.
func (i *Installer) IssueRevocation(ctx context.Context, password []byte, enrollment EnrollmentPin, issuerKey []byte) ([]byte, error) {
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return nil, ErrInstall
	}
	previous, _, e := snapshot(ctx, s)
	if e != nil || previous.cas.State != "active" || previous.cas.HeadRevision == 0 || previous.cas.HeadRevision == ^uint64(0) || previous.cas.HeadRowVersion == ^uint64(0) || previous.cas.GrantRowVersion == ^uint64(0) {
		return nil, ErrInstall
	}
	key, e := s.privateKey(issuerKey)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	h := previous.head
	h.Revision++
	h.State = "revoked"
	head, e := owner.EncodeHead(h)
	if e != nil {
		return nil, ErrInstall
	}
	signature := ed25519.Sign(key, append([]byte(owner.HeadDomain), head...))
	if s.authority(ctx, enrollment) != nil {
		return nil, ErrInstall
	}
	again, _, e := snapshot(ctx, s)
	if e != nil || again.cas != previous.cas || !s.live(ctx) {
		return nil, ErrInstall
	}
	return encodeBundle(AuthorityBundle{SchemaVersion: RevocationBundleVersion, PlanSHA256: i.planHash, Enrollment: enrollment, Expected: previous.cas, Pin: s.pinFor(previous.record, previous.cas.GrantSHA256, h.Revision), Record: previous.recordRaw, RecordSignature: previous.recordSig, Head: head, HeadSignature: signature})
}

// ImportRevocation takes no private key and requires no provider to be healthy
// or reachable. It authenticates the current original operator and atomically
// revokes the exact original head/grant without resetting or renewing either.
func (i *Installer) ImportRevocation(ctx context.Context, password []byte, enrollment EnrollmentPin, raw []byte, rawSHA string) (AuthorityReceipt, error) {
	var zero AuthorityReceipt
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	b, r, _, e := s.decodeBundle(raw, rawSHA, enrollment)
	if e != nil || b.SchemaVersion != RevocationBundleVersion || b.RequestFilesSHA256 != "" {
		return zero, ErrInstall
	}
	before, _, e := snapshot(ctx, s)
	if e != nil {
		return zero, e
	}
	if exactCommitted(before, b) {
		return s.receipt(before, true), nil
	}
	if validateTransition(before, b) != nil {
		return zero, ErrInstall
	}
	if s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	if _, e = s.lockAdmin(ctx, tx); e != nil {
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
	if validateTransition(locked, b) != nil || s.writeHead(ctx, tx, b) != nil {
		return zero, ErrInstall
	}
	if one(tx.ExecContext(ctx, `UPDATE system_backup_installation_owner_grants SET grant_state='revoked',row_version=row_version+1 WHERE installation_id=? AND enrollment_id=? AND grant_id=? AND record_revision=? AND row_version=? AND record_sha256=? AND grant_state='active'`, i.plan.Target.InstallationID, i.plan.EnrollmentID, r.GrantID, r.Revision, b.Expected.GrantRowVersion, b.Expected.GrantSHA256)) != nil {
		return zero, ErrInstall
	}
	final, e := s.current(ctx, tx, true)
	if e != nil || !exactCommitted(final, b) {
		return zero, ErrInstall
	}
	if _, e = s.lockAdmin(ctx, tx); e != nil {
		return zero, e
	}
	if tx.Commit() != nil {
		return zero, ErrCommitUnknown
	}
	return s.confirmCommitted(ctx, b, false)
}
