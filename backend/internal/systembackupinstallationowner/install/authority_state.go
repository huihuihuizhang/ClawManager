package install

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

const AuthorityBundleVersion = "system-backup-installation-owner-capture-import.v1"
const RevocationBundleVersion = "system-backup-installation-owner-revoke-import.v1"

// HeadCAS describes actual original source rows, not a signed predecessor hash
// chain. A zero value is accepted only when the locked exact head is absent.
type HeadCAS struct {
	HeadRevision, HeadRowVersion   uint64
	HeadSHA256, GrantID            string
	GrantRevision, GrantRowVersion uint64
	GrantSHA256, State             string
}
type AuthorityBundle struct {
	SchemaVersion, PlanSHA256                    string
	Enrollment                                   EnrollmentPin
	Expected                                     HeadCAS
	RequestFilesSHA256                           string
	Pin                                          owner.TrustPin
	Record, RecordSignature, Head, HeadSignature []byte
}
type AuthorityReceipt struct {
	SchemaVersion, InstallationID, EnrollmentID, GrantID, RecordSHA256, HeadSHA256, State string
	HeadRevision, HeadRowVersion, GrantRevision, GrantRowVersion                          uint64
	Replayed                                                                              bool
}
type currentAuthority struct {
	cas                                    HeadCAS
	head                                   owner.Head
	record                                 owner.Record
	headRaw, headSig, recordRaw, recordSig []byte
}

func (s *authenticatedOperator) sameHeadIdentity(h owner.Head) bool {
	p := s.installer.plan
	return h.InstallationID == p.Target.InstallationID && h.EnrollmentID == p.EnrollmentID && h.EnrollmentRevision == p.EnrollmentRevision && h.IssuerID == p.IssuerID && h.OwnerSubject == p.OwnerUsername
}
func (s *authenticatedOperator) current(ctx context.Context, tx *sql.Tx, write bool) (currentAuthority, error) {
	var out currentAuthority
	if !s.live(ctx) || tx == nil {
		return out, ErrInstall
	}
	p := s.installer.plan
	suffix := " FOR SHARE"
	if write {
		suffix = " FOR UPDATE"
	}
	e := tx.QueryRowContext(ctx, `SELECT head_revision,head_sha256,signed_head,signature,head_state,row_version FROM system_backup_installation_owner_heads WHERE installation_id=? AND enrollment_id=?`+suffix, p.Target.InstallationID, p.EnrollmentID).Scan(&out.cas.HeadRevision, &out.cas.HeadSHA256, &out.headRaw, &out.headSig, &out.cas.State, &out.cas.HeadRowVersion)
	if errors.Is(e, sql.ErrNoRows) {
		return currentAuthority{}, nil
	}
	if e != nil || out.cas.HeadRowVersion == 0 || hash(out.headRaw) != out.cas.HeadSHA256 {
		return currentAuthority{}, ErrInstall
	}
	h, e := owner.InspectInstallationHead(out.headRaw, out.headSig, s.installer.public)
	if e != nil || !s.sameHeadIdentity(h) || h.Revision != out.cas.HeadRevision || h.State != out.cas.State {
		return currentAuthority{}, ErrInstall
	}
	out.head = h
	out.cas.GrantID = h.GrantID
	out.cas.GrantRevision = h.GrantRevision
	var grantState string
	if tx.QueryRowContext(ctx, `SELECT record_sha256,signed_record,signature,grant_state,row_version FROM system_backup_installation_owner_grants WHERE installation_id=? AND enrollment_id=? AND grant_id=? AND record_revision=?`+suffix, p.Target.InstallationID, p.EnrollmentID, h.GrantID, h.GrantRevision).Scan(&out.cas.GrantSHA256, &out.recordRaw, &out.recordSig, &grantState, &out.cas.GrantRowVersion) != nil || grantState != h.State || out.cas.GrantRowVersion == 0 || out.cas.GrantSHA256 != h.RecordSHA256 || hash(out.recordRaw) != h.RecordSHA256 || decodeExact(out.recordRaw, &out.record) != nil || !s.matchesRecord(out.record) || out.record.GrantID != h.GrantID || out.record.Revision != h.GrantRevision {
		return currentAuthority{}, ErrInstall
	}
	if _, e := owner.VerifyRecord(out.recordRaw, out.recordSig, s.pinFor(out.record, h.RecordSHA256, h.Revision)); e != nil {
		return currentAuthority{}, ErrInstall
	}
	return out, nil
}

func snapshot(ctx context.Context, s *authenticatedOperator) (currentAuthority, time.Time, error) {
	tx, e := s.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return currentAuthority{}, time.Time{}, ErrInstall
	}
	defer tx.Rollback()
	before, e := s.lockAdmin(ctx, tx)
	if e != nil {
		return currentAuthority{}, time.Time{}, e
	}
	current, e := s.current(ctx, tx, false)
	if e != nil {
		return currentAuthority{}, time.Time{}, e
	}
	after, e := s.installer.database(ctx, tx, s.until)
	if e != nil || after.Before(before) {
		return currentAuthority{}, time.Time{}, ErrInstall
	}
	if tx.Rollback() != nil {
		return currentAuthority{}, time.Time{}, ErrInstall
	}
	return current, after, nil
}

func nextHead(previous currentAuthority, r owner.Record, now time.Time) (owner.Head, error) {
	if previous.cas.HeadRevision == ^uint64(0) || previous.cas.HeadRowVersion == ^uint64(0) || previous.cas.State == "revoked" || previous.cas.HeadRevision > 0 && (now.Before(previous.head.NotBefore) || !now.Before(previous.head.Until)) {
		return owner.Head{}, ErrInstall
	}
	if r.Revision == 0 || previous.cas.HeadRevision == 0 && r.Revision != 1 || previous.cas.HeadRevision > 0 && (r.GrantID == previous.cas.GrantID && (previous.cas.GrantRevision == ^uint64(0) || r.Revision != previous.cas.GrantRevision+1) || r.GrantID != previous.cas.GrantID && r.Revision != 1) {
		return owner.Head{}, ErrInstall
	}
	return owner.Head{SchemaVersion: owner.HeadVersion, InstallationID: r.Target.InstallationID, EnrollmentID: r.EnrollmentID, IssuerID: r.IssuerID, OwnerSubject: r.Actor.OwnerSubject, EnrollmentRevision: r.EnrollmentRevision, Revision: previous.cas.HeadRevision + 1, GrantID: r.GrantID, GrantRevision: r.Revision, State: "active", NotBefore: r.NotBefore, Until: r.Until}, nil
}
func (s *authenticatedOperator) decodeBundle(raw []byte, expectedSHA string, pin EnrollmentPin) (AuthorityBundle, owner.Record, owner.Head, error) {
	var b AuthorityBundle
	var r owner.Record
	if len(raw) == 0 || len(raw) > 262144 {
		return b, r, owner.Head{}, ErrInstall
	}
	raw = bytes.Clone(raw)
	if hash(raw) != expectedSHA || decodeExact(raw, &b) != nil || (b.SchemaVersion != AuthorityBundleVersion && b.SchemaVersion != RevocationBundleVersion) || b.PlanSHA256 != s.installer.planHash || b.Enrollment != pin || decodeExact(b.Record, &r) != nil || !s.matchesRecord(r) || b.Expected.HeadRowVersion == ^uint64(0) || b.Expected.GrantRowVersion == ^uint64(0) {
		return b, r, owner.Head{}, ErrInstall
	}
	state := "active"
	if b.SchemaVersion == RevocationBundleVersion {
		state = "revoked"
	}
	h, e := owner.InspectInstallationHead(b.Head, b.HeadSignature, s.installer.public)
	if e != nil || !s.sameHeadIdentity(h) || h.State != state || h.Revision != b.Expected.HeadRevision+1 || b.Expected.HeadRevision == ^uint64(0) || h.RecordSHA256 != hash(b.Record) || h.GrantID != r.GrantID || h.GrantRevision != r.Revision || state == "active" && (!h.NotBefore.Equal(r.NotBefore) || !h.Until.Equal(r.Until)) || !samePin(b.Pin, s.pinFor(r, hash(b.Record), h.Revision)) {
		return b, r, h, ErrInstall
	}
	if _, e := owner.VerifyRecord(b.Record, b.RecordSignature, b.Pin); e != nil {
		return b, r, h, ErrInstall
	}
	return b, r, h, nil
}
func encodeBundle(b AuthorityBundle) ([]byte, error) {
	raw, e := canonical(b)
	if e != nil || len(raw) > 262144 {
		return nil, ErrInstall
	}
	return raw, nil
}
func (s *authenticatedOperator) receipt(current currentAuthority, replayed bool) AuthorityReceipt {
	p := s.installer.plan
	c := current.cas
	return AuthorityReceipt{SchemaVersion: "system-backup-installation-owner-source-result.v1", InstallationID: p.Target.InstallationID, EnrollmentID: p.EnrollmentID, GrantID: c.GrantID, RecordSHA256: c.GrantSHA256, HeadSHA256: c.HeadSHA256, State: c.State, HeadRevision: c.HeadRevision, HeadRowVersion: c.HeadRowVersion, GrantRevision: c.GrantRevision, GrantRowVersion: c.GrantRowVersion, Replayed: replayed}
}
func exactCommitted(c currentAuthority, b AuthorityBundle) bool {
	state := "active"
	grantRow := uint64(1)
	if b.SchemaVersion == RevocationBundleVersion {
		state = "revoked"
		grantRow = b.Expected.GrantRowVersion + 1
	}
	return c.cas.HeadRevision == b.Expected.HeadRevision+1 && c.cas.HeadRowVersion == b.Expected.HeadRowVersion+1 && c.cas.GrantRowVersion == grantRow && c.cas.State == state && bytes.Equal(c.headRaw, b.Head) && bytes.Equal(c.headSig, b.HeadSignature) && bytes.Equal(c.recordRaw, b.Record) && bytes.Equal(c.recordSig, b.RecordSignature)
}
