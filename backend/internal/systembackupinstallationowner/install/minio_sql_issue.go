package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
)

// IssueMinIOSQLInstall signs ORIGINAL scoped metadata after actual existing
// operator/enrollment auth and current original Kubernetes binding. It does
// not create SQL rows or assert native operation capability. Fresh bootstrap
// still requires its real lock-free permission/protocol observation.
func (i *Installer) IssueMinIOSQLInstall(ctx context.Context, password []byte, enrollment EnrollmentPin, intentFile, intentSHA string, issuerPrivate []byte) ([]byte, error) {
	raw, e := ReadPrivateFile(intentFile, 262144)
	if e != nil || hash(raw) != intentSHA {
		return nil, ErrInstall
	}
	var intent MinIOSQLInstallIntent
	if decodeExact(raw, &intent) != nil || intent.Version != MinIOSQLInstallIntentVersion || len(intent.References) != 5 {
		return nil, ErrInstall
	}
	s, e := i.authenticate(ctx, password)
	if e != nil || s.minioSQLPin(ctx, enrollment, intent.Pin) != nil || !minioSQLActor(s, intent.Grant) {
		return nil, ErrInstall
	}
	_, absent, e := minioSQLRead(ctx, s, intent.Pin)
	if e != nil || !absent {
		return nil, ErrInstall
	}
	now, e := i.database(ctx, i.db, s.until)
	if e != nil || now.Before(intent.Grant.NotBefore) || !now.Before(intent.Grant.Until) || s.minioSQLKubernetes(ctx, intent.Grant, intent.References, now) != nil {
		return nil, ErrInstall
	}
	key, e := s.privateKey(issuerPrivate)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(key)
	b := ma.SQLBundle{Version: ma.SQLBundleVersion, Action: ma.SQLActionInstall, PlanSHA256: ma.Digest(i.planHash), EnrollmentDocumentSHA256: ma.Digest(enrollment.DocumentSHA256)}
	for n, purpose := range minioSQLPurposes() {
		r := intent.References[n]
		if r.Reference.Purpose != purpose {
			return nil, ErrInstall
		}
		record, e := ma.EncodeSQLReference(r)
		if e != nil {
			return nil, ErrInstall
		}
		b.References = append(b.References, ma.SQLSignedReference{Purpose: purpose, Record: record, Signature: ed25519.Sign(key, append([]byte(ma.SQLReferenceDomain), record...))})
	}
	b.Grant, e = ma.EncodeSQLGrant(intent.Grant)
	if e != nil {
		return nil, ErrInstall
	}
	b.GrantSignature = ed25519.Sign(key, append([]byte(ma.SQLGrantDomain), b.Grant...))
	g := intent.Grant
	head := ma.SQLHead{Version: ma.SQLHeadVersion, AuthorityID: g.AuthorityID, Target: g.Target, Enrollment: g.Enrollment, HeadRevision: 1, PermissionEpoch: g.PermissionEpoch, CurrentGrantID: g.GrantID, CurrentGrantRevision: g.RecordRevision, GrantSHA256: ma.Digest(hash(b.Grant)), ReferenceSetSHA256: g.ReferenceSetSHA256, State: ma.StateActive, NotBefore: g.NotBefore, Until: g.Until}
	b.Head, e = ma.EncodeSQLHead(head)
	if e != nil {
		return nil, ErrInstall
	}
	b.HeadSignature = ed25519.Sign(key, append([]byte(ma.SQLHeadDomain), b.Head...))
	if _, e = ma.VerifySQLRecordSet(intent.Pin, b.Grant, b.GrantSignature, b.Head, b.HeadSignature, b.References); e != nil {
		return nil, ErrInstall
	}
	again, e := ReadPrivateFile(intentFile, 262144)
	if e != nil || !bytes.Equal(raw, again) || hash(again) != intentSHA || s.minioSQLPin(ctx, enrollment, intent.Pin) != nil {
		return nil, ErrInstall
	}
	now, e = i.database(ctx, i.db, s.until)
	if e != nil || now.Before(g.NotBefore) || !now.Before(g.Until) || s.minioSQLKubernetes(ctx, g, intent.References, now) != nil {
		return nil, ErrInstall
	}
	// Final actual admin/hash/current-domain snapshot after signing and
	// Kubernetes tails. No signing or Kubernetes request runs under this tx.
	if _, absent, e := minioSQLRead(ctx, s, intent.Pin); e != nil || !absent {
		return nil, ErrInstall
	}
	return ma.EncodeSQLBundle(b)
}

// IssueMinIOSQLRevocation freezes a terminal signed SQL-head transition and
// exact original seven-row CAS tuple. No MinIO probe/health or new native
// permission is required to revoke. Original operator/enrollment auth remains.
func (i *Installer) IssueMinIOSQLRevocation(ctx context.Context, password []byte, enrollment EnrollmentPin, pin ma.SQLTrustPin, issuerPrivate []byte) ([]byte, error) {
	pin.IssuerPublic = bytes.Clone(pin.IssuerPublic)
	s, e := i.authenticate(ctx, password)
	if e != nil || s.minioSQLPin(ctx, enrollment, pin) != nil {
		return nil, ErrInstall
	}
	snapshot, absent, e := minioSQLRead(ctx, s, pin)
	if e != nil || absent {
		return nil, ErrInstall
	}
	expected, _, e := snapshot.Comparison()
	if e != nil || expected.State != ma.StateActive || !minioSQLCanIncrement(expected) {
		return nil, ErrInstall
	}
	g, h, _, e := snapshot.Declarations()
	if e != nil || !minioSQLActor(s, g) {
		return nil, ErrInstall
	}
	grant, gs, _, _, refs, e := snapshot.SignedRecords()
	if e != nil {
		return nil, ErrInstall
	}
	key, e := s.privateKey(issuerPrivate)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(key)
	h.HeadRevision++
	h.State = ma.StateRevoked
	head, e := ma.EncodeSQLHead(h)
	if e != nil {
		return nil, ErrInstall
	}
	b := ma.SQLBundle{Version: ma.SQLBundleVersion, Action: ma.SQLActionRevoke, PlanSHA256: ma.Digest(i.planHash), EnrollmentDocumentSHA256: ma.Digest(enrollment.DocumentSHA256), Expected: expected, Grant: grant, GrantSignature: gs, Head: head, HeadSignature: ed25519.Sign(key, append([]byte(ma.SQLHeadDomain), head...)), References: refs}
	if s.minioSQLPin(ctx, enrollment, pin) != nil {
		return nil, ErrInstall
	}
	again, absent, e := minioSQLRead(ctx, s, pin)
	if e != nil || absent {
		return nil, ErrInstall
	}
	current, _, e := again.Comparison()
	if e != nil || !minioSQLSameExpected(current, expected) {
		return nil, ErrInstall
	}
	return ma.EncodeSQLBundle(b)
}

func minioSQLCanIncrement(e ma.SQLExpected) bool {
	const maximum = uint64(9007199254740991)
	if e.HeadRevision != 1 || e.HeadRowVersion == 0 || e.HeadRowVersion >= maximum || e.GrantRowVersion == 0 || e.GrantRowVersion >= maximum || len(e.ReferenceRows) != 5 {
		return false
	}
	for _, v := range e.ReferenceRows {
		if v.RowVersion == 0 || v.RowVersion >= maximum {
			return false
		}
	}
	return true
}

// SaveMinIOSQLBundle exclusively writes public signed transport bytes. A
// frozen bundle is not a startup trust file or physical readiness receipt.
func SaveMinIOSQLBundle(directory string, raw []byte) error {
	if _, e := ma.DecodeSQLBundle(raw, ma.Digest(hash(raw))); e != nil {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{"minio-sql-authority.bundle.json": raw})
}

// SQL time, not an invented renewed lease, is supplied by current locked SQL.
func minioSQLOriginalWindow(snapshot *ma.SQLCurrentSnapshot, now time.Time) error {
	if snapshot == nil || snapshot.RequireCurrent(now) != nil {
		return ErrInstall
	}
	return nil
}
