package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"

	owner "clawreef/internal/systembackupinstallationowner"
)

// Read the exact ORIGINAL installed bytes under real authenticated installer
// admin -> purpose head -> selected grant. This is a separate signer domain;
// no capture/task/provider state or broad consumer privilege is borrowed.
func signingResourceOriginal(ctx context.Context, s *authenticatedOperator, p owner.SigningResourceTrustPin, b SigningResourceBundle) (owner.SigningResourceCAS, error) {
	var c owner.SigningResourceCAS
	if s == nil || !s.live(ctx) {
		return c, ErrInstall
	}
	tx, e := s.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return c, ErrInstall
	}
	defer tx.Rollback()
	before, e := s.lockAdmin(ctx, tx)
	if e != nil {
		return c, ErrInstall
	}
	var hr, hs, gr, gs []byte
	var epoch, revision uint64
	if tx.QueryRowContext(ctx, owner.SigningResourceHeadReadSQL, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose).Scan(&c.HeadRevision, &epoch, &c.GrantID, &revision, &c.HeadSHA256, &hr, &hs, &c.State, &c.HeadRowVersion) != nil || c.HeadRowVersion < 1 || c.HeadRowVersion >= 9007199254740991 || c.State != "active" || c.HeadSHA256 != hash(hr) {
		return c, ErrInstall
	}
	h, e := owner.InspectSigningResourceHead(hr, hs, p)
	if e != nil || h.HeadRevision != c.HeadRevision || h.PermissionEpoch != epoch || h.CurrentGrantID != c.GrantID || h.CurrentGrantRevision != revision || h.State != c.State || !bytes.Equal(hr, b.Head) || !bytes.Equal(hs, b.HeadSignature) || before.Before(h.NotBefore) || !before.Before(h.Until) {
		return c, ErrInstall
	}
	var state string
	if tx.QueryRowContext(ctx, owner.SigningResourceGrantReadSQL, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose, p.GrantID, p.GrantRevision).Scan(&c.PermissionEpoch, &c.GrantSHA256, &gr, &gs, &state, &c.GrantRowVersion) != nil || c.GrantRowVersion < 1 || c.GrantRowVersion >= 9007199254740991 || c.PermissionEpoch != epoch || state != c.State || c.GrantSHA256 != p.GrantSHA256 || !bytes.Equal(gr, b.Grant) || !bytes.Equal(gs, b.GrantSignature) {
		return c, ErrInstall
	}
	g, e := owner.InspectSigningResourceGrant(gr, gs, p)
	if e != nil || !g.NotBefore.Equal(h.NotBefore) || !g.Until.Equal(h.Until) {
		return c, ErrInstall
	}
	c.GrantRevision = revision
	after, e := s.lockAdmin(ctx, tx)
	if e != nil || after.Before(before) || after.Before(g.NotBefore) || !after.Before(g.Until) {
		return c, ErrInstall
	}
	return c, nil
}

// Provider-independent original revocation: preserve the exact signed grant
// and original window/epoch; freeze only a terminal head revision 1 -> 2.
// This produces inert transport; D's importer must do exact exclusive CAS,
// commit-unknown resolution and final readback. No SQL write occurs here.
func (i *Installer) IssueSigningResourceRevocation(ctx context.Context, password []byte, enrollment EnrollmentPin, p owner.SigningResourceTrustPin, bundleFile, bundleSHA string, issuerPrivate []byte) ([]byte, error) {
	raw, e := ReadPrivateFile(bundleFile, 262144)
	if e != nil {
		return nil, ErrInstall
	}
	b, g, h, e := signingResourceBundle(raw, bundleSHA, p)
	if e != nil || b.Action != "install" {
		return nil, ErrInstall
	}
	s, e := i.authenticate(ctx, password)
	if e != nil || s.signingResourcePin(ctx, enrollment, p) != nil || b.PlanSHA256 != i.planHash || b.EnrollmentDocumentSHA256 != enrollment.DocumentSHA256 {
		return nil, ErrInstall
	}
	expected, e := signingResourceOriginal(ctx, s, p, b)
	if e != nil {
		return nil, ErrInstall
	}
	key, e := s.privateKey(issuerPrivate)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(key)
	h.HeadRevision, h.State = 2, "revoked"
	head, e := owner.EncodeSigningResourceHead(h)
	if e != nil {
		return nil, ErrInstall
	}
	revoked := SigningResourceBundle{Version: SigningResourceBundleVersion, Action: "revoke", PlanSHA256: g.PlanSHA256, EnrollmentDocumentSHA256: g.EnrollmentDocumentSHA256, Expected: expected, Grant: bytes.Clone(b.Grant), GrantSignature: bytes.Clone(b.GrantSignature), Head: head, HeadSignature: ed25519.Sign(key, append([]byte(owner.SigningResourceHeadDomain), head...))}
	encoded, e := canonical(revoked)
	if e != nil {
		return nil, ErrInstall
	}
	if _, _, _, e := signingResourceBundle(encoded, hash(encoded), p); e != nil {
		return nil, ErrInstall
	}
	again, e := ReadPrivateFile(bundleFile, 262144)
	if e != nil || !bytes.Equal(raw, again) || hash(again) != bundleSHA || s.signingResourcePin(ctx, enrollment, p) != nil {
		return nil, ErrInstall
	}
	current, e := signingResourceOriginal(ctx, s, p, b)
	if e != nil || current != expected {
		return nil, ErrInstall
	}
	return encoded, nil
}
