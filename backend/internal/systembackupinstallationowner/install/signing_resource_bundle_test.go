package install

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

// Signed transport/codec DATA only. No installer SQL row or fresh resource
// permission is created here, and no full bootstrap success is asserted.
func originalSigningResourceBundleFixture(t *testing.T) (owner.SigningResourceTrustPin, SigningResourceBundle, *authorityFixture) {
	t.Helper()
	f := newAuthorityFixture(t)
	r := f.record
	g := owner.SigningResourceGrant{SchemaVersion: owner.SigningResourceGrantVersion, AuthorityID: "signing-original", GrantID: "catalog-original", PlanSHA256: f.i.planHash, EnrollmentID: r.EnrollmentID, IssuerID: r.IssuerID, EnrollmentDocumentSHA256: f.enrollment.DocumentSHA256, EnrollmentRevision: r.EnrollmentRevision, RecordRevision: 1, PermissionEpoch: 1, Target: r.Target, Actor: r.Actor, BootstrapGrantSHA256: r.GrantSHA256, ConfigSHA256: r.ConfigSHA256, SigningMaterialSHA256: strings.Repeat("e", 64), SigningMaterialRevision: 1, Histories: r.Histories, NotBefore: r.NotBefore, Until: r.Until}
	for _, h := range g.Histories {
		b := r.Binding
		b.Purpose, b.KeyID, b.KeyName = h.Purpose, h.KeyName, h.KeyName
		b.AuthMount, b.Role, b.Policy = "jwt-"+h.Purpose, "role-"+h.Purpose, "policy-"+h.Purpose
		g.Bindings = append(g.Bindings, b)
		if h.Purpose == "catalog_record" {
			g.Binding = b
		}
	}
	id, e := owner.SigningResourceReferenceIdentity(g.Binding)
	if e != nil {
		t.Fatal(e)
	}
	g.Reference = sec.BootstrapSecretRef{Purpose: "catalog_signing", IdentityHash: id, Version: g.Binding.KeyVersion}
	raw, e := owner.EncodeSigningResourceGrant(g)
	if e != nil {
		t.Fatal(e)
	}
	p := owner.SigningResourceTrustPin{Target: g.Target, Actor: g.Actor, EnrollmentID: g.EnrollmentID, IssuerID: g.IssuerID, EnrollmentDocumentSHA256: g.EnrollmentDocumentSHA256, OwnerSubject: g.Actor.OwnerSubject, EnrollmentRevision: g.EnrollmentRevision, Issuer: f.i.public, AuthorityID: g.AuthorityID, Purpose: g.Binding.Purpose, GrantID: g.GrantID, GrantSHA256: hash(raw), GrantRevision: 1, MinimumHeadRevision: 1, MinimumPermissionEpoch: 1}
	h := owner.SigningResourceHead{SchemaVersion: owner.SigningResourceHeadVersion, AuthorityID: g.AuthorityID, Purpose: g.Binding.Purpose, EnrollmentID: g.EnrollmentID, IssuerID: g.IssuerID, EnrollmentRevision: g.EnrollmentRevision, HeadRevision: 1, PermissionEpoch: 1, Target: g.Target, OwnerSubject: g.Actor.OwnerSubject, CurrentGrantID: g.GrantID, CurrentGrantRevision: 1, GrantSHA256: p.GrantSHA256, State: "active", NotBefore: g.NotBefore, Until: g.Until}
	head, e := owner.EncodeSigningResourceHead(h)
	if e != nil {
		t.Fatal(e)
	}
	b := SigningResourceBundle{Version: SigningResourceBundleVersion, Action: "install", PlanSHA256: g.PlanSHA256, EnrollmentDocumentSHA256: g.EnrollmentDocumentSHA256, Grant: raw, GrantSignature: ed25519.Sign(f.key, append([]byte(owner.SigningResourceGrantDomain), raw...)), Head: head, HeadSignature: ed25519.Sign(f.key, append([]byte(owner.SigningResourceHeadDomain), head...))}
	return p, b, f
}

func TestSigningResourceBundleSeparateGrantAndTerminalRevocation(t *testing.T) {
	p, b, f := originalSigningResourceBundleFixture(t)
	raw, e := canonical(b)
	if e != nil {
		t.Fatal(e)
	}
	_, g, h, e := signingResourceBundle(raw, hash(raw), p)
	if e != nil {
		t.Fatal("signed install transport", e)
	}
	oldGrant, oldSig := bytes.Clone(b.Grant), bytes.Clone(b.GrantSignature)
	b.Action = "revoke"
	b.Expected = owner.SigningResourceCAS{HeadRevision: 1, HeadRowVersion: 1, GrantRevision: 1, GrantRowVersion: 1, PermissionEpoch: 1, GrantID: g.GrantID, HeadSHA256: hash(b.Head), GrantSHA256: p.GrantSHA256, State: "active"}
	h.HeadRevision, h.State = 2, "revoked"
	b.Head, e = owner.EncodeSigningResourceHead(h)
	if e != nil {
		t.Fatal(e)
	}
	b.HeadSignature = ed25519.Sign(f.key, append([]byte(owner.SigningResourceHeadDomain), b.Head...))
	raw, e = canonical(b)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = signingResourceBundle(raw, hash(raw), p); e != nil || !bytes.Equal(oldGrant, b.Grant) || !bytes.Equal(oldSig, b.GrantSignature) {
		t.Fatal("exact original grant retained", e)
	}
	for _, edit := range []func(*SigningResourceBundle){
		func(b *SigningResourceBundle) { b.Expected.PermissionEpoch = 2 },
		func(b *SigningResourceBundle) { b.Expected.State = "revoked" },
		func(b *SigningResourceBundle) { b.Expected.GrantRowVersion = 0 },
		func(b *SigningResourceBundle) { b.PlanSHA256 = strings.Repeat("f", 64) },
		func(b *SigningResourceBundle) { b.EnrollmentDocumentSHA256 = strings.Repeat("f", 64) },
	} {
		changed := b
		edit(&changed)
		raw, e := canonical(changed)
		if e != nil {
			t.Fatal(e)
		}
		if _, _, _, e := signingResourceBundle(raw, hash(raw), p); e == nil {
			t.Fatal("bad original scope/CAS accepted")
		}
	}
}
