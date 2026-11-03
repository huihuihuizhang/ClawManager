//go:build systembackup_mysql

package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

// Explicit TEST issuer declarations for native SQL lifecycle tests only.
// This does NOT call IssueSigningResourceInstall or prove provider observation,
// installed signing material, original intent authorization or usable admission.
// Construct each declaration for THIS enrolled native target before signing it;
// never transplant/re-sign an old model-target signed grant or invoke the old
// originalSigningResourceBundleFixture. The actual Import/Resolve, admin auth,
// enrollment, SQL transactions and consumer codecs remain real below.
func nativeSignerOriginalDeclarationInputs(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture) []SigningResourceSQLInput {
	t.Helper()
	n := f.n
	r, plan := n.f.record, n.f.i.plan
	if r.Target != plan.Target || !bytes.Equal(ed25519.PrivateKey(n.f.key).Public().(ed25519.PublicKey), n.f.i.public) {
		t.Fatal("test issuer declaration requires original enrolled native target/key")
	}
	operator, err := n.f.i.authenticate(ctx, n.f.password)
	if err != nil {
		t.Fatal("actual native local admin authentication for test declaration", err)
	}
	pins := make([]owner.SigningResourceTrustPin, 0, 2)
	bundles := make([][]byte, 0, 2)
	for _, purpose := range owner.SigningResourcePurposes() {
		g := owner.SigningResourceGrant{
			SchemaVersion: owner.SigningResourceGrantVersion,
			AuthorityID:   "native-test-declaration", GrantID: "native-test-" + purpose,
			PlanSHA256: n.f.i.planHash, EnrollmentID: plan.EnrollmentID,
			IssuerID: plan.IssuerID, EnrollmentDocumentSHA256: n.f.enrollment.DocumentSHA256,
			EnrollmentRevision: plan.EnrollmentRevision, RecordRevision: 1, PermissionEpoch: 1,
			Target: plan.Target, Actor: r.Actor,
			BootstrapGrantSHA256: r.GrantSHA256, ConfigSHA256: r.ConfigSHA256,
			SigningMaterialSHA256:   hash([]byte("explicit-native-sql-test-declaration-no-provider-material")),
			SigningMaterialRevision: 1,
			Histories:               r.Histories, NotBefore: r.NotBefore, Until: r.Until,
		}
		for _, history := range g.Histories {
			binding := r.Binding
			binding.Purpose, binding.KeyID, binding.KeyName = history.Purpose, history.KeyName, history.KeyName
			binding.AuthMount = "jwt-" + history.Purpose
			binding.Role, binding.Policy = "role-"+history.Purpose, "policy-"+history.Purpose
			g.Bindings = append(g.Bindings, binding)
			if history.Purpose == purpose {
				g.Binding = binding
			}
		}
		identity, err := owner.SigningResourceReferenceIdentity(g.Binding)
		if err != nil {
			t.Fatal(err)
		}
		g.Reference = sec.BootstrapSecretRef{Purpose: owner.SigningResourceBootstrapPurpose(purpose), IdentityHash: identity, Version: g.Binding.KeyVersion}
		grant, err := owner.EncodeSigningResourceGrant(g)
		if err != nil {
			t.Fatal(err)
		}
		pin := owner.SigningResourceTrustPin{
			Target: g.Target, Actor: g.Actor, EnrollmentID: g.EnrollmentID, IssuerID: g.IssuerID,
			EnrollmentDocumentSHA256: g.EnrollmentDocumentSHA256, OwnerSubject: g.Actor.OwnerSubject,
			EnrollmentRevision: g.EnrollmentRevision, Issuer: bytes.Clone(n.f.i.public),
			AuthorityID: g.AuthorityID, Purpose: purpose, GrantID: g.GrantID, GrantSHA256: hash(grant),
			GrantRevision: 1, MinimumHeadRevision: 1, MinimumPermissionEpoch: 1,
		}
		if operator.signingResourcePin(ctx, n.f.enrollment, pin) != nil {
			t.Fatal("actual enrolled owner/pin check for explicit test declaration")
		}
		head, err := owner.EncodeSigningResourceHead(owner.SigningResourceHead{
			SchemaVersion: owner.SigningResourceHeadVersion, AuthorityID: g.AuthorityID, Purpose: purpose,
			EnrollmentID: g.EnrollmentID, IssuerID: g.IssuerID, EnrollmentRevision: g.EnrollmentRevision,
			HeadRevision: 1, PermissionEpoch: 1, Target: g.Target, OwnerSubject: g.Actor.OwnerSubject,
			CurrentGrantID: g.GrantID, CurrentGrantRevision: 1, GrantSHA256: pin.GrantSHA256,
			State: "active", NotBefore: g.NotBefore, Until: g.Until,
		})
		if err != nil {
			t.Fatal(err)
		}
		bundle := SigningResourceBundle{
			Version: SigningResourceBundleVersion, Action: "install", PlanSHA256: g.PlanSHA256,
			EnrollmentDocumentSHA256: g.EnrollmentDocumentSHA256,
			Grant:                    grant, GrantSignature: ed25519.Sign(n.f.key, append([]byte(owner.SigningResourceGrantDomain), grant...)),
			Head: head, HeadSignature: ed25519.Sign(n.f.key, append([]byte(owner.SigningResourceHeadDomain), head...)),
		}
		raw, err := canonical(bundle)
		if err != nil {
			t.Fatal(err)
		}
		pins, bundles = append(pins, pin), append(bundles, raw)
	}
	// Reuse the existing exact tuple/codec verifier only. Its earlier expected
	// production-issuer provenance is NOT established by these test declarations.
	t.Log("explicit native TEST issuer declaration: real enrolled issuer signatures and SQL lifecycle; production IssueSigningResourceInstall/provider authorization NOT verified")
	return nativeSignerIssuedInputs(t, f, pins, bundles)
}
