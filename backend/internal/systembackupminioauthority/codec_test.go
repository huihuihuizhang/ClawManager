package systembackupminioauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

// Pure declaration/cryptographic fixture. It does not enroll an issuer,
// install SQL authority or supply native permission/capability evidence.
type sqlRecordFixture struct {
	key                                  ed25519.PrivateKey
	pin                                  SQLTrustPin
	grant                                SQLGrant
	head                                 SQLHead
	refs                                 []SQLReferenceRecord
	grantRaw, headRaw, grantSig, headSig []byte
	signedRefs                           []SQLSignedReference
}

func newSQLRecordFixture(t *testing.T) *sqlRecordFixture {
	t.Helper()
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(key) })
	f := &sqlRecordFixture{key: key}
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := Target{InstallationID: "installation_original_minio", ServerUUID: "12345678-1234-1234-1234-123456789abc", Database: "original_database", ConsumerDatabaseAccount: "original_consumer@localhost", ClusterUID: "original-cluster", Namespace: "original-namespace", NamespaceUID: "original-namespace-uid"}
	enrollment := Enrollment{ID: "original-enrollment", Revision: 1, ConfigMapName: "original-enrollment", ConfigMapUID: "original-enrollment-uid", DocumentSHA256: digest([]byte("original-enrollment")), PlanSHA256: digest([]byte("original-plan")), IssuerID: "original-issuer", IssuerPublicSHA256: digest(public), OwnerSubject: "original-owner", OwnerUID: "original-owner-uid", OwnerGroupsSHA256: digest([]byte("original-groups"))}
	obj := func(name string) ObjectIdentity { return ObjectIdentity{Name: name, UID: name + "-uid"} }
	f.grant = SQLGrant{Version: SQLGrantVersion, AuthorityID: "original-authority", GrantID: "original-grant", RecordRevision: 1, PermissionEpoch: 1, Target: target, Enrollment: enrollment, Actor: Actor{LocalAdminUserID: 41, LocalAdminUsername: "original-admin", InstallerDatabaseAccount: "original_installer@localhost"}, ConfigSHA256: digest([]byte("original-disabled-config")), BootstrapGrantSHA256: digest([]byte("original-bootstrap-grant")), Provider: Provider{IdentityHash: digest([]byte("original-provider")), IdentityProfile: "original-provider.v1", Endpoint: "https://minio.original.invalid", Region: "us-east-1", DeploymentID: "original-deployment", CASHA256: digest([]byte("original-ca")), SPKISHA256: digest([]byte("original-spki")), ServerVersion: "2025-04-22T22:12:26Z", ServerCommit: "0d7408fc9969caf07de6a8c3a84f9fbb10a6739e", ImageProvenanceSHA256: digest([]byte("original-image-provenance")), Deployment: obj("minio"), ReplicaSet: obj("minio-rs"), Pod: obj("minio-pod"), Service: obj("minio-service"), ServiceAccount: obj("minio-sa"), Container: "minio", ImageID: "sha256:original-image", Node: "original-node", NodeUID: "original-node-uid"}, PermissionSource: PermissionSource{Profile: PermissionProfile, Grant: obj("permission-grant"), Head: obj("permission-head"), GrantSHA256: digest([]byte("original-permission-grant")), InitialHeadSHA256: digest([]byte("original-permission-head")), ObserverAccountSHA256: digest([]byte("observer-account")), ObserverCredentialFileSHA256: digest([]byte("observer-file")), ObserverLocatorSHA256: digest([]byte("observer-locator")), ObserverPolicyName: "original-observer", ObserverNormalizedPolicySHA256: digest([]byte("observer-policy"))}, Observation: ObservationBinding{Profile: NativeObservationProfile, DefinitionSHA256: digest([]byte("original-definition")), CapabilityIntentSHA256: digest([]byte("original-capability-intent")), MaximumAgeMicroseconds: MaximumObservationAgeMicroseconds}, NotBefore: now.Add(-time.Minute), Until: now.Add(30 * time.Minute)}
	for _, purpose := range purposes() {
		r := Reference{Purpose: purpose, IdentityHash: digest([]byte("identity-" + string(purpose))), IdentityVersion: "original-1", DescriptorSHA256: digest([]byte("descriptor-" + string(purpose))), IdentityProfile: "original-reference.v1", ProviderIdentityHash: f.grant.Provider.IdentityHash, ScopeSHA256: digest([]byte("scope-" + string(purpose))), ScopeProfile: "original-scope.v1", AccountSHA256: digest([]byte("account-" + string(purpose))), CredentialFileSHA256: digest([]byte("credential-" + string(purpose))), CredentialLocatorSHA256: digest([]byte("locator-" + string(purpose))), PolicyName: string(purpose), NormalizedPolicySHA256: digest([]byte("policy-" + string(purpose))), Bucket: "original-artifacts", Root: target.InstallationID + "/", StagingRoot: target.InstallationID + "_staging/", CapabilityProfile: "original-protocol.v1", CapabilityIntentSHA256: f.grant.Observation.CapabilityIntentSHA256, NotBefore: now.Add(-2 * time.Minute), Until: now.Add(time.Hour), ProtectedUntil: now.Add(2 * time.Hour)}
		switch purpose {
		case ArtifactRead:
			r.Capability = "exact_read"
		case ArtifactWrite:
			r.Capability = "conditional_create"
		case ArtifactDelete:
			r.Capability = "exact_delete"
		case CatalogRead:
			r.Capability = "exact_read"
		case CatalogAppend:
			r.Capability = "append_record"
		}
		if purpose == CatalogRead || purpose == CatalogAppend {
			r.Bucket = "original-catalog"
			r.Root = target.InstallationID + "/catalog/"
			r.StagingRoot = ""
		}
		record := SQLReferenceRecord{Version: SQLReferenceVersion, AuthorityID: f.grant.AuthorityID, GrantID: f.grant.GrantID, RecordRevision: 1, PermissionEpoch: 1, Target: target, Enrollment: enrollment, ConfigSHA256: f.grant.ConfigSHA256, Reference: r}
		raw, e := EncodeSQLReference(record)
		if e != nil {
			t.Fatal(e)
		}
		f.refs = append(f.refs, record)
		f.signedRefs = append(f.signedRefs, SQLSignedReference{purpose, raw, ed25519.Sign(key, append([]byte(SQLReferenceDomain), raw...))})
		f.grant.References = append(f.grant.References, SQLReferenceHash{purpose, digest(raw)})
	}
	set, _ := canonical(f.grant.References)
	f.grant.ReferenceSetSHA256 = digest(set)
	f.grantRaw, e = EncodeSQLGrant(f.grant)
	if e != nil {
		t.Fatal(e)
	}
	f.grantSig = ed25519.Sign(key, append([]byte(SQLGrantDomain), f.grantRaw...))
	f.head = SQLHead{Version: SQLHeadVersion, AuthorityID: f.grant.AuthorityID, Target: target, Enrollment: enrollment, HeadRevision: 1, PermissionEpoch: 1, CurrentGrantID: f.grant.GrantID, CurrentGrantRevision: 1, GrantSHA256: digest(f.grantRaw), ReferenceSetSHA256: f.grant.ReferenceSetSHA256, State: StateActive, NotBefore: f.grant.NotBefore, Until: f.grant.Until}
	f.headRaw, e = EncodeSQLHead(f.head)
	if e != nil {
		t.Fatal(e)
	}
	f.headSig = ed25519.Sign(key, append([]byte(SQLHeadDomain), f.headRaw...))
	f.pin = SQLTrustPin{Target: target, Enrollment: enrollment, AuthorityID: f.grant.AuthorityID, GrantID: f.grant.GrantID, GrantRevision: 1, MinimumHeadRevision: 1, MinimumPermissionEpoch: 1, GrantSHA256: digest(f.grantRaw), ReferenceSetSHA256: f.grant.ReferenceSetSHA256, IssuerPublic: public}
	return f
}

func TestMinIOSQLRecordSetExactSignedSevenRecordDAG(t *testing.T) {
	f := newSQLRecordFixture(t)
	s, e := VerifySQLRecordSet(f.pin, f.grantRaw, f.grantSig, f.headRaw, f.headSig, f.signedRefs)
	if e != nil {
		t.Fatal(e)
	}
	g, h, refs, e := s.Detached()
	if e != nil || g.AuthorityID != f.grant.AuthorityID || h.State != StateActive || len(refs) != 5 {
		t.Fatal("verified original declarations", e)
	}
	g.References[0].SHA256 = digest([]byte("mutated detached"))
	refs[0].Reference.IdentityVersion = "changed"
	g2, _, refs2, e := s.Detached()
	if e != nil || g2.References[0].SHA256 == g.References[0].SHA256 || refs2[0].Reference.IdentityVersion == refs[0].Reference.IdentityVersion {
		t.Fatal("detached mutable caller changed verified source", e)
	}
	if _, e = s.MarshalJSON(); e == nil {
		t.Fatal("declaration set became serializable admission")
	}
	f.head.HeadRevision = 2
	f.head.State = StateRevoked
	raw, e := EncodeSQLHead(f.head)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifySQLRecordSet(f.pin, f.grantRaw, f.grantSig, raw, ed25519.Sign(f.key, append([]byte(SQLHeadDomain), raw...)), f.signedRefs); e != nil {
		t.Fatal("authentic revoked declaration must remain inspectable, not authorize fresh use", e)
	}
}

func TestMinIOSQLRecordSetRejectsOriginalPinDomainAndReferenceSubstitution(t *testing.T) {
	for _, scenario := range []string{"wrong-pin", "wrong-grant-domain", "wrong-head-domain", "wrong-reference-domain", "missing-ref", "wrong-ref-order", "ref-signature", "noncanonical", "unknown-member", "duplicate-case-member", "trailing", "head-key-substitution", "window-renewal", "epoch-bypass"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSQLRecordFixture(t)
			pin := f.pin
			g, h, gs, hs := bytes.Clone(f.grantRaw), bytes.Clone(f.headRaw), bytes.Clone(f.grantSig), bytes.Clone(f.headSig)
			refs := append([]SQLSignedReference(nil), f.signedRefs...)
			switch scenario {
			case "wrong-pin":
				pin.AuthorityID = "other-authority"
			case "wrong-grant-domain":
				gs = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), g...))
			case "wrong-head-domain":
				hs = ed25519.Sign(f.key, append([]byte(SQLGrantDomain), h...))
			case "wrong-reference-domain":
				refs[0].Signature = ed25519.Sign(f.key, append([]byte(SQLGrantDomain), refs[0].Record...))
			case "missing-ref":
				refs = refs[:4]
			case "wrong-ref-order":
				refs[0], refs[1] = refs[1], refs[0]
			case "ref-signature":
				refs[0].Signature = bytes.Clone(refs[0].Signature)
				refs[0].Signature[0] ^= 1
			case "noncanonical":
				h = append(h, '\n')
				hs = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), h...))
			case "unknown-member":
				h = append([]byte(`{"Extra":"undeclared",`), h[1:]...)
				h, _ = canonical(json.RawMessage(h))
				hs = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), h...))
			case "duplicate-case-member":
				h = append([]byte(`{"state":"active",`), h[1:]...)
				h, _ = canonical(json.RawMessage(h))
				hs = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), h...))
			case "trailing":
				h = append(h, []byte(` {}`)...)
				hs = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), h...))
			case "head-key-substitution":
				f.head.AuthorityID = "other-authority"
				h, _ = EncodeSQLHead(f.head)
				hs = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), h...))
			case "window-renewal":
				f.head.Until = f.head.Until.Add(time.Second)
				h, _ = EncodeSQLHead(f.head)
				hs = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), h...))
			case "epoch-bypass":
				f.head.PermissionEpoch = 2
				h, _ = canonical(f.head)
				hs = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), h...))
			}
			if _, e := VerifySQLRecordSet(pin, g, gs, h, hs, refs); e == nil {
				t.Fatal("substituted declaration accepted")
			}
		})
	}
}

func TestMinIOSQLBundleExactInitialAndRevokeCASShape(t *testing.T) {
	f := newSQLRecordFixture(t)
	b := SQLBundle{Version: SQLBundleVersion, Action: SQLActionInstall, PlanSHA256: f.pin.Enrollment.PlanSHA256, EnrollmentDocumentSHA256: f.pin.Enrollment.DocumentSHA256, Grant: f.grantRaw, GrantSignature: f.grantSig, Head: f.headRaw, HeadSignature: f.headSig, References: f.signedRefs}
	raw, e := EncodeSQLBundle(b)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeSQLBundle(raw, digest(raw)); e != nil {
		t.Fatal(e)
	}
	b.Action = SQLActionRevoke
	revoked := f.head
	revoked.HeadRevision = 2
	revoked.State = StateRevoked
	b.Head, e = EncodeSQLHead(revoked)
	if e != nil {
		t.Fatal(e)
	}
	b.HeadSignature = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), b.Head...))
	b.Expected = SQLExpected{HeadRevision: 1, PermissionEpoch: 1, HeadRowVersion: 1, CurrentGrantID: f.grant.GrantID, CurrentGrantRevision: 1, GrantRowVersion: 1, HeadSHA256: digest(f.headRaw), GrantSHA256: digest(f.grantRaw), ReferenceSetSHA256: f.grant.ReferenceSetSHA256, State: StateActive}
	for _, v := range f.signedRefs {
		b.Expected.ReferenceRows = append(b.Expected.ReferenceRows, SQLReferenceCAS{v.Purpose, digest(v.Record), 1})
	}
	if _, e = EncodeSQLBundle(b); e != nil {
		t.Fatal(e)
	}
	b.Expected.ReferenceRows[0].RowVersion = 0
	if _, e = EncodeSQLBundle(b); e == nil {
		t.Fatal("unproved zero original CAS ref generation accepted")
	}
	b.Expected.ReferenceRows[0].RowVersion = 1
	b.Action = SQLActionInstall
	if _, e = EncodeSQLBundle(b); e == nil {
		t.Fatal("initial install accepted existing-head CAS")
	}
}
