package systembackupminioauthority

import (
	"crypto/ed25519"
	"testing"
)

func resignSeptemberFixture(t *testing.T, f *sqlRecordFixture) {
	t.Helper()
	f.signedRefs, f.grant.References = nil, nil
	for _, r := range f.refs {
		raw, err := EncodeSQLReference(r)
		if err != nil {
			t.Fatal(err)
		}
		f.signedRefs = append(f.signedRefs, SQLSignedReference{r.Reference.Purpose, raw, ed25519.Sign(f.key, append([]byte(SQLReferenceDomain), raw...))})
		f.grant.References = append(f.grant.References, SQLReferenceHash{r.Reference.Purpose, digest(raw)})
	}
	set, err := canonical(f.grant.References)
	if err != nil {
		t.Fatal(err)
	}
	f.grant.ReferenceSetSHA256 = digest(set)
	f.grantRaw, err = EncodeSQLGrant(f.grant)
	if err != nil {
		t.Fatal(err)
	}
	f.grantSig = ed25519.Sign(f.key, append([]byte(SQLGrantDomain), f.grantRaw...))
	f.head.GrantSHA256, f.head.ReferenceSetSHA256 = digest(f.grantRaw), f.grant.ReferenceSetSHA256
	f.headRaw, err = EncodeSQLHead(f.head)
	if err != nil {
		t.Fatal(err)
	}
	f.headSig = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), f.headRaw...))
	f.pin.GrantSHA256, f.pin.ReferenceSetSHA256 = digest(f.grantRaw), f.grant.ReferenceSetSHA256
}

func newSeptemberRecordFixture(t *testing.T) *sqlRecordFixture {
	t.Helper()
	f := newSQLRecordFixture(t)
	profile, _ := NativeProfile(SeptemberPermissionProfile)
	f.grant.PermissionSource.Profile, f.grant.Observation.Profile = profile.Permission, profile.Observation
	f.grant.Provider.ServerVersion, f.grant.Provider.ServerCommit, f.grant.Provider.IdentityProfile = profile.ServerVersion, profile.ServerCommit, profile.Provider
	for n := range f.refs {
		r := &f.refs[n].Reference
		r.IdentityProfile, r.ScopeProfile, r.CapabilityProfile = profile.Reference, profile.Scope, profile.Protocol
		r.CapabilityIntentSHA256 = f.grant.Observation.CapabilityIntentSHA256
		if r.Purpose == ArtifactRead {
			r.Capability = "range_read"
		}
	}
	resignSeptemberFixture(t, f)
	return f
}

func TestMinIOSeptemberSignedRecordSetAndAprilHistory(t *testing.T) {
	for _, makeFixture := range []func(*testing.T) *sqlRecordFixture{newSQLRecordFixture, newSeptemberRecordFixture} {
		f := makeFixture(t)
		if _, err := VerifySQLRecordSet(f.pin, f.grantRaw, f.grantSig, f.headRaw, f.headSig, f.signedRefs); err != nil {
			t.Fatal("separate original seven-record profile", err)
		}
	}
}

func TestMinIOSeptemberRejectsMixedProviderObservationTuple(t *testing.T) {
	april, _ := NativeProfile(PermissionProfile)
	cases := []struct {
		name   string
		change func(*SQLGrant)
	}{
		{"april-version", func(g *SQLGrant) { g.Provider.ServerVersion = april.ServerVersion }},
		{"april-commit", func(g *SQLGrant) { g.Provider.ServerCommit = april.ServerCommit }},
		{"april-permission", func(g *SQLGrant) { g.PermissionSource.Profile = april.Permission }},
		{"april-observation", func(g *SQLGrant) { g.Observation.Profile = april.Observation }},
		{"april-provider-profile", func(g *SQLGrant) { g.Provider.IdentityProfile = april.Provider }},
		{"unknown-permission", func(g *SQLGrant) { g.PermissionSource.Profile = "minio-2025-09-07-builtin-flat.v2" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSeptemberRecordFixture(t)
			tc.change(&f.grant)
			if _, err := EncodeSQLGrant(f.grant); err == nil {
				t.Fatal("mixed original native tuple accepted")
			}
		})
	}
}

func TestMinIOSeptemberRejectsResignedMixedReferenceProfiles(t *testing.T) {
	april, _ := NativeProfile(PermissionProfile)
	cases := []struct {
		name   string
		change func(*Reference)
	}{
		{"april-reference", func(r *Reference) { r.IdentityProfile = april.Reference }},
		{"april-scope", func(r *Reference) { r.ScopeProfile = april.Scope }},
		{"april-protocol", func(r *Reference) { r.CapabilityProfile = april.Protocol }},
		{"different-intent", func(r *Reference) { r.CapabilityIntentSHA256 = digest([]byte("different-original-intent")) }},
		{"no-range", func(r *Reference) { r.Capability = "exact_read" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSeptemberRecordFixture(t)
			tc.change(&f.refs[1].Reference)
			// All signatures, reference hashes, head and independent pins are rebuilt
			// correctly: the failure must come from the cross-profile constraint.
			resignSeptemberFixture(t, f)
			if _, err := VerifySQLRecordSet(f.pin, f.grantRaw, f.grantSig, f.headRaw, f.headSig, f.signedRefs); err == nil {
				t.Fatal("resigned mixed original reference accepted")
			}
		})
	}
}
