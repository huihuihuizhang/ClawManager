package systembackupinstallationowner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

type signingResourceFixture struct {
	capture  recordFixture
	grant    SigningResourceGrant
	pin      SigningResourceTrustPin
	raw, sig []byte
}

func originalSigningResourceFixture(t *testing.T, purpose string) *signingResourceFixture {
	t.Helper()
	c := ownerRecordFixture(t)
	g := SigningResourceGrant{SchemaVersion: SigningResourceGrantVersion, AuthorityID: "signing-original", GrantID: "resource-" + purpose, PlanSHA256: strings.Repeat("b", 64), EnrollmentID: c.pin.EnrollmentID, IssuerID: c.pin.IssuerID, EnrollmentDocumentSHA256: strings.Repeat("c", 64), EnrollmentRevision: 1, RecordRevision: 1, PermissionEpoch: 1, Target: c.record.Target, Actor: c.record.Actor, BootstrapGrantSHA256: strings.Repeat("d", 64), ConfigSHA256: c.record.ConfigSHA256, SigningMaterialSHA256: strings.Repeat("e", 64), SigningMaterialRevision: 1, Histories: c.record.Histories, NotBefore: c.record.NotBefore, Until: c.record.Until}
	for _, h := range g.Histories {
		b := c.record.Binding
		b.Purpose, b.KeyID, b.KeyName = h.Purpose, h.KeyName, h.KeyName
		b.AuthMount, b.Role, b.Policy = "jwt-"+h.Purpose, "role-"+h.Purpose, "policy-"+h.Purpose
		g.Bindings = append(g.Bindings, b)
		if h.Purpose == purpose {
			g.Binding = b
		}
	}
	id, e := SigningResourceReferenceIdentity(g.Binding)
	if e != nil {
		t.Fatal(e)
	}
	g.Reference = sec.BootstrapSecretRef{Purpose: SigningResourceBootstrapPurpose(purpose), IdentityHash: id, Version: g.Binding.KeyVersion}
	p := SigningResourceTrustPin{Target: g.Target, Actor: g.Actor, EnrollmentID: g.EnrollmentID, IssuerID: g.IssuerID, EnrollmentDocumentSHA256: g.EnrollmentDocumentSHA256, OwnerSubject: g.Actor.OwnerSubject, EnrollmentRevision: 1, Issuer: c.pin.Issuer, AuthorityID: g.AuthorityID, Purpose: purpose, GrantID: g.GrantID, GrantRevision: 1, MinimumHeadRevision: 1, MinimumPermissionEpoch: 1}
	f := &signingResourceFixture{capture: c, grant: g, pin: p}
	f.resign(t)
	return f
}

func (f *signingResourceFixture) resign(t *testing.T) {
	t.Helper()
	raw, e := EncodeSigningResourceGrant(f.grant)
	if e != nil {
		t.Fatal(e)
	}
	f.raw, f.pin.GrantSHA256 = raw, digest(raw)
	f.sig = ed25519.Sign(f.capture.private, append([]byte(SigningResourceGrantDomain), raw...))
}
func (f *signingResourceFixture) head(t *testing.T, revoked bool) ([]byte, []byte) {
	t.Helper()
	g := f.grant
	h := SigningResourceHead{SchemaVersion: SigningResourceHeadVersion, AuthorityID: g.AuthorityID, Purpose: g.Binding.Purpose, EnrollmentID: g.EnrollmentID, IssuerID: g.IssuerID, EnrollmentRevision: 1, HeadRevision: 1, PermissionEpoch: 1, Target: g.Target, OwnerSubject: g.Actor.OwnerSubject, CurrentGrantID: g.GrantID, CurrentGrantRevision: 1, GrantSHA256: f.pin.GrantSHA256, State: "active", NotBefore: g.NotBefore, Until: g.Until}
	if revoked {
		h.HeadRevision, h.State = 2, "revoked"
	}
	raw, e := EncodeSigningResourceHead(h)
	if e != nil {
		t.Fatal(e)
	}
	return raw, ed25519.Sign(f.capture.private, append([]byte(SigningResourceHeadDomain), raw...))
}

func TestSigningResourceIndependentPurposeAndOriginalGrantDomain(t *testing.T) {
	for _, purpose := range SigningResourcePurposes() {
		f := originalSigningResourceFixture(t, purpose)
		if _, e := InspectSigningResourceGrant(f.raw, f.sig, f.pin); e != nil {
			t.Fatal(purpose, e)
		}
		for _, domain := range []string{RecordDomain, HeadDomain, ProbeDomain, SigningResourceProbeDomain, sec.InstallationSigningDomain, "system-backup-acceptance-record.v1\x00"} {
			sig := ed25519.Sign(f.capture.private, append([]byte(domain), f.raw...))
			if _, e := InspectSigningResourceGrant(f.raw, sig, f.pin); e == nil {
				t.Fatal("cross-domain authorization", domain)
			}
		}
		pin := f.pin
		if purpose == "acceptance_record" {
			pin.Purpose = "catalog_record"
		} else {
			pin.Purpose = "acceptance_record"
		}
		if _, e := InspectSigningResourceGrant(f.raw, f.sig, pin); e == nil {
			t.Fatal("cross-purpose grant")
		}
		for _, mutate := range []func(*SigningResourceGrant){
			func(g *SigningResourceGrant) {
				g.Bindings[1].Role = g.Bindings[0].Role
				g.Bindings[1].AuthMount = g.Bindings[0].AuthMount
			},
			func(g *SigningResourceGrant) { g.Bindings[1].Policy = g.Bindings[0].Policy },
			func(g *SigningResourceGrant) { g.Histories[1].Keys[0].PublicKey = g.Histories[0].Keys[0].PublicKey },
			func(g *SigningResourceGrant) { g.Actor.UserID++ },
			func(g *SigningResourceGrant) { g.PermissionEpoch = 2 },
			func(g *SigningResourceGrant) { g.RecordRevision = 2 },
			func(g *SigningResourceGrant) { g.SigningMaterialSHA256 = "" },
			func(g *SigningResourceGrant) { g.Histories = g.Histories[:2] },
		} {
			c := originalSigningResourceFixture(t, purpose)
			mutate(&c.grant)
			c.resign(t)
			if _, e := InspectSigningResourceGrant(c.raw, c.sig, c.pin); e == nil {
				t.Fatal("invalid original scope/separation accepted")
			}
		}
		raw, sig := f.head(t, true)
		h, e := InspectSigningResourceHead(raw, sig, f.pin)
		if e != nil || h.State != "revoked" {
			t.Fatal("revoked head must remain readable DATA", e)
		}
		s := &SigningResourceSnapshot{head: h, grant: f.grant, cas: SigningResourceCAS{State: "revoked"}}
		if s.RequireCurrent(time.Now().UTC().Truncate(time.Microsecond)) == nil {
			t.Fatal("revocation admitted history")
		}
	}
}

func (f *signingResourceFixture) material(t *testing.T) SigningResourceMaterial {
	t.Helper()
	r := sec.InstallationSigningRecord{InstallationID: f.grant.Target.InstallationID, Revision: 1, NotBefore: f.grant.NotBefore, Until: f.grant.Until}
	for n, b := range f.grant.Bindings {
		r.Permissions = append(r.Permissions, sec.InstallationSigningPermission{Binding: sec.TransitSigningBinding{InstallationID: b.InstallationID, Purpose: b.Purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, Endpoint: b.Endpoint, KeyName: b.KeyName, ProviderVersion: b.ProviderVersion}, AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, CASHA256: b.CASHA256})
		for _, key := range f.grant.Histories[n].Keys {
			pub, _ := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
			r.Keys = append(r.Keys, sec.ArtifactSigningPublicKey{InstallationID: b.InstallationID, Purpose: b.Purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, PublicKey: pub, NotBefore: f.grant.NotBefore, NotAfter: key.ProtectedUntil})
		}
	}
	raw, e := canonical(r)
	if e != nil {
		t.Fatal(e)
	}
	sig := ed25519.Sign(f.capture.private, append([]byte(sec.InstallationSigningDomain), raw...))
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	files := RecordFiles{RecordFile: filepath.Join(dir, "installed.json"), SignatureFile: filepath.Join(dir, "installed.sig")}
	if os.WriteFile(files.RecordFile, raw, 0600) != nil || os.WriteFile(files.SignatureFile, sig, 0600) != nil {
		t.Fatal("material files")
	}
	f.grant.SigningMaterialSHA256 = digest(raw)
	f.resign(t)
	return SigningResourceMaterial{Files: files, Pin: sec.InstallationSigningPin{InstallationID: r.InstallationID, Revision: r.Revision, RecordSHA256: digest(raw), Issuer: f.capture.pin.Issuer}}
}

func TestSigningResourceReusesExactInstalledMappingAndCompletePublicHistory(t *testing.T) {
	f := originalSigningResourceFixture(t, "catalog_record")
	m := f.material(t)
	if e := CheckSigningResourceMaterial(context.Background(), m, f.grant); e != nil {
		t.Fatal("installed exact public mapping", e)
	}
	for _, edit := range []func(*SigningResourceGrant){
		func(g *SigningResourceGrant) { g.Bindings[0].Role = "other-role" },
		func(g *SigningResourceGrant) { g.Bindings[2].KeyVersion = "other-registry" },
		func(g *SigningResourceGrant) { g.Histories[1].Keys = nil },
		func(g *SigningResourceGrant) { g.SigningMaterialRevision++ },
	} {
		raw, _ := json.Marshal(f.grant)
		var g SigningResourceGrant
		_ = json.Unmarshal(raw, &g)
		edit(&g)
		if CheckSigningResourceMaterial(context.Background(), m, g) == nil {
			t.Fatal("unrelated or incomplete installed mapping accepted")
		}
	}
	raw, e := os.ReadFile(m.Files.RecordFile)
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(m.Files.RecordFile, append(bytes.Clone(raw), '\n'), 0600) != nil {
		t.Fatal("mutation")
	}
	if CheckSigningResourceMaterial(context.Background(), m, f.grant) == nil {
		t.Fatal("material byte replacement")
	}
}

func TestSigningResourcePreservesLegacySignedMaterialBytes(t *testing.T) {
	f := originalSigningResourceFixture(t, "acceptance_record")
	m := f.material(t)
	raw, e := os.ReadFile(m.Files.RecordFile)
	if e != nil {
		t.Fatal(e)
	}
	var r sec.InstallationSigningRecord
	if json.Unmarshal(raw, &r) != nil {
		t.Fatal("installed material")
	}
	zone := time.FixedZone("installed-offset", 8*60*60)
	r.NotBefore = f.grant.NotBefore.Add(-time.Minute).Add(time.Nanosecond).In(zone)
	r.Until = f.grant.Until.Add(time.Minute).Add(time.Nanosecond).In(zone)
	for n := range r.Keys {
		r.Keys[n].NotBefore = r.NotBefore
		r.Keys[n].NotAfter = r.Until
	}
	raw, e = json.MarshalIndent(r, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	sig := ed25519.Sign(f.capture.private, append([]byte(sec.InstallationSigningDomain), raw...))
	if os.WriteFile(m.Files.RecordFile, raw, 0600) != nil || os.WriteFile(m.Files.SignatureFile, sig, 0600) != nil {
		t.Fatal("legacy signed original")
	}
	m.Pin.RecordSHA256 = digest(raw)
	f.grant.SigningMaterialSHA256 = digest(raw)
	if CheckSigningResourceMaterial(context.Background(), m, f.grant) != nil {
		t.Fatal("existing valid owner material demanded rewriting/re-signing")
	}
	again, e := os.ReadFile(m.Files.RecordFile)
	if e != nil || !bytes.Equal(raw, again) {
		t.Fatal("consumer changed original signed bytes")
	}
}
