package systembackupinstallationowner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

type recordFixture struct {
	record   Record
	pin      TrustPin
	private  ed25519.PrivateKey
	raw, sig []byte
	signing  map[string]ed25519.PrivateKey
}

func ownerRecordFixture(t *testing.T) recordFixture {
	t.Helper()
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(private) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	h := strings.Repeat("a", 64)
	p := TrustPin{InstallationID: "installation_test", EnrollmentID: "enrollment-1", IssuerID: "owner-1", EnrollmentRevision: 1, MinimumHeadRevision: 1, Issuer: pub, ClusterID: "cluster-1", NamespaceUID: "namespace-uid", OwnerSubject: "actual-owner-subject", ServerUUID: "01234567-89ab-cdef-0123-456789abcdef", Database: "backup_fixture", DatabaseAccount: "bootstrap@localhost", GrantID: "grant-1", GrantRevision: 1, RecordSHA256: h}
	b := Binding{InstallationID: p.InstallationID, Purpose: "capture_certificate", KeyID: "capture-key", KeyVersion: "registry-1", Endpoint: "https://vault.invalid", ProviderClusterID: "vault-1", TransitMount: "transit", KeyName: "capture-key", ProviderVersion: "1", AuthMount: "backup-jwt", Role: "capture-role", Policy: "capture-policy", Audience: "capture-audience", Namespace: "backup-system", NamespaceUID: p.NamespaceUID, PodName: "controller", PodUID: "controller-uid", ServiceAccountName: "controller", ServiceAccountUID: "controller-sa-uid", CASHA256: h, RoleSHA256: h, PolicySHA256: h, JWTConfigSHA256: h}
	identity, e := ReferenceIdentity(b)
	if e != nil {
		t.Fatal(e)
	}
	r := Record{SchemaVersion: RecordVersion, EnrollmentID: p.EnrollmentID, IssuerID: p.IssuerID, GrantID: p.GrantID, EnrollmentRevision: 1, Revision: 1, NotBefore: now.Add(-time.Minute), Until: now.Add(10 * time.Minute), Target: Target{p.InstallationID, p.ServerUUID, p.Database, p.DatabaseAccount, p.ClusterID, b.Namespace, p.NamespaceUID}, Actor: Actor{7, "local-admin", p.OwnerSubject}, Endpoint: sec.BootstrapConfigEndpoint, IdempotencyKey: "bootstrap-original", MatrixKey: "original-matrix", GrantSHA256: h, ConfigSHA256: h, RegistrySetSHA256: h, ReferenceSetSHA256: h, SelectionSHA256: h, CanonicalProfile: "system-backup-config-values.v1", Reference: sec.BootstrapSecretRef{Purpose: "capture_signing", IdentityHash: identity, Version: b.KeyVersion}, Binding: b, Probe: Probe{h, now.Add(5 * time.Minute)}}
	keys := map[string]ed25519.PrivateKey{}
	for _, entry := range []struct{ purpose, name string }{{"acceptance_record", "acceptance-key"}, {"capture_certificate", "capture-key"}, {"catalog_record", "catalog-key"}} {
		k, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		keys[entry.name] = priv
		t.Cleanup(func() { clear(priv) })
		r.Histories = append(r.Histories, PurposeKeys{entry.purpose, entry.name, []PublicKey{{"1", base64.StdEncoding.EncodeToString(k), r.Until.Add(time.Hour)}}})
	}
	f := recordFixture{record: r, pin: p, private: private, signing: keys}
	f.resign(t)
	return f
}
func (f *recordFixture) resign(t *testing.T) {
	t.Helper()
	raw, e := EncodeRecord(f.record)
	if e != nil {
		t.Fatal(e)
	}
	f.raw = raw
	f.pin.RecordSHA256 = digest(raw)
	f.sig = ed25519.Sign(f.private, append([]byte(RecordDomain), raw...))
}
func TestInstallationOwnerCodecIndependentPinAndPurpose(t *testing.T) {
	f := ownerRecordFixture(t)
	if _, e := VerifyRecord(f.raw, f.sig, f.pin); e != nil {
		t.Fatal("valid signed record", e)
	}
	for _, tc := range []struct {
		name string
		edit func(*recordFixture)
	}{
		{"wrong_installation", func(f *recordFixture) { f.record.Target.InstallationID = "other" }},
		{"wrong_actor", func(f *recordFixture) { f.record.Actor.OwnerSubject = "other" }},
		{"wrong_schema", func(f *recordFixture) { f.record.SchemaVersion = "other" }},
		{"wrong_purpose", func(f *recordFixture) { f.record.Reference.Purpose = "catalog_signing" }},
		{"wrong_signing_purpose", func(f *recordFixture) { f.record.Binding.Purpose = "catalog_record" }},
		{"latest", func(f *recordFixture) { f.record.Binding.ProviderVersion = "latest" }},
		{"cross_key_reuse", func(f *recordFixture) {
			f.record.Histories[1].Keys[0].PublicKey = f.record.Histories[0].Keys[0].PublicKey
		}},
		{"missing_history", func(f *recordFixture) { f.record.Histories = f.record.Histories[:2] }},
		{"probe_extends_grant", func(f *recordFixture) { f.record.Probe.Until = f.record.Until.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ownerRecordFixture(t)
			tc.edit(&c)
			c.resign(t)
			if _, e := VerifyRecord(c.raw, c.sig, c.pin); e == nil {
				t.Fatal("invalid owner meaning accepted")
			}
		})
	}
	changed := f.pin
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	changed.Issuer = other
	if _, e := VerifyRecord(f.raw, f.sig, changed); e == nil {
		t.Fatal("record chose its own issuer")
	}
	sig := ed25519.Sign(f.private, append([]byte("system-backup-capture-certificate.v1\x00"), f.raw...))
	if _, e := VerifyRecord(f.raw, sig, f.pin); e == nil {
		t.Fatal("business domain accepted for owner")
	}
}
func TestInstallationOwnerCodecRejectsCaseDuplicateUnknownAndWhitespace(t *testing.T) {
	f := ownerRecordFixture(t)
	var m map[string]json.RawMessage
	if json.Unmarshal(f.raw, &m) != nil {
		t.Fatal("fixture")
	}
	lower := map[string]json.RawMessage{}
	for k, v := range m {
		lower[k] = v
	}
	lower["schemaVersion"] = lower["SchemaVersion"]
	delete(lower, "SchemaVersion")
	raw, _ := canonical(lower)
	unknown := map[string]json.RawMessage{}
	for k, v := range m {
		unknown[k] = v
	}
	unknown["Approved"] = json.RawMessage("true")
	extra, _ := canonical(unknown)
	duplicate := append([]byte(`{"SchemaVersion":"bad",`), f.raw[1:]...)
	for _, body := range [][]byte{raw, extra, duplicate, append(bytes.Clone(f.raw), '\n')} {
		p := f.pin
		p.RecordSHA256 = digest(body)
		sig := ed25519.Sign(f.private, append([]byte(RecordDomain), body...))
		if _, e := VerifyRecord(body, sig, p); e == nil {
			t.Fatal("non-contract JSON accepted")
		}
	}
}
func TestInstallationOwnerCodecNestedReferenceUsesExactJSONTags(t *testing.T) {
	f := ownerRecordFixture(t)
	if _, e := VerifyRecord(f.raw, f.sig, f.pin); e != nil {
		t.Fatal("declared nested wire names rejected", e)
	}
	for _, field := range []struct{ wire, alias string }{{"purpose", "Purpose"}, {"identity_hash", "IDENTITY_HASH"}, {"identity_hash", "IdentityHash"}, {"version", "Version"}} {
		t.Run(field.alias, func(t *testing.T) {
			for _, duplicate := range []bool{false, true} {
				var record map[string]json.RawMessage
				var reference map[string]json.RawMessage
				if json.Unmarshal(f.raw, &record) != nil || json.Unmarshal(record["Reference"], &reference) != nil {
					t.Fatal("fixture")
				}
				reference[field.alias] = reference[field.wire]
				if !duplicate {
					delete(reference, field.wire)
				}
				nested, e := canonical(reference)
				if e != nil {
					t.Fatal(e)
				}
				record["Reference"] = nested
				raw, e := canonical(record)
				if e != nil {
					t.Fatal(e)
				}
				p := f.pin
				p.RecordSHA256 = digest(raw)
				sig := ed25519.Sign(f.private, append([]byte(RecordDomain), raw...))
				if _, e := VerifyRecord(raw, sig, p); e == nil {
					t.Fatal("nested alias accepted", field.alias, "duplicate", duplicate)
				}
			}
		})
	}
}
func TestInstallationOwnerHeadRevocationAndOriginalWindow(t *testing.T) {
	f := ownerRecordFixture(t)
	h := Head{SchemaVersion: HeadVersion, InstallationID: f.pin.InstallationID, EnrollmentID: f.pin.EnrollmentID, IssuerID: f.pin.IssuerID, OwnerSubject: f.pin.OwnerSubject, EnrollmentRevision: 1, Revision: 1, GrantID: f.pin.GrantID, GrantRevision: 1, RecordSHA256: f.pin.RecordSHA256, State: "active", NotBefore: f.record.NotBefore, Until: f.record.Until}
	sign := func(h Head) ([]byte, []byte) {
		raw, _ := EncodeHead(h)
		return raw, ed25519.Sign(f.private, append([]byte(HeadDomain), raw...))
	}
	raw, sig := sign(h)
	if _, e := verifyHead(raw, sig, f.pin); e != nil {
		t.Fatal(e)
	}
	h.State = "revoked"
	raw, sig = sign(h)
	if _, e := verifyHead(raw, sig, f.pin); e == nil {
		t.Fatal("revoked owner accepted")
	}
	h.State = "active"
	h.Revision = 0
	raw, sig = sign(h)
	if _, e := verifyHead(raw, sig, f.pin); e == nil {
		t.Fatal("old head accepted")
	}
	h.Revision = 1
	h.GrantRevision++
	raw, sig = sign(h)
	if _, e := verifyHead(raw, sig, f.pin); e == nil {
		t.Fatal("different grant selected")
	}
}

func TestInstallationOwnerCurrentIdentityCanDescribeExpiredPhysicalDependency(t *testing.T) {
	f := ownerRecordFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.record.NotBefore = now.Add(-time.Second)
	f.record.Probe.Until = now.Add(-2 * time.Second)
	f.resign(t)
	if _, e := VerifyRecord(f.raw, f.sig, f.pin); e != nil {
		t.Fatal("old physical window rejected current signed identity before L3", e)
	}
}
