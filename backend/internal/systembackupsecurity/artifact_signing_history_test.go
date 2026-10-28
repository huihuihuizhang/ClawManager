package systembackupsecurity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestArtifactSigningKeyHistorySeparationAndCopies(t *testing.T) {
	newPublic := func() ed25519.PublicKey {
		t.Helper()
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public
	}
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(30 * 24 * time.Hour)
	keys := []ArtifactSigningPublicKey{
		{InstallationID: "installation_test", Purpose: "capture_certificate", KeyID: "capture", KeyVersion: "v1", PublicKey: newPublic(), NotBefore: start, NotAfter: end},
		{InstallationID: "installation_test", Purpose: "acceptance_record", KeyID: "acceptance", KeyVersion: "v1", PublicKey: newPublic(), NotBefore: start, NotAfter: end, Revoked: true},
		{InstallationID: "installation_test", Purpose: "catalog_record", KeyID: "catalog", KeyVersion: "v1", PublicKey: newPublic(), NotBefore: start, NotAfter: end},
		{InstallationID: "installation_test", Purpose: "acceptance_record", KeyID: "acceptance", KeyVersion: "v2", PublicKey: newPublic(), NotBefore: end, NotAfter: end.Add(30 * 24 * time.Hour)},
	}
	history, err := NewArtifactSigningKeyHistory("installation_test", keys)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), keys[1].PublicKey...)
	keys[1].PublicKey[0] ^= 0xff
	got := history.PurposeKeys("acceptance_record")
	if len(got) != 2 {
		t.Fatalf("historical versions missing: %d", len(got))
	}
	var found bool
	for _, key := range got {
		if key.KeyVersion == "v1" {
			found = true
			if !key.Revoked || string(key.PublicKey) != string(original) {
				t.Fatal("source changed frozen historical key")
			}
			key.PublicKey[0] ^= 0xff
		}
	}
	if !found {
		t.Fatal("revoked historical version missing")
	}
	for _, key := range history.PurposeKeys("acceptance_record") {
		if key.KeyVersion == "v1" && string(key.PublicKey) != string(original) {
			t.Fatal("returned key mutated history")
		}
	}
	if history.PurposeKeys("strong_auth_issuer") != nil {
		t.Fatal("non-artifact purpose available")
	}
	keys[1].PublicKey = original
	for name, change := range map[string]func([]ArtifactSigningPublicKey) []ArtifactSigningPublicKey{
		"missing purpose": func(k []ArtifactSigningPublicKey) []ArtifactSigningPublicKey { return k[:2] },
		"same material across purposes": func(k []ArtifactSigningPublicKey) []ArtifactSigningPublicKey {
			k[2].PublicKey = k[0].PublicKey
			return k
		},
		"same material across versions": func(k []ArtifactSigningPublicKey) []ArtifactSigningPublicKey {
			k[3].PublicKey = k[1].PublicKey
			return k
		},
		"duplicate identity": func(k []ArtifactSigningPublicKey) []ArtifactSigningPublicKey { k[3].KeyVersion = "v1"; return k },
		"invalid interval": func(k []ArtifactSigningPublicKey) []ArtifactSigningPublicKey {
			k[1].NotAfter = k[1].NotBefore
			return k
		},
	} {
		t.Run(name, func(t *testing.T) {
			copyKeys := append([]ArtifactSigningPublicKey(nil), keys...)
			if _, err := NewArtifactSigningKeyHistory("installation_test", change(copyKeys)); err == nil {
				t.Fatal("invalid history accepted")
			}
		})
	}
	other := append([]ArtifactSigningPublicKey(nil), keys...)
	other[1].InstallationID = "installation_other"
	if _, err := NewArtifactSigningKeyHistory("installation_test", other); err == nil {
		t.Fatal("cross-installation key accepted")
	}
}

func TestArtifactSigningRetention(t *testing.T) {
	public := func() ed25519.PublicKey {
		key, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(30 * 24 * time.Hour)
	keys := []ArtifactSigningPublicKey{
		{InstallationID: "installation_test", Purpose: "capture_certificate", KeyID: "capture", KeyVersion: "v1", PublicKey: public(), NotBefore: start, NotAfter: end},
		{InstallationID: "installation_test", Purpose: "acceptance_record", KeyID: "acceptance", KeyVersion: "v1", PublicKey: public(), NotBefore: start, NotAfter: end},
		{InstallationID: "installation_test", Purpose: "catalog_record", KeyID: "catalog", KeyVersion: "v1", PublicKey: public(), NotBefore: start, NotAfter: end},
	}
	makeHistory := func(input []ArtifactSigningPublicKey) *ArtifactSigningKeyHistory {
		t.Helper()
		history, err := NewArtifactSigningKeyHistory("installation_test", input)
		if err != nil {
			t.Fatal(err)
		}
		return history
	}
	previous := makeHistory(keys)
	ref := []ArtifactSigningReference{{Purpose: "acceptance_record", KeyID: "acceptance", KeyVersion: "v1"}}
	rotated := append([]ArtifactSigningPublicKey(nil), keys...)
	rotated = append(rotated, ArtifactSigningPublicKey{InstallationID: "installation_test", Purpose: "acceptance_record", KeyID: "acceptance", KeyVersion: "v2", PublicKey: public(), NotBefore: end, NotAfter: end.Add(30 * 24 * time.Hour)})
	if result, err := ValidateArtifactSigningRetention(previous, makeHistory(rotated), ref); err != nil || len(result.DegradedReferences) != 0 {
		t.Fatal(err)
	}
	if _, err := ValidateArtifactSigningRetention(previous, makeHistory(rotated), nil); err == nil {
		t.Fatal("unknown reference scan accepted")
	}
	removed := []ArtifactSigningPublicKey{keys[0], keys[2], rotated[3]}
	if _, err := ValidateArtifactSigningRetention(previous, makeHistory(removed), ref); err == nil {
		t.Fatal("referenced historical key removed")
	}
	if _, err := ValidateArtifactSigningRetention(previous, makeHistory(removed), []ArtifactSigningReference{}); err != nil {
		t.Fatal("unreferenced retirement rejected", err)
	}
	rebound := append([]ArtifactSigningPublicKey(nil), rotated...)
	rebound[1].PublicKey = public()
	if _, err := ValidateArtifactSigningRetention(previous, makeHistory(rebound), ref); err == nil {
		t.Fatal("historical key material rebound")
	}
	shortened := append([]ArtifactSigningPublicKey(nil), rotated...)
	shortened[1].NotBefore = start.Add(time.Hour)
	if _, err := ValidateArtifactSigningRetention(previous, makeHistory(shortened), ref); err == nil {
		t.Fatal("historical key start moved forward")
	}
	shortened[1].NotBefore = start
	shortened[1].NotAfter = end.Add(-time.Hour)
	if _, err := ValidateArtifactSigningRetention(previous, makeHistory(shortened), ref); err == nil {
		t.Fatal("historical key expiry moved backward")
	}
	extended := append([]ArtifactSigningPublicKey(nil), rotated...)
	extended[1].NotBefore = start.Add(-time.Hour)
	extended[1].NotAfter = end.Add(time.Hour)
	if _, err := ValidateArtifactSigningRetention(previous, makeHistory(extended), ref); err != nil {
		t.Fatal("non-shrinking historical key window rejected", err)
	}
	revoked := append([]ArtifactSigningPublicKey(nil), rotated...)
	revoked[1].Revoked = true
	if result, err := ValidateArtifactSigningRetention(previous, makeHistory(revoked), append(ref, ref...)); err != nil || len(result.DegradedReferences) != 1 || result.DegradedReferences[0] != ref[0] {
		t.Fatal("compromise revocation blocked", err)
	}
	if _, err := ValidateArtifactSigningRetention(makeHistory(revoked), makeHistory(rotated), ref); err == nil {
		t.Fatal("revocation rollback accepted")
	}
	if _, err := ValidateArtifactSigningRetention(previous, makeHistory(rotated), []ArtifactSigningReference{{Purpose: "acceptance_record", KeyID: "missing", KeyVersion: "v1"}}); err == nil {
		t.Fatal("unknown referenced key accepted")
	}
}
