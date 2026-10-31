package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSigningOwnerFixture(t *testing.T, record ArtifactSigningOwnerRecord) (ArtifactSigningOwnerSource, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reader := FileSigningRecordReader{filepath.Join(t.TempDir(), "owner.json"), filepath.Join(t.TempDir(), "owner.sig")}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if err := os.WriteFile(reader.RecordFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reader.SignatureFile, ed25519.Sign(key, append([]byte(ArtifactSigningOwnerDomain), raw...)), 0600); err != nil {
		t.Fatal(err)
	}
	return ArtifactSigningOwnerSource{Reader: reader, Pin: ArtifactSigningOwnerPin{InstallationID: record.Authorization.Signing.Binding.InstallationID, Purpose: record.Authorization.Signing.Binding.Purpose, RecordSHA256: hex.EncodeToString(h[:]), Revision: record.Revision, Issuer: pub}}, key
}

func TestPinnedInstallationArtifactSignersOriginalOwnerFileToTLS(t *testing.T) {
	f := newInstallationSigningFixture(t)
	var sources []ArtifactSigningOwnerSource
	for _, mount := range f.mounts {
		input := []byte("frozen-owner-input-for-" + mount.Binding.Purpose)
		h := sha256.Sum256(input)
		r := ArtifactSigningOwnerRecord{Authorization: ArtifactSigningAuthorizationRequest{Task: f.task, Signing: TransitSigningRequest{Binding: mount.Binding, InputSHA256: hex.EncodeToString(h[:])}}, Revision: 4, NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}
		source, _ := writeSigningOwnerFixture(t, r)
		sources = append(sources, source)
	}
	s, err := NewPinnedInstallationArtifactSigners(context.Background(), f.reader, f.pin, f.mounts, f.task, sources)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, mount := range f.mounts {
		input := []byte("frozen-owner-input-for-" + mount.Binding.Purpose)
		signer, err := s.Signer(mount.Binding.Purpose)
		if err != nil {
			t.Fatal(err)
		}
		value, err := signer.Sign(context.Background(), input)
		if err != nil {
			t.Fatal("original owner chain rejected", mount.Binding.Purpose, err)
		}
		history, err := s.History(context.Background())
		if err != nil || !ed25519.Verify(history.PurposeKeys(mount.Binding.Purpose)[0].PublicKey, input, value) {
			t.Fatal("independent signature verification failed", err)
		}
	}
	if f.login != 3 || f.signed != 3 || f.authorized != 0 {
		t.Fatal("production factory did not use concrete owner readers", f.login, f.signed, f.authorized)
	}
	// The owner record freezes one exact input; a different payload never
	// obtains a JWT, even with the same installation/task/key/workload.
	signer, _ := s.Signer("capture_certificate")
	if value, err := signer.Sign(context.Background(), []byte("different-frozen-input")); err == nil || len(value) != 0 || f.login != 3 {
		t.Fatal("original owner record authorized a different input")
	}
	// Removing just this original owner's record revokes this purpose without
	// destroying unrelated retained public verification material.
	reader := sources[0].Reader.(FileSigningRecordReader)
	if err := os.Remove(reader.RecordFile); err != nil {
		t.Fatal(err)
	}
	if value, err := signer.Sign(context.Background(), []byte("frozen-owner-input-for-capture_certificate")); err == nil || len(value) != 0 || f.login != 3 {
		t.Fatal("missing original owner record reached provider")
	}
	if _, err := s.History(context.Background()); err != nil {
		t.Fatal("owner grant removal destroyed retained public keys", err)
	}
}

func TestPinnedArtifactSigningAuthorityRejectsOriginalUseSubstitution(t *testing.T) {
	f := newInstallationSigningFixture(t)
	base := ArtifactSigningOwnerRecord{Authorization: ArtifactSigningAuthorizationRequest{Task: f.task, Signing: TransitSigningRequest{Binding: f.mounts[0].Binding, InputSHA256: strings.Repeat("a", 64)}}, Revision: 8, NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}
	for name, change := range map[string]func(*ArtifactSigningOwnerRecord){
		"installation":     func(r *ArtifactSigningOwnerRecord) { r.Authorization.Signing.Binding.InstallationID = "other" },
		"purpose":          func(r *ArtifactSigningOwnerRecord) { r.Authorization.Signing.Binding.Purpose = "acceptance_record" },
		"registry-version": func(r *ArtifactSigningOwnerRecord) { r.Authorization.Signing.Binding.KeyVersion = "other" },
		"provider-version": func(r *ArtifactSigningOwnerRecord) { r.Authorization.Signing.Binding.ProviderVersion = "8" },
		"task":             func(r *ArtifactSigningOwnerRecord) { r.Authorization.Task.BackupPublicID = "sbk_other" },
		"attempt":          func(r *ArtifactSigningOwnerRecord) { r.Authorization.Task.AttemptNo++ },
		"operation":        func(r *ArtifactSigningOwnerRecord) { r.Authorization.Task.OperationID = "other" },
		"workload":         func(r *ArtifactSigningOwnerRecord) { r.Authorization.Task.Workload.PodUID = "other" },
		"digest":           func(r *ArtifactSigningOwnerRecord) { r.Authorization.Signing.InputSHA256 = strings.Repeat("b", 64) },
		"revoked":          func(r *ArtifactSigningOwnerRecord) { r.Revoked = true },
		"expired":          func(r *ArtifactSigningOwnerRecord) { r.Until = time.Now().Add(-time.Second) },
		"future":           func(r *ArtifactSigningOwnerRecord) { r.NotBefore = time.Now().Add(time.Second) },
		"overlong":         func(r *ArtifactSigningOwnerRecord) { r.Until = r.NotBefore.Add(25 * time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			record := base
			change(&record)
			source, _ := writeSigningOwnerFixture(t, record)
			a, err := NewPinnedArtifactSigningAuthority(source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.AuthorizeArtifactSigning(context.Background(), base.Authorization); err == nil {
				t.Fatal("wrong signed original use accepted")
			}
		})
	}
	source, key := writeSigningOwnerFixture(t, base)
	a, err := NewPinnedArtifactSigningAuthority(source)
	if err != nil {
		t.Fatal(err)
	}
	u, err := a.AuthorizeArtifactSigning(context.Background(), base.Authorization)
	if err != nil {
		t.Fatal(err)
	}
	if err = u.Use.Recheck(context.Background(), base.Authorization.Signing); err != nil {
		t.Fatal(err)
	}
	record := base
	record.Revision++
	record.Revoked = true
	raw, _ := json.Marshal(record)
	reader := source.Reader.(FileSigningRecordReader)
	if err = os.WriteFile(reader.RecordFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(reader.SignatureFile, ed25519.Sign(key, append([]byte(ArtifactSigningOwnerDomain), raw...)), 0600); err != nil {
		t.Fatal(err)
	}
	if u.Use.Recheck(context.Background(), base.Authorization.Signing) == nil {
		t.Fatal("same original use survived changed/revoked owner material")
	}
	if f.login != 0 || f.signed != 0 {
		t.Fatal("authority-only validation contacted provider")
	}
}

func TestSigningTokenCannotLeakThroughFormatting(t *testing.T) {
	token := SigningToken{Secret: []byte("must-not-enter-logs-or-json")}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, token), string(token.Secret)) {
			t.Fatal("secret in formatted token")
		}
	}
	if raw, err := json.Marshal(token); err == nil || len(raw) != 0 {
		t.Fatal("token serialized")
	}
}
