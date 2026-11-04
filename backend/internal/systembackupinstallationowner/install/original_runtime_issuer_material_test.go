package install

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// Exercises the actual signed-material reader. It supplies no SQL/native
// authority and is not an integration assertion about installer authentication.
func runtimeIssuerReaderFixture(t *testing.T, mutate func(*OriginalRuntimeIssuerMaterial), signingForeign bool) (*Installer, EnrollmentPin, BootstrapSourceFilePin) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	i := &Installer{public: public, planHash: hash([]byte("original-plan"))}
	i.plan.Target.InstallationID = "installation_original"
	enrollment := EnrollmentPin{ConfigMapUID: "actual-enrollment-uid", DocumentSHA256: hash([]byte("original-enrollment"))}
	m := OriginalRuntimeIssuerMaterial{Version: "original-runtime-purpose-issuers.v1", PlanSHA256: i.planHash, Enrollment: enrollment, Target: i.plan.Target, Issuers: map[string]OriginalRuntimeIssuerFiles{}}
	for _, purpose := range originalRuntimeIssuerPurposes {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		for name, raw := range map[string][]byte{purpose + ".private": priv, purpose + ".public": pub} {
			if e := os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
				clear(priv)
				t.Fatal(e)
			}
		}
		m.Issuers[purpose] = OriginalRuntimeIssuerFiles{PrivateKey: BootstrapSourceFilePin{File: filepath.Join(dir, purpose+".private"), SHA256: hash(priv)}, PublicKey: BootstrapSourceFilePin{File: filepath.Join(dir, purpose+".public"), SHA256: hash(pub)}}
		clear(priv)
	}
	for _, name := range []string{"execution-record.key", "capture-record.key"} {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			clear(raw)
			t.Fatal(err)
		}
		pin := BootstrapSourceFilePin{File: file, SHA256: hash(raw)}
		clear(raw)
		if name == "execution-record.key" {
			m.RecordKey = pin
		} else {
			m.CaptureKey = pin
		}
	}
	if mutate != nil {
		mutate(&m)
	}
	record, e := canonical(m)
	if e != nil {
		t.Fatal(e)
	}
	if signingForeign {
		_, other, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		clear(key)
		key = other
		defer clear(other)
	}
	raw, e := canonical(signedOriginalRuntimeIssuerMaterial{Record: record, Signature: ed25519.Sign(key, append([]byte(OriginalRuntimeIssuerMaterialDomain), record...))})
	if e != nil {
		t.Fatal(e)
	}
	pin := BootstrapSourceFilePin{File: filepath.Join(dir, "original-runtime-issuers.json"), SHA256: hash(raw)}
	if e := os.WriteFile(pin.File, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return i, enrollment, pin
}

func TestOriginalRuntimeIssuerReaderAcceptsOnlyExactOwnerMaterial(t *testing.T) {
	i, enrollment, pin := runtimeIssuerReaderFixture(t, nil, false)
	m, err := i.readOriginalRuntimeIssuerMaterial(pin, enrollment)
	if err != nil || len(m.Issuers) != 6 {
		t.Fatalf("exact original material rejected: %v", err)
	}
	if _, err := i.readOriginalRuntimeIssuerMaterial(pin, EnrollmentPin{ConfigMapUID: "foreign", DocumentSHA256: enrollment.DocumentSHA256}); err == nil {
		t.Fatal("foreign enrollment accepted")
	}
}

func TestOriginalRuntimeIssuerReaderRejectsCandidateTrustAndPlan(t *testing.T) {
	for _, foreignSigner := range []bool{true, false} {
		i, enrollment, pin := runtimeIssuerReaderFixture(t, func(m *OriginalRuntimeIssuerMaterial) {
			if !foreignSigner {
				m.PlanSHA256 = hash([]byte("foreign-plan"))
			}
		}, foreignSigner)
		if _, err := i.readOriginalRuntimeIssuerMaterial(pin, enrollment); err == nil {
			t.Fatal("candidate authority or foreign plan accepted")
		}
	}
}

func TestOriginalRuntimeIssuerReaderRejectsCrossPurposeAndDuplicateRoots(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		i, enrollment, pin := runtimeIssuerReaderFixture(t, func(m *OriginalRuntimeIssuerMaterial) {
			a, b := m.Issuers["forward_execution"], m.Issuers["provider_permission"]
			if duplicate {
				b.PublicKey.SHA256 = a.PublicKey.SHA256
				m.Issuers["provider_permission"] = b
			} else {
				m.Issuers["forward_execution"], m.Issuers["provider_permission"] = b, a
			}
		}, false)
		if _, err := i.readOriginalRuntimeIssuerMaterial(pin, enrollment); err == nil {
			t.Fatal("purpose replacement accepted")
		}
	}
}

func TestOriginalRuntimeIssuerReaderRejectsChangedKeyOrManifest(t *testing.T) {
	for _, manifest := range []bool{true, false} {
		i, enrollment, pin := runtimeIssuerReaderFixture(t, nil, false)
		path := pin.File
		if !manifest {
			path = filepath.Join(filepath.Dir(pin.File), "provider_permit_delivery.private")
		}
		if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := i.readOriginalRuntimeIssuerMaterial(pin, enrollment); err == nil {
			t.Fatal("changed original file accepted")
		}
	}
}

func TestOriginalRuntimeIssuerWriterNeverReplacesRetainedMaterial(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeOriginalRuntimeIssuerFiles(dir, map[string][]byte{"retained.private": []byte("original")}); err != nil {
		t.Fatal(err)
	}
	if err := writeOriginalRuntimeIssuerFiles(dir, map[string][]byte{"retained.private": []byte("replacement"), "another.private": []byte("new")}); err == nil {
		t.Fatal("overwrite accepted")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "retained.private"))
	if err != nil || string(raw) != "original" {
		t.Fatal("original material changed")
	}
	if _, err := os.Stat(filepath.Join(dir, "another.private")); !os.IsNotExist(err) {
		t.Fatal("failed preflight created additional key")
	}
}

func TestOriginalRuntimeIssuerReaderRejectsForeignTargetOrRecordPurpose(t *testing.T) {
	for _, foreignTarget := range []bool{true, false} {
		i, enrollment, pin := runtimeIssuerReaderFixture(t, func(m *OriginalRuntimeIssuerMaterial) {
			if foreignTarget {
				m.Target.InstallationID = "installation_foreign"
			} else {
				m.CaptureKey.SHA256 = m.RecordKey.SHA256
			}
		}, false)
		if _, err := i.readOriginalRuntimeIssuerMaterial(pin, enrollment); err == nil {
			t.Fatal("foreign target or duplicate record purpose accepted")
		}
	}
}

func TestOriginalRuntimeIssuerReaderRejectsChangedRecordKey(t *testing.T) {
	i, enrollment, pin := runtimeIssuerReaderFixture(t, nil, false)
	if err := os.WriteFile(filepath.Join(filepath.Dir(pin.File), "execution-record.key"), make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := i.readOriginalRuntimeIssuerMaterial(pin, enrollment); err == nil {
		t.Fatal("changed record key accepted")
	}
}
