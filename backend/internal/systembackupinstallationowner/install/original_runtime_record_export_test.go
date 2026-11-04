package install

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The existing r2 fixture supplies real private/public files, not native SQL
// authority. Re-sign its material with a known test owner for export tests.
func runtimeRecordExportFixture(t *testing.T, mutate func(*OriginalRuntimeRecordExport), foreignSigner bool) (*Installer, EnrollmentPin, BootstrapSourceFilePin, BootstrapSourceFilePin) {
	t.Helper()
	i, enrollment, material := runtimeIssuerReaderFixture(t, nil, false)
	raw, err := os.ReadFile(material.File)
	if err != nil {
		t.Fatal(err)
	}
	var original signedOriginalRuntimeIssuerMaterial
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	i.public = public
	raw, err = canonical(signedOriginalRuntimeIssuerMaterial{Record: original.Record, Signature: ed25519.Sign(key, append([]byte(OriginalRuntimeIssuerMaterialDomain), original.Record...))})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(material.File, raw, 0600); err != nil {
		t.Fatal(err)
	}
	material.SHA256 = hash(raw)
	m, err := i.readOriginalRuntimeIssuerMaterial(material, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	d := OriginalRuntimeRecordExport{Version: "original-runtime-record-key-export.v1", PlanSHA256: i.planHash, Enrollment: enrollment, Target: i.plan.Target, Material: material}
	for name, source := range map[string]BootstrapSourceFilePin{"execution-record.key": m.RecordKey, "capture-record.key": m.CaptureKey} {
		raw, err := os.ReadFile(source.File)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(directory, name)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			clear(raw)
			t.Fatal(err)
		}
		pin := BootstrapSourceFilePin{File: file, SHA256: hash(raw)}
		clear(raw)
		if name == "execution-record.key" {
			d.RecordKey = pin
		} else {
			d.CaptureKey = pin
		}
	}
	if mutate != nil {
		mutate(&d)
	}
	if foreignSigner {
		_, other, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		clear(key)
		key = other
		defer clear(other)
	}
	record, err := canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = canonical(signedOriginalRuntimeRecordExport{Record: record, Signature: ed25519.Sign(key, append([]byte(OriginalRuntimeRecordExportDomain), record...))})
	if err != nil {
		t.Fatal(err)
	}
	pin := BootstrapSourceFilePin{File: filepath.Join(directory, "record-export.signed.json"), SHA256: hash(raw)}
	if err := os.WriteFile(pin.File, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return i, enrollment, material, pin
}

func TestOriginalRuntimeRecordExportReaderAcceptsAuthenticatedRelocation(t *testing.T) {
	i, enrollment, material, pin := runtimeRecordExportFixture(t, nil, false)
	d, err := i.readOriginalRuntimeRecordExport(enrollment, material, pin)
	if err != nil {
		t.Fatal(err)
	}
	m, err := i.readOriginalRuntimeIssuerMaterial(material, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if d.RecordKey.SHA256 != m.RecordKey.SHA256 || d.CaptureKey.SHA256 != m.CaptureKey.SHA256 || d.RecordKey.File == m.RecordKey.File || d.CaptureKey.File == m.CaptureKey.File {
		t.Fatal("original purpose bytes or separate runtime paths lost")
	}
}

func TestOriginalRuntimeRecordExportReaderRejectsPurposePlanAndCandidateSigner(t *testing.T) {
	for _, choice := range []string{"purpose", "plan", "signer"} {
		i, enrollment, material, pin := runtimeRecordExportFixture(t, func(d *OriginalRuntimeRecordExport) {
			switch choice {
			case "purpose":
				d.RecordKey, d.CaptureKey = d.CaptureKey, d.RecordKey
			case "plan":
				d.PlanSHA256 = hash([]byte("foreign-plan"))
			}
		}, choice == "signer")
		if _, err := i.readOriginalRuntimeRecordExport(enrollment, material, pin); err == nil {
			t.Fatal("foreign record export accepted")
		}
	}
}

func TestOriginalRuntimeRecordExportReaderRejectsChangedExportedBytes(t *testing.T) {
	i, enrollment, material, pin := runtimeRecordExportFixture(t, nil, false)
	if err := os.WriteFile(filepath.Join(filepath.Dir(pin.File), "capture-record.key"), make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := i.readOriginalRuntimeRecordExport(enrollment, material, pin); err == nil {
		t.Fatal("changed exported purpose bytes accepted")
	}
}
