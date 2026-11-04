package install

import (
	"context"
	"crypto/ed25519"
	"path/filepath"

	owner "clawreef/internal/systembackupinstallationowner"
)

const OriginalRuntimeRecordExportDomain = "system-backup-original-runtime-record-key-export.v1\x00"

type OriginalRuntimeRecordExport struct {
	Version, PlanSHA256             string
	Enrollment                      EnrollmentPin
	Target                          owner.Target
	Material, RecordKey, CaptureKey BootstrapSourceFilePin
}

type signedOriginalRuntimeRecordExport struct{ Record, Signature []byte }

type OriginalRuntimeRecordExportReceipt struct {
	Version                                 string
	Material, Export, RecordKey, CaptureKey BootstrapSourceFilePin
}

// Only these TWO original random32 files are exported to the runtime mount.
// The six purpose Ed25519 signers remain solely in the original owner directory.
func (i *Installer) ExportOriginalRuntimeRecordKeys(ctx context.Context, password []byte, enrollment EnrollmentPin, material BootstrapSourceFilePin, issuerPrivate []byte, directory string) (OriginalRuntimeRecordExportReceipt, error) {
	var zero OriginalRuntimeRecordExportReceipt
	if i == nil || privateDirectory(directory) != nil || filepath.Dir(material.File) == directory {
		return zero, ErrInstall
	}
	s, err := i.authenticate(ctx, password)
	if err != nil {
		return zero, ErrInstall
	}
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, nil); err != nil {
		return zero, err
	}
	before, _, err := snapshot(ctx, s)
	if err != nil {
		return zero, ErrInstall
	}
	m, err := i.readOriginalRuntimeIssuerMaterial(material, enrollment)
	if err != nil {
		return zero, err
	}
	key, err := s.privateKey(issuerPrivate)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	d := OriginalRuntimeRecordExport{Version: "original-runtime-record-key-export.v1", PlanSHA256: i.planHash, Enrollment: enrollment, Target: i.plan.Target, Material: material}
	files := map[string][]byte{}
	defer func() {
		for _, raw := range files {
			clear(raw)
		}
	}()
	for name, pin := range map[string]BootstrapSourceFilePin{"execution-record.key": m.RecordKey, "capture-record.key": m.CaptureKey} {
		raw, err := readBootstrapSourcePin(pin, 32)
		if err != nil || len(raw) != 32 {
			clear(raw)
			return zero, ErrInstall
		}
		files[name] = raw
		target := BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(raw)}
		if name == "execution-record.key" {
			d.RecordKey = target
		} else {
			d.CaptureKey = target
		}
	}
	record, err := canonical(d)
	if err != nil {
		return zero, ErrInstall
	}
	raw, err := canonical(signedOriginalRuntimeRecordExport{Record: record, Signature: ed25519.Sign(key, append([]byte(OriginalRuntimeRecordExportDomain), record...))})
	if err != nil {
		return zero, ErrInstall
	}
	files["record-export.signed.json"] = raw
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, &before.cas); err != nil {
		return zero, err
	}
	if writeOriginalRuntimeIssuerFiles(directory, files) != nil {
		return zero, ErrOriginalRuntimeIssuerMaterialUnconfirmed
	}
	pin := BootstrapSourceFilePin{File: filepath.Join(directory, "record-export.signed.json"), SHA256: hash(raw)}
	if _, err = i.readOriginalRuntimeRecordExport(enrollment, material, pin); err != nil {
		return zero, ErrOriginalRuntimeIssuerMaterialUnconfirmed
	}
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, &before.cas); err != nil {
		return zero, ErrOriginalRuntimeIssuerMaterialUnconfirmed
	}
	return OriginalRuntimeRecordExportReceipt{Version: "original-runtime-record-key-export-result.v1", Material: material, Export: pin, RecordKey: d.RecordKey, CaptureKey: d.CaptureKey}, nil
}

func (i *Installer) readOriginalRuntimeRecordExport(enrollment EnrollmentPin, material, pin BootstrapSourceFilePin) (OriginalRuntimeRecordExport, error) {
	var zero OriginalRuntimeRecordExport
	if i == nil || filepath.Base(pin.File) != "record-export.signed.json" || privateDirectory(filepath.Dir(pin.File)) != nil {
		return zero, ErrInstall
	}
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(pin.File)); err != nil || resolved != filepath.Dir(pin.File) {
		return zero, ErrInstall
	}
	m, err := i.readOriginalRuntimeIssuerMaterial(material, enrollment)
	if err != nil {
		return zero, err
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	var signed signedOriginalRuntimeRecordExport
	if err != nil || decodeExact(raw, &signed) != nil || !ed25519.Verify(i.public, append([]byte(OriginalRuntimeRecordExportDomain), signed.Record...), signed.Signature) {
		return zero, ErrInstall
	}
	var d OriginalRuntimeRecordExport
	if decodeExact(signed.Record, &d) != nil || d.Version != "original-runtime-record-key-export.v1" || d.PlanSHA256 != i.planHash || d.Enrollment != enrollment || d.Target != i.plan.Target || d.Material != material || d.RecordKey.SHA256 != m.RecordKey.SHA256 || d.CaptureKey.SHA256 != m.CaptureKey.SHA256 || d.RecordKey.SHA256 == d.CaptureKey.SHA256 {
		return zero, ErrInstall
	}
	for name, key := range map[string]BootstrapSourceFilePin{"execution-record.key": d.RecordKey, "capture-record.key": d.CaptureKey} {
		if key.File != filepath.Join(filepath.Dir(pin.File), name) {
			return zero, ErrInstall
		}
		raw, err := readBootstrapSourcePin(key, 32)
		valid := err == nil && len(raw) == 32
		clear(raw)
		if !valid {
			return zero, ErrInstall
		}
	}
	return d, nil
}

// The real first Forward issuer consumes THIS original-owner-authenticated
// export, derives its RecordKey/CaptureKey pins and matches core.KeyDirectory.
// Runtime paths differ from custody paths; original purpose bytes never do.
func (i *Installer) ReadOriginalRuntimeRecordExport(ctx context.Context, password []byte, enrollment EnrollmentPin, material, pin BootstrapSourceFilePin) (OriginalRuntimeRecordExport, error) {
	var zero OriginalRuntimeRecordExport
	if i == nil {
		return zero, ErrInstall
	}
	s, err := i.authenticate(ctx, password)
	if err != nil {
		return zero, ErrInstall
	}
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, nil); err != nil {
		return zero, err
	}
	before, _, err := snapshot(ctx, s)
	if err != nil {
		return zero, ErrInstall
	}
	d, err := i.readOriginalRuntimeRecordExport(enrollment, material, pin)
	if err != nil {
		return zero, err
	}
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, &before.cas); err != nil {
		return zero, err
	}
	return d, nil
}
