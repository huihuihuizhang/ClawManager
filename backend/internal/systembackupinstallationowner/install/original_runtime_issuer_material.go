package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	owner "clawreef/internal/systembackupinstallationowner"
)

const OriginalRuntimeIssuerMaterialDomain = "system-backup-original-runtime-issuer-material.v1\x00"

// These existing consumers have independent authorities. In particular neither
// adoption keys nor the enrollment signer is a runtime purpose signer.
var originalRuntimeIssuerPurposes = []string{
	"forward_execution", "installation_mapping", "provider_permission",
	"formal_verifier", "provider_permit_business", "provider_permit_delivery",
}

var ErrOriginalRuntimeIssuerMaterialUnconfirmed = errors.New("original runtime issuer files retained; original owner confirmation required")

type OriginalRuntimeIssuerFiles struct {
	PrivateKey, PublicKey BootstrapSourceFilePin
}

// Locator data only, never a provider permission, grant or successful task.
// The exact canonical document is signed by the already enrolled owner.
type OriginalRuntimeIssuerMaterial struct {
	Version, PlanSHA256   string
	Enrollment            EnrollmentPin
	Target                owner.Target
	Issuers               map[string]OriginalRuntimeIssuerFiles
	RecordKey, CaptureKey BootstrapSourceFilePin
}

type signedOriginalRuntimeIssuerMaterial struct{ Record, Signature []byte }

// PrepareOriginalRuntimeIssuerMaterial uses the same authenticated native
// installer boundary as original adoption issuer preparation. It does not
// replace immutable enrollment or allow a candidate key to establish trust.
func (i *Installer) PrepareOriginalRuntimeIssuerMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, issuerPrivate []byte, directory string) (BootstrapSourceFilePin, error) {
	var zero BootstrapSourceFilePin
	if i == nil || privateDirectory(directory) != nil {
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
	ownerKey, err := s.privateKey(issuerPrivate)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(ownerKey)
	m := OriginalRuntimeIssuerMaterial{Version: "original-runtime-purpose-issuers.v1", PlanSHA256: i.planHash, Enrollment: enrollment, Target: i.plan.Target, Issuers: map[string]OriginalRuntimeIssuerFiles{}}
	files := map[string][]byte{}
	defer func() {
		for _, raw := range files {
			clear(raw)
		}
	}()
	seen := map[string]bool{hash(i.public): true}
	for _, purpose := range originalRuntimeIssuerPurposes {
		public, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return zero, ErrInstall
		}
		files[purpose+".private"], files[purpose+".public"] = private, public
		if seen[hash(public)] {
			return zero, ErrInstall
		}
		seen[hash(public)] = true
		m.Issuers[purpose] = OriginalRuntimeIssuerFiles{
			PrivateKey: BootstrapSourceFilePin{File: filepath.Join(directory, purpose+".private"), SHA256: hash(private)},
			PublicKey:  BootstrapSourceFilePin{File: filepath.Join(directory, purpose+".public"), SHA256: hash(public)},
		}
	}
	for _, name := range []string{"execution-record.key", "capture-record.key"} {
		key := make([]byte, 32)
		files[name] = key
		if _, err := rand.Read(key); err != nil || seen[hash(key)] {
			return zero, ErrInstall
		}
		seen[hash(key)] = true
		pin := BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(key)}
		if name == "execution-record.key" {
			m.RecordKey = pin
		} else {
			m.CaptureKey = pin
		}
	}
	record, err := canonical(m)
	if err != nil {
		return zero, ErrInstall
	}
	raw, err := canonical(signedOriginalRuntimeIssuerMaterial{Record: record, Signature: ed25519.Sign(ownerKey, append([]byte(OriginalRuntimeIssuerMaterialDomain), record...))})
	if err != nil {
		return zero, ErrInstall
	}
	files["original-runtime-issuers.json"] = raw
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, &before.cas); err != nil {
		return zero, err
	}
	// Create-only files are deliberately retained after any partial write. A
	// subsequent invocation never overwrites them or generates replacements.
	if writeOriginalRuntimeIssuerFiles(directory, files) != nil {
		return zero, ErrOriginalRuntimeIssuerMaterialUnconfirmed
	}
	pin := BootstrapSourceFilePin{File: filepath.Join(directory, "original-runtime-issuers.json"), SHA256: hash(raw)}
	if _, err = i.readOriginalRuntimeIssuerMaterial(pin, enrollment); err != nil {
		return zero, ErrOriginalRuntimeIssuerMaterialUnconfirmed
	}
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, &before.cas); err != nil {
		return zero, ErrOriginalRuntimeIssuerMaterialUnconfirmed
	}
	return pin, nil
}

func writeOriginalRuntimeIssuerFiles(directory string, files map[string][]byte) error {
	if privateDirectory(directory) != nil {
		return ErrInstall
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return ErrInstall
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return ErrInstall
	}
	defer root.Close()
	for name := range files {
		if filepath.Base(name) != name {
			return ErrInstall
		}
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			return ErrInstall
		}
	}
	for name, raw := range files {
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return ErrInstall
		}
		n, writeErr := f.Write(raw)
		syncErr, closeErr := f.Sync(), f.Close()
		if writeErr != nil || n != len(raw) || syncErr != nil || closeErr != nil {
			return ErrInstall
		}
	}
	if runtime.GOOS != "windows" {
		f, err := os.Open(directory)
		if err != nil {
			return ErrInstall
		}
		syncErr, closeErr := f.Sync(), f.Close()
		if syncErr != nil || closeErr != nil {
			return ErrInstall
		}
	}
	return nil
}

func (i *Installer) readOriginalRuntimeIssuerMaterial(pin BootstrapSourceFilePin, enrollment EnrollmentPin) (OriginalRuntimeIssuerMaterial, error) {
	var zero OriginalRuntimeIssuerMaterial
	if i == nil || len(i.public) != ed25519.PublicKeySize || !filepath.IsAbs(pin.File) || filepath.Clean(pin.File) != pin.File || filepath.Base(pin.File) != "original-runtime-issuers.json" || privateDirectory(filepath.Dir(pin.File)) != nil {
		return zero, ErrInstall
	}
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(pin.File)); err != nil || resolved != filepath.Dir(pin.File) {
		return zero, ErrInstall
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	var signed signedOriginalRuntimeIssuerMaterial
	if err != nil || decodeExact(raw, &signed) != nil || !ed25519.Verify(i.public, append([]byte(OriginalRuntimeIssuerMaterialDomain), signed.Record...), signed.Signature) {
		return zero, ErrInstall
	}
	var m OriginalRuntimeIssuerMaterial
	if decodeExact(signed.Record, &m) != nil || m.Version != "original-runtime-purpose-issuers.v1" || m.PlanSHA256 != i.planHash || m.Enrollment != enrollment || m.Target != i.plan.Target || len(m.Issuers) != len(originalRuntimeIssuerPurposes) {
		return zero, ErrInstall
	}
	seen := map[string]bool{hash(i.public): true}
	for _, purpose := range originalRuntimeIssuerPurposes {
		key, ok := m.Issuers[purpose]
		if !ok || key.PrivateKey.File != filepath.Join(filepath.Dir(pin.File), purpose+".private") || key.PublicKey.File != filepath.Join(filepath.Dir(pin.File), purpose+".public") || seen[key.PublicKey.SHA256] {
			return zero, ErrInstall
		}
		private, e := readBootstrapSourcePin(key.PrivateKey, ed25519.PrivateKeySize)
		public, pe := readBootstrapSourcePin(key.PublicKey, ed25519.PublicKeySize)
		valid := e == nil && pe == nil && len(private) == ed25519.PrivateKeySize && len(public) == ed25519.PublicKeySize
		if valid {
			canonicalKey := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
			valid = bytes.Equal(private, canonicalKey) && bytes.Equal(public, canonicalKey[ed25519.SeedSize:])
			clear(canonicalKey)
		}
		clear(private)
		if !valid {
			return zero, ErrInstall
		}
		seen[key.PublicKey.SHA256] = true
	}
	for name, pin := range map[string]BootstrapSourceFilePin{"execution-record.key": m.RecordKey, "capture-record.key": m.CaptureKey} {
		if pin.File != filepath.Join(filepath.Dir(pin.File), name) || filepath.Dir(pin.File) != filepath.Dir(m.Issuers["forward_execution"].PrivateKey.File) || seen[pin.SHA256] {
			return zero, ErrInstall
		}
		raw, err := readBootstrapSourcePin(pin, 32)
		valid := err == nil && len(raw) == 32
		clear(raw)
		if !valid {
			return zero, ErrInstall
		}
		seen[pin.SHA256] = true
	}
	return m, nil
}

// ReadOriginalRuntimeIssuerMaterial reauthenticates the actual admin, original
// enrollment and live head. The original purpose manifest supplies locators;
// its own candidate public keys can never authenticate the manifest.
func (i *Installer) ReadOriginalRuntimeIssuerMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, pin BootstrapSourceFilePin) (OriginalRuntimeIssuerMaterial, error) {
	var zero OriginalRuntimeIssuerMaterial
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
	m, err := i.readOriginalRuntimeIssuerMaterial(pin, enrollment)
	if err != nil {
		return zero, err
	}
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, &before.cas); err != nil {
		return zero, err
	}
	return m, nil
}

// This returns a purpose key only to the actual Go issuer, which must still
// authenticate its original native business inputs before granting anything.
func (i *Installer) ReadOriginalRuntimeIssuerKey(ctx context.Context, password []byte, enrollment EnrollmentPin, pin BootstrapSourceFilePin, purpose string) (ed25519.PrivateKey, error) {
	m, err := i.ReadOriginalRuntimeIssuerMaterial(ctx, password, enrollment, pin)
	if err != nil {
		return nil, err
	}
	selected, ok := m.Issuers[purpose]
	if !ok {
		return nil, ErrInstall
	}
	raw, err := readBootstrapSourcePin(selected.PrivateKey, ed25519.PrivateKeySize)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		clear(raw)
		return nil, ErrInstall
	}
	return ed25519.PrivateKey(raw), nil
}

// Existing Forward record/capture file pins use separate random32 bytes;
// neither is an Ed25519 signer, credential or permit root.
func (i *Installer) ReadOriginalRuntimeRecordKey(ctx context.Context, password []byte, enrollment EnrollmentPin, pin BootstrapSourceFilePin, purpose string) ([]byte, error) {
	m, err := i.ReadOriginalRuntimeIssuerMaterial(ctx, password, enrollment, pin)
	if err != nil {
		return nil, err
	}
	var selected BootstrapSourceFilePin
	switch purpose {
	case "record":
		selected = m.RecordKey
	case "capture":
		selected = m.CaptureKey
	default:
		return nil, ErrInstall
	}
	raw, err := readBootstrapSourcePin(selected, 32)
	if err != nil || len(raw) != 32 {
		clear(raw)
		return nil, ErrInstall
	}
	return raw, nil
}
