package install

import (
	"bytes"
	kek "clawreef/internal/systembackupkekadapter"
	probe "clawreef/internal/systembackupreferenceprobe"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"sort"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const SixReferenceVersion = "original-six-provider-references.v1"
const sixReferenceDomain = SixReferenceVersion + "\x00"

// This binds six CURRENT provider reference purposes. It grants no task,
// backup execution, wrap/decrypt operation or configuration mutation permission.
// Its exact hash is selected BEFORE final config/capture association signing.
type SixReferenceDefinition struct {
	Version          string
	References       []sec.BootstrapSecretRef
	Deployment       BootstrapSourceFilePin
	S3               probe.S3Profile
	Vault            kek.EvidenceVaultObserverConfig
	VaultCA          BootstrapSourceFilePin
	NotBefore, Until time.Time
}

type SixReferenceFiles struct{ RecordFile, RecordSHA256, SignatureFile string }
type SignedSixReference struct{ Record, Signature []byte }
type sixReferenceRecord struct {
	Version, PlanSHA256, CaptureRecordSHA256, DefinitionSHA256, NativeIdentitySHA256 string
	Target                                                                           owner.Target
	Actor                                                                            owner.Actor
	Enrollment                                                                       EnrollmentPin
	Selection                                                                        pd.BootstrapConsumptionRequest
	References                                                                       []sec.BootstrapSecretRef
	Definition                                                                       SixReferenceDefinition
	NotBefore, Until                                                                 time.Time
}

var sixReferencePurposes = []string{"artifact_upload_issuer", "evidence_delete", "evidence_kek", "evidence_read", "evidence_store", "evidence_write"}

func sameSixReferences(a, b []sec.BootstrapSecretRef) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	x, y := append([]sec.BootstrapSecretRef(nil), a...), append([]sec.BootstrapSecretRef(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i].Purpose < x[j].Purpose })
	sort.Slice(y, func(i, j int) bool { return y[i].Purpose < y[j].Purpose })
	for n := range x {
		if x[n] != y[n] || x[n].Purpose != sixReferencePurposes[n] {
			return false
		}
	}
	return true
}

func validateSixReference(d SixReferenceDefinition) error {
	if d.Version != SixReferenceVersion || !bootstrapSourcePinValid(d.Deployment) || !bootstrapSourcePinValid(d.VaultCA) || d.NotBefore.IsZero() || !d.NotBefore.Before(d.Until) || d.Until.Sub(d.NotBefore) > 24*time.Hour || !sameSixReferences(d.References, d.References) || probe.ValidateS3Profile(d.S3) != nil || kek.ValidateEvidenceVaultObserver(d.Vault) != nil || d.Vault.Transit.Installation != d.S3.Installation || d.VaultCA.SHA256 != d.Vault.Transit.CASHA256 {
		return ErrInstall
	}
	for _, ref := range d.References {
		if !digestPattern.MatchString(ref.IdentityHash) || !namePattern.MatchString(ref.Version) || ref.Version == "current" || ref.Version == "latest" {
			return ErrInstall
		}
		switch ref.Purpose {
		case "evidence_store":
			if ref.IdentityHash != d.S3.Evidence.Identity || ref.Version != d.S3.Evidence.Version {
				return ErrInstall
			}
		case "evidence_kek":
			if ref.IdentityHash != d.Vault.Transit.Key.Identity || ref.Version != d.Vault.Transit.Key.Version {
				return ErrInstall
			}
		}
	}
	return nil
}

// Selection DATA only; the distinct original issue action and current native
// observations below are mandatory. No reference hash certifies permission.
func SixReferenceIdentities(raw []byte, sha string) ([]sec.BootstrapSecretRef, error) {
	var d SixReferenceDefinition
	if hash(raw) != sha || decodeExact(raw, &d) != nil || validateSixReference(d) != nil {
		return nil, ErrInstall
	}
	encoded, e := canonical(d)
	if e != nil || !bytes.Equal(raw, encoded) {
		return nil, ErrInstall
	}
	return append([]sec.BootstrapSecretRef(nil), d.References...), nil
}
func sixConfigReferences(c sec.BootstrapConfig) ([]sec.BootstrapSecretRef, error) {
	refs := []sec.BootstrapSecretRef{}
	for _, ref := range c.References() {
		for _, purpose := range sixReferencePurposes {
			if ref.Purpose == purpose {
				refs = append(refs, ref)
			}
		}
	}
	if !sameSixReferences(refs, refs) {
		return nil, ErrInstall
	}
	return refs, nil
}

// Separate original purpose association. The capture record is used solely as
// current enrollment/revocation anchor; it does not grant provider operation or configuration write authority.
func (i *Installer) IssueSixReference(ctx context.Context, password []byte, enrollment EnrollmentPin, bundleRaw []byte, bundleSHA, definitionFile, definitionSHA string, selection pd.BootstrapConsumptionRequest, files RequestFiles, issuerPrivate []byte) (SignedSixReference, error) {
	var zero SignedSixReference
	bundleRaw = bytes.Clone(bundleRaw)
	selectionRaw, e := json.Marshal(selection)
	var frozen pd.BootstrapConsumptionRequest
	if e != nil || len(selectionRaw) > 262144 || json.Unmarshal(selectionRaw, &frozen) != nil {
		return zero, ErrInstall
	}
	selection = frozen
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	b, capture, _, e := s.decodeBundle(bundleRaw, bundleSHA, enrollment)
	if e != nil || b.SchemaVersion != AuthorityBundleVersion || !functionalSelectionMatches(capture, selection) {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(BootstrapSourceFilePin{definitionFile, definitionSHA}, 262144)
	var d SixReferenceDefinition
	ref, re := SixReferenceIdentities(raw, definitionSHA)
	if e != nil || re != nil || decodeExact(raw, &d) != nil || d.S3.Namespace != capture.Target.Namespace || d.S3.NamespaceUID != capture.Target.NamespaceUID {
		return zero, ErrInstall
	}
	request, e := readConsumerCaptureRequest(i, files)
	if e != nil {
		return zero, ErrInstall
	}
	defer request.observer.Close()
	actualRef, e := sixConfigReferences(request.config)
	if e != nil || !sameSixReferences(actualRef, ref) || !request.matchesDraft(capture) {
		return zero, ErrInstall
	}
	before, now, e := snapshot(ctx, s)
	if e != nil || !exactCommitted(before, b) || now.Before(d.NotBefore) || !now.Before(d.Until) || now.Before(capture.NotBefore) || !now.Before(capture.Until) {
		return zero, ErrInstall
	}
	native, e := observeSixReference(ctx, i.kube, capture.Target, d)
	if e != nil {
		return zero, ErrInstall
	}
	end := capture.Until
	if d.Until.Before(end) {
		end = d.Until
	}
	start := capture.NotBefore
	if d.NotBefore.After(start) {
		start = d.NotBefore
	}
	r := sixReferenceRecord{Version: SixReferenceVersion, PlanSHA256: i.planHash, CaptureRecordSHA256: hash(b.Record), DefinitionSHA256: definitionSHA, NativeIdentitySHA256: native.identity, Target: capture.Target, Actor: capture.Actor, Enrollment: enrollment, Selection: selection, References: ref, Definition: d, NotBefore: start, Until: end}
	encoded, e := canonical(r)
	if e != nil || len(encoded) > 262144 {
		return zero, ErrInstall
	}
	key, e := s.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	signature := ed25519.Sign(key, append([]byte(sixReferenceDomain), encoded...))
	for _, pin := range []BootstrapSourceFilePin{{definitionFile, definitionSHA}, {files.ConfigFile, files.ConfigFileSHA256}, {files.GrantFile, files.GrantFileSHA256}, {files.ObserverFile, files.ObserverFileSHA256}} {
		v, e := readBootstrapSourcePin(pin, 262144)
		clear(v)
		if e != nil {
			return zero, ErrInstall
		}
	}
	tail, e := observeSixReference(ctx, i.kube, capture.Target, d)
	if e != nil || tail.identity != native.identity || !time.Now().Before(native.until) || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	after, now, e := snapshot(ctx, s)
	if e != nil || after.cas != before.cas || !exactCommitted(after, b) || now.Before(start) || !now.Before(end) || !now.Before(native.until) || !s.live(ctx) {
		return zero, ErrInstall
	}
	return SignedSixReference{Record: encoded, Signature: signature}, nil
}

func SaveFrozenSixReference(directory string, signed SignedSixReference) error {
	var r sixReferenceRecord
	if len(signed.Record) == 0 || len(signed.Record) > 262144 || len(signed.Signature) != ed25519.SignatureSize || decodeExact(signed.Record, &r) != nil || r.Version != SixReferenceVersion {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{"six-provider-references.record.json": bytes.Clone(signed.Record), "six-provider-references.signature": bytes.Clone(signed.Signature), "six-provider-references.sha256": []byte(hash(signed.Record))})
}

type OriginalSixReference struct {
	capture *CaptureSigningConsumer
	files   SixReferenceFiles
}

func NewOriginalSixReference(capture *CaptureSigningConsumer, files SixReferenceFiles) (*OriginalSixReference, error) {
	if capture == nil || !digestPattern.MatchString(files.RecordSHA256) || files.RecordFile == files.SignatureFile {
		return nil, ErrInstall
	}
	for _, p := range []string{files.RecordFile, files.SignatureFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, ErrInstall
		}
	}
	return &OriginalSixReference{capture: capture, files: files}, nil
}
func (*OriginalSixReference) TerminalKeys() []string {
	return []string{"reference:artifact_upload_issuer", "reference:evidence_store", "reference:evidence_write", "reference:evidence_read", "reference:evidence_delete", "reference:evidence_kek"}
}
func (*OriginalSixReference) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*OriginalSixReference) Prepare(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return nil, ErrInstall
}
func (p *OriginalSixReference) BindingSHA256() (string, error) {
	if p == nil || p.capture == nil {
		return "", ErrInstall
	}
	raw, e := canonical(struct {
		Version, Capture, Pin string
		Files                 SixReferenceFiles
	}{SixReferenceVersion, p.capture.sourceFile, p.capture.sourcePinFile, p.files})
	if e != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}
