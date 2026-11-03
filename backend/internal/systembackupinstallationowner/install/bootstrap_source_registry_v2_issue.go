package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func bootstrapSourceV2FileLimit(d BootstrapSourceRegistryV2Definition, pin BootstrapSourceFilePin) int64 {
	if pin == d.Materials {
		return 8 << 20
	}
	if pin == d.MetadataIssuerPublic {
		return ed25519.PublicKeySize
	}
	return 262144
}

func checkBootstrapSourceV2Files(d BootstrapSourceRegistryV2Definition) error {
	for _, pin := range bootstrapSourceV2Files(d) {
		raw, err := readBootstrapSourcePin(pin, bootstrapSourceV2FileLimit(d, pin))
		clear(raw)
		if err != nil {
			return ErrInstall
		}
	}
	return nil
}

// This is a DISTINCT original issuer action for the mandatory control observer
// and exactly two native read operations. It never upgrades old v1 metadata or
// gateway permission, creates a task, or declares a physical census successful.
func (i *Installer) IssueBootstrapSourceRegistriesV2(ctx context.Context, password []byte, enrollment EnrollmentPin, bundleRaw []byte, bundleSHA, definitionFile, definitionSHA string, selection pd.BootstrapConsumptionRequest, files RequestFiles, issuerPrivate []byte) (SignedBootstrapSourceRegistriesV2, error) {
	var zero SignedBootstrapSourceRegistriesV2
	bundleRaw = bytes.Clone(bundleRaw)
	selectionRaw, err := json.Marshal(selection)
	var frozen pd.BootstrapConsumptionRequest
	if err != nil || len(selectionRaw) > 262144 || json.Unmarshal(selectionRaw, &frozen) != nil {
		return zero, ErrInstall
	}
	selection = frozen
	s, err := i.authenticate(ctx, password)
	if err != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	bundle, capture, _, err := s.decodeBundle(bundleRaw, bundleSHA, enrollment)
	if err != nil || bundle.SchemaVersion != AuthorityBundleVersion || !functionalSelectionMatches(capture, selection) {
		return zero, ErrInstall
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{definitionFile, definitionSHA}, 262144)
	var d BootstrapSourceRegistryV2Definition
	if err != nil || decodeExact(raw, &d) != nil || d.SchemaVersion != BootstrapSourceRegistryV2Version || len(d.Connections) != 5 {
		return zero, ErrInstall
	}
	request, err := readConsumerCaptureRequest(i, files)
	if err != nil {
		return zero, ErrInstall
	}
	defer request.observer.Close()
	if !request.matchesDraft(capture) {
		return zero, ErrInstall
	}
	parts, writers := bootstrapSourceRegistryPins(request.config)
	metadataRaw, err := readBootstrapSourcePin(d.MetadataGrant, 65536)
	if err != nil {
		return zero, ErrInstall
	}
	public, err := readBootstrapSourcePin(d.MetadataIssuerPublic, ed25519.PublicKeySize)
	if err != nil || !bytes.Equal(public, i.public) {
		return zero, ErrInstall
	}
	metadata, metadataSHA, err := decodeBootstrapSourceMetadata(metadataRaw, public)
	if err != nil {
		return zero, ErrInstall
	}
	r := BootstrapSourceRegistryV2Record{SchemaVersion: BootstrapSourceRegistryV2Version, Profile: BootstrapSourceRegistryProfile, PlanSHA256: i.planHash, CaptureRecordSHA256: hash(bundle.Record), DefinitionSHA256: definitionSHA, Target: capture.Target, Actor: capture.Actor, Enrollment: enrollment, NotBefore: capture.NotBefore, Until: capture.Until, Selection: selection, Parts: parts, SourceWriters: writers, Source: d, Metadata: metadata, MetadataRecordSHA256: metadataSHA, MetadataIssuerSHA256: hash(public)}
	if validateBootstrapSourceV2(r) != nil {
		return zero, ErrInstall
	}
	before, now, err := snapshot(ctx, s)
	if err != nil || !exactCommitted(before, bundle) || now.Before(r.NotBefore) || !now.Before(r.Until) {
		return zero, ErrInstall
	}
	// All owner locks are released. Authenticate the REAL selected definitions
	// and account/CA/credential locators before signing the new source authority.
	if checkBootstrapSourceV2Files(d) != nil || checkBootstrapSourceV2SelectedInputs(r) != nil || observeBootstrapSourceController(ctx, i.kube, r.Target, d.Controller) != nil {
		return zero, ErrInstall
	}
	encoded, err := canonical(r)
	if err != nil || len(encoded) > 262144 {
		return zero, ErrInstall
	}
	key, err := s.privateKey(issuerPrivate)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	signature := ed25519.Sign(key, append([]byte(BootstrapSourceRegistryV2Domain), encoded...))
	for _, pin := range []BootstrapSourceFilePin{{definitionFile, definitionSHA}, {files.ConfigFile, files.ConfigFileSHA256}, {files.GrantFile, files.GrantFileSHA256}, {files.ObserverFile, files.ObserverFileSHA256}} {
		actual, err := readBootstrapSourcePin(pin, 262144)
		clear(actual)
		if err != nil {
			return zero, ErrInstall
		}
	}
	if checkBootstrapSourceV2Files(d) != nil || checkBootstrapSourceV2SelectedInputs(r) != nil || observeBootstrapSourceController(ctx, i.kube, r.Target, d.Controller) != nil || s.authority(ctx, enrollment) != nil || ctx.Err() != nil || !time.Now().Before(r.Until) {
		return zero, ErrInstall
	}
	after, now, err := snapshot(ctx, s)
	if err != nil || after.cas != before.cas || !exactCommitted(after, bundle) || now.Before(r.NotBefore) || !now.Before(r.Until) || !s.live(ctx) {
		return zero, ErrInstall
	}
	return SignedBootstrapSourceRegistriesV2{Record: encoded, Signature: signature}, nil
}

func SaveFrozenBootstrapSourceRegistriesV2(directory string, signed SignedBootstrapSourceRegistriesV2) error {
	var record BootstrapSourceRegistryV2Record
	if len(signed.Record) == 0 || len(signed.Record) > 262144 || len(signed.Signature) != ed25519.SignatureSize || decodeExact(signed.Record, &record) != nil || validateBootstrapSourceV2(record) != nil {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{"bootstrap-source-registries-v2.record.json": bytes.Clone(signed.Record), "bootstrap-source-registries-v2.signature": bytes.Clone(signed.Signature), "bootstrap-source-registries-v2.sha256": []byte(hash(signed.Record))})
}
