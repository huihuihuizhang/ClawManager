package install

import (
	"bytes"
	"context"
	"crypto/ed25519"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// V2 remains an original identity only, never a terminal resource or fresh
// observation. The private common object shares capture guard/context/tx/latch
// mechanics; no caller can obtain it as a v1 grant or silently add V2 rights.
type PreparedBootstrapSourceRegistriesV2 struct {
	origin *PreparedBootstrapSourceRegistriesV2
	base   *PreparedBootstrapSourceRegistries
	record BootstrapSourceRegistryV2Record
}

func (*PreparedBootstrapSourceRegistriesV2) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (p *PreparedBootstrapSourceRegistriesV2) reject() error {
	if p != nil {
		if p.base != nil {
			_ = p.base.fail()
		}
		if p.origin != nil && p.origin.base != nil {
			_ = p.origin.base.fail()
		}
	}
	return ErrInstall
}

func (c *CaptureSigningConsumer) PrepareBootstrapSourceRegistriesV2(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, selection pd.BootstrapConsumptionRequest, files BootstrapSourceRegistryFiles) (*PreparedBootstrapSourceRegistriesV2, error) {
	if c == nil || !bootstrapSourcePinValid(BootstrapSourceFilePin{files.RecordFile, files.RecordSHA256}) {
		return nil, ErrInstall
	}
	source, err := c.load(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	defer source.request.observer.Close()
	if source.request.grant != grant || source.request.config.SHA256() != config.SHA256() {
		return nil, ErrInstall
	}
	locatorRaw, err := readBootstrapSourceAuthenticated(source, c.sourceFile, 262144)
	var locator CaptureConsumerFiles
	if err != nil || decodeExact(locatorRaw, &locator) != nil {
		return nil, ErrInstall
	}
	public, err := readBootstrapSourceAuthenticated(source, locator.IssuerPublicFile, ed25519.PublicKeySize)
	if err != nil || hash(public) != locator.IssuerPublicSHA256 {
		return nil, ErrInstall
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{files.RecordFile, files.RecordSHA256}, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	signature, err := ReadPrivateFile(files.SignatureFile, ed25519.SignatureSize)
	if err != nil {
		return nil, ErrInstall
	}
	r, err := verifyBootstrapSourceV2(raw, signature, public)
	if err != nil || r.PlanSHA256 != locator.PlanSHA256 || bootstrapSourceSelectionHash(r.Selection) != bootstrapSourceSelectionHash(selection) {
		return nil, ErrInstall
	}
	ownerRaw, err := readBootstrapSourceAuthenticated(source, locator.RecordFile, 262144)
	var capture owner.Record
	if err != nil || decodeExact(ownerRaw, &capture) != nil || r.CaptureRecordSHA256 != hash(ownerRaw) || !functionalSelectionMatches(capture, r.Selection) || r.Target != capture.Target || r.Actor != capture.Actor || !r.NotBefore.Equal(capture.NotBefore) || !r.Until.Equal(capture.Until) {
		return nil, ErrInstall
	}
	enrolRaw, err := readBootstrapSourceAuthenticated(source, locator.EnrollmentPinFile, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	enrol, err := DecodeEnrollmentPin(enrolRaw, locator.EnrollmentPinSHA256)
	parts, writers := bootstrapSourceRegistryPins(config)
	if err != nil || enrol != r.Enrollment || parts != r.Parts || writers != r.SourceWriters {
		return nil, ErrInstall
	}
	metadataRaw, err := readBootstrapSourcePin(r.Source.MetadataGrant, 65536)
	if err != nil {
		return nil, ErrInstall
	}
	metadataPublic, err := readBootstrapSourcePin(r.Source.MetadataIssuerPublic, ed25519.PublicKeySize)
	if err != nil || !bytes.Equal(public, metadataPublic) {
		return nil, ErrInstall
	}
	metadata, digest, err := decodeBootstrapSourceMetadata(metadataRaw, metadataPublic)
	if err != nil || metadata != r.Metadata || digest != r.MetadataRecordSHA256 {
		return nil, ErrInstall
	}
	pinRaw, err := readBootstrapSourceAuthenticated(source, locator.TrustPinFile, 262144)
	var pin owner.TrustPin
	if err != nil || decodeExact(pinRaw, &pin) != nil || pin.RecordSHA256 != hash(ownerRaw) {
		return nil, ErrInstall
	}
	identity, err := owner.NewCaptureSigningIdentityOnlyValidator(pin, owner.RecordFiles{RecordFile: locator.RecordFile, SignatureFile: locator.SignatureFile})
	if err != nil {
		return nil, ErrInstall
	}
	prepared, err := identity.PrepareCandidateAttempt(ctx, grant, config, r.Selection)
	if err != nil {
		return nil, ErrInstall
	}
	base := &PreparedBootstrapSourceRegistries{ctx: ctx, source: source, record: bootstrapSourceV2IdentityProjection(r), prepared: prepared, files: []consumerPinnedFile{{files.RecordFile, files.RecordSHA256, 262144}, {files.SignatureFile, hash(signature), 64}}}
	base.origin = base
	p := &PreparedBootstrapSourceRegistriesV2{base: base, record: r}
	p.origin = p
	// Public original declaration bytes are identity inputs. Native CA/credential
	// absence remains a separate physical failure; do not preempt exact history.
	var inputs [][]byte
	for _, file := range []BootstrapSourceFilePin{r.Source.Deployment, r.Source.Materials, r.Source.ExecutionProfile, r.Source.ForwardGrant} {
		data, err := readBootstrapSourcePin(file, bootstrapSourceV2FileLimit(r.Source, file))
		if err != nil {
			return nil, p.reject()
		}
		base.files = append(base.files, consumerPinnedFile{file.File, file.SHA256, bootstrapSourceV2FileLimit(r.Source, file)})
		inputs = append(inputs, data)
	}
	if ValidateBootstrapSourceV2Inputs(r, inputs[0], inputs[1], inputs[2], inputs[3]) != nil || base.local(ctx) != nil {
		return nil, p.reject()
	}
	return p, nil
}

func (p *PreparedBootstrapSourceRegistriesV2) Association() (BootstrapSourceRegistryV2Record, error) {
	if p == nil || p.origin != p || p.base == nil || p.base.failed.Load() {
		return BootstrapSourceRegistryV2Record{}, p.reject()
	}
	r, err := cloneBootstrapSourceV2(p.record)
	if err != nil {
		return BootstrapSourceRegistryV2Record{}, p.reject()
	}
	return r, nil
}
func (p *PreparedBootstrapSourceRegistriesV2) AuthorizeIdentity(ctx context.Context, q pd.BootstrapSQL) (*pd.Timestamp, error) {
	if p == nil || p.origin != p || p.base == nil {
		return nil, p.reject()
	}
	return p.base.AuthorizeIdentity(ctx, q)
}
func (p *PreparedBootstrapSourceRegistriesV2) RecheckIdentity(ctx context.Context, q pd.BootstrapReadSQL) error {
	if p == nil || p.origin != p || p.base == nil {
		return p.reject()
	}
	return p.base.RecheckIdentity(ctx, q)
}
func (p *PreparedBootstrapSourceRegistriesV2) ReadSelectedFile(ctx context.Context, pin BootstrapSourceFilePin) ([]byte, error) {
	if p == nil || p.origin != p || p.base == nil {
		return nil, p.reject()
	}
	b := p.base
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.selectedReadCurrent(ctx) != nil {
		return nil, p.reject()
	}
	for _, selected := range bootstrapSourceV2Files(p.record.Source) {
		if selected == pin {
			raw, err := readBootstrapSourcePin(pin, bootstrapSourceV2FileLimit(p.record.Source, pin))
			return b.finishSelectedRead(ctx, raw, err)
		}
	}
	return nil, p.reject()
}
