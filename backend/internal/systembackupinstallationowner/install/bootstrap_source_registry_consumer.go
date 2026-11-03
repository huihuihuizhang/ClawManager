package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type BootstrapSourceRegistryFiles struct{ RecordFile, RecordSHA256, SignatureFile string }

// PreparedBootstrapSourceRegistries is only the authenticated original-source
// identity portion of a future concrete B owner. It deliberately implements NO
// BootstrapTerminalResource/Check, exposes no fresh deadline and fills no slot.
// Physical completeness, registry semantics and original observation age must
// be established by B's actual finite reader, never supplied in a DTO.
type PreparedBootstrapSourceRegistries struct {
	mu       sync.Mutex
	origin   *PreparedBootstrapSourceRegistries
	ctx      context.Context
	source   *consumerCaptureState
	record   BootstrapSourceRegistryRecord
	files    []consumerPinnedFile
	prepared *owner.PreparedCaptureSigning
	guard    *owner.OwnerGuard
	tx       pd.BootstrapSQL
	failed   atomic.Bool
}

func (*PreparedBootstrapSourceRegistries) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*PreparedBootstrapSourceRegistries) String() string {
	return "OriginalBootstrapSourceRegistryIdentity"
}

// Every reread is bound to a pin already authenticated by capture.load. Merely
// restoring the original locator before the final current check cannot select
// a transient new public key, record, enrollment, plan or trust pin here.
func readBootstrapSourceAuthenticated(source *consumerCaptureState, path string, limit int64) ([]byte, error) {
	if source == nil {
		return nil, ErrInstall
	}
	for _, pin := range source.files {
		if pin.path == path {
			return readBootstrapSourcePin(BootstrapSourceFilePin{path, pin.sha}, limit)
		}
	}
	return nil, ErrInstall
}

func (c *CaptureSigningConsumer) PrepareBootstrapSourceRegistries(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, selection pd.BootstrapConsumptionRequest, files BootstrapSourceRegistryFiles) (*PreparedBootstrapSourceRegistries, error) {
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
	r, err := verifyBootstrapSourceRegistries(raw, signature, public)
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
	p := &PreparedBootstrapSourceRegistries{ctx: ctx, source: source, record: r, prepared: prepared, files: []consumerPinnedFile{{files.RecordFile, files.RecordSHA256, 262144}, {files.SignatureFile, hash(signature), 64}}}
	p.origin = p
	// Only immutable public association bytes belong to history identity.
	// CA/credentials/materials/registries remain physical reader dependencies;
	// missing bytes must close fresh use without bypassing current SQL revoke.
	if p.local(ctx) != nil {
		return nil, ErrInstall
	}
	return p, nil
}

func (p *PreparedBootstrapSourceRegistries) fail() error {
	if p != nil {
		p.failed.Store(true)
		if p.origin != nil {
			p.origin.failed.Store(true)
		}
	}
	return ErrInstall
}

func (p *PreparedBootstrapSourceRegistries) local(ctx context.Context) error {
	if p == nil || p.origin != p || p.failed.Load() || !consumerSameContext(ctx, p.ctx) || ctx.Err() != nil || p.source == nil || p.source.current(ctx) != nil {
		return p.fail()
	}
	for _, pin := range p.files {
		// V2 adds its authenticated original Materials bytes to this identity
		// tail. Only that exact selected pin may use the source-material bound.
		if pin.limit == 8<<20 && (pin.path != p.record.Source.Materials.File || pin.sha != p.record.Source.Materials.SHA256) {
			return p.fail()
		}
		raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{pin.path, pin.sha}, pin.limit)
		clear(raw)
		if err != nil {
			return p.fail()
		}
	}
	return nil
}

// Association is detached comparison data. It cannot construct a prepared
// identity, extend its window or supply any physical observation.
func (p *PreparedBootstrapSourceRegistries) Association() (BootstrapSourceRegistryRecord, error) {
	var out BootstrapSourceRegistryRecord
	if p == nil || p.origin != p || p.failed.Load() {
		return out, p.fail()
	}
	raw, err := json.Marshal(p.record)
	if err != nil || json.Unmarshal(raw, &out) != nil {
		return out, p.fail()
	}
	return out, nil
}

func (p *PreparedBootstrapSourceRegistries) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if p == nil || p.origin != p {
		return nil, p.fail()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.guard != nil || p.prepared == nil || !pd.SameBootstrapTransaction(tx, tx) || p.local(ctx) != nil {
		return nil, p.fail()
	}
	p.tx = tx
	var err error
	p.guard, err = p.prepared.AuthorizeCandidate(ctx, tx)
	if err != nil {
		return nil, p.fail()
	}
	end, ok := terminalMinimum(p.record.Until, p.guard.IdentityDeadline())
	if !ok {
		return nil, p.fail()
	}
	stamp := terminalTimestamp(end)
	return &stamp, nil
}

func (p *PreparedBootstrapSourceRegistries) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p == nil || p.origin != p {
		return p.fail()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.guard == nil || !pd.SameBootstrapTransaction(p.tx, view) || p.local(ctx) != nil {
		return p.fail()
	}
	before, err := view.SampleTime(ctx)
	if err != nil || before.Before(p.record.NotBefore) || !before.Before(p.record.Until) || p.guard.RecheckCandidateIdentity(ctx, view) != nil || p.local(ctx) != nil {
		return p.fail()
	}
	// The final local-file tail precedes the LAST authoritative sample. Shared
	// SampleTime retains its own floor/failure latch, including the private D
	// final read view. No raw SQL clock or wall time substitutes for this sample.
	after, err := view.SampleTime(ctx)
	deadline := p.guard.IdentityDeadline()
	if err != nil || after.Before(before) || after.Before(p.record.NotBefore) || !after.Before(p.record.Until) || deadline == nil || ctx.Err() != nil {
		return p.fail()
	}
	end, err := deadline.Time()
	if err != nil || !after.Before(end) {
		return p.fail()
	}
	return nil
}

// Wall time is ONLY a pre-SQL private-read boundary. Check the original signed
// window before p.local can read any file, and again after its final file tail.
func (p *PreparedBootstrapSourceRegistries) selectedReadCurrent(ctx context.Context) error {
	if p == nil || p.origin != p || p.failed.Load() || p.tx != nil || !consumerSameContext(ctx, p.ctx) || ctx.Err() != nil {
		return p.fail()
	}
	now := time.Now().UTC()
	if now.Before(p.record.NotBefore) || !now.Before(p.record.Until) || p.local(ctx) != nil {
		return p.fail()
	}
	now = time.Now().UTC()
	if now.Before(p.record.NotBefore) || !now.Before(p.record.Until) || ctx.Err() != nil {
		return p.fail()
	}
	return nil
}

func (p *PreparedBootstrapSourceRegistries) finishSelectedRead(ctx context.Context, raw []byte, err error) ([]byte, error) {
	if err != nil || p.selectedReadCurrent(ctx) != nil {
		clear(raw)
		return nil, p.fail()
	}
	return raw, nil
}

// ReadSelectedFile supplies exact selected private bytes only under this
// opaque identity. It is an outside-SQL preparation API for B's actual finite
// native reader, never a callback or proof of permissions/completeness. It must
// not be called after AuthorizeIdentity starts the caller SQL lock prefix.
func (p *PreparedBootstrapSourceRegistries) ReadSelectedFile(ctx context.Context, pin BootstrapSourceFilePin) ([]byte, error) {
	if p == nil || p.origin != p {
		return nil, p.fail()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.selectedReadCurrent(ctx) != nil {
		return nil, p.fail()
	}
	for _, selected := range bootstrapSourceFiles(p.record.Source) {
		if selected == pin {
			raw, err := readBootstrapSourcePin(pin, 262144)
			return p.finishSelectedRead(ctx, raw, err)
		}
	}
	return nil, p.fail()
}

// RecheckSelectedFile does not return a credential or expose a SQL handle.
// A real reader calls this only for exact source files it already prepared.
func (p *PreparedBootstrapSourceRegistries) RecheckSelectedFile(ctx context.Context, pin BootstrapSourceFilePin) error {
	if p == nil || p.origin != p {
		return p.fail()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// This context-only API has NO SQL clock capability. Forbid it once SQL
	// begins; final locked checking goes through RecheckIdentity's supplied view.
	if p.selectedReadCurrent(ctx) != nil {
		return p.fail()
	}
	for _, selected := range bootstrapSourceFiles(p.record.Source) {
		if selected == pin {
			raw, err := readBootstrapSourcePin(pin, 262144)
			checked, err := p.finishSelectedRead(ctx, raw, err)
			clear(checked)
			return err
		}
	}
	return p.fail()
}
