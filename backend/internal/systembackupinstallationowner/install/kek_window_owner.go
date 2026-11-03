package install

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"sync"

	owner "clawreef/internal/systembackupinstallationowner"
	kek "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// ONE concrete object supplies the terminal association AND the independent
// KEK preparation. No generic PreparedAdmission/callback can be injected. The
// original preparation is called exactly once per original attempt; its exact
// opaque return object (including OriginalEvidence/OriginalCoverage) goes to D.
type OriginalWindowKEK struct {
	origin                     *OriginalWindowKEK
	capture                    *CaptureSigningConsumer
	preparation                *kek.SQLBootstrapKEKPreparation
	cfg                        kek.SQLBootstrapKEKConfig
	preparationSHA, bindingSHA string
	files                      BootstrapKEKWindowFiles
	mu                         sync.Mutex
	pending                    map[context.Context]*originalWindowKEKCheck
}

func NewOriginalWindowKEK(capture *CaptureSigningConsumer, preparation *kek.SQLBootstrapKEKPreparation, files BootstrapKEKWindowFiles) (*OriginalWindowKEK, error) {
	if capture == nil || !digestPattern.MatchString(files.RecordSHA256) || files.RecordFile == files.SignatureFile {
		return nil, ErrInstall
	}
	for _, path := range []string{files.RecordFile, files.SignatureFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, ErrInstall
		}
	}
	cfg, sourceSHA, err := kekWindowPreparation(preparation)
	if err != nil {
		return nil, ErrInstall
	}
	raw, err := canonical(struct {
		Version, CaptureFile, CapturePin, PreparationSHA256 string
		Files                                               BootstrapKEKWindowFiles
	}{BootstrapKEKWindowVersion, capture.sourceFile, capture.sourcePinFile, sourceSHA, files})
	if err != nil {
		return nil, ErrInstall
	}
	p := &OriginalWindowKEK{capture: capture, preparation: preparation, cfg: cfg, preparationSHA: sourceSHA, bindingSHA: hash(raw), files: files, pending: map[context.Context]*originalWindowKEKCheck{}}
	p.origin = p
	return p, nil
}
func (*OriginalWindowKEK) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*OriginalWindowKEK) TerminalKeys() []string       { return []string{"reference:kek"} }
func (p *OriginalWindowKEK) BindingSHA256() (string, error) {
	if p == nil || p.origin != p || !digestPattern.MatchString(p.bindingSHA) {
		return "", ErrInstall
	}
	return p.bindingSHA, nil
}
func (*OriginalWindowKEK) Prepare(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return nil, ErrInstall
}

func readKEKWindowAuthenticated(source *consumerCaptureState, path string, limit int64) ([]byte, error) {
	if source == nil {
		return nil, ErrInstall
	}
	for _, pin := range source.files {
		if pin.path == path {
			raw, err := ReadPrivateFile(path, limit)
			if err != nil || hash(raw) != pin.sha {
				return nil, ErrInstall
			}
			return raw, nil
		}
	}
	return nil, ErrInstall
}

func (p *OriginalWindowKEK) PrepareTerminalResource(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	if p == nil || p.origin != p || !consumerSameContext(ctx, ctx) || ctx.Err() != nil {
		return nil, ErrInstall
	}
	source, err := p.capture.load(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	defer source.request.observer.Close()
	if source.request.grant != grant || source.request.config.SHA256() != config.SHA256() {
		return nil, ErrInstall
	}
	locator, _, public, err := readBootstrapOriginalPublicSource(ctx, p.capture, source)
	if err != nil {
		return nil, ErrInstall
	}
	raw, err := ReadPrivateFile(p.files.RecordFile, 262144)
	if err != nil || hash(raw) != p.files.RecordSHA256 {
		return nil, ErrInstall
	}
	sig, err := ReadPrivateFile(p.files.SignatureFile, 64)
	if err != nil {
		return nil, ErrInstall
	}
	r, err := verifyKEKWindow(raw, sig, public)
	if err != nil || r.PlanSHA256 != locator.PlanSHA256 || r.PreparationSHA256 != p.preparationSHA {
		return nil, ErrInstall
	}
	ownerRaw, err := readKEKWindowAuthenticated(source, locator.RecordFile, 262144)
	var capture owner.Record
	if err != nil || decodeExact(ownerRaw, &capture) != nil || r.CaptureRecordSHA256 != hash(ownerRaw) || r.Target != capture.Target || r.Actor != capture.Actor || !r.NotBefore.Equal(capture.NotBefore) || !r.Until.Equal(capture.Until) || !functionalSelectionMatches(capture, r.Selection) {
		return nil, ErrInstall
	}
	enrolRaw, err := readKEKWindowAuthenticated(source, locator.EnrollmentPinFile, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	enrol, err := DecodeEnrollmentPin(enrolRaw, locator.EnrollmentPinSHA256)
	ref, re := kekWindowReference(config)
	if err != nil || re != nil || enrol != r.Enrollment || ref != r.Reference || p.cfg.Database.ServerUUID != r.Target.ServerUUID || p.cfg.Database.Database != r.Target.Database || p.cfg.InstallationID != r.Target.InstallationID || p.cfg.Mapping.IdentityHash != ref.IdentityHash || p.cfg.Mapping.Version != ref.Version {
		return nil, ErrInstall
	}
	pinRaw, err := readKEKWindowAuthenticated(source, locator.TrustPinFile, 262144)
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
	check := &originalWindowKEKCheck{owner: p, ctx: ctx, source: source, record: r, identity: prepared, raw: bytes.Clone(raw), signature: bytes.Clone(sig)}
	check.origin = check
	if check.local(ctx) != nil {
		return nil, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, old := range p.pending {
		if key.Err() != nil {
			delete(p.pending, key)
			old.failed.Store(true)
		}
	}
	if old := p.pending[ctx]; old != nil {
		old.failed.Store(true)
		return nil, ErrInstall
	}
	if len(p.pending) >= 64 {
		return nil, ErrInstall
	}
	p.pending[ctx] = check
	context.AfterFunc(ctx, func() {
		p.mu.Lock()
		if p.pending[ctx] == check {
			delete(p.pending, ctx)
		}
		p.mu.Unlock()
	})
	return check, nil
}

func (p *OriginalWindowKEK) PrepareBootstrapKEK(ctx context.Context, db *sql.DB, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (reg.PreparedAdmission, error) {
	if p == nil || p.origin != p || db == nil || !consumerSameContext(ctx, ctx) || ctx.Err() != nil {
		return nil, ErrInstall
	}
	p.mu.Lock()
	check := p.pending[ctx]
	p.mu.Unlock()
	if check == nil {
		return nil, ErrInstall
	}
	check.mu.Lock()
	if check.started || check.local(ctx) != nil || grant != check.source.request.grant || config.SHA256() != check.source.request.config.SHA256() {
		check.mu.Unlock()
		return nil, check.fail()
	}
	check.started = true
	check.mu.Unlock()
	var account, server, database string
	if db.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE()`).Scan(&account, &server, &database) != nil || account != check.record.Target.DatabaseAccount || server != check.record.Target.ServerUUID || database != check.record.Target.Database {
		check.mu.Lock()
		check.completed = true
		check.mu.Unlock()
		return nil, check.fail()
	}
	// No terminal check holds SQL/provider locks here. Actual source admission
	// authenticates every original source; no second resource preparation runs.
	actual, err := p.preparation.PrepareBootstrapKEK(ctx, db, grant, config)
	check.mu.Lock()
	defer check.mu.Unlock()
	check.completed = true
	if check.local(ctx) != nil {
		return nil, check.fail()
	}
	if err != nil || consumerNil(actual) || !check.matches(actual) {
		return nil, ErrInstall
	}
	check.actual = actual
	return actual, nil
}

var _ sec.BootstrapTerminalResource = (*OriginalWindowKEK)(nil)
var _ sec.BootstrapKEKPreparation = (*OriginalWindowKEK)(nil)
