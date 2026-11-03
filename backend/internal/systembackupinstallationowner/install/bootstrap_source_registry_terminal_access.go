package install

import (
	"context"
	"path/filepath"

	pd "clawreef/internal/systembackupproducer"
)

// This is a composition binding, not a grant. It includes the SAME original
// enrolled capture locator and its independently deployed pin. No constructor
// performs an I/O or accepts a replacement issuer/observation/SQL capability.
func (c *CaptureSigningConsumer) BootstrapSourceRegistryBindingSHA256(files BootstrapSourceRegistryFiles) (string, error) {
	if c == nil || !bootstrapSourcePinValid(BootstrapSourceFilePin{File: files.RecordFile, SHA256: files.RecordSHA256}) {
		return "", ErrInstall
	}
	for _, path := range []string{c.sourceFile, c.sourcePinFile, files.SignatureFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return "", ErrInstall
		}
	}
	raw, err := canonical(struct {
		Version, CaptureSourceFile, CaptureSourcePinFile string
		Files                                            BootstrapSourceRegistryFiles
	}{"original-source-registry-terminal-binding.v1", c.sourceFile, c.sourcePinFile, files})
	if err != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}

// RecheckPhysicalFiles is the controlled-transaction counterpart to the
// outside-SQL reader access. It performs LOCAL exact-pin reads only. Native
// SQL/Redis/object/API/agent requests are never repeated under the caller lock.
// History identity intentionally does not call this fresh-only method.
func (p *PreparedBootstrapSourceRegistriesV2) RecheckPhysicalFiles(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p == nil || p.origin != p || p.base == nil {
		return p.reject()
	}
	b := p.base
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.origin != b || b.failed.Load() || b.guard == nil || !consumerSameContext(ctx, b.ctx) || ctx.Err() != nil || !pd.SameBootstrapTransaction(b.tx, view) {
		return p.reject()
	}
	before, err := view.SampleTime(ctx)
	if err != nil || before.Before(p.record.NotBefore) || !before.Before(p.record.Until) || b.local(ctx) != nil || b.guard.RecheckCandidateIdentity(ctx, view) != nil {
		return p.reject()
	}
	for _, pin := range bootstrapSourceV2Files(p.record.Source) {
		raw, err := readBootstrapSourcePin(pin, bootstrapSourceV2FileLimit(p.record.Source, pin))
		clear(raw)
		if err != nil {
			return p.reject()
		}
	}
	if b.local(ctx) != nil {
		return p.reject()
	}
	// The last authoritative sample follows the LAST file tail. It uses the
	// supplied transaction/final read view and its existing floor/failure latch.
	after, err := view.SampleTime(ctx)
	deadline := b.guard.IdentityDeadline()
	if err != nil || after.Before(before) || after.Before(p.record.NotBefore) || !after.Before(p.record.Until) || deadline == nil || ctx.Err() != nil {
		return p.reject()
	}
	end, err := deadline.Time()
	if err != nil || !after.Before(end) {
		return p.reject()
	}
	return nil
}
