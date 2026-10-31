package systembackupkekadapter

import (
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	"context"
)

// CaptureParts discovers only locators; ForPart independently authenticates
// each original sealed result, Job, invocation and finished key-use record.
func (f *PublisherVerifierFactory) CaptureParts(ctx context.Context, scope security.PublisherCaptureScope) ([]string, error) {
	if f == nil {
		return nil, publisherVerifierFailure("inventory factory")
	}
	scope.Part = "publication_inventory"
	access, err := security.NewSQLPublisherCaptureAuthority(ctx, f.cfg.Authority, scope)
	if err != nil {
		return nil, err
	}
	return f.cfg.Records.PublisherCaptureParts(ctx, access)
}

// CaptureAccess authenticates the new live publisher for bounded original SQL
// journal work. It cannot decrypt a record or authorize a provider operation.
func (f *PublisherVerifierFactory) CaptureAccess(ctx context.Context, scope security.PublisherCaptureScope) (*security.SQLPublisherCaptureAuthority, error) {
	if f == nil {
		return nil, publisherVerifierFailure("current access")
	}
	scope.Part = "publication_journal"
	return security.NewSQLPublisherCaptureAuthority(ctx, f.cfg.Authority, scope)
}

func (v *PublisherVerifier) CapturedRecord(ctx context.Context) (c.PublisherCaptureRecord, error) {
	if v == nil || v.Recheck(ctx) != nil {
		return c.PublisherCaptureRecord{}, publisherVerifierFailure("original record")
	}
	return v.history.Detached()
}
