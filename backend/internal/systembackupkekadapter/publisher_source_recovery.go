package systembackupkekadapter

import (
	"context"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// OpenSourceRecovery is the controlled current-publisher bridge to D's opaque
// original source-recovery record. It accepts no caller record, old capture
// authority, proof callback or replacement SQL reader. The SAME concrete access
// authenticates both original capture history and physical recovery history.
// The caller must retain this returned access for D.RecheckTx; a renewed or
// independently reconstructed authority is deliberately a different scope.
func (f *PublisherVerifierFactory) OpenSourceRecovery(ctx context.Context, scope security.PublisherCaptureScope) (*c.PublisherSourceRecovery, *security.SQLPublisherCaptureAuthority, error) {
	if f == nil || nilSource(ctx) || ctx.Err() != nil || scope.Part != ce.Part {
		return nil, nil, publisherVerifierFailure("source recovery scope")
	}
	// ForPart uses the actual configured records, current independent publisher
	// workload/claim, pinned historical mapping and Unwrap capability. Constructing
	// a verifier performs no Generate/Unwrap provider request or source restart.
	verifier, err := f.ForPart(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	defer verifier.Close()
	if verifier.factory != f || verifier.access == nil || verifier.access.Scope() != scope || publisherVerifierHistoryHash(verifier.history) != verifier.historyHash {
		return nil, nil, publisherVerifierFailure("source recovery original history")
	}
	source, err := f.cfg.Records.OpenPublisherSourceRecovery(ctx, verifier.access, verifier.history)
	if err != nil {
		return nil, nil, err
	}
	// Do not let D's record-key/history work turn the earlier current claim or
	// provider check into a reusable authorization. Re-read the original scope.
	if source == nil || verifier.Recheck(ctx) != nil {
		return nil, nil, publisherVerifierFailure("source recovery current tail")
	}
	return source, verifier.access, nil
}
