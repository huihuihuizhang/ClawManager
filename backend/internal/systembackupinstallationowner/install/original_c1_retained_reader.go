package install

import (
	"context"
	"sync/atomic"

	ev "clawreef/internal/systembackupevidence"
)

// A fresh single-read credential for one authenticated ORIGINAL C1 envelope.
// It never borrows the archive producer's one-wrap/one-unwrap counter or task
// DEK. Each actual reader login still checks original scope, real current Pod,
// TokenReview, Vault role/policy, original maintenance SQL and shortest expiry.
type originalRetainedC1ReadCredential struct {
	provider *OriginalAdoptionArchiveProvider
	key      ev.KeyRef
	used     atomic.Bool
}

func (c *originalRetainedC1ReadCredential) Resolve(ctx context.Context, key ev.KeyRef, operation ev.TransitOperation) (ev.TransitCredential, error) {
	if c == nil || c.provider == nil || c.provider.origin != c.provider || !consumerSameContext(ctx, c.provider.ctx) || ctx.Err() != nil || key != c.key || key != c.provider.definition.Vault.Transit.Key || operation != ev.TransitUnwrap || c.used.Swap(true) || c.provider.current() != nil {
		return ev.TransitCredential{}, ErrInstall
	}
	return c.provider.originalReaderCredential()
}
