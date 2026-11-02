package systembackupinstallationowner

import (
	"context"
	"database/sql"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

var _ sec.BootstrapOriginalResourceAuthority = (*PreparedCaptureSigning)(nil)

// AuthorizeBootstrapOriginal connects the concrete capture owner to the
// original legacy admission's L2 call, before its operation/history lookup.
// Subsequent checks retain the exact original guard/transaction and deadline;
// they do not prepare, re-probe or reinterpret expired resource authority.
func (p *PreparedCaptureSigning) AuthorizeBootstrapOriginal(ctx context.Context, tx *sql.Tx, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, _ time.Time) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	if p.origin != p || p.failed || p.candidateHash != "" || !sameContext(ctx, p.ctx) || grant != p.grant || config.SHA256() != p.config.SHA256() {
		p.failed = true
		p.mu.Unlock()
		return ErrOwner
	}
	guard := p.guard
	p.mu.Unlock()
	if guard != nil {
		return guard.RecheckOriginalIdentity(ctx, tx)
	}
	_, e := p.AuthorizeOriginal(ctx, tx, grant, config)
	return e
}
