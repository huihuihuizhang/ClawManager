package systembackupsecurity

import (
	"context"
	"database/sql"
	"time"
)

// BootstrapOriginalResourceAuthority is the current-identity L2 portion of a
// prepared concrete resource. It runs after the original admin/RBAC prefix and
// before operation-key/history lookup, including historical retries. It must
// only read/lock its original SQL source and controlled local immutable files:
// no provider I/O, preparation, credential hashing or transaction completion.
// Resource freshness remains the separate BootstrapResourceCheck.Recheck.
type BootstrapOriginalResourceAuthority interface {
	AuthorizeBootstrapOriginal(context.Context, *sql.Tx, OfflineBootstrapGrant, BootstrapConfig, time.Time) error
}

func (a *preparedBootstrapAdmission) authorizeOriginalResources(ctx context.Context, tx *sql.Tx, g OfflineBootstrapGrant, c BootstrapConfig, now time.Time) error {
	for _, check := range a.checks {
		if current, ok := check.(BootstrapOriginalResourceAuthority); ok {
			if candidateAuthorityNil(current) || ctx.Err() != nil || current.AuthorizeBootstrapOriginal(ctx, tx, g, c, now) != nil {
				return ErrRegistrationPermission
			}
		}
	}
	return nil
}
