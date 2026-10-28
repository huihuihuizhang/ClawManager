package systembackupevidence

import (
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"time"
)

// Fixed algorithm/composition used by historical candidates and the explicit
// full adapter. Real grants/metadata/DDL freeze and deployment protocol
// authority remain mandatory; no caller supplies a replacement finalizer.
func (s *SQLDownloadRetentionGC) collectFrozenCandidate(ctx context.Context, c downloadGCFreezeConfig, operation string) (downloadGCFreezeOutcome, error) {
	return s.collectFrozenWithPreparedCapacity(ctx, c, operation, nil)
}

func (s *SQLDownloadRetentionGC) collectFrozenWithPreparedCapacity(ctx context.Context, c downloadGCFreezeConfig, operation string, capacity *sec.PreparedConfigMutationCapacity) (downloadGCFreezeOutcome, error) {
	denied := downloadGCFreezeOutcome{Transaction: "not_started", Unlock: "not_acquired"}
	if s == nil || ctx == nil || ctx.Err() != nil || !downloadAdmissionOperationID.MatchString(operation) || operation == s.c.OperationID || c.Server != s.c.Registry.ServerUUID || c.Database != s.c.Registry.Database {
		return denied, errDownloadGCFreezeDenied
	}
	if s.freeze != nil && capacity == nil {
		return denied, errDownloadGCFreezeDenied
	}
	peer, err := pinnedPeerExpiry(ctx, s, s.roots, s.c.CertificateSHA256, s.c.ExpiresAt)
	if err != nil {
		return denied, errDownloadGCFreezeDenied
	}
	var completed *downloadGCWorkFinalizer
	var workErr error
	out, runErr := runDownloadGCFreezeProtocol(ctx, c, func(workCtx context.Context, tx *sql.Tx) error {
		var server, database string
		var now time.Time
		var offset int64
		if tx.QueryRowContext(workCtx, downloadGCConnectionIdentitySQL).Scan(&server, &database, &now, &offset) != nil || server != s.c.Registry.ServerUUID || database != s.c.Registry.Database || now.IsZero() || offset != 0 {
			return ErrDenied
		}
		workErr = s.collectProtectedWorkWithCapacity(workCtx, tx, operation, peer, now, &completed, capacity)
		return workErr
	}, func(finalCtx context.Context, tx *sql.Tx) error {
		// This callback is internal and fixed. It runs after the final ticket,
		// before the sole owner commit, using only the real work's capability.
		if completed == nil {
			return errDownloadGCFinalizationDenied
		}
		return completed.finish(finalCtx, tx, s, operation)
	})
	if runErr == errDownloadGCFreezeDenied && out.Transaction == "rolled_back" && out.Unlock == "confirmed" && workErr != nil {
		return out, boundary(workErr)
	}
	return out, runErr
}
