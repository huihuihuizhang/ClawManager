package systembackupevidence

import (
	"context"
	"database/sql"
	"time"
)

func (a *SQLWriteRecovery) lockConfig(ctx context.Context, tx *sql.Tx) (time.Duration, error) {
	c, s := a.c, a.c.Registry
	rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
	if err != nil {
		return 0, ErrUnavailable
	}
	count, found := 0, false
	for rows.Next() {
		var installation string
		if rows.Scan(&installation) != nil {
			rows.Close()
			return 0, ErrUnavailable
		}
		count++
		if count > 10000 {
			rows.Close()
			return 0, ErrDenied
		}
		found = found || installation == s.Installation
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil || !found {
		return 0, ErrDenied
	}
	var version int64
	if tx.QueryRowContext(ctx, "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", s.Installation).Scan(&version) != nil || version != c.ConfigVersion {
		return 0, ErrDenied
	}
	var configHash string
	var store, read KeyRef
	var retrySeconds int64
	if tx.QueryRowContext(ctx, `SELECT config_sha256,evidence_store_identity_hash,evidence_store_ref_version,evidence_read_identity_hash,evidence_read_ref_version,retry_max_backoff_seconds
FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE`, s.Installation, c.ConfigVersion).Scan(&configHash, &store.Identity, &store.Version, &read.Identity, &read.Version, &retrySeconds) != nil || configHash != c.ConfigSHA256 || store != c.Store || read != c.Read || retrySeconds < 5 || retrySeconds > 600 {
		return 0, ErrDenied
	}
	return time.Duration(retrySeconds) * time.Second, nil
}

type recoveryCandidate struct {
	sequence int64
	id       string
}

// RecoveryBatch is an internal worker checkpoint, not an Admin API DTO.
// Continue from AfterID while More is true; start the next scheduled sweep
// from zero after the end. IDs are hints, never authority to access an object.
type RecoveryBatch struct {
	AfterID int64
	More    bool
	Results []RecoveryResult
}

type RecoveryResult struct {
	EvidenceID string
	Err        error
}

// ReconcileBatch performs one bounded scan and sequential recovery pass. No
// provider calls occur while the scan transaction holds control-plane locks.
// A failed candidate advances the cursor so poison rows cannot starve later
// candidates. They are revisited on the next sweep; no row is dropped.
func (a *SQLWriteRecovery) ReconcileBatch(ctx context.Context, afterID int64, limit int, store RecoveryStat) (RecoveryBatch, error) {
	batch := RecoveryBatch{AfterID: afterID}
	if a == nil || store == nil || afterID < 0 || limit < 1 || limit > 100 {
		return batch, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	candidates, more, err := a.scan(ctx, afterID, limit)
	if err != nil {
		return batch, err
	}
	batch.More = more
	for index, candidate := range candidates {
		if ctx.Err() != nil {
			batch.More = true
			return batch, ErrUnavailable
		}
		err := a.Reconcile(ctx, candidate.id, store)
		batch.Results = append(batch.Results, RecoveryResult{EvidenceID: candidate.id, Err: boundaryOrNil(err)})
		batch.AfterID = candidate.sequence
		if ctx.Err() != nil {
			batch.More = more || index+1 < len(candidates)
			return batch, ErrUnavailable
		}
	}
	return batch, nil
}

func (a *SQLWriteRecovery) scan(ctx context.Context, afterID int64, limit int) ([]recoveryCandidate, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	until, err := pinnedPeerExpiry(ctx, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
	if err != nil {
		return nil, false, ErrDenied
	}
	s := a.c.Registry
	tx, _, err := s.begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if _, err = a.lockConfig(ctx, tx); err != nil {
		return nil, false, err
	}
	// A literal prefix comparison avoids SQL LIKE's underscore wildcard in
	// installation IDs. Policy.LockScope still proves ownership per candidate.
	prefix := a.c.Root + "/" + s.Installation + "/"
	rows, err := tx.QueryContext(ctx, recoveryCandidatesSQL, afterID, a.c.Store.Identity, a.c.Store.Version, len(prefix), prefix, limit+1)
	if err != nil {
		return nil, false, ErrUnavailable
	}
	var candidates []recoveryCandidate
	last := afterID
	for rows.Next() {
		var c recoveryCandidate
		if rows.Scan(&c.sequence, &c.id) != nil || c.sequence <= last || !idPattern.MatchString(c.id) || len(candidates) >= limit+1 {
			rows.Close()
			return nil, false, ErrIntegrity
		}
		last = c.sequence
		candidates = append(candidates, c)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil {
		return nil, false, ErrUnavailable
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(until) || time.Since(now) > 5*time.Second || time.Until(now) > 5*time.Second {
		return nil, false, ErrDenied
	}
	if tx.Commit() != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return nil, false, ErrUnavailable
	}
	more := len(candidates) > limit
	if more {
		candidates = candidates[:limit]
	}
	return candidates, more, nil
}

const recoveryCandidatesSQL = `SELECT id,public_id FROM system_backup_v2_evidence
WHERE id>? AND storage_state IN ('pending','write_unknown')
AND storage_provider_role='evidence' AND storage_identity_hash=? AND storage_ref_version=?
AND NOT (owner_target_type='system' AND evidence_type='capability_snapshot')
AND LEFT(storage_relative_key,?)=? AND storage_immutable_version IS NULL
AND (next_reconcile_at IS NULL OR next_reconcile_at<=UTC_TIMESTAMP(6))
AND (claim_owner IS NULL OR claim_expires_at<=UTC_TIMESTAMP(6))
ORDER BY id LIMIT ?`
