package systembackupevidence

import (
	"context"
	"database/sql"
	"time"
)

// These locks are shared by provider authorization and the GC claim/result
// transactions. Keep installation/config -> owner scope -> operation -> evidence.
func (a *SQLGCAuthority) lockConfig(ctx context.Context, tx *sql.Tx) (time.Duration, error) {
	c, s := a.c, a.c.Registry
	rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
	if err != nil {
		return 0, ErrDenied
	}
	count, found := 0, false
	for rows.Next() {
		var installation string
		if rows.Scan(&installation) != nil {
			rows.Close()
			return 0, ErrDenied
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
	var store, del KeyRef
	var retrySeconds int64
	if tx.QueryRowContext(ctx, `SELECT config_sha256,evidence_store_identity_hash,evidence_store_ref_version,evidence_delete_identity_hash,evidence_delete_ref_version,retry_max_backoff_seconds
FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE`, s.Installation, c.ConfigVersion).Scan(&configHash, &store.Identity, &store.Version, &del.Identity, &del.Version, &retrySeconds) != nil || configHash != c.ConfigSHA256 || store != c.Store || del != c.Delete || retrySeconds < 5 || retrySeconds > 600 {
		return 0, ErrDenied
	}
	return time.Duration(retrySeconds) * time.Second, nil
}

type gcOperation struct {
	until, deadline time.Time
	rowVersion      int64
}

func (a *SQLGCAuthority) lockOperation(ctx context.Context, tx *sql.Tx) (gcOperation, error) {
	c, s := a.c, a.c.Registry
	var opType, targetType, targetID, actorType, actorID, status, claim string
	var rowVersion int64
	var opUntil, deadline time.Time
	if tx.QueryRowContext(ctx, `SELECT operation_type,target_type,target_public_id,actor_type,actor_id,status,claim_owner,claim_expires_at,row_version,deadline_at
FROM system_backup_v2_operations WHERE origin_installation_id=? AND public_id=? FOR UPDATE`, s.Installation, c.OperationID).Scan(&opType, &targetType, &targetID, &actorType, &actorID, &status, &claim, &opUntil, &rowVersion, &deadline) != nil ||
		opType != "evidence_gc" || targetType != "system" || targetID != s.Installation || actorType != "system" || actorID != "system:controller" || status != "running" || claim != c.OperationClaim || rowVersion != c.OperationRowVersion {
		return gcOperation{}, ErrDenied
	}
	return gcOperation{opUntil, deadline, rowVersion}, nil
}
