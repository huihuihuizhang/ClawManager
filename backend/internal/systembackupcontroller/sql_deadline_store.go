package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type SQLDeadlineStore struct {
	DB *sql.DB
}

func (s SQLDeadlineStore) ListExpiredPending(ctx context.Context, installationID string, kind TargetKind, owner string, limit int) ([]DeadlineCandidate, error) {
	if s.DB == nil {
		return nil, errors.New("nil system backup SQL deadline database")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !controllerOwnerPattern.MatchString(owner) {
		return nil, errors.New("invalid system backup SQL deadline owner")
	}
	if !installationIDPattern.MatchString(installationID) {
		return nil, errors.New("invalid system backup SQL deadline installation ID")
	}
	if limit < 1 || limit > MaxDeadlineSweepBatch {
		return nil, fmt.Errorf("deadline candidate limit must be between 1 and %d", MaxDeadlineSweepBatch)
	}
	query, err := expiredPendingCandidateSQL(kind)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, query, installationID, owner, limit)
	if err != nil {
		return nil, fmt.Errorf("query expired pending %s tasks: %w", kind, err)
	}
	defer rows.Close()

	candidates := make([]DeadlineCandidate, 0)
	for rows.Next() {
		var publicID string
		var rowVersion uint64
		if err := rows.Scan(&publicID, &rowVersion); err != nil {
			return nil, fmt.Errorf("scan expired pending %s task: %w", kind, err)
		}
		candidate := DeadlineCandidate{Target: Target{Kind: kind, PublicID: publicID}, RowVersion: rowVersion}
		if _, err := candidate.Target.descriptor(); err != nil {
			return nil, fmt.Errorf("database returned invalid %s deadline candidate: %w", kind, err)
		}
		if rowVersion < 1 {
			return nil, fmt.Errorf("database returned invalid %s deadline row version", kind)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expired pending %s tasks: %w", kind, err)
	}
	return candidates, nil
}

func (s SQLDeadlineStore) Acquire(ctx context.Context, installationID string, candidate DeadlineCandidate, owner string, policy LeasePolicy) (ClaimToken, error) {
	if s.DB == nil {
		return ClaimToken{}, errors.New("nil system backup SQL deadline database")
	}
	return (ClaimCoordinator{Executor: s.DB, InstallationID: installationID}).Acquire(ctx, candidate.Target, owner, candidate.RowVersion, policy)
}

func (s SQLDeadlineStore) Expire(ctx context.Context, installationID string, token ClaimToken) (uint64, error) {
	if s.DB == nil {
		return 0, errors.New("nil system backup SQL deadline database")
	}
	if !installationIDPattern.MatchString(installationID) {
		return 0, errors.New("invalid system backup SQL deadline installation ID")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin pending deadline transaction: %w", err)
	}
	return ExpirePendingClaim(ctx, tx, installationID, token)
}

func (s SQLDeadlineStore) Release(ctx context.Context, installationID string, token ClaimToken, policy LeasePolicy) (uint64, error) {
	if s.DB == nil {
		return 0, errors.New("nil system backup SQL deadline database")
	}
	return (ClaimCoordinator{Executor: s.DB, InstallationID: installationID}).Release(ctx, token, policy.ReconcileInterval)
}

func expiredPendingCandidateSQL(kind TargetKind) (string, error) {
	descriptor, ok := targetDescriptors[kind]
	if !ok || kind == TargetOperation {
		return "", fmt.Errorf("unsupported pending deadline target kind %q", kind)
	}
	guard := fmt.Sprintf(
		"NOT EXISTS (SELECT 1 FROM system_backup_attempts AS attempt WHERE attempt.target_type = '%s' AND attempt.target_public_id = %s.public_id)",
		kind,
		descriptor.table,
	)
	if kind == TargetBackup {
		guard += " AND NOT EXISTS (SELECT 1 FROM system_backup_external_actions AS action WHERE action.target_type = 'backup' AND action.target_public_id = system_backups.public_id)"
	} else {
		guard += fmt.Sprintf(
			" AND NOT EXISTS (SELECT 1 FROM system_artifact_leases AS artifact_lease WHERE artifact_lease.holder_type = '%s' AND artifact_lease.holder_public_id = %s.public_id)",
			kind,
			descriptor.table,
		)
	}
	return fmt.Sprintf(
		"SELECT public_id, row_version FROM %s WHERE origin_installation_id = ? AND status = 'pending' AND deadline_at <= UTC_TIMESTAMP(6) AND (next_reconcile_at IS NULL OR next_reconcile_at <= UTC_TIMESTAMP(6)) AND (%s IS NULL OR %s = ? OR %s <= UTC_TIMESTAMP(6)) AND %s ORDER BY deadline_at, id LIMIT ?",
		descriptor.table,
		descriptor.ownerColumn,
		descriptor.ownerColumn,
		descriptor.leaseColumn,
		guard,
	), nil
}
