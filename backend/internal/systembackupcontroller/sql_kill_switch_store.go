package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type SQLKillSwitchStore struct {
	DB *sql.DB
}

func (s SQLKillSwitchStore) ListPending(ctx context.Context, installationID string, kind TargetKind, effectiveEnabled bool, limit int) ([]KillSwitchCandidate, error) {
	if s.DB == nil {
		return nil, errors.New("nil system backup SQL kill-switch database")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !installationIDPattern.MatchString(installationID) {
		return nil, errors.New("invalid SQL kill-switch installation ID")
	}
	if limit < 1 || limit > MaxKillSwitchBatch {
		return nil, fmt.Errorf("SQL kill-switch limit must be between 1 and %d", MaxKillSwitchBatch)
	}
	query, err := killSwitchCandidateSQL(kind, effectiveEnabled)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, query, installationID, limit)
	if err != nil {
		return nil, fmt.Errorf("query pending %s kill-switch candidates: %w", kind, err)
	}
	defer rows.Close()

	candidates := make([]KillSwitchCandidate, 0)
	for rows.Next() {
		var candidate KillSwitchCandidate
		candidate.Target.Kind = kind
		if err := rows.Scan(&candidate.Target.PublicID, &candidate.RowVersion, &candidate.PendingReason); err != nil {
			return nil, fmt.Errorf("scan pending %s kill-switch candidate: %w", kind, err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending %s kill-switch candidates: %w", kind, err)
	}
	return candidates, nil
}

func (s SQLKillSwitchStore) TransitionPending(ctx context.Context, installationID string, candidate KillSwitchCandidate, desired PendingReason) (uint64, error) {
	if s.DB == nil {
		return 0, errors.New("nil system backup SQL kill-switch database")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !installationIDPattern.MatchString(installationID) || !desired.valid() || desired == candidate.PendingReason || candidate.RowVersion < 1 {
		return 0, errors.New("invalid SQL kill-switch transition")
	}
	descriptor, err := candidate.Target.descriptor()
	if err != nil {
		return 0, fmt.Errorf("invalid SQL kill-switch target: %w", err)
	}
	if candidate.Target.Kind == TargetOperation {
		return 0, errors.New("operation is not a kill-switch task target")
	}
	query := fmt.Sprintf(
		"UPDATE %s SET pending_reason = ?, row_version = row_version + 1 WHERE origin_installation_id = ? AND public_id = ? AND status = 'pending' AND pending_reason = ? AND row_version = ?",
		descriptor.table,
	)
	result, err := s.DB.ExecContext(ctx, query, desired, installationID, candidate.Target.PublicID, candidate.PendingReason, candidate.RowVersion)
	if err != nil {
		return 0, fmt.Errorf("update pending %s kill-switch reason: %w", candidate.Target.Kind, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read pending %s kill-switch result: %w", candidate.Target.Kind, err)
	}
	if rows != 1 {
		return 0, ErrKillSwitchTransitionRejected
	}
	return candidate.RowVersion + 1, nil
}

func killSwitchCandidateSQL(kind TargetKind, effectiveEnabled bool) (string, error) {
	descriptor, ok := targetDescriptors[kind]
	if !ok || kind == TargetOperation {
		return "", fmt.Errorf("unsupported kill-switch target kind %q", kind)
	}
	reasonPredicate := "pending_reason <> 'kill_switch'"
	if effectiveEnabled {
		reasonPredicate = "pending_reason = 'kill_switch'"
	}
	return fmt.Sprintf(
		"SELECT public_id, row_version, pending_reason FROM %s WHERE origin_installation_id = ? AND status = 'pending' AND %s ORDER BY id LIMIT ?",
		descriptor.table,
		reasonPredicate,
	), nil
}
