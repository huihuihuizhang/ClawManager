package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type SQLGateRecoveryStore struct {
	DB *sql.DB
}

func (s SQLGateRecoveryStore) ListExpiredGates(ctx context.Context, installationID string, limit int) ([]GateRecoveryCandidate, error) {
	if s.DB == nil {
		return nil, errors.New("nil system backup SQL gate recovery database")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !installationIDPattern.MatchString(installationID) {
		return nil, errors.New("invalid system backup SQL gate recovery installation ID")
	}
	if limit < 1 || limit > MaxGateRecoveryBatch {
		return nil, fmt.Errorf("SQL gate recovery limit must be between 1 and %d", MaxGateRecoveryBatch)
	}
	rows, err := s.DB.QueryContext(ctx, expiredGateCandidateSQL(), installationID, limit)
	if err != nil {
		return nil, fmt.Errorf("query expired system backup maintenance gates: %w", err)
	}
	defer rows.Close()

	candidates := make([]GateRecoveryCandidate, 0)
	for rows.Next() {
		var candidate GateRecoveryCandidate
		var state string
		if err := rows.Scan(&candidate.Key.InstallationID, &candidate.Key.Scope, &state, &candidate.RowVersion); err != nil {
			return nil, fmt.Errorf("scan expired system backup maintenance gate: %w", err)
		}
		candidate.State = GateState(state)
		if err := candidate.validate(); err != nil {
			return nil, fmt.Errorf("database returned invalid maintenance gate recovery candidate: %w", err)
		}
		if candidate.Key.InstallationID != installationID {
			return nil, errors.New("database returned maintenance gate for another installation")
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expired system backup maintenance gates: %w", err)
	}
	return candidates, nil
}

func (s SQLGateRecoveryStore) RecoverAcquiring(ctx context.Context, candidate GateRecoveryCandidate, readiness GateRecoveryReadinessVerifier) (uint64, error) {
	if s.DB == nil {
		return 0, errors.New("nil system backup SQL gate recovery database")
	}
	if err := candidate.validate(); err != nil {
		return 0, err
	}
	if candidate.State != GateAcquiring {
		return 0, errors.New("gate recovery candidate is not acquiring")
	}
	if readiness == nil {
		return 0, errors.Join(ErrGateRecoveryNotReady, errors.New("nil participant running readiness verifier"))
	}
	coordinator := GateCoordinator{
		Factory:           SQLCoordinationTransactionFactory{DB: s.DB},
		RecoveryReadiness: readiness,
	}
	return coordinator.RecoverAcquiring(ctx, candidate.Key, candidate.RowVersion)
}

func (s SQLGateRecoveryStore) FenceForRelease(ctx context.Context, candidate GateRecoveryCandidate, owner string, policy GatePolicy) (GateToken, error) {
	if s.DB == nil {
		return GateToken{}, errors.New("nil system backup SQL gate recovery database")
	}
	if err := candidate.validate(); err != nil {
		return GateToken{}, err
	}
	if candidate.State != GateHeld && candidate.State != GateReleasing {
		return GateToken{}, errors.New("gate recovery candidate cannot be fenced for release")
	}
	coordinator := GateCoordinator{Factory: SQLCoordinationTransactionFactory{DB: s.DB}}
	return coordinator.RecoverRelease(ctx, candidate.Key, owner, candidate.RowVersion, policy)
}

func expiredGateCandidateSQL() string {
	return `SELECT origin_installation_id, scope, gate_state, row_version
FROM system_maintenance_locks
WHERE origin_installation_id = ?
  AND (
    (gate_state = 'acquiring' AND (lease_expires_at <= UTC_TIMESTAMP(6) OR acquisition_deadline_at <= UTC_TIMESTAMP(6)))
    OR (gate_state = 'held' AND (lease_expires_at <= UTC_TIMESTAMP(6) OR absolute_hold_deadline_at <= UTC_TIMESTAMP(6)))
    OR (gate_state = 'releasing' AND lease_expires_at <= UTC_TIMESTAMP(6))
  )
ORDER BY state_changed_at, id
LIMIT ?`
}
