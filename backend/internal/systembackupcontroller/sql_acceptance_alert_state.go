package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const acceptanceAnomalyStateKey = "acceptance-consecutive-anomalies"

// SQLAcceptanceAnomalyReader reads the D-owned persisted sequence without
// tying it to the active alert profile. Profile switches change severity, not
// the historical consecutive count. Missing rows remain missing so the
// controller-state predicate can apply its fail-closed missing-series rule.
type SQLAcceptanceAnomalyReader struct {
	DB *sql.DB
}

// Evaluate reads the installation-scoped persisted sequence and produces the
// two acceptance decisions. A missing row remains missing and therefore fires;
// a failed read never publishes a partial decision set.
func (r SQLAcceptanceAnomalyReader) Evaluate(ctx context.Context, installationID, profile string) ([]ControllerStateAlertDecision, error) {
	if profile != "production" && profile != "development" {
		return nil, errors.New("invalid controller-state alert profile")
	}
	counts, err := r.Read(ctx, installationID)
	if err != nil {
		return nil, err
	}
	return evaluateAcceptanceAnomalyDecisions(profile, counts)
}

func (r SQLAcceptanceAnomalyReader) Read(ctx context.Context, installationID string) (map[TargetKind]uint64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.DB == nil {
		return nil, errors.New("nil acceptance anomaly database")
	}
	if !installationIDPattern.MatchString(installationID) {
		return nil, errors.New("invalid acceptance anomaly installation ID")
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT task_type, consecutive_anomaly_count
FROM system_backup_alert_states
WHERE origin_installation_id = ?
  AND rule_key = ?
  AND matrix_key = 'all'
  AND task_purpose = 'acceptance'
  AND task_type IN ('backup', 'drill')
ORDER BY task_type
LIMIT 3`, installationID, acceptanceAnomalyStateKey)
	if err != nil {
		return nil, fmt.Errorf("read acceptance anomaly state: %w", err)
	}
	defer rows.Close()
	counts := make(map[TargetKind]uint64, 2)
	for rows.Next() {
		var kind TargetKind
		var count uint64
		if err := rows.Scan(&kind, &count); err != nil {
			return nil, fmt.Errorf("scan acceptance anomaly state: %w", err)
		}
		if kind != TargetBackup && kind != TargetDrill {
			return nil, fmt.Errorf("unexpected acceptance anomaly task type %q", kind)
		}
		if _, exists := counts[kind]; exists {
			return nil, fmt.Errorf("duplicate acceptance anomaly task type %q", kind)
		}
		counts[kind] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate acceptance anomaly state: %w", err)
	}
	return counts, nil
}
