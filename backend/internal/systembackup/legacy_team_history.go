package systembackup

import (
	"context"
	"errors"
)

// These records are never converted into public-v1 tasks. In particular,
// unfinished work is evidence requiring inspection, not permission to replay.
type LegacyTeamHistoryEntry struct {
	TeamDataJob
	RequiresInspection bool `json:"requires_inspection"`
}

type LegacyTeamHistoryPage struct {
	Items           []LegacyTeamHistoryEntry `json:"items"`
	NextCursor      string                   `json:"next_cursor,omitempty"`
	UnfinishedCount int64                    `json:"unfinished_count"`
	HistoryOnly     bool                     `json:"history_only"`
	WritesAvailable bool                     `json:"writes_available"`
}

func legacyTeamHistoryEntry(j TeamDataJob) LegacyTeamHistoryEntry {
	terminal := j.Status == "succeeded" || j.Status == "failed" || j.Status == "canceled" || j.Status == "cleaned" || j.Status == "deleted"
	// A failed SQL projection is not proof that an isolated copy was removed or
	// an uncertain publish never happened. Preserve these for owned inspection.
	uncertain := j.Phase == "interrupted" || j.Error == "backup_result_unconfirmed" || j.Error == "restore_result_unconfirmed" || j.Error == "operation_result_unconfirmed" ||
		((j.Operation == "restore" || j.Operation == "cleanup") && (j.Status == "failed" || j.Status == "canceled"))
	return LegacyTeamHistoryEntry{TeamDataJob: j, RequiresInspection: !terminal || uncertain || j.Phase == "retry_pending" || j.Phase == "retry_blocked" || j.Phase == "retry_stopped"}
}

func (s Store) LegacyTeamHistoryJob(ctx context.Context, id string) (LegacyTeamHistoryEntry, error) {
	if s.DB == nil || s.InstallationID == "" {
		return LegacyTeamHistoryEntry{}, errors.New("not_ready")
	}
	j, err := (&TeamDataService{db: s.DB}).Get(ctx, id)
	return legacyTeamHistoryEntry(j), err
}

func (s Store) LegacyTeamHistory(ctx context.Context, before string) (LegacyTeamHistoryPage, error) {
	out := LegacyTeamHistoryPage{Items: []LegacyTeamHistoryEntry{}, HistoryOnly: true}
	if s.DB == nil || s.InstallationID == "" {
		return out, errors.New("not_ready")
	}
	query := "SELECT " + teamDataColumns + " FROM system_team_data_backup_jobs"
	args := []any{}
	if before != "" {
		prior, err := s.LegacyTeamHistoryJob(ctx, before)
		if err != nil {
			return out, err
		}
		query += " WHERE (created_at,public_id)<(?,?)"
		args = append(args, prior.CreatedAt, prior.ID)
	}
	// The extra row detects another page without losing jobs sharing a timestamp.
	rows, err := s.DB.QueryContext(ctx, query+" ORDER BY created_at DESC,public_id DESC LIMIT 51", args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		j, err := scanTeamDataJob(rows)
		if err != nil {
			return out, err
		}
		if len(out.Items) == 50 {
			out.NextCursor = out.Items[49].ID
			break
		}
		out.Items = append(out.Items, legacyTeamHistoryEntry(j))
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if err = rows.Close(); err != nil {
		return out, err
	}
	// Inspect all history, not just the most recent page. Unknown states fail
	// toward inspection and are never guessed to be successful or safe to resume.
	err = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_team_data_backup_jobs
WHERE status NOT IN ('succeeded','failed','canceled','cleaned','deleted')
OR phase IN ('retry_pending','retry_blocked','retry_stopped','interrupted')
OR error_code IN ('backup_result_unconfirmed','restore_result_unconfirmed','operation_result_unconfirmed')
OR (operation IN ('restore','cleanup') AND status IN ('failed','canceled'))`).Scan(&out.UnfinishedCount)
	return out, err
}
