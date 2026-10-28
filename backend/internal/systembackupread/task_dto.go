package systembackupread

import "time"

const maxJSONSafeInteger = uint64(1<<53 - 1)

// TaskDTO is the v12 Task list resource. It is built only from the fixed,
// authorized task projection; sensitive task and owner columns are absent.
type TaskDTO struct {
	SchemaVersion        string   `json:"schema_version"`
	PublicID             string   `json:"public_id"`
	OriginInstallationID string   `json:"origin_installation_id"`
	TaskType             TaskKind `json:"task_type"`
	ActorType            string   `json:"actor_type"`
	ActorID              string   `json:"actor_id"`
	Endpoint             string   `json:"endpoint"`
	IdempotencyKey       string   `json:"idempotency_key"`
	RequestHash          string   `json:"request_hash"`
	RequestID            string   `json:"request_id"`
	RetryOfPublicID      *string  `json:"retry_of_public_id"`
	Status               string   `json:"status"`
	PendingReason        string   `json:"pending_reason"`
	AttentionReason      string   `json:"attention_reason"`
	CanCancel            bool     `json:"can_cancel"`
	ConfigVersion        uint64   `json:"config_version"`
	Retryable            bool     `json:"retryable"`
	FailureCategory      string   `json:"failure_category"`
	RowVersion           uint64   `json:"row_version"`
	DeadlineAt           string   `json:"deadline_at"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
}

type TaskListDTO struct {
	Items       []TaskDTO `json:"items"`
	NextCursor  *string   `json:"next_cursor"`
	Consistency string    `json:"consistency"`
}

func ProjectTask(item TaskHeader) (TaskDTO, error) {
	table, ok := taskTables[item.Kind]
	if !ok || !installationID.MatchString(item.InstallationID) ||
		len(item.PublicID) != len(table.prefix)+36 || item.PublicID[:len(table.prefix)] != table.prefix ||
		!taskUUID.MatchString(item.PublicID[len(table.prefix):]) || !table.status[item.Status] ||
		item.ConfigVersion == 0 || item.ConfigVersion > maxJSONSafeInteger ||
		item.RowVersion == 0 || item.RowVersion > maxJSONSafeInteger || item.DeadlineAt.IsZero() ||
		item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() || !validTaskProjection(item, table) {
		return TaskDTO{}, ErrUnavailable
	}
	var retry *string
	if item.RetryOfPublicID.Valid {
		value := item.RetryOfPublicID.String
		retry = &value
	}
	return TaskDTO{
		SchemaVersion: "system-backup-task.v1", PublicID: item.PublicID,
		OriginInstallationID: item.InstallationID, TaskType: item.Kind,
		ActorType: item.ActorType, ActorID: item.ActorID, Endpoint: item.Endpoint,
		IdempotencyKey: item.IdempotencyKey, RequestHash: item.RequestHash,
		RequestID: item.RequestID, RetryOfPublicID: retry, Status: item.Status,
		PendingReason: item.PendingReason, AttentionReason: item.AttentionReason,
		CanCancel: item.CanCancel, ConfigVersion: item.ConfigVersion,
		Retryable: item.Retryable, FailureCategory: item.FailureCategory,
		RowVersion: item.RowVersion, DeadlineAt: item.DeadlineAt.UTC().Format(time.RFC3339Nano),
		CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func ProjectTaskList(result ListResult) (TaskListDTO, error) {
	page := result.Page
	if page.Consistency != "stable_cutoff" && page.Consistency != "eventual" ||
		!installationID.MatchString(page.InstallationID) || len(page.Items) > 500 ||
		page.HasMore != (result.NextCursor != "") || len(result.NextCursor) > maxCursorBytes ||
		page.HasMore && (len(page.Items) == 0 || page.BeforeID == 0) ||
		!page.HasMore && page.BeforeID != 0 {
		return TaskListDTO{}, ErrUnavailable
	}
	dto := TaskListDTO{Items: make([]TaskDTO, 0, len(page.Items)), Consistency: page.Consistency}
	if result.NextCursor != "" {
		cursor := result.NextCursor
		dto.NextCursor = &cursor
	}
	previousID := page.CutoffID
	for index, item := range page.Items {
		if item.InstallationID != page.InstallationID || item.ID == 0 ||
			item.ID > page.CutoffID || index > 0 && item.ID >= previousID ||
			index == len(page.Items)-1 && page.HasMore && item.ID != page.BeforeID ||
			index > 0 && item.Kind != page.Items[0].Kind {
			return TaskListDTO{}, ErrUnavailable
		}
		previousID = item.ID
		projected, err := ProjectTask(item)
		if err != nil {
			return TaskListDTO{}, err
		}
		dto.Items = append(dto.Items, projected)
	}
	return dto, nil
}
