package systembackupread

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"clawreef/internal/systembackupcontract"
)

const TaskEventInstallationHeader = "X-System-Backup-Origin-Installation-ID"
const TaskEventRowVersionHeader = "X-System-Backup-Task-Row-Version"
const taskEventMessageSQLPrefix = "SELECT id,message FROM system_backup_v2_events WHERE origin_installation_id=? AND target_type=? AND target_public_id=? AND id IN ("

// The event table contains already-redacted events under the v12 event table and EventResource contract.
// Redaction belongs to the producer's admission path. Reading these records
// needs current read authority, not a second provider/report-health decision.
// Transport metadata binds the page to the selected task even when its full
// multi-Owner detail is unavailable; it is not added to the public JSON DTO.
type TaskEventDTOResult struct {
	Resource       systembackupcontract.EventResourceList
	InstallationID string
	TaskRowVersion uint64
}

func (TaskEventDTOResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func (s *Service) ListTaskEventsDTO(ctx context.Context, kind TaskKind, publicID string, limit int, token string) (TaskEventDTOResult, error) {
	if s == nil || s.reader == nil || s.cursor == nil {
		return TaskEventDTOResult{}, ErrDenied
	}
	request := TaskEventPageRequest{Kind: kind, PublicID: publicID, Limit: limit}
	if token != "" {
		var err error
		request, err = s.cursor.DecodeTaskEvents(token, kind, publicID, limit)
		if err != nil {
			return TaskEventDTOResult{}, err
		}
	}
	return readTaskEventControlInTransaction(ctx, s.reader, request, func(ctx context.Context, q detailReadSQL, page TaskEventControlPage) (TaskEventDTOResult, error) {
		var zero TaskEventDTOResult
		if _, err := ProjectTask(page.task); err != nil {
			return zero, err
		}
		messages, err := readTaskEventMessages(ctx, q, page)
		if err != nil {
			return zero, err
		}
		resource := systembackupcontract.EventResourceList{Items: make([]systembackupcontract.EventResource, 0, len(page.events)), Consistency: page.consistency}
		for _, event := range page.events {
			item := systembackupcontract.EventResource{SchemaVersion: "system-backup-event.v1", TargetType: string(event.Kind), TargetPublicID: event.PublicID,
				EventType: event.EventType, Level: event.Level, TaskStatus: eventTextPointer(event.TaskStatus.String, event.TaskStatus.Valid), Message: messages[event.ID],
				RequestID: eventTextPointer(event.RequestID.String, event.RequestID.Valid), CreatedAt: event.CreatedAt.UTC().Format(time.RFC3339Nano)}
			if event.DetailsPresent {
				if event.OriginalSize.Valid && event.OriginalSize.V > maxJSONSafeInteger {
					return zero, ErrUnavailable
				}
				item.Details = &systembackupcontract.EventDetails{
					PreviousStatus: eventTextPointer(event.PreviousStatus.String, event.PreviousStatus.Valid), CurrentStatus: eventTextPointer(event.CurrentStatus.String, event.CurrentStatus.Valid),
					Reason: eventTextPointer(event.Reason.String, event.Reason.Valid), AttemptNumber: eventNumberPointer(event.AttemptNumber.V, event.AttemptNumber.Valid),
					OperationPublicID: eventTextPointer(event.OperationPublicID.String, event.OperationPublicID.Valid), EvidencePublicID: eventTextPointer(event.EvidencePublicID.String, event.EvidencePublicID.Valid),
					Truncated: event.Truncated.Valid && event.Truncated.Bool, OriginalSize: eventNumberPointer(event.OriginalSize.V, event.OriginalSize.Valid), ContentHash: eventTextPointer(event.ContentHash.String, event.ContentHash.Valid),
				}
			}
			resource.Items = append(resource.Items, item)
		}
		if page.hasMore {
			next, err := s.cursor.EncodeTaskEvents(request, page)
			if err != nil {
				return zero, err
			}
			resource.NextCursor = &next
		}
		return TaskEventDTOResult{Resource: resource, InstallationID: page.installation, TaskRowVersion: page.task.RowVersion}, nil
	})
}

func readTaskEventMessages(ctx context.Context, q detailReadSQL, page TaskEventControlPage) (map[uint64]string, error) {
	messages := make(map[uint64]string, len(page.events))
	if len(page.events) == 0 {
		return messages, nil
	}
	if len(page.events) > 500 {
		return nil, ErrUnavailable
	}
	allowed := make(map[uint64]bool, len(page.events))
	args := []any{page.installation, string(page.task.Kind), page.task.PublicID}
	for _, event := range page.events {
		allowed[event.ID] = true
		args = append(args, event.ID)
	}
	query := taskEventMessageSQLPrefix + strings.TrimSuffix(strings.Repeat("?,", len(page.events)), ",") + ")"
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, ErrUnavailable
	}
	for rows.Next() {
		var id uint64
		var message string
		if err := rows.Scan(&id, &message); err != nil || !allowed[id] || !utf8.ValidString(message) || utf8.RuneCountInString(message) > 2048 {
			rows.Close()
			return nil, ErrUnavailable
		}
		if _, duplicate := messages[id]; duplicate {
			rows.Close()
			return nil, ErrUnavailable
		}
		messages[id] = message
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return nil, ErrUnavailable
	}
	if len(messages) != len(page.events) {
		return nil, ErrUnavailable
	}
	return messages, nil
}

func eventTextPointer(value string, valid bool) *string {
	if !valid {
		return nil
	}
	return &value
}
func eventNumberPointer(value uint64, valid bool) *int64 {
	if !valid {
		return nil
	}
	number := int64(value)
	return &number
}
