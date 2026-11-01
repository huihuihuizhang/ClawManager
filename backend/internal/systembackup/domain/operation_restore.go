package domain

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/systembackup/team"
)

const NorthboundOperation077Normalizer = "northbound-operation.077"

// Reviewed migrations 045/066/077. Session/key/team/template identifiers are
// historical references, not credentials or permission to recreate deleted work.
const operation077Columns = "id operation_id user_id session_id operation_type idempotency_key_hash request_hash request_payload status available_at instance_id attempt_count lease_owner lease_expires_at error_code error_message created_at started_at finished_at updated_at api_key_id auth_scope owner team_id template_id owner_request_key"

func operationRestoreTime(raw string) (time.Time, error) {
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || !strings.HasSuffix(raw, "Z") || at.Year() < 1000 || at.Year() > 9999 || at.Nanosecond()%1000 != 0 {
		return time.Time{}, ErrNormalization
	}
	return at, nil
}

func validateOperation077Adapter(a TableAdapter, t Table) error {
	if t.Name != "northbound_operations" || len(t.Columns) != 26 || len(t.PrimaryKey) != 1 || t.PrimaryKey[0] != "id" {
		return ErrSchema
	}
	if _, err := operationRestoreTime(a.InterruptedAt); err != nil {
		return err
	}
	for _, name := range strings.Fields(operation077Columns) {
		if !hasColumn(t, name) || a.Columns[name] != "preserve" {
			return ErrSchema
		}
	}
	return nil
}

func operation077Projection(row Row) (models.NorthboundOperation, error) {
	var op models.NorthboundOperation
	err := decodeOwnerCells(row, map[string]any{
		"id": &op.ID, "operation_id": &op.OperationID, "user_id": &op.UserID, "session_id": &op.SessionID,
		"operation_type": &op.OperationType, "idempotency_key_hash": &op.IdempotencyKeyHash, "request_hash": &op.RequestHash,
		"request_payload": &op.RequestPayload, "status": &op.Status, "available_at": &op.AvailableAt,
		"instance_id": &op.InstanceID, "attempt_count": &op.AttemptCount, "lease_owner": &op.LeaseOwner,
		"lease_expires_at": &op.LeaseExpiresAt, "error_code": &op.ErrorCode, "error_message": &op.ErrorMessage,
		"created_at": &op.CreatedAt, "started_at": &op.StartedAt, "finished_at": &op.FinishedAt, "updated_at": &op.UpdatedAt,
		"api_key_id": &op.APIKeyID, "auth_scope": &op.AuthScope, "owner": &op.Owner, "team_id": &op.TeamID,
		"template_id": &op.TemplateID, "owner_request_key": &op.OwnerRequestKey,
	})
	if err != nil {
		return op, err
	}
	if op.ID <= 0 || op.UserID <= 0 || op.OperationID == "" || op.AttemptCount < 0 || !json.Valid([]byte(op.RequestPayload)) {
		return op, ErrData
	}
	for _, at := range []time.Time{op.CreatedAt, op.UpdatedAt, op.AvailableAt} {
		if at.Year() < 1000 || at.Year() > 9999 {
			return op, ErrData
		}
	}
	for _, at := range []*time.Time{op.StartedAt, op.FinishedAt, op.LeaseExpiresAt} {
		if at != nil && (at.Year() < 1000 || at.Year() > 9999) {
			return op, ErrData
		}
	}
	return op, nil
}

func normalizeOperation077(row Row, frozenTime string) error {
	at, err := operationRestoreTime(frozenTime)
	if err != nil {
		return err
	}
	op, err := operation077Projection(row)
	if err != nil {
		return err
	}
	if at.Before(op.CreatedAt) || at.Before(op.UpdatedAt) {
		return ErrData
	}
	source := make(team.Row, len(row))
	for name, cell := range row {
		source[name] = team.Cell{IsNull: cell.Null, Data: append([]byte(nil), cell.Bytes...)}
	}
	change, err := team.Normalize("northbound_operations", source, at)
	if err != nil {
		return ErrNormalization
	}
	// Consume the owner's existing state machine: active -> failed, terminal
	// history unchanged, both leases NULL, finished_at filled only if absent on
	// interrupted work. Never invoke an operation scheduler/completion handler.
	for _, name := range []string{"status", "lease_owner", "lease_expires_at", "finished_at"} {
		cell := change.After[name]
		row[name] = Cell{Null: cell.IsNull, Bytes: append([]byte(nil), cell.Data...)}
	}
	return nil
}

// Also protects older explicitly pinned adapters: terminal status and cleared
// leases are required regardless of how the expected encrypted file was made.
// Current full rows additionally get the typed 077 data checks. This does not
// grant a schema exception; Normalize still enforces each selected exact pin.
func VerifyOperationQuarantine(ctx context.Context, snapshot Snapshot) error {
	for _, table := range snapshot.Tables {
		if table.Name != "northbound_operations" {
			continue
		}
		for _, row := range table.Rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if row["status"].Null || !slices.Contains([]string{"succeeded", "failed", "canceled"}, row["status"].String()) {
				return ErrNormalization
			}
			for _, name := range []string{"lease_owner", "lease_expires_at"} {
				if cell, present := row[name]; present && !cell.Null {
					return ErrNormalization
				}
			}
			if hasColumn(table, "request_payload") {
				if len(table.Columns) != 26 {
					return ErrSchema
				}
				if _, err := operation077Projection(row); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
