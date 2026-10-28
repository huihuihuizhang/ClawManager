package systembackupread

import (
	"context"
	"database/sql"
	"time"
)

// OperationDTO leaves failure_message null and omits raw response evidence;
// those stored values have no reviewed redaction source for this read path.
type OperationDTO struct {
	SchemaVersion          string  `json:"schema_version"`
	PublicID               string  `json:"public_id"`
	OriginInstallationID   string  `json:"origin_installation_id"`
	OperationType          string  `json:"operation_type"`
	TargetType             string  `json:"target_type"`
	TargetPublicID         string  `json:"target_public_id"`
	ActorType              string  `json:"actor_type"`
	ActorID                string  `json:"actor_id"`
	Endpoint               string  `json:"endpoint"`
	IdempotencyKey         string  `json:"idempotency_key"`
	RequestHash            string  `json:"request_hash"`
	Status                 string  `json:"status"`
	ResultResourcePublicID *string `json:"result_resource_public_id"`
	ResultConfigVersion    *uint64 `json:"result_config_version"`
	Retryable              bool    `json:"retryable"`
	FailureCategory        string  `json:"failure_category"`
	FailureMessage         *string `json:"failure_message"`
	HTTPStatus             *int    `json:"http_status"`
	RowVersion             uint64  `json:"row_version"`
	DeadlineAt             string  `json:"deadline_at"`
	StartedAt              *string `json:"started_at"`
	FinishedAt             *string `json:"finished_at"`
	CreatedAt              string  `json:"created_at"`
	UpdatedAt              string  `json:"updated_at"`
}

func ProjectOperation(row OperationSnapshot) (OperationDTO, error) {
	if !validOperationSnapshot(row, row.installationID) {
		return OperationDTO{}, ErrUnavailable
	}
	var resource *string
	if row.resultResourcePublicID.Valid {
		value := row.resultResourcePublicID.String
		resource = &value
	}
	var version *uint64
	if row.resultConfigVersion.Valid {
		value := uint64(row.resultConfigVersion.Int64)
		version = &value
	}
	var status *int
	if row.httpStatus.Valid {
		value := int(row.httpStatus.Int64)
		status = &value
	}
	return OperationDTO{
		SchemaVersion: "system-backup-operation.v1", PublicID: row.publicID,
		OriginInstallationID: row.installationID, OperationType: row.operationType,
		TargetType: row.targetType, TargetPublicID: row.targetPublicID,
		ActorType: row.actorType, ActorID: row.actorID, Endpoint: row.endpoint,
		IdempotencyKey: row.idempotencyKey, RequestHash: row.requestHash, Status: row.status,
		ResultResourcePublicID: resource, ResultConfigVersion: version,
		Retryable: row.retryable, FailureCategory: row.failureCategory, HTTPStatus: status,
		RowVersion: row.rowVersion, DeadlineAt: row.deadlineAt.UTC().Format(time.RFC3339Nano),
		StartedAt: operationTime(row.startedAt), FinishedAt: operationTime(row.finishedAt),
		CreatedAt: row.createdAt.UTC().Format(time.RFC3339Nano), UpdatedAt: row.updatedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func operationTime(value sql.NullTime) *string {
	if !value.Valid {
		return nil
	}
	formatted := value.Time.UTC().Format(time.RFC3339Nano)
	return &formatted
}

func (s *Service) GetOperationDTO(ctx context.Context, publicID string) (OperationDTO, error) {
	if s == nil || s.reader == nil {
		return OperationDTO{}, ErrDenied
	}
	row, err := s.reader.GetOperation(ctx, publicID)
	if err != nil {
		return OperationDTO{}, err
	}
	return ProjectOperation(row)
}
