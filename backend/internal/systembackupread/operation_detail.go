package systembackupread

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackupcontract"
)

const operationProjectionColumns = `schema_version,public_id,origin_installation_id,operation_type,target_type,target_public_id,
actor_type,actor_id,endpoint,idempotency_key,request_hash,status,result_resource_public_id,result_config_version,
retryable,failure_category,http_status,row_version,deadline_at,started_at,finished_at,created_at,updated_at`

var operationEndpoint = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,127}$`)
var operationActorID = regexp.MustCompile(`^[0-9]+$`)

var operationTypes = statusSet(systembackupcontract.OperationTypes...)
var operationStatuses = statusSet("pending", "running", "succeeded", "failed")
var synchronousOperationTypes = statusSet("config_update", "provider_proof_register", "manual_hold_update", "promotion_create", "promotion_revoke")
var operationTargetPrefixes = map[string]string{
	"backup": "sbk_", "backup_staging": "sbs_", "external_action": "sxa_", "drill": "sdr_",
	"restore_resource": "srr_", "preflight": "spf_", "artifact_verify": "sav_", "catalog_scan": "scs_",
	"catalog_import": "sci_", "prune_run": "spr_", "promotion": "spm_",
	"evidence": "sev_",
}
var operationResultPrefixes = map[string]string{
	"provider_proof_register": "sev_", "promotion_create": "spm_", "catalog_scan": "scs_", "catalog_import": "sci_",
}

type OperationSnapshot struct {
	publicID               string
	installationID         string
	operationType          string
	targetType             string
	targetPublicID         string
	actorType              string
	actorID                string
	endpoint               string
	idempotencyKey         string
	requestHash            string
	status                 string
	resultResourcePublicID sql.NullString
	resultConfigVersion    sql.NullInt64
	retryable              bool
	failureCategory        string
	httpStatus             sql.NullInt64
	rowVersion             uint64
	deadlineAt             time.Time
	startedAt              sql.NullTime
	finishedAt             sql.NullTime
	createdAt              time.Time
	updatedAt              time.Time
}

func (OperationSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func (r *Reader) GetOperation(ctx context.Context, publicID string) (OperationSnapshot, error) {
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return OperationSnapshot{}, ErrDenied
	}
	if !operationPublicID(publicID) {
		return OperationSnapshot{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return OperationSnapshot{}, ErrUnavailable
	}
	defer tx.Rollback()
	installation, err := r.scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return OperationSnapshot{}, scopeReadFailure(err)
	}
	if !installationID.MatchString(installation) {
		return OperationSnapshot{}, ErrDenied
	}
	query := `SELECT ` + operationProjectionColumns + ` FROM system_backup_v2_operations
WHERE origin_installation_id=? AND public_id=? FOR SHARE`
	row, err := scanOperation(tx.QueryRowContext(ctx, query, installation, publicID), installation)
	missing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !missing || !missing && row.publicID != publicID {
		return OperationSnapshot{}, ErrUnavailable
	}
	if err := r.scope.RecheckRead(ctx, tx, installation); err != nil {
		return OperationSnapshot{}, scopeReadFailure(err)
	}
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		return OperationSnapshot{}, ErrUnavailable
	}
	if missing {
		return OperationSnapshot{}, ErrNotFound
	}
	return row, nil
}

type operationScanner interface{ Scan(...any) error }

func scanOperation(scanner operationScanner, installation string) (OperationSnapshot, error) {
	return scanOperationWithID(scanner, installation, nil)
}

func scanOperationWithID(scanner operationScanner, installation string, id *uint64) (OperationSnapshot, error) {
	var row OperationSnapshot
	var schemaVersion string
	targets := []any{
		&schemaVersion, &row.publicID, &row.installationID, &row.operationType, &row.targetType,
		&row.targetPublicID, &row.actorType, &row.actorID, &row.endpoint, &row.idempotencyKey,
		&row.requestHash, &row.status, &row.resultResourcePublicID, &row.resultConfigVersion,
		&row.retryable, &row.failureCategory, &row.httpStatus, &row.rowVersion, &row.deadlineAt,
		&row.startedAt, &row.finishedAt, &row.createdAt, &row.updatedAt,
	}
	if id != nil {
		targets = append([]any{id}, targets...)
	}
	err := scanner.Scan(targets...)
	if err != nil {
		return OperationSnapshot{}, err
	}
	if schemaVersion != "system-backup-operation.v1" || !validOperationSnapshot(row, installation) {
		return OperationSnapshot{}, ErrUnavailable
	}
	return row, nil
}

func operationPublicID(value string) bool { return prefixedOperationUUID(value, "sop_") }

func prefixedOperationUUID(value, prefix string) bool {
	return len(value) == len(prefix)+36 && strings.HasPrefix(value, prefix) && taskUUID.MatchString(value[len(prefix):])
}

func validOperationSnapshot(row OperationSnapshot, installation string) bool {
	if row.installationID != installation || !operationPublicID(row.publicID) ||
		!operationTypes[row.operationType] || !operationStatuses[row.status] ||
		!operationTargetID(row.targetType, row.targetPublicID, installation) ||
		row.actorType != "admin" && row.actorType != "system" ||
		row.actorType == "admin" && !operationActorID.MatchString(row.actorID) ||
		row.actorType == "system" && row.actorID != "system:controller" ||
		!operationEndpoint.MatchString(row.endpoint) ||
		len(row.idempotencyKey) < 16 || len(row.idempotencyKey) > 128 || !taskToken.MatchString(row.idempotencyKey) ||
		!taskHash.MatchString(row.requestHash) ||
		row.rowVersion == 0 || row.rowVersion > maxJSONSafeInteger ||
		!operationFailureCategory(row.failureCategory) || !operationStatusFacts(row) ||
		row.createdAt.IsZero() || row.updatedAt.Before(row.createdAt) || !row.deadlineAt.After(row.createdAt) ||
		row.startedAt.Valid && row.startedAt.Time.Before(row.createdAt) ||
		row.finishedAt.Valid && row.finishedAt.Time.Before(row.createdAt) ||
		row.finishedAt.Valid && row.startedAt.Valid && row.finishedAt.Time.Before(row.startedAt.Time) {
		return false
	}
	return true
}

func operationTargetID(kind, id, installation string) bool {
	if prefix, ok := operationTargetPrefixes[kind]; ok {
		return prefixedOperationUUID(id, prefix)
	}
	if kind == "system" {
		return id == installation
	}
	return kind == "matrix" && (id == "k8s-cluster" || id == "k3s-cluster" ||
		id == "k8s-single-node" || id == "k3s-single-node")
}

func operationFailureCategory(category string) bool {
	for _, allowed := range systembackupcontract.FailureCategories {
		if category == allowed {
			return true
		}
	}
	return false
}

func operationStatusFacts(row OperationSnapshot) bool {
	// Admission is a committed synchronous fact, not a download-result audit.
	// Evidence targets are reserved for this exact type and endpoint.
	if row.operationType == "evidence_download_admission" || row.targetType == "evidence" {
		actor, err := strconv.ParseInt(row.actorID, 10, 32)
		return row.operationType == "evidence_download_admission" && row.targetType == "evidence" &&
			row.endpoint == "getSystemBackupEvidence" && row.actorType == "admin" && err == nil && actor > 0 && strconv.FormatInt(actor, 10) == row.actorID &&
			row.status == "succeeded" && !row.retryable && row.failureCategory == "none" &&
			row.httpStatus.Valid && row.httpStatus.Int64 == 200 && !row.resultResourcePublicID.Valid && !row.resultConfigVersion.Valid &&
			row.startedAt.Valid && row.finishedAt.Valid && row.createdAt.Equal(row.startedAt.Time) &&
			row.createdAt.Equal(row.finishedAt.Time) && row.createdAt.Equal(row.updatedAt)
	}
	terminal := row.status == "succeeded" || row.status == "failed"
	if row.status == "pending" && (row.startedAt.Valid || row.finishedAt.Valid) ||
		row.status == "running" && (!row.startedAt.Valid || row.finishedAt.Valid) ||
		terminal && !row.finishedAt.Valid ||
		!terminal && row.httpStatus.Valid ||
		row.httpStatus.Valid && (row.httpStatus.Int64 < 100 || row.httpStatus.Int64 > 599) ||
		row.status != "failed" && (row.failureCategory != "none" || row.retryable) ||
		row.status == "failed" && row.failureCategory == "none" {
		return false
	}
	if synchronousOperationTypes[row.operationType] && !terminal {
		return false
	}
	if row.status != "succeeded" || row.operationType != "config_update" {
		if row.resultConfigVersion.Valid {
			return false
		}
	} else if !row.resultConfigVersion.Valid || row.resultConfigVersion.Int64 < 1 ||
		uint64(row.resultConfigVersion.Int64) > maxJSONSafeInteger {
		return false
	}
	if row.status == "succeeded" {
		if prefix, needsResource := operationResultPrefixes[row.operationType]; needsResource {
			return row.resultResourcePublicID.Valid && prefixedOperationUUID(row.resultResourcePublicID.String, prefix)
		}
	}
	return !row.resultResourcePublicID.Valid
}
