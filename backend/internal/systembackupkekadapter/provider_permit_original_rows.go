package systembackupkekadapter

import (
	"context"
	"database/sql"
	"reflect"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	kms "clawreef/internal/systembackupkms"
)

// Created only after the complete OriginalCapturePlan.RecheckTx succeeds in
// StageOriginal. This is a private, request/transaction/owner-bound lock fact;
// it contains neither row data nor an authorization result. Each read fetches
// all original fields CURRENT again, including this transaction's own writes.
type heldProviderOriginalRows struct {
	ctx       context.Context
	tx        *sql.Tx
	issue     *PreparedProviderPermitIssue
	guard     *c.ExecutionAuthorityGuard
	plan      *c.OriginalCapturePlan
	authority d.Authority
}

// The plan row is ALREADY locked by the complete original-plan check. The
// scalar subquery cannot introduce an earlier new lock regardless of optimizer
// order. Its explicit FOR SHARE keeps it a current read under REPEATABLE READ.
// The outer Job predicate is identical to the original standalone query.
const heldProviderOriginalRowsQuery = `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),
(SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind='plan' FOR SHARE),
key_use_json,request_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND revoked=FALSE AND stopped_at IS NULL AND lifecycle='ready' FOR SHARE`

func (r *heldProviderOriginalRows) read(ctx context.Context, tx *sql.Tx, p *PreparedProviderPermitIssue, guard *c.ExecutionAuthorityGuard) ([]byte, error) {
	if r == nil || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != r.ctx || ctx.Err() != nil || tx == nil || tx != r.tx || p == nil || p != r.issue || p.issuer == nil || guard == nil || guard != r.guard || p.original == nil || p.original != r.plan || p.scope.Input.Authority != r.authority {
		return nil, kms.ErrPermission
	}
	a, j := r.authority, p.scope.Job
	var account, server, database, planHash, specHash string
	var keyUse []byte
	err := tx.QueryRowContext(ctx, heldProviderOriginalRowsQuery, a.InstallationID, a.TaskPublicID, a.AttemptNo, a.TaskPublicID, a.AttemptNo, j.Namespace, j.Name, j.UID).Scan(&account, &server, &database, &planHash, &keyUse, &specHash)
	if err != nil || account != p.grant.DatabaseAccount || server != p.grant.Database.ServerUUID || database != p.grant.Database.Database || planHash != p.planHash || specHash != p.specHash {
		return nil, kms.ErrPermission
	}
	return keyUse, nil
}
