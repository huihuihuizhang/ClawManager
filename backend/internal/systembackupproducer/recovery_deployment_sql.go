package systembackupproducer

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"time"
)

// recoveryDeploymentRow is the D-owned L1a SQL projection. It is deliberately
// private: reading or writing this row alone never grants recovery authority.
// The caller must hold the L0 installation parent lock before Lock, and must
// update the exact L2 revocation row in the same transaction before commit.
type recoveryDeploymentRow struct {
	installation    string
	workload        []byte
	issuer          []byte
	subject         []byte
	managerIssuer   []byte
	actor           []byte
	admission       []byte
	clientCA        []byte
	certificate     []byte
	statProfile     []byte
	enabled         bool
	epoch           int64
	authorizedUntil time.Time
	version         int64
}

const recoveryDeploymentLockSQL = `SELECT origin_installation_id,workload_identity_hash,issuer_identity_hash,subject_hash,management_issuer_identity_hash,actor_identity_hash,admission_hash,client_ca_sha256,certificate_sha256,stat_profile_hash,enabled,deployment_epoch,authorized_until,row_version FROM system_backup_v2_recovery_deployments WHERE scope_key=? FOR UPDATE`
const recoveryDeploymentReadSQL = `SELECT origin_installation_id,workload_identity_hash,issuer_identity_hash,subject_hash,management_issuer_identity_hash,actor_identity_hash,admission_hash,client_ca_sha256,certificate_sha256,stat_profile_hash,enabled,deployment_epoch,authorized_until,row_version FROM system_backup_v2_recovery_deployments WHERE scope_key=?`
const recoveryDeploymentInsertSQL = `INSERT INTO system_backup_v2_recovery_deployments (scope_key,origin_installation_id,workload_identity_hash,issuer_identity_hash,subject_hash,management_issuer_identity_hash,actor_identity_hash,admission_hash,client_ca_sha256,certificate_sha256,stat_profile_hash,enabled,deployment_epoch,authorized_until,row_version,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))`
const recoveryDeploymentUpdateSQL = `UPDATE system_backup_v2_recovery_deployments SET workload_identity_hash=?,issuer_identity_hash=?,subject_hash=?,management_issuer_identity_hash=?,actor_identity_hash=?,admission_hash=?,client_ca_sha256=?,certificate_sha256=?,stat_profile_hash=?,enabled=?,deployment_epoch=?,authorized_until=?,row_version=?,updated_at=UTC_TIMESTAMP(6) WHERE scope_key=? AND origin_installation_id=? AND workload_identity_hash=? AND deployment_epoch=? AND row_version=?`

func (r recoveryDeploymentRow) valid(scope Scope) bool {
	if r.installation != string(scope.Installation) || r.epoch < 1 || r.version < 1 || !validDBTime(r.authorizedUntil) {
		return false
	}
	for _, digest := range [][]byte{r.workload, r.issuer, r.subject, r.managerIssuer, r.actor, r.admission, r.clientCA, r.certificate, r.statProfile} {
		if len(digest) != 32 {
			return false
		}
	}
	return true
}

func readRecoveryDeployment(ctx context.Context, tx ReadSQL, scope Scope, lock bool) (recoveryDeploymentRow, bool, error) {
	key, err := recoveryScopeKey(scope)
	if err != nil {
		return recoveryDeploymentRow{}, false, err
	}
	query := recoveryDeploymentReadSQL
	if lock {
		query = recoveryDeploymentLockSQL
	}
	var row recoveryDeploymentRow
	err = tx.QueryRowContext(ctx, query, key).Scan(&row.installation, &row.workload, &row.issuer,
		&row.subject, &row.managerIssuer, &row.actor, &row.admission, &row.clientCA,
		&row.certificate, &row.statProfile, &row.enabled, &row.epoch, &row.authorizedUntil, &row.version)
	if errors.Is(err, sql.ErrNoRows) {
		return recoveryDeploymentRow{}, false, nil
	}
	if err != nil {
		return recoveryDeploymentRow{}, false, ErrUnavailable
	}
	if !row.valid(scope) {
		return recoveryDeploymentRow{}, false, ErrGuardRequired
	}
	return row, true, nil
}

// stageRecoveryDeployment performs one exact L1a CAS. The expected row must
// come from readRecoveryDeployment under L0/L1a locks, and next must come from
// a separately authenticated manager admission. This helper never commits.
func stageRecoveryDeployment(ctx context.Context, tx *Transaction, scope Scope, current *recoveryDeploymentRow, next recoveryDeploymentRow) error {
	if tx == nil || !next.valid(scope) {
		return ErrGuardRequired
	}
	key, err := recoveryScopeKey(scope)
	if err != nil {
		return err
	}
	if current == nil {
		if next.epoch != 1 || next.version != 1 {
			return ErrInvalid
		}
		return tx.CAS(ctx, recoveryDeploymentInsertSQL, key, next.installation, next.workload,
			next.issuer, next.subject, next.managerIssuer, next.actor, next.admission,
			next.clientCA, next.certificate, next.statProfile, next.enabled, next.epoch,
			next.authorizedUntil, next.version)
	}
	if !current.valid(scope) || current.epoch == 1<<63-1 || current.version == 1<<63-1 ||
		next.epoch != current.epoch+1 || next.version != current.version+1 {
		return ErrInvalid
	}
	return tx.CAS(ctx, recoveryDeploymentUpdateSQL, next.workload, next.issuer, next.subject,
		next.managerIssuer, next.actor, next.admission, next.clientCA, next.certificate,
		next.statProfile, next.enabled, next.epoch, next.authorizedUntil, next.version,
		key, current.installation, current.workload, current.epoch, current.version)
}

// recheckRecoveryDeployment only rereads the row acquired above. It must run
// after both the L1a and L2 mutations and result audit, inside FinalGuard.
func recheckRecoveryDeployment(ctx context.Context, tx ReadSQL, scope Scope, want recoveryDeploymentRow) error {
	got, found, err := readRecoveryDeployment(ctx, tx, scope, false)
	if err != nil || !found || !reflect.DeepEqual(got, want) {
		return ErrGuardRequired
	}
	return nil
}
