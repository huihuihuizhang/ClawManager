package systembackupsecurity

import (
	"context"
	"database/sql"
	"reflect"

	reg "clawreef/internal/systembackupkekregistry"
)

func verifyCommittedKEK(ctx context.Context, db *sql.DB, installation, operation string, prepared reg.PreparedAdmission) error {
	b, o, err := (reg.SQLStore{}).ReadCommitted(ctx, db, installation, operation)
	if err != nil || candidateAuthorityNil(prepared) || !reflect.DeepEqual(b, prepared.Binding()) || o != prepared.Observation() {
		return ErrRegistrationCommitUnknown
	}
	return nil
}

// BootstrapKEKPreparation is a trusted deployment composition of C's original
// source and A's validator. It runs before the original transaction takes any
// locks and must return their frozen, independently authenticated admission.
// No request or config object may implement this as its own authority.
type BootstrapKEKPreparation interface {
	PrepareBootstrapKEK(context.Context, *sql.DB, OfflineBootstrapGrant, BootstrapConfig) (reg.PreparedAdmission, error)
}

// stageBootstrapKEK only receives the original transaction's SQL capability.
// The caller owns Commit/Rollback and must call Recheck before that Commit.
func stageBootstrapKEK(ctx context.Context, tx reg.SQLWriteView, installation, operation string, prepared reg.PreparedAdmission, requireExisting bool) (*reg.Bound, error) {
	if requireExisting {
		var existing string
		if err := tx.QueryRowContext(ctx, `SELECT operation_id FROM system_backup_v2_kek_admissions WHERE installation_id=? AND operation_id=? FOR SHARE`, installation, operation).Scan(&existing); err != nil || existing != operation {
			return nil, ErrRegistrationUnavailable
		}
	}
	bound, _, err := (reg.SQLStore{}).Bind(ctx, tx, installation)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	if err = bound.StageAdmission(ctx, operation, 1, prepared); err != nil {
		return nil, ErrRegistrationUnavailable
	}
	return bound, nil
}
