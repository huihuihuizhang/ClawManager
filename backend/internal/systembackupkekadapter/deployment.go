package systembackupkekadapter

import (
	"context"
	"database/sql"
	"reflect"

	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// SQLOriginalReader reads an owner-managed installation authority table. This
// table is deliberately not created or written by the config admission path.
// Its owner must fence updates under the installation KEK fence. Signed bytes
// and revocations are read again through the caller's original transaction.
type SQLOriginalReader struct{ DB *sql.DB }

const originalQuery = `SELECT signed_record,signature FROM system_backup_installation_kek_authority WHERE installation_id=? AND identity_hash=? AND registry_version=?`

func (r SQLOriginalReader) ReadOriginal(ctx context.Context, installation string, pin reg.ReferencePin) ([]byte, []byte, error) {
	if r.DB == nil {
		return nil, nil, sec.ErrRegistrationUnavailable
	}
	return readOriginal(ctx, r.DB, installation, pin)
}
func (r SQLOriginalReader) RecheckOriginal(ctx context.Context, view reg.SQLReadView, installation string, pin reg.ReferencePin) ([]byte, []byte, error) {
	var raw, sig []byte
	err := view.QueryRowContext(ctx, originalQuery+" FOR SHARE", installation, pin.IdentityHash, pin.Version).Scan(&raw, &sig)
	return raw, sig, err
}
func readOriginal(ctx context.Context, view reg.SQLReadView, installation string, pin reg.ReferencePin) ([]byte, []byte, error) {
	var raw, sig []byte
	err := view.QueryRowContext(ctx, originalQuery, installation, pin.IdentityHash, pin.Version).Scan(&raw, &sig)
	return raw, sig, err
}

// WireServices is the production composition boundary. Both services must use
// the same independently pinned original authority; missing owners fail closed.
func WireServices(bootstrap sec.ConfigBootstrapService, mutation sec.ConfigMutationService, source BootstrapAdmissionSource, mutations MutationAdmissionSource, original InstallationPreparation) (sec.ConfigBootstrapService, sec.ConfigMutationService, error) {
	if bootstrap.DB == nil || bootstrap.DB != mutation.DB || nilSource(source) || nilSource(mutations) || nilSource(original.Reader) || nilSource(original.Capabilities) || original.Now == nil || len(original.Issuer) != 32 {
		return sec.ConfigBootstrapService{}, sec.ConfigMutationService{}, sec.ErrRegistrationUnavailable
	}
	validator := KEKAdmissionValidator{Original: original, Now: original.Now}
	if reader, ok := original.Reader.(SQLOriginalReader); ok && reader.DB != bootstrap.DB {
		return sec.ConfigBootstrapService{}, sec.ConfigMutationService{}, sec.ErrRegistrationUnavailable
	}
	bootstrap.KEK = BootstrapComposition{Source: source, Validator: validator}
	mutation.KEK = MutationComposition{Source: mutations, Validator: validator}
	return bootstrap, mutation, nil
}

// VerifyCommitted is for the original owner after a successful Commit. Failure
// is an observation failure, never permission to repeat the write.
func VerifyCommitted(ctx context.Context, db *sql.DB, installation, operation string, prepared reg.PreparedAdmission) error {
	b, o, err := (reg.SQLStore{}).ReadCommitted(ctx, db, installation, operation)
	if err != nil || nilSource(prepared) || !reflect.DeepEqual(b, prepared.Binding()) || o != prepared.Observation() {
		return sec.ErrRegistrationCommitUnknown
	}
	return nil
}
