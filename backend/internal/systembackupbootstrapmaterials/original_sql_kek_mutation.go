package systembackupbootstrapmaterials

import (
	"database/sql"

	kek "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
)

// Select the actual config-mutation preparation from the SAME independently
// installed original source document. No bootstrap grant, DB/credential read,
// provider call, physical witness or enabled config is created by this loader.
func LoadOriginalSQLMutationKEKPreparation(sourceFile, sourceSHA string) (*kek.SQLMutationKEKPreparation, error) {
	original, err := LoadOriginalSQLBootstrapKEKPreparation(sourceFile, sourceSHA)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	cfg, err := original.OriginalConfiguration()
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return kek.NewSQLMutationKEKPreparation(cfg)
}

// Use the returned SAME object in resolverSources.References["kek"] and
// ConfigMutationService.KEK. Missing either link refuses the actual attempt.
func LoadOriginalSQLMutationKEKResource(db *sql.DB, sourceFile, sourceSHA string) (*kek.SQLMutationKEKResource, error) {
	original, err := LoadOriginalSQLBootstrapKEKPreparation(sourceFile, sourceSHA)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	cfg, err := original.OriginalConfiguration()
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return kek.NewSQLMutationKEKResource(db, cfg)
}
