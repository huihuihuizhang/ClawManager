package install

import (
	"context"
	"database/sql"
	"time"

	adapter "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

type OriginalCoverageSQLTableName struct{ Table, Engine string }
type OriginalCoverageSQLTableInventory struct {
	Version, InstallationID, State string
	Database                       reg.DatabaseIdentity
	ObservedAt                     time.Time
	Tables                         []OriginalCoverageSQLTableName
}

// Actual schema names are retained even when the strict ORIGINAL census later
// refuses an unknown legacy table. This diagnostic never classifies/ignores
// that table, hashes an empty row set or changes sqlCensusSources' allowlist.
func (i *Installer) InspectOriginalSQLCoverageTables(ctx context.Context, password []byte, enrollment EnrollmentPin, definitionFile, definitionSHA string) (OriginalCoverageSQLTableInventory, error) {
	zero := OriginalCoverageSQLTableInventory{}
	if i.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, definitionFile, definitionSHA) != nil {
		return zero, ErrInstall
	}
	result := OriginalCoverageSQLTableInventory{Version: "original-backup-sql-source-table-inventory.v1", InstallationID: i.plan.Target.InstallationID, State: "unclassified_unadmitted_original_table_names_only", Tables: []OriginalCoverageSQLTableName{}}
	if i.db.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&result.Database.ServerUUID, &result.Database.Database, &result.ObservedAt) != nil || result.Database.ServerUUID != i.plan.Target.ServerUUID || result.Database.Database != i.plan.Target.Database {
		return zero, ErrInstall
	}
	rows, e := i.db.QueryContext(ctx, `SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND (LEFT(TABLE_NAME,13)='system_backup' OR TABLE_NAME='system_team_data_backup_jobs') ORDER BY TABLE_NAME`)
	if e != nil {
		return zero, ErrInstall
	}
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		var engine sql.NullString
		if rows.Scan(&name, &engine) != nil || name == "" || seen[name] || len(result.Tables) >= 256 {
			rows.Close()
			return zero, ErrInstall
		}
		seen[name] = true
		result.Tables = append(result.Tables, OriginalCoverageSQLTableName{Table: name, Engine: engine.String})
	}
	cursorErr := rows.Err()
	extra := rows.NextResultSet()
	closeErr := rows.Close()
	if cursorErr != nil || extra || closeErr != nil || ctx.Err() != nil {
		return zero, ErrInstall
	}
	return result, nil
}

// Read-only original operator authentication for source collection. Unlike
// initial permission issuance, collection does NOT require grant/head names
// absent and cannot create/import/sign any authority or adopted coverage.
// The original bounded context, local admin, immutable enrollment and real
// installer SQL/Kubernetes subjects remain mandatory for every source phase.
func (i *Installer) AuthenticateOriginalCoverageCensus(ctx context.Context, password []byte, enrollment EnrollmentPin, definitionFile, definitionSHA string) error {
	if i == nil {
		return ErrInstall
	}
	raw, e := ReadSourceMaterialFile(definitionFile)
	if e != nil {
		return ErrInstall
	}
	definition, e := DecodeMinIOPermissionDefinition(raw, definitionSHA)
	if e != nil || definition.Grant.Installation != i.plan.Target.InstallationID || definition.Grant.Namespace != i.plan.Target.Namespace || definition.Grant.NamespaceUID != i.plan.Target.NamespaceUID {
		return ErrInstall
	}
	operator, e := i.authenticate(ctx, password)
	if e != nil || operator.authority(ctx, enrollment) != nil {
		return ErrInstall
	}
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: false, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	_, e = operator.lockAdmin(ctx, tx)
	rollbackErr := tx.Rollback()
	if e != nil || rollbackErr != nil {
		return ErrInstall
	}
	// SQL locks are released BEFORE the final Kubernetes/enrollment recheck.
	// Authenticate again after scope/enrollment reads. No source observation or
	// success flag can replace the actual original account/password identity.
	if operator.authority(ctx, enrollment) != nil || !operator.live(ctx) {
		return ErrInstall
	}
	again, e := ReadSourceMaterialFile(definitionFile)
	if e != nil || hash(again) != definitionSHA {
		return ErrInstall
	}
	return nil
}

func (i *Installer) ObserveOriginalSQLCoverageCensus(ctx context.Context, password []byte, enrollment EnrollmentPin, definitionFile, definitionSHA string) (*adapter.UnadmittedSQLCoverageCensus, error) {
	if i.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, definitionFile, definitionSHA) != nil {
		return nil, ErrInstall
	}
	census, e := adapter.NewSQLCoverageCensus(i.db, reg.DatabaseIdentity{ServerUUID: i.plan.Target.ServerUUID, Database: i.plan.Target.Database}, i.plan.Target.InstallationID)
	if e != nil {
		return nil, ErrInstall
	}
	observed, e := census.Observe(ctx)
	if e != nil {
		return nil, e
	}
	if i.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, definitionFile, definitionSHA) != nil {
		return nil, ErrInstall
	}
	return observed, nil
}
