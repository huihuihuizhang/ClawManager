package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sort"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/schemaobjects"
)

var errFixtureCensusCatalog = errors.New("owned fixture full catalog/business/control census differs")

// The privileged reader is the already-owned disposable fixture pool, never
// a production source role. It checks the real complete migrated catalog to
// EOF instead of assuming a historical number of control tables exists.
func checkOriginalFixtureCensusCatalog(ctx context.Context, db *sql.DB, census domain.BusinessSchemaCensusObjects, schema []string) error {
	rows, err := db.QueryContext(ctx, `SELECT TABLE_NAME,TABLE_TYPE,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME`)
	if err != nil {
		return errFixtureCensusCatalog
	}
	defer rows.Close()
	var catalog []string
	for rows.Next() {
		var name, kind, engine string
		if rows.Scan(&name, &kind, &engine) != nil || kind != "BASE TABLE" || engine != "InnoDB" || len(catalog) >= 1000 || ctx.Err() != nil {
			return errFixtureCensusCatalog
		}
		catalog = append(catalog, name)
	}
	if rows.Err() != nil || rows.Close() != nil || ctx.Err() != nil {
		return errFixtureCensusCatalog
	}
	return originalFixtureCensusCatalogParity(census, schema, catalog)
}

func originalFixtureCensusCatalogParity(census domain.BusinessSchemaCensusObjects, schema, catalog []string) error {
	business, control := map[string]bool{}, map[string]bool{}
	for _, name := range domain.BusinessCaptureTables() {
		business[name] = true
	}
	for _, name := range schemaobjects.ExcludedControlTables() {
		if business[name] {
			return errFixtureCensusCatalog
		}
		control[name] = true
	}
	expected := domain.BusinessSchemaCensusObjects{Business: []string{}, Control: []string{}}
	seen := map[string]bool{}
	for _, name := range catalog {
		if name == "" || seen[name] || !business[name] && !control[name] {
			return errFixtureCensusCatalog
		}
		seen[name] = true
		if business[name] {
			expected.Business = append(expected.Business, name)
		} else {
			expected.Control = append(expected.Control, name)
		}
	}
	sort.Strings(expected.Business)
	sort.Strings(expected.Control)
	// Exact named sets, not counts: no control object may become captured
	// business data, and no missing/unknown/duplicated object is accepted.
	if !reflect.DeepEqual(census, expected) || !reflect.DeepEqual(schema, expected.Business) {
		return errFixtureCensusCatalog
	}
	return nil
}

func TestOriginalFixtureCensusParityTracksActualCatalogWithoutCapturingControl(t *testing.T) {
	business := domain.BusinessCaptureTables()
	control := []string{"schema_migrations", "system_backup_installation_owner_grants", "system_backup_installation_owner_heads", "system_backup_signing_resource_grants", "system_backup_signing_resource_heads"}
	sort.Strings(control)
	for _, fault := range []string{"current", "new-control-omitted", "control-captured", "missing-business", "unknown-table", "duplicate-table", "business-census-missing"} {
		t.Run(fault, func(t *testing.T) {
			census := domain.BusinessSchemaCensusObjects{Business: append([]string{}, business...), Control: append([]string{}, control...)}
			schema := append([]string{}, business...)
			catalog := append(append([]string{}, business...), control...)
			switch fault {
			case "new-control-omitted":
				census.Control = census.Control[:len(census.Control)-1]
			case "control-captured":
				schema = append(schema, control[0])
			case "missing-business":
				catalog = catalog[1:]
			case "unknown-table":
				catalog = append(catalog, "unknown_future_source")
			case "duplicate-table":
				catalog = append(catalog, business[0])
			case "business-census-missing":
				census.Business = census.Business[1:]
			}
			if err := originalFixtureCensusCatalogParity(census, schema, catalog); (err == nil) != (fault == "current") {
				t.Fatal("full original catalog classification accepted drift or rejected current control additions", fault, err)
			}
		})
	}
}
