package domain

import (
	"clawreef/internal/systembackup/schemaobjects"
	"context"
	"database/sql"
	"regexp"
	"sort"
	"strings"
)

const BusinessTableSourceScope = "reviewed-business-tables.v1"

var businessTableGrant = regexp.MustCompile("^GRANT SELECT ON `([A-Za-z0-9_]+)`\\.`([A-Za-z0-9_]+)` TO (?:'[^']+'|`[^`]+`)@(?:'[^']+'|`[^`]+`)$")

// The exact same reviewed rules select every shared SQL capture table. No
// control-row SELECT, data wildcard, role or future unknown table enters this
// source capability. SHOW_ROUTINE is read-only metadata, needed to authenticate
// the ONE executed census routine body. New rules require an owner role update.
func BusinessCaptureTables() []string {
	excluded := map[string]bool{}
	for _, name := range schemaobjects.ExcludedControlTables() {
		excluded[name] = true
	}
	names := make([]string, 0, len(rules()))
	for name := range rules() {
		if !excluded[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func ValidateBusinessSourceGrants(database string, grants []string) error {
	if !identifier.MatchString(database) || len(grants) == 0 || len(grants) > 1000 {
		return ErrIsolation
	}
	allowed := map[string]bool{}
	for _, name := range BusinessCaptureTables() {
		allowed[name] = true
	}
	seen := map[string]bool{}
	census := false
	routineMetadata := false
	for _, grant := range grants {
		if strings.HasPrefix(grant, "GRANT USAGE ON *.* TO ") && !strings.Contains(grant, " WITH GRANT OPTION") {
			continue
		}
		if schemaCensusGrant(database, grant) {
			if census {
				return ErrIsolation
			}
			census = true
			continue
		}
		if regexp.MustCompile("^GRANT SHOW_ROUTINE ON \\*\\.\\* TO (?:'[^']+'|`[^`]+`)@(?:'[^']+'|`[^`]+`)$").MatchString(grant) {
			if routineMetadata {
				return ErrIsolation
			}
			routineMetadata = true
			continue
		}
		match := businessTableGrant.FindStringSubmatch(grant)
		if len(match) != 3 || match[1] != database || !allowed[match[2]] || seen[match[2]] {
			return ErrIsolation
		}
		seen[match[2]] = true
	}
	optional := map[string]bool{}
	for _, name := range schemaobjects.OptionalBusinessTables() {
		optional[name] = true
	}
	for name := range allowed {
		if !seen[name] && !optional[name] {
			return ErrIsolation
		}
	}
	if !census || !routineMetadata {
		return ErrIsolation
	}
	return nil
}

// The production finite-table path retains the same source session, one RR,
// row/capacity checks and original authorization as CaptureSourceGuarded.
func CaptureBusinessSourceGuarded(ctx context.Context, db *sql.DB, limits Limits, database, serverUUID string, authorize func(context.Context) error, census ...SchemaCensusSpec) (Snapshot, error) {
	if !identifier.MatchString(database) || serverUUID == "" || authorize == nil || len(census) != 1 || census[0].Validate() != nil {
		return Snapshot{}, ErrIsolation
	}
	return capture(ctx, db, limits, func(conn *sql.Conn) error {
		var actualDB, actualUUID, role string
		if conn.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&actualDB, &actualUUID) != nil || actualDB != database || actualUUID != serverUUID {
			return ErrIsolation
		}
		if conn.QueryRowContext(ctx, "SELECT CURRENT_ROLE()").Scan(&role) != nil || role != "NONE" {
			return ErrIsolation
		}
		rows, err := conn.QueryContext(ctx, "SHOW GRANTS FOR CURRENT_USER")
		if err != nil {
			return ErrIsolation
		}
		defer rows.Close()
		var grants []string
		for rows.Next() {
			var grant string
			if rows.Scan(&grant) != nil || len(grants) >= 1000 {
				return ErrIsolation
			}
			grants = append(grants, grant)
		}
		if rows.Err() != nil {
			return ErrIsolation
		}
		if err := ValidateBusinessSourceGrants(database, grants); err != nil {
			return err
		}
		return CheckBusinessSchemaCensus(ctx, conn, census[0])
	}, func() error { return authorize(ctx) })
}
