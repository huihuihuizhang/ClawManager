package domain

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"clawreef/internal/systembackup/schemaobjects"
)

const SchemaCensusVersion = "mysql-full-schema-census.v1"
const SchemaCensusRoutine = "system_backup_source_schema_census"

type SchemaCensusSpec struct {
	Version                   string `json:"schema_version"`
	Definer, DefinitionSHA256 string
	PartialRevokes            bool
}

func (s SchemaCensusSpec) Validate() error {
	if s.Version != SchemaCensusVersion || !regexp.MustCompile(`^[A-Za-z0-9_]+@[A-Za-z0-9_.:%-]+$`).MatchString(s.Definer) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(s.DefinitionSHA256) {
		return ErrIsolation
	}
	return nil
}

func SchemaCensusPolicySHA256() string {
	raw, _ := json.Marshal(struct {
		Version, View string
		Excluded      []string
	}{SchemaCensusVersion, SchemaCensusRoutine, schemaobjects.ExcludedControlTables()})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// The source owner installs this READS SQL DATA routine, never the collector.
// MySQL views preserve invoker information_schema filtering, so the census
// requires a routine's separate security context. Only metadata is projected.
func SchemaCensusProjection(database, definer string, partialRevokes bool) (string, error) {
	if !identifier.MatchString(database) || !regexp.MustCompile(`^[A-Za-z0-9_]+@[A-Za-z0-9_.:%-]+$`).MatchString(definer) {
		return "", ErrIsolation
	}
	parts := strings.SplitN(definer, "@", 2)
	grantSchema := database
	if !partialRevokes {
		grantSchema = strings.ReplaceAll(database, "_", `\_`)
	}
	grantee := "CONCAT(CHAR(39),'" + parts[0] + "',CHAR(39),'@',CHAR(39),'" + parts[1] + "',CHAR(39))"
	capability := "CURRENT_USER()='" + definer + "' AND CURRENT_ROLE()='NONE' AND (SELECT COUNT(DISTINCT PRIVILEGE_TYPE) FROM information_schema.SCHEMA_PRIVILEGES WHERE BINARY TABLE_SCHEMA=0x" + hex.EncodeToString([]byte(grantSchema)) + " AND GRANTEE=" + grantee + " AND PRIVILEGE_TYPE IN ('SELECT','SHOW VIEW','TRIGGER','EVENT'))=4 AND (SELECT COUNT(*) FROM mysql.global_grants WHERE USER='" + parts[0] + "' AND HOST='" + parts[1] + "' AND PRIV='SHOW_ROUTINE')=1 AND NOT EXISTS(SELECT 1 FROM mysql.role_edges WHERE TO_USER='" + parts[0] + "' AND TO_HOST='" + parts[1] + "')"
	return "SELECT '__census_capability__' AS object_name,IF(" + capability + ",'CENSUS_READY','CENSUS_INCOMPLETE') AS object_type,'" + SchemaCensusVersion + "' AS engine UNION ALL SELECT TABLE_NAME,TABLE_TYPE,COALESCE(ENGINE,'') FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "' UNION ALL SELECT TRIGGER_NAME,'TRIGGER','' FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='" + database + "' UNION ALL SELECT ROUTINE_NAME,ROUTINE_TYPE,'' FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='" + database + "' UNION ALL SELECT EVENT_NAME,'EVENT','' FROM information_schema.EVENTS WHERE EVENT_SCHEMA='" + database + "'", nil
}

func schemaCensusGrant(database, grant string) bool {
	pattern := regexp.MustCompile("^GRANT EXECUTE ON PROCEDURE `" + regexp.QuoteMeta(database) + "`\\.`" + SchemaCensusRoutine + "` TO (?:'[^']+'|`[^`]+`)@(?:'[^']+'|`[^`]+`)$")
	return pattern.MatchString(grant)
}

type schemaCensusReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func CheckBusinessSchemaCensus(ctx context.Context, q schemaCensusReader, spec SchemaCensusSpec) error {
	if ctx == nil || ctx.Err() != nil || q == nil || spec.Validate() != nil {
		return ErrIsolation
	}
	var database string
	if q.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database) != nil {
		return ErrIsolation
	}
	var partialRevokes bool
	if q.QueryRowContext(ctx, "SELECT @@GLOBAL.partial_revokes").Scan(&partialRevokes) != nil || partialRevokes != spec.PartialRevokes {
		return ErrIsolation
	}
	projection, err := SchemaCensusProjection(database, spec.Definer, partialRevokes)
	if err != nil {
		return ErrIsolation
	}
	expectedDefinition := "BEGIN " + projection + "; END"
	identity := func() error {
		var definition, definer, security, access string
		if q.QueryRowContext(ctx, "SELECT ROUTINE_DEFINITION,DEFINER,SECURITY_TYPE,SQL_DATA_ACCESS FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME=? AND ROUTINE_TYPE='PROCEDURE'", SchemaCensusRoutine).Scan(&definition, &definer, &security, &access) != nil {
			return ErrIsolation
		}
		h := sha256.Sum256([]byte(definition))
		if hex.EncodeToString(h[:]) != spec.DefinitionSHA256 || definition != expectedDefinition || definer != spec.Definer || security != "DEFINER" || access != "READS SQL DATA" {
			return ErrIsolation
		}
		return nil
	}
	if identity() != nil {
		return ErrIsolation
	}
	rows, err := q.QueryContext(ctx, "CALL `"+SchemaCensusRoutine+"`()")
	if err != nil {
		return ErrIsolation
	}
	excluded := map[string]bool{}
	for _, name := range schemaobjects.ExcludedControlTables() {
		excluded[name] = true
	}
	business := map[string]bool{}
	for _, name := range BusinessCaptureTables() {
		business[name] = true
	}
	seen := map[string]bool{}
	censusFound := false
	capabilityFound := false
	count := 0
	for rows.Next() {
		var name, kind, engine string
		if rows.Scan(&name, &kind, &engine) != nil || ctx.Err() != nil || count >= 1000 {
			rows.Close()
			return ErrSchema
		}
		count++
		if name == "__census_capability__" && kind == "CENSUS_READY" && engine == SchemaCensusVersion && !capabilityFound {
			capabilityFound = true
			continue
		}
		if name == SchemaCensusRoutine && kind == "PROCEDURE" && !censusFound {
			censusFound = true
			continue
		}
		if kind != "BASE TABLE" || engine != "InnoDB" || seen[name] || (!business[name] && !excluded[name]) {
			rows.Close()
			return ErrSchema
		}
		seen[name] = true
	}
	err = rows.Err()
	for err == nil && rows.NextResultSet() {
		columns, e := rows.Columns()
		if e != nil || len(columns) != 0 {
			rows.Close()
			return ErrSchema
		}
	}
	if rows.Err() != nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil || !censusFound || !capabilityFound || identity() != nil {
		return ErrIsolation
	}
	for name := range business {
		if !seen[name] {
			return ErrSchema
		}
	}
	return ctx.Err()
}
