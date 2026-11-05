package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
)

// Explicit owner-selected profile only. SQL privilege is not MinIO consent;
// the dedicated signed owner contract must still authorize each actual read.
const MinIOMetadataReadProfile = "public-runtime-c1-minio-metadata-read.v1"

var minioMetadataTables = []string{"system_backup_minio_owner_heads", "system_backup_minio_owner_grants", "system_backup_minio_owner_refs"}
var minioActorColumns = []string{"id", "username", "role", "is_active", "auth_provider"}
var minioActorGrant = regexp.MustCompile(`^GRANT SELECT [(]([^)]+)[)] ON ` + "`" + `([A-Za-z0-9_]+)` + "`" + `[.]` + "`users`" + ` TO .+$`)

func minioMetadataReadTableGrants(runtime, permits, publication bool) map[string][]string {
	out := controlEvidenceTableGrants(runtime, permits, publication)
	for _, table := range minioMetadataTables {
		out[table] = []string{"SELECT"}
	}
	return out
}

func MinIOMetadataReadGrantSQL(schema, user, host string, allowAnyHost, runtime, permits, publication bool) ([]string, error) {
	grants, err := controllerGrantSQL(schema, user, host, allowAnyHost, minioMetadataReadTableGrants(runtime, permits, publication))
	if err != nil {
		return nil, err
	}
	// Keep the quoting/account validation from the actual table generator.
	for _, column := range minioActorColumns {
		statement, err := controllerGrantSQL(schema, user, host, allowAnyHost, map[string][]string{"users": {"SELECT (`" + column + "`)"}})
		if err != nil {
			return nil, err
		}
		grants = append(grants, statement...)
	}
	return grants, nil
}

func ValidateMinIOMetadataReadGrants(schema string, statements []string, runtime, permits, publication bool) error {
	tables := make([]string, 0, len(statements))
	columns := map[string]bool{}
	allowed := map[string]bool{}
	for _, column := range minioActorColumns {
		allowed[column] = true
	}
	for _, statement := range statements {
		match := minioActorGrant.FindStringSubmatch(statement)
		if match == nil {
			tables = append(tables, statement)
			continue
		}
		if match[2] != schema || strings.Contains(statement, " WITH GRANT OPTION") || strings.Contains(statement, " WITH ADMIN OPTION") {
			return errors.New("invalid original MinIO actor column grant")
		}
		for _, raw := range strings.Split(match[1], ",") {
			column := strings.TrimSpace(raw)
			if len(column) < 3 || column[0] != '`' || column[len(column)-1] != '`' {
				return errors.New("invalid original MinIO actor column")
			}
			column = column[1 : len(column)-1]
			if !allowed[column] {
				return errors.New("unapproved original MinIO actor column")
			}
			columns[column] = true
		}
	}
	if len(columns) != len(allowed) {
		return errors.New("missing original MinIO actor column SELECT")
	}
	return validateControllerGrants(schema, tables, minioMetadataReadTableGrants(runtime, permits, publication))
}

type SQLMinIOMetadataReadGrantProbe struct {
	DB                                    *sql.DB
	Schema, User                          string
	Runtime, ProviderPermits, Publication bool
}

func (p SQLMinIOMetadataReadGrantProbe) Check(ctx context.Context) (result error) {
	if ctx == nil || ctx.Err() != nil || p.DB == nil || !controllerSchemaName.MatchString(p.Schema) || strings.TrimSpace(p.User) == "" {
		return errors.New("invalid original MinIO metadata SQL probe")
	}
	conn, err := p.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, conn.Close()) }()
	var account, role string
	if err = conn.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&account); err != nil {
		return err
	}
	separator := strings.LastIndexByte(account, '@')
	if separator < 1 || account[:separator] != p.User || separator == len(account)-1 {
		return errors.New("original MinIO metadata SQL account differs")
	}
	if err = conn.QueryRowContext(ctx, "SELECT CURRENT_ROLE()").Scan(&role); err != nil {
		return err
	}
	if !strings.EqualFold(role, "NONE") {
		return errors.New("original MinIO metadata SQL roles forbidden")
	}
	rows, err := conn.QueryContext(ctx, "SHOW GRANTS")
	if err != nil {
		return err
	}
	var statements []string
	for rows.Next() {
		var statement string
		if err = rows.Scan(&statement); err != nil {
			_ = rows.Close()
			return err
		}
		statements = append(statements, statement)
	}
	if err = errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	return ValidateMinIOMetadataReadGrants(p.Schema, statements, p.Runtime, p.ProviderPermits, p.Publication)
}
