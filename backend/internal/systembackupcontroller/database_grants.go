package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Current controller runtime only. Extending the controller requires an
// explicit review of this matrix and a live positive/negative grant test.
var controllerTableGrants = map[string][]string{
	"schema_migrations":                    {"SELECT"},
	"system_backup_installation_state":     {"SELECT", "UPDATE"},
	"system_backup_configs":                {"SELECT"},
	"system_maintenance_locks":             {"SELECT", "INSERT", "UPDATE"},
	"system_backup_events":                 {"INSERT"},
	"system_backup_alert_states":           {"SELECT", "INSERT", "UPDATE"},
	"system_backup_attempts":               {"SELECT"},
	"system_backup_external_actions":       {"SELECT"},
	"system_artifact_leases":               {"SELECT"},
	"system_backups":                       {"SELECT", "UPDATE"},
	"system_restore_drills":                {"SELECT", "UPDATE"},
	"system_backup_preflights":             {"SELECT", "UPDATE"},
	"system_backup_artifact_verifications": {"SELECT", "UPDATE"},
	"system_backup_operations":             {"SELECT", "UPDATE"},
}

var (
	controllerSchemaName  = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	controllerAccountName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	controllerHostName    = regexp.MustCompile(`^[A-Za-z0-9.:-]+$`)
	controllerTableGrant  = regexp.MustCompile(`^GRANT ([A-Z, ]+) ON ` + "`" + `([A-Za-z0-9_]+)` + "`" + `\.` + "`" + `([A-Za-z0-9_]+)` + "`" + ` TO .+$`)
	controllerUsageGrant  = regexp.MustCompile(`^GRANT USAGE ON \*\.\* TO .+$`)
)

// SQLControllerGrantProbe checks direct grants reported by MySQL. It rejects
// active roles and role grants because they can hide broader inherited rights.
// SHOW GRANTS is read-only; it does not create a canary table or mutate data.
type SQLControllerGrantProbe struct {
	DB     *sql.DB
	Schema string
	User   string
}

// ControllerGrantSQL renders the exact direct table grants checked by the
// runtime probe. It never creates a user, sets a password, or executes SQL.
// A wildcard host must be acknowledged explicitly by the operator.
func ControllerGrantSQL(schema, user, host string, allowAnyHost bool) ([]string, error) {
	if !controllerSchemaName.MatchString(schema) || !controllerAccountName.MatchString(user) {
		return nil, errors.New("invalid controller grant schema or user")
	}
	if err := ValidateControllerDatabaseUser(user); err != nil {
		return nil, err
	}
	if host == "%" {
		if !allowAnyHost {
			return nil, errors.New("wildcard controller grant host requires explicit acknowledgement")
		}
	} else if !controllerHostName.MatchString(host) {
		return nil, errors.New("invalid controller grant host")
	}
	tables := make([]string, 0, len(controllerTableGrants))
	for table := range controllerTableGrants {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	statements := make([]string, 0, len(tables))
	for _, table := range tables {
		statements = append(statements, fmt.Sprintf("GRANT %s ON `%s`.`%s` TO '%s'@'%s';", strings.Join(controllerTableGrants[table], ", "), schema, table, user, host))
	}
	return statements, nil
}

func (p SQLControllerGrantProbe) Check(ctx context.Context) (checkErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.DB == nil {
		return errors.New("nil controller grant database")
	}
	if !controllerSchemaName.MatchString(p.Schema) {
		return errors.New("invalid controller grant schema name")
	}
	if strings.TrimSpace(p.User) == "" {
		return errors.New("empty controller grant user")
	}
	conn, err := p.DB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire controller grant connection: %w", err)
	}
	defer func() {
		checkErr = errors.Join(checkErr, conn.Close())
	}()
	var effectiveUser string
	if err := conn.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&effectiveUser); err != nil {
		return fmt.Errorf("read effective controller database user: %w", err)
	}
	accountSeparator := strings.LastIndexByte(effectiveUser, '@')
	if accountSeparator < 1 || effectiveUser[:accountSeparator] != p.User || accountSeparator == len(effectiveUser)-1 {
		return errors.New("effective controller database user differs from explicit DB_USER")
	}
	var role string
	if err := conn.QueryRowContext(ctx, "SELECT CURRENT_ROLE()").Scan(&role); err != nil {
		return fmt.Errorf("read controller active role: %w", err)
	}
	if !strings.EqualFold(role, "NONE") {
		return errors.New("controller database role must be NONE")
	}
	rows, err := conn.QueryContext(ctx, "SHOW GRANTS")
	if err != nil {
		return fmt.Errorf("read controller direct grants: %w", err)
	}
	var statements []string
	for rows.Next() {
		var statement string
		if err := rows.Scan(&statement); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan controller direct grant: %w", err)
		}
		statements = append(statements, statement)
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil {
		return fmt.Errorf("iterate controller direct grants: %w", iterationErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close controller direct grants: %w", closeErr)
	}
	return ValidateControllerGrantStatements(p.Schema, statements)
}

// ValidateControllerGrantStatements accepts only exact table-level grants for
// the current D-only runtime. A grant with an unknown syntax fails closed.
func ValidateControllerGrantStatements(schema string, statements []string) error {
	if !controllerSchemaName.MatchString(schema) || len(statements) == 0 {
		return errors.New("controller grant inventory is empty or schema is invalid")
	}
	observed := make(map[string]map[string]struct{}, len(controllerTableGrants))
	for _, statement := range statements {
		if strings.Contains(statement, " WITH GRANT OPTION") || strings.Contains(statement, " WITH ADMIN OPTION") {
			return errors.New("controller database user may not delegate privileges")
		}
		if controllerUsageGrant.MatchString(statement) {
			continue
		}
		parts := controllerTableGrant.FindStringSubmatch(statement)
		if parts == nil || parts[2] != schema {
			return fmt.Errorf("controller grant is not an allowed direct table grant: %q", statement)
		}
		table, expected := parts[3], controllerTableGrants[parts[3]]
		if len(expected) == 0 {
			return fmt.Errorf("controller grant references unapproved table %q", table)
		}
		if observed[table] == nil {
			observed[table] = make(map[string]struct{})
		}
		for _, verb := range strings.Split(parts[1], ", ") {
			allowed := false
			for _, item := range expected {
				allowed = allowed || item == verb
			}
			if !allowed {
				return fmt.Errorf("controller grant has unapproved %s privilege on %s", verb, table)
			}
			observed[table][verb] = struct{}{}
		}
	}
	for table, verbs := range controllerTableGrants {
		for _, verb := range verbs {
			if _, ok := observed[table][verb]; !ok {
				return fmt.Errorf("controller grant lacks %s privilege on %s", verb, table)
			}
		}
	}
	return nil
}
