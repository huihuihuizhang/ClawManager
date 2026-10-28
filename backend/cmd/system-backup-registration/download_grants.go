package main

import (
	"context"
	"database/sql"
	"regexp"
	"sort"
	"strings"
	"time"
)

// These are deployment-pinned expectations, not an approval or GRANT request.
// Startup checks actual direct grants on one connection. Minimality and the
// final D role profile still require independent review and restricted SQL E2E.
type downloadGrantPins struct {
	SchemaVersion string   `json:"schema_version"`
	ServerUUID    string   `json:"server_uuid"`
	Database      string   `json:"database"`
	User          string   `json:"user"`
	Statements    []string `json:"statements"`
}

const downloadGrantee = "(?:'([A-Za-z0-9_]+)'|`([A-Za-z0-9_]+)`)@(?:'[^']+'|`[^`]+`)"

var downloadUsageGrant = regexp.MustCompile(`^GRANT USAGE ON \*\.\* TO ` + downloadGrantee + `$`)
var downloadLockGrant = regexp.MustCompile("^GRANT LOCK TABLES ON `([A-Za-z0-9_]+)`\\.\\* TO " + downloadGrantee + "$")
var downloadTableGrant = regexp.MustCompile("^GRANT ([A-Z ,]+) ON `([A-Za-z0-9_]+)`\\.`([A-Za-z0-9_]+)` TO " + downloadGrantee + "$")

// Read-only owner/audit sources never gain UPDATE to satisfy FOR UPDATE.
// A database-scoped LOCK TABLES grant is recognized explicitly. This parser
// never issues LOCK TABLES or any grant; lock-mode/role approval is external.
var downloadWritableTables = map[string]map[string]bool{
	"audit_logs":                                {"INSERT": true},
	"system_backup_v2_operations":                  {"INSERT": true},
	"system_backup_v2_evidence":                    {"INSERT": true, "UPDATE": true},
	"system_backup_v2_download_admission_receipts": {"INSERT": true},
	"system_backup_v2_download_result_receipts":    {"INSERT": true},
	"system_backup_v2_strong_auth_nonces":          {"INSERT": true, "UPDATE": true},
	"system_backup_v2_metadata_reservations":       {"INSERT": true, "UPDATE": true},
	"system_backup_v2_admin_sessions":              {"INSERT": true, "UPDATE": true},
	"system_backup_v2_admin_revocations":           {"INSERT": true, "UPDATE": true},
	"system_backup_v2_totp_credentials":            {"INSERT": true, "UPDATE": true},
}

func downloadGrantShape(c downloadDeployment, statements []string) error {
	if !downloadUser.MatchString(c.DatabaseUser) || strings.EqualFold(c.DatabaseUser, "root") || len(statements) == 0 || len(statements) > 256 {
		return errDownloadDeployment
	}
	seen := map[string]bool{}
	locked := false
	byTable := map[string]map[string]bool{}
	for _, statement := range statements {
		if len(statement) > 2048 || seen[statement] {
			return errDownloadDeployment
		}
		seen[statement] = true
		if m := downloadUsageGrant.FindStringSubmatch(statement); m != nil {
			if m[1] != c.DatabaseUser && m[2] != c.DatabaseUser {
				return errDownloadDeployment
			}
			continue
		}
		if m := downloadLockGrant.FindStringSubmatch(statement); m != nil {
			if m[1] != c.Database || (m[2] != c.DatabaseUser && m[3] != c.DatabaseUser) || locked {
				return errDownloadDeployment
			}
			locked = true
			continue
		}
		m := downloadTableGrant.FindStringSubmatch(statement)
		if m == nil || m[2] != c.Database || (m[4] != c.DatabaseUser && m[5] != c.DatabaseUser) {
			return errDownloadDeployment
		}
		table := m[3]
		if !(strings.HasPrefix(table, "system_backup_") || strings.HasPrefix(table, "system_restore_") || table == "system_backup_v2_backups" || table == "users" || table == "audit_logs" || table == "schema_migrations") {
			return errDownloadDeployment
		}
		privileges := map[string]bool{}
		for _, priv := range strings.Split(m[1], ", ") {
			if privileges[priv] || priv != "SELECT" && !downloadWritableTables[table][priv] {
				return errDownloadDeployment
			}
			privileges[priv] = true
		}
		if byTable[table] == nil {
			byTable[table] = map[string]bool{}
		}
		for priv := range privileges {
			byTable[table][priv] = true
		}
	}
	if !locked {
		return errDownloadDeployment
	}
	for table, required := range map[string][]string{
		"system_backup_v2_backups": {"SELECT"}, "system_backup_v2_restore_drills": {"SELECT"}, "system_backup_v2_preflights": {"SELECT"}, "system_backup_v2_artifact_verifications": {"SELECT"},
		"users": {"SELECT"}, "audit_logs": {"SELECT", "INSERT"}, "system_backup_v2_installation_state": {"SELECT"}, "system_backup_v2_configs": {"SELECT"},
		"system_backup_v2_operations": {"SELECT", "INSERT"}, "system_backup_v2_evidence": {"SELECT", "INSERT", "UPDATE"}, "system_backup_v2_evidence_chunks": {"SELECT"},
		"system_backup_v2_download_admission_receipts": {"SELECT", "INSERT"}, "system_backup_v2_download_result_receipts": {"SELECT", "INSERT"},
		"system_backup_v2_strong_auth_nonces": {"SELECT", "INSERT"}, "system_backup_v2_metadata_reservations": {"SELECT", "INSERT", "UPDATE"},
		"system_backup_v2_admin_sessions": {"SELECT", "INSERT", "UPDATE"}, "system_backup_v2_admin_revocations": {"SELECT"}, "system_backup_v2_totp_credentials": {"SELECT", "INSERT", "UPDATE"},
	} {
		for _, priv := range required {
			if !byTable[table][priv] {
				return errDownloadDeployment
			}
		}
	}
	return nil
}

func checkDownloadDatabasePins(ctx context.Context, db *sql.DB, c downloadDeployment) error {
	if ctx == nil || ctx.Err() != nil || db == nil {
		return errDownloadDeployment
	}
	raw, err := pinnedDeploymentBytes(c.GrantsFile, c.GrantsSHA256, 65536)
	if err != nil {
		return err
	}
	var pins downloadGrantPins
	if strictDeploymentJSON(raw, &pins) != nil || pins.SchemaVersion != "system-backup-download-sql-pins.v1" || pins.ServerUUID != c.ServerUUID || pins.Database != c.Database || pins.User != c.DatabaseUser || downloadGrantShape(c, pins.Statements) != nil {
		return errDownloadDeployment
	}
	probe, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	conn, err := db.Conn(probe)
	if err != nil {
		return errDownloadDeployment
	}
	defer conn.Close()
	var server, database, account, role string
	if conn.QueryRowContext(probe, "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE()").Scan(&server, &database, &account, &role) != nil || server != c.ServerUUID || database != c.Database || !strings.HasPrefix(account, c.DatabaseUser+"@") || len(account) <= len(c.DatabaseUser)+1 || role != "NONE" {
		return errDownloadDeployment
	}
	rows, err := conn.QueryContext(probe, "SHOW GRANTS")
	if err != nil {
		return errDownloadDeployment
	}
	defer rows.Close()
	var actual []string
	for rows.Next() {
		var grant string
		if rows.Scan(&grant) != nil || len(actual) >= len(pins.Statements) {
			return errDownloadDeployment
		}
		actual = append(actual, grant)
	}
	err = rows.Err()
	closed := rows.Close()
	if err != nil || closed != nil || downloadGrantShape(c, actual) != nil || len(actual) != len(pins.Statements) {
		return errDownloadDeployment
	}
	sort.Strings(actual)
	sort.Strings(pins.Statements)
	for n := range actual {
		if actual[n] != pins.Statements[n] {
			return errDownloadDeployment
		}
	}
	return nil
}
