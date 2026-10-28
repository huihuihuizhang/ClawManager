package systembackupsecurity

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CapacityCollectorConfig is a public, SHA-pinned deployment input. The table
// list is generated from the current schema registry, never from this user's
// potentially incomplete information_schema visibility.
type CapacityCollectorConfig struct {
	ServerUUID string   `json:"server_uuid"`
	Database   string   `json:"database"`
	User       string   `json:"user"`
	DataDir    string   `json:"data_directory"`
	Tables     []string `json:"tables"`
}

var capacityIdentifier = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
var capacityUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const capacityGrantee = "(?:'[^']+'|`[^`]+`)@(?:'[^']+'|`[^`]+`)"

var capacityGrant = regexp.MustCompile("^GRANT SELECT ON `([A-Za-z0-9_]+)`\\.`([A-Za-z0-9_]+)` TO " + capacityGrantee + "$")
var capacityUsage = regexp.MustCompile(`^GRANT USAGE ON \*\.\* TO ` + capacityGrantee + "$")

func (c CapacityCollectorConfig) Validate() error {
	if !capacityUUID.MatchString(c.ServerUUID) || !capacityIdentifier.MatchString(c.Database) || !capacityIdentifier.MatchString(c.User) || strings.EqualFold(c.User, "root") || !filepath.IsAbs(c.DataDir) || filepath.Clean(c.DataDir) != c.DataDir || c.DataDir == string(filepath.Separator) || len(c.Tables) == 0 {
		return ErrRegistrationUnavailable
	}
	seen := map[string]bool{}
	for _, table := range c.Tables {
		if !capacityIdentifier.MatchString(table) || seen[table] || !(strings.HasPrefix(table, "system_backup_") || strings.HasPrefix(table, "system_restore_") || table == "system_backup_v2_backups" || table == "audit_logs") {
			return ErrRegistrationUnavailable
		}
		seen[table] = true
	}
	if !seen["audit_logs"] || !seen["system_backup_v2_configs"] || !seen["system_backup_v2_backups"] {
		return ErrRegistrationUnavailable
	}
	return nil
}

func LoadCapacityCollectorConfig(path, digest string) (CapacityCollectorConfig, error) {
	var c CapacityCollectorConfig
	raw, err := boundedFile(path, 65536)
	if err != nil || decodePinnedRegistry(raw, digest, &c) != nil || c.Validate() != nil {
		return c, ErrRegistrationUnavailable
	}
	return c, nil
}

// Only exact direct SELECT grants are accepted. Roles, wildcards, writes,
// delegation and unknown syntax fail closed; no privilege canary is written.
func ValidateCapacityGrants(c CapacityCollectorConfig, grants []string) error {
	if c.Validate() != nil || len(grants) == 0 {
		return ErrRegistrationUnavailable
	}
	expected := map[string]bool{}
	for _, table := range c.Tables {
		expected[table] = false
	}
	for _, grant := range grants {
		if capacityUsage.MatchString(grant) {
			continue
		}
		m := capacityGrant.FindStringSubmatch(grant)
		if m == nil || m[1] != c.Database {
			return ErrRegistrationUnavailable
		}
		if _, ok := expected[m[2]]; !ok {
			return ErrRegistrationUnavailable
		}
		expected[m[2]] = true
	}
	for _, present := range expected {
		if !present {
			return ErrRegistrationUnavailable
		}
	}
	return nil
}

// Keep identity, roles, grants and measurement on one physical SQL connection.
func CollectPinnedRegistrationCapacity(ctx context.Context, db *sql.DB, c CapacityCollectorConfig) (CapacityReport, error) {
	var empty CapacityReport
	if c.Validate() != nil {
		return empty, ErrRegistrationUnavailable
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	defer conn.Close()
	var account, role string
	if conn.QueryRowContext(ctx, "SELECT CURRENT_USER(),CURRENT_ROLE()").Scan(&account, &role) != nil || !strings.HasPrefix(account, c.User+"@") || len(account) <= len(c.User)+1 || role != "NONE" {
		return empty, ErrRegistrationUnavailable
	}
	rows, err := conn.QueryContext(ctx, "SHOW GRANTS")
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	var grants []string
	for rows.Next() {
		var grant string
		if rows.Scan(&grant) != nil {
			rows.Close()
			return empty, ErrRegistrationUnavailable
		}
		grants = append(grants, grant)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil || closeErr != nil || ValidateCapacityGrants(c, grants) != nil {
		return empty, ErrRegistrationUnavailable
	}
	return collectRegistrationCapacity(ctx, conn, c)
}

// Same-directory rename gives readers a complete report. Group readability
// lets the collector's MySQL UID differ from the HTTP UID; no world access.
func WriteCapacityReport(path string, data []byte) error {
	if !filepath.IsAbs(path) {
		return ErrRegistrationUnavailable
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".d-capacity-")
	if err != nil {
		return ErrRegistrationUnavailable
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0640); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil || closeErr != nil {
		return ErrRegistrationUnavailable
	}
	if os.Rename(temp.Name(), path) != nil {
		return ErrRegistrationUnavailable
	}
	return nil
}
