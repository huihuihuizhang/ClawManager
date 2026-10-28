package systembackupsecurity

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Shared by the actual proof/writer MySQL fixture. These are synthetic values
// in a run-owned DB, not defaults added to the production migration.
const configProofInstallationStateInsert = "INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key) VALUES (?,1,?,'k8s-cluster')"

func configProofMissingRequiredColumns(ddl, statement string) []string {
	match := regexp.MustCompile(`^INSERT INTO system_backup_v2_installation_state\(([^)]+)\)\s+VALUES\s*\(`).FindStringSubmatch(statement)
	provided := map[string]bool{}
	if len(match) == 2 {
		for _, name := range strings.Split(match[1], ",") {
			provided[name] = true
		}
	}
	var missing []string
	for _, column := range regexp.MustCompile(`(?m)^  ([a-z][a-z0-9_]*) ([^\n]+)`).FindAllStringSubmatch(ddl, -1) {
		definition := column[2]
		if strings.Contains(definition, " NOT NULL") && !strings.Contains(definition, " DEFAULT ") && !strings.Contains(definition, " AUTO_INCREMENT") && !provided[column[1]] {
			missing = append(missing, column[1])
		}
	}
	sort.Strings(missing)
	return missing
}
func assertConfigProofInstallationStateSeed(t *testing.T, ddl string) {
	t.Helper()
	if !strings.HasPrefix(ddl, "CREATE TABLE IF NOT EXISTS system_backup_v2_installation_state (") || !strings.Contains(ddl, "last_effective_enabled_transition_at DATETIME(6) NOT NULL") || !strings.Contains(ddl, "matrix_key ENUM('k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node') NOT NULL") {
		t.Fatal("incomplete formal installation-state fixture schema")
	}
	if missing := configProofMissingRequiredColumns(ddl, configProofInstallationStateInsert); len(missing) != 0 {
		t.Fatal("fixture omits required nondefault SQL columns", missing)
	}
	old := configProofMissingRequiredColumns(ddl, "INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version) VALUES(?,1)")
	if !reflect.DeepEqual(old, []string{"last_effective_enabled_transition_at", "matrix_key"}) {
		t.Fatal("old fixture regression no longer matches full-schema required columns", old)
	}
}
func TestConfigProofFixtureCoversFormalInstallationStateRequiredColumns(t *testing.T) {
	raw, err := os.ReadFile("../db/migrations/096_backup_v2_add_system_backup_control_metadata_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	match := regexp.MustCompile(`(?ms)^CREATE TABLE IF NOT EXISTS system_backup_v2_installation_state \(.*?\) ENGINE=InnoDB[^;]*;`).FindString(text)
	if match == "" {
		t.Fatal("formal installation-state schema not found")
	}
	embedded, err := os.ReadFile("testdata/config_proof_installation_schema_065.sql")
	if err != nil {
		t.Fatal(err)
	}
	if string(embedded) != match+"\n" {
		t.Fatal("detached seed schema differs from exact formal 065 table")
	}
	assertConfigProofInstallationStateSeed(t, match)
}
