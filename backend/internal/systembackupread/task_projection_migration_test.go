package systembackupread

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Keep the fixed read projection aligned with the migrated task tables. The
// SQL execution and data-distribution checks still require isolated MySQL.
func TestTaskProjectionExistsInAllMigratedTaskTables(t *testing.T) {
	migration, err := os.ReadFile(filepath.Join("..", "db", "migrations", "098_backup_v2_add_system_backup_task_execution_core.sql"))
	if err != nil {
		t.Fatal(err)
	}
	columns := strings.Split(taskProjectionColumns, ",")
	if len(columns) == 0 || columns[len(columns)-1] != "schema_version" {
		t.Fatal("task schema version is not projected")
	}
	for _, table := range taskTables {
		start := "CREATE TABLE IF NOT EXISTS " + table.name + " ("
		parts := strings.Split(string(migration), start)
		if len(parts) != 2 {
			t.Fatalf("expected one migrated table %s", table.name)
		}
		body, _, found := strings.Cut(parts[1], ") ENGINE=InnoDB")
		if !found {
			t.Fatalf("migrated table has no end: %s", table.name)
		}
		for _, column := range columns {
			if !regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(column) + `\s+`).MatchString(body) {
				t.Errorf("%s has no projected column %s", table.name, column)
			}
		}
	}
	for _, forbidden := range []string{"config_snapshot_json", "failure_message", "controller_owner", "artifact_uri", "provider_data"} {
		for _, column := range columns {
			if column == forbidden {
				t.Errorf("sensitive column %s entered task projection", column)
			}
		}
	}
}
