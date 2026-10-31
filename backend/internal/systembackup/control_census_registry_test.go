package systembackup

import (
	"clawreef/internal/systembackup/schemaobjects"
	"reflect"
	"sort"
	"testing"
)

func TestControlCensusRegistryMatchesOriginalPolicy(t *testing.T) {
	var names []string
	for _, policy := range Registry() {
		if policy.Category == "system_backup" && policy.BackupStrategy == "metadata_only" {
			names = append(names, policy.Name)
		}
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, schemaobjects.ExcludedControlTables()) {
		t.Fatal("shared full schema census control exclusions drifted from original reviewed registry")
	}
}

func TestOptionalSourceTablesRetainOriginalBusinessClassification(t *testing.T) {
	for _, name := range schemaobjects.OptionalBusinessTables() {
		if !teamDataHistoricalOperationTable(name) {
			t.Fatal("optional source has no original historical-runtime policy", name)
		}
		p, ok := Policy(name)
		if !ok || p.Category != "instances" || p.Classification != "secret" || p.BackupStrategy != "mysql_dump" {
			t.Fatal("optional business rows were reclassified as controls", name)
		}
	}
}
