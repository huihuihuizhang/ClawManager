package install

import (
	"reflect"
	"testing"

	appdb "clawreef/internal/db"
)

func TestOriginalSQLC1ProfileKeepsSourceAndRuntimeIndependent(t *testing.T) {
	present := originalSQLTestTables()
	for _, table := range originalSQLC1Tables {
		present[table] = true
	}
	present["runtime_pods"] = true
	present["instance_runtime_bindings"] = true
	a := originalSQLAccount{User: "sbk_test", Host: "10.1.2.3"}
	for _, role := range []string{"source", "runtime", "control_sql", "census"} {
		old, e := originalSQLRolePrivilegesForProfile(role, "clawmanager", a, present, false, originalSQLPublicRuntimeProfile)
		current, ce := originalSQLRolePrivilegesForProfile(role, "clawmanager", a, present, false, originalSQLC1Profile)
		if e != nil || ce != nil || !reflect.DeepEqual(old, current) {
			t.Fatal("unrelated principal expanded", role)
		}
	}
	for _, role := range []string{"installer", "business"} {
		rights, e := originalSQLRolePrivilegesForProfile(role, "clawmanager", a, present, false, originalSQLC1Profile)
		if e != nil {
			t.Fatal(e)
		}
		got := map[string]map[string]bool{}
		for _, v := range rights {
			if got[v.Object] == nil {
				got[v.Object] = map[string]bool{}
			}
			got[v.Object][v.Verb] = true
		}
		for _, table := range originalSQLC1Tables {
			if role == "business" && table == "system_backup_producer_command_receipts" {
				if len(got[table]) != 0 {
					t.Fatal("business command receipt rights")
				}
				continue
			}
			if !got[table]["SELECT"] || got[table]["DELETE"] {
				t.Fatal("nonfinite C1 rights", role, table)
			}
			if role == "business" && (got[table]["INSERT"] || got[table]["UPDATE"] && table != "system_backup_producer_domains") {
				t.Fatal("consumer edits original evidence", table)
			}
		}
	}
	delete(present, "system_backup_producer_runs")
	if _, e := originalSQLRolePrivilegesForProfile("installer", "clawmanager", a, present, false, originalSQLC1Profile); e == nil {
		t.Fatal("partial C1 schema accepted")
	}
	if originalSQLProfileOperationVersion(originalSQLC1Profile) == originalSQLProfileOperationVersion(originalSQLPublicRuntimeProfile) {
		t.Fatal("old operation reinterpreted")
	}
}

func TestOriginalSQLC1LedgerIsExactUnionWithRealEmbeddedCatalog(t *testing.T) {
	expected, err := originalSQLC1ExpectedLedger()
	if err != nil { // Root must overlay formal137 before this package can pass.
		t.Fatal("same-release formal137 catalog required", err)
	}
	if !originalSQLC1LedgerMatches(expected) {
		t.Fatal("exact ledger refused")
	}
	if originalSQLC1LedgerMatches(append(append([]string(nil), expected...), "unreviewed.sql")) || originalSQLC1LedgerMatches(expected[1:]) {
		t.Fatal("foreign/partial ledger accepted")
	}
}

func TestOriginalSQLFreshLedgerCannotReinterpretHistoricalOperation(t *testing.T) {
	current := originalSQLInputs{runtimeProfile: originalSQLMinIOMetadataProfile, freshInstallation: true}
	historical := originalSQLInputs{runtimeProfile: current.runtimeProfile}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil || len(catalog.Filenames) < 2 {
		t.Fatal("current embedded catalog unavailable", err)
	}
	old, err := originalSQLC1ExpectedLedger()
	if err != nil || !historical.ledgerMatches(old) || !current.ledgerMatches(catalog.Filenames) {
		t.Fatal("expected ledger refused", err)
	}
	if current.ledgerMatches(old) || historical.ledgerMatches(catalog.Filenames) || current.ledgerMatches(catalog.Filenames[1:]) {
		t.Fatal("accepted foreign or partial ledger")
	}
	foreign := append([]string(nil), catalog.Filenames...)
	foreign[len(foreign)-1] = "999_unreviewed.sql"
	if current.ledgerMatches(foreign) || current.operationVersion() == "" || current.operationVersion() == historical.operationVersion() {
		t.Fatal("accepted altered ledger or reused historical operation version")
	}
	current.runtimeProfile = originalSQLC1Profile
	if current.operationVersion() != "" {
		t.Fatal("accepted unsupported fresh runtime profile")
	}
}
