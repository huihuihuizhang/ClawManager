package install

import (
	"reflect"
	"slices"
	"testing"
)

func TestOriginalSQLCensusDefinerExecutePreservesFrozenLegacyPlan(t *testing.T) {
	account := originalSQLAccount{Role: "census", Locked: true, Host: "localhost", User: "sbk_census_test"}
	planned, err := originalSQLRolePrivilegesForProfile(account.Role, "clawmanager", account, originalSQLTestTables(), true, originalSQLPublicRuntimeProfile)
	if err != nil || !slices.Contains(planned, originalCensusExecute) {
		t.Fatal("new plan omits the exact census definer privilege", err)
	}
	account.Privileges = slices.DeleteFunc(slices.Clone(planned), func(v originalSQLPrivilege) bool { return v == originalCensusExecute })
	legacy := slices.Clone(account.Privileges)
	if !reflect.DeepEqual(originalSQLWithCensusExecute(account), planned) || !reflect.DeepEqual(account.Privileges, legacy) {
		t.Fatal("frozen plan was mutated or reconstructed with the wrong privilege")
	}
	account.Privileges = planned
	if !reflect.DeepEqual(originalSQLWithCensusExecute(account), planned) {
		t.Fatal("already planned definer privilege was duplicated")
	}
	account.Role, account.Privileges = "source", legacy
	if !reflect.DeepEqual(originalSQLWithCensusExecute(account), legacy) {
		t.Fatal("definer compatibility expanded another role")
	}
}
