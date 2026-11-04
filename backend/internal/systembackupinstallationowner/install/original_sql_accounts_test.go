package install

import (
	"bytes"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/schemaobjects"
	"context"
	"strings"
	"testing"
)

func originalSQLTestTables() map[string]bool {
	p := map[string]bool{}
	for _, n := range schemaobjects.ExcludedControlTables() {
		p[n] = true
	}
	for _, n := range domain.BusinessCaptureTables() {
		p[n] = true
	}
	return p
}
func TestOriginalSQLAccountsFiniteRolesAndSeparation(t *testing.T) {
	present := originalSQLTestTables()
	for _, role := range []string{"installer", "business", "source", "runtime", "control_sql", "census"} {
		a := originalSQLAccount{User: "sbk_actual_user", Host: "10.1.2.3"}
		rights, e := originalSQLRolePrivileges(role, "clawmanager", a, present, false)
		if e != nil || len(rights) == 0 {
			t.Fatal("finite actual role unavailable", role)
		}
		tables := map[string]bool{}
		for _, v := range rights {
			if v.Kind == "table" {
				tables[v.Object] = true
			}
			if v.Verb == "GRANT OPTION" || v.Verb == "CREATE" || v.Verb == "DROP" || v.Verb == "ALTER" {
				t.Fatal("DDL/delegation entered ordinary role", role)
			}
			if role == "source" && (v.Kind == "table" || v.Kind == "column") && (strings.HasPrefix(v.Object, "system_backup_") || strings.HasPrefix(v.Object, "dlegacy_")) {
				t.Fatal("control rows entered capture credential")
			}
			if role == "source" && v.Kind == "routine" && (v.Object != domain.SchemaCensusRoutine || v.Verb != "EXECUTE") {
				t.Fatal("source gained an unrelated routine capability")
			}
			if role == "source" && v.Verb != "SELECT" && v.Verb != "SHOW_ROUTINE" && v.Verb != "EXECUTE" {
				t.Fatal("source gained mutation")
			}
			if role == "business" && v.Object == "users" && (v.Kind != "column" || v.Column == "password_hash" || v.Verb != "SELECT") {
				t.Fatal("bootstrap consumer gained user mutation/password material")
			}
			if role == "business" && strings.HasPrefix(v.Object, "system_backup_signing_resource_") && v.Verb != "SELECT" {
				t.Fatal("consumer gained signer issuance")
			}
			if (role == "installer" || role == "business") && strings.HasPrefix(v.Object, "dlegacy_") && v.Verb != "SELECT" {
				t.Fatal("retained source gained DML")
			}
		}
		if role == "runtime" && len(tables) != 14 {
			t.Fatal("controller runtime is not exact14 table matrix", len(tables))
		}
		if role == "control_sql" && (len(rights) != 1 || !tables["system_backup_participants"]) {
			t.Fatal("participant observer borrowed another role")
		}
		if role == "installer" || role == "business" {
			for _, name := range schemaobjects.RetainedOriginalLegacyControlTables() {
				if !tables[name] {
					t.Fatal("exact retained original source omitted", role, name)
				}
			}
		}
	}
	if _, e := originalSQLRolePrivileges("root", "clawmanager", originalSQLAccount{}, present, false); e == nil {
		t.Fatal("unknown role accepted")
	}
	if _, e := originalSQLRolePrivileges("runtime", "clawmanager", originalSQLAccount{User: "sbk_runtime", Host: "%"}, present, false); e == nil {
		t.Fatal("wildcard host silently accepted")
	}
}

func TestOriginalSQLAccountsOnlyExactCreatorAutoGrant(t *testing.T) {
	allowed := []string{"GRANT EXECUTE, ALTER ROUTINE ON PROCEDURE `clawmanager`.`system_backup_source_schema_census` TO 'root'@'localhost'", "GRANT ALTER ROUTINE, EXECUTE ON PROCEDURE `clawmanager`.`system_backup_source_schema_census` TO `root`@`%`"}
	for _, s := range allowed {
		if !originalSQLCreatorGrant(s, "clawmanager") {
			t.Fatal("native exact automatic grant not recognized")
		}
	}
	for _, s := range []string{strings.ReplaceAll(allowed[0], "EXECUTE, ALTER ROUTINE", "ALL PRIVILEGES"), allowed[0] + " WITH GRANT OPTION", strings.ReplaceAll(allowed[0], "schema_census", "other"), strings.ReplaceAll(allowed[0], "'root'", "'other'"), strings.ReplaceAll(allowed[0], "`clawmanager`", "`other`")} {
		if originalSQLCreatorGrant(s, "clawmanager") {
			t.Fatal("foreign original privilege ignored", s)
		}
	}
}

func TestOriginalSQLAccountsRetainedCensusIsExactNotPrefix(t *testing.T) {
	retained := schemaobjects.RetainedOriginalLegacyControlTables()
	if len(retained) != 35 {
		t.Fatal("retained profile")
	}
	all := map[string]bool{}
	for _, n := range schemaobjects.ExcludedControlTables() {
		all[n] = true
	}
	for _, n := range retained {
		if !all[n] {
			t.Fatal("known original alias omitted", n)
		}
	}
	if all["dlegacy_99_unreviewed"] {
		t.Fatal("prefix exclusion")
	}
	copy := schemaobjects.RetainedOriginalLegacyControlTables()
	copy[0] = "changed"
	if schemaobjects.RetainedOriginalLegacyControlTables()[0] == "changed" {
		t.Fatal("mutable global policy exposed")
	}
}

func TestOriginalSQLAccountsCLIRejectsMissingOriginalInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"--mode", "apply"}, {"--mode", "prepare"}, {"--mode", "inspect"}, {"--mode", "rollback", "--operation-file", "/tmp/claimed"}, {"--enable"}} {
		var out bytes.Buffer
		if RunOriginalSQLAccounts(context.Background(), args, &out) != 2 || out.Len() != 0 {
			t.Fatal("unqualified inputs reached original SQL", args)
		}
	}
}
