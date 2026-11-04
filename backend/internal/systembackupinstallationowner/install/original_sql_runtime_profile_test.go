package install

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestOriginalSQLPublicRuntimeProfileSeparatesSourceAndAuthority(t *testing.T) {
	present := originalSQLTestTables()
	for _, table := range []string{"runtime_pods", "instance_runtime_bindings"} {
		present[table] = true
	}
	a := originalSQLAccount{User: "sbk_runtime_test", Host: "10.1.2.3"}
	for _, role := range []string{"installer", "business", "source", "control_sql", "census"} {
		old, e := originalSQLRolePrivileges(role, "clawmanager", a, present, false)
		public, pe := originalSQLRolePrivilegesForProfile(role, "clawmanager", a, present, false, originalSQLPublicRuntimeProfile)
		if e != nil || pe != nil || !reflect.DeepEqual(old, public) {
			t.Fatal("public runtime changed another principal", role)
		}
	}
	rights, e := originalSQLRolePrivilegesForProfile("runtime", "clawmanager", a, present, false, originalSQLPublicRuntimeProfile)
	if e != nil {
		t.Fatal(e)
	}
	found := map[string]map[string]bool{}
	for _, p := range rights {
		if p.Kind != "table" || p.Database != "" || p.Column != "" || p.Verb != "SELECT" && p.Verb != "INSERT" && p.Verb != "UPDATE" && p.Verb != "DELETE" {
			t.Fatal("nonfinite privilege", p.Kind, p.Verb)
		}
		if !strings.HasPrefix(p.Object, "system_backup_") && !strings.HasPrefix(p.Object, "gateway_runtime_") && p.Object != "audit_logs" && p.Object != "schema_migrations" && p.Object != "instances" && p.Object != "instance_runtime_bindings" && p.Object != "runtime_pods" {
			t.Fatal("business capture entered controller credential", p.Object)
		}
		if (p.Object == "audit_logs" || strings.Contains(p.Object, "config") || strings.Contains(p.Object, "signing_resource") || strings.Contains(p.Object, "installation_owner")) && p.Verb != "SELECT" {
			t.Fatal("runtime received source authority mutation", p.Object, p.Verb)
		}
		if found[p.Object] == nil {
			found[p.Object] = map[string]bool{}
		}
		found[p.Object][p.Verb] = true
	}
	for table, verb := range map[string]string{"audit_logs": "SELECT", "system_backup_v2_external_actions": "UPDATE", "system_backup_v2_evidence_chunks": "INSERT", "system_backup_v2_kek_references": "UPDATE", "system_backup_v2_kek_fences": "UPDATE"} {
		if !found[table][verb] {
			t.Fatal("actual full runtime branch omitted", table, verb)
		}
	}
	if len(found) <= 14 {
		t.Fatal("historical runtime silently reused")
	}
}

func TestOriginalSQLRuntimeProfileCannotReinterpretOriginalOperation(t *testing.T) {
	if originalSQLProfileOperationVersion("") != originalSQLProfileOperationVersion(originalSQLHistoricalRuntimeProfile) ||
		originalSQLProfileOperationVersion(originalSQLPublicRuntimeProfile) != "original198-sql-accounts-operation.v2" ||
		originalSQLProfileOperationVersion(originalSQLPublicRuntimeProfile) == originalSQLProfileOperationVersion(originalSQLHistoricalRuntimeProfile) {
		t.Fatal("original plan profile not frozen")
	}
	if _, e := originalSQLRolePrivilegesForProfile("runtime", "clawmanager", originalSQLAccount{User: "sbk_runtime", Host: "%"}, originalSQLTestTables(), false, originalSQLPublicRuntimeProfile); e == nil {
		t.Fatal("public runtime bypassed wildcard host acknowledgement")
	}
	for _, profile := range []string{"root", "public-runtime", "public-runtime-publication-permits-control-evidence.v2"} {
		if originalSQLProfileOperationVersion(profile) != "" {
			t.Fatal("unknown profile accepted")
		}
		var out bytes.Buffer
		if RunOriginalSQLAccounts(context.Background(), []string{"--runtime-profile", profile}, &out) != 2 || out.Len() != 0 {
			t.Fatal("unknown profile reached production connection")
		}
	}
}
