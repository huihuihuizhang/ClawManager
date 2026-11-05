package install

import (
	c "clawreef/internal/systembackupcontroller"
	"reflect"
	"strings"
	"testing"
)

func TestOriginalSQLMinIOMetadataProfileRequiresFreshOperationAndFiniteColumns(t *testing.T) {
	if originalSQLProfileOperationVersion(originalSQLMinIOMetadataProfile) != "original-c1-minio-metadata-sql-accounts-operation.v4" || originalSQLProfileOperationVersion(originalSQLMinIOMetadataProfile) == originalSQLProfileOperationVersion(originalSQLC1Profile) {
		t.Fatal("signed old operation reinterpreted")
	}
	if originalSQLMinIOMetadataProfile != c.MinIOMetadataReadProfile {
		t.Fatal("native probe and enrollment profile differ")
	}
	present := originalSQLTestTables()
	for _, table := range append(append([]string{}, originalSQLC1Tables...), "users", "runtime_pods", "instance_runtime_bindings") {
		present[table] = true
	}
	for _, table := range []string{"system_backup_minio_owner_heads", "system_backup_minio_owner_grants", "system_backup_minio_owner_refs"} {
		present[table] = true
	}
	account := originalSQLAccount{User: "runtime_reader", Host: "127.0.0.1"}
	for _, role := range []string{"installer", "business", "source", "control_sql", "census"} {
		before, e := originalSQLRolePrivilegesForProfile(role, "capture", account, present, false, originalSQLC1Profile)
		after, ae := originalSQLRolePrivilegesForProfile(role, "capture", account, present, false, originalSQLMinIOMetadataProfile)
		if e != nil || ae != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("another principal changed", role, e, ae)
		}
	}
	rights, e := originalSQLRolePrivilegesForProfile("runtime", "capture", account, present, false, originalSQLMinIOMetadataProfile)
	if e != nil {
		t.Fatal(e)
	}
	var statements []string
	p := originalSQLPlan{Database: "capture"}
	for _, right := range rights {
		statements = append(statements, originalSQLGrant(p, account, right))
	}
	if e = c.ValidateMinIOMetadataReadGrants("capture", statements, true, true, true); e != nil {
		t.Fatal("actual owner renderer incompatible with exact native probe", e)
	}
	for _, right := range rights {
		if right.Object == "users" && (right.Kind != "column" || right.Verb != "SELECT" || strings.Contains(right.Column, "password")) {
			t.Fatal("users authority widened", right)
		}
	}
}
