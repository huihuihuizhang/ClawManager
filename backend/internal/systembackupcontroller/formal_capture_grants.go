package systembackupcontroller

import (
	"context"
	"database/sql"
)

// Extends the selected original capture role only for A's controller Unwrap
// reader. Registry/owner records remain immutable; the KEK fence alone takes
// INSERT+UPDATE for original SQLStore.Bind's create-if-absent/exclusive lock.
func formalCaptureTableGrants(runtime bool) map[string][]string {
	source := publicCaptureTableGrants
	if runtime {
		source = runtimeControlTableGrants()
	}
	out := map[string][]string{}
	for table, verbs := range source {
		out[table] = append([]string(nil), verbs...)
	}
	for _, table := range []string{"system_backup_installation_kek_authority", "system_backup_v2_kek_bindings", "system_backup_v2_kek_coverage", "system_backup_v2_kek_references"} {
		out[table] = []string{"SELECT"}
	}
	out["system_backup_v2_kek_fences"] = []string{"SELECT", "INSERT", "UPDATE"}
	return out
}
func FormalCaptureGrantSQL(schema, user, host string, allowAnyHost, runtime bool) ([]string, error) {
	return controllerGrantSQL(schema, user, host, allowAnyHost, formalCaptureTableGrants(runtime))
}
func ValidateFormalCaptureGrants(schema string, statements []string, runtime bool) error {
	return validateControllerGrants(schema, statements, formalCaptureTableGrants(runtime))
}

type SQLFormalCaptureGrantProbe struct {
	DB           *sql.DB
	Schema, User string
	Runtime      bool
}

func (p SQLFormalCaptureGrantProbe) Check(ctx context.Context) error {
	return (SQLControllerGrantProbe{DB: p.DB, Schema: p.Schema, User: p.User}).check(ctx, formalCaptureTableGrants(p.Runtime))
}
