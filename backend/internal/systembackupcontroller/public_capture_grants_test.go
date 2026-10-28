package systembackupcontroller

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func publicTestGrants(t *testing.T) []string {
	t.Helper()
	s, e := PublicCaptureGrantSQL("capture", "backup_capture", "127.0.0.1", false)
	if e != nil {
		t.Fatal(e)
	}
	for i := range s {
		s[i] = strings.TrimSuffix(s[i], ";")
	}
	return s
}
func TestPublicCaptureGrantsSeparateBusinessAndImmutableCustody(t *testing.T) {
	grants := publicTestGrants(t)
	if e := ValidatePublicCaptureGrants("capture", grants); e != nil {
		t.Fatal(e)
	}
	for _, extra := range []string{
		"GRANT SELECT ON `capture`.`users` TO 'backup_capture'@'127.0.0.1'",
		"GRANT UPDATE ON `capture`.`system_backup_v2_configs` TO 'backup_capture'@'127.0.0.1'",
		"GRANT UPDATE ON `capture`.`system_backup_v2_execution_records` TO 'backup_capture'@'127.0.0.1'",
		"GRANT DELETE ON `capture`.`system_backup_v2_runtime_resources` TO 'backup_capture'@'127.0.0.1'",
		"GRANT ALL PRIVILEGES ON `capture`.* TO 'backup_capture'@'127.0.0.1'",
		"GRANT SELECT ON *.* TO 'backup_capture'@'127.0.0.1'",
	} {
		if ValidatePublicCaptureGrants("capture", append(append([]string(nil), grants...), extra)) == nil {
			t.Fatal("excess privilege accepted")
		}
	}
	if ValidatePublicCaptureGrants("capture", grants[1:]) == nil {
		t.Fatal("missing privilege accepted")
	}
	if ValidateControllerGrantStatements("capture", grants) == nil {
		t.Fatal("public privileges accepted in legacy mode")
	}
}
func TestPublicCaptureGrantProbeRejectsRole(t *testing.T) {
	for _, role := range []string{"NONE", "`broad_role`@`%`"} {
		db := sql.OpenDB(grantProbeConnector{user: "backup_capture@127.0.0.1", role: role, grants: publicTestGrants(t)})
		e := (SQLPublicCaptureGrantProbe{DB: db, Schema: "capture", User: "backup_capture"}).Check(context.Background())
		db.Close()
		if (e == nil) != (role == "NONE") {
			t.Fatal("role validation", role, e)
		}
	}
}
