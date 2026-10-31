package systembackupcontroller

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func TestFormalVerifierRoleKeepsOriginalRecordsAndEvidenceImmutable(t *testing.T) {
	for _, runtime := range []bool{false, true} {
		grants, err := FormalCaptureGrantSQL("capture", "reader", "127.0.0.1", false, runtime)
		if err != nil {
			t.Fatal(err)
		}
		for i := range grants {
			grants[i] = strings.TrimSuffix(grants[i], ";")
		}
		if ValidateFormalCaptureGrants("capture", grants, runtime) != nil {
			t.Fatal("exact formal role rejected")
		}
		if ValidatePublicCaptureGrants("capture", grants) == nil || ValidateRuntimeControlGrants("capture", grants) == nil {
			t.Fatal("formal permissions silently admitted by legacy role")
		}
		for _, extra := range []string{
			"GRANT UPDATE ON `capture`.`system_backup_installation_kek_authority` TO 'reader'@'127.0.0.1'",
			"GRANT UPDATE ON `capture`.`system_backup_v2_kek_bindings` TO 'reader'@'127.0.0.1'",
			"GRANT UPDATE ON `capture`.`system_backup_v2_evidence` TO 'reader'@'127.0.0.1'",
			"GRANT DELETE ON `capture`.`system_backup_v2_kek_fences` TO 'reader'@'127.0.0.1'",
		} {
			if ValidateFormalCaptureGrants("capture", append(append([]string{}, grants...), extra), runtime) == nil {
				t.Fatal("excess formal privilege accepted", extra)
			}
		}
		db := sql.OpenDB(grantProbeConnector{user: "reader@127.0.0.1", role: "NONE", grants: grants})
		err = (SQLFormalCaptureGrantProbe{DB: db, Schema: "capture", User: "reader", Runtime: runtime}).Check(context.Background())
		db.Close()
		if err != nil {
			t.Fatal("production grant probe rejected exact role", err)
		}
	}
}

func TestFormalProviderPermitRoleRetainsUnknownWithoutSourceMutation(t *testing.T) {
	for _, runtime := range []bool{false, true} {
		grants, err := FormalProviderPermitGrantSQL("capture", "issuer", "127.0.0.1", false, runtime)
		if err != nil {
			t.Fatal(err)
		}
		for i := range grants {
			grants[i] = strings.TrimSuffix(grants[i], ";")
		}
		if ValidateFormalProviderPermitGrants("capture", grants, runtime) != nil {
			t.Fatal("exact producer role rejected")
		}
		if ValidateFormalCaptureGrants("capture", grants, runtime) == nil {
			t.Fatal("reader role admitted producer writes")
		}
		for _, extra := range []string{"GRANT DELETE ON `capture`.`system_backup_v2_kek_references` TO 'issuer'@'127.0.0.1'", "GRANT UPDATE ON `capture`.`system_backup_v2_evidence` TO 'issuer'@'127.0.0.1'", "GRANT UPDATE ON `capture`.`system_backup_installation_kek_authority` TO 'issuer'@'127.0.0.1'"} {
			if ValidateFormalProviderPermitGrants("capture", append(append([]string(nil), grants...), extra), runtime) == nil {
				t.Fatal("extra producer privilege accepted", extra)
			}
		}
		db := sql.OpenDB(grantProbeConnector{user: "issuer@127.0.0.1", role: "NONE", grants: grants})
		err = (SQLFormalProviderPermitGrantProbe{DB: db, Schema: "capture", User: "issuer", Runtime: runtime}).Check(context.Background())
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}
