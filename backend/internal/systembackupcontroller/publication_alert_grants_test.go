package systembackupcontroller

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPublicationAlertGrantsMatchTerminalTransaction(t *testing.T) {
	for _, runtime := range []bool{false, true} {
		for _, permits := range []bool{false, true} {
			for _, evidence := range []bool{false, true} {
				t.Run(fmt.Sprintf("runtime=%t/permits=%t/evidence=%t", runtime, permits, evidence), func(t *testing.T) {
					grants, err := PublicationGrantSQL("clawmanager", "alert_publication", "127.0.0.1", false, runtime, permits)
					if evidence {
						grants, err = ControlEvidenceGrantSQL("clawmanager", "alert_publication", "127.0.0.1", false, runtime, permits, true)
					}
					if err != nil {
						t.Fatal(err)
					}
					want := "GRANT SELECT, INSERT, UPDATE ON `clawmanager`.`system_backup_v2_alert_states` TO 'alert_publication'@'127.0.0.1';"
					found := false
					for i := range grants {
						found = found || grants[i] == want
						grants[i] = strings.TrimSuffix(grants[i], ";")
					}
					if !found {
						t.Fatal("publication generator omits exact terminal alert SELECT/INSERT/UPDATE")
					}
					check := func(statements []string, role string) error {
						db := sql.OpenDB(grantProbeConnector{user: "alert_publication@127.0.0.1", role: role, grants: statements})
						defer db.Close()
						if evidence {
							return (SQLControlEvidenceGrantProbe{DB: db, Schema: "clawmanager", User: "alert_publication", Runtime: runtime, ProviderPermits: permits, Publication: true}).Check(context.Background())
						}
						return (SQLPublicationGrantProbe{DB: db, Schema: "clawmanager", User: "alert_publication", Runtime: runtime, ProviderPermits: permits}).Check(context.Background())
					}
					validate := func(statements []string) error {
						if evidence {
							return validateControllerGrants("clawmanager", statements, controlEvidenceTableGrants(runtime, permits, true))
						}
						return ValidatePublicationGrants("clawmanager", statements, runtime, permits)
					}
					if err := validate(grants); err != nil {
						t.Fatal(err)
					}
					if err := check(grants, "NONE"); err != nil {
						t.Fatal(err)
					}
					for _, verb := range []string{"SELECT", "INSERT", "UPDATE"} {
						t.Run("missing-"+verb, func(t *testing.T) {
							changed := append([]string(nil), grants...)
							for i, statement := range changed {
								if strings.Contains(statement, ".`system_backup_v2_alert_states` TO") {
									remaining := []string{}
									for _, v := range []string{"SELECT", "INSERT", "UPDATE"} {
										if v != verb {
											remaining = append(remaining, v)
										}
									}
									changed[i] = strings.Replace(statement, "SELECT, INSERT, UPDATE", strings.Join(remaining, ", "), 1)
								}
							}
							if err := check(changed, "NONE"); err == nil {
								t.Fatal("incomplete terminal privileges admitted")
							}
							if err := validate(changed); err == nil {
								t.Fatal("validator accepted incomplete terminal privileges")
							}
						})
					}
					for _, extra := range []string{
						"GRANT DELETE ON `clawmanager`.`system_backup_v2_alert_states` TO 'alert_publication'@'127.0.0.1'",
						"GRANT UPDATE ON `clawmanager`.`system_backup_v2_configs` TO 'alert_publication'@'127.0.0.1'",
						"GRANT INSERT ON `clawmanager`.`users` TO 'alert_publication'@'127.0.0.1'",
						"GRANT ALL PRIVILEGES ON *.* TO 'alert_publication'@'127.0.0.1'",
					} {
						if err := check(append(append([]string(nil), grants...), extra), "NONE"); err == nil {
							t.Fatal("excess privileges admitted")
						}
						if err := validate(append(append([]string(nil), grants...), extra)); err == nil {
							t.Fatal("validator accepted excess privileges")
						}
					}
					if err := check(grants, "`admin_role`@`%`"); err == nil {
						t.Fatal("active role admitted")
					}
				})
			}
			if got := controlEvidenceTableGrants(runtime, permits, false)["system_backup_v2_alert_states"]; !reflect.DeepEqual(got, []string{"SELECT"}) {
				t.Fatalf("capture-only control evidence changed: %v", got)
			}
			if _, found := formalCaptureTableGrants(runtime)["system_backup_v2_alert_states"]; found {
				t.Fatal("formal capture gained alert mutation rights")
			}
			if _, found := formalProviderPermitTableGrants(runtime)["system_backup_v2_alert_states"]; found {
				t.Fatal("provider permit capture gained alert mutation rights")
			}
		}
	}
	if _, found := publicCaptureTableGrants["system_backup_v2_alert_states"]; found {
		t.Fatal("base public capture gained alert rights")
	}
}
