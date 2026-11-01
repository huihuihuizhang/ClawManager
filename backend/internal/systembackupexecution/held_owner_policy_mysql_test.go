package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

func assertHeldOwnerCurrentPolicy(t *testing.T, owner *PublicJobOwner, admin *sql.DB, a d.Authority) {
	t.Helper()
	ctx := context.Background()
	policy, ok := owner.Gate.Authority.Authorization.(deploymentAuthorization)
	if !ok || policy.Service == nil {
		t.Fatal("original deployment owner policy missing")
	}
	var database, account string
	if owner.Gate.Authority.DB.QueryRowContext(ctx, "SELECT DATABASE(),CURRENT_USER()").Scan(&database, &account) != nil {
		t.Fatal("owned policy fixture identity")
	}
	parts := strings.Split(account, "@")
	run := strings.TrimPrefix(database, "ad_d_consumer_")
	decoded, err := hex.DecodeString(run)
	if err != nil || len(decoded) != 8 || database != "ad_d_consumer_"+run || len(parts) != 2 || parts[0] != "ad_d_read_"+run || parts[1] != "127.0.0.1" {
		t.Fatal("current policy mutation fixture is not privately owned")
	}
	// Only this narrow private fixture can mutate its own profile after Bind.
	// This is not a production role/admission or formal-DDL mutation claim.
	if _, err := admin.ExecContext(ctx, "GRANT UPDATE ON `"+database+"`.`system_backup_v2_execution_inputs` TO '"+parts[0]+"'@'127.0.0.1'"); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"profile_json", "profile_sha256", "effective-enabled", "forward-flag", "config-file"} {
		for _, combined := range []bool{false, true} {
			name := "separate-"
			if combined {
				name = "combined-"
			}
			t.Run(name+mutation, func(t *testing.T) {
				store := owner.Gate.Authority
				if !combined {
					store.Authorization = dSeparateHeldAuthorization{store.Authorization}
				}
				tx, err := store.DB.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				guard, err := store.Bind(ctx, tx, a)
				if err != nil || guard.Recheck(ctx, tx) != nil {
					t.Fatal("original current owner baseline", mutation, combined, err)
				}
				beforeRows := providerStageRows(t, ctx, tx)
				var rejected error
				func() {
					switch mutation {
					case "forward-flag":
						original := policy.Service.ForwardEnabled
						policy.Service.ForwardEnabled = false
						defer func() { policy.Service.ForwardEnabled = original }()
					case "config-file":
						path := policy.Service.ConfigPath
						withdrawn := path + ".test-withdrawn"
						if err := os.Rename(path, withdrawn); err != nil {
							t.Fatal("actual original deployment file withdrawal", err)
						}
						defer func() {
							if err := os.Rename(withdrawn, path); err != nil {
								t.Error("original fixture config restoration", err)
							}
						}()
					default:
						table, column, value := "system_backup_v2_execution_inputs", mutation, "CONCAT(profile_json,' ')"
						if mutation == "profile_sha256" {
							value = "REPEAT('f',64)"
						} else if mutation == "effective-enabled" {
							table, column, value = "system_backup_v2_installation_state", "last_effective_enabled", "0"
						}
						var original, changed []byte
						if tx.QueryRowContext(ctx, "SELECT "+column+" FROM "+table+" WHERE origin_installation_id=?", a.InstallationID).Scan(&original) != nil {
							t.Fatal("original current owner field")
						}
						result, err := tx.ExecContext(ctx, "UPDATE "+table+" SET "+column+"="+value+" WHERE origin_installation_id=?", a.InstallationID)
						if err != nil {
							t.Fatal(err)
						}
						count, err := result.RowsAffected()
						if err != nil || count != 1 || tx.QueryRowContext(ctx, "SELECT "+column+" FROM "+table+" WHERE origin_installation_id=?", a.InstallationID).Scan(&changed) != nil || bytes.Equal(original, changed) {
							t.Fatal("owner current field change not independently observed", count, err)
						}
					}
					rejected = guard.Recheck(ctx, tx)
				}()
				if rejected == nil || !guard.ValidUntil().IsZero() || guard.Recheck(ctx, tx) == nil || providerStageRows(t, ctx, tx) != beforeRows {
					t.Fatal("current owner callback was bypassed/revived or wrote original rows", mutation, combined, rejected)
				}
			})
		}
	}
}
