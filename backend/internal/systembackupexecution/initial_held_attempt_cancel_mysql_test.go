package systembackupexecution

import (
	"context"
	"os"
	"testing"
)

func TestInitialHeldSnapshotScopesLatestAttemptAndCurrentCancelMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	owner, _, admin, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{})
	refresh()
	ctx := context.Background()
	for _, test := range []struct {
		name, kind, status string
		other, allowed     bool
	}{
		{"pending-cancel", "cancel", "pending", false, false},
		{"running-cancel", "cancel", "running", false, false},
		{"finished-cancel", "cancel", "succeeded", false, true},
		{"other-task-cancel", "cancel", "pending", true, true},
		{"newer-original-attempt", "attempt", "running", false, false},
		{"other-task-attempt", "attempt", "running", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := a.TaskPublicID
			if test.other {
				target = "sbk_00000000-0000-4000-8000-000000000000"
			}
			if test.kind == "cancel" {
				result, err := admin.Exec("INSERT INTO system_backup_v2_operations(origin_installation_id,target_type,target_public_id,operation_type,status) VALUES(?,'backup',?,'cancel',?)", a.InstallationID, target, test.status)
				if err != nil {
					t.Fatal(err)
				}
				count, err := result.RowsAffected()
				if err != nil || count != 1 {
					t.Fatal("cancel was not inserted", count, err)
				}
				id, err := result.LastInsertId()
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := admin.Exec("DELETE FROM system_backup_v2_operations WHERE id=?", id); err != nil {
						t.Error(err)
					}
				}()
				var observed int
				if admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_operations WHERE id=? AND origin_installation_id=? AND target_type='backup' AND target_public_id=? AND operation_type='cancel' AND status=?", id, a.InstallationID, target, test.status).Scan(&observed) != nil || observed != 1 {
					t.Fatal("cancel independent readback")
				}
			} else {
				result, err := admin.Exec("INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status,row_version) VALUES('backup',?,?,'capture',?,1)", target, a.AttemptNo+1, test.status)
				if err != nil {
					t.Fatal(err)
				}
				count, err := result.RowsAffected()
				if err != nil || count != 1 {
					t.Fatal("attempt was not inserted", count, err)
				}
				defer func() {
					if _, err := admin.Exec("DELETE FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='capture'", target, a.AttemptNo+1); err != nil {
						t.Error(err)
					}
				}()
				var latest uint64
				if admin.QueryRow("SELECT attempt_no FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND phase='capture' ORDER BY attempt_no DESC LIMIT 1", target).Scan(&latest) != nil || latest != a.AttemptNo+1 {
					t.Fatal("newer attempt independent readback")
				}
			}
			tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			guard, bindErr := owner.Gate.Authority.Bind(ctx, tx, a)
			if bindErr == nil {
				bindErr = guard.Recheck(ctx, tx)
			}
			tx.Rollback()
			if (bindErr == nil) != test.allowed {
				t.Fatal("initial held facts selected wrong current task/attempt/cancel scope", test.allowed, bindErr)
			}
		})
	}
}
