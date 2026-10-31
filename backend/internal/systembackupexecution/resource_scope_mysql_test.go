package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

func TestOriginalAttemptResourceScopeRejectsShadowedDispatchedJobAndPending(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	for _, fault := range []string{"absent", "other-attempt", "other-phase", "other-target", "shadowed-prior-attempt"} {
		t.Run(fault, func(t *testing.T) {
			owner, _, admin, db, a, j, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{ConfigureGrant: func(g *c.ExecutionGrant) { g.Actions = []string{"capture", "recover"} }})
			ctx := context.Background()
			lookup := a
			intent := kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: j.Namespace, Name: j.Name}}
			switch fault {
			case "absent":
				if _, err := admin.Exec("DELETE FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=?", a.TaskPublicID, j.Namespace, j.Name); err != nil {
					t.Fatal(err)
				}
			case "other-attempt":
				lookup.AttemptNo++
			case "other-phase":
				lookup.Phase = "publish"
			case "other-target":
				lookup.TaskType = "restore_drill"
			case "shadowed-prior-attempt":
				// Explicit corrupt/prior-ledger negative fixture, never a fake
				// attempt inserted to bypass the attempt 3 positive FK checks.
				if _, err := admin.Exec("INSERT INTO system_backup_v2_attempts VALUES('backup',?,1,'capture','running',1)", a.TaskPublicID); err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec("UPDATE system_backup_v2_runtime_resources SET attempt_no=1 WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=?", a.TaskPublicID, j.Namespace, j.Name); err != nil {
					t.Fatal(err)
				}
			}
			rows, err := owner.rows(lookup)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = rows.Load(ctx, tx, intent)
			_, undispatched, pendingErr := loadPendingOriginalJob(ctx, tx, rows, b.JobPart{Intent: d.JobIntent{Namespace: j.Namespace, Name: j.Name}})
			tx.Rollback()
			if fault == "absent" {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("true physical PK absence rejected", err)
				}
			} else if err != kube.ErrJournal {
				t.Fatal("same PK wrong scope became absence/adoption", err)
			}
			if fault == "absent" {
				if !undispatched || pendingErr != nil {
					t.Fatal("true absence no longer classifies as never dispatched", pendingErr)
				}
			} else if undispatched || pendingErr == nil {
				t.Fatal("Pending classified shadowed original as never dispatched", pendingErr)
			}
			if fault == "shadowed-prior-attempt" {
				refresh()
				snapshot, err := owner.Pending(ctx, a)
				if err == nil || len(snapshot.Undispatched) != 0 {
					t.Fatal("shadowed dispatched Job became recovery Undispatched proof", err, snapshot.Undispatched)
				}
			}
		})
	}
}
