package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// This named fixture has only ONE original portable-workspace part. The actual
// service must take the original task claim, enumerate the complete original
// plan, and reject it before producing index data or making a native write.
func TestAOriginalPublicationFirstForwardRejectsIncompleteOriginalPlan(t *testing.T) {
	x, _, state := newAOriginalPublicationService(t)
	h, ctx := x.history, context.Background()
	h.service.staging = h.owner.Staging
	var before int
	if h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_events WHERE target_public_id=? AND event_type=?`, h.original.TaskPublicID, c.TaskClaimAcquiredEvent).Scan(&before) != nil {
		t.Fatal("original claim receipt count")
	}
	version, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Release(ctx, h.token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err = h.service.RunPublicationPass(ctx); !errors.Is(err, c.ErrExecutionRecord) {
		t.Fatal("actual first-forward did not reject incomplete original part set", err)
	}
	var after, actions, assembly int
	var owner sql.NullString
	var status string
	var actualVersion uint64
	var eligible bool
	if h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_events WHERE target_public_id=? AND event_type=?`, h.original.TaskPublicID, c.TaskClaimAcquiredEvent).Scan(&after) != nil || after != before+1 {
		t.Fatal("first-forward did not acquire same original task through common receipt", before, after)
	}
	if h.db.QueryRow(`SELECT controller_owner,row_version,status,acceptance_eligible FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&owner, &actualVersion, &status, &eligible) != nil || owner.Valid || actualVersion <= version || status != "validating" || eligible {
		t.Fatal("first-forward changed terminal/eligibility or failed to release exact claim")
	}
	if h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_public_id=?`, h.original.TaskPublicID).Scan(&actions) != nil || actions != 0 || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=?`, publicationMaterialID(h.original.InstallationID, h.original.TaskPublicID, h.original.AttemptNo)).Scan(&assembly) != nil || assembly != 0 || state.puts != 0 || x.decrypts.Load() != 0 {
		t.Fatal("incomplete original plan produced assembly, provider use or native write", actions, assembly, state.puts, x.decrypts.Load())
	}
}
