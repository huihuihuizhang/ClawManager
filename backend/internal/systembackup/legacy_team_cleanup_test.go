package systembackup

import (
	"context"
	"strings"
	"testing"
)

func TestLegacyCleanupInventoryPreservesUnknownResourcesAndOriginalState(t *testing.T) {
	s := teamDataJobFixture(t)
	job := failRetryFixture(t, s, "restore", "sbk_"+strings.Repeat("a", 32))
	ctx := context.Background()
	if _, err := s.db.Exec("UPDATE system_team_data_backup_jobs SET provisioning_json=JSON_OBJECT('database',JSON_OBJECT('target',?,'state','created','server','restore-server'),'bucket',JSON_OBJECT('target',?,'state','intent')),status='running',owner_id='old-executor' WHERE public_id=?", teamDataDatabase(job.ID), teamDataBucket(job.ID), job.ID); err != nil {
		t.Fatal(err)
	}
	store := Store{DB: s.db, InstallationID: "historical-installation"}
	location := LegacyRecoveryLocation{ConfigSHA256: s.configHash, Namespace: "cm-recovery", RestoreRoot: "/isolated/restores", SourceRoot: "/source/workspaces", SourceDatabase: "source", SourceBucket: "source-bucket"}
	op := "sop_11111111-1111-4111-8111-111111111111"
	plan, err := store.ReadLegacyCleanupInventory(ctx, job.ID, op, location)
	if err != nil || !plan.RequiresOriginalExitProof || len(plan.Candidates) != 4 || plan.OriginalStatus != "running" {
		t.Fatal("ownership gap hidden", plan, err)
	}
	for _, candidate := range plan.Candidates {
		if candidate.Blocker == "" {
			t.Fatal("candidate treated as deletion permission")
		}
	}
	unchanged, err := s.Get(ctx, job.ID)
	if err != nil || unchanged.Status != "running" || unchanged.Owner != "old-executor" {
		t.Fatal("legacy state changed", err)
	}
	wrong := location
	wrong.ConfigSHA256 = strings.Repeat("b", 64)
	if _, err = store.ReadLegacyCleanupInventory(ctx, job.ID, op, wrong); err == nil {
		t.Fatal("current/foreign config substituted")
	}
	wrong = location
	wrong.RestoreRoot = "/source/workspaces/restore"
	if _, err = store.ReadLegacyCleanupInventory(ctx, job.ID, op, wrong); err == nil {
		t.Fatal("source-overlapping location accepted")
	}
	if _, err = s.db.Exec("UPDATE system_team_data_backup_jobs SET provisioning_json=JSON_OBJECT('database',JSON_OBJECT('target','source','state','created','server','restore-server')) WHERE public_id=?", job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ReadLegacyCleanupInventory(ctx, job.ID, op, location); err == nil {
		t.Fatal("source cleanup candidate accepted")
	}
}
