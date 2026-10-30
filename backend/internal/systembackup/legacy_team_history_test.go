package systembackup

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyTeamHistoryPagesAndDetectsUnfinishedBeyondFirstPage(t *testing.T) {
	s := teamDataJobFixture(t)
	ctx := context.Background()
	for i := 0; i < 53; i++ {
		j := failRetryFixture(t, s, "backup", "")
		if _, err := s.db.Exec("UPDATE system_team_data_backup_jobs SET created_at='2026-10-30 00:00:00',status='succeeded',phase='complete' WHERE public_id=?", j.ID); err != nil {
			t.Fatal(err)
		}
	}
	var oldest string
	if err := s.db.QueryRow("SELECT public_id FROM system_team_data_backup_jobs ORDER BY created_at,public_id LIMIT 1").Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE system_team_data_backup_jobs SET status='running',phase='capture_mysql',owner_id='retired-owner' WHERE public_id=?", oldest); err != nil {
		t.Fatal(err)
	}
	store := Store{DB: s.db, InstallationID: "test-history"}
	page, err := store.LegacyTeamHistory(ctx, "")
	if err != nil || len(page.Items) != 50 || page.NextCursor == "" || page.UnfinishedCount != 1 || !page.HistoryOnly || page.WritesAvailable {
		t.Fatalf("first page: %+v %v", page, err)
	}
	seen := map[string]bool{}
	for _, j := range page.Items {
		seen[j.ID] = true
	}
	next, err := store.LegacyTeamHistory(ctx, page.NextCursor)
	if err != nil || len(next.Items) != 3 || next.NextCursor != "" || next.UnfinishedCount != 1 {
		t.Fatalf("second page: %+v %v", next, err)
	}
	for _, j := range next.Items {
		if seen[j.ID] {
			t.Fatal("duplicate page entry", j.ID)
		}
		seen[j.ID] = true
	}
	j, err := store.LegacyTeamHistoryJob(ctx, oldest)
	if err != nil || j.Status != "running" || !j.RequiresInspection || j.Owner != "retired-owner" {
		t.Fatalf("original operation changed: %+v %v", j, err)
	}
	raw, err := json.Marshal(j)
	if err != nil || strings.Contains(string(raw), "retired-owner") || strings.Contains(string(raw), s.configHash) {
		t.Fatal("internal owner or config leaked", err)
	}
	if _, err = store.LegacyTeamHistory(ctx, "invalid"); err == nil || err.Error() != "not_found" {
		t.Fatal("invalid cursor", err)
	}
	for _, update := range []string{
		"operation='restore',status='failed',phase='restore_mysql'",
		"operation='cleanup',status='canceled',phase='cleanup'",
		"operation='backup',status='failed',phase='interrupted'",
		"operation='backup',status='failed',phase='publishing',error_code='operation_result_unconfirmed'",
	} {
		if _, err = s.db.Exec("UPDATE system_team_data_backup_jobs SET "+update+" WHERE public_id=?", oldest); err != nil {
			t.Fatal(err)
		}
		current, e := store.LegacyTeamHistory(ctx, "")
		if e != nil || current.UnfinishedCount != 1 {
			t.Fatal("uncertain result hidden by terminal status", update, current.UnfinishedCount, e)
		}
		detail, e := store.LegacyTeamHistoryJob(ctx, oldest)
		if e != nil || !detail.RequiresInspection {
			t.Fatal("inspection summary/detail drift", update, e)
		}
	}
}

func TestLegacyTeamHistoryInspectionNeverGuessesUnknownSuccess(t *testing.T) {
	for _, j := range []TeamDataJob{{Status: "pending"}, {Status: "running"}, {Status: "canceling"}, {Status: "future-state"}, {Status: "succeeded", Phase: "retry_pending"}, {Status: "succeeded", Phase: "retry_blocked"}, {Status: "failed", Phase: "interrupted"}, {Operation: "restore", Status: "failed"}, {Operation: "cleanup", Status: "canceled"}, {Status: "failed", Error: "backup_result_unconfirmed"}} {
		if !legacyTeamHistoryEntry(j).RequiresInspection {
			t.Fatal("unsafe historical operation hidden", j)
		}
	}
	if legacyTeamHistoryEntry(TeamDataJob{Status: "succeeded", Phase: "complete"}).RequiresInspection {
		t.Fatal("completed history mislabeled")
	}
}
