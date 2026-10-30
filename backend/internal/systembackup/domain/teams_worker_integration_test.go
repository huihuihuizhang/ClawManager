package domain_test

import (
	"context"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
)

func TestPublicSQLWorkerKeepsNonemptyOwnerTeamAndDoesNotReplay(t *testing.T) {
	f := newWorkerFixture(t)
	f.sql.Close()
	f.sql = domain.NewTestTeamsSQLFixture()
	t.Cleanup(f.sql.Close)
	d := *f.restore.Database
	d.Placements, d.TeamPlacements = f.sql.Policy.Placements, f.sql.Policy.TeamPlacements
	d.Configs = f.sql.Policy.Configs.(domain.JSONRegistry)
	d.Dependencies = f.sql.Policy.Dependencies
	f.restore.Database = &d
	captured, err := worker.RunDatabase(context.Background(), f.capture, worker.DatabaseEnvironment{Database: f.sql.Source, Staging: f.store, Key: f.key, Check: allowWorker})
	if err != nil || f.sql.SourceWrites() != 0 {
		t.Fatal("shared SQL capture", err)
	}
	f.restore.Receipt = captured.Receipt
	f.sql.Source.Close() // Recovery must not depend on live source data.
	restored, err := f.restoreData(allowWorker)
	if err != nil || restored.Verified || !restored.Quarantined {
		t.Fatal("restore", restored, err)
	}
	plan := f.sql.Snapshot()
	if err := domain.VerifyTeamQuarantine(plan); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, table := range plan.Tables {
		counts[table.Name] = len(table.Rows)
		for _, row := range table.Rows {
			switch table.Name {
			case "teams":
				if row["owner"].String() != "owner-c" || row["display_name"].String() != "保留 owner 名称" {
					t.Fatal("owner data lost")
				}
			case "team_members":
				if row["icon_key"].String() != "crown" {
					t.Fatal("member icon lost")
				}
			case "team_tasks":
				if !strings.Contains(row["result_json"].String(), "中断前结果") {
					t.Fatal("partial result lost")
				}
			case "team_work_items":
				if !strings.Contains(row["artifact_refs_json"].String(), "results/report.bin") {
					t.Fatal("artifact references lost")
				}
			case "northbound_operations":
				if row["status"].String() != "failed" || !row["lease_owner"].Null {
					t.Fatal("B fixture operation can replay")
				}
			}
		}
	}
	if counts["team_work_items"] != 8 || counts["team_events"] != 1 || counts["custom_team_templates"] != 1 || counts["owner_team_provision_steps"] != 1 || counts["team_event_outbox"] != 0 || counts["owner_team_admission_locks"] != 0 {
		t.Fatal("C data dropped or old work copied", counts)
	}
	v := f.restore
	v.Operation, v.Binding, v.Receipt = "verify-database", d.EvidenceBinding, restored.Evidence
	vd := d
	vd.Placements, vd.TeamPlacements, vd.Configs, vd.EvidenceName = nil, nil, nil, ""
	v.Database = &vd
	reader := f.sql.Verifier()
	defer reader.Close()
	before := f.sql.Writes()
	verified, err := worker.RunDatabase(context.Background(), v, worker.DatabaseEnvironment{Database: reader, Staging: f.evidence, Key: f.key, Check: allowWorker})
	if err != nil || !verified.Verified || f.sql.Writes() != before {
		t.Fatal("independent read-only verification", verified, err)
	}
}
