package domain_test

import (
	"context"
	"errors"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
)

func TestOperation077PublicWorkerFreezesPlanAndRollsBack(t *testing.T) {
	for _, lostFence := range []bool{false, true} {
		f := newWorkerFixture(t)
		f.sql.Close()
		f.sql = domain.NewTestOperationSQLFixture()
		t.Cleanup(f.sql.Close)
		f.restore.Database.Dependencies = f.sql.Policy.Dependencies
		f.restore.Database.Configs = f.sql.Policy.Configs.(domain.JSONRegistry)
		captured, err := worker.RunDatabase(context.Background(), f.capture, worker.DatabaseEnvironment{Database: f.sql.Source, Staging: f.store, Key: f.key, Check: allowWorker})
		if err != nil || captured.Rows != 12 || f.sql.SourceWrites() != 0 {
			t.Fatal("capture", err)
		}
		f.restore.Receipt = captured.Receipt
		f.sql.Source.Close()
		before, _ := domain.Digest(f.sql.Snapshot())
		check := func(_ context.Context, phase string, request worker.Request) error {
			// Both the original caller's map and the callback's copy are untrusted
			// after freezing. Neither may change the interruption time in SQL.
			for _, mapping := range []map[string]domain.TableAdapter{f.restore.Database.Dependencies, request.Database.Dependencies} {
				a := mapping["northbound_operations"]
				a.InterruptedAt = "2099-01-01T00:00:00Z"
				mapping["northbound_operations"] = a
			}
			if lostFence && phase == "before-database-commit" {
				return errors.New("fixture final fence lost")
			}
			return nil
		}
		r, err := f.restoreData(check)
		if lostFence {
			after, _ := domain.Digest(f.sql.Snapshot())
			if err == nil || before != after || f.sql.Commits() != 0 || f.sql.Writes() == 0 {
				t.Fatal("operation rollback", err)
			}
			continue
		}
		if err != nil || !r.Quarantined || f.sql.Commits() != 1 {
			t.Fatal("restore", err)
		}
		seen := false
		for _, table := range f.sql.Snapshot().Tables {
			if table.Name == "northbound_operations" {
				seen = len(table.Rows) == 6
				if table.Rows[0]["finished_at"].String() != "2026-11-01 08:00:00.123456" {
					t.Fatal("callback changed frozen timestamp")
				}
			}
		}
		if !seen {
			t.Fatal("operation rows missing")
		}
		f.sql.Target.Close()
		v := f.restore
		v.Operation, v.Binding, v.Receipt = "verify-database", v.Database.EvidenceBinding, r.Evidence
		d := *v.Database
		d.Placements, d.Configs, d.EvidenceName = nil, nil, ""
		v.Database = &d
		verifier := f.sql.Verifier()
		defer verifier.Close()
		writes := f.sql.Writes()
		verified, err := worker.RunDatabase(context.Background(), v, worker.DatabaseEnvironment{Database: verifier, Staging: f.evidence, Key: f.key, Check: allowWorker})
		if err != nil || !verified.Verified || f.sql.Writes() != writes {
			t.Fatal("independent operation verification", err)
		}
	}
}
