package domain_test

import (
	"context"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
)

func TestRouting061PublicSQLWorkerAndIndependentReader(t *testing.T) {
	f := newWorkerFixture(t)
	f.sql.Close()
	f.sql = domain.NewTestRoutingSQLFixture()
	t.Cleanup(f.sql.Close)
	f.restore.Database.Dependencies = f.sql.Policy.Dependencies
	captured, err := worker.RunDatabase(context.Background(), f.capture, worker.DatabaseEnvironment{Database: f.sql.Source, Staging: f.store, Key: f.key, Check: allowWorker})
	if err != nil || captured.Rows != 7 || f.sql.SourceWrites() != 0 {
		t.Fatal("capture", err)
	}
	f.restore.Receipt = captured.Receipt
	f.sql.Source.Close()
	restored, err := f.restoreData(allowWorker)
	if err != nil || !restored.Quarantined || f.sql.Commits() != 1 {
		t.Fatal("restore", err)
	}
	f.sql.Target.Close()
	v := f.restore
	v.Operation, v.Binding, v.Receipt = "verify-database", v.Database.EvidenceBinding, restored.Evidence
	d := *v.Database
	d.Placements, d.Configs, d.EvidenceName = nil, nil, ""
	v.Database = &d
	reader := f.sql.Verifier()
	defer reader.Close()
	writes := f.sql.Writes()
	verified, err := worker.RunDatabase(context.Background(), v, worker.DatabaseEnvironment{Database: reader, Staging: f.evidence, Key: f.key, Check: allowWorker})
	if err != nil || !verified.Verified || f.sql.Writes() != writes {
		t.Fatal("independent verification", err)
	}
}
