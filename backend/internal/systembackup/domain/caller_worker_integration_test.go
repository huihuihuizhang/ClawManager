package domain_test

import (
	"context"
	"errors"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
)

// Exercises actual staging/worker/SQL transaction/readback with a named SQL
// driver. allowWorker is a fixture only, not source or target authentication.
func TestCaller066DatabaseWorkerTransactionAndReadback(t *testing.T) {
	for _, failCommit := range []bool{false, true} {
		name := "restore-and-independent-verify"
		if failCommit {
			name = "lost-final-fence-rolls-back"
		}
		t.Run(name, func(t *testing.T) {
			f := newWorkerFixture(t)
			f.sql.Close()
			f.sql = domain.NewTestCallerSQLFixture()
			t.Cleanup(f.sql.Close)
			f.restore.Database.Dependencies = f.sql.Policy.Dependencies
			captured, err := worker.RunDatabase(context.Background(), f.capture, worker.DatabaseEnvironment{Database: f.sql.Source, Staging: f.store, Key: f.key, Check: allowWorker})
			if err != nil || captured.Tables != 6 || captured.Rows != 7 || f.sql.SourceWrites() != 0 {
				t.Fatal("caller capture failed", err)
			}
			f.restore.Receipt = captured.Receipt
			f.sql.Source.Close()
			before, _ := domain.Digest(f.sql.Snapshot())
			check := allowWorker
			if failCommit {
				check = func(_ context.Context, phase string, _ worker.Request) error {
					if phase == "before-database-commit" {
						return errors.New("fixture final fence lost")
					}
					return nil
				}
			}
			r, err := f.restoreData(check)
			if failCommit {
				after, _ := domain.Digest(f.sql.Snapshot())
				if err == nil || before != after || f.sql.Commits() != 0 || f.sql.Writes() == 0 {
					t.Fatal("transaction did not roll back after final fence loss", err)
				}
				return
			}
			if err != nil || !r.Quarantined || f.sql.Commits() != 1 {
				t.Fatal("caller restore failed", err)
			}
			found := false
			for _, table := range f.sql.Snapshot().Tables {
				if table.Name == "northbound_caller_policies" {
					found = len(table.Rows) == 1
					row := table.Rows[0]
					if row["enabled"].String() != "0" || row["api_keys_json"].String() != "[]" || row["api_keys_version"].String() != "9223372036854775807" || row["updated_by"].String() != "1" {
						t.Fatal("actual SQL insert lost caller policy semantics")
					}
				}
			}
			if !found {
				t.Fatal("caller table omitted")
			}
			f.sql.Target.Close()
			v := f.restore
			v.Operation, v.Binding, v.Receipt = "verify-database", v.Database.EvidenceBinding, r.Evidence
			d := *v.Database
			d.Placements, d.Configs, d.EvidenceName = nil, nil, ""
			v.Database = &d
			verifier := f.sql.Verifier()
			defer verifier.Close()
			env := worker.DatabaseEnvironment{Database: verifier, Staging: f.evidence, Key: f.key, Check: allowWorker}
			writes := f.sql.Writes()
			verified, err := worker.RunDatabase(context.Background(), v, env)
			if err != nil || !verified.Verified || f.sql.Writes() != writes {
				t.Fatal("caller independent readback failed", err)
			}
			f.sql.TamperCallerKeys()
			if _, err := worker.RunDatabase(context.Background(), v, env); err == nil || f.sql.Writes() != writes {
				t.Fatal("independent verifier accepted changed caller credentials")
			}
		})
	}
}
