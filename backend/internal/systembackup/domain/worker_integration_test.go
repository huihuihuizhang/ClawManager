package domain_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
)

type workerFixture struct {
	sql              *domain.TestSQLFixture
	capture, restore worker.Request
	store, evidence  *os.Root
	key              []byte
}

func newWorkerFixture(t *testing.T) *workerFixture {
	t.Helper()
	f := &workerFixture{sql: domain.NewTestSQLFixture(), key: bytes.Repeat([]byte{19}, 32)}
	t.Cleanup(f.sql.Close)
	var err error
	f.store, err = os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	f.evidence, err = os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.evidence.Close() })
	d := worker.DatabaseSpec{Address: "fixture.invalid:3306", Name: "source", ServerUUID: "fixture-server", TLSServerName: "fixture.invalid", RootCA: []byte("unused test-driver CA"), MaxRows: 100, MaxMemoryBytes: 1 << 20}
	f.capture = worker.Request{Version: worker.Version, Operation: "capture-database", Database: &d, Deadline: time.Now().Add(time.Minute), ArtifactName: "source.enc", MaxArchiveBytes: 1 << 20, MaxCompressedBytes: 1 << 20, Binding: staging.Binding{BackupID: "fixture", Attempt: "1", Path: "mysql/domain", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "fixture-memory-key"}}
	f.restore = f.capture
	f.restore.Operation = "restore-database"
	f.restore.ArtifactName = ""
	f.restore.PolicyVersion = "fixture-v1"
	target := d
	target.Name = "cm_drill_fixture"
	target.Placements = f.sql.Policy.Placements
	target.EvidenceName = "expected.enc"
	target.EvidenceBinding = f.capture.Binding
	target.EvidenceBinding.Path = "mysql/expected"
	f.restore.Database = &target
	return f
}
func allowWorker(context.Context, string, worker.Request) error { return nil }
func (f *workerFixture) captureData(t *testing.T) {
	t.Helper()
	r, err := worker.RunDatabase(context.Background(), f.capture, worker.DatabaseEnvironment{Database: f.sql.Source, Staging: f.store, Key: f.key, Check: allowWorker})
	if err != nil {
		t.Fatal(err)
	}
	if r.Tables != 5 || r.Rows != 6 || f.sql.SourceWrites() != 0 {
		t.Fatal("capture not lossless/read-only")
	}
	f.restore.Receipt = r.Receipt
	data, err := f.store.ReadFile(r.Receipt.Name)
	if err != nil || bytes.Contains(data, []byte("synthetic-source-hash")) {
		t.Fatal("plaintext staging")
	}
	f.sql.Source.Close()
}
func (f *workerFixture) restoreData(check func(context.Context, string, worker.Request) error) (worker.Result, error) {
	return worker.RunDatabase(context.Background(), f.restore, worker.DatabaseEnvironment{Database: f.sql.Target, Staging: f.store, Evidence: f.evidence, Key: f.key, Check: check})
}
func TestDatabaseWorkerOfflineCaptureRestoreAndIndependentVerify(t *testing.T) {
	f := newWorkerFixture(t)
	f.captureData(t)
	r, err := f.restoreData(allowWorker)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Quarantined || r.Verified || r.Evidence.Name != "expected.enc" || f.sql.Commits() != 1 {
		t.Fatal("missing restore evidence")
	}
	f.sql.Target.Close()
	v := f.restore
	v.Operation = "verify-database"
	v.Binding = v.Database.EvidenceBinding
	v.Receipt = r.Evidence
	d := *v.Database
	d.Placements = nil
	d.Configs = nil
	d.EvidenceName = ""
	v.Database = &d
	verifier := f.sql.Verifier()
	defer verifier.Close()
	env := worker.DatabaseEnvironment{Database: verifier, Staging: f.evidence, Key: f.key, Check: allowWorker}
	before := f.sql.Writes()
	verified, err := worker.RunDatabase(context.Background(), v, env)
	if err != nil || !verified.Verified || !verified.Quarantined || f.sql.Writes() != before {
		t.Fatal("independent verification failed", err)
	}
	f.sql.SetTargetGrant("GRANT ALL PRIVILEGES ON `cm_drill_fixture`.* TO 'writer'@'localhost'")
	if _, err = worker.RunDatabase(context.Background(), v, env); err == nil {
		t.Fatal("writer accepted as verifier")
	}
	f.sql.SetTargetGrant("GRANT SELECT ON `cm_drill_fixture`.* TO 'verifier'@'localhost'")
	f.sql.Tamper()
	if _, err = worker.RunDatabase(context.Background(), v, env); err == nil {
		t.Fatal("tampered database passed")
	}
}
func TestDatabaseWorkerFailuresPreserveBootstrapAndNeverPublish(t *testing.T) {
	for _, mode := range []string{"missing-authorization", "wrong-key", "wrong-uuid", "evidence-collision", "lost-before-commit", "wrong-input-hash", "production-target", "memory-limit"} {
		t.Run(mode, func(t *testing.T) {
			f := newWorkerFixture(t)
			f.captureData(t)
			before, _ := domain.Digest(f.sql.Snapshot())
			check := allowWorker
			switch mode {
			case "missing-authorization":
				check = nil
			case "wrong-key":
				f.key = bytes.Repeat([]byte{27}, 32)
			case "wrong-uuid":
				f.restore.Database.ServerUUID = "other"
			case "evidence-collision":
				if err := f.evidence.WriteFile("expected.enc", []byte("another owner"), 0600); err != nil {
					t.Fatal(err)
				}
			case "lost-before-commit":
				check = func(_ context.Context, p string, _ worker.Request) error {
					if p == "before-database-commit" {
						return errors.New("lost fence")
					}
					return nil
				}
			case "wrong-input-hash":
				f.restore.Receipt.SHA256 = strings.Repeat("b", 64)
			case "production-target":
				f.restore.Database.Name = "clawmanager"
			case "memory-limit":
				f.restore.Database.MaxMemoryBytes = 1
			}
			if _, err := f.restoreData(check); err == nil {
				t.Fatal("unsafe restore succeeded")
			}
			after, _ := domain.Digest(f.sql.Snapshot())
			if before != after || f.sql.Commits() != 0 {
				t.Fatal("failed restore changed bootstrap")
			}
			if mode != "evidence-collision" && mode != "lost-before-commit" && f.sql.Writes() != 0 {
				t.Fatal("wrote before integrity/identity checks")
			}
			if mode == "evidence-collision" {
				b, _ := f.evidence.ReadFile("expected.enc")
				if string(b) != "another owner" {
					t.Fatal("overwrote evidence")
				}
			}
		})
	}
}
func TestDatabaseWorkerRejectsSourceIdentityAndWriteGrants(t *testing.T) {
	for _, mode := range []string{"uuid", "grant"} {
		t.Run(mode, func(t *testing.T) {
			f := newWorkerFixture(t)
			if mode == "uuid" {
				f.capture.Database.ServerUUID = "wrong"
			} else {
				f.sql.SetSourceGrant("GRANT ALL PRIVILEGES ON `source`.* TO 'app'@'localhost'")
			}
			if _, err := worker.RunDatabase(context.Background(), f.capture, worker.DatabaseEnvironment{Database: f.sql.Source, Staging: f.store, Key: f.key, Check: allowWorker}); err == nil {
				t.Fatal("unapproved source captured")
			}
			if _, err := f.store.Stat("source.enc"); !os.IsNotExist(err) {
				t.Fatal("failed capture published artifact")
			}
		})
	}
}
