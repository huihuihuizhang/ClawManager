package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func journaledGCFixture(t *testing.T, mode string) (*gcRuntimeFixture, GCFailureJournalConfig) {
	t.Helper()
	x := newGCRuntimeFixture(t, mode)
	config := failureJournalConfig(t)
	x.c.Authority.Registry.ServerUUID, x.c.Authority.Registry.Database = config.ServerUUID, config.Database
	x.db.plan[0].values[0], x.db.plan[0].values[1] = config.ServerUUID, config.Database
	x.c.Failure = nil
	return x, GCFailureJournalConfig(config)
}

func openJournaledGC(t *testing.T, x *gcRuntimeFixture, c GCFailureJournalConfig) (*GCRuntime, context.Context) {
	t.Helper()
	r, err := NewJournaledGCRuntime(x.c, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ctx, err := r.AuthenticateRequest(x.f.peer.request)
	if err != nil || r.CheckFailurePersistence() != nil {
		t.Fatal("journaled worker not ready", err)
	}
	return r, ctx
}

func TestJournaledGCDurableFailureAndSuccess(t *testing.T) {
	for _, mode := range []string{"ok", "no_proof", "chunks"} {
		t.Run(mode, func(t *testing.T) {
			x, c := journaledGCFixture(t, mode)
			r, ctx := openJournaledGC(t, x, c)
			original := x.db.record
			results := r.GC(ctx, []string{original.Manifest.Identity.ID})
			raw, err := os.ReadFile(c.Path)
			if err != nil || len(results) != 1 || r.CheckFailurePersistence() != nil {
				t.Fatal("missing durable result", err, results)
			}
			if mode == "ok" {
				if results[0] != nil || x.db.record.State != "deleted" || x.deletes.Load() != 1 || len(raw) != 0 {
					t.Fatal("successful GC did not keep journal empty", results)
				}
				return
			}
			if results[0] == nil || x.db.record.Ref != original.Ref || hash(canonical(x.db.record.Manifest)) != hash(canonical(original.Manifest)) || bytes.Count(raw, []byte{'\n'}) != 1 || len(raw) > 2049 {
				t.Fatal("failed GC discarded reference or lost its durable record", results)
			}
			var entry recoveryAuditJournalEntry
			if json.Unmarshal(raw, &entry) != nil || entry.Kind != "evidence_gc_failure" || entry.GC == nil || entry.Download != nil || entry.Bootstrap != nil || entry.Authority != nil || entry.Revocation != nil {
				t.Fatal("GC failure mislabeled as another workflow")
			}
			got := entry.GC
			if got.SchemaVersion != "system-backup-evidence-gc-failure.v1" || got.Installation != c.Installation || got.ServerUUID != c.ServerUUID || got.Database != c.Database || got.Operation != x.c.Authority.OperationID || got.Principal != r.authority.principal || got.EvidenceID != original.Manifest.Identity.ID || got.Code != "evidence_incomplete" || got.RecordedAt.IsZero() {
				t.Fatal("durable failure lost original worker/evidence identity")
			}
			for _, secret := range []string{x.c.Authority.OperationClaim, original.Ref.RelativeKey, original.Ref.ImmutableVersion, x.c.Authority.TokenFile} {
				if strings.Contains(string(raw), secret) {
					t.Fatal("private runtime fact reached journal")
				}
			}
		})
	}
}

func TestJournaledGCRefusesUnavailableStorageBeforeWork(t *testing.T) {
	for _, mode := range []string{"closed", "full", "replaced", "busy"} {
		t.Run(mode, func(t *testing.T) {
			x, c := journaledGCFixture(t, "ok")
			r, ctx := openJournaledGC(t, x, c)
			j := r.journal.storage
			switch mode {
			case "closed":
				j.Close()
			case "full":
				for j.Check() == nil {
					if r.journal.append(context.Background(), journalEvidence, "evidence_incomplete") != nil {
						t.Fatal("could not fill journal")
					}
				}
			case "replaced":
				replaceFailureJournalPath(t, j)
			case "busy":
				j.journal.mu.Lock()
				defer j.journal.mu.Unlock()
			}
			if r.CheckFailurePersistence() == nil {
				t.Fatal("unavailable journal reported healthy")
			}
			if _, err := r.AuthenticateRequest(x.f.peer.request); err == nil {
				t.Fatal("worker admitted with unavailable persistence")
			}
			results := r.GC(ctx, []string{journalEvidence})
			if len(results) != 1 || results[0] != ErrUnavailable || x.db.begins != 0 || x.db.writes != 0 || x.exchanges.Load()+x.heads.Load()+x.deletes.Load()+x.proofs.Load() != 0 {
				t.Fatal("unavailable journal reached SQL/provider", results)
			}
		})
	}
}

func TestJournaledGCLossDuringWorkKeepsReferencesAndStopsBatch(t *testing.T) {
	for _, mode := range []string{"claim_audit", "grant_recheck", "absence_proof", "result_audit"} {
		t.Run(mode, func(t *testing.T) {
			x, c := journaledGCFixture(t, "ok")
			r, ctx := openJournaledGC(t, x, c)
			closeJournal := func() { r.journal.storage.journal.file.Close() }
			switch mode {
			case "claim_audit":
				x.policy.afterAudit = func(n int) {
					if n == 1 {
						closeJournal()
					}
				}
			case "grant_recheck":
				x.policy.afterCheck = func() {
					if x.policy.deletableChecks == 2 {
						closeJournal()
					}
				}
			case "absence_proof":
				// Keep the real authority wrapper on both sides of the independent proof.
				r.store.absence = GCAbsenceVerifier{Authority: r.authority, Verifier: s3AbsenceFunc(func(ctx context.Context, request S3AbsenceRequest) (S3AbsenceProof, error) {
					proof, err := x.c.Absence.VerifyAbsent(ctx, request)
					closeJournal()
					return proof, err
				})}
			case "result_audit":
				x.policy.afterAudit = func(n int) {
					if n == 2 {
						closeJournal()
					}
				}
			}
			original := x.db.record
			results := r.GC(ctx, []string{original.Manifest.Identity.ID, original.Manifest.Identity.ID})
			if len(results) != 2 || results[0] == nil || results[1] != ErrUnavailable || r.CheckFailurePersistence() == nil || x.db.record.Ref != original.Ref || hash(canonical(x.db.record.Manifest)) != hash(canonical(original.Manifest)) {
				t.Fatal("lost journal allowed result commit or next candidate", results)
			}
			if mode == "claim_audit" && (x.db.record.State != "ready" || len(x.db.audits) != 0 || x.exchanges.Load() != 0) {
				t.Fatal("claim transaction escaped persistence guard")
			}
			if mode == "grant_recheck" && (x.deletes.Load() != 0 || x.exchanges.Load() != 0) {
				t.Fatal("provider grant escaped persistence guard")
			}
			if mode == "absence_proof" || mode == "result_audit" {
				if x.db.record.State != "deleting" || x.db.record.Claim == "" || len(x.db.audits) != 1 || x.deletes.Load() != 1 {
					t.Fatal("provider result lost reconciliation reference")
				}
			}
			raw, err := os.ReadFile(c.Path)
			if err != nil || len(raw) != 0 {
				t.Fatal("failed write manufactured durable success", err)
			}
		})
	}
}

func TestJournaledGCRejectsUnboundStorageAndClosesOwnership(t *testing.T) {
	for _, mode := range []string{"callback", "installation", "server", "database", "missing", "constructor", "close"} {
		t.Run(mode, func(t *testing.T) {
			x, c := journaledGCFixture(t, "ok")
			switch mode {
			case "callback":
				x.c.Failure = func(context.Context, string, string) {}
			case "installation":
				c.Installation = "installation_other"
			case "server":
				c.ServerUUID = "99999999-2222-4333-8444-555555555555"
			case "database":
				c.Database = "other_database"
			case "missing":
				os.Remove(c.Path)
			case "constructor":
				x.c.S3.CASHA256 = strings.Repeat("0", 64)
			}
			r, err := NewJournaledGCRuntime(x.c, c)
			if mode == "close" {
				if err != nil {
					t.Fatal(err)
				}
				r.Close()
				r.Close()
				if r.CheckFailurePersistence() == nil || r.journal.storage.journal.file != nil {
					t.Fatal("closed runtime retained journal")
				}
			} else if err == nil || r != nil {
				if r != nil {
					r.Close()
				}
				t.Fatal("unbound persistence accepted")
			}
			if mode == "missing" {
				if _, err := os.Stat(c.Path); !os.IsNotExist(err) {
					t.Fatal("journal file created")
				}
			} else if err := os.Rename(c.Path, c.Path+".closed"); err != nil {
				t.Fatal("constructor/close leaked file ownership", err)
			}
		})
	}
}

func TestJournaledGCRejectsPrivateDiagnosticsAndLatches(t *testing.T) {
	for _, mode := range []string{"evidence", "code", "context", "operation", "principal"} {
		t.Run(mode, func(t *testing.T) {
			x, c := journaledGCFixture(t, "ok")
			r, _ := openJournaledGC(t, x, c)
			var ctx context.Context = context.Background()
			id, code := journalEvidence, "evidence_incomplete"
			switch mode {
			case "evidence":
				id = "PRIVATE locator"
			case "code":
				code = "PRIVATE provider error"
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "operation":
				r.journal.operation = "PRIVATE claim"
			case "principal":
				r.journal.principal = "PRIVATE token"
			}
			if r.journal.append(ctx, id, code) == nil || r.CheckFailurePersistence() == nil || r.journal.append(context.Background(), journalEvidence, "evidence_incomplete") == nil {
				t.Fatal("invalid journal append revived")
			}
			if raw, err := os.ReadFile(c.Path); err != nil || len(raw) != 0 {
				t.Fatal("private data written", err)
			}
		})
	}
}
