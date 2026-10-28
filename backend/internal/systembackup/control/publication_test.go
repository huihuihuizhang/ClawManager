package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql/driver"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/staging"
)

func publicationFixture(t *testing.T) (Task, Publication, artifact.Directory) {
	t.Helper()
	ctx := context.Background()
	source, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { source.Close() })
	target, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { target.Close() })
	keys := artifact.SecretKeys{"kek-one": bytes.Repeat([]byte{3}, 32)}
	dek := bytes.Repeat([]byte{7}, 32)
	binding := staging.Binding{BackupID: "sb-test", Attempt: "one", Path: "database", EnvelopeID: "database-envelope", CaptureContextHash: strings.Repeat("a", 64)}
	receipt, e := staging.SealFile(ctx, source, "database.enc", dek, binding, func(w io.Writer) error { _, e := w.Write([]byte("isolated database fixture")); return e })
	if e != nil {
		t.Fatal(e)
	}
	wrapped, e := keys.Wrap(ctx, binding, "kek-one", dek)
	if e != nil {
		t.Fatal(e)
	}
	p := Publication{KeyID: "sign-one", Bundle: artifact.Bundle{Version: artifact.Version, ID: "sb-test", Purpose: "functional_test", Scope: []string{"users", "instances"}, PolicyVersion: "fixture-one", Users: 1, Parts: []artifact.Part{{ID: "database", Receipt: receipt, Binding: binding, Key: wrapped}}}}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	d := artifact.Directory{Root: target, Keys: keys, VerifyKeys: map[string]ed25519.PublicKey{"sign-one": public}, MaxCiphertextBytes: 1 << 20, MaxPlaintextBytes: 1 << 20, Authorize: func(context.Context, string, string) error { return nil }}
	if e = d.Publish(ctx, p.Bundle, p.KeyID, private, func(part artifact.Part) (io.ReadCloser, error) { return source.Open(part.Receipt.Name) }); e != nil {
		t.Fatal(e)
	}
	source.Close() // reconciliation cannot fall back to the original source
	task := testTask()
	task.Owner = "resolver"
	task.Generation = 2
	task.LeaseUntil = time.Now().Add(time.Minute).UnixMilli()
	task.Status = "finalization_unknown"
	task.CanCancel = false
	return task, p, d
}
func publicationFenceSteps(task Task) []sqlStep {
	out := workerCommit(task)
	return append(out, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT commit_started_at_ms", rows: [][]driver.Value{{int64(1)}}})
}
func TestPublicationReconcileAuthenticatesExactIntentWithoutSource(t *testing.T) {
	for _, scenario := range []string{"committed", "tampered", "lost-control-commit"} {
		t.Run(scenario, func(t *testing.T) {
			task, p, d := publicationFixture(t)
			raw, hash, e := publicationBytes(p)
			if e != nil {
				t.Fatal(e)
			}
			if scenario == "tampered" {
				published, _ := artifact.PublishedBundle(p.Bundle)
				file, e := d.Root.OpenFile(published.Parts[0].Receipt.Name, os.O_WRONLY, 0)
				if e != nil { // Windows read-only files require an explicit test-only chmod.
					if e = d.Root.Chmod(published.Parts[0].Receipt.Name, 0600); e != nil {
						t.Fatal(e)
					}
					file, e = d.Root.OpenFile(published.Parts[0].Receipt.Name, os.O_WRONLY, 0)
					if e != nil {
						t.Fatal(e)
					}
				}
				file.WriteAt([]byte("bad"), 0)
				file.Close()
			}
			steps := workerCommit(task)
			steps = append(steps, sqlStep{contains: "SELECT intent_json,published_sha256", rows: [][]driver.Value{{raw, hash}}})
			steps = append(steps, publicationFenceSteps(task)...)
			steps = append(steps, publicationFenceSteps(task)...)
			if scenario != "tampered" {
				steps = append(steps, workerCommit(task)...)
				steps = append(steps, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT published_sha256,commit_started_at_ms", rows: [][]driver.Value{{hash, int64(1)}}}, sqlStep{contains: "SET committed=TRUE", affected: 1})
				steps = append(steps, workerCommit(task)...)
			}
			store, script := scriptStore(t, steps...)
			if scenario == "lost-control-commit" {
				script.loseCommit = true
			}
			publisher := Publisher{Store: store, Directory: d}
			e = publisher.Reconcile(context.Background(), task)
			if scenario == "committed" {
				if e != nil || script.commits != 1 {
					t.Fatal("exact publication not confirmed", e)
				}
			} else if e == nil {
				t.Fatal("uncertain or tampered artifact confirmed")
			}
			if scenario == "tampered" && script.writes != 0 {
				t.Fatal("bad artifact wrote confirmation")
			}
		})
	}
}
func TestCommitWindowRequiresPersistedPublicationIntent(t *testing.T) {
	task := testTask()
	task.Status = "publishing"
	task.Owner = "controller"
	task.Generation = 1
	task.LeaseUntil = time.Now().Add(time.Minute).UnixMilli()
	steps := workerCommit(task)
	steps = append(steps, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT commit_started_at_ms"})
	store, script := scriptStore(t, steps...)
	if _, e := store.BeginCommit(context.Background(), task); e != ErrConflict || script.writes != 0 {
		t.Fatal("cancellation closed without immutable intent", e)
	}
}
func TestBackupSuccessRequiresConfirmedPublication(t *testing.T) {
	task := testTask()
	task.Status = "publishing"
	task.CanCancel = false
	task.Owner = "controller"
	task.Generation = 1
	task.LeaseUntil = time.Now().Add(time.Minute).UnixMilli()
	steps := workerCommit(task)
	steps = append(steps, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT (SELECT COUNT(*)", rows: [][]driver.Value{{int64(0)}}}, sqlStep{contains: "SELECT committed", rows: [][]driver.Value{{false}}})
	store, script := scriptStore(t, steps...)
	if _, e := store.Advance(context.Background(), task, "succeeded", ""); e != ErrConflict || script.writes != 0 {
		t.Fatal("unconfirmed artifact marked successful", e)
	}
}
