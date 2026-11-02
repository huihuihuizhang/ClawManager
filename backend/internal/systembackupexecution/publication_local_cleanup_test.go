package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"testing"

	"clawreef/internal/systembackup/staging"
)

// Incomplete private handles must reject before SQL or any filesystem action.
// These negatives confer no SQL, native cleanup or final acceptance proof.
func TestPublicationCompleteCleanupRejectsIncompleteHandles(t *testing.T) {
	ctx := context.Background()
	for _, p := range []*publicationCompleteCleanup{nil, {}, {native: &publicationNativeCleanup{}}, {native: &publicationNativeCleanup{done: true}}, {native: &publicationNativeCleanup{done: true, candidate: &publicationCandidateCleanup{}}}} {
		called := false
		if err := p.transaction(ctx, "deleting", func(*sql.Tx) error { called = true; return nil }); err == nil || called {
			t.Fatal("incomplete handle reached deletion callback")
		}
		if _, _, err := p.expectedEvidence(); err == nil {
			t.Fatal("incomplete handle manufactured evidence")
		}
		if err := p.recheckCompleteTx(ctx, nil); err == nil {
			t.Fatal("incomplete handle manufactured complete receipt")
		}
	}
	for _, native := range []*publicationNativeCleanup{nil, {}, {done: true}, {done: true, candidate: &publicationCandidateCleanup{exit: &publicationUploadExit{}}}} {
		var service *DeploymentService
		if receipt, err := service.cleanupOriginalPublicationLocal(ctx, native); err == nil || receipt != nil {
			t.Fatal("missing current service produced cleanup receipt")
		}
	}
}

// Filesystem mechanics only, not a SQL receipt or production acceptance.
func TestPublicationLocalCleanupAbsenceRejectsLateUnlistedSeal(t *testing.T) {
	for _, mode := range []string{"same-task", "unpaired-foreign", "unknown-partial", "paired-foreign", "paired-foreign-unreadable"} {
		t.Run(mode, func(t *testing.T) {
			owner, stage, seals := newPublicationLocalFilesFixture(t)
			ctx := context.Background()
			plan, err := preparePublicationLocalFiles(ctx, owner, stage, seals)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.close()
			var survivor string
			if err = staging.WithCustodyLock(ctx, plan.custody, func() error {
				if err := plan.removeLocked(ctx, func(remove func() error) error { return remove() }); err != nil {
					return err
				}
				if !publicationLocalFilesAbsent(owner.Staging, plan.custody, stage.owner.Task, seals) {
					t.Fatal("initial complete absence rejected")
				}
				scope := seals[0].Intent.Scope
				scope.Unit = "late-unlisted-member"
				scope.JobUID = "late-unlisted-job"
				scope.InvocationSHA256 = hash([]byte("late unlisted invocation DATA"))
				if mode == "unknown-partial" {
					survivor = "unknown.partial"
					return writeStageExclusive(plan.custody, "unknown.partial", []byte("uncertain partial DATA"))
				}
				if mode != "same-task" {
					scope.Task = "sbk_22222222-2222-4222-8222-222222222222"
					scope.Binding.BackupID = scope.Task
				}
				late := writePublicationLocalSealFixture(t, plan.custody, scope, "late.enc", []byte("late original ciphertext DATA"))
				survivor = late.Name
				if mode == "paired-foreign" || mode == "paired-foreign-unreadable" {
					// Intentionally violate the foreign payload checksum while
					// retaining its exact size and canonical attribution intent.
					// Our cleanup must not inspect/verify foreign ciphertext.
					if err := plan.custody.Chmod(late.Name, 0600); err != nil {
						return err
					}
					writeErr := plan.custody.WriteFile(late.Name, bytes.Repeat([]byte{'x'}, len("late original ciphertext DATA")), 0600)
					modeErr := plan.custody.Chmod(late.Name, 0400)
					if writeErr != nil {
						return writeErr
					}
					if modeErr != nil {
						return modeErr
					}
				}
				if mode == "unpaired-foreign" {
					return plan.custody.Remove(late.Name + ".intent.json")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err = staging.WithCustodyLock(ctx, plan.custody, func() error {
				if mode == "paired-foreign-unreadable" {
					if err := plan.custody.Chmod(survivor, 0000); err != nil {
						return err
					}
					defer plan.custody.Chmod(survivor, 0400)
					probe, err := plan.custody.Open(survivor)
					if err == nil {
						_ = probe.Close()
						t.Log("ciphertext read-open denial unavailable for this OS/current identity; checksum-independence remains exercised")
					} else if !os.IsPermission(err) {
						return err
					} else {
						t.Log("foreign ciphertext read-open is permission denied; metadata-only absence must still pass")
					}
				}
				if absent := publicationLocalFilesAbsent(owner.Staging, plan.custody, stage.owner.Task, seals); absent != (mode == "paired-foreign" || mode == "paired-foreign-unreadable") {
					t.Fatal("late custody attribution not enforced", mode, absent)
				}
				if _, err := plan.custody.Stat(survivor); err != nil {
					t.Fatal("query-only observation removed survivor", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
