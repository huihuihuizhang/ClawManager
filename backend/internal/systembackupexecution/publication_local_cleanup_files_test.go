package systembackupexecution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"clawreef/internal/systembackup/staging"
	d "clawreef/internal/systembackupdispatch"
	"github.com/google/uuid"
)

// Actual filesystem mechanics only. The explicit callback in these tests is
// a protocol counter, not SQL authority, a C proof or a cleanup_result receipt.
func newPublicationLocalFilesFixture(t *testing.T) (*PublicJobOwner, originalStageResource, []publicationLocalSeal) {
	t.Helper()
	parent, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	owner := &PublicJobOwner{Staging: parent}
	a := d.Authority{TaskType: "backup", Phase: "capture", InstallationID: "installation_local_cleanup", TaskPublicID: "sbk_" + uuid.NewString(), AttemptNo: 1, ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64)}
	data, err := owner.stageScope(a)
	if err != nil {
		t.Fatal(err)
	}
	data.Resource, data.KeyVersion = "sbs_"+uuid.NewString(), uuid.NewString()
	key := []byte(strings.Repeat("k", 32))
	stage := originalStageResource{owner: data, mac: stageMAC(data, key), lifecycle: "ready", version: 1}
	keys, err := stageKeyRoot(parent, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeStageOwnerKey(context.Background(), keys, data.KeyVersion+".key", key); err != nil {
		t.Fatal(err)
	}
	_ = keys.Close()
	if err = parent.Mkdir(data.Task, 0700); err != nil {
		t.Fatal(err)
	}
	task, err := parent.OpenRoot(data.Task)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeStageExclusive(task, originalStageMarkerName, stageMarkerBytes(stage)); err != nil {
		t.Fatal(err)
	}
	if err = writeStageExclusive(task, "payload.enc", []byte("owned ciphertext DATA")); err != nil {
		t.Fatal(err)
	}
	if err = task.Chmod("payload.enc", 0400); err != nil {
		t.Fatal(err)
	}
	_ = task.Close()
	custody, err := staging.OpenSealCustody(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	seals := []publicationLocalSeal{}
	if err = staging.WithCustodyLock(context.Background(), custody, func() error {
		for _, name := range []string{"cipher.enc", "envelope.enc"} {
			scope := staging.SealScope{Installation: data.Installation, Task: data.Task, Phase: "capture", Unit: "original-part", Namespace: "backup", JobName: "original-job", JobUID: "original-job-uid", Attempt: 1, Generation: 1, ConfigVersion: 1, ConfigSHA256: data.ConfigSHA256, InvocationSHA256: strings.Repeat("b", 64), Binding: staging.Binding{BackupID: data.Task}}
			body := []byte(name + " original sealed DATA")
			seal := writePublicationLocalSealFixture(t, custody, scope, name, body)
			seals = append(seals, seal)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(seals, func(i, j int) bool { return seals[i].Name < seals[j].Name })
	return owner, stage, seals
}

func writePublicationLocalSealFixture(t *testing.T, root *os.Root, scope staging.SealScope, name string, body []byte) publicationLocalSeal {
	t.Helper()
	intent := staging.SealIntent{Schema: "controller-staging-seal-intent.v1", Scope: scope, Original: staging.Receipt{Name: name, Size: int64(len(body)), SHA256: hash(body)}}
	ref, err := staging.SealReferenceForIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	seal := publicationLocalSeal{Intent: intent, Name: strings.TrimPrefix(ref, "controller-staging-seal.v1/")}
	raw, _ := json.Marshal(intent)
	if err = writeStageExclusive(root, seal.Name, body); err != nil {
		t.Fatal(err)
	}
	if err = writeStageExclusive(root, seal.Name+".intent.json", raw); err != nil {
		t.Fatal(err)
	}
	if err = root.Chmod(seal.Name, 0400); err != nil {
		t.Fatal(err)
	}
	return seal
}

func TestPublicationLocalCleanupRemovesExactOwnedFilesAndPreservesForeignTask(t *testing.T) {
	owner, stage, seals := newPublicationLocalFilesFixture(t)
	custody, err := openPublicationLocalCustody(owner.Staging)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	foreignScope := seals[0].Intent.Scope
	foreignScope.Task = "sbk_" + uuid.NewString()
	foreignScope.Binding.BackupID = foreignScope.Task
	foreignScope.JobUID, foreignScope.InvocationSHA256 = "foreign-job-uid", strings.Repeat("c", 64)
	foreign := writePublicationLocalSealFixture(t, custody, foreignScope, "foreign.enc", []byte("foreign sealed DATA"))
	plan, err := preparePublicationLocalFiles(context.Background(), owner, stage, seals)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	if len(plan.flatFiles) != 4 {
		t.Fatal("foreign ciphertext entered the removal inventory", len(plan.flatFiles))
	}
	authorizations := 0
	err = staging.WithCustodyLock(context.Background(), plan.custody, func() error {
		return plan.removeLocked(context.Background(), func(remove func() error) error { authorizations++; return remove() })
	})
	if err != nil || authorizations != 1 || !publicationLocalFilesAbsent(owner.Staging, plan.custody, stage.owner.Task, seals) {
		t.Fatal("exact physical cleanup failed", err, authorizations)
	}
	for _, name := range []string{foreign.Name, foreign.Name + ".intent.json", ".custody.lock"} {
		if _, err = custody.Lstat(name); err != nil {
			t.Fatal("foreign/control inode was removed", name, err)
		}
	}
	keys, err := stageKeyRoot(owner.Staging, false)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	if _, err = keys.Lstat(stage.owner.KeyVersion + ".key"); err != nil {
		t.Fatal("owner key disappeared while original ledger persists", err)
	}
}

func TestPublicationLocalCleanupRejectsUnknownOwnedSealBeforeAnyRemoval(t *testing.T) {
	owner, stage, seals := newPublicationLocalFilesFixture(t)
	custody, err := openPublicationLocalCustody(owner.Staging)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	_ = writePublicationLocalSealFixture(t, custody, seals[0].Intent.Scope, "unregistered.enc", []byte("unknown owned seal"))
	if plan, err := preparePublicationLocalFiles(context.Background(), owner, stage, seals); err == nil || plan != nil {
		t.Fatal("unregistered same-task flat seal omitted")
	}
	if _, err = owner.Staging.Lstat(stage.owner.Task); err != nil {
		t.Fatal("refused plan removed task", err)
	}
	for _, seal := range seals {
		if _, err = custody.Lstat(seal.Name); err != nil {
			t.Fatal("refused plan removed a seal", err)
		}
	}
}

func TestPublicationLocalCleanupRejectsInodeReplacementBeforeAuthorization(t *testing.T) {
	owner, stage, seals := newPublicationLocalFilesFixture(t)
	plan, err := preparePublicationLocalFiles(context.Background(), owner, stage, seals)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	original, err := plan.task.Stat("payload.enc")
	if err != nil {
		t.Fatal(err)
	}
	body, err := plan.task.ReadFile("payload.enc")
	if err != nil {
		t.Fatal(err)
	}
	if err = writeStageExclusive(owner.Staging, "replacement", body); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(filepath.Join(owner.Staging.Name(), "replacement"), original.ModTime(), original.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err = plan.task.Chmod("payload.enc", 0600); err != nil {
		t.Fatal(err)
	}
	if err = plan.task.Remove("payload.enc"); err != nil {
		t.Fatal(err)
	}
	if err = owner.Staging.Rename("replacement", filepath.Join(stage.owner.Task, "payload.enc")); err != nil {
		t.Fatal(err)
	}
	authorizations := 0
	err = staging.WithCustodyLock(context.Background(), plan.custody, func() error {
		return plan.removeLocked(context.Background(), func(remove func() error) error { authorizations++; return remove() })
	})
	if err == nil || authorizations != 0 {
		t.Fatal("same-content replacement reached removal", err, authorizations)
	}
	for _, seal := range seals {
		if _, err = plan.custody.Lstat(seal.Name); err != nil {
			t.Fatal("replacement refusal removed a seal", err)
		}
	}
}

func TestPublicationLocalCleanupBindsCanonicalCustodyDirectory(t *testing.T) {
	for _, afterRemoval := range []bool{false, true} {
		name := "before-removal"
		if afterRemoval {
			name = "after-removal-absence"
		}
		t.Run(name, func(t *testing.T) {
			owner, stage, seals := newPublicationLocalFilesFixture(t)
			plan, err := preparePublicationLocalFiles(context.Background(), owner, stage, seals)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.close()
			if afterRemoval {
				err = staging.WithCustodyLock(context.Background(), plan.custody, func() error {
					return plan.removeLocked(context.Background(), func(remove func() error) error { return remove() })
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err = owner.Staging.Rename(".controller-seals", "retired-custody"); err != nil {
				t.Fatal("actual original directory rename", err)
			}
			current, err := staging.OpenSealCustody(owner.Staging)
			if err != nil {
				t.Fatal(err)
			}
			defer current.Close()
			if err = staging.WithCustodyLock(context.Background(), current, func() error {
				for _, seal := range seals {
					body := []byte(seal.Intent.Original.Name + " original sealed DATA")
					got := writePublicationLocalSealFixture(t, current, seal.Intent.Scope, seal.Intent.Original.Name, body)
					if got.Name != seal.Name {
						t.Fatal("replacement did not retain exact original seal name")
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if publicationLocalCustodyCurrent(owner.Staging, plan.custody) {
				t.Fatal("retired custody inode adopted canonical replacement")
			}
			if afterRemoval {
				if publicationLocalFilesAbsent(owner.Staging, plan.custody, stage.owner.Task, seals) {
					t.Fatal("empty retired inode hid canonical surviving payload")
				}
			} else {
				calls := 0
				err = staging.WithCustodyLock(context.Background(), plan.custody, func() error {
					return plan.removeLocked(context.Background(), func(remove func() error) error { calls++; return remove() })
				})
				if err == nil || calls != 0 {
					t.Fatal("renamed custody reached a removal action", err, calls)
				}
			}
			for _, seal := range seals {
				if _, err = current.Lstat(seal.Name); err != nil {
					t.Fatal("canonical replacement payload was modified", err)
				}
			}
		})
	}
}
