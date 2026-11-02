package systembackupexecution

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clawreef/internal/systembackup/staging"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

func TestPublicationLocalCleanupDoesNotReadForeignCiphertext(t *testing.T) {
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
	foreign := writePublicationLocalSealFixture(t, custody, foreignScope, "foreign.enc", []byte("foreign ciphertext whose bytes must not be read"))
	path, err := windows.UTF16PtrFromString(filepath.Join(custody.Name(), foreign.Name))
	if err != nil {
		t.Fatal(err)
	}
	// A share-deny handle can also deny Root.Lstat's metadata handle on Windows.
	// Use a real exclusive byte-range lock instead: all metadata/share modes
	// remain available, but another handle cannot read the cipher's first byte.
	if err = custody.Chmod(foreign.Name, 0600); err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	lock := &windows.Overlapped{}
	if err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, lock); err != nil {
		t.Fatal("actual foreign content lock", err)
	}
	defer windows.UnlockFileEx(handle, 0, 1, 0, lock)
	if _, err = custody.Lstat(foreign.Name); err != nil {
		t.Fatal("fixture denied required metadata access", err)
	}
	file, err := os.Open(filepath.Join(custody.Name(), foreign.Name))
	if err != nil {
		t.Fatal("fixture denied a shared metadata/content handle", err)
	}
	_, readErr := file.Read(make([]byte, 1))
	_ = file.Close()
	if !errors.Is(readErr, windows.ERROR_LOCK_VIOLATION) {
		t.Fatal("fixture did not actually deny foreign content bytes", readErr)
	}
	plan, err := preparePublicationLocalFiles(context.Background(), owner, stage, seals)
	if err != nil {
		t.Fatal("local inventory tried to read a foreign cipher body", err)
	}
	defer plan.close()
	if len(plan.flatFiles) != 4 {
		t.Fatal("foreign cipher entered exact removal set")
	}
	ctx := context.Background()
	if err = staging.WithCustodyLock(ctx, plan.custody, func() error {
		if err := plan.removeLocked(ctx, func(remove func() error) error { return remove() }); err != nil {
			return err
		}
		if !publicationLocalFilesAbsent(owner.Staging, plan.custody, stage.owner.Task, seals) {
			return errors.New("absence scan read a locked foreign cipher or rejected its metadata")
		}
		_, err := plan.custody.Lstat(foreign.Name)
		return err
	}); err != nil {
		t.Fatal("query-only absence must preserve and avoid reading foreign ciphertext", err)
	}
}
