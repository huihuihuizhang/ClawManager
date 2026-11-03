package systembackuphostpatharchive

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"clawreef/internal/systembackup/staging"
)

func TestRecoveredArchivePinnedIdentityRejectsReplacement(t *testing.T) {
	grant, _, cleanup := independentReaderFixture(t)
	defer cleanup()
	root, err := os.OpenRoot(filepath.Dir(grant.File))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receipt := staging.Receipt{Name: grant.Receipt.Name, Size: grant.Receipt.Size, SHA256: grant.Receipt.SHA256}
	opened, err := OpenPinnedRecoveredReadSource(context.Background(), root, receipt, grant.HeaderSHA256, grant.Identity)
	if err != nil {
		t.Fatal("original retained file rejected", err)
	}
	opened.Close()
	raw, err := os.ReadFile(grant.File)
	if err != nil {
		t.Fatal(err)
	}
	replacement := grant.File + ".new"
	if os.WriteFile(replacement, raw, 0400) != nil || os.Rename(replacement, grant.File) != nil {
		t.Fatal("replacement fixture")
	}
	if opened, err = OpenPinnedRecoveredReadSource(context.Background(), root, receipt, grant.HeaderSHA256, grant.Identity); err == nil {
		opened.Close()
		t.Fatal("same bytes/SHA replaced inode became original version")
	}
}
