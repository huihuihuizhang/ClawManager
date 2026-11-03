package systembackuphostpatharchive

import (
	"context"
	"os"

	"clawreef/internal/systembackup/staging"
)

// OpenPinnedRecoveredReadSource preserves the original retained native file
// identity across process exit. The Installer must authenticate the persisted
// descriptor and hold current original custody authority BEFORE calling it.
// Neither a caller descriptor nor this handle is a writer/history witness.
// The subsequent independent reader must still unwrap and verify full AEAD EOF.
func OpenPinnedRecoveredReadSource(ctx context.Context, root *os.Root, receipt staging.Receipt, headerSHA string, expected FileIdentity) (*RecoveredReadSource, error) {
	if expected.Inode == 0 {
		return nil, ErrArchive
	}
	recovered, err := OpenRecoveredReadSource(ctx, root, receipt, headerSHA)
	if err != nil {
		return nil, ErrArchive
	}
	info, err := recovered.file.Stat()
	if err != nil {
		recovered.Close()
		return nil, ErrArchive
	}
	actual, err := fileIdentity(info)
	if err != nil || actual != expected {
		recovered.Close()
		return nil, ErrArchive
	}
	return recovered, nil
}
