package systembackuphostpatharchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"time"

	"clawreef/internal/systembackup/staging"
	ev "clawreef/internal/systembackupevidence"
)

// RecoveredReadSource is NOT the original native producer. Construction reads
// actual persisted ciphertext against the original authenticated owner journal;
// positive independent unwrap/AEAD readback is still required. No caller JSON
// can reconstruct LocalArchive or PreparedCoverage through this API.
type RecoveredReadSource struct {
	file    *os.File
	receipt staging.Receipt
	header  []byte
}

func OpenRecoveredReadSource(ctx context.Context, root *os.Root, receipt staging.Receipt, headerSHA string) (*RecoveredReadSource, error) {
	if !pinPattern.MatchString(headerSHA) {
		return nil, ErrArchive
	}
	f, err := staging.OpenFile(ctx, root, receipt)
	if err != nil {
		return nil, ErrArchive
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || info.Mode().Perm() != 0400 {
		return nil, ErrArchive
	}
	if _, err = fileIdentity(info); err != nil {
		return nil, ErrArchive
	}
	prefix := make([]byte, 16)
	if _, err = io.ReadFull(f, prefix); err != nil || !bytes.Equal(prefix[:12], []byte("CMHPARCH0001")) {
		return nil, ErrArchive
	}
	size := binary.BigEndian.Uint32(prefix[12:])
	if size == 0 || size > 16384 {
		return nil, ErrArchive
	}
	header := make([]byte, size)
	if _, err = io.ReadFull(f, header); err != nil {
		return nil, ErrArchive
	}
	h := sha256.Sum256(header)
	if hex.EncodeToString(h[:]) != headerSHA {
		return nil, ErrArchive
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, ErrArchive
	}
	ok = true
	return &RecoveredReadSource{file: f, receipt: receipt, header: header}, nil
}

func (r *RecoveredReadSource) Close() error {
	if r == nil || r.file == nil {
		return ErrArchive
	}
	err := r.file.Close()
	r.file = nil
	return err
}
func (r *RecoveredReadSource) NewPipeGrant(file, operation, plan string, transit ev.TransitConfig,
	credential ev.TransitCredential, until time.Time, challenge, authenticator []byte) (PipeGrant, error) {
	if r == nil || r.file == nil {
		return PipeGrant{}, ErrArchive
	}
	// Internal shared mechanics only. The temporary value never escapes as
	// an original producer or as a source/history/physical permission token.
	local := LocalArchive{file: r.file, receipt: r.receipt, header: r.header}
	return local.NewPipeGrant(file, operation, plan, transit, credential, until, challenge, authenticator)
}
