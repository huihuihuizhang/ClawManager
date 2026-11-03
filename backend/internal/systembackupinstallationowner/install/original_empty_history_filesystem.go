package install

import (
	"context"
	"errors"
	"io"
	"os"
)

var errOriginalEmptyHistoryFilesystem = errors.New("original history filesystem unavailable, changed or nonempty")

// The original installed-source owner supplies the root capability and checks
// its source/path/custody binding. This reader does not discover roots, ignore
// control files, treat a missing directory as empty or authenticate that owner.
type originalEmptyHistoryRootObservation struct {
	origin *originalEmptyHistoryRootObservation
	root   *os.Root
	info   os.FileInfo
	failed bool
}

func (*originalEmptyHistoryRootObservation) MarshalJSON() ([]byte, error) {
	return nil, errOriginalEmptyHistoryFilesystem
}

// Accept only an actually opened, completely empty directory. Unknown files,
// directories and links all require the existing nonempty classification path.
// No directory entry is excluded by a guessed filename or prefix.
func observeEmptyOriginalHistoryRoot(ctx context.Context, root *os.Root) (*originalEmptyHistoryRootObservation, error) {
	if ctx == nil || ctx.Err() != nil || root == nil {
		return nil, errOriginalEmptyHistoryFilesystem
	}
	before, err := root.Stat(".")
	if err != nil || !before.IsDir() {
		return nil, errOriginalEmptyHistoryFilesystem
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, errOriginalEmptyHistoryFilesystem
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !sameEmptyHistoryDirectory(before, opened) {
		return nil, errOriginalEmptyHistoryFilesystem
	}
	entries, err := dir.ReadDir(128)
	closeErr := dir.Close()
	if ctx.Err() != nil || len(entries) != 0 || err != io.EOF || closeErr != nil {
		return nil, errOriginalEmptyHistoryFilesystem
	}
	after, err := root.Stat(".")
	if err != nil || !sameEmptyHistoryDirectory(opened, after) {
		return nil, errOriginalEmptyHistoryFilesystem
	}
	result := &originalEmptyHistoryRootObservation{root: root, info: after}
	result.origin = result
	return result, nil
}

func sameEmptyHistoryDirectory(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.IsDir() && b.IsDir() && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// Recheck performs actual filesystem I/O. Call outside the final SQL lock
// segment, together with the original source owner and real holder rechecks.
func (o *originalEmptyHistoryRootObservation) recheck(ctx context.Context) error {
	if o == nil || o.origin != o || o.root == nil || o.info == nil || o.failed {
		return errOriginalEmptyHistoryFilesystem
	}
	actual, err := observeEmptyOriginalHistoryRoot(ctx, o.root)
	if err != nil || !sameEmptyHistoryDirectory(o.info, actual.info) {
		o.failed = true
		return errOriginalEmptyHistoryFilesystem
	}
	return nil
}
