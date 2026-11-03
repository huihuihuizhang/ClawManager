package install

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/staging"
)

const originalWriterJournalVersion = "original-writer-maintenance-journal.v1"

// Records contain only public identity, ORIGINAL checkpoints, original sealed
// material references and authenticated native receipts. Never secret restart
// commands, credentials, or reconstructed success acknowledgements.
type originalWriterJournalRecord struct {
	Version, Operation, InventorySHA256, PreviousSHA256 string
	Sequence                                            uint64
	At                                                  time.Time
	Writer, Action                                      string
	Original                                            *flow.State     `json:",omitempty"`
	Data                                                json.RawMessage `json:",omitempty"`
}

type originalWriterJournal struct {
	directory                  string
	directoryIdentity          os.FileInfo
	mu                         sync.Mutex
	root                       *os.Root
	operation, inventory, tail string
	sequence                   uint64
	failed                     bool
	recoveryClosed             bool
	recoveryBoundary           uint64
	lastSourceMutation         uint64
}

func originalWriterPrivateOwner(info os.FileInfo) bool {
	if runtime.GOOS != "linux" {
		return true
	}
	v := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if !v.IsValid() {
		return false
	}
	uid := v.FieldByName("Uid")
	return uid.IsValid() && uid.CanUint() && uid.Uint() == uint64(os.Geteuid())
}

func (j *originalWriterJournal) checkDirectory() error {
	if j.directoryIdentity == nil {
		return ErrInstall
	}
	info, err := os.Lstat(j.directory)
	if err != nil || !os.SameFile(info, j.directoryIdentity) || !info.IsDir() || !originalWriterPrivateOwner(info) || runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		return ErrInstall
	}
	return nil
}

func newOriginalWriterJournal(ctx context.Context, p *OriginalWriterMaintenance, directory, inventory string) (*originalWriterJournal, error) {
	if p == nil || p.check(ctx) != nil || !digestPattern.MatchString(inventory) || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrInstall
	}
	before, err := os.Lstat(directory)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || !originalWriterPrivateOwner(before) || runtime.GOOS == "linux" && before.Mode().Perm()&0077 != 0 {
		return nil, ErrInstall
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrInstall
	}
	f, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, ErrInstall
	}
	opened, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(before, opened) {
		root.Close()
		return nil, ErrInstall
	}
	j := &originalWriterJournal{root: root, operation: p.operation, inventory: inventory, directory: directory, directoryIdentity: before}
	return j, nil
}

// append writes a new immutable file and verifies complete bytes after both
// file and directory fsync. A write/fsync/readback failure permanently poisons
// this process's writer, retaining any unknown file for authenticated recovery.
func (j *originalWriterJournal) append(ctx context.Context, writer, action string, original *flow.State, data any) error {
	_, _, err := j.appendReceipt(ctx, writer, action, original, data)
	return err
}

// The returned digest is the exact durable file written by this call, even if
// another read-only receipt is appended immediately afterwards.
func (j *originalWriterJournal) appendReceipt(ctx context.Context, writer, action string, original *flow.State, data any) (uint64, string, error) {
	if j == nil {
		return 0, "", ErrInstall
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.recoveryClosed && originalSourceMutationIntent(action) {
		return 0, "", ErrInstall
	}
	if j.failed || j.root == nil || ctx == nil || ctx.Err() != nil || action == "" || j.checkDirectory() != nil {
		return 0, "", ErrInstall
	}
	var encoded json.RawMessage
	if data != nil {
		raw, err := json.Marshal(data)
		if err != nil || len(raw) > 1<<20 {
			return 0, "", ErrInstall
		}
		encoded = raw
	}
	record := originalWriterJournalRecord{Version: originalWriterJournalVersion, Operation: j.operation, InventorySHA256: j.inventory, PreviousSHA256: j.tail, Sequence: j.sequence + 1, At: time.Now().UTC().Truncate(time.Microsecond), Writer: writer, Action: action, Original: original, Data: encoded}
	raw, err := json.Marshal(record)
	if err != nil {
		return 0, "", ErrInstall
	}
	name := fmt.Sprintf("original-writers-%s-%08d.json", j.operation, record.Sequence)
	err = staging.WithCustodyLock(ctx, j.root, func() error {
		f, err := j.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
		if err != nil {
			return ErrInstall
		}
		_, writeErr := io.Copy(f, bytes.NewReader(raw))
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return ErrInstall
		}
		dir, err := j.root.Open(".")
		if err != nil {
			return ErrInstall
		}
		syncErr = dir.Sync()
		closeErr = dir.Close()
		if syncErr != nil || closeErr != nil {
			return ErrInstall
		}
		info, err := j.root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(raw)) {
			return ErrInstall
		}
		got, err := j.root.ReadFile(name)
		if err != nil || !bytes.Equal(got, raw) {
			return ErrInstall
		}
		return nil
	})
	if err != nil {
		j.failed = true
		return 0, "", ErrInstall
	}
	j.tail = hash(raw)
	j.sequence = record.Sequence
	if originalSourceMutationIntent(action) {
		j.lastSourceMutation = record.Sequence
	}
	return j.sequence, j.tail, nil
}

func (j *originalWriterJournal) close() error {
	if j == nil {
		return ErrInstall
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.root == nil {
		return ErrInstall
	}
	err := j.root.Close()
	j.root = nil
	return err
}

// v1 uses this exact struct encoding, not JCS. Roundtrip comparison also
// rejects duplicate keys, reordered fields and alternate spellings.
func decodeOriginalWriterJournal(raw []byte, r *originalWriterJournalRecord) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(r) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInstall
	}
	again, err := json.Marshal(r)
	if err != nil || !bytes.Equal(again, raw) {
		return ErrInstall
	}
	return nil
}

// OriginalWriterJournalInspection is recovery DATA only. It cannot restore an
// opaque hold or turn intent/send_unknown into a positive native receipt.
type OriginalWriterJournalInspection struct {
	Version, Operation, InventorySHA256, TailSHA256 string
	Records                                         []originalWriterJournalRecord
}

// A new actual authenticated original administrator may inspect the durable
// chain after process death. It is deliberately not a replay/stop authority.
func (p *OriginalWriterMaintenance) InspectWriterJournal(ctx context.Context, directory, operation, inventory string) (OriginalWriterJournalInspection, error) {
	var out OriginalWriterJournalInspection
	if p == nil {
		return out, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.check(ctx) != nil || len(operation) != 32 || !digestPattern.MatchString(inventory) {
		return out, ErrInstall
	}
	for _, v := range operation {
		if !(v >= '0' && v <= '9' || v >= 'a' && v <= 'f') {
			return out, ErrInstall
		}
	}
	// Use the fresh administrator solely to open and authenticate this private
	// custody directory; the inspected original operation is never reminted.
	j, err := newOriginalWriterJournal(ctx, p, directory, inventory)
	if err != nil {
		return out, err
	}
	defer j.close()
	out, err = j.inspect(ctx, operation, inventory)
	if err != nil || p.check(ctx) != nil {
		return OriginalWriterJournalInspection{}, ErrInstall
	}
	return out, nil
}

func (j *originalWriterJournal) inspect(ctx context.Context, operation, inventory string) (OriginalWriterJournalInspection, error) {
	var out OriginalWriterJournalInspection
	err := staging.WithCustodyLock(ctx, j.root, func() error {
		if j.checkDirectory() != nil {
			return ErrInstall
		}
		dir, err := j.root.Open(".")
		if err != nil {
			return ErrInstall
		}
		entries, err := dir.ReadDir(10001)
		closeErr := dir.Close()
		if err != nil && err != io.EOF || closeErr != nil || len(entries) > 10000 {
			return ErrInstall
		}
		names := map[string]bool{}
		prefix := "original-writers-" + operation + "-"
		for _, e := range entries {
			if len(e.Name()) >= len(prefix) && e.Name()[:len(prefix)] == prefix {
				names[e.Name()] = true
			}
		}
		if len(names) == 0 || len(names) > 10000 {
			return ErrInstall
		}
		out = OriginalWriterJournalInspection{Version: originalWriterJournalVersion, Operation: operation, InventorySHA256: inventory}
		for n := 1; n <= len(names); n++ {
			name := fmt.Sprintf("%s%08d.json", prefix, n)
			if !names[name] {
				return ErrInstall
			}
			info, err := j.root.Lstat(name)
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 2<<20 {
				return ErrInstall
			}
			f, err := j.root.Open(name)
			if err != nil {
				return ErrInstall
			}
			opened, statErr := f.Stat()
			if statErr != nil || !os.SameFile(info, opened) || !originalWriterPrivateOwner(opened) || runtime.GOOS == "linux" && opened.Mode().Perm()&0077 != 0 {
				f.Close()
				return ErrInstall
			}
			raw, err := io.ReadAll(io.LimitReader(f, 2<<20+1))
			after, statErr := f.Stat()
			closeErr := f.Close()
			var r originalWriterJournalRecord
			if err != nil || statErr != nil || closeErr != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || len(raw) > 2<<20 || decodeOriginalWriterJournal(raw, &r) != nil || r.Version != out.Version || r.Operation != operation || r.InventorySHA256 != inventory || r.Sequence != uint64(n) || r.PreviousSHA256 != out.TailSHA256 {
				return ErrInstall
			}
			out.Records = append(out.Records, r)
			out.TailSHA256 = hash(raw)
		}
		return j.checkDirectory()
	})
	if err != nil {
		return OriginalWriterJournalInspection{}, ErrInstall
	}
	return out, nil
}
