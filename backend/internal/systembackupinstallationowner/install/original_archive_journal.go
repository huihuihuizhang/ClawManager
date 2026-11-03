package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	controller "clawreef/internal/systembackupcontroller"
	archive "clawreef/internal/systembackuphostpatharchive"
)

const originalArchiveJournalVersion = "original-adoption-archive-journal.v1"

// These records describe a real original-provider invocation. They are never
// grants, immutable history receipts, prepared coverage or permission to thaw.
type originalArchiveJournalEntry struct {
	Version, State, PreviousSHA256                              string
	OperationIdentitySHA256, DefinitionSHA256, NativePlanSHA256 string
	SourceIdentitySHA256, CustodyIdentitySHA256, Name           string
	Until                                                       time.Time
	Copy                                                        *OriginalArchiveCopyObservation
}

// OriginalArchiveJournalInspection is inert recovery data. An unknown send
// remains unknown after restart; parsing a receipt cannot recreate a producer.
type OriginalArchiveJournalInspection struct {
	Version, State, IntentSHA256, SendSHA256, CopySHA256 string
	OperationIdentitySHA256, Name                        string
	RequiresOriginalReadback                             bool
}

// JournaledOriginalArchiveCopy retains the actual producer and exact local
// archive. Only this live invocation can create it, after durable native copy
// readback. It is intentionally not any PreparedCoverage/Reference interface.
type JournaledOriginalArchiveCopy struct {
	provider *OriginalAdoptionArchiveProvider
	local    *archive.LocalArchive
	entries  [3][]byte
	data     OriginalArchiveJournalInspection
}

func (*JournaledOriginalArchiveCopy) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func originalArchiveJournalHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func (p *OriginalAdoptionArchiveProvider) originalArchiveJournalRoot(ctx context.Context) (*os.Root, string, error) {
	if p == nil || !consumerSameContext(ctx, p.outer) || p.current() != nil {
		return nil, "", ErrInstall
	}
	identity, err := controller.OriginalAdoptionReservationIdentitySHA256(p.reservation)
	if err != nil || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(p.reservation.OperationID) {
		return nil, "", ErrInstall
	}
	// The intent must never be written into the old MinIO source tree, even
	// when the later C copy would refuse that custody selection.
	source, _, _, err := p.sourcePath()
	if err != nil {
		return nil, "", ErrInstall
	}
	canonical, err := filepath.EvalSymlinks(p.definition.CustodyRoot)
	if err != nil || canonical != p.definition.CustodyRoot || strings.HasPrefix(canonical+string(os.PathSeparator), source+string(os.PathSeparator)) {
		return nil, "", ErrInstall
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return nil, "", ErrInstall
	}
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		root.Close()
		return nil, "", ErrInstall
	}
	return root, identity, nil
}

func originalArchiveJournalNames(operation string) [3]string {
	base := "original-adoption-archive-" + operation
	return [3]string{base + ".01-intent.json", base + ".02-send-unknown.json", base + ".03-copy-readback.json"}
}

// Append-only O_EXCL records: an uncertain write is never replaced. Sync of
// both file and directory must succeed before the next external side effect.
func appendOriginalArchiveJournal(root *os.Root, name string, entry originalArchiveJournalEntry) ([]byte, error) {
	raw, err := json.Marshal(entry)
	if err != nil || len(raw) > 64<<10 {
		return nil, ErrInstall
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return nil, ErrInstall
	}
	n, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || n != len(raw) || syncErr != nil || closeErr != nil {
		return nil, ErrInstall
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, ErrInstall
	}
	syncErr = dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil || closeErr != nil {
		return nil, ErrInstall
	}
	actual, err := readOriginalArchiveJournal(root, name)
	if err != nil || !bytes.Equal(actual, raw) {
		return nil, ErrInstall
	}
	return raw, nil
}

func readOriginalArchiveJournal(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() <= 0 || info.Size() > 64<<10 {
		return nil, ErrInstall
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, ErrInstall
	}
	return raw, nil
}

// CreateJournaledOriginalAdoptionCopy is the only D archive invocation body.
// The original authenticated provider supplies authority, original deadlines,
// source and custody identities. Caller JSON cannot supply any of those.
// No final evidence/KEK SQL locks may be held while invoking this method.
func (p *OriginalAdoptionArchiveProvider) CreateJournaledOriginalAdoptionCopy(ctx context.Context, name string, native archive.NativeStream) (*JournaledOriginalArchiveCopy, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(name) || !digestPattern.MatchString(native.PlanSHA256) {
		return nil, ErrInstall
	}
	root, identity, err := p.originalArchiveJournalRoot(ctx)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	names := originalArchiveJournalNames(p.reservation.OperationID)
	entry := originalArchiveJournalEntry{Version: originalArchiveJournalVersion, State: "reserved",
		OperationIdentitySHA256: identity, DefinitionSHA256: p.sourceSHA, NativePlanSHA256: native.PlanSHA256,
		SourceIdentitySHA256: p.sourceIdentity, CustodyIdentitySHA256: p.custodyIdentity(), Name: name, Until: p.until}
	intent, err := appendOriginalArchiveJournal(root, names[0], entry)
	if err != nil {
		return nil, ErrInstall
	}
	// Recheck actual original authorization after durable reserve and BEFORE
	// any copy/wrap send. A crash from this point retains an unknown outcome.
	if p.current() != nil {
		return nil, ErrInstall
	}
	entry.State, entry.PreviousSHA256 = "send_unknown", originalArchiveJournalHash(intent)
	send, err := appendOriginalArchiveJournal(root, names[1], entry)
	if err != nil {
		return nil, ErrInstall
	}
	local, err := p.CreateUnadmittedEncryptedCopy(ctx, name, native)
	if err != nil {
		// Do not delete the intent, ciphertext or unknown result. The caller
		// still owes actual process-stop confirmation and original recovery.
		return nil, ErrInstall
	}
	observation, err := p.ObserveOriginalCopy(ctx, local)
	if err != nil {
		return nil, ErrInstall
	}
	entry.State, entry.PreviousSHA256, entry.Copy = "copy_readback", originalArchiveJournalHash(send), &observation
	copyRaw, err := appendOriginalArchiveJournal(root, names[2], entry)
	if err != nil {
		return nil, ErrInstall
	}
	result := &JournaledOriginalArchiveCopy{provider: p, local: local, entries: [3][]byte{intent, send, copyRaw}, data: OriginalArchiveJournalInspection{
		Version: originalArchiveJournalVersion, State: "copy_readback_not_immutable_not_admitted", OperationIdentitySHA256: identity, Name: name,
		IntentSHA256: originalArchiveJournalHash(intent), SendSHA256: originalArchiveJournalHash(send), CopySHA256: originalArchiveJournalHash(copyRaw)}}
	if p.RecheckJournaledOriginalCopy(ctx, result) != nil {
		return nil, ErrInstall
	}
	return result, nil
}

// RecheckJournaledOriginalCopy consumes the same actual C producer, native
// ciphertext readback and exact immutable journal bytes. It does not prove
// independent custody retention or resolve unknown old-history/key mappings.
func (p *OriginalAdoptionArchiveProvider) RecheckJournaledOriginalCopy(ctx context.Context, copy *JournaledOriginalArchiveCopy) error {
	if copy == nil || copy.provider != p || p.RecheckOriginalCopy(ctx, copy.local) != nil {
		return ErrInstall
	}
	root, identity, err := p.originalArchiveJournalRoot(ctx)
	if err != nil {
		return ErrInstall
	}
	defer root.Close()
	if identity != copy.data.OperationIdentitySHA256 {
		return ErrInstall
	}
	for i, name := range originalArchiveJournalNames(p.reservation.OperationID) {
		raw, err := readOriginalArchiveJournal(root, name)
		if err != nil || !bytes.Equal(raw, copy.entries[i]) {
			return ErrInstall
		}
	}
	return nil
}

func (p *JournaledOriginalArchiveCopy) Inspection() OriginalArchiveJournalInspection {
	if p == nil {
		return OriginalArchiveJournalInspection{}
	}
	return p.data
}

// InspectOriginalArchiveJournal is a real fresh-authority recovery read, with
// no writes and no external copy/send. It NEVER reconstructs the opaque copy
// producer or changes send_unknown into success from persisted receipt data.
func (p *OriginalAdoptionArchiveProvider) InspectOriginalArchiveJournal(ctx context.Context) (OriginalArchiveJournalInspection, error) {
	zero := OriginalArchiveJournalInspection{}
	root, identity, err := p.originalArchiveJournalRoot(ctx)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	names := originalArchiveJournalNames(p.reservation.OperationID)
	data := OriginalArchiveJournalInspection{Version: originalArchiveJournalVersion, State: "no_journal", OperationIdentitySHA256: identity, RequiresOriginalReadback: true}
	var prior string
	var first originalArchiveJournalEntry
	for i, name := range names {
		raw, err := readOriginalArchiveJournal(root, name)
		if errors.Is(err, os.ErrNotExist) {
			// A gap followed by another record is never a valid prefix.
			for _, later := range names[i+1:] {
				if _, e := root.Stat(later); !errors.Is(e, os.ErrNotExist) {
					return zero, ErrInstall
				}
			}
			return data, nil
		}
		var entry originalArchiveJournalEntry
		if err != nil || decodeOriginalArchiveRecord(raw, &entry) != nil || entry.Version != originalArchiveJournalVersion || entry.OperationIdentitySHA256 != identity ||
			entry.DefinitionSHA256 != p.sourceSHA || entry.SourceIdentitySHA256 != p.sourceIdentity || entry.CustodyIdentitySHA256 != p.custodyIdentity() ||
			entry.PreviousSHA256 != prior || i > 0 && entry.Name != data.Name || entry.State != [3]string{"reserved", "send_unknown", "copy_readback"}[i] ||
			!digestPattern.MatchString(entry.NativePlanSHA256) || entry.Until.IsZero() ||
			!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(entry.Name) ||
			i > 0 && (entry.NativePlanSHA256 != first.NativePlanSHA256 || !entry.Until.Equal(first.Until)) ||
			(i < 2 && entry.Copy != nil) || (i == 2 && entry.Copy == nil) {
			return zero, ErrInstall
		}
		if i == 0 {
			first = entry
		}
		prior = originalArchiveJournalHash(raw)
		data.Name = entry.Name
		switch i {
		case 0:
			data.State, data.IntentSHA256 = "reserved_requires_original_recovery", prior
		case 1:
			data.State, data.SendSHA256 = "send_unknown_requires_original_readback", prior
		case 2:
			data.State, data.CopySHA256 = "recorded_copy_requires_fresh_original_readback_not_admitted", prior
		}
	}
	return data, nil
}
