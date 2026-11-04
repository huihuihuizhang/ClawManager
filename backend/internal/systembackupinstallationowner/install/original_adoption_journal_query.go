package install

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"regexp"
	"runtime"
)

var originalJournalFilePattern = regexp.MustCompile(`^original-writers-([0-9a-f]{32})-([0-9]{8})\.json$`)

// InspectOriginalAdoptionJournalCommit is an authenticated, comparison-only
// cross-process entry. It never rebuilds an opaque hold, adopts coverage,
// appends the old journal, acquires a gate, or grants physical recovery. All
// expectations are read from the one retained private original journal.
func (i *Installer) InspectOriginalAdoptionJournalCommit(ctx context.Context, password []byte, enrollment EnrollmentPin, selectionPin BootstrapSourceFilePin) (OriginalAdoptionCommitInspection, error) {
	var zero OriginalAdoptionCommitInspection
	raw, err := readBootstrapSourcePin(selectionPin, 262144)
	if err != nil {
		return zero, ErrInstall
	}
	var selection OriginalWriterSetSelection
	if decodeExact(raw, &selection) != nil || selection.Version != OriginalWriterSetSelectionVersion || selection.Policy.Validate() != nil || privateDirectory(selection.JournalDirectory) != nil {
		return zero, ErrInstall
	}
	// This existing preparation authenticates current admin/enrollment/head and
	// reads instances only. Its new, unused operation never acquires a gate; the
	// inspected operation below is solely the original durable operation.
	reader, err := i.PrepareOriginalWriterMaintenance(ctx, password, enrollment, selection.Policy)
	if err != nil {
		return zero, err
	}
	operation, inventory, err := originalJournalCoordinates(selection.JournalDirectory)
	if err != nil {
		return zero, ErrCommitUnknown
	}
	journal, err := reader.InspectWriterJournal(ctx, selection.JournalDirectory, operation, inventory)
	if err != nil {
		return zero, ErrCommitUnknown
	}
	expected, err := originalJournalCommitExpected(journal, selectionPin, i.plan.Target.InstallationID, i.plan.Target.ServerUUID, i.plan.Target.Database)
	if err != nil || readbackOriginalAdoptionCommitOutcome(ctx, i.db, expected, true) != nil {
		return zero, ErrCommitUnknown
	}
	// Complete private chain/custody and original target authority must still
	// agree after the SQL comparison; concurrent journal changes are unknown.
	after, err := reader.InspectWriterJournal(ctx, selection.JournalDirectory, operation, inventory)
	if err != nil || after.TailSHA256 != journal.TailSHA256 || !reflect.DeepEqual(after.Records, journal.Records) {
		return zero, ErrCommitUnknown
	}
	return OriginalAdoptionCommitInspection{Version: "original-adoption-commit-inspection.v1", Operation: expected.Operation,
		State: "committed_exact_original_journal_readback_only_no_source_recovery", InventorySHA256: expected.InventorySHA256,
		ExpectedSHA256: originalObjectSHA(expected), ExpectedEpoch: expected.NewEpoch}, nil
}

func originalJournalCoordinates(directory string) (string, string, error) {
	if privateDirectory(directory) != nil {
		return "", "", ErrInstall
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", "", ErrInstall
	}
	defer root.Close()
	f, err := root.Open(".")
	if err != nil {
		return "", "", ErrInstall
	}
	entries, readErr := f.ReadDir(10001)
	closeErr := f.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) > 10000 {
		return "", "", ErrInstall
	}
	operation, first := "", ""
	for _, entry := range entries {
		match := originalJournalFilePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		if operation != "" && operation != match[1] {
			return "", "", ErrCommitUnknown
		}
		operation = match[1]
		if match[2] == "00000001" {
			first = entry.Name()
		}
	}
	if first == "" {
		return "", "", ErrCommitUnknown
	}
	// Preserve the journal's existing 2MiB bound; the generic private input
	// reader deliberately accepts at most256KiB. Keep this read rooted to the
	// exact opened journal directory and use the original journal protections.
	info, err := root.Lstat(first)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 2<<20 {
		return "", "", ErrCommitUnknown
	}
	file, err := root.Open(first)
	if err != nil {
		return "", "", ErrCommitUnknown
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) || !originalWriterPrivateOwner(opened) || runtime.GOOS == "linux" && opened.Mode().Perm()&0077 != 0 {
		file.Close()
		return "", "", ErrCommitUnknown
	}
	raw, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	after, statErr := file.Stat()
	closeErr = file.Close()
	var record originalWriterJournalRecord
	if err != nil || statErr != nil || closeErr != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || len(raw) > 2<<20 || decodeOriginalWriterJournal(raw, &record) != nil || record.Version != originalWriterJournalVersion || record.Sequence != 1 || record.Operation != operation || !digestPattern.MatchString(record.InventorySHA256) {
		return "", "", ErrCommitUnknown
	}
	return operation, record.InventorySHA256, nil
}

func originalJournalCommitExpected(journal OriginalWriterJournalInspection, pin BootstrapSourceFilePin, installation, server, database string) (originalAdoptionCommitExpected, error) {
	var expected originalAdoptionCommitExpected
	prepared, sent := 0, 0
	for _, record := range journal.Records {
		switch record.Action {
		case "prepared_original_complete_set":
			prepared++
			var data struct{ Selection BootstrapSourceFilePin }
			if json.Unmarshal(record.Data, &data) != nil || data.Selection != pin || record.Writer != "" || record.Original != nil {
				return expected, ErrCommitUnknown
			}
		case "adoption_commit_send_unknown":
			sent++
			decoder := json.NewDecoder(bytes.NewReader(record.Data))
			decoder.DisallowUnknownFields()
			if prepared != 1 || record.Writer != "" || record.Original != nil || decoder.Decode(&expected) != nil || decoder.Decode(new(any)) != io.EOF {
				return expected, ErrCommitUnknown
			}
			encoded, err := json.Marshal(expected)
			if err != nil || !bytes.Equal(encoded, record.Data) {
				return expected, ErrCommitUnknown
			}
		}
	}
	if prepared != 1 || sent != 1 || expected.Version != "original-adoption-commit-expectation.v1" || expected.Operation != journal.Operation || expected.InventorySHA256 != journal.InventorySHA256 ||
		expected.InstallationID != installation || expected.ServerUUID != server || expected.Database != database || len(expected.ControlRows) != 17 || len(expected.Sources) != 4 || expected.References == nil || expected.Bindings == nil || expected.NewEpoch != expected.OldEpoch+1 {
		return expected, ErrCommitUnknown
	}
	return expected, nil
}
