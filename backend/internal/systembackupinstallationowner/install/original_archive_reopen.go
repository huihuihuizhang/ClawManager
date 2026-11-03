package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"reflect"
	"time"

	"clawreef/internal/systembackup/staging"
	archive "clawreef/internal/systembackuphostpatharchive"
)

// The frozen journal/retention writers emit json.Marshal bytes, not JCS.
// Strict roundtrip accepts exactly that original format: no duplicate/unknown
// fields, extra JSON, whitespace rewrites or truncated/defaulted fields.
func decodeOriginalArchiveRecord(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return ErrInstall
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrInstall
	}
	encoded, err := json.Marshal(out)
	if err != nil || !bytes.Equal(encoded, raw) {
		return ErrInstall
	}
	return nil
}

// ReopenedOriginalArchive is a fresh independent read of an EXISTING retained
// version. No LocalArchive/JournaledOriginalArchiveCopy producer is recreated.
// It is not a physical hold, historical Reference source or PreparedCoverage.
type ReopenedOriginalArchive struct {
	origin                *ReopenedOriginalArchive
	provider              *OriginalAdoptionArchiveProvider
	data                  originalRetainedVersion
	policy, version       []byte
	readerFile, readerSHA string
	readback              archive.ReaderReceipt
}

func (*ReopenedOriginalArchive) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (r *ReopenedOriginalArchive) SnapshotRevision() string {
	if r == nil || r.origin != r {
		return ""
	}
	return r.data.SnapshotRevision
}
func (r *ReopenedOriginalArchive) ValidUntil() time.Time {
	if r == nil || r.origin != r {
		return time.Time{}
	}
	if r.provider != nil && r.provider.until.Before(r.data.Copy.Until) {
		return r.provider.until
	}
	return r.data.Copy.Until
}

func (p *OriginalAdoptionArchiveProvider) validateRecoveredVersion(d originalRetainedVersion, journal OriginalArchiveJournalInspection, definition OriginalCustodyReaderDefinition, readerSHA, identity string, now time.Time) error {
	c := d.Copy
	if d.Version != "original-retained-controller-custody.v1" || d.State != "retained-independent-readback-requires-access-and-history-proof" || d.DR || d.ReaderDefinitionSHA256 != readerSHA || d.Identity.Inode == 0 ||
		definition.Version != "original-maintenance-custody-reader.v1" || definition.ProviderDefinitionSHA256 != p.sourceSHA || definition.OperationIdentitySHA256 != identity || definition.MaximumCustodyBytes < 1<<20 || definition.MaximumCustodyBytes > 1<<40 ||
		journal.State != "recorded_copy_requires_fresh_original_readback_not_admitted" || d.Journal.Version != journal.Version || d.Journal.OperationIdentitySHA256 != identity || d.Journal.Name != journal.Name || d.Journal.IntentSHA256 != journal.IntentSHA256 || d.Journal.SendSHA256 != journal.SendSHA256 || d.Journal.CopySHA256 != journal.CopySHA256 ||
		c.Version != OriginalArchiveProviderVersion || c.State != "encrypted_raw_copy_only_not_admitted" || c.DefinitionSHA256 != p.sourceSHA || !reflect.DeepEqual(c.Reservation, p.reservation) || c.NativePermissionSHA256 != p.permissionSHA || c.SourceIdentitySHA256 != p.sourceIdentity || c.CustodyIdentitySHA256 != p.custodyIdentity() || c.EvidenceKey != p.definition.Vault.Transit.Key || c.Name != journal.Name || c.CiphertextBytes < 1 || !digestPattern.MatchString(c.CiphertextSHA256) || !digestPattern.MatchString(c.AssociationSHA256) || !digestPattern.MatchString(c.NativePlanSHA256) || !now.Before(c.Until) || c.Until.After(p.reservation.ExpiresAt) ||
		d.Readback.OperationID != p.reservation.OperationID || d.Readback.NativePlanSHA256 != c.NativePlanSHA256 || d.Readback.HeaderSHA256 != c.AssociationSHA256 || d.Readback.CiphertextSHA256 != c.CiphertextSHA256 || d.Readback.CiphertextBytes != c.CiphertextBytes || !digestPattern.MatchString(d.Readback.PlaintextSHA256) {
		return ErrInstall
	}
	versionInput, _ := json.Marshal(struct {
		Journal  OriginalArchiveJournalInspection
		Copy     OriginalArchiveCopyObservation
		Identity archive.FileIdentity
	}{d.Journal, c, d.Identity})
	if d.SnapshotRevision != "controller-custody-v1:"+hash(versionInput) {
		return ErrInstall
	}
	return nil
}

// Caller must use a freshly AUTHENTICATED original Installer provider for the
// SAME reservation/definition. This route reads only: missing or unknown journal
// prefixes/retention records stay unresolved, never create/retry a copy.
func (p *OriginalAdoptionArchiveProvider) ReopenRetainedOriginalArchive(ctx context.Context, readerFile, readerSHA string) (*ReopenedOriginalArchive, error) {
	if p == nil || !consumerSameContext(ctx, p.outer) || p.current() != nil || !p.used.CompareAndSwap(false, true) {
		return nil, ErrInstall
	}
	defer close(p.done)
	readerRaw, err := ReadPrivateFile(readerFile, 65536)
	var definition OriginalCustodyReaderDefinition
	if err != nil || hash(readerRaw) != readerSHA || decodeExact(readerRaw, &definition) != nil || originalReaderExecutable(definition.ExecutableFile, definition.ExecutableSHA256) != nil {
		return nil, ErrInstall
	}
	root, identity, err := p.originalArchiveJournalRoot(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	defer root.Close()
	var result *ReopenedOriginalArchive
	err = staging.WithCustodyLock(p.ctx, root, func() error {
		journal, e := p.InspectOriginalArchiveJournal(ctx)
		if e != nil {
			return ErrInstall
		}
		version, e := readOriginalArchiveJournal(root, "original-adoption-archive-"+p.reservation.OperationID+".04-retained-version.json")
		if e != nil {
			return ErrInstall
		}
		var data originalRetainedVersion
		if decodeOriginalArchiveRecord(version, &data) != nil || p.validateRecoveredVersion(data, journal, definition, readerSHA, identity, time.Now()) != nil {
			return ErrInstall
		}
		copyRaw, e := readOriginalArchiveJournal(root, originalArchiveJournalNames(p.reservation.OperationID)[2])
		if e != nil {
			return ErrInstall
		}
		var copyEntry originalArchiveJournalEntry
		if decodeOriginalArchiveRecord(copyRaw, &copyEntry) != nil || copyEntry.Copy == nil || !reflect.DeepEqual(*copyEntry.Copy, data.Copy) || !copyEntry.Until.Equal(data.Copy.Until) || copyEntry.NativePlanSHA256 != data.Copy.NativePlanSHA256 {
			return ErrInstall
		}
		policy, e := readOriginalArchiveJournal(root, ".original-maintenance-retention.json")
		if e != nil {
			return ErrInstall
		}
		expected, _ := json.Marshal(originalRetentionPolicy{"original-maintenance-custody-retention.v1", p.reservation.InstallationID, p.stableCustodyStorageIdentity(), "retain-all-no-auto-delete", definition.MaximumCustodyBytes})
		if !bytes.Equal(policy, expected) {
			return ErrInstall
		}
		// A fresh admin login must NEVER extend the original copy's absolute cap.
		if data.Copy.Until.Before(p.until) {
			oldCancel := p.cancel
			bounded, cancel := context.WithDeadline(p.ctx, data.Copy.Until)
			p.ctx = bounded
			p.operator.ctx = bounded
			p.until = data.Copy.Until
			p.cancel = func() {
				cancel()
				if oldCancel != nil {
					oldCancel()
				}
			}
		}
		if p.current() != nil {
			return ErrInstall
		}
		if _, e = p.inspectNativeOriginalCustodyAccess(); e != nil {
			return ErrInstall
		}
		recovered, e := archive.OpenPinnedRecoveredReadSource(p.ctx, root, staging.Receipt{Name: data.Copy.Name, Size: data.Copy.CiphertextBytes, SHA256: data.Copy.CiphertextSHA256}, data.Copy.AssociationSHA256, data.Identity)
		if e != nil {
			return ErrInstall
		}
		defer recovered.Close()
		readback, e := p.readRecoveredOriginalArchive(recovered, data, definition)
		if e != nil || readback.PlaintextSHA256 != data.Readback.PlaintextSHA256 || readback.PlaintextBytes != data.Readback.PlaintextBytes || p.current() != nil {
			return ErrInstall
		}
		if _, e = p.inspectNativeOriginalCustodyAccess(); e != nil {
			return ErrInstall
		}
		current, e := readOriginalArchiveJournal(root, "original-adoption-archive-"+p.reservation.OperationID+".04-retained-version.json")
		if e != nil || !bytes.Equal(current, version) {
			return ErrInstall
		}
		result = &ReopenedOriginalArchive{provider: p, data: data, policy: policy, version: version, readerFile: readerFile, readerSHA: readerSHA, readback: readback}
		result.origin = result
		return nil
	})
	if err != nil {
		return nil, ErrInstall
	}
	return result, nil
}

func (p *OriginalAdoptionArchiveProvider) readRecoveredOriginalArchive(source *archive.RecoveredReadSource, data originalRetainedVersion, definition OriginalCustodyReaderDefinition) (archive.ReaderReceipt, error) {
	credential, err := p.originalReaderCredential()
	if err != nil {
		return archive.ReaderReceipt{}, ErrInstall
	}
	defer clear(credential.Secret)
	challenge, key := make([]byte, 32), make([]byte, 32)
	defer clear(key)
	if _, err = rand.Read(challenge); err != nil {
		return archive.ReaderReceipt{}, ErrInstall
	}
	if _, err = rand.Read(key); err != nil {
		return archive.ReaderReceipt{}, ErrInstall
	}
	grant, err := source.NewPipeGrant(filepath.Join(p.definition.CustodyRoot, data.Copy.Name), p.reservation.OperationID, data.Copy.NativePlanSHA256, p.definition.Vault.Transit, credential, p.until, challenge, key)
	if err != nil || grant.Identity != data.Identity {
		return archive.ReaderReceipt{}, ErrInstall
	}
	defer clear(grant.Authenticator)
	body, err := json.Marshal(grant)
	if err != nil {
		return archive.ReaderReceipt{}, ErrInstall
	}
	defer clear(body)
	var output limitedOriginalReaderOutput
	cmd := exec.CommandContext(p.ctx, definition.ExecutableFile, "verify-original-custody-pipe")
	cmd.Stdin = bytes.NewReader(body)
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 5 * time.Second
	if cmd.Run() != nil || cmd.Process == nil || output.failed || originalReaderExecutable(definition.ExecutableFile, definition.ExecutableSHA256) != nil {
		return archive.ReaderReceipt{}, ErrInstall
	}
	return archive.AuthenticateReaderReceipt(output.Bytes(), grant, cmd.Process.Pid)
}

// No network under final SQL locks: D calls this boundary beforehand while its
// actual complete B/D hold is retained. No history/coverage proof is returned.
func (r *ReopenedOriginalArchive) RecheckBeforeOriginalSQL(ctx context.Context) error {
	if r == nil || r.origin != r || r.provider == nil {
		return ErrInstall
	}
	p := r.provider
	root, _, err := p.originalArchiveJournalRoot(ctx)
	if err != nil {
		return ErrInstall
	}
	defer root.Close()
	return staging.WithCustodyLock(p.ctx, root, func() error {
		if p.current() != nil || !time.Now().Before(r.ValidUntil()) {
			return ErrInstall
		}
		for name, expected := range map[string][]byte{".original-maintenance-retention.json": r.policy, "original-adoption-archive-" + p.reservation.OperationID + ".04-retained-version.json": r.version} {
			raw, e := readOriginalArchiveJournal(root, name)
			if e != nil || !bytes.Equal(raw, expected) {
				return ErrInstall
			}
		}
		reader, e := ReadPrivateFile(r.readerFile, 65536)
		if e != nil || hash(reader) != r.readerSHA {
			return ErrInstall
		}
		journal, e := p.InspectOriginalArchiveJournal(ctx)
		if e != nil || journal.IntentSHA256 != r.data.Journal.IntentSHA256 || journal.SendSHA256 != r.data.Journal.SendSHA256 || journal.CopySHA256 != r.data.Journal.CopySHA256 {
			return ErrInstall
		}
		reopened, e := archive.OpenPinnedRecoveredReadSource(p.ctx, root, staging.Receipt{Name: r.data.Copy.Name, Size: r.data.Copy.CiphertextBytes, SHA256: r.data.Copy.CiphertextSHA256}, r.data.Copy.AssociationSHA256, r.data.Identity)
		if e != nil {
			return ErrInstall
		}
		reopened.Close()
		_, e = p.inspectNativeOriginalCustodyAccess()
		return e
	})
}
