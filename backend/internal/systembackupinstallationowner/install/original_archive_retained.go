package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"clawreef/internal/systembackup/staging"
	controller "clawreef/internal/systembackupcontroller"
	ev "clawreef/internal/systembackupevidence"
	archive "clawreef/internal/systembackuphostpatharchive"
)

// Additional trusted local Installer input for this SAME original operation.
// No boolean permission/isolation flag, task identity or new storage endpoint.
type OriginalCustodyReaderDefinition struct {
	Version, ProviderDefinitionSHA256, OperationIdentitySHA256 string
	ExecutableFile, ExecutableSHA256                           string
	MaximumCustodyBytes                                        int64
}

type originalRetentionPolicy struct {
	Version, Installation, CustodyIdentity, Mode string
	MaximumBytes                                 int64
}

type originalRetainedVersion struct {
	Version, State, SnapshotRevision, ReaderDefinitionSHA256 string
	Journal                                                  OriginalArchiveJournalInspection
	Copy                                                     OriginalArchiveCopyObservation
	Identity                                                 archive.FileIdentity
	Readback                                                 archive.ReaderReceipt
	Access                                                   originalCustodyAccess
	DR                                                       bool
}

// RetainedOriginalArchive is created only after actual D intent/copy, shared
// custody lock, create-only retention record and independent native EOF/SHA/
// provider-unwrap/AEAD reader. It is STILL not a complete snapshot/backfill/
// writer/PreparedCoverage source: B custody access closure and ALL history/
// external roots remain mandatory. No API here deletes a retained version.
type RetainedOriginalArchive struct {
	origin                *RetainedOriginalArchive
	provider              *OriginalAdoptionArchiveProvider
	journal               *JournaledOriginalArchiveCopy
	policy, version       []byte
	versionName           string
	data                  originalRetainedVersion
	readerFile, readerSHA string
}

func (*RetainedOriginalArchive) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (r *RetainedOriginalArchive) SnapshotRevision() string {
	if r == nil || r.origin != r {
		return ""
	}
	return r.data.SnapshotRevision
}

func originalReaderExecutable(path, sha string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !digestPattern.MatchString(sha) {
		return ErrInstall
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return ErrInstall
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrInstall
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > 128<<20 {
		return ErrInstall
	}
	raw, err := io.ReadAll(io.LimitReader(f, (128<<20)+1))
	if err != nil || int64(len(raw)) != info.Size() || hash(raw) != sha {
		return ErrInstall
	}
	return nil
}

func exactOriginalPolicy(root *os.Root, name string, raw []byte) error {
	if existing, err := readOriginalArchiveJournal(root, name); err == nil {
		if !bytes.Equal(existing, raw) {
			return ErrInstall
		}
		return nil
	} else if !os.IsNotExist(err) {
		return ErrInstall
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return ErrInstall
	}
	n, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || n != len(raw) || syncErr != nil || closeErr != nil || staging.SyncDirectory(root) != nil {
		return ErrInstall
	}
	existing, err := readOriginalArchiveJournal(root, name)
	if err != nil || !bytes.Equal(existing, raw) {
		return ErrInstall
	}
	return nil
}

func originalCustodyBytes(root *os.Root, maximum int64) (int64, error) {
	f, err := root.Open(".")
	if err != nil {
		return 0, ErrInstall
	}
	defer f.Close()
	var total int64
	count := 0
	for {
		entries, e := f.ReadDir(128)
		if e != nil && e != io.EOF {
			return 0, ErrInstall
		}
		for _, entry := range entries {
			info, err := root.Lstat(entry.Name())
			if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || total > maximum-info.Size() {
				return 0, ErrInstall
			}
			total += info.Size()
			count++
			if count > 10000 {
				return 0, ErrInstall
			}
		}
		if e == io.EOF {
			return total, nil
		}
	}
}

// Separate actual original read action. Unlike copy's private resolver this
// may ONLY unwrap the original exact evidence ref for independent readback.
// It does not lie to copy's wrap/unwrap call counters or renew any old cap.
func (p *OriginalAdoptionArchiveProvider) originalReaderCredential() (ev.TransitCredential, error) {
	if p.current() != nil {
		return ev.TransitCredential{}, ErrInstall
	}
	role, source := p.definition.Vault.Unwrap, p.definition.UnwrapJWT
	jwt, err := p.readJWT(source, role)
	if err != nil {
		return ev.TransitCredential{}, ErrInstall
	}
	defer clear(jwt)
	body, err := json.Marshal(struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}{role.Role, string(jwt)})
	if err != nil {
		return ev.TransitCredential{}, ErrInstall
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(p.ctx, http.MethodPost, p.definition.Vault.Transit.Endpoint+"/v1/auth/"+role.AuthMount+"/login", bytes.NewReader(body))
	if err != nil {
		return ev.TransitCredential{}, ErrInstall
	}
	request.Header.Set("Content-Type", "application/json")
	started := time.Now()
	response, err := p.client.Do(request)
	if err != nil {
		return ev.TransitCredential{}, ErrInstall
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return ev.TransitCredential{}, ErrInstall
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	defer clear(raw)
	if err != nil || len(raw) > 65536 {
		return ev.TransitCredential{}, ErrInstall
	}
	secret, ttl, err := originalArchiveBatchToken(raw, role.Role, role.Policy)
	if err != nil || originalArchiveLoginIdentity(raw, source.PodUID, role) != nil {
		clear(secret)
		return ev.TransitCredential{}, ErrInstall
	}
	expires := started.Add(ttl)
	if !time.Now().Before(expires) || time.Now().Add(ttl+5*time.Second).After(p.until) ||
		p.checkJWT(source, role) != nil || p.operator.authority(p.ctx, p.enrollment) != nil {
		clear(secret)
		return ev.TransitCredential{}, ErrInstall
	}
	if _, err = p.currentSQL(false); err != nil {
		clear(secret)
		return ev.TransitCredential{}, ErrInstall
	}
	return ev.TransitCredential{Key: p.definition.Vault.Transit.Key, Installation: p.reservation.InstallationID,
		Operation: ev.TransitUnwrap, Secret: secret, ExpiresAt: expires}, nil
}

func (p *OriginalAdoptionArchiveProvider) independentOriginalReader(local *archive.LocalArchive, nativePlan string,
	definition OriginalCustodyReaderDefinition) (archive.ReaderReceipt, error) {
	if originalReaderExecutable(definition.ExecutableFile, definition.ExecutableSHA256) != nil {
		return archive.ReaderReceipt{}, ErrInstall
	}
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
	file := filepath.Join(p.definition.CustodyRoot, local.Receipt().Name)
	grant, err := local.NewPipeGrant(file, p.reservation.OperationID, nativePlan, p.definition.Vault.Transit,
		credential, p.until, challenge, key)
	if err != nil {
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

type limitedOriginalReaderOutput struct {
	bytes.Buffer
	failed bool
}

func (b *limitedOriginalReaderOutput) Write(raw []byte) (int, error) {
	if b.Len()+len(raw) > 8192 {
		b.failed = true
		return 0, ErrInstall
	}
	return b.Buffer.Write(raw)
}

// CreateRetainedOriginalAdoptionCopy is the minimum local-custody PRODUCER.
// D invokes it outside its final SQL prefix, under its actual B physical hold.
// It consumes D's REAL durable intent/body rather than a caller JSON receipt.
// No independent fault domain/storage service is required; DR is always false.
func (p *OriginalAdoptionArchiveProvider) CreateRetainedOriginalAdoptionCopy(ctx context.Context,
	native archive.NativeStream, readerFile, readerSHA string) (*RetainedOriginalArchive, error) {
	if p == nil || !consumerSameContext(ctx, p.outer) || p.current() != nil {
		return nil, ErrInstall
	}
	raw, err := ReadPrivateFile(readerFile, 65536)
	var definition OriginalCustodyReaderDefinition
	identity, identityErr := controller.OriginalAdoptionReservationIdentitySHA256(p.reservation)
	if err != nil || hash(raw) != readerSHA || decodeExact(raw, &definition) != nil || identityErr != nil ||
		definition.Version != "original-maintenance-custody-reader.v1" || definition.ProviderDefinitionSHA256 != p.sourceSHA ||
		definition.OperationIdentitySHA256 != identity || definition.MaximumCustodyBytes < 1<<20 || definition.MaximumCustodyBytes > 1<<40 ||
		originalReaderExecutable(definition.ExecutableFile, definition.ExecutableSHA256) != nil {
		return nil, ErrInstall
	}
	root, _, err := p.originalArchiveJournalRoot(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	defer root.Close()
	var result *RetainedOriginalArchive
	err = staging.WithCustodyLock(p.ctx, root, func() error {
		if p.current() != nil {
			return ErrInstall
		}
		policyRaw, _ := json.Marshal(originalRetentionPolicy{"original-maintenance-custody-retention.v1",
			p.reservation.InstallationID, p.stableCustodyStorageIdentity(), "retain-all-no-auto-delete", definition.MaximumCustodyBytes})
		if exactOriginalPolicy(root, ".original-maintenance-retention.json", policyRaw) != nil {
			return ErrInstall
		}
		used, err := originalCustodyBytes(root, definition.MaximumCustodyBytes)
		// Metadata/EOF overflow must refuse, never truncate the source. Actual
		// final file size is checked again; unknown files always count/retain.
		if err != nil || native.MaxBytes <= 0 || native.MaxBytes > definition.MaximumCustodyBytes-used {
			return ErrInstall
		}
		if _, err = p.inspectNativeOriginalCustodyAccess(); err != nil {
			return ErrInstall
		}
		name := "original-custody-" + identity + ".enc"
		journal, err := p.CreateJournaledOriginalAdoptionCopy(ctx, name, native)
		if err != nil {
			return ErrInstall
		}
		if _, err = originalCustodyBytes(root, definition.MaximumCustodyBytes); err != nil {
			return ErrInstall
		}
		readback, err := p.independentOriginalReader(journal.local, native.PlanSHA256, definition)
		if err != nil || p.RecheckJournaledOriginalCopy(ctx, journal) != nil {
			return ErrInstall
		}
		access, err := p.inspectNativeOriginalCustodyAccess()
		if err != nil {
			return ErrInstall
		}
		observation, err := p.ObserveOriginalCopy(ctx, journal.local)
		if err != nil {
			return ErrInstall
		}
		fileIdentity, err := journal.local.IndependentIdentity()
		if err != nil {
			return ErrInstall
		}
		versionInput, _ := json.Marshal(struct {
			Journal  OriginalArchiveJournalInspection
			Copy     OriginalArchiveCopyObservation
			Identity archive.FileIdentity
		}{journal.data, observation, fileIdentity})
		version := "controller-custody-v1:" + hash(versionInput)
		data := originalRetainedVersion{Version: "original-retained-controller-custody.v1",
			State: "retained-independent-readback-requires-access-and-history-proof", SnapshotRevision: version,
			ReaderDefinitionSHA256: readerSHA, Journal: journal.data, Copy: observation, Identity: fileIdentity, Readback: readback, Access: access, DR: false}
		versionRaw, _ := json.Marshal(data)
		versionName := "original-adoption-archive-" + p.reservation.OperationID + ".04-retained-version.json"
		if exactOriginalPolicy(root, versionName, versionRaw) != nil {
			return ErrInstall
		}
		result = &RetainedOriginalArchive{provider: p, journal: journal, policy: policyRaw, version: versionRaw,
			versionName: versionName, data: data, readerFile: readerFile, readerSHA: readerSHA}
		result.origin = result
		return p.RecheckJournaledOriginalCopy(ctx, journal)
	})
	if err != nil {
		return nil, ErrInstall
	}
	return result, nil
}

// Original final caller runs this BEFORE evidence/source/KEK SQL locks. All
// actual native/provider/hash IO remains outside the final original tx prefix.
func (p *OriginalAdoptionArchiveProvider) RecheckRetainedOriginalArchive(ctx context.Context, r *RetainedOriginalArchive) error {
	if r == nil || r.origin != r || r.provider != p || !consumerSameContext(ctx, p.outer) {
		return ErrInstall
	}
	root, _, err := p.originalArchiveJournalRoot(ctx)
	if err != nil {
		return ErrInstall
	}
	defer root.Close()
	return staging.WithCustodyLock(p.ctx, root, func() error {
		if p.RecheckJournaledOriginalCopy(ctx, r.journal) != nil {
			return ErrInstall
		}
		for name, expected := range map[string][]byte{".original-maintenance-retention.json": r.policy, r.versionName: r.version} {
			raw, err := readOriginalArchiveJournal(root, name)
			if err != nil || !bytes.Equal(raw, expected) {
				return ErrInstall
			}
		}
		readerRaw, err := ReadPrivateFile(r.readerFile, 65536)
		if err != nil || hash(readerRaw) != r.readerSHA {
			return ErrInstall
		}
		_, err = p.inspectNativeOriginalCustodyAccess()
		return err
	})
}
