package install

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"time"

	ev "clawreef/internal/systembackupevidence"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	wire "clawreef/internal/systembackupwire"
)

// Concrete original installer-owned retained KEY provenance. This object does
// not claim a complete history census or external immutable snapshot. Only the
// final source-owning adoption entry may attach/stage it after B/C prefix locks.
// A DTO or a PreparedRetainedEvidenceBackfill implementation cannot create it.
type OriginalC1RetainedEvidence struct {
	origin         *OriginalC1RetainedEvidence
	receipt        *originalC1HistoryReceipt
	provider       *OriginalAdoptionArchiveProvider
	native         *a.EvidenceVaultObservation
	before         reg.Snapshot
	bindings       []reg.Binding
	refs           []reg.Reference
	until          time.Time
	tx             *sql.Tx
	failed, staged bool
}

func (*OriginalC1RetainedEvidence) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

// All native Vault, Kubernetes, private-material and SQL-source reads happen
// BEFORE the final original transaction. No task token or backup KEK is used.
// This entry accepts only the actual original C archive-provider object and a
// purpose-signed original mixed receipt authenticated against installed Plan.
func (p *PreparedOriginalAdoptionSQLCut) PrepareOriginalC1RetainedEvidence(ctx context.Context, h *OriginalWriterHold, pin BootstrapSourceFilePin, provider *OriginalAdoptionArchiveProvider) (*OriginalC1RetainedEvidence, error) {
	if p == nil || h == nil || h.set == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !originalEmptyHistoryOwner(ctx, p, h, false) || provider == nil || provider.origin != provider || provider.operator == nil || provider.operator.installer != p.operator.installer || provider.enrollment != p.enrollment || provider.reservation != p.reservation || !consumerSameContext(ctx, provider.outer) || provider.current() != nil || provider.keys == nil {
		return nil, ErrInstall
	}
	receipt, err := readOriginalC1HistoryReceipt(ctx, p, h, pin)
	if err != nil {
		return nil, ErrInstall
	}
	native, err := a.ObserveEvidenceVault(ctx, provider.definition.Vault)
	if err != nil || native.IdentitySHA256() != provider.permissionSHA || native.ValidUntil().IsZero() {
		return nil, ErrInstall
	}
	before, err := (reg.SQLStore{}).ReadSnapshot(ctx, p.operator.installer.db, p.reservation.InstallationID)
	if err != nil || !originalAdoptionEmptyRegistry(p, before) || before.Epoch != receipt.receipt.Snapshot.FenceAfter {
		return nil, ErrInstall
	}
	r := &OriginalC1RetainedEvidence{receipt: receipt, provider: provider, native: native, before: before, until: minTime(receipt.until, minTime(provider.until, native.ValidUntil()))}
	r.origin = r
	if err = r.deriveAndVerifyOriginalKeys(ctx); err != nil {
		r.failed = true
		return nil, err
	}
	if err = r.recheckBeforeSQL(ctx); err != nil {
		r.failed = true
		return nil, err
	}
	return r, nil
}

// Closed actual source derivation, never a public binding/reference DTO signer.
// Different source observations of the same key must derive the exact same
// native binding. The source aggregates the genuine complete signed receipt;
// each retained reference still identifies its own original evidence/run/hold.
func (r *OriginalC1RetainedEvidence) deriveAndVerifyOriginalKeys(ctx context.Context) error {
	if r == nil || r.origin != r || r.receipt == nil || r.provider == nil {
		return ErrInstall
	}
	snapshot := r.receipt.receipt.Snapshot.C1
	if snapshot == nil || len(snapshot.Sources) == 0 || len(snapshot.Sources) > 20 {
		return ErrInstall
	}
	// The backup mapping may be installed while the KEK execution registry is
	// still empty. Reject both logical and native-key aliases against that
	// authenticated original mapping, not just the existing registry rows.
	var backup a.OriginalRecord
	if json.Unmarshal(r.receipt.receipt.Snapshot.MappingRecord, &backup) != nil || backup.Binding.InstallationID != snapshot.InstallationID || backup.Binding.Retention != nil {
		return ErrInstall
	}
	keys := map[reg.ReferencePin]reg.Binding{}
	seen := map[string]bool{}
	for _, source := range snapshot.Sources {
		m := source.Record.Manifest
		if seen[m.Identity.ID] || m.Identity.Installation != snapshot.InstallationID || m.Identity.OwnerID != snapshot.InstallationID || source.Record.State != "ready" || source.Record.Failure != "none" || source.Record.Ref.ImmutableVersion == "" || source.KeySource.Transit.Key != m.Key {
			return ErrInstall
		}
		seen[m.Identity.ID] = true
		actual := r.provider.definition.Vault.Transit
		actual.CAPEM = nil
		if backup.Binding.ConfigRef == (reg.ReferencePin{IdentityHash: m.Key.Identity, Version: m.Key.Version}) || backup.Binding.Provider.Endpoint == actual.Endpoint && backup.Binding.Provider.KeyName == actual.KeyName {
			return ErrInstall
		}
		if !reflect.DeepEqual(actual, source.KeySource.Transit) || source.KeySource.ProfileSHA256 == "" || r.provider.current() != nil {
			return ErrInstall
		}
		if err := r.verifyOriginalWrappedDEK(ctx, source); err != nil {
			return err
		}
		contextValue, err := ev.EvidenceTransitContext(snapshot.InstallationID, m.Key)
		if err != nil {
			return ErrInstall
		}
		mapping := reg.SourceRecord{SourceID: "original-enrolled-c1-retained-key.v1", RecordID: r.receipt.pin.SHA256, RecordVersion: r.receipt.receipt.Version, ContentSHA256: r.receipt.pin.SHA256}
		caSource := reg.SourceRecord{SourceID: "original-evidence-provider.v1", RecordID: r.provider.reservation.OperationID, RecordVersion: "1", ContentSHA256: r.provider.sourceSHA}
		binding := reg.Binding{InstallationID: snapshot.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: m.Key.Identity, Version: m.Key.Version}, Key: wire.KeyBinding{Provider: reg.RetainedEvidenceProvider, IdentityHash: m.Key.Identity, RegistryVersion: m.Key.Version, ProviderKeyID: actual.KeyName, ProviderVersion: strconv.FormatUint(uint64(actual.KeyVersion), 10)}, Provider: reg.ProviderBinding{Endpoint: actual.Endpoint, KeyName: actual.KeyName, ProviderIdentityHash: r.provider.permissionSHA, ScopeHash: hash([]byte(contextValue)), CAPEMSHA256: actual.CASHA256, CASource: caSource}, Retention: &reg.RetainedEvidenceSource{Purpose: reg.RetainedEvidencePurpose, Source: mapping, KeyContextSHA256: hash([]byte(contextValue))}}
		if previous, ok := keys[binding.ConfigRef]; ok && !reflect.DeepEqual(previous, binding) {
			return ErrInstall
		}
		keys[binding.ConfigRef] = binding
		for _, old := range r.before.Bindings {
			if old.Binding.ConfigRef == binding.ConfigRef || old.Binding.Provider.Endpoint == actual.Endpoint && old.Binding.Provider.KeyName == actual.KeyName {
				return ErrInstall
			}
		}
		fingerprint, err := reg.BindingFingerprint(binding)
		if err != nil {
			return ErrInstall
		}
		requestSource := reg.SourceRecord{SourceID: "original-c1-result-request.v1", RecordID: string(source.Receipt.ReceiptKeyHash), RecordVersion: string(source.Receipt.ResultVersion), ContentSHA256: string(source.Receipt.RequestHash)}
		lifecycleSource := reg.SourceRecord{SourceID: "original-c1-run.v1", RecordID: string(source.Run.RunID), RecordVersion: string(source.Run.RowVersion), ContentSHA256: originalObjectSHA(source.Run)}
		if source.Run.State != "committed" || source.Receipt.Request.Evidence.EvidenceID != source.History.Evidence.EvidenceID || requestSource.RecordID == "" || requestSource.RecordVersion == "" || !digestPattern.MatchString(requestSource.ContentSHA256) {
			return ErrInstall
		}
		r.refs = append(r.refs, reg.Reference{Partition: reg.RetainedArtifacts, State: reg.ReferenceRetained, SourceRecordID: m.Identity.ID, SourceRecordVersion: strconv.FormatInt(source.EvidenceRowVersion, 10), EnvelopeID: m.Identity.ID, Key: binding.Key, BindingSHA256: fingerprint, MappingSource: mapping, ExpectedRequestSource: requestSource, LifecycleSource: lifecycleSource})
		// Preserve EACH original producer reference, including independent receipt
		// protection and the original pending hold; do not collapse them into one
		// synthetic evidence-level hold or lose their exact protection deadlines.
		if len(source.References) == 0 || len(source.References) > 4096 {
			return ErrInstall
		}
		seenRefs := map[string]bool{}
		for _, reference := range source.References {
			if reference.Scope != source.History.Scope || reference.EvidenceID != source.History.Evidence.EvidenceID || !digestPattern.MatchString(string(reference.ReferenceKeyHash)) {
				return ErrInstall
			}
			switch reference.ReferenceKind {
			case "producer_result", "producer_receipt", "bootstrap_candidate", "hold":
			default:
				return ErrInstall
			}
			id := m.Identity.ID + "/" + reference.ReferenceKind + "/" + string(reference.ReferenceKeyHash)
			protected, err := reference.ProtectedUntil.Time()
			if err != nil || seenRefs[id] || !time.Now().Before(protected) {
				return ErrInstall
			}
			seenRefs[id] = true
			r.until = minTime(r.until, protected)
			revision := originalObjectSHA(reference)
			refSource := reg.SourceRecord{SourceID: "original-c1-evidence-reference.v1", RecordID: string(reference.ReferenceKeyHash), RecordVersion: revision, ContentSHA256: revision}
			r.refs = append(r.refs, reg.Reference{Partition: reg.HoldsAndCatalog, State: reg.ReferenceRetained, SourceRecordID: id, SourceRecordVersion: revision, EnvelopeID: m.Identity.ID, Key: binding.Key, BindingSHA256: fingerprint, MappingSource: mapping, ExpectedRequestSource: requestSource, LifecycleSource: refSource})
		}
	}
	for _, binding := range keys {
		r.bindings = append(r.bindings, binding)
	}
	sort.Slice(r.bindings, func(i, j int) bool {
		if r.bindings[i].Key.IdentityHash != r.bindings[j].Key.IdentityHash {
			return r.bindings[i].Key.IdentityHash < r.bindings[j].Key.IdentityHash
		}
		return r.bindings[i].Key.RegistryVersion < r.bindings[j].Key.RegistryVersion
	})
	sort.Slice(r.refs, func(i, j int) bool {
		if r.refs[i].Partition != r.refs[j].Partition {
			return r.refs[i].Partition < r.refs[j].Partition
		}
		return r.refs[i].SourceRecordID < r.refs[j].SourceRecordID
	})
	return nil
}

// Real unwrap of the original wrapped DEK using C's fresh maintenance reader.
// No plaintext, provider secret or task authority is stored or returned.
func (r *OriginalC1RetainedEvidence) verifyOriginalWrappedDEK(ctx context.Context, source ev.OriginalC1EvidenceFacts) error {
	m, header := source.Record.Manifest, source.KeySource.EnvelopeHeader
	if len(header) == 0 || len(header) > ev.MaxHeader || int64(12+len(header)) != m.HeaderSize || hash(header) != m.EnvelopeHash {
		return ErrInstall
	}
	var env struct {
		Schema   string      `json:"schema_version"`
		Identity ev.Identity `json:"identity"`
		Key      ev.KeyRef   `json:"key"`
		Wrapped  string      `json:"wrapped_dek_base64"`
	}
	if decodeExact(header, &env) != nil || env.Schema != ev.Framing || env.Identity != m.Identity || env.Key != m.Key {
		return ErrInstall
	}
	raw, err := canonical(env)
	if err != nil || !bytes.Equal(raw, header) {
		return ErrInstall
	}
	wrapped, err := base64.StdEncoding.Strict().DecodeString(env.Wrapped)
	if err != nil || len(wrapped) == 0 || len(wrapped) > 4096 || base64.StdEncoding.EncodeToString(wrapped) != env.Wrapped {
		return ErrInstall
	}
	keys, err := ev.NewTransitKeys(r.provider.definition.Vault.Transit, &originalRetainedC1ReadCredential{provider: r.provider, key: m.Key})
	if err != nil {
		return ErrInstall
	}
	dek, err := keys.Unwrap(r.provider.ctx, m.Key, wrapped)
	defer clear(dek)
	if err != nil || len(dek) != 32 || ctx.Err() != nil || r.provider.current() != nil {
		return ErrInstall
	}
	return nil
}

func (r *OriginalC1RetainedEvidence) recheckBeforeSQL(ctx context.Context) error {
	if r == nil || r.origin != r || r.failed || r.staged || r.tx != nil || !time.Now().Before(r.until) || r.receipt.recheckBeforeSQL(ctx) != nil || r.provider.current() != nil {
		return ErrInstall
	}
	actual, err := (reg.SQLStore{}).ReadSnapshot(ctx, r.receipt.prep.operator.installer.db, r.before.InstallationID)
	if err != nil || !reg.SameSnapshotFacts(actual, r.before) || actual.ObservedAt.Before(r.before.ObservedAt) {
		return ErrInstall
	}
	return nil
}

func retainedC1Copy[T any](v T) T {
	var out T
	raw, err := json.Marshal(v)
	if err != nil || json.Unmarshal(raw, &out) != nil {
		return out
	}
	return out
}
func (r *OriginalC1RetainedEvidence) Bindings() []reg.Binding {
	if r == nil || r.origin != r || r.failed {
		return nil
	}
	return retainedC1Copy(r.bindings)
}
func (r *OriginalC1RetainedEvidence) References() []reg.Reference {
	if r == nil || r.origin != r || r.failed {
		return nil
	}
	return retainedC1Copy(r.refs)
}
func (r *OriginalC1RetainedEvidence) ExpectedSnapshot() reg.Snapshot {
	if r == nil || r.origin != r || r.failed {
		return reg.Snapshot{}
	}
	return retainedC1Copy(r.before)
}
func (r *OriginalC1RetainedEvidence) ValidUntil() time.Time {
	if r == nil || r.origin != r || r.failed {
		return time.Time{}
	}
	return r.until
}

// SQL-only final callback. tx is attached only by the private original final
// owner below, after its original prefix locks. Never authenticate another tx.
func (r *OriginalC1RetainedEvidence) RecheckOriginalRetained(ctx context.Context, view reg.SQLReadView, locked reg.LockedSnapshot, now time.Time) error {
	if r == nil || r.origin != r || r.failed || r.tx == nil || view != r.tx || !consumerSameContext(ctx, r.receipt.prep.ctx) || ctx.Err() != nil || now.Before(r.before.ObservedAt) || !now.Before(r.until) || !reg.SameSnapshotFacts(locked.Facts(), r.before) {
		return ErrInstall
	}
	return r.receipt.recheckLocked(ctx, r.tx, r.before.Epoch)
}

// Private same-transaction composition hook. The complete authenticated C
// history owner MUST be present at the call site; this hook does not manufacture
// immutable external history or 17 controls and is deliberately not exported.
// It never Begins/Commits or advances the fence. Any error poisons this object;
// the final caller MUST roll back all retained rows and controls together.
func (r *OriginalC1RetainedEvidence) stageOriginalRetained(ctx context.Context, original *a.OriginalSQLCoverageTransaction, bound *reg.Bound) error {
	if r == nil || r.origin != r || r.failed || r.staged || r.tx == nil || original == nil || original.Tx() != r.tx || bound == nil || !reg.SameSnapshotFacts(bound.Snapshot().Facts(), r.before) {
		return ErrInstall
	}
	if bound.StageInitialRetainedEvidence(ctx, r) != nil {
		r.failed = true
		return ErrInstall
	}
	r.staged = true
	return nil
}

// Call before KEK Bind. The concrete scanner authenticates both the original
// RR transaction and the complete earlier source ranges. No arbitrary *sql.Tx
// can acquire this association from a public DTO or from a later callback.
func (r *OriginalC1RetainedEvidence) lockOriginalRetainedPrefix(ctx context.Context, original *a.OriginalSQLCoverageTransaction) error {
	if r == nil || r.origin != r || r.failed || r.tx != nil || r.staged || original == nil || original.Tx() == nil || !consumerSameContext(ctx, r.receipt.prep.ctx) || !time.Now().Before(r.until) {
		return ErrInstall
	}
	p := r.receipt.prep
	if _, err := p.scanner.LockOriginalSources(ctx, original, p.observed); err != nil {
		r.failed = true
		return ErrInstall
	}
	// This concrete owner will Bind/write on this SAME original transaction.
	// Take its existing fence exclusively before any full mixed mapping read;
	// a shared comparison lock followed by Bind would be an S-to-X upgrade.
	var epoch uint64
	if original.Tx().QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE", r.before.InstallationID).Scan(&epoch) != nil || epoch != r.before.Epoch || !time.Now().Before(r.until) {
		r.failed = true
		return ErrInstall
	}
	if r.receipt.recheckLocked(ctx, original.Tx(), r.before.Epoch) != nil {
		r.failed = true
		return ErrInstall
	}
	r.tx = original.Tx()
	return nil
}

var _ reg.PreparedRetainedEvidenceBackfill = (*OriginalC1RetainedEvidence)(nil)
