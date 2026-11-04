package install

import (
	"context"
	"database/sql"
	"reflect"
	"sort"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const OriginalDisabledInitializationEndpoint = "initializeOriginalSystemBackupDisabledUnverified"
const originalDisabledInitializationVersion = "original-disabled-unverified-initialization.v1"

// These are genuine original objects, never JSON proof/Passed/hash fields.
// CapacityDB is a real peer for the ORIGINAL producer's pinned native collector.
// Keep the original Production/Source context alive until this call completes;
// recovery has already permanently poisoned/stopped the collection owners.
type OriginalDisabledInitializationInputs struct {
	Request    RequestFiles
	Production *OriginalC1SigningProduction
	Recovered  *PreparedOriginalWriterSet
	Coverage   *a.SQLCoverageOwnerPreparation
	CapacityDB *sql.DB
}

type OriginalDisabledInitializationReceipt struct {
	// Exact original write delta is comparison data, not caller authority.
	Evidence                                                                       OriginalDisabledInitializationEvidence
	Version, State, CurrentHealth, HistoricalReferences, KEKAdmission, DomainState string
	Result                                                                         sec.ConfigBootstrapResult
	Epoch                                                                          uint64
}

type OriginalDisabledInitializationEvidence struct {
	PublicID, ContentSHA256                         string
	RowID, ContentSizeBytes, RowVersion, ChunkCount uint64
	InlineJSON                                      []byte
}

type originalDisabledInitializationRecord struct {
	Version, Operation, RequestSHA256, InstallationID, ConfigSHA256     string
	Head                                                                HeadCAS
	Epoch                                                               uint64
	SnapshotSHA256, C1HistorySHA256, AdoptionOperation, InventorySHA256 string
	Domain                                                              pd.DomainRecord
	CurrentHealth, HistoricalReferences, KEKAdmission                   string
	StartedAt, FinishedAt, DeadlineAt, RetainUntil                      time.Time
}

// InitializeOriginalDisabledUnverified is a DISTINCT original-owner action.
// It does not bypass/change BootstrapConsume, consume expired health, stage a
// KEK admission, advance the KEK/domain epoch, enable a config or create a task.
// Unknown sends are durable and QUERY ONLY; calling this action again refuses.
func (i *Installer) InitializeOriginalDisabledUnverified(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalDisabledInitializationInputs) (OriginalDisabledInitializationReceipt, error) {
	var zero OriginalDisabledInitializationReceipt
	if i == nil || ctx == nil || ctx.Err() != nil || in.Production == nil || in.Recovered == nil || in.Coverage == nil || in.CapacityDB == nil {
		return zero, ErrInstall
	}
	p := in.Production
	if p.origin != p || p.run == nil || p.run.parent == nil || p.run.parent.operator == nil || p.run.parent.operator.installer != i || !consumerSameContext(ctx, p.ctx) || p.run.parent.enrollment != enrollment || p.run.parent.input.Request != in.Request || p.head1 == nil {
		return zero, ErrInstall
	}
	s := in.Recovered
	s.mu.Lock()
	defer s.mu.Unlock()
	if !originalDisabledRecoveredOwner(ctx, i, enrollment, s) {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	r, e := readRequest(i, in.Request)
	if e != nil {
		return zero, ErrInstall
	}
	defer r.observer.Close()
	before, now, e := originalAdoptionAuthoritySnapshot(ctx, op)
	if e != nil || !originalDisabledAuthority(r, before, now) || before.cas != s.owner.initial || before.cas.HeadSHA256 != p.head1.Authority.HeadSHA256 || before.cas.GrantSHA256 != p.head1.Authority.RecordSHA256 {
		return zero, ErrInstall
	}
	plan, e := r.config.DisabledInitializationPlan(r.grant)
	if e != nil {
		return zero, ErrInstall
	}
	requestSHA, operation, e := originalDisabledIdentity(i, enrollment, r, before)
	if e != nil {
		return zero, ErrInstall
	}
	journal, e := originalDisabledJournal(ctx, s)
	if e != nil {
		return zero, e
	}
	for _, record := range journal.Records {
		if record.Action == "disabled_initialization_send_unknown" {
			return zero, ErrCommitUnknown
		}
	}
	snapshot, e := (reg.SQLStore{}).ReadSnapshot(ctx, i.db, r.grant.InstallationID)
	if e != nil {
		return zero, ErrInstall
	}
	configuration, e := in.Coverage.FirstAdoptionConfiguration()
	if e != nil || configuration.DB != i.db || configuration.InstallationID != r.grant.InstallationID || configuration.Database != snapshot.Database {
		return zero, ErrInstall
	}
	adopted, e := originalDisabledAdoptedJournal(journal, snapshot, configuration)
	if e != nil {
		return zero, ErrInstall
	}
	coverage, e := in.Coverage.Prepare(ctx, snapshot)
	if e != nil {
		return zero, ErrInstall
	}
	sources, e := p.CompleteOriginalSources(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	selectedRaw, e := readBootstrapSourcePin(p.head1.Selection, 8<<20)
	var selected pd.BootstrapConsumptionRequest
	if e != nil || decodeOriginalBootstrapRequest(selectedRaw, &selected) != nil {
		return zero, ErrInstall
	}
	digests, e := originalFirstCaptureSelection(r, selected)
	if e != nil || digests.selection != before.record.SelectionSHA256 {
		return zero, ErrInstall
	}
	actual := []pd.BootstrapCandidateSelection{}
	for _, batch := range append([]*OriginalC1SigningProduction{p}, p.children...) {
		actual = append(actual, batch.selections...)
	}
	sort.Slice(actual, func(i, j int) bool { return actual[i].Purpose < actual[j].Purpose })
	if !reflect.DeepEqual(actual, selected.Candidates) {
		return zero, ErrInstall
	}
	// A fresh NATIVE metadata observation, never the pre-cold report or JSON.
	report, e := sec.CollectPinnedRegistrationCapacity(ctx, in.CapacityDB, p.run.capacity)
	if e != nil || report.ServerUUID != i.plan.Target.ServerUUID || report.Database != i.plan.Target.Database || !originalC1CapacityFresh(report, time.Now().UTC()) || plan.CapacityBytes != p.run.parent.capacity {
		return zero, ErrInstall
	}
	until := minTime(op.until, minTime(r.end, minTime(before.head.Until, before.record.Until)))
	until = minTime(until, minTime(coverage.ValidUntil(), now.Add(plan.OperationDeadline)))
	until = minTime(until, report.ObservedAt.Add(5*time.Second))
	until = until.UTC().Truncate(time.Microsecond) // only shortens to SQL precision
	if r.recheck(i) != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	if originalDisabledSQLSession(ctx, tx) != nil {
		return zero, ErrInstall
	}
	// Gates -> global installation/config -> admin/head -> C1 protocol/evidence
	// -> original17 evidence -> metadata reservation -> F/index. No network here.
	if originalDisabledLockReleasedGates(ctx, tx, s) != nil || originalDisabledLockConfigPrefix(ctx, tx, r.grant.InstallationID) != nil {
		return zero, ErrInstall
	}
	started, e := op.lockAdmin(ctx, tx)
	if e != nil {
		return zero, ErrInstall
	}
	head, e := op.current(ctx, tx, false)
	if e != nil || head.cas != before.cas || !originalDisabledAuthority(r, head, started) {
		return zero, ErrInstall
	}
	history, e := a.AuthenticateOriginalC1History(ctx, tx, sources)
	if e != nil {
		return zero, ErrInstall
	}
	historical, e := history.Snapshot()
	if e != nil || historical.InstallationID != r.grant.InstallationID || historical.Database != snapshot.Database || len(historical.Sources) == 0 {
		return zero, ErrInstall
	}
	if coverage.LockOriginalEvidence(ctx, tx) != nil {
		return zero, ErrInstall
	}
	if originalDisabledLockCommittedControls(ctx, tx, adopted) != nil {
		return zero, ErrInstall
	}
	cost := int64(2*len(r.config.CanonicalJSON()) + 65536)
	reservation, e := originalDisabledReserveMetadata(ctx, tx, report, plan.CapacityBytes, cost)
	if e != nil {
		return zero, ErrInstall
	}
	bound, locked, e := (reg.SQLStore{}).Bind(ctx, tx, r.grant.InstallationID)
	if e != nil || !reg.SameSnapshotFacts(locked.Facts(), snapshot) {
		return zero, ErrInstall
	}
	if _, e = bound.CompleteScan(ctx, coverage); e != nil {
		return zero, ErrInstall
	}
	finish, e := i.database(ctx, tx, until)
	if e != nil || finish.Before(started) {
		return zero, ErrInstall
	}
	record := originalDisabledInitializationRecord{Version: originalDisabledInitializationVersion, Operation: operation, RequestSHA256: requestSHA, InstallationID: r.grant.InstallationID, ConfigSHA256: r.config.SHA256(), Head: head.cas, Epoch: snapshot.Epoch, SnapshotSHA256: originalDisabledSnapshotSHA(snapshot), C1HistorySHA256: originalObjectSHA(historical), AdoptionOperation: adopted.Operation, InventorySHA256: adopted.InventorySHA256, Domain: historical.Sources[0].Domain, CurrentHealth: "unknown", HistoricalReferences: "authenticated_original_history", KEKAdmission: "absent", StartedAt: started, FinishedAt: finish, DeadlineAt: until, RetainUntil: finish.Add(plan.Retention)}
	if record.Domain.State != "open" || record.Domain.Admission.Unconfigured == nil || record.Domain.Admission.Configured != nil {
		return zero, ErrInstall
	}
	for _, source := range historical.Sources {
		if !reflect.DeepEqual(source.Domain, record.Domain) {
			return zero, ErrInstall
		}
	}
	if originalDisabledWriteRows(ctx, tx, r.grant, plan, record) != nil {
		return zero, ErrInstall
	}
	// Source-only rereads permit ONLY this action's own inline receipt addition;
	// the complete eight C1 tables and every genuine parent/chunk remain exact.
	if history.Recheck(ctx, tx) != nil {
		return zero, ErrInstall
	}
	current, e := (reg.SQLStore{}).ReadExistingSnapshotInView(ctx, tx, record.InstallationID)
	if e != nil || !reg.SameSnapshotFacts(current, snapshot) || coverage.Recheck(ctx, tx, locked, finish) != nil || originalDisabledNoAdmission(ctx, tx, record.InstallationID) != nil {
		return zero, ErrInstall
	}
	if r.recheck(i) != nil || reservation.recheck(ctx, tx, finish) != nil {
		return zero, ErrInstall
	}
	head, e = op.current(ctx, tx, false)
	if e != nil || head.cas != before.cas {
		return zero, ErrInstall
	}
	if _, e = op.lockAdmin(ctx, tx); e != nil {
		return zero, ErrInstall
	}
	// Record EXACT send intent before COMMIT; no caller receipt authorizes retry.
	if s.journal.append(ctx, "", "disabled_initialization_send_unknown", nil, record) != nil {
		return zero, ErrInstall
	}
	last, e := i.database(ctx, tx, until)
	if e != nil || last.Before(finish) || !originalDisabledAuthority(r, head, last) || !last.Before(report.ObservedAt.Add(5*time.Second)) {
		return zero, ErrInstall
	}
	if e = tx.Commit(); e != nil {
		return zero, ErrCommitUnknown
	}
	// New authenticated independent transaction, even after known COMMIT.
	result, e := i.QueryOriginalDisabledUnverified(ctx, password, enrollment, in.Request)
	if e != nil {
		return zero, ErrCommitUnknown
	}
	if s.journal.append(ctx, "", "disabled_initialization_readback", nil, record) != nil {
		return zero, ErrCommitUnknown
	}
	result.Result.Replayed = false
	return result, nil
}

func originalDisabledAuthority(r *originalRequest, h currentAuthority, now time.Time) bool {
	return r != nil && h.cas.HeadRevision == 1 && h.cas.State == "active" && h.cas.HeadRowVersion > 0 && h.cas.GrantRowVersion > 0 && r.matchesDraft(h.record) && requestWindow(h.record, r, now) && !now.Before(h.head.NotBefore) && now.Before(h.head.Until)
}

func originalDisabledIdentity(i *Installer, enrollment EnrollmentPin, r *originalRequest, h currentAuthority) (string, string, error) {
	if i == nil || r == nil {
		return "", "", ErrInstall
	}
	raw, e := canonical(struct {
		Version, Plan string
		Enrollment    EnrollmentPin
		Request       RequestFiles
		Head          HeadCAS
		Grant         sec.OfflineBootstrapGrant
	}{originalDisabledInitializationVersion, i.planHash, enrollment, r.files, h.cas, r.grant})
	if e != nil {
		return "", "", ErrInstall
	}
	digest := hash(raw)
	// Deterministic v4-shaped public ID; the full SHA remains the request key.
	return digest, "sop_" + digest[:8] + "-" + digest[8:12] + "-4" + digest[13:16] + "-8" + digest[17:20] + "-" + digest[20:32], nil
}

func originalDisabledSnapshotSHA(s reg.Snapshot) string {
	s.ObservedAt = time.Time{}
	return originalObjectSHA(s)
}

func originalDisabledReceipt(r originalDisabledInitializationRecord) OriginalDisabledInitializationReceipt {
	return OriginalDisabledInitializationReceipt{Version: originalDisabledInitializationVersion, State: "disabled_v1_committed_exact_readback_dependencies_unverified", CurrentHealth: "unknown", HistoricalReferences: "authenticated_original_history", KEKAdmission: "absent", DomainState: "open_is_not_write_authority_head1_and_config_fence", Result: sec.ConfigBootstrapResult{OperationPublicID: r.Operation, Version: 1, ConfigSHA256: r.ConfigSHA256}, Epoch: r.Epoch}
}
