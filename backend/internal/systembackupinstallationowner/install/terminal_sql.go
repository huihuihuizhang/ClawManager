package install

import (
	"context"
	"reflect"
	"sort"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func sameOriginalAdmission(a, b pd.Admission) bool { return reflect.DeepEqual(a, b) }

func (s *bootstrapTerminalSession) selectedFacts(facts pd.BootstrapConsumptionFacts) ([]pd.ResultFacts, error) {
	expected := map[pd.Hash]pd.BootstrapCandidateSelection{}
	for _, candidate := range s.request.Candidates {
		digests, e := pd.ResultHashes(candidate.Request)
		if e != nil {
			return nil, ErrInstall
		}
		if prior, ok := expected[digests.Key]; ok && (!reflect.DeepEqual(prior.Request, candidate.Request) || prior.ResultVersion != candidate.ResultVersion) {
			return nil, ErrInstall
		}
		expected[digests.Key] = candidate
	}
	if len(facts.Candidates) != len(expected) || facts.Domain.Scope != s.request.Scope {
		return nil, ErrInstall
	}
	seen := map[pd.Hash]bool{}
	for _, actual := range facts.Candidates {
		if actual.Receipt == nil || actual.Grant == nil || actual.Run == nil || actual.History == nil {
			return nil, ErrInstall
		}
		digests, e := pd.ResultHashes(actual.Receipt.Request)
		if e != nil {
			return nil, ErrInstall
		}
		chosen, ok := expected[digests.Key]
		if !ok || seen[digests.Key] || !reflect.DeepEqual(chosen.Request, actual.Receipt.Request) || actual.Receipt.RequestHash != digests.Request || actual.Receipt.ResultVersion != chosen.ResultVersion || actual.Grant.Scope != s.request.Scope || actual.Grant.GrantID != chosen.Request.GrantID || actual.Grant.Generation != chosen.Request.GrantGeneration || actual.Grant.State != "active" || string(actual.Grant.IssuerIdentityHash) != s.loaded.mapping.ProducerIssuerIdentitySHA256 || !sameOriginalAdmission(actual.Grant.Admission, chosen.Request.Admission) || actual.Run.RunID != chosen.Request.RunID || actual.Run.GrantID != actual.Grant.GrantID || actual.Run.State != "committed" || actual.History.RunID != actual.Run.RunID || actual.History.Evidence.EvidenceID != chosen.Request.Evidence.EvidenceID {
			return nil, ErrInstall
		}
		seen[digests.Key] = true
	}
	return sortedTerminalCandidates(facts), nil
}

func (s *bootstrapTerminalSession) lockHosts(ctx context.Context, tx pd.BootstrapSQL, facts pd.BootstrapConsumptionFacts) error {
	selected, e := s.selectedFacts(facts)
	if e != nil {
		return e
	}
	before, e := tx.SampleTime(ctx)
	if e != nil || !s.hostCurrent(before) {
		return ErrInstall
	}
	if e := s.lockOriginalProducerSources(ctx, tx, selected); e != nil {
		return e
	}
	hosts := map[string]bool{}
	for _, host := range s.loaded.mapping.Hosts {
		hosts[host.WorkloadIdentitySHA256] = true
	}
	seen := map[pd.ID]bool{}
	for _, candidate := range selected {
		grant := candidate.Grant
		if grant.Host.Service == nil || grant.Host.Job != nil || !hosts[string(grant.Host.Service.WorkloadIdentityHash)] {
			return ErrInstall
		}
		if seen[grant.GrantID] {
			continue
		}
		var actual pd.GrantRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, tx, s.request.Scope, pd.RecordKey{ID: grant.GrantID}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, *grant) {
			return ErrInstall
		}
		// D locked this exact grant at L3; no earlier new range is acquired.
		copy := actual
		s.grants = append(s.grants, &copy)
		seen[grant.GrantID] = true
	}
	after, e := tx.SampleTime(ctx)
	if e != nil || after.Before(before) || !s.hostCurrent(after) {
		return ErrInstall
	}
	return nil
}
func (s *bootstrapTerminalSession) hostCurrent(now time.Time) bool {
	if s.loaded.hostUntil == nil {
		return false
	}
	until, e := s.loaded.hostUntil.Time()
	return e == nil && !now.Before(s.loaded.mapping.NotBefore) && now.Before(until) && now.Before(s.loaded.mapping.Until)
}
func (s *bootstrapTerminalSession) lockTargets(ctx context.Context, tx pd.BootstrapSQL, facts pd.BootstrapConsumptionFacts) error {
	selected, e := s.selectedFacts(facts)
	if e != nil {
		return e
	}
	byHash := map[pd.Hash]pd.TargetRecord{}
	for _, candidate := range selected {
		if candidate.Target == nil {
			return ErrInstall
		}
		digests, e := pd.ResultHashes(candidate.Receipt.Request)
		if e != nil || candidate.Target.Scope != s.request.Scope || candidate.Target.TargetHash != digests.Target || !reflect.DeepEqual(candidate.Target.Target, candidate.Receipt.Request.Target) || candidate.Target.CurrentRunID != candidate.Receipt.Request.RunID || candidate.Target.Generation != candidate.Receipt.Request.TargetGeneration || candidate.Target.ResultVersion != pd.ZeroCounter(candidate.Receipt.ResultVersion) {
			return ErrInstall
		}
		if prior, ok := byHash[digests.Target]; ok && !reflect.DeepEqual(prior, *candidate.Target) {
			return ErrInstall
		}
		byHash[digests.Target] = *candidate.Target
	}
	keys := make([]pd.Hash, 0, len(byHash))
	for key := range byHash {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		var actual pd.TargetRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, tx, s.request.Scope, pd.RecordKey{Hash: key}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, byHash[key]) {
			return ErrInstall
		}
		copy := actual
		s.targets = append(s.targets, &copy)
	}
	return nil
}
func (s *bootstrapTerminalSession) matchesEvidenceFacts(facts pd.BootstrapConsumptionFacts) bool {
	selected, e := s.selectedFacts(facts)
	if e != nil {
		return false
	}
	expected, e := s.loaded.evidence.ExpectedBindings()
	if e != nil {
		return false
	}
	byID := map[pd.EvidenceID]pd.EvidenceBinding{}
	for _, entry := range expected {
		byID[entry.EvidenceID] = entry
	}
	for _, candidate := range selected {
		r := candidate.Receipt.Request
		original, ok := byID[r.Evidence.EvidenceID]
		if !ok || !reflect.DeepEqual(original, r.Evidence) || candidate.History.Evidence.EvidenceID != r.Evidence.EvidenceID {
			return false
		}
	}
	return true
}
func (s *bootstrapTerminalSession) captureReferences(facts pd.BootstrapConsumptionFacts) error {
	selected, e := s.selectedFacts(facts)
	if e != nil {
		return e
	}
	type key struct {
		id   pd.EvidenceID
		kind string
		hash pd.Hash
	}
	seen := map[key]pd.ReferenceRecord{}
	for _, candidate := range selected {
		if len(candidate.References) != 3 {
			return ErrInstall
		}
		kinds := map[string]bool{}
		for _, ref := range candidate.References {
			if ref.Scope != s.request.Scope || ref.EvidenceID != candidate.Receipt.Request.Evidence.EvidenceID || kinds[ref.ReferenceKind] {
				return ErrInstall
			}
			want := candidate.History.RetentionExpiresAt
			digests, e := pd.ResultHashes(candidate.Receipt.Request)
			if e != nil {
				return ErrInstall
			}
			switch ref.ReferenceKind {
			case "bootstrap_candidate":
				if ref.ReferenceKeyHash != digests.Key {
					return ErrInstall
				}
			case "hold":
				hold, e := pd.OriginalPendingReferenceHash(*candidate.History)
				if e != nil || ref.ReferenceKeyHash != hold || ref.CreatedAt != candidate.History.CreatedAt {
					return ErrInstall
				}
			case "producer_receipt":
				want = candidate.Receipt.RetentionExpiresAt
				if ref.ReferenceKeyHash != digests.Key {
					return ErrInstall
				}
			default:
				return ErrInstall
			}
			if ref.ProtectedUntil != want {
				return ErrInstall
			}
			kinds[ref.ReferenceKind] = true
			k := key{ref.EvidenceID, ref.ReferenceKind, ref.ReferenceKeyHash}
			if previous, ok := seen[k]; ok && !reflect.DeepEqual(previous, ref) {
				return ErrInstall
			}
			seen[k] = ref
		}
	}
	keys := make([]key, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.id != b.id {
			return a.id < b.id
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.hash < b.hash
	})
	for _, key := range keys {
		s.references = append(s.references, seen[key])
	}
	return nil
}
func (s *bootstrapTerminalSession) recheckSQLSources(ctx context.Context, view pd.BootstrapReadSQL) error {
	before, e := view.SampleTime(ctx)
	if e != nil || !s.hostCurrent(before) {
		return ErrInstall
	}
	for _, expected := range s.receipts {
		var actual pd.ReceiptRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, view, s.request.Scope, pd.RecordKey{Hash: expected.ReceiptKeyHash}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, *expected) {
			return ErrInstall
		}
	}
	for _, expected := range s.grants {
		var actual pd.GrantRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, view, s.request.Scope, pd.RecordKey{ID: expected.GrantID}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, *expected) {
			return ErrInstall
		}
	}
	for _, expected := range s.runs {
		var actual pd.RunRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, view, s.request.Scope, pd.RecordKey{ID: expected.RunID}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, *expected) {
			return ErrInstall
		}
	}
	for _, expected := range s.histories {
		var actual pd.HistoricalBindingRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, view, s.request.Scope, pd.RecordKey{EvidenceID: expected.Evidence.EvidenceID}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, *expected) {
			return ErrInstall
		}
	}
	for _, expected := range s.targets {
		var actual pd.TargetRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, view, s.request.Scope, pd.RecordKey{Hash: expected.TargetHash}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, *expected) {
			return ErrInstall
		}
	}
	for _, expected := range s.references {
		var actual pd.ReferenceRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, view, s.request.Scope, pd.RecordKey{EvidenceID: expected.EvidenceID, ReferenceKind: expected.ReferenceKind, Hash: expected.ReferenceKeyHash}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, expected) {
			return ErrInstall
		}
	}
	after, e := view.SampleTime(ctx)
	if e != nil || after.Before(before) || !s.hostCurrent(after) {
		return ErrInstall
	}
	return nil
}

func (s *bootstrapTerminalSession) lockOriginalProducerSources(ctx context.Context, view pd.BootstrapReadSQL, selected []pd.ResultFacts) error {
	byReceipt := map[pd.Hash]*pd.ReceiptRecord{}
	byRun := map[pd.ID]*pd.RunRecord{}
	byHistory := map[pd.EvidenceID]*pd.HistoricalBindingRecord{}
	for _, candidate := range selected {
		digests, e := pd.ResultHashes(candidate.Receipt.Request)
		if e != nil || candidate.Receipt.ReceiptKeyHash != digests.Key {
			return ErrInstall
		}
		byReceipt[digests.Key] = candidate.Receipt
		if prior, ok := byRun[candidate.Run.RunID]; ok && !reflect.DeepEqual(prior, candidate.Run) {
			return ErrInstall
		}
		byRun[candidate.Run.RunID] = candidate.Run
		if prior, ok := byHistory[candidate.History.Evidence.EvidenceID]; ok && !reflect.DeepEqual(prior, candidate.History) {
			return ErrInstall
		}
		byHistory[candidate.History.Evidence.EvidenceID] = candidate.History
	}
	receiptIDs := make([]pd.Hash, 0, len(byReceipt))
	for key := range byReceipt {
		receiptIDs = append(receiptIDs, key)
	}
	sort.Slice(receiptIDs, func(i, j int) bool { return receiptIDs[i] < receiptIDs[j] })
	for _, key := range receiptIDs {
		var actual pd.ReceiptRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, view, s.request.Scope, pd.RecordKey{Hash: key}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, *byReceipt[key]) {
			return ErrInstall
		}
		copy := actual
		s.receipts = append(s.receipts, &copy)
	}
	runIDs := make([]pd.ID, 0, len(byRun))
	for key := range byRun {
		runIDs = append(runIDs, key)
	}
	sort.Slice(runIDs, func(i, j int) bool { return runIDs[i] < runIDs[j] })
	for _, key := range runIDs {
		var actual pd.RunRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, view, s.request.Scope, pd.RecordKey{ID: key}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, *byRun[key]) {
			return ErrInstall
		}
		copy := actual
		s.runs = append(s.runs, &copy)
	}
	historyIDs := make([]pd.EvidenceID, 0, len(byHistory))
	for key := range byHistory {
		historyIDs = append(historyIDs, key)
	}
	sort.Slice(historyIDs, func(i, j int) bool { return historyIDs[i] < historyIDs[j] })
	for _, key := range historyIDs {
		var actual pd.HistoricalBindingRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, view, s.request.Scope, pd.RecordKey{EvidenceID: key}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, *byHistory[key]) {
			return ErrInstall
		}
		copy := actual
		s.histories = append(s.histories, &copy)
	}
	return nil
}
