package install

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	c "clawreef/internal/systembackupcontroller"
)

// The journal is obtained only from the real opaque set. Read the original
// directory under its custody lock and compare the complete prepared census,
// original states and actual dispatched actors. An inspection DTO cannot enter.
func (r *OriginalWriterRecoveryAuthorization) inspectOriginal(ctx context.Context) (OriginalWriterJournalInspection, error) {
	var zero OriginalWriterJournalInspection
	s, j := r.set, r.journal
	if j == nil {
		return zero, ErrInstall
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	// A poisoned/closed writer requires separate exact journal reconciliation;
	// do not erase a failed fsync or manufacture an appendable prefix here.
	if j.failed || j.root == nil || j.operation != r.operation || j.inventory != r.inventory {
		return zero, ErrInstall
	}
	out, err := j.inspect(ctx, r.operation, r.inventory)
	if err != nil || out.TailSHA256 != j.tail || uint64(len(out.Records)) != j.sequence {
		return zero, ErrInstall
	}
	states := map[string]any{}
	for _, provider := range s.preAdoptionProviders {
		if provider == nil || provider.origin != provider || provider.set != s {
			return zero, ErrInstall
		}
		states["provider-dependency/"+provider.input.Workload.Deployment] = provider.originalState()
	}
	for _, provider := range s.providerDependencies {
		if provider == nil || provider.origin != provider || provider.set != s {
			return zero, ErrInstall
		}
		states["provider-dependency/"+provider.selection.Deployment] = provider.initial
	}

	actors := map[string]flow.State{}
	dispatched := map[string]bool{}
	actions := map[string]string{}
	add := func(id string, original flow.State, owner *OriginalWriterMaintenance, journal *originalWriterJournal, stopped bool, action string) bool {
		if id == "" || owner != s.owner || journal != j {
			return false
		}
		if _, duplicate := states[id]; duplicate {
			return false
		}
		states[id], actors[id], dispatched[id], actions[id] = original, original, stopped, action
		return true
	}
	for _, g := range s.gateways {
		if g == nil || !add(g.ID(), g.state, g.owner, g.journal, g.stopDispatched, "stop_send_unknown") {
			return zero, ErrInstall
		}
	}
	for _, w := range s.deployments {
		action := "scale_zero_send_unknown"
		if w != nil && w.redis != nil {
			action = "redis_acl_gate_send_unknown"
		}
		if w != nil && w.replicas == 0 {
			action = ""
		} // originally stopped: no scale RPC was necessary
		if w == nil || !add(w.ID(), w.original, w.owner, w.journal, w.stopDispatched, action) {
			return zero, ErrInstall
		}
	}
	for _, w := range s.proPods {
		if w == nil || !add(w.ID(), w.original, w.owner, w.journal, w.stopDispatched, "delete_original_pod_send_unknown") {
			return zero, ErrInstall
		}
	}
	for _, observed := range s.stoppedObservations {
		if observed == nil || observed.baseline.SourceKey == "" {
			return zero, ErrInstall
		}
		id := observed.baseline.SourceKey
		if _, duplicate := states[id]; duplicate {
			return zero, ErrInstall
		}
		states[id] = observed.baseline
	}
	expected, err := json.Marshal(struct {
		Selection BootstrapSourceFilePin
		Instances []domain.SourceInstance
		Census    originalMaintenanceKubernetesCensus
		States    map[string]any
	}{s.selectionPin, s.owner.instances, s.initial, states})
	if err != nil {
		return zero, ErrInstall
	}
	prepared, acquisition := 0, false
	seen := map[string]bool{}
	for _, record := range out.Records {
		if record.Action == "prepared_original_complete_set" {
			prepared++
			if record.Writer != "" || record.Original != nil || !bytes.Equal(record.Data, expected) {
				return zero, ErrInstall
			}
		}
		if record.Action == "capture_gate_acquire_send_unknown" {
			if prepared != 1 || record.Writer != "" {
				return zero, ErrInstall
			}
			acquisition = true
		}
		if action, ok := actions[record.Writer]; ok && action != "" && record.Action == action {
			if !acquisition || !dispatched[record.Writer] || record.Original == nil || *record.Original != actors[record.Writer] {
				return zero, ErrInstall
			}
			seen[record.Writer] = true
		}
	}
	if prepared != 1 || !acquisition {
		return zero, ErrInstall
	}
	for id, stopped := range dispatched {
		if stopped && actions[id] != "" && !seen[id] {
			return zero, ErrInstall
		}
	}
	return out, nil
}

func (r *OriginalWriterRecoveryAuthorization) checkJournal(ctx context.Context) error {
	j := r.journal
	if j == nil {
		return ErrInstall
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || j.root == nil || j.operation != r.operation || j.inventory != r.inventory {
		return ErrInstall
	}
	out, err := j.inspect(ctx, r.operation, r.inventory)
	if err != nil || out.TailSHA256 != j.tail || uint64(len(out.Records)) != j.sequence ||
		r.prefixLength < 1 || len(out.Records) < r.prefixLength {
		return ErrInstall
	}
	raw, err := json.Marshal(out.Records[r.prefixLength-1])
	if err != nil || hash(raw) != r.prefixSHA {
		return ErrInstall
	}
	return nil
}

type originalRecoveryProviderIntent struct {
	Claim                    c.OriginalAdoptionReservation
	SourceFile, SourceSHA256 string
}

func (r *OriginalWriterRecoveryAuthorization) hasProviderIntent(j OriginalWriterJournalInspection) bool {
	for _, record := range j.Records {
		if record.Action == "archive_provider_prepare" {
			return true
		}
	}
	return false
}

func (r *OriginalWriterRecoveryAuthorization) providersMatchJournal(providers []*OriginalAdoptionArchiveProvider, j OriginalWriterJournalInspection) bool {
	seen := map[*OriginalAdoptionArchiveProvider]bool{}
	used := map[int]bool{}
	for _, provider := range providers {
		if provider == nil || provider.origin != provider || seen[provider] || provider.operator == nil ||
			provider.operator.installer != r.operator.installer || provider.operator.userID != r.operator.userID ||
			provider.enrollment != r.enrollment || !consumerSameContext(provider.outer, r.set.owner.ctx) ||
			provider.reservation.OperationID != r.operation || provider.until.After(r.set.owner.until) {
			return false
		}
		seen[provider] = true
		found := false
		for n, record := range j.Records {
			if used[n] || record.Action != "archive_provider_prepare" {
				continue
			}
			var intent originalRecoveryProviderIntent
			if json.Unmarshal(record.Data, &intent) != nil {
				return false
			}
			raw, err := json.Marshal(intent)
			if err != nil || !bytes.Equal(raw, record.Data) {
				return false
			}
			if reflect.DeepEqual(intent.Claim, provider.reservation) && intent.SourceFile == provider.sourceFile && intent.SourceSHA256 == provider.sourceSHA {
				used[n], found = true, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
