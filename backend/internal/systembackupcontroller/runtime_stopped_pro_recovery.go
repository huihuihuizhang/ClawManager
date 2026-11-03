package systembackupcontroller

import (
	"context"
	"encoding/json"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

// A completed control row alone is not a native observation. This performs a
// new authenticated native sample against the exact original persisted anchor.
func (o *SQLRuntimeControl) ObserveStoppedProSourceRecovery(ctx context.Context, a d.Authority, writer b.FrozenWriter) (RuntimeStoppedProRecord, error) {
	row, record, err := o.stoppedProRead(ctx, a, writer.ID, writer.Original, true)
	if err != nil || !row.Completed || !row.Stopped.Valid || record.Stopped == nil || record.Recovered == nil {
		return RuntimeStoppedProRecord{}, ErrSourceRecoveryStoppedWitnessRequired
	}
	proof, err := o.stoppedProObserve(ctx, a, row, record, "recovered-stopped")
	if err != nil {
		return RuntimeStoppedProRecord{}, err
	}
	again, _, err := o.stoppedProRead(ctx, a, writer.ID, writer.Original, true)
	if err != nil || again.Version != row.Version || again.Spec != row.Spec {
		return RuntimeStoppedProRecord{}, ErrSourceRecoveryProofRequired
	}
	response := proof.Response()
	record.Recovered = &response
	return record, nil
}

func validStoppedProRecoveryRecord(record RuntimeStoppedProRecord, spec b.RuntimeWriterSpec, a d.Authority) bool {
	baseline, err := stoppedProSpec(spec)
	r := record.Request
	if err != nil || record.Version != "runtime-current-stopped-pro.v1" || record.Stopped == nil || record.Recovered == nil || !sourceRecoveryEqual(r.Baseline, baseline) || r.Binding.InstallationID != a.InstallationID || r.Binding.OperationID != a.TaskPublicID || r.Binding.Generation != uint64(spec.Source.Generation) || r.Binding.Kind != q.StoppedProObservationProtocol || r.Binding.NamespaceUID != baseline.NamespaceUID || r.OriginalStateSHA256 != q.StoppedProOriginalStateSHA256(spec.Stopped) || r.NativeScopeSHA256 != q.StoppedProNativeScopeSHA256(r) || !executionHash.MatchString(r.OriginalReservationIdentitySHA256) || record.Prepare.Anchor == "" || record.Prepare.BootID == "" {
		return false
	}
	for _, response := range []q.StoppedProNodeObservationResponse{record.Prepare, *record.Stopped, *record.Recovered} {
		if response.Anchor != record.Prepare.Anchor || response.BootID != record.Prepare.BootID || !sourceRecoveryEqual(response.Binding, r.Binding) || response.BaselineSHA256 != q.StoppedProBaselineSHA256(baseline) || response.OriginalReservationIdentitySHA256 != r.OriginalReservationIdentitySHA256 || response.OriginalStateSHA256 != r.OriginalStateSHA256 || response.NativeScopeSHA256 != r.NativeScopeSHA256 || response.TasksChecked <= 0 || response.Files <= 0 || !executionHash.MatchString(response.CRIObservationSHA256) || response.FinishedAt.Before(response.StartedAt) || !response.FinishedAt.Before(response.ValidUntil) {
			return false
		}
		wire := r
		wire.Version, wire.Action, wire.Nonce, wire.Deadline = response.Version, response.Action, response.Nonce, response.ValidUntil
		wire.Anchor = ""
		if response.Action != "prepare" {
			wire.Anchor = record.Prepare.Anchor
		}
		body, err := json.Marshal(wire)
		if err != nil || response.Version != q.StoppedProObservationProtocol || !executionHash.MatchString(response.Nonce) || recordHash(body) != response.RequestSHA256 {
			return false
		}
	}
	return record.Prepare.Action == "prepare" && record.Stopped.Action == "stopped" && record.Recovered.Action == "recovered-stopped" && !record.Stopped.StartedAt.Before(record.Prepare.StartedAt) && !record.Recovered.StartedAt.Before(record.Stopped.StartedAt)
}

func (p *PreparedSourceRecovery) validateStoppedProLeaf(writer b.FrozenWriter, leaf sourceRecoveryLeaf, instances map[int]b.InstanceIdentity, materials []json.RawMessage) error {
	var facts struct {
		Version, Kind string
		Runtime       SourceRecoveryRuntime
		Material      json.RawMessage
		Native        RuntimeStoppedProRecord
	}
	if leaf.SourceRecoveryObservation.Scope != "current_stopped_pro_native_baseline_and_volume_bindings" || json.Unmarshal(leaf.Facts, &facts) != nil || facts.Version != "source-recovery-current-stopped-pro.v1" || facts.Kind != "stopped" || writer.Original.Running || facts.Runtime.Spec.Stopped != writer.Original || !validStoppedProRecoveryRecord(facts.Native, facts.Runtime.Spec, p.a) {
		return ErrSourceRecoveryStoppedWitnessRequired
	}
	r := facts.Runtime
	raw, err := json.Marshal(r.Spec)
	instance, exists := instances[r.Spec.Source.ID]
	if err != nil || recordHash(raw) != r.SpecSHA256 || !exists || instance != r.Spec.Source || runtimeWriterID(r.Spec) != writer.ID {
		return ErrSourceRecoveryProofRequired
	}
	var material struct {
		Version  string
		Source   b.InstanceIdentity
		Baseline q.StoppedProBaseline
	}
	if json.Unmarshal(facts.Material, &material) != nil || material.Version != "current-stopped-pro-source-material.v1" || material.Source != instance || !sourceRecoveryEqual(material.Baseline, facts.Native.Request.Baseline) {
		return ErrSourceRecoveryProofRequired
	}
	pins := 0
	for _, original := range materials {
		if sourceRecoveryEqual(original, facts.Material) {
			pins++
		}
	}
	if pins != 1 {
		return ErrSourceRecoveryProofRequired
	}
	var control struct {
		Spec               b.RuntimeWriterSpec
		Completed, Claimed bool
		Resumed            json.RawMessage
		Stopped            struct {
			String string
			Valid  bool
		}
	}
	var source b.InstanceIdentity
	var saved RuntimeStoppedProRecord
	if json.Unmarshal(r.ControlRow, &control) != nil || !control.Completed || control.Claimed || control.Spec != r.Spec || !sourceRecoveryEqual(control.Resumed, r.Resumed) || json.Unmarshal(r.SourceRow, &source) != nil || source != instance || json.Unmarshal(r.Resumed, &saved) != nil || !validStoppedProRecoveryRecord(saved, r.Spec, p.a) || !sourceRecoveryEqual(saved.Request, facts.Native.Request) || !sourceRecoveryEqual(saved.Prepare, facts.Native.Prepare) || !sourceRecoveryEqual(saved.Stopped, facts.Native.Stopped) {
		return ErrSourceRecoveryProofRequired
	}
	body, err := json.Marshal(saved.Stopped)
	if err != nil || !control.Stopped.Valid || control.Stopped.String != recordHash(body) {
		return ErrSourceRecoveryProofRequired
	}
	// Facts are a bounded native sample, not a start receipt or an incremented
	// source generation. The actual keeper observed this while admission was held.
	if facts.Native.Recovered.FinishedAt.After(time.Now().Add(2 * time.Second)) {
		return ErrSourceRecoveryProofRequired
	}
	delete(instances, instance.ID)
	return nil
}
