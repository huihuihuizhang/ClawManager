package publicadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
)

// Explicit port/evidence fixtures exercise the real runner and flow ordering.
// CE refuses dispatch until all business evidence has been read; no SQL,
// physical source quiescence or cryptographic observer is claimed here.
type controlOrderPorts struct {
	*fixture
	parts          map[string]JobPart
	bindings       map[string]d.JobBinding
	results        map[string][]byte
	businessRead   map[string]bool
	stops          map[string]bool
	dispatched     []string
	failedBusiness bool
}

func (p *controlOrderPorts) EnsureJob(_ context.Context, _ d.Authority, intent d.JobIntent) (d.JobBinding, error) {
	part, ok := p.parts[intent.JobUnitKey]
	if !ok || !reflect.DeepEqual(part.Intent, intent) || !contains(p.events, "check-paused") {
		return d.JobBinding{}, errors.New("unexpected original intent or missing barrier")
	}
	if part.Part == ce.Part || part.Part == ce.ProofPart {
		if len(p.businessRead) != len(p.parts)-2 {
			return d.JobBinding{}, errors.New("CE dispatched before independent business observations")
		}
	} else if p.failedBusiness {
		return d.JobBinding{}, errors.New("named failed business dispatch")
	}
	p.ensures++
	p.dispatched = append(p.dispatched, part.Part)
	return p.bindings[part.Part], nil
}

func (p *controlOrderPorts) ObserveJob(_ context.Context, _ d.Authority, binding d.JobBinding) (d.JobObservation, error) {
	part, ok := p.parts[binding.JobUnitKey]
	if !ok || binding != p.bindings[part.Part] {
		return d.JobObservation{}, errors.New("foreign original binding")
	}
	a := p.in.Authority
	checkpoint := Checkpoint{SchemaVersion: "system-backup-b-checkpoint.v1", InstallationID: a.InstallationID, ConfigVersion: a.ConfigVersion, TaskPublicID: a.TaskPublicID, AttemptNo: a.AttemptNo, Phase: a.Phase, ConfigSHA256: a.ConfigSHA256, InventorySHA256: p.x.SourceSHA256, Part: part.Part, JobUID: binding.UID, JobGeneration: binding.Generation, InvocationSHA256: part.InvocationSHA256, SealedRef: "named-order-evidence-fixture", ContentSHA256: part.InvocationSHA256}
	rawCheckpoint, _ := json.Marshal(checkpoint)
	raw, _ := json.Marshal(d.ModuleResult{SchemaVersion: "system-backup-part-result.v1", Part: part.Part, Category: part.Category, Status: "completed", Checkpoint: rawCheckpoint, Statistics: map[string]uint64{}, Warnings: []d.Warning{}, EvidenceIDs: []string{}, FailureCategory: "none"})
	p.results[part.Part] = raw
	return d.JobObservation{Binding: binding, Complete: true, ResultEvidence: &d.EvidenceRef{PublicID: "sev_order_" + part.Part, SHA256: digest(raw)}}, nil
}

func (p *controlOrderPorts) Read(_ context.Context, _ d.Authority, binding d.JobBinding, ref d.EvidenceRef) ([]byte, error) {
	raw := p.results[binding.JobUnitKey]
	if len(raw) == 0 || digest(raw) != ref.SHA256 {
		return nil, errors.New("missing original evidence")
	}
	if binding.JobUnitKey != ce.Part && binding.JobUnitKey != ce.ProofPart {
		p.businessRead[binding.JobUnitKey] = true
	}
	return append([]byte{}, raw...), nil
}

func (p *controlOrderPorts) StopJob(_ context.Context, _ d.Authority, binding d.JobBinding) error {
	if binding != p.bindings[binding.JobUnitKey] {
		return errors.New("foreign stop")
	}
	p.stops[binding.JobUnitKey] = true
	p.stopped = len(p.stops) == len(p.dispatched)
	return nil
}

func TestControlEvidenceExecutesAfterBusinessEvidenceWithoutChangingFrozenPlan(t *testing.T) {
	for _, fault := range []string{"valid", "failed-business"} {
		t.Run(fault, func(t *testing.T) {
			f, control := controlModuleFixture(t)
			for index, request := range []*CapturePartRequest{&control.Sidecar, &control.Proofs} {
				request.Invocation.Request.Binding.PartIndex = uint32(index)
				request.Invocation.ProviderKey.Request.Context.PartIndex = strconv.Itoa(index)
			}
			registration, err := NewControlEvidenceModule(control)
			if err != nil {
				t.Fatal(err)
			}
			database := moduleTestRegistration(t, f, "d_database", "B", "original_sql")
			database.Descriptor.Parts[0].RequestedPart, database.Descriptor.Parts[0].Operation = "mysql", "capture-database"
			workspace := moduleTestRegistration(t, f, "z_workspace", "C", "original_workspace")
			modules, err := NewCaptureModules([]CaptureModuleRegistration{registration, database, workspace}, moduleTestContext)
			if err != nil {
				t.Fatal(err)
			}
			source := SourceInventory{Database: "source", ServerUUID: "source-uuid"}
			f.x.Parts, err = modules.BuildParts(f.in, source, f.x.HoldUntil)
			if err != nil {
				t.Fatal(err)
			}
			f.x.Source, _ = json.Marshal(source)
			f.x.SourceSHA256 = digest(f.x.Source)
			if f.x.Parts[0].Part != ce.Part {
				t.Fatal("fixture does not expose original alphabetical CE-first dependency")
			}
			ports := &controlOrderPorts{fixture: f, parts: map[string]JobPart{}, bindings: map[string]d.JobBinding{}, results: map[string][]byte{}, businessRead: map[string]bool{}, stops: map[string]bool{}, failedBusiness: fault == "failed-business"}
			var originalOrder []string
			for index, part := range f.x.Parts {
				originalOrder = append(originalOrder, part.Part)
				ports.parts[part.Part] = part
				binding := f.binding
				binding.JobUnitKey, binding.Name, binding.Namespace, binding.Generation = part.Part, part.Intent.Name, part.Intent.Namespace, part.Intent.Generation
				binding.UID = fmt.Sprintf("%08d-0000-4000-8000-000000000000", index+1)
				ports.bindings[part.Part] = binding
			}
			runner, err := NewPublicRunner(Dependencies{Profiles: map[ProfileKey]Profile{{f.in.ProfileID, f.in.ProfileRevision}: f}, Results: ports, Recovery: f, RecoveryTimeout: time.Second, Admission: func(context.Context, d.Input) error { return nil }, ValidateInventory: func(context.Context, d.Input, Discovery) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := runner.Prepare(context.Background(), f.in, ports)
			if err != nil || ports.ensures != 0 {
				t.Fatal("prepare dispatched a collector", err)
			}
			original := append([]byte{}, plan.CanonicalJSON...)
			results, err := runner.Capture(context.Background(), f.in, plan, ports)
			if fault == "failed-business" {
				if err == nil || len(results) != 0 || len(ports.dispatched) != 0 {
					t.Fatal("business failure dispatched CE or returned completed parts", err)
				}
				return
			}
			if err != nil || len(results) != 4 || len(ports.dispatched) != 4 || ports.dispatched[2] != ce.Part || ports.dispatched[3] != ce.ProofPart {
				t.Fatal("CE dependency ordering", ports.dispatched, err)
			}
			var resultOrder []string
			for _, result := range results {
				resultOrder = append(resultOrder, result.Part)
			}
			if !reflect.DeepEqual(resultOrder, originalOrder) || string(plan.CanonicalJSON) != string(original) || !ports.stopped || at(f.events, "resume") == -1 {
				t.Fatal("execution ordering changed original plan/results or omitted stop/resume")
			}
		})
	}
}
