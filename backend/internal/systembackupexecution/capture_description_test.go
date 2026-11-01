package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
)

// Real production constructors and typed historical packets; all bodies and
// candidate receipts here are DATA fixtures, not SQL/AEAD/certificate evidence.
func descriptionFactoryFixture(t *testing.T) (b.Discovery, worker.Invocation, cd.Description) {
	t.Helper()
	originalMemory := debug.SetMemoryLimit(4 << 30)
	t.Cleanup(func() { debug.SetMemoryLimit(originalMemory) })
	in, source, hold, writers, operations := productionModuleFixture(t)
	op := operations[ce.Operation]
	op.Formal.MaxFrames = 1024
	// D has no source material input: its original using Job pulls its own
	// already observed task records from the existing authenticated controller.
	mapping := *op.Workload.FormalMaterials
	mapping.Inputs = []kube.FormalInputMount{{Volume: "formal-public-ca", Kind: "ConfigMap", Name: "public-provider-ca", Directory: "/run/backup/materials/public", Items: []corev1.KeyToPath{{Key: "ca.pem", Path: "ca.pem"}}}}
	op.Workload.FormalMaterials = &mapping
	operations[cd.Operation] = op
	modules, err := productionCaptureModules(in, source, hold, writers, operations, "description-r1")
	if err != nil {
		t.Fatal("production factory", err)
	}
	parts, err := modules.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal("final BuildParts", err)
	}
	sourceRaw, _ := json.Marshal(source)
	discovery := b.Discovery{Source: sourceRaw, SourceSHA256: hash(sourceRaw), Parts: parts, Writers: writers, HoldUntil: hold}
	var carrier worker.Invocation
	for _, p := range parts {
		if p.Part == cd.Part {
			if json.Unmarshal(p.InvocationJSON, &carrier) != nil {
				t.Fatal("carrier")
			}
		}
	}
	if carrier.Request.CaptureDescription == nil {
		t.Fatal("D was not predeclared")
	}
	seed := *carrier.Request.CaptureDescription
	admin, err := descriptionPlan(seed, parts)
	if err != nil {
		t.Fatal(err)
	}
	description := cd.Description{Version: cd.Version, Scope: cd.Scope{InstallationID: in.Authority.InstallationID, TaskPublicID: in.Authority.TaskPublicID, ConfigVersion: in.Authority.ConfigVersion, ConfigSHA256: in.Authority.ConfigSHA256, AttemptNo: in.Authority.AttemptNo, CaptureContextSHA256: carrier.Request.Binding.CaptureContextHash}, Seed: seed, SourceInventoryJSON: bytes.Clone(sourceRaw), SourceInventorySHA256: hash(sourceRaw), Members: []cd.Member{}, AdministrativeInvocations: admin}
	byName := map[string]b.JobPart{}
	for _, p := range parts {
		byName[p.Part] = p
	}
	for _, selection := range seed.Members {
		p := byName[selection.Part]
		var inv worker.Invocation
		json.Unmarshal(p.InvocationJSON, &inv)
		job := d.JobBinding{JobUnitKey: p.Intent.JobUnitKey, Namespace: p.Intent.Namespace, Name: p.Intent.Name, UID: "fixture-uid-" + p.Part, Generation: p.Intent.Generation}
		candidate := worker.FormalCaptureResult{Version: "public-c-stream-candidate.v1alpha1", InvocationSHA256: p.InvocationSHA256, Ciphertext: staging.Receipt{Name: inv.Request.ArtifactName, Size: 128, SHA256: strings.Repeat("a", 64)}, Envelope: staging.Receipt{Name: inv.FormalCapture.EnvelopeName, Size: 16, SHA256: strings.Repeat("b", 64)}}
		if inv.Request.Database != nil {
			candidate.Tables = 1
		}
		wrapper := FormalCandidateRecord{Version: "public-formal-candidate-record.v1", Authority: in.Authority, Job: job, Pod: BoundPod{Namespace: job.Namespace, Name: "fixture-pod", UID: "fixture-pod-uid", ServiceAccountUID: "fixture-sa-uid"}, InvocationSHA256: p.InvocationSHA256, KeyUseNonce: strings.Repeat("c", 32), ExecutionGrantSHA256: strings.Repeat("d", 64), Candidate: candidate}
		raw, _ := json.Marshal(wrapper)
		description.Members = append(description.Members, cd.Member{Invocation: cd.Invocation{Selection: selection, JSON: bytes.Clone(p.InvocationJSON), SHA256: p.InvocationSHA256}, CandidateJSON: raw, CandidateSHA256: hash(raw), ResultSHA256: strings.Repeat("e", 64)})
	}
	return discovery, carrier, description
}

func TestOriginalDescriptionFactoryPreservesAcyclicBusinessAndControlSets(t *testing.T) {
	discovery, carrier, description := descriptionFactoryFixture(t)
	defer description.Clear()
	if len(description.Members) != len(discovery.Parts)-3 {
		t.Fatal("D/E/P entered business content set")
	}
	raw, err := cd.Encode(description)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if err = inspectOriginalDescriptionPart(context.Background(), bytes.NewReader(raw), carrier, &discovery, description.Scope); err != nil {
		t.Fatal("complete original typed fixture", err)
	}
	foreignConfig := description.Scope
	foreignConfig.ConfigVersion++
	if inspectOriginalDescriptionPart(context.Background(), bytes.NewReader(raw), carrier, &discovery, foreignConfig) == nil {
		t.Fatal("carrier self-declared ConfigVersion replaced authenticated outer scope")
	}
	for _, p := range discovery.Parts {
		if p.Part != cd.Part {
			continue
		}
		var job struct {
			Spec struct{ Template struct{ Spec corev1.PodSpec } }
		}
		if json.Unmarshal(p.Intent.SpecJSON, &job) != nil {
			t.Fatal("job")
		}
		pod := job.Spec.Template.Spec
		memory, err := cd.DecodeMemoryBudget(description.Seed)
		if err != nil || pod.Containers[0].Resources.Requests.Memory().Value() != memory || pod.Containers[0].Resources.Limits.Memory().Value() != memory {
			t.Fatal("description memory was not frozen in original job")
		}
		for _, volume := range pod.Volumes {
			if volume.Name == "workspace" || volume.Name == "source" {
				t.Fatal("D mounted a business source")
			}
		}
	}
	for _, v := range description.AdministrativeInvocations {
		var inv worker.Invocation
		json.Unmarshal(v.JSON, &inv)
		if inv.Request.ControlEvidence != nil {
			if len(inv.Request.ControlEvidence.Finalization.Parts) != len(description.Members) {
				t.Fatal("control policy includes future D result")
			}
			for _, p := range inv.Request.ControlEvidence.Finalization.Parts {
				if p.Part == cd.Part {
					t.Fatal("cycle")
				}
			}
		}
	}
}

func TestOriginalDescriptionReaderRefusesInnerScopeAndBootstrapSubstitution(t *testing.T) {
	for _, fault := range []string{"wrapper-scope", "inner-invocation", "control-policy", "external-plan", "source"} {
		t.Run(fault, func(t *testing.T) {
			discovery, carrier, description := descriptionFactoryFixture(t)
			defer description.Clear()
			switch fault {
			case "wrapper-scope", "inner-invocation":
				var wrapper FormalCandidateRecord
				json.Unmarshal(description.Members[0].CandidateJSON, &wrapper)
				if fault == "wrapper-scope" {
					wrapper.Authority.TaskPublicID = "other-backup"
				} else {
					wrapper.Candidate.InvocationSHA256 = strings.Repeat("f", 64)
				}
				description.Members[0].CandidateJSON, _ = json.Marshal(wrapper)
				description.Members[0].CandidateSHA256 = hash(description.Members[0].CandidateJSON)
			case "control-policy":
				var inv worker.Invocation
				json.Unmarshal(description.AdministrativeInvocations[1].JSON, &inv)
				inv.Request.ControlEvidence.Finalization.Parts[0].InvocationSHA256 = strings.Repeat("f", 64)
				description.AdministrativeInvocations[1].JSON, _ = json.Marshal(inv)
				description.AdministrativeInvocations[1].SHA256 = hash(description.AdministrativeInvocations[1].JSON)
			case "external-plan":
				discovery.Parts = append([]b.JobPart{}, discovery.Parts...)
				discovery.Parts = discovery.Parts[:len(discovery.Parts)-1]
			case "source":
				description.SourceInventoryJSON = []byte(`{"replacement_source":true}`)
				description.SourceInventorySHA256 = hash(description.SourceInventoryJSON)
			}
			raw, err := cd.Encode(description)
			if err != nil {
				t.Fatal("transport fixture", err)
			}
			defer clear(raw)
			if inspectOriginalDescriptionPart(context.Background(), bytes.NewReader(raw), carrier, &discovery, description.Scope) == nil {
				t.Fatal("unbound historical contents accepted")
			}
		})
	}
}
