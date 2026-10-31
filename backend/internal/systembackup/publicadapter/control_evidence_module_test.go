package publicadapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	corev1 "k8s.io/api/core/v1"
)

// This fixture tests pure assembly, not registered proof production or a live
// source grant. Actual source/pull/C-stream tests remain in worker and CLI.
func controlModuleFixture(t *testing.T) (*fixture, ControlEvidenceModuleConfig) {
	t.Helper()
	f := moduleTestInput(t)
	f.in.Backup.RequestedParts = []string{"mysql", "workspace"}
	now := time.Now().UTC().Add(-time.Minute)
	locator := ce.CaptureLocator{Version: "system-backup-control-evidence-source.v1", Expected: ce.Expected{Scope: ce.Scope{Installation: f.in.Authority.InstallationID, Backup: f.in.Authority.TaskPublicID, Attempt: f.in.Authority.AttemptNo}, ConfigSHA256: f.in.Authority.ConfigSHA256, SourceIdentitySHA256: strings.Repeat("d", 64), SchemaRegistry: ce.RegistryPin{Version: "s1", SHA256: strings.Repeat("a", 64)}, RedactionRegistry: ce.RegistryPin{Version: "r1", SHA256: strings.Repeat("b", 64)}}, Generated: now, Start: now, End: now, SidecarSHA256: strings.Repeat("e", 64), ProofsSHA256: strings.Repeat("f", 64)}
	for n := 0; n < 13; n++ {
		locator.Evidence = append(locator.Evidence, ce.EvidenceRef{PublicID: fmt.Sprintf("sev_fixture_%02d", n), SHA256: strings.Repeat("a", 64)})
	}
	if locator.Validate() != nil {
		t.Fatal("invalid fixture locator")
	}
	point, _ := moduleTestContext(f.in, SourceInventory{}, f.x.HoldUntil, strings.Repeat("a", 64))
	input := CaptureModuleInput{Input: f.in, Context: point, Parts: []CaptureModuleSelection{{CaptureModulePart{ce.Part, ce.Part, "mysql", ce.Operation}, 1}, {CaptureModulePart{ce.ProofPart, ce.Part, "mysql", ce.Operation}, 2}}}
	requests, err := moduleTestRequests(t, f, input)
	if err != nil {
		t.Fatal(err)
	}
	for index := range requests {
		r := &requests[index]
		r.Workload.Source = corev1.Volume{}
		r.Workload.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: "control-formal", Inputs: []kube.FormalInputMount{{Volume: "formal-control-source", Kind: "ConfigMap", Name: "original-source-grant", Directory: "/run/backup/materials/control-source", Items: []corev1.KeyToPath{{Key: "grant.json", Path: "grant.json"}}}}}
		r.Invocation.WorkspacePath = ""
		r.Invocation.Request.MaxFiles, r.Invocation.Request.MaxFileBytes = 0, 0
		r.Invocation.Request.MaxArchiveBytes, r.Invocation.Request.MaxCompressedBytes = ce.MaxBytes, ce.MaxBytes
		r.Invocation.Request.ArtifactName = ce.LogicalCipherName
		if index == 1 {
			r.Invocation.Request.MaxArchiveBytes, r.Invocation.Request.MaxCompressedBytes = ce.MaxProofBytes, ce.MaxProofBytes
			r.Invocation.Request.ArtifactName = ce.LogicalProofCipherName
		}
		r.Invocation.Request.ControlEvidence = &locator
		r.Invocation.FormalCapture = &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), SourceConfigSHA256: f.in.Authority.ConfigSHA256, EnvelopeName: r.Part + ".envelope", MaxFrames: 64, PermitDelivery: &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("e", 64)}}
		binding := r.Invocation.Request.Binding
		r.Invocation.ProviderKey = &k.Access{Operation: k.Generate, Endpoint: "https://bao.invalid", KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("a", 64), RegistryVersion: "r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: f.in.Authority.InstallationID, BackupPublicID: binding.BackupID, AttemptNo: binding.Attempt, Phase: "capture", Part: r.Part, PartIndex: strconv.Itoa(index + 1), EnvelopeID: binding.EnvelopeID, CaptureContextHash: binding.CaptureContextHash}}}
	}
	return f, ControlEvidenceModuleConfig{Revision: "control-r1", Sidecar: requests[0], Proofs: requests[1]}
}

func TestControlEvidenceModuleActualJobsAndGlobalIndices(t *testing.T) {
	f, cfg := controlModuleFixture(t)
	registration, err := NewControlEvidenceModule(cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := moduleTestRegistration(t, f, "a_workspace", "B", "earlier_workspace")
	catalog, err := NewCaptureModules([]CaptureModuleRegistration{registration, before}, moduleTestContext)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := catalog.BuildParts(f.in, SourceInventory{}, f.x.HoldUntil)
	if err != nil || len(parts) != 3 {
		t.Fatal("assembly", err)
	}
	for index, part := range parts {
		var invocation worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &invocation) != nil || invocation.Request.Binding.PartIndex != uint32(index) {
			t.Fatal("wrong global index")
		}
		if index > 0 && (!bytes.Contains(part.Intent.SpecJSON, []byte("--formal-config")) || bytes.Contains(part.Intent.SpecJSON, []byte("source-pvc"))) {
			t.Fatal("not original source-free formal Job")
		}
	}
	// Constructor must freeze caller data.
	cfg.Sidecar.Invocation.Request.ControlEvidence.Evidence[0].SHA256 = strings.Repeat("0", 64)
	cfg.Sidecar.Invocation.Request.ControlEvidence.SidecarSHA256 = strings.Repeat("0", 64)
	cfg.Proofs.Invocation.Request.ControlEvidence.ProofsSHA256 = strings.Repeat("0", 64)
	cfg.Sidecar.Invocation.FormalCapture.PermitDelivery.Issuer[0] ^= 1
	cfg.Proofs.Invocation.ProviderKey.Endpoint = "https://foreign.invalid"
	cfg.Sidecar.Workload.FormalMaterials.Inputs[0].Items[0].Path = "foreign"
	cfg.Proofs.Workload.WorkerControl.InvocationConfigMap = "foreign"
	after, err := catalog.BuildParts(f.in, SourceInventory{}, f.x.HoldUntil)
	if err != nil {
		t.Fatal("caller mutated frozen source", err)
	}
	beforeJSON, _ := json.Marshal(parts)
	afterJSON, _ := json.Marshal(after)
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatal("caller mutation changed original invocation/Job/hash")
	}
}

func TestControlEvidenceModuleRejectsMixedLocatorAndMalformedRegistrations(t *testing.T) {
	f, cfg := controlModuleFixture(t)
	for _, fault := range []string{"mixed-locator", "missing-proof", "wrong-owner", "extra-part", "seventh-selector", "wrong-index", "source-volume"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(cfg)
			var copy ControlEvidenceModuleConfig
			json.Unmarshal(raw, &copy)
			switch fault {
			case "mixed-locator":
				copy.Proofs.Invocation.Request.ControlEvidence.ProofsSHA256 = strings.Repeat("0", 64)
			case "wrong-index":
				copy.Proofs.Invocation.Request.Binding.PartIndex = 1
				copy.Proofs.Invocation.ProviderKey.Request.Context.PartIndex = "1"
			case "source-volume":
				copy.Proofs.Workload.Source = corev1.Volume{Name: "source"}
			}
			r, err := NewControlEvidenceModule(copy)
			if fault == "mixed-locator" || fault == "source-volume" {
				if err == nil {
					t.Fatal("unsafe constructor")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "missing-proof":
				r.Descriptor.Parts = r.Descriptor.Parts[:1]
			case "wrong-owner":
				r.Descriptor.Owner = "A"
			case "extra-part":
				r.Descriptor.Parts = append(r.Descriptor.Parts, CaptureModulePart{"extra", ce.Part, "mysql", ce.Operation})
			case "seventh-selector":
				r.Descriptor.Parts[0].RequestedPart = ce.Part
			}
			catalog, err := NewCaptureModules([]CaptureModuleRegistration{r}, moduleTestContext)
			if fault != "wrong-index" {
				if err == nil {
					t.Fatal("unsafe catalog")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			in := cloneInput(f.in)
			in.Backup.RequestedParts = []string{"mysql"}
			if _, err := catalog.BuildParts(in, SourceInventory{}, f.x.HoldUntil); err == nil {
				t.Fatal("wrong global index accepted")
			}
		})
	}
}
