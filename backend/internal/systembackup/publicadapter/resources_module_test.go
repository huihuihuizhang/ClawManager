package publicadapter

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	corev1 "k8s.io/api/core/v1"
)

func TestDResourceModuleMaterializesBothActualJobsAndNeverDowngradesMissingPart(t *testing.T) {
	f := moduleTestInput(t)
	f.in.Backup.RequestedParts = []string{"deployment_resources", "secret_bundle"}
	point, _ := moduleTestContext(f.in, SourceInventory{Users: []int{1}}, f.x.HoldUntil, strings.Repeat("a", 64))
	input := CaptureModuleInput{Input: f.in, Source: SourceInventory{Users: []int{1}}, Context: point, Parts: []CaptureModuleSelection{{CaptureModulePart{"deployment_resources", "deployment_resources", "deployment_resources", "capture-deployment-resources"}, 0}, {CaptureModulePart{"secret_bundle", "secret_bundle", "secret_bundle", "capture-secret-bundle"}, 1}}}
	requests, err := moduleTestRequests(t, f, input)
	if err != nil {
		t.Fatal(err)
	}
	for index := range requests {
		r := &requests[index]
		part := r.Part
		resource := "configmaps"
		if part == "secret_bundle" {
			resource = "secrets"
		}
		r.Workload.Source = corev1.Volume{}
		r.Workload.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: strings.ReplaceAll(part, "_", "-") + "-mapping", Inputs: []kube.FormalInputMount{{Volume: "formal-resource-source", Kind: "Secret", Name: strings.ReplaceAll(part, "_", "-") + "-reader", Directory: "/run/backup/materials/resource-source", Items: []corev1.KeyToPath{{Key: "token", Path: "token"}}}}}
		r.Invocation.WorkspacePath = ""
		r.Invocation.Request.MaxFiles, r.Invocation.Request.MaxFileBytes = 0, 0
		r.Invocation.Request.Resources = &worker.ResourceCaptureSpec{Part: part, Namespace: r.Workload.Identity.Namespace, NamespaceUID: "source-namespace-uid", ServiceAccountName: "reader-" + strconv.Itoa(index), ServiceAccountUID: "source-sa-" + strconv.Itoa(index), Selections: []c.KubernetesSelection{{Version: "v1", Resource: resource, Name: "original", UID: "original-uid"}}, MaxItems: 10, OriginalWriters: []worker.ResourceWriterOriginal{}}
		r.Invocation.FormalCapture = &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), EnvelopeName: part + ".envelope", MaxFrames: 8}
		binding := r.Invocation.Request.Binding
		r.Invocation.ProviderKey = &k.Access{Operation: k.Generate, Endpoint: "https://bao.invalid", KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("a", 64), RegistryVersion: "r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: f.in.Authority.InstallationID, BackupPublicID: binding.BackupID, AttemptNo: binding.Attempt, Phase: "capture", Part: part, PartIndex: strconv.Itoa(index), EnvelopeID: binding.EnvelopeID, CaptureContextHash: binding.CaptureContextHash}}}
	}
	for _, fault := range []string{"", "same-source-sa", "same-materials", "wrong-namespace", "missing-formal", "missing-part"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(ResourceCaptureModuleConfig{Revision: "d-resource-r1", Deployment: requests[0], Secrets: requests[1]})
			var cfg ResourceCaptureModuleConfig
			json.Unmarshal(raw, &cfg)
			switch fault {
			case "same-source-sa":
				cfg.Secrets.Invocation.Request.Resources.ServiceAccountUID = cfg.Deployment.Invocation.Request.Resources.ServiceAccountUID
			case "same-materials":
				cfg.Secrets.Workload.FormalMaterials.ConfigMap = cfg.Deployment.Workload.FormalMaterials.ConfigMap
			case "wrong-namespace":
				cfg.Secrets.Invocation.Request.Resources.NamespaceUID = "other-namespace"
			case "missing-formal":
				cfg.Deployment.Invocation.FormalCapture = nil
			}
			registration, err := NewResourceCaptureModule(cfg)
			if fault != "" && fault != "missing-part" {
				if err == nil {
					t.Fatal("unsafe resources module accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := NewCaptureModules([]CaptureModuleRegistration{registration}, moduleTestContext)
			if err != nil {
				t.Fatal(err)
			}
			in := cloneInput(f.in)
			if fault == "missing-part" {
				in.Backup.RequestedParts = []string{"deployment_resources"}
			}
			parts, err := catalog.BuildParts(in, input.Source, f.x.HoldUntil)
			if fault == "missing-part" {
				if err == nil {
					t.Fatal("missing secret bundle downgraded to success")
				}
				return
			}
			if err != nil || len(parts) != 2 {
				t.Fatal("actual D jobs failed assembly", err)
			}
			for _, part := range parts {
				if !strings.Contains(string(part.Intent.SpecJSON), "--formal-config") {
					t.Fatal("formal CLI mount missing")
				}
			}
		})
	}
}
