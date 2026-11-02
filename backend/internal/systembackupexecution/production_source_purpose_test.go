package systembackupexecution

import (
	"encoding/json"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
)

type productionPurposeFixture struct {
	in        d.Input
	source    b.SourceInventory
	hold      time.Time
	binding   *productionSourceBinding
	modules   *b.CaptureModules
	discovery b.Discovery
}

// These are explicit original constructor inputs and actual generated Jobs,
// not SQL admission, deployed source observations or readiness evidence.
func newProductionPurposeFixture(t *testing.T, purpose string) productionPurposeFixture {
	t.Helper()
	in, source, hold, writers, operations := productionModuleFixture(t)
	in.Backup.TaskPurpose = purpose
	var metadata productionCaptureMetadata
	if json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
		t.Fatal("metadata")
	}
	metadata.Redis.Policy.Purpose = purpose
	metadata.FormalMountIdentities = map[string][]kube.MountIdentity{}
	metadata.MountIdentities = map[string]kube.MountIdentity{}
	for name, operation := range operations {
		formal := operation.Workload.FormalMaterials
		pins := []kube.MountIdentity{{Volume: "formal-mapping", Kind: "ConfigMap", Name: formal.ConfigMap, UID: name + "-mapping-uid", SHA256: hash([]byte(name))}}
		for _, input := range formal.Inputs {
			pins = append(pins, kube.MountIdentity{Volume: input.Volume, Kind: input.Kind, Name: input.Name, UID: name + "-input-uid", SHA256: hash([]byte(name + "-input"))})
		}
		operation.MountIdentities = pins
		if !validProductionOperationMounts(operation) {
			t.Fatal("original operation mount pins", name)
		}
		operations[name] = operation
		metadata.FormalMountIdentities[name] = pins
	}
	source.CaptureMetadata, _ = json.Marshal(metadata)
	plan, err := newProductionCapturePlan(operations, "purpose-original-r1")
	if err != nil {
		t.Fatal(err)
	}
	binding := capturePlanBindingFixture(t, plan, operations)
	binding.service.Config.InstallationID = in.Authority.InstallationID
	factory := binding.moduleFactory()
	modules, err := factory(in, source, hold, writers)
	if err != nil {
		t.Fatal("original modules", err)
	}
	parts, err := modules.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal("original Jobs", err)
	}
	// Resolve every source PVC from the actual constructed Job, then rebuild
	// against that complete frozen metadata, including its new context digest.
	for _, part := range parts {
		var job batchv1.Job
		if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
			t.Fatal("Job")
		}
		for _, volume := range job.Spec.Template.Spec.Volumes {
			if volume.Name == "workspace" && volume.PersistentVolumeClaim != nil {
				metadata.MountIdentities[part.Part] = kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: volume.PersistentVolumeClaim.ClaimName, UID: part.Part + "-claim-uid", PVName: part.Part + "-pv", PVUID: part.Part + "-pv-uid", SHA256: hash([]byte(part.Part))}
			}
		}
	}
	source.CaptureMetadata, _ = json.Marshal(metadata)
	modules, err = factory(in, source, hold, writers)
	if err != nil {
		t.Fatal("complete original modules", err)
	}
	parts, err = modules.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal("complete original Jobs", err)
	}
	raw, _ := json.Marshal(source)
	return productionPurposeFixture{in, source, hold, binding, modules, b.Discovery{Parts: parts, Writers: writers, Source: raw, SourceSHA256: hash(raw), HoldUntil: hold}}
}

func TestProductionSixPartOrdinaryPurposeUsesOriginalInputModulesAndMounts(t *testing.T) {
	for _, purpose := range []string{"acceptance", "functional_test"} {
		t.Run(purpose, func(t *testing.T) {
			f := newProductionPurposeFixture(t, purpose)
			if supportedPublicCapture(f.in) == nil || f.binding.owner.supportsCapture(f.in) != nil || len(f.discovery.Parts) != 11 {
				t.Fatal("complete original six-part input was not retained")
			}
			stopped := false
			for _, instance := range f.source.Instances {
				stopped = stopped || instance.ID == 9 && instance.Status == "stopped"
			}
			if !stopped {
				t.Fatal("original stopped fixture removed")
			}
			for _, part := range f.discovery.Parts {
				pins, production, err := f.binding.owner.productionMountsFromOriginal(f.in, f.discovery, part)
				if err != nil || !production || len(pins) < 2 {
					t.Fatal("six-part operation skipped original mount identity checks", part.Part, production, err)
				}
			}
		})
	}
}

func TestProductionSixPartOrdinaryPurposeRequiresCompleteOriginalBinding(t *testing.T) {
	for _, fault := range []string{"unbound", "foreign-owner", "foreign-installation", "workspace-scope", "not-backup", "no-spec", "partial", "duplicate-part", "unknown-part", "unknown-purpose", "wrong-runner", "partial-acceptance"} {
		t.Run(fault, func(t *testing.T) {
			in, _, _, _, _ := productionModuleFixture(t)
			in.Backup.TaskPurpose = "functional_test"
			owner := &PublicJobOwner{}
			service := &DeploymentService{Config: DeploymentConfig{CaptureScope: "six-part", InstallationID: in.Authority.InstallationID}}
			owner.productionSource = &productionSourceBinding{service: service, owner: owner}
			switch fault {
			case "unbound":
				owner.productionSource = nil
			case "foreign-owner":
				owner.productionSource.owner = &PublicJobOwner{}
			case "foreign-installation":
				in.Authority.InstallationID = "foreign"
			case "workspace-scope":
				service.Config.CaptureScope = "runtime-workspace"
			case "not-backup":
				in.Authority.TaskType = "restore"
			case "no-spec":
				in.Backup = nil
			case "partial":
				in.Backup.RequestedParts = []string{"mysql", "workspace"}
			case "duplicate-part":
				in.Backup.RequestedParts[0] = "workspace"
			case "unknown-part":
				in.Backup.RequestedParts[0] = "unknown"
			case "unknown-purpose":
				in.Backup.TaskPurpose = "ordinary"
			case "wrong-runner":
				in.Backup.Runner = "k3s"
			case "partial-acceptance":
				in.Backup.TaskPurpose = "acceptance"
				in.Backup.RequestedParts = []string{"workspace"}
			}
			if owner.supportsCapture(in) == nil {
				t.Fatal("unsupported input or missing original binding accepted")
			}
			if fault == "unbound" {
				if _, production, err := owner.productionMountsFromOriginal(in, b.Discovery{}, b.JobPart{}); err == nil || production {
					t.Fatal("unbound complete capture skipped production mount checks")
				}
			}
		})
	}
	// The original single-workspace path remains supported without attaching
	// a six-part production binding or treating it as a complete backup.
	in, _, _, _, _ := productionModuleFixture(t)
	in.Backup.TaskPurpose, in.Backup.RequestedParts = "functional_test", []string{"workspace"}
	owner := &PublicJobOwner{productionSource: &productionSourceBinding{}}
	if supportedPublicCapture(in) != nil || owner.supportsCapture(in) != nil {
		t.Fatal("original workspace path changed")
	}
	if pins, production, err := owner.productionMountsFromOriginal(in, b.Discovery{}, b.JobPart{}); err != nil || production || len(pins) != 0 {
		t.Fatal("workspace was reclassified as full production capture", err)
	}
}

func TestProductionSixPartOrdinaryPurposeRejectsOriginalMountAndPurposeDrift(t *testing.T) {
	for _, purpose := range []string{"functional_test", "acceptance"} {
		f := newProductionPurposeFixture(t, purpose)
		var workspace b.JobPart
		for _, part := range f.discovery.Parts {
			if part.Part == "instance_7_workspace" {
				workspace = part
			}
		}
		if workspace.Part == "" {
			t.Fatal("original workspace missing")
		}
		for _, fault := range []string{"purpose-drift", "unknown-purpose", "partial", "foreign-installation", "foreign-unit", "invocation-bytes", "job-bytes", "missing-operation", "foreign-formal-name", "missing-formal-uid", "missing-pv-uid"} {
			t.Run(purpose+"/"+fault, func(t *testing.T) {
				var changed struct {
					Input     d.Input
					Discovery b.Discovery
					Part      b.JobPart
				}
				raw, _ := json.Marshal(struct {
					Input     d.Input
					Discovery b.Discovery
					Part      b.JobPart
				}{f.in, f.discovery, workspace})
				if json.Unmarshal(raw, &changed) != nil {
					t.Fatal("fixture copy")
				}
				var source b.SourceInventory
				var metadata productionCaptureMetadata
				if json.Unmarshal(changed.Discovery.Source, &source) != nil || json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
					t.Fatal("original metadata")
				}
				switch fault {
				case "purpose-drift":
					changed.Input.Backup.TaskPurpose = "functional_test"
					if purpose == "functional_test" {
						changed.Input.Backup.TaskPurpose = "acceptance"
					}
					if _, err := f.modules.BuildParts(changed.Input, f.source, f.hold); err == nil {
						t.Fatal("original module accepted a changed task purpose")
					}
				case "unknown-purpose":
					changed.Input.Backup.TaskPurpose = "ordinary"
				case "partial":
					changed.Input.Backup.RequestedParts = []string{"mysql", "workspace"}
				case "foreign-installation":
					changed.Input.Authority.InstallationID = "foreign"
				case "foreign-unit":
					changed.Part.Intent.JobUnitKey = "foreign"
				case "invocation-bytes":
					changed.Part.InvocationJSON = append(changed.Part.InvocationJSON, ' ')
				case "job-bytes":
					changed.Part.Intent.SpecJSON = append(changed.Part.Intent.SpecJSON, ' ')
				case "missing-operation":
					delete(metadata.FormalMountIdentities, "capture-workspace")
				case "foreign-formal-name":
					metadata.FormalMountIdentities["capture-workspace"][0].Name = "foreign"
				case "missing-formal-uid":
					metadata.FormalMountIdentities["capture-workspace"][0].UID = ""
				case "missing-pv-uid":
					pin := metadata.MountIdentities[changed.Part.Part]
					pin.PVUID = ""
					metadata.MountIdentities[changed.Part.Part] = pin
				}
				source.CaptureMetadata, _ = json.Marshal(metadata)
				changed.Discovery.Source, _ = json.Marshal(source)
				changed.Discovery.SourceSHA256 = hash(changed.Discovery.Source)
				if _, production, err := f.binding.owner.productionMountsFromOriginal(changed.Input, changed.Discovery, changed.Part); err == nil || production {
					t.Fatal("foreign input skipped original production security checks", production, err)
				}
			})
		}
	}
}
