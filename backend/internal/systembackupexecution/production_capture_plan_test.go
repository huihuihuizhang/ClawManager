package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	ce "clawreef/internal/systembackupcontrolevidence"
)

// Pure original constructor fixtures only; these never approve deployed source
// permissions, physical stopped witnesses, or readiness.
func capturePlanBindingFixture(t *testing.T, plan *productionCapturePlan, operations map[string]productionCaptureOperation) *productionSourceBinding {
	t.Helper()
	raw, err := json.Marshal(operations)
	if err != nil {
		t.Fatal(err)
	}
	owner := &PublicJobOwner{}
	s := &DeploymentService{ForwardEnabled: true, Config: DeploymentConfig{CaptureScope: "six-part", Workspace: WorkspaceCapture{Node: "original-node"}, Security: kube.WorkerSecurity{NodeUIDs: map[string]string{"original-node": "original-node-uid"}}}, captureMaterials: &productionCaptureMaterials{Revision: plan.revision, Operations: operations}, captureInput: &ProductionCaptureInput{SHA256: hash(raw)}, Runtime: &PublicCapture{Owner: owner}}
	binding := &productionSourceBinding{service: s, owner: owner, plan: plan, materialSHA256: s.captureInput.SHA256}
	owner.productionSource = binding
	return binding
}

func TestProductionCapturePlanPreservesOriginalFactory(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	stopped := false
	for _, instance := range source.Instances {
		stopped = stopped || instance.ID == 9 && instance.Status == "stopped"
	}
	if !stopped {
		t.Fatal("original stopped fixture was removed; this is not a site inventory")
	}
	plan, err := newProductionCapturePlan(operations, "r1")
	if err != nil {
		t.Fatal(err)
	}
	binding := capturePlanBindingFixture(t, plan, operations)
	factory := binding.moduleFactory()
	actual, err := factory(in, source, hold, writers)
	if err != nil {
		t.Fatal("attached factory", err)
	}
	parts, err := actual.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal(err)
	}
	var originalOperations map[string]productionCaptureOperation
	if json.Unmarshal([]byte(plan.operationsJSON), &originalOperations) != nil {
		t.Fatal("fixture decode")
	}
	for name, operation := range originalOperations {
		operation.Workload.NodeName = "original-node"
		originalOperations[name] = operation
	}
	// This is the unchanged constructor body, before the shared plan wrapper.
	original, err := buildOriginalProductionCaptureModules(in, source, hold, writers, originalOperations, "r1")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := original.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(expected)
	after, _ := json.Marshal(parts)
	if len(parts) != 11 || string(before) != string(after) {
		t.Fatal("original constructor/shared-part/global-index/Job bytes drifted")
	}
	// An equivalent replacement is not the originally attached plan object.
	replacement, err := newProductionCapturePlan(operations, "r1")
	if err != nil {
		t.Fatal(err)
	}
	binding.plan = replacement
	if _, err := factory(in, source, hold, writers); err == nil {
		t.Fatal("factory silently adopted replacement plan")
	}
}

func TestProductionCapturePlanRejectsMissingInputsAndMutation(t *testing.T) {
	for _, fault := range []string{"nil", "revision", "missing-database", "missing-control", "unknown-operation", "oversized", "nested-mutation"} {
		t.Run(fault, func(t *testing.T) {
			in, source, hold, writers, operations := productionModuleFixture(t)
			revision := "r1"
			switch fault {
			case "nil":
				operations = nil
			case "revision":
				revision = ""
			case "missing-database":
				delete(operations, "capture-database")
			case "missing-control":
				delete(operations, ce.Operation)
			case "unknown-operation":
				operations["unknown-capture"] = productionCaptureOperation{}
			case "oversized":
				operation := operations["capture-database"]
				operation.Request.ArtifactName = strings.Repeat("x", 8<<20)
				operations["capture-database"] = operation
			}
			plan, err := newProductionCapturePlan(operations, revision)
			if fault != "nested-mutation" {
				if err == nil || plan != nil {
					t.Fatal("invalid plan inputs accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			binding := capturePlanBindingFixture(t, plan, operations)
			factory := binding.moduleFactory()
			first, err := plan.build(in, source, hold, writers, "original-node")
			if err != nil {
				t.Fatal(err)
			}
			firstParts, err := first.BuildParts(in, source, hold)
			if err != nil {
				t.Fatal(err)
			}
			operations["capture-database"].Request.Database.RootCA[0] ^= 1
			operations["capture-workspace"].Workload.FormalMaterials.Inputs[0].Items[0].Path = "replacement.json"
			operations["capture-workspace"].Formal.PermitDelivery.Issuer[0] ^= 1
			if plan.matches(operations, revision) {
				t.Fatal("mutated material still matches original plan")
			}
			if _, err := factory(in, source, hold, writers); err == nil {
				t.Fatal("attached factory accepted changed original material")
			}
			second, err := plan.build(in, source, hold, writers, "original-node")
			if err != nil {
				t.Fatal(err)
			}
			secondParts, err := second.BuildParts(in, source, hold)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(firstParts)
			after, _ := json.Marshal(secondParts)
			if string(before) != string(after) {
				t.Fatal("caller nested mutation changed immutable plan output")
			}
		})
	}
}
