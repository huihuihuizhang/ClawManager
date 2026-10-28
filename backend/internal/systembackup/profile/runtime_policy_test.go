package profile

import (
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackup/workspace"
)

func TestConfigurationRejectsUnregisteredReleaseAndConflictingLegacyRules(t *testing.T) {
	d, _, _ := fixture(t)
	d.Config.Instances = []Instance{{ID: 1, Namespace: "source", Workspace: "/workspace", WorkloadKind: "Stopped", Policy: "release"}}
	if d.Config.Validate() == nil {
		t.Fatal("missing release policy accepted")
	}
	p := worker.RuntimePolicy{Version: "fixture-release", Image: "agent@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: "openclaw", Mode: "pro", OS: "linux"}, Files: []worker.FileRule{{Path: "agent.json", Format: "json", Required: true, Fields: []domain.JSONRule{{Path: []string{"token"}, Action: "stub", Required: true}}}}}
	d.Config.RuntimePolicies = map[string]worker.RuntimePolicy{"release": p}
	if e := d.Config.Validate(); e != nil {
		t.Fatal(e)
	}
	d.Config.Instances[0].Files = []worker.FileRule{{Path: "different.json"}}
	if d.Config.Validate() == nil {
		t.Fatal("conflicting legacy rules silently ignored")
	}
	d.Config.Instances[0].Files = nil
	p.Image = "agent:latest"
	d.Config.RuntimePolicies["release"] = p
	if d.Config.Validate() == nil {
		t.Fatal("mutable runtime release accepted")
	}
}

func TestWineLayoutChangesSignedRuntimeContract(t *testing.T) {
	d, _, _ := fixture(t)
	d.Config.Instances = []Instance{{ID: 7, Policy: "release"}}
	p := worker.RuntimePolicy{Version: "workbuddy-release", Image: "workbuddy@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: "workbuddy", Mode: "lite", Variant: "linux", OS: "linux"}}
	d.Config.RuntimePolicies = map[string]worker.RuntimePolicy{"release": p}
	old := d.contract().RuntimePolicies["instance-7"]
	p.WorkspaceLayout = workspace.WorkBuddyWineV1
	d.Config.RuntimePolicies["release"] = p
	if d.contract().RuntimePolicies["instance-7"] == old {
		t.Fatal("layout not bound to signed release contract")
	}
}
