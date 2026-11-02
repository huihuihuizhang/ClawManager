package systembackupexecution

import (
	"context"
	"encoding/json"
	"testing"
)

func TestSixPartCapabilityRemainsNotReadyWithoutActualSources(t *testing.T) {
	for _, fault := range []string{"structurally-complete", "no-runtime", "no-binding", "no-plan", "changed-revision", "changed-material-pin", "foreign-service", "foreign-owner", "recovery-mode"} {
		t.Run(fault, func(t *testing.T) {
			_, _, _, _, operations := productionModuleFixture(t)
			plan, err := newProductionCapturePlan(operations, "r1")
			if err != nil {
				t.Fatal(err)
			}
			binding := capturePlanBindingFixture(t, plan, operations)
			s := binding.service
			switch fault {
			case "no-runtime":
				s.Runtime = nil
			case "no-binding":
				binding.owner.productionSource = nil
			case "no-plan":
				binding.plan = nil
			case "changed-revision":
				s.captureMaterials.Revision = "changed"
			case "changed-material-pin":
				s.captureInput.SHA256 = "replaced"
			case "foreign-service":
				binding.service = &DeploymentService{}
			case "foreign-owner":
				binding.owner = &PublicJobOwner{}
			case "recovery-mode":
				s.ForwardEnabled = false
			}
			if err := s.checkCaptureCapability(); err == nil {
				t.Fatal("missing actual taskless source observations/publisher dependencies approved")
			}
			// No database/client/grant is supplied. A rejection before the SQL
			// write must not dereference them, even for the complete pure plan.
			if err := s.PublishReadiness(context.Background()); err == nil {
				t.Fatal("unavailable six-part readiness published")
			}
			var public struct {
				Parts           []string `json:"parts"`
				AcceptanceReady bool     `json:"acceptance_ready"`
			}
			if json.Unmarshal(s.PublicCapability(), &public) != nil || public.Parts == nil || len(public.Parts) != 0 || public.AcceptanceReady {
				t.Fatal("six-part failure claimed workspace/six-part or acceptance")
			}
		})
	}
}

func TestWorkspaceCapabilityKeepsOriginalChecks(t *testing.T) {
	for _, scope := range []string{"platform-workspace", "runtime-workspace"} {
		s := &DeploymentService{ForwardEnabled: true, Config: DeploymentConfig{CaptureScope: scope}}
		if err := s.checkCaptureCapability(); err != nil {
			t.Fatal("structural batch blocked original workspace profile", err)
		}
		// Passing only the new structural check is not readiness. The original
		// pinned-file check must reject this configuration before reaching SQL.
		if err := s.PublishReadiness(context.Background()); err == nil {
			t.Fatal("workspace bypassed original pinned config check")
		}
		var public struct {
			Parts           []string `json:"parts"`
			AcceptanceReady bool     `json:"acceptance_ready"`
		}
		if json.Unmarshal(s.PublicCapability(), &public) != nil || len(public.Parts) != 1 || public.Parts[0] != "workspace" || public.AcceptanceReady {
			t.Fatal("original workspace diagnostic or false acceptance value changed")
		}
		s.ForwardEnabled = false
		if s.checkCaptureCapability() == nil {
			t.Fatal("recovery mode granted forward readiness")
		}
	}
	if (&DeploymentService{ForwardEnabled: true, Config: DeploymentConfig{CaptureScope: "unknown"}}).checkCaptureCapability() == nil {
		t.Fatal("unknown profile accepted")
	}
}
