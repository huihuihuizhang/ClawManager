package scope

import (
	"errors"
	"testing"
)

func TestLinuxRuntimeCoverageIncludesAllRegisteredPersistentData(t *testing.T) {
	for _, profile := range RuntimeProfiles() {
		for _, mode := range profile.Modes {
			t.Run(profile.Type+"/"+mode, func(t *testing.T) {
				backend := "desktop"
				if mode == "lite" {
					backend = "gateway"
				}
				plan, err := PlanRuntime(Runtime{Type: profile.Type, Mode: mode, Backend: backend, Variant: "linux", OS: profile.Type})
				if err != nil {
					t.Fatal(err)
				}
				if plan.CaptureScope != "all_registered_persistent_mounts" || !plan.IncludeSessions || !plan.IncludeSkills || !plan.IncludeTaskConfigs || plan.RestorePowerState != "stopped" {
					t.Fatalf("incomplete migration plan: %+v", plan)
				}
			})
		}
	}
}

func TestRuntimePlanRejectsUnsupportedAndAmbiguousCombinations(t *testing.T) {
	for _, runtime := range []Runtime{
		{Type: "unknown", Mode: "pro"},
		{Type: "openclaw", Mode: "future-mode"},
		{Type: "openclaw", Mode: "pro", Backend: "gateway"},
		{Type: "hermes", Mode: "lite", Backend: "desktop"},
		{Type: "codex", Mode: "pro"},
		{Type: "workbuddy", Mode: "pro"},
		{Type: "claude-code", Mode: "lite", Backend: "gateway"},
		{Type: "codex", Variant: "linux", Mode: "lite"},
		{Type: "openclaw", Mode: "pro", OS: "unknown-os"},
		{Type: "openclaw", Mode: "pro", Variant: "future-platform"},
		{Type: "openclaw"},
	} {
		if _, err := PlanRuntime(runtime); !errors.Is(err, ErrUnsupportedRuntime) {
			t.Errorf("runtime %+v: expected unsupported, got %v", runtime, err)
		}
	}
}

func TestRuntimePlanRejectsWindowsBeforeInterpretingAgentType(t *testing.T) {
	for _, runtime := range []Runtime{
		{Type: "codex", Mode: "pro", Variant: "Windows", OS: "linux"},
		{Type: "workbuddy", Mode: "pro", OS: "windows"},
		{Type: "openclaw", Mode: "pro", Variant: "linux", OS: "Windows Server"},
	} {
		if _, err := PlanRuntime(runtime); !errors.Is(err, ErrWindowsExcluded) {
			t.Errorf("runtime %+v: expected Windows exclusion, got %v", runtime, err)
		}
	}
}

func TestLegacyRuntimeModeIsDerivedFromActualBackend(t *testing.T) {
	plan, err := PlanRuntime(Runtime{Type: " Hermes ", Backend: " Gateway "})
	if err != nil || plan.Mode != "lite" || plan.Type != "hermes" {
		t.Fatalf("unexpected legacy mode: %+v, %v", plan, err)
	}
}
