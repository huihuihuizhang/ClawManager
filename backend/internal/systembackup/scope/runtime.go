package scope

import (
	"errors"
	"strings"
)

var (
	ErrUnsupportedRuntime = errors.New("agent runtime or mode is not covered by the Linux backup scope")
	ErrWindowsExcluded    = errors.New("Windows instances are outside this backup scope")
	ErrStorageUnresolved  = errors.New("workspace storage identity is incomplete or unsafe")
)

// Runtime describes an instance without configuration values or credentials.
// Variant must already be resolved using the platform's runtime selection rules.
type Runtime struct {
	Type    string `json:"type"`
	Mode    string `json:"mode"`
	Backend string `json:"backend"`
	Variant string `json:"variant"`
	OS      string `json:"os"`
}

type RuntimeProfile struct {
	Type  string   `json:"type"`
	Modes []string `json:"modes"`
}

func RuntimeProfiles() []RuntimeProfile {
	return []RuntimeProfile{
		{"openclaw", []string{"lite", "pro"}},
		{"hermes", []string{"lite", "pro"}},
		{"opencode", []string{"lite", "pro"}},
		{"deepseek-harness", []string{"lite", "pro"}},
		{"workbuddy", []string{"lite", "pro"}},
		{"codex", []string{"pro"}},
		{"claude-code", []string{"pro"}},
	}
}

type RuntimePlan struct {
	Type               string `json:"type"`
	Mode               string `json:"mode"`
	CaptureScope       string `json:"capture_scope"`
	IncludeSessions    bool   `json:"include_sessions"`
	IncludeSkills      bool   `json:"include_skills"`
	IncludeTaskConfigs bool   `json:"include_task_configs"`
	RestorePowerState  string `json:"restore_power_state"`
}

// PlanRuntime describes coverage, not a verified restore capability. Capturing
// only an agent's dot-directory misses project files, state and other mounts.
func PlanRuntime(runtime Runtime) (RuntimePlan, error) {
	for _, field := range []*string{&runtime.Type, &runtime.Mode, &runtime.Backend, &runtime.Variant, &runtime.OS} {
		*field = strings.ToLower(strings.TrimSpace(*field))
	}
	if runtime.Variant == "windows" || strings.HasPrefix(runtime.OS, "win") {
		return RuntimePlan{}, ErrWindowsExcluded
	}
	if runtime.Variant != "" && runtime.Variant != "linux" {
		return RuntimePlan{}, ErrUnsupportedRuntime
	}
	if (runtime.Type == "workbuddy" || runtime.Type == "codex") && runtime.Variant != "linux" {
		// Their default/legacy image may be a Windows VM. Do not guess Linux.
		return RuntimePlan{}, ErrUnsupportedRuntime
	}
	if runtime.Mode == "" {
		if runtime.Backend == "gateway" {
			runtime.Mode = "lite"
		} else if runtime.Backend == "desktop" || runtime.Backend == "shell" {
			runtime.Mode = "pro"
		} else {
			return RuntimePlan{}, ErrUnsupportedRuntime
		}
	}
	if runtime.Backend != "" {
		switch runtime.Backend {
		case "gateway":
			if runtime.Mode != "lite" {
				return RuntimePlan{}, ErrUnsupportedRuntime
			}
		case "desktop", "shell":
			if runtime.Mode != "pro" {
				return RuntimePlan{}, ErrUnsupportedRuntime
			}
		default:
			return RuntimePlan{}, ErrUnsupportedRuntime
		}
	}
	if !knownLinuxOS(runtime.OS, runtime.Type) {
		return RuntimePlan{}, ErrUnsupportedRuntime
	}
	for _, profile := range RuntimeProfiles() {
		if profile.Type != runtime.Type {
			continue
		}
		for _, mode := range profile.Modes {
			if mode == runtime.Mode {
				return RuntimePlan{
					Type: runtime.Type, Mode: mode, CaptureScope: "all_registered_persistent_mounts",
					IncludeSessions: true, IncludeSkills: true, IncludeTaskConfigs: true, RestorePowerState: "stopped",
				}, nil
			}
		}
	}
	return RuntimePlan{}, ErrUnsupportedRuntime
}

func knownLinuxOS(os, runtimeType string) bool {
	// Older UI records use the agent name itself as os_type.
	if os == runtimeType {
		return true
	}
	switch os {
	case "", "linux", "ubuntu", "debian", "centos", "alpine", "fedora", "rocky", "rhel":
		return true
	default:
		return false
	}
}
