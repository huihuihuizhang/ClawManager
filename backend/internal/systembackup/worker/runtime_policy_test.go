package worker

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/workspace"
)

func TestReleasePolicyChecksAllLinuxTypesWithoutRewritingSource(t *testing.T) {
	for _, runtime := range scope.RuntimeProfiles() {
		for _, mode := range runtime.Modes {
			t.Run(runtime.Type+"-"+mode, func(t *testing.T) {
				root, e := os.OpenRoot(t.TempDir())
				if e != nil {
					t.Fatal(e)
				}
				defer root.Close()
				raw := []byte(`{"token":"original credential","enabled":true}`)
				f, e := root.OpenFile("config.json", os.O_WRONLY|os.O_CREATE, 0600)
				if e != nil {
					t.Fatal(e)
				}
				f.Write(raw)
				f.Close()
				p := RuntimePolicy{Version: "fixture-v1", Image: "runtime@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: runtime.Type, Mode: mode, Variant: "linux", OS: "linux"}, Files: []FileRule{{Path: "config.json", Required: true, Fields: []domain.JSONRule{{Path: []string{"token"}, Action: "stub", Required: true}, {Path: []string{"enabled"}, Action: "disable", Required: true}}}}}
				if e := CheckRuntimeFiles(context.Background(), root, p); e != nil {
					t.Fatal(e)
				}
				got, e := root.ReadFile("config.json")
				if e != nil || string(got) != string(raw) {
					t.Fatal("capture changed source credentials")
				}
				p.Files[0].Fields = p.Files[0].Fields[:1]
				if CheckRuntimeFiles(context.Background(), root, p) == nil {
					t.Fatal("new config field accepted")
				}
			})
		}
	}
}

func TestEmptyLayoutPreservesLegacySignedPolicyEncoding(t *testing.T) {
	p := RuntimePolicy{Version: "legacy", Image: "agent@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: "openclaw", Mode: "lite", OS: "linux"}, Files: []FileRule{{Path: "config.json", Required: true, Fields: []domain.JSONRule{{Path: []string{"value"}, Action: "preserve"}}}}}
	legacy := struct {
		Version, Image string
		Runtime        scope.Runtime
		Files          []FileRule
	}{p.Version, p.Image, p.Runtime, p.Files}
	want, e := json.Marshal(legacy)
	if e != nil {
		t.Fatal(e)
	}
	got, e := json.Marshal(p)
	if e != nil || string(got) != string(want) {
		t.Fatal("legacy policy digest would change", e)
	}
}

func TestWineLayoutRequiresExplicitWorkBuddyLiteRelease(t *testing.T) {
	p := RuntimePolicy{Version: "tested-release", Image: "workbuddy@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: "workbuddy", Mode: "lite", Variant: "linux", OS: "linux"}, WorkspaceLayout: workspace.WorkBuddyWineV1, Files: []FileRule{{Path: "config.json", Fields: []domain.JSONRule{{Path: []string{"value"}, Action: "preserve"}}}}}
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []string{"pro", "other-agent", "windows", "unknown-layout", "mutable-image"} {
		t.Run(change, func(t *testing.T) {
			q := p
			switch change {
			case "pro":
				q.Runtime.Mode = "pro"
			case "other-agent":
				q.Runtime.Type = "openclaw"
			case "windows":
				q.Runtime.Variant = "windows"
			case "unknown-layout":
				q.WorkspaceLayout = "wine-anything"
			case "mutable-image":
				q.Image = "workbuddy:latest"
			}
			if q.Validate() == nil {
				t.Fatal("unbound Wine layout accepted")
			}
		})
	}
}

func TestDeepSeekLayoutRequiresMatchingImmutableLinuxRelease(t *testing.T) {
	p := RuntimePolicy{Version: "tested-rc6", Image: "dsh@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: "deepseek-harness", Mode: "lite", Variant: "linux", OS: "linux"}, WorkspaceLayout: workspace.DeepSeekHarnessV1, Files: []FileRule{{Path: "config.json", Fields: []domain.JSONRule{{Path: []string{"value"}, Action: "preserve"}}}}}
	for _, mode := range []string{"lite", "pro"} {
		p.Runtime.Mode = mode
		if e := p.Validate(); e != nil {
			t.Fatal(mode, e)
		}
	}
	for _, change := range []string{"other-agent", "windows", "mutable-image"} {
		q := p
		switch change {
		case "other-agent":
			q.Runtime.Type = "openclaw"
		case "windows":
			q.Runtime.OS = "windows"
		case "mutable-image":
			q.Image = "dsh:latest"
		}
		if q.Validate() == nil {
			t.Fatal("unbound DeepSeek layout accepted", change)
		}
	}
}
