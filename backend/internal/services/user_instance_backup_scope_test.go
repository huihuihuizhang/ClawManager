package services

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"clawreef/internal/models"
	"clawreef/internal/systembackup/scope"
)

func TestUserInstanceBackupScopeReusesPlatformVariantsWithoutLeakingSecrets(t *testing.T) {
	secret := "source-private-credential-that-must-never-appear"
	users := []models.User{{ID: 1, Username: "admin", Role: "admin", PasswordHash: secret}}
	instances := []models.Instance{{ID: 2, UserID: 1, Type: "codex", RuntimeType: "desktop", InstanceMode: "pro", MountPath: "/config", AccessToken: &secret, EnvironmentOverridesJSON: &secret}}
	mounts := map[int][]scope.Mount{2: {{ContainerPath: "/config", Storage: scope.Storage{Kind: "hostpath", HostPath: "/data/user-1/instance-2", NodeName: "worker-1", AdditionalMountsKnown: true}}}}
	plan, err := BuildUserInstanceBackupInventory("kubernetes", "single-node", 1, 1, users, instances, mounts)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("scope adapter leaked source credential values")
	}
	if plan.Instances[0].Runtime.Type != "codex" || plan.Instances[0].Runtime.RestorePowerState != "stopped" {
		t.Fatalf("wrong runtime plan: %+v", plan.Instances[0])
	}
	if instances[0].Status != "" || instances[0].AccessToken == nil || *instances[0].AccessToken != secret {
		t.Fatal("read-only planning mutated source instance")
	}
	instances[0].RuntimeVariant = "future-platform"
	if _, err := BuildUserInstanceBackupInventory("kubernetes", "single-node", 1, 1, users, instances, mounts); !errors.Is(err, scope.ErrUnsupportedRuntime) {
		t.Fatalf("unknown explicit variant must not be hidden by inferred Linux variant: %v", err)
	}
	instances[0].RuntimeVariant = ""
	instances[0].MountPath = "/storage"
	if _, err := BuildUserInstanceBackupInventory("kubernetes", "single-node", 1, 1, users, instances, mounts); !errors.Is(err, scope.ErrWindowsExcluded) {
		t.Fatalf("legacy Windows VM was misidentified as Linux: %v", err)
	}
}

func TestUserInstanceBackupScopeKeepsCurrentGatewayTypesInCoverage(t *testing.T) {
	for _, runtimeType := range []string{RuntimeTypeOpenClaw, RuntimeTypeHermes, RuntimeTypeOpenCode, RuntimeTypeDeepSeekHarness} {
		if _, ok := NormalizeV2RuntimeType(runtimeType); !ok {
			t.Fatalf("platform runtime %s is not recognized", runtimeType)
		}
		if _, err := scope.PlanRuntime(scope.Runtime{Type: runtimeType, Backend: RuntimeBackendGateway}); err != nil {
			t.Fatalf("platform Lite runtime %s has no backup scope: %v", runtimeType, err)
		}
	}
}

func TestNewRuntimeConstantsRequireExplicitBackupCoverage(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "runtime_capacity.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	covered := make(map[string]bool)
	for _, profile := range scope.RuntimeProfiles() {
		covered[profile.Type] = true
	}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for index, name := range spec.Names {
			if !strings.HasPrefix(name.Name, "RuntimeType") || index >= len(spec.Values) {
				continue
			}
			literal, ok := spec.Values[index].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			runtimeType, err := strconv.Unquote(literal.Value)
			if err != nil || !covered[runtimeType] {
				t.Errorf("platform runtime %s needs an explicit backup scope decision", name.Name)
			}
		}
		return true
	})
}
