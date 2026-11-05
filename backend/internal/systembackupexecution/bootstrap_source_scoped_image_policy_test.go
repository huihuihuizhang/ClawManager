package systembackupexecution

import (
	"reflect"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/worker"
)

// Synthetic DATA-only validator fixture, never original admin/source authority.
func scopedImagePolicyFixture(t *testing.T) (*bootstrapSourceRegistryReader, *bootstrapSourceSQLFacts) {
	t.Helper()
	instances := []b.InstanceIdentity{
		{ID: 11, UserID: 2, Generation: 1, Type: "openclaw", Mode: "lite", OS: "linux", Status: "running"},
		{ID: 12, UserID: 2, Generation: 1, Type: "hermes", Mode: "lite", OS: "linux", Status: "running"},
		{ID: 13, UserID: 2, Generation: 1, Type: "workbuddy", Mode: "lite", OS: "linux", Status: "running"},
		{ID: 14, UserID: 2, Generation: 1, Type: "openclaw", Mode: "pro", OS: "linux", Status: "stopped"},
		{ID: 31, UserID: 2, Generation: 0, Type: "opencode", Mode: "lite", OS: "linux", Status: "error"},
		{ID: 42, UserID: 3, Generation: 0, Type: "deepseek-harness", Mode: "lite", OS: "linux", Status: "error"},
	}
	approved, e := domain.NewKnownErrorLiteRuntimeTestScope("synthetic-i", "synthetic-s", "synthetic-d", "synthetic-n", instances)
	if e != nil {
		t.Fatal(e)
	}
	x := &bootstrapSourceRegistryReader{config: DeploymentConfig{InstallationID: approved.InstallationID, SourceServerUUID: approved.ServerUUID, SourceDatabase: approved.Database, NamespaceUID: approved.NamespaceUID, RuntimeSources: &RuntimeSourceConfig{RuntimeTestScope: approved}}}
	x.materials.Discovery = &productionSourceDiscovery{}
	facts := &bootstrapSourceSQLFacts{inventory: b.SourceInventory{ServerUUID: approved.ServerUUID, Database: approved.Database, Users: []int{2, 3}, Instances: instances, RuntimeTestScope: approved.Clone()}, metadata: productionSQLSourceMetadata{Images: map[int]string{}}}
	version, image := "original-version", "registry.example/runtime@sha256:"+strings.Repeat("a", 64)
	for _, instance := range instances {
		if approved.IsDeferred(instance) {
			facts.metadata.Images[instance.ID] = productionImageReference(instance, &version, nil, nil)
			continue
		}
		facts.metadata.Images[instance.ID] = productionImageReference(instance, &version, &image, nil)
		x.materials.Discovery.RuntimePolicies = append(x.materials.Discovery.RuntimePolicies, worker.RuntimePolicy{Image: image, Runtime: scope.Runtime{Type: instance.Type, Mode: instance.Mode, Backend: instance.Backend, Variant: instance.Variant, OS: instance.OS}})
	}
	return x, facts
}

func TestScopedRuntimeImagePolicyDefersOnlyExactTwoAndPreservesAllSQLFacts(t *testing.T) {
	x, facts := scopedImagePolicyFixture(t)
	original := append([]b.InstanceIdentity{}, facts.inventory.Instances...)
	images := map[int]string{}
	for k, v := range facts.metadata.Images {
		images[k] = v
	}
	users := append([]int{}, facts.inventory.Users...)
	if e := x.checkRuntimeImagePolicies(facts); e != nil {
		t.Fatal(e)
	}
	if len(facts.inventory.Instances) != 6 || len(facts.metadata.Images) != 6 || !reflect.DeepEqual(facts.inventory.Instances, original) || !reflect.DeepEqual(facts.metadata.Images, images) || !reflect.DeepEqual(facts.inventory.Users, users) {
		t.Fatal("runtime deferral filtered or modified SQL/image/owner facts")
	}
}

func TestScopedRuntimeImagePolicyRejectsMissingRetainedPolicyAndScopeDrift(t *testing.T) {
	t.Run("retained-policy-missing", func(t *testing.T) {
		x, f := scopedImagePolicyFixture(t)
		x.materials.Discovery.RuntimePolicies = x.materials.Discovery.RuntimePolicies[1:]
		if x.checkRuntimeImagePolicies(f) == nil {
			t.Fatal("missing retained runtime policy accepted")
		}
	})
	t.Run("retained-image-mismatch", func(t *testing.T) {
		x, f := scopedImagePolicyFixture(t)
		f.metadata.Images[11] = productionImageReference(f.inventory.Instances[0], nil, nil, nil)
		if x.checkRuntimeImagePolicies(f) == nil {
			t.Fatal("unmatched retained image accepted")
		}
	})
	t.Run("deferred-generation-drift", func(t *testing.T) {
		x, f := scopedImagePolicyFixture(t)
		f.inventory.Instances[4].Generation++
		if x.checkRuntimeImagePolicies(f) == nil {
			t.Fatal("deferred identity drift bypassed scope validation")
		}
	})
	t.Run("new-error", func(t *testing.T) {
		x, f := scopedImagePolicyFixture(t)
		f.inventory.Instances = append(f.inventory.Instances, b.InstanceIdentity{ID: 99, UserID: 3, Type: "opencode", Mode: "lite", Status: "error"})
		if x.checkRuntimeImagePolicies(f) == nil {
			t.Fatal("new error bypassed scope validation")
		}
	})
	t.Run("default-strict", func(t *testing.T) {
		x, f := scopedImagePolicyFixture(t)
		x.config.RuntimeSources.RuntimeTestScope = nil
		f.inventory.RuntimeTestScope = nil
		if x.checkRuntimeImagePolicies(f) == nil {
			t.Fatal("nil scope ignored two unmatched runtime policies")
		}
	})
}
