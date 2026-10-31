package systembackupexecution

import (
	"strings"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/worker"
)

func TestProductionRuntimeImageUsesOriginalTypedNullableSource(t *testing.T) {
	image := "original/runtime@sha256:" + strings.Repeat("a", 64)
	empty, version := "", "latest"
	for _, kind := range []string{"openclaw", "hermes", "opencode", "workbuddy"} {
		t.Run(kind, func(t *testing.T) {
			instance := b.InstanceIdentity{Type: kind, Mode: "pro", Variant: "linux", OS: "linux", Status: "stopped"}
			policy := worker.RuntimePolicy{Image: image, Runtime: scope.Runtime{Type: kind, Mode: "pro", Variant: "linux", OS: "linux"}}
			if !productionImageMatches(productionImageReference(instance, &version, &image, nil), policy, nil) {
				t.Fatal("original full registry digest refused")
			}
			if productionImageMatches(productionImageReference(instance, &version, &empty, &image), policy, nil) {
				t.Fatal("tag-only text was treated as actual runtime image")
			}
			ref := productionImageReference(instance, &version, nil, nil)
			if productionImageMatches(ref, policy, nil) {
				t.Fatal("absent original default mapping guessed")
			}
			// A signed owner mapping resolves this exact original type/variant/
			// backend/default input, including stopped instances with no Pod.
			aliases := map[string]string{ref: image}
			if !productionImageMatches(ref, policy, aliases) {
				t.Fatal("explicit original owner default binding refused")
			}
			if productionImageMatches(productionImageReference(instance, &version, &empty, nil), policy, aliases) {
				t.Fatal("NULL registry collapsed into empty non-NULL registry")
			}
			other := instance
			other.Type = "other"
			if productionImageMatches(productionImageReference(other, &version, nil, nil), policy, aliases) {
				t.Fatal("different original runtime inherited default binding")
			}
			other = instance
			other.Backend = "gateway"
			if productionImageMatches(productionImageReference(other, &version, nil, nil), policy, aliases) {
				t.Fatal("different original backend inherited default binding")
			}
			if productionImageMatches(`["",""]`, policy, map[string]string{`["",""]`: image}) {
				t.Fatal("untyped ambiguous legacy alias accepted")
			}
		})
	}
}
