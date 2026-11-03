package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEnableOnlyMutationRejectsEveryOtherChange(t *testing.T) {
	current, e := DecodeConfigValues(bootstrapFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	proposed, e := DecodeConfigValues(bytes.Replace(current.CanonicalJSON(), []byte(`"enabled":false`), []byte(`"enabled":true`), 1))
	if e != nil {
		t.Fatal(e)
	}
	in := ConfigMutationResourceInput{current: current, proposed: proposed}
	if ValidateEnableOnlyConfigMutation(in) != nil {
		t.Fatal("exact first enable rejected")
	}
	if ValidateEnableOnlyConfigMutation(ConfigMutationResourceInput{}) == nil {
		t.Fatal("empty snapshots accepted")
	}
	if ValidateEnableOnlyConfigMutation(ConfigMutationResourceInput{current: proposed, proposed: current}) == nil {
		t.Fatal("disable accepted")
	}
	if ValidateEnableOnlyConfigMutation(ConfigMutationResourceInput{current: proposed, proposed: proposed}) == nil {
		t.Fatal("already enabled accepted")
	}
	// Exercise reference, registry and non-reference business configuration
	// changes against the complete canonical snapshots, including array order.
	for _, change := range []func(*bootstrapValues){
		func(v *bootstrapValues) { v.References[0].Version += "-changed" },
		func(v *bootstrapValues) { v.Registries[0].Version += "-changed" },
		func(v *bootstrapValues) { v.MinimumRecoveryPoints = json.Number("2") },
		func(v *bootstrapValues) { v.References[0], v.References[1] = v.References[1], v.References[0] },
	} {
		var values bootstrapValues
		if json.Unmarshal(proposed.CanonicalJSON(), &values) != nil {
			t.Fatal("fixture")
		}
		change(&values)
		raw, e := json.Marshal(values)
		if e != nil {
			t.Fatal(e)
		}
		changed, e := DecodeConfigValues(raw)
		if e != nil {
			t.Fatal(e)
		}
		if ValidateEnableOnlyConfigMutation(ConfigMutationResourceInput{current: current, proposed: changed}) == nil {
			t.Fatal("additional change accepted")
		}
	}
}
