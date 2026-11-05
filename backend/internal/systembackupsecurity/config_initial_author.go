package systembackupsecurity

import (
	"encoding/json"
)

// DefaultDisabledConfig authors operational ConfigValues from actual original
// registry/reference selectors. Numeric defaults are installation policy, not
// a capacity measurement or native approval. Real admission remains mandatory.
func DefaultDisabledConfig(registries []BootstrapRegistryRef, references []BootstrapSecretRef, stagingBytes int64) (BootstrapConfig, error) {
	if stagingBytes < bootstrapNumberRules["capacity"]["staging_capacity_bytes"].Min || stagingBytes > bootstrapNumberRules["capacity"]["staging_capacity_bytes"].Max {
		return BootstrapConfig{}, ErrBootstrapConfig
	}
	groups := map[string]map[string]json.Number{}
	for group, rules := range bootstrapNumberRules {
		groups[group] = map[string]json.Number{}
		for name, rule := range rules {
			groups[group][name] = json.Number(bootstrapDecimal(rule.Default, rule.Scale))
		}
	}
	groups["capacity"]["staging_capacity_bytes"] = json.Number(bootstrapDecimal(stagingBytes, 1))
	artifact := stagingBytes / 5 * 4
	available := stagingBytes - bootstrapNumberRules["capacity"]["max_index_bytes"].Default
	if guarded := available / 11 * 10; artifact > guarded {
		artifact = guarded
	}
	if maximum := bootstrapNumberRules["capacity"]["max_artifact_bytes"].Max; artifact > maximum {
		artifact = maximum
	}
	groups["capacity"]["max_artifact_bytes"] = json.Number(bootstrapDecimal(artifact, 1))
	values := bootstrapValues{Enabled: false, AlertProfile: "production", MinimumRecoveryPoints: json.Number("1"),
		Durations: groups["durations"], Capacity: groups["capacity"], Concurrency: groups["concurrency"], Preflight: groups["preflight_limits"],
		Registries: append([]BootstrapRegistryRef(nil), registries...), References: append([]BootstrapSecretRef(nil), references...)}
	raw, err := json.Marshal(values)
	if err != nil {
		return BootstrapConfig{}, ErrBootstrapConfig
	}
	return DecodeBootstrapConfig(raw)
}
