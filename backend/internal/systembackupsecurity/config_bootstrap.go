package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ErrBootstrapConfig = errors.New("bootstrap_config_invalid")

type bootstrapNumberRule struct{ Min, Max, Default, Scale int64 }

type BootstrapRegistryRef struct {
	Kind    string `json:"registry_kind"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
type BootstrapSecretRef struct {
	Purpose      string `json:"purpose"`
	IdentityHash string `json:"identity_hash"`
	Version      string `json:"version"`
}
type bootstrapValues struct {
	Enabled               bool                   `json:"enabled"`
	AlertProfile          string                 `json:"alert_profile"`
	MinimumRecoveryPoints json.Number            `json:"minimum_recovery_points"`
	Durations             map[string]json.Number `json:"durations"`
	Capacity              map[string]json.Number `json:"capacity"`
	Concurrency           map[string]json.Number `json:"concurrency"`
	Preflight             map[string]json.Number `json:"preflight_limits"`
	Registries            []BootstrapRegistryRef `json:"registries"`
	References            []BootstrapSecretRef   `json:"references"`
}

// BootstrapConfig is an immutable, fully specified ConfigValues snapshot.
// Parsing validates structure, ranges and cross-field rules, NOT the existence
// or authority of a registry/ref. BootstrapAdmission must establish those.
type BootstrapConfig struct {
	values    bootstrapValues
	canonical []byte
	numbers   map[string]int64
}

func (c BootstrapConfig) SHA256() string        { return registrationHash(string(c.canonical)) }
func (c BootstrapConfig) CanonicalJSON() []byte { return append([]byte(nil), c.canonical...) }
func (c BootstrapConfig) Registries() []BootstrapRegistryRef {
	return append([]BootstrapRegistryRef(nil), c.values.Registries...)
}
func (c BootstrapConfig) References() []BootstrapSecretRef {
	return append([]BootstrapSecretRef(nil), c.values.References...)
}

var bootstrapVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func DecodeBootstrapConfig(raw []byte) (BootstrapConfig, error) {
	return decodeConfigValues(raw, false)
}

// Shared validation keeps bootstrap disabled while allowing the D mutation
// decoder to validate both enabled states without reconstructing ConfigValues.
func decodeConfigValues(raw []byte, allowEnabled bool) (BootstrapConfig, error) {
	fail := func() (BootstrapConfig, error) { return BootstrapConfig{}, ErrBootstrapConfig }
	var v bootstrapValues
	if decodePinnedRegistry(raw, registrationHash(string(raw)), &v) != nil || (!allowEnabled && v.Enabled) || (v.AlertProfile != "production" && v.AlertProfile != "development") {
		return fail()
	}
	// json.Number.UnmarshalJSON also accepts quoted numbers. Reject those at
	// the wire boundary before normalizing values or computing a digest.
	docDecoder := json.NewDecoder(bytes.NewReader(raw))
	docDecoder.UseNumber()
	var doc map[string]any
	if docDecoder.Decode(&doc) != nil {
		return fail()
	}
	if _, ok := doc["minimum_recovery_points"].(json.Number); !ok {
		return fail()
	}
	for group := range bootstrapNumberRules {
		members, ok := doc[group].(map[string]any)
		if !ok {
			return fail()
		}
		for _, member := range members {
			if _, ok := member.(json.Number); !ok {
				return fail()
			}
		}
	}
	minimum, ok := bootstrapNumber(v.MinimumRecoveryPoints, bootstrapNumberRule{Min: 1, Max: 100, Scale: 1})
	if !ok {
		return fail()
	}
	v.MinimumRecoveryPoints = json.Number(strconv.FormatInt(minimum, 10))
	c := BootstrapConfig{values: v, numbers: map[string]int64{}}
	groups := map[string]map[string]json.Number{"durations": v.Durations, "capacity": v.Capacity, "concurrency": v.Concurrency, "preflight_limits": v.Preflight}
	for group, rules := range bootstrapNumberRules {
		values := groups[group]
		if len(values) != len(rules) {
			return fail()
		}
		for name, rule := range rules {
			n, exists := values[name]
			if !exists {
				return fail()
			}
			scaled, valid := bootstrapNumber(n, rule)
			if !valid {
				return fail()
			}
			column := name
			if group == "preflight_limits" {
				column = "preflight_" + name
			}
			c.numbers[column] = scaled
			values[name] = json.Number(bootstrapDecimal(scaled, rule.Scale))
		}
	}
	if !bootstrapRelationships(c.numbers) || len(v.Registries) != len(bootstrapRegistryKinds) || len(v.References) != len(bootstrapReferencePurposes) {
		return fail()
	}
	seen := map[string]bool{}
	for _, r := range v.Registries {
		if !contains(bootstrapRegistryKinds, r.Kind) || seen[r.Kind] || !bootstrapVersion.MatchString(r.Version) || !providerHashPattern.MatchString(r.SHA256) {
			return fail()
		}
		seen[r.Kind] = true
	}
	seen = map[string]bool{}
	identityPurpose := map[string]string{}
	for _, r := range v.References {
		if !contains(bootstrapReferencePurposes, r.Purpose) || seen[r.Purpose] || !bootstrapVersion.MatchString(r.Version) || !providerHashPattern.MatchString(r.IdentityHash) {
			return fail()
		}
		if prior, ok := identityPurpose[r.IdentityHash]; ok && (bootstrapSigningPurpose(prior) || bootstrapSigningPurpose(r.Purpose)) {
			return fail()
		}
		identityPurpose[r.IdentityHash] = r.Purpose
		seen[r.Purpose] = true
	}
	// All object keys are fixed ASCII; all numeric values fit exactly into the
	// JCS integer range, except the bounded two-decimal safety factor. Array
	// order is preserved. Do not sort arrays or silently fill missing defaults.
	normalized, err := json.Marshal(c.values)
	if err != nil {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(normalized))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil {
		return fail()
	}
	var out strings.Builder
	bootstrapCanonical(&out, value)
	c.canonical = []byte(out.String())
	if len(c.canonical) > 262144 {
		return fail()
	}
	return c, nil
}

func bootstrapSigningPurpose(purpose string) bool {
	return purpose == "capture_signing" || purpose == "acceptance_signing" || purpose == "catalog_signing"
}

func bootstrapNumber(n json.Number, r bootstrapNumberRule) (int64, bool) {
	s := string(n)
	if len(s) == 0 || len(s) > 32 {
		return 0, false
	}
	// Bound exponent work before big.Rat allocation (untrusted input).
	if p := strings.IndexAny(s, "eE"); p >= 0 {
		e, err := strconv.Atoi(s[p+1:])
		if err != nil || e < -20 || e > 20 {
			return 0, false
		}
	}
	x, ok := new(big.Rat).SetString(s)
	if !ok {
		return 0, false
	}
	x.Mul(x, new(big.Rat).SetInt64(r.Scale))
	if !x.IsInt() || !x.Num().IsInt64() {
		return 0, false
	}
	v := x.Num().Int64()
	return v, v >= r.Min && v <= r.Max
}
func bootstrapDecimal(n, scale int64) string {
	if scale == 1 {
		return strconv.FormatInt(n, 10)
	}
	return strconv.FormatFloat(float64(n)/float64(scale), 'f', -1, 64)
}
func bootstrapRelationships(n map[string]int64) bool {
	for _, p := range []string{"controller_claim", "mutation_lease", "artifact_lease"} {
		if n[p+"_heartbeat_seconds"]*3 > n[p+"_ttl_seconds"] {
			return false
		}
	}
	return n["maintenance_lock_ttl_seconds"] >= n["quiesce_max_hold_seconds"]+n["watchdog_safety_margin_seconds"]+2*n["controller_claim_ttl_seconds"] &&
		n["retry_max_backoff_seconds"] >= n["retry_initial_backoff_seconds"] && n["evidence_retention_seconds"] >= n["retention_seconds"] &&
		n["control_metadata_retention_seconds"] >= n["retention_seconds"] && n["control_metadata_retention_seconds"] >= n["evidence_retention_seconds"] && n["control_metadata_retention_seconds"] >= n["logs_retention_seconds"] &&
		n["staging_capacity_bytes"]*10 >= n["max_artifact_bytes"]*11+n["max_index_bytes"]*10 && n["log_chunk_bytes"] <= n["max_log_bytes"] && n["log_chunk_lines"] <= n["max_log_lines"] && n["capture_certificate_ttl_seconds"] > n["backup_task_deadline_seconds"]
}
func bootstrapCanonical(b *strings.Builder, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(jcsString(k))
			b.WriteByte(':')
			bootstrapCanonical(b, x[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			bootstrapCanonical(b, e)
		}
		b.WriteByte(']')
	case string:
		b.WriteString(jcsString(x))
	case json.Number:
		b.WriteString(string(x))
	case bool:
		b.WriteString(strconv.FormatBool(x))
	}
}

func (c BootstrapConfig) sqlValues(installation, actor, reason string) ([]string, []any) {
	columns := []string{"origin_installation_id", "version", "config_sha256", "config_size_bytes", "enabled", "alert_profile", "minimum_recovery_points", "created_by", "change_reason"}
	args := []any{installation, int64(1), c.SHA256(), len(c.canonical), false, c.values.AlertProfile, string(c.values.MinimumRecoveryPoints), actor, reason}
	keys := make([]string, 0, len(c.numbers))
	for k := range c.numbers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		columns = append(columns, k)
		if k == "source_size_safety_factor" {
			args = append(args, bootstrapDecimal(c.numbers[k], 100))
		} else {
			args = append(args, c.numbers[k])
		}
	}
	for _, r := range c.values.Registries {
		columns = append(columns, r.Kind+"_registry_version", r.Kind+"_registry_sha256")
		args = append(args, r.Version, r.SHA256)
	}
	for _, r := range c.values.References {
		columns = append(columns, r.Purpose+"_identity_hash", r.Purpose+"_ref_version")
		args = append(args, r.IdentityHash, r.Version)
	}
	return columns, args
}
