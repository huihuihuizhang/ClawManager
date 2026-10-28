package host

import (
	"fmt"
	"sort"

	"clawreef/internal/systembackup/recovery"
)

type Diagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Field    string `json:"field"`
	Material string `json:"material,omitempty"`
}
type PolicyCoverage struct {
	Profile   int `json:"profile_index"`
	Instances int `json:"instances"`
	Covered   int `json:"covered"`
	Policies  int `json:"policies"`
}
type DiagnosticReport struct {
	Version         string           `json:"version"`
	StructureValid  bool             `json:"structure_valid"`
	RuntimeVerified bool             `json:"runtime_verified"`
	Coverage        []PolicyCoverage `json:"coverage"`
	Findings        []Diagnostic     `json:"findings"`
}

// Diagnose is pure. It never reads referenced credentials/certificates or
// contacts SQL/Kubernetes/provider endpoints. Findings contain fixed codes and
// generated field positions, never values from the submitted configuration.
func Diagnose(raw []byte) DiagnosticReport {
	r := DiagnosticReport{Version: "backup-diagnostics.v1", Coverage: []PolicyCoverage{}, Findings: []Diagnostic{}}
	add := func(severity, code, field, material string) {
		r.Findings = append(r.Findings, Diagnostic{severity, code, field, material})
	}
	var c Config
	if len(raw) > 4<<20 {
		add("error", "input_too_large", "$", "")
		return r
	}
	if _, e := recovery.Canonical(raw); e != nil || decodeConfig(raw, &c) != nil {
		add("error", "invalid_configuration_json", "$", "configuration_template")
		return r
	}
	r.StructureValid = c.Validate() == nil
	if !r.StructureValid {
		add("error", "configuration_structure_invalid", "$", "configuration_template")
	}
	for _, v := range []struct{ field, value string }{{"Owner", c.Owner}, {"ControlDatabase", c.ControlDatabase}, {"KeysFile", c.KeysFile}} {
		if v.value == "" {
			add("error", "required_field_missing", v.field, "configuration_template")
		}
	}
	for i, p := range c.Profiles {
		base := fmt.Sprintf("Profiles[%d]", i)
		if p.Config.Validate() != nil {
			add("error", "profile_structure_invalid", base+".Config", "configuration_template")
		}
		row := PolicyCoverage{Profile: i, Instances: len(p.Config.Instances), Policies: len(p.Config.RuntimePolicies)}
		for j, in := range p.Config.Instances {
			policy, ok := p.Config.RuntimePolicies[in.Policy]
			if !ok || policy.Validate() != nil {
				add("error", "runtime_policy_missing_or_invalid", fmt.Sprintf("%s.Config.Instances[%d].Policy", base, j), "agent_release")
			} else {
				row.Covered++
			}
		}
		r.Coverage = append(r.Coverage, row)
		add("required_evidence", "runtime_layout_unverified", base+".Config.RuntimePolicies", "agent_release")
		if p.Config.WorkBuddy == nil {
			add("conditional", "workbuddy_schema_not_configured", base+".Config.WorkBuddy", "workbuddy_schema")
		}
		if p.Config.Mode != "target" {
			if len(p.Config.Applications) == 0 {
				add("error", "application_inventory_missing", base+".Config.Applications", "writer_inventory")
			}
			if p.Config.WriterProofURL == "" {
				add("error", "writer_proof_endpoint_missing", base+".Config.WriterProofURL", "writer_inventory")
			}
			add("required_evidence", "writer_coverage_unverified", base+".Config.Applications", "writer_inventory")
		}
		if p.Config.SixDomainModule != nil {
			add("required_adapter", "six_domain_owner_required", base+".Config.SixDomainModule", "domain_owners")
		}
		if p.Config.AcceptancePolicy != nil {
			add("required_evidence", "acceptance_policy_and_independent_evidence_unverified", base+".Config.AcceptancePolicy", "domain_owners")
		}
		if p.Config.SharedWorkspaceModule != nil {
			add("required_adapter", "shared_workspace_owner_required", base+".Config.SharedWorkspaceModule", "storage_layout")
		}
		if p.Config.ExclusiveNFSProofURL != "" {
			add("required_evidence", "external_nfs_writers_unverified", base+".Config.ExclusiveNFSProofURL", "storage_layout")
		}
		add("required_evidence", "database_schema_and_target_isolation_unverified", base+".Config.Target", "isolated_environment")
	}
	for i, p := range c.Catalogs {
		base := fmt.Sprintf("Catalogs[%d]", i)
		if p.Provider.Validate() != nil || p.Provider.AllowAppend {
			add("error", "invalid_read_provider", base+".Provider", "object_storage")
		}
		if !pinned(p.Trust) {
			add("error", "trust_pin_missing_or_invalid", base+".Trust", "trust_configuration")
		}
		add("required_adapter", "native_provider_evidence_required", base+".Provider", "object_storage")
		add("required_evidence", "mounted_trust_and_tls_not_read", base+".Trust", "trust_configuration")
		for j, a := range p.Artifacts {
			field := fmt.Sprintf("%s.Artifacts[%d]", base, j)
			if !pinned(a.Codec) || !pinned(a.WrappingKeys) || a.Bootstrap.Validate() != nil || a.Bootstrap.KEK != a.WrappingKeys.Reference {
				add("error", "artifact_pins_or_bootstrap_invalid", field, "artifact_format")
			}
			add("required_evidence", "artifact_codec_and_keys_not_read", field+".Codec", "artifact_format")
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		return a.Code < b.Code
	})
	return r
}

type MaterialRequirement struct {
	ID     string   `json:"id"`
	Needed []string `json:"needed"`
	Format string   `json:"format"`
}

func MaterialsTemplate() any {
	return struct {
		Version                   string                `json:"version"`
		ProductionSecretsRequired bool                  `json:"production_secrets_required"`
		Items                     []MaterialRequirement `json:"items"`
	}{"backup-materials.v1", false, []MaterialRequirement{
		{"configuration_template", []string{"controller configuration with placeholder file paths", "profile mode and supported operation kinds"}, "JSON; no embedded credentials"},
		{"agent_release", []string{"agent type and Lite/Pro variant", "image digest", "persistent paths for files, skills, sessions and tasks", "redacted configuration and field meanings"}, "release manifest and redacted JSON/YAML/TOML/env"},
		{"workbuddy_schema", []string{"identity table DDL and version", "instance/storage identity/UID/GID mappings"}, "DDL or source branch; no user rows"},
		{"writer_inventory", []string{"application workloads and replicas", "external database/object/NFS writers", "runtime pause/resume capability specification"}, "redacted workload manifests and interface specification"},
		{"storage_layout", []string{"CSI/NFS/HostPath layout", "PVC/PV/StorageClass manifests", "shared directories and UID/GID", "external mounts and fencing mechanism"}, "redacted YAML and directory layout"},
		{"object_storage", []string{"product/version and bucket versioning", "native conditional creation and expiry semantics", "read/append/delete role policies", "immutable inventory mechanism"}, "vendor specification and redacted policies"},
		{"redis_layout", []string{"version and topology", "DB/prefix ownership", "TTL policy", "stream/group schema", "dedicated or shared keyspace"}, "redacted schema and examples"},
		{"domain_owners", []string{"versioned collectors and independent verifiers", "table and JSON policies", "normalization and stop requirements"}, "source or interface contract"},
		{"artifact_format", []string{"encrypted framing and envelope version", "codec descriptor schema", "immutable key references and recovery procedure"}, "specification and synthetic encrypted fixture; no production keys"},
		{"trust_configuration", []string{"public signing-key purposes and versions", "revocation procedure", "TLS identity and certificate rotation rules"}, "public configuration; no private keys"},
		{"isolated_environment", []string{"MySQL/Kubernetes/Redis versions", "empty target schema", "storage drivers and isolation controls"}, "isolated environment manifest"},
	}}
}
