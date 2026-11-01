package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"regexp"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// Closed v12 public DTO. Parsing is content validation only, never evidence
// that a caller completed C/domain verification, Job upload or acceptance.
type publicationManifestV12 struct {
	Version            string                                 `json:"schema_version"`
	AppVersion         string                                 `json:"app_version"`
	GitCommit          string                                 `json:"git_commit"`
	Generated          time.Time                              `json:"generated_at"`
	Installation       string                                 `json:"origin_installation_id"`
	Backup             string                                 `json:"backup_public_id"`
	Attempt            uint64                                 `json:"attempt_no"`
	Orchestrator       string                                 `json:"orchestrator"`
	Profile            string                                 `json:"deployment_profile"`
	Runner             string                                 `json:"runner_type"`
	Purpose            string                                 `json:"task_purpose"`
	MigrationCatalog   string                                 `json:"migration_catalog_hash"`
	Schema             string                                 `json:"schema_hash"`
	CaptureContext     string                                 `json:"capture_context_hash"`
	CaptureCertificate string                                 `json:"capture_certificate_hash"`
	Target             publicationManifestTarget              `json:"target"`
	KEK                publicationManifestKEK                 `json:"kek_recovery"`
	Consistency        string                                 `json:"consistency"`
	Eligibility        publicationManifestEligibility         `json:"precommit_eligibility"`
	Parts              map[string]publicationManifestPart     `json:"parts"`
	Index              publicationManifestIndex               `json:"artifact_index"`
	Marker             publicationManifestMarker              `json:"commit_marker"`
	Control            publicationManifestControl             `json:"control_evidence"`
	SecretPolicy       publicationSecretPolicySummary         `json:"secret_policy"`
	SchemaCoverage     publicationManifestCoverage            `json:"schema_object_coverage"`
	Config             publicationManifestConfig              `json:"config_recovery"`
	Business           map[string]publicationManifestBusiness `json:"business_summaries"`
	Warnings           []publicationManifestWarning           `json:"warnings"`
}
type publicationManifestTarget struct {
	Class             string   `json:"target_class"`
	Domain            string   `json:"failure_domain_id"`
	Risks             []string `json:"risks"`
	AttestationID     *string  `json:"attestation_id"`
	AttestationSHA256 *string  `json:"attestation_hash"`
}
type publicationManifestKEK struct {
	Provider          string  `json:"provider"`
	KeyID             string  `json:"key_id"`
	KeyVersion        string  `json:"key_version"`
	SourceIndependent bool    `json:"source_independent"`
	RecoveryProof     *string `json:"recovery_proof_hash"`
}
type publicationManifestEligibility struct {
	PartsComplete     bool     `json:"required_parts_complete"`
	VerifiersComplete bool     `json:"required_verifiers_complete"`
	Disqualifiers     []string `json:"disqualifier_codes"`
	InputsSHA256      string   `json:"inputs_hash"`
}
type publicationManifestPart struct {
	Required         bool      `json:"required"`
	Status           string    `json:"status"`
	Consistency      string    `json:"consistency"`
	CheckpointType   string    `json:"checkpoint_type"`
	CheckpointSHA256 string    `json:"checkpoint_hash"`
	Captured         time.Time `json:"captured_at"`
	Objects          int64     `json:"objects"`
	Bytes            int64     `json:"bytes"`
	CipherSHA256     string    `json:"ciphertext_sha256"`
	Evidence         []string  `json:"evidence_ids"`
}
type publicationManifestIndex struct {
	Path     string `json:"path"`
	Checksum string `json:"checksum"`
}
type publicationManifestMarker struct {
	Path    string `json:"path"`
	Version string `json:"schema_version"`
}
type publicationManifestControl struct {
	Path     string `json:"path"`
	Version  string `json:"schema_version"`
	Checksum string `json:"checksum"`
}
type publicationManifestCoverage struct {
	RegistryVersion string `json:"registry_version"`
	RegistrySHA256  string `json:"registry_hash"`
	Covered         int64  `json:"covered"`
	Excluded        int64  `json:"excluded"`
}
type publicationManifestConfig struct {
	Version    uint64                     `json:"config_version"`
	SHA256     string                     `json:"snapshot_hash"`
	Parameters map[string]json.RawMessage `json:"redacted_parameters"`
}
type publicationManifestBusiness struct {
	Objects        int64  `json:"objects"`
	Rows           int64  `json:"rows"`
	Bytes          int64  `json:"bytes"`
	VerifierSHA256 string `json:"verifier_summary_hash"`
}
type publicationManifestWarning struct {
	Code          string          `json:"code"`
	Category      string          `json:"category"`
	Disqualifying bool            `json:"disqualifying"`
	Details       json.RawMessage `json:"details_hash,omitempty"`
}

func decodePublicationManifestV12(raw []byte) (publicationManifestV12, error) {
	var zero publicationManifestV12
	if len(raw) < 2 || len(raw) > 262144 {
		return zero, errPublicationConflict
	}
	var m publicationManifestV12
	if decodeProviderDeploymentJSON(raw, &m) != nil {
		return zero, errPublicationConflict
	}
	canonical, err := ce.Canonical(m)
	if err != nil || !bytes.Equal(raw, canonical) || m.validate() != nil {
		return zero, errPublicationConflict
	}
	return m, nil
}

func manifestOneOf(value string, values ...string) bool {
	for _, allowed := range values {
		if value == allowed {
			return true
		}
	}
	return false
}
func manifestCount(value int64) bool           { return value >= 0 && value <= 9007199254740991 }
func manifestBound(value string, max int) bool { return value != "" && len(value) <= max }

func (m publicationManifestV12) validate() error {
	bad := errPublicationConflict
	if m.Version != "system-backup.v1" || !manifestBound(m.AppVersion, 128) || !regexp.MustCompile(`^[a-f0-9]{7,64}$`).MatchString(m.GitCommit) || m.Generated.IsZero() || !manifestBound(m.Installation, 128) || !regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`).MatchString(m.Backup) || m.Attempt < 1 || m.Attempt > 9007199254740991 || !manifestOneOf(m.Orchestrator, "kubernetes", "k3s") || !manifestOneOf(m.Profile, "cluster", "single-node") || m.Runner != "kubernetes" || !manifestOneOf(m.Purpose, "acceptance", "functional_test") || !manifestOneOf(m.Consistency, "strong", "bounded", "weak") {
		return bad
	}
	for _, sum := range []string{m.MigrationCatalog, m.Schema, m.CaptureContext, m.CaptureCertificate, m.Index.Checksum, m.Control.Checksum, m.SecretPolicy.RegistrySHA256, m.SchemaCoverage.RegistrySHA256, m.Config.SHA256, m.Eligibility.InputsSHA256} {
		if !formalCandidateDigest(sum) {
			return bad
		}
	}
	t := m.Target
	if !manifestOneOf(t.Class, "dr-ready-external", "same-cluster-copy") || !manifestBound(t.Domain, 128) || t.Risks == nil {
		return bad
	}
	seen := map[string]bool{}
	for _, risk := range t.Risks {
		if seen[risk] || !manifestOneOf(risk, "source_overlap", "same_failure_domain", "artifact_credential_source_dependent", "kek_source_dependent", "signing_key_source_dependent", "catalog_source_dependent", "attestation_missing", "attestation_expired", "conditional_commit_unavailable", "transport_unverified", "broad_egress", "provider_capability_degraded") {
			return bad
		}
		seen[risk] = true
	}
	if (t.AttestationID == nil) != (t.AttestationSHA256 == nil) {
		return bad
	}
	if t.AttestationID != nil && (!manifestBound(*t.AttestationID, 128) || !formalCandidateDigest(*t.AttestationSHA256)) {
		return bad
	}
	k := m.KEK
	if !manifestOneOf(k.Provider, "external-kms", "external-secret", "k8s-secret") || !manifestBound(k.KeyID, 256) || !manifestBound(k.KeyVersion, 128) || k.RecoveryProof != nil && !formalCandidateDigest(*k.RecoveryProof) || k.SourceIndependent && k.RecoveryProof == nil {
		return bad
	}
	if !m.Eligibility.PartsComplete || !m.Eligibility.VerifiersComplete || m.Eligibility.Disqualifiers == nil {
		return bad
	}
	seen = map[string]bool{}
	for _, code := range m.Eligibility.Disqualifiers {
		if seen[code] || !manifestOneOf(code, "functional_test", "consistency_not_strong", "disqualifying_warning", "target_not_external", "target_risk", "attestation_invalid", "kek_not_recoverable") {
			return bad
		}
		seen[code] = true
	}
	if len(m.Parts) < 1 || len(m.Parts) > 6 {
		return bad
	}
	for name, part := range m.Parts {
		if !manifestOneOf(name, publicationRequestedParts...) || !part.Required || part.Status != "completed" || !manifestOneOf(part.Consistency, "strong", "bounded", "weak") || !manifestOneOf(part.CheckpointType, "mysql_transaction", "redis_rdb", "redis_scan_window", "csi_snapshot", "object_version_copy", "gate_staging") || !formalCandidateDigest(part.CheckpointSHA256) || !formalCandidateDigest(part.CipherSHA256) || part.Captured.IsZero() || !manifestCount(part.Objects) || !manifestCount(part.Bytes) || part.Evidence == nil {
			return bad
		}
		evidence := map[string]bool{}
		for _, id := range part.Evidence {
			if evidence[id] || !regexp.MustCompile(`^sev_[A-Za-z0-9_-]+$`).MatchString(id) {
				return bad
			}
			evidence[id] = true
		}
	}
	if m.Purpose == "acceptance" && len(m.Parts) != 6 {
		return bad
	}
	if m.Index.Path != "artifact-index.json" || m.Marker.Path != "_COMMITTED" || m.Marker.Version != "system-backup-committed.v1" || m.Control.Path != ce.CipherPath || m.Control.Version != ce.Version {
		return bad
	}
	if !manifestBound(m.SecretPolicy.RegistryVersion, 128) || !manifestCount(m.SecretPolicy.RequiredEntries) || !manifestCount(m.SecretPolicy.CapturedEntries) || m.SecretPolicy.CapturedEntries < m.SecretPolicy.RequiredEntries || !manifestBound(m.SchemaCoverage.RegistryVersion, 128) || !manifestCount(m.SchemaCoverage.Covered) || !manifestCount(m.SchemaCoverage.Excluded) || m.Config.Version < 1 || m.Config.Version > 9007199254740991 || m.Config.Parameters == nil || len(m.Config.Parameters) > 64 || len(m.Business) != 6 || m.Warnings == nil {
		return bad
	}
	for _, category := range []string{"users", "instances", "ai_gateway", "teams", "resources", "skill_hub"} {
		summary, ok := m.Business[category]
		if !ok || !manifestCount(summary.Objects) || !manifestCount(summary.Rows) || !manifestCount(summary.Bytes) || !formalCandidateDigest(summary.VerifierSHA256) {
			return bad
		}
	}
	for _, warning := range m.Warnings {
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`).MatchString(warning.Code) || !manifestOneOf(warning.Category, "data-integrity-warning", "consistency-warning", "operational-warning", "unsupported-evidence-warning") {
			return bad
		}
		if len(warning.Details) > 0 && !bytes.Equal(warning.Details, []byte("null")) {
			var sum string
			if json.Unmarshal(warning.Details, &sum) != nil || !formalCandidateDigest(sum) {
				return bad
			}
		}
	}
	return nil
}
