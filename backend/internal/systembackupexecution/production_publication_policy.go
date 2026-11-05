package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
)

const originalPublicationPolicyVersion = "system-backup-original-publication-policy.v1"

// Independent fixed owner input, bound into the signed source-owner scope
// BEFORE capture. Positive declarations select evidence; only the independent
// current publisher evidence verifier can authenticate those declarations.
type originalPublicationPolicyReference struct{ Protocol, Path, SHA256 string }

func (r originalPublicationPolicyReference) validate() error {
	if r.Protocol != originalPublicationPolicyVersion || !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || !formalCandidateDigest(r.SHA256) {
		return d.ErrNotReady
	}
	return nil
}

type originalPublicationPolicy struct {
	Version                string                        `json:"schema_version"`
	Installation           string                        `json:"origin_installation_id"`
	ConfigSHA256           string                        `json:"original_config_sha256"`
	FailureDomains         ce.RegistryPin                `json:"original_failure_domains_registry"`
	Target                 publicationManifestTarget     `json:"target"`
	RecoveryEvidenceStatus string                        `json:"recovery_evidence_status"`
	RecoveryEvidence       *publicationRecoverySelection `json:"recovery_evidence,omitempty"`
}
type frozenPublicationPolicy struct {
	SHA256 string                    `json:"sha256"`
	Policy originalPublicationPolicy `json:"policy"`
}

func (p originalPublicationPolicy) validate() error {
	if p.Version != originalPublicationPolicyVersion || !strings.HasPrefix(p.Installation, "installation_") || len(p.Installation) > 128 || !formalCandidateDigest(p.ConfigSHA256) || !manifestBound(p.FailureDomains.Version, 128) || !formalCandidateDigest(p.FailureDomains.SHA256) || !manifestOneOf(p.Target.Class, "dr-ready-external", "same-cluster-copy") || !manifestBound(p.Target.Domain, 128) || p.Target.Risks == nil {
		return d.ErrNotReady
	}
	if p.RecoveryEvidenceStatus == "not_provided" {
		if p.RecoveryEvidence != nil || p.Target.AttestationID != nil || p.Target.AttestationSHA256 != nil {
			return d.ErrNotReady
		}
	} else if p.RecoveryEvidenceStatus == "provided" {
		if p.RecoveryEvidence == nil || p.RecoveryEvidence.validate() != nil || p.Target.AttestationID == nil || p.Target.AttestationSHA256 == nil || *p.Target.AttestationID != p.RecoveryEvidence.Attestation.ID || *p.Target.AttestationSHA256 != p.RecoveryEvidence.Attestation.SHA256 {
			return d.ErrNotReady
		}
	} else {
		return d.ErrNotReady
	}
	previous := ""
	for _, risk := range p.Target.Risks {
		if risk <= previous || !manifestOneOf(risk, "source_overlap", "same_failure_domain", "artifact_credential_source_dependent", "kek_source_dependent", "signing_key_source_dependent", "catalog_source_dependent", "attestation_missing", "attestation_expired", "conditional_commit_unavailable", "transport_unverified", "broad_egress", "provider_capability_degraded") {
			return d.ErrNotReady
		}
		previous = risk
	}
	return nil
}

func (p frozenPublicationPolicy) validate() error {
	raw, err := ce.Canonical(p.Policy)
	if err != nil || p.Policy.validate() != nil || hash(raw) != p.SHA256 {
		return d.ErrNotReady
	}
	return nil
}

func originalFailureDomainsPin(raw []byte) (ce.RegistryPin, error) {
	var config struct {
		Registries []struct {
			Kind    string `json:"registry_kind"`
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"registries"`
	}
	var pin ce.RegistryPin
	if len(raw) < 2 || len(raw) > 262144 || json.Unmarshal(raw, &config) != nil {
		return pin, d.ErrNotReady
	}
	for _, ref := range config.Registries {
		if ref.Kind != "failure_domains" {
			continue
		}
		if pin.Version != "" || !manifestBound(ref.Version, 128) || !formalCandidateDigest(ref.SHA256) {
			return ce.RegistryPin{}, d.ErrNotReady
		}
		pin = ce.RegistryPin{Version: ref.Version, SHA256: ref.SHA256}
	}
	if pin.Version == "" {
		return pin, d.ErrNotReady
	}
	return pin, nil
}

func decodeOriginalPublicationPolicy(raw []byte, sha, installation, configSHA string, pin ce.RegistryPin, target publicationManifestTarget) (frozenPublicationPolicy, error) {
	var zero frozenPublicationPolicy
	if len(raw) < 2 || len(raw) > 65536 || !formalCandidateDigest(sha) || hash(raw) != sha {
		return zero, d.ErrNotReady
	}
	var policy originalPublicationPolicy
	if decodeProviderDeploymentJSON(raw, &policy) != nil || policy.validate() != nil || policy.Installation != installation || policy.ConfigSHA256 != configSHA || policy.FailureDomains != pin {
		return zero, d.ErrNotReady
	}
	canonical, err := ce.Canonical(policy)
	if err != nil || !bytes.Equal(canonical, raw) {
		return zero, d.ErrNotReady
	}
	// SQL freezes class/domain/risks. Attestation pins are separately selected
	// before capture and authenticated against independent publisher trust.
	declared := policy.Target
	declared.AttestationID, declared.AttestationSHA256 = nil, nil
	actual, err := ce.Canonical(target)
	expected, targetErr := ce.Canonical(declared)
	if err != nil || targetErr != nil || !bytes.Equal(actual, expected) {
		return zero, d.ErrNotReady
	}
	return frozenPublicationPolicy{SHA256: sha, Policy: policy}, nil
}

func (x *originalSourceMetadataAuthority) loadOriginalPublicationPolicy(ctx context.Context) (frozenPublicationPolicy, error) {
	var zero frozenPublicationPolicy
	if x == nil || x.service == nil || x.owner == nil || x.owner.Gate.Authority.DB == nil || x.service.captureMaterials == nil || x.service.captureMaterials.Discovery == nil || x.service.captureMaterials.Discovery.PublicationPolicy == nil || x.Recheck(ctx) != nil {
		return zero, d.ErrNotReady
	}
	ref := *x.service.captureMaterials.Discovery.PublicationPolicy
	if ref.validate() != nil {
		return zero, d.ErrNotReady
	}
	pin, err := originalFailureDomainsPin(x.input.ConfigSnapshot)
	if err != nil {
		return zero, err
	}
	a := x.input.Authority
	var rowPin ce.RegistryPin
	var target publicationManifestTarget
	var risks string
	if x.owner.Gate.Authority.DB.QueryRowContext(ctx, `SELECT cfg.failure_domains_registry_version,cfg.failure_domains_registry_sha256,b.target_class,b.target_risks,b.target_failure_domain_id FROM system_backup_v2_configs cfg JOIN system_backup_v2_backups b ON b.origin_installation_id=cfg.origin_installation_id AND b.config_version=cfg.version AND b.config_snapshot_sha256=cfg.config_sha256 WHERE cfg.origin_installation_id=? AND cfg.version=? AND cfg.config_sha256=? AND b.public_id=?`, a.InstallationID, a.ConfigVersion, a.ConfigSHA256, a.TaskPublicID).Scan(&rowPin.Version, &rowPin.SHA256, &target.Class, &risks, &target.Domain) != nil || rowPin != pin || x.Recheck(ctx) != nil {
		return zero, d.ErrNotReady
	}
	target.Risks = []string{}
	if risks != "" {
		target.Risks = strings.Split(risks, ",")
		sort.Strings(target.Risks)
	}
	raw, err := pinnedDeploymentFile(ref.Path, ref.SHA256, 65536)
	if err != nil {
		return zero, err
	}
	configSHA := a.ConfigSHA256
	var original originalPublicationPolicy
	if decodeProviderDeploymentJSON(raw, &original) != nil || original.validate() != nil {
		return zero, d.ErrNotReady
	}
	if original.ConfigSHA256 != configSHA {
		view, err := x.owner.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: false, Isolation: sql.LevelRepeatableRead})
		if err != nil {
			return zero, d.ErrNotReady
		}
		_, lineageErr := readOriginalEnabledConfiguration(ctx, view, a.InstallationID, original.ConfigSHA256, a.ConfigVersion, a.ConfigSHA256, x.input.ConfigSnapshot)
		closed := view.Rollback()
		if lineageErr != nil || closed != nil {
			return zero, d.ErrNotReady
		}
		configSHA = original.ConfigSHA256
	}
	policy, err := decodeOriginalPublicationPolicy(raw, ref.SHA256, a.InstallationID, configSHA, pin, target)
	if err != nil || x.Recheck(ctx) != nil {
		return zero, d.ErrNotReady
	}
	if policy.Policy.RecoveryEvidenceStatus == "provided" {
		publisher := x.service.publisherVerifier
		if publisher == nil || publisher.RecoveryTrust == nil || publisher.RecoveryTrust.validate() != nil || x.service.checkPublisherVerifierBinding(ctx) != nil || !reflect.DeepEqual(policy.Policy.RecoveryEvidence, &publisher.RecoveryTrust.Selection) {
			return zero, d.ErrNotReady
		}
		if _, err := publicationDomainIdentities(publisher.RecoveryTrust.FailureDomainRegistry, a.InstallationID, pin); err != nil {
			return zero, d.ErrNotReady
		}
	}
	return policy, nil
}
