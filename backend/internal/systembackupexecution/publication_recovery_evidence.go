package systembackupexecution

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	security "clawreef/internal/systembackupsecurity"
)

const publicationAttestationDomain = "system-backup-original-failure-domain-attestation.v1\x00"

func decodePublicationCanonical(raw []byte, out any) error {
	if decodeProviderDeploymentJSON(raw, out) != nil {
		return errPublicationConflict
	}
	canonical, err := ce.Canonical(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errPublicationConflict
	}
	return nil
}

type publicationEvidencePin struct{ ID, SHA256 string }

func (p publicationEvidencePin) validate() error {
	if !strings.HasPrefix(p.ID, "sev_") || !manifestBound(p.ID, 128) || !formalCandidateDigest(p.SHA256) {
		return errPublicationConflict
	}
	return nil
}

type publicationRecoverySelection struct {
	Attestation                      publicationEvidencePin
	Capability                       publicationEvidencePin
	OwnerRecordSHA256, OwnerRevision string
}

func (p publicationRecoverySelection) validate() error {
	if p.Attestation.validate() != nil || p.Capability.validate() != nil || p.Attestation.ID == p.Capability.ID || !formalCandidateDigest(p.OwnerRecordSHA256) || !manifestBound(p.OwnerRevision, 128) {
		return errPublicationConflict
	}
	return nil
}

// Administrator-installed trust, never taken from the policy or artifact.
// This authorizes no provider use. Registry bytes and source domain identities
// are independently pinned before capture in the publisher deployment material.
type PublicationRecoveryTrust struct {
	Selection             publicationRecoverySelection `json:"selection"`
	AttestationIssuer     ed25519.PublicKey            `json:"attestation_issuer"`
	Capability            a.ProviderCapabilityPin      `json:"capability"`
	FailureDomainRegistry []byte                       `json:"failure_domain_registry"`
	SourceDomains         []string                     `json:"source_domains"`
}

func (p PublicationRecoveryTrust) validate() error {
	if p.Selection.validate() != nil || len(p.AttestationIssuer) != ed25519.PublicKeySize || len(p.Capability.Issuer) != ed25519.PublicKeySize || p.Capability.Source.RecordID != p.Selection.Capability.ID || !formalCandidateDigest(p.Capability.Source.ContentSHA256) || len(p.FailureDomainRegistry) < 2 || len(p.FailureDomainRegistry) > 65536 || !publicationSortedDomains(p.SourceDomains) {
		return errPublicationConflict
	}
	return nil
}

type publicationFailureDomainEvent struct {
	Sequence       uint64 `json:"sequence"`
	Domain         string `json:"domain_id"`
	IdentitySHA256 string `json:"identity_sha256"`
	State          string `json:"state"`
	PreviousSHA256 string `json:"previous_sha256"`
}
type publicationFailureDomainRegistry struct {
	Version      string                          `json:"schema_version"`
	Installation string                          `json:"origin_installation_id"`
	Revision     string                          `json:"registry_version"`
	History      []publicationFailureDomainEvent `json:"history"`
}

// Complete append-only history: stable IDs cannot change identity, and an
// inactive identity cannot be reissued under its old ID or another display ID.
func publicationDomainIdentities(raw []byte, installation string, pin ce.RegistryPin) (map[string]string, error) {
	var r publicationFailureDomainRegistry
	if len(raw) < 2 || len(raw) > 65536 || hash(raw) != pin.SHA256 || decodePublicationCanonical(raw, &r) != nil || r.Version != "system-backup-original-failure-domains.v1" || r.Installation != installation || r.Revision != pin.Version || len(r.History) < 2 || len(r.History) > 256 {
		return nil, errPublicationConflict
	}
	identities, owners, inactive := map[string]string{}, map[string]string{}, map[string]bool{}
	previous := ""
	for i, e := range r.History {
		if e.Sequence != uint64(i+1) || !manifestBound(e.Domain, 128) || !formalCandidateDigest(e.IdentitySHA256) || !manifestOneOf(e.State, "active", "inactive") || e.PreviousSHA256 != previous || inactive[e.Domain] {
			return nil, errPublicationConflict
		}
		old, exists := identities[e.Domain]
		if exists && (old != e.IdentitySHA256 || e.State != "inactive") || !exists && e.State != "active" || owners[e.IdentitySHA256] != "" && owners[e.IdentitySHA256] != e.Domain {
			return nil, errPublicationConflict
		}
		identities[e.Domain], owners[e.IdentitySHA256] = e.IdentitySHA256, e.Domain
		inactive[e.Domain] = e.State == "inactive"
		b, err := ce.Canonical(e)
		if err != nil {
			return nil, err
		}
		previous = hash(b)
	}
	for id := range inactive {
		if inactive[id] {
			delete(identities, id)
		}
	}
	return identities, nil
}
func publicationSortedDomains(domains []string) bool {
	if len(domains) < 1 || len(domains) > 64 {
		return false
	}
	prev := ""
	for _, id := range domains {
		if !manifestBound(id, 128) || id <= prev {
			return false
		}
		prev = id
	}
	return true
}

type publicationRecoveryDependency struct {
	Purpose        string `json:"purpose"`
	IdentitySHA256 string `json:"identity_hash"`
	Version        string `json:"version"`
	Domain         string `json:"failure_domain_id"`
}
type publicationFailureDomainAttestation struct {
	Version           string                          `json:"schema_version"`
	ID                string                          `json:"evidence_id"`
	Installation      string                          `json:"origin_installation_id"`
	ConfigSHA256      string                          `json:"original_config_sha256"`
	Registry          ce.RegistryPin                  `json:"failure_domains_registry"`
	TargetDomain      string                          `json:"target_failure_domain_id"`
	TargetSHA256      string                          `json:"artifact_target_sha256"`
	SourceDomains     []string                        `json:"source_failure_domain_ids"`
	Dependencies      []publicationRecoveryDependency `json:"dependencies"`
	CapabilitySHA256  string                          `json:"recovery_capability_sha256"`
	OwnerRecordSHA256 string                          `json:"original_kek_record_sha256"`
	Actor             string                          `json:"signed_actor"`
	AuditID           string                          `json:"audit_id"`
	Issued, Expires   time.Time
	Revoked           bool `json:"revoked"`
}
type publicationSignedAttestation struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type publicationCurrentEvidence struct {
	Raw     []byte
	Expires time.Time
}

// Private receipt is tied to all original inputs and current evidence bytes.
// It does not carry a grant, claim, DEK, or an acceptance/signing result.
type publicationRecoveryFacts struct {
	Target                      publicationManifestTarget
	KEK                         publicationManifestKEK
	evidenceSHA256              string
	captureSHA256, targetSHA256 string
	until                       time.Time
}

func verifyPublicationRecoveryEvidence(config []byte, policy frozenPublicationPolicy, trust *PublicationRecoveryTrust, binding reg.Binding, ownerIssuer ed25519.PublicKey, ownerRaw, ownerSignature []byte, attestation, capability publicationCurrentEvidence, targetSHA string, now time.Time) (publicationRecoveryFacts, error) {
	var zero publicationRecoveryFacts
	p := policy.Policy
	if policy.validate() != nil || p.RecoveryEvidenceStatus != "provided" || p.RecoveryEvidence == nil || trust == nil || trust.validate() != nil || !reflect.DeepEqual(*p.RecoveryEvidence, trust.Selection) || hash(config) != p.ConfigSHA256 || binding.InstallationID != p.Installation || !formalCandidateDigest(targetSHA) || now.IsZero() || !now.Before(attestation.Expires) || !now.Before(capability.Expires) || len(attestation.Raw) > 8192 || hash(attestation.Raw) != trust.Selection.Attestation.SHA256 || hash(capability.Raw) != trust.Selection.Capability.SHA256 {
		return zero, errPublicationConflict
	}
	identities, err := publicationDomainIdentities(trust.FailureDomainRegistry, p.Installation, p.FailureDomains)
	if err != nil {
		return zero, err
	}
	var envelope publicationSignedAttestation
	var statement publicationFailureDomainAttestation
	if decodePublicationCanonical(attestation.Raw, &envelope) != nil || len(envelope.Payload) < 2 || len(envelope.Payload) > 6144 || !ed25519.Verify(trust.AttestationIssuer, append([]byte(publicationAttestationDomain), envelope.Payload...), envelope.Signature) || decodePublicationCanonical(envelope.Payload, &statement) != nil {
		return zero, errPublicationConflict
	}
	if statement.Version != "system-backup-original-failure-domain-attestation.v1" || statement.ID != trust.Selection.Attestation.ID || statement.Installation != p.Installation || statement.ConfigSHA256 != p.ConfigSHA256 || statement.Registry != p.FailureDomains || statement.TargetDomain != p.Target.Domain || statement.TargetSHA256 != targetSHA || !reflect.DeepEqual(statement.SourceDomains, trust.SourceDomains) || statement.CapabilitySHA256 != trust.Selection.Capability.SHA256 || statement.OwnerRecordSHA256 != trust.Selection.OwnerRecordSHA256 || !manifestBound(statement.Actor, 256) || !manifestBound(statement.AuditID, 256) || statement.Revoked || statement.Issued.IsZero() || statement.Issued.After(now) || !now.Before(statement.Expires) {
		return zero, errPublicationConflict
	}
	source := map[string]bool{}
	for _, id := range trust.SourceDomains {
		if identities[id] == "" {
			return zero, errPublicationConflict
		}
		source[id] = true
	}
	independent := func(id string) bool { return identities[id] != "" && !source[id] }
	if !independent(p.Target.Domain) || p.Target.Class != "dr-ready-external" || len(p.Target.Risks) != 0 {
		return zero, errPublicationConflict
	}
	cfg, err := security.DecodeConfigValues(config)
	if err != nil {
		return zero, err
	}
	refs := cfg.References()
	kekMatched := false
	for _, ref := range refs {
		if ref.Purpose == "kek" && ref.IdentityHash == binding.ConfigRef.IdentityHash && ref.Version == binding.ConfigRef.Version {
			kekMatched = true
		}
	}
	if !kekMatched {
		return zero, errPublicationConflict
	}
	if len(refs) != len(statement.Dependencies) {
		return zero, errPublicationConflict
	}
	seen := map[string]bool{}
	for _, dep := range statement.Dependencies {
		if seen[dep.Purpose] || !independent(dep.Domain) {
			return zero, errPublicationConflict
		}
		seen[dep.Purpose] = true
		matched := false
		for _, ref := range refs {
			if ref.Purpose == dep.Purpose && ref.IdentityHash == dep.IdentitySHA256 && ref.Version == dep.Version {
				matched = true
				break
			}
		}
		if !matched {
			return zero, errPublicationConflict
		}
	}
	if a.InspectOriginalKEKMaterial(ownerRaw, ownerSignature, ownerIssuer, trust.Selection.OwnerRecordSHA256, p.Installation, trust.Selection.OwnerRevision, binding.ConfigRef, now) != nil {
		return zero, errPublicationConflict
	}
	var owner a.OriginalRecord
	if json.Unmarshal(ownerRaw, &owner) != nil || !reflect.DeepEqual(owner.Binding, binding) {
		return zero, errPublicationConflict
	}
	record, err := a.InspectProviderCapabilityMaterial(capability.Raw, trust.Capability, binding, kms.Unwrap, capability.Expires, now)
	if err != nil || record.Facts.Permission.ControllerVerifier != nil || binding.Key.Provider != "external-kms" {
		return zero, errPublicationConflict
	}
	proof, err := ce.Canonical(struct{ Policy, Attestation, Capability, Owner, Target string }{policy.SHA256, hash(attestation.Raw), hash(capability.Raw), hash(ownerRaw), targetSHA})
	if err != nil {
		return zero, err
	}
	sum := hash(proof)
	out := publicationRecoveryFacts{Target: p.Target, KEK: publicationManifestKEK{Provider: binding.Key.Provider, KeyID: binding.Key.ProviderKeyID, KeyVersion: binding.Key.ProviderVersion, SourceIndependent: true, RecoveryProof: &sum}, evidenceSHA256: sum}
	out.until = statement.Expires
	for _, deadline := range []time.Time{attestation.Expires, capability.Expires, owner.Until, record.Until} {
		if deadline.Before(out.until) {
			out.until = deadline
		}
	}
	// Keep detached public values: callers cannot mutate the frozen policy.
	out.Target.Risks = append([]string{}, p.Target.Risks...)
	id, sha := *p.Target.AttestationID, *p.Target.AttestationSHA256
	out.Target.AttestationID, out.Target.AttestationSHA256 = &id, &sha
	if !bytes.Equal(config, cfg.CanonicalJSON()) {
		return zero, errPublicationConflict
	}
	return out, nil
}
