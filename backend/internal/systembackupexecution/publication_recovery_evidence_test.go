package systembackupexecution

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	a "clawreef/internal/systembackupkekadapter"
	candidate "clawreef/internal/systembackupkekcandidate"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	security "clawreef/internal/systembackupsecurity"
	w "clawreef/internal/systembackupwire"
)

type publicationRecoveryData struct {
	config                   []byte
	policy                   frozenPublicationPolicy
	trust                    *PublicationRecoveryTrust
	binding                  reg.Binding
	owner                    a.OriginalRecord
	cap                      a.ProviderCapabilityRecord
	statement                publicationFailureDomainAttestation
	ownerKey, capKey, attKey ed25519.PrivateKey
	now                      time.Time
	target                   string
}

// Named administrator/owner signatures over bounded local DATA. This does not
// create a current SQL observation, grant, source capture or acceptance.
func newPublicationRecoveryData(t *testing.T) *publicationRecoveryData {
	t.Helper()
	x := &publicationRecoveryData{now: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), target: hash([]byte("named target DATA"))}
	ownerPub, ownerKey, _ := ed25519.GenerateKey(rand.Reader)
	_ = ownerPub
	x.ownerKey = ownerKey
	_, x.capKey, _ = ed25519.GenerateKey(rand.Reader)
	_, x.attKey, _ = ed25519.GenerateKey(rand.Reader)
	raw, err := os.ReadFile("../systembackupkekcandidate/testdata/mapping.json")
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := candidate.DecodeMapping(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := mapping.Input()
	src := func(s candidate.SourceRecord) reg.SourceRecord {
		return reg.SourceRecord{SourceID: s.SourceID, RecordID: s.RecordID, RecordVersion: s.RecordVersion, ContentSHA256: s.ContentSHA256}
	}
	ref := func(r candidate.KMSReference) reg.TypedReference {
		b, _ := json.Marshal(r)
		return reg.TypedReference{RawJSON: b, SHA256: hash(b)}
	}
	x.binding = reg.Binding{InstallationID: m.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: m.ConfigRef.IdentityHash, Version: m.ConfigRef.Version}, Key: w.KeyBinding{Provider: m.KeyBinding.Provider, IdentityHash: m.KeyBinding.IdentityHash, RegistryVersion: m.KeyBinding.RegistryVersion, ProviderKeyID: m.KeyBinding.ProviderKeyID, ProviderVersion: m.KeyBinding.ProviderVersion}, Provider: reg.ProviderBinding{Endpoint: m.Provider.Endpoint, KeyName: m.Provider.KeyName, ProviderIdentityHash: m.Provider.ProviderIdentityHash, ScopeHash: m.Provider.ScopeHash, CAPEMSHA256: m.Provider.CAPEMSHA256, CASource: src(m.Provider.CASource)}, GenerateRef: ref(m.GenerateRef), UnwrapRef: ref(m.UnwrapRef)}
	bindingRaw, _ := json.Marshal(x.binding)
	x.owner = a.OriginalRecord{Binding: x.binding, Source: reg.SourceRecord{SourceID: "original-owner", RecordID: "original-kek", RecordVersion: "r1", ContentSHA256: hash(bindingRaw)}, Revision: "r1", NotBefore: x.now.Add(-time.Hour), Until: x.now.Add(time.Hour)}
	x.cap = a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: x.binding, Operation: kms.Unwrap, Permission: a.ProviderCapabilityPermission{Path: "transit/decrypt/" + x.binding.Provider.KeyName, ProviderVersion: x.binding.Key.ProviderVersion, AuthMount: "recovery-jwt", Role: "recovery-role", Policy: "recovery-policy", PolicySHA256: strings.Repeat("a", 64), RoleSHA256: strings.Repeat("b", 64), JWTTrustSHA256: strings.Repeat("c", 64), Reference: x.binding.UnwrapRef}}, Source: reg.SourceRecord{SourceID: "independent-permission-owner", RecordID: "sev_recovery_cap_DATA", RecordVersion: "r1"}, Revision: "r1", NotBefore: x.now.Add(-time.Minute), Until: x.now.Add(time.Hour)}
	registry := publicationFailureDomainRegistry{Version: "system-backup-original-failure-domains.v1", Installation: x.binding.InstallationID, Revision: "r1", History: []publicationFailureDomainEvent{{Sequence: 1, Domain: "source", IdentitySHA256: hash([]byte("named source physical DATA")), State: "active"}, {Sequence: 2, Domain: "target", IdentitySHA256: hash([]byte("named target physical DATA")), State: "active"}}}
	first, _ := ce.Canonical(registry.History[0])
	registry.History[1].PreviousSHA256 = hash(first)
	registryRaw, _ := ce.Canonical(registry)
	target := PublicationTargetMaterials{ReadIdentityHash: hash([]byte("named read identity DATA")), ReadRefVersion: "r1", WriteIdentityHash: hash([]byte("named write identity DATA")), WriteRefVersion: "r1", CAIdentityHash: hash([]byte("named CA identity DATA")), CARefVersion: "r1"}
	original := publicationOriginalFixtureConfig(t, target, nil)
	var config map[string]json.RawMessage
	json.Unmarshal(original, &config)
	var refs []security.BootstrapSecretRef
	json.Unmarshal(config["references"], &refs)
	for i, r := range refs {
		if r.Purpose == "kek" {
			refs[i].IdentityHash = x.binding.ConfigRef.IdentityHash
			refs[i].Version = x.binding.ConfigRef.Version
		}
	}
	config["references"], _ = ce.Canonical(refs)
	var pins []security.BootstrapRegistryRef
	json.Unmarshal(config["registries"], &pins)
	for i, p := range pins {
		if p.Kind == "failure_domains" {
			pins[i].Version = registry.Revision
			pins[i].SHA256 = hash(registryRaw)
		}
	}
	config["registries"], _ = ce.Canonical(pins)
	x.config, _ = ce.Canonical(config)
	if _, err := security.DecodeConfigValues(x.config); err != nil {
		t.Fatal("complete original config DATA", err)
	}
	pin := ce.RegistryPin{Version: registry.Revision, SHA256: hash(registryRaw)}
	x.statement = publicationFailureDomainAttestation{Version: "system-backup-original-failure-domain-attestation.v1", ID: "sev_attestation_DATA", Installation: x.binding.InstallationID, ConfigSHA256: hash(x.config), Registry: pin, TargetDomain: "target", TargetSHA256: x.target, SourceDomains: []string{"source"}, Dependencies: []publicationRecoveryDependency{}, Actor: "administrator-DATA", AuditID: "audit-DATA", Issued: x.now.Add(-time.Minute), Expires: x.now.Add(time.Hour)}
	for _, r := range refs {
		x.statement.Dependencies = append(x.statement.Dependencies, publicationRecoveryDependency{Purpose: r.Purpose, IdentitySHA256: r.IdentityHash, Version: r.Version, Domain: "target"})
	}
	x.trust = &PublicationRecoveryTrust{AttestationIssuer: x.attKey.Public().(ed25519.PublicKey), Capability: a.ProviderCapabilityPin{Issuer: x.capKey.Public().(ed25519.PublicKey)}, FailureDomainRegistry: registryRaw, SourceDomains: []string{"source"}}
	x.policy.Policy = originalPublicationPolicy{Version: originalPublicationPolicyVersion, Installation: x.binding.InstallationID, ConfigSHA256: hash(x.config), FailureDomains: pin, Target: publicationManifestTarget{Class: "dr-ready-external", Domain: "target", Risks: []string{}}, RecoveryEvidenceStatus: "provided"}
	return x
}

func (x *publicationRecoveryData) signed(t *testing.T) ([]byte, []byte, publicationCurrentEvidence, publicationCurrentEvidence) {
	t.Helper()
	owner, _ := json.Marshal(x.owner)
	sig := ed25519.Sign(x.ownerKey, append([]byte("system-backup-original-kek.v1\x00"), owner...))
	facts, _ := json.Marshal(x.cap.Facts)
	x.cap.Source.ContentSHA256 = hash(facts)
	x.trust.Capability.Source = x.cap.Source
	capRecord, _ := json.Marshal(x.cap)
	capRaw, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: capRecord, Signature: ed25519.Sign(x.capKey, append([]byte(a.ProviderCapabilityDomain), capRecord...))})
	x.statement.OwnerRecordSHA256 = hash(owner)
	x.statement.CapabilitySHA256 = hash(capRaw)
	statement, _ := ce.Canonical(x.statement)
	attRaw, _ := ce.Canonical(publicationSignedAttestation{Payload: statement, Signature: ed25519.Sign(x.attKey, append([]byte(publicationAttestationDomain), statement...))})
	sel := publicationRecoverySelection{Attestation: publicationEvidencePin{ID: x.statement.ID, SHA256: hash(attRaw)}, Capability: publicationEvidencePin{ID: x.cap.Source.RecordID, SHA256: hash(capRaw)}, OwnerRecordSHA256: hash(owner), OwnerRevision: x.owner.Revision}
	x.trust.Selection = sel
	x.policy.Policy.RecoveryEvidence = &sel
	id, sha := sel.Attestation.ID, sel.Attestation.SHA256
	x.policy.Policy.Target.AttestationID = &id
	x.policy.Policy.Target.AttestationSHA256 = &sha
	p, _ := ce.Canonical(x.policy.Policy)
	x.policy.SHA256 = hash(p)
	return owner, sig, publicationCurrentEvidence{Raw: attRaw, Expires: x.now.Add(time.Hour)}, publicationCurrentEvidence{Raw: capRaw, Expires: x.now.Add(time.Hour)}
}

func TestPublicationRecoveryRequiresIndependentCurrentOriginalEvidence(t *testing.T) {
	for _, mode := range []string{"current", "missing-attestation", "missing-trust", "wrong-issuer", "signature", "scope", "expired-attestation", "revoked-attestation", "expired-row", "missing-dependency", "wrong-reference", "source-dependent", "owner-revoked", "owner-expired", "capability-revoked", "capability-expired", "controller-workload", "wrong-key", "wrong-capability-source", "target-drift", "policy-selects-own-evidence"} {
		t.Run(mode, func(t *testing.T) {
			x := newPublicationRecoveryData(t)
			switch mode {
			case "scope":
				x.statement.Installation = "installation_other"
			case "expired-attestation":
				x.statement.Expires = x.now
			case "revoked-attestation":
				x.statement.Revoked = true
			case "missing-dependency":
				x.statement.Dependencies = x.statement.Dependencies[1:]
			case "wrong-reference":
				x.statement.Dependencies[0].Version = "different"
			case "source-dependent":
				x.statement.Dependencies[0].Domain = "source"
			case "owner-revoked":
				x.owner.UnwrapRevoked = true
			case "owner-expired":
				x.owner.Until = x.now
			case "capability-revoked":
				x.cap.Revoked = true
			case "capability-expired":
				x.cap.Until = x.now
			case "controller-workload":
				x.cap.Facts.Permission.ControllerVerifier = &a.ControllerVerifierWorkload{}
			case "wrong-key":
				x.cap.Facts.Binding.Key.ProviderVersion = "different"
			}
			owner, sig, att, cap := x.signed(t)
			switch mode {
			case "missing-attestation":
				att.Raw = nil
			case "missing-trust":
				x.trust = nil
			case "wrong-issuer":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				x.trust.AttestationIssuer = pub
			case "signature":
				sig[0] ^= 1
			case "expired-row":
				cap.Expires = x.now
			case "wrong-capability-source":
				x.trust.Capability.Source.RecordVersion = "other"
			case "target-drift":
				x.target = hash([]byte("other target"))
			case "policy-selects-own-evidence":
				sel := *x.policy.Policy.RecoveryEvidence
				sel.OwnerRevision = "self-selected"
				x.policy.Policy.RecoveryEvidence = &sel
				p, _ := ce.Canonical(x.policy.Policy)
				x.policy.SHA256 = hash(p)
			}
			got, err := verifyPublicationRecoveryEvidence(x.config, x.policy, x.trust, x.binding, x.ownerKey.Public().(ed25519.PublicKey), owner, sig, att, cap, x.target, x.now)
			if mode == "current" {
				if err != nil || !got.KEK.SourceIndependent || got.KEK.RecoveryProof == nil || got.Target.AttestationID == nil || got.evidenceSHA256 == "" {
					t.Fatal("independent original evidence DATA rejected", err)
				}
				return
			}
			if err == nil || got.evidenceSHA256 != "" {
				t.Fatal("invalid original evidence accepted", mode)
			}
		})
	}
}

func TestPublicationFailureDomainHistoryRejectsIdentityReuseAndBrokenChain(t *testing.T) {
	for _, mode := range []string{"current", "alias-physical-identity", "broken-chain", "identity-mutation", "inactive-reuse"} {
		t.Run(mode, func(t *testing.T) {
			x := newPublicationRecoveryData(t)
			var r publicationFailureDomainRegistry
			json.Unmarshal(x.trust.FailureDomainRegistry, &r)
			switch mode {
			case "alias-physical-identity":
				r.History[1].IdentitySHA256 = r.History[0].IdentitySHA256
			case "broken-chain":
				r.History[1].PreviousSHA256 = strings.Repeat("0", 64)
			case "identity-mutation":
				r.History[1].Domain = r.History[0].Domain
			case "inactive-reuse":
				e := r.History[0]
				e.Sequence = 3
				e.State = "inactive"
				prev, _ := ce.Canonical(r.History[1])
				e.PreviousSHA256 = hash(prev)
				r.History = append(r.History, e)
				e.Sequence = 4
				e.State = "active"
				prev, _ = ce.Canonical(r.History[2])
				e.PreviousSHA256 = hash(prev)
				r.History = append(r.History, e)
			}
			raw, _ := ce.Canonical(r)
			got, err := publicationDomainIdentities(raw, r.Installation, ce.RegistryPin{Version: r.Revision, SHA256: hash(raw)})
			if mode == "current" {
				if err != nil || len(got) != 2 {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid append-only identity history accepted")
			}
		})
	}
}
