package install

import (
	"crypto/ed25519"
	"regexp"
	"sort"
	"strconv"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const FunctionalClassificationVersion = "system-backup-original-functional-classification.v1"
const FunctionalClassificationDomain = FunctionalClassificationVersion + "\x00"
const FunctionalNonDRProfile = "functional-backup.non-dr.v1"
const FunctionalDisasterMappingVersion = "system-backup-original-disaster-identity-map.v1"

var functionalDomainToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// An explicit ORIGINAL owner classification. It supplies neither provider
// permission nor source-completeness/restore proof. Every other original owner,
// six-domain capture/nonempty scope, actual key permission, writer recovery and
// independent publication/readback/catalog/terminal requirement stays intact.
type FunctionalClassificationDefinition struct {
	SchemaVersion, Profile, TaskPurpose, TargetClass, TargetFailureDomain, RecoveryEvidenceStatus string
	FailureRegistryFile, FailureRegistrySHA256, MappingRegistryFile, MappingRegistrySHA256        string
	SourceDomains                                                                                 []string
	TargetRisks                                                                                   []string
}

type FunctionalFailureDomainEvent struct {
	Sequence       uint64 `json:"sequence"`
	Domain         string `json:"domain_id"`
	IdentitySHA256 string `json:"identity_sha256"`
	State          string `json:"state"`
	PreviousSHA256 string `json:"previous_sha256"`
}

// Same existing failure-domain wire as publication_recovery_evidence.go.
// A functional profile permits ONE actual administrative failure domain. It
// never invents a second domain/identity to satisfy independent-DR validation.
type FunctionalFailureDomainRegistry struct {
	SchemaVersion string                         `json:"schema_version"`
	Installation  string                         `json:"origin_installation_id"`
	Version       string                         `json:"registry_version"`
	History       []FunctionalFailureDomainEvent `json:"history"`
}

type FunctionalDisasterIdentityEntry struct {
	Purpose, IdentityHash, ReferenceVersion, State, Reason string
}

// Unavailable is affirmative signed metadata, not an available disaster
// identity. There is no alternate credential/ref field to guess or use.
type FunctionalDisasterIdentityRegistry struct {
	SchemaVersion, Profile, Installation, Version, State string
	Entries                                              []FunctionalDisasterIdentityEntry
}

type FunctionalClassificationRecord struct {
	SchemaVersion, Profile, TaskPurpose, TargetClass, TargetFailureDomain, RecoveryEvidenceStatus string
	PlanSHA256, CaptureRecordSHA256, DefinitionSHA256                                             string
	Target                                                                                        owner.Target
	Actor                                                                                         owner.Actor
	Enrollment                                                                                    EnrollmentPin
	NotBefore, Until                                                                              time.Time
	FailureDomains, DisasterMapping                                                               sec.BootstrapRegistryRef
	SourceDomains, TargetRisks                                                                    []string
	Selection                                                                                     pd.BootstrapConsumptionRequest
	PublicationPolicySHA256                                                                       string
}

type SignedFunctionalClassification struct {
	Record, Signature, PublicationPolicy []byte
}

func classificationPins(config sec.BootstrapConfig) (sec.BootstrapRegistryRef, sec.BootstrapRegistryRef, error) {
	var failure, mapping sec.BootstrapRegistryRef
	for _, pin := range config.Registries() {
		switch pin.Kind {
		case "failure_domains":
			failure = pin
		case "disaster_identity_mapping":
			mapping = pin
		}
	}
	if failure.Kind == "" || mapping.Kind == "" {
		return failure, mapping, ErrInstall
	}
	return failure, mapping, nil
}

func validateFunctionalDefinition(d FunctionalClassificationDefinition) error {
	if d.SchemaVersion != FunctionalClassificationVersion || d.Profile != FunctionalNonDRProfile || d.TaskPurpose != "functional_test" || d.TargetClass != "same-cluster-copy" || d.RecoveryEvidenceStatus != "not_provided" || !functionalDomainToken.MatchString(d.TargetFailureDomain) || len(d.SourceDomains) == 0 || len(d.SourceDomains) > 64 || len(d.TargetRisks) < 2 {
		return ErrInstall
	}
	previous, includesTarget := "", false
	for _, domain := range d.SourceDomains {
		if !functionalDomainToken.MatchString(domain) || domain <= previous {
			return ErrInstall
		}
		includesTarget = includesTarget || domain == d.TargetFailureDomain
		previous = domain
	}
	if !includesTarget {
		return ErrInstall
	}
	// These are conservative source-dependence classifications only. Missing
	// transport/conditional-commit/provider capabilities are still hard failures
	// in their real owners; this profile cannot relabel them as harmless DR risk.
	allowed := map[string]bool{"attestation_missing": true, "same_failure_domain": true, "source_overlap": true, "artifact_credential_source_dependent": true, "kek_source_dependent": true, "signing_key_source_dependent": true, "catalog_source_dependent": true}
	seen := map[string]bool{}
	previous = ""
	for _, risk := range d.TargetRisks {
		if !allowed[risk] || risk <= previous {
			return ErrInstall
		}
		seen[risk], previous = true, risk
	}
	if !seen["attestation_missing"] || !seen["same_failure_domain"] {
		return ErrInstall
	}
	return nil
}

func validateFunctionalRegistries(d FunctionalClassificationDefinition, installation string, config sec.BootstrapConfig, failureRaw, mappingRaw []byte) error {
	if validateFunctionalDefinition(d) != nil {
		return ErrInstall
	}
	failurePin, mappingPin, err := classificationPins(config)
	if err != nil || hash(failureRaw) != failurePin.SHA256 || hash(mappingRaw) != mappingPin.SHA256 || d.FailureRegistrySHA256 != failurePin.SHA256 || d.MappingRegistrySHA256 != mappingPin.SHA256 || len(failureRaw) > 65536 || len(mappingRaw) > 65536 {
		return ErrInstall
	}
	var failure FunctionalFailureDomainRegistry
	if decodeExact(failureRaw, &failure) != nil || failure.SchemaVersion != "system-backup-original-failure-domains.v1" || failure.Installation != installation || failure.Version != failurePin.Version || len(failure.History) < 1 || len(failure.History) > 256 {
		return ErrInstall
	}
	identities, assigned, inactive := map[string]string{}, map[string]string{}, map[string]bool{}
	previous := ""
	for n, event := range failure.History {
		if event.Sequence != uint64(n+1) || !functionalDomainToken.MatchString(event.Domain) || !digestPattern.MatchString(event.IdentitySHA256) || event.State != "active" && event.State != "inactive" || event.PreviousSHA256 != previous || inactive[event.Domain] {
			return ErrInstall
		}
		old, exists := identities[event.Domain]
		if exists && (old != event.IdentitySHA256 || event.State != "inactive") || !exists && event.State != "active" || assigned[event.IdentitySHA256] != "" && assigned[event.IdentitySHA256] != event.Domain {
			return ErrInstall
		}
		identities[event.Domain], assigned[event.IdentitySHA256], inactive[event.Domain] = event.IdentitySHA256, event.Domain, event.State == "inactive"
		raw, err := canonical(event)
		if err != nil {
			return ErrInstall
		}
		previous = hash(raw)
	}
	for _, domain := range d.SourceDomains {
		if identities[domain] == "" || inactive[domain] {
			return ErrInstall
		}
	}
	var mapping FunctionalDisasterIdentityRegistry
	if decodeExact(mappingRaw, &mapping) != nil || mapping.SchemaVersion != FunctionalDisasterMappingVersion || mapping.Profile != FunctionalNonDRProfile || mapping.Installation != installation || mapping.Version != mappingPin.Version || mapping.State != "unavailable" {
		return ErrInstall
	}
	refs := config.References()
	sort.Slice(refs, func(a, b int) bool { return refs[a].Purpose < refs[b].Purpose })
	if len(mapping.Entries) != len(refs) || len(refs) != 20 {
		return ErrInstall
	}
	for n, entry := range mapping.Entries {
		ref := refs[n]
		if entry.Purpose != ref.Purpose || entry.IdentityHash != ref.IdentityHash || entry.ReferenceVersion != ref.Version || entry.State != "unavailable" || entry.Reason != "not_provided" && entry.Reason != "not_provisioned" && entry.Reason != "source_dependent" && entry.Reason != "not_independently_observed" {
			return ErrInstall
		}
	}
	return nil
}

func functionalSelectionMatches(record owner.Record, request pd.BootstrapConsumptionRequest) bool {
	selection, err := pd.BootstrapConsumptionHash(request)
	return err == nil && string(selection) == record.SelectionSHA256 && request.Scope == (pd.Scope{ServerUUID: pd.ServerUUID(record.Target.ServerUUID), Database: pd.Database(record.Target.Database), Installation: pd.Installation(record.Target.InstallationID)}) && request.ActorID == pd.Counter(strconv.FormatInt(record.Actor.UserID, 10)) && request.Username == record.Actor.Username && request.MatrixKey == record.MatrixKey && request.Endpoint == record.Endpoint && request.IdempotencyKey == record.IdempotencyKey && string(request.OfflineGrantHash) == record.GrantSHA256 && string(request.ConfigHash) == record.ConfigSHA256 && string(request.RegistrySetHash) == record.RegistrySetSHA256 && string(request.RefSetHash) == record.ReferenceSetSHA256
}

// Exact existing originalPublicationPolicy wire. Null attestation pins and
// not_provided stay explicit. This cannot produce a positive DR qualification.
type functionalPolicyRegistryPin struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
type functionalPolicyTarget struct {
	Class             string   `json:"target_class"`
	Domain            string   `json:"failure_domain_id"`
	Risks             []string `json:"risks"`
	AttestationID     *string  `json:"attestation_id"`
	AttestationSHA256 *string  `json:"attestation_hash"`
}
type functionalPolicyWire struct {
	Version        string                      `json:"schema_version"`
	Installation   string                      `json:"origin_installation_id"`
	ConfigSHA256   string                      `json:"original_config_sha256"`
	FailureDomains functionalPolicyRegistryPin `json:"original_failure_domains_registry"`
	Target         functionalPolicyTarget      `json:"target"`
	Status         string                      `json:"recovery_evidence_status"`
}

func functionalPublicationPolicy(record FunctionalClassificationRecord) ([]byte, error) {
	return canonical(functionalPolicyWire{Version: "system-backup-original-publication-policy.v1", Installation: record.Target.InstallationID, ConfigSHA256: string(record.Selection.ConfigHash), FailureDomains: functionalPolicyRegistryPin{Version: record.FailureDomains.Version, SHA256: record.FailureDomains.SHA256}, Target: functionalPolicyTarget{Class: record.TargetClass, Domain: record.TargetFailureDomain, Risks: append([]string(nil), record.TargetRisks...)}, Status: record.RecoveryEvidenceStatus})
}

func verifyFunctionalClassification(raw, signature []byte, public ed25519.PublicKey) (FunctionalClassificationRecord, error) {
	var record FunctionalClassificationRecord
	if len(raw) == 0 || len(raw) > 262144 || len(signature) != 64 || len(public) != 32 || !ed25519.Verify(public, append([]byte(FunctionalClassificationDomain), raw...), signature) || decodeExact(raw, &record) != nil || record.SchemaVersion != FunctionalClassificationVersion || !record.NotBefore.Before(record.Until) || record.Until.Sub(record.NotBefore) > 24*time.Hour {
		return record, ErrInstall
	}
	d := FunctionalClassificationDefinition{SchemaVersion: record.SchemaVersion, Profile: record.Profile, TaskPurpose: record.TaskPurpose, TargetClass: record.TargetClass, TargetFailureDomain: record.TargetFailureDomain, RecoveryEvidenceStatus: record.RecoveryEvidenceStatus, SourceDomains: record.SourceDomains, TargetRisks: record.TargetRisks}
	if validateFunctionalDefinition(d) != nil {
		return record, ErrInstall
	}
	for _, digest := range []string{record.PlanSHA256, record.CaptureRecordSHA256, record.DefinitionSHA256, record.PublicationPolicySHA256} {
		if !digestPattern.MatchString(digest) {
			return record, ErrInstall
		}
	}
	policy, err := functionalPublicationPolicy(record)
	if err != nil || hash(policy) != record.PublicationPolicySHA256 {
		return record, ErrInstall
	}
	return record, nil
}
