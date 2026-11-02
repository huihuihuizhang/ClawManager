package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"

	pd "clawreef/internal/systembackupproducer"
)

// IssueFunctionalClassification is a separate explicit ORIGINAL owner action.
// It authenticates actual password/admin, Kubernetes enrollment/subject and
// exact currently committed original capture scope. Capture's signing grant
// is NOT interpreted as a classification: this distinct record/domain selects
// real registry bytes and expressly declines DR/restore availability claims.
func (i *Installer) IssueFunctionalClassification(ctx context.Context, password []byte, enrollment EnrollmentPin, bundleRaw []byte, bundleSHA, definitionFile, definitionSHA string, selection pd.BootstrapConsumptionRequest, files RequestFiles, issuerPrivate []byte) (SignedFunctionalClassification, error) {
	var zero SignedFunctionalClassification
	bundleRaw = bytes.Clone(bundleRaw)
	selectionRaw, err := json.Marshal(selection)
	var frozen pd.BootstrapConsumptionRequest
	if err != nil || len(selectionRaw) > 262144 || json.Unmarshal(selectionRaw, &frozen) != nil {
		return zero, ErrInstall
	}
	selection = frozen
	s, err := i.authenticate(ctx, password)
	if err != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	b, r, _, err := s.decodeBundle(bundleRaw, bundleSHA, enrollment)
	if err != nil || b.SchemaVersion != AuthorityBundleVersion || !functionalSelectionMatches(r, selection) {
		return zero, ErrInstall
	}
	raw, err := ReadPrivateFile(definitionFile, 262144)
	var d FunctionalClassificationDefinition
	if err != nil || !digestPattern.MatchString(definitionSHA) || hash(raw) != definitionSHA || decodeExact(raw, &d) != nil || validateFunctionalDefinition(d) != nil {
		return zero, ErrInstall
	}
	request, err := readConsumerCaptureRequest(i, files)
	if err != nil {
		return zero, ErrInstall
	}
	defer request.observer.Close()
	if !request.matchesDraft(r) {
		return zero, ErrInstall
	}
	failureRaw, err := ReadPrivateFile(d.FailureRegistryFile, 65536)
	if err != nil {
		return zero, ErrInstall
	}
	mappingRaw, err := ReadPrivateFile(d.MappingRegistryFile, 65536)
	if err != nil || validateFunctionalRegistries(d, r.Target.InstallationID, request.config, failureRaw, mappingRaw) != nil {
		return zero, ErrInstall
	}
	before, now, err := snapshot(ctx, s)
	if err != nil || !exactCommitted(before, b) || now.Before(r.NotBefore) || !now.Before(r.Until) {
		return zero, ErrInstall
	}
	failure, mapping, err := classificationPins(request.config)
	if err != nil {
		return zero, ErrInstall
	}
	classified := FunctionalClassificationRecord{SchemaVersion: FunctionalClassificationVersion, Profile: FunctionalNonDRProfile, TaskPurpose: d.TaskPurpose, TargetClass: d.TargetClass, TargetFailureDomain: d.TargetFailureDomain, RecoveryEvidenceStatus: d.RecoveryEvidenceStatus, PlanSHA256: i.planHash, CaptureRecordSHA256: hash(b.Record), DefinitionSHA256: definitionSHA, Target: r.Target, Actor: r.Actor, Enrollment: enrollment, NotBefore: r.NotBefore, Until: r.Until, FailureDomains: failure, DisasterMapping: mapping, SourceDomains: append([]string(nil), d.SourceDomains...), TargetRisks: append([]string(nil), d.TargetRisks...), Selection: selection}
	policy, err := functionalPublicationPolicy(classified)
	if err != nil {
		return zero, ErrInstall
	}
	classified.PublicationPolicySHA256 = hash(policy)
	encoded, err := canonical(classified)
	if err != nil || len(encoded) > 262144 {
		return zero, ErrInstall
	}
	key, err := s.privateKey(issuerPrivate)
	if err != nil {
		return zero, err
	}
	defer clear(key)
	// This distinct signature is frozen with NO SQL locks held. It declares
	// unavailable DR identities, not provider/readiness or a task permission.
	signature := ed25519.Sign(key, append([]byte(FunctionalClassificationDomain), encoded...))
	for _, pin := range []consumerPinnedFile{{definitionFile, definitionSHA, 262144}, {d.FailureRegistryFile, d.FailureRegistrySHA256, 65536}, {d.MappingRegistryFile, d.MappingRegistrySHA256, 65536}, {files.ConfigFile, files.ConfigFileSHA256, 262144}, {files.GrantFile, files.GrantFileSHA256, 16384}, {files.ObserverFile, files.ObserverFileSHA256, 262144}} {
		actual, err := ReadPrivateFile(pin.path, pin.limit)
		if err != nil || hash(actual) != pin.sha {
			return zero, ErrInstall
		}
	}
	if s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	after, now, err := snapshot(ctx, s)
	if err != nil || after.cas != before.cas || !exactCommitted(after, b) || now.Before(r.NotBefore) || !now.Before(r.Until) || !s.live(ctx) {
		return zero, ErrInstall
	}
	return SignedFunctionalClassification{Record: encoded, Signature: signature, PublicationPolicy: policy}, nil
}

// Inert transport only. Consumer verifies independently enrolled issuer/pin,
// exact current original SQL and both complete registries; files create no
// consumer trust or positive DR qualification and are never overwritten.
func SaveFrozenFunctionalClassification(directory string, signed SignedFunctionalClassification) error {
	var record FunctionalClassificationRecord
	if len(signed.Record) == 0 || len(signed.Record) > 262144 || len(signed.Signature) != 64 || decodeExact(signed.Record, &record) != nil || record.SchemaVersion != FunctionalClassificationVersion || hash(signed.PublicationPolicy) != record.PublicationPolicySHA256 {
		return ErrInstall
	}
	policy, err := functionalPublicationPolicy(record)
	if err != nil || !bytes.Equal(policy, signed.PublicationPolicy) {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{"functional-classification.record.json": bytes.Clone(signed.Record), "functional-classification.signature": bytes.Clone(signed.Signature), "functional-classification.sha256": []byte(hash(signed.Record)), "functional-publication-policy.json": bytes.Clone(policy), "functional-publication-policy.sha256": []byte(hash(policy))})
}
