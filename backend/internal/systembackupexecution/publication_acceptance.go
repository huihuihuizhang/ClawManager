package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	security "clawreef/internal/systembackupsecurity"
)

// Exact public-v12 payload. In particular no legacy identity/config_snapshot,
// millisecond timestamp, installation field or caller eligibility flag enters.
type publicationAcceptancePayload struct {
	Version        string                         `json:"schema_version"`
	Backup         string                         `json:"backup_public_id"`
	Attempt        uint64                         `json:"attempt_no"`
	ManifestSHA256 string                         `json:"manifest_checksum"`
	MarkerSHA256   string                         `json:"marker_checksum"`
	CleanupID      string                         `json:"staging_cleanup_evidence_id"`
	CleanupSHA256  string                         `json:"staging_cleanup_evidence_hash"`
	Accepted       bool                           `json:"local_acceptance"`
	Reasons        []string                       `json:"local_reason_codes"`
	ReasonsSHA256  string                         `json:"local_reason_codes_hash"`
	DecisionAt     string                         `json:"decision_at"`
	ConfigVersion  uint64                         `json:"config_version"`
	Key            security.PublicationSigningKey `json:"signing_key"`
}

func decodePublicationAcceptancePayload(raw []byte) (publicationAcceptancePayload, error) {
	var p publicationAcceptancePayload
	if len(raw) < 2 || len(raw) > 8192 || decodePublicationCanonical(raw, &p) != nil || p.Version != "system-backup-acceptance.v1" || !regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`).MatchString(p.Backup) || !manifestBound(p.Backup, 128) || p.Attempt < 1 || p.Attempt > 9007199254740991 || p.ConfigVersion < 1 || p.ConfigVersion > 9007199254740991 || !regexp.MustCompile(`^sev_[A-Za-z0-9_-]+$`).MatchString(p.CleanupID) || !manifestBound(p.CleanupID, 128) || p.Key.Purpose != "acceptance_record" || !manifestBound(p.Key.KeyID, 256) || !manifestBound(p.Key.KeyVersion, 128) {
		return publicationAcceptancePayload{}, c.ErrExecutionRecord
	}
	for _, sha := range []string{p.ManifestSHA256, p.MarkerSHA256, p.CleanupSHA256, p.ReasonsSHA256} {
		if !formalCandidateDigest(sha) {
			return publicationAcceptancePayload{}, c.ErrExecutionRecord
		}
	}
	at, err := time.Parse(time.RFC3339Nano, p.DecisionAt)
	if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != p.DecisionAt || len(p.Reasons) < 1 || len(p.Reasons) > 7 {
		return publicationAcceptancePayload{}, c.ErrExecutionRecord
	}
	allowed := map[string]bool{"eligible": true, "functional_test": true, "consistency_not_strong": true, "disqualifying_warning": true, "target_not_external": true, "target_risk": true, "attestation_invalid": true, "kek_not_recoverable": true}
	last := ""
	for _, reason := range p.Reasons {
		if !allowed[reason] || reason <= last || (!p.Accepted && reason == "eligible") {
			return publicationAcceptancePayload{}, c.ErrExecutionRecord
		}
		last = reason
	}
	if p.Accepted && (len(p.Reasons) != 1 || p.Reasons[0] != "eligible") {
		return publicationAcceptancePayload{}, c.ErrExecutionRecord
	}
	reasons, err := ce.Canonical(p.Reasons)
	if err != nil || hash(reasons) != p.ReasonsSHA256 {
		return publicationAcceptancePayload{}, c.ErrExecutionRecord
	}
	return p, nil
}

// Comparison only: the caller must obtain these facts from the registry's
// validated read in the SAME fence-locked transaction, never from a DTO.
func validateAcceptanceCurrentKEKBinding(facts reg.BindingFacts, expected reg.Binding) error {
	fingerprint, err := reg.BindingFingerprint(facts.Binding)
	if err != nil || facts.RowVersion < 1 || fingerprint != facts.BindingSHA256 || facts.Binding.InstallationID != expected.InstallationID || facts.Binding.ConfigRef != expected.ConfigRef || !reg.SameSecurityBinding(facts.Binding, expected) || facts.UnwrapRevoked != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}

// ReadBindingTx validates the persisted exact core/hash/RV/revocations in this
// original transaction and takes only existing shared locks. It must not be
// replaced with SQLStore.Bind, which has an INSERT even in a read-only tail.
func acceptanceCurrentKEKBindingTx(ctx context.Context, tx *sql.Tx, expected reg.Binding) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || expected.InstallationID == "" {
		return c.ErrExecutionAuthority
	}
	facts, err := (&reg.SQLStore{}).ReadBindingTx(ctx, tx, expected.InstallationID, expected.ConfigRef)
	if err != nil {
		return c.ErrExecutionAuthority
	}
	return validateAcceptanceCurrentKEKBinding(facts, expected)
}

// A signed positive payload is produced only from actual current recovery
// evidence; manifest precommit flags alone cannot make a target independent.
// This joins the SAME publishing transaction, without changing the old
// validating-only manifest-preparation helper or any A authorization API.
func acceptanceRecoveryFactsTx(ctx context.Context, tx *sql.Tx, proof *publicationFinalVerification) (publicationRecoveryFacts, time.Time, error) {
	var zero publicationRecoveryFacts
	if proof == nil || proof.service == nil || proof.service.publisherVerifier == nil || proof.cleanup == nil || !proof.cleanup.ready() {
		return zero, time.Time{}, c.ErrExecutionAuthority
	}
	if err := proof.recheckVerifiedTx(ctx, tx); err != nil {
		return zero, time.Time{}, err
	}
	s := proof.service
	capture := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	if capture.SourceFacts.PublicationPolicy == nil {
		return zero, time.Time{}, c.ErrExecutionRecord
	}
	policy := *capture.SourceFacts.PublicationPolicy
	trust := s.publisherVerifier.RecoveryTrust
	if policy.validate() != nil || policy.Policy.Installation != capture.Input.InstallationID || policy.Policy.ConfigSHA256 != capture.Input.ConfigSHA256 {
		return zero, time.Time{}, c.ErrExecutionRecord
	}
	var now time.Time
	var epoch uint64
	if tx.QueryRowContext(ctx, `SELECT epoch,UTC_TIMESTAMP(6) FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, s.Config.InstallationID).Scan(&epoch, &now) != nil {
		return zero, time.Time{}, c.ErrExecutionAuthority
	}
	binding := s.publisherVerifier.Binding
	if binding.InstallationID != s.Config.InstallationID || acceptanceCurrentKEKBindingTx(ctx, tx, binding) != nil {
		return zero, time.Time{}, c.ErrExecutionAuthority
	}
	currentOwner, err := a.ReadCurrentOriginalUnwrapTx(ctx, tx, binding, s.publisherVerifier.InstallationIssuer, now)
	if err != nil {
		return zero, time.Time{}, err
	}
	if currentOwner.GenerateRevoked {
		return zero, time.Time{}, c.ErrExecutionAuthority
	}
	if policy.Policy.RecoveryEvidenceStatus == "not_provided" {
		if capture.Input.Backup.TaskPurpose != "functional_test" {
			return zero, time.Time{}, c.ErrExecutionRecord
		}
		zero.Target = policy.Policy.Target
		zero.KEK = publicationManifestKEK{Provider: binding.Key.Provider, KeyID: binding.Key.ProviderKeyID, KeyVersion: binding.Key.ProviderVersion}
		raw, err := ce.Canonical(struct{ Policy, Target, Capture string }{policy.SHA256, publicationRecoveryTargetSHA(proof.target), capture.receipt.sha256})
		if err != nil {
			return zero, time.Time{}, err
		}
		zero.evidenceSHA256, zero.captureSHA256, zero.targetSHA256 = hash(raw), capture.receipt.sha256, publicationRecoveryTargetSHA(proof.target)
		zero.until = proof.access.ValidUntil()
		if currentOwner.Until.Before(zero.until) {
			zero.until = currentOwner.Until
		}
		return zero, now, nil
	}
	if policy.Policy.RecoveryEvidenceStatus != "provided" || trust == nil || trust.validate() != nil {
		return zero, time.Time{}, c.ErrExecutionRecord
	}
	owner, sig, err := (a.SQLOriginalReader{}).RecheckOriginal(ctx, tx, s.Config.InstallationID, binding.ConfigRef)
	if err != nil {
		return zero, time.Time{}, err
	}
	att, err := readPublicationRecoveryEvidence(ctx, tx, s.Config.InstallationID, "failure_domain_attestation", trust.Selection.Attestation)
	if err != nil {
		return zero, time.Time{}, err
	}
	capability, err := readPublicationRecoveryEvidence(ctx, tx, s.Config.InstallationID, "capability_snapshot", trust.Selection.Capability)
	if err != nil {
		return zero, time.Time{}, err
	}
	facts, err := verifyPublicationRecoveryEvidence(capture.Input.ConfigSnapshot, policy, trust, binding, s.publisherVerifier.InstallationIssuer, owner, sig, att, capability, publicationRecoveryTargetSHA(proof.target), now)
	if err != nil {
		return zero, time.Time{}, err
	}
	if proof.access.ValidUntil().Before(facts.until) {
		facts.until = proof.access.ValidUntil()
	}
	facts.captureSHA256 = capture.receipt.sha256
	facts.targetSHA256 = publicationRecoveryTargetSHA(proof.target)
	return facts, now, nil
}

// Qualification is derived only after the full common publication proof. The
// ordinary purpose changes DR classification, never the required data scope.
func publicationManifestEvaluation(m publicationManifestV12) (bool, []string, error) {
	if m.validate() != nil || m.Consistency != "strong" || len(m.Parts) != 6 || !m.Eligibility.PartsComplete || !m.Eligibility.VerifiersComplete {
		return false, nil, c.ErrExecutionRecord
	}
	for _, name := range publicationRequestedParts {
		p, ok := m.Parts[name]
		if !ok || !p.Required || p.Status != "completed" || p.Consistency != "strong" {
			return false, nil, c.ErrExecutionRecord
		}
	}
	for _, warning := range m.Warnings {
		if warning.Disqualifying {
			return false, nil, c.ErrExecutionRecord
		}
	}
	reasons := []string{}
	if m.Purpose == "functional_test" {
		reasons = append(reasons, "functional_test")
	}
	if m.Target.Class != "dr-ready-external" {
		reasons = append(reasons, "target_not_external")
	}
	if len(m.Target.Risks) != 0 {
		reasons = append(reasons, "target_risk")
	}
	if m.Target.AttestationID == nil {
		reasons = append(reasons, "attestation_invalid")
	}
	if !m.KEK.SourceIndependent || m.KEK.RecoveryProof == nil {
		reasons = append(reasons, "kek_not_recoverable")
	}
	sort.Strings(reasons)
	original := append([]string{}, m.Eligibility.Disqualifiers...)
	sort.Strings(original)
	if !reflect.DeepEqual(reasons, original) || m.Purpose == "acceptance" && len(reasons) != 0 {
		return false, nil, c.ErrExecutionRecord
	}
	if len(reasons) == 0 {
		return true, []string{"eligible"}, nil
	}
	return false, reasons, nil
}

func publicationOriginalEvaluation(proof *publicationFinalVerification) (bool, []string, error) {
	if proof == nil || !proof.cleanup.ready() || !formalCandidateDigest(proof.verifiedSHA256) {
		return false, nil, c.ErrExecutionAuthority
	}
	m, err := decodePublicationManifestV12(proof.manifest)
	if err != nil {
		return false, nil, err
	}
	capture := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	if !capture.checked() || m.Purpose != capture.Input.Backup.TaskPurpose {
		return false, nil, c.ErrExecutionRecord
	}
	return publicationManifestEvaluation(m)
}

func validateAcceptanceBusinessPayload(raw []byte, proof *publicationFinalVerification, recovery publicationRecoveryFacts, now time.Time) error {
	if proof == nil || !proof.cleanup.ready() || !formalCandidateDigest(proof.verifiedSHA256) || now.IsZero() || !now.Before(recovery.until) {
		return c.ErrExecutionAuthority
	}
	p, err := decodePublicationAcceptancePayload(raw)
	if err != nil {
		return err
	}
	capture := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	m, err := decodePublicationManifestV12(proof.manifest)
	if err != nil || !capture.checked() || recovery.captureSHA256 != capture.receipt.sha256 || recovery.targetSHA256 != publicationRecoveryTargetSHA(proof.target) || !reflect.DeepEqual(m.Target, recovery.Target) || !reflect.DeepEqual(m.KEK, recovery.KEK) {
		return c.ErrExecutionRecord
	}
	eligible, reasons, err := publicationOriginalEvaluation(proof)
	if err != nil || p.Accepted != eligible || !reflect.DeepEqual(p.Reasons, reasons) {
		return c.ErrExecutionRecord
	}
	for _, warning := range m.Warnings {
		if warning.Disqualifying {
			return c.ErrExecutionRecord
		}
	}
	decision, _ := time.Parse(time.RFC3339Nano, p.DecisionAt)
	if p.Backup != proof.claim.Target.PublicID || p.Attempt != proof.attempt || p.ConfigVersion != capture.Input.ConfigVersion || p.ManifestSHA256 != proof.manifestObject.SHA256 || p.MarkerSHA256 != proof.markerObject.SHA256 || p.CleanupID != proof.cleanup.evidence.PublicID || p.CleanupSHA256 != proof.cleanup.evidence.SHA256 || decision.After(now) || decision.Before(m.Generated) {
		return c.ErrExecutionRecord
	}
	return nil
}

type publicationSignedAcceptance struct {
	prepared *preparedPublicationAcceptance
	raw      []byte
	sha256   string
}

func (p *publicationSignedAcceptance) verifyBytes(ctx context.Context) error {
	if p == nil || !p.prepared.ready() || ctx == nil || ctx.Err() != nil || len(p.raw) < 2 || len(p.raw) > 8192 || hash(p.raw) != p.sha256 {
		return c.ErrExecutionRecord
	}
	history, err := p.prepared.proof.service.PublicationSigningHistory(ctx)
	if err != nil {
		return err
	}
	sha, err := verifyPublicationAcceptanceRecord(p.raw, p.prepared.intent.Payload, history, security.ArtifactSigningTask{BackupPublicID: p.prepared.proof.claim.Target.PublicID, AttemptNo: int64(p.prepared.proof.attempt)})
	if err != nil || sha != p.sha256 {
		return c.ErrExecutionRecord
	}
	return nil
}

func verifyPublicationAcceptanceRecord(raw, expectedPayload []byte, history *security.ArtifactSigningKeyHistory, task security.ArtifactSigningTask) (string, error) {
	if history == nil || len(raw) < 2 || len(raw) > 8192 {
		return "", c.ErrExecutionRecord
	}
	var envelope struct {
		Payload   json.RawMessage `json:"payload"`
		Signature json.RawMessage `json:"signature"`
	}
	if decodePublicationCanonical(raw, &envelope) != nil || !bytes.Equal(envelope.Payload, expectedPayload) {
		return "", c.ErrExecutionRecord
	}
	if _, err := decodePublicationAcceptancePayload(envelope.Payload); err != nil {
		return "", err
	}
	sha, err := history.VerifyPublicationRecord(raw, task, "acceptance_record")
	if err != nil || sha != hash(raw) {
		return "", c.ErrExecutionRecord
	}
	return sha, nil
}

// Typed same-tx gate used ONLY for a new acceptance_put. Existing generic
// actions remain query-only; their receipts cannot manufacture this type.
func (p *publicationSignedAcceptance) recheckTx(ctx context.Context, tx *sql.Tx, s *DeploymentService, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, intent publicationJSONIntent) error {
	if p == nil || !p.prepared.ready() {
		return c.ErrExecutionAuthority
	}
	proof := p.prepared.proof
	if proof.service != s || proof.claim != claim || proof.attempt != attempt || proof.target != target || intent.Kind != "acceptance_put" || intent.Key != target.Root+claim.Target.PublicID+"/"+strconv.FormatUint(attempt, 10)+"/_ACCEPTANCE" || !bytes.Equal(intent.Payload, p.raw) {
		return c.ErrExecutionAuthority
	}
	recovery, _, err := p.prepared.recheckTx(ctx, tx)
	if err != nil {
		return err
	}
	if intent.Deadline.IsZero() || intent.Deadline.After(recovery.until) {
		return c.ErrExecutionAuthority
	}
	if err = p.verifyBytes(ctx); err != nil {
		return err
	}
	known, err := readAcceptanceSigningResultTx(ctx, tx, p.prepared)
	if err != nil || !bytes.Equal(known, p.raw) {
		return c.ErrExecutionRecord
	}
	return proof.recheckVerifiedTx(ctx, tx)
}

type publicationAcceptedObject struct {
	signed *publicationSignedAcceptance
	object nativePublicationObject
}

func (p *publicationAcceptedObject) recheckTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.signed == nil || !p.signed.prepared.ready() || p.object.receipt == nil {
		return c.ErrExecutionAuthority
	}
	proof := p.signed.prepared.proof
	intent := publicationJSONIntent{Kind: "acceptance_put", Key: p.object.Key, Payload: p.signed.raw, Deadline: p.object.receipt.action.Deadline}
	if p.object.SHA256 != p.signed.sha256 || p.object.Size != int64(len(p.signed.raw)) {
		return c.ErrExecutionRecord
	}
	if err := p.signed.recheckTx(ctx, tx, proof.service, proof.claim, proof.attempt, proof.target, intent); err != nil {
		return err
	}
	return p.object.recheckPublicationReceiptTx(ctx, tx, proof.claim)
}

func (s *DeploymentService) publishOriginalPublicationAcceptance(ctx context.Context, signed *publicationSignedAcceptance) (*publicationAcceptedObject, error) {
	if signed == nil || signed.prepared == nil || signed.prepared.proof == nil || signed.prepared.proof.service != s || signed.verifyBytes(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	proof := signed.prepared.proof
	if proof.access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	recovery, _, err := signed.prepared.recheckTx(ctx, tx)
	_ = tx.Rollback()
	if err != nil {
		return nil, err
	}
	store, err := s.publicationStore(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	deadline := recovery.until.UTC().Truncate(time.Microsecond)
	intent := publicationJSONIntent{Kind: "acceptance_put", Key: proof.target.Root + proof.claim.Target.PublicID + "/" + strconv.FormatUint(proof.attempt, 10) + "/_ACCEPTANCE", Payload: signed.raw, Deadline: deadline}
	object, err := s.publishOriginalJSONWithAcceptanceProof(ctx, proof.claim, proof.attempt, store, intent, nil, nil, nil, signed)
	if err != nil {
		return nil, err
	}
	if object.receipt == nil || object.SHA256 != signed.sha256 || object.Size != int64(len(signed.raw)) {
		return nil, c.ErrExecutionRecord
	}
	// The common transport has just read the exact immutable object to EOF.
	// Repeat independent signature and original-payload semantics before typing.
	if err = signed.verifyBytes(ctx); err != nil {
		return nil, err
	}
	accepted := &publicationAcceptedObject{signed: signed, object: object}
	tx, err = s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = accepted.recheckTx(ctx, tx); err != nil {
		return nil, err
	}
	return accepted, nil
}

// Normal first-success producer. Unknown signing results stop in the original
// journal; lack of a provider query API does not obstruct this first send.
func (s *DeploymentService) completeOriginalPublicationAcceptance(ctx context.Context, proof *publicationFinalVerification) (*publicationAcceptedObject, error) {
	p, err := s.prepareOriginalPublicationAcceptance(ctx, proof)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	signed, err := p.SignCommitted(ctx)
	if err != nil {
		return nil, err
	}
	return s.publishOriginalPublicationAcceptance(ctx, signed)
}
