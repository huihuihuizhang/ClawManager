package systembackupexecution

import (
	"context"
	"database/sql"
	"net/url"
	"sort"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// Terminal facts are DATA, not a Ready constructor or an eligibility flag.
// D consumes these only through the actual typed Ready's same-tx gate.
type publicationTerminalObject struct {
	URI, Key, Version, SHA256, IdentitySHA256 string
	Size                                      int64
}

type publicationTerminalFacts struct {
	ContentSamplesSHA256                                                     string
	SourceRecovery                                                           c.PublisherSourceRecoveryFacts
	Installation, Backup, ConfigSHA256                                       string
	Attempt, ConfigVersion                                                   uint64
	Claim                                                                    c.ClaimToken
	RequestedParts                                                           string
	Artifact, Manifest, Index, Marker, Acceptance, Catalog                   publicationTerminalObject
	RegistrationID, RegistrationSHA256                                       string
	Decision, Cleanup                                                        ce.EvidenceRef
	DecisionAt, VerifiedAt, Until                                            time.Time
	OriginalSHA256, ContentSHA256, CaptureContextSHA256, CaptureResultSHA256 string
	CaptureCertificateSHA256, CaptureCheckpointsSHA256                       string
	ArtifactBytes                                                            int64
	Purpose, TargetClass, TargetRisks, FailureDomain, QualificationReasons   string
	Eligible                                                                 bool
}

func publicationTerminalASCII(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// URI names the actual native object, without presigned queries/credentials.
// Its immutable version remains a separate original locator field.
func publicationTerminalLocator(target PublicationTargetMaterials, object ArtifactReadObject) (publicationTerminalObject, error) {
	var zero publicationTerminalObject
	base, err := url.Parse(target.Endpoint)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || !safePublicationKey(object.Key) || !strings.HasPrefix(object.Key, target.Root) || !publicationTerminalASCII(object.Version, 256) || !fixedPublicationReadVersion(object.Version) || !formalCandidateDigest(object.SHA256) || !formalCandidateDigest(target.ReadIdentityHash) || object.Size < 1 || object.Size > MaxPublicationArtifactBytes {
		return zero, c.ErrExecutionRecord
	}
	base.Path = "/" + target.Bucket + "/" + object.Key
	uri := base.String()
	if len(uri) > 2048 {
		return zero, c.ErrExecutionRecord
	}
	return publicationTerminalObject{URI: uri, Key: object.Key, Version: object.Version, SHA256: object.SHA256, IdentitySHA256: target.ReadIdentityHash, Size: object.Size}, nil
}

type publicationPhysicalObject struct {
	Identity string
	Object   ArtifactReadObject
}

// Sum UNIQUE outer physical versions, never inner member/plaintext sizes.
// A duplicate identity/key/version must agree exactly on bytes and checksum.
func publicationUniqueOuterBytes(objects []publicationPhysicalObject, limit int64) (int64, error) {
	if len(objects) == 0 || len(objects) > 100000 || limit < 1 || limit > MaxPublicationArtifactBytes {
		return 0, c.ErrExecutionRecord
	}
	type identity struct{ Provider, Key, Version string }
	seen := map[identity]ArtifactReadObject{}
	var total int64
	for _, value := range objects {
		object := value.Object
		if !formalCandidateDigest(value.Identity) || !safePublicationKey(object.Key) || !fixedPublicationReadVersion(object.Version) || !publicationTerminalASCII(object.Version, 256) || !formalCandidateDigest(object.SHA256) || object.Size < 1 {
			return 0, c.ErrExecutionRecord
		}
		key := identity{value.Identity, object.Key, object.Version}
		if old, ok := seen[key]; ok {
			if old != object {
				return 0, c.ErrExecutionRecord
			}
			continue
		}
		if object.Size > limit-total || object.Size > 9007199254740991-total {
			return 0, c.ErrExecutionRecord
		}
		seen[key] = object
		total += object.Size
	}
	return total, nil
}

func publicationOriginalOuterObjects(proof *publicationFinalVerification, accepted *publicationAcceptedObject) ([]publicationPhysicalObject, error) {
	if proof == nil || !proof.cleanup.ready() || accepted == nil || accepted.signed == nil || !accepted.signed.prepared.ready() || accepted.signed.prepared.proof != proof || accepted.object.receipt == nil {
		return nil, c.ErrExecutionAuthority
	}
	objects := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.objects
	if len(objects.Containers) != 6 || len(objects.Control) != 6 || len(objects.Metadata) != 3 {
		return nil, c.ErrExecutionRecord
	}
	out := []publicationPhysicalObject{}
	for _, group := range []map[string]ArtifactReadObject{objects.Containers, objects.Control, objects.Metadata} {
		keys := make([]string, 0, len(group))
		for key := range group {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			out = append(out, publicationPhysicalObject{proof.target.ReadIdentityHash, group[key]})
		}
	}
	out = append(out, publicationPhysicalObject{proof.target.ReadIdentityHash, proof.manifestObject}, publicationPhysicalObject{proof.target.ReadIdentityHash, proof.markerObject}, publicationPhysicalObject{proof.target.ReadIdentityHash, ArtifactReadObject{Key: accepted.object.Key, Version: accepted.object.Version, SHA256: accepted.object.SHA256, Size: accepted.object.Size}})
	return out, nil
}

// Derivation only: caller must consume the complete decision/final SOURCE gate
// in its same transaction before and after using these values. It cannot mint
// a Ready. Repeated derivation preserves the original internal decision time.
func originalPublicationTerminalFacts(decision *publicationDecisionEvidence, verifiedAt time.Time) (publicationTerminalFacts, error) {
	var facts publicationTerminalFacts
	if decision == nil || verifiedAt.IsZero() || !verifiedAt.Equal(verifiedAt.Truncate(time.Microsecond)) {
		return facts, c.ErrExecutionAuthority
	}
	proof := decisionRegisteredProof(decision.registered)
	if proof == nil || proof.claim.RowVersion == 0 || proof.claim.RowVersion == ^uint64(0) {
		return facts, c.ErrExecutionAuthority
	}
	preimage, at, err := decodePublicationDecision(decision.row.raw)
	if err != nil || at.After(verifiedAt) || decision.ref.SHA256 != hash(decision.row.raw) {
		return facts, c.ErrExecutionRecord
	}
	registered := decision.registered
	accepted := registered.signed.prepared.accepted
	if proof.access == nil || accepted.object.receipt == nil || accepted.object.receipt.access == nil || registered.object.receipt == nil || registered.object.receipt.access == nil {
		return facts, c.ErrExecutionAuthority
	}
	if err = validateDecisionOriginal(decision.row.raw, registered, verifiedAt); err != nil {
		return facts, err
	}
	recovered, err := publicationSourceRecoveryFacts(proof, proof.sourceRecovery)
	if err != nil || recovered.ObservedAt.After(verifiedAt) {
		return facts, c.ErrExecutionRecord
	}
	_, sampleSHA, err := proof.contentSamples.snapshot()
	if err != nil {
		return facts, err
	}
	m, err := decodePublicationManifestV12(proof.manifest)
	if err != nil {
		return facts, c.ErrExecutionRecord
	}
	eligible, reasons, err := publicationOriginalEvaluation(proof)
	if err != nil || preimage.Eligible != eligible || strings.Join(preimage.Reasons, ",") != strings.Join(reasons, ",") {
		return facts, c.ErrExecutionRecord
	}
	for _, name := range publicationRequestedParts {
		if p, ok := m.Parts[name]; !ok || !p.Required || p.Status != "completed" || p.Consistency != "strong" {
			return facts, c.ErrExecutionRecord
		}
	}
	completion := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion
	capture := completion.capture
	index, ok := completion.objects.Metadata["artifact-index.json"]
	if !ok || index.SHA256 != hash(proof.index) || index.Size != int64(len(proof.index)) {
		return facts, c.ErrExecutionRecord
	}
	_, checkpoints, err := publicationCertificateParts(capture)
	if err != nil {
		return facts, err
	}
	// The aggregate is the JCS SHA256 of the ORIGINAL certificate's sorted
	// [{part, checkpoint_hash}] array, not a new checkpoint or first-member hash.
	checkpointBytes, err := ce.Canonical(checkpoints)
	if err != nil {
		return facts, err
	}
	facts = publicationTerminalFacts{Installation: proof.target.InstallationID, Backup: proof.claim.Target.PublicID, Attempt: proof.attempt, Claim: proof.claim, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, RequestedParts: strings.Join(publicationRequestedParts, ","), RegistrationID: preimage.RegistrationID, RegistrationSHA256: preimage.RegistrationSHA, Decision: decision.ref, Cleanup: proof.cleanup.evidence, DecisionAt: at, VerifiedAt: verifiedAt, Until: proof.access.ValidUntil(), OriginalSHA256: proof.originalSHA256, ContentSHA256: proof.verifiedSHA256, CaptureContextSHA256: capture.CaptureContextSHA256, CaptureResultSHA256: capture.CaptureResultSHA256, CaptureCertificateSHA256: preimage.CaptureSHA256, CaptureCheckpointsSHA256: hash(checkpointBytes)}
	facts.SourceRecovery = recovered
	facts.Purpose, facts.Eligible, facts.QualificationReasons = m.Purpose, eligible, strings.Join(reasons, ",")
	facts.TargetClass, facts.TargetRisks, facts.FailureDomain = m.Target.Class, strings.Join(m.Target.Risks, ","), m.Target.Domain
	facts.ContentSamplesSHA256 = sampleSHA
	for _, bound := range []time.Time{decision.row.expires, accepted.object.receipt.access.ValidUntil(), registered.object.receipt.access.ValidUntil()} {
		if bound.Before(facts.Until) {
			facts.Until = bound
		}
	}
	if !verifiedAt.Before(facts.Until) || !publicationTerminalASCII(facts.RegistrationID, 128) {
		return publicationTerminalFacts{}, c.ErrExecutionAuthority
	}
	facts.Manifest, err = publicationTerminalLocator(proof.target, proof.manifestObject)
	if err != nil {
		return publicationTerminalFacts{}, err
	}
	facts.Artifact = facts.Manifest // One actual object; no second archive/size.
	facts.Index, err = publicationTerminalLocator(proof.target, index)
	if err != nil {
		return publicationTerminalFacts{}, err
	}
	facts.Marker, err = publicationTerminalLocator(proof.target, proof.markerObject)
	if err != nil {
		return publicationTerminalFacts{}, err
	}
	facts.Acceptance, err = publicationTerminalLocator(proof.target, ArtifactReadObject{Key: accepted.object.Key, Version: accepted.object.Version, SHA256: accepted.object.SHA256, Size: accepted.object.Size})
	if err != nil {
		return publicationTerminalFacts{}, err
	}
	facts.Catalog, err = publicationTerminalLocator(registered.signed.prepared.catalog.transport(), ArtifactReadObject{Key: registered.object.Key, Version: registered.object.Version, SHA256: registered.object.SHA256, Size: registered.object.Size})
	if err != nil {
		return publicationTerminalFacts{}, err
	}
	outer, err := publicationOriginalOuterObjects(proof, accepted)
	if err != nil {
		return publicationTerminalFacts{}, err
	}
	facts.ArtifactBytes, err = publicationUniqueOuterBytes(outer, proof.limits.MaxArtifactBytes)
	if err != nil {
		return publicationTerminalFacts{}, err
	}
	return facts, nil
}

func recheckPublicationTerminalProjectionTx(ctx context.Context, tx *sql.Tx, facts publicationTerminalFacts) error {
	if tx == nil || ctx == nil || ctx.Err() != nil {
		return c.ErrExecutionAuthority
	}
	var status, purpose, parts, state, target, risks, domain string
	var consistency sql.NullString
	var started sql.NullTime
	var cancel bool
	var cert, checkpoints, registrationID, registrationSHA, decisionSHA sql.NullString
	var decided sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT status,task_purpose,requested_parts,artifact_state,target_class,target_risks,target_failure_domain_id,consistency,commit_started_at,can_cancel,capture_certificate_sha256,capture_checkpoint_sha256,artifact_registration_id,artifact_registration_hash,eligibility_decision_hash,eligibility_decided_at FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND config_version=? AND config_snapshot_sha256=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) FOR SHARE`, facts.Installation, facts.Backup, facts.Claim.Owner, facts.Claim.RowVersion, facts.ConfigVersion, facts.ConfigSHA256).Scan(&status, &purpose, &parts, &state, &target, &risks, &domain, &consistency, &started, &cancel, &cert, &checkpoints, &registrationID, &registrationSHA, &decisionSHA, &decided)
	if err != nil || status != "publishing" || purpose != facts.Purpose || parts != facts.RequestedParts || (state != "staging" && state != "committed") || target != facts.TargetClass || risks != facts.TargetRisks || domain != facts.FailureDomain || consistency.Valid && consistency.String != "strong" || !started.Valid || cancel {
		return c.ErrExecutionAuthority
	}
	for _, item := range []struct {
		actual   sql.NullString
		expected string
	}{{cert, facts.CaptureCertificateSHA256}, {checkpoints, facts.CaptureCheckpointsSHA256}, {registrationID, facts.RegistrationID}, {registrationSHA, facts.RegistrationSHA256}, {decisionSHA, facts.Decision.SHA256}} {
		if item.actual.Valid && item.actual.String != item.expected {
			return c.ErrExecutionRecord
		}
	}
	if registrationID.Valid != registrationSHA.Valid || decisionSHA.Valid != decided.Valid || decided.Valid && !decided.Time.Equal(facts.DecisionAt) {
		return c.ErrExecutionRecord
	}
	var originalBytes sql.NullInt64
	if tx.QueryRowContext(ctx, `SELECT artifact_bytes FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR SHARE`, facts.Installation, facts.Backup).Scan(&originalBytes) != nil || originalBytes.Valid && originalBytes.Int64 != facts.ArtifactBytes || state == "committed" && !originalBytes.Valid {
		return c.ErrExecutionRecord
	}
	for _, item := range []struct {
		prefix string
		object publicationTerminalObject
	}{{"artifact", facts.Artifact}, {"manifest", facts.Manifest}, {"index", facts.Index}, {"marker", facts.Marker}, {"acceptance", facts.Acceptance}} {
		var uri, version, sha sql.NullString
		// Prefixes above are a closed internal column family, never input SQL.
		query := `SELECT ` + item.prefix + `_uri,` + item.prefix + `_immutable_version,` + item.prefix + `_checksum FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR SHARE`
		if tx.QueryRowContext(ctx, query, facts.Installation, facts.Backup).Scan(&uri, &version, &sha) != nil || uri.Valid != version.Valid || uri.Valid != sha.Valid || uri.Valid && (uri.String != item.object.URI || version.String != item.object.Version || sha.String != item.object.SHA256) || state == "committed" && !uri.Valid {
			return c.ErrExecutionRecord
		}
	}
	return nil
}

// Birth requires the real committed decision, registered/accepted independent
// readback receipts, complete content verification and original physical source
// recovery. Neither a DTO nor an eligibility boolean can mint this handle.
type publicationTerminalReady struct {
	decision *publicationDecisionEvidence
	facts    publicationTerminalFacts
	sha256   string
}

func (p *publicationTerminalReady) Facts() publicationTerminalFacts {
	if p == nil || p.decision == nil || !formalCandidateDigest(p.sha256) {
		return publicationTerminalFacts{}
	}
	return p.facts // All fields are detached scalar comparison data.
}

// Redacted report of this final read, for the accepted task's verification
// evidence/reporting. It is inert data and grants no terminal or restore writes.
func (p *publicationTerminalReady) ContentSamples() (publicationContentSampleReport, error) {
	if p == nil || p.decision == nil || !formalCandidateDigest(p.sha256) {
		return publicationContentSampleReport{}, c.ErrExecutionAuthority
	}
	proof := decisionRegisteredProof(p.decision.registered)
	if proof == nil {
		return publicationContentSampleReport{}, c.ErrExecutionAuthority
	}
	report, digest, err := proof.contentSamples.snapshot()
	if err != nil || digest != p.facts.ContentSamplesSHA256 {
		return publicationContentSampleReport{}, c.ErrExecutionRecord
	}
	return report, nil
}

// D calls this BEFORE its sole terminal CAS using the SAME concrete *sql.Tx.
// This gate does SQL/history reads only; it never signs, PUTs, renews, stages
// another decision, opens local seals, invokes a provider or starts source I/O.
func (p *publicationTerminalReady) recheckTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.decision == nil || tx == nil || ctx == nil || ctx.Err() != nil || !formalCandidateDigest(p.sha256) {
		return c.ErrExecutionAuthority
	}
	if err := p.decision.recheckTx(ctx, tx); err != nil {
		return err
	}
	facts, err := originalPublicationTerminalFacts(p.decision, p.facts.VerifiedAt)
	if err != nil {
		return err
	}
	raw, err := ce.Canonical(facts)
	if err != nil || hash(raw) != p.sha256 {
		return c.ErrExecutionRecord
	}
	original, err := ce.Canonical(p.facts)
	if err != nil || hash(original) != p.sha256 {
		return c.ErrExecutionRecord
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || now.Before(facts.VerifiedAt) || !now.Before(facts.Until) {
		return c.ErrExecutionAuthority
	}
	return recheckPublicationTerminalProjectionTx(ctx, tx, facts)
}

// This is read-only and may be repeated with an independently queried known
// decision. It never retries the original decision write after uncertainty.
func (s *DeploymentService) completeOriginalPublicationReady(ctx context.Context, decision *publicationDecisionEvidence) (*publicationTerminalReady, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || decision == nil {
		return nil, c.ErrExecutionAuthority
	}
	proof := decisionRegisteredProof(decision.registered)
	if proof == nil || proof.service != s || proof.access == nil || s.publisherVerifierDB == nil {
		return nil, c.ErrExecutionAuthority
	}
	if err := proof.access.Check(ctx); err != nil {
		return nil, err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var now time.Time
	if err = tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return nil, err
	}
	facts, err := originalPublicationTerminalFacts(decision, now)
	if err != nil {
		return nil, err
	}
	raw, err := ce.Canonical(facts)
	if err != nil {
		return nil, err
	}
	ready := &publicationTerminalReady{decision: decision, facts: facts, sha256: hash(raw)}
	if err = ready.recheckTx(ctx, tx); err != nil {
		return nil, err
	}
	return ready, nil
}
