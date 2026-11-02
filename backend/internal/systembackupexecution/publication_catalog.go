package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"regexp"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	"github.com/google/uuid"
)

// Naming only. Neither UUIDv5 nor this stable operation coordinate authorizes
// a signature or an append; the original proof, SHA256 and signatures do.
func publicationCatalogIdentity(installation, backup string, attempt uint64) []byte {
	raw, _ := ce.Canonical([]any{"original-publication-registration.v1", installation, backup, attempt, "artifact_registered"})
	return raw
}

func publicationCatalogRecordID(installation, backup string, attempt uint64) string {
	return "scr_" + uuid.NewSHA1(uuid.NameSpaceURL, publicationCatalogIdentity(installation, backup, attempt)).String()
}

func publicationCatalogKey(material PublicationCatalogMaterials, backup string, attempt uint64) string {
	return material.Root + "registrations/" + publicationCatalogRecordID(material.InstallationID, backup, attempt) + ".json"
}

// Reuse the public content DTO, with a separate closed canonical decoder for
// this original registration producer. No legacy/tombstone fields enter.
func decodePublicationCatalogPayload(raw []byte) (artifactRegistrationPayload, error) {
	var p artifactRegistrationPayload
	if len(raw) < 2 || len(raw) > 8192 || decodePublicationCanonical(raw, &p) != nil || p.Version != "system-backup-catalog-record.v1" || p.Event != "artifact_registered" || !manifestBound(p.Installation, 256) || !regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`).MatchString(p.Backup) || !manifestBound(p.Backup, 128) || p.Attempt < 1 || p.Attempt > 9007199254740991 || !manifestBound(p.ID, 256) || p.Key.Purpose != "catalog_record" || !manifestBound(p.Key.KeyID, 256) || !manifestBound(p.Key.KeyVersion, 128) || p.Manifest.Provider != "s3" || !formalCandidateDigest(p.Manifest.Identity) || !safePublicationKey(p.Manifest.Key) || len(p.Manifest.Key) > 1024 || !fixedPublicationReadVersion(p.Manifest.Version) {
		return artifactRegistrationPayload{}, c.ErrExecutionRecord
	}
	for _, sha := range []string{p.ManifestSHA256, p.MarkerSHA256, p.AcceptanceSHA256, p.CaptureSHA256, p.IndexSHA256} {
		if !formalCandidateDigest(sha) {
			return artifactRegistrationPayload{}, c.ErrExecutionRecord
		}
	}
	at, err := time.Parse(time.RFC3339Nano, p.At)
	if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != p.At {
		return artifactRegistrationPayload{}, c.ErrExecutionRecord
	}
	return p, nil
}

func catalogPayloadFromOriginal(accepted *publicationAcceptedObject, key security.PublicationSigningKey, now time.Time) (artifactRegistrationPayload, error) {
	if accepted == nil || accepted.signed == nil || !accepted.signed.prepared.ready() || accepted.object.receipt == nil {
		return artifactRegistrationPayload{}, c.ErrExecutionAuthority
	}
	proof := accepted.signed.prepared.proof
	m, err := decodePublicationManifestV12(proof.manifest)
	if err != nil {
		return artifactRegistrationPayload{}, err
	}
	return artifactRegistrationPayload{Version: "system-backup-catalog-record.v1", Installation: proof.target.InstallationID, Backup: proof.claim.Target.PublicID, Attempt: proof.attempt, ID: publicationCatalogRecordID(proof.target.InstallationID, proof.claim.Target.PublicID, proof.attempt), At: now.UTC().Format(time.RFC3339Nano), Key: key, Event: "artifact_registered", Manifest: artifactCatalogManifestLocator{Provider: "s3", Identity: proof.target.ReadIdentityHash, Key: proof.manifestObject.Key, Version: proof.manifestObject.Version}, ManifestSHA256: proof.manifestObject.SHA256, MarkerSHA256: proof.markerObject.SHA256, AcceptanceSHA256: accepted.object.SHA256, CaptureSHA256: m.CaptureCertificate, IndexSHA256: m.Index.Checksum}, nil
}

func validateCatalogBusinessPayload(raw []byte, accepted *publicationAcceptedObject, now time.Time) error {
	p, err := decodePublicationCatalogPayload(raw)
	if err != nil {
		return err
	}
	at, _ := time.Parse(time.RFC3339Nano, p.At)
	want, err := catalogPayloadFromOriginal(accepted, p.Key, at)
	if err != nil || p != want || now.IsZero() || at.After(now) {
		return c.ErrExecutionRecord
	}
	local, err := decodePublicationAcceptancePayload(accepted.signed.prepared.intent.Payload)
	eligible, reasons, evaluationErr := publicationOriginalEvaluation(accepted.signed.prepared.proof)
	decision, parseErr := time.Parse(time.RFC3339Nano, local.DecisionAt)
	if err != nil || parseErr != nil || evaluationErr != nil || local.Accepted != eligible || !reflect.DeepEqual(local.Reasons, reasons) || at.Before(decision) || accepted.object.SHA256 != accepted.signed.sha256 || accepted.object.Size != int64(len(accepted.signed.raw)) {
		return c.ErrExecutionRecord
	}
	return nil
}

type publicationSignedCatalog struct {
	prepared *preparedPublicationCatalog
	raw      []byte
	sha256   string
}

func verifyPublicationCatalogRecord(raw, expectedPayload []byte, history *security.ArtifactSigningKeyHistory, task security.ArtifactSigningTask) (string, error) {
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
	if _, err := decodePublicationCatalogPayload(envelope.Payload); err != nil {
		return "", err
	}
	sha, err := history.VerifyPublicationRecord(raw, task, "catalog_record")
	if err != nil || sha != hash(raw) {
		return "", c.ErrExecutionRecord
	}
	return sha, nil
}

func (p *publicationSignedCatalog) verifyBytes(ctx context.Context) error {
	if p == nil || !p.prepared.ready() || ctx == nil || ctx.Err() != nil || hash(p.raw) != p.sha256 {
		return c.ErrExecutionRecord
	}
	history, err := p.prepared.proof.service.PublicationSigningHistory(ctx)
	if err != nil {
		return err
	}
	sha, err := verifyPublicationCatalogRecord(p.raw, p.prepared.intent.Payload, history, security.ArtifactSigningTask{BackupPublicID: p.prepared.proof.claim.Target.PublicID, AttemptNo: int64(p.prepared.proof.attempt)})
	if err != nil || sha != p.sha256 {
		return c.ErrExecutionRecord
	}
	return nil
}

func (p *publicationSignedCatalog) recheckTx(ctx context.Context, tx *sql.Tx, s *DeploymentService, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, intent publicationJSONIntent) error {
	if p == nil || !p.prepared.ready() {
		return c.ErrExecutionAuthority
	}
	proof := p.prepared.proof
	if proof.service != s || proof.claim != claim || proof.attempt != attempt || p.prepared.catalog.transport() != target || intent.Kind != "catalog_registration_append" || intent.Key != publicationCatalogKey(p.prepared.catalog, claim.Target.PublicID, attempt) || !bytes.Equal(intent.Payload, p.raw) {
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
	known, err := readCatalogSigningResultTx(ctx, tx, p.prepared)
	if err != nil || !bytes.Equal(known, p.raw) {
		return c.ErrExecutionRecord
	}
	return p.prepared.accepted.recheckTx(ctx, tx)
}

// Registered is an independently read original catalog object, not terminal
// eligibility. Only this producer can combine its actual typed predecessors.
type publicationRegisteredObject struct {
	signed *publicationSignedCatalog
	object nativePublicationObject
}

func (p *publicationRegisteredObject) recheckTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.signed == nil || !p.signed.prepared.ready() || p.object.receipt == nil {
		return c.ErrExecutionAuthority
	}
	proof := p.signed.prepared.proof
	if p.object.SHA256 != p.signed.sha256 || p.object.Size != int64(len(p.signed.raw)) {
		return c.ErrExecutionRecord
	}
	intent := publicationJSONIntent{Kind: "catalog_registration_append", Key: p.object.Key, Payload: p.signed.raw, Deadline: p.object.receipt.action.Deadline}
	if err := p.signed.recheckTx(ctx, tx, proof.service, proof.claim, proof.attempt, p.signed.prepared.catalog.transport(), intent); err != nil {
		return err
	}
	return p.object.recheckPublicationReceiptTx(ctx, tx, proof.claim)
}

func (s *DeploymentService) publishOriginalPublicationCatalog(ctx context.Context, signed *publicationSignedCatalog) (*publicationRegisteredObject, error) {
	if signed == nil || !signed.prepared.ready() || signed.prepared.proof.service != s || signed.verifyBytes(ctx) != nil {
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
	store, err := s.catalogStore(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	if store.catalog == nil || *store.catalog != signed.prepared.catalog {
		return nil, c.ErrExecutionAuthority
	}
	intent := publicationJSONIntent{Kind: "catalog_registration_append", Key: publicationCatalogKey(signed.prepared.catalog, proof.claim.Target.PublicID, proof.attempt), Payload: signed.raw, Deadline: recovery.until.UTC().Truncate(time.Microsecond)}
	object, err := s.publishOriginalJSONWithCatalogProof(ctx, proof.claim, proof.attempt, store, intent, nil, nil, nil, nil, signed)
	if err != nil {
		return nil, err
	}
	if object.receipt == nil || object.SHA256 != signed.sha256 || object.Size != int64(len(signed.raw)) {
		return nil, c.ErrExecutionRecord
	}
	// The common sender compared every independently GET-read byte to raw,
	// through EOF at the original fixed version; now repeat public verification.
	if err = signed.verifyBytes(ctx); err != nil {
		return nil, err
	}
	registered := &publicationRegisteredObject{signed: signed, object: object}
	tx, err = s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = registered.recheckTx(ctx, tx); err != nil {
		return nil, err
	}
	return registered, nil
}

func (s *DeploymentService) completeOriginalPublicationCatalog(ctx context.Context, accepted *publicationAcceptedObject) (*publicationRegisteredObject, error) {
	p, err := s.prepareOriginalPublicationCatalog(ctx, accepted)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	signed, err := p.SignCommitted(ctx)
	if err != nil {
		return nil, err
	}
	return s.publishOriginalPublicationCatalog(ctx, signed)
}
