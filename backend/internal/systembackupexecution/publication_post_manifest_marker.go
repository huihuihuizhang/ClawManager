package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// Exact existing v12 DTO. The marker's own checksum is external to these bytes.
type publicationCommittedMarker struct {
	Version        string `json:"schema_version"`
	Backup         string `json:"backup_public_id"`
	ManifestSHA256 string `json:"manifest_checksum"`
	IndexSHA256    string `json:"artifact_index_checksum"`
}

// Comparison DATA only. A valid public marker is not publication authority.
func originalCommittedMarkerData(raw []byte, manifest ArtifactReadObject, installation, backup string, attempt uint64, root string) ([]byte, error) {
	m, err := decodePublicationManifestV12(raw)
	if err != nil || m.Installation != installation || m.Backup != backup || m.Attempt != attempt || manifest.Key != root+backup+"/"+strconv.FormatUint(attempt, 10)+"/manifest.json" || manifest.SHA256 != hash(raw) || manifest.Size != int64(len(raw)) || manifest.Version == "" || manifest.Version == "latest" || manifest.Version == "null" || len(manifest.Version) > 256 || strings.ContainsAny(manifest.Version, "\x00\r\n") {
		return nil, c.ErrExecutionRecord
	}
	return ce.Canonical(publicationCommittedMarker{Version: "system-backup-committed.v1", Backup: backup, ManifestSHA256: manifest.SHA256, IndexSHA256: m.Index.Checksum})
}

type publicationPostManifestMarker struct {
	service    *DeploymentService
	claim      c.ClaimToken
	attempt    uint64
	target     PublicationTargetMaterials
	manifest   nativePublicationObject
	completion *publicationPostCManifest
	intent     publicationJSONIntent
}

func (p *publicationPostManifestMarker) recheckClockTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.completion == nil || p.manifest.receipt == nil || p.manifest.receipt.access == nil || tx == nil {
		return c.ErrExecutionAuthority
	}
	// The OLD C authority is used only as an upper time bound here. It is not
	// rebound across validating->publishing. The actual current authority is
	// the parent's independently read confirmed-manifest receipt below.
	if err := p.completion.recheckClockTx(ctx, tx); err != nil {
		return err
	}
	if err := p.manifest.recheckPublicationReceiptTx(ctx, tx, p.claim); err != nil {
		return err
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil {
		return c.ErrExecutionAuthority
	}
	if err := checkPostCManifestClock(now, p.completion.clockFloor, p.intent.Deadline, p.manifest.receipt.access.ValidUntil(), p.completion.certificate, p.completion.capture); err != nil {
		return err
	}
	p.completion.clockFloor = now
	return nil
}

func (p *publicationPostManifestMarker) recheckTx(ctx context.Context, tx *sql.Tx, s *DeploymentService, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, intent publicationJSONIntent) error {
	if p == nil || ctx == nil || ctx.Err() != nil || tx == nil || p.service != s || p.claim != claim || p.attempt != attempt || p.target != target || p.manifest.receipt == nil || p.manifest.receipt.postCManifest != p.completion || p.completion == nil || p.completion.service != s || p.completion.claim != claim || p.completion.attempt != attempt || p.completion.target != target || intent.Kind != "marker_put" || intent.Key != target.Root+claim.Target.PublicID+"/"+strconv.FormatUint(attempt, 10)+"/_COMMITTED" || intent.Key != p.intent.Key || !intent.Deadline.Equal(p.intent.Deadline) || !bytes.Equal(intent.Payload, p.intent.Payload) {
		return c.ErrExecutionAuthority
	}
	completed := p.completion
	if !completed.capture.checked() || completed.receipt == nil || !completed.receipt.checked(completed.capture, completed.objects) || completed.uploaded == nil || hash(completed.uploaded.Manifest) != p.manifest.SHA256 || !bytes.Equal(completed.intent.Payload, completed.uploaded.Manifest) || intent.Deadline.After(completed.intent.Deadline) {
		return c.ErrExecutionRecord
	}
	parent := p.manifest.receipt
	if parent.service != s || parent.target != target || parent.action.Kind != "manifest_put" || parent.action.State != "confirmed_present" || !bytes.Equal(parent.action.Payload, completed.uploaded.Manifest) {
		return c.ErrExecutionRecord
	}
	expected, err := originalCommittedMarkerData(completed.uploaded.Manifest, ArtifactReadObject{Key: p.manifest.Key, Version: p.manifest.Version, SHA256: p.manifest.SHA256, Size: p.manifest.Size}, target.InstallationID, claim.Target.PublicID, attempt, target.Root)
	if err != nil || !bytes.Equal(expected, intent.Payload) {
		return c.ErrExecutionRecord
	}
	if err = p.manifest.recheckPublicationReceiptTx(ctx, tx, claim); err != nil {
		return err
	}
	guard, err := parent.access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	limits, err := readPublicationLimitsTx(ctx, tx, guard)
	if err != nil || limits != completed.receipt.limits {
		return c.ErrExecutionAuthority
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return err
	}
	known, err := readOriginalCaptureCertificateBytes(ctx, tx, completed.capture)
	if err != nil || !bytes.Equal(known, completed.certificate.bytes) {
		return c.ErrExecutionRecord
	}
	if err = completed.recheckUploadedTx(ctx, tx); err != nil {
		return err
	}
	return p.recheckClockTx(ctx, tx)
}

// Only an actual C-gated manifest send + complete fixed-version readback may
// supply its typed completion. Ordinary JSON receipts and recovery observations
// cannot reconstruct this proof or silently adopt a new claim. Query-only102
// recovery remains enabled, but cannot mint a new next-stage input by itself.
func (s *DeploymentService) publishOriginalCommittedMarkerAfterManifest(ctx context.Context, claim c.ClaimToken, attempt uint64, store *nativePublicationS3, manifest nativePublicationObject) (nativePublicationObject, error) {
	var zero nativePublicationObject
	if s == nil || ctx == nil || ctx.Err() != nil || store == nil || manifest.receipt == nil || manifest.receipt.access == nil || manifest.receipt.service != s || manifest.receipt.postCManifest == nil {
		return zero, c.ErrExecutionAuthority
	}
	completed := manifest.receipt.postCManifest
	if completed.service != s || completed.claim != claim || completed.attempt != attempt || completed.target != store.config || completed.uploaded == nil || manifest.receipt.access.Check(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	raw, err := originalCommittedMarkerData(completed.uploaded.Manifest, ArtifactReadObject{Key: manifest.Key, Version: manifest.Version, SHA256: manifest.SHA256, Size: manifest.Size}, store.config.InstallationID, claim.Target.PublicID, attempt, store.config.Root)
	if err != nil {
		return zero, err
	}
	deadline, err := postCManifestDeadline(manifest.receipt.access.ValidUntil(), completed.certificate)
	if err != nil {
		return zero, err
	}
	if completed.intent.Deadline.Before(deadline) {
		deadline = completed.intent.Deadline
	}
	p := &publicationPostManifestMarker{service: s, claim: claim, attempt: attempt, target: store.config, manifest: manifest, completion: completed, intent: publicationJSONIntent{Kind: "marker_put", Key: store.config.Root + claim.Target.PublicID + "/" + strconv.FormatUint(attempt, 10) + "/_COMMITTED", Payload: raw, Deadline: deadline}}
	return s.publishOriginalJSONWithStageProof(ctx, claim, attempt, store, p.intent, nil, nil, p)
}

// Actual first-forward caller consumes both stages in the SAME latest original
// claim. It does not extend C/provider/DEK time, issue a signature, clean up,
// make an artifact usable or promote a terminal task.
func (s *DeploymentService) completeOriginalPublicationManifestAndMarker(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, store *nativePublicationS3, capture publicationVerifiedCapture) (nativePublicationObject, error) {
	manifest, err := s.completeOriginalPublicationUploadedManifest(ctx, claim, attempt, policy, store, capture)
	if err != nil {
		return nativePublicationObject{}, err
	}
	return s.publishOriginalCommittedMarkerAfterManifest(ctx, *claim, attempt, store, manifest)
}
