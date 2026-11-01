package systembackupexecution

import (
	"bytes"
	"context"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// Public immutable DATA for the independent remote-content verifier. Neither
// this type nor its transport checks prove C, signature validity, sealing or
// acceptance. It deliberately carries no credential, grant or owner HMAC.
type publicationUploadedCaptureData struct {
	RequestSHA256, JobUID                   string
	JobGeneration                           int64
	Manifest, Index, Certificate, Bootstrap []byte
	Objects                                 map[string]ArtifactReadObject
	Candidate                               ArtifactReadObject
	// Original sequence-validated canonical bodies, not current-SQL or C
	// authority. A later transaction must compare rather than redefine them.
	ResultBodySHA256 [16]string
}

func originalPublicationUploadedData(observed publicationUploadPollData) (*publicationUploadedCaptureData, error) {
	complete, err := publicationUploadCompletion(observed.Request, observed.RequestSHA, observed.JobUID, observed.Generation, observed.Job, observed.Cursor.Sequence, observed.Cursor.Status.String, observed.Messages)
	if err != nil {
		return nil, err
	}
	if !complete {
		return nil, ErrJobUncertain
	}
	request := observed.Request
	manifest, _, err := request.validate()
	if err != nil {
		return nil, err
	}
	if _, err := decodePublicationManifestV12(manifest); err != nil || len(request.Objects) != 15 || len(request.CaptureCertificate) == 0 || len(request.CaptureBootstrap) == 0 {
		return nil, c.ErrExecutionRecord
	}
	result := &publicationUploadedCaptureData{RequestSHA256: observed.RequestSHA, JobUID: observed.JobUID, JobGeneration: observed.Generation, Manifest: bytes.Clone(manifest), Index: bytes.Clone(request.IndexBytes), Certificate: bytes.Clone(request.CaptureCertificate), Bootstrap: bytes.Clone(request.CaptureBootstrap), Objects: make(map[string]ArtifactReadObject, len(request.Objects))}
	for i, expected := range request.Objects {
		object := observed.Messages[i].Object
		result.Objects[expected.Path] = ArtifactReadObject{Key: object.Key, Version: object.Version, SHA256: object.SHA256, Size: object.Bytes}
	}
	object := observed.Messages[len(request.Objects)].Object
	result.Candidate = ArtifactReadObject{Key: object.Key, Version: object.Version, SHA256: object.SHA256, Size: object.Bytes}
	for i, message := range observed.Messages {
		raw, err := ce.Canonical(message)
		if err != nil {
			return nil, c.ErrExecutionRecord
		}
		result.ResultBodySHA256[i] = hash(raw)
	}
	return result, nil
}

// Reopens only existing original material and its bound Job. This current
// entry cannot issue a new capability or adopt another claim's upload. Public
// bytes are cloned before private material is closed, so they remain usable as
// DATA after an explicit next-stage claim transition. Expired material needs a
// separate query-only reconciliation path; it is never regenerated here.
func (s *DeploymentService) readOriginalPublicationUploadedData(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials) (*publicationUploadedCaptureData, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, c.ErrExecutionAuthority
	}
	original, err := s.loadPublicationMaterialIntent(ctx, claim, attempt)
	if err != nil {
		return nil, err
	}
	if original.Claim != claim {
		return nil, c.ErrClaimLost
	}
	m, err := s.preparePublicationJobMaterials(ctx, claim, attempt, target, PublicationUploadRequest{})
	if err != nil {
		return nil, err
	}
	defer m.Close()
	if m.intent.Claim != claim {
		return nil, c.ErrClaimLost
	}
	job, _, err := s.readBoundPublicationJob(ctx, claim, attempt, m)
	if err != nil {
		return nil, err
	}
	observed, err := s.readOriginalPublicationUploadCompletion(ctx, claim, m, job)
	if err != nil {
		return nil, err
	}
	result, err := originalPublicationUploadedData(observed)
	if err != nil {
		return nil, err
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil || ctx.Err() != nil {
		return nil, c.ErrClaimLost
	}
	return result, nil
}
