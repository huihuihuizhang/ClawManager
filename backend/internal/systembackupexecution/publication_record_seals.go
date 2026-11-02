package systembackupexecution

import (
	"path"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
)

// Comparison DATA from a current authenticated original record. Upload mounts
// consume this pair; it grants no filesystem deletion or cleanup receipt.
func publicationRecordSeals(record c.PublisherCaptureRecord) ([2]publicationLocalSeal, error) {
	var out [2]publicationLocalSeal
	var original FormalCandidateRecord
	digest, err := record.Invocation.Hash()
	scope := record.SealScope
	i := record.Input
	j := record.Job
	if err != nil || decodeProviderDeploymentJSON(record.CandidateJSON, &original) != nil || hash(record.CandidateJSON) != record.CandidateSHA256 || !worker.ValidateFormalCaptureResult(record.Invocation, &original.Candidate) || scope.Installation != i.InstallationID || scope.Task != i.TaskPublicID || scope.Phase != "capture" || scope.Attempt != i.CaptureAttemptNo || scope.ConfigVersion != i.ConfigVersion || scope.ConfigSHA256 != i.ConfigSHA256 || scope.InvocationSHA256 != digest || scope.Binding != record.Invocation.Request.Binding || scope.Namespace != j.Namespace || scope.JobName != j.Name || scope.JobUID != j.UID || scope.Generation != j.Generation || scope.Unit != j.JobUnitKey {
		return out, c.ErrExecutionRecord
	}
	for index, receipt := range []staging.Receipt{original.Candidate.Ciphertext, original.Candidate.Envelope} {
		member := scope
		if index == 1 {
			member.Unit += "/formal-envelope"
		}
		intent := staging.SealIntent{Schema: "controller-staging-seal-intent.v1", Scope: member, Original: receipt}
		ref, err := staging.SealReferenceForIntent(intent)
		if err != nil {
			return [2]publicationLocalSeal{}, err
		}
		out[index] = publicationLocalSeal{Intent: intent, Name: path.Base(ref)}
	}
	return out, nil
}
