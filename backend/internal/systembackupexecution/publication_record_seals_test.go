package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

func TestPublicationLocalSealsMatchOriginalUploadCustodyData(t *testing.T) {
	_, _, scope, invocation, candidate, _ := formalObserverFixture(t)
	raw, err := json.Marshal(FormalCandidateRecord{Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	record := c.PublisherCaptureRecord{Input: c.HistoricalCaptureInput{InstallationID: scope.Installation, TaskPublicID: scope.Task, CaptureAttemptNo: scope.Attempt, ConfigVersion: scope.ConfigVersion, ConfigSHA256: scope.ConfigSHA256}, Job: d.JobBinding{Namespace: scope.Namespace, Name: scope.JobName, UID: scope.JobUID, Generation: scope.Generation, JobUnitKey: scope.Unit}, Invocation: invocation, CandidateJSON: raw, CandidateSHA256: hash(raw), SealScope: scope}
	pair, err := publicationRecordSeals(record)
	if err != nil {
		t.Fatal(err)
	}
	for index, receipt := range []staging.Receipt{candidate.Ciphertext, candidate.Envelope} {
		original := scope
		if index == 1 {
			original.Unit += "/formal-envelope"
		}
		ref, err := staging.SealReferenceForIntent(staging.SealIntent{Schema: "controller-staging-seal-intent.v1", Scope: original, Original: receipt})
		if err != nil || ref != "controller-staging-seal.v1/"+pair[index].Name || pair[index].Intent.Original != receipt {
			t.Fatal("cleanup selection differs from original upload custody", err)
		}
	}
	for _, mode := range []string{"task", "attempt", "job", "generation", "invocation", "binding", "candidate-hash", "candidate-content"} {
		t.Run(mode, func(t *testing.T) {
			bad := record
			switch mode {
			case "task":
				bad.Input.TaskPublicID += "other"
			case "attempt":
				bad.Input.CaptureAttemptNo++
			case "job":
				bad.Job.UID += "other"
			case "generation":
				bad.Job.Generation++
			case "invocation":
				bad.SealScope.InvocationSHA256 = strings.Repeat("e", 64)
			case "binding":
				bad.SealScope.Binding.BackupID += "other"
			case "candidate-hash":
				bad.CandidateSHA256 = strings.Repeat("e", 64)
			case "candidate-content":
				changed := candidate
				changed.InvocationSHA256 = strings.Repeat("e", 64)
				bad.CandidateJSON, _ = json.Marshal(FormalCandidateRecord{Candidate: changed})
				bad.CandidateSHA256 = hash(bad.CandidateJSON)
			}
			if _, err := publicationRecordSeals(bad); err == nil {
				t.Fatal("accepted changed original record")
			}
		})
	}
}
