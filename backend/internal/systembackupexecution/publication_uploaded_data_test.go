package systembackupexecution

import (
	"bytes"
	"errors"
	"testing"

	c "clawreef/internal/systembackupcontroller"
	batchv1 "k8s.io/api/batch/v1"
)

func TestOriginalUploadedCaptureDataRequiresCompleteTransport(t *testing.T) {
	for _, mode := range []string{"complete", "pending-native-exit", "missing-result", "foreign-result", "foreign-job"} {
		t.Run(mode, func(t *testing.T) {
			observed := originalUploadPollFixtureData(t)
			var want error
			switch mode {
			case "pending-native-exit":
				observed.Job.Status = batchv1.JobStatus{}
				want = ErrJobUncertain
			case "missing-result":
				observed.Messages = observed.Messages[:len(observed.Messages)-1]
				want = c.ErrExecutionRecord
			case "foreign-result":
				observed.Messages[0].Object.Version = "latest"
				want = c.ErrExecutionRecord
			case "foreign-job":
				observed.Job.UID = "foreign-data-job"
				want = c.ErrExecutionRecord
			}
			data, err := originalPublicationUploadedData(observed)
			if want != nil {
				if !errors.Is(err, want) || data != nil {
					t.Fatal("incomplete transport produced output DATA", err)
				}
				return
			}
			if err != nil || data == nil || len(data.Objects) != 15 || data.Candidate.Key == "" || data.RequestSHA256 != observed.RequestSHA || data.JobUID != observed.JobUID || data.JobGeneration != observed.Generation {
				t.Fatal("complete original transport DATA lost", err)
			}
			manifest, index := bytes.Clone(data.Manifest), bytes.Clone(data.Index)
			certificate, bootstrap := bytes.Clone(data.Certificate), bytes.Clone(data.Bootstrap)
			clear(observed.Request.ManifestInput)
			clear(observed.Request.IndexBytes)
			clear(observed.Request.CaptureCertificate)
			clear(observed.Request.CaptureBootstrap)
			observed.Messages[0].Object.Version = "changed-input-data"
			if !bytes.Equal(data.Manifest, manifest) || !bytes.Equal(data.Index, index) || !bytes.Equal(data.Certificate, certificate) || !bytes.Equal(data.Bootstrap, bootstrap) {
				t.Fatal("public DATA aliased closed private material")
			}
			for _, object := range data.Objects {
				if object.Version != "fixed-native-poll-data" {
					t.Fatal("fixed-version DATA aliased an input observation")
				}
			}
		})
	}
}
