package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	ce "clawreef/internal/systembackupcontrolevidence"
)

// Named mapping DATA only. The test-local receipt allows exercising the closed
// historical decoder; it supplies no actual C, SQL, claim or signing authority
// and is not evidence that a complete six-domain capture succeeded.
func publicationCertificateMappingData(t *testing.T) publicationVerifiedCapture {
	t.Helper()
	var capture publicationVerifiedCapture
	capture.Input.InstallationID = "installation_mapping_data"
	capture.Input.TaskPublicID = "sbk_11111111-1111-4111-8111-111111111111"
	capture.Input.ConfigVersion, capture.Input.CaptureAttemptNo = 1, 1
	capture.Input.ConfigSHA256 = hash([]byte("named config DATA"))
	capture.Input.SourceSHA256 = hash([]byte("named source DATA"))
	capture.CaptureContextSHA256 = hash([]byte("named capture context DATA"))
	capture.SourceFacts = productionPublicationSourceFacts{Version: "system-backup-original-publication-source-facts.v1", AppVersion: "dev", GitCommit: "abcdef0", MigrationCatalogSHA256: hash([]byte("named catalog DATA")), SchemaSHA256: hash([]byte("named schema DATA")), SchemaRegistry: ce.RegistryPin{Version: "named-r1", SHA256: hash([]byte("named registry DATA"))}, CoveredObjects: 1, ExcludedObjects: 1}
	names := []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle", ce.Part, ce.ProofPart}
	for index, name := range names {
		part := publicationVerifiedPart{Part: name, InvocationSHA256: hash([]byte("named invocation DATA " + name)), CipherSHA256: hash([]byte("named C DATA " + name)), Index: uint32(index)}
		if index < 6 {
			part.RequestedPart = name
		}
		original := b.Checkpoint{SchemaVersion: "system-backup-b-checkpoint.v1", InstallationID: capture.Input.InstallationID, TaskPublicID: capture.Input.TaskPublicID, ConfigVersion: 1, ConfigSHA256: capture.Input.ConfigSHA256, AttemptNo: 1, Phase: "capture", InventorySHA256: capture.Input.SourceSHA256, Part: name, JobUID: "named-job-data-" + name, JobGeneration: 1, InvocationSHA256: part.InvocationSHA256, SealedRef: "named seal DATA", ContentSHA256: part.CipherSHA256}
		part.Checkpoint, _ = json.Marshal(original)
		capture.Parts = append(capture.Parts, part)
	}
	capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
	return capture
}

func TestPublicationCertificatePartsBindOriginalCheckpointFields(t *testing.T) {
	for _, mode := range []string{"unchanged", "scope", "phase", "generation", "content", "duplicate-job", "missing-domain", "source", "commit", "field-alias", "no-verification-receipt"} {
		t.Run(mode, func(t *testing.T) {
			capture := publicationCertificateMappingData(t)
			var checkpoint b.Checkpoint
			if json.Unmarshal(capture.Parts[0].Checkpoint, &checkpoint) != nil {
				t.Fatal("named checkpoint DATA")
			}
			switch mode {
			case "scope":
				checkpoint.TaskPublicID = "sbk_22222222-2222-4222-8222-222222222222"
			case "phase":
				checkpoint.Phase = "publish"
			case "generation":
				checkpoint.JobGeneration = 0
			case "content":
				checkpoint.ContentSHA256 = hash([]byte("different C DATA"))
			case "duplicate-job":
				checkpoint.JobUID = "named-job-data-redis"
			case "missing-domain":
				capture.Parts[5].RequestedPart = ""
			case "source":
				capture.Input.SourceSHA256 = hash([]byte("different source DATA"))
			case "commit":
				capture.SourceFacts.GitCommit = "unknown"
			}
			capture.Parts[0].Checkpoint, _ = json.Marshal(checkpoint)
			if mode == "field-alias" {
				capture.Parts[0].Checkpoint = []byte(strings.Replace(string(capture.Parts[0].Checkpoint), `"job_uid"`, `"JOB_UID"`, 1))
			}
			capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
			if mode == "no-verification-receipt" {
				capture.receipt = nil
			}
			jobs, checkpoints, err := publicationCertificateParts(capture)
			if mode != "unchanged" {
				if err == nil || jobs != nil || checkpoints != nil {
					t.Fatal("changed historical mapping DATA accepted", mode)
				}
				return
			}
			if err != nil || len(jobs) != 8 || len(checkpoints) != 8 {
				t.Fatal("complete named mapping DATA refused", err)
			}
			for index := 1; index < len(jobs); index++ {
				if jobs[index-1].UID >= jobs[index].UID || checkpoints[index-1].Part >= checkpoints[index].Part {
					t.Fatal("certificate identities are not deterministically sorted")
				}
			}
		})
	}
}
