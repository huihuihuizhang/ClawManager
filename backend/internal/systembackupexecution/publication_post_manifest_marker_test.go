package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	c "clawreef/internal/systembackupcontroller"
)

// Exact v12 canonical marker DATA only; it cannot create a C/manifest receipt.
func TestCommittedMarkerBindsExactManifestData(t *testing.T) {
	for _, mode := range []string{"complete", "foreign-installation", "foreign-task", "foreign-attempt", "foreign-key", "latest-version", "null-version", "wrong-hash", "wrong-size", "changed-manifest-bytes", "empty-manifest"} {
		t.Run(mode, func(t *testing.T) {
			request, m, _ := publicationContainerRequestData(t)
			manifest := ArtifactReadObject{Key: request.ArtifactRoot + m.Backup + "/1/manifest.json", Version: "fixed-native-marker-DATA", Size: int64(len(request.ManifestInput)), SHA256: hash(request.ManifestInput)}
			installation, backup, attempt := m.Installation, m.Backup, m.Attempt
			raw := bytes.Clone(request.ManifestInput)
			switch mode {
			case "foreign-installation":
				installation += "_foreign"
			case "foreign-task":
				backup = "sbk_22222222-2222-4222-8222-222222222222"
			case "foreign-attempt":
				attempt++
			case "foreign-key":
				manifest.Key = "foreign/manifest.json"
			case "latest-version":
				manifest.Version = "latest"
			case "null-version":
				manifest.Version = "null"
			case "wrong-hash":
				manifest.SHA256 = hash([]byte("foreign MF DATA"))
			case "wrong-size":
				manifest.Size++
			case "changed-manifest-bytes":
				raw = append(raw, ' ')
			case "empty-manifest":
				raw = nil
			}
			marker, err := originalCommittedMarkerData(raw, manifest, installation, backup, attempt, request.ArtifactRoot)
			if mode != "complete" {
				if err == nil || marker != nil {
					t.Fatal("foreign marker input accepted", mode)
				}
				return
			}
			var fields map[string]string
			if err != nil || json.Unmarshal(marker, &fields) != nil || len(fields) != 4 || fields["schema_version"] != "system-backup-committed.v1" || fields["backup_public_id"] != backup || fields["manifest_checksum"] != manifest.SHA256 || fields["artifact_index_checksum"] != m.Index.Checksum {
				t.Fatal("marker changed exact existing v12 fields", err)
			}
			if _, ok := fields["marker_checksum"]; ok {
				t.Fatal("marker embedded its own checksum")
			}
		})
	}
}

func TestCommittedMarkerProductionGateRejectsUntypedPredecessor(t *testing.T) {
	service := &DeploymentService{}
	store := &nativePublicationS3{}
	claim := c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}, Owner: "controller:marker-DATA", RowVersion: 1}
	for _, object := range []nativePublicationObject{{}, {receipt: &publicationObjectReceipt{}}} {
		result, err := service.publishOriginalCommittedMarkerAfterManifest(context.Background(), claim, 1, store, object)
		if !errors.Is(err, c.ErrExecutionAuthority) || result.Key != "" {
			t.Fatal("ordinary public object/JSON receipt admitted marker", err)
		}
	}
	var proof *publicationPostManifestMarker
	if err := proof.recheckTx(context.Background(), nil, service, claim, 1, PublicationTargetMaterials{}, publicationJSONIntent{}); !errors.Is(err, c.ErrExecutionAuthority) {
		t.Fatal("missing marker proof/TX admitted")
	}
}
