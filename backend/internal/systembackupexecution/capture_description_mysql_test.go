package systembackupexecution

import (
	"context"
	"encoding/json"
	"runtime/debug"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (f *dOriginalSixPartTask) capturePartCount() int {
	if f.captureDescription {
		return 11
	}
	return 10
}

// Follow the real startup order: formal mapping, real pinned publisher loader,
// then the D-enabled capture material. All of this precedes the FIRST Prepare
// and frozen source/context. The existing original grant times stay unchanged.
func (f *dOriginalSixPartTask) enableOriginalDescriptionBeforePrepare(ctx context.Context, t *testing.T) {
	t.Helper()
	s := f.service
	if s.Config.PublisherVerifier != nil && (s.publisherVerifier == nil || s.publisherVerifier.DescriptionMaxPlaintextBytes < 16<<20) {
		t.Fatal("real publisher material must be loaded before enabling original D template")
	}
	var description productionCaptureOperation
	raw, _ := json.Marshal(s.captureMaterials.Operations["capture-workspace"])
	if json.Unmarshal(raw, &description) != nil || description.Workload.FormalMaterials == nil {
		t.Fatal("original actual provider mapping template")
	}
	original, err := f.owner.Client.CoreV1().ConfigMaps(s.Config.Namespace).Get(ctx, description.Workload.FormalMaterials.ConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal("original actual mapping read", err)
	}
	var mapping worker.FormalCaptureMaterials
	if json.Unmarshal([]byte(original.Data["materials.json"]), &mapping) != nil || mapping.Sources != nil || mapping.Resources != nil || mapping.ControlEvidence != nil {
		t.Fatal("administrative mapping cannot inherit business source credentials")
	}
	mappingObject := original.DeepCopy()
	mappingObject.ObjectMeta = metav1.ObjectMeta{Name: "capture-description-materials", Namespace: s.Config.Namespace, UID: types.UID("capture-description-mapping-uid")}
	created, err := f.owner.Client.CoreV1().ConfigMaps(s.Config.Namespace).Create(ctx, mappingObject, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("local original description mapping declaration", err)
	}
	description.Workload.FormalMaterials.ConfigMap = created.Name
	description.Workload.Source, description.Workload.SourceSubPath = corev1.Volume{}, ""
	description.MountIdentities[0].Name, description.MountIdentities[0].UID, description.MountIdentities[0].SHA256 = created.Name, string(created.UID), kube.ContentHash([]any{created.Data, created.BinaryData})
	description.Request.MaxArchiveBytes, description.Request.MaxCompressedBytes = 16<<20, 16<<20
	description.Request.MaxFiles, description.Request.MaxFileBytes = 0, 0
	description.Formal.MaxFrames = 1024
	s.captureMaterials.Operations[cd.Operation] = description
	f.repinOriginalMetadataSource(t)
}

// Explicit NEW protocol variant, declared before original metadata/material
// signatures and Prepare. It adds one dedicated collector, never retrofits an
// old ten-worker capture. No original provider/key-use/hold TTL is extended.
func TestAOriginalSixPartDescriptionCaptureMySQL(t *testing.T) {
	// A declared local process resource allowance, not a key/source permission.
	previous := debug.SetMemoryLimit(4 << 30)
	defer debug.SetMemoryLimit(previous)
	runAOriginalSixPartCertificatePublication(t, "capture-description", func(ctx context.Context, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture) {
		if !capture.checked() || !formalCandidateDigest(capture.DescriptionSHA256) || len(capture.Parts) != 11 {
			t.Fatal("same-task description was not independently read and closed")
		}
		var descriptions int
		for _, p := range capture.Parts {
			if p.Part == cd.Part {
				descriptions++
				if p.Operation != cd.Operation || p.RequestedPart != "" || p.CipherPath != cd.CipherPath || p.EnvelopePath != cd.EnvelopePath {
					t.Fatal("dedicated administrative identity/path")
				}
			}
		}
		if descriptions != 1 {
			t.Fatal("missing or duplicate dedicated carrier")
		}
		policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
		bootstrap, err := f.service.prepareOriginalPublicationBootstrap(ctx, claim, capture.Input.CaptureAttemptNo, policy, capture)
		if err != nil || len(bootstrap) == 0 {
			t.Fatal("same original signed checkpoint bootstrap", err)
		}
		t.Log("same original task complete description C/certificate", f.publicID, capture.DescriptionSHA256)
	})
}
