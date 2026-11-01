package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	"context"
	"errors"
	"testing"
)

func TestOriginalCandidateCleanupCannotUseUnregisteredExitOrOrdinaryMarker(t *testing.T) {
	service := &DeploymentService{}
	store := &nativePublicationS3{config: PublicationTargetMaterials{DeleteIdentityHash: hash([]byte("delete mapping DATA"))}}
	claim := c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}, Owner: "publisher-original", RowVersion: 1}
	for _, exit := range []*publicationUploadExit{nil, {}, {service: service, claim: claim, attempt: 1, marker: nativePublicationObject{receipt: &publicationObjectReceipt{postManifestMarker: &publicationPostManifestMarker{}}}}} {
		result, err := service.cleanupOriginalPublicationCandidate(context.Background(), claim, 1, store, exit)
		if !errors.Is(err, c.ErrExecutionAuthority) || result != nil {
			t.Fatal("ordinary marker/prepared exit authorized DELETE", err)
		}
	}
	var proof *publicationCandidateCleanup
	if err := proof.recheckPredecessorsTx(context.Background(), nil); !errors.Is(err, c.ErrExecutionAuthority) {
		t.Fatal("missing original SQL proof accepted")
	}
}
