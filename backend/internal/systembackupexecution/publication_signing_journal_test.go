package systembackupexecution

import (
	"context"
	"testing"

	c "clawreef/internal/systembackupcontroller"
)

func TestPublicationSigningJournalRejectsUncommittedProducer(t *testing.T) {
	for _, prepared := range []*preparedPublicationAcceptance{nil, {}, {intent: publicationAcceptanceSigningIntent{Version: "system-backup-original-acceptance-signing.v1"}}} {
		if result, err := prepared.SignCommitted(context.Background()); err == nil || result != nil {
			t.Fatal("missing real committed producer reached signer")
		}
		if _, err := prepared.expectedSend(); err == nil {
			t.Fatal("uncommitted input manufactured sent intent")
		}
		prepared.Close()
	}
	var service *DeploymentService
	if _, err := service.prepareOriginalPublicationAcceptance(context.Background(), nil); err == nil {
		t.Fatal("nil current proof prepared signing")
	}
	if _, err := service.publishOriginalPublicationAcceptance(context.Background(), nil); err == nil {
		t.Fatal("nil signature published acceptance")
	}
	if _, _, err := service.beginPublicationActionWithAcceptanceProof(context.Background(), c.ClaimToken{}, 1, PublicationTargetMaterials{}, publicationJSONIntent{}, nil, nil, nil, nil); err == nil {
		t.Fatal("nil service created publication")
	}
}

func TestPublicationSigningJournalIdentitySeparatesOriginalOperations(t *testing.T) {
	base := acceptanceSigningID("installation_one", "sbk_original", 1)
	seen := map[string]bool{base: true}
	for _, id := range []string{acceptanceSigningID("installation_two", "sbk_original", 1), acceptanceSigningID("installation_one", "sbk_other", 1), acceptanceSigningID("installation_one", "sbk_original", 2)} {
		if seen[id] {
			t.Fatal("another task/attempt/installation aliases original signature operation")
		}
		seen[id] = true
	}
	if base != acceptanceSigningID("installation_one", "sbk_original", 1) {
		t.Fatal("original operation has unstable identity")
	}
}
