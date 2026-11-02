package systembackupexecution

import (
	"context"
	"strings"
	"testing"

	c "clawreef/internal/systembackupcontroller"
	"github.com/google/uuid"
)

func TestPublicationCatalogSigningJournalRejectsUncommittedProducer(t *testing.T) {
	for _, prepared := range []*preparedPublicationCatalog{nil, {}, {intent: publicationCatalogSigningIntent{Version: "system-backup-original-catalog-signing.v1"}}, {accepted: &publicationAcceptedObject{signed: &publicationSignedAcceptance{prepared: &preparedPublicationAcceptance{}}}}} {
		if result, err := prepared.SignCommitted(context.Background()); err == nil || result != nil {
			t.Fatal("missing real committed predecessor reached signer")
		}
		if _, err := prepared.expectedSend(); err == nil {
			t.Fatal("uncommitted catalog input manufactured sent intent")
		}
		prepared.Close()
	}
	var service *DeploymentService
	if _, err := service.prepareOriginalPublicationCatalog(context.Background(), nil); err == nil {
		t.Fatal("nil current accepted proof prepared catalog")
	}
	if _, err := service.publishOriginalPublicationCatalog(context.Background(), nil); err == nil {
		t.Fatal("nil signature published catalog")
	}
	if _, _, err := service.beginPublicationActionWithCatalogProof(context.Background(), c.ClaimToken{}, 1, PublicationTargetMaterials{}, publicationJSONIntent{}, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("nil service created catalog")
	}
}

func TestPublicationCatalogSigningJournalIdentitySeparatesOriginalOperations(t *testing.T) {
	installation, backup := "installation_one", "sbk_original"
	base := catalogSigningID(installation, backup, 1)
	seen := map[string]bool{base: true}
	for _, id := range []string{catalogSigningID("installation_two", backup, 1), catalogSigningID(installation, "sbk_other", 1), catalogSigningID(installation, backup, 2), acceptanceSigningID(installation, backup, 1)} {
		if seen[id] {
			t.Fatal("another operation aliases original catalog signing root")
		}
		seen[id] = true
	}
	identity := []byte(`["original-publication-registration.v1","installation_one","sbk_original",1,"artifact_registered"]`)
	want := "scr_" + uuid.NewSHA1(uuid.NameSpaceURL, identity).String()
	if base != "sev_pub_catalog_"+hash(identity) || publicationCatalogRecordID(installation, backup, 1) != want {
		t.Fatal("approved stable identity recipe drifted")
	}
	material := PublicationCatalogMaterials{InstallationID: installation, Root: installation + "/catalog/"}
	if key := publicationCatalogKey(material, backup, 1); key != material.Root+"registrations/"+want+".json" || strings.Count(key, installation) != 1 {
		t.Fatal("registration key drifted or duplicated installation root", key)
	}
	if len(want) > 128 || !strings.HasPrefix(want, "scr_") {
		t.Fatal("record id exceeds terminal SQL boundary")
	}
}
