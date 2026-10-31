package main

import "testing"

func TestConfiguredPublicStartupCarriesIndependentPublicationPin(t *testing.T) {
	for _, key := range []string{"SYSTEM_BACKUP_VERIFIER_MATERIALS_FILE", "SYSTEM_BACKUP_VERIFIER_MATERIALS_SHA256", "SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_FILE", "SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_SHA256", "SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_FILE", "SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_SHA256"} {
		t.Setenv(key, "")
	}
	t.Setenv("POD_NAME", "original-controller-pod")
	if got := configuredPublicStartupInputs(); len(got.PublicationSigners) != 0 || len(got.FormalVerifier) != 0 || got.ControllerPodName != "original-controller-pod" {
		t.Fatal("absent optional material changed original startup identity")
	}
	t.Setenv("SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_FILE", "independent-publication.json")
	t.Setenv("SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_SHA256", "external-deployment-pin")
	t.Setenv("SYSTEM_BACKUP_VERIFIER_MATERIALS_FILE", "independent-verifier.json")
	t.Setenv("SYSTEM_BACKUP_VERIFIER_MATERIALS_SHA256", "verifier-pin")
	got := configuredPublicStartupInputs()
	if len(got.PublicationSigners) != 1 || got.PublicationSigners[0].File != "independent-publication.json" || got.PublicationSigners[0].SHA256 != "external-deployment-pin" || len(got.FormalVerifier) != 1 || got.FormalVerifier[0].SHA256 != "verifier-pin" {
		t.Fatal("real public startup lost independent inputs")
	}
	t.Setenv("SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_FILE", "independent-publisher.json")
	t.Setenv("SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_SHA256", "independent-owner-secret-pin")
	got = configuredPublicStartupInputs()
	if len(got.PublisherVerifier) != 1 || got.PublisherVerifier[0].File != "independent-publisher.json" || got.PublisherVerifier[0].SHA256 != "independent-owner-secret-pin" {
		t.Fatal("actual CLI lost independently injected publisher input")
	}
}
