package systembackupexecution

import (
	sec "clawreef/internal/systembackupsecurity"
	"testing"
)

func TestMinIOConfigMutationReferencesRequireSameSixOriginalPins(t *testing.T) {
	wanted := []sec.BootstrapSecretRef{}
	for _, purpose := range []string{"artifact_read", "artifact_write", "artifact_delete", "catalog_read", "catalog_append", "catalog_snapshot"} {
		wanted = append(wanted, sec.BootstrapSecretRef{Purpose: purpose, IdentityHash: hash([]byte(purpose)), Version: "original-v1"})
	}
	if !minioMutationReferencesMatch(wanted, wanted, wanted) {
		t.Fatal("same original six pins refused")
	}
	changed := append([]sec.BootstrapSecretRef(nil), wanted...)
	changed[5].Version = "foreign-v2"
	if minioMutationReferencesMatch(wanted, changed, wanted) {
		t.Fatal("snapshot rotation silently authorized")
	}
	changed = append([]sec.BootstrapSecretRef(nil), wanted...)
	changed[0].IdentityHash = wanted[1].IdentityHash
	if minioMutationReferencesMatch(wanted, changed, wanted) {
		t.Fatal("purpose substitution silently authorized")
	}
	if minioMutationReferencesMatch(wanted, wanted[:5], wanted) || minioMutationReferencesMatch(append(wanted, wanted[0]), wanted, wanted) {
		t.Fatal("missing or duplicate pin admitted")
	}
}
