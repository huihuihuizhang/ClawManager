package systembackupexecution

import (
	"testing"

	ma "clawreef/internal/systembackupminioauthority"
)

func TestDeleteCompatPublicationRuleScope(t *testing.T) {
	const bucket, root, staging = "owned-artifacts", "installation/", "installation_staging/"
	newRules, err := minioPermissionObjectRulesForProfile(ma.DeleteCompatPermissionProfile, "artifact_delete", bucket, root, staging)
	if err != nil {
		t.Fatal(err)
	}
	if len(newRules) != 1 || len(newRules[0].Actions) != 1 || newRules[0].Actions[0] != "s3:DeleteObjectVersion" ||
		len(newRules[0].Resources) != 1 || newRules[0].Resources[0] != "arn:aws:s3:::owned-artifacts/installation_staging/*" {
		t.Fatal("delete-compat must permit only exact versions in staging")
	}
	for _, profile := range []string{ma.PermissionProfile, ma.SeptemberPermissionProfile} {
		legacy, err := minioPermissionObjectRulesForProfile(profile, "artifact_delete", bucket, root, staging)
		if err != nil {
			t.Fatal(err)
		}
		policy, pin, err := nativeInstallPolicy(legacy)
		if err != nil {
			t.Fatal(err)
		}
		if len(legacy) != 1 || len(legacy[0].Actions) != 2 || legacy[0].Actions[0] != "s3:DeleteObject" ||
			legacy[0].Actions[1] != "s3:DeleteObjectVersion" || len(legacy[0].Resources) != 1 ||
			legacy[0].Resources[0] != "arn:aws:s3:::owned-artifacts/installation_staging/*" {
			t.Fatalf("legacy rule changed for %s", profile)
		}
		if _, err := minioPermissionNormalizedPolicyV2(policy, pin, newRules); err == nil {
			t.Fatalf("delete-compat accepted broader %s policy with a matching pin", profile)
		}
	}
	if _, err := minioPermissionObjectRulesForProfile(ma.DeleteCompatPermissionProfile, "artifact_delete", bucket, root, ""); err == nil {
		t.Fatal("delete-compat accepted missing staging scope")
	}
	if _, err := minioPermissionObjectRulesForProfile("unsupported", "artifact_delete", bucket, root, staging); err == nil {
		t.Fatal("unknown profile selected publication rules")
	}
}
