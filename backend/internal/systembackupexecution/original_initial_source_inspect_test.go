package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInitialSourceInspectionDoesNotExposeRejectedValues(t *testing.T) {
	secret := "fixture-credential-never-print"
	for _, raw := range []string{`{"UnknownField":"` + secret + `"}`, `{"Version":123,"ignored":"` + secret + `"}`} {
		r := InspectOriginalInitialSourceDefinition([]byte(raw), "/fixture-only/not-created")
		body, err := json.Marshal(r)
		if err != nil || strings.Contains(string(body), secret) || r.DefinitionDecoded || r.NativeAuthorCalled || r.BackupReady {
			t.Fatalf("unsafe definition diagnostic")
		}
	}
}

func TestInitialSourceInspectionDoesNotTreatEmptyDefinitionAsQualified(t *testing.T) {
	r := InspectOriginalInitialSourceDefinition([]byte(`{}`), "/fixture-only/not-created")
	if !r.DefinitionDecoded || r.DeploymentValid || r.ProfileValid || r.OutputPathsMatch || r.MaterialsValid || r.NativeAuthorCalled || r.BackupReady {
		t.Fatal("empty definition gained authority")
	}
}

func TestInitialSourceInspectionReportsOnlyMaterialField(t *testing.T) {
	secret := "fixture-material-secret-never-print"
	r := InspectOriginalInitialSourceDefinition([]byte(`{"Materials":{"UnknownTemplateField":"`+secret+`"}}`), "/fixture-only/not-created")
	body, err := json.Marshal(r)
	if err != nil || !r.DefinitionDecoded || r.MaterialsDecoded || r.Stage != "materials_decode" || r.Field != "UnknownTemplateField" || strings.Contains(string(body), secret) || r.NativeAuthorCalled || r.BackupReady {
		t.Fatal("unsafe material diagnostic")
	}
}
