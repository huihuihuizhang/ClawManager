package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	"k8s.io/client-go/kubernetes/fake"
)

func TestOriginalCaptureInstallationRejectsFilledGrantBeforeIssuingComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	var original productionCaptureMaterials
	if json.Unmarshal(f.definition.Materials, &original) != nil {
		t.Fatal("original declaration")
	}
	template := OriginalCaptureMappingDefinition{Version: OriginalCaptureInstallationTemplateVersion, OriginalDefinitionSHA256: f.definitionSHA, Files: []OriginalCaptureMappingFile{{WorkerPath: original.Redis.GrantFile, File: "caller-grant", SHA256: hash([]byte("caller-grant"))}, {WorkerPath: original.Objects.GrantFile}}}
	input := writeInstallationTemplateComponent(t, f, template)
	before := f.model.queries.Load()
	if _, err := InstallOriginalCaptureMappings(ctx, f.installer, fake.NewSimpleClientset(), f.password, f.enrollment, input); err == nil || f.model.queries.Load() != before {
		t.Fatal("filled template grant issued before validation", err)
	}
	for _, name := range f.outputs {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatal("preflight published a source output", err)
		}
	}
}

func TestOriginalCaptureInstallationUsesActualSequenceAndRetainsIssuedGrantsOnFailureComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	var original productionCaptureMaterials
	if json.Unmarshal(f.definition.Materials, &original) != nil {
		t.Fatal("original declaration")
	}
	// Exact declared grant placeholders; deliberately absent KMS owner inputs.
	// The real sequence issues both actual grants, then materialization refuses.
	template := OriginalCaptureMappingDefinition{Version: OriginalCaptureInstallationTemplateVersion, OriginalDefinitionSHA256: f.definitionSHA, Files: []OriginalCaptureMappingFile{{WorkerPath: original.Redis.GrantFile}, {WorkerPath: original.Objects.GrantFile}}}
	input := writeInstallationTemplateComponent(t, f, template)
	client := fake.NewSimpleClientset()
	if receipt, err := InstallOriginalCaptureMappings(ctx, f.installer, client, f.password, f.enrollment, input); err == nil || receipt != (ProductionMaterialReceipt{}) {
		t.Fatal("missing actual component owners became a completed bundle", err)
	}
	for _, mount := range []worker.FormalSourceMount{original.Redis, original.Objects} {
		raw, err := os.ReadFile(mount.GrantFile)
		var signed worker.SignedFormalSourceGrant
		var grant worker.FormalSourceGrant
		if err != nil || decodeMetadataCanonical(raw, &signed) != nil || decodeMetadataCanonical(signed.Record, &grant) != nil || !ed25519.Verify(mount.Issuer, append([]byte(worker.FormalSourceGrantDomain), signed.Record...), signed.Signature) || !grant.Until.Equal(f.definition.Until) {
			t.Fatal("entry did not retain actual original sequence grant", err)
		}
	}
	resolved, err := os.ReadFile(input.ResolvedComponentsFile)
	var components OriginalCaptureMappingDefinition
	if err != nil || decodeMetadataCanonical(resolved, &components) != nil || components.Version != OriginalCaptureMappingDefinitionVersion {
		t.Fatal("actual resolved component stage", err)
	}
	for _, file := range components.Files {
		actual, err := os.ReadFile(file.File)
		if err != nil || file.WorkerPath != file.File || hash(actual) != file.SHA256 {
			t.Fatal("resolved source grant pin was fabricated", err)
		}
	}
	for _, name := range []string{input.IntermediateFile, original.Discovery.GrantFile, f.core.CaptureModules.Path} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatal("failed stage published final metadata", err)
		}
	}
	if len(client.Actions()) != 0 || f.model.executions.Load() != 0 {
		t.Fatal("incomplete owners mutated Kube/SQL")
	}
}

func writeInstallationTemplateComponent(t *testing.T, f *materialProducerComponent, template OriginalCaptureMappingDefinition) OriginalCaptureInstallationInputs {
	t.Helper()
	directory := filepath.Dir(f.definitionFile)
	raw, err := json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "installation-template.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return OriginalCaptureInstallationInputs{DefinitionFile: f.definitionFile, DefinitionSHA256: f.definitionSHA, IssuerPrivateFile: f.privateFile, TemplateFile: file, TemplateSHA256: hash(raw), ResolvedComponentsFile: filepath.Join(directory, "resolved-components.json"), IntermediateFile: filepath.Join(directory, "installation-intermediate.json")}
}
