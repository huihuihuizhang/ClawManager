package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
)

func checkComponentMaterialOutputs(t *testing.T, f *materialProducerComponent) (productionCaptureMaterials, []byte) {
	t.Helper()
	raw, err := os.ReadFile(f.core.CaptureModules.Path)
	var materials productionCaptureMaterials
	if err != nil || decodeMetadataCanonical(raw, &materials) != nil || materials.Discovery == nil || materials.Discovery.Redis.Policy.Purpose != "functional_test" || len(materials.Operations) != 7 {
		t.Fatal("actual complete material bytes/purpose", err)
	}
	public := ed25519.PrivateKey(f.key).Public().(ed25519.PublicKey)
	for _, mount := range []worker.FormalSourceMount{materials.Redis, materials.Objects} {
		envelopeRaw, err := os.ReadFile(mount.GrantFile)
		var envelope worker.SignedFormalSourceGrant
		var grant worker.FormalSourceGrant
		if err != nil || hash(envelopeRaw) != mount.GrantSHA256 || decodeMetadataCanonical(envelopeRaw, &envelope) != nil || decodeMetadataCanonical(envelope.Record, &grant) != nil || !ed25519.Verify(public, append([]byte(worker.FormalSourceGrantDomain), envelope.Record...), envelope.Signature) || !grant.NotBefore.Equal(f.definition.NotBefore) || !grant.Until.Equal(f.definition.Until) || grant.ConfigSHA256 != f.definition.ConfigSHA256 || grant.CredentialSHA256 != mount.CredentialSHA256 {
			t.Fatal("actual original worker grant signature/window/bindings", err)
		}
		want, err := producerWorkerScope(materials, grant.Operation)
		if err != nil || want != grant.ScopeSHA256 {
			t.Fatal("worker scope changed during actual issuance", err)
		}
	}
	metadataRaw, err := os.ReadFile(materials.Discovery.GrantFile)
	var envelope signedSourceMetadataGrant
	var grant originalSourceMetadataGrant
	want, scopeErr := sourceMetadataScope(materials)
	if err != nil || scopeErr != nil || hash(metadataRaw) != materials.Discovery.GrantSHA256 || decodeMetadataCanonical(metadataRaw, &envelope) != nil || decodeMetadataCanonical(envelope.Record, &grant) != nil || !ed25519.Verify(public, append([]byte(sourceMetadataGrantDomain), envelope.Record...), envelope.Signature) || grant.ScopeSHA256 != want || !grant.NotBefore.Equal(f.definition.NotBefore) || !grant.Until.Equal(f.definition.Until) || grant.DeploymentConfigSHA256 != f.definition.CoreSHA256 || grant.CaptureGrantSHA256 != f.definition.ForwardGrantSHA256 {
		t.Fatal("actual metadata signature/scope/original window", err)
	}
	return materials, raw
}

func TestOriginalMaterialProducerFullSigningAndLocalConsumerComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	queries := f.model.queries.Load()
	receipt, err := ProduceOriginalCaptureMaterials(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
	if err != nil || receipt.Purpose != "functional_test" || receipt.File != f.core.CaptureModules.Path || !receipt.NotBefore.Equal(f.definition.NotBefore) || !receipt.Until.Equal(f.definition.Until) || f.model.queries.Load() <= queries {
		t.Fatal("complete real producer call with actual A authenticated source", err)
	}
	materials, raw := checkComponentMaterialOutputs(t, f)
	if hash(raw) != receipt.SHA256 {
		t.Fatal("public receipt did not identify the actual complete output")
	}
	// Independent ordinary production consumer load of the actual generated
	// files. This is the real local bundle loader, not whole-service readiness.
	consumer := &DeploymentService{ForwardEnabled: true, Config: f.core, ConfigPath: f.definition.CoreFile, ConfigDigest: f.definition.CoreSHA256, Forward: f.forward}
	if consumer.loadProductionCapture([]ProductionCaptureInput{{File: receipt.File, SHA256: receipt.SHA256}}) != nil || consumer.checkProductionCaptureMaterials() != nil {
		t.Fatal("actual consumer rejected producer output")
	}
	if consumer.captureMaterials == nil || consumer.captureMaterials.Discovery.GrantSHA256 != materials.Discovery.GrantSHA256 {
		t.Fatal("consumer loaded different material/signatures")
	}
	second, err := ProduceOriginalCaptureMaterials(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
	after, readErr := os.ReadFile(receipt.File)
	if err != nil || readErr != nil || second != receipt || !bytes.Equal(after, raw) || f.model.executions.Load() != 0 || f.model.openTx.Load() != 0 || f.enrollmentWrites.Load() != 1 {
		t.Fatal("deterministic original retry mutated SQL/enrollment/window/bytes", err, readErr)
	}
	// Consumer hash drift is rejected; this changes only the test-owned file,
	// never re-signs/renews the original declaration or uses a success DTO.
	if err := os.WriteFile(receipt.File, append(append([]byte{}, raw...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if consumer.checkProductionCaptureMaterials() == nil {
		t.Fatal("consumer accepted altered actual bundle bytes")
	}
}

func TestOriginalMaterialProducerRejectsOriginalSQLWindowTailAfterOutputComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	deadline, _ := ctx.Deadline()
	if !f.model.afterSourceWindow.After(f.definition.Until) || !f.model.afterSourceWindow.Before(deadline) {
		t.Fatal("tail injection must exceed ORIGINAL grant window while operator/context remain valid")
	}
	f.armTail.Store(true)
	receipt, err := ProduceOriginalCaptureMaterials(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
	if err == nil || receipt != (ProductionMaterialReceipt{}) || !f.tailReached.Load() || !f.model.clockBeyondOriginalWindow.Load() {
		t.Fatal("did not reach/reject the actual post-output original SQL window tail", err)
	}
	// Four actual complete signed files existed before the model advanced the
	// SQL clock. Verify signatures and their unchanged original Until; their
	// presence is explicitly not a successful producer receipt or activation.
	checkComponentMaterialOutputs(t, f)
	originalFiles := map[string][]byte{}
	for _, path := range f.outputs {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		originalFiles[path] = raw
	}
	if retry, retryErr := ProduceOriginalCaptureMaterials(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile); retryErr == nil || retry != (ProductionMaterialReceipt{}) {
		t.Fatal("failed original window was renewed or treated as a successful retry", retryErr)
	}
	for path, original := range originalFiles {
		actual, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(actual, original) {
			t.Fatal("tail failure/retry changed or deleted original output", readErr)
		}
	}
	definitionRaw, readErr := os.ReadFile(f.definitionFile)
	var original ProductionMaterialDefinition
	if readErr != nil || json.Unmarshal(definitionRaw, &original) != nil || hash(definitionRaw) != f.definitionSHA || !original.Until.Equal(f.definition.Until) || f.model.executions.Load() != 0 || f.model.openTx.Load() != 0 || f.enrollmentWrites.Load() != 1 {
		t.Fatal("tail failure rewrote original declaration/state", readErr)
	}
}
