package systembackupexecution

import (
	"errors"
	"math"
	"runtime/debug"
	"testing"

	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
)

func TestDescriptionProductionStartupRequiresExplicitControllerAndPublisherMemory(t *testing.T) {
	original := debug.SetMemoryLimit(math.MaxInt64)
	defer debug.SetMemoryLimit(original)
	for _, mode := range []string{"disabled", "undeclared", "insufficient", "current", "missing-publisher-cap", "low-publisher-cap", "invalid-template"} {
		t.Run(mode, func(t *testing.T) {
			debug.SetMemoryLimit(4 << 30)
			s := &DeploymentService{Config: DeploymentConfig{PublisherVerifier: &PublisherVerifierReference{}}, publisherVerifier: &PublisherVerifierMaterials{DescriptionMaxPlaintextBytes: 16 << 20}}
			materials := productionCaptureMaterials{Operations: map[string]productionCaptureOperation{cd.Operation: {Request: worker.Request{MaxArchiveBytes: 16 << 20, MaxCompressedBytes: 16 << 20}}}}
			switch mode {
			case "disabled":
				materials.Operations = map[string]productionCaptureOperation{}
				debug.SetMemoryLimit(math.MaxInt64)
			case "undeclared":
				debug.SetMemoryLimit(math.MaxInt64)
			case "insufficient":
				debug.SetMemoryLimit(128 << 20)
			case "missing-publisher-cap":
				s.publisherVerifier.DescriptionMaxPlaintextBytes = 0
			case "low-publisher-cap":
				s.publisherVerifier.DescriptionMaxPlaintextBytes = 8 << 20
			case "invalid-template":
				operation := materials.Operations[cd.Operation]
				operation.Request.MaxArchiveBytes = 0
				materials.Operations[cd.Operation] = operation
			}
			err := s.validateDescriptionMemoryStartup(materials)
			if mode == "current" || mode == "disabled" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, cd.ErrMemoryDeclaration) {
				t.Fatal("startup did not reject explicit resource declaration", err)
			}
		})
	}
	debug.SetMemoryLimit(math.MaxInt64)
	if err := (PublisherVerifierMaterials{DescriptionMaxPlaintextBytes: 16 << 20}).validateDescriptionMemoryDeclaration(); !errors.Is(err, cd.ErrMemoryDeclaration) {
		t.Fatal("publisher startup admitted unbounded process", err)
	}
}
