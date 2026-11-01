package systembackupexecution

import (
	"testing"

	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
)

func TestOriginalDescriptionFactoryCannotRaiseOriginalTemplateByteCap(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	operation := operations[ce.Operation]
	operation.Formal.MaxFrames = 1024
	operation.Request.MaxArchiveBytes, _ = cd.Budget(1)
	operation.Request.MaxCompressedBytes = operation.Request.MaxArchiveBytes
	operations[cd.Operation] = operation
	if _, err := productionCaptureModules(in, source, hold, writers, operations, "original-declared-cap"); err == nil {
		t.Fatal("actual business set exceeded its independently declared original cap")
	}
}
