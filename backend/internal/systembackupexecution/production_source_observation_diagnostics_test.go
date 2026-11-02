package systembackupexecution

import (
	"bytes"
	"log"
	"strings"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

func TestSourceObservationDiagnosticsKeepOriginalErrorAndFixedLabels(t *testing.T) {
	writer := log.Writer()
	var output bytes.Buffer
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(writer) })
	for _, stage := range []sourceObservationStage{sourceObserverBindings, sourceObserverController, sourceObserverSQLMetadata, sourceObserverResources, 255} {
		if sourceObservationRejected(stage) != d.ErrNotReady {
			t.Fatal("diagnostics changed public rejection")
		}
	}
	for _, label := range []string{"observer-bindings", "controller-workload", "source-sql-schema-metadata", "resource-metadata", "unknown-source-boundary"} {
		if !strings.Contains(output.String(), "stage="+label+" status=rejected") {
			t.Fatal("fixed boundary diagnostic missing", label)
		}
	}
}
