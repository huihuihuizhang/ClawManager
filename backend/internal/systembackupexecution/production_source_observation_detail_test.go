package systembackupexecution

import (
	"bytes"
	d "clawreef/internal/systembackupdispatch"
	"log"
	"strings"
	"testing"
)

func TestSourceObservationDetailDiagnosticsPreservePublicErrorAndClosedVocabulary(t *testing.T) {
	previous := log.Writer()
	var output bytes.Buffer
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	for _, detail := range []sourceObservationDetail{sourceSQLClockRead, sourceSQLClockWindow, sourceInventoryBaseline, sourceInventoryUsersEOF, sourceInventoryMetadataDrift, sourceInventoryDeadline, 255} {
		if sourceObservationDetailRejected(detail) != d.ErrNotReady {
			t.Fatal("detail logging changed public rejection")
		}
	}
	for _, label := range []string{
		"stage=source-sql-observation boundary=clock-read status=rejected",
		"stage=source-sql-observation boundary=clock-original-window status=rejected",
		"stage=source-inventory boundary=baseline-observation status=rejected",
		"stage=source-inventory boundary=users-eof status=rejected",
		"stage=source-inventory boundary=metadata-drift status=rejected",
		"stage=source-inventory boundary=original-deadline status=rejected",
		"stage=unknown-source-boundary boundary=unknown-detail status=rejected",
	} {
		if strings.Count(output.String(), label) != 1 {
			t.Fatal("fixed detail boundary missing or duplicated", label)
		}
	}
	if strings.Count(output.String(), "status=rejected") != 7 {
		t.Fatal("unexpected diagnostic content")
	}
}
