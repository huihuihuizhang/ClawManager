package systembackupexecution

import "testing"

func TestProductionSameTaskOriginalAllSixPartsCaptureMySQL(t *testing.T) {
	runDOriginalSixPartCapture(t, false, true)
}
