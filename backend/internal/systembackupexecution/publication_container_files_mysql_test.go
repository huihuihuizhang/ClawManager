package systembackupexecution

import (
	"bytes"
	"context"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// Actual same task and current complete C receipt. This exercises durable
// private file preparation/reopen, not a fabricated MF, publish Job or terminal.
func TestAOriginalSixPartDurableContainerInputsMySQL(t *testing.T) {
	runAOriginalSixPartCertificatePublication(t, "current", func(ctx context.Context, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture) {
		policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
		first, err := f.service.preparePublicationContainerFiles(ctx, claim, capture.Input.CaptureAttemptNo, policy, capture)
		if err != nil || len(first.Files) != 6 {
			t.Fatal("actual durable original container inputs", err)
		}
		before, err := ce.Canonical(first)
		if err != nil {
			t.Fatal(err)
		}
		again, err := f.service.preparePublicationContainerFiles(ctx, claim, capture.Input.CaptureAttemptNo, policy, capture)
		after, encodeErr := ce.Canonical(again)
		if err != nil || encodeErr != nil || !bytes.Equal(before, after) {
			t.Fatal("same original file receipt retry drifted", err, encodeErr)
		}
		objects := map[string]PublicationUploadInput{}
		var physical int64
		for _, file := range first.Files {
			objects[file.Path] = PublicationUploadInput{Path: file.Path, SHA256: file.Receipt.SHA256, Bytes: file.Receipt.Size}
			physical += file.Receipt.Size
		}
		inputs, err := f.service.loadPublicationContainerJobInputs(ctx, *claim, capture.Input.CaptureAttemptNo, objects)
		if err != nil || len(inputs) != 6 || len(objects) != 0 {
			t.Fatal("current original durable input readback for Job definition", err)
		}
		var actions, jobs, records int
		id := publicationContainerPlanID(capture.Input.InstallationID, capture.Input.TaskPublicID, capture.Input.CaptureAttemptNo)
		if f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_public_id=?`, f.publicID).Scan(&actions) != nil || f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_job_send_intents WHERE task_public_id=? AND phase='publish'`, f.publicID).Scan(&jobs) != nil || f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id IN (?,?)`, id, id+"_files").Scan(&records) != nil || actions != 0 || jobs != 0 || records != 2 {
			t.Fatal("private preparation emitted a send or lost original receipts", actions, jobs, records)
		}
		t.Log("actual same original six durable containers and exact reopen; no publish send", f.publicID, physical, id)
	})
}
