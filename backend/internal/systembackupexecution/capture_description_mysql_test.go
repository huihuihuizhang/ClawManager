package systembackupexecution

import (
	"context"
	"runtime/debug"
	"testing"
	"time"

	cd "clawreef/internal/systembackupcapturedescription"
	c "clawreef/internal/systembackupcontroller"
)

func (f *dOriginalSixPartTask) capturePartCount() int {
	if f.captureDescription {
		return 11
	}
	return 10
}

// Explicit NEW protocol variant, declared before original metadata/material
// signatures and Prepare. It adds one dedicated collector, never retrofits an
// old ten-worker capture. No original provider/key-use/hold TTL is extended.
func TestAOriginalSixPartDescriptionCaptureMySQL(t *testing.T) {
	// A declared local process resource allowance, not a key/source permission.
	previous := debug.SetMemoryLimit(4 << 30)
	defer debug.SetMemoryLimit(previous)
	runAOriginalSixPartCertificatePublication(t, "capture-description", func(ctx context.Context, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture) {
		if !capture.checked() || !formalCandidateDigest(capture.DescriptionSHA256) || len(capture.Parts) != 11 {
			t.Fatal("same-task description was not independently read and closed")
		}
		var descriptions int
		for _, p := range capture.Parts {
			if p.Part == cd.Part {
				descriptions++
				if p.Operation != cd.Operation || p.RequestedPart != "" || p.CipherPath != cd.CipherPath || p.EnvelopePath != cd.EnvelopePath {
					t.Fatal("dedicated administrative identity/path")
				}
			}
		}
		if descriptions != 1 {
			t.Fatal("missing or duplicate dedicated carrier")
		}
		policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
		bootstrap, err := f.service.prepareOriginalPublicationBootstrap(ctx, claim, capture.Input.CaptureAttemptNo, policy, capture)
		if err != nil || len(bootstrap) == 0 {
			t.Fatal("same original signed checkpoint bootstrap", err)
		}
		t.Log("same original task complete description C/certificate", f.publicID, capture.DescriptionSHA256)
	})
}
