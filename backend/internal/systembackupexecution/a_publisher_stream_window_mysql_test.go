package systembackupexecution

import (
	"context"
	"io"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
	s "clawreef/internal/systembackupsecurity"
	w "clawreef/internal/systembackupwire"
)

type aDelayedCiphertext struct {
	io.Reader
	delay   time.Duration
	started bool
}

func (r *aDelayedCiphertext) Read(p []byte) (int, error) {
	if !r.started {
		r.started = true
		time.Sleep(r.delay)
	}
	return r.Reader.Read(p)
}

// Actual 1.5MiB incompressible workspace archive, original encrypted frames,
// exact original envelope, original SQL/history/new claim and TLS provider.
// This is full cipher-frame authentication, not six-domain/terminal acceptance.
func TestAPublisherOriginalStreamCrossesTokenTTLWithinFixedDEKWindow(t *testing.T) {
	x := newAPublisherVerifierFixtureOptions(t, aPublisherVerifierFixtureOptions{SourceBytes: 3 << 19})
	h := x.history
	ctx := context.Background()
	verifier, err := x.factory.ForPart(ctx, h.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	until := verifier.ValidUntil()
	bound, err := verifier.ForEnvelope(ctx, x.envelope)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := h.owner.Staging.OpenRoot(h.original.TaskPublicID)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	source, err := staging.OpenFile(ctx, stage, h.candidate.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	delayed := &aDelayedCiphertext{Reader: source, delay: 1500 * time.Millisecond}
	invocation := h.invocation
	spec := w.StreamSpec{Request: verifier.ExpectedRequest(), Path: invocation.Request.ArtifactName, MaxPlaintextBytes: invocation.Request.MaxCompressedBytes, MaxFrames: invocation.FormalCapture.MaxFrames}
	inspected := int64(0)
	result, err := w.InspectWrappedStream(ctx, spec, x.envelope, delayed, bound, func(reader io.Reader) error { var err error; inspected, err = io.Copy(io.Discard, reader); return err })
	if err != nil || !delayed.started || inspected <= 1<<20 || result.CiphertextSHA256() != h.candidate.Ciphertext.SHA256 || result.CiphertextBytes() != h.candidate.Ciphertext.Size {
		t.Fatal("entire original encrypted object failed within independent DEK permission", err, inspected)
	}
	if time.Since(time.Unix(0, x.credentialIssuedAt.Load())) <= time.Second || !time.Now().Before(until) || !verifier.ValidUntil().Equal(until) || x.logins.Load() != 1 || x.decrypts.Load() != 1 {
		t.Fatal("positive did not cross real 1s credential TTL within same fixed DEK window")
	}
	if verifier.Recheck(ctx) != nil {
		t.Fatal("current unchanged permission failed after complete frame authentication")
	}
}

func TestAPublisherOriginalStreamRejectsFixedDEKWindowExpiryWithoutAdoption(t *testing.T) {
	x := newAPublisherVerifierFixtureOptions(t, aPublisherVerifierFixtureOptions{SourceBytes: 3 << 19, CapabilityWindow: 5 * time.Second})
	h := x.history
	ctx := context.Background()
	verifier, err := x.factory.ForPart(ctx, h.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	until := verifier.ValidUntil()
	bound, err := verifier.ForEnvelope(ctx, x.envelope)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := h.owner.Staging.OpenRoot(h.original.TaskPublicID)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	source, err := staging.OpenFile(ctx, stage, h.candidate.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	delayed := &aDelayedCiphertext{Reader: source, delay: 6 * time.Second}
	invocation := h.invocation
	result, err := w.InspectWrappedStream(ctx, w.StreamSpec{Request: verifier.ExpectedRequest(), Path: invocation.Request.ArtifactName, MaxPlaintextBytes: invocation.Request.MaxCompressedBytes, MaxFrames: invocation.FormalCapture.MaxFrames}, x.envelope, delayed, bound, func(reader io.Reader) error { _, err := io.Copy(io.Discard, reader); return err })
	if err == nil || !delayed.started || result.CiphertextSHA256() != "" || result.CiphertextBytes() != 0 || time.Now().Before(until) || !verifier.ValidUntil().Equal(until) {
		t.Fatal("expired fixed DEK use produced an accepted stream result", err)
	}
	if x.logins.Load() != 1 || x.decrypts.Load() != 1 || verifier.Recheck(ctx) == nil {
		t.Fatal("expired stream was retried or old permission adopted")
	}
	// Prove the CURRENT real task claim remains live; the shorter original
	// capability is the exhausted permission, not a synthetic task expiry.
	var live bool
	if h.db.QueryRow("SELECT controller_lease_expires_at>UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&live) != nil || !live {
		t.Fatal("negative did not retain independently live claim")
	}
	fresh, err := c.RenewClaimInInstallation(ctx, h.db, h.original.InstallationID, h.token, c.LeasePolicy{TTL: 45 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	scope := h.scope
	scope.Claim = s.SQLSigningClaim{ControllerOwner: fresh.Owner, RowVersion: fresh.RowVersion}
	if _, err = x.factory.ForPart(ctx, scope); err == nil || x.logins.Load() != 1 || x.decrypts.Load() != 1 {
		t.Fatal("fresh claim silently extended expired original unwrap permission")
	}
	var status string
	if h.db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&status) != nil || status != "validating" {
		t.Fatal("stream crypto boundary fabricated publication terminal state")
	}
}
