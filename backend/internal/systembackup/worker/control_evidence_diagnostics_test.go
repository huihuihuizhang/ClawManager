package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

func TestControlEvidenceRejectDiagnosticOmitsPrivateInput(t *testing.T) {
	var output bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer log.SetOutput(previous)
	defer log.SetFlags(flags)
	secret := "PRIVATE_REQUEST_AND_TOKEN_MUST_NOT_APPEAR"
	err := captureControlEvidence(context.Background(), Invocation{Request: Request{ArtifactName: secret}}, nil, io.Discard, func() error { return nil })
	if !errors.Is(err, ErrNotReady) {
		t.Fatal("diagnostic changed rejection", err)
	}
	logControlEvidenceRejection("worker-formal-dek-before-callback", context.Background(), time.Now().Add(time.Second), time.Now(), false, false)
	got := output.String()
	if strings.Contains(got, secret) || !strings.Contains(got, "stage=worker-capture-input-current sentinel=ce_rejected") || !strings.Contains(got, "key_remaining_us=") || !strings.Contains(got, "context_remaining_us=") || !strings.Contains(got, "callback_entered=false callback_succeeded=false") {
		t.Fatal("unsafe or missing fixed CE diagnostic fields")
	}
}
