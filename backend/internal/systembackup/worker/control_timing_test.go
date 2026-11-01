package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCaptureControlTimingDoesNotChangeActualMTLSRejection(t *testing.T) {
	inv := keyInvocation(t)
	sum, _ := inv.Hash()
	var calls int
	client, _ := mutualTLSFixture(t, ControlHandler{Authorizer: authorizeFunc(func(context.Context, string, ControlRequest) (Lease, error) { calls++; return Lease{}, ErrExecution })})
	defer client.Close()
	before := client.CaptureControlTimingData()
	if before != (CaptureControlTimingData{}) {
		t.Fatal("new client had observed sends")
	}
	for _, action := range []string{"key-check", "key-end", "key-check"} {
		lease, err := client.send(context.Background(), ControlRequest{Invocation: inv, InvocationSHA256: sum, Action: action, Point: strings.Repeat("a", 32)})
		lease.Clear()
		if !errors.Is(err, ErrExecution) {
			t.Fatal("diagnostics changed actual mTLS rejection", err)
		}
	}
	if lease, err := client.send(context.Background(), ControlRequest{Invocation: inv, InvocationSHA256: sum, Action: "key-check"}); !errors.Is(err, ErrRequest) {
		lease.Clear()
		t.Fatal("timing bypassed local validation", err)
	}
	after := client.CaptureControlTimingData()
	if calls != 3 || after.KeyCheck.Calls != 3 || after.KeyCheck.HTTPAttempts != 2 || after.KeyCheck.Failures != 3 || after.KeyEnd.Calls != 1 || after.KeyEnd.HTTPAttempts != 1 || after.KeyEnd.Failures != 1 || after.KeyCheck.ElapsedNanos < 0 || after.KeyEnd.ElapsedNanos < 0 || after.KeyCheck.MaxNanos > after.KeyCheck.ElapsedNanos || after.KeyCheck.LastNanos > after.KeyCheck.MaxNanos || after.KeyEnd.MaxNanos != after.KeyEnd.ElapsedNanos || after.KeyEnd.LastNanos != after.KeyEnd.MaxNanos || after.KeyReserve != (CaptureControlCallTimingData{}) || after.KeyBegin != (CaptureControlCallTimingData{}) || after.Candidate != (CaptureControlCallTimingData{}) {
		t.Fatal("completed calls miscounted", calls, after)
	}
	if client.CaptureControlTimingData() != after || calls != 3 {
		t.Fatal("reading DATA issued another request")
	}
	var missing *ControlClient
	if missing.CaptureControlTimingData() != (CaptureControlTimingData{}) {
		t.Fatal("missing client fabricated timing")
	}
}
