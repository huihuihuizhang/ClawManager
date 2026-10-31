package systembackupexecution

import (
	"context"
	"errors"
	"testing"
)

func TestPublicationServicePassRunsOriginalUnknownAfterCaptureTaskFailure(t *testing.T) {
	taskFailure := errors.New("original capture task failure")
	calls := 0
	err := runCaptureAndPublicationPass(context.Background(), func(context.Context) error { calls++; return taskFailure }, func(context.Context) error { calls++; return nil })
	if err != taskFailure || calls != 2 {
		t.Fatal("failed capture starved original publication recovery", err, calls)
	}
}

func TestPublicationServicePassNeverStartsRecoveryAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := runCaptureAndPublicationPass(ctx, func(context.Context) error { calls++; cancel(); return nil }, func(context.Context) error { calls++; return nil })
	if err != context.Canceled || calls != 1 {
		t.Fatal("cancel started a new pass", err, calls)
	}
}
