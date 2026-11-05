package systembackupexecution

import (
	"context"
	"testing"
)

func TestOriginalTeamModeCannotResolveWithoutOriginalAuthority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &OriginalCaptureSequence{ctx: ctx}
	mode, err := s.resolveOriginalTeamObjectMode(ctx)
	if err == nil || mode != originalTeamObjectUnknown || !s.failed {
		t.Fatal("no-authority resolved a source mode")
	}
	if mode, err = s.resolveOriginalTeamObjectMode(ctx); err == nil || mode != originalTeamObjectUnknown {
		t.Fatal("failed original sequence revived")
	}
}

func TestOriginalTeamModeRejectsForeignContextBeforeAnyRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &OriginalCaptureSequence{ctx: ctx}
	if mode, err := s.resolveOriginalTeamObjectMode(context.Background()); err == nil || mode != originalTeamObjectUnknown || !s.failed {
		t.Fatal("foreign context adopted")
	}
}
