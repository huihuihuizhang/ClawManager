package systembackupcatrust

import (
	"context"
	"testing"
)

func TestTerminalCACopyPoisonsOriginalBeforeSQL(t *testing.T) {
	original := &terminalCA{ctx: context.Background()}
	original.origin = original
	copy := *original
	if _, err := copy.AuthorizeIdentity(original.ctx, nil); err == nil || !original.failed || original.DependencyDeadline() != nil {
		t.Fatal("copied CA check revived an original attempt")
	}
	if original.RecheckIdentity(original.ctx, nil) == nil || original.Recheck(original.ctx, nil) == nil {
		t.Fatal("restored original CA context revived failed check")
	}
}
