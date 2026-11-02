package systembackupnoncebootstrap

import (
	"context"
	"testing"
)

func TestTerminalNonceCopyPoisonsOriginalBeforeSQL(t *testing.T) {
	original := &terminalNonce{ctx: context.Background()}
	original.origin = original
	copy := *original
	if _, err := copy.AuthorizeIdentity(original.ctx, nil); err == nil || !original.failed || original.DependencyDeadline() != nil {
		t.Fatal("copied nonce check revived an original attempt")
	}
	if original.RecheckIdentity(original.ctx, nil) == nil || original.Recheck(original.ctx, nil) == nil {
		t.Fatal("restored original nonce context revived failed check")
	}
}
