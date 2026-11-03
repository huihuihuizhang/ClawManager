package main

import (
	"bytes"
	"context"
	"testing"
)

func TestKEKWindowCLIRefusesMissingAndForeignActionsBeforeInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"requirements"}, {"apply"}, {"issue"}, {"owner-binding"}, {"issue", "--approved"}, {"issue", "--force"}, {"owner-binding", "--issuer-private-file", "must-not-open"}, {"issue", "--record-file", "must-not-open"}, {"issue", "--task-id", "foreign-task"}} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out); code != 2 || out.Len() != 0 {
			t.Fatal("invalid/foreign authority flags reached material inputs", args, code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if run(ctx, []string{"issue"}, &bytes.Buffer{}) != 2 {
		t.Fatal("cancelled request reached material inputs")
	}
}
