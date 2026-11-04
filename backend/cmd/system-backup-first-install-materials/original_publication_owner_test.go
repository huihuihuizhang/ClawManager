package main

import (
	"context"
	"io"
	"testing"
)

func TestOriginalPublicationOwnerActionsRequireNativeInputs(t *testing.T) {
	for _, action := range []string{"issue-signing-material", "issue-publication-authorization"} {
		t.Run(action, func(t *testing.T) {
			for _, args := range [][]string{{action}, {action, "--Passed=true"}, {action, "--source-issuer-private-file=/tmp/key"}} {
				if exit := run(context.Background(), args, io.Discard); exit != 2 {
					t.Fatalf("missing original source accepted: %d", exit)
				}
			}
		})
	}
}
