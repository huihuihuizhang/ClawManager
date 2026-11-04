package main

import (
	"context"
	"io"
	"testing"
)

func TestFunctionalPublicationActionRejectsMissingOriginalInputs(t *testing.T) {
	for name, args := range map[string][]string{"empty": nil, "unknown": {"--Passed=true"}, "partial": {"--classification-directory=/tmp/output"}} {
		t.Run(name, func(t *testing.T) {
			if got := runFunctionalPublication(context.Background(), args, io.Discard); got != 2 {
				t.Fatalf("missing original inputs exit=%d", got)
			}
		})
	}
	if got := runFunctionalPublication(nil, nil, io.Discard); got != 2 {
		t.Fatal("nil context accepted")
	}
}
