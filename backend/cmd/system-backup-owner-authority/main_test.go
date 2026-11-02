package main

import (
	"bytes"
	"context"
	"testing"
)

func TestOwnerAuthorityCLIRejectsMissingOrBypassInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"--approved"}, {"issue-capture", "--user-id", "7"}, {"import-capture", "--issuer-private-file", "private"}, {"revoke", "--force"}, {"resolve", "--retry-sign"}, {"export-consumer"}, {"issue-revoke"}, {"import-revoke"}, {"apply"}} {
		var out bytes.Buffer
		if run(context.Background(), args, &out) != 2 || out.Len() != 0 {
			t.Fatal("unsupported authority bypass accepted", args)
		}
	}
}
