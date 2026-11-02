package main

import (
	"bytes"
	"context"
	"testing"
)

func TestOwnerEnrollCLIRequiresExplicitTrustedInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"--approved"}, {"--user-id", "7"}, {"--issuer-private-file", "private"}, {"issue"}, {"import"}, {"revoke"}, {"--plan-file", "relative"}} {
		var out bytes.Buffer
		if run(context.Background(), args, &out) != 2 || out.Len() != 0 {
			t.Fatal("incomplete or unsupported enrollment accepted", args)
		}
	}
}
