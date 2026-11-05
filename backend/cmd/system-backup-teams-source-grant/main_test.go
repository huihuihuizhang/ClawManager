package main

import (
	"context"
	"io"
	"testing"
)

func TestTeamsSourceCLIRefusesUnknownAndQueryPrivateKey(t *testing.T) {
	for _, args := range [][]string{nil, {"retry"}, {"query", "--source-issuer-private-file", "/private/key"}, {"issue"}, {"query", "--Passed", "true"}} {
		if code := run(context.Background(), args, io.Discard); code != 2 {
			t.Fatalf("invalid argument returned %d", code)
		}
	}
}
