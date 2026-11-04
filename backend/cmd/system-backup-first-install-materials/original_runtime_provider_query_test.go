package main

import (
	"context"
	"io"
	"testing"
)

func TestOriginalRuntimeProviderQueryCannotReplayOrAcceptCallerApproval(t *testing.T) {
	for _, args := range [][]string{nil, {"--Passed=true"}, {"--retry=true"}, {"--runtime-sql-metadata-receipt-file=caller.json"}} {
		if runOriginalRuntimeProviderQuery(context.Background(), args, io.Discard) != 2 {
			t.Fatal("invalid query flags accepted")
		}
	}
}
