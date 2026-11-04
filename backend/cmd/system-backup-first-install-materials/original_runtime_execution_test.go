package main

import (
	"context"
	"io"
	"testing"
)

func TestOriginalRuntimeIssuanceCLIRejectsMissingNativeSources(t *testing.T) {
	for _, provider := range []bool{false, true} {
		for _, args := range [][]string{nil, {"--Passed=true"}, {"--runtime-issuers-file=caller.json"}} {
			if runOriginalRuntimeMaterials(context.Background(), args, io.Discard, provider) != 2 {
				t.Fatal("incomplete/caller approval accepted")
			}
		}
	}
}
