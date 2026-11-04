package main

import (
	"context"
	"io"
	"testing"
)

func TestOriginalFirstCaptureDraftCLIRejectsMissingAndSyntheticProof(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing", nil},
		{"passed", []string{"--passed=true"}},
		{"record_dto", []string{"--record-draft-file=caller-record.json"}},
		{"selection_hash_without_source", []string{"--selection-sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{"retry", []string{"--retry=true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"prepare-initial-capture-draft"}, tc.args...)
			if got := run(context.Background(), args, io.Discard); got != 2 {
				t.Fatalf("exit=%d", got)
			}
		})
	}
}
