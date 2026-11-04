package main

import (
	"bytes"
	"context"
	"testing"
)

func TestOriginalC1EvidenceMaterialCLIRefusesIncompleteAndQueryIssuanceFlags(t *testing.T) {
	for _, action := range []string{"issue-initial-c1-evidence-material", "query-initial-c1-evidence-material"} {
		for _, args := range [][]string{nil, {"--passed", "true"}, {"--management-allowed", "true"}, {"--output-directory", "/tmp/untrusted"}} {
			var out bytes.Buffer
			if runOriginalC1EvidenceMaterial(context.Background(), action, args, &out) != 2 || out.Len() != 0 {
				t.Fatal("missing native inputs reached connection", action)
			}
		}
	}
	var out bytes.Buffer
	if runOriginalC1EvidenceMaterial(context.Background(), "query-initial-c1-evidence-material", []string{"--source-issuer-private-file", "/tmp/key"}, &out) != 2 {
		t.Fatal("query accepted issuance private key")
	}
}
