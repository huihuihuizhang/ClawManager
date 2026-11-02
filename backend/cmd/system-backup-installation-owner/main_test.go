package main

import (
	"bytes"
	"testing"
)

func TestInstallationOwnerCLIOnlyGeneratesUntrustedCandidate(t *testing.T) {
	for _, action := range []string{"enroll", "issue", "import", "revoke", "apply", "--approve"} {
		var out bytes.Buffer
		if run([]string{action}, &out) != 2 || out.Len() != 0 {
			t.Fatal("unauthorized action accepted", action)
		}
	}
	var out bytes.Buffer
	if run([]string{"prepare-enrollment", "--output-directory", t.TempDir()}, &out) != 0 || !bytes.Contains(out.Bytes(), []byte("untrusted_candidate_requires_user_enrollment")) {
		t.Fatal("candidate generation", out.String())
	}
}
