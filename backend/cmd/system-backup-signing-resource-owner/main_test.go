package main

import (
	"bytes"
	"context"
	"testing"
)

func TestSigningResourceCLIRejectsMixedOperationBeforeCredentialReads(t *testing.T) {
	common := []string{"--plan-file", "not-an-absolute-input", "--plan-sha256", "x", "--issuer-public-file", "x", "--issuer-public-sha256", "x", "--kubeconfig-file", "x", "--kubeconfig-sha256", "x", "--dsn-file", "x", "--database-ca-file", "x", "--local-admin-password-file", "x", "--enrollment-pin-file", "x", "--enrollment-pin-sha256", "x", "--sql-inputs-file", "x", "--sql-inputs-sha256", "x"}
	for _, action := range []string{"import", "resolve"} {
		args := append([]string{action}, common...)
		args = append(args, "--issuer-private-file", "must-not-open-this-file")
		var out bytes.Buffer
		if code := run(context.Background(), args, &out); code != 2 || out.Len() != 0 {
			t.Fatal("mixed signing key accepted by non-signing operation", action, code)
		}
	}
	if code := run(context.Background(), []string{"publish"}, &bytes.Buffer{}); code != 2 {
		t.Fatal("future task/publisher operation accepted", code)
	}
}
