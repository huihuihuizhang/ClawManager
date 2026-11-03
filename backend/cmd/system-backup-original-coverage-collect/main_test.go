package main

import (
	"context"
	"io"
	"testing"
)

func TestOriginalCoverageCollectCommandRequiresExplicitReadOnlyScope(t *testing.T) {
	for _, a := range [][]string{nil, {"sql"}, {"minio"}, {"adopt"}, {"minio", "--insecure"}, {"sql", "--force-empty"}, {"sql", "--issuer-private-file", "operator-key"}} {
		if run(context.Background(), a, io.Discard) != 2 {
			t.Fatal("invalid/unreviewed authority mode admitted")
		}
	}
}
