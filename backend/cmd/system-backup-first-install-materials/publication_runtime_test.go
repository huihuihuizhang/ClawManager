package main

import (
	"context"
	"io"
	"testing"
)

func TestPublicationRuntimeActionRequiresOriginalSources(t *testing.T) {
	for _, args := range [][]string{{"issue-runtime-materials"}, {"issue-runtime-materials", "--Passed=true"}, {"issue-runtime-materials", "--runtime-sources-file=/tmp/record"}} {
		if got := run(context.Background(), args, io.Discard); got != 2 {
			t.Fatalf("missing original authorization exit=%d", got)
		}
	}
}
