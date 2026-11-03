package main

import (
	"bytes"
	"context"
	"testing"
)

func TestDatabaseSourceGrantCommandRequiresOriginalNativeInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"--purpose", "acceptance"}, {"--database-source-definition-file", "missing"}, {"--definition-file", "missing"}, {"--approved"}, {"positional"}} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out); code != 2 || out.Len() != 0 {
			t.Fatal("uncontrolled database grant input performed work", code)
		}
	}
}
