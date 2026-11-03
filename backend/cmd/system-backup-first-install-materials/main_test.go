package main

import (
	"bytes"
	"context"
	"testing"
)

func TestFirstInstallMaterialsCommandRequiresAllOriginalInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"--purpose", "acceptance"}, {"--components-template-file", "missing"}, {"--definition-file", "missing"}, {"--apply"}, {"positional"}} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out); code != 2 || out.Len() != 0 {
			t.Fatal("incomplete/foreign mode performed work", code)
		}
	}
}
