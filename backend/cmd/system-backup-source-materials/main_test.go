package main

import (
	"bytes"
	"context"
	"testing"
)

func TestSourceMaterialsCommandRejectsMissingOrUnknownInputsWithoutOutput(t *testing.T) {
	for _, args := range [][]string{nil, {"--purpose", "acceptance"}, {"--definition-file", "missing"}, {"unexpected-positional"}} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out); code != 2 || out.Len() != 0 {
			t.Fatal("invalid CLI input performed work or wrote a receipt", code)
		}
	}
}
