package main

import (
	"context"
	"io"
	"testing"
)

func TestMinIONativeInstallRequiresExplicitOriginalInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"--requirements"}, {"generate"}, {"apply"}, {"probe"}, {"apply", "--insecure"}, {"generate", "--admin-user-file", "root"}} {
		if code := run(context.Background(), args, io.Discard); code != 2 {
			t.Fatalf("invalid setup attempted native operation: %d", code)
		}
	}
}
