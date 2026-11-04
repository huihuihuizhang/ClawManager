package main

import (
	"bytes"
	"context"
	"testing"
)

func TestOriginalBootstrapQueryRejectsMissingBindingsBeforeConnections(t *testing.T) {
	for _, args := range [][]string{nil, {"-bootstrap-deployment-file", "/private/existing.json"}, {"-consumption-file", "/private/original-request.json"}, {"-apply"}} {
		var out bytes.Buffer
		if code := runOriginalBootstrapQuery(context.Background(), args, &out); code != 2 || out.Len() != 0 {
			t.Fatal("missing original binding admitted", code)
		}
	}
}
