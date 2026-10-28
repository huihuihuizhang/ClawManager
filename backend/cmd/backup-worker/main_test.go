package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestWorkerDoesNotRunWithoutTaskControlIdentity(t *testing.T) {
	for _, args := range [][]string{nil, {"--key", "private-key"}, {"--control-url", "https://fixture"}} {
		var out bytes.Buffer
		if e := run(context.Background(), args, strings.NewReader(`{"password":"private"}`), &out); e == nil {
			t.Fatal("started without authorization")
		}
		if out.Len() != 0 {
			t.Fatal("input reflected into output")
		}
	}
}
