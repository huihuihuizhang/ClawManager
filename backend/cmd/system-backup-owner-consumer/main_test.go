package main

import (
	"bytes"
	"context"
	"testing"
)

func TestCaptureConsumerCLIRejectsPrivateKeyAndBypassInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"--issuer-private-file", "must-not-open"}, {"--approved"}, {"--force"}, {"--user-id", "7"}, {"--plan-file", "missing"}, {"--apply"}} {
		var out bytes.Buffer
		if run(context.Background(), args, &out) != 2 || out.Len() != 0 {
			t.Fatal("export CLI accepted bypass/missing original source", args)
		}
	}
}
