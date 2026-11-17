//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

func TestLonghornHelperOutputBound(t *testing.T) {
	stopped := false
	w := &longhornHelperOutput{stop: func() { stopped = true }}
	if _, e := w.Write(make([]byte, longhornHelperOutputLimit)); e != nil {
		t.Fatal(e)
	}
	if _, e := w.Write([]byte("x")); e == nil || !stopped || w.Len() != longhornHelperOutputLimit {
		t.Fatal("unbounded stdout")
	}
}
func TestLonghornHelperContextAndPrivateError(t *testing.T) {
	raw, e := os.ReadFile("/usr/bin/python3.12")
	if e != nil {
		t.Skip("no python3")
	}
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])
	var stderr bytes.Buffer
	out, e := runLonghornPreColdHelper(context.Background(), []byte("import sys;sys.stderr.write('private-diagnostic');print('{}')"), nil, sha, &stderr)
	if e != nil || string(out) != "{}\n" || stderr.String() != "private-diagnostic" {
		t.Fatal("private diagnostic lost", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e = runLonghornPreColdHelper(ctx, []byte("import time;time.sleep(30)"), nil, sha, &stderr)
	if e == nil || time.Since(start) > 6*time.Second {
		t.Fatal("deadline not preserved", e)
	}
}
