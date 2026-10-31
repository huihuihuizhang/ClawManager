package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"clawreef/internal/systembackup/worker"
)

func TestPublicationUploadCommandRejectsCaptureAndUnknownArguments(t *testing.T) {
	for _, args := range [][]string{
		{"publish-upload-only"},
		{"publish-upload-only", "--control-url", "https://capture.invalid"},
		{"publish-upload-only", "--formal-config", "/run/source.json"},
		{"publish-upload-only", "--request", "/request.json", "--ca", "/ca.pem", "--credential", "/upload.json", "--input", "/input", "--result", "/result", "extra"},
	} {
		if err := run(context.Background(), args, bytes.NewReader(nil), &bytes.Buffer{}); !errors.Is(err, worker.ErrRequest) {
			t.Fatal("upload command accepted capture/unknown input", args, err)
		}
	}
}

func TestPublicationUploadCommandPinsExactOriginalRequestBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	raw := []byte(`{"original":"public upload input"}`)
	digest := sha256.Sum256(raw)
	pin := hex.EncodeToString(digest[:])
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("owned request")
	}
	got, err := readPublicationUploadRequest(path, pin)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("original Job request", err)
	}
	if os.WriteFile(path, append(raw, ' '), 0600) != nil {
		t.Fatal("owned replacement")
	}
	if _, err = readPublicationUploadRequest(path, pin); !errors.Is(err, worker.ErrRequest) {
		t.Fatal("same-name request byte change admitted", err)
	}
}
