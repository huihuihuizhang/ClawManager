package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOriginalMaterialIssuerRejectsShortMismatchedAndNoncanonicalPrivateKeys(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "original-owner.key")
	for _, value := range [][]byte{key[:31], append([]byte(nil), key...), append([]byte(nil), key...)} {
		if len(value) == ed25519.PrivateKeySize {
			value[len(value)-1] ^= 1
		}
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
		if result, err := readIssuer(path, digest(public)); err == nil || result != nil {
			t.Fatal("short/noncanonical private key admitted")
		}
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := readIssuer(path, digest(public))
	defer clear(result)
	if err != nil || !bytes.Equal(result, key) {
		t.Fatal("original pinned issuer rejected", err)
	}
	if result, err := readIssuer(path, digest([]byte("foreign public key DATA"))); err == nil || result != nil {
		t.Fatal("foreign issuer pin accepted")
	}
}

func TestOriginalMaterialsRequireIndependentOwnersBeforeProviderIO(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "input.json")
	output := filepath.Join(dir, "output")
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	input := materialInput{}
	input.MappingSource.RecordID = "mapping"
	input.GenerateSource.RecordID = "generate"
	input.UnwrapSource.RecordID = "unwrap"
	input.MappingIssuerPublicSHA256 = digest([]byte("same issuer DATA"))
	input.PermissionIssuerPublicSHA256 = input.MappingIssuerPublicSHA256
	raw, _ := json.Marshal(input)
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--config-file", config, "--config-sha256", digest(raw), "--output-directory", output}, &out); err == nil || out.Len() != 0 {
		t.Fatal("missing independent owners emitted success")
	}
	files, err := os.ReadDir(output)
	if err != nil || len(files) != 0 {
		t.Fatal("invalid original inputs produced artifacts")
	}
}
