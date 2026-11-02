package install

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOwnerAuthorityGenerateIssuerCreateOnlyRawFormat(t *testing.T) {
	directory := t.TempDir()
	result, e := GenerateIssuer(directory)
	if e != nil || result.Status != "local_issuer_created_unenrolled" {
		t.Fatal("local generation", e)
	}
	private, e := ReadPrivateFile(result.PrivateFile, ed25519.PrivateKeySize)
	if e != nil || len(private) != ed25519.PrivateKeySize {
		t.Fatal("raw private format", e)
	}
	defer clear(private)
	public, e := ReadPrivateFile(result.PublicFile, ed25519.PublicKeySize)
	if e != nil || len(public) != ed25519.PublicKeySize || hash(public) != result.PublicKeySHA256 || !bytes.Equal(private[ed25519.SeedSize:], public) {
		t.Fatal("independent public fingerprint/raw format", e)
	}
	message := []byte("local issuer format check")
	if !ed25519.Verify(public, message, ed25519.Sign(private, message)) {
		t.Fatal("generated raw key is not usable")
	}
	for _, path := range []string{result.PrivateFile, result.PublicFile} {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || runtime.GOOS == "linux" && info.Mode().Perm() != 0600 {
			t.Fatal("private output mode", e)
		}
	}
	if _, e = GenerateIssuer(directory); e == nil {
		t.Fatal("existing issuer replaced")
	}
	again, e := os.ReadFile(result.PrivateFile)
	defer clear(again)
	if e != nil || !bytes.Equal(again, private) {
		t.Fatal("failed retry changed original issuer", e)
	}
}

func TestOwnerAuthorityGenerateIssuerCollisionLeavesOnlyOriginal(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "issuer.public")
	before := []byte("independently supplied existing public file")
	if os.WriteFile(path, before, 0600) != nil {
		t.Fatal("fixture")
	}
	if _, e := GenerateIssuer(directory); e == nil {
		t.Fatal("pre-existing output accepted")
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("original output changed", e)
	}
	entries, e := os.ReadDir(directory)
	if e != nil || len(entries) != 1 {
		t.Fatal("failed generation left another file", e)
	}
}
