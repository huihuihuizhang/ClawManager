package install

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
)

type GeneratedIssuer struct {
	Status          string `json:"status"`
	PrivateFile     string `json:"private_file"`
	PublicFile      string `json:"public_file"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

// GenerateIssuer creates only raw Ed25519 files in an existing private
// directory. Generation is not registration, enrollment or an authority grant.
// No private key/seed is returned, logged or written into application config.
func GenerateIssuer(directory string) (GeneratedIssuer, error) {
	var zero GeneratedIssuer
	if privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	for _, name := range []string{"issuer.private", "issuer.public"} {
		if _, e := os.Lstat(filepath.Join(directory, name)); !os.IsNotExist(e) {
			return zero, ErrInstall
		}
	}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(private)
	if writeNewFiles(directory, map[string][]byte{"issuer.private": private, "issuer.public": public}) != nil {
		return zero, ErrInstall
	}
	return GeneratedIssuer{Status: "local_issuer_created_unenrolled", PrivateFile: filepath.Join(directory, "issuer.private"), PublicFile: filepath.Join(directory, "issuer.public"), PublicKeySHA256: hash(public)}, nil
}
