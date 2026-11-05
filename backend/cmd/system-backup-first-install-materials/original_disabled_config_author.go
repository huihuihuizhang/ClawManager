package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"

	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func runOriginalDisabledConfigAuthor(args []string, out io.Writer) int {
	f := flag.NewFlagSet("author-disabled-config", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("definition-file", "", "actual pinned original registry/reference locations")
	digest := f.String("definition-sha256", "", "original input bytes")
	target := f.String("output-file", "", "new private canonical config; data only")
	if out == nil || f.Parse(args) != nil || f.NArg() != 0 || *file == "" || *digest == "" || !filepath.IsAbs(*target) {
		return 2
	}
	raw, err := install.ReadPrivateFile(*file, 262144)
	if err != nil {
		return 1
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != *digest {
		return 1
	}
	if _, err = jsoncanonicalizer.Transform(raw); err != nil {
		return 1
	}
	var definition struct {
		Version      string
		Registries   []sec.BootstrapRegistryRef
		References   []sec.BootstrapSecretRef
		StagingBytes int64
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&definition) != nil || decoder.Decode(new(any)) != io.EOF || definition.Version != "original-disabled-config-selections.v1" {
		return 1
	}
	config, err := sec.DefaultDisabledConfig(definition.Registries, definition.References, definition.StagingBytes)
	if err != nil {
		return 1
	}
	parent := filepath.Dir(*target)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return 1
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return 1
	}
	output, err := os.OpenFile(*target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 1
	}
	data := config.CanonicalJSON()
	n, err := output.Write(data)
	flush := output.Sync()
	closed := output.Close()
	if err != nil || n != len(data) || flush != nil || closed != nil {
		return 1
	}
	dir, err := os.Open(parent)
	if err != nil {
		return 1
	}
	flush = dir.Sync()
	closed = dir.Close()
	if flush != nil || closed != nil {
		return 1
	}
	result := struct {
		Version                                        string
		Config                                         install.BootstrapSourceFilePin
		AuthorityIssued, CapacityVerified, BackupReady bool
	}{
		Version: "original-disabled-config-authored.v1", Config: install.BootstrapSourceFilePin{File: *target, SHA256: config.SHA256()}}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	return 0
}
