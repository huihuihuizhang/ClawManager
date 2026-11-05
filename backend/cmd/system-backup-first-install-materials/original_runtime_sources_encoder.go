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

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
)

// Type-fixed DATA encoding only. The unchanged original native owner and
// runtime producer perform all authorization/signature/native checks later.
func runOriginalRuntimeSourcesEncoder(args []string, out io.Writer) int {
	if out == nil {
		return 2
	}
	f := flag.NewFlagSet("encode-publication-runtime-sources", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("inputs-file", "", "")
	pin := f.String("inputs-sha256", "", "")
	destination := f.String("output-file", "", "")
	if f.Parse(args) != nil || f.NArg() != 0 || *file == "" || *pin == "" || !filepath.IsAbs(*destination) || filepath.Clean(*destination) != *destination || *destination == *file {
		return 2
	}
	raw, e := install.ReadPrivateFile(*file, 262144)
	if e != nil {
		return 1
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != *pin {
		return 1
	}
	var value execution.PublicationRuntimeSources
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || value.Version != "original-publication-runtime-sources.v1" {
		return 1
	}
	body, e := json.Marshal(value)
	if e != nil {
		return 1
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(*destination))
	if e != nil || parent != filepath.Dir(*destination) {
		return 1
	}
	target, e := os.OpenFile(*destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return 1
	}
	n, e := target.Write(body)
	if e == nil && n != len(body) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = target.Sync()
	}
	closeErr := target.Close()
	if e != nil || closeErr != nil {
		return 1
	}
	directory, e := os.Open(parent)
	if e != nil {
		return 1
	}
	e = directory.Sync()
	closeErr = directory.Close()
	if e != nil || closeErr != nil {
		return 1
	}
	sum = sha256.Sum256(body)
	if json.NewEncoder(out).Encode(install.BootstrapSourceFilePin{File: *destination, SHA256: hex.EncodeToString(sum[:])}) != nil {
		return 3
	}
	return 0
}
