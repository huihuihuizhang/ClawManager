package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
)

// Pure operational DATA author, not an owner/permission approval. Native
// installer/source/grant and mapping constructors still run independently.
func runOriginalCaptureInputAuthor(args []string, out io.Writer) int {
	if out == nil {
		return 2
	}
	f := flag.NewFlagSet("author-capture-operational-inputs", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("inputs-file", "", "")
	pin := f.String("inputs-sha256", "", "")
	if f.Parse(args) != nil || f.NArg() != 0 || *file == "" || *pin == "" {
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
	var in execution.OriginalCaptureInputAuthorInputs
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		return 1
	}
	result, e := execution.AuthorOriginalCaptureOperationalInputs(in)
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	return 0
}

func runOriginalPublishedCaptureDatabaseInput(args []string, out io.Writer) int {
	if out == nil {
		return 2
	}
	f := flag.NewFlagSet("bind-published-capture-database-inputs", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("inputs-file", "", "")
	pin := f.String("inputs-sha256", "", "")
	if f.Parse(args) != nil || f.NArg() != 0 || *file == "" || *pin == "" {
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
	var in execution.OriginalPublishedCaptureDatabaseInputs
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		return 1
	}
	result, e := execution.BindOriginalPublishedCaptureDatabaseInputs(in)
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	return 0
}
