package main

import (
	"encoding/json"
	"flag"
	"io"

	"clawreef/internal/systembackupinstallationowner/install"
)

// This local-only action deliberately has no plan, enrollment, SQL or API
// inputs. Its public fingerprint must still be independently selected/pinned.
func generateIssuer(args []string, out io.Writer) int {
	f := flag.NewFlagSet("generate-issuer", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	directory := f.String("output-directory", "", "")
	if f.Parse(args) != nil || f.NArg() != 0 || *directory == "" {
		return 2
	}
	result, e := install.GenerateIssuer(*directory)
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	return 0
}
