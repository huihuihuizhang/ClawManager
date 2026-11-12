// A read-only diagnostic for the retained initial source definition. It has no
// installer, connection, issuer, mutation or native author invocation mode.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
)

func run(args []string, out io.Writer) int {
	f := flag.NewFlagSet("initial-source-inspect", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("definition-file", "", "retained original definition")
	digest := f.String("definition-sha256", "", "retained exact definition SHA256")
	directory := f.String("output-directory", "", "original author output coordinates; never created or written")
	if f.Parse(args) != nil || f.NArg() != 0 || *file == "" || *directory == "" {
		return 2
	}
	raw, err := install.ReadSourceMaterialFile(*file)
	if err != nil {
		return 1
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != *digest {
		return 1
	}
	if json.NewEncoder(out).Encode(execution.InspectOriginalInitialSourceDefinition(raw, *directory)) != nil {
		return 3
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
