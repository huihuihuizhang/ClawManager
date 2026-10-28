// backup-inventory checks a credential-free source inventory offline. It does
// not connect to Kubernetes/MySQL, stop agents, create Jobs or restore data.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"clawreef/internal/systembackup/scope"
)

const maxInputBytes = 16 << 20

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("backup-inventory", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "-", "credential-free JSON input path, or - for stdin")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("usage: backup-inventory [-input inventory.json|-]")
	}
	reader := stdin
	if *inputPath != "-" {
		file, err := os.Open(*inputPath)
		if err != nil {
			return errors.New("cannot open inventory input")
		}
		defer file.Close()
		reader = file
	}
	limited := &io.LimitedReader{R: reader, N: maxInputBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var input scope.Input
	if err := decoder.Decode(&input); err != nil {
		// Do not reflect arbitrary input or sensitive field names/values.
		return errors.New("invalid inventory JSON; only credential-free scope fields are accepted")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || limited.N == 0 {
		return errors.New("inventory input must contain one JSON object and be at most 16 MiB")
	}
	plan, err := scope.BuildInventory(input)
	if err != nil {
		return err
	}
	fingerprint, err := plan.Fingerprint()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(struct {
		Inventory   *scope.Inventory `json:"inventory"`
		Fingerprint string           `json:"fingerprint"`
	}{plan, fingerprint})
}
