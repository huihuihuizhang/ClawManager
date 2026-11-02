// Offline material preparation ONLY. Authenticated enroll/issue/import/revoke
// are deliberately not implemented or accepted as aliases by this command.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"

	owner "clawreef/internal/systembackupinstallationowner"
)

func run(args []string, out io.Writer) int {
	if len(args) == 0 || args[0] != "prepare-enrollment" {
		return 2
	}
	flags := flag.NewFlagSet("prepare-enrollment", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("output-directory", "", "existing private absolute directory")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *directory == "" {
		return 2
	}
	candidate, e := owner.GenerateEnrollmentCandidate(*directory)
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(candidate) != nil {
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
