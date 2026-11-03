package main

import (
	archive "clawreef/internal/systembackuphostpatharchive"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "verify-original-custody-pipe" || archive.RunIndependentReader() != nil {
		fmt.Fprintln(os.Stderr, "original independent archive readback refused")
		os.Exit(2)
	}
}
