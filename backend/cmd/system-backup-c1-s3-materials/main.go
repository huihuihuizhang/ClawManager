package main

import (
	"context"
	"encoding/json"
	"os"

	"clawreef/internal/buildinfo"
	"clawreef/internal/systembackupinstallationowner/install"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		if json.NewEncoder(os.Stdout).Encode(buildinfo.Current()) != nil {
			os.Exit(3)
		}
		return
	}
	os.Exit(install.RunOriginalC1S3Materials(context.Background(), os.Args[1:], os.Stdout))
}
