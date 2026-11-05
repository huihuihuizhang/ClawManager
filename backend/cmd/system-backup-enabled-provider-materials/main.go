package main

import (
	"context"
	"os"

	"clawreef/internal/systembackupinstallationowner/install"
)

func main() {
	os.Exit(install.RunOriginalEnabledProviderMaterials(context.Background(), os.Args[1:], os.Stdout))
}
