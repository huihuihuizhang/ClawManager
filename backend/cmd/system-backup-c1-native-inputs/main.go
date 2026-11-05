package main

import (
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"github.com/go-sql-driver/mysql"
	"io"
	"log"
	"os"
)

func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	args := os.Args[1:]
	if len(args) == 0 {
		os.Exit(2)
	}
	switch args[0] {
	case "runtime-test-scope":
		os.Exit(install.RunOriginalRuntimeTestScopeCommand(context.Background(), args[1:], os.Stdout))
	case "capacity-collect":
		os.Exit(install.RunOriginalCapacityCollector(context.Background(), args[1:], os.Stdout))
	case "capacity":
		os.Exit(install.RunOriginalC1CapacityAccount(context.Background(), args[1:], os.Stdout))
	case "definitions":
		os.Exit(install.RunOriginalC1ProviderDefinitions(context.Background(), args[1:], os.Stdout))
	case "relay-pki":
		os.Exit(install.RunOriginalRelayPKICommand(context.Background(), args[1:], os.Stdout))
	case "relay-serve":
		os.Exit(install.RunOriginalReadOnlyStatusRelay(context.Background(), args[1:], os.Stdout))
	case "relay-tls":
		os.Exit(install.RunOriginalRelaySQLTLSLocationCommand(context.Background(), args[1:], os.Stdout))
	case "relay-handover":
		os.Exit(install.RunOriginalRelayHandoverCommand(context.Background(), args[1:], os.Stdout))
	default:
		os.Exit(2)
	}
}
