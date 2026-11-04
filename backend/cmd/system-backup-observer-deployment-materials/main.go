// Authenticated original observer ServiceAccount preparation and per-node host
// deployment materials. No task/backup readiness or native installation claim.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-observer-deployment-materials", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "", "service-account, host-materials or shared-agent-tls")
	planFile := f.String("plan-file", "", "original canonical installation plan")
	planSHA := f.String("plan-sha256", "", "independently pinned original plan hash")
	publicFile := f.String("issuer-public-file", "", "original enrolled Ed25519 public key")
	publicSHA := f.String("issuer-public-sha256", "", "original public key pin")
	kubeFile := f.String("kubeconfig-file", "", "private authenticated owner kubeconfig")
	kubeSHA := f.String("kubeconfig-sha256", "", "original owner kubeconfig pin")
	dsnFile := f.String("dsn-file", "", "private authenticated installer SQL DSN")
	dbCA := f.String("database-ca-file", "", "original pinned database TLS CA")
	passwordFile := f.String("local-admin-password-file", "", "private exact local administrator password bytes")
	pinFile := f.String("enrollment-pin-file", "", "original enrollment receipt pin")
	pinSHA := f.String("enrollment-pin-sha256", "", "original enrollment pin file hash")
	definitionFile := f.String("definition-file", "", "canonical original-observer-service-account.v1 or original-observer-host-deployment.v1")
	definitionSHA := f.String("definition-sha256", "", "independently selected definition hash")
	directory := f.String("output-directory", "", "existing private directory; all PKI output names must be absent")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, v := range []*string{planFile, planSHA, publicFile, publicSHA, kubeFile, kubeSHA, dsnFile, dbCA, passwordFile, pinFile, pinSHA, definitionFile, definitionSHA} {
		if *v == "" {
			return 2
		}
	}
	raw, err := install.ReadPrivateFile(*planFile, 262144)
	if err != nil {
		return 1
	}
	plan, err := install.DecodePlan(raw, *planSHA)
	if err != nil {
		return 1
	}
	public, err := install.ReadPrivateFile(*publicFile, 32)
	if err != nil {
		return 1
	}
	password, err := install.ReadPrivateFile(*passwordFile, 1024)
	if err != nil {
		return 1
	}
	defer clear(password)
	pinRaw, err := install.ReadPrivateFile(*pinFile, 262144)
	if err != nil {
		return 1
	}
	pin, err := install.DecodeEnrollmentPin(pinRaw, *pinSHA)
	if err != nil {
		return 1
	}
	db, kube, err := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *dbCA)
	if err != nil {
		return 1
	}
	defer db.Close()
	i, err := install.New(db, kube, raw, *planSHA, public, *publicSHA)
	if err != nil {
		return 1
	}
	budget := 2 * time.Minute
	if *mode == "workspace-runtime-readback" {
		budget = 15 * time.Minute
	}
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var receipt any
	switch *mode {
	case "service-account":
		if *directory != "" {
			return 2
		}
		receipt, err = i.PrepareOriginalObserverServiceAccount(bounded, password, pin, *definitionFile, *definitionSHA)
	case "workspace-runtime-baseline", "workspace-runtime-readback":
		if *directory == "" {
			return 2
		}
		receipt, err = i.ProduceOriginalWorkspaceRuntimeMaterials(bounded, password, pin, *definitionFile, *definitionSHA, *directory, *mode == "workspace-runtime-readback")
	case "workspace-runtime-stop":
		if *directory == "" {
			return 2
		}
		receipt, err = i.StopOriginalWorkspaceGateway(bounded, password, pin, *definitionFile, *definitionSHA, *directory)
	case "shared-agent-tls":
		if *directory == "" {
			return 2
		}
		receipt, err = i.ProduceOriginalSharedAgentTLSMaterials(bounded, password, pin, *definitionFile, *definitionSHA, *directory)
	case "host-materials":
		if *directory == "" {
			return 2
		}
		receipt, err = i.ProduceOriginalObserverHostMaterials(bounded, password, pin, *definitionFile, *definitionSHA, *directory)
	default:
		return 2
	}
	if errors.Is(err, install.ErrOriginalObserverPKIUnconfirmed) {
		return 3 // Retained create-only material, no confirmed success receipt.
	}
	if err != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3 // Files exist; inspect exact pins instead of reissuing/replacing.
	}
	return 0
}

func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout))
}
