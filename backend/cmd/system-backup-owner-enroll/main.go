// Authenticated offline enrollment only. The prepare-only owner command and
// runtime app are unchanged; neither receives an installation signing key.
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
	flags := flag.NewFlagSet("system-backup-owner-enroll", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planFile := flags.String("plan-file", "", "user-selected canonical public target plan")
	planSHA := flags.String("plan-sha256", "", "independently pinned plan bytes")
	publicFile := flags.String("issuer-public-file", "", "selected raw Ed25519 public key")
	publicSHA := flags.String("issuer-public-sha256", "", "public key fingerprint selected independently by the user")
	kubeFile := flags.String("kubeconfig-file", "", "trusted existing operator kubeconfig")
	kubeSHA := flags.String("kubeconfig-sha256", "", "exact private kubeconfig bytes")
	dsnFile := flags.String("dsn-file", "", "private installer SQL DSN")
	dbCAFile := flags.String("database-ca-file", "", "pinned target database CA")
	passwordFile := flags.String("local-admin-password-file", "", "private exact local admin password bytes")
	if ctx == nil || out == nil || flags.Parse(args) != nil || flags.NArg() != 0 || *planFile == "" || *planSHA == "" || *publicFile == "" || *publicSHA == "" || *kubeFile == "" || *kubeSHA == "" || *dsnFile == "" || *dbCAFile == "" || *passwordFile == "" {
		return 2
	}
	raw, e := install.ReadPrivateFile(*planFile, 262144)
	if e != nil {
		return 1
	}
	plan, e := install.DecodePlan(raw, *planSHA)
	if e != nil {
		return 1
	}
	public, e := install.ReadPrivateFile(*publicFile, 32)
	if e != nil {
		return 1
	}
	password, e := install.ReadPrivateFile(*passwordFile, 1024)
	if e != nil {
		return 1
	}
	defer clear(password)
	db, kube, e := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *dbCAFile)
	if e != nil {
		return 1
	}
	defer db.Close()
	installer, e := install.New(db, kube, raw, *planSHA, public, *publicSHA)
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	receipt, e := installer.Enroll(active, password)
	if errors.Is(e, install.ErrCommitUnknown) {
		return 3
	}
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
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
