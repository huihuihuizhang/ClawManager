// Real original three-signing-reference producer stage. This commits genuine
// result evidence; it cannot claim complete20/first adoption/config enable.
package main

import (
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"encoding/json"
	"flag"
	"github.com/go-sql-driver/mysql"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-original-c1-signing", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	planFile := f.String("plan-file", "", "original canonical installation plan")
	planSHA := f.String("plan-sha256", "", "original selected plan hash")
	publicFile := f.String("issuer-public-file", "", "original enrolled public key")
	publicSHA := f.String("issuer-public-sha256", "", "original selected public key hash")
	kubeFile := f.String("kubeconfig-file", "", "private enrolled owner kubeconfig")
	kubeSHA := f.String("kubeconfig-sha256", "", "original kubeconfig hash")
	dsnFile := f.String("dsn-file", "", "private original installer DSN")
	dbCA := f.String("database-ca-file", "", "original pinned database CA")
	passwordFile := f.String("local-admin-password-file", "", "original local admin private bytes")
	privateFile := f.String("issuer-private-file", "", "original enrolled issuer private bytes")
	enrollmentFile := f.String("enrollment-pin-file", "", "original enrollment pin")
	enrollmentSHA := f.String("enrollment-pin-sha256", "", "original enrollment pin hash")
	inputFile := f.String("input-file", "", "producer-generated pinned data selections, not authorization")
	inputSHA := f.String("input-sha256", "", "original selected data input hash")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, v := range []*string{planFile, planSHA, publicFile, publicSHA, kubeFile, kubeSHA, dsnFile, dbCA, passwordFile, privateFile, enrollmentFile, enrollmentSHA, inputFile, inputSHA} {
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
	private, err := install.ReadPrivateFile(*privateFile, 64)
	if err != nil {
		return 1
	}
	defer clear(private)
	pinRaw, err := install.ReadPrivateFile(*enrollmentFile, 262144)
	if err != nil {
		return 1
	}
	pin, err := install.DecodeEnrollmentPin(pinRaw, *enrollmentSHA)
	if err != nil {
		return 1
	}
	inputRaw, err := install.ReadPrivateFile(*inputFile, 262144)
	if err != nil {
		return 1
	}
	in, err := install.DecodeOriginalC1SigningInvocation(inputRaw, *inputSHA)
	if err != nil {
		return 1
	}
	db, kube, err := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *dbCA)
	if err != nil {
		return 1
	}
	defer db.Close()
	installer, err := install.New(db, kube, raw, *planSHA, public, *publicSHA)
	if err != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	production, err := installer.RunOriginalC1SigningProduction(active, password, pin, in, private)
	if err != nil {
		return 1
	}
	defer production.Close()
	receipt, err := production.StageReceipt(active)
	if err != nil {
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
