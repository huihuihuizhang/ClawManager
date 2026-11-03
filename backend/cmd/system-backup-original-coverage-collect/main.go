package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || len(args) == 0 || out == nil {
		return 2
	}
	action := args[0]
	if action != "sql" && action != "minio" {
		return 2
	}
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	definition := f.String("definition-file", "", "")
	definitionSHA := f.String("definition-sha256", "", "")
	directory := f.String("output-directory", "", "")
	planFile := f.String("plan-file", "", "")
	planSHA := f.String("plan-sha256", "", "")
	publicFile := f.String("issuer-public-file", "", "")
	publicSHA := f.String("issuer-public-sha256", "", "")
	kubeFile := f.String("kubeconfig-file", "", "")
	kubeSHA := f.String("kubeconfig-sha256", "", "")
	dsn := f.String("dsn-file", "", "")
	databaseCA := f.String("database-ca-file", "", "")
	passwordFile := f.String("local-admin-password-file", "", "")
	enrollmentFile := f.String("enrollment-pin-file", "", "")
	enrollmentSHA := f.String("enrollment-pin-sha256", "", "")
	adminUser := f.String("admin-user-file", "", "")
	adminPassword := f.String("admin-password-file", "", "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	for _, value := range []string{*definition, *definitionSHA, *directory, *planFile, *planSHA, *publicFile, *publicSHA, *kubeFile, *kubeSHA, *dsn, *databaseCA, *passwordFile, *enrollmentFile, *enrollmentSHA} {
		if value == "" {
			return 2
		}
	}
	if action == "minio" {
		if *adminUser == "" || *adminPassword == "" {
			return 2
		}
	} else if *adminUser != "" || *adminPassword != "" {
		return 2
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	planRaw, e := install.ReadPrivateFile(*planFile, 262144)
	if e != nil {
		return 1
	}
	plan, e := install.DecodePlan(planRaw, *planSHA)
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
	enrollmentRaw, e := install.ReadPrivateFile(*enrollmentFile, 262144)
	if e != nil {
		return 1
	}
	enrollment, e := install.DecodeEnrollmentPin(enrollmentRaw, *enrollmentSHA)
	if e != nil {
		return 1
	}
	db, kube, e := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsn, *databaseCA)
	if e != nil {
		return 1
	}
	defer db.Close()
	owner, e := install.New(db, kube, planRaw, *planSHA, public, *publicSHA)
	if e != nil {
		return 1
	}
	var value execution.OriginalCoverageSourceOutput
	if action == "sql" {
		value, e = execution.CollectOriginalSQLCoverageSource(active, owner, password, enrollment, *definition, *definitionSHA, *directory)
	} else {
		value, e = execution.CollectOriginalMinIOCoverageSources(active, owner, kube, password, enrollment, *definition, *definitionSHA, execution.MinIONativeAdminFiles{UserFile: *adminUser, PasswordFile: *adminPassword}, *directory)
	}
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(value) != nil {
		return 1
	}
	return 0
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := run(ctx, os.Args[1:], os.Stdout)
	if code != 0 {
		_, _ = io.WriteString(os.Stderr, "original source collection incomplete; keep partial private facts for source-owner inspection; no completeness/adoption/empty-history claim\n")
	}
	os.Exit(code)
}
