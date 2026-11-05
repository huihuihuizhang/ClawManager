// Independent native Teams object source issuance/query. Actual original
// owner/SQL/Teams inventory/TLS/version reads; never Skills authority.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	if len(args) == 0 || (args[0] != "issue" && args[0] != "query") {
		return 2
	}
	action := args[0]
	flags := flag.NewFlagSet("system-backup-teams-source-grant "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planFile := flags.String("plan-file", "", "original independently selected canonical installation plan")
	planSHA := flags.String("plan-sha256", "", "original selected plan SHA256")
	publicFile := flags.String("issuer-public-file", "", "original selected raw Ed25519 public key")
	publicSHA := flags.String("issuer-public-sha256", "", "independently selected issuer public key SHA256")
	kubeFile := flags.String("kubeconfig-file", "", "private authenticated installation owner kubeconfig")
	kubeSHA := flags.String("kubeconfig-sha256", "", "original selected kubeconfig SHA256")
	dsnFile := flags.String("dsn-file", "", "private installer SQL DSN")
	dbCAFile := flags.String("database-ca-file", "", "original pinned database CA")
	runtimeDSNFile := flags.String("runtime-dsn-file", "", "original dedicated public controller SQL DSN")
	passwordFile := flags.String("local-admin-password-file", "", "private exact original local administrator password bytes")
	enrollmentFile := flags.String("enrollment-pin-file", "", "original independently selected enrollment receipt pin")
	enrollmentSHA := flags.String("enrollment-pin-sha256", "", "original enrollment pin file SHA256")
	definitionFile := flags.String("definition-file", "", "private unsigned original six-domain source declaration")
	definitionSHA := flags.String("definition-sha256", "", "original selected source declaration SHA256")
	privateFile := flags.String("source-issuer-private-file", "", "private original enrolled canonical Ed25519 key")
	metadataProfile := flags.Bool("minio-metadata-profile", false, "authenticate existing original MinIO metadata owner profile")
	if ctx == nil || out == nil || flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	for _, value := range []*string{planFile, planSHA, publicFile, publicSHA, kubeFile, kubeSHA, dsnFile, runtimeDSNFile, dbCAFile, passwordFile, enrollmentFile, enrollmentSHA, definitionFile, definitionSHA} {
		if *value == "" {
			return 2
		}
	}
	if action == "issue" && *privateFile == "" || action == "query" && *privateFile != "" {
		return 2
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
	pinRaw, err := install.ReadPrivateFile(*enrollmentFile, 262144)
	if err != nil {
		return 1
	}
	pin, err := install.DecodeEnrollmentPin(pinRaw, *enrollmentSHA)
	if err != nil {
		return 1
	}
	db, kube, err := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *dbCAFile)
	if err != nil {
		return 1
	}
	defer db.Close()
	installer, err := install.New(db, kube, raw, *planSHA, public, *publicSHA)
	if err != nil {
		return 1
	}
	runtimeDB, _, err := install.OpenConnections(plan, *kubeFile, *kubeSHA, *runtimeDSNFile, *dbCAFile)
	if err != nil {
		return 1
	}
	defer runtimeDB.Close()
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var receipt install.TeamsSourceIssueResult
	workflow := func(actual context.Context) error {
		sequence, e := execution.PrepareOriginalCaptureSourceSequence(actual, installer, password, pin, *definitionFile, *definitionSHA, *privateFile, runtimeDB)
		if e != nil {
			return e
		}
		if action == "issue" {
			receipt, e = sequence.IssueTeamsSourceGrant(actual)
		} else {
			receipt, e = sequence.QueryTeamsSourceGrant(actual)
		}
		return e
	}
	if *metadataProfile {
		err = installer.RunOriginalMinIOMetadataSourceFactory(active, runtimeDB, password, pin, workflow)
	} else {
		err = workflow(active)
	}
	if err != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3 // Files may exist; inspect exact bytes instead of replacing them.
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
