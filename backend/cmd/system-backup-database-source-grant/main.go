// Offline native database-source delegation. Authenticated original issuer,
// actual Service identity/TLS/finite grants/full census; no task or readiness.
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
	flags := flag.NewFlagSet("system-backup-database-source-grant", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planFile := flags.String("plan-file", "", "original independently selected canonical installation plan")
	planSHA := flags.String("plan-sha256", "", "original selected plan SHA256")
	publicFile := flags.String("issuer-public-file", "", "original selected raw Ed25519 public key")
	publicSHA := flags.String("issuer-public-sha256", "", "independently selected issuer public key SHA256")
	kubeFile := flags.String("kubeconfig-file", "", "private authenticated installation owner kubeconfig")
	kubeSHA := flags.String("kubeconfig-sha256", "", "original selected kubeconfig SHA256")
	dsnFile := flags.String("dsn-file", "", "private installer SQL DSN")
	dbCAFile := flags.String("database-ca-file", "", "original pinned database CA")
	passwordFile := flags.String("local-admin-password-file", "", "private exact original local administrator password bytes")
	enrollmentFile := flags.String("enrollment-pin-file", "", "original independently selected enrollment receipt pin")
	enrollmentSHA := flags.String("enrollment-pin-sha256", "", "original enrollment pin file SHA256")
	definitionFile := flags.String("definition-file", "", "private unsigned original six-domain source declaration")
	definitionSHA := flags.String("definition-sha256", "", "original selected source declaration SHA256")
	privateFile := flags.String("source-issuer-private-file", "", "private original enrolled canonical Ed25519 key")
	databaseIssueFile := flags.String("database-source-definition-file", "", "private canonical original database source/service/credential mapping")
	databaseIssueSHA := flags.String("database-source-definition-sha256", "", "independently selected database source definition SHA256")
	if ctx == nil || out == nil || flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	for _, value := range []*string{planFile, planSHA, publicFile, publicSHA, kubeFile, kubeSHA, dsnFile, dbCAFile, passwordFile, enrollmentFile, enrollmentSHA, definitionFile, definitionSHA, privateFile, databaseIssueFile, databaseIssueSHA} {
		if *value == "" {
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
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	sequence, err := execution.BeginOriginalCaptureSequence(active, installer, password, pin, *definitionFile, *definitionSHA, *privateFile)
	if err != nil {
		return 1
	}
	receipt, err := sequence.IssueDatabaseSourceGrant(active, *databaseIssueFile, *databaseIssueSHA)
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
