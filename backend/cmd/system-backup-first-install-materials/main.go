// Offline first-install materialization: actual original issuer -> immutable
// worker inputs/mappings -> independently finalized metadata. No task/enable.
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
	if len(args) > 0 && args[0] == "issue-initial-provider-authorities" {
		return runOriginalRuntimeProvider(ctx, args[1:], out)
	}
	if len(args) > 0 && args[0] == "issue-initial-forward" {
		return runOriginalRuntimeExecution(ctx, args[1:], out)
	}
	if len(args) > 0 && (args[0] == "issue-signing-material" || args[0] == "issue-publication-authorization" || args[0] == "reissue-enabled-forward" || args[0] == "issue-enabled-publication-authorization") {
		return runOriginalPublicationOwner(ctx, args, out)
	}
	if len(args) > 0 && args[0] == "issue-runtime-materials" {
		return runPublicationRuntime(ctx, args[1:], out)
	}
	if len(args) > 0 && args[0] == "issue-functional-materials" {
		return runFunctionalPublication(ctx, args[1:], out)
	}
	flags := flag.NewFlagSet("system-backup-first-install-materials", flag.ContinueOnError)
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
	templateFile := flags.String("components-template-file", "", "private original component template; only two original grant pins are pending")
	templateSHA := flags.String("components-template-sha256", "", "independent original component template SHA256")
	resolvedFile := flags.String("resolved-components-file", "", "create-only private resolved component output beside original bundle")
	intermediateFile := flags.String("intermediate-file", "", "create-only private materialized declaration output beside original bundle")
	if ctx == nil || out == nil || flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	for _, value := range []*string{planFile, planSHA, publicFile, publicSHA, kubeFile, kubeSHA, dsnFile, runtimeDSNFile, dbCAFile, passwordFile, enrollmentFile, enrollmentSHA, definitionFile, definitionSHA, privateFile, templateFile, templateSHA, resolvedFile, intermediateFile} {
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
	runtimeDB, _, err := install.OpenConnections(plan, *kubeFile, *kubeSHA, *runtimeDSNFile, *dbCAFile)
	if err != nil {
		return 1
	}
	defer runtimeDB.Close()
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	receipt, err := execution.InstallOriginalCaptureMappings(active, installer, kube, password, pin, execution.OriginalCaptureInstallationInputs{DefinitionFile: *definitionFile, DefinitionSHA256: *definitionSHA, IssuerPrivateFile: *privateFile, TemplateFile: *templateFile, TemplateSHA256: *templateSHA, ResolvedComponentsFile: *resolvedFile, IntermediateFile: *intermediateFile}, runtimeDB)
	if err != nil {
		if diagnostic, ok := execution.MaterializationDiagnosticForError(err); ok {
			_ = json.NewEncoder(out).Encode(diagnostic)
		}
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
