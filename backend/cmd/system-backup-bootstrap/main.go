// D offline composition entry. No HTTP bootstrap route or owner bypass flags.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	bootstrapsecurity "clawreef/internal/systembackupbootstrapsecurity"
	security "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
)

// Link concrete owner implementations here. A supplies the local pinned RBAC
// and issuer-registry validators; remaining resources stay unavailable. Never
// populate these interfaces from deployment approval booleans.
func linkedOwnerAdapters() security.BootstrapOwnerAdapters {
	issuers := bootstrapsecurity.NewIssuers("/run/system-backup/registries")
	return security.BootstrapOwnerAdapters{Registries: map[string]security.BootstrapResourceValidator{
		"rbac_bindings":          bootstrapsecurity.NewRBAC("/run/system-backup/registries"),
		"provider_proof_issuers": issuers,
		"strong_auth_issuers":    issuers,
	}}
}

func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code := run(ctx, os.Args[1:], os.Stdout, linkedOwnerAdapters())
	if code != 0 && code != 2 {
		fmt.Fprintln(os.Stderr, "bootstrap rejected or failed; retain the same target and idempotency key")
	}
	os.Exit(code)
}

func run(ctx context.Context, args []string, out io.Writer, owners security.BootstrapOwnerAdapters) int {
	flags := flag.NewFlagSet("system-backup-bootstrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requirements := flags.Bool("requirements", false, "list missing compiled owner adapters without reading inputs or opening SQL")
	check := flags.Bool("check", false, "check pinned deployment input integrity only")
	apply := flags.Bool("apply", false, "create disabled v1 through the bootstrap transaction after full admission")
	path := flags.String("deployment-file", "", "deployment-owned JSON file")
	digest := flags.String("deployment-sha256", "", "exact SHA-256 of the deployment file")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 1
	}
	modes := 0
	for _, enabled := range []bool{*requirements, *check, *apply} {
		if enabled {
			modes++
		}
	}
	if modes != 1 {
		return 1
	}
	emit := func(v any, code int) int {
		if json.NewEncoder(out).Encode(v) != nil {
			return 1
		}
		return code
	}
	if *requirements {
		if *path != "" || *digest != "" {
			return 1
		}
		missing := security.MissingBootstrapOwnerAdapters(owners)
		status, code := "adapters_linked", 0
		if len(missing) != 0 {
			status, code = "blocked", 2
		}
		return emit(map[string]any{"status": status, "missing_adapters": missing, "provider_admission": "not_run", "database_opened": false, "configuration_mutated": false}, code)
	}
	if *path == "" || *digest == "" {
		return 1
	}
	d, err := security.LoadBootstrapDeployment(*path, *digest, owners)
	if err != nil {
		return 1
	}
	r, err := d.Inspect()
	if err != nil {
		return 1
	}
	// Candidate Apply defers non-authorizing physical registry failures until
	// the locked history/new-use branch. Check remains a complete input report;
	// missing owner implementations always block before credentials/providers.
	if r.Status == "blocked" && (!*apply || !d.UsesCandidateConsumption() || len(r.MissingAdapters) != 0) {
		return emit(r, 2)
	}
	if *check {
		return emit(r, 0)
	}
	ctx, done := context.WithTimeout(ctx, 2*time.Minute)
	defer done()
	result, err := d.Apply(ctx)
	if errors.Is(err, security.ErrRegistrationCommitUnknown) {
		return emit(map[string]any{"status": "commit_unknown", "same_key_retry_required": true, "backup_enabled": false, "human_mfa_verified": false}, 3)
	}
	if err != nil {
		return 1
	}
	return emit(map[string]any{"status": "disabled_config_initialized", "result": result, "backup_enabled": false, "human_mfa_verified": false}, 0)
}
