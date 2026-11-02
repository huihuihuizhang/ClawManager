// Offline original-owner installation tool. Never linked into an HTTP path.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || len(args) == 0 || out == nil {
		return 2
	}
	action := args[0]
	if action != "policies" && action != "observe" && action != "produce" {
		return 2
	}
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	definition := f.String("definition-file", "", "")
	definitionSHA := f.String("definition-sha256", "", "")
	planFile := f.String("plan-file", "", "")
	planSHA := f.String("plan-sha256", "", "")
	pubFile := f.String("issuer-public-file", "", "")
	pubSHA := f.String("issuer-public-sha256", "", "")
	kubeFile := f.String("kubeconfig-file", "", "")
	kubeSHA := f.String("kubeconfig-sha256", "", "")
	dsnFile := f.String("dsn-file", "", "")
	caFile := f.String("database-ca-file", "", "")
	passwordFile := f.String("local-admin-password-file", "", "")
	enrolFile := f.String("enrollment-pin-file", "", "")
	enrolSHA := f.String("enrollment-pin-sha256", "", "")
	keyFile := f.String("issuer-private-file", "", "")
	directory := f.String("output-directory", "", "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *definition == "" || *definitionSHA == "" {
		return 2
	}
	common := []string{*planFile, *planSHA, *pubFile, *pubSHA, *kubeFile, *kubeSHA, *dsnFile, *caFile, *passwordFile, *enrolFile, *enrolSHA}
	if action == "policies" {
		for _, v := range append(common, *keyFile, *directory) {
			if v != "" {
				return 2
			}
		}
		policies, err := systembackupexecution.PlanOriginalMinIOPermissionPolicies(*definition, *definitionSHA)
		if err != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(policies) != nil {
			return 3
		}
		return 0
	}
	for _, v := range common {
		if v == "" {
			return 2
		}
	}
	if action == "produce" {
		if *keyFile == "" || *directory == "" || install.CheckNewMinIOPermissionDirectory(*directory) != nil {
			return 2
		}
	} else if *keyFile != "" || *directory != "" {
		return 2
	}
	planRaw, err := install.ReadPrivateFile(*planFile, 262144)
	if err != nil {
		return 1
	}
	plan, err := install.DecodePlan(planRaw, *planSHA)
	if err != nil {
		return 1
	}
	public, err := install.ReadPrivateFile(*pubFile, 32)
	if err != nil {
		return 1
	}
	password, err := install.ReadPrivateFile(*passwordFile, 1024)
	if err != nil {
		return 1
	}
	defer clear(password)
	enrolRaw, err := install.ReadPrivateFile(*enrolFile, 262144)
	if err != nil {
		return 1
	}
	enrollment, err := install.DecodeEnrollmentPin(enrolRaw, *enrolSHA)
	if err != nil {
		return 1
	}
	db, kube, err := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *caFile)
	if err != nil {
		return 1
	}
	defer db.Close()
	owner, err := install.New(db, kube, planRaw, *planSHA, public, *pubSHA)
	if err != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if action == "observe" {
		issuer, err := owner.PrepareMinIOPermissionIssue(active, password, enrollment, *definition, *definitionSHA)
		if err != nil {
			return 1
		}
		observation, err := systembackupexecution.ObserveOriginalMinIOPermissions(active, kube, *definition, *definitionSHA)
		if err != nil || issuer.Recheck(active) != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(observation) != nil {
			return 3
		}
		return 0
	}
	receipt, err := systembackupexecution.ProduceOriginalMinIOPermissionSource(active, owner, kube, password, enrollment, *definition, *definitionSHA, *keyFile, *directory)
	if errors.Is(err, install.ErrCommitUnknown) {
		return 4
	}
	if err != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 4
	}
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := run(ctx, os.Args[1:], os.Stdout)
	if code != 0 {
		_, _ = io.WriteString(os.Stderr, "original MinIO owner operation refused; exit 4 means inspect partial/unknown commit before retry\n")
	}
	os.Exit(code)
}
