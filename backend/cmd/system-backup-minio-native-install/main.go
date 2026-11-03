// Once-only original MinIO administrator setup; no runtime task route.
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

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || len(args) == 0 || out == nil {
		return 2
	}
	action := args[0]
	if action != "generate" && action != "bind-d" && action != "probe" && action != "apply" {
		return 2
	}
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	templateFile := f.String("definition-template-file", "", "")
	templateSHA := f.String("definition-template-sha256", "", "")
	directory := f.String("output-directory", "", "")
	dPreparedFile := f.String("d-prepared-receipt-file", "", "")
	dPreparedSHA := f.String("d-prepared-receipt-sha256", "", "")
	materialsFile := f.String("native-materials-file", "", "")
	materialsSHA := f.String("native-materials-sha256", "", "")
	adminUser := f.String("admin-user-file", "", "")
	adminPassword := f.String("admin-password-file", "", "")
	mcFile := f.String("mc-file", "", "")
	mcSHA := f.String("mc-sha256", "", "")
	planFile := f.String("plan-file", "", "")
	planSHA := f.String("plan-sha256", "", "")
	publicFile := f.String("issuer-public-file", "", "")
	publicSHA := f.String("issuer-public-sha256", "", "")
	kubeFile := f.String("kubeconfig-file", "", "")
	kubeSHA := f.String("kubeconfig-sha256", "", "")
	dsnFile := f.String("dsn-file", "", "")
	databaseCA := f.String("database-ca-file", "", "")
	passwordFile := f.String("local-admin-password-file", "", "")
	enrollmentFile := f.String("enrollment-pin-file", "", "")
	enrollmentSHA := f.String("enrollment-pin-sha256", "", "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	common := []string{*planFile, *planSHA, *publicFile, *publicSHA, *kubeFile, *kubeSHA, *dsnFile, *databaseCA, *passwordFile, *enrollmentFile, *enrollmentSHA}
	if action != "apply" {
		for _, v := range common {
			if v != "" {
				return 2
			}
		}
		if *materialsFile != "" || *materialsSHA != "" || *mcFile != "" || *mcSHA != "" || *templateFile == "" || *templateSHA == "" {
			return 2
		}
	}
	if action != "bind-d" && (*dPreparedFile != "" || *dPreparedSHA != "") {
		return 2
	}
	if action == "generate" || action == "bind-d" {
		if *directory == "" || *adminUser != "" || *adminPassword != "" {
			return 2
		}
		var value execution.MinIONativeInstallOutput
		var e error
		if action == "bind-d" {
			if *dPreparedFile == "" || *dPreparedSHA == "" {
				return 2
			}
			value, e = execution.BindDPreparedMinIONativeMaterials(*templateFile, *templateSHA, *dPreparedFile, *dPreparedSHA, *directory)
		} else {
			value, e = execution.GenerateOriginalMinIONativeMaterials(*templateFile, *templateSHA, *directory)
		}
		if e != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(value) != nil {
			return 4
		}
		return 0
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	admin := execution.MinIONativeAdminFiles{UserFile: *adminUser, PasswordFile: *adminPassword, MCFile: *mcFile, MCSHA256: *mcSHA}
	if *adminUser == "" || *adminPassword == "" {
		return 2
	}
	if action == "probe" {
		if *directory != "" {
			return 2
		}
		value, e := execution.InspectOriginalMinIONativeProvider(active, *templateFile, *templateSHA, admin)
		if e != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(value) != nil {
			return 4
		}
		return 0
	}
	if *templateFile != "" || *templateSHA != "" || *directory != "" || *materialsFile == "" || *materialsSHA == "" || *mcFile == "" || *mcSHA == "" {
		return 2
	}
	for _, v := range common {
		if v == "" {
			return 2
		}
	}
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
	db, kube, e := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *databaseCA)
	if e != nil {
		return 1
	}
	defer db.Close()
	owner, e := install.New(db, kube, planRaw, *planSHA, public, *publicSHA)
	if e != nil {
		return 1
	}
	value, e := execution.ApplyOriginalMinIONativeMaterials(active, owner, kube, password, enrollment, *materialsFile, *materialsSHA, admin)
	if json.NewEncoder(out).Encode(value) != nil {
		return 4
	}
	if errors.Is(e, install.ErrCommitUnknown) {
		return 4
	}
	if e != nil {
		return 1
	}
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := run(ctx, os.Args[1:], os.Stdout)
	if code != 0 {
		_, _ = io.WriteString(os.Stderr, "native MinIO setup incomplete; retain this same original material intent and inspect same-name state before retry; no account secret/password was logged\n")
	}
	os.Exit(code)
}
