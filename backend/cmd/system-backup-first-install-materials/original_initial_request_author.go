package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

func runOriginalInitialRequestAuthor(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("prepare-initial-request", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	v := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "config-file", "config-sha256", "signing-material-file", "signing-material-sha256", "matrix-key", "change-reason", "until", "output-directory"} {
		v[name] = f.String(name, "", "actual original owner source or explicit installation policy")
	}
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, value := range v {
		if *value == "" {
			return 2
		}
	}
	get := func(name string) string { return *v[name] }
	pin := func(name string) install.BootstrapSourceFilePin {
		return install.BootstrapSourceFilePin{File: get(name + "-file"), SHA256: get(name + "-sha256")}
	}
	until, err := time.Parse(time.RFC3339Nano, get("until"))
	if err != nil {
		return 2
	}
	planRaw, err := install.ReadPrivateFile(get("plan-file"), 262144)
	if err != nil {
		return 1
	}
	plan, err := install.DecodePlan(planRaw, get("plan-sha256"))
	if err != nil {
		return 1
	}
	public, err := install.ReadPrivateFile(get("issuer-public-file"), 32)
	if err != nil {
		return 1
	}
	password, err := install.ReadPrivateFile(get("local-admin-password-file"), 1024)
	if err != nil {
		return 1
	}
	defer clear(password)
	enrollmentRaw, err := install.ReadPrivateFile(get("enrollment-pin-file"), 262144)
	if err != nil {
		return 1
	}
	enrollment, err := install.DecodeEnrollmentPin(enrollmentRaw, get("enrollment-pin-sha256"))
	if err != nil {
		return 1
	}
	db, kube, err := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if err != nil {
		return 1
	}
	defer db.Close()
	owner, err := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if err != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	receipt, err := owner.ProduceOriginalInitialRequestInputs(active, password, enrollment, install.OriginalInitialRequestAuthorInputs{
		Config: pin("config"), SigningMaterial: pin("signing-material"), MatrixKey: get("matrix-key"), ChangeReason: get("change-reason"), Until: until, OutputDirectory: get("output-directory")})
	if err != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
