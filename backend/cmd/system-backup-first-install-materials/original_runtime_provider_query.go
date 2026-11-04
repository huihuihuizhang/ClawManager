package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

func runOriginalRuntimeProviderQuery(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return 2
	}
	f := flag.NewFlagSet("query-initial-provider-authorities", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	names := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "runtime-sql-metadata-receipt-file", "runtime-sql-metadata-receipt-sha256", "pending-provider-result-file", "pending-provider-result-sha256"}
	values := map[string]*string{}
	for _, name := range names {
		values[name] = f.String(name, "", "")
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, name := range names {
		if *values[name] == "" {
			return 2
		}
	}
	get := func(name string) string { return *values[name] }
	planRaw, e := install.ReadPrivateFile(get("plan-file"), 262144)
	if e != nil {
		return 1
	}
	plan, e := install.DecodePlan(planRaw, get("plan-sha256"))
	if e != nil {
		return 1
	}
	public, e := install.ReadPrivateFile(get("issuer-public-file"), 32)
	if e != nil {
		return 1
	}
	password, e := install.ReadPrivateFile(get("local-admin-password-file"), 1024)
	if e != nil {
		return 1
	}
	defer clear(password)
	enrollmentRaw, e := install.ReadPrivateFile(get("enrollment-pin-file"), 262144)
	if e != nil {
		return 1
	}
	enrollment, e := install.DecodeEnrollmentPin(enrollmentRaw, get("enrollment-pin-sha256"))
	if e != nil {
		return 1
	}
	db, kube, e := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer db.Close()
	owner, e := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result, e := owner.QueryOriginalRuntimeProviderInstallation(active, password, enrollment, install.BootstrapSourceFilePin{File: get("runtime-sql-metadata-receipt-file"), SHA256: get("runtime-sql-metadata-receipt-sha256")}, install.BootstrapSourceFilePin{File: get("pending-provider-result-file"), SHA256: get("pending-provider-result-sha256")})
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	if result.State == "committed_original_rows_verified" {
		return 0
	}
	return 4
}
