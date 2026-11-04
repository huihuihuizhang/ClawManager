package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

func runOriginalBootstrapQuery(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || out == nil {
		return 2
	}
	f := flag.NewFlagSet("query-original", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	values := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "bootstrap-deployment-file", "bootstrap-deployment-sha256", "consumption-file", "consumption-sha256"} {
		values[name] = f.String(name, "", "")
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, value := range values {
		if *value == "" {
			return 2
		}
	}
	v := func(name string) string { return *values[name] }
	raw, err := install.ReadPrivateFile(v("plan-file"), 262144)
	if err != nil {
		return 1
	}
	plan, err := install.DecodePlan(raw, v("plan-sha256"))
	if err != nil {
		return 1
	}
	public, err := install.ReadPrivateFile(v("issuer-public-file"), 32)
	if err != nil {
		return 1
	}
	password, err := install.ReadPrivateFile(v("local-admin-password-file"), 1024)
	if err != nil {
		return 1
	}
	defer clear(password)
	enrollmentRaw, err := install.ReadPrivateFile(v("enrollment-pin-file"), 262144)
	if err != nil {
		return 1
	}
	enrollment, err := install.DecodeEnrollmentPin(enrollmentRaw, v("enrollment-pin-sha256"))
	if err != nil {
		return 1
	}
	db, kube, err := install.OpenConnections(plan, v("kubeconfig-file"), v("kubeconfig-sha256"), v("dsn-file"), v("database-ca-file"))
	if err != nil {
		return 1
	}
	defer db.Close()
	i, err := install.New(db, kube, raw, v("plan-sha256"), public, v("issuer-public-sha256"))
	if err != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	inspection, err := i.InspectOriginalBootstrapCommit(active, password, enrollment, install.BootstrapSourceFilePin{File: v("bootstrap-deployment-file"), SHA256: v("bootstrap-deployment-sha256")}, install.BootstrapSourceFilePin{File: v("consumption-file"), SHA256: v("consumption-sha256")})
	if err != nil {
		_ = json.NewEncoder(out).Encode(map[string]any{"state": "original_bootstrap_outcome_unknown_no_resend", "resubmit_allowed": false})
		return 3
	}
	if json.NewEncoder(out).Encode(inspection) != nil {
		return 3
	}
	return 0
}
