package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

func runOriginalInitialSourceCoordinates(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("author-initial-source-coordinates", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	runningOnly := f.String("running-only-runtime-test", "", "approved running IDs:deferred IDs in SQL order")
	v := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "output-directory"} {
		v[name] = f.String(name, "", "actual original enrolled installer source location")
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
	fail := func(phase string) int {
		_ = json.NewEncoder(out).Encode(map[string]string{
			"state": "VALIDATION_SOURCE_INVENTORY_UNCONFIRMED",
			"phase": phase,
		})
		return 1
	}
	planRaw, err := install.ReadPrivateFile(get("plan-file"), 262144)
	if err != nil {
		return fail("plan_file")
	}
	plan, err := install.DecodePlan(planRaw, get("plan-sha256"))
	if err != nil {
		return fail("plan_pin")
	}
	public, err := install.ReadPrivateFile(get("issuer-public-file"), 32)
	if err != nil {
		return fail("issuer_public_file")
	}
	password, err := install.ReadPrivateFile(get("local-admin-password-file"), 1024)
	if err != nil {
		return fail("admin_password_file")
	}
	defer clear(password)
	enrollmentRaw, err := install.ReadPrivateFile(get("enrollment-pin-file"), 262144)
	if err != nil {
		return fail("enrollment_pin_file")
	}
	enrollment, err := install.DecodeEnrollmentPin(enrollmentRaw, get("enrollment-pin-sha256"))
	if err != nil {
		return fail("enrollment_pin")
	}
	db, kube, err := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if err != nil {
		return fail("connection_inputs")
	}
	defer db.Close()
	owner, err := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if err != nil {
		return fail("installer_identity")
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	connect, stop := context.WithTimeout(active, 10*time.Second)
	err = db.PingContext(connect)
	stop()
	if err != nil {
		return fail("sql_tls_connect")
	}
	receipt, err := owner.ProduceOriginalInitialSourceCoordinates(active, password, enrollment, get("output-directory"), *runningOnly)
	if err != nil {
		return fail(err.Error())
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
