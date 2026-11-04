package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

func runOriginalFirstCaptureDraft(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return 2
	}
	f := flag.NewFlagSet("prepare-initial-capture-draft", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	names := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "request-files-file", "request-files-sha256", "signing-material-file", "signing-material-sha256", "selection-file", "selection-sha256", "controller-deployment", "controller-pod-name", "until", "output-directory"}
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
	until, e := time.Parse(time.RFC3339Nano, get("until"))
	if e != nil {
		return 2
	}
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
	requestRaw, e := install.ReadPrivateFile(get("request-files-file"), 262144)
	if e != nil {
		return 1
	}
	request, e := install.DecodeRequestFiles(requestRaw, get("request-files-sha256"))
	if e != nil {
		return 1
	}
	db, kube, e := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer db.Close()
	installer, e := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result, e := installer.PrepareOriginalFirstCaptureDraft(active, password, enrollment, install.OriginalFirstCaptureDraftInputs{Request: request, SigningMaterial: install.BootstrapSourceFilePin{File: get("signing-material-file"), SHA256: get("signing-material-sha256")}, Selection: install.BootstrapSourceFilePin{File: get("selection-file"), SHA256: get("selection-sha256")}, ControllerDeployment: get("controller-deployment"), ControllerPodName: get("controller-pod-name"), OutputDirectory: get("output-directory"), Until: until})
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	return 0
}
