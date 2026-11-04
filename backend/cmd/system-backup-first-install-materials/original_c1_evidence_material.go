package main

import (
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"
)

func runOriginalC1EvidenceMaterial(ctx context.Context, action string, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || out == nil || action != "issue-initial-c1-evidence-material" && action != "query-initial-c1-evidence-material" {
		return 2
	}
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	names := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "output-directory"}
	if action == "issue-initial-c1-evidence-material" {
		names = append(names, "writer-selection-file", "writer-selection-sha256", "vault-owner-material-file", "vault-owner-material-sha256", "source-issuer-private-file", "controller-deployment", "controller-pod-name", "until")
	}
	values := map[string]*string{}
	for _, n := range names {
		values[n] = f.String(n, "", "")
	}
	var initJSON *bool
	if action == "issue-initial-c1-evidence-material" {
		initJSON = f.Bool("vault-owner-material-is-init-json", false, "")
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, v := range values {
		if *v == "" {
			return 2
		}
	}
	get := func(n string) string { return *values[n] }
	var until time.Time
	var err error
	if action == "issue-initial-c1-evidence-material" {
		until, err = time.Parse(time.RFC3339Nano, get("until"))
		if err != nil {
			return 2
		}
	}
	raw, err := install.ReadPrivateFile(get("plan-file"), 262144)
	if err != nil {
		return 1
	}
	plan, err := install.DecodePlan(raw, get("plan-sha256"))
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
	installer, err := install.New(db, kube, raw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if err != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var receipt install.OriginalC1EvidenceMaterialReceipt
	if action == "query-initial-c1-evidence-material" {
		receipt, err = installer.QueryOriginalC1EvidenceMaterial(active, password, enrollment, get("output-directory"))
	} else {
		private, e := install.ReadPrivateFile(get("source-issuer-private-file"), 64)
		if e != nil {
			return 1
		}
		defer clear(private)
		receipt, err = installer.ProduceOriginalC1EvidenceMaterial(active, password, enrollment, install.OriginalC1EvidenceMaterialOptions{WriterSelection: install.BootstrapSourceFilePin{File: get("writer-selection-file"), SHA256: get("writer-selection-sha256")}, VaultOwnerMaterial: install.BootstrapSourceFilePin{File: get("vault-owner-material-file"), SHA256: get("vault-owner-material-sha256")}, VaultOwnerMaterialIsInitJSON: *initJSON, ControllerDeployment: get("controller-deployment"), ControllerPodName: get("controller-pod-name"), OutputDirectory: get("output-directory"), Until: until}, private)
	}
	if receipt.Version != "" {
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
	}
	if err != nil {
		return 1
	}
	return 0
}
