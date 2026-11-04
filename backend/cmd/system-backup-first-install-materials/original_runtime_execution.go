package main

import (
	a "clawreef/internal/systembackupkekadapter"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

func runOriginalRuntimeExecution(ctx context.Context, args []string, out io.Writer) int {
	return runOriginalRuntimeMaterials(ctx, args, out, false)
}
func runOriginalRuntimeProvider(ctx context.Context, args []string, out io.Writer) int {
	return runOriginalRuntimeMaterials(ctx, args, out, true)
}
func runOriginalRuntimeMaterials(ctx context.Context, args []string, out io.Writer, provider bool) int {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return 2
	}
	f := flag.NewFlagSet("issue-initial-forward", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	names := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "runtime-dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "runtime-issuers-file", "runtime-issuers-sha256", "request-files-file", "request-files-sha256", "core-file", "core-sha256", "profile-file", "profile-sha256", "record-export-file", "record-export-sha256", "controller-deployment", "controller-pod-name", "until", "output-directory"}
	if provider {
		kept := names[:0]
		for _, n := range names {
			if n != "profile-file" && n != "profile-sha256" && n != "record-export-file" && n != "record-export-sha256" {
				kept = append(kept, n)
			}
		}
		names = append(kept, "forward-grant-file", "forward-grant-sha256", "provider-file", "provider-sha256", "worker-jwt-identity-file", "runtime-owner-inputs-file", "runtime-owner-inputs-sha256")
	}
	values := map[string]*string{}
	for _, n := range names {
		values[n] = f.String(n, "", "")
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, n := range names {
		if *values[n] == "" {
			return 2
		}
	}
	get := func(n string) string { return *values[n] }
	pin := func(a, b string) install.BootstrapSourceFilePin {
		return install.BootstrapSourceFilePin{File: get(a), SHA256: get(b)}
	}
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
	owner, e := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	runtimeDB, _, e := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("runtime-dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer runtimeDB.Close()
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if provider {
		result, e := owner.IssueOriginalRuntimeProviderAuthorities(active, runtimeDB, password, enrollment, install.OriginalRuntimeProviderIssueInputs{Issuers: pin("runtime-issuers-file", "runtime-issuers-sha256"), Core: pin("core-file", "core-sha256"), Forward: pin("forward-grant-file", "forward-grant-sha256"), Provider: pin("provider-file", "provider-sha256"), PublicationOwnerInputs: pin("runtime-owner-inputs-file", "runtime-owner-inputs-sha256"), Request: request, ControllerDeployment: get("controller-deployment"), ControllerPodName: get("controller-pod-name"), WorkerJWTIdentityFile: get("worker-jwt-identity-file"), Until: until, OutputDirectory: get("output-directory")})
		if e != nil {
			if errors.Is(e, a.ErrAuthorityCommitUnknown) {
				file := filepath.Join(get("output-directory"), "runtime-provider-authorities.json")
				raw, readErr := install.ReadPrivateFile(file, 262144)
				if readErr != nil {
					return 4
				}
				sum := sha256.Sum256(raw)
				metadataFile := filepath.Join(get("output-directory"), "runtime-installed-metadata.receipt.json")
				metadataRaw, metadataErr := install.ReadPrivateFile(metadataFile, 262144)
				if metadataErr != nil {
					return 4
				}
				metadataSum := sha256.Sum256(metadataRaw)
				if json.NewEncoder(out).Encode(struct {
					State              string
					Pending            install.BootstrapSourceFilePin
					SQLMetadataReceipt install.BootstrapSourceFilePin
					RetryAllowed       bool
				}{"commit_unknown_verify_original_rows", install.BootstrapSourceFilePin{File: file, SHA256: hex.EncodeToString(sum[:])}, install.BootstrapSourceFilePin{File: metadataFile, SHA256: hex.EncodeToString(metadataSum[:])}, false}) != nil {
					return 3
				}
				return 4
			}
			return 1
		}
		if json.NewEncoder(out).Encode(result) != nil {
			return 3
		}
		return 0
	}
	result, e := owner.IssueOriginalRuntimeExecution(active, runtimeDB, password, enrollment, install.OriginalRuntimeExecutionIssueInputs{Issuers: pin("runtime-issuers-file", "runtime-issuers-sha256"), Core: pin("core-file", "core-sha256"), Profile: pin("profile-file", "profile-sha256"), RecordExport: pin("record-export-file", "record-export-sha256"), Request: request, ControllerDeployment: get("controller-deployment"), ControllerPodName: get("controller-pod-name"), Until: until, OutputDirectory: get("output-directory")})
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	return 0
}
