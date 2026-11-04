package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"time"

	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
)

// Existing first-install tool, explicit independent purpose issuance actions.
// Neither action accepts a pre-filled Record/SQLOwner/Grant/Passed DTO.
func runOriginalPublicationOwner(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || out == nil || len(args) == 0 {
		return 2
	}
	runtime := args[0] == "issue-publication-authorization"
	if !runtime && args[0] != "issue-signing-material" {
		return 2
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	names := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "source-issuer-private-file", "controller-deployment", "controller-pod-name", "output-directory"}
	if runtime {
		names = append(names, "request-files-file", "request-files-sha256", "runtime-dsn-file", "core-file", "core-sha256", "config-file", "config-sha256", "forward-grant-sha256", "signing-material-file", "signing-material-sha256")
	} else {
		names = append(names, "vault-endpoint", "vault-cluster-id", "vault-jwt-mount", "capture-key", "acceptance-key", "catalog-key", "vault-ca-file", "vault-ca-sha256", "vault-owner-material-file", "vault-owner-material-sha256", "until")
	}
	values := map[string]*string{}
	for _, name := range names {
		values[name] = f.String(name, "", "")
	}
	initJSON := f.Bool("vault-owner-material-is-init-json", false, "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || runtime && *initJSON {
		return 2
	}
	for _, n := range names {
		if *values[n] == "" {
			return 2
		}
	}
	get := func(n string) string { return *values[n] }
	pin := func(file, sha string) install.BootstrapSourceFilePin {
		return install.BootstrapSourceFilePin{File: get(file), SHA256: get(sha)}
	}
	planRaw, e := install.ReadPrivateFile(get("plan-file"), 262144)
	if e != nil {
		return 1
	}
	plan, e := install.DecodePlan(planRaw, get("plan-sha256"))
	if e != nil {
		return 1
	}
	pub, e := install.ReadPrivateFile(get("issuer-public-file"), 32)
	if e != nil {
		return 1
	}
	password, e := install.ReadPrivateFile(get("local-admin-password-file"), 1024)
	if e != nil {
		return 1
	}
	defer clear(password)
	key, e := install.ReadPrivateFile(get("source-issuer-private-file"), 64)
	if e != nil {
		return 1
	}
	defer clear(key)
	enrolRaw, e := install.ReadPrivateFile(get("enrollment-pin-file"), 262144)
	if e != nil {
		return 1
	}
	enrol, e := install.DecodeEnrollmentPin(enrolRaw, get("enrollment-pin-sha256"))
	if e != nil {
		return 1
	}
	db, kube, e := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer db.Close()
	installer, e := install.New(db, kube, planRaw, get("plan-sha256"), pub, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if !runtime {
		until, e := time.Parse(time.RFC3339Nano, get("until"))
		if e != nil {
			return 2
		}
		receipt, e := installer.ProduceOriginalPublicationSigningMaterial(active, password, enrol, install.OriginalPublicationSigningOptions{Endpoint: get("vault-endpoint"), ProviderClusterID: get("vault-cluster-id"), JWTMount: get("vault-jwt-mount"), CaptureKey: get("capture-key"), AcceptanceKey: get("acceptance-key"), CatalogKey: get("catalog-key"), ControllerDeployment: get("controller-deployment"), ControllerPodName: get("controller-pod-name"), CA: pin("vault-ca-file", "vault-ca-sha256"), VaultOwnerMaterial: pin("vault-owner-material-file", "vault-owner-material-sha256"), VaultOwnerMaterialIsInitJSON: *initJSON, Until: until, OutputDirectory: get("output-directory")}, key)
		if e != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		return 0
	}
	requestRaw, e := install.ReadPrivateFile(get("request-files-file"), 262144)
	if e != nil {
		return 1
	}
	request, e := install.DecodeRequestFiles(requestRaw, get("request-files-sha256"))
	if e != nil {
		return 1
	}
	core, e := execution.LoadDeploymentConfig(get("core-file"), get("core-sha256"))
	if e != nil {
		return 1
	}
	public, e := base64.StdEncoding.DecodeString(core.ForwardGrant.PublicKey)
	if e != nil {
		return 1
	}
	forward, e := c.NewPinnedExecutionIdentity(core.ForwardGrant.Path, get("forward-grant-sha256"), core.KeyDirectory, public)
	if e != nil {
		return 1
	}
	profile, e := api.LoadExecutionProfile(core.ProfileFile)
	if e != nil {
		return 1
	}
	_, profileSHA, e := profile.CanonicalIdentity()
	if e != nil {
		return 1
	}
	runtimeDB, _, e := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("runtime-dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer runtimeDB.Close()
	receipt, e := installer.IssueOriginalPublicationAuthorization(active, runtimeDB, password, enrol, install.OriginalPublicationAuthorizationInputs{Request: request, Forward: forward, DeploymentCore: pin("core-file", "core-sha256"), Config: pin("config-file", "config-sha256"), Profile: install.BootstrapSourceFilePin{File: core.ProfileFile, SHA256: profileSHA}, SigningMaterial: pin("signing-material-file", "signing-material-sha256"), ControllerDeployment: get("controller-deployment"), ControllerPodName: get("controller-pod-name"), OutputDirectory: get("output-directory")}, key)
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
