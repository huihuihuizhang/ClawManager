package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"time"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
)

// Explicit existing-tool action, never an alias for install/enable/task.
func runPublicationRuntime(ctx context.Context, args []string, out io.Writer) int {
	return runPublicationRuntimeSelected(ctx, args, out, false)
}

func runEnabledPublicationRuntime(ctx context.Context, args []string, out io.Writer) int {
	return runPublicationRuntimeSelected(ctx, args, out, true)
}

func runPublicationRuntimeSelected(ctx context.Context, args []string, out io.Writer, enabledMode bool) int {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return 2
	}
	f := flag.NewFlagSet("issue-runtime-materials", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	names := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "runtime-dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "source-definition-file", "source-definition-sha256", "components-template-file", "components-template-sha256", "runtime-sources-file", "runtime-sources-sha256", "runtime-owner-inputs-file", "runtime-owner-inputs-sha256", "output-definition-file", "output-components-file"}
	if enabledMode {
		names = append(names, "enable-operation-file", "enable-operation-sha256", "request-files-file", "request-files-sha256", "enabled-forward-file", "enabled-forward-sha256", "original-forward-file", "original-forward-sha256", "output-signers-file", "output-verifier-file")
	}
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
	read := func(name, pin string, limit int64) ([]byte, error) {
		raw, e := install.ReadPrivateFile(get(name), limit)
		sum := sha256.Sum256(raw)
		if e != nil || hex.EncodeToString(sum[:]) != get(pin) {
			return nil, install.ErrInstall
		}
		return raw, nil
	}
	planRaw, e := read("plan-file", "plan-sha256", 262144)
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
	enrolRaw, e := read("enrollment-pin-file", "enrollment-pin-sha256", 262144)
	if e != nil {
		return 1
	}
	enrollment, e := install.DecodeEnrollmentPin(enrolRaw, get("enrollment-pin-sha256"))
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
	pin := func(file, hash string) install.BootstrapSourceFilePin {
		return install.BootstrapSourceFilePin{File: get(file), SHA256: get(hash)}
	}
	runtimeDB, _, e := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("runtime-dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer runtimeDB.Close()
	in := execution.PublicationRuntimeMaterialInputs{OwnerInputs: pin("runtime-owner-inputs-file", "runtime-owner-inputs-sha256"), SourceDefinition: pin("source-definition-file", "source-definition-sha256"), ComponentsTemplate: pin("components-template-file", "components-template-sha256"), Sources: pin("runtime-sources-file", "runtime-sources-sha256"), OutputDefinitionFile: get("output-definition-file"), OutputComponentsFile: get("output-components-file")}
	var receipt execution.PublicationRuntimeMaterialReceipt
	if enabledMode {
		requestRaw, err := install.ReadPrivateFile(get("request-files-file"), 262144)
		if err != nil {
			return 1
		}
		request, err := install.DecodeRequestFiles(requestRaw, get("request-files-sha256"))
		if err != nil {
			return 1
		}
		enabled, err := owner.PrepareOriginalEnabledPublication(active, password, enrollment, pin("enable-operation-file", "enable-operation-sha256"), request)
		if err != nil {
			return 1
		}
		defer enabled.Close()
		files := execution.EnabledPublicationStartupFiles{Forward: execution.OriginalEnabledSourcePin{File: get("enabled-forward-file"), SHA256: get("enabled-forward-sha256")}, OriginalForward: execution.OriginalEnabledSourcePin{File: get("original-forward-file"), SHA256: get("original-forward-sha256")}, Signers: execution.PublicationSignerInput{File: get("output-signers-file")}, Verifier: execution.PublisherVerifierInput{File: get("output-verifier-file")}}
		receipt, e = execution.ProduceEnabledPublicationRuntimeMaterialsAtSources(active, owner, runtimeDB, kube, password, enrollment, in, enabled, files)
	} else {
		receipt, e = execution.ProducePublicationRuntimeMaterials(active, owner, runtimeDB, kube, password, enrollment, in)
	}
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
