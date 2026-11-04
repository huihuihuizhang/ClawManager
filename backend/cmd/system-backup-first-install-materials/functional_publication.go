package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"time"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
)

// Explicit existing-tool action, never an alias for install/enable/task.
func runFunctionalPublication(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return 2
	}
	f := flag.NewFlagSet("issue-functional-materials", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	names := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "bundle-file", "bundle-sha256", "classification-definition-file", "classification-definition-sha256", "source-definition-file", "source-definition-sha256", "components-template-file", "components-template-sha256", "consumption-file", "consumption-sha256", "request-files-file", "request-files-sha256", "source-issuer-private-file", "classification-directory", "registry-directory", "output-definition-file", "output-components-file"}
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
	requestRaw, e := read("request-files-file", "request-files-sha256", 262144)
	if e != nil {
		return 1
	}
	request, e := install.DecodeRequestFiles(requestRaw, get("request-files-sha256"))
	if e != nil {
		return 1
	}
	consumptionRaw, e := read("consumption-file", "consumption-sha256", 262144)
	if e != nil {
		return 1
	}
	var consumption pd.BootstrapConsumptionRequest
	decoder := json.NewDecoder(bytes.NewReader(consumptionRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&consumption) != nil || decoder.Decode(new(any)) != io.EOF {
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
	receipt, e := execution.ProduceFunctionalPublicationMaterials(active, owner, password, enrollment, execution.FunctionalPublicationMaterialInputs{Bundle: pin("bundle-file", "bundle-sha256"), ClassificationDefinition: pin("classification-definition-file", "classification-definition-sha256"), SourceDefinition: pin("source-definition-file", "source-definition-sha256"), ComponentsTemplate: pin("components-template-file", "components-template-sha256"), Selection: consumption, Request: request, IssuerPrivateFile: get("source-issuer-private-file"), ClassificationDirectory: get("classification-directory"), RegistryDirectory: get("registry-directory"), OutputDefinitionFile: get("output-definition-file"), OutputComponentsFile: get("output-components-file")})
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
