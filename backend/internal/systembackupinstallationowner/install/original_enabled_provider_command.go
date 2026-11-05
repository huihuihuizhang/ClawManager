package install

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"path/filepath"
	"time"
)

type OriginalEnabledProviderMaterialReceipt struct {
	Version, State string
	Material       BootstrapSourceFilePin
	Provider       OriginalRuntimeProviderIssueReceipt
	ConfigVersion  uint64
	ConfigSHA256   string
	Until          time.Time
}

// Standalone owner CLI; no D shared main or request-handler surface changes.
// Query accepts ONLY retained original material, never inputs/new Until.
func RunOriginalEnabledProviderMaterials(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || out == nil || len(args) == 0 || (args[0] != "issue" && args[0] != "query") {
		return 2
	}
	action := args[0]
	f := flag.NewFlagSet("system-backup-enabled-provider-materials "+action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	metadata := f.Bool("minio-metadata-profile", false, "")
	values := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "runtime-dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "inputs-file", "inputs-sha256", "material-file", "material-sha256"} {
		values[name] = f.String(name, "", "")
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	get := func(name string) string { return *values[name] }
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "runtime-dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256"} {
		if get(name) == "" {
			return 2
		}
	}
	if action == "issue" && (get("inputs-file") == "" || get("inputs-sha256") == "" || get("material-file") != "" || get("material-sha256") != "") {
		return 2
	}
	if action == "query" && (get("material-file") == "" || get("material-sha256") == "" || get("inputs-file") != "" || get("inputs-sha256") != "") {
		return 2
	}
	read := func(file, sha string, limit int64) ([]byte, error) {
		return readBootstrapSourcePin(BootstrapSourceFilePin{File: get(file), SHA256: get(sha)}, limit)
	}
	planRaw, e := read("plan-file", "plan-sha256", 262144)
	if e != nil {
		return 1
	}
	plan, e := DecodePlan(planRaw, get("plan-sha256"))
	if e != nil {
		return 1
	}
	public, e := read("issuer-public-file", "issuer-public-sha256", 32)
	if e != nil {
		return 1
	}
	password, e := ReadPrivateFile(get("local-admin-password-file"), 1024)
	if e != nil {
		return 1
	}
	defer clear(password)
	eraw, e := read("enrollment-pin-file", "enrollment-pin-sha256", 262144)
	if e != nil {
		return 1
	}
	enrollment, e := DecodeEnrollmentPin(eraw, get("enrollment-pin-sha256"))
	if e != nil {
		return 1
	}
	db, kube, e := OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer db.Close()
	runtimeDB, _, e := OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("runtime-dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer runtimeDB.Close()
	i, e := New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var result OriginalRuntimeProviderIssueReceipt
	var pin BootstrapSourceFilePin
	if action == "issue" {
		raw, e := read("inputs-file", "inputs-sha256", 262144)
		var in OriginalEnabledRuntimeProviderInputs
		if e != nil || decodeExact(raw, &in) != nil {
			return 1
		}
		if *metadata {
			result, e = i.IssueOriginalEnabledRuntimeProviderAuthoritiesForMinIOMetadata(active, runtimeDB, password, enrollment, in)
		} else {
			result, e = i.IssueOriginalEnabledRuntimeProviderAuthorities(active, runtimeDB, password, enrollment, in)
		}
		if e != nil {
			_ = json.NewEncoder(out).Encode(map[string]string{"Version": "original-enabled-provider-materials-result.v1", "State": "unconfirmed_retain_original_material_do_not_retry"})
			return 1
		}
		file := filepath.Join(in.OutputDirectory, "enabled-provider.material.json")
		material, e := ReadPrivateFile(file, 262144)
		if e != nil {
			return 1
		}
		pin = BootstrapSourceFilePin{File: file, SHA256: hash(material)}
	} else {
		pin = BootstrapSourceFilePin{File: get("material-file"), SHA256: get("material-sha256")}
		if *metadata {
			result, e = i.QueryOriginalEnabledRuntimeProviderAuthoritiesForMinIOMetadata(active, runtimeDB, password, enrollment, pin)
		} else {
			result, e = i.QueryOriginalEnabledRuntimeProviderAuthorities(active, runtimeDB, password, enrollment, pin)
		}
		if e != nil {
			_ = json.NewEncoder(out).Encode(map[string]string{"Version": "original-enabled-provider-materials-result.v1", "State": "unconfirmed_original_rows_or_authority_not_verified"})
			return 1
		}
	}
	raw, e := readBootstrapSourcePin(pin, 262144)
	var m originalEnabledProviderMaterial
	if e != nil || decodeExact(raw, &m) != nil {
		return 1
	}
	receipt := OriginalEnabledProviderMaterialReceipt{Version: "original-enabled-provider-materials-result.v1", State: result.State, Material: pin, Provider: result, ConfigVersion: result.FormalWorkload.ConfigVersion, ConfigSHA256: result.FormalWorkload.ConfigSHA256, Until: m.Until}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
