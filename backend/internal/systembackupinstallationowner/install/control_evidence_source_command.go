package install

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"
)

// Intent is original unsigned DATA selected by the same actual factory; the
// existing original constructor authenticates it. Query never accepts a key,
// signs again, rewrites a grant, or extends the selected original deadline.
func RunOriginalControlEvidenceSourceGrant(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || out == nil || len(args) == 0 || (args[0] != "issue" && args[0] != "query") {
		return 2
	}
	action := args[0]
	f := flag.NewFlagSet("system-backup-control-evidence-source-grant "+action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	v := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "intent-file", "intent-sha256", "source-issuer-private-file"} {
		v[name] = f.String(name, "", "")
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	get := func(name string) string { return *v[name] }
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "intent-file", "intent-sha256"} {
		if get(name) == "" {
			return 2
		}
	}
	if action == "issue" && get("source-issuer-private-file") == "" || action == "query" && get("source-issuer-private-file") != "" {
		return 2
	}
	read := func(file, sha string, limit int64) ([]byte, error) {
		return readBootstrapSourcePin(BootstrapSourceFilePin{File: get(file), SHA256: get(sha)}, limit)
	}
	raw, e := read("plan-file", "plan-sha256", 262144)
	if e != nil {
		return 1
	}
	plan, e := DecodePlan(raw, get("plan-sha256"))
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
	iraw, e := read("intent-file", "intent-sha256", 262144)
	if e != nil {
		return 1
	}
	intent, e := DecodeControlEvidenceSourceIntent(iraw, get("intent-sha256"))
	if e != nil {
		return 1
	}
	db, kube, e := OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer db.Close()
	i, e := New(db, kube, raw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	p, e := i.PrepareSourceMaterialIssue(active, password, enrollment, intent)
	if e != nil {
		return 1
	}
	var result ControlEvidenceSourceIssueResult
	if action == "issue" {
		key, e := ReadPrivateFile(get("source-issuer-private-file"), 64)
		if e != nil {
			return 1
		}
		defer clear(key)
		result, e = p.IssueControlEvidenceSource(active, key)
		if e != nil {
			return 1
		}
	} else {
		result, e = p.QueryControlEvidenceSource(active)
		if e != nil {
			return 1
		}
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	return 0
}
