package install

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"
)

// RunOriginalC1S3Materials is a standalone command, leaving D's shared CLI
// untouched. Exit 2 is usage, 1 is rejection/native uncertainty, 3 is output
// loss. Query recovers only a complete retained signed result without reissue.
func RunOriginalC1S3Materials(ctx context.Context, args []string, out io.Writer) int {
	if len(args) == 0 || (args[0] != "issue" && args[0] != "query") || ctx == nil || out == nil {
		return 2
	}
	action := args[0]
	f := flag.NewFlagSet("system-backup-c1-s3-materials "+action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	v := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "inputs-file", "inputs-sha256", "issuer-private-file", "issuer-private-sha256", "output-directory"} {
		v[name] = f.String(name, "", "")
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	get := func(name string) string { return *v[name] }
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256"} {
		if get(name) == "" {
			return 2
		}
	}
	if action == "issue" && (get("inputs-file") == "" || get("inputs-sha256") == "" || get("issuer-private-file") == "" || get("issuer-private-sha256") == "") {
		return 2
	}
	if action == "query" && (get("output-directory") == "" || get("issuer-private-file") != "" || get("issuer-private-sha256") != "" || get("inputs-file") != "" || get("inputs-sha256") != "") {
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
	db, kube, e := OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer db.Close()
	i, e := New(db, kube, raw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var receipt OriginalC1S3Receipt
	if action == "issue" {
		b, e := read("inputs-file", "inputs-sha256", 262144)
		var in OriginalC1S3Inputs
		if e != nil || decodeExact(b, &in) != nil {
			return 1
		}
		private, e := read("issuer-private-file", "issuer-private-sha256", 64)
		if e != nil {
			return 1
		}
		defer clear(private)
		receipt, e = i.ProduceOriginalC1S3Material(active, password, enrollment, in, private)
		if e != nil {
			_ = json.NewEncoder(out).Encode(receipt)
			return 1
		}
	} else {
		receipt, e = i.QueryOriginalC1S3Material(active, password, enrollment, get("output-directory"))
		if e != nil {
			_ = json.NewEncoder(out).Encode(receipt)
			return 1
		}
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
