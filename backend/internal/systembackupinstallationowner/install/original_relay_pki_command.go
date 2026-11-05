package install

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"
)

func RunOriginalRelayPKICommand(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-c1-native-inputs relay-pki", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	v := map[string]*string{}
	for _, n := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "inputs-file", "inputs-sha256", "issuer-private-file", "issuer-private-sha256"} {
		v[n] = f.String(n, "", "")
	}
	mode := f.String("mode", "issue", "")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for n, p := range v {
		if n != "issuer-private-file" && n != "issuer-private-sha256" && *p == "" {
			return 2
		}
	}
	get := func(n string) string { return *v[n] }
	raw, e := readBootstrapSourcePin(BootstrapSourceFilePin{get("plan-file"), get("plan-sha256")}, 262144)
	if e != nil {
		return 1
	}
	plan, e := DecodePlan(raw, get("plan-sha256"))
	if e != nil {
		return 1
	}
	public, e := readBootstrapSourcePin(BootstrapSourceFilePin{get("issuer-public-file"), get("issuer-public-sha256")}, 32)
	if e != nil {
		return 1
	}
	password, e := ReadPrivateFile(get("local-admin-password-file"), 1024)
	if e != nil {
		return 1
	}
	defer clear(password)
	eraw, e := readBootstrapSourcePin(BootstrapSourceFilePin{get("enrollment-pin-file"), get("enrollment-pin-sha256")}, 262144)
	if e != nil {
		return 1
	}
	enrollment, e := DecodeEnrollmentPin(eraw, get("enrollment-pin-sha256"))
	if e != nil {
		return 1
	}
	inraw, e := readBootstrapSourcePin(BootstrapSourceFilePin{get("inputs-file"), get("inputs-sha256")}, 262144)
	var in OriginalRelayPKIInputs
	if e != nil || decodeExact(inraw, &in) != nil {
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
	var receipt OriginalRelayPKIReceipt
	if *mode == "query" {
		receipt, e = i.QueryOriginalRelayPKI(active, password, enrollment, in.OutputDirectory)
	} else if *mode == "issue" {
		private, pe := readBootstrapSourcePin(BootstrapSourceFilePin{get("issuer-private-file"), get("issuer-private-sha256")}, 64)
		if pe != nil {
			return 1
		}
		defer clear(private)
		receipt, e = i.IssueOriginalRelayPKI(active, password, enrollment, in, private)
	} else {
		return 2
	}
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
