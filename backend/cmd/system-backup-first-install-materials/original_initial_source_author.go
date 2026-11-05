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
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func runOriginalInitialSourceAuthor(ctx context.Context, args []string, out io.Writer) int {
	return runOriginalSourceAuthorAction(ctx, args, out, false)
}
func runOriginalSourceAPIRefresh(ctx context.Context, args []string, out io.Writer) int {
	return runOriginalSourceAuthorAction(ctx, args, out, true)
}
func runOriginalSourceAuthorAction(ctx context.Context, args []string, out io.Writer, refresh bool) int {
	f := flag.NewFlagSet("author-initial-source-inputs", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	v := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "definition-file", "definition-sha256", "output-directory"} {
		v[name] = f.String(name, "", "actual original owner source or generated operational definition")
	}
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, value := range v {
		if *value == "" {
			return 2
		}
	}
	get := func(name string) string { return *v[name] }
	planRaw, err := install.ReadPrivateFile(get("plan-file"), 262144)
	if err != nil {
		return 1
	}
	plan, err := install.DecodePlan(planRaw, get("plan-sha256"))
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
	raw, err := install.ReadSourceMaterialFile(get("definition-file"))
	if err != nil {
		return 1
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != get("definition-sha256") {
		return 1
	}
	if _, err = jsoncanonicalizer.Transform(raw); err != nil {
		return 1
	}
	var definition execution.OriginalInitialSourceAuthorInputs
	var successor execution.OriginalSourceAPIRefreshInputs
	var selected any = &definition
	if refresh {
		selected = &successor
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(selected) != nil || d.Decode(new(any)) != io.EOF {
		return 1
	}
	db, kube, err := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if err != nil {
		return 1
	}
	defer db.Close()
	owner, err := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if err != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var receipt any
	if refresh {
		receipt, err = execution.ProduceOriginalSourceAPISuccessor(active, owner, password, enrollment, successor, get("output-directory"))
	} else {
		receipt, err = execution.ProduceOriginalInitialSourceInputs(active, owner, password, enrollment, definition, get("output-directory"))
	}
	if err != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
