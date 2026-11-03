// Offline original relay transport reference. No future task/Job permission.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
	"github.com/go-sql-driver/mysql"
)

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func pinned(file, sha string, limit int64) ([]byte, error) {
	raw, e := install.ReadPrivateFile(file, limit)
	if e != nil || digest(raw) != sha {
		return nil, install.ErrInstall
	}
	return raw, nil
}
func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || out == nil || len(args) == 0 {
		return 2
	}
	action := args[0]
	if action != "reference-identity" && action != "issue" && action != "owner-binding" {
		return 2
	}
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	values := map[string]*string{}
	for _, key := range []string{"definition-file", "definition-sha256", "plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "bundle-file", "bundle-sha256", "request-files-file", "request-files-sha256", "consumption-file", "consumption-sha256", "issuer-private-file", "output-directory", "capture-consumer-file", "capture-consumer-pin-file", "record-file", "record-sha256", "signature-file"} {
		values[key] = f.String(key, "", "")
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	required := []string{"definition-file", "definition-sha256"}
	if action == "owner-binding" {
		required = []string{"capture-consumer-file", "capture-consumer-pin-file", "record-file", "record-sha256", "signature-file"}
	}
	if action == "issue" {
		required = append(required, "plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "bundle-file", "bundle-sha256", "request-files-file", "request-files-sha256", "consumption-file", "consumption-sha256", "issuer-private-file", "output-directory")
	}
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
		if *values[key] == "" {
			return 2
		}
	}
	for key, value := range values {
		if !allowed[key] && *value != "" {
			return 2
		}
	}
	get := func(key string) string { return *values[key] }
	if action == "owner-binding" {
		capture := install.NewCaptureSigningConsumer(get("capture-consumer-file"), get("capture-consumer-pin-file"))
		resource, e := install.NewOriginalStatusRelayReference(capture, install.StatusRelayReferenceFiles{RecordFile: get("record-file"), RecordSHA256: get("record-sha256"), SignatureFile: get("signature-file")})
		if e != nil {
			return 1
		}
		binding, e := resource.BindingSHA256()
		if e != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(install.BootstrapOriginalOwnerBinding{Key: "reference:status_relay", SHA256: binding}) != nil {
			return 3
		}
		return 0
	}
	definition, e := pinned(get("definition-file"), get("definition-sha256"), 262144)
	if e != nil {
		return 1
	}
	ref, e := install.StatusRelayReferenceIdentity(definition, get("definition-sha256"))
	if e != nil {
		return 1
	}
	if action == "reference-identity" {
		if json.NewEncoder(out).Encode(map[string]any{"reference": ref, "native_source_observed": false, "authority_issued": false}) != nil {
			return 3
		}
		return 0
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
	defer clear(password)
	if e != nil {
		return 1
	}
	enrollmentRaw, e := pinned(get("enrollment-pin-file"), get("enrollment-pin-sha256"), 262144)
	if e != nil {
		return 1
	}
	enrollment, e := install.DecodeEnrollmentPin(enrollmentRaw, get("enrollment-pin-sha256"))
	if e != nil {
		return 1
	}
	bundle, e := pinned(get("bundle-file"), get("bundle-sha256"), 262144)
	if e != nil {
		return 1
	}
	requestRaw, e := pinned(get("request-files-file"), get("request-files-sha256"), 262144)
	if e != nil {
		return 1
	}
	request, e := install.DecodeRequestFiles(requestRaw, get("request-files-sha256"))
	if e != nil {
		return 1
	}
	selectionRaw, e := pinned(get("consumption-file"), get("consumption-sha256"), 262144)
	var selection pd.BootstrapConsumptionRequest
	if e != nil {
		return 1
	}
	decoder := json.NewDecoder(bytes.NewReader(selectionRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&selection) != nil || decoder.Decode(new(any)) != io.EOF {
		return 1
	}
	key, e := install.ReadPrivateFile(get("issuer-private-file"), 64)
	defer clear(key)
	if e != nil {
		return 1
	}
	db, kube, e := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer db.Close()
	installer, e := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	signed, e := installer.IssueStatusRelayReference(active, password, enrollment, bundle, get("bundle-sha256"), get("definition-file"), get("definition-sha256"), selection, request, key)
	if e != nil || install.SaveFrozenStatusRelayReference(get("output-directory"), signed) != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(map[string]any{"status": "original_relay_transport_reference_issued", "record_sha256": digest(signed.Record), "task_or_Job_authorized": false, "sql_mutated": false}) != nil {
		return 3
	}
	return 0
}
func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout))
}
