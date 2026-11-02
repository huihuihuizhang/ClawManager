// Offline original-owner issue/import/revoke. It is never an app/HTTP entry.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || out == nil || len(args) == 0 {
		return 2
	}
	action := args[0]
	if action == "generate-issuer" {
		return generateIssuer(args[1:], out)
	}
	switch action {
	case "issue-capture", "import-capture", "issue-revoke", "revoke", "import-revoke", "resolve", "export-consumer":
	default:
		return 2
	}
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	planFile := f.String("plan-file", "", "")
	planSHA := f.String("plan-sha256", "", "")
	pubFile := f.String("issuer-public-file", "", "")
	pubSHA := f.String("issuer-public-sha256", "", "")
	kubeFile := f.String("kubeconfig-file", "", "")
	kubeSHA := f.String("kubeconfig-sha256", "", "")
	dsnFile := f.String("dsn-file", "", "")
	caFile := f.String("database-ca-file", "", "")
	passwordFile := f.String("local-admin-password-file", "", "")
	enrolFile := f.String("enrollment-pin-file", "", "")
	enrolSHA := f.String("enrollment-pin-sha256", "", "")
	requestFile := f.String("request-files-file", "", "")
	requestSHA := f.String("request-files-sha256", "", "")
	draftFile := f.String("record-draft-file", "", "")
	draftSHA := f.String("record-draft-sha256", "", "")
	keyFile := f.String("issuer-private-file", "", "")
	bundleFile := f.String("bundle-file", "", "")
	bundleSHA := f.String("bundle-sha256", "", "")
	directory := f.String("output-directory", "", "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	for _, value := range []string{*planFile, *planSHA, *pubFile, *pubSHA, *kubeFile, *kubeSHA, *dsnFile, *caFile, *passwordFile, *enrolFile, *enrolSHA} {
		if value == "" {
			return 2
		}
	}
	signing := action == "issue-capture" || action == "issue-revoke" || action == "revoke"
	needsRequest := action == "issue-capture" || action == "import-capture"
	if signing != (*keyFile != "") || needsRequest != (*requestFile != "" && *requestSHA != "") || !needsRequest && (*requestFile != "" || *requestSHA != "") {
		return 2
	}
	if action == "issue-capture" && (*draftFile == "" || *draftSHA == "") || action != "issue-capture" && (*draftFile != "" || *draftSHA != "") {
		return 2
	}
	if signing && (*directory == "" || *bundleFile != "" || *bundleSHA != "") || !signing && (*bundleFile == "" || *bundleSHA == "") || !signing && action != "export-consumer" && *directory != "" || action == "export-consumer" && *directory == "" {
		return 2
	}
	if signing && install.CheckNewBundleDirectory(*directory) != nil {
		return 1
	}
	read := func(path string, limit int64) ([]byte, error) { return install.ReadPrivateFile(path, limit) }
	planRaw, e := read(*planFile, 262144)
	if e != nil {
		return 1
	}
	p, e := install.DecodePlan(planRaw, *planSHA)
	if e != nil {
		return 1
	}
	public, e := read(*pubFile, 32)
	if e != nil {
		return 1
	}
	password, e := read(*passwordFile, 1024)
	if e != nil {
		return 1
	}
	defer clear(password)
	enrolRaw, e := read(*enrolFile, 262144)
	if e != nil {
		return 1
	}
	enrol, e := install.DecodeEnrollmentPin(enrolRaw, *enrolSHA)
	if e != nil {
		return 1
	}
	db, kube, e := install.OpenConnections(p, *kubeFile, *kubeSHA, *dsnFile, *caFile)
	if e != nil {
		return 1
	}
	defer db.Close()
	i, e := install.New(db, kube, planRaw, *planSHA, public, *pubSHA)
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var files install.RequestFiles
	if needsRequest {
		raw, e := read(*requestFile, 262144)
		if e != nil {
			return 1
		}
		files, e = install.DecodeRequestFiles(raw, *requestSHA)
		if e != nil {
			return 1
		}
	}
	var bundle []byte
	if signing {
		key, e := read(*keyFile, 64)
		if e != nil {
			return 1
		}
		defer clear(key)
		if action == "issue-capture" {
			draft, e := read(*draftFile, 262144)
			if e != nil {
				return 1
			}
			bundle, e = i.IssueCapture(active, password, enrol, draft, *draftSHA, key, files)
			if e != nil {
				return 1
			}
		} else {
			bundle, e = i.IssueRevocation(active, password, enrol, key)
			if e != nil {
				return 1
			}
		}
		if install.SaveFrozenBundle(*directory, bundle) != nil {
			return 1
		}
		if action != "revoke" {
			if json.NewEncoder(out).Encode(map[string]string{"status": "signed_bundle_frozen", "bundle_sha256": digest(bundle)}) != nil {
				return 3
			}
			return 0
		}
	} else {
		bundle, e = read(*bundleFile, 262144)
		if e != nil || digest(bundle) != *bundleSHA {
			return 1
		}
	}
	var result install.AuthorityReceipt
	switch action {
	case "import-capture":
		result, e = i.ImportCapture(active, password, enrol, bundle, digest(bundle), files)
	case "revoke", "import-revoke":
		result, e = i.ImportRevocation(active, password, enrol, bundle, digest(bundle))
	case "resolve":
		result, e = i.Resolve(active, password, enrol, bundle, digest(bundle))
	case "export-consumer":
		result, e = i.ExportCommitted(active, password, enrol, bundle, digest(bundle), *directory)
	}
	if errors.Is(e, install.ErrCommitUnknown) {
		if json.NewEncoder(out).Encode(map[string]string{"status": "commit_unknown", "next_action": "resolve_same_frozen_bundle", "bundle_sha256": digest(bundle)}) != nil {
			return 3
		}
		return 3
	}
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	return 0
}
func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout))
}
