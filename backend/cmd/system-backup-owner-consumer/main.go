// Offline authenticated export of current original capture consumer inputs.
package main

import (
	"context"
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

func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || out == nil {
		return 2
	}
	f := flag.NewFlagSet("system-backup-owner-consumer", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	planFile, planSHA := f.String("plan-file", "", ""), f.String("plan-sha256", "", "")
	publicFile, publicSHA := f.String("issuer-public-file", "", ""), f.String("issuer-public-sha256", "", "")
	kubeFile, kubeSHA := f.String("kubeconfig-file", "", ""), f.String("kubeconfig-sha256", "", "")
	dsnFile, caFile := f.String("dsn-file", "", ""), f.String("database-ca-file", "", "")
	passwordFile := f.String("local-admin-password-file", "", "")
	enrollmentFile, enrollmentSHA := f.String("enrollment-pin-file", "", ""), f.String("enrollment-pin-sha256", "", "")
	bundleFile, bundleSHA := f.String("bundle-file", "", ""), f.String("bundle-sha256", "", "")
	requestFile, requestSHA := f.String("request-files-file", "", ""), f.String("request-files-sha256", "", "")
	consumerKubeFile, consumerKubeSHA := f.String("consumer-kubeconfig-file", "", ""), f.String("consumer-kubeconfig-sha256", "", "")
	directory := f.String("output-directory", "", "")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, value := range []string{*planFile, *planSHA, *publicFile, *publicSHA, *kubeFile, *kubeSHA, *dsnFile, *caFile, *passwordFile, *enrollmentFile, *enrollmentSHA, *bundleFile, *bundleSHA, *requestFile, *requestSHA, *consumerKubeFile, *consumerKubeSHA, *directory} {
		if value == "" {
			return 2
		}
	}
	planRaw, e := install.ReadPrivateFile(*planFile, 262144)
	if e != nil {
		return 1
	}
	plan, e := install.DecodePlan(planRaw, *planSHA)
	if e != nil {
		return 1
	}
	public, e := install.ReadPrivateFile(*publicFile, 32)
	if e != nil {
		return 1
	}
	password, e := install.ReadPrivateFile(*passwordFile, 1024)
	if e != nil {
		return 1
	}
	defer clear(password)
	enrollmentRaw, e := install.ReadPrivateFile(*enrollmentFile, 262144)
	if e != nil {
		return 1
	}
	enrollment, e := install.DecodeEnrollmentPin(enrollmentRaw, *enrollmentSHA)
	if e != nil {
		return 1
	}
	requestRaw, e := install.ReadPrivateFile(*requestFile, 262144)
	if e != nil {
		return 1
	}
	request, e := install.DecodeRequestFiles(requestRaw, *requestSHA)
	if e != nil {
		return 1
	}
	bundle, e := install.ReadPrivateFile(*bundleFile, 262144)
	if e != nil {
		return 1
	}
	db, kube, e := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *caFile)
	if e != nil {
		return 1
	}
	defer db.Close()
	i, e := install.New(db, kube, planRaw, *planSHA, public, *publicSHA)
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result, e := i.ExportBootstrapCaptureConsumer(active, password, enrollment, bundle, *bundleSHA, request, *consumerKubeFile, *consumerKubeSHA, *directory)
	if errors.Is(e, install.ErrCommitUnknown) {
		_ = json.NewEncoder(out).Encode(map[string]string{"status": "original_source_readback_unknown", "next_action": "resolve_same_frozen_bundle", "bundle_sha256": *bundleSHA})
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
