// Original owner first nonce-file issue / same-intent recovery / current mount
// binding. Outputs are actual producer facts, never caller authorization JSON.
package main

import (
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"encoding/json"
	"flag"
	"github.com/go-sql-driver/mysql"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-original-nonce-material", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "", "issue, resume (same intent only), or bind (actual mount only)")
	planFile := f.String("plan-file", "", "original installation plan")
	planSHA := f.String("plan-sha256", "", "original plan hash")
	publicFile := f.String("issuer-public-file", "", "original enrolled public key")
	publicSHA := f.String("issuer-public-sha256", "", "original public key hash")
	kubeFile := f.String("kubeconfig-file", "", "private original owner kubeconfig")
	kubeSHA := f.String("kubeconfig-sha256", "", "original kubeconfig hash")
	dsnFile := f.String("dsn-file", "", "private installer DSN")
	dbCA := f.String("database-ca-file", "", "original database CA")
	passwordFile := f.String("local-admin-password-file", "", "private actual admin password")
	privateFile := f.String("issuer-private-file", "", "original enrolled private key")
	enrollmentFile := f.String("enrollment-pin-file", "", "actual original enrollment output")
	enrollmentSHA := f.String("enrollment-pin-sha256", "", "original enrollment pin")
	directory := f.String("output-directory", "", "private issue/bind output; resume uses SAME original directory")
	untilText := f.String("until", "", "issue only: fixed RFC3339Nano expiry, at most24h, never renewed on resume")
	sourceFile := f.String("source-file", "", "bind only: issued actual source file")
	sourceSHA := f.String("source-sha256", "", "bind only: issued actual source hash")
	requestFile := f.String("request-files-file", "", "bind only: producer-selected request files DATA")
	requestSHA := f.String("request-files-sha256", "", "bind only: actual request selection hash")
	deployment := f.String("controller-deployment", "", "actual original controller")
	pod := f.String("controller-pod", "", "actual current Pod, re-observe after rollout")
	container := f.String("container", "", "actual readonly mount container")
	volume := f.String("volume", "", "actual readonly original Secret volume")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, v := range []*string{action, planFile, planSHA, publicFile, publicSHA, kubeFile, kubeSHA, dsnFile, dbCA, passwordFile, privateFile, enrollmentFile, enrollmentSHA, directory} {
		if *v == "" {
			return 2
		}
	}
	if *action != "issue" && *action != "resume" && *action != "bind" || *action != "issue" && *untilText != "" {
		return 2
	}
	var until time.Time
	var request install.RequestFiles
	var err error
	if *action == "issue" {
		until, err = time.Parse(time.RFC3339Nano, *untilText)
		if err != nil {
			return 2
		}
	}
	if *action == "bind" {
		for _, v := range []*string{sourceFile, sourceSHA, requestFile, requestSHA, deployment, pod, container, volume} {
			if *v == "" {
				return 2
			}
		}
		raw, e := install.ReadPrivateFile(*requestFile, 262144)
		if e != nil {
			return 1
		}
		request, err = install.DecodeRequestFiles(raw, *requestSHA)
		if err != nil {
			return 1
		}
	}
	raw, err := install.ReadPrivateFile(*planFile, 262144)
	if err != nil {
		return 1
	}
	plan, err := install.DecodePlan(raw, *planSHA)
	if err != nil {
		return 1
	}
	public, err := install.ReadPrivateFile(*publicFile, 32)
	if err != nil {
		return 1
	}
	password, err := install.ReadPrivateFile(*passwordFile, 1024)
	if err != nil {
		return 1
	}
	defer clear(password)
	private, err := install.ReadPrivateFile(*privateFile, 64)
	if err != nil {
		return 1
	}
	defer clear(private)
	pinRaw, err := install.ReadPrivateFile(*enrollmentFile, 262144)
	if err != nil {
		return 1
	}
	pin, err := install.DecodeEnrollmentPin(pinRaw, *enrollmentSHA)
	if err != nil {
		return 1
	}
	db, kube, err := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *dbCA)
	if err != nil {
		return 1
	}
	defer db.Close()
	installer, err := install.New(db, kube, raw, *planSHA, public, *publicSHA)
	if err != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var receipt any
	switch *action {
	case "issue":
		receipt, err = installer.PrepareOriginalNonceMaterial(active, password, pin, install.OriginalNonceMaterialOptions{OutputDirectory: *directory, Until: until}, private)
	case "resume":
		receipt, err = installer.ResumeOriginalNonceMaterial(active, password, pin, *directory, private)
	case "bind":
		receipt, err = installer.BindOriginalNonceMaterial(active, password, pin, install.OriginalNonceMountOptions{Source: install.BootstrapSourceFilePin{File: *sourceFile, SHA256: *sourceSHA}, Request: request, ControllerDeployment: *deployment, ControllerPod: *pod, Container: *container, Volume: *volume, OutputDirectory: *directory}, private)
	}
	if err != nil {
		// Preserve private original intent/material/native resources. No secret
		// values or native errors go to stdout/stderr; resume the same operation.
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
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
