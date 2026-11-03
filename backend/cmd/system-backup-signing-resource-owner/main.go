// Offline original signer-resource lifecycle. No HTTP/task/publisher admission.
package main

import (
	"bytes"
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
	"path/filepath"
	"syscall"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func pinnedJSON(file, sha string, out any) error {
	raw, err := install.ReadPrivateFile(file, 262144)
	if err != nil || digest(raw) != sha {
		return install.ErrInstall
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return install.ErrInstall
	}
	round, err := ce.Canonical(out)
	if err != nil || !bytes.Equal(round, raw) {
		return install.ErrInstall
	}
	return nil
}

func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || len(args) == 0 || out == nil {
		return 2
	}
	action := args[0]
	required := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256"}
	switch action {
	case "issue-install":
		required = append(required, "intent-file", "intent-sha256", "request-files-file", "request-files-sha256", "pin-file", "pin-sha256", "issuer-private-file", "output-directory")
	case "issue-revocation":
		required = append(required, "pin-file", "pin-sha256", "bundle-file", "bundle-sha256", "issuer-private-file", "output-directory")
	case "import", "resolve":
		required = append(required, "sql-inputs-file", "sql-inputs-sha256")
	case "export-consumer":
		required = append(required, "sql-inputs-file", "sql-inputs-sha256", "assets-file", "assets-sha256", "consumer-kubeconfig-file", "consumer-kubeconfig-sha256", "output-directory")
	default:
		return 2
	}
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	values := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "intent-file", "intent-sha256", "request-files-file", "request-files-sha256", "pin-file", "pin-sha256", "bundle-file", "bundle-sha256", "issuer-private-file", "output-directory", "sql-inputs-file", "sql-inputs-sha256", "assets-file", "assets-sha256", "consumer-kubeconfig-file", "consumer-kubeconfig-sha256"} {
		values[name] = flags.String(name, "", "")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	allowed := map[string]bool{}
	for _, name := range required {
		allowed[name] = true
		if *values[name] == "" {
			return 2
		}
	}
	for name, value := range values {
		if !allowed[name] && *value != "" {
			return 2
		}
	}
	get := func(name string) string { return *values[name] }
	var pin owner.SigningResourceTrustPin
	var inputs []install.SigningResourceSQLInput
	var assets []install.SigningResourceConsumerAsset
	if action == "issue-install" || action == "issue-revocation" {
		if pinnedJSON(get("pin-file"), get("pin-sha256"), &pin) != nil || install.CheckNewSigningResourceBundleDirectory(get("output-directory"), pin.Purpose) != nil {
			return 1
		}
	} else if action == "export-consumer" && install.CheckNewSigningResourceConsumerDirectory(get("output-directory")) != nil {
		return 1
	}
	if action == "issue-install" {
		var intent install.SigningResourceInstallIntent
		if pinnedJSON(get("intent-file"), get("intent-sha256"), &intent) != nil || intent.Version != install.SigningResourceInstallIntentVersion {
			return 1
		}
		x, xerr := ce.Canonical(intent.Pin)
		y, yerr := ce.Canonical(pin)
		if xerr != nil || yerr != nil || !bytes.Equal(x, y) {
			return 1
		}
	} else if action != "issue-revocation" {
		var err error
		inputs, err = install.LoadSigningResourceSQLInputs(get("sql-inputs-file"), get("sql-inputs-sha256"))
		if err != nil {
			return 1
		}
		if action == "export-consumer" {
			assets, err = install.LoadSigningResourceConsumerAssets(get("assets-file"), get("assets-sha256"))
			if err != nil {
				return 1
			}
		}
	}
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
	enrolRaw, err := install.ReadPrivateFile(get("enrollment-pin-file"), 262144)
	if err != nil {
		return 1
	}
	enrollment, err := install.DecodeEnrollmentPin(enrolRaw, get("enrollment-pin-sha256"))
	if err != nil {
		return 1
	}
	db, kube, err := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if err != nil {
		return 1
	}
	defer db.Close()
	installer, err := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if err != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var result any
	if action == "issue-install" || action == "issue-revocation" {
		key, readErr := install.ReadPrivateFile(get("issuer-private-file"), 64)
		if readErr != nil {
			return 1
		}
		defer clear(key)
		var raw []byte
		if action == "issue-install" {
			requestRaw, readErr := install.ReadPrivateFile(get("request-files-file"), 262144)
			if readErr != nil {
				return 1
			}
			request, decodeErr := install.DecodeRequestFiles(requestRaw, get("request-files-sha256"))
			if decodeErr != nil {
				return 1
			}
			raw, err = installer.IssueSigningResourceInstall(active, password, enrollment, get("intent-file"), get("intent-sha256"), request, key)
		} else {
			raw, err = installer.IssueSigningResourceRevocation(active, password, enrollment, pin, get("bundle-file"), get("bundle-sha256"), key)
		}
		if err == nil {
			err = install.SaveFrozenSigningResourceBundle(get("output-directory"), raw, digest(raw), pin)
			// Issuance may already have signed/probed. A failed create-only save
			// must not invite silent re-issuance or overwrite of frozen output.
			if err != nil {
				return 4
			}
		}
		result = struct{ Version, Action, File, SHA256 string }{"original-signing-resource-signed-transport.v1", action, filepath.Join(get("output-directory"), pin.Purpose+".signing-resource.bundle.json"), digest(raw)}
	} else {
		switch action {
		case "import":
			result, err = installer.ImportSigningResourceSQLAuthority(active, password, enrollment, inputs)
		case "resolve":
			result, err = installer.ResolveSigningResourceSQLAuthority(active, password, enrollment, inputs)
		case "export-consumer":
			result, err = installer.ExportSigningResourceConsumer(active, password, enrollment, inputs, assets, get("consumer-kubeconfig-file"), get("consumer-kubeconfig-sha256"), get("output-directory"))
		}
	}
	if errors.Is(err, install.ErrCommitUnknown) {
		return 4
	}
	if err != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 4
	}
	return 0
}

func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := run(ctx, os.Args[1:], os.Stdout)
	if code != 0 {
		_, _ = io.WriteString(os.Stderr, "original signing-resource operation refused; exit 4 requires exact frozen-output/current-tuple inspection before retry\n")
	}
	os.Exit(code)
}
