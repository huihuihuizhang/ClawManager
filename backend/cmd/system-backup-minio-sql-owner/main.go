// Original offline installation only. This command is never an HTTP route or
// a controller task; it does not create native accounts or accept Passed data.
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
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
)

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func pinnedJSON(file, sha string, out any) error {
	raw, e := install.ReadPrivateFile(file, 262144)
	if e != nil || digest(raw) != sha {
		return install.ErrInstall
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return install.ErrInstall
	}
	round, e := ce.Canonical(out)
	if e != nil || !bytes.Equal(raw, round) {
		return install.ErrInstall
	}
	return nil
}

func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || len(args) == 0 || out == nil {
		return 2
	}
	action := args[0]
	switch action {
	case "issue-install", "prepare-input", "issue-revocation", "import-qualified", "import-revocation", "resolve", "export-terminal":
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
	enrollmentFile := f.String("enrollment-pin-file", "", "")
	enrollmentSHA := f.String("enrollment-pin-sha256", "", "")
	intentFile := f.String("intent-file", "", "")
	intentSHA := f.String("intent-sha256", "", "")
	materialsFile := f.String("materials-file", "", "")
	materialsSHA := f.String("materials-sha256", "", "")
	inputFile := f.String("terminal-input-file", "", "")
	inputSHA := f.String("terminal-input-sha256", "", "")
	pinFile := f.String("pin-file", "", "")
	pinSHA := f.String("pin-sha256", "", "")
	bundleFile := f.String("bundle-file", "", "")
	bundleSHA := f.String("bundle-sha256", "", "")
	keyFile := f.String("issuer-private-file", "", "")
	directory := f.String("output-directory", "", "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	for _, value := range []string{*planFile, *planSHA, *pubFile, *pubSHA, *kubeFile, *kubeSHA, *dsnFile, *caFile, *passwordFile, *enrollmentFile, *enrollmentSHA} {
		if value == "" {
			return 2
		}
	}
	require := func(values ...string) bool {
		for _, value := range values {
			if value == "" {
				return false
			}
		}
		return true
	}
	deny := func(values ...string) bool {
		for _, value := range values {
			if value != "" {
				return true
			}
		}
		return false
	}
	if action != "prepare-input" && deny(*materialsFile, *materialsSHA) {
		return 2
	}
	switch action {
	case "issue-install":
		if !require(*intentFile, *intentSHA, *keyFile, *directory) || deny(*inputFile, *inputSHA, *pinFile, *pinSHA, *bundleFile, *bundleSHA) {
			return 2
		}
	case "issue-revocation":
		if !require(*pinFile, *pinSHA, *keyFile, *directory) || deny(*inputFile, *inputSHA, *intentFile, *intentSHA, *bundleFile, *bundleSHA) {
			return 2
		}
	case "prepare-input":
		if !require(*intentFile, *intentSHA, *bundleFile, *bundleSHA, *materialsFile, *materialsSHA, *directory) || deny(*inputFile, *inputSHA, *pinFile, *pinSHA, *keyFile) {
			return 2
		}
	case "import-qualified":
		if !require(*inputFile, *inputSHA) || deny(*intentFile, *intentSHA, *pinFile, *pinSHA, *bundleFile, *bundleSHA, *keyFile, *directory) {
			return 2
		}
	case "resolve", "import-revocation":
		if !require(*pinFile, *pinSHA, *bundleFile, *bundleSHA) || deny(*intentFile, *intentSHA, *inputFile, *inputSHA, *keyFile, *directory) {
			return 2
		}
	case "export-terminal":
		if !require(*inputFile, *inputSHA, *directory) || deny(*intentFile, *intentSHA, *pinFile, *pinSHA, *bundleFile, *bundleSHA, *keyFile) {
			return 2
		}
	}
	if action == "issue-install" || action == "issue-revocation" {
		if install.CheckNewMinIOSQLBundleDirectory(*directory) != nil {
			return 1
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
	public, e := install.ReadPrivateFile(*pubFile, 32)
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
	var pin ma.SQLTrustPin
	if action == "resolve" || action == "issue-revocation" || action == "import-revocation" {
		if pinnedJSON(*pinFile, *pinSHA, &pin) != nil {
			return 1
		}
	}
	db, kube, e := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *caFile)
	if e != nil {
		return 1
	}
	defer db.Close()
	owner, e := install.New(db, kube, planRaw, *planSHA, public, *pubSHA)
	if e != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var result any
	if action == "issue-install" || action == "issue-revocation" {
		key, readError := install.ReadPrivateFile(*keyFile, 64)
		if readError != nil {
			return 1
		}
		defer clear(key)
		var raw []byte
		if action == "issue-install" {
			raw, e = owner.IssueMinIOSQLInstall(active, password, enrollment, *intentFile, *intentSHA, key)
		} else {
			raw, e = owner.IssueMinIOSQLRevocation(active, password, enrollment, pin, key)
		}
		if e == nil {
			e = install.SaveMinIOSQLBundle(*directory, raw)
		}
		result = struct{ Version, Action, File, SHA256 string }{"original-minio-sql-signed-transport.v1", action, filepath.Join(*directory, "minio-sql-authority.bundle.json"), digest(raw)}
	} else if action == "prepare-input" {
		result, e = execution.PrepareOriginalMinIOTerminalInput(active, owner, kube, password, enrollment, *intentFile, *intentSHA, *bundleFile, *bundleSHA, *materialsFile, *materialsSHA, *directory)
	} else if action == "resolve" || action == "import-revocation" {
		raw, readError := install.ReadSourceMaterialFile(*bundleFile)
		if readError != nil {
			return 1
		}
		if action == "resolve" {
			result, e = owner.ResolveMinIOSQLAuthority(active, password, enrollment, pin, raw, *bundleSHA)
		} else {
			bundle, decodeError := ma.DecodeSQLBundle(raw, ma.Digest(*bundleSHA))
			if decodeError != nil || bundle.Action != ma.SQLActionRevoke {
				return 1
			}
			result, e = owner.ImportMinIOSQLAuthority(active, password, enrollment, pin, raw, *bundleSHA)
		}
	} else if action == "import-qualified" {
		result, e = execution.ImportOriginalMinIOTerminalAuthority(active, owner, kube, password, enrollment, *inputFile, *inputSHA)
	} else {
		result, e = execution.ExportOriginalMinIOTerminalInput(active, owner, kube, password, enrollment, *inputFile, *inputSHA, *directory)
	}
	if errors.Is(e, install.ErrCommitUnknown) {
		return 4
	}
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 4
	}
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := run(ctx, os.Args[1:], os.Stdout)
	if code != 0 {
		_, _ = io.WriteString(os.Stderr, "original MinIO SQL-owner operation refused; exit 4 requires independent inspection of exact frozen bytes/current tuple before retry\n")
	}
	os.Exit(code)
}
