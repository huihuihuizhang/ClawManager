// Offline original KEK-window material issuance. No HTTP/task admission or
// coverage/adoption fabrication; source and original authority are real inputs.
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
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	materials "clawreef/internal/systembackupbootstrapmaterials"
	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-sql-driver/mysql"
)

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func pinned(file, sha string, limit int64) ([]byte, error) {
	raw, err := install.ReadPrivateFile(file, limit)
	if err != nil || digest(raw) != sha {
		clear(raw)
		return nil, install.ErrInstall
	}
	return raw, nil
}

func selectionFile(file, sha string) (pd.BootstrapConsumptionRequest, error) {
	var out pd.BootstrapConsumptionRequest
	raw, err := pinned(file, sha, 262144)
	if err != nil {
		return out, install.ErrInstall
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return out, install.ErrInstall
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF {
		return out, install.ErrInstall
	}
	return out, nil
}

func newOutput(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return install.ErrInstall
	}
	st, err := os.Lstat(directory)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return install.ErrInstall
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return install.ErrInstall
	}
	defer root.Close()
	for _, name := range []string{"bootstrap-kek-window.record.json", "bootstrap-kek-window.signature", "bootstrap-kek-window.sha256"} {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			return install.ErrInstall
		}
	}
	return nil
}

func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || out == nil || len(args) == 0 {
		return 2
	}
	action := args[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	values := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "bundle-file", "bundle-sha256", "request-files-file", "request-files-sha256", "consumption-file", "consumption-sha256", "issuer-private-file", "output-directory", "kek-source-file", "kek-source-sha256", "capture-consumer-file", "capture-consumer-pin-file", "record-file", "record-sha256", "signature-file"} {
		values[name] = flags.String(name, "", "")
	}
	var required []string
	switch action {
	case "issue":
		required = []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "bundle-file", "bundle-sha256", "request-files-file", "request-files-sha256", "consumption-file", "consumption-sha256", "issuer-private-file", "output-directory", "kek-source-file", "kek-source-sha256"}
	case "owner-binding":
		required = []string{"kek-source-file", "kek-source-sha256", "capture-consumer-file", "capture-consumer-pin-file", "record-file", "record-sha256", "signature-file"}
	default:
		return 2
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
	preparation, err := materials.LoadOriginalSQLBootstrapKEKPreparation(get("kek-source-file"), get("kek-source-sha256"))
	if err != nil {
		return 1
	}
	if action == "owner-binding" {
		capture := install.NewCaptureSigningConsumer(get("capture-consumer-file"), get("capture-consumer-pin-file"))
		resource, err := install.NewOriginalWindowKEK(capture, preparation, install.BootstrapKEKWindowFiles{RecordFile: get("record-file"), RecordSHA256: get("record-sha256"), SignatureFile: get("signature-file")})
		if err != nil {
			return 1
		}
		binding, err := resource.BindingSHA256()
		if err != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(install.BootstrapOriginalOwnerBinding{Key: "reference:kek", SHA256: binding}) != nil {
			return 3
		}
		return 0
	}
	if newOutput(get("output-directory")) != nil {
		return 1
	}
	selection, err := selectionFile(get("consumption-file"), get("consumption-sha256"))
	if err != nil {
		return 1
	}
	requestRaw, err := pinned(get("request-files-file"), get("request-files-sha256"), 262144)
	if err != nil {
		return 1
	}
	request, err := install.DecodeRequestFiles(requestRaw, get("request-files-sha256"))
	if err != nil {
		return 1
	}
	bundle, err := pinned(get("bundle-file"), get("bundle-sha256"), 262144)
	if err != nil {
		return 1
	}
	planRaw, err := pinned(get("plan-file"), get("plan-sha256"), 262144)
	if err != nil {
		return 1
	}
	plan, err := install.DecodePlan(planRaw, get("plan-sha256"))
	if err != nil {
		return 1
	}
	public, err := pinned(get("issuer-public-file"), get("issuer-public-sha256"), 32)
	if err != nil {
		return 1
	}
	enrollmentRaw, err := pinned(get("enrollment-pin-file"), get("enrollment-pin-sha256"), 262144)
	if err != nil {
		return 1
	}
	enrollment, err := install.DecodeEnrollmentPin(enrollmentRaw, get("enrollment-pin-sha256"))
	if err != nil {
		return 1
	}
	password, err := install.ReadPrivateFile(get("local-admin-password-file"), 1024)
	if err != nil {
		return 1
	}
	defer clear(password)
	key, err := install.ReadPrivateFile(get("issuer-private-file"), 64)
	if err != nil {
		return 1
	}
	defer clear(key)
	if ctx.Err() != nil {
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
	signed, err := installer.IssueBootstrapKEKWindow(active, password, enrollment, bundle, get("bundle-sha256"), selection, request, preparation, key)
	if err != nil {
		return 1
	}
	if install.SaveFrozenBootstrapKEKWindow(get("output-directory"), signed) != nil {
		return 3
	}
	files := install.BootstrapKEKWindowFiles{RecordFile: filepath.Join(get("output-directory"), "bootstrap-kek-window.record.json"), RecordSHA256: digest(signed.Record), SignatureFile: filepath.Join(get("output-directory"), "bootstrap-kek-window.signature")}
	if json.NewEncoder(out).Encode(struct {
		Status string
		Files  install.BootstrapKEKWindowFiles
	}{"original_kek_window_material_frozen", files}) != nil {
		return 3
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
		_, _ = io.WriteString(os.Stderr, "original KEK-window operation refused; inspect exact outputs before retry\n")
	}
	os.Exit(code)
}
