// Offline original Installer source-registry production and V2 signing. No
// config enabling, HTTP/task/Job admission or caller-supplied observation.
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
	"runtime"
	"syscall"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
	"github.com/go-sql-driver/mysql"
)

func digest(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func pinnedJSON(path, sha string, out any) error {
	raw, err := install.ReadPrivateFile(path, 262144)
	if err != nil || digest(raw) != sha {
		return install.ErrInstall
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return install.ErrInstall
	}
	round, err := ce.Canonical(out)
	if err != nil || !bytes.Equal(raw, round) {
		return install.ErrInstall
	}
	return nil
}

func newV2Output(directory string) error {
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
	for _, name := range []string{"bootstrap-source-registries-v2.record.json", "bootstrap-source-registries-v2.signature", "bootstrap-source-registries-v2.sha256"} {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			return install.ErrInstall
		}
	}
	return nil
}

// Composition DATA only. The original mapping issuer must independently sign
// these bindings and the eventual consumer authenticates the complete V2 path.
// Paths are the exact final deployed coordinates, not staging aliases.
func ownerBindings(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("owner-bindings", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	captureFile := flags.String("capture-consumer-file", "", "")
	capturePin := flags.String("capture-consumer-pin-file", "", "")
	recordFile := flags.String("record-file", "", "")
	recordSHA := flags.String("record-sha256", "", "")
	signatureFile := flags.String("signature-file", "", "")
	redisFile := flags.String("redis-sources-file", "", "")
	redisSHA := flags.String("redis-sources-sha256", "", "")
	secretFile := flags.String("secret-allowlist-file", "", "")
	secretSHA := flags.String("secret-allowlist-sha256", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	for _, v := range []string{*captureFile, *capturePin, *recordFile, *recordSHA, *signatureFile} {
		if v == "" {
			return 2
		}
	}
	capture := install.NewCaptureSigningConsumer(*captureFile, *capturePin)
	files := install.BootstrapSourceRegistryFiles{RecordFile: *recordFile, RecordSHA256: *recordSHA, SignatureFile: *signatureFile}
	var resource *execution.BootstrapSourceRegistryTerminalResource
	var err error
	if *redisFile != "" || *redisSHA != "" || *secretFile != "" || *secretSHA != "" {
		for _, v := range []string{*redisFile, *redisSHA, *secretFile, *secretSHA} {
			if v == "" {
				return 2
			}
		}
		resource, err = execution.NewBootstrapSourceRegistryTerminalResourceWithNativeRegistries(capture, files, execution.BootstrapSourceNativeRegistryFiles{RedisSources: install.BootstrapSourceFilePin{File: *redisFile, SHA256: *redisSHA}, SecretAllowlist: install.BootstrapSourceFilePin{File: *secretFile, SHA256: *secretSHA}})
	} else {
		resource, err = execution.NewBootstrapSourceRegistryTerminalResource(capture, files)
	}
	if err != nil {
		return 1
	}
	binding, err := resource.BindingSHA256()
	if err != nil {
		return 1
	}
	bindings := []install.BootstrapOriginalOwnerBinding{}
	for _, key := range resource.TerminalKeys() {
		bindings = append(bindings, install.BootstrapOriginalOwnerBinding{Key: key, SHA256: binding})
	}
	if json.NewEncoder(out).Encode(bindings) != nil {
		return 4
	}
	return 0
}

func run(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || len(args) == 0 || out == nil {
		return 2
	}
	action := args[0]
	if action == "install-redis-files" {
		flags := flag.NewFlagSet(action, flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		pin := flags.String("manifest-sha256", "", "")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
			return 2
		}
		if execution.InstallFormalRedisFiles(ctx, *pin) != nil {
			return 1
		}
		return 0
	}
	if action == "install-provider-files" {
		flags := flag.NewFlagSet(action, flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		observer := flags.String("observer-sha256", "", "")
		token := flags.String("token-sha256", "", "")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
			return 2
		}
		if execution.InstallFormalVaultDependencyFiles(ctx, *observer, *token) != nil {
			return 1
		}
		return 0
	}
	if action == "owner-bindings" {
		return ownerBindings(args[1:], out)
	}
	required := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256"}
	switch action {
	case "produce-facts":
		required = append(required, "source-selection-file", "source-selection-sha256")
	case "prepare-redis-materials", "prepare-provider-materials", "prepare-observer-materials":
		required = append(required, "source-selection-file", "source-selection-sha256", "writer-selection-file", "writer-selection-sha256", "controller-container", "output-directory")
	case "prepare-mount-materials":
		required = append(required, "source-selection-file", "source-selection-sha256", "mount-layouts-file", "mount-layouts-sha256", "output-directory")
	case "issue-v2":
		required = append(required, "definition-file", "definition-sha256", "consumption-file", "consumption-sha256", "request-files-file", "request-files-sha256", "bundle-file", "bundle-sha256", "issuer-private-file", "output-directory")
	default:
		return 2
	}
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	values := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "source-selection-file", "source-selection-sha256", "mount-layouts-file", "mount-layouts-sha256", "writer-selection-file", "writer-selection-sha256", "controller-container", "definition-file", "definition-sha256", "consumption-file", "consumption-sha256", "request-files-file", "request-files-sha256", "bundle-file", "bundle-sha256", "issuer-private-file", "output-directory"} {
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
	for name, v := range values {
		if !allowed[name] && *v != "" {
			return 2
		}
	}
	get := func(name string) string { return *values[name] }
	var consumption pd.BootstrapConsumptionRequest
	var request install.RequestFiles
	var bundle []byte
	if action == "issue-v2" {
		if newV2Output(get("output-directory")) != nil || pinnedJSON(get("consumption-file"), get("consumption-sha256"), &consumption) != nil {
			return 1
		}
		raw, err := install.ReadPrivateFile(get("request-files-file"), 262144)
		if err != nil {
			return 1
		}
		request, err = install.DecodeRequestFiles(raw, get("request-files-sha256"))
		if err != nil {
			return 1
		}
		bundle, err = install.ReadPrivateFile(get("bundle-file"), 262144)
		if err != nil || digest(bundle) != get("bundle-sha256") {
			return 1
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
	enrollmentRaw, err := install.ReadPrivateFile(get("enrollment-pin-file"), 262144)
	if err != nil {
		return 1
	}
	enrollment, err := install.DecodeEnrollmentPin(enrollmentRaw, get("enrollment-pin-sha256"))
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
	if action == "prepare-redis-materials" {
		receipt, e := execution.ProduceFormalRedisReadMaterials(active, installer, password, enrollment, get("source-selection-file"), get("source-selection-sha256"), get("writer-selection-file"), get("writer-selection-sha256"), get("controller-container"), get("output-directory"))
		if e != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 4
		}
		return 0
	}
	if action == "prepare-provider-materials" {
		receipt, err := execution.ProduceFormalVaultDependencyMaterials(active, installer, password, enrollment, get("source-selection-file"), get("source-selection-sha256"), get("writer-selection-file"), get("writer-selection-sha256"), get("controller-container"), get("output-directory"))
		if err != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 4
		}
		return 0
	}
	if action == "prepare-observer-materials" {
		receipt, err := execution.ProduceFormalStoppedProObserverMaterials(active, installer, password, enrollment, get("source-selection-file"), get("source-selection-sha256"), get("writer-selection-file"), get("writer-selection-sha256"), get("controller-container"), get("output-directory"))
		if err != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 4
		}
		return 0
	}
	if action == "prepare-mount-materials" {
		receipt, err := execution.ProduceOriginalInstanceMountMaterials(active, installer, password, enrollment, get("source-selection-file"), get("source-selection-sha256"), get("mount-layouts-file"), get("mount-layouts-sha256"), get("output-directory"))
		if err != nil {
			var missing *execution.InstanceMountInputError
			if errors.As(err, &missing) {
				_ = json.NewEncoder(out).Encode(struct {
					Status, Code string
					InstanceID   int
					MountID      string
				}{"original_mount_materials_blocked", missing.Code, missing.InstanceID, missing.MountID})
			}
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 4
		}
		return 0
	}
	if action == "produce-facts" {
		receipt, err := execution.ProduceOriginalBootstrapSourceRegistries(active, installer, password, enrollment, get("source-selection-file"), get("source-selection-sha256"))
		if err != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 4
		}
		return 0
	}
	key, err := install.ReadPrivateFile(get("issuer-private-file"), 64)
	if err != nil {
		return 1
	}
	defer clear(key)
	signed, err := installer.IssueBootstrapSourceRegistriesV2(active, password, enrollment, bundle, get("bundle-sha256"), get("definition-file"), get("definition-sha256"), consumption, request, key)
	if err != nil {
		return 1
	}
	if install.SaveFrozenBootstrapSourceRegistriesV2(get("output-directory"), signed) != nil {
		return 4
	}
	files := install.BootstrapSourceRegistryFiles{RecordFile: filepath.Join(get("output-directory"), "bootstrap-source-registries-v2.record.json"), RecordSHA256: digest(signed.Record), SignatureFile: filepath.Join(get("output-directory"), "bootstrap-source-registries-v2.signature")}
	if json.NewEncoder(out).Encode(struct {
		Status string
		Files  install.BootstrapSourceRegistryFiles
	}{"signed_source_registry_transport_frozen", files}) != nil {
		return 4
	}
	return 0
}

func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code := run(ctx, os.Args[1:], os.Stdout)
	if code != 0 {
		_, _ = io.WriteString(os.Stderr, "original source-registry operation refused; inspect exact selected outputs before retry\n")
	}
	os.Exit(code)
}
