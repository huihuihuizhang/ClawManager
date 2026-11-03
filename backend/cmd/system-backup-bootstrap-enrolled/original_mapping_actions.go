package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type originalMappingIssueFiles struct {
	Version                                                                                            string
	Plan, PublicIssuer, Kubeconfig, Enrollment, Bundle, Consumption, OwnerBindings, NativeHostBindings install.BootstrapSourceFilePin
	DSNFile, DatabaseCAFile, LocalAdminPasswordFile, IssuerPrivateFile                                 string
	EvidenceSourceSHA256, CapacityReportFile                                                           string
}

func readEnrolledActionJSON(file, expected string, limit int64, target any) ([]byte, error) {
	raw, e := readEnrolledActionBytes(file, limit)
	if e != nil {
		return nil, install.ErrInstall
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expected {
		return nil, install.ErrInstall
	}
	canonical, e := jsoncanonicalizer.Transform(raw)
	if e != nil || !bytes.Equal(raw, canonical) {
		return nil, install.ErrInstall
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return nil, install.ErrInstall
	}
	return raw, nil
}

func runOriginalMappingAction(ctx context.Context, args []string, out io.Writer) int {
	if ctx == nil || ctx.Err() != nil || out == nil || len(args) == 0 {
		return 2
	}
	action := args[0]
	if action != "catalog-owner-bindings" && action != "issue-original-mapping" {
		return 2
	}
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	source := f.String("source-file", "", "private original metadata input")
	sha := f.String("source-sha256", "", "independent exact metadata SHA256")
	directory := f.String("output-directory", "", "existing private create-only signed mapping output")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *source == "" || *sha == "" {
		return 2
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if action == "catalog-owner-bindings" {
		if *directory != "" {
			return 2
		}
		var input execution.CatalogInitialInventoryTerminalInput
		if _, e := readEnrolledActionJSON(*source, *sha, 262144, &input); e != nil {
			return 1
		}
		capture := install.NewCaptureSigningConsumer(enrolledCaptureSource, enrolledCapturePin)
		kube, e := capture.OpenTerminalKubernetes(active)
		if e != nil {
			return 1
		}
		resource, e := execution.NewOriginalCatalogInitialInventory(kube, input)
		if e != nil {
			return 1
		}
		binding, e := resource.BindingSHA256()
		if e != nil {
			return 1
		}
		bindings := []install.BootstrapOriginalOwnerBinding{}
		for _, key := range resource.TerminalKeys() {
			bindings = append(bindings, install.BootstrapOriginalOwnerBinding{Key: key, SHA256: binding})
		}
		if json.NewEncoder(out).Encode(bindings) != nil {
			return 3
		}
		return 0
	}
	if !filepath.IsAbs(*directory) || filepath.Clean(*directory) != *directory {
		return 2
	}
	st, e := os.Lstat(*directory)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return 1
	}
	for _, name := range []string{"bootstrap-original.record.json", "bootstrap-original.signature", "bootstrap-original.sha256", "bootstrap-native-hosts.record.json", "bootstrap-native-hosts.signature", "bootstrap-native-hosts.sha256"} {
		if _, e := os.Lstat(filepath.Join(*directory, name)); !os.IsNotExist(e) {
			return 1
		}
	}
	var d originalMappingIssueFiles
	if _, e = readEnrolledActionJSON(*source, *sha, 262144, &d); e != nil || d.Version != "original-bootstrap-native-mapping-input.v1" {
		return 1
	}
	planRaw, e := install.ReadPrivateFile(d.Plan.File, 262144)
	if e != nil {
		return 1
	}
	plan, e := install.DecodePlan(planRaw, d.Plan.SHA256)
	if e != nil {
		return 1
	}
	public, e := install.ReadPrivateFile(d.PublicIssuer.File, 32)
	if e != nil {
		return 1
	}
	enrolRaw, e := install.ReadPrivateFile(d.Enrollment.File, 262144)
	if e != nil {
		return 1
	}
	enrollment, e := install.DecodeEnrollmentPin(enrolRaw, d.Enrollment.SHA256)
	if e != nil {
		return 1
	}
	var selection pd.BootstrapConsumptionRequest
	if _, e = readEnrolledActionJSON(d.Consumption.File, d.Consumption.SHA256, 8<<20, &selection); e != nil {
		return 1
	}
	var bindings []install.BootstrapOriginalOwnerBinding
	if _, e = readEnrolledActionJSON(d.OwnerBindings.File, d.OwnerBindings.SHA256, 262144, &bindings); e != nil {
		return 1
	}
	if validateCompleteOriginalOwnerBindings(bindings) != nil {
		return 1
	}
	var hosts []install.BootstrapNativeHostBinding
	if _, e = readEnrolledActionJSON(d.NativeHostBindings.File, d.NativeHostBindings.SHA256, 8<<20, &hosts); e != nil {
		return 1
	}
	bundle, e := install.ReadPrivateFile(d.Bundle.File, 262144)
	if e != nil {
		return 1
	}
	password, e := install.ReadPrivateFile(d.LocalAdminPasswordFile, 1024)
	if e != nil {
		return 1
	}
	defer clear(password)
	key, e := install.ReadPrivateFile(d.IssuerPrivateFile, 64)
	if e != nil {
		return 1
	}
	defer clear(key)
	db, kube, e := install.OpenConnections(plan, d.Kubeconfig.File, d.Kubeconfig.SHA256, d.DSNFile, d.DatabaseCAFile)
	if e != nil {
		return 1
	}
	defer db.Close()
	issuer, e := install.New(db, kube, planRaw, d.Plan.SHA256, public, d.PublicIssuer.SHA256)
	if e != nil {
		return 1
	}
	actual, e := issuer.IssueBootstrapOriginalNativeMapping(active, password, enrollment, bundle, d.Bundle.SHA256, selection, bindings, d.EvidenceSourceSHA256, d.CapacityReportFile, hosts, key)
	if e != nil {
		return 1
	}
	if install.SaveFrozenBootstrapNativeHostBundle(*directory, actual) != nil {
		return 3
	}
	if json.NewEncoder(out).Encode(map[string]any{"status": "original_mapping_and_native_hosts_issued", "coverage_adopted": false, "configuration_mutated": false, "task_created": false}) != nil {
		return 3
	}
	return 0
}

// Match the original 8MiB consumption/native-source contract without widening
// install.ReadPrivateFile's unrelated fixed 256KiB credential/source limits.
func readEnrolledActionBytes(file string, limit int64) ([]byte, error) {
	if limit <= 262144 {
		return install.ReadPrivateFile(file, limit)
	}
	if limit != 8<<20 || !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return nil, install.ErrInstall
	}
	before, e := os.Lstat(file)
	if e != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit || runtime.GOOS == "linux" && before.Mode().Perm()&0077 != 0 {
		return nil, install.ErrInstall
	}
	f, e := os.Open(file)
	if e != nil {
		return nil, install.ErrInstall
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return nil, install.ErrInstall
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	after, se := f.Stat()
	if e != nil || se != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || int64(len(raw)) > limit {
		clear(raw)
		return nil, install.ErrInstall
	}
	return raw, nil
}

// Complete association shape DATA only. Issuance still authenticates actual
// owner/enrollment/native/current source, and each terminal owns real readiness.
// The original issuer adds the actual capture record hash if that key is absent.
func validateCompleteOriginalOwnerBindings(bindings []install.BootstrapOriginalOwnerBinding) error {
	known := map[string]bool{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}) {
		known[key] = true
	}
	seen := map[string]bool{}
	for _, binding := range bindings {
		raw, e := hex.DecodeString(binding.SHA256)
		if !known[binding.Key] || seen[binding.Key] || e != nil || len(raw) != 32 || hex.EncodeToString(raw) != binding.SHA256 {
			return install.ErrInstall
		}
		seen[binding.Key] = true
	}
	for key := range known {
		if key != "reference:capture_signing" && !seen[key] {
			return install.ErrInstall
		}
	}
	if len(seen) != len(known) && len(seen) != len(known)-1 {
		return install.ErrInstall
	}
	return nil
}
