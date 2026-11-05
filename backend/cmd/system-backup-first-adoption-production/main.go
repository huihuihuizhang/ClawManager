// Real first-adoption production caller. Diagnostic CheckControls remains a
// separate CLI. This entry never accepts coverage/control/observation JSON.
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
	"syscall"
	"time"

	c "clawreef/internal/systembackupcontroller"
	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	a "clawreef/internal/systembackupkekadapter"
	"github.com/go-sql-driver/mysql"
)

func readPin(file, digest string, limit int64) ([]byte, error) {
	raw, e := install.ReadPrivateFile(file, limit)
	if e != nil {
		return nil, install.ErrInstall
	}
	if digest != "" {
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != digest {
			clear(raw)
			return nil, install.ErrInstall
		}
	}
	return raw, nil
}

func run(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-first-adoption-production", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "run", "run, prepare-minio-history, prepare-native-plan, prepare-inputs query-disabled-initialization prepare-recovery-descriptor or query-minio-recovery")
	values := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "issuer-private-file", "issuer-private-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "inputs-file", "inputs-sha256"} {
		values[name] = f.String(name, "", "original independently selected owner input")
	}
	recoveryPassword := f.String("recovery-admin-password-file", "", "fresh original local admin credential file; defaults to selected original file")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	get := func(n string) string { return *values[n] }
	if *action != "run" && *action != "run-minio-metadata" && *action != "prepare-minio-history" && *action != "prepare-native-plan" && *action != "prepare-inputs" && *action != "query-disabled-initialization" && *action != "prepare-recovery-descriptor" && *action != "query-minio-recovery" && *action != "prepare-archive-materials" && *action != "query-archive-materials" && *action != "issue-minio-runtime-metadata" && *action != "query-minio-runtime-metadata" {
		return 2
	}
	for name, value := range values {
		if (*action == "run" || *action == "run-minio-metadata" || *action == "prepare-archive-materials" || *action == "issue-minio-runtime-metadata" || name != "issuer-private-file" && name != "issuer-private-sha256") && *value == "" {
			return 2
		}
	}
	planRaw, e := readPin(get("plan-file"), get("plan-sha256"), 262144)
	if e != nil {
		return 1
	}
	plan, e := install.DecodePlan(planRaw, get("plan-sha256"))
	if e != nil {
		return 1
	}
	public, e := readPin(get("issuer-public-file"), get("issuer-public-sha256"), 32)
	if e != nil {
		return 1
	}
	password, e := readPin(get("local-admin-password-file"), "", 1024)
	if e != nil {
		return 1
	}
	defer clear(password)
	freshPassword := bytes.Clone(password)
	if *recoveryPassword != "" {
		clear(freshPassword)
		freshPassword, e = readPin(*recoveryPassword, "", 1024)
		if e != nil {
			return 1
		}
	}
	defer clear(freshPassword)
	enrollmentRaw, e := readPin(get("enrollment-pin-file"), get("enrollment-pin-sha256"), 262144)
	if e != nil {
		return 1
	}
	var enrollment install.EnrollmentPin
	d := json.NewDecoder(bytes.NewReader(enrollmentRaw))
	d.DisallowUnknownFields()
	if d.Decode(&enrollment) != nil || d.Decode(new(any)) != io.EOF {
		return 1
	}
	raw, e := readPin(get("inputs-file"), get("inputs-sha256"), 262144)
	if e != nil {
		return 1
	}
	db, kube, e := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if e != nil {
		return 1
	}
	defer db.Close()
	owner, e := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	if *action == "issue-minio-runtime-metadata" || *action == "query-minio-runtime-metadata" {
		return runMinIORuntimeMetadata(ctx, owner, password, enrollment, raw, get, out, *action == "query-minio-runtime-metadata")
	}
	if *action == "prepare-archive-materials" || *action == "query-archive-materials" {
		active, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		var receipt install.OriginalArchiveEvidenceMaterialReceipt
		if *action == "query-archive-materials" {
			var in struct{ Version, OutputDirectory string }
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Version != "original-archive-evidence-material-query-inputs.v1" {
				return 1
			}
			receipt, e = owner.QueryOriginalArchiveEvidenceMaterial(active, password, enrollment, in.OutputDirectory)
		} else {
			var in install.OriginalArchiveEvidenceMaterialOptions
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
				return 1
			}
			private, pe := readPin(get("issuer-private-file"), get("issuer-private-sha256"), 64)
			if pe != nil {
				return 1
			}
			defer clear(private)
			receipt, e = owner.ProduceOriginalArchiveEvidenceMaterial(active, password, enrollment, in, private)
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		if e != nil {
			if receipt.Version != "" {
				return 3
			}
			return 1
		}
		return 0
	}
	if *action == "query-minio-recovery" {
		var in struct {
			Version    string
			Descriptor install.BootstrapSourceFilePin
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Version != "original-minio-recovery-query-inputs.v1" {
			return 1
		}
		active, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		receipt, e := owner.QueryOriginalMinIORecoveryProjection(active, freshPassword, enrollment, in.Descriptor)
		if e != nil {
			if errors.Is(e, install.ErrCommitUnknown) {
				return 3
			}
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		return 0
	}
	if *action == "prepare-recovery-descriptor" {
		var in install.OriginalMinIORecoveryDescriptorInputs
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			return 1
		}
		active, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		receipt, e := owner.PrepareOriginalMinIORecoveryDescriptor(active, password, enrollment, in)
		if e != nil {
			if errors.Is(e, install.ErrCommitUnknown) {
				return 3
			}
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		return 0
	}
	if *action == "query-disabled-initialization" {
		var in struct {
			Version string
			Request install.RequestFiles
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Version != "original-disabled-initialization-query-inputs.v1" {
			return 1
		}
		active, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		receipt, e := owner.QueryOriginalDisabledUnverified(active, freshPassword, enrollment, in.Request)
		if e != nil {
			if errors.Is(e, install.ErrCommitUnknown) {
				return 3
			}
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		return 0
	}
	if *action == "prepare-native-plan" {
		var in install.OriginalMinIOHistoryNativePlanInputs
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			return 1
		}
		active, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		plan, e := owner.PrepareOriginalMinIOHistoryNativePlan(active, password, enrollment, in)
		if e != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(plan) != nil {
			return 3
		}
		return 0
	}
	if *action == "prepare-inputs" {
		var in install.OriginalFirstAdoptionInputSelections
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			return 1
		}
		active, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		receipt, e := owner.PrepareOriginalFirstAdoptionProductionInputs(active, password, enrollment, in)
		if e != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		return 0
	}
	if *action == "prepare-minio-history" {
		var in struct {
			Version                   string
			SourceSelection, Provider install.BootstrapSourceFilePin
			OutputDirectory           string
			Policy                    c.GatePolicy
			Admin                     execution.MinIONativeAdminFiles
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Version != "original-minio-whole-history-setup-inputs.v1" {
			return 1
		}
		active, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		read, e := owner.PrepareBootstrapSourceRegistryAuthoring(active, password, enrollment, in.SourceSelection.File, in.SourceSelection.SHA256)
		if e != nil {
			return 1
		}
		defer read.Close()
		write, e := owner.PrepareOriginalWriterMaintenance(active, password, enrollment, in.Policy)
		if e != nil {
			return 1
		}
		receipt, e := execution.ProduceOriginalMinIOWholeHistoryReadMaterials(active, write, read, kube, in.Provider.File, in.Provider.SHA256, in.OutputDirectory, in.Admin)
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		if e != nil {
			if receipt.NativeWritesAttempted {
				return 3
			}
			return 1
		}
		return 0
	}
	private, e := readPin(get("issuer-private-file"), get("issuer-private-sha256"), 64)
	if e != nil {
		return 1
	}
	defer clear(private)
	in, e := install.DecodeOriginalFirstAdoptionProductionInputs(raw, get("inputs-sha256"))
	if e != nil {
		return 1
	}
	runProduction := owner.RunOriginalFirstAdoptionProduction
	if *action == "run-minio-metadata" {
		runProduction = owner.RunOriginalFirstAdoptionProductionForMinIOMetadata
	}
	receipt, e := runProduction(ctx, password, freshPassword, private, enrollment, in)
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	if e != nil {
		// Receipt contains fixed stages/comparison data. Native/SQL errors and
		// private credentials are never logged or returned through stdout.
		if errors.Is(e, install.ErrCommitUnknown) || errors.Is(e, a.ErrAuthorityCommitUnknown) {
			return 3
		}
		return 1
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
