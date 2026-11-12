// Actual original maintenance caller. A successful trial is neither a backup
// nor first adoption. Every source mutation and recovery is the real library
// operation on one genuine in-memory original set and its durable journal.
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

	sb "clawreef/internal/systembackup"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	if len(args) == 1 && args[0] == "redis-native-helper" {
		active, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		if sb.RunRedisBootstrapNative(active, os.Stdin, out) != nil {
			return 1
		}
		return 0
	}
	flags := flag.NewFlagSet("system-backup-original-maintenance", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planFile := flags.String("plan-file", "", "user-selected canonical public target plan")
	planSHA := flags.String("plan-sha256", "", "independently pinned plan bytes")
	publicFile := flags.String("issuer-public-file", "", "selected raw Ed25519 public key")
	publicSHA := flags.String("issuer-public-sha256", "", "public key fingerprint selected independently by the user")
	kubeFile := flags.String("kubeconfig-file", "", "trusted existing operator kubeconfig")
	kubeSHA := flags.String("kubeconfig-sha256", "", "exact private kubeconfig bytes")
	dsnFile := flags.String("dsn-file", "", "private installer SQL DSN")
	dbCAFile := flags.String("database-ca-file", "", "pinned target database CA")
	passwordFile := flags.String("local-admin-password-file", "", "private exact local admin password bytes")
	redisFile := flags.String("redis-materials-file", "", "actual native Redis installer options")
	redisSHA := flags.String("redis-materials-sha256", "", "exact options SHA256")
	mode := flags.String("mode", "", "explicit preflight or round-trip")
	enrollmentFile := flags.String("enrollment-pin-file", "", "original independently retained immutable enrollment pin")
	enrollmentSHA := flags.String("enrollment-pin-sha256", "", "original enrollment pin bytes")
	selectionFile := flags.String("selection-file", "", "original complete writer/source selection")
	selectionSHA := flags.String("selection-sha256", "", "original complete selection pin")
	providerValues := map[string]*string{}
	for _, name := range []string{"provider-deployment", "provider-service", "provider-claim", "provider-data-mount", "provider-endpoint", "provider-cluster-id", "provider-transit-mount", "provider-key-name", "provider-key-version", "provider-jwt-mount", "provider-ca-file", "provider-ca-sha256", "provider-owner-token-file", "provider-owner-token-sha256", "output-directory"} {
		providerValues[name] = flags.String(name, "", "actual existing provider installation input; no future binding")
	}
	recoveryPasswordFile := flags.String("recovery-admin-password-file", "", "existing private fresh recovery password; defaults to original selected file")
	if ctx == nil || out == nil || flags.Parse(args) != nil || flags.NArg() != 0 || *planFile == "" || *planSHA == "" || *publicFile == "" || *publicSHA == "" || *kubeFile == "" || *kubeSHA == "" || *dsnFile == "" || *dbCAFile == "" || *passwordFile == "" || *mode != "preflight" && *mode != "round-trip" && *mode != "provider-materials" && *mode != "redis-materials" || *enrollmentFile == "" || *enrollmentSHA == "" || *selectionFile == "" || *selectionSHA == "" {
		return 2
	}
	if *mode == "redis-materials" {
		if *redisFile == "" || *redisSHA == "" {
			return 2
		}
	} else if *redisFile != "" || *redisSHA != "" {
		return 2
	}
	if *mode == "provider-materials" {
		for name, value := range providerValues {
			if name != "provider-data-mount" && *value == "" {
				return 2
			}
		}
	} else {
		for _, value := range providerValues {
			if *value != "" {
				return 2
			}
		}
	}
	raw, e := install.ReadPrivateFile(*planFile, 262144)
	if e != nil {
		return 1
	}
	plan, e := install.DecodePlan(raw, *planSHA)
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
	db, kube, e := install.OpenConnections(plan, *kubeFile, *kubeSHA, *dsnFile, *dbCAFile)
	if e != nil {
		return 1
	}
	defer db.Close()
	installer, e := install.New(db, kube, raw, *planSHA, public, *publicSHA)
	if e != nil {
		return 1
	}
	enrollmentRaw, e := install.ReadPrivateFile(*enrollmentFile, 262144)
	if e != nil {
		return 1
	}
	sum := sha256.Sum256(enrollmentRaw)
	if hex.EncodeToString(sum[:]) != *enrollmentSHA {
		return 1
	}
	var enrollment install.EnrollmentPin
	decoder := json.NewDecoder(bytes.NewReader(enrollmentRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&enrollment) != nil || decoder.Decode(new(any)) != io.EOF {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	if *mode == "redis-materials" {
		defer cancel()
		data, e := install.ReadPrivateFile(*redisFile, 262144)
		if e != nil {
			return 1
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != *redisSHA {
			return 1
		}
		var options install.RedisNativeMaterialOptions
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if dec.Decode(&options) != nil || dec.Decode(new(any)) != io.EOF {
			return 1
		}
		receipt, e := installer.ProduceOriginalRedisNativeMaterials(active, password, enrollment, install.BootstrapSourceFilePin{File: *selectionFile, SHA256: *selectionSHA}, install.BootstrapSourceFilePin{File: *kubeFile, SHA256: *kubeSHA}, options)
		if e != nil {
			var failure install.OriginalRedisMaterialFailure
			if errors.As(e, &failure) {
				_ = json.NewEncoder(out).Encode(struct {
					Version, State, Mode, Phase string
				}{"original-redis-native-material-failure.v1", "unconfirmed_preserve_original_materials", options.Mode, failure.Phase()})
			}
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		return 0
	}
	if *mode == "provider-materials" {
		defer cancel()
		get := func(name string) string { return *providerValues[name] }
		receipt, e := installer.ProducePreAdoptionVaultMaterials(active, password, enrollment, install.BootstrapSourceFilePin{File: *selectionFile, SHA256: *selectionSHA}, install.PreAdoptionVaultMaterialOptions{Deployment: get("provider-deployment"), Service: get("provider-service"), Claim: get("provider-claim"), DataMountPath: get("provider-data-mount"), Endpoint: get("provider-endpoint"), ClusterID: get("provider-cluster-id"), TransitMount: get("provider-transit-mount"), KeyName: get("provider-key-name"), KeyVersion: get("provider-key-version"), JWTMount: get("provider-jwt-mount"), CA: install.BootstrapSourceFilePin{File: get("provider-ca-file"), SHA256: get("provider-ca-sha256")}, OwnerToken: install.BootstrapSourceFilePin{File: get("provider-owner-token-file"), SHA256: get("provider-owner-token-sha256")}}, get("output-directory"))
		if e != nil {
			var failure *install.VaultDependencyMaterialFailure
			if errors.As(e, &failure) {
				_ = json.NewEncoder(out).Encode(struct {
					Version, State, Phase string
				}{"original-vault-dependency-material-failure.v1", "unconfirmed_preserve_original_materials", failure.Phase()})
			}
			return 1
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		return 0
	}
	set, e := installer.PrepareOriginalWriterSet(active, password, enrollment, install.BootstrapSourceFilePin{File: *selectionFile, SHA256: *selectionSHA})
	if e != nil {
		cancel()
		return 1
	}
	if *mode == "preflight" {
		cancel()
		if json.NewEncoder(out).Encode(trialReport{Version: "original-maintenance-native-trial.v1", State: "original_complete_preflight_only_no_stop_no_backup"}) != nil {
			return 3
		}
		return 0
	}
	hold, acquireErr := set.Acquire(active)
	// Close the original context before making a NEW recovery authority. This
	// does not extend capture and never changes the original owner ctx/until.
	cancel()
	freshPassword := bytes.Clone(password)
	if *recoveryPasswordFile != "" {
		clear(freshPassword)
		freshPassword, e = install.ReadPrivateFile(*recoveryPasswordFile, 1024)
		if e != nil {
			return reportFailure(out, "original_recovery_credential_unavailable_retains_gates", 3)
		}
	}
	defer clear(freshPassword)
	recoveryCtx, recoveryCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer recoveryCancel()
	authorization, recoveryErr := installer.PrepareOriginalWriterRecovery(recoveryCtx, freshPassword, enrollment, set)
	if recoveryErr != nil {
		return reportFailure(out, "fresh_original_recovery_refused_retains_gates", 3)
	}
	if acquireErr != nil || hold == nil {
		_, abortErr := set.AbortUnstartedOriginalAcquisition(recoveryCtx, authorization)
		if abortErr == nil {
			if json.NewEncoder(out).Encode(trialReport{Version: "original-maintenance-native-trial.v1", State: "unstarted_original_acquisition_aborted_no_source_recovery_claim", AdmissionAbortVerified: true}) != nil {
				return 3
			}
			return 1
		}
		if !errors.Is(abortErr, install.ErrOriginalSourceDispatchPresent) {
			return reportFailure(out, "original_admission_abort_unverified_retains_gates", 3)
		}
	}
	recoveryErr = set.RestoreOriginalSources(recoveryCtx, authorization)
	if recoveryErr != nil {
		state := "original_sources_not_completely_verified_retains_gates"
		if errors.Is(recoveryErr, install.ErrCommitUnknown) {
			state = "original_recovery_commit_unknown_requires_exact_readback"
		}
		return reportFailure(out, state, 3)
	}
	if acquireErr != nil || hold == nil {
		if json.NewEncoder(out).Encode(trialReport{Version: "original-maintenance-native-trial.v1", State: "original_acquisition_failed_actual_sources_recovered_only", SourceRecoveryVerified: true}) != nil {
			return 3
		}
		return 1
	}
	// This is solely an actual maintenance trial. No collector, evidence, first
	// adoption, config enable, formal task or publication is fabricated here.
	if json.NewEncoder(out).Encode(trialReport{Version: "original-maintenance-native-trial.v1", State: "actual_original_hold_and_source_recovery_only_no_backup", HoldVerified: true, SourceRecoveryVerified: true}) != nil {
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

type trialReport struct {
	Version, State                       string
	HoldVerified, SourceRecoveryVerified bool
	AdmissionAbortVerified               bool
	PageBackupCompleted                  bool
}

func reportFailure(out io.Writer, state string, code int) int {
	if json.NewEncoder(out).Encode(trialReport{Version: "original-maintenance-native-trial.v1", State: state}) != nil {
		return 3
	}
	return code
}
