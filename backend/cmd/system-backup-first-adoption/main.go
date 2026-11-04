// Production first-adoption caller. This executes genuine source preparation,
// actual source-owner issuance and CommitOriginalAdoption on the SAME coverage.
// It never calls CheckControls or accepts caller evidence/coverage JSON.
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
	"regexp"
	"syscall"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("system-backup-first-adoption", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	action := flags.String("action", "adopt", "explicit prepare-selection, prepare-issuers or adopt")
	writerSelection := registerWriterSelectionFlags(flags)
	issuerDirectory := flags.String("issuer-output-directory", "", "existing private directory for actual authenticated five-role material authoring")
	planFile := flags.String("plan-file", "", "user-selected canonical public target plan")
	planSHA := flags.String("plan-sha256", "", "independently pinned plan bytes")
	publicFile := flags.String("issuer-public-file", "", "selected raw Ed25519 public key")
	publicSHA := flags.String("issuer-public-sha256", "", "public key fingerprint selected independently by the user")
	kubeFile := flags.String("kubeconfig-file", "", "trusted existing operator kubeconfig")
	kubeSHA := flags.String("kubeconfig-sha256", "", "exact private kubeconfig bytes")
	dsnFile := flags.String("dsn-file", "", "private installer SQL DSN")
	dbCAFile := flags.String("database-ca-file", "", "pinned target database CA")
	passwordFile := flags.String("local-admin-password-file", "", "private exact local admin password bytes")
	issuerDefinitionFile := flags.String("issuer-definition-file", "", "actual owner-tool generated private source-issuer material definition")
	issuerDefinitionSHA := flags.String("issuer-definition-sha256", "", "independently retained original source-issuer definition pin")
	enrollmentFile := flags.String("enrollment-pin-file", "", "original independently retained immutable enrollment pin")
	enrollmentSHA := flags.String("enrollment-pin-sha256", "", "original enrollment pin bytes")
	selectionFile := flags.String("selection-file", "", "original complete writer/source selection")
	selectionSHA := flags.String("selection-sha256", "", "original complete selection pin")
	runtimeMetadataFile := flags.String("runtime-sql-metadata-receipt-file", "", "actual signed provider SQL-installation source receipt")
	runtimeMetadataSHA := flags.String("runtime-sql-metadata-receipt-sha256", "", "exact original SQL installation receipt SHA")
	recoveryPasswordFile := flags.String("recovery-admin-password-file", "", "existing private fresh recovery password; defaults to original selected file")
	if ctx == nil || out == nil || flags.Parse(args) != nil || flags.NArg() != 0 || *planFile == "" || *planSHA == "" || *publicFile == "" || *publicSHA == "" || *kubeFile == "" || *kubeSHA == "" || *dsnFile == "" || *dbCAFile == "" || *passwordFile == "" || *enrollmentFile == "" || *enrollmentSHA == "" {
		return 2
	}
	if *action != "adopt" && *action != "prepare-issuers" && *action != "prepare-selection" && *action != "query-original" {
		return 2
	}
	if *action == "prepare-selection" && !writerSelection.valid() {
		return 2
	}
	if *action == "query-original" && (*selectionFile == "" || *selectionSHA == "") {
		return 2
	}
	if (*runtimeMetadataFile == "") != (*runtimeMetadataSHA == "") {
		return 2
	}
	if *action == "adopt" && (*selectionFile == "" || *selectionSHA == "" || *issuerDefinitionFile == "" || *issuerDefinitionSHA == "") {
		return 2
	}
	if *action == "prepare-issuers" && *issuerDirectory == "" {
		return 2
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
	defer cancel()
	if *action == "prepare-selection" {
		receipt, err := writerSelection.produce(active, installer, password, enrollment)
		if err != nil {
			return reportStageFailure(out, "original_selection_material_refused_no_source_stop_preserve_outputs", "selection_materials", err, install.OriginalAdoptionCommitInspection{}, 1)
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		return 0
	}
	if *action == "prepare-issuers" {
		pin, err := installer.PrepareOriginalAdoptionIssuerMaterial(active, password, enrollment, *issuerDirectory)
		if errors.Is(err, install.ErrOriginalAdoptionIssuerMaterialUnconfirmed) {
			return reportStageFailure(out, "original_issuer_material_unconfirmed_preserve_private_directory", "issuer_materials", err, install.OriginalAdoptionCommitInspection{}, 3)
		}
		if err != nil {
			return reportStageFailure(out, "original_issuer_material_refused_preserve_private_directory", "issuer_materials", err, install.OriginalAdoptionCommitInspection{}, 1)
		}
		if json.NewEncoder(out).Encode(pin) != nil {
			return 3
		}
		return 0
	}
	if *action == "query-original" {
		inspection, err := installer.InspectOriginalAdoptionJournalCommit(active, password, enrollment, install.BootstrapSourceFilePin{File: *selectionFile, SHA256: *selectionSHA})
		if err != nil {
			return reportStageFailure(out, "original_adoption_journal_outcome_unknown_no_replay", "original_journal_query", err, inspection, 3)
		}
		if json.NewEncoder(out).Encode(adoptionReport{Version: "original-first-adoption-execution.v1", State: "original_adoption_commit_verified_only_source_recovery_not_claimed", Adoption: inspection}) != nil {
			return 3
		}
		return 0
	}
	set, e := installer.PrepareOriginalWriterSet(active, password, enrollment, install.BootstrapSourceFilePin{File: *selectionFile, SHA256: *selectionSHA})
	if e != nil {
		cancel()
		return reportStageFailure(out, "original_preflight_refused_no_source_stop", "source_preflight", e, install.OriginalAdoptionCommitInspection{}, 1)
	}
	hold, acquireErr := set.Acquire(active)
	var committed install.OriginalAdoptionCommitInspection
	adoptionAttempted := false
	adoptionErr := acquireErr
	adoptionStage := "source_acquisition"
	if acquireErr == nil && hold != nil {
		adoptionStage = "history_preparation"
		var runtimeMetadata []install.BootstrapSourceFilePin
		if *runtimeMetadataFile != "" {
			runtimeMetadata = append(runtimeMetadata, install.BootstrapSourceFilePin{File: *runtimeMetadataFile, SHA256: *runtimeMetadataSHA})
		}
		source, prepareErr := hold.PrepareOriginalFirstAdoption(active, password, enrollment, runtimeMetadata...)
		adoptionErr = prepareErr
		if prepareErr == nil {
			adoptionAttempted = true
			adoptionStage = "owner_issuance_and_adoption"
			committed, adoptionErr = source.AdoptOriginalFilesystem(active, *issuerDefinitionFile, *issuerDefinitionSHA)
		}
	}
	// Close the original context before making a NEW recovery authority. This
	// does not extend capture and never changes the original owner ctx/until.
	cancel()
	freshPassword := bytes.Clone(password)
	if *recoveryPasswordFile != "" {
		clear(freshPassword)
		freshPassword, e = install.ReadPrivateFile(*recoveryPasswordFile, 1024)
		if e != nil {
			return reportStageFailure(out, "original_recovery_credential_unavailable_retains_gates", "recovery_credentials", e, committed, 3)
		}
	}
	defer clear(freshPassword)
	recoveryCtx, recoveryCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer recoveryCancel()
	if adoptionAttempted && errors.Is(adoptionErr, install.ErrCommitUnknown) {
		var resolveErr error
		committed, resolveErr = installer.ReconcileOriginalAdoptionCommit(recoveryCtx, freshPassword, enrollment, set)
		if resolveErr != nil {
			return reportStageFailure(out, "original_adoption_commit_unresolved_retains_original_gates_journal", "adoption_commit_reconciliation", resolveErr, committed, 3)
		}
		adoptionErr = nil
	}
	authorization, recoveryErr := installer.PrepareOriginalWriterRecovery(recoveryCtx, freshPassword, enrollment, set)
	if recoveryErr != nil {
		return reportStageFailure(out, "fresh_original_recovery_refused_retains_gates", "recovery_authorization", recoveryErr, committed, 3)
	}
	if acquireErr != nil || hold == nil {
		_, abortErr := set.AbortUnstartedOriginalAcquisition(recoveryCtx, authorization)
		if abortErr == nil {
			if json.NewEncoder(out).Encode(adoptionReport{Version: "original-first-adoption-execution.v1", State: "unstarted_original_acquisition_aborted_no_source_recovery_claim", AdmissionAbortVerified: true}) != nil {
				return 3
			}
			return 1
		}
		if !errors.Is(abortErr, install.ErrOriginalSourceDispatchPresent) {
			return reportStageFailure(out, "original_admission_abort_unverified_retains_gates", "admission_abort", abortErr, committed, 3)
		}
	}
	recoveryErr = set.RestoreOriginalSources(recoveryCtx, authorization)
	if recoveryErr != nil {
		state := "original_sources_not_completely_verified_retains_gates"
		if errors.Is(recoveryErr, install.ErrCommitUnknown) {
			state = "original_recovery_commit_unknown_requires_exact_readback"
		}
		return reportStageFailure(out, state, "source_recovery", recoveryErr, committed, 3)
	}
	if adoptionErr != nil || hold == nil {
		if json.NewEncoder(out).Encode(adoptionReport{Version: "original-first-adoption-execution.v1", State: "original_adoption_failed_actual_sources_recovered_only", SourceRecoveryVerified: true, Failure: classifiedAdoptionFailure(adoptionStage, adoptionErr), Adoption: committed}) != nil {
			return 3
		}
		return 1
	}
	if adoptionErr != nil || !adoptionAttempted || committed.State == "" {
		return reportFailure(out, "original_adoption_not_committed_sources_recovered", 1)
	}
	if json.NewEncoder(out).Encode(adoptionReport{Version: "original-first-adoption-execution.v1", State: "original_adoption_committed_exact_readback_sources_recovered", HoldVerified: true, SourceRecoveryVerified: true, Adoption: committed}) != nil {
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

type adoptionReport struct {
	Version, State                       string
	HoldVerified, SourceRecoveryVerified bool
	AdmissionAbortVerified               bool
	PageBackupCompleted                  bool
	Adoption                             install.OriginalAdoptionCommitInspection
	Failure                              *adoptionFailure `json:",omitempty"`
}

func reportFailure(out io.Writer, state string, code int) int {
	if json.NewEncoder(out).Encode(adoptionReport{Version: "original-first-adoption-execution.v1", State: state}) != nil {
		return 3
	}
	return code
}

// Operator diagnostics carry fixed stages and the genuine source dependency,
// never raw SQL/native errors, credentials or private object bodies.
type adoptionFailure struct {
	Stage                    string
	InstanceID               int    `json:",omitempty"`
	Mode, Status, Dependency string `json:",omitempty"`
}

var adoptionDiagnosticCode = regexp.MustCompile(`^[A-Za-z0-9_./:-]+$`)

func classifiedAdoptionFailure(stage string, err error) *adoptionFailure {
	f := &adoptionFailure{Stage: stage}
	var source install.OriginalWriterSourceFailure
	if errors.As(err, &source) {
		f.InstanceID = source.InstanceID
		if len(source.Mode) <= 1024 && adoptionDiagnosticCode.MatchString(source.Mode) {
			f.Mode = source.Mode
		}
		if len(source.Status) <= 1024 && adoptionDiagnosticCode.MatchString(source.Status) {
			f.Status = source.Status
		}
		if len(source.Dependency) <= 1024 && adoptionDiagnosticCode.MatchString(source.Dependency) {
			f.Dependency = source.Dependency
		}
	}
	return f
}
func reportStageFailure(out io.Writer, state, stage string, err error, committed install.OriginalAdoptionCommitInspection, code int) int {
	if json.NewEncoder(out).Encode(adoptionReport{Version: "original-first-adoption-execution.v1", State: state, Adoption: committed, Failure: classifiedAdoptionFailure(stage, err)}) != nil {
		return 3
	}
	return code
}
