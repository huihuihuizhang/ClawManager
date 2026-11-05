package install

import (
	ma "clawreef/internal/systembackupminioauthority"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	sb "clawreef/internal/systembackup"
	archive "clawreef/internal/systembackuphostpatharchive"
)

// Producer-file locations and bounded operational limits only. The actual
// owner creates the runtime mapping, C1 sources, head1, B reservation, archive
// association, retained references and every signed control inside this call.
type OriginalFirstAdoptionProductionInputs struct {
	Version                                                                                          string
	RuntimeDSN, RuntimeCA, C1Invocation, WriterSelection, MinIOWholeHistoryMaterial, AdoptionIssuers BootstrapSourceFilePin
	Provider                                                                                         OriginalRuntimeProviderIssueInputs
	Native                                                                                           archive.NativeStream
	History                                                                                          OriginalMixedFirstAdoptionInputs
	MinIORecoveryDescriptor                                                                          BootstrapSourceFilePin
	Head1Directory, WarmDirectory                                                                    string
	CaptureSeconds, RecoverySeconds                                                                  int
}

type OriginalFirstAdoptionProductionReceipt struct {
	Version, State, Stage                                                           string
	ProviderResultFile                                                              BootstrapSourceFilePin
	RuntimeMetadata                                                                 BootstrapSourceFilePin
	Head1                                                                           OriginalC1Head1Receipt
	C1BeforeCold                                                                    OriginalC1SigningStageReceipt
	MinIORecovery                                                                   *sb.MinIOReadServiceObservationData `json:",omitempty"`
	Adoption                                                                        OriginalAdoptionCommitInspection
	ProviderResult                                                                  *OriginalRuntimeProviderIssueReceipt    `json:",omitempty"`
	DisabledInitialization                                                          *OriginalDisabledInitializationReceipt  `json:",omitempty"`
	MinIORecoveryProjection                                                         *OriginalMinIORecoveryProjectionReceipt `json:",omitempty"`
	DisabledInitializationVerified                                                  bool
	RecoverySQLClock, OriginalObservationMinimum                                    time.Time
	OriginalObservationsStillFreshAtRecovery                                        bool
	HoldVerified, AdoptionCommitted, SourceRecoveryVerified, AdmissionAbortVerified bool
	CurrentReferencesQualified, ConfigurationEnabled, PageBackupCompleted           bool
	PhysicalSourceRecoveryVerified, RecoveryAdmissionRetained                       bool
	MinIORecoveryProjectionStage                                                    string
}

type OriginalFirstAdoptionProductionFailure struct {
	Stage string
	Cause error
}

func (e OriginalFirstAdoptionProductionFailure) Error() string {
	return "original first-adoption production stage refused: " + e.Stage
}
func (e OriginalFirstAdoptionProductionFailure) Unwrap() error { return e.Cause }

func DecodeOriginalFirstAdoptionProductionInputs(raw []byte, digest string) (OriginalFirstAdoptionProductionInputs, error) {
	var in OriginalFirstAdoptionProductionInputs
	if hash(raw) != digest || decodeExact(raw, &in) != nil || in.Version != "original-first-adoption-production-inputs.v1" || in.Provider.C1 != nil || (!bootstrapSourcePinValid(in.History.BusinessSourceSelection) || !bootstrapSourcePinValid(in.MinIORecoveryDescriptor)) {
		return in, ErrInstall
	}
	return in, nil
}

// This is a real committing production entry, distinct from the independent
// CheckControls rollback diagnostic. It never accepts signed controls or a
// PreparedCoverage/observation DTO from the caller. Partial or unknown results
// keep the one original directory, operation, credentials, journal and gate.
func (i *Installer) RunOriginalFirstAdoptionProduction(ctx context.Context, password, recoveryPassword, issuerPrivate []byte, enrollment EnrollmentPin, in OriginalFirstAdoptionProductionInputs) (receipt OriginalFirstAdoptionProductionReceipt, resultErr error) {
	return i.runOriginalFirstAdoptionProductionForSQLProfile(ctx, password, recoveryPassword, issuerPrivate, enrollment, in, false)
}

func (i *Installer) RunOriginalFirstAdoptionProductionForMinIOMetadata(ctx context.Context, password, recoveryPassword, issuerPrivate []byte, enrollment EnrollmentPin, in OriginalFirstAdoptionProductionInputs) (OriginalFirstAdoptionProductionReceipt, error) {
	return i.runOriginalFirstAdoptionProductionForSQLProfile(ctx, password, recoveryPassword, issuerPrivate, enrollment, in, true)
}

func (i *Installer) runOriginalFirstAdoptionProductionForSQLProfile(ctx context.Context, password, recoveryPassword, issuerPrivate []byte, enrollment EnrollmentPin, in OriginalFirstAdoptionProductionInputs, metadataSQL bool) (receipt OriginalFirstAdoptionProductionReceipt, resultErr error) {
	receipt = OriginalFirstAdoptionProductionReceipt{Version: "original-first-adoption-production.v1", State: "original_production_started", Stage: "input_validation"}
	fail := func(stage string, cause error) (OriginalFirstAdoptionProductionReceipt, error) {
		if cause == nil {
			cause = ErrInstall
		}
		receipt.Stage = stage
		receipt.State = "original_production_not_completed_preserve_original_materials"
		return receipt, OriginalFirstAdoptionProductionFailure{Stage: stage, Cause: cause}
	}
	if i == nil || ctx == nil || len(password) == 0 || len(recoveryPassword) == 0 || (!bootstrapSourcePinValid(in.History.BusinessSourceSelection) || !bootstrapSourcePinValid(in.MinIORecoveryDescriptor)) || in.Version != "original-first-adoption-production-inputs.v1" || in.CaptureSeconds < 1 || in.CaptureSeconds > 600 || in.RecoverySeconds < 1 || in.RecoverySeconds > 600 || privateDirectory(in.Head1Directory) != nil || privateDirectory(in.WarmDirectory) != nil {
		return fail("input_validation", ErrInstall)
	}
	active, cancel := context.WithTimeout(ctx, time.Duration(in.CaptureSeconds)*time.Second)
	defer cancel()
	descriptorRaw, e := readBootstrapSourcePin(in.MinIORecoveryDescriptor, 65536)
	if e != nil {
		return fail("recovery_descriptor_input_preflight", e)
	}
	descriptor, e := ma.DecodeMinIORecoveryDescriptor(descriptorRaw)
	if e != nil {
		return fail("recovery_descriptor_input_preflight", ErrInstall)
	}
	if _, e = os.Lstat(descriptor.ProjectionFile); !os.IsNotExist(e) {
		return fail("existing_recovery_projection_query_only", ErrCommitUnknown)
	}
	runtimeDB, identity, e := openOriginalEnrollmentDatabase(active, in.RuntimeDSN, in.RuntimeCA, i.plan.DatabaseTLSServerName)
	if e != nil || identity.ServerUUID != i.plan.Target.ServerUUID || identity.Database != i.plan.Target.Database || identity.Account == i.plan.InstallerDatabaseAccount {
		if runtimeDB != nil {
			runtimeDB.Close()
		}
		return fail("actual_runtime_sql_peer", ErrInstall)
	}
	defer runtimeDB.Close()
	if metadataSQL {
		scoped, closeScope, err := i.originalMetadataOwnerContext(active, runtimeDB, password, enrollment)
		if err != nil {
			return fail("actual_metadata_sql_owner_boundary", err)
		}
		defer closeScope()
		active = scoped
	}
	c1Raw, e := readBootstrapSourcePin(in.C1Invocation, 262144)
	if e != nil {
		return fail("c1_input_source", e)
	}
	c1Invocation, e := DecodeOriginalC1PendingRuntimeInvocation(c1Raw, in.C1Invocation.SHA256)
	if e != nil {
		return fail("c1_input_source", e)
	}
	installed, e := i.PrepareRunAndInstallOriginalRuntimeC1(active, runtimeDB, password, enrollment, in.Provider, c1Raw, in.C1Invocation.SHA256, issuerPrivate)
	if e != nil {
		return fail("native_material_c1_once_runtime_install", e)
	}
	defer installed.Close()
	// Preserve the genuine already queried material locations. A later disabled
	// initialization adds its own E row; never rerun the pure-C1 whole-E query.
	providerResult := retainedC1Copy(installed.result)
	receipt.ProviderResult = &providerResult
	providerRaw, e := canonical(providerResult)
	if e != nil || privateDirectory(in.History.OutputDirectory) != nil || writeNewFiles(in.History.OutputDirectory, map[string][]byte{"original-runtime-installed-materials.json": providerRaw}) != nil {
		return fail("original_installed_materials_durable_copy", ErrInstall)
	}
	receipt.ProviderResultFile = BootstrapSourceFilePin{File: filepath.Join(in.History.OutputDirectory, "original-runtime-installed-materials.json"), SHA256: hash(providerRaw)}
	receipt.RuntimeMetadata = installed.result.SQLMetadataReceipt
	receipt.Head1, e = installed.ImportOriginalPreColdHead1(active, password, issuerPrivate, in.Head1Directory)
	if e != nil {
		return fail("actual_original_head1", e)
	}
	receipt.C1BeforeCold, e = installed.production.StageReceipt(active)
	if e != nil || !receipt.C1BeforeCold.Complete20 {
		return fail("actual_current20_before_cold", ErrInstall)
	}
	minimum, e := receipt.C1BeforeCold.MinimumObservationUntil.Time()
	if e != nil {
		return fail("actual_current20_timing", ErrInstall)
	}
	receipt.OriginalObservationMinimum = minimum
	set, e := i.PrepareOriginalWriterSet(active, password, enrollment, in.WriterSelection)
	if e != nil {
		return fail("complete_original_writer_preflight", e)
	}
	defer set.closePrivate()
	if e = set.PrepareOriginalMinIOHistoryCapture(active, in.MinIOWholeHistoryMaterial, in.Native, in.WarmDirectory); e != nil {
		return fail("whole_minio_native_history_preflight", e)
	}
	if e = set.PrepareOriginalMinIOBusinessSourceSelection(active, in.History.BusinessSourceSelection); e != nil {
		return fail("actual_business_source_preflight", e)
	}
	if e = set.PrepareOriginalMinIORecoverySource(active, in.MinIORecoveryDescriptor); e != nil {
		return fail("actual_pre_cold_resource_baseline", e)
	}
	var session *PreparedOriginalMixedFirstAdoption
	hold, adoptionErr := set.Acquire(active)
	stage := "original_full_source_acquisition"
	if adoptionErr == nil && hold != nil {
		receipt.HoldVerified = true
		stage = "actual_nonempty_history_source"
		var prepareErr error
		session, prepareErr = hold.PrepareOriginalMixedAdoptionFromCapturedHistory(active, password, enrollment, installed, in.History)
		adoptionErr = prepareErr
		if prepareErr == nil {
			stage = "actual17_backfill_adopt_commit_readback"
			receipt.Adoption, adoptionErr = session.AdoptOriginal(active, in.AdoptionIssuers)
		}
	}
	receipt.AdoptionCommitted = receipt.Adoption.State != "" && adoptionErr == nil
	// A's fresh recovery permanently closes capture and stops registered
	// providers independently. Preserve the original C1 SOURCE context until
	// the real disabled-unverified owner initialization has read its history.
	// Defer cancellation at invocation completion; never revive an old context,
	// re-date observations, reset an epoch or repeat adoption.
	recoveryCtx, recoveryCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(in.RecoverySeconds)*time.Second)
	defer recoveryCancel()

	if errors.Is(adoptionErr, ErrCommitUnknown) && hold != nil && hold.adoptionUnknown {
		receipt.Adoption, e = i.ReconcileOriginalAdoptionCommit(recoveryCtx, recoveryPassword, enrollment, set)
		if e != nil {
			return fail("original_adoption_commit_unknown_exact_query", e)
		}
		adoptionErr = nil
		receipt.AdoptionCommitted = true
	}
	authority, e := i.PrepareOriginalWriterRecovery(recoveryCtx, recoveryPassword, enrollment, set)
	if e != nil {
		return fail("fresh_original_source_recovery_authorization", e)
	}
	if hold == nil {
		_, abortErr := set.AbortUnstartedOriginalAcquisition(recoveryCtx, authority)
		if abortErr == nil {
			receipt.AdmissionAbortVerified = true
			return fail(stage, adoptionErr)
		}
		if !errors.Is(abortErr, ErrOriginalSourceDispatchPresent) {
			return fail("original_unstarted_admission_abort", abortErr)
		}
	}
	if receipt.AdoptionCommitted && set.minioHistory != nil {
		set.minioHistory.adoption = receipt.Adoption
		set.minioHistory.adoptionCommitted = true
		if e = set.minioHistory.configureOriginalRecoverySigning(recoveryCtx, recoveryPassword, issuerPrivate, authority); e != nil {
			// Metadata cannot cancel the already-authorized physical recovery.
			// Its private failure blocks admission only after every actual source
			// has been restored and the final native proof has been read back.
			set.minioHistory.projectionFailure = e
		} else {
			defer set.minioHistory.signing.close()
		}
	}
	// This actual B entry now includes original native MinIO permission restore
	// BEFORE source mutations close, complete final native recovery, and actual
	// two-gate SQL release/readback. A Pod merely becoming Running is insufficient.
	if e = set.RestoreOriginalSources(recoveryCtx, authority); e != nil {
		if r := set.minioHistory; r != nil {
			if r.recovered != nil {
				data := r.recovered.Data()
				receipt.MinIORecovery = &data
			}
			if r.signing != nil {
				receipt.MinIORecoveryProjection = r.signing.receipt
			}
			if errors.Is(e, ErrOriginalRecoveryProjectionPending) && r.physicalRecoveryVerified {
				receipt.PhysicalSourceRecoveryVerified = true
				receipt.RecoveryAdmissionRetained = true
				receipt.MinIORecoveryProjectionStage = "original_projection_unverified_query_original_only"
				return fail("original_sources_physically_recovered_projection_pending_admission_retained", e)
			}
		}
		return fail("complete_original_source_recovery", e)
	}
	receipt.PhysicalSourceRecoveryVerified = true
	receipt.SourceRecoveryVerified = true
	if set.minioHistory != nil && set.minioHistory.signing != nil && set.minioHistory.signing.receipt != nil {
		receipt.MinIORecoveryProjection = set.minioHistory.signing.receipt
		receipt.MinIORecoveryProjectionStage = "original_projection_exact_readback"
	}
	if set.minioHistory != nil && set.minioHistory.recovered != nil {
		data := set.minioHistory.recovered.Data()
		receipt.MinIORecovery = &data
	}
	var server, database string
	if i.db.QueryRowContext(recoveryCtx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&server, &database, &receipt.RecoverySQLClock) != nil || server != i.plan.Target.ServerUUID || database != i.plan.Target.Database {
		return fail("original_recovery_clock_readback", ErrInstall)
	}
	receipt.OriginalObservationsStillFreshAtRecovery = receipt.RecoverySQLClock.Before(minimum)
	if adoptionErr != nil || hold == nil || receipt.Adoption.State == "" {
		return fail(stage, adoptionErr)
	}
	receipt.AdoptionCommitted = true
	if session == nil || session.origin != session || session.owner == nil {
		return fail("actual_original17_initialization_preparation", ErrInstall)
	}
	// The original C1 invocation closes its capacity SQL peer after production.
	// Reopen the SAME pinned SELECT-only native capacity TLS/credential inputs;
	// the original producer still supplies the actual collector configuration.
	capacityDB, e := i.openOriginalC1Capacity(c1Invocation)
	if e != nil {
		return fail("original_initialization_capacity_peer", e)
	}
	defer capacityDB.Close()
	initialized, e := i.InitializeOriginalDisabledUnverified(active, recoveryPassword, enrollment, OriginalDisabledInitializationInputs{Request: in.Provider.Request, Production: installed.production, Recovered: set, Coverage: session.owner, CapacityDB: capacityDB})
	if errors.Is(e, ErrCommitUnknown) {
		// Resolve only this original deterministic operation. Never send another
		// initialization, renew its source window or repeat adoption.
		initialized, e = i.QueryOriginalDisabledUnverified(recoveryCtx, recoveryPassword, enrollment, in.Provider.Request)
	}
	if e != nil {
		return fail("original_disabled_initialization_exact_query", e)
	}
	if initialized.State != "disabled_v1_committed_exact_readback_dependencies_unverified" || initialized.CurrentHealth != "unknown" || initialized.KEKAdmission != "absent" || initialized.Result.Version != 1 || initialized.Epoch != receipt.Adoption.ExpectedEpoch {
		return fail("original_disabled_initialization_readback_identity", ErrInstall)
	}
	receipt.DisabledInitialization = &initialized
	receipt.DisabledInitializationVerified = true
	receipt.Stage = "original_disabled_initialization_verified"
	receipt.State = "original_adoption_committed_sources_recovered_disabled_v1_dependencies_unverified"
	// Freshness comparison above is DATA only, not a current-reference permit.
	// A's lawful post-cold current-reference/index path must qualify enable;
	// this committing D1 entry never pretends old20 are final current health.
	return receipt, nil
}
