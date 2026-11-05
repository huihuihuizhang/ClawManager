package install

import (
	"context"
	"path/filepath"

	archive "clawreef/internal/systembackuphostpatharchive"
)

// Locations emitted by actual owner/material producers. None is a source
// census, observation, authorization, coverage or successful-operation claim.
type OriginalFirstAdoptionInputSelections struct {
	Version                                                                            string
	ProviderInputs, C1Invocation, NativePlanReceipt                                    BootstrapSourceFilePin
	RuntimeDSN, RuntimeCA, WriterSelection, MinIOWholeHistoryMaterial, AdoptionIssuers BootstrapSourceFilePin
	MinIORecoveryDescriptor                                                            BootstrapSourceFilePin
	BusinessSourceSelection                                                            BootstrapSourceFilePin
	ArchiveTemplate, CustodyReader                                                     BootstrapSourceFilePin
	OutputDirectory, HistoryDirectory, Head1Directory, WarmDirectory                   string
	CaptureSeconds, RecoverySeconds                                                    int
}

type OriginalFirstAdoptionInputReceipt struct {
	Version, State                                               string
	MinIORecoveryQuery                                           BootstrapSourceFilePin
	Inputs, DisabledInitializationQuery                          BootstrapSourceFilePin
	AdoptionCommitted, ConfigurationEnabled, PageBackupCompleted bool
}

// Concrete normal owner command builds canonical invocation bytes from the
// actual pinned producer outputs. The field operator never handwrites an
// authorization JSON, original reservation, source facts or 17 control records.
func (i *Installer) PrepareOriginalFirstAdoptionProductionInputs(ctx context.Context, password []byte, enrollment EnrollmentPin, selection OriginalFirstAdoptionInputSelections) (OriginalFirstAdoptionInputReceipt, error) {
	var zero OriginalFirstAdoptionInputReceipt
	if i == nil || ctx == nil || selection.Version != "original-first-adoption-input-selections.v1" || selection.CaptureSeconds < 1 || selection.CaptureSeconds > 600 || selection.RecoverySeconds < 1 || selection.RecoverySeconds > 600 {
		return zero, ErrInstall
	}
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	for _, directory := range []string{selection.OutputDirectory, selection.HistoryDirectory, selection.Head1Directory, selection.WarmDirectory} {
		if privateDirectory(directory) != nil {
			return zero, ErrInstall
		}
	}
	raw, e := readBootstrapSourcePin(selection.ProviderInputs, 262144)
	var provider OriginalRuntimeProviderIssueInputs
	if e != nil || decodeExact(raw, &provider) != nil || provider.C1 != nil {
		return zero, ErrInstall
	}
	raw, e = readBootstrapSourcePin(selection.C1Invocation, 262144)
	if e != nil {
		return zero, ErrInstall
	}
	c1, e := DecodeOriginalC1PendingRuntimeInvocation(raw, selection.C1Invocation.SHA256)
	if e != nil || c1.Domain.Request != provider.Request || c1.Signing.ControllerDeployment != provider.ControllerDeployment || c1.Signing.ControllerPod != provider.ControllerPodName {
		return zero, ErrInstall
	}
	raw, e = readBootstrapSourcePin(selection.NativePlanReceipt, 262144)
	var native archive.NativeStream
	if e != nil || decodeOriginalNativeJSON(raw, &native, 262144) != nil || native.MaxFiles <= 0 || native.MaxBytes <= 0 || native.MaxSeconds < 1 || native.MaxSeconds > 600 {
		return zero, ErrInstall
	}
	// Reading these pinned producer files validates custody/bytes, not authority.
	// The actual production invocation still authenticates all real native/SQL
	// sources and constructs its private original holders/preparations itself.
	for _, pin := range []BootstrapSourceFilePin{selection.MinIORecoveryDescriptor, selection.BusinessSourceSelection, selection.WriterSelection, selection.MinIOWholeHistoryMaterial, selection.AdoptionIssuers, selection.ArchiveTemplate, selection.CustodyReader, provider.Core, provider.Forward, provider.Provider, provider.PublicationOwnerInputs, provider.Issuers} {
		limit := int64(262144)
		if pin == selection.CustodyReader {
			if originalReaderExecutable(pin.File, pin.SHA256) != nil {
				return zero, ErrInstall
			}
			continue
		}
		bytes, e := readBootstrapSourcePin(pin, limit)
		clear(bytes)
		if e != nil {
			return zero, ErrInstall
		}
	}
	data := OriginalFirstAdoptionProductionInputs{Version: "original-first-adoption-production-inputs.v1", MinIORecoveryDescriptor: selection.MinIORecoveryDescriptor, RuntimeDSN: selection.RuntimeDSN, RuntimeCA: selection.RuntimeCA, C1Invocation: selection.C1Invocation, WriterSelection: selection.WriterSelection, MinIOWholeHistoryMaterial: selection.MinIOWholeHistoryMaterial, AdoptionIssuers: selection.AdoptionIssuers, Provider: provider, Native: native, History: OriginalMixedFirstAdoptionInputs{BusinessSourceSelection: selection.BusinessSourceSelection, ArchiveTemplate: selection.ArchiveTemplate, CustodyReader: selection.CustodyReader, OutputDirectory: selection.HistoryDirectory}, Head1Directory: selection.Head1Directory, WarmDirectory: selection.WarmDirectory, CaptureSeconds: selection.CaptureSeconds, RecoverySeconds: selection.RecoverySeconds}
	raw, e = canonical(data)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	queryRaw, e := canonical(struct {
		Version string
		Request RequestFiles
	}{"original-disabled-initialization-query-inputs.v1", provider.Request})
	if e != nil {
		return zero, ErrInstall
	}
	minioQueryRaw, e := canonical(struct {
		Version    string
		Descriptor BootstrapSourceFilePin
	}{"original-minio-recovery-query-inputs.v1", selection.MinIORecoveryDescriptor})
	if e != nil {
		return zero, ErrInstall
	}
	const minioQueryName = "first-adoption.minio-recovery-query.json"
	const name = "first-adoption.production-inputs.json"
	const queryName = "first-adoption.disabled-initialization-query.json"
	if writeNewFiles(selection.OutputDirectory, map[string][]byte{name: raw, queryName: queryRaw, minioQueryName: minioQueryRaw}) != nil {
		return zero, ErrInstall
	}
	return OriginalFirstAdoptionInputReceipt{Version: "original-first-adoption-input-receipt.v1", State: "actual_producer_locations_bound_not_adopted_not_enabled", Inputs: BootstrapSourceFilePin{File: filepath.Join(selection.OutputDirectory, name), SHA256: hash(raw)}, DisabledInitializationQuery: BootstrapSourceFilePin{File: filepath.Join(selection.OutputDirectory, queryName), SHA256: hash(queryRaw)}, MinIORecoveryQuery: BootstrapSourceFilePin{File: filepath.Join(selection.OutputDirectory, minioQueryName), SHA256: hash(minioQueryRaw)}}, nil
}
