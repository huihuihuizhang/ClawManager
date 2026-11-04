package install

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"

	a "clawreef/internal/systembackupkekadapter"
)

// This is the actual original producer-to-installation bridge. No source
// pointer is decoded from a receipt/CLI file, no old metadata is labelled C1,
// and the actual original ctx/Installer/config/source lifetime is retained.
func (i *Installer) IssueOriginalRuntimeProviderAuthoritiesForC1(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalRuntimeProviderIssueInputs, production *OriginalC1SigningProduction) (OriginalRuntimeProviderIssueReceipt, error) {
	var zero OriginalRuntimeProviderIssueReceipt
	if production == nil || production.origin != production || production.run == nil || production.run.parent == nil || production.run.parent.operator == nil || production.run.parent.operator.installer != i || !consumerSameContext(ctx, production.ctx) || ctx.Err() != nil || production.run.parent.enrollment != enrollment || production.run.parent.input.Request != in.Request || len(in.originalC1Sources) != 0 {
		return zero, ErrInstall
	}
	sources, err := production.CompleteOriginalSources(ctx)
	if err != nil {
		return zero, err
	}
	in.originalC1Sources = sources
	issued, err := i.IssueOriginalRuntimeProviderAuthorities(ctx, runtimeDB, password, enrollment, in)
	if err != nil && !errors.Is(err, a.ErrAuthorityCommitUnknown) {
		return zero, err
	}
	// Known COMMIT and lost reply both independently query the SAME persisted
	// signed original mixed receipt and pending operation. Absence is UNKNOWN,
	// never permission to rerun the provider installer or issue another mapping.
	metadataPath := filepath.Join(in.OutputDirectory, "runtime-installed-metadata.receipt.json")
	metadataRaw, readErr := ReadSourceMaterialFile(metadataPath)
	if readErr != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	metadata := BootstrapSourceFilePin{File: metadataPath, SHA256: hash(metadataRaw)}
	pendingPath := filepath.Join(in.OutputDirectory, "runtime-provider-authorities.json")
	pendingRaw, readErr := ReadPrivateFile(pendingPath, 262144)
	if readErr != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	pending := BootstrapSourceFilePin{File: pendingPath, SHA256: hash(pendingRaw)}
	if err == nil && issued.SQLMetadataReceipt != metadata {
		return zero, a.ErrAuthorityCommitUnknown
	}
	resolved, readErr := i.QueryOriginalRuntimeProviderInstallation(ctx, password, enrollment, metadata, pending)
	if readErr != nil || resolved.State != "committed_original_rows_verified" || resolved.OriginalAuthorizationExpired || resolved.MaterialState != "original_result_sources_verified" || resolved.ProviderResult == nil || resolved.RetryAllowed {
		return zero, a.ErrAuthorityCommitUnknown
	}
	// Keep real opaque sources alive through later mixed-history/17 adoption.
	// The caller must NOT BootstrapConsume (which closes/mutates this domain)
	// before all history consumers/final guards finish their original rereads.
	if _, err = production.CompleteOriginalSources(ctx); err != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	return *resolved.ProviderResult, nil
}
