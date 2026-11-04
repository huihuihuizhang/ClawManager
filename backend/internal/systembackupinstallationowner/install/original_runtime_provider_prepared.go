package install

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"time"

	ev "clawreef/internal/systembackupevidence"
	a "clawreef/internal/systembackupkekadapter"
)

type originalRuntimeProviderPreparationSlot struct {
	prepared *OriginalRuntimeProviderPrepared
}

// A private continuation of the ACTUAL native issuer call, not an input DTO,
// fake pending result, signing callback or a separately renewed permission.
// Only PrepareOriginalRuntimeProviderAuthorities creates it; original files,
// signatures, auth/native checks, context and expiry remain unchanged.
type OriginalRuntimeProviderPrepared struct {
	mu         sync.Mutex
	origin     *OriginalRuntimeProviderPrepared
	ctx        context.Context
	installer  *Installer
	enrollment EnrollmentPin
	request    RequestFiles
	result     OriginalRuntimeProviderIssueReceipt
	stage      func([]*ev.OriginalC1EvidenceSource) (OriginalRuntimeProviderIssueReceipt, error)
	clear      func()
	until      time.Time
	used       bool
}

func (*OriginalRuntimeProviderPrepared) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func (p *OriginalRuntimeProviderPrepared) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clear != nil {
		p.clear()
		p.clear = nil
	}
	p.stage = nil
	p.used = true
}

func (i *Installer) PrepareOriginalRuntimeProviderAuthorities(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalRuntimeProviderIssueInputs) (*OriginalRuntimeProviderPrepared, error) {
	if in.C1 != nil || len(in.originalC1Sources) != 0 || in.preparation != nil {
		return nil, ErrInstall
	}
	slot := &originalRuntimeProviderPreparationSlot{}
	in.preparation = slot
	result, err := i.IssueOriginalRuntimeProviderAuthorities(ctx, runtimeDB, password, enrollment, in)
	if err != nil || slot.prepared == nil || result.State != "material_issued_sql_install_pending" {
		return nil, ErrInstall
	}
	return slot.prepared, nil
}

// A comparison view of the real signed materials, deliberately still pending.
// It provides the actual BackupKEK group's mapping files before SQL install.
func (p *OriginalRuntimeProviderPrepared) OriginalPendingMaterials(ctx context.Context) (OriginalRuntimeProviderIssueReceipt, error) {
	if p == nil {
		return OriginalRuntimeProviderIssueReceipt{}, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.used || p.stage == nil || !consumerSameContext(ctx, p.ctx) || ctx.Err() != nil || !time.Now().Before(p.until) || p.result.State != "material_issued_sql_install_pending" {
		return OriginalRuntimeProviderIssueReceipt{}, ErrInstall
	}
	return retainedC1Copy(p.result), nil
}

// This is the ONE actual original installation commit, after C1 material has
// been published/read back. The real A closure sees a pure C1 evidence universe
// first; the original three capabilities then join in that same transaction.
// It never stages an already-installed singleton again to refresh a receipt.
func (p *OriginalRuntimeProviderPrepared) InstallWithOriginalC1(ctx context.Context, password []byte, production *OriginalC1SigningProduction) (OriginalRuntimeProviderIssueReceipt, error) {
	var zero OriginalRuntimeProviderIssueReceipt
	if p == nil {
		return zero, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.used || p.stage == nil || p.installer == nil || !consumerSameContext(ctx, p.ctx) || ctx.Err() != nil || !time.Now().Before(p.until) || production == nil || production.origin != production || production.run == nil || production.run.parent == nil || production.run.parent.operator.installer != p.installer || production.run.parent.enrollment != p.enrollment || production.run.parent.input.Request != p.request {
		return zero, ErrInstall
	}
	sources, err := production.CompleteOriginalSources(ctx)
	if err != nil {
		return zero, err
	}
	p.used = true // Every partial/unknown result remains the original install.
	defer func() {
		if p.clear != nil {
			p.clear()
			p.clear = nil
		}
		p.stage = nil
	}()
	issued, err := p.stage(sources)
	if err != nil && !errors.Is(err, a.ErrAuthorityCommitUnknown) {
		return zero, err
	}
	directory := filepath.Dir(p.result.MappingRecord.File)
	metadataPath := filepath.Join(directory, "runtime-installed-metadata.receipt.json")
	metadataRaw, readErr := ReadSourceMaterialFile(metadataPath)
	if readErr != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	metadata := BootstrapSourceFilePin{File: metadataPath, SHA256: hash(metadataRaw)}
	pendingPath := filepath.Join(directory, "runtime-provider-authorities.json")
	pendingRaw, readErr := ReadPrivateFile(pendingPath, 262144)
	if readErr != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	if err == nil && issued.SQLMetadataReceipt != metadata {
		return zero, a.ErrAuthorityCommitUnknown
	}
	resolved, readErr := p.installer.QueryOriginalRuntimeProviderInstallation(ctx, password, p.enrollment, metadata, BootstrapSourceFilePin{File: pendingPath, SHA256: hash(pendingRaw)})
	if readErr != nil || resolved.State != "committed_original_rows_verified" || resolved.OriginalAuthorizationExpired || resolved.MaterialState != "original_result_sources_verified" || resolved.ProviderResult == nil || resolved.RetryAllowed {
		return zero, a.ErrAuthorityCommitUnknown
	}
	return *resolved.ProviderResult, nil
}
