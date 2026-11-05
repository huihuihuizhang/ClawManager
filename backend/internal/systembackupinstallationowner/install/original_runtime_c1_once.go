package install

import (
	"context"
	"database/sql"
	"path/filepath"

	ev "clawreef/internal/systembackupevidence"
)

// This invocation contains actual producer-file locations, not authority or
// observations. BackupKEK is deliberately absent: only the real native
// preparation below can supply its mapping and independent observer files.
func DecodeOriginalC1PendingRuntimeInvocation(raw []byte, digest string) (OriginalC1SigningInvocation, error) {
	var in OriginalC1SigningInvocation
	if hash(raw) != digest || decodeExact(raw, &in) != nil || in.Version != "original-c1-pending-runtime-invocation.v3" || in.Groups == nil || in.PreColdHead1Directory != "" || in.Groups.BackupKEK != (BootstrapSourceFilePin{}) || in.CapacityTLS.Validate() != nil || !in.CapacityTLS.Selected() || in.Signing.Capacity.Validate() != nil {
		return in, ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{in.Groups.Six, in.Groups.MinIO, in.Groups.StatusRelay, in.Groups.Nonce, in.Groups.CatalogCheckpoint} {
		if !bootstrapSourcePinValid(pin) {
			return in, ErrInstall
		}
	}
	if in.Groups.EvidenceCA != (BootstrapSourceFilePin{}) && !bootstrapSourcePinValid(in.Groups.EvidenceCA) {
		return in, ErrInstall
	}
	for _, directory := range []string{in.Groups.SixOutputDirectory, in.Groups.MinIOOutputDirectory, in.Groups.StatusRelayOutputDirectory, in.Groups.NonceOutputDirectory, in.Groups.EvidenceCAOutputDirectory, in.Groups.BackupKEKOutputDirectory, in.Groups.CatalogCheckpointOutputDirectory} {
		if privateDirectory(directory) != nil {
			return in, ErrInstall
		}
	}
	return in, nil
}

// OriginalRuntimeC1Installed preserves the actual opaque sources for the
// subsequent head1/history/adoption caller in this same process/context.
// It is not a coverage source and cannot be reconstructed from a receipt.
type OriginalRuntimeC1Installed struct {
	origin     *OriginalRuntimeC1Installed
	ctx        context.Context
	production *OriginalC1SigningProduction
	result     OriginalRuntimeProviderIssueReceipt
}

func (*OriginalRuntimeC1Installed) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func (r *OriginalRuntimeC1Installed) Close() {
	if r != nil && r.origin == r && r.production != nil {
		r.production.Close()
	}
}

func (r *OriginalRuntimeC1Installed) CompleteOriginalSources(ctx context.Context) ([]*ev.OriginalC1EvidenceSource, error) {
	if r == nil || r.origin != r || !consumerSameContext(ctx, r.ctx) || r.production == nil {
		return nil, ErrInstall
	}
	return r.production.CompleteOriginalSources(ctx)
}

func (r *OriginalRuntimeC1Installed) OriginalInstallationResult(ctx context.Context) (OriginalRuntimeProviderIssueReceipt, error) {
	if _, err := r.CompleteOriginalSources(ctx); err != nil {
		return OriginalRuntimeProviderIssueReceipt{}, err
	}
	return retainedC1Copy(r.result), nil
}

// Actual native owner preparation -> all20 actual producers -> ONE original
// mixed SQL install -> independent exact-result query. The caller keeps this
// returned object alive through head1 and all history/adoption final guards.
// It does not enable config or report adoption/backup success.
func (i *Installer) PrepareRunAndInstallOriginalRuntimeC1(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, provider OriginalRuntimeProviderIssueInputs, c1Raw []byte, c1SHA string, issuerPrivate []byte) (_ *OriginalRuntimeC1Installed, resultErr error) {
	in, err := DecodeOriginalC1PendingRuntimeInvocation(c1Raw, c1SHA)
	if err != nil || in.Domain.Request != provider.Request || in.Signing.ControllerDeployment != provider.ControllerDeployment || in.Signing.ControllerPod != provider.ControllerPodName {
		return nil, ErrInstall
	}
	pending, err := i.PrepareOriginalRuntimeProviderAuthorities(ctx, runtimeDB, password, enrollment, provider)
	if err != nil {
		return nil, err
	}
	defer pending.Close()
	materials, err := pending.OriginalPendingMaterials(ctx)
	if err != nil {
		return nil, err
	}
	// Derive from the SAME native owner call's real signed mapping/observer.
	// No caller can select alternate mapping bytes or sign reference facts.
	kek := originalC1BackupKEKInputs{Observer: provider.Provider, Record: materials.MappingRecord, Signature: materials.MappingSignature, RuntimeIssuers: provider.Issuers}
	raw, err := canonical(kek)
	const name = "original-backup-kek-owner-inputs.json"
	if err != nil || writeNewFiles(in.Groups.BackupKEKOutputDirectory, map[string][]byte{name: raw}) != nil {
		return nil, ErrInstall
	}
	groups := *in.Groups
	if groups.EvidenceCA == (BootstrapSourceFilePin{}) {
		groups.EvidenceCA, err = i.prepareOriginalC1EvidenceCAInputs(ctx, password, enrollment, provider.Request, groups.Six, groups.EvidenceCAOutputDirectory)
		if err != nil {
			return nil, err
		}
	}
	groups.BackupKEK = BootstrapSourceFilePin{File: filepath.Join(groups.BackupKEKOutputDirectory, name), SHA256: hash(raw)}
	in.Groups = &groups
	in.Version = "original-c1-current-references-invocation.v2"
	raw, err = canonical(in)
	if err != nil {
		return nil, ErrInstall
	}
	in, err = DecodeOriginalC1SigningInvocation(raw, hash(raw))
	if err != nil {
		return nil, err
	}
	production, err := i.RunOriginalC1SigningProduction(ctx, password, enrollment, in, issuerPrivate)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			production.Close()
		}
	}()
	installed, err := pending.InstallWithOriginalC1(ctx, password, production)
	if err != nil {
		return nil, err
	}
	r := &OriginalRuntimeC1Installed{ctx: ctx, production: production, result: installed}
	r.origin = r
	return r, nil
}

// The real head0 -> head1 owner action follows the ONE mapping/C1 commit;
// doing it inside RunOriginalC1SigningProduction would change the authority
// before the pending continuation's original head0 recheck.
func (r *OriginalRuntimeC1Installed) ImportOriginalPreColdHead1(ctx context.Context, password, issuerPrivate []byte, directory string) (OriginalC1Head1Receipt, error) {
	if r == nil || r.origin != r || !consumerSameContext(ctx, r.ctx) || r.production == nil || r.production.head1 != nil {
		return OriginalC1Head1Receipt{}, ErrInstall
	}
	head, err := r.production.ImportOriginalPreColdHead1(ctx, password, issuerPrivate, directory)
	if err != nil {
		return OriginalC1Head1Receipt{}, err
	}
	r.production.head1 = &head
	return head, nil
}
