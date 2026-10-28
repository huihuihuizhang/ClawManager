package systembackupsecurity

import (
	"context"
	"encoding/json"

	pd "clawreef/internal/systembackupproducer"
)

// BootstrapDeploymentCandidates is constructor-fixed Go composition, not a
// deployment-file DTO or approval. The original authority MUST authenticate
// deployment/purpose/resource mappings and all original resource checks.
// Selecting receipts, supplying hashes or linking this object grants nothing.
type BootstrapDeploymentCandidates struct {
	state *bootstrapDeploymentCandidateState
}

type bootstrapDeploymentCandidateState struct {
	selections []pd.BootstrapCandidateSelection
	authority  BootstrapCandidateAuthority
}

func (BootstrapDeploymentCandidates) String() string   { return "BootstrapDeploymentCandidates" }
func (BootstrapDeploymentCandidates) GoString() string { return "BootstrapDeploymentCandidates" }
func (BootstrapDeploymentCandidates) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*BootstrapDeploymentCandidates) UnmarshalJSON([]byte) error { return ErrRegistrationUnavailable }

func (c *BootstrapDeploymentCandidates) valid() bool {
	return c != nil && c.state != nil && len(c.state.selections) > 0 && len(c.state.selections) <= 20 && !candidateAuthorityNil(c.state.authority)
}

// UsesCandidateConsumption describes a fixed compiled route, never permission.
// Apply still performs current grant/RBAC, original authority and SQL checks.
func (d *BootstrapDeployment) UsesCandidateConsumption() bool {
	return d != nil && d.candidates.valid()
}

func NewBootstrapDeploymentCandidates(selections []pd.BootstrapCandidateSelection, original BootstrapCandidateAuthority) (*BootstrapDeploymentCandidates, error) {
	if len(selections) == 0 || len(selections) > 20 || candidateAuthorityNil(original) {
		return nil, ErrRegistrationUnavailable
	}
	for _, selection := range selections {
		if selection.Request.Admission.Unconfigured == nil || selection.Request.Admission.Configured != nil {
			return nil, ErrRegistrationUnavailable
		}
		if _, err := pd.ResultHashes(selection.Request); err != nil {
			return nil, ErrRegistrationUnavailable
		}
	}
	// Copy complete nested requests; no caller-owned slice survives composition.
	raw, err := json.Marshal(selections)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	var owned []pd.BootstrapCandidateSelection
	if json.Unmarshal(raw, &owned) != nil {
		return nil, ErrRegistrationUnavailable
	}
	return &BootstrapDeploymentCandidates{state: &bootstrapDeploymentCandidateState{selections: owned, authority: original}}, nil
}

func (d *BootstrapDeployment) inspectCandidateInputs(ctx context.Context) error {
	if d == nil || candidateAuthorityNil(ctx) || ctx.Err() != nil || !d.candidates.valid() {
		return ErrRegistrationUnavailable
	}
	r, err := d.Inspect()
	if err != nil {
		return err
	}
	// Keep every original owner dependency, including typed-nil rejection. The
	// candidate authority is not a substitute for missing owner implementations.
	owners := BootstrapOwnerAdapters{Registries: d.sources.Registries, References: d.sources.References, CrossResources: d.sources.CrossResources}
	if len(r.MissingAdapters) != 0 || len(MissingBootstrapOwnerAdapters(owners)) != 0 {
		return ErrRegistrationUnavailable
	}
	for _, missing := range r.MissingInputs {
		if missing == "registry:rbac_bindings" {
			return ErrRegistrationPermission
		}
		// Only original non-authorizing resource-file errors may reach L3. The
		// real file authority records them privately and refuses all NEW use.
		known := false
		for _, kind := range bootstrapRegistryKinds {
			if missing == "registry:"+kind {
				known = true
			}
		}
		if !known {
			return ErrRegistrationUnavailable
		}
	}
	if ctx.Err() != nil {
		return ErrRegistrationUnavailable
	}
	return nil
}

func (d *BootstrapDeployment) applyCandidates(ctx context.Context) (ConfigBootstrapResult, error) {
	var zero ConfigBootstrapResult
	if err := d.inspectCandidateInputs(ctx); err != nil {
		return zero, err
	}
	original := d.candidates.state
	// Concrete current grant/RBAC/registry sources are mandatory even when the
	// independently fixed mapping/resource authority supplied its own snapshots.
	authority, err := NewBootstrapCandidateFileAuthority(d.config, original.authority)
	if err != nil {
		return zero, err
	}
	attempt, err := PrepareConfigBootstrapCandidateAttempt(ctx, d.grant, d.raw, original.selections, authority, false)
	if err != nil {
		return zero, err
	}
	defer attempt.Close()
	// Provider preparation may revoke/remove controlled files or outlive the
	// caller. Re-read pinned sources BEFORE handing A the credential/DB opener.
	// Missing non-RBAC physical bytes remain a private history/new-use decision.
	if err = d.inspectCandidateInputs(ctx); err != nil {
		return zero, err
	}
	return attempt.Apply(d.openDatabase)
}
