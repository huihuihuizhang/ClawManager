package main

import (
	"context"
	"io"

	"clawreef/internal/systembackupbootstrapmaterials"
	"clawreef/internal/systembackupcatrust"
	"clawreef/internal/systembackupnoncebootstrap"
	"clawreef/internal/systembackupproducer"
	"clawreef/internal/systembackupsecurity"
)

// Explicit Go inputs from the original reviewed deployment mapping. This is
// deliberately not a CLI/JSON DTO and carries no approval booleans. Main cannot
// construct these from browser input, receipt hashes or resource files alone.
type bootstrapMaterialInputs struct {
	Original               systembackupsecurity.BootstrapCandidateAuthority
	Nonce                  systembackupnoncebootstrap.Binding
	ArtifactCA, EvidenceCA systembackupcatrust.Binding
	Selections             []systembackupproducer.BootstrapCandidateSelection
}

// composeBootstrapMaterials consumes A's real constructors without modifying
// their policy. The remaining owner slots are still checked by the unchanged
// run/LoadBootstrapDeployment path before credentials or SQL are opened.
func composeBootstrapMaterials(base systembackupsecurity.BootstrapOwnerAdapters, inputs bootstrapMaterialInputs) (systembackupsecurity.BootstrapOwnerAdapters, error) {
	owners, materials, err := composeBootstrapMaterialOwners(base, inputs)
	if err != nil {
		return systembackupsecurity.BootstrapOwnerAdapters{}, err
	}
	candidates, err := systembackupsecurity.NewBootstrapDeploymentCandidates(inputs.Selections, materials)
	if err != nil {
		return systembackupsecurity.BootstrapOwnerAdapters{}, err
	}
	owners.Candidates = candidates
	return owners, nil
}

func composeBootstrapMaterialOwners(base systembackupsecurity.BootstrapOwnerAdapters, inputs bootstrapMaterialInputs) (systembackupsecurity.BootstrapOwnerAdapters, *systembackupbootstrapmaterials.Materials, error) {
	materials, err := systembackupbootstrapmaterials.New(inputs.Original, inputs.Nonce, inputs.ArtifactCA, inputs.EvidenceCA)
	if err != nil {
		return systembackupsecurity.BootstrapOwnerAdapters{}, nil, err
	}
	owners, err := materials.Owners(base)
	if err != nil {
		return systembackupsecurity.BootstrapOwnerAdapters{}, nil, err
	}
	return owners, materials, nil
}

// A deployment-specific compiled link may call this once its independent
// original authority/bindings and all owners are available. No success fallback,
// bypass flag, additional credentials loader or HTTP bootstrap route is added.
func runWithBootstrapMaterials(ctx context.Context, args []string, out io.Writer, base systembackupsecurity.BootstrapOwnerAdapters, inputs bootstrapMaterialInputs) int {
	owners, err := composeBootstrapMaterials(base, inputs)
	if err != nil {
		return 1
	}
	return run(ctx, args, out, owners)
}
