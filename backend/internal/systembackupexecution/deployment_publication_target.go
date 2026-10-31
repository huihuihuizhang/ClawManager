package systembackupexecution

import (
	"context"
	"os"
	"path/filepath"
	"reflect"

	c "clawreef/internal/systembackupcontroller"
)

type PublicationTargetReference struct {
	Protocol string `json:"protocol"`
	Path     string `json:"path"`
}
type PublicationTargetInput struct{ File, SHA256 string }

func PublicationTargetInputsFromEnvironment() []PublicationTargetInput {
	file, pin := os.Getenv("SYSTEM_BACKUP_PUBLICATION_TARGET_FILE"), os.Getenv("SYSTEM_BACKUP_PUBLICATION_TARGET_SHA256")
	if file == "" && pin == "" {
		return nil
	}
	return []PublicationTargetInput{{File: file, SHA256: pin}}
}

func (r PublicationTargetReference) validate() error {
	if r.Protocol != publicationTargetVersion || !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path {
		return c.ErrExecutionAuthority
	}
	return nil
}

func loadPublicationTarget(cfg DeploymentConfig, inputs []PublicationTargetInput) (*PublicationTargetMaterials, error) {
	if cfg.PublicationTarget == nil {
		if len(inputs) != 0 {
			return nil, c.ErrExecutionAuthority
		}
		return nil, nil
	}
	if cfg.PublicationTarget.validate() != nil || cfg.PublisherVerifier == nil || len(inputs) != 1 || inputs[0].File != cfg.PublicationTarget.Path {
		return nil, c.ErrExecutionAuthority
	}
	raw, err := pinnedDeploymentFile(inputs[0].File, inputs[0].SHA256, 65536)
	if err != nil {
		return nil, err
	}
	var materials PublicationTargetMaterials
	if decodeProviderDeploymentJSON(raw, &materials) != nil || materials.validate() != nil || materials.InstallationID != cfg.InstallationID {
		return nil, c.ErrExecutionAuthority
	}
	// Enforce a dedicated installation namespace even when the admitted role is
	// accidentally broader. The independently pinned material owns its root.
	if materials.Root != cfg.InstallationID+"/" {
		return nil, c.ErrExecutionAuthority
	}
	store, err := newNativePublicationS3(materials)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	// Credential use windows are operation-specific. In particular, an expired
	// write credential must not prevent original query-only reconciliation
	// using the separately pinned, still-valid read principal.
	return &materials, nil
}

func (d *DeploymentService) loadPublicationTargetInput(inputs []PublicationTargetInput) error {
	materials, err := loadPublicationTarget(d.Config, inputs)
	if err != nil {
		return err
	}
	if materials == nil {
		return nil
	}
	if d.publicationBinding() != nil {
		return c.ErrExecutionAuthority
	}
	input := inputs[0]
	d.publicationTargetInput = &input
	d.publicationTarget = materials
	return nil
}

func (d *DeploymentService) publicationStore(ctx context.Context) (*nativePublicationS3, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !d.ForwardEnabled || d.publicationBinding() != nil || d.publicationTarget == nil || d.publicationTargetInput == nil || d.checkPublisherVerifierBinding(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	materials, err := loadPublicationTarget(d.Config, []PublicationTargetInput{*d.publicationTargetInput})
	if err != nil || !reflect.DeepEqual(materials, d.publicationTarget) {
		return nil, c.ErrExecutionAuthority
	}
	return newNativePublicationS3(*materials)
}
