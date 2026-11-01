package systembackupexecution

import (
	"errors"

	cd "clawreef/internal/systembackupcapturedescription"
	c "clawreef/internal/systembackupcontroller"
)

// Both real startup loaders call this through their material validators.
// GOMEMLIMIT is an explicit operator process declaration. Nothing here raises
// process/OS/Pod limits. Runtime allocation admission still accounts every
// actual Seed and concurrent pipeline against current Go memory usage.
func (s *DeploymentService) validateDescriptionMemoryStartup(materials productionCaptureMaterials) error {
	operation, enabled := materials.Operations[cd.Operation]
	if !enabled {
		return nil
	}
	cap := operation.Request.MaxArchiveBytes
	if s == nil || operation.Request.MaxCompressedBytes != cap || cd.ValidateProcessMemoryDeclaration(cap) != nil {
		return errors.Join(c.ErrExecutionAuthority, cd.ErrMemoryDeclaration)
	}
	if s.Config.PublisherVerifier != nil && (s.publisherVerifier == nil || s.publisherVerifier.DescriptionMaxPlaintextBytes < cap || s.publisherVerifier.validateDescriptionMemoryDeclaration() != nil) {
		return errors.Join(c.ErrExecutionAuthority, cd.ErrMemoryDeclaration)
	}
	return nil
}

func (p PublisherVerifierMaterials) validateDescriptionMemoryDeclaration() error {
	if p.DescriptionMaxPlaintextBytes == 0 {
		return nil
	} // legacy reader protocol
	if cd.ValidateProcessMemoryDeclaration(p.DescriptionMaxPlaintextBytes) != nil {
		return errors.Join(c.ErrExecutionAuthority, cd.ErrMemoryDeclaration)
	}
	return nil
}

// Pure material/RBAC rendering checks the cap's shape only. It does not run a
// controller, allocate a descriptor or require an execution-process budget.
func (p PublisherVerifierMaterials) validateDescriptionMemoryShape() error {
	if p.DescriptionMaxPlaintextBytes == 0 {
		return nil
	}
	if _, err := cd.MemoryBudgetForPlaintext(p.DescriptionMaxPlaintextBytes); err != nil {
		return errors.Join(c.ErrExecutionAuthority, cd.ErrMemoryDeclaration)
	}
	return nil
}
