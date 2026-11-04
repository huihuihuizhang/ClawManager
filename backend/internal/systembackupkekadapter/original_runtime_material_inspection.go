package systembackupkekadapter

import (
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	"context"
)

// Authenticate source FILES through the unchanged original grant validators.
// This returns no factory, prepared capability, job, task or provider permit;
// normal installed binding/admission/per-use checks remain mandatory.
func InspectOriginalRuntimeGrantMaterials(ctx context.Context, formal ControllerVerifierGrantMount, workload ControllerVerifierWorkload, installation, capture string, database reg.DatabaseIdentity, permit ProviderPermitIssuerConfig) error {
	if ctx == nil || ctx.Err() != nil || permit.Capabilities == nil || permit.Capabilities.database != database || permit.Capabilities.installation != installation {
		return kms.ErrPermission
	}
	if _, e := readControllerVerifierGrant(ctx, formal, workload, installation, capture, database); e != nil {
		return e
	}
	grant, e := readPermitIssuerGrant(ctx, permit)
	if e != nil {
		return e
	}
	key, e := readPermitSigningKey(permit.SigningKeyFile, grant.SigningPublicKey)
	clear(key)
	return e
}
