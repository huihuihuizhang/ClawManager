package systembackupbootstrapmaterials

import (
	"context"

	sec "clawreef/internal/systembackupsecurity"
)

// InputStatus contains closed names only: no paths, pins, tokens, material,
// wrapped provider errors, subject IDs, or credential-derived identity hashes.
type InputStatus struct {
	Slot   string `json:"slot"`
	Status string `json:"status"`
}

// InspectInputs does local I/O only. Successful output is inputs_checked, never
// admission/authorization; it cannot be supplied to Apply or a candidate API.
// Nonce preparation reads/wipes the real 32-byte inputs through the existing
// helper. CA inspection checks exact public PEM/descriptor bytes without TLS.
func (m *Materials) InspectInputs(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) []InputStatus {
	out := []InputStatus{{Slot: "reference:nonce_hmac", Status: "not_ready"}, {Slot: "reference:artifact_ca", Status: "not_ready"}, {Slot: "reference:evidence_ca", Status: "not_ready"}}
	if m == nil || m.nonce == nil || m.artifact == nil || m.evidence == nil || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return out
	}
	if _, err := m.nonce.Prepare(ctx, g, c); err == nil {
		out[0].Status = "inputs_checked"
	}
	if m.artifact.InspectInputs(ctx, g, c) == nil {
		out[1].Status = "inputs_checked"
	}
	if m.evidence.InspectInputs(ctx, g, c) == nil {
		out[2].Status = "inputs_checked"
	}
	return out
}
