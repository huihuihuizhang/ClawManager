package publicadapter

import (
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
)

// ValidateFinalSkillWorkspaceParts rechecks only frozen Skills relationships.
// The caller must authenticate source and every original part, including full
// remote AEAD/EOF and current authority, before calling. This pure check grants
// no source access, capture eligibility, publication receipt or restore power.
// Parts need their original Part, Category, InvocationJSON and InvocationSHA256;
// Kubernetes intents and local staging files are neither read nor required.
func ValidateFinalSkillWorkspaceParts(source SourceInventory, parts []JobPart) error {
	if source.Skills == nil {
		return d.ErrNotReady
	}
	for _, part := range parts {
		var inv worker.Invocation
		if decodeStrict(part.InvocationJSON, &inv) != nil || !worker.ValidateRecordedInvocation(inv) {
			return d.ErrNotReady
		}
		sha, err := inv.Hash()
		if err != nil || sha != part.InvocationSHA256 || part.Part != inv.Request.Binding.Path {
			return d.ErrNotReady
		}
	}
	return validateSkillWorkspaceParts(source, parts)
}
