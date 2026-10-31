package systembackupcontrolevidence

import "encoding/json"

// Required comparisons are determined by this compiled policy and the exact
// original part basis. They are not discovered from a caller's passed checks.
// The concrete B reader must derive the zero violation count by completing
// the inert parser for the named operation; syntax alone proves no such read.
type OwnerCheckRequirement struct {
	Category          string
	ID                string
	Expected          json.RawMessage
	ResultEvidenceRef string
}

func ownedPartCategory(operation string) string {
	switch operation {
	case "capture-database", "capture-workspace", "capture-source-redis":
		return "instances"
	case "capture-skill-objects":
		return "skill_hub"
	case "capture-deployment-resources", "capture-secret-bundle":
		return "resources"
	case "capture-team-redis", "capture-team-objects":
		return "teams"
	}
	return ""
}

func RequiredOwnerChecks(owner string, basis OwnedReportBasis) ([]OwnerCheckRequirement, error) {
	if !validOwnerBasis(basis) {
		return nil, ErrInvalid
	}
	out := []OwnerCheckRequirement{}
	for _, part := range basis.Parts {
		category := ownedPartCategory(part.Operation)
		if category == "" {
			return nil, ErrInvalid
		}
		appendCheck := func(category, suffix, key string, value any) {
			raw, _ := Canonical(map[string]any{key: value})
			out = append(out, OwnerCheckRequirement{Category: category, ID: category + "." + part.Part + "." + suffix, Expected: raw, ResultEvidenceRef: part.ResultEvidenceRef})
		}
		switch owner {
		case "B":
			appendCheck(category, "source_binding", "hash", part.InvocationSHA256)
			appendCheck(category, "domain_violations", "violations", uint64(0))
		case "C":
			appendCheck("artifact", "ciphertext", "hash", part.CiphertextSHA256)
			appendCheck("artifact", "ciphertext_bytes", "bytes", part.CiphertextBytes)
			appendCheck("artifact", "envelope", "hash", part.EnvelopeSHA256)
		case "D":
			appendCheck("control_plane", "capture_context", "hash", basis.CaptureContextSHA256)
			appendCheck("control_plane", "invocation", "hash", part.InvocationSHA256)
			appendCheck("control_plane", "registered_result", "hash", part.ResultSHA256)
		default:
			return nil, ErrInvalid
		}
	}
	return out, nil
}
