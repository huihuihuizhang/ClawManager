package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"clawreef/internal/systembackupsecurity"
)

// ConfigResponseContentPolicy is an internal authenticated-writer policy. Its
// business facts and already-redacted reason MUST be independently obtained;
// deriving this policy from the untrusted body would erase the trust boundary.
// ContentAuthority remains responsible for current producer/operation scope,
// approved reason policy, revocation and exact committed/prepared response facts.
type ConfigResponseContentPolicy struct {
	EvidenceID     string
	Classification string
	Response       systembackupsecurity.ConfigMutationResponseContentPolicy
	ValidUntil     time.Time
}

// ConfigResponseRedactor validates an already-redacted complete response. It
// never strips unknown fields, truncates to inline size, or sanitizes free text.
// Only large system-owned diagnostic/application-json evidence is admitted.
type ConfigResponseRedactor struct {
	installation, evidenceID, classification string
	until                                    time.Time
	expected                                 []byte
}

func NewConfigResponseRedactor(p ConfigResponseContentPolicy) (*ConfigResponseRedactor, error) {
	if !installationPattern.MatchString(p.Response.InstallationID) || !idPattern.MatchString(p.EvidenceID) ||
		!oneOf(p.Classification, "internal", "confidential", "sensitive") || !time.Now().Before(p.ValidUntil) {
		return nil, ErrRedaction
	}
	raw, err := systembackupsecurity.CanonicalConfigMutationResponse(p.Response)
	if err != nil || len(raw) <= 8192 {
		return nil, ErrRedaction
	}
	return &ConfigResponseRedactor{installation: p.Response.InstallationID, evidenceID: p.EvidenceID,
		classification: p.Classification, until: p.ValidUntil, expected: raw}, nil
}

func (v *ConfigResponseRedactor) policyHash() string {
	raw, _ := json.Marshal(map[string]any{"profile": "system-backup-config-response-content.v1", "installation_id": v.installation,
		"evidence_public_id": v.evidenceID, "classification": v.classification, "content_sha256": hash(v.expected),
		"valid_until": v.until.UTC().Format(time.RFC3339Nano)})
	return hash(raw)
}

func (v *ConfigResponseRedactor) Validate(ctx context.Context, i Identity, src io.Reader) error {
	if v == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(src) || !i.validExternal() || i.OwnerType != "system" || i.OwnerID != v.installation ||
		i.Installation != v.installation || i.ID != v.evidenceID || i.Type != "diagnostic" || i.Media != "application/json" ||
		i.Classification != v.classification || i.ContentSize != int64(len(v.expected)) || i.ContentHash != hash(v.expected) || !time.Now().Before(v.until) {
		return ErrRedaction
	}
	raw, err := io.ReadAll(io.LimitReader(src, systembackupsecurity.MaxConfigMutationResponseBytes+1))
	defer wipe(raw)
	if err != nil || ctx.Err() != nil || !time.Now().Before(v.until) || !bytes.Equal(raw, v.expected) {
		return ErrRedaction
	}
	return nil
}
