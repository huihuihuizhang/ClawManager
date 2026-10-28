package systembackupsecurity

import (
	"time"
	"unicode/utf8"
)

const MaxConfigMutationResponseBytes = 262144 + 8192

// ConfigMutationResponseContentPolicy comes from the authenticated writer's
// independently checked snapshot, not by extracting claims from response JSON.
// RedactedReason must already be the approved redactor's output. This builder
// neither sanitizes arbitrary text nor grants write/evidence permissions.
// Keep this canonical-only helper independent of the evidence storage package.
type ConfigMutationResponseContentPolicy struct {
	InstallationID    string
	CreatedBy         int64
	Version           int64
	Config            ConfigValues
	RedactedReason    *string
	CreatedAt         time.Time
	DeploymentEnabled bool
}

// CanonicalConfigMutationResponse constructs the complete closed ConfigResource
// from trusted typed facts. Byte comparison against this result validates every
// field, including nested config, without accepting unknown secret fields or
// canonicalizing attacker-controlled extras away. It supports enabled configs.
func CanonicalConfigMutationResponse(p ConfigMutationResponseContentPolicy) ([]byte, error) {
	_, offset := p.CreatedAt.Zone()
	if !configMutationInstallation.MatchString(p.InstallationID) || p.CreatedBy < 1 || p.Version < 2 || p.Version > 9007199254740991 ||
		len(p.Config.CanonicalJSON()) < 2 || p.CreatedAt.IsZero() || offset != 0 {
		return nil, ErrConfigMutation
	}
	var reason *string
	if p.RedactedReason != nil {
		copy := *p.RedactedReason
		if copy == "" || len(copy) > 512 || !utf8.ValidString(copy) {
			return nil, ErrConfigMutation
		}
		reason = &copy
	}
	raw, err := configMutationResponse(p.InstallationID, RegistrationActor{UserID: p.CreatedBy}, p.Version, p.Config, reason, p.CreatedAt, p.DeploymentEnabled)
	if err != nil || len(raw) > MaxConfigMutationResponseBytes {
		return nil, ErrConfigMutation
	}
	return raw, nil
}
