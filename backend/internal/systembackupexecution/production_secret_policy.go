package systembackupexecution

import (
	"context"
	"encoding/json"
	"path/filepath"

	root "clawreef/internal/systembackup"
	d "clawreef/internal/systembackupdispatch"
)

// A separate owner-mounted fixed policy, never generated from this task's UID
// observations. Its complete JCS bytes are anchored to original 097 config.
type originalSecretPolicyReference struct {
	Protocol string `json:"protocol"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
}

func (r originalSecretPolicyReference) validate() error {
	if r.Protocol != root.SecretCapturePolicyVersion || !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || !formalCandidateDigest(r.SHA256) {
		return d.ErrNotReady
	}
	return nil
}

func originalSecretPolicyConfigPin(raw []byte) (string, string, error) {
	var config struct {
		Registries []struct {
			Kind    string `json:"registry_kind"`
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"registries"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &config) != nil {
		return "", "", d.ErrNotReady
	}
	version, sha := "", ""
	for _, registry := range config.Registries {
		if registry.Kind != "secret_allowlist" {
			continue
		}
		if version != "" || registry.Version == "" || !formalCandidateDigest(registry.SHA256) {
			return "", "", d.ErrNotReady
		}
		version, sha = registry.Version, registry.SHA256
	}
	if version == "" {
		return "", "", d.ErrNotReady
	}
	return version, sha, nil
}

func (x *originalSourceMetadataAuthority) loadOriginalSecretPolicy(ctx context.Context) (root.FrozenSecretCapturePolicy, error) {
	var zero root.FrozenSecretCapturePolicy
	if x == nil || x.service == nil || x.owner == nil || x.owner.Gate.Authority.DB == nil || x.service.captureMaterials == nil || x.service.captureMaterials.Discovery == nil || x.service.captureMaterials.Discovery.SecretPolicy == nil || x.Recheck(ctx) != nil {
		return zero, d.ErrNotReady
	}
	ref := *x.service.captureMaterials.Discovery.SecretPolicy
	if ref.validate() != nil {
		return zero, d.ErrNotReady
	}
	version, sha, err := originalSecretPolicyConfigPin(x.input.ConfigSnapshot)
	if err != nil || sha != ref.SHA256 {
		return zero, d.ErrNotReady
	}
	var rowVersion, rowSHA string
	a := x.input.Authority
	if x.owner.Gate.Authority.DB.QueryRowContext(ctx, `SELECT secret_allowlist_registry_version,secret_allowlist_registry_sha256 FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=?`, a.InstallationID, a.ConfigVersion, a.ConfigSHA256).Scan(&rowVersion, &rowSHA) != nil || rowVersion != version || rowSHA != sha || x.Recheck(ctx) != nil {
		return zero, d.ErrNotReady
	}
	raw, err := pinnedDeploymentFile(ref.Path, sha, root.MaxSecretCapturePolicyBytes)
	if err != nil {
		return zero, d.ErrNotReady
	}
	policy, err := root.DecodeSecretCapturePolicy(raw, version, sha)
	if err != nil || x.Recheck(ctx) != nil {
		return zero, d.ErrNotReady
	}
	return policy, nil
}
